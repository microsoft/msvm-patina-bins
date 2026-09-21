//! Intel TDX virtualization exception handling.

#![cfg_attr(not(target_os = "uefi"), allow(dead_code))]

use core::{
    arch::asm,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(target_os = "uefi")]
use core::arch::global_asm;
use patina_dxe_core::ExceptionContextX64;

use super::{COM1_REGISTER_BASE, COM2_REGISTER_BASE};

#[cfg(target_os = "uefi")]
global_asm!(include_str!("tdx.asm"));

pub(super) const EXCEPTION_VECTOR_VE: usize = 20;

const VE_EXIT_CODE_CPUID: u32 = 10;
const VE_EXIT_CODE_HLT: u32 = 12;
const VE_EXIT_CODE_IO: u32 = 30;
const VE_EXIT_CODE_RDMSR: u32 = 31;
const VE_EXIT_CODE_WRMSR: u32 = 32;

const TDVMCALL_HALT: u64 = 12;
const TDVMCALL_IO: u64 = 30;
const TDVMCALL_RDMSR: u64 = 31;

const HV_CPUID_VENDOR_AND_MAX_FUNCTION: u32 = 0x4000_0000;
const HV_CPUID_INTERFACE: u32 = 0x4000_0001;
const HV_CPUID_FEATURES: u32 = 0x4000_0003;
const HV_CPUID_ENLIGHTENMENT_INFORMATION: u32 = 0x4000_0004;
const HV_CPUID_ISOLATION_CONFIGURATION: u32 = 0x4000_000C;
const HV_MICROSOFT_INTERFACE: u32 = u32::from_le_bytes(*b"Hv#1");
const HV_PARTITION_PRIVILEGES_LOW: u32 = 0x7E;
const HV_PARTITION_PRIVILEGES_HIGH: u32 = 1 << (54 - 32);
const HV_FEATURE_DEBUG_REGS_AVAILABLE: u32 = 1 << 11;
const HV_FEATURE_DIRECT_SYNTHETIC_TIMERS: u32 = 1 << 19;

const HV_X64_MSR_VP_INDEX: u64 = 0x4000_0002;
const HV_X64_MSR_TIME_REF_COUNT: u64 = 0x4000_0020;
const HV_X64_MSR_DEBUG_DEVICE_OPTIONS: u64 = 0x4000_00FF;
const MSR_IA32_MTRRCAP: u64 = 0xFE;
const MSR_IA32_APIC_BASE: u64 = 0x1B;
const MSR_IA32_EFER: u64 = 0xC000_0080;

const BIOS_ADDRESS_PORT: u16 = 0x28;
const BIOS_DATA_PORT: u16 = BIOS_ADDRESS_PORT + 4;

const HV_PARTITION_ISOLATION_TYPE_TDX: u32 = 3;
const HV_ISOLATION_SHARED_GPA_BOUNDARY_ACTIVE: u32 = 1 << 5;
const HV_ISOLATION_SHARED_GPA_BOUNDARY_BITS_SHIFT: u32 = 6;

#[cfg(target_os = "uefi")]
static TSC_MULTIPLIER: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "uefi")]
static TSC_DIVISOR: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "uefi")]
static ISOLATION_CONFIGURATION_EBX: AtomicU64 = AtomicU64::new(0);

/// Last #VE exit reason that the handler could not process.
#[unsafe(no_mangle)]
pub static MSVM_LAST_VE_EXIT_REASON: AtomicU64 = AtomicU64::new(0);

/// Last #VE exit qualification that the handler could not process.
#[unsafe(no_mangle)]
pub static MSVM_LAST_VE_EXIT_QUALIFICATION: AtomicU64 = AtomicU64::new(0);

/// RIP of the last #VE that the handler could not process.
#[unsafe(no_mangle)]
pub static MSVM_LAST_VE_RIP: AtomicU64 = AtomicU64::new(0);

/// RCX from the last #VE that the handler could not process.
#[unsafe(no_mangle)]
pub static MSVM_LAST_VE_RCX: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "uefi")]
unsafe extern "efiapi" {
    #[link_name = "SecGetTdxVeInfo"]
    fn sec_get_tdx_ve_info(ve_info: &mut TdxVeInfo) -> i64;

    #[link_name = "SecGetTdInfo"]
    fn sec_get_td_info(gpa_width: &mut u32) -> i64;

    #[link_name = "TdVmCall"]
    fn td_vm_call(
        call: u64,
        parameter1: u64,
        parameter2: u64,
        parameter3: u64,
        parameter4: u64,
        value: *mut u64,
    ) -> u64;
}

#[derive(Default)]
#[repr(C)]
struct TdxVeInfo {
    exit_reason: u32,
    valid: u32,
    exit_qualification: u64,
    guest_linear_address: u64,
    guest_physical_address: u64,
    instruction_length: u32,
    instruction_info: u32,
}

#[derive(Default)]
#[repr(C)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[derive(Debug, PartialEq)]
struct IoQualification {
    access_size: u32,
    is_read: bool,
    is_string: bool,
    port: u16,
}

impl IoQualification {
    fn decode(value: u64) -> Self {
        Self {
            access_size: ((value & 0x3) + 1) as u32,
            is_read: value & (1 << 3) != 0,
            is_string: value & (1 << 4) != 0,
            port: (value >> 16) as u16,
        }
    }
}

pub(super) fn process_virtualization_exception(context: &mut ExceptionContextX64) -> bool {
    let mut ve_info = TdxVeInfo::default();
    // SAFETY: The assembly routine writes exactly one TdxVeInfo to the supplied reference.
    if unsafe { get_tdx_ve_info(&mut ve_info) }.is_err() {
        return false;
    }

    let handled = match ve_info.exit_reason {
        VE_EXIT_CODE_RDMSR => process_msr_read(context),
        VE_EXIT_CODE_WRMSR => process_msr_write(context),
        VE_EXIT_CODE_CPUID => process_cpuid(context),
        VE_EXIT_CODE_HLT => process_hlt(),
        VE_EXIT_CODE_IO => process_io(context, ve_info.exit_qualification),
        _ => false,
    };

    if handled {
        context.rip = context.rip.wrapping_add(u64::from(ve_info.instruction_length));
    } else {
        MSVM_LAST_VE_EXIT_REASON.store(u64::from(ve_info.exit_reason), Ordering::Relaxed);
        MSVM_LAST_VE_EXIT_QUALIFICATION.store(ve_info.exit_qualification, Ordering::Relaxed);
        MSVM_LAST_VE_RIP.store(context.rip, Ordering::Relaxed);
        MSVM_LAST_VE_RCX.store(context.rcx, Ordering::Relaxed);
    }
    handled
}

#[cfg(target_os = "uefi")]
unsafe fn get_tdx_ve_info(ve_info: &mut TdxVeInfo) -> Result<(), ()> {
    // SAFETY: The caller provides writable storage for the TDCALL output registers.
    (unsafe { sec_get_tdx_ve_info(ve_info) } >= 0).then_some(()).ok_or(())
}

#[cfg(not(target_os = "uefi"))]
unsafe fn get_tdx_ve_info(_ve_info: &mut TdxVeInfo) -> Result<(), ()> {
    Err(())
}

fn process_msr_read(context: &mut ExceptionContextX64) -> bool {
    let value = match context.rcx {
        HV_X64_MSR_TIME_REF_COUNT => match time_reference_count() {
            Some(value) => value,
            None => return false,
        },
        HV_X64_MSR_DEBUG_DEVICE_OPTIONS => match vmcall(TDVMCALL_RDMSR, context.rcx, 0, 0, 0) {
            Some(value) => value,
            None => return false,
        },
        HV_X64_MSR_VP_INDEX | MSR_IA32_MTRRCAP => 0,
        MSR_IA32_APIC_BASE => 0xD00,
        _ => return false,
    };

    context.rax = u64::from(value as u32);
    context.rdx = value >> 32;
    true
}

fn process_msr_write(context: &ExceptionContextX64) -> bool {
    let value = msr_write_value(context);
    context.rcx == MSR_IA32_EFER && value == read_msr(MSR_IA32_EFER as u32)
}

fn msr_write_value(context: &ExceptionContextX64) -> u64 {
    (context.rdx << 32) | u64::from(context.rax as u32)
}

fn process_cpuid(context: &mut ExceptionContextX64) -> bool {
    let mut result = CpuidResult::default();
    let leaf = context.rax as u32;
    let isolation_configuration =
        if leaf == HV_CPUID_ISOLATION_CONFIGURATION { tdx_isolation_configuration() } else { None };
    if !customize_cpuid_result(leaf, &mut result, isolation_configuration) {
        return false;
    }
    context.rax = u64::from(result.eax);
    context.rbx = u64::from(result.ebx);
    context.rcx = u64::from(result.ecx);
    context.rdx = u64::from(result.edx);
    true
}

// TODO: This assumes Microsoft Hypervisor. Porting to other hypervisors may require changes.
fn customize_cpuid_result(leaf: u32, result: &mut CpuidResult, isolation_configuration: Option<CpuidResult>) -> bool {
    match leaf >> 28 {
        0 | 8 => *result = CpuidResult::default(),
        4 => match leaf {
            HV_CPUID_VENDOR_AND_MAX_FUNCTION => {
                result.eax = HV_CPUID_ISOLATION_CONFIGURATION;
                result.ebx = u32::from_le_bytes(*b"Micr");
                result.ecx = u32::from_le_bytes(*b"osof");
                result.edx = u32::from_le_bytes(*b"t Hv");
            }
            HV_CPUID_INTERFACE => {
                *result = CpuidResult { eax: HV_MICROSOFT_INTERFACE, ..CpuidResult::default() };
            }
            HV_CPUID_FEATURES => {
                *result = CpuidResult {
                    eax: HV_PARTITION_PRIVILEGES_LOW,
                    ebx: HV_PARTITION_PRIVILEGES_HIGH,
                    ecx: 0,
                    edx: HV_FEATURE_DEBUG_REGS_AVAILABLE | HV_FEATURE_DIRECT_SYNTHETIC_TIMERS,
                };
            }
            HV_CPUID_ENLIGHTENMENT_INFORMATION => *result = CpuidResult::default(),
            HV_CPUID_ISOLATION_CONFIGURATION => match isolation_configuration {
                Some(configuration) => *result = configuration,
                None => return false,
            },
            _ => return false,
        },
        _ => return false,
    }

    if leaf == 1 {
        result.ecx |= 1 << 31;
    }
    true
}

fn tdx_isolation_configuration() -> Option<CpuidResult> {
    #[cfg(not(target_os = "uefi"))]
    return None;

    #[cfg(target_os = "uefi")]
    {
        let cached_ebx = ISOLATION_CONFIGURATION_EBX.load(Ordering::Relaxed);
        if cached_ebx != 0 {
            return Some(CpuidResult { ebx: cached_ebx as u32, ..CpuidResult::default() });
        }

        let mut gpa_width = 0;
        // SAFETY: The assembly routine writes the GPA width to the supplied reference.
        if unsafe { sec_get_td_info(&mut gpa_width) } != 0 {
            return None;
        }
        let configuration = isolation_configuration_from_gpa_width(gpa_width)?;
        ISOLATION_CONFIGURATION_EBX.store(u64::from(configuration.ebx), Ordering::Relaxed);
        Some(configuration)
    }
}

fn isolation_configuration_from_gpa_width(gpa_width: u32) -> Option<CpuidResult> {
    let shared_gpa_boundary_bits = gpa_width.checked_sub(1)?;
    if shared_gpa_boundary_bits > 0x3F {
        return None;
    }
    Some(CpuidResult {
        ebx: HV_PARTITION_ISOLATION_TYPE_TDX
            | HV_ISOLATION_SHARED_GPA_BOUNDARY_ACTIVE
            | (shared_gpa_boundary_bits << HV_ISOLATION_SHARED_GPA_BOUNDARY_BITS_SHIFT),
        ..CpuidResult::default()
    })
}

fn process_hlt() -> bool {
    vmcall(TDVMCALL_HALT, 0, 0, 0, 0).is_some()
}

fn process_io(context: &mut ExceptionContextX64, exit_qualification: u64) -> bool {
    let qualification = IoQualification::decode(exit_qualification);
    if qualification.is_string || !is_port_access_allowed(qualification.port) {
        return false;
    }

    if qualification.is_read {
        let value = vmcall(TDVMCALL_IO, u64::from(qualification.access_size), 0, u64::from(qualification.port), 0)
            .unwrap_or(u64::from(u32::MAX));
        let mask = (1_u64 << (qualification.access_size * 8)) - 1;
        context.rax = (context.rax & !mask) | (value & mask);
        if qualification.access_size == 4 {
            context.rax = u64::from(context.rax as u32);
        }
    } else {
        let mask = (1_u64 << (qualification.access_size * 8)) - 1;
        let _ = vmcall(
            TDVMCALL_IO,
            u64::from(qualification.access_size),
            1,
            u64::from(qualification.port),
            context.rax & mask,
        );
    }
    true
}

#[cfg(target_os = "uefi")]
fn vmcall(call: u64, parameter1: u64, parameter2: u64, parameter3: u64, parameter4: u64) -> Option<u64> {
    let mut value = 0;
    // SAFETY: The assembly shim follows the efiapi ABI and preserves all nonvolatile registers.
    let status = unsafe { td_vm_call(call, parameter1, parameter2, parameter3, parameter4, &mut value) };
    (status == 0).then_some(value)
}

#[cfg(not(target_os = "uefi"))]
fn vmcall(_call: u64, _parameter1: u64, _parameter2: u64, _parameter3: u64, _parameter4: u64) -> Option<u64> {
    None
}

fn is_port_access_allowed(port: u16) -> bool {
    (COM1_REGISTER_BASE..COM1_REGISTER_BASE + 8).contains(&port)
        || (COM2_REGISTER_BASE..COM2_REGISTER_BASE + 8).contains(&port)
        || port == BIOS_ADDRESS_PORT
        || port == BIOS_DATA_PORT
}

fn time_reference_count() -> Option<u64> {
    #[cfg(not(target_os = "uefi"))]
    return None;

    #[cfg(target_os = "uefi")]
    {
        let (multiplier, divisor) = reference_time_scale()?;
        Some(mul_div(read_tsc(), multiplier, divisor))
    }
}

#[cfg(target_os = "uefi")]
fn reference_time_scale() -> Option<(u64, u64)> {
    let cached_divisor = TSC_DIVISOR.load(Ordering::Relaxed);
    if cached_divisor != 0 {
        return Some((TSC_MULTIPLIER.load(Ordering::Relaxed), cached_divisor));
    }

    // Read CPUID leaf 0x15 directly to match SecIso.c's AsmCpuid initialization path.
    let frequency = core::arch::x86_64::__cpuid_count(0x15, 0);
    let multiplier = u64::from(frequency.eax).checked_mul(10_000_000)?;
    let divisor = u64::from(frequency.ecx).checked_mul(u64::from(frequency.ebx))?.max(1);
    TSC_MULTIPLIER.store(multiplier, Ordering::Relaxed);
    TSC_DIVISOR.store(divisor, Ordering::Relaxed);
    Some((multiplier, divisor))
}

#[cfg(target_os = "uefi")]
fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: RDTSC reads a CPU counter and does not access memory.
    unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nostack, nomem)) };
    (u64::from(high) << 32) | u64::from(low)
}

fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: This is only used for EFER while handling an intercepted write at CPL 0.
    unsafe { asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nostack, nomem)) };
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(target_os = "uefi")]
fn mul_div(value: u64, multiplier: u64, divisor: u64) -> u64 {
    let result: u64;
    // SAFETY: DIV's nonzero divisor is guaranteed by time_reference_count.
    unsafe {
        asm!(
            "mul {multiplier}",
            "div {divisor}",
            multiplier = in(reg) multiplier,
            divisor = in(reg) divisor,
            inout("rax") value => result,
            out("rdx") _,
            options(nostack, nomem)
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exception_context() -> ExceptionContextX64 {
        // SAFETY: SystemContextX64 contains only integers and byte arrays, for which zero is valid.
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn test_x64_decode_io_qualification() {
        let qualification = IoQualification::decode((u64::from(COM1_REGISTER_BASE) << 16) | (1 << 3) | 3);
        assert_eq!(
            qualification,
            IoQualification { access_size: 4, is_read: true, is_string: false, port: COM1_REGISTER_BASE }
        );
    }

    #[test]
    fn test_x64_rejects_string_io_and_unapproved_ports() {
        let mut context = exception_context();
        assert!(!process_io(&mut context, (u64::from(COM1_REGISTER_BASE) << 16) | (1 << 4)));
        assert!(!process_io(&mut context, u64::from(0x1234_u16) << 16));
    }

    #[test]
    fn test_x64_port_access_filter() {
        assert!(is_port_access_allowed(COM2_REGISTER_BASE));
        assert!(is_port_access_allowed(COM1_REGISTER_BASE + 7));
        assert!(is_port_access_allowed(BIOS_ADDRESS_PORT));
        assert!(is_port_access_allowed(BIOS_DATA_PORT));
        assert!(!is_port_access_allowed(0x80));
    }

    #[test]
    fn test_x64_msr_write_value_uses_edx_eax() {
        let mut context = exception_context();
        context.rax = 0xFFFF_FFFF_89AB_CDEF;
        context.rcx = 0x80B;
        context.rdx = 0x0123_4567;
        assert_eq!(msr_write_value(&context), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn test_x64_cpuid_hypervisor_vendor_leaf() {
        let mut result = CpuidResult::default();
        assert!(customize_cpuid_result(HV_CPUID_VENDOR_AND_MAX_FUNCTION, &mut result, None));
        assert_eq!(result.eax, HV_CPUID_ISOLATION_CONFIGURATION);
        assert_eq!(result.ebx.to_le_bytes(), *b"Micr");
        assert_eq!(result.ecx.to_le_bytes(), *b"osof");
        assert_eq!(result.edx.to_le_bytes(), *b"t Hv");
    }

    #[test]
    fn test_x64_cpuid_hypervisor_features_leaf() {
        let mut result = CpuidResult::default();
        assert!(customize_cpuid_result(HV_CPUID_FEATURES, &mut result, None));
        assert_eq!(result.eax, HV_PARTITION_PRIVILEGES_LOW);
        assert_eq!(result.ebx, HV_PARTITION_PRIVILEGES_HIGH);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, HV_FEATURE_DEBUG_REGS_AVAILABLE | HV_FEATURE_DIRECT_SYNTHETIC_TIMERS);
    }

    #[test]
    fn test_x64_cpuid_sets_hypervisor_present_and_rejects_unknown_leaves() {
        let mut result = CpuidResult { eax: u32::MAX, ebx: u32::MAX, ecx: u32::MAX, edx: u32::MAX };
        assert!(customize_cpuid_result(1, &mut result, None));
        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 1 << 31);
        assert_eq!(result.edx, 0);
        assert!(!customize_cpuid_result(0x4000_0002, &mut result, None));
        assert!(!customize_cpuid_result(0x2000_0000, &mut result, None));
    }

    #[test]
    fn test_x64_cpuid_uses_local_isolation_configuration() {
        let configuration = isolation_configuration_from_gpa_width(48).unwrap();
        let mut result = CpuidResult::default();
        assert!(customize_cpuid_result(HV_CPUID_ISOLATION_CONFIGURATION, &mut result, Some(configuration)));
        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0xBE3);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn test_x64_rejects_unknown_msrs() {
        let mut context = exception_context();
        context.rcx = 0xDEAD_BEEF;
        assert!(!process_msr_read(&mut context));
        assert!(!process_msr_write(&context));
    }
}
