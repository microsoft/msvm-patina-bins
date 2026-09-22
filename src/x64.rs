//! MSVM X64 Specific Functionality
//!
//! This module provides x64 platform resources and virtualization exception registration.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//! SPDX-License-Identifier: Apache-2.0

mod tdx;

use crate::FailFast;
#[cfg(target_os = "uefi")]
use core::arch::global_asm;
#[cfg(target_os = "uefi")]
use patina_dxe_core::{ExceptionContext, ExceptionType, InterruptHandler};

#[cfg(target_os = "uefi")]
global_asm!(include_str!("x64/fail_fast.asm"));

#[cfg(target_os = "uefi")]
unsafe extern "efiapi" {
    fn msvm_triple_fault(error_code: usize, param1: usize, param2: usize, param3: usize) -> !;
}

pub use tdx::{MSVM_LAST_VE_EXIT_QUALIFICATION, MSVM_LAST_VE_EXIT_REASON, MSVM_LAST_VE_RCX, MSVM_LAST_VE_RIP};

/// Base I/O port for the MSVM COM1 UART.
pub const COM1_REGISTER_BASE: u16 = 0x3F8;
/// Base I/O port for the MSVM COM2 UART.
pub const COM2_REGISTER_BASE: u16 = 0x2F8;

const HV_CPUID_FEATURES: u32 = 0x4000_0003;
const HV_FEATURE_GUEST_CRASH_REGS_AVAILABLE: u32 = 1 << 10;
const HV_X64_MSR_CRASH_P0: u32 = 0x4000_0100;
const HV_X64_MSR_CRASH_P1: u32 = 0x4000_0101;
const HV_X64_MSR_CRASH_P2: u32 = 0x4000_0102;
const HV_X64_MSR_CRASH_P3: u32 = 0x4000_0103;
const HV_X64_MSR_CRASH_P4: u32 = 0x4000_0104;
const HV_X64_MSR_CRASH_CTL: u32 = 0x4000_0105;
const HV_CRASH_CTL_PRE_OS_ID_MASK: u64 = 0x7 << 58;
const HV_CRASH_CTL_PRE_OS_ID: u64 = 1 << 58;
const HV_CRASH_CTL_NO_CRASH_DUMP: u64 = 1 << 61;
const HV_CRASH_CTL_MESSAGE: u64 = 1 << 62;
const HV_CRASH_CTL_NOTIFY: u64 = 1 << 63;

/// MSVM X64 fatal error handler.
pub struct MsvmFailFast;

impl FailFast for MsvmFailFast {
    fn fail_fast(error_code: usize, param1: usize, param2: usize, message_buffer: usize, message_length: usize) -> ! {
        report_crash(error_code, param1, param2, message_buffer, message_length);
        notify_host_to_process_efi_diagnostics();
        reset_after_crash(error_code, param1, param2)
    }
}

fn report_crash(error_code: usize, param1: usize, param2: usize, message_buffer: usize, message_length: usize) {
    let features = core::arch::x86_64::__cpuid(HV_CPUID_FEATURES);
    if (features.edx & HV_FEATURE_GUEST_CRASH_REGS_AVAILABLE) == 0 {
        return;
    }

    let crash_capabilities = read_msr(HV_X64_MSR_CRASH_CTL);
    if (crash_capabilities & HV_CRASH_CTL_NOTIFY) == 0 {
        return;
    }

    write_msr(HV_X64_MSR_CRASH_P0, error_code as u64);
    write_msr(HV_X64_MSR_CRASH_P1, param1 as u64);
    write_msr(HV_X64_MSR_CRASH_P2, param2 as u64);
    write_msr(HV_X64_MSR_CRASH_P3, message_buffer as u64);
    write_msr(HV_X64_MSR_CRASH_P4, message_length as u64);

    let mut crash_control = HV_CRASH_CTL_NOTIFY;
    crash_control |= crash_capabilities & (HV_CRASH_CTL_MESSAGE | HV_CRASH_CTL_NO_CRASH_DUMP);
    if (crash_capabilities & HV_CRASH_CTL_PRE_OS_ID_MASK) >= HV_CRASH_CTL_PRE_OS_ID {
        crash_control |= HV_CRASH_CTL_PRE_OS_ID;
    }
    write_msr(HV_X64_MSR_CRASH_CTL, crash_control);
}

const BIOS_BASE_PORT: u16 = 0x28;
const BIOS_CONFIG_PROCESS_EFI_DIAGNOSTICS: u32 = 0x2C;

fn notify_host_to_process_efi_diagnostics() {
    // SAFETY: These are the defined BIOS device ports.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") BIOS_BASE_PORT,
            in("eax") BIOS_CONFIG_PROCESS_EFI_DIAGNOSTICS,
            options(nostack, nomem, preserves_flags),
        );
        core::arch::asm!(
            "out dx, eax",
            in("dx") BIOS_BASE_PORT + 4,
            in("eax") 1_u32,
            options(nostack, nomem, preserves_flags),
        );
    }
}
fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: The caller only supplies Hyper-V synthetic MSRs after CPUID advertises support.
    unsafe { core::arch::asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nostack)) };
    (u64::from(high) << 32) | u64::from(low)
}

fn write_msr(index: u32, value: u64) {
    // SAFETY: The caller only supplies Hyper-V synthetic MSRs after CPUID advertises support.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") index,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack),
        );
    }
}

fn reset_after_crash(_error_code: usize, _param1: usize, _param2: usize) -> ! {
    // SAFETY: The firmware cannot continue after a panic. This forces a triple fault intentionally.
    #[cfg(target_os = "uefi")]
    unsafe {
        msvm_triple_fault(_error_code, _param1, _param2, 0)
    }

    #[cfg(not(target_os = "uefi"))]
    panic!("MSVM crash handler invoked outside of UEFI environment");
}

/// Handles MSVM virtualization exceptions dispatched by Patina.
pub struct MsvmInterruptHandler;

/// MSVM virtualization exception handler instance.
pub static MSVM_INTERRUPT_HANDLER: MsvmInterruptHandler = MsvmInterruptHandler;

#[cfg(target_os = "uefi")]
static MSVM_EXCEPTION_HANDLERS: [(ExceptionType, &'static dyn InterruptHandler); 1] =
    [(tdx::EXCEPTION_VECTOR_VE, &MSVM_INTERRUPT_HANDLER)];

/// Returns the MSVM-specific exception handlers that Patina must register.
#[cfg(target_os = "uefi")]
pub fn exception_handlers() -> &'static [(ExceptionType, &'static dyn InterruptHandler)] {
    &MSVM_EXCEPTION_HANDLERS
}

#[cfg(target_os = "uefi")]
impl InterruptHandler for MsvmInterruptHandler {
    fn handle_interrupt(&'static self, exception_type: ExceptionType, context: &mut ExceptionContext) {
        assert_eq!(exception_type, tdx::EXCEPTION_VECTOR_VE, "Unexpected exception dispatched to MSVM VE handler");
        assert!(tdx::process_virtualization_exception(context), "Unhandled MSVM virtualization exception");
    }
}
