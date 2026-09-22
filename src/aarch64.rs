//! MSVM AArch64 specific functionality.
//!
//! Copyright (C) Microsoft Corporation.
//! SPDX-License-Identifier: Apache-2.0

use crate::FailFast;

const HV_STATUS_SUCCESS: u64 = 0;
const HV_REGISTER_GUEST_OS_ID: u32 = 0x0009_0002;
const HV_REGISTER_PRIVILEGES_AND_FEATURES_INFO: u32 = 0x0000_0200;
const HV_REGISTER_GUEST_CRASH_P0: u32 = 0x0000_0210;
const HV_REGISTER_GUEST_CRASH_P1: u32 = 0x0000_0211;
const HV_REGISTER_GUEST_CRASH_P2: u32 = 0x0000_0212;
const HV_REGISTER_GUEST_CRASH_P3: u32 = 0x0000_0213;
const HV_REGISTER_GUEST_CRASH_P4: u32 = 0x0000_0214;
const HV_REGISTER_GUEST_CRASH_CTL: u32 = 0x0000_0215;
const HV_GUEST_CRASH_REGS_AVAILABLE: u64 = 1 << 8;
const HV_GUEST_OS_MICROSOFT_UNDEFINED: u64 = 0;
const HV_GUEST_OS_VENDOR_MICROSOFT: u64 = 1 << 48;
const HV_CRASH_CTL_NOTIFY: u64 = 1 << 63;
const HV_CRASH_CTL_MESSAGE: u64 = 1 << 62;
const HV_CRASH_CTL_NO_CRASH_DUMP: u64 = 1 << 61;
const HV_CRASH_CTL_PRE_OS_ID: u64 = 1 << 58;

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_SYSTEM_RESET2_AARCH64: u64 = 0xC400_0012;
const HV_SYSTEM_RESET2_FIRMWARE_CRASH: u64 = 0x8000_0001;

/// MSVM AArch64 fatal error handler.
pub struct MsvmFailFast;

impl FailFast for MsvmFailFast {
    fn fail_fast(error_code: usize, param1: usize, param2: usize, message_buffer: usize, message_length: usize) -> ! {
        report_crash(error_code, param1, param2, message_buffer, message_length);
        notify_host_to_process_efi_diagnostics();
        reset_after_crash(error_code)
    }
}

fn report_crash(error_code: usize, param1: usize, param2: usize, message_buffer: usize, message_length: usize) {
    let Ok((guest_os_id, _)) = get_vp_register(HV_REGISTER_GUEST_OS_ID) else {
        return;
    };
    let microsoft_undefined_guest_os_id = HV_GUEST_OS_VENDOR_MICROSOFT | HV_GUEST_OS_MICROSOFT_UNDEFINED;
    if guest_os_id == 0 && set_vp_register(HV_REGISTER_GUEST_OS_ID, microsoft_undefined_guest_os_id).is_err() {
        return;
    }

    let Ok((_, features)) = get_vp_register(HV_REGISTER_PRIVILEGES_AND_FEATURES_INFO) else {
        return;
    };
    if (features & HV_GUEST_CRASH_REGS_AVAILABLE) == 0 {
        return;
    }

    let crash_registers = [
        (HV_REGISTER_GUEST_CRASH_P0, error_code as u64),
        (HV_REGISTER_GUEST_CRASH_P1, param1 as u64),
        (HV_REGISTER_GUEST_CRASH_P2, param2 as u64),
        (HV_REGISTER_GUEST_CRASH_P3, message_buffer as u64),
        (HV_REGISTER_GUEST_CRASH_P4, message_length as u64),
    ];
    for (register, value) in crash_registers {
        if set_vp_register(register, value).is_err() {
            return;
        }
    }

    let crash_control =
        HV_CRASH_CTL_NOTIFY | HV_CRASH_CTL_MESSAGE | HV_CRASH_CTL_NO_CRASH_DUMP | HV_CRASH_CTL_PRE_OS_ID;
    let _ = set_vp_register(HV_REGISTER_GUEST_CRASH_CTL, crash_control);
}

const BIOS_BASE_ADDRESS: usize = 0xEFFE_D000;
const BIOS_CONFIG_PROCESS_EFI_DIAGNOSTICS: u32 = 0x2C;

fn notify_host_to_process_efi_diagnostics() {
    // SAFETY: These are the defined BIOS device addresses
    unsafe {
        core::ptr::write_volatile(BIOS_BASE_ADDRESS as *mut u32, BIOS_CONFIG_PROCESS_EFI_DIAGNOSTICS);
        core::ptr::write_volatile((BIOS_BASE_ADDRESS + 4) as *mut u32, 1);
    }
}
fn get_vp_register(register: u32) -> Result<(u64, u64), ()> {
    // set to the hypercall input; it will be updated with the status after the HVC call.
    let mut status = 0x0000_0001_0001_0050_u64;
    let low: u64;
    let high: u64;

    // SAFETY: This is the Hyper-V fast GetVpRegisters ABI for the current VP.
    unsafe {
        core::arch::asm!(
            "hvc #1",
            inout("x0") status,
            in("x1") u64::MAX,            // partition ID (self)
            in("x2") 0xFFFF_FFFE_u64,     // vp index (self), padding
            in("x3") u64::from(register),
            in("x4") 0_u64,               // OUT padding to 16 byte alignment
            in("x5") 0_u64,               // OUT InputList[0].RegisterValue.Low
            in("x6") 0_u64,               // OUT InputList[0].RegisterValue.High
            lateout("x15") low,
            lateout("x16") high,
            options(nostack),
        );
    }

    ((status & 0xFFFF) == HV_STATUS_SUCCESS).then_some((low, high)).ok_or(())
}

fn set_vp_register(register: u32, value: u64) -> Result<(), ()> {
    // set to the hypercall input; it will be updated with the status after the HVC call.
    let mut status = 0x0000_0001_0001_0051_u64;

    // SAFETY: This is the Hyper-V fast SetVpRegisters ABI for the current VP.
    unsafe {
        core::arch::asm!(
            "hvc #1",
            inout("x0") status,
            in("x1") u64::MAX,            // partition ID (self)
            in("x2") 0xFFFF_FFFE_u64,     // vp index (self), padding
            in("x3") u64::from(register),
            in("x4") 0_u64,               // IN padding to 16 byte alignment
            in("x5") value,
            in("x6") 0_u64,               // IN InputList[0].RegisterValue.High
            options(nostack),
        );
    }

    ((status & 0xFFFF) == HV_STATUS_SUCCESS).then_some(()).ok_or(())
}

fn reset_after_crash(error_code: usize) -> ! {
    // SAFETY: The firmware cannot continue after a panic. This tries PSCI RESET2 first and then falls
    // back to RESET v1 if needed.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") PSCI_SYSTEM_RESET2_AARCH64 => _,
            in("x1") HV_SYSTEM_RESET2_FIRMWARE_CRASH,
            in("x2") error_code,
            options(nostack),
        );
        core::arch::asm!(
            "smc #0",
            "brk #0",
            in("x0") PSCI_SYSTEM_RESET,
            options(noreturn, nostack),
        );
    }
}
