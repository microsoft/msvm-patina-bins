//! MSVM X64 Specific Functionality
//!
//! This module provides x64 platform resources and virtualization exception registration.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//! SPDX-License-Identifier: Apache-2.0

mod tdx;

#[cfg(target_os = "uefi")]
use patina_dxe_core::{ExceptionContext, ExceptionType, InterruptHandler};

pub use tdx::{MSVM_LAST_VE_EXIT_QUALIFICATION, MSVM_LAST_VE_EXIT_REASON, MSVM_LAST_VE_RCX, MSVM_LAST_VE_RIP};

/// Base I/O port for the MSVM COM1 UART.
pub const COM1_REGISTER_BASE: u16 = 0x3F8;
/// Base I/O port for the MSVM COM2 UART.
pub const COM2_REGISTER_BASE: u16 = 0x2F8;

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
