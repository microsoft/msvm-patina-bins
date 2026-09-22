//! MSVM Resources
//!
//! This module provides resources such as components and services used in the MSVM platform.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![no_std]
#![cfg_attr(coverage, feature(coverage_attribute))]

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod config;
#[cfg(target_arch = "x86_64")]
pub mod x64;

/// Reports a fatal firmware error and terminates execution.
pub trait FailFast {
    /// Reports crash parameters to the host, then resets or crashes the VM.
    fn fail_fast(error_code: usize, param1: usize, param2: usize, message_buffer: usize, message_length: usize) -> !;
}
