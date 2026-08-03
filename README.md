# MSVM DXE Core Binaries

## Overview

The main purpose of this repository is to integrate the Patina DXE core for MSVM X64 and AArch64.

## Documentation

The documentation in this repo can be generated with the following commands:

- `cargo make doc` - This will build the documentation for all packages in the workspace.
- `cargo make doc-open` - This will build the documentation for all packages in the workspace and open it in a
  web browser.

## Building

To build an executable, this repo uses the same compiler setup steps that are used in the patina project
[readme.md file build section](https://github.com/OpenDevicePartnership/patina#Build).

- MSVM X64 debug

   ```shell
   Compile Command:  'cargo make msvm-x64'
   Output File:      'target/x86_64-unknown-uefi/debug/msvm_x64_dxe_core.efi'
   ```

- MSVM X64 release

   ```shell
   Compile Command:  'cargo make msvm-x64-release'
   Output File:      'target/x86_64-unknown-uefi/release/msvm_x64_dxe_core.efi'
   ```

- MSVM AArch64 debug

   ```shell
   Compile Command:  'cargo make msvm-aarch64'
   Output File:      'target/aarch64-unknown-uefi/debug/msvm_aarch64_dxe_core.efi'
   ```

- MSVM AArch64 release

   ```shell
   Compile Command:  'cargo make msvm-aarch64-release'
   Output File:      'target/aarch64-unknown-uefi/release/msvm_aarch64_dxe_core.efi'
   ```

The [patina_debugger](https://github.com/OpenDevicePartnership/patina/blob/main/docs/src/dxe_core/debugging.md) is
built by default on debug builds, but not release builds. It can be built on release builds by passing the
`build_debugger` feature to the build, e.g. `cargo make msvm-x64-release --features build_debugger`. The debugger
is disabled by default, passing the `enable_debugger` feature to the build will enable it.

## Cargo Bloat

A size breakdown, whether by function or crate, can be analyzed by using `cargo make bloat-msvm-x64` or
`cargo make bloat-msvm-aarch64`. Optionally, additional arguments can be passed, e.g. to see a crate breakdown:
`cargo make bloat-msvm-aarch64 --crates -n 40`.

## Publishing

This repository publishes the dxe core binaries to GitHub releases to be consumed by
[mu_msvm](https://github.com/microsoft/mu_msvm).
