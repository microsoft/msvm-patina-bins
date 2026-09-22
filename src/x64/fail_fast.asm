# MSVM X64 fatal error handling.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0

.section .text
.global msvm_triple_fault

# void msvm_triple_fault(error_code, param1, param2, param3)
msvm_triple_fault:
    mov     rax, rcx
    mov     rbx, rdx
    mov     rcx, r8
    mov     rdx, r9
    cli
    push    0
    push    0
    lidt    [rsp]
    ud2
