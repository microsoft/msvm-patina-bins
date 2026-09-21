#
# MSVM TDX instruction shims.
#
# ABI interfaces defined in the Intel TDX Module Architecture ABI Reference Spec May 2026
# https://www.intel.com/content/www/us/en/content-details/865802/intel-tdx-module-abi-specification.html. This
# document is referred to as "Spec" throughout
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0
#

.section .text
.global SecGetTdxVeInfo
.global SecGetTdInfo
.global TdVmCall

# Spec 5.5.25
SecGetTdxVeInfo:
    mov     r11, rcx
    mov     eax, 3
    .byte   0x66, 0x0f, 0x01, 0xcc
    mov     qword ptr [r11], rcx
    mov     qword ptr [r11 + 8], rdx
    mov     qword ptr [r11 + 16], r8
    mov     qword ptr [r11 + 24], r9
    mov     qword ptr [r11 + 32], r10
    ret

# Spec 5.5.21
SecGetTdInfo:
    push    r12
    mov     r12, rcx
    mov     eax, 1
    .byte   0x66, 0x0f, 0x01, 0xcc
    and     ecx, 0x3f
    mov     dword ptr [r12], ecx
    pop     r12
    ret

# Spec 5.5.1
# u64 TdVmCall(u64 call, u64 p1, u64 p2, u64 p3, u64 p4, u64 *value)
TdVmCall:
    push    rbp
    mov     rbp, rsp
    push    r15
    push    r14
    push    r13
    push    r12
    push    rbx
    push    rsi
    push    rdi

    mov     r11, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     r14, r9
    mov     r15, qword ptr [rsp + 104]
    xor     eax, eax
    mov     ecx, 0xffcc
    xor     r10d, r10d
    xor     ebx, ebx
    xor     esi, esi
    xor     edi, edi
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    .byte   0x66, 0x0f, 0x01, 0xcc

    test    rax, rax
    jnz     .Lvmcall_done
    mov     rax, r10
    mov     r9, qword ptr [rsp + 112]
    test    r9, r9
    jz      .Lvmcall_done
    mov     qword ptr [r9], r11

.Lvmcall_done:
    xor     ebx, ebx
    xor     esi, esi
    xor     edi, edi
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    xor     r10d, r10d
    xor     r11d, r11d
    pop     rdi
    pop     rsi
    pop     rbx
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    pop     rbp
    ret
