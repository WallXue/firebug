.global _shellcode_start_s
.global _shellcode_end_s
.global _hookstub_function_addr_s
.global _old_function_addr_s

.data

_shellcode_start_s:
    push    {r0, r1, r2, r3}                ;取push完r0-r4的sp，后面在这个基础上进行更改，所以我们需要保存的r13的值就是sp+0x10
    mrs     r0, cpsr                        ;将CPSR寄存器内容读出到R0
    str     r0, [sp, #0xC]                  ;将cpsr保存到sp+#0xC的位置
    str     r14, [sp, #8]                   ;将r14(lr)保存到sp+8
    add     r14, sp, #0x10                  ;sp+0x10的值存放进r14
    str     r14, [sp, #4]                   ;保存寄存器r13的值到sp+4的位置
    pop     {r0}                            ;sp+4
    push    {r0-r12}                        ;保存寄存器的值。sp+4-0x34=sp-0x30，将r0-r12压栈
    mov     r0, sp                          ;将栈顶位置放入r0，作为参数传入_hookstub_function_addr_s函数内
    ldr     r3, _hookstub_function_addr_s
    blx     r3                              ;调用用户自定义函数callback
    ldr     r0, [sp, #0x3C]                 ;sp-0x30+0x3c=sp+0xc,刚好是之前保存cpsr的栈地址
    msr     cpsr, r0                        ;恢复cpsr
    ldmfd   sp!, {r0-r12}                   ;恢复r0-r12的寄存器的值，sp-0x30+0x34=sp+4
    ldr     r14, [sp, #4]                   ;恢复r14的值。sp+4+4=sp+8刚好是保存了r14寄存器的值
    ldr     sp, [r13]                       ;恢复寄存器r13的值(r13=sp+4)刚好是之前保存的r13的值
    ldr     pc, _old_function_addr_s        ;跳转回即将构造的原指令函数处

_hookstub_function_addr_s:
.word 0xffffffff

_old_function_addr_s:
.word 0xffffffff

_shellcode_end_s:

.end