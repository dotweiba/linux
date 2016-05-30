#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/debug-monitors.h>
#include <asm/esr.h>
#include <asm/fpsimdmacros.h>
#include <asm/kvm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/memory.h>
#include <asm/kvmdef_asm.h>

	.text
	.pushsection	.hypkvmdef.text,	"ax"
	.align PAGE_SHIFT

.extern kvm_init_mm_pa
.extern init_mmm_pa
.extern vectors
.extern true_el1_sync_hyp_ret
.extern hyp_check_iabt
.extern hyp_check_dabt

//fake the action "pop lr, xzr" and restore sp_el2
	.macro restore_sp_el2
	add sp, sp, #0x10
	.endm

//flush all right now
//needs better tlb flush methods using ASID
	.macro kvm_tlb_flush
	dsb 	ishst
	tlbi	vmalle1
	dsb		nsh
	isb
	.endm

//switch linear space between kvm an kern
//use reg as tmp reg
	.macro switch_ttbr1	reg, inout

	.if \inout == 1
	ldr \reg, =kvm_init_mm_pa
	.else
	ldr \reg, =init_mm_pa
	.endif
	kern_hyp_va \reg
	ldr \reg, [\reg]
	msr ttbr1_el1, \reg
	isb
	.endm

//switch vectors between kvm an kern
//use reg as tmp reg
	.macro	switch_vec, reg, inout
	.if \inout == 1
	ldr \reg, =kvmvectors
	.else
	ldr \reg, =vectors
	.endif

	msr vbar_el1, \reg
	.endm

//ret to kvmentry.S
	.macro true_el1_sync_ret r_sp
	kern_hyp_va \r_sp
//	ldr	lr, [\r_sp, #S_LR]		//recover lr
	switch_ttbr1 	\r_sp, 0	//use r_sp as tmp reg
	switch_vec 		\r_sp, 0	//use r_sp as tmp reg
	kvm_tlb_flush
	ldr \r_sp, =true_el1_sync_hyp_ret
	msr elr_el2, \r_sp
	eret
	.endm

//x0 holds pt_regs *regs
	.macro restore_jumpout
	add	x1, x0, #S_FRAME_SIZE
	msr sp_el1, x1		// restore sp

	kern_hyp_va x0

	ldp	x21, x22, [x0, #S_PC]		// load ELR, SPSR
	msr	elr_el2, x21			// set up the return data
	msr	spsr_el2, x22			//	modify spsr_el2 to return back to el1

	ldp	x2, x3, [x0, #16 * 1]
	ldp	x4, x5, [x0, #16 * 2]
	ldp	x6, x7, [x0, #16 * 3]
	ldp	x8, x9, [x0, #16 * 4]
	ldp	x10, x11, [x0, #16 * 5]
	ldp	x12, x13, [x0, #16 * 6]
	ldp	x14, x15, [x0, #16 * 7]
	ldp	x16, x17, [x0, #16 * 8]
	ldp	x18, x19, [x0, #16 * 9]
	ldp	x20, x21, [x0, #16 * 10]
	ldp	x22, x23, [x0, #16 * 11]
	ldp	x24, x25, [x0, #16 * 12]
	ldp	x26, x27, [x0, #16 * 13]
	ldp	x28, x29, [x0, #16 * 14]

	ldr	lr, [x0, #S_LR]		//recover lr

	ldp	x0, x1, [x0, #16 * 0]	//recover x0 x1
	eret
	.endm

//cause el1_sync exception that coded in kvm/hyp.S
//and never back
ENTRY(kvmdef_call_hyp)
	hvc	#0
ENDPROC(kvmdef_call_hyp)

// esr_el1	far_el1		lr		sp
// x0  		x1 			x2		x3
ENTRY(check_kvmout)
	mrs x21, esr_el1		//esr
	lsr	x24, x21, #ESR_ELx_EC_SHIFT	// exception class
	cmp	x24, #ESR_ELx_EC_DABT_CUR	// data abort in EL1
	b.eq	kvm_da
	cmp	x24, #ESR_ELx_EC_IABT_CUR	// data abort in EL1
	b.eq	kvm_ia
	cmp	x24, #ESR_ELx_EC_SYS64		// configurable trap
	b.eq	kvm_undef
	cmp	x24, #ESR_ELx_EC_SP_ALIGN	// stack alignment exception
	b.eq	kvm_sp_pc
	cmp	x24, #ESR_ELx_EC_PC_ALIGN	// pc alignment exception
	b.eq	kvm_sp_pc
	cmp	x24, #ESR_ELx_EC_UNKNOWN	// unknown exception in EL1
	b.eq	kvm_undef
	cmp	x24, #ESR_ELx_EC_BREAKPT_CUR	// debug exception in EL1
	b.ge	kvm_dbg
	b		kvm_inv

//switch
handle_dabt:
//append tag that indicates this abort is from kvm and need to be mapped to kvm
	mrs x23, esr_el1
	orr x23, x23, #0x000C000
	msr esr_el1, x23
	disable_irq
	true_el1_sync_ret x24
handle_ret_abort:
	disable_irq
	mov x0, x24		//x24 holds sp
	switch_ttbr1	x24, 0	//use x24
	switch_vec 		x24, 0	//use x24

	kvm_tlb_flush
	//x0 sill holds pt_regs *regs
	restore_jumpout	// return to kernel
ENDPROC(handle_ret_abort)

handle_bl_abort:
	disable_irq
	mov x0, x24		//x0 holds sp
	switch_ttbr1	x24, 0	//use x24
	switch_vec 		x24, 0	//use x24

	kvm_tlb_flush
	//x0 sill holds pt_regs *regs
	restore_jumpout	// return to kernel
ENDPROC(handle_bl_abort)

kvm_da:
//	mov x21, x0		//esr
//	mov x22, x1		//far
//	mov x23, x2		//lr
//	mov x24, x3		//sp
	mrs x22, far_el1	//far
	mov x23, x0			//lr param1
	mrs x24, sp_el1		//sp
	enable_dbg
//	// re-enable interrupts if they were enabled in the aborted context
//	tbnz	x23, #7, 1f			// PSR_I_BIT
//	enable_irq
//1:
	mov x0, x23		//lr x23
	mov x1 ,x22		//far x1
	restore_sp_el2
	bl 		hyp_check_dabt
	cmp x0,	#DABT_HANDLE
	b.eq	handle_dabt
	b 		dabt_err

kvm_ia:
	mrs x21,elr_el1 //elr to be compared with far
	mrs x22, far_el1	//far
	mov x23, x0			//lr param1
	mrs x24, sp_el1		//sp
	enable_dbg
//	// re-enable interrupts if they were enabled in the aborted context
//	tbnz	x23, #7, 1f			// PSR_I_BIT
//	enable_irq
//1:
	cmp x21, x22
	b.ne iabt_err	//someone must have modified ELR_EL1, cause FAR and ELR are the same in iabt
	mov x0, x23		//lr x0
	mov x1 ,x22		//far x1
	restore_sp_el2
	bl 		hyp_check_iabt

	cmp	x0, #IABT_ERR
	b.gt	iabt_err

	cmp x0, #RET_IABT_HANDLE

	mrs x22, hcr_el2
	and  x22, x22, #0xfffffffffbffffff
	 //use x22  to clear HCR_EL2.TVM
	msr hcr_el2, x22
	b.eq	handle_ret_abort

	cmp x0, #BL_IABT_HANDLE

	b.eq	handle_bl_abort

	b		iabt_err

no_such_abort:

kvm_undef:

kvm_sp_pc:

kvm_dbg:

kvm_inv:

dabt_err:

iabt_err:
	disable_irq
	true_el1_sync_ret x24	//use x24
ENDPROC(check_kvmout)

//handle do_memabort caused by kvmdef
//x0 holds sp
ENTRY(__kvm_mabort)
	switch_ttbr1 x24, 1//use x24
	switch_vec 	x24, 1 //use x24

	kvm_tlb_flush
	restore_sp_el2
	//x0 sill holds pt_regs *regs
//back to the inst causing abort
	restore_jumpout	// return to kernel

ENDPROC(__kvm_mabort)


//handle bad_mode caused by kvmdef
//x0 holds sp
ENTRY(__kern_inv)
	switch_ttbr1 x24, 1//use x24
	switch_vec 	x24, 1 //use x24

	mrs x24, hcr_el2
	orr x24, x24, 0x4000000 // use x24 to set HCR_EL2.TVM bit
	msr hcr_el2, x24
	kvm_tlb_flush
	restore_sp_el2
	//x0 sill holds pt_regs *regs
	restore_jumpout	// return to kernel

ENDPROC(__kern_inv)
	.popsection
