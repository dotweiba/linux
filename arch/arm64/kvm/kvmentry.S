/*
 * Handling Low-level Exception from KVM
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/cpufeature.h>
#include <asm/errno.h>
#include <asm/esr.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#include <asm/kvmdef_asm.h>

	.text
	.pushsection .kvmvectors,	"ax"
	.align PAGE_SHIFT

//four params and never back directly
	.macro asm_call_hyp funcname param1
	ldr x0, =\funcname
	mov x1, \param1
	hvc #0
	.endm
/*
 * Context tracking subsystem.  Used to instrument transitions
 * between user and kernel mode.
 */
	.macro ct_user_exit, syscall = 0
#ifdef CONFIG_CONTEXT_TRACKING
	bl	context_tracking_user_exit
	.if \syscall == 1
	/*
	 * Save/restore needed during syscalls.  Restore syscall arguments from
	 * the values already saved on stack during kernel_entry.
	 */
	ldp	x0, x1, [sp]
	ldp	x2, x3, [sp, #S_X2]
	ldp	x4, x5, [sp, #S_X4]
	ldp	x6, x7, [sp, #S_X6]
	.endif
#endif
	.endm

	.macro ct_user_enter
#ifdef CONFIG_CONTEXT_TRACKING
	bl	context_tracking_user_enter
#endif
	.endm

/*
 * Bad Abort numbers
 *-----------------
 */
#define BAD_SYNC	0
#define BAD_IRQ		1
#define BAD_FIQ		2
#define BAD_ERROR	3

	.macro	kernel_entry, el, regsize = 64
	sub	sp, sp, #S_FRAME_SIZE
	.if	\regsize == 32
	mov	w0, w0				// zero upper 32 bits of x0
	.endif
	stp	x0, x1, [sp, #16 * 0]
	stp	x2, x3, [sp, #16 * 1]
	stp	x4, x5, [sp, #16 * 2]
	stp	x6, x7, [sp, #16 * 3]
	stp	x8, x9, [sp, #16 * 4]
	stp	x10, x11, [sp, #16 * 5]
	stp	x12, x13, [sp, #16 * 6]
	stp	x14, x15, [sp, #16 * 7]
	stp	x16, x17, [sp, #16 * 8]
	stp	x18, x19, [sp, #16 * 9]
	stp	x20, x21, [sp, #16 * 10]
	stp	x22, x23, [sp, #16 * 11]
	stp	x24, x25, [sp, #16 * 12]
	stp	x26, x27, [sp, #16 * 13]
	stp	x28, x29, [sp, #16 * 14]

	.if	\el == 0
	mrs	x21, sp_el0
	get_thread_info tsk			// Ensure MDSCR_EL1.SS is clear,
	ldr	x19, [tsk, #TI_FLAGS]		// since we can unmask debug
	disable_step_tsk x19, x20		// exceptions when scheduling.
	.else
	add	x21, sp, #S_FRAME_SIZE
	.endif
	mrs	x22, elr_el1
	mrs	x23, spsr_el1
	stp	lr, x21, [sp, #S_LR]
	stp	x22, x23, [sp, #S_PC]

	/*
	 * Set syscallno to -1 by default (overridden later if real syscall).
	 */
	.if	\el == 0
	mvn	x21, xzr
	str	x21, [sp, #S_SYSCALLNO]
	.endif

	/*
	 * Registers that may be useful after this macro is invoked:
	 *
	 * x21 - aborted SP
	 * x22 - aborted PC
	 * x23 - aborted PSTATE
	*/
	.endm

	.macro	kernel_exit, el
	ldp	x21, x22, [sp, #S_PC]		// load ELR, SPSR
	.if	\el == 0
	ct_user_enter
	ldr	x23, [sp, #S_SP]		// load return stack pointer
	msr	sp_el0, x23
#ifdef CONFIG_ARM64_ERRATUM_845719
alternative_if_not ARM64_WORKAROUND_845719
	nop
	nop
#ifdef CONFIG_PID_IN_CONTEXTIDR
	nop
#endif
alternative_else
	tbz	x22, #4, 1f
#ifdef CONFIG_PID_IN_CONTEXTIDR
	mrs	x29, contextidr_el1
	msr	contextidr_el1, x29
#else
	msr contextidr_el1, xzr
#endif
1:
alternative_endif
#endif
	.endif
	msr	elr_el1, x21			// set up the return data
	msr	spsr_el1, x22
	ldp	x0, x1, [sp, #16 * 0]
	ldp	x2, x3, [sp, #16 * 1]
	ldp	x4, x5, [sp, #16 * 2]
	ldp	x6, x7, [sp, #16 * 3]
	ldp	x8, x9, [sp, #16 * 4]
	ldp	x10, x11, [sp, #16 * 5]
	ldp	x12, x13, [sp, #16 * 6]
	ldp	x14, x15, [sp, #16 * 7]
	ldp	x16, x17, [sp, #16 * 8]
	ldp	x18, x19, [sp, #16 * 9]
	ldp	x20, x21, [sp, #16 * 10]
	ldp	x22, x23, [sp, #16 * 11]
	ldp	x24, x25, [sp, #16 * 12]
	ldp	x26, x27, [sp, #16 * 13]
	ldp	x28, x29, [sp, #16 * 14]
	ldr	lr, [sp, #S_LR]
	add	sp, sp, #S_FRAME_SIZE		// restore sp
	eret					// return to kernel
	.endm

	.macro	get_thread_info, rd
	mov	\rd, sp
	and	\rd, \rd, #~(THREAD_SIZE - 1)	// top of stack
	.endm

/*
 * These are the registers used in the syscall handler, and allow us to
 * have in theory up to 7 arguments to a function - x0 to x6.
 *
 * x7 is reserved for the system call number in 32-bit mode.
 */
sc_nr	.req	x25		// number of system calls
scno	.req	x26		// syscall number
stbl	.req	x27		// syscall table pointer
tsk		.req	x28		// current thread_info

/*
 * Interrupt handling.
 */
	.macro	irq_handler
	adrp	x1, handle_arch_irq
	ldr	x1, [x1, #:lo12:handle_arch_irq]
	mov	x0, sp
	blr	x1
	.endm


/*
 * Exception vectors.
 */

	.align	11
ENTRY(kvmvectors)
	ventry	kvm_el1_sync_invalid		// Synchronous EL1t
	ventry	kvm_el1_irq_invalid			// IRQ EL1t
	ventry	kvm_el1_fiq_invalid			// FIQ EL1t
	ventry	kvm_el1_error_invalid		// Error EL1t

	ventry	kvm_el1_sync			// Synchronous EL1h
	ventry	kvm_el1_irq				// IRQ EL1h
	ventry	kvm_el1_fiq_invalid			// FIQ EL1h
	ventry	kvm_el1_error_invalid		// Error EL1h
END(kvmvectors)

/*
 * Invalid mode handlers
 */
	.macro	inv_entry, el, reason, regsize = 64
	kernel_entry el, \regsize
	mov	x0, sp
	mov	x1, #\reason
	mrs	x2, esr_el1
	b	bad_mode
	.endm


kvm_el1_sync_invalid:
	inv_entry 1, BAD_SYNC
ENDPROC(kvm_el1_sync_invalid)

kvm_el1_irq_invalid:
	inv_entry 1, BAD_IRQ
ENDPROC(kvm_el1_irq_invalid)

kvm_el1_fiq_invalid:
	inv_entry 1, BAD_FIQ
ENDPROC(kvm_el1_fiq_invalid)

kvm_el1_error_invalid:
	inv_entry 1, BAD_ERROR
ENDPROC(kvm_el1_error_invalid)

//hyp out
ENTRY(true_el1_sync_hyp_ret)
	b	true_el1_sync
ENDPROC(true_el1_sync_hyp_ret)

/*
 * EL1 mode handlers.
 */
	.align	6
kvm_el1_sync:
	kernel_entry 1
//	mrs x1, esr_el1
//	mrs x2, far_el1
	asm_call_hyp check_kvmout lr
kvm_el1_da:
	/*
	 * Data abort handling
	 */
	mrs	x0, far_el1
	enable_dbg
	// re-enable interrupts if they were enabled in the aborted context
	tbnz	x23, #7, 1f			// PSR_I_BIT
	enable_irq
1:
	mov	x2, sp				// struct pt_regs
	bl	do_mem_abort

	// disable interrupts before pulling preserved data off the stack
	disable_irq
	kernel_exit 1
kvm_el1_sp_pc:
	/*
	 * Stack or PC alignment exception handling
	 */
	mrs	x0, far_el1
	enable_dbg
	mov	x2, sp
	b	do_sp_pc_abort
kvm_el1_undef:
	/*
	 * Undefined instruction
	 */
	enable_dbg
	mov	x0, sp
	b	do_undefinstr
kvm_el1_dbg:
	/*
	 * Debug exception handling
	 */
	cmp	x24, #ESR_ELx_EC_BRK64		// if BRK64
	cinc	x24, x24, eq			// set bit '0'
	tbz	x24, #0, kvm_el1_inv		// EL1 only
	mrs	x0, far_el1
	mov	x2, sp				// struct pt_regs
	bl	do_debug_exception
	kernel_exit 1
kvm_el1_inv:
	// TODO: add support for undefined instructions in kernel mode
	mrs	x3, far_el1 //kvmdef
	enable_dbg
	mov	x0, sp
	mov	x2, x1
	mov	x1, #BAD_SYNC
	b	bad_mode
ENDPROC(kvm_el1_sync)

	.align	6
kvm_el1_irq:
	kernel_entry 1
	enable_dbg
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_off
#endif

	irq_handler

#ifdef CONFIG_PREEMPT
	get_thread_info tsk
	ldr	w24, [tsk, #TI_PREEMPT]		// get preempt count
	cbnz	w24, 1f				// preempt count != 0
	ldr	x0, [tsk, #TI_FLAGS]		// get flags
	tbz	x0, #TIF_NEED_RESCHED, 1f	// needs rescheduling?
	bl	kvm_el1_preempt
1:
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_on
#endif
	kernel_exit 1
ENDPROC(kvm_el1_irq)

#ifdef CONFIG_PREEMPT
kvm_el1_preempt:
	mov	x24, lr
1:	bl	preempt_schedule_irq		// irq en/disable is done inside
	ldr	x0, [tsk, #TI_FLAGS]		// get new tasks TI_FLAGS
	tbnz	x0, #TIF_NEED_RESCHED, 1b	// needs rescheduling?
	ret	x24
#endif
	.popsection
