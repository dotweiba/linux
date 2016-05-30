#ifndef _LINUX_KVMDEF_H
#define _LINUX_KVMDEF_H
#include <asm/pgtable.h>
//#define CONFIG_KVMDEF

//#define TS_EVAL
#ifdef 	KVMDEF_DEBUG
#define kdd(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#else
#define kdd(format, ...) do {} while (0)
#endif

enum pgsel{
	KERPG,
	KVMPG
};

#define __kvmdata 		__attribute__((section(".kvm.data")))
#define __kvmtext 		__attribute__((section(".kvm.text")))
#define __kvmdefdata 		__attribute__((section(".kvmdef.data")))
#define __kvmdeftext 		__attribute__((section(".kvmdef.text")))

/*
 * kvmdef tag
 */
#define KVMDEF_TAG 			(_AT(pteval_t, 3) << 62)
#define KVMDEF_TAG_MASK 	(_AT(pteval_t, 3) << 62)

#define VALID_TAG 			(_AT(pteval_t, 1) << 0)
#define VALID_TAG_MASK 		(_AT(pteval_t, 1) << 0)

#define PGDCHK(name, x)		PGD##name(x)
#define PUDCHK(name, x)		PUD##name(x)
#define PMDCHK(name, x)		PMD##name(x)
#define PTECHK(name, x)		PTE##name(x)

#define PGD_UND_KVMDEF(pgd)		((pgd_val(pgd) & KVMDEF_TAG_MASK )== KVMDEF_TAG)
#define PUD_UND_KVMDEF(pud)		((pud_val(pud) & KVMDEF_TAG_MASK )== KVMDEF_TAG)
#define PMD_UND_KVMDEF(pmd)		((pmd_val(pmd) & KVMDEF_TAG_MASK )== KVMDEF_TAG)
#define PTE_UND_KVMDEF(pte)		((pte_val(pte) & KVMDEF_TAG_MASK )== KVMDEF_TAG)

#define PTE_IS_VALID(x)			((pte_val(x) & VALID_TAG_MASK )== VALID_TAG)
#define PMD_IS_VALID(x)		((pmd_val(x) & VALID_TAG_MASK )== VALID_TAG)
#define PUD_IS_VALID(x)			((pud_val(x) & VALID_TAG_MASK )== VALID_TAG)
#define PGD_IS_VALID(x)			((pgd_val(x) & VALID_TAG_MASK )== VALID_TAG)

#define KVMDEF_NONE 		KVMDEF_TAG | (PAGE_KERNEL_EXEC &~PTE_VALID) // invalid pte TLB swap out problem
#define KVMDEF_UNMAP		(_AT(pteval_t, 0))
#define KVM_PG_DEFAULT	__pgprot(_PAGE_DEFAULT)
#define KVM_PG_ROX		PAGE_KERNEL_ROX
#define KVM_PG_RO		PAGE_KERNEL_RO
#define KVM_PG_RW		PAGE_KERNEL
#define KVMDEF_RO		KVMDEF_TAG | KVM_PG_RO


/*
 * SECT & TABLE
 */
#define TYPE_MASK 		(_AT(pgdval_t, 1) << 1)
#define TYPE_SECT 		(_AT(pgdval_t, 0) << 1)
#define TYPE_TABLE 		(_AT(pgdval_t, 1) << 1)

#define PGD_SECT(pgd) 	((pgd_val(pgd) & TYPE_MASK) == TYPE_SECT)
#define PGD_TABLE(pgd)	((pgd_val(pgd) & TYPE_MASK) == TYPE_TABLE)

#define PUD_SECT(pgd) 	((pud_val(pgd) & TYPE_MASK) == TYPE_SECT)
#define PUD_TABLE(pgd) 	((pud_val(pgd) & TYPE_MASK) == TYPE_TABLE)

#define PMD_SECT(pgd) 	((pmd_val(pgd) & TYPE_MASK) == TYPE_SECT)
#define PMD_TABLE(pgd) 	((pmd_val(pgd) & TYPE_MASK) == TYPE_TABLE)

/*
 * link scripts symbols
 */
extern char __kvmdef_sdata[], __kvmdef_edata[];
extern char __kvmdef_stext[], __kvmdef_etext[];
extern char __kvm_sdata[], __kvm_edata[];
extern char __kvm_stext[], __kvm_etext[];

#define check_pg(addr,PGSEL,chk) check_pg##chk(PGSEL,(unsigned long)addr)
int check_pg_UND_KVMDEF(enum pgsel,unsigned long);
int check_pg_IS_VALID(enum pgsel, unsigned long);
int mark_kvmdef_attr(void);
void kvmdef_map_threadinfo(void);
int kvmdef_create_init_mapping(void);
void kvmdef_switch_ttbr1(int);
void kvmdef_unmap_range(void* start, void* end);
void kvmdef_map_range(void* start, void* end);
void kvmdef_chk_map_page(void* addr);

u64 kvmdef_call_hyp(void *hypfn, ...);
extern int  hyp_check_iabt(unsigned long, unsigned long);
extern int  hyp_check_dabt(unsigned long, unsigned long);
//asmlinkage void do_kvmmem_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs);
#endif
