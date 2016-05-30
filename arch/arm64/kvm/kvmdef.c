#include <linux/kvmdef.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <asm/memory.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/kvmdef_asm.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>

#include <linux/delay.h>

extern int create_hyp_mappings(void *from, void *to);

extern void create_mapping_late_public(phys_addr_t phys, unsigned long virt,
				  phys_addr_t size, pgprot_t prot);

struct __kvmdef_region{
	void* start;
	void* end;
	pteval_t prot;
};
typedef struct __kvmdef_region region_attr;

unsigned long __kvmdefdata kvm_init_mm_pa;
unsigned long __kvmdefdata init_mm_pa;
static DEFINE_MUTEX(kvmdef_pgd_mutex);
struct mm_struct kvm_init_mm = {
	.mm_rb		= RB_ROOT,
//	.pgd		= swapper_pg_dir,
	.mm_users	= ATOMIC_INIT(2),
	.mm_count	= ATOMIC_INIT(1),
	.mmap_sem	= __RWSEM_INITIALIZER(kvm_init_mm.mmap_sem),
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(kvm_init_mm.page_table_lock),
	.mmlist		= LIST_HEAD_INIT(kvm_init_mm.mmlist)
//	INIT_MM_CONTEXT(kvm_init_mm)
};
int KVMDEF_ON=0;
//kvmdef mapped region info
#define KVM_R_N	3	//kvmdef mapping area number
static  region_attr  __kvmdefdata kvm_region[KVM_R_N]={
		{__kvm_stext,__kvm_etext,  KVM_PG_ROX},
		{__kvm_sdata,__kvm_edata,  KVM_PG_RW},
		{__kvmvec_stext,__kvmvec_etext,  KVM_PG_ROX},
//		{__hyp_kvmdef_stext,__hyp_kvmdef_etext,  KVMDEF_UNMAP}
};


#ifdef CONFIG_KVMDEF
//set pte with KVM_PG_DEFAULT
static int kvmdef_mapping_pte(pte_t* dst_pmd, unsigned long pfn, unsigned long addr, unsigned long end, pteval_t prot){
	pte_t* dst_pte;

	do {
		dst_pte=pte_offset_kernel(dst_pmd, addr);
		set_pte(dst_pte, pfn_pte(pfn,prot)); //PAGE_DEFAULT
		get_page(virt_to_page(dst_pte));
		__flush_dcache_area(dst_pte, sizeof(*dst_pte));
		pfn++;
#ifdef KVMDEF_DEBUG
//	pr_warn("	--->DST_PTE: 0x%016llx\n",pte_val(*dst_pte));
#endif
	} while (addr += PAGE_SIZE, addr!=end);
	return 0;
}


static int kvmdef_mapping_pmd(pud_t* dst_pud, unsigned long pfn, unsigned long addr,unsigned long end, pteval_t prot){

	unsigned long next;
	pmd_t  *dst_pmd;
	pte_t  *dst_pte;
	int err;
	do{
		dst_pmd=pmd_offset(dst_pud,addr);
		if(pmd_none(*dst_pmd)){
			dst_pte=pte_alloc_one_kernel(&init_mm,addr);
			if(!dst_pte)
				return -ENOMEM;
			pmd_populate_kernel(NULL, dst_pmd, dst_pte);
			get_page(virt_to_page(dst_pmd));
			__flush_dcache_area(dst_pmd, sizeof(*dst_pmd));
		}

#ifdef KVMDEF_DEBUG
	kdd("	--->DST_PMD: 0x%016llx\n",pmd_val(*dst_pmd));
#endif
	next = pmd_addr_end(addr, end);
	err=kvmdef_mapping_pte(dst_pmd, pfn, addr, next,prot);
	if(err){
		return err;
	}
	pfn += (next - addr) >> PAGE_SHIFT;

	} while (addr=next,addr != end);
	return 0;
}

static int kvmdef_mapping_pud(pgd_t* dst_pgd, unsigned long pfn, unsigned long addr,unsigned long end, pteval_t prot){

	unsigned long next;
	pud_t  *dst_pud;
	pmd_t  *dst_pmd;
	int err;

	do{
		dst_pud=pud_offset(dst_pgd,addr);
		if(pud_none(*dst_pud)){
			dst_pmd=pmd_alloc_one(&init_mm,addr);
			if(!dst_pmd){
				return  -ENOMEM;

			}
		pud_populate(NULL,dst_pud,dst_pmd);
		get_page(virt_to_page(dst_pud));
		__flush_dcache_area(dst_pud, sizeof(*dst_pud));
		}
#if defined KVMDEF_DEBUG
#if CONFIG_PGTABLE_LEVELS > 2
	kdd("--->DST_PUD: 0x%016llx\n",pud_val(*dst_pud));
#endif
#endif
		next= pud_addr_end(addr,end);
		err=kvmdef_mapping_pmd(dst_pud,pfn,addr,next,prot);
		if(err){
			return err;
		}
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr=next,addr != end);

	return 0;
}

static phys_addr_t kvmdef_kaddr_to_phys(void *kaddr)
{
	if (!is_vmalloc_addr(kaddr)) {
		BUG_ON(!virt_addr_valid(kaddr));
		return __pa(kaddr);
	} else {
		return page_to_phys(vmalloc_to_page(kaddr)) +
		       offset_in_page(kaddr);
	}
}

static int kvmdef_mapping_pgd(unsigned long addr,unsigned long end, pteval_t prot){
	unsigned long next;
	unsigned long pfn;
	phys_addr_t pa;
	pgd_t *dst_pgd;
	pud_t *dst_pud;
	int err;

	if(addr==end) //in case that region is empty
		return 0;
	//align start and end
	addr = addr & PAGE_MASK;
	end = PAGE_ALIGN(end);
//	kdd("kvmdef: mapping aligned address from 0x%016lx to 0x%016lx\n",addr,end);
	mutex_lock(&kvmdef_pgd_mutex);
	do{
		dst_pgd = kvm_pgd_offset_k(addr);
		if(pgd_none(*dst_pgd)){
			dst_pud=pud_alloc_one(&init_mm,addr);
			if(!dst_pud){
				err=-ENOMEM;
				goto out;
			}
			pgd_populate(NULL,dst_pgd,dst_pud);
			get_page(virt_to_page(dst_pgd));
			__flush_dcache_area(dst_pgd, sizeof(*dst_pgd));
		}
#ifdef KVMDEF_DEBUG
#if CONFIG_PGTABLE_LEVELS > 3
	kdd("DST_PGD: 0x%016llx\n",pgd_val(*dst_pgd));
#endif
#endif
		pa=kvmdef_kaddr_to_phys((void*)addr);
		next= pgd_addr_end(addr,end);
		err=kvmdef_mapping_pud(dst_pgd,__phys_to_pfn(pa),addr,next,prot);
		if(err){
			goto out;
		}
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr=next,addr != end);
out:
	mutex_unlock(&kvmdef_pgd_mutex);
	return 0;
}

void kvmdef_unmap_range(void* start, void* end){

//	kvmdef_unmapping_pgd((unsigned long)start,(unsigned long)end,_PAGE_DEFAULT);
}


void kvmdef_map_range(void* start, void* end){

	kvmdef_mapping_pgd((unsigned long)start,(unsigned long)end, KVM_PG_DEFAULT);

}

static void kvmdef_map_page(void* addr){
	kvmdef_mapping_pgd((unsigned long)addr & PAGE_MASK,((unsigned long)addr & PAGE_MASK) + PAGE_SIZE, KVM_PG_DEFAULT);
}

/*
*traverse the specific mem region and duplicate a map for each
*/
static int kvmdef_traverse_region(region_attr *region){

	int r;
	int i=0;
	for(i=0;i<KVM_R_N;i++){
		//use attributes defined in region_attr *region
		r=kvmdef_mapping_pgd((unsigned long)(region->start),(unsigned long)(region->end), region->prot);
		kdd("kvmdef: mapping %dth region 0x%016lx - 0x%016lx\n",
				i,(unsigned long)(region->start),(unsigned long)(region->end));
		if(r)
		{
			pr_err("kvmdef: failed to map region %d\n",i);
			break;
		}
		region++;
	}

	return -r;
}

int kvmdef_create_init_mapping(void){

	int r;
	unsigned long va;

	//get two pages for kvm paging dir
	va=__get_free_pages(PGALLOC_GFP,1);

	//use va to map all the memory because this happens with MMU enabled
	(&kvm_init_mm)->pgd=(pgd_t *)va;

	kvm_init_mm_pa=	__pa(va);
	init_mm_pa=		__pa((&init_mm)->pgd);

	r=kvmdef_traverse_region(kvm_region);
	if(r)
	{
		return 1;
	}
	return 0;
}


static inline int kvmdef_check_curmap(void){
	if(current->kvmdef_map_already==1)
		return 1;
	else
		return 0;
}

static inline void kvmdef_kvm_mapping_threadinfo(union thread_union* cur_threadinfo){
	kvmdef_mapping_pgd((unsigned long)cur_threadinfo,(unsigned long)(cur_threadinfo+1), KVM_PG_DEFAULT);
}

static inline void kvmdef_hyp_mapping_threadinfo(union thread_union* cur_threadinfo){
	create_hyp_mappings(cur_threadinfo,cur_threadinfo+1);
}

inline void kvmdef_map_threadinfo(void){
	union thread_union* cur_threadinfo;
//	if(kvmdef_check_curmap())
//		return;

	cur_threadinfo=(union thread_union*)current_thread_info();
	if(check_pg(cur_threadinfo, KVMPG, _IS_VALID))
		return;
	kvmdef_kvm_mapping_threadinfo(cur_threadinfo);
	kvmdef_hyp_mapping_threadinfo(cur_threadinfo);
	current->kvmdef_map_already = 1;
	kdd("kvmdef: map current_thread_info 0x%016lx\n",(unsigned long)cur_threadinfo);
}

//switch ttbr1_el1 firstly so any __kvmdeftext functions could work normally without causing aborts
//static int  kvmdef_mapping_already=0;
//void inline kvmdef_switch_ttbr1(int tokvmdef){
//	if(tokvmdef==1){
////		 asm volatile("msr ttbr1_el1, %0\n""isb":: "r"(__pa((&kvm_init_mm)->pgd)));
//		kvmdef_call_hyp(switch_ttbr1_el1,(__pa((&kvm_init_mm)->pgd)));
//		kdd("kvmdef: changing ttbr1_el1 to kvmdef_pg_dir\n");
//		kvmdef_flush_tlb_all();
//	}
//	else{
////		asm volatile("msr ttbr1_el1, %0\n""isb":: "r"(__pa((&init_mm)->pgd)));
//		kvmdef_call_hyp(switch_ttbr1_el1,(__pa((&init_mm)->pgd)));
//		kdd("kvmdef: changing ttbr1_el1 to init_mm pgd\n");
//		kvmdef_flush_tlb_all();
//	}
//	if(kvmdef_mapping_already==0){
//		kvmdef_hyp_mapping_threadinfo();
//		kvmdef_mapping_already=1;
//		kvmdef_flush_tlb_all();
//	}
//}

//mapped to hyp
asmlinkage int __kvmdeftext hyp_check_dabt(unsigned long lr, unsigned long far){
	int flr=0;
	int ffar=0;
	//check something

	return DABT_HANDLE;

}

//mapped to hyp
asmlinkage int __kvmdeftext hyp_check_kvmdef_region(unsigned long addr){
	int i=0;
	for(i=0; i<KVM_R_N; i++){
	//ranges from start to end
		if( ((unsigned long)(kvm_region[i].start)<addr)
				&& ((unsigned long)(kvm_region[i].end)>addr)){
				   return 1;
		}
   }
   return 0;

}

//mapped to hyp
asmlinkage int __kvmdeftext hyp_check_iabt(unsigned long lr, unsigned long far){
	int flr=0;
	int ffar=0;
	flr= hyp_check_kvmdef_region(lr);
	if(lr==far){
		if(flr==0){
			return RET_IABT_HANDLE;
		}
		else{
			return RET_IABT_ERR;
		}
	}
	ffar=hyp_check_kvmdef_region(far);
	if(( flr==1 )&&(ffar==0)){
		return BL_IABT_HANDLE;
	}
	else{
		return BL_IABT_ERR;
	}
}


//returning 1 indicates it is in one of kvmdef regions or valid
#define pgcheck_declare(addr, chk)	\
		static inline int check_pg_pte##chk(pmd_t* pmd, unsigned long addr){\
			int r=0;\
			pte_t* ptep=pte_offset_kernel(pmd, addr);\
			if(pte_none(*ptep))\
				r=0;\
			else if(PTE##chk(*ptep)){\
				r=1;\
			}\
			return r;\
		}\
\
		static inline int check_pg_pmd##chk(pud_t* pud, unsigned long addr){\
			int r=0;\
			pmd_t* pmdp=pmd_offset(pud,addr);\
			if(pmd_none(*pmdp)){\
				r= 0;\
			}\
			else if(PMD_TABLE(*pmdp)){\
					r=check_pg_pte##chk(pmdp,addr);\
				}\
			else if(PMD_SECT(*pmdp)&&PMDCHK(chk,*pmdp)){\
				r= 1;\
			}\
			return r;\
		}\
\
		static inline int check_pg_pud##chk(pgd_t* pgd,unsigned long addr){\
			int r=0;\
			pud_t* pudp=pud_offset(pgd, addr);\
\
			if(pud_none(*pudp)){\
				r= 0;\
			}\
			else if(PUD_TABLE(*pudp)){\
					r=check_pg_pmd##chk(pudp, addr);\
				}\
			else if(PUD_SECT(*pudp)&&PUDCHK(chk,*pudp)){\
				r=1;\
			}\
\
			return r;\
		}\
		inline int check_pg##chk(enum pgsel sel,unsigned long addr){\
			int r=0; pgd_t* pgdp;\
			if(sel==KERPG){\
				pgdp=pgd_offset_k(addr);}\
			else{\
				pgdp=kvm_pgd_offset_k(addr);}\
				\
			if(pgd_none(*pgdp)){\
				r= 0;\
			}\
			else if(PGD_TABLE(*pgdp)){\
				r=check_pg_pud##chk(pgdp, addr);\
			}\
			else if(PGD_SECT(*pgdp)&&PGDCHK(chk,*pgdp)){\
				r= 1;\
			}\
			return r;\
		}

pgcheck_declare(addr, _UND_KVMDEF)
pgcheck_declare(addr, _IS_VALID)

//all __kvm regions will be marked invalid
//will not check padding area(contains no function)address
int mark_kvmdef_attr(){
	pgprot_t  rattr;
	unsigned long rs,re;
	int i=0;
	for(i=0; i<KVM_R_N; i++){
		rs=(unsigned long)kvm_region[i].start;
		re=(unsigned long)kvm_region[i].end;
//		rattr=kvm_region[i].prot;
		rattr=KVMDEF_NONE;
		if(rs-re==0) //in case that region is empty
			return 0;
		create_mapping_late_public(__pa(rs),rs, re - rs,rattr);
		kdd("kvmdef: mark %dth region 0x%016lx - 0x%016lx with prot 0x%llx\n",i,rs,re,rattr);

	}
	return 0;
}

void kvmdef_chk_map_page(void* addr){
	if(!check_pg(addr, KVMPG, _IS_VALID)){
		kvmdef_map_page(addr);
	}
	return;
}
#else
int mark_kvmdef_attr(){return 0;}
void kvmdef_map_range(void* start, void* end){return;}
int  hyp_check_iabt(unsigned long x, unsigned long y){return 0;}
int  hyp_check_dabt(unsigned long x, unsigned long y){return 0;}

#endif
