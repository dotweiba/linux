#ifndef __ASM_KVMDEF_ASM_H__
#define __ASM_KVMDEF_ASM_H__
#include <asm/page.h>

//IABT
#define	IABT_ERR		0x10
#define RET_IABT_ERR	0x11
#define BL_IABT_ERR		0x12

#define RET_IABT_HANDLE		0x1
#define BL_IABT_HANDLE		0x2

//DABT
#define DABT_HANDLE		0x31

#ifndef __ASSEMBLY__	//unknown mnemonic bugs

extern char __hyp_kvmdef_stext[];
extern char __hyp_kvmdef_etext[];
extern char __kvmvec_stext[];
extern char __kvmvec_etext[];

extern void 	__kern_inv(void*);
extern void 	__kvm_mabort(void*);

#endif
#endif
