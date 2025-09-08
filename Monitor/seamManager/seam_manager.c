#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "np_loader.h"
#include "emulator.h"
#include "configs.h"
#include "pseamldr_api.h"
#include "tdx_local_data.h"
#include "analyzer.h"

extern int instrument_seam_sw_code(SEAM_SW sw);
extern void get_tdx_special_ins_info();
extern void init_instrumentation_module();
extern ulong get_offset(OFFSET_TYPE type);

extern void setup_regs(struct kvm_regs *regs);
extern int setup_sregs(struct kvm_sregs *sregs);
extern int emulate_ins(struct insInfo *ins_info);

extern void setup_tdx_module_global_data();
extern int switch_to_pseamldr_context(uint64_t seamcall);
extern ulong get_region_base_pa(REGION region);
extern int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
extern void enable_single_step();
extern void launch_interpreter();

extern SEAMRR_PT_CTX SeamrrPtCtx;
extern uint8_t *ins_names[];
extern const uint8_t seam_agent_bin_start[], seam_agent_bin_end[];
extern int get_khole_edit_ins_adrs(uint32_t *adrs);
extern void get_khole_edit_ins_info();
extern int get_cr_ins_address(ulong *adrs);
extern int get_tdxcall_end_adrs(ulong *seamcall, ulong *vmlaunch, ulong *vmresume);

extern void vmm_agent();
extern void td_agent();

ulong do_tdxcall(ulong seamcall);
void log_active_keyhole_mappings();
void block_persistant_khole_mappings(ulong current_lp);
void set_debug_bp(ulong address, ulong dr_num, ulong trigger_condition, ulong bp_size);
void remove_debug_bp(ulong dr_num);
void enable_khole_map_tracking();
ulong get_tdr_va_of_running_td(ulong pa, ulong lp);
ulong va_to_pa(ulong cr3, ulong va);
void fill_khole_refs(ulong lp);

uint64_t get_saved_register_value(REGS_64 reg);

struct comArea *com;
struct vm *vm;
struct vcpu *vcpu;

struct pt_data agent_pt_data;
ulong txcall_count = 0;

ulong t0 = 0;
ulong t1 = 0;
static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

void do_sanity_checks(){	
	uint32_t ecx;
	uint32_t movdir64b_support;
	uint32_t serialize_support;
	/*to enable CR4.OSXSAVE for VM, which allows the use of the XSAVE, XRSTOR
	our usage is in xgetbv ins emcountered in module*/
	uint32_t xgetbv_support; 
	
	LOG("doing sanity checks\n");
	/*we have allocated a fe MB region for the shared area*/
	assert(sizeof(struct comArea) < SEAM_AGENT_MGR_SHARED_AREA_SZ);
	LOG("size of struct comArea: 0x%lx\n", sizeof(struct comArea));
	assert(SEAM_AGENT_BASE_PA + SEAM_AGENT_ADR_SPC_SZ > _20M);

	/*check cpu features, movdir64b is used by pseamldr/tdxmodule*/
	asm volatile(	"mov $0x7, %%eax; \n\t"
					"cpuid; \n\t"
					"mov %%ecx, %0; \n\t"
					:"=m"(ecx)::"%eax", "%ecx");
	movdir64b_support = (ecx & (1 << 28)) >> 28;
	serialize_support = (ecx & (1 << 14)) >> 14;
	xgetbv_support = (ecx & (1 << 27)) >> 27;

	LOG("cpuid movdir64b support: %x\n", movdir64b_support);
	LOG("cpuid serialize support: %x\n", serialize_support);
	LOG("cpuid xgetbv support: %x\n", xgetbv_support);

#ifndef EMULATE_XGETBV
	/*if xgetbv is not configureed to be emulated, the CPU must support it*/
	if(!xgetbv_support){
		LOG("CPU does not support XGETBV, enable XGETBV_EMULATION in configs.h\n");
		exit(0);
	}
#endif

#ifndef EMULATE_MOVDIR64B
	/*if movdir64b is not configured to be emulated, the CPU must support it*/
	if(!movdir64b_support){
		LOG("CPU does not support MOVDIR64B, MOVDIR64B_EMULATION in configs.h\n");
		exit(0);
	}
#endif

#ifdef INSTRUCTION_TRACER_ON
#ifdef SINGLE_STEP_TDX_MOD
	LOG("At do_sanity_checks(): ");
	LOG("Single stepping and tracer can not coexist, turn one off ... exitting\n");
	exit(0);
#endif
#endif

	if(TD_GPA_RANGE_MAX > _1G){
		LOG("in create_td(), we assume the initial gparange to be < 1G\n");
		exit(0);
	}
	LOG("sanity checks done\n");
}

void vm_init()
{
	int api_ver;
	struct kvm_userspace_memory_region memreg;

	vm->sys_fd = open("/dev/kvm", O_RDWR);
	if (vm->sys_fd < 0) {
		perror("open /dev/kvm");
		exit(1);
	}

	api_ver = ioctl(vm->sys_fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0) {
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	if (api_ver != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
		api_ver, KVM_API_VERSION);
		exit(1);
	}

	vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
	if (vm->fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

    if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	memreg.slot = 0;
	memreg.flags = 0;
	memreg.guest_phys_addr = 0;
	memreg.memory_size = SEAM_ENV_PHY_MEM;
	memreg.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
	}

	/*setup additional memory for the vm to do the TD setup*/
	memreg.slot = 1;
	memreg.flags = 0;
	memreg.guest_phys_addr = _1GB; /*this block pf phy mem is for TD creation*/
	memreg.memory_size = SEAM_PHY_RANGE_2;
	memreg.userspace_addr = (unsigned long)vm->mem2;
    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
	}
}

void vcpu_init()
{
	int vcpu_mmap_size;

	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
        if (vcpu->fd < 0) {
		perror("KVM_CREATE_VCPU");
                exit(1);
	}

	vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
                exit(1);
	}

	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vcpu->fd, 0);
	if (vcpu->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

/*TOFIX immediately*/
/*provides the GPR saved by int3 handler on its stack*/
ulong get_saved_reg64(REGS_64 reg){
	return *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg]);
}

void init_int3_stack_offset_array(){

    com->int3_stack_offsets[RAX]    = AGENT_STACK_RAX_OFFSET;
    com->int3_stack_offsets[RBX]    = AGENT_STACK_RBX_OFFSET;
    com->int3_stack_offsets[RCX]    = AGENT_STACK_RCX_OFFSET;
    com->int3_stack_offsets[RDX]    = AGENT_STACK_RDX_OFFSET;
    com->int3_stack_offsets[RDI]    = AGENT_STACK_RDI_OFFSET;
    com->int3_stack_offsets[RSI]    = AGENT_STACK_RSI_OFFSET;
    com->int3_stack_offsets[RBP]    = AGENT_STACK_RBP_OFFSET;
    com->int3_stack_offsets[R8]     = AGENT_STACK_R8_OFFSET;
    com->int3_stack_offsets[R9]     = AGENT_STACK_R9_OFFSET;
    com->int3_stack_offsets[R10]    = AGENT_STACK_R10_OFFSET;
    com->int3_stack_offsets[R11]    = AGENT_STACK_R11_OFFSET;
    com->int3_stack_offsets[R12]    = AGENT_STACK_R12_OFFSET;
    com->int3_stack_offsets[R13]    = AGENT_STACK_R13_OFFSET;
    com->int3_stack_offsets[R14]    = AGENT_STACK_R14_OFFSET;
    com->int3_stack_offsets[R15]    = AGENT_STACK_R15_OFFSET;

}

void set_debug_bp(ulong address, ulong dr_num, ulong trigger_condition, ulong bp_size){

	struct kvm_debugregs dregs;

	if(trigger_condition == DB_CONDITION_INS_EXEC){
		if(bp_size != DB_LENGTH_1_BYTE){
			LOG("set_debug_bp: if debug BP condition is ins exec, mem loc size must by 0b00\n");
			exit(0);
		}
	}
	if(dr_num > 4 || dr_num < 0){
		LOG("set_debug_bp: ivalid debug reg\n");
		exit(0);
	}
	if(trigger_condition > 0b11 || bp_size > 0b11){
		LOG("set_debug_bp: invalid trigger condition or bp mem loc size\n");
		exit(0);
	}

	if (ioctl(vcpu->fd, KVM_GET_DEBUGREGS, &dregs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	dregs.db[dr_num] = address;
	dregs.dr7 = dregs.dr7 |
				((1UL << dr_num*2) |                       /*bits 0,2,4,6 for local dr0-dr3*/
				(trigger_condition << (16 + dr_num*4)) | /*bits 16-17,20-21,24-25,28-30 hold conditions for dr0-dr3*/
				(bp_size << (18 + dr_num*4)) |           /*bits 18-19,22-23,26-27,3-31 hold bp size for dr0-dr3*/
				(1UL << 10));                             /*bit 10 is reserved 1*/

	if (ioctl(vcpu->fd, KVM_SET_DEBUGREGS, &dregs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
}

void remove_debug_bp(ulong dr_num){

	struct kvm_debugregs dregs;

	if(dr_num > 4 || dr_num < 0){
		LOG("set_debug_bp: ivalid debug reg\n");
		exit(0);
	}

	if (ioctl(vcpu->fd, KVM_GET_DEBUGREGS, &dregs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	dregs.db[0] = 0x0;
	dregs.dr7 &= ~(1UL << dr_num);                      /*bits 0-3 for dr0-dr3*/

	if (ioctl(vcpu->fd, KVM_SET_DEBUGREGS, &dregs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
}

/*given a va and cr3 prints the PT details for debugging*/
void print_pt_details(uint64_t va, uint64_t cr3){

	uint32_t idx;
	uint64_t *pml4, *pdpt, *pd, *pt, pde;
	uint64_t pdpt_pa, pd_pa, pt_pa;

	pml4 = (void *)(vm->mem + cr3);
	idx = (va >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
	pde = pml4[idx];
	LOG("pml4 ");
	LOG("idx:%d\tPDE:0x%lx\tp:%d\n", idx, pde, (pde & PDE64_PRESENT)? 1 : 0);

	pdpt_pa = pde & PTE_TO_PA_MASK;
	pdpt = (void *)(vm->mem + pdpt_pa);
	idx = (va >> PDPT_IDX_SHIFT) & PGT_IDX_MASK;
	pde = pdpt[idx];
	LOG("pdpt ");
	LOG("idx:%d\tPDE:0x%lx\tp:%d\n", idx, pde, (pde & PDE64_PRESENT)? 1 : 0);

	pd_pa = pde & PTE_TO_PA_MASK;
	pd = (void *)(vm->mem + pd_pa);
	idx = (va >> PD_IDX_SHIFT) & PGT_IDX_MASK;
	pde = pd[idx];
	LOG("pd ");
	LOG("idx:%d\tPDE:0x%lx\tp:%d\n", idx, pde, (pde & PDE64_PRESENT)? 1 : 0);

	pt_pa = pde & PTE_TO_PA_MASK;
	pt = (void *)(vm->mem + pt_pa);
	idx = (va >> PT_IDX_SHIFT) & PGT_IDX_MASK;
	pde = pt[idx];
	LOG("pt ");
	LOG("idx:%d\tPDE:0x%lx\tp:%d\n", idx, pde, (pde & PDE64_PRESENT)? 1 : 0);
}

void update_pseamldr_pt_full_fuse(){

	ulong *seam_agent_pml4 = (ulong *)(vm->mem + SEAM_AGENT_PT_BASE_PA);
	uint32_t pml4_idx = (SEAM_AGENT_BASE_VA >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
	ulong *pseamldr_pml4 = (ulong *)(vm->mem + SeamrrPtCtx.PtBaseAddrPa);
	LOG("vm->mem:0x%lx\n", (ulong)vm->mem);
	LOG("seam_agent_pml4:0x%lx pml4_idx:%d\n", (ulong)seam_agent_pml4, pml4_idx);
	LOG("pseamldr_pml4:0x%lx\n", (ulong)pseamldr_pml4);

	if((pseamldr_pml4[pml4_idx] & PDE64_PRESENT) != 0){
		LOG("ERROR seam agent linear addr overlap with pseamldr linear addr: pml4_idx:0x%x\n", pml4_idx);
		exit(0);
	}
	pseamldr_pml4[pml4_idx] = seam_agent_pml4[pml4_idx];
	LOG("fused pml4 entry:0x%lx\n", seam_agent_pml4[pml4_idx]);

}

/*given a tdx sw cr3, this function fuses its address space in to that of s_semulator*/
void update_s_emulator_pt(uint64_t cr3){
	uint32_t idx;
	uint64_t *s_emulator_pml4 = (ulong *)(vm->mem + SEAM_AGENT_PT_BASE_PA);
	uint64_t *tdx_sw_pml4 = (ulong*)(vm->mem + cr3);

	/*iterate pseamldr_pml4 entries and fuse the corresponding PDPTs with seam_agent_pml4*/
	for(idx = 0; idx <= 511; idx++){
		if((tdx_sw_pml4[idx] & PDE64_PRESENT) != 0){
			if((s_emulator_pml4[idx] & PDE64_PRESENT) != 0){
				/*at this stage, we do not expect seam agent to have mappings for pseamlr's linear address space*/
				LOG("ERROR s_smulator linear addr space overlap with tdx sw linear addr: pml4_idx:0x%x\n", idx);
				exit(0);
			}
			else{
				/*fuse now*/
				LOG("fusing tdx sw PDPT with agent PML4, pml4 idx: %d\n", idx);
				s_emulator_pml4[idx] = tdx_sw_pml4[idx];
			}
		}
	}	
}

/*map a given page to the PT hierachy identified by the cr3, 
IMPORTANT: The pt pages are allocated from the SEAM env PT region in the following PA range dedicated for 
seam agent's own mappings
pt range start: SEAM_AGENT_PT_BASE_PA
pt range size: SEAM_AGENT_PT_RGN_SZ
Since part of this range has already been used for seam agent's mappings earlier, the next available page
to be used as a PT page is saved in the global variable: vm->next_pt_pa */
void map4K_agent_page(uint64_t va, uint64_t pa, uint64_t cr3){

	uint32_t pml4_idx, pdpt_idx, pd_idx, pt_idx;
	uint64_t *pml4, *pdpt, *pd, *pt;
	uint64_t pdpt_pa, pd_pa, pt_pa, next_pt_pa;
	

	next_pt_pa = vm->next_pt_pa;
	if(next_pt_pa >= (SEAM_AGENT_PT_BASE_PA + SEAM_AGENT_PT_RGN_SZ)){
		LOG("SEAM agent's PT region is exhausted\n");
		exit(0);
	}

	pml4 = (void *)(vm->mem + cr3);
	pml4_idx = (va >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
	/*LOG("\nva:0x%lx pa:0x%lx pml4_idx:%d\n", (ulong)va, (ulong)pa, pml4_idx);*/
	if(pml4[pml4_idx] & PDE64_PRESENT){
	/*Actually, when we try to map a seam agent page in to pseamldr's hieracy for the first time, the pml4 
	entry must not be present; if present --> seam agent's and pseamldr's linesr address ranges probably overlap*/
		pdpt_pa = pml4[pml4_idx] & PTE_TO_PA_MASK;
	}
	else{
	/*if no pml4 entry, allocate a PDPT page from SEAM agent's PT region*/
		pdpt_pa = next_pt_pa;
		/*LOG("new pdpt_pa:0x%lx\n", pdpt_pa);*/
		next_pt_pa += PAGE_SIZE_4K;
		pml4[pml4_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_pa;
	}
	pdpt = (uint64_t *)(vm->mem + pdpt_pa);

	pdpt_idx = (va >> PDPT_IDX_SHIFT) & PGT_IDX_MASK;
	/*LOG("pdpt idx:%d\n", pdpt_idx);*/
	if(pdpt[pdpt_idx] & PDE64_PRESENT){
		pd_pa = pdpt[pdpt_idx] & PTE_TO_PA_MASK;
	}
	else{
		pd_pa = next_pt_pa;
		/*LOG("new pd_pa:0x%lx\n", pd_pa);*/
		next_pt_pa += PAGE_SIZE_4K;
		pdpt[pdpt_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_pa;
	}
	pd = (uint64_t *)(vm->mem + pd_pa);

	pd_idx = (va >> PD_IDX_SHIFT) & PGT_IDX_MASK;
	/*LOG("pd idx:%d\n", pd_idx);*/
	if(pd[pd_idx] & PDE64_PRESENT){
		pt_pa = pd[pd_idx] & PTE_TO_PA_MASK;
	}
	else{
		pt_pa = next_pt_pa;
		/*LOG("new pt_pa:0x%lx\n", pt_pa);*/
		next_pt_pa += PAGE_SIZE_4K;
		pd[pd_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_pa;
	}
	pt = (uint64_t *)(vm->mem + pt_pa);

	pt_idx = (va >> PT_IDX_SHIFT) & PGT_IDX_MASK;
	/*LOG("pt idx:%d\n", pt_idx);*/
	if(!(pt[pt_idx] & PDE64_PRESENT)){ 
		/*if not mapped, map the page*/
		pt[pt_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pa;
	}
	/*LOG("pt[pt_idx]:0x%lx\n", pt[pt_idx]);*/

	if(next_pt_pa > (SEAM_AGENT_PT_BASE_PA + SEAM_AGENT_PT_RGN_SZ)){
	/*it's ok if next_pt_pa becomes equal to SEAM_AGENT_PT_BASE_PA + SEAM_AGENT_PT_RGN_SZ
	That means the above PT page allocations has not gone beyond the limit.
	so, the above condition only checks if greater than...*/
		LOG("SEAM agent's PT region is exhausted\n");
		exit(0);
	}
	vm->next_pt_pa = next_pt_pa;
}

/*update the tdx sw's PTs to access seam agent, gdt & idt
tdx sw, identified by provided cr3
After the installation of each tdx sw, this is to be called.*/
void update_tdx_sw_pt(uint64_t cr3){

	/*map seam agent's code page to tdx sw*/
	map4K_agent_page(SEAM_AGENT_CODE, SEAM_AGENT_CODE_PA, cr3);

	/*seam agent has its own stack, 1 page, map that stack page to tdx sw*/
	map4K_agent_page(SEAM_AGENT_STACK_PAGE_LOW, SEAM_AGENT_STACK_PAGE_LOW_PA, cr3);

	/*map SEAM environment's GDT and IDT pages to tdx sw*/
	map4K_agent_page(SEAM_ENV_GDT, SEAM_ENV_GDT_PA, cr3);
	map4K_agent_page(SEAM_ENV_IDT, SEAM_ENV_IDT_PA, cr3);

	/*
	LOG("traversing mappings for seam agent code page for debugging...\n");
	LOG("seam agent PTs\n");
	print_pt_details(SEAM_AGENT_CODE, SEAM_AGENT_PT_BASE_PA);
	LOG("\ntdx sw PTs\n");
	print_pt_details(SEAM_AGENT_CODE, cr3);
	LOG("\n");
	*/
}

static void setup_page_tables(){

	uint64_t pml4_pa = SEAM_AGENT_PT_BASE_PA;
	uint64_t *pml4 = (void *)(vm->mem + pml4_pa);
	uint64_t next_pt_pa = (uint64_t)pml4_pa + PAGE_SIZE_4K;
	uint64_t pdpt_pa, pd_pa, pt_pa;
	uint64_t *pdpt, *pd, *pt;
	uint32_t pml4_idx, pdpt_idx, pd_idx, pt_idx;
	
	uint64_t agent_va = SEAM_AGENT_BASE_VA;
	uint64_t agent_pa = SEAM_AGENT_BASE_PA;

	agent_pt_data.seam_agent_pdpt_count = 0;

	if(agent_va & 0xfff){
		LOG("SEAM_AGENT_BASE_VA is not a page boundary\n");
		exit(0);
	}
	if(agent_pa & 0xfff){
		LOG("SEAM_AGENT_BASE_PA is not a page boundary\n");
		exit(0);
	}
	
	memset((void *)vm->mem + SEAM_AGENT_PT_BASE_PA, 0, SEAM_AGENT_PT_RGN_SZ);
	while(agent_va < (SEAM_AGENT_BASE_VA + SEAM_AGENT_ADR_SPC_SZ)){

		//LOG("agent_va: 0x%lx\t agent_pa: 0x%lx ----------------\n", (ulong)agent_va, (ulong)agent_pa);
		pml4_idx = (agent_va >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
		//LOG("\npml4_idx: 0x%x\n", pml4_idx);
		if(pml4[pml4_idx] & PDE64_PRESENT){ /*if pdpt exists use that, else create a new pdpt*/
			pdpt_pa = pml4[pml4_idx] & PTE_TO_PA_MASK;
			//LOG("pdpt exists, pdpt_pa: 0x%lx\n", (ulong)pdpt_pa);
		}
		else{
			pdpt_pa = next_pt_pa;
			next_pt_pa += PAGE_SIZE_4K;
			pml4[pml4_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_pa;

			if(agent_pt_data.seam_agent_pdpt_count == 0){
				agent_pt_data.seam_agent_pdpt_count = 1;
				agent_pt_data.seam_agent_pdpt_pa = pdpt_pa;
			}
			else if(agent_pt_data.seam_agent_pdpt_count == 1){
				LOG("ERROR we do not expect more than 1 PDPT table for seam agent\n");
				exit(0);
			}
			/*LOG("new pdpt allocated, pdpt_pa: 0x%lx\n", (ulong)pdpt_pa);*/
		}
		pdpt = (void *)(vm->mem + pdpt_pa);
		//LOG("pdpt: 0x%lx\n\n", (ulong)pdpt);

		pdpt_idx = (agent_va >> PDPT_IDX_SHIFT) & PGT_IDX_MASK;
		if(pdpt[pdpt_idx] & PDE64_PRESENT){ /*if pdt exists use that, else create a new pdt*/
			pd_pa = pdpt[pdpt_idx] & PTE_TO_PA_MASK;
		}
		else{
			pd_pa = next_pt_pa;
			next_pt_pa += PAGE_SIZE_4K;
			pdpt[pdpt_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_pa;
		}
		pd = (void *)(vm->mem + pd_pa);

		pd_idx = (agent_va >> PD_IDX_SHIFT) & PGT_IDX_MASK;
		if(pd[pd_idx] & PDE64_PRESENT){ /*if pt exists use that, else create a new pt*/
			pt_pa = pd[pd_idx] & PTE_TO_PA_MASK;
		}
		else{
			pt_pa = next_pt_pa;
			next_pt_pa += PAGE_SIZE_4K;
			pd[pd_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_pa;
		}
		pt = (void *)(vm->mem + pt_pa);


		pt_idx = (agent_va >> PT_IDX_SHIFT) & PGT_IDX_MASK;
		if(!(pt[pt_idx] & PDE64_PRESENT)) /*if not mapped, map the page*/
			pt[pt_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | agent_pa;
		
		agent_pa += PAGE_SIZE_4K;
		agent_va += PAGE_SIZE_4K;
	}
	vm->next_pt_pa = (ulong)next_pt_pa;
	/*LOG("setup_page_tables: next_pt_pa: 0x%lx\n", (ulong)next_pt_pa);*/
}

void load_seam_agent(){

	/*loading seam agent's code*/
	memcpy(vm->mem + SEAM_AGENT_CODE_PA, seam_agent_bin_start, seam_agent_bin_end - seam_agent_bin_start);
}

int do_64bit_specifics()
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int status;

	LOG("doing 64-bit specifics ...\n");
	setup_page_tables();

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	status = setup_sregs(&sregs);
	if(status != 0){
		LOG("setup sregs failed, exiting now\n");
		exit(0);
	}

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}
	LOG("aft setup GDT base:%lx lim:0x%x\n", (ulong)sregs.gdt.base, sregs.gdt.limit);

	memset(&regs, 0, sizeof(regs));
	setup_regs(&regs);
	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	load_seam_agent();
	/*get agent cr ins addrs*/
	get_cr_ins_address((ulong *)&com->sreq.agent_cr_addr[0]);
	com->sreq.agent_code_start = SEAM_AGENT_CODE;

	return 0;
}

void update_sec_page_table(){

	ulong pamt_start_pa = TDX_PAMT0_START_PA;
	ulong pamt_end_pa = TDX_PAMT0_START_PA + TDX_PAMT0_SIZE;
	ulong pamt_pa = pamt_start_pa;
	while(pamt_pa < pamt_end_pa){

		securePage sp;
		long page_idx = (pamt_pa >> 12) - (TDX_TDMR0_START_PA >> 12);
		assert(page_idx < SECURE_PAGE_COUNT);

		sp.mdata.base_pa = pamt_pa >> 12;
		// sp.mdata.hkid = TDX_GLOBAL_PRIVATE_HKID;
		sp.mdata.hkid = 0;
		sp.mdata.hkid_owner = TDX_MOD;
		sp.mdata.td = TDX_MOD;

		com->sreq.secPages[page_idx].raw = sp.raw;
		pamt_pa+= _4K;
	}
}

uint64_t *get_saved_register_address(REGS_64 reg){

	uint64_t *adr, *current_target_rsp;

	if(reg == RSP ){
		current_target_rsp = (ulong *)(*(ulong *)(vm->mem + SEAM_AGENT_STACK_PA - 0x8));
		adr = &current_target_rsp[4];
	}
	else if(reg == R15){
		current_target_rsp = (ulong *)(*(ulong *)(vm->mem + SEAM_AGENT_STACK_PA - 0x8));
		adr = &current_target_rsp[0];
	}
	else{
		adr = (uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg]);
	}

	return adr;
}

uint64_t get_saved_register_value(REGS_64 reg){

	return *get_saved_register_address(reg);
}

uint64_t get_last_seam_env_reg(REGS_64 reg){
	struct kvm_regs regs;

	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	if(reg == RIP){
		return regs.rip;
	}
	else if(reg == RAX){
		return regs.rax;
	}
	else{
		LOG("get_last_seam_env_reg() not supported for reg:%d", reg);
		exit(0);
	}
}

void debug_info(){
	struct kvm_regs regs;
	struct kvm_sregs sregs;

	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
	LOG("\nrip:0x%lx rsp:0x%lx\n", (ulong)regs.rip, (ulong)regs.rsp);
	LOG("rbp:0x%lx rax:0x%lx rbx:0x%lx rcx:0x%lx rdx:0x%lx rdi:0x%lx\n", (ulong)regs.rbp, (ulong)regs.rax, (ulong)regs.rbx, (ulong)regs.rcx, (ulong)regs.rdx, (ulong)regs.rdi);
	LOG("r8:0x%lx r9:0x%lx r10:0x%lx r11:0x%lx \n", (ulong)regs.r8, (ulong)regs.r9, (ulong)regs.r10, (ulong)regs.r11);
	LOG("rflags:0x%lx \n", (ulong)regs.rflags);

	if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}
	LOG("cr2:0x%llx\n", sregs.cr2);
}

void print_tdx_ret_regs(){

	TDXCALL_LOG("rax:0x%lx rcx:0x%lx rdx:0x%lx\n", get_saved_reg64(RAX), get_saved_reg64(RCX), get_saved_reg64(RDX) );
	TDXCALL_LOG("r8:0x%lx r9:0x%lx r10:0x%lx r11:0x%lx \n", get_saved_reg64(R8), get_saved_reg64(R9), get_saved_reg64(R10), get_saved_reg64(R11));
}

void print_sept_rd_result(){
	struct kvm_regs regs;

	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
	LOG("rcx:0x%lx \n", get_saved_reg64(RCX));
	LOG("rdx:0x%lx \n", get_saved_reg64(RDX));
}

ulong seam_agent_va_to_mgr_va(ulong va){
	return (ulong)(va - SEAM_AGENT_BASE_VA + vm->mem + SEAM_AGENT_BASE_PA);
}

void read_pseamldr_data_t(){

	uint64_t data_region_pa = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize 
								- (_4KB + SeamldrData.PSeamldrConsts->CCodeRgnSize 
										+ SeamldrData.PSeamldrConsts->CDataStackSize 
										+ C_P_SYS_INFO_TABLE_SIZE 
										+ SeamldrData.PSeamldrConsts->CDataRgnSize
								);

	pseamldr_data_t* pseamldr_data = (pseamldr_data_t *)(vm->mem + data_region_pa);
	
	LOG("seam range base: 0x%lx\n", pseamldr_data->system_info.seamrr_base);
	LOG("seam range size: 0x%lx\n", pseamldr_data->system_info.seamrr_size);
	LOG("max pa: %lu\n", pseamldr_data->system_info.max_pa);
	LOG("private_hkid_min: %lu\n", pseamldr_data->system_info.private_hkid_min);
	LOG("hkid_mask: 0x%lx\n", pseamldr_data->system_info.hkid_mask);

}

void log_seam_error_and_exit(){
	CODE hcall_code = com->hcall_code;
	uint32_t msr_idx, cpuid_leaf, cpuid_subleaf;

	LOG("\n");
	debug_info();
	LOG("SEAM ERROR: ");
	switch (hcall_code){
		case CODE_UNHANDLED_MSR:
		{
			msr_idx = *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - AGENT_STACK_RCX_OFFSET) & R32_BITS;
			LOG("unhandled MSR: 0x%x", msr_idx);
		}break;
		case CODE_UNHANDLED_INS:
		{
			LOG("unhandled instruction.");
		} break;
		case CODE_NOT_A_SPECIAL_INS:
		{
			LOG("int3 triggered, but not a special instruction.");
		} break;
		case CODE_UNHANDLED_CPUID:
		{
			cpuid_leaf = *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - AGENT_STACK_RAX_OFFSET) & R32_BITS;
			cpuid_subleaf = *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - AGENT_STACK_RCX_OFFSET) & R32_BITS;
			LOG("unhandled cpuid, leaf:0x%x subleaf:0x%x\n", cpuid_leaf, cpuid_subleaf);
		} break;
		case CODE_UNHANDLED_CPUID_SUBLEAF:
		{
			LOG("unhandled cpuid subleaf");
		} break;
		case CODE_UNHANDLED_SEAMOPS_LEAF:
		{
			LOG("unhandled seamops leaf");
		} break;
		case CODE_OPERANDS_NOT_EXTRACTED:
		{
			LOG("operands have not been extracted");
		} break;
		case CODE_UNHANDLED_VMREAD_FIELD:
		{
			struct insData *idata;
			REGS_64 reg0;
			uint64_t op0;
 
			if(com->current_sw == SEAM_SW_PSEAMLDR){
				idata = (struct insData *)com->pseamldr_ins;
			}
			else{
				idata = (struct insData *)com->tdxmodule_ins;
			}

			if(idata[com->int3_ins_info.insdata_idx].operands_extracted != true){
				LOG("unhandled vmread field, cut can not identify the file\n");
				break;
			}
			reg0 = idata[com->int3_ins_info.insdata_idx].op0.reg; /*op0 allways a reg*/
			op0 = get_saved_register_value(reg0);
			LOG("unhandled vmread field: 0x%lx", op0);
		} break;
		case CODE_UNABLE_TO_FIND_VMCS:
		{
			LOG("Unable to find VMCS\n");
		} break;
		default:
		{
			LOG("Unknown seam error code.");
		} break;
	}

#ifdef INSTRUCTION_TRACER_ON
    LOG("\n# of instructions executted: ~%lu, regular:%lu special:%lu", com->regular_ins_count + com->emulated_ins_count, com->regular_ins_count, com->emulated_ins_count);
#endif
	LOG(" exiting now...\n");
	exit(0);
}

void handle_trace_ins(){

	ulong adr, *stack, target_code_pa, target_stack_pa, lp_stack_size, data_stack_size, max_ins_idx;
	struct insData *idata;
	ulong int3_adr = com->int3_adr;
	ulong target_stack = (*(ulong *)((ulong)vm->mem + SEAM_AGENT_STACK_PA - 0x8)); /*saved stack va of the target*/
	ulong ins_count = 0;

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		target_code_pa = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize 
							- (SeamldrData.PSeamldrConsts->CCodeRgnSize + C_P_SYS_INFO_TABLE_SIZE); /*pa offset from seamrr base*/
		target_stack_pa = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - C_P_SYS_INFO_TABLE_SIZE 
								- (SeamldrData.PSeamldrConsts->CCodeRgnSize) 
								- (SeamldrData.PSeamldrConsts->CDataStackSize) 
								- P_SEAMLDR_SHADOW_STACK_SIZE; /*pa offset from seamrr base*/ 
		stack = (ulong *)((ulong)vm->mem + target_stack_pa + (target_stack - SeamldrData.PSysInfoTable->StackRgn.Base));
		idata = (struct insData*)com->pseamldr_total_ins;
		max_ins_idx = PSEAMLDR_TOTAL_INS_COUNT;
	}
	else{ /*SEAM_SW_TDXMODULE*/
		target_code_pa = SEAM_RANGE_START_PA + MODULE_RANGE_SIZE - SEAMRR_MODULE_CODE_REGION_SIZE;
		data_stack_size = (TDX_MODULE_STACK_PAGES + 1)*_4KB; /*(seam_sigstruct->num_stack_pages + 1) * _4KB*/
		lp_stack_size = data_stack_size + TDX_MODULE_PER_LP_SHDW_STACK_SIZE;
		target_stack_pa = target_code_pa - lp_stack_size*EFFECTIVE_NUM_ADDRESSIBLE_LPS;
		stack = (ulong *)((ulong)vm->mem + target_stack_pa + (target_stack - (LINEAR_BASE_STACK_REGION | TDX_MODULE_ADR_MASK)));
		idata = (struct insData*)com->tdxmodule_total_ins;
		max_ins_idx = TDXMODULE_TOTAL_INS_COUNT;
	}
	LOG("SEAM: TRACE regular ins rip:0x%lx\n", int3_adr);

	while((ins_count < max_ins_idx) && (idata[ins_count].size != 0)){
	
		if(int3_adr == idata[ins_count].va){
			adr = (ulong)vm->mem + target_code_pa + idata[ins_count].offset;
			*(uint8_t *)adr = idata[ins_count].first_byte; /*restore the first byte of the ins*/
			stack[1] -= 1; /*reduce the rip saved by Hw upon int3 on stack by 1*/
		}
		ins_count++;
	}
}

void print_seamldr_info(seamldr_info_t *seamldr_info){
	uint8_t data_8;
	uint16_t data_16;
	
	LOG("pseamldr returned SEAMLDR_INFO:\n");
	LOG("VERSION\t\t\t:%d\n", seamldr_info->version); 
	LOG("ATTRIBUTES\t\t:0x%x\n", seamldr_info->attributes.raw); 
	LOG("VENDORID\t\t:0x%x\n", seamldr_info->version); 
	LOG("BUILD_DATE\t\t:%d\n", seamldr_info->build_date); 
	LOG("BUILD_NUM\t\t:%d\n", seamldr_info->build_num); 
	LOG("MINOR_VER\t\t:%d\n", seamldr_info->minor); 
	LOG("MAJOR_VER\t\t:%d\n", seamldr_info->major); 
	LOG("ACM_X2APICID\t\t:%d\n", seamldr_info->acm_x2apic); 
	LOG("NUM_REMAINING_UPDATES\t:%d\n", seamldr_info->minor);
	LOG("SEAMEXTEND.valid\t:0x%lx\n", seamldr_info->seamextend.valid);

	data_16 = seamldr_info->seamextend.tee_tcb_svn.current_seam_svn;
	LOG("SEAMEXTEND.tee_tcb_svn.current_seam_svn\t\t:0x%x\n", data_16); 

	data_8 = seamldr_info->seamextend.tee_tcb_svn.last_patch_se_svn;
	LOG("SEAMEXTEND.tee_tcb_svn.last_patch_se_svn\t:0x%x\n", data_8);
	
	data_8 = seamldr_info->seamextend.seam_ready;
	LOG("SEAMEXTEND.seam_ready\t\t:0x%x\n", data_8); 

	data_8 = seamldr_info->seamextend.system_under_debug;
	LOG("SEAMEXTEND.system_under_debug\t:0x%x\n", data_8); 

	data_8 = seamldr_info->seamextend.p_seamldr_ready;
	LOG("SEAMEXTEND.p_seamldr_ready\t:0x%x\n", data_8); 
}

void print_seamldr_seaminfo(p_sysinfo_table_t *seamldr_seaminfo){

	uint8_t data_8;

	LOG("pseamldr returned SEAMLDR_SEAMINFO:\n");
	LOG("version\t\t\t:0x%lx\n", seamldr_seaminfo->version);
	LOG("tot num lps\t\t:0x%x\n", seamldr_seaminfo->tot_num_lps);
	LOG("tot num sockets\t\t:0x%x\n", seamldr_seaminfo->tot_num_sockets);
	// LOG socket_cpuid_table[MAX_PKGS] : TODO
	LOG("pseamldr range base\t:0x%lx\n", seamldr_seaminfo->p_seamldr_range_base);
	LOG("pseamldr range size\t:0x%lx\n", seamldr_seaminfo->p_seamldr_range_size);
	
	data_8 = seamldr_seaminfo->skip_smrr2_check;
	LOG("skip_smrr2_check\t:0x%x\n", data_8);
	data_8 = seamldr_seaminfo->tdx_ac;
	LOG("tdx_ac\t\t\t:0x%x\n", data_8);
	// LOG cmr_data : TODO
}

void handle_seam_log_request(CODE type){
	
	switch (type)
	{
	case CODE_LOG_INT3_TRIGGERED:
		if(com->is_last_api_call == 1){
			LOGSEAM("last_call_int3 triggered\n");
		}
		LOGSEAM("int3 triggered, rip:0x%lx", ((com->int3_adr <= 0) ? 0 : (com->int3_adr)));
		LOG(" %s\n", ins_names[com->int3_ins]);
		break;
	case CODE_KHOLE_EDIT_ACCESS:
		LOGSEAM("pf triggered, rip:0x%lx pfAdr:0x%lx errcode:0x%lx\n", com->pf_rip, com->pf_adr, com->pf_errcode);
		assert((com->pf_errcode >> 1) & 0x1UL); //0 = Read, 1 = Write, we only expect writes
	break;
	default:
		LOG("unhandled log type received from SEAM\n");
		break;
	}
}

void enable_khole_map_tracking(){

	/**com->khole_data.khole_edit_pml4_pte &= ~(PDE64_RW);*/
	*com->khole_data.khole_edit_pml4_pte &= ~(PDE64_PRESENT);

}

void dissable_khole_map_tracking(){

	/**com->khole_data.khole_edit_pml4_pte &= PDE64_RW;*/
	*com->khole_data.khole_edit_pml4_pte &= PDE64_PRESENT;

}

ulong va_to_pa(ulong cr3, ulong va){
	uint64_t *pt = (uint64_t *)(cr3 + (uint64_t)vm->mem);
	uint64_t pa = cr3;
	uint32_t idx;
	int i = 0;
	while(i <= 3){
		pt = (uint64_t *)(pa + (uint64_t)vm->mem);
		idx = (va >> (39 - i*9)) & PGT_IDX_MASK;
		if(pt[idx] & PDE64_PRESENT){
			pa = pt[idx] & PTE_TO_PA_MASK;
			if( i == 2 && (pt[idx] & PDE64_PS)){ /*2M page*/
				return pa;
			}
		}
		else{
			return 0;
		}
		i++;
	}
	return pa;
}

ulong get_tdr_va_of_running_td(ulong pa, ulong lp){

	ulong *khole_edit_pte = (ulong *)com->lp_khole_state[lp].khole_edit_rgn_mgr_base;
	return com->khole_data.khole_rgn_base + lp*128*_4K + 94*_4K;
}

void fill_khole_refs(ulong lp){

	tdxmod_keyhole_state_t *khs = (tdxmod_keyhole_state_t *)com->lp_khole_state[LP_0].khole_state;
	// LOG("total_ref_count: %d\n", khs->total_ref_count);

	com->sreq.khole_state_seam_va = (ulong)com->lp_khole_state[lp].khole_state;
	ulong ofst = (ulong)&khs->total_ref_count - (ulong)com->lp_khole_state[lp].khole_state;
	com->sreq.lp_khole_ref_adr.tot_ref_count_adr = (ulong)com->lp_khole_state[lp].khole_state_seam_va + ofst;
	int idx = 0;
	while(idx < 128){
		// LOG("mapped pa: 0x%lx ref:%lu\n", khs->keyhole_array[idx].mapped_pa, khs->keyhole_array[idx].ref_count);
		ofst = (ulong)&khs->keyhole_array[idx].ref_count - (ulong)com->lp_khole_state[lp].khole_state;
		/*LOG("hole ref adr: 0x%lx \n", com->lp_khole_state[lp].khole_state_seam_va + ofst);*/
		com->sreq.lp_khole_ref_adr.hole_ref_count_adr[idx] = (ulong)com->lp_khole_state[lp].khole_state_seam_va + ofst;
		idx++;
	}
}

void get_key_hole_rgn_info(ulong cr3){

	uint64_t *pml4;
	uint32_t idx;
	sysinfo_table_t* sysinfo_table = (sysinfo_table_t*)(vm->mem + SEAM_RANGE_START_PA);
	ulong lp_local_data_pa, lp, key_hole_edit_start_pa;

	if(sysinfo_table->keyhole_rgn_base == 0){
		LOG("sysinfo_table->keyhole_rgn_base is 0\n");
		exit(0);
	}
	com->khole_data.khole_rgn_base = sysinfo_table->keyhole_rgn_base;
	com->khole_data.khole_rgn_size = sysinfo_table->keyhole_rgn_size;
	LOG("com->khole_data.khole_rgn_base:0x%lx\n", com->khole_data.khole_rgn_base);
	LOG("com->khole_data.khole_rgn_size:0x%lx\n", com->khole_data.khole_rgn_size);
	pml4 = (uint64_t *)(cr3 + vm->mem);
	idx = (sysinfo_table->keyhole_edit_rgn_base >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
	com->khole_data.khole_edit_pml4_pte = (uint64_t *)&pml4[idx];

	if((sysinfo_table->keyhole_edit_rgn_base == 0) || (sysinfo_table->keyhole_edit_rgn_size == 0)){
		LOG("keyhole_edit_rgn_base OR keyhole_edit_rgn_size is 0");
		exit(0);
	}
	com->khole_data.khole_edit_rgn_base = sysinfo_table->keyhole_edit_rgn_base;
	com->khole_data.khole_edit_rgn_size = sysinfo_table->keyhole_edit_rgn_size;
	LOG("com->khole_data.khole_edit_rgn_size: %lx\n", com->khole_data.khole_edit_rgn_size);

	key_hole_edit_start_pa = va_to_pa(cr3, sysinfo_table->keyhole_edit_rgn_base);
	if(key_hole_edit_start_pa == 0){
		LOG("key_hole_edit_start_pa is 0\n");
		exit(0);
	}

	lp = 0;
	while( lp < NUM_ADDRESSIBLE_LPS){

		lp_local_data_pa = SEAM_RANGE_START_PA + 
	                        _4K + /*sysinfo table*/
	                        _4K*EFFECTIVE_NUM_ADDRESSIBLE_LPS + /*In our configuration, NUM_ADDRESSIBLE_LPS can also be used here as #LP = 2*/
	                        (TDX_MODULE_HANDOFF_DATA_PAGES + 1)*_4K +
							(TDX_MODULE_TLS_PAGES + 1)*_4K*lp;
		com->lp_khole_state[lp].khole_state = (void *)(vm->mem + lp_local_data_pa + KHOLE_STATE_OFFSET_IN_LOCAL_DATA);

		com->lp_khole_state[lp].khole_state_seam_va = (void *)(com->seamcall_vmcs[lp].gsbase + KHOLE_STATE_OFFSET_IN_LOCAL_DATA);
		/*While the vmm can determine the keyhole region size at TDXMOD install, and while PSEAMLDR determines khole edit region size based on khole
		region size, the per lp keyhole edit region start is deteermined by the tdx module as follows.
		In TDX Mod's fill_keyhole_pte(): lp_keyhole_edit_base = keyhole_edit_rgn_base + lp_id * MAX_KEYHOLE_PER_LP * sizeof(ia32e_pxe_t); We follow the 
		same here. It appears that each LP has only 128 entries (that takes up 128*8 bytes) to map 128 pages in to it's keyhole region at runtime.*/
		com->lp_khole_state[lp].khole_edit_rgn_pa = key_hole_edit_start_pa + lp*MAX_KEYHOLE_PER_LP*8;
		com->lp_khole_state[lp].khole_edit_rgn_mgr_base = (ulong)(vm->mem + com->lp_khole_state[lp].khole_edit_rgn_pa);																		
		com->lp_khole_state[lp].khole_map_count = 0;
		com->lp_khole_state[lp].khole_free_count = 0;

		LOG("lp:%lu com->lp_khole_state[lp].khole_edit_rgn_pa: %lx\n", lp, com->lp_khole_state[lp].khole_edit_rgn_pa);

		lp++;
	}

	/*for TRover's use*/
	com->sreq.khole_start_seam_va = com->khole_data.khole_rgn_base;
	com->sreq.khole_edit_start_seam_va = com->khole_data.khole_edit_rgn_base;
}

void log_active_keyhole_mappings(){

	tdxmod_keyhole_state_t *khole_state;
	uint64_t *khole_edit_rgn;
	int idx;
	ulong lp, pa;

	/*as per tdx module implementation, each LP has a keyhole region of 128 pages. Each of these pages correspond to one 
	entry (each entry is a pte entry of 8B) in khole edit region. 
	i.e.
	khole   0 va: keyhole va           --> khole edit entry idx = 0   --> khole edit pte entry adr : khole edit va
	khole   1 va: keyhole va + 4KB     --> khole edit entry idx = 1   --> khole edit pte entry adr : khole edit va + 8*1
	...
	...
	khole 127 va: keyhole va + 4KB*127 --> khole edit entry idx = 127 --> khole edit pte entry adr : khole edit va + 8*127

	Since we have only 2 LP, our tdx mod only uses a khole edit region of size 128*2*8B
	The rest of this keyhole edit page remain unused. */
	lp = 0;
	while(lp < NUM_ADDRESSIBLE_LPS){

		khole_state =  (tdxmod_keyhole_state_t *)com->lp_khole_state[lp].khole_state;
		khole_edit_rgn = (uint64_t *)(com->lp_khole_state[lp].khole_edit_rgn_pa + vm->mem);

		LOG("lp khole tot ref count: %lu\n", khole_state->total_ref_count);
		for(idx = 0; idx < MAX_KEYHOLE_PER_LP; idx++){
			if(khole_state->keyhole_array[idx].state == 1){
				LOG("lp: %lu khole idx: %d ref count:%lu hkid+pa with active mapping: %lx\n", lp, idx, 
					khole_state->keyhole_array[idx].ref_count,
					khole_state->keyhole_array[idx].mapped_pa);
			}
		}
		/*LOG("dumping khole edit region with present PTE\n");
		for(idx = 0; idx < MAX_KEYHOLE_PER_LP; idx++){
			if(khole_edit_rgn[idx] & PDE64_PRESENT){
				LOG("lp: %lu khole idx: %d pte: %lx\n", lp, idx, khole_edit_rgn[idx]);
			}
		}*/
		
		lp++;
	}

}

void block_persistant_khole_mappings(ulong current_lp){
	return;
	uint64_t *lp_khole_edit_rgn;
	ulong lp_to_block;
	int idx;
	return;
	/*We inspect persistant keyhole mappings and temporily dissable the mappings that do not belong to the active TD and tdx mod.
	We simply mark the entries as not present.
	Also mark the active mappings of the current TD as present in case if they have been maked not present previously.
	The current TD is identified by the hkid provided*/
	lp_to_block = 0; 
	while(lp_to_block < NUM_ADDRESSIBLE_LPS){
		
		lp_khole_edit_rgn = (uint64_t *)com->lp_khole_state[lp_to_block].khole_edit_rgn_mgr_base;
		LOG("lp_khole_edit_rgn: %lx\n", (ulong)lp_khole_edit_rgn);
		// exit(0);
		if(lp_to_block != current_lp){
			
			for(idx = 0; idx < 128; idx++){
				lp_khole_edit_rgn[idx] &= ~(PDE64_PRESENT);
			}
			LOG("marked lp: %lu khole edit pte entries as NOT present\n", lp_to_block);
		}
		else{
			for(idx = 0; idx < 128; idx++){
				lp_khole_edit_rgn[idx] |= PDE64_PRESENT;
			}
			LOG("marked lp: %lu khole edit pte entries as present\n", lp_to_block);
		}

		lp_to_block++;
	}

}

void inspect_keyholes_for_agent(){

	ulong mapped_pa, hkid, lp_keyhole_va_base, lp_khole_edit_base_va, seam_va;
	tdxmod_keyhole_state_t *lp_khole_state =  (tdxmod_keyhole_state_t *)com->lp_khole_state[com->current_lp].khole_state;

	mapped_pa = com->khole_data.last_khole_edit_pte & PTE_TO_PA_MASK;
	hkid = (com->khole_data.last_khole_edit_pte & HKID_MASK) >> HKID_START_BIT;
	LOG("\nkhole_edit_pte_adr: %lx\n", com->khole_data.last_khole_edit_pte_adr);
	LOG("pa being mapped: %lx hkid: %lx\n", mapped_pa, hkid);
	LOG("lp khole_tot_refs: %lx\n", (ulong)lp_khole_state->total_ref_count);
	lp_keyhole_va_base = ((LINEAR_BASE_KEYHOLE_REGION | TDX_MODULE_ADR_MASK)) + com->current_lp*(_4K * 128);
	LOG("lp_keyhole_va_base: %lx\n", lp_keyhole_va_base);
	lp_khole_edit_base_va = com->khole_data.khole_edit_rgn_base + com->current_lp*8*128;
	LOG("lp_khole_edit_base_va: %lx\n", lp_khole_edit_base_va);
	seam_va = lp_keyhole_va_base + ((com->khole_data.last_khole_edit_pte_adr - lp_khole_edit_base_va)/8)*_4K;
	LOG("keyhole va: %lx\n", seam_va);
	LOG("khole edit pte: %lx\n", com->khole_data.last_khole_edit_pte);

	/*log_active_keyhole_mappings();*/
}

void handle_pseamldr_info_seamret(){
	ulong seamcall;
	seamldr_info_t *seamldr_info;
	p_sysinfo_table_t *seamldr_seaminfo;

	seamcall = com->last_seamcall.tdxcall;
	com->last_seamcall.return_status = get_saved_reg64(RAX);

	switch (seamcall){
		case PSEAMLDR_SEAMCALL_SEAMLDR_INFO:
		{
			seamldr_info = (seamldr_info_t *)((ulong)vm->mem + com->last_seamcall.rcx);
			if(com->last_seamcall.return_status == PSEAMLDR_SUCCESS){
				print_seamldr_info(seamldr_info);
			}
		} break;
		case PSEAMLDR_SEAMCALL_SEAMLDR_SEAMINFO:
		{
			seamldr_seaminfo = (p_sysinfo_table_t *)((ulong)vm->mem + com->last_seamcall.rcx);
			if(com->last_seamcall.return_status == PSEAMLDR_SUCCESS){
				print_seamldr_seaminfo(seamldr_seaminfo);
			}
		} break;
		default:
		{
			/*DO NOTHING*/
		}
	}
}

void print_seamcall_name(){
	char *name;

	switch (com->last_seamcall.tdxcall)
	{
	case PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL:
		name = (char *)PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL_NAME;
		break;
	case TDH_SYS_INIT:
		name = (char *)TDH_SYS_INIT_NAME;
		break;
	case TDH_SYS_LP_INIT:
		name = (char *)TDH_SYS_LP_INIT_NAME;
		break;
	case TDH_SYS_CONFIG:
		name = (char *)TDH_SYS_CONFIG_NAME;
		break;
	case TDH_SYS_KEY_CONFIG:
		name = (char *)TDH_SYS_KEY_CONFIG_NAME;
		break;
	case TDH_SYS_TDMR_INIT:
		name = (char *)TDH_SYS_TDMR_INIT_NAME; 
		break;
	case TDH_MNG_CREATE:
		name = (char *)TDH_MNG_CREATE_NAME;
		break;
	case TDH_MNG_KEY_CONFIG:
		name = (char *)TDH_MNG_KEY_CONFIG_NAME;
		break;
	case TDH_MNG_ADDCX:
		name = (char *)TDH_MNG_ADDCX_NAME;
		break;
	case TDH_SYS_INFO:
		name = (char *)TDH_SYS_INFO_NAME;
		break;
	case TDH_MNG_INIT:
		name = (char *)TDH_MNG_INIT_NAME;
		break;
	case TDH_VP_CREATE:
		name = (char *)TDH_VP_CREATE_NAME;
		break;
	case TDH_VP_ADDCX:
		name = (char *)TDH_VP_ADDCX_NAME;
		break;
	case TDH_VP_INIT:
		name = (char *)TDH_VP_INIT_NAME;
		break;
	case TDH_VP_WR:
		name = (char *)TDH_VP_WR_NAME;
		break;
	case TDH_MEM_SEPT_ADD:
		name = (char *)TDH_MEM_SEPT_ADD_NAME;
		break;
	case TDH_MEM_PAGE_ADD:
		name = (char *)TDH_MEM_PAGE_ADD_NAME;
		break;
	case TDH_MEM_PAGE_AUG:
		name = (char *)TDH_MEM_PAGE_AUG_NAME;
		break;
	case TDH_MEM_SEPT_RD:
		name = (char *)TDH_MEM_SEPT_RD_NAME;
		break;
	case TDH_MR_EXTEND:
		name = (char *)TDH_MR_EXTEND_NAME;
		break;
	case TDH_MR_FINALIZE:
		name = (char *)TDH_MR_FINALIZE_NAME;
		break;
	case TDH_VP_ENTER:
		name = (char *)TDH_VP_ENTER_NAME;
		break;
	case TDH_SERVTD_BIND:
		name = (char *)TDH_SERVTD_BIND_NAME;
		break;
	case TDH_SERVTD_PREBIND:
		name = (char *)TDH_SERVTD_PREBIND_NAME;
		break;
	case TDH_MNG_RD:
		name = (char *)TDH_MNG_RD_NAME;
		break;
	case TDH_MNG_WR:
		name = (char *)TDH_MNG_WR_NAME;
		break;
	case TDH_MEM_RD:
		name = (char *)TDH_MEM_RD_NAME;
		break;
	case TDH_SYS_RD:
		name = (char *)TDH_SYS_RD_NAME;
		break;
	case TDH_MEM_WR:
		name = (char *)TDH_MEM_WR_NAME;
		break;
	case TDH_VP_FLUSH:
		name = (char *)TDH_VP_FLUSH_NAME;
		break;
	case TDH_MNG_VPFLUSHDONE:
		name = (char *)TDH_MNG_VPFLUSHDONE_NAME;
		break;
	case TDH_VP_RD:
		name = (char *)TDH_VP_RD_NAME;
		break;
	case TDH_SYS_RDALL:
		name = (char *)TDH_SYS_RDALL_NAME;
		break;
	case TDH_MEM_PAGE_RELOCATE:
		name = (char *)TDH_MEM_PAGE_RELOCATE_NAME;
		break;
	case TDH_MEM_RANGE_BLOCK:
		name = (char *)TDH_MEM_RANGE_BLOCK_NAME;
		break;
	case TDH_MEM_RANGE_UNBLOCK:
		name = (char *)TDH_MEM_RANGE_UNBLOCK_NAME;
		break;
	case TDH_MEM_TRACK:
		name = (char *)TDH_MEM_TRACK_NAME;
		break;
	case TDH_MEM_PAGE_REMOVE:
		name = (char *)TDH_MEM_PAGE_REMOVE_NAME;
		break;
	case TDH_MEM_SEPT_REMOVE:
		name = (char *)TDH_MEM_SEPT_REMOVE_NAME;
		break;
	case TDH_PHYMEM_PAGE_RECLAIM:
		name = (char *)TDH_PHYMEM_PAGE_RECLAIM_NAME;
		break;
	case TDH_MEM_PAGE_DEMOTE:
		name = (char *)TDH_MEM_PAGE_DEMOTE_NAME;
		break;
	case TDH_MEM_PAGE_PROMOTE:
		name = (char *)TDH_MEM_PAGE_PROMOTE_NAME;
		break;
	default:
		LOG("unknown tdxcall name\n");
		exit(0);
		break;
	}
	TDXCALL_LOG("SEAMCALL %s ", name);
}

void print_tdcall_name(){
	char *name;

	switch (com->last_tdcall.tdxcall)
	{
	case TDG_VP_VMCALL:
		name = (char *)TDG_VP_VMCALL_NAME;
		break;
	case TDG_MEM_PAGE_ATTR_RD:
		name = (char *)TDG_MEM_PAGE_ATTR_RD_NAME;
		break;
	case TDG_MEM_PAGE_ATTR_WR:
		name = (char *)TDG_MEM_PAGE_ATTR_WR_NAME;
		break;
	case TDG_MEM_PAGE_ACCEPT:
		name = (char *)TDG_MEM_PAGE_ACCEPT_NAME;
		break;
	case TDG_MR_REPORT:
		name = (char *)TDG_MR_REPORT_NAME;
		break;
	case TDG_SYS_RD:
		name = (char *)TDG_SYS_RD_NAME;
		break;
	case TDG_SYS_RDALL:
		name = (char *)TDG_SYS_RDALL_NAME;
		break;
	case TDG_VM_RD:
		name = (char *)TDG_VM_RD_NAME;
		break;
	case TDG_VM_WR:
		name = (char *)TDG_VM_WR_NAME;
		break;
	case TDG_VP_WR:
		name = (char *)TDG_VP_WR_NAME;
		break;
	case TDG_VP_INVEPT:
		name = (char *)TDG_VP_INVEPT_NAME;
		break;
	case TDG_VP_INFO:
		name = (char *)TDG_VP_INFO_NAME;
		break;
	case TDG_VP_VEINFO_GET:
		name = (char *)TDG_VP_VEINFO_GET_NAME;
		break;
	case TDG_VP_CPUIDVE_SET:
		name = (char *)TDG_VP_CPUIDVE_SET_NAME;
		break;
	case TDG_VP_RD:
		name = (char *)TDG_VP_RD_NAME;
		break;
	case TDG_MR_RTMR_EXTEND:
		name = (char *)TDG_MR_RTMR_EXTEND_NAME;
		break;
	case TDG_SERVTD_WR:
		name = (char *)TDG_SERVTD_WR_NAME;
		break;
	case TDG_SERVTD_RD:
		name = (char *)TDG_SERVTD_RD_NAME;
		break;
	default:
		LOG("unknown tdcall name\n");
		exit(0);
		break;
	}
	TDXCALL_LOG("TDCALL %s ", name);
}

void log_mktme_error_and_exit(){

	ulong mod_running_td_ctx = com->td_owner_for_next_tdxcall;
	ulong pfn = ((com->khole_data.last_khole_edit_pte & ~(HKID_MASK)) & PTE_TO_PA_MASK) >> 12;
	ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);
	ulong page_owner_td = com->sreq.secPages[secure_page_idx].mdata.td;
	ulong hkid = (com->khole_data.last_khole_edit_pte & HKID_MASK) >> HKID_START_BIT;

	LOG("hkid: %lu\n", hkid);
	LOG("PTE: 0x%lx\n", com->khole_data.last_khole_edit_pte);
	LOG("sec pg idx: 0x%lx\n", secure_page_idx);
	LOG("sec pg pa: 0x%lx\n", (pfn << 12));

	switch (com->hcall_code)
	{
	case CODE_HKID_UNCONFIGURED:
	{
		LOG("\nTDXplorer ERROR: UNCONFIGURED HKID %lu for page 0x%lx\n", hkid, (pfn << 12));
	} break;
	case CODE_HKID_INVALID_FOR_PAGE:
	{
		LOG("\nTDXplorer ERROR: INVALID HKID %lu for page 0x%lx\n", hkid, (pfn << 12));
	} break;
	case CODE_HKID_INVALID_TD_CONTEXT:
	{
		LOG("\nTDXplorer ERROR: INVALID page 0x%lx (TD: %lu) for currently serving TD %lu context\n", (pfn << 12), page_owner_td, mod_running_td_ctx);
	} break;		
	default:
		break;
	}
	LOG(" exiting now...\n");
	exit(0);
}

void handle_hcall(){

	struct insInfo *ins_info;
	ulong rax;

	switch (com->hcall_no)
	{
		case HCALL_EMULATE_PSEAMLDR_INS:
		{	
			ins_info = (struct insInfo *)&com->int3_ins_info;
			/*validate insInfo*/
			if(com->current_sw == SEAM_SW_TDXMODULE){
				if((ins_info->insdata_idx >= TDXMODULE_SPECIAL_INS_COUNT) && (ins_info->int3_adr == 0)){
					LOG("ERR: invalid ins info\n");
				}
			}
			else{
				if((ins_info->insdata_idx >= PSEAMLDR_SPECIAL_INS_COUNT) && (ins_info->int3_adr == 0)){
					LOG("ERR: invalid ins info\n");
				}
			}
			emulate_ins(ins_info);
		}	break;
		case HCALL_MKTME_ERROR:
		{
			log_mktme_error_and_exit();
		} break;
		case HCALL_SEAM_ERROR:
		{
			log_seam_error_and_exit();
		} break;
		case HCALL_SEAMRET:
		{
		#ifdef MEASURE_TDXCALL_TIME
			t1 = rdtsc();
		#endif
			com->last_seamcall.return_status = get_saved_reg64(RAX);
			TDXCALL_LOG("########## CALL_COUNT: %04lu ", txcall_count);
			print_seamcall_name();
			TDXCALL_LOG("return code: %lx\n", com->last_seamcall.return_status); 
			/*TDXCALL_LOG("status: %lx %s \n", com->last_seamcall.return_status, 
								(get_saved_reg64(RAX) == SEAMCALL_SUCCESS) ? "SUCCESS" : "FAIL");*/
			#ifdef MEASURE_TDXCALL_TIME
				LOG("\n##time for tdx call: %lu\n\n", (t1 - t0));
			#endif
			print_tdx_ret_regs();
			txcall_count++;
	#ifdef INSTRUCTION_TRACER_ON
			LOG("\n# of instructions executted: ~%lu, regular:~%lu special:%lu\n", com->regular_ins_count + com->emulated_ins_count, com->regular_ins_count, com->emulated_ins_count);
	#endif
		} break;
		case HCALL_VMLAUNCH:
		{
		#ifdef MEASURE_TDXCALL_TIME
			t1 = rdtsc();
		#endif
			com->last_seamcall.return_status = get_saved_reg64(RAX);
			if(com->last_seamcall.return_status == SEAMCALL_SUCCESS){
				TDXCALL_LOG("########## VMLAUNCH TD %lu launched\n", com->td_owner_for_next_tdxcall);
			}
			TDXCALL_LOG("########## CALL_COUNT: %04lu ", txcall_count);
			print_seamcall_name();
			TDXCALL_LOG("return code: %lx\n", com->last_seamcall.return_status);
			/*TDXCALL_LOG("status: %lx %s \n", com->last_seamcall.return_status, 
								(com->last_seamcall.return_status == SEAMCALL_SUCCESS) ? "SUCCESS" : "FAIL");*/
		#ifdef MEASURE_TDXCALL_TIME
			LOG("\n##time for tdx call: %lu\n\n", (t1 - t0));
		#endif
			print_tdx_ret_regs();
			txcall_count++;
		} break;
		case HCALL_VMRESUME:
		{
		#ifdef MEASURE_TDXCALL_TIME
			t1 = rdtsc();
		#endif
			/*LOG("\n########## VMRESUME TD %d resumed \n", com->td_owner_for_next_tdxcall);*/
			com->last_tdcall.return_status = get_saved_reg64(RAX);
			TDXCALL_LOG("########## CALL_COUNT: %04lu ", txcall_count);
			print_tdcall_name();
			TDXCALL_LOG("return code: %lx\n", com->last_tdcall.return_status);
			/*TDXCALL_LOG("status: %lx %s \n", com->last_tdcall.return_status, 
								(get_saved_reg64(RAX) == SEAMCALL_SUCCESS) ? "SUCCESS" : "FAIL");*/
		#ifdef MEASURE_TDXCALL_TIME
			LOG("\n##time for tdx call: %lu\n\n", (t1 - t0));
		#endif
			print_tdx_ret_regs();
			txcall_count++;
		} break;
		case HCALL_TRACE_INS:
		{
			handle_trace_ins();
		} break;
		case HCALL_LOG:
		{
			handle_seam_log_request(com->hcall_code);
		} break;
		case HCALL_INSPECT_KHOLES:
		{
			inspect_keyholes_for_agent();
		} break;
		case HCALL_END_OF_ANALYSIS: {
			LOG("end of analysis, terminating TDXplorer\n");
			exit(0);
		}
		default:
		{
			debug_info();
			/*exit(0);*/
		} break;
	}
}

ulong do_tdxcall(ulong seamcall){

	for (;;) {
		
		if(com->last_seamcall.state == STATE_DO_SEAMCALL){
			TDXCALL_LOG("\n########## issuing ");
			print_seamcall_name();
			TDXCALL_LOG("\n");
			com->last_seamcall.state = STATE_ISSUED;
		#ifdef MEASURE_TDXCALL_TIME
			t0 = rdtsc();
		#endif
		}
		else if(com->last_tdcall.state == STATE_DO_TDCALL){
			TDXCALL_LOG("\n########## issuing ");
			print_tdcall_name();
			TDXCALL_LOG("\n");
			com->last_tdcall.state = STATE_ISSUED;
		#ifdef MEASURE_TDXCALL_TIME
			t0 = rdtsc();
		#endif		
		}
		if (ioctl(vcpu->fd, KVM_RUN, 0) < 0) {
			perror("KVM_RUN");
			exit(1);
		}

		switch (vcpu->kvm_run->exit_reason) {
			case KVM_EXIT_HLT:
			{
				handle_hcall();
				if(com->hcall_no == HCALL_SEAMRET){

					com->last_seamcall.state = STATE_SEAMRET_DONE;
					/*allways reset*/
					com->hcall_no = NO_HCALL;
					com->hcall_code = CODE_NONE;
					return com->last_seamcall.return_status;
				}
				else if(com->hcall_no == HCALL_VMLAUNCH){

					com->last_seamcall.state == STATE_VMLAUNCH_DONE;
					/*allways reset*/
					com->hcall_no = NO_HCALL;
					com->hcall_code = CODE_NONE;
					return com->last_seamcall.return_status;
				}
				else if(com->hcall_no == HCALL_VMRESUME){

					com->last_seamcall.state == STATE_VMRESUME_DONE;
					/*allways reset*/
					com->hcall_no = NO_HCALL;
					com->hcall_code = CODE_NONE;
					return com->last_tdcall.return_status;
				}
				/*allways reset*/
				com->hcall_no = NO_HCALL;
				com->hcall_code = CODE_NONE;
			} break;
			case KVM_EXIT_IO:
			{
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
					&& vcpu->kvm_run->io.port == 0xE9) {
					char *p = (char *)vcpu->kvm_run;
					fwrite(p + vcpu->kvm_run->io.data_offset,
						vcpu->kvm_run->io.size, 1, stdout);
					fflush(stdout);
					continue;
				}
			} break;
			case KVM_EXIT_HYPERCALL:
			{
				LOG("KVM_EXIT_HYPERCALL\n");
				continue;
			}
			default:{
				if(get_last_seam_env_reg(RIP) == com->sreq.seamret){
				#ifdef MEASURE_TDXCALL_TIME
					t1 = rdtsc();
				#endif
					com->last_tdcall.return_status = get_last_seam_env_reg(RAX);
					TDXCALL_LOG("########## CALL_COUNT: %04lu ", txcall_count);
					print_tdcall_name();
					TDXCALL_LOG("return code: %lx\n", com->last_tdcall.return_status);
					/*TDXCALL_LOG("status: %lx %s\n", 
					com->last_tdcall.return_status, 
								(com->last_tdcall.return_status == VMEXIT_REASON_TDCALL) ? "SUCCESS" : "FAIL");*/
				#ifdef MEASURE_TDXCALL_TIME
					LOG("\n##time for tdx call: %lu\n\n", (t1 - t0));
				#endif
					print_tdx_ret_regs();
					txcall_count++;
					return com->last_tdcall.return_status;
				}
				else{
					TDXCALL_LOG("unhandled exit reason ... :0x%x \n", vcpu->kvm_run->exit_reason);
					debug_info();
					exit(1);
				}
			}
		}
	}

	return -1;
}


void print_bases(){
	int lp = 0;
	LOG("\n");
	while(lp < NUM_ADDRESSIBLE_LPS){
		LOG("cur-LP:%lu LP:%d fs:%lx gs:%lx\n",com->current_lp, lp, com->seamcall_vmcs[lp].fsbase, com->seamcall_vmcs[lp].gsbase);
		lp++;
	}
}


void install_tdx_module(){

	ulong lp;
	ulong i_t0 = 0;
	ulong i_t1 = 0;

	LOG("\ninstalling tdx module\n");
	/*For TDX mod, a seamcall is a vmexit from vmm*/
	com->seamvmcs.vm_exit_reason = VMEXIT_REASON_SEAMCALL;

#ifdef MEASURE_MOD_INSTALL_TIME_AND_STOP
	i_t0 = rdtsc();
#endif
	lp = 0;
	while(lp < NUM_ADDRESSIBLE_LPS){
		com->current_lp = lp;
		switch_to_pseamldr_context(PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL);
		com->last_seamcall.tdxcall = PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL;
		do_tdxcall(PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL);
		lp++;
	}
#ifdef MEASURE_MOD_INSTALL_TIME_AND_STOP
	i_t1 = rdtsc();
	LOG("\ninstalling tdx module, completed\n");
	LOG("\n\nmodule installation, time cost: %lu\n", (i_t1 - i_t0));
	exit(0);
#endif
}

void set_max_pa(){

	uint32_t eax, ebx, ecx, edx;
	ulong max_pa_width;

    /*Get max physical and virtual address width*/
    asm volatile (
        "movl $0x80000008, %%eax \n\t"
        "cpuid \n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x80000008)                             
    );

    max_pa_width = eax & 0xFF;  // Bits 7:0 of EAX
    LOG("max physical address width: %lu bits\n", max_pa_width);
	if(max_pa_width < HKID_START_BIT){
		com->max_pa_bit_below_hkid = max_pa_width;
	}
	else{
		com->max_pa_bit_below_hkid = HKID_START_BIT - 1;;
	}
	assert(com->max_pa_bit_below_hkid);
    LOG("com->max_pa_bit_below_hkid: %lu\n", com->max_pa_bit_below_hkid);
}

void install_tdx_module_epilogue(){
	ulong tdx_module_cr3, next_seam_call, data_rgn_base, handoff_data_size, lp_id, lp_data_rgn_size;
	ulong lp_data_stack_size, lp_tot_stack_size, stack_rgn_base;
	uint32_t khole_edit_ins_adr[2];
	ulong seamret_adr, vmlaunch_adr, vmresume_adr;

	LOG("\ninstall tdx module epilogue\n");

	tdx_module_cr3 = get_region_base_pa(RGN_PML4); /*tdx module pml4 is adjacent to its stack region base pa*/
	update_s_emulator_pt(tdx_module_cr3); /*fuse entire tdx module linear address space with s_emulator*/
	update_tdx_sw_pt(tdx_module_cr3); /*map seam agent, idt & gdt to tdx module's address space*/

	/*moving the followig to take place in launch_interpreter() after the mappings are extracted to update interpreter's PTs*/
	// enable_khole_map_tracking(); /*Mark keyhole edit pages read only, to intercept writes during keyhole mappings*/
	
	instrument_seam_sw_code(SEAM_SW_TDXMODULE);
	get_tdx_special_ins_info();

#ifdef PRINT_SPECIAL_INSTRUCTIONS

	LOG("\n\nprinting spcial instruction, done\n");
	exit(0);
#endif

	get_khole_edit_ins_info(); /*expected to be done after mod install*/
	com->sreq.khole_edit_rip[0] = com->khole_data.idata[0].va;
	com->sreq.khole_edit_rip[1] = com->khole_data.idata[1].va;

	/*set the initial fsbase and gsbase for tdxmodule in com area. later, when switch_to_tdx_module_context() 
	sets the corresponding msrs of the seam env vCPU for the firt time, these values are used.
	At runtime, the tdx module updates the fsbase using a vmwrite( we ave not encountered a vmwrite to change gsbase yet)
	When that happens, these values in the com area are also updated at runtime.
	Later when switch_to_tdx_module_context() is called before each new tdxmod seamcall, it will use the fsbase and gsbase 
	from the com area to setup initial context. So the fsbase and gsbase values changes by one seamcall will persist for the
	next seam call to maintain state consistency across seamcalls.
	data_rgn_base = LINEAR_BASE_DATA_REGION | TDX_MODULE_ADR_MASK;
	/*this is how pseamldr computes handoff_data_size during module installation*/
	data_rgn_base = LINEAR_BASE_DATA_REGION | TDX_MODULE_ADR_MASK;
	lp_data_rgn_size = (TDX_MODULE_TLS_PAGES + 1)*_4K;
	/*this is how pseamldr computes handoff_data_size during module installation*/
	handoff_data_size = (TDX_MODULE_HANDOFF_DATA_PAGES + 1) * _4KB;

	lp_data_stack_size = (TDX_MODULE_STACK_PAGES + 1)*_4KB; /*(seam_sigstruct->num_stack_pages + 1) * _4KB*/
	lp_tot_stack_size = lp_data_stack_size + _4KB; /*tot stack size includes an extra 4K for shadow stack*/
	stack_rgn_base = (LINEAR_BASE_STACK_REGION | TDX_MODULE_ADR_MASK);
	/*Initialize per LP data*/
	lp_id = 0;
	while(lp_id < NUM_ADDRESSIBLE_LPS){

		/*initial fsbase*, as setup in LP vmcs by p-seamlder during tdxmod install*/
		com->seamcall_vmcs[lp_id].fsbase = (ulong)(LINEAR_BASE_SYSINFO_TABLE | TDX_MODULE_ADR_MASK);
		com->seamcall_vmcs[lp_id].gsbase = data_rgn_base + handoff_data_size + lp_id*lp_data_rgn_size;
		com->seamcall_vmcs[lp_id].rsp = stack_rgn_base + lp_data_stack_size + lp_id*lp_tot_stack_size - 0x8;
		/*per LP vmcs starts after the 4KB sysinfo page*/
		com->seamcall_vmcs[lp_id].vmcs_pa = SEAM_RANGE_START_PA + _4K + lp_id*_4K;
		lp_id++;
	}

	/*get tdx module entry point offsets*/
	com->tdxmod_seamcall_entry_offset = get_offset(OFFSET_TYPE_TDX_MOD_ENTRY_SEAMCALL);
	com->tdxmod_tdcall_entry_offset = get_offset(OFFSET_TYPE_TDX_MOD_ENTRY_TDCALL);

	/*prepare com area for Krover seam agent*/
	com->sreq.khole_start  = (LINEAR_BASE_KEYHOLE_REGION | TDX_MODULE_ADR_MASK);
	com->sreq.khole_size = _4K*(TDX_MODULE_KEYHOLE_PAGES + 1)*EFFECTIVE_NUM_ADDRESSIBLE_LPS;
	com->sreq.mod_code_rgn_start = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK);
	com->sreq.mod_stack_rgn_start = (LINEAR_BASE_STACK_REGION | TDX_MODULE_ADR_MASK);
	com->sreq.mod_data_rgn_start = (LINEAR_BASE_DATA_REGION | TDX_MODULE_ADR_MASK);

	get_khole_edit_ins_adrs(khole_edit_ins_adr);
	com->sreq.keyhole_edit_ins_adr[0] = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + khole_edit_ins_adr[0];
	com->sreq.keyhole_edit_ins_adr[1] = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + khole_edit_ins_adr[1];
	
	get_tdxcall_end_adrs(&seamret_adr, &vmlaunch_adr, &vmresume_adr);
	com->sreq.seamret = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + seamret_adr;
	com->sreq.vmlaunch = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + vmlaunch_adr;
	com->sreq.vmresume = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + vmresume_adr;

	get_key_hole_rgn_info(tdx_module_cr3);

	set_max_pa();
}

void seam_manage(){

	uint64_t pseamldr_cr3;

	com->se.interpreter_pt_updates_done = false;
	com->tdmr_next_avl_pa = TDX_TDMR0_START_PA;
	/*for tdxmodules own use we use the TDX_GLOBAL_PRIVATE_HKID. here, we get the next hkid available 
	in our emulation environment derived in advance for the first td*/
	com->next_td_hkid = TDX_GLOBAL_PRIVATE_HKID + 1;
	com->sept.sept_add_leaf_version = 1;
	com->sept.allow_existing = 0;
	com->seam_state = SEAM_STATE_NONE;
	com->se.target_owner = TARGET_OWNER_NONE;
	com->is_tdcall = 0;
	com->sreq.terminate = 0;
	/*reset instruction counters, used for tracing mode*/
	com->regular_ins_count = 0;
	com->emulated_ins_count = 0;

	com->current_sw = SEAM_SW_PSEAMLDR; /*this is how s_emulator knows the origin of the special ins*/
	install_tdx_module();
	install_tdx_module_epilogue();

	for(int i = 0; i < EFFECTIVE_NUM_ADDRESSIBLE_LPS; i++){ 
		com->sreq.td_num_on_lp[i] = 0xff; /*because LP_IDs start at 0, we initialize to ff*/
	}
	
	com->current_sw = SEAM_SW_TDXMODULE; /*Requests KRover manager to get seam mappings for Krover*/
	LOG("seam_manager's wait for interpreter's PT update: START\n");
	while (true)
	{
		if(com->se.interpreter_pt_updates_done == true)
			break;
	}
	LOG("seam_manager's wait for interpreter's PT update: END\n");

	update_sec_page_table();
    enable_khole_map_tracking(); 

	analyzer_function();

}

int main()
{
	pid_t pid;
	int status;
	uint64_t pseamldr_cr3;

	LOG("starting Monitor\n");
	do_sanity_checks();

	vm = mmap(NULL, sizeof(struct vm), PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (vm == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}
	vcpu = mmap(NULL, sizeof(struct vcpu), PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (vcpu == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}

	/*allocate memory for the vm, SEAM environment*/
	vm->mem = mmap(NULL, SEAM_ENV_PHY_MEM + SEAM_PHY_RANGE_2, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_NORESERVE | MAP_SHARED, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}
	/*vm-mem2 corresponds to the second range of contiguous physical memory 
	used for TD creation. The size of this range is SEAM_PHY_RANGE_2*/
	vm->mem2 = vm->mem + SEAM_ENV_PHY_MEM;
	LOG("seam manager's va for seam env pa: 0x%lx\n", (ulong)vm->mem);

	com = (struct comArea *)(vm->mem + SEAM_AGENT_MGR_SHARED_PA);
	memset((void *)com, 0, sizeof(struct comArea));
	memset((void *)com->sreq.secPages, 0, SECURE_PAGE_COUNT*8);
	com->hcall_no = NO_HCALL;
	com->hcall_code = CODE_NONE;
	com->regular_ins_count = 0;
	com->emulated_ins_count = 0;
	com->seam_env_ready = false;
	com->current_seed = INITIAL_RDSEED_SEED;
	
	vm_init();
	vcpu_init();
	do_64bit_specifics();
	LOG("preliminary seam environment prep done\n");

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

	/* Load P-SEAMLDR */
	LOG("loading p-seamloder\n");
	if(load_p_seamldr() == false){
		LOG("load_p_seamldr failed, exiting now ...\n");
		exit(0);
	}
	LOG("load p-seamldr successful ...\n");

	init_int3_stack_offset_array();
	init_instrumentation_module();

	/*instrument P-SEAMLDR*/
	if(instrument_seam_sw_code(SEAM_SW_PSEAMLDR) != 0){
		LOG("pseamldr code instrumentation failed\n");
		exit(0);
	}
	/*LOG("pseamldr code instrumentation successful ...\n");*/

	com->current_sw = SEAM_SW_PSEAMLDR; /*this is how s_emulator knows the origin of the special ins*/
	com->se.interpreter_pt_updates_done = false;
	com->seam_state = SEAM_STATE_NONE;
	com->single_step_on = false;
	com->request_to_read_seam = false;
	pseamldr_cr3 = SeamrrPtCtx.PtBaseAddrPa;
	update_s_emulator_pt(pseamldr_cr3);	/*fuse entire pseamldr linear address space with s_emulator*/
	update_tdx_sw_pt(pseamldr_cr3); /*map seam agent, gdt & idt to pseamldr*/

	pid = fork();
	switch (pid) {
		case -1:
			perror("fork");
			exit(EXIT_FAILURE);
		case 0: { /*child*/
			launch_interpreter();

			LOG("interpreter's core, exiting now\n");
			exit(EXIT_SUCCESS);
		}
		default: { /*parent*/
			LOG("executing Monitor/SEAM environment process\n");
			seam_manage();
			wait(0);

			LOG("ending seam environment, parent exiting ...\n");
			exit(EXIT_SUCCESS);
		}
	}

	return 1;
}
