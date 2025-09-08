#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "emulator.h"
#include "np_loader.h"
#include "configs.h"

int instrument_seam_sw_code(SEAM_SW sw);
void get_tdx_special_ins_info();
void init_instrumentation_module();
void get_khole_edit_ins_info();

extern int read_sw_objdump(struct file_data *fdata);
extern ulong get_offset(OFFSET_TYPE type);

extern struct comArea *com;
extern struct vm *vm;
extern struct vcpu *vcpu;

uint8_t pseamldr_so[] = "data/pseamldr/pseamldr.so.objdump";
uint8_t tdxmodule_so[] = "data/tdxmodule/libtdx.so.objdump";
uint8_t khole_edit_ins[] = "data/tdxmodule/libtdx-khole-edit-write.ins";

ulong seam_sw_code_pa;
uint8_t *ins_names[MAX_INS];
uint32_t ins_name_len[MAX_INS];
uint8_t *reg_64_names[MAX_REGS_64];

/*we must not instrument (bad) ins for tracing*/
char BAD_STR[]      = "(bad)";
ulong trace_skip_list[PSEAMLDR_TRACE_SKIP_COUNT] = {0};

char RDMSR_STR[]    = "rdmsr";
char WRMSR_STR[]    = "wrmsr";
char RDFSBASE_STR[] = "rdfsbase";
char RDGSBASE_STR[] = "rdgsbase";
char CPUID_STR[]    = "cpuid";
char SEAMOPS_STR[]  = "seamops"; /*special handling during extraction from objdump*/
char SEAMRET_STR[]  = "seamret"; /*special handling during extraction from objdump*/
char VMCLEAR_STR[]  = "vmclear";
char VMREAD_STR[]   = "vmread";
char VMWRITE_STR[]  = "vmwrite";
char VMLAUNCH_STR[] = "vmlaunch";
char VMRESUME_STR[] = "vmresume";
char VMPTRLD_STR[]  = "vmptrld";
char INVLPG_STR[]   = "invlpg";
char INVEPT_STR[]   = "invept";
char INVVPID_STR[]  = "invvpid";
char INT_STR[]      = "int";
char RDRAND_STR[]   = "rdrand";
char RDSEED_STR[]   = "rdseed";
char CFLUSHOPT_STR[]= "cflushopt";
char PCONFIG_STR[]  = "pconfig";
char XGETBV_STR[]   = "xgetbv";
char MOVDIR64B_STR[]= "movdir64b";
char DATA16_STR[]   = "data16";

char RAX_STR[]      = "rax";
char RBX_STR[]      = "rbx";
char RCX_STR[]      = "rcx";
char RDX_STR[]      = "rdx";
char RDI_STR[]      = "rdi";
char RSI_STR[]      = "rsi";
char R8_STR[]       = "r8";
char R9_STR[]       = "r9";
char R10_STR[]      = "r10";
char R11_STR[]      = "r11";
char R12_STR[]      = "r12";
char R13_STR[]      = "r13";
char R14_STR[]      = "r14";
char R15_STR[]      = "r15";
char RBP_STR[]      = "rbp";
char RIP_STR[]      = "rip";
char RSP_STR[]      = "rsp";

uint8_t SEAMRET_HEX[] = {0x66, 0x0F, 0x01, 0xCD};
uint8_t SEAMOPS_HEX[] = {0x66, 0x0F, 0x01, 0xCE};

/*we do not treat movdir64b to be a special instruction as of now. if cpu can not execute, treat as such*/
uint8_t MOVDIR64B_HEX[] = {0x66, 0x0F, 0x38, 0xF8,/*movdir64b op*/ 0x37/*ModRM = RDI->RSI*/};

ulong ipp_crypto_start_offset = 0;

void init_reg_64_names_array(){
    reg_64_names[RAX]   = RAX_STR;
    reg_64_names[RBX]   = RBX_STR;
    reg_64_names[RCX]   = RCX_STR;
    reg_64_names[RDX]   = RDX_STR;
    reg_64_names[RDI]   = RDI_STR;
    reg_64_names[RSI]   = RSI_STR;
    reg_64_names[R8]    = R8_STR;
    reg_64_names[R9]    = R9_STR;
    reg_64_names[R10]   = R10_STR;
    reg_64_names[R11]   = R11_STR;
    reg_64_names[R12]   = R12_STR;
    reg_64_names[R13]   = R13_STR;
    reg_64_names[R14]   = R14_STR;
    reg_64_names[R15]   = R15_STR;
    reg_64_names[RBP]   = RBP_STR;
    reg_64_names[RIP]   = RIP_STR;    
    reg_64_names[RSP]   = RSP_STR;  
}

void init_ins_names_array(){

    ins_names[RDMSR]    = RDMSR_STR;
    ins_names[WRMSR]    = WRMSR_STR;
    ins_names[RDFSBASE] = RDFSBASE_STR;
	ins_names[RDGSBASE] = RDGSBASE_STR;
	ins_names[CPUID]    = CPUID_STR;
	ins_names[SEAMOPS]  = SEAMOPS_STR;
	ins_names[SEAMRET]  = SEAMRET_STR;
	ins_names[VMCLEAR]  = VMCLEAR_STR;
	ins_names[VMREAD]   = VMREAD_STR;
	ins_names[VMWRITE]  = VMWRITE_STR;
    ins_names[VMLAUNCH] = VMLAUNCH_STR;
    ins_names[VMRESUME] = VMRESUME_STR;
    ins_names[VMPTRLD]  = VMPTRLD_STR;
	// ins_names[INVLPG]   = INVLPG_STR;
    ins_names[INVEPT]   = INVEPT_STR;
    ins_names[INVVPID]  = INVVPID_STR;
	/*ins_names[INT]      = INT_STR;*/
    ins_names[RDRAND]   = RDRAND_STR;
    ins_names[RDSEED]   = RDSEED_STR;
    ins_names[CFLUSHOPT]= CFLUSHOPT_STR;
    ins_names[PCONFIG]  = PCONFIG_STR;
#ifdef EMULATE_XGETBV
    ins_names[XGETBV]   = XGETBV_STR;
#endif
#ifdef EMULATE_MOVDIR64B
    ins_names[MOVDIR64B]= MOVDIR64B_STR;
#endif
    ins_names[DATA16]   = DATA16_STR;

    ins_name_len[RDMSR]    = strlen(RDMSR_STR);
    ins_name_len[WRMSR]    = strlen(WRMSR_STR);
    ins_name_len[RDFSBASE] = strlen(RDFSBASE_STR);
	ins_name_len[RDGSBASE] = strlen(RDGSBASE_STR);
	ins_name_len[CPUID]    = strlen(CPUID_STR);
	ins_name_len[SEAMOPS]  = strlen(SEAMOPS_STR);
	ins_name_len[SEAMRET]  = strlen(SEAMRET_STR);
	ins_name_len[VMCLEAR]  = strlen(VMCLEAR_STR);
	ins_name_len[VMREAD]   = strlen(VMREAD_STR);
	ins_name_len[VMWRITE]  = strlen(VMWRITE_STR);
    ins_name_len[VMLAUNCH] = strlen(VMLAUNCH_STR);
    ins_name_len[VMRESUME] = strlen(VMRESUME_STR);
    ins_name_len[VMPTRLD]  = strlen(VMPTRLD_STR);
	// ins_name_len[INVLPG]   = strlen(INVLPG_STR);
    ins_name_len[INVEPT]   = strlen(INVEPT_STR);
    ins_name_len[INVVPID]  = strlen(INVVPID_STR);
	/*ins_name_len[INT]      = strlen(INT_STR);*/
    ins_name_len[RDRAND]   = strlen(RDRAND_STR);
    ins_name_len[RDSEED]   = strlen(RDSEED_STR);
    ins_name_len[CFLUSHOPT]= strlen(CFLUSHOPT_STR);
    ins_name_len[PCONFIG]  = strlen(PCONFIG_STR);
#ifdef EMULATE_XGETBV
    ins_name_len[XGETBV]   = strlen(XGETBV_STR);
#endif
#ifdef EMULATE_MOVDIR64B
    ins_name_len[MOVDIR64B]= strlen(MOVDIR64B_STR);
#endif
    ins_name_len[DATA16]   = strlen(DATA16_STR);
    
    }

/*given a number, returns the resultant string length when converted to hex
eg: num = 300 -> 0x12c, so return length = 3*/
int hex_str_len(uint64_t num){
    int i = 0;
    int val = 1;
    while(val <= num){
        val *= 16;
        i++;
    }
    return i;
}

REGS_64 get_reg_64(ulong adr){

    ulong reg_name, reg_str_start;

    reg_str_start = adr;
    while((*(uint8_t *)(adr) != ',') && (*(uint8_t *)(adr) != '\n') && (*(uint8_t *)(adr) != ')')){
        adr++; 
    }

    for(reg_name = NO_REG_64 + 1; reg_name < MAX_REGS_64; reg_name++){
        if(strncmp(reg_64_names[reg_name], (uint8_t *)reg_str_start, adr - reg_str_start) == 0){
            return (REGS_64)reg_name;
        }
    }

    return NO_REG_64;
}

uint64_t extract_mem_operand(ulong adr, OP *op){
    
    uint64_t    ofst;
    uint32_t    ofst_hex_len;
    REGS_64     reg;
    int         reg_name_len;

    if(*(uint8_t *)adr == '0' && *(uint8_t *)(adr + 1) == 'x'){
        adr+= 2;
        ofst = strtol((uint8_t *)adr, NULL, 16);
        op->is_addr = true;
        op->offset = ofst;
        ofst_hex_len = hex_str_len(ofst);
        // LOG("ofst: 0x%lx length of hex representation: %d\n", ofst, ofst_hex_len);
        
        adr += ofst_hex_len;
    }
    else{
        op->is_addr = true;
        op->offset = 0;
    }

    if(*(uint8_t *)adr != '(' || *(uint8_t *)(adr + 1) != '%'){
        LOG("expected a left bracket followed by a percentage character\n");
        return 0;
    }
    adr +=2;
    reg = get_reg_64(adr);
    if(reg == NO_REG_64){
        LOG("get_reg_64 failed\n");
        return 0;
    }
    op->reg = reg;
    reg_name_len = strlen(reg_64_names[reg]);
    adr += (reg_name_len + 1); /*add 1 to move in to right bracket position*/

    return adr;
}

uint64_t extract_reg_operand(ulong adr, OP *op){

    REGS_64     reg;
    int         reg_name_len;
    
    if(*(uint8_t *)adr != '%'){
        LOG("expected percentage character\n");
        return 0;
    }
    adr++; 
    reg = get_reg_64(adr); 
    if(reg == NO_REG_64){
        LOG("get_reg_64 failed\n");
        return 0;
    }
    op->reg = reg;
    op->is_addr = false;
    reg_name_len = strlen(reg_64_names[reg]);
    adr += reg_name_len;

    return adr;
}

uint64_t extract_reg_from_operand(ulong adr, REGS_64 *r){

    REGS_64     reg;
    int         reg_name_len;

    if(*(uint8_t *)adr != '%'){
        LOG("expected percentage character\n");
        return 0;
    }
    adr++;
    reg = get_reg_64(adr);
        if(reg == NO_REG_64){
        LOG("get_reg_64 failed\n");
        return 0;
    }
    *r = reg;
    reg_name_len = strlen(reg_64_names[reg]);
    adr += reg_name_len;

    return adr;
}

/*We only implement operand extraction for instrucions we encounter during experiments.
returns -1 for errors*/
int extract_operand_info(struct insData *idata, ulong adr){

    REGS_64     reg;
    int         reg_name_len;
    uint64_t    ofst;
    uint32_t    ofst_hex_len;

    switch (idata->in)
    {
        case RDFSBASE:
        case RDGSBASE:
        case RDRAND:
        case RDSEED:
        {           
#ifdef INSTRUMENTATION_LOG_ON
            LOG("%s ", ins_names[idata->in]);
#endif
            adr = extract_reg_operand(adr, &idata->op0);
            if (adr == 0)
            {
                LOG("extract_reg_operand failed \n");
                return -1;
            }
            idata->operands_extracted = true;
#ifdef INSTRUMENTATION_LOG_ON
            LOG("operand op0:%s detected\n", reg_64_names[idata->op0.reg]);
#endif
        } break;
#ifdef EMULATE_MOVDIR64B
        case MOVDIR64B:
        {
            /*movdir64b (%rdi),%rsi*/
#ifdef INSTRUMENTATION_LOG_ON
            LOG("%s ", ins_names[idata->in]);
#endif
            /*the first operand is a memory address in a reg*/
            if((*(uint8_t *)adr == '0' && *(uint8_t *)(adr + 1) == 'x') || (*(uint8_t *)adr == '(')){
                adr = extract_mem_operand(adr, &idata->op0);
            }
            if(adr == 0){
                LOG("extract_mem_operand failed \n");
                return -1;
            }

            if(*(uint8_t *)adr != ','){
                LOG("expected a comma character\n");
                return -1;
            }
            adr++;

            /*next operand is a reg*/
            adr = extract_reg_operand(adr, &idata->op1);
            if (adr == 0){
                LOG("extract_reg_operand failed \n");
                return -1;
            }
            idata->operands_extracted = true;
#ifdef INSTRUMENTATION_LOG_ON
            LOG("operands op0:0x%lx(%s) op1:%s\n", idata->op0.offset, reg_64_names[idata->op0.reg], reg_64_names[idata->op1.reg]);
#endif 
        } break;
#endif /*EMULATE_MOVDIR64B*/
        case VMREAD:
        {
            /*  vmread %rax,0x10(%rsp)    or
                vmread %rax,%rbx
                src operand is a r64 , destination r/m64*/
#ifdef INSTRUMENTATION_LOG_ON
            LOG("%s ", ins_names[idata->in]);
#endif
            adr = extract_reg_operand(adr, &idata->op0);
            if (adr == 0)
            {
                LOG("extract_reg_operand failed \n");
                return -1;
            }
            if(*(uint8_t *)adr != ','){
                LOG("expected a comma character\n");
                return -1;
            }
            adr++;
            /*next, it could be a r64 (eg %rax) or m64 (eg 0x10(%rsp or (%rsp)  ))
            currently we do not handle if the offset is negative and in the form of
            -0x10(%rsp, will probably cause an error)
            */
            if((*(uint8_t *)adr == '0' && *(uint8_t *)(adr + 1) == 'x') || (*(uint8_t *)adr == '(')){
                adr = extract_mem_operand(adr, &idata->op1);
                if (adr == 0)
                {
                    LOG("extract_mem_operand failed \n");
                    return -1;
                }
                idata->operands_extracted = true;
#ifdef INSTRUMENTATION_LOG_ON
                LOG("operands op0:%s op1:0x%lx %s\n", reg_64_names[idata->op0.reg], idata->op1.offset, reg_64_names[idata->op1.reg]);
#endif            
            }
            else if(*(uint8_t *)adr == '%'){
                LOG("TODO extract_operand_info:%s\n", ins_names[idata->in]);
                return -1;
            }
            else{
                LOG("expected 0x or ( characters\n");
                return -1;
            }

        } break;
        case VMWRITE:
        {
            /* vmwrite 0x10(%rsp), %rax,    or
                vmwrite %rax,%rbx
                src operand is  r/m64 destination is r64 */
#ifdef INSTRUMENTATION_LOG_ON
            LOG("%s ", ins_names[idata->in]);
#endif
            if(*(uint8_t *)adr == '%'){
                adr = extract_reg_operand(adr, &idata->op0);

                if (adr == 0)
                {
                    LOG("extract_reg_operand failed \n");
                    return -1;
                }
                if(*(uint8_t *)adr != ','){
                    LOG("expected a comma character\n");
                    return -1;
                }
                adr++;
#ifdef INSTRUMENTATION_LOG_ON
                LOG("operand op0:%s ", reg_64_names[idata->op0.reg]);
#endif
            }
            else if((*(uint8_t *)adr == '0' && *(uint8_t *)(adr + 1) == 'x') || (*(uint8_t *)adr == '(')){
                LOG("TODO extract_operand_info:%s\n", ins_names[idata->in]);
                return -1;
            }
            else{
                LOG("expected 0x or ( characters\n");
                return -1;
            }

            /*next operand is always r64*/
            adr = extract_reg_operand(adr, &idata->op1);
            if (adr == 0)
            {
                LOG("extract_reg_operand failed \n");
                return -1;
            }
            idata->operands_extracted = true;
#ifdef INSTRUMENTATION_LOG_ON
            LOG("operand op01:%s\n", reg_64_names[idata->op1.reg]);
#endif

        } break;
        case VMPTRLD:
        {
            /*vmptrld 0x20(%rsp)
              vmptrld (%rsp)
              One operand and it is a memory location.*/
            if((*(uint8_t *)adr == '0' && *(uint8_t *)(adr + 1) == 'x') || (*(uint8_t *)adr == '(')){
                adr = extract_mem_operand(adr, &idata->op0);
                if (adr == 0)
                {
                    LOG("extract_mem_operand failed \n");
                    return -1;
                }
                idata->operands_extracted = true;
#ifdef INSTRUMENTATION_LOG_ON
                LOG("operand op0:0x%lx %s\n", idata->op0.offset, reg_64_names[idata->op0.reg]);
#endif            
            }
        } break;
        default:
            break;
    }

    return 0;
}

ulong offset_to_va(ulong offset, SEAM_SW sw){

    ulong va;
    
    if(sw == SEAM_SW_PSEAMLDR){
        va = offset + C_CODE_RGN_BASE + (((UINT64)(NP_SEAMLDR_ASLR_SEED & ASLR_MASK)) << 32);
    }
    else{
        va = offset + LINEAR_BASE_CODE_REGION + (((UINT64)(PSEAMLDR_RDRAND_VAL & ASLR_MASK)) << 32);
    }

    return va;
}

void extract_all_ins_data(SEAM_SW sw, ulong start, ulong bin_size){
    ulong ofst, line_start, ins_count, obj;
    uint32_t size;
    struct insData *idata_all;

    if(sw == SEAM_SW_PSEAMLDR){
        idata_all = (struct insData *)com->pseamldr_total_ins;
    }
    else{
        idata_all = (struct insData *)com->tdxmodule_total_ins;
        LOG("\n\nextract_all_ins_data\n\n");
    }

    obj = start;
    line_start = obj;
    ins_count = 0;
    while(obj < (ulong)start + bin_size){
        ofst = strtol((uint8_t *)line_start, NULL, 16);

        // if(sw == SEAM_SW_TDXMODULE)
        //     LOG("all ofst:0x%lx\n", ofst);

        if((sw == SEAM_SW_TDXMODULE) && (ofst >= ipp_crypto_start_offset)){
            break;
        }
        idata_all[ins_count].offset = ofst;
        // if(ins_count < 100)
        //     LOG("offset:0x%lx\n", idata_all[ins_count].offset);

        while(*(uint8_t *)(obj) != '\n'){
            obj++;
        }
        line_start = obj++;
        size = strtol((uint8_t *)line_start, NULL, 16) - idata_all[ins_count].offset;

        idata_all[ins_count].size = size;

        // if(ins_count < 100)
        //     LOG("size:%d\n", idata_all[ins_count].size);

        idata_all[ins_count].operands_extracted = false;
        idata_all[ins_count].va = offset_to_va(ofst, sw);
        ins_count++;
        // if(ins_count < 100){
        //     LOG("offset:0x%lx size:%d\n", idata_all[ins_count-1].offset, idata_all[ins_count-1].size);
        // }
    }
}

struct insData * extract_ins_data(SEAM_SW sw){

    int fd;
    ulong size, obj, line_start, ins_str_start, ofst, ins_name, ins_count, line, adr, trc_skip_count;
    uint8_t *objd;
    struct insData *idata;
    struct file_data fdata;
    
    if(sw == SEAM_SW_PSEAMLDR){
        idata = (struct insData *)(com->pseamldr_ins);
        fdata.fname = (uint8_t *)&pseamldr_so;
    }
    else{
        idata = (struct insData *)(com->tdxmodule_ins);
        fdata.fname = (uint8_t *)&tdxmodule_so;
    }
    
    /*LOG("seam_sw_code_pa:0x%lx\n", seam_sw_code_pa);*/

    read_sw_objdump(&fdata);
    size = fdata.size;
    fd = fdata.fd;

    objd = mmap(NULL, size, PROT_READ , MAP_SHARED, fd, 0);
	if (objd == MAP_FAILED) {
        LOG("mmap failed\n");
        goto exit;
	}

    /*read objdump and extract details*/
    line = 0;
    ins_count = 0;
    trc_skip_count = 0;
    obj = (ulong)objd;
    line_start = obj;

#ifdef INSTRUCTION_TRACER_ON
    extract_all_ins_data(sw, (ulong)objd, size);
#endif

    while(obj < (ulong)objd + size){        

        line++;
        /*LOG("LINE:0x%lx\n", line);*/
        while(*(uint8_t *)(obj) != ':'){
            obj++;
        }

        obj++;
        if(*(uint8_t *)(obj) != '\t'){
            LOG("expected tab character\n");
            goto exit;
        }

        obj++;
        ins_str_start = obj;
        while(*(uint8_t *)(obj) != ' '){
            obj++;
        }
        
        ofst = strtol((uint8_t *)line_start, NULL, 16);
        for(ins_name = START_INS + 1; ins_name < MAX_INS; ins_name++){
            if(strncmp(ins_names[ins_name], (uint8_t *)ins_str_start, ins_name_len[ins_name]) == 0){
                errno = 0;
                ofst = strtol((uint8_t *)line_start, NULL, 16);
                // LOG("ofst2 : 0x%lx ", ofst);

                if(sw == SEAM_SW_TDXMODULE && ofst >= ipp_crypto_start_offset){
                    if(ins_name != CPUID){
                        break;
                    }
                }

                // if(sw == SEAM_SW_TDXMODULE && ofst >= ipp_crypto_start_offset){
                //     LOG("\n\nbeyond--------------------------------------------\n\n");
                // }

                if(errno != 0){
                    LOG("strtol() error\n");
                    goto exit;
                }
                if(ins_name == DATA16){
                    adr = (ulong)vm->mem + seam_sw_code_pa + ofst;
                    if(strncmp((uint8_t *)adr, (uint8_t *)SEAMRET_HEX, 0x4) == 0){
                        idata[ins_count].in = SEAMRET;
                    }
                    else if(strncmp((uint8_t *)adr, (uint8_t *)SEAMOPS_HEX, 0x4) == 0){
                        idata[ins_count].in = SEAMOPS;
                    }
                    else{
#ifdef INSTRUMENTATION_LOG_ON
                        LOG("data16 is not seamret or seamops\n");
#endif
                    }
                }
                else{
                    idata[ins_count].in = ins_name;
                }
                
                if(idata[ins_count].in > START_INS){
                    idata[ins_count].offset = ofst;
                    idata[ins_count].va = offset_to_va(ofst, sw);

                    /*extract operand info for specific instructions now*/
                    while(*(uint8_t *)(obj) == ' '){
                        obj++;
                    }
                    if(extract_operand_info(&idata[ins_count], obj) < 0){
                        LOG("operand info extraction error\n");
                        goto exit;
                    }
#ifdef INSTRUMENTATION_LOG_ON
                    LOG("INS %4s\tfound sp ins count:%lu >> ", ins_names[idata[ins_count].in], ins_count);
#endif                    
                }
                break;
            }
        }

#ifdef INSTRUCTION_TRACER_ON
        if(ofst < ipp_crypto_start_offset){
            if(strncmp(BAD_STR, (uint8_t *)ins_str_start, obj - ins_str_start) == 0){
                trace_skip_list[trc_skip_count] = strtol((uint8_t *)line_start, NULL, 16);
                trc_skip_count++;
            }
        }
#endif
        // if(ofst == 0x3f5f4){
        //     LOG("\n\nhere \n");
        //     exit(0);
        // }

        while(*(uint8_t *)(obj) != '\n'){
            obj++;
        }
        line_start = obj++;
        if(idata[ins_count].in > START_INS){

            if(idata[ins_count].in == SEAMRET | idata[ins_count].in == SEAMOPS){
                idata[ins_count].size = 0x4;
            }
            else{
                errno = 0;
                idata[ins_count].size = strtol((uint8_t *)line_start, NULL, 16) - idata[ins_count].offset;
                if(errno != 0){
                    LOG("strtol() error\n");
                    goto exit;
                }
            }
#ifdef INSTRUMENTATION_LOG_ON
            LOG("offset:0x%lx\tva:0x%lx\tsize:0x%x\n", idata[ins_count].offset, idata[ins_count].va, idata[ins_count].size);
#endif            
            ins_count++;
        }
        // LOG("round end\n");
    }

    if(close(fd) == -1){
        LOG("unable to close %s\n", fdata.fname);
    }

    return idata;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fdata.fname);
    }
    return NULL;
}

int instrument_code(SEAM_SW sw){

    ulong ins_count;
    uint8_t int3_opcode = 0xcc;
    uint8_t nop_opcode = 0x90;
    int position;
    uint8_t first_byte;
    ulong skip_trc_count, max_sp_ins, max_tot_ins;
    uint8_t skip_ins;   
    struct insData *idata;
    struct insData *idata_all;

    if(sw == SEAM_SW_PSEAMLDR){
        idata = (struct insData *)(com->pseamldr_ins);
        idata_all = (struct insData *)(com->pseamldr_total_ins);
        max_sp_ins = PSEAMLDR_SPECIAL_INS_COUNT;
        max_tot_ins = PSEAMLDR_TOTAL_INS_COUNT;
    }
    else if(sw == SEAM_SW_TDXMODULE){
        idata = (struct insData *)(com->tdxmodule_ins);
        idata_all = (struct insData *)(com->tdxmodule_total_ins);
        max_sp_ins = TDXMODULE_SPECIAL_INS_COUNT;
        max_tot_ins = TDXMODULE_TOTAL_INS_COUNT;
    }

    ins_count = 0;
    while((ins_count < max_sp_ins) && (idata[ins_count].size != 0)){ /*for all valid struct buffer entries*/
        /*After backing up, the first byte of the special instruction is replaced by int3*/
        idata[ins_count].first_byte = *(uint8_t *)(vm->mem + seam_sw_code_pa + idata[ins_count].offset);
        *(uint8_t *)(vm->mem + seam_sw_code_pa + idata[ins_count].offset) = int3_opcode;
        // LOG("offset:%lx\n", idata[ins_count].offset);

        /*Remaing bytes of the special instruction are made nop*/
        /*commenting this functionality as now seam agent updates the rip to point to the next instruction
        after a special instruction has been emulated
        position = 1;
        while(position < (idata[ins_count].size)){
            *(uint8_t *)(vm->mem + seam_sw_code_pa + idata[ins_count].offset + position) = nop_opcode;
            position++;
        }*/


    //    //debug
    //     if(sw == SEAM_SW_TDXMODULE){

    //         if(idata[ins_count].va == 0xffffa0000001e56f){
    //             printf("found ...............\n");
    //         }
    //         printf("%03lu :%lx \n", ins_count, idata[ins_count].va);
    //     }

        ins_count++;
    }

    // //debug
    // if(sw == SEAM_SW_TDXMODULE){

    //     printf("exitting ...............\n");
    //     exit(0);
    // }

    if(ins_count == 0){
        LOG("Nothing to instrument\n");
        return -1;
    }
    else{
        /*LOG("special instructuons count: %lu\n", ins_count);*/
    }

#ifdef INSTRUCTION_TRACER_ON
    ins_count = 0;

    
    while((ins_count < max_tot_ins) && (idata_all[ins_count].size != 0)){

        /*	due to some limitations in objdump, the object dump contains some instructions as "(bad)"
            we skip instrumenting this instruction for traceing, as it sometimes affects its predessor's execution*/
        skip_trc_count = 0;
        skip_ins = 0;
        while(trace_skip_list[skip_trc_count] != 0){
            if(idata_all[ins_count].offset == trace_skip_list[skip_trc_count]){
                skip_ins = 1;
                LOG("offset: %lx\n", trace_skip_list[skip_trc_count]);
                break;
            }
            skip_trc_count++;
        }
        if(skip_ins == 1){
            ins_count++;
            continue;
        }

        first_byte = *(uint8_t *)(vm->mem + seam_sw_code_pa + idata_all[ins_count].offset);
        if(first_byte != 0xcc){
            idata_all[ins_count].first_byte = first_byte;
            *(uint8_t *)(vm->mem + seam_sw_code_pa + idata_all[ins_count].offset) = int3_opcode;
        }
        ins_count++;
    }
#endif 
    /*place int3 for debug purposses, REMEMBER TO REMOVE*/
    /*
    *(uint8_t *)(vm->mem + seam_sw_code_pa + 0xe07) = 0xf4;
    ins_count = 0;
    while(ins_count < 5){
        *(uint8_t *)(vm->mem + seam_sw_code_pa + 0x2d1a + ins_count) = nop_opcode;
        ins_count++;
    }
    */


    return 0;
}

void init_instrumentation_module(){
    init_ins_names_array();
    init_reg_64_names_array();
}

ulong extract_reg_from_op(ulong obj, REGS_64 *reg){

    obj = extract_reg_from_operand(obj, reg);
    if (obj == 0)
    {
        LOG("extract_reg_operand failed \n");
        return -1;
    }
    if(*(uint8_t *)obj != ','){
        LOG("expected a comma character\n");
        return -1;
    }
    obj++;
    
    return obj;
}

void get_khole_edit_ins_info(){

    uint8_t objd[128];
    int fd, cnst;
    ulong size, obj, row, ins_str_start, row_start, ofst;
    struct file_data fdata;
    fdata.fname = (uint8_t *)&khole_edit_ins;

    read_sw_objdump(&fdata);
    size = fdata.size;
    fd = fdata.fd;

    if(read(fd, (void *)(&objd), size) != size){
        LOG("%s read error\n", fdata.fname);
        goto exit;
    }

    obj = (ulong)objd;
    row = 0;
    row_start = obj;
    while(obj < (ulong)objd + size && row < 2){

        while(*(uint8_t *)(obj) != ':'){
            obj++;
        }

        obj++;
        if(*(uint8_t *)(obj) != '\t'){
            LOG("expected tab character\n");
            goto exit;
        }

        obj++;
        ins_str_start = obj;
        while(*(uint8_t *)(obj) != ' '){
            obj++;
        }
        if(obj - ins_str_start != 3){
            LOG("expected a 3 char ins (mov)\n");
            goto exit;
        }

        ofst = strtol((uint8_t *)row_start, NULL, 16);
        /*printf("ofst %lx\n", ofst);*/

        com->khole_data.idata[row].offset = ofst;
        com->khole_data.idata[row].va = offset_to_va(ofst, SEAM_SW_TDXMODULE);
        /*printf("ofst %lx\n", com->khole_data.idata[row].offset);*/

        while(*(uint8_t *)(obj) == ' '){
            obj++;
        }

        obj = extract_reg_from_op(obj, &com->khole_data.idata[row].reg0);
        if(*(uint8_t *)obj != '('){
            LOG("expected a '(' character\n");
            goto exit;
        }
        obj++;

        obj = extract_reg_from_op(obj, &com->khole_data.idata[row].reg1);
        obj = extract_reg_from_op(obj, &com->khole_data.idata[row].reg2);
        cnst = strtol((uint8_t *)obj, NULL, 16);
        com->khole_data.idata[row].cnst = cnst;

        while(*(uint8_t *)(obj) != '\n'){
            obj++;
        }
        row_start = obj++;
        row++;

    }

    if(close(fd) == -1){
        LOG("unable to close %s\n", fdata.fname);
    }
    return;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fdata.fname);
    }
    exit(0);
}

void get_tdx_special_ins_info() {

    int count = 0;
    struct insData * tdx_sp_ins = (struct insData *)com->tdxmodule_ins;
    struct iData * idata = (struct iData *)com->tdx_ins;

    while(tdx_sp_ins[count].size != 0 && count < TDXMODULE_SPECIAL_INS_COUNT){
        idata[count].va = tdx_sp_ins[count].va;
        idata[count].size = tdx_sp_ins[count].size;
        idata[count].first_byte = tdx_sp_ins[count].first_byte;
        count++;
    }
    if(count == 0){
        printf("No special instructions in tdx mod\n");
        exit(0);
    }
}

int instrument_seam_sw_code(SEAM_SW sw){

    /*LOG("at instrument_seam_sw_code\n");*/

    struct insData *idata;
    int status;
    ulong max_sp_ins, max_tot_ins;

    if(sw == SEAM_SW_PSEAMLDR){
        seam_sw_code_pa = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - (SeamldrData.PSeamldrConsts->CCodeRgnSize + C_P_SYS_INFO_TABLE_SIZE);
        max_sp_ins = PSEAMLDR_SPECIAL_INS_COUNT;
        max_tot_ins = PSEAMLDR_TOTAL_INS_COUNT;
    }
    else if(sw == SEAM_SW_TDXMODULE){
        seam_sw_code_pa = SeamldrData.SeamrrBase + MODULE_RANGE_SIZE - SEAMRR_MODULE_CODE_REGION_SIZE;
        max_sp_ins = TDXMODULE_SPECIAL_INS_COUNT;
        max_tot_ins = TDXMODULE_TOTAL_INS_COUNT;
        ipp_crypto_start_offset = get_offset(OFFSET_TYPE_IPP_CRYPTO_START);
        /*LOG("ipp_crypto_start_offset : 0x%lx\n", ipp_crypto_start_offset);*/
        if(ipp_crypto_start_offset == 0){
            LOG("invalid ipp_crypto_start_offset\n");
            exit(0);
        }
    }
    else{
        LOG("invalid SEAM_SW type: %d\n", sw);
        exit(0);
    }

    idata = extract_ins_data(sw);
    if(idata == NULL)
        return -1;

    status = instrument_code(sw);
    if(status != 0)
        return -1;

    return 0;
}
