#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>

#include "defs.h"
#include "common.h"
#include "com.h"

uint8_t tdx_mod_entry[] = "data/tdxmodule/libtdx-seamentry.address";
uint8_t ipp_crypto_start[] = "data/tdxmodule/libtdx-ippcrypto.start.address";
uint8_t khole_edit_writes[] = "data/tdxmodule/libtdx-khole-edit-write.ins";
uint8_t tdexit_tdx_mod_entry[] = "data/tdxmodule/libtdx-tdexit-entry.address";
uint8_t tdh_mem_page_aug_leaf[] = "data/tdxmodule/libtdx-tdh_mem_page_aug.address";
uint8_t tdh_mem_sept_add_leaf[] = "data/tdxmodule/libtdx-tdh_mem_sept_add.address";
uint8_t tdh_servtd_bind_leaf[] = "data/tdxmodule/libtdx-ttdh_servtd_bind.address";
uint8_t tdg_mem_page_attr_rd_leaf[] = "data/tdxmodule/libtdx-tdg_mem_page_attr_rd.address";
uint8_t cr_ins_address[] = "data/agent/cr_ins.address";
uint8_t seamret_address[] = "data/tdxmodule/libtdx-seamret.address";
uint8_t vmlaunch_address[] = "data/tdxmodule/libtdx-vmlaunch.address";
uint8_t vmresume_address[] = "data/tdxmodule/libtdx-vmresume.address";

ulong copy_tdx_module(ulong adr);
ulong get_offset(OFFSET_TYPE type);
int read_sw_objdump(struct file_data *fdata);
int get_khole_edit_ins_adrs(uint32_t *buf);
int get_cr_ins_address(ulong *adrs);
int get_tdxcall_end_adrs(ulong *seamret, ulong *vmlaunch, ulong *vmresume);

int get_tdxcall_end_adrs(ulong *seamret, ulong *vmlaunch, ulong *vmresume){

    int ret, round;
    uint8_t *fname;
    uint8_t buf[64];
    ulong *out;
    int fd;

    round = 0;
    while(round < 3){
        if(round == 0){
            fname = seamret_address;
            out = seamret;
        }
        else if(round == 1){
            fname = vmlaunch_address;
            out = vmlaunch;
        }
        else if(round == 2){
            fname = vmresume_address;
            out = vmresume;
        }
        /*LOG("%s\n", fname);*/


        fd = open(fname, O_RDONLY);
        if(fd == -1){
            LOG("%s open error\n", fname);
            goto end;
        }

        if(read(fd, (void *)(buf), 16) == 0){
            LOG("%s read error\n", fname);
            goto exit;
        }

        *out = strtol((uint8_t *)buf, NULL, 16);
        /*printf("%lx\n", *out);*/

        round++;
    }
    ret = 0;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fname);
    }
end:
    if(ret == 1){
        LOG("error at get_tdxcall_end_adrs()\n");
        exit(0);
    }
    return ret;
}

int get_cr_ins_address(ulong *adrs){

    uint8_t *fname = &cr_ins_address;
    uint8_t buf[256];
    int i = 0;
    int ret = 1;
    int adr_count = 0;

    int fd = open(fname, O_RDONLY);

    if(fd == -1){
        LOG("%s open error\n", fname);
        goto end;
    }
    
    if(read(fd, (void *)(buf), 256) == 0){
        LOG("%s read error\n", fname);
        goto exit;
    }

    while(adr_count < AGENT_CR_INS_COUNT){

        adrs[adr_count] = strtol((uint8_t *)&buf[i], NULL, 16);

        while(i < 256){
            if(buf[i] == '\n'){
                i++;
                break;
            }
            i++;
        }
        adr_count++;
    }
    ret = 0;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fname);
    }
end:
    if(ret == 1){
        LOG("error at get_cr_ins_address()\n");
        exit(0);
    }
    return ret;
}


ulong copy_tdx_module(ulong adr){
    ulong size;

    int fd = open("data/tdxmodule/libtdx.so", O_RDONLY);
    if(fd == -1)
    {
        LOG("unable to open libtdx.so\n");
        return 0;
    }
    
    size = lseek(fd, 0UL, SEEK_END);
    /*LOG("libtdx.so size : 0x%lx\n", size);*/
    if(size == 0){
        LOG("invalid libtdx.so size\n");
        goto exit;
    }
    if(lseek(fd, 0UL, SEEK_SET) != 0){
        LOG("lseek SEEK_SET failed\n");
        goto exit;
    }

    if(read(fd, (void *)(adr), size) != size){
        LOG("libtdx.so read error\n");
        goto exit;
    }
    if(close(fd) == -1){
        LOG("unable to close libtdx.so\n");
    }
    return size;

exit:
    if(close(fd) == -1){
        LOG("unable to close libtdx.so\n");
    }
    return 0;
}

int get_khole_edit_ins_adrs(uint32_t *adrs){

    uint8_t *fname = &khole_edit_writes;
    uint8_t buf[128];
    int i = 0;
    int ret = 1;

    int fd = open(fname, O_RDONLY);

    if(fd == -1)
    {
        LOG("%s open error\n", fname);
        goto end;
    }
    
    if(read(fd, (void *)(buf), 128) == 0){
        LOG("%s read error\n", fname);
        goto exit;
    }

    adrs[0] = strtol((uint8_t *)buf, NULL, 16);
    while(i < 128){
        if(buf[i] == '\n'){
            break;
        }
        i++;
    }
    adrs[1] = strtol((uint8_t *)&buf[i], NULL, 16);
    /*printf("%x %x\n", (int)adrs[0], (int)adrs[1]);*/
    ret = 0;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fname);
    }
end:
    if(ret == 1){
        LOG("error at get_khole_edit_ins_adrs()\n");
        exit(0);
    }
    return ret;
}


ulong get_offset(OFFSET_TYPE type){

    uint8_t *fname;
    
    ulong offset;
    uint8_t buf[16] = { 0 };
    
    if(type == OFFSET_TYPE_TDX_MOD_ENTRY_SEAMCALL){
        fname = (uint8_t *)&tdx_mod_entry;
    }
    else if(type == OFFSET_TYPE_IPP_CRYPTO_START){
        fname = (uint8_t *)&ipp_crypto_start;
    }
    else if(type == OFFSET_TYPE_TDX_MOD_ENTRY_TDCALL){
        fname = (uint8_t *)&tdexit_tdx_mod_entry;
    }
    else if(type == OFFSET_TYPE_TDH_MEM_PAGE_AUG_LEAF){
        fname = (uint8_t *)&tdh_mem_page_aug_leaf;
    }
    else if(type == OFFSET_TYPE_TDH_MEM_SEPT_ADD_LEAF){
        fname = (uint8_t *)&tdh_mem_sept_add_leaf;
    }
    else if(type == OFFSET_TYPE_TDH_SERVTD_BIND_LEAF){
        fname = (uint8_t *)&tdh_servtd_bind_leaf;
    }
    else if(type == OFFSET_TYPE_TDG_MEM_PAGE_ATTR_RD_LEAF){
        fname = (uint8_t *)&tdg_mem_page_attr_rd_leaf;
    }
    else{
        LOG("Invalid OFFSET_TYPE at get_offset()\n");
        return 0;
    }


    int fd = open(fname, O_RDONLY);

    if(fd == -1)
    {
        LOG("%s open error\n", fname);
        return 0;
    }

    if(read(fd, (void *)(buf), 16) != 16){
        LOG("%s read error\n", fname);
        goto exit;
    }

    offset = strtol((uint8_t *)buf, NULL, 16);
    if(close(fd) == -1){
        LOG("%s close error\n", fname);
    }

    /*LOG("%s offset: 0x%lx\n", fname, offset);*/
    if(offset == 0){
        LOG("invalid offset\n");
        goto exit;
    }
    return offset;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fname);
    }
    return 0;
}

int read_sw_objdump(struct file_data *fdata){

    int fd;
    ulong size; 
    
    fd = open(fdata->fname, O_RDONLY);
    if(fd == -1)
    {
        LOG("unable to open %s\n", fdata->fname);
        exit(0);
    }
    
    size = lseek(fd, 0UL, SEEK_END);
    /*LOG("%s size : 0x%lx\n", fdata->fname, size);*/
    if(size == 0){
        LOG("%s is empty\n", fdata->fname);
        goto exit;
    }

    if(lseek(fd, 0UL, SEEK_SET) != 0){
        LOG("lseek SEEK_SET failed\n");
        goto exit;
    }

    fdata->fd = fd;
    fdata->size = size;
    return 0;

exit:
    if(close(fd) == -1){
        LOG("unable to close %s\n", fdata->fname);
    }
    exit(0);
}