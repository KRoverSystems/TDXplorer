#include "pageManager.h"

#include <cstring>
#include <iomanip>

extern servReq *sreq;
extern std::map<ulong, ulong> seam_va_pa_map;

#define _1GB            0x40000000UL
#define _128MB          0x8000000UL
#define REGION_SIZE     _128MB

void pageManager::initPageManager(void) {    
    
    bkp_pg_count = 0;
    pagePool4K = (ulong)&sreq->pg_pool;
    pagePool4K = ((ulong)pagePool4K + 0xfff) & VA_TO_PG_VA_MASK;
    std::cout << "pagePool4K: 0x" << std::hex << pagePool4K << std::endl;
    assert (pagePool4K);
}

void pageManager::sendSeamPageAccessReq(SERVREQ req, ulong seam_pg_va, ulong bkp_pg_count){
            
    sreq->req = req;
    sreq->seam_pg_va = seam_pg_va;
    if((req == SERVREQ_BACKUP_PAGE) || (req == SERVREQ_RESTORE_PAGE)){
        sreq->bkp_pg_count = bkp_pg_count;
        // std::cout << "sreq->bkp_pg_count " << std::dec << sreq->bkp_pg_count << std::endl;
    }
    else if(req != SERVREQ_READ_MEM){
        std::cout << "unhandled req type in sendSeamPageAccessReq() ..." << std::endl;
        assert(0);
    }
    // std::cout << "sreq->seam_pg_va: 0x" << std::hex << sreq->seam_pg_va << std::endl;

    sreq->req_owner = SERVREQ_OWNER_S_AGENT;
    asm volatile ("mfence; \n");

    while(sreq->req_owner == SERVREQ_OWNER_S_AGENT){
        /*wait*/
        asm volatile ("mfence; \n");
    }
    assert(sreq->req_owner == SERVREQ_OWNER_INTERPRETER);
    // std::cout << "sendSeamPageAccessReq completed" << std::endl;
}

void pageManager::restore_pages() {

    // std::cout << "bkp_pg_count " << std::dec << bkp_pg_count << std::endl;
    ulong seam_pg_va, khole_pgs, non_khole_pgs;
    int idx = bkp_pg_count - 1; /*we do not clear the backup_order[] buffer after each path. so start at this idx.*/

    khole_pgs = 0;
    non_khole_pgs = 0;
    while(idx >= 0){
        seam_pg_va = backup_order[idx];
        if(seam_pg_va > 0){
            // std::cout << "idx " << std::dec << idx << " seam_pg_va: 0x" << std::hex << seam_pg_va << std::endl;
            auto it = pg_bkp_map.find(seam_pg_va);
            assert(!(it == pg_bkp_map.end()));
            // std::cout << "restoring : 0x" << std::hex << it->second.bkp_pg_va << " to : 0x" << seam_pg_va << " bkp_pg_count " << std::dec << it->second.bkp_pg_count  << std::endl;
            
            if((seam_pg_va >= sreq->khole_start) && (seam_pg_va < (sreq->khole_start + sreq->khole_size))){
                khole_pgs++;
                sendSeamPageAccessReq(SERVREQ_RESTORE_PAGE, seam_pg_va, it->second.bkp_pg_count);
            }
            else{
                non_khole_pgs++;
                memcpy((void *)seam_pg_va, (void *)it->second.bkp_pg_va, PAGE_SZ_4K);
            }
        }
        idx--;
    }
    pg_bkp_map.clear();
    assert(pg_bkp_map.empty());
    bkp_pg_count = 0 ;
    // std::cout << "key hole pages restored : " << std::dec << khole_pgs << std::endl;
    // std::cout << "non key hole pages restored : " << std::dec << non_khole_pgs << std::endl;
}

void pageManager::iterateMap(){
    std::cout << "\n map -------\n";
    for(auto it = pg_bkp_map.begin(); it != pg_bkp_map.end(); it++){
        std::cout << "key 0x" << std::hex << it->first << "seam va 0x" << it->second.bkp_pg_va << "bkp idx " << it->second.bkp_pg_count << std::endl;        
    }

    int i = 0;
    while(i < PAGE_POOL_4K_PGS){
        std::cout << "bkp seam va 0x" << std::hex << backup_order[i] << std::endl;
        i++;
    }
}

// ulong page_bk_ct = 0;
void pageManager::backup_page(ulong seam_va) {

    ulong seam_pg_va;
    ulong bkp_pg_va;

    seam_pg_va = seam_va & VA_TO_PG_VA_MASK;
    // std::cout << " seam_va: 0x" << std::hex << seam_va << " seam_pg_va: 0x" << std::hex << seam_pg_va << std::endl;

    auto it = pg_bkp_map.find(seam_pg_va);
    if(it == pg_bkp_map.end()){ /*pg not backed up*/
        bkp_pg_va = pagePool4K + bkp_pg_count*(PAGE_SZ_4K);
        // std::cout << "next backp idx: " << std::dec << bkp_pg_count << " backing up on to: 0x" << std::hex << bkp_pg_va << std::endl;
        // page_bk_ct++;
        /*backup page*/
        if((seam_pg_va >= sreq->khole_start) && (seam_pg_va < (sreq->khole_start + sreq->khole_size))){
            /*get seam agents help to backup*/
            // std::cout << "seam khole adr" << std::endl;
            sendSeamPageAccessReq(SERVREQ_BACKUP_PAGE, seam_pg_va, bkp_pg_count);
        }
        else{
            memcpy((void *)bkp_pg_va, (void *)seam_pg_va, PAGE_SZ_4K);
        }

        auto res1 = pg_bkp_map.insert({seam_pg_va, {bkp_pg_va, bkp_pg_count, seam_pg_va}});
        if(!res1.second){ assert(0);}
        backup_order[bkp_pg_count] = seam_pg_va;
     
        // std::cout << "map size: " << pg_bkp_map.size() << std::endl;
        /*iterateMap();*/
        bkp_pg_count++;
    }
    else{
        // std::cout << "already backed up" << std::endl;
    }
    assert(bkp_pg_count < PAGE_POOL_4K_PGS);
}

void pageManager::cmpTdxPages(unsigned long seam_va, unsigned long bkp_va){

    assert(seam_va);
    assert(bkp_va);

    ulong *pg_data;
    ulong tdx_data_va = seam_va;
    unsigned long a;
    unsigned long b;
    unsigned long ofset = 0;
    int result;

    if( (seam_va >= sreq->khole_start) && (seam_va < (sreq->khole_start + sreq->khole_size))){
        sendSeamPageAccessReq(SERVREQ_READ_MEM, seam_va, 0 /*N.A. for this req type*/);
        tdx_data_va = (ulong)sreq->page_data;
    }

    result = std::memcmp((void *)tdx_data_va, (void *)bkp_va, 4096);

    if(result != 0){
        std::cout << "page contents mismatched" << std::endl;
        a = tdx_data_va;
        b = bkp_va;
        while(ofset < 4096){
            result = std::memcmp((void *)(a + ofset), (void *)(b + ofset), 8);
            if(result != 0){
                std::cout   << "Modified 8 byte block: seam va: 0x" << std::hex << seam_va + ofset 
                            << " from:0x" << std::setw(16) << std::setfill('0') << *((ulong *)(b + ofset)) 
                            << " to:0x" << std::setw(16) << std::setfill('0') << *((ulong *)(a + ofset)) << std::endl;
            }
            ofset+=8;
        }
    }
    else{
        std::cout << "page contents ok" << std::endl;
    }

}

// void pageManager::cmpKholePages(ulong seam_va, ulong *pg_data){

//     ulong current_adr = seam_va;
//     ulong idx = 0;
//     long data;

//     while(idx < 512){
//         current_adr = current_adr + 8*idx;

//         sendSeamPageAccessReq(SERVREQ_READ_MEM, current_adr, data, 8);
//         pg_data[idx] = data;
//         idx++;
//     }
// }


void pageManager::checkModifiedData(){

    std::cout << "at checkModifiedData" << std::endl;
    unsigned long seam_pg_va;
    unsigned long bkp_pg_va;
    ulong khole_mapped_pa = 0;

    if(pg_bkp_map.size() == 0){
        std::cout << "no backed up pages !" << std::endl;
    }

    for (auto it = pg_bkp_map.begin(); it != pg_bkp_map.end(); it ++){
        seam_pg_va = it->first;
        bkp_pg_va = it->second.bkp_pg_va;
        std::cout << "\nseam_page_va :0x" << std::hex << seam_pg_va << "----------------------------------------------------------" << std::endl;

        /*code page*/
        if((seam_pg_va >= sreq->mod_code_rgn_start) && (seam_pg_va < (sreq->mod_code_rgn_start + REGION_SIZE))){
            std::cout << "a code page has been modified !!!" << std::endl;
            assert(0);
        }
        /*stack page*/
        else if((seam_pg_va >= sreq->mod_stack_rgn_start) && (seam_pg_va < (sreq->mod_stack_rgn_start + REGION_SIZE))){
            std::cout << "a stack page has been modified !!!" << std::endl;
        }
        /*data page*/
        else if((seam_pg_va >= sreq->mod_data_rgn_start) && (seam_pg_va < (sreq->mod_data_rgn_start + REGION_SIZE))){
            std::cout << "a data page has been modified !!! " << std::endl;
            cmpTdxPages(seam_pg_va, bkp_pg_va);
        }
        /*khole edit page*/
        else if((seam_pg_va >= sreq->khole_edit_start_seam_va) && (seam_pg_va < (sreq->khole_edit_start_seam_va + REGION_SIZE))){
            std::cout << "a khole edit page has been modified !!! " << std::endl;
            cmpTdxPages(seam_pg_va, bkp_pg_va);
        }
        /*khole page*/
        else if((seam_pg_va >= sreq->khole_start) && (seam_pg_va < (sreq->khole_start + REGION_SIZE))){
            std::cout << "a khole page has been modified !!! " << std::endl;
            auto it = seam_va_pa_map.find(seam_pg_va);
            if(it != seam_va_pa_map.end()){
                khole_mapped_pa = it->second;
            }
            else{
                assert(0);
            }
            std::cout << "khole_mapped_pa:0x" << khole_mapped_pa << std::endl;
            cmpTdxPages(seam_pg_va, bkp_pg_va);
        }
        else {
            assert(0);
        }
    }


}