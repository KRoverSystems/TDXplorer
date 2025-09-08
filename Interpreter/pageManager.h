#ifndef PAGE_MANAGE_H
#define PAGE_MANAGE_H

#include "com.h" /*from seam manager*/
#include <iostream>
#include <fstream>
#include <linux/types.h>
#include <ucontext.h>
#include <cassert> 
#include <string.h>
#include <map>

/*#define PAGE_POOL_4K_PGS           128 from com.h*/
#define VA_TO_PG_VA_MASK ~(0xfffUL)
#define PAGE_SZ_4K 0x1000UL

struct BackupPg {
    ulong bkp_pg_va;
    ulong bkp_pg_count; /*identifies the backed up page idx*/
    ulong seam_page_va;

    BackupPg (ulong bkp_pg_va, ulong bkp_pg_count, ulong seam_pg_va) :
            bkp_pg_va(bkp_pg_va), bkp_pg_count(bkp_pg_count), seam_page_va(seam_page_va) {
                // std::cout << "BackupPg Constructor: seam_pg_va = 0x" << std::hex << seam_pg_va << std::endl;
            }
};

class pageManager {

    ulong bkp_pg_count;
    ulong pagePool4K;

    std::map<ulong/*seam pg va*/, BackupPg> pg_bkp_map;
    ulong backup_order[PAGE_POOL_4K_PGS];

    public:
        pageManager () {};
        ~pageManager() {};

        void backup_page(ulong seam_va);
        void restore_pages();
        void sendSeamPageAccessReq(SERVREQ req, ulong seam_pg_va, ulong bkp_pg_count);
        void initPageManager(void);   
        void iterateMap();
        void checkModifiedData();
        void cmpTdxPages(unsigned long tdx_va, unsigned long bkp_va); 
        void cmpKholePages(unsigned long tdx_va, ulong *pg_data); 
};

#endif

