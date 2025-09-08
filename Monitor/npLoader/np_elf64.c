#include "np_elf64.h"
#include "defs.h"

uint64_t RelocateSection(uint64_t ElfImage, Elf64_Shdr* SectionHeader, uint64_t RelocationAddr) {
    Elf64_Rela* CurRela;

    /*if the section holds a table of fixed size entries, "sh_entsize" gives the size of each entry*/
    if (SectionHeader->sh_entsize == 0) { /*if section has no table*/
        return -1;
    }
    //NPLOG(" sh_addr:0x%lx sh_addr:0x%lx\n", SectionHeader->sh_addr, SectionHeader->sh_offset );
    /*iterate through each entry in the table of fixed size entries in the section(in the form of a table)
    sh_size / sh_entsize = number of entries*/
    for (uint64_t i = 0; i < SectionHeader->sh_size / SectionHeader->sh_entsize; i++) {     
        
        /*each relocation entry is in the form of struct Elf64_Rela
        Adr of relocation entry = Elf_start + offset to section start + (entry_number * entry_size)*/   
        CurRela = (Elf64_Rela*)(ElfImage + SectionHeader->sh_addr + i * SectionHeader->sh_entsize); 
        /*sh_addr gives the VA of the section, sh_offset gives the offset of th section.
        I was hoping intlel would've used sh_offset in above.
        Note:in pseamldr.so's RELA section, both values are the same. because this is a .so ?*/

        if (CurRela->r_info == R_X86_64_RELATIVE) {
            /*update the address(i.e. value at r_offset) as RelocationAddr + r_addend*/            
            *(uint64_t *)(ElfImage + CurRela->r_offset) = RelocationAddr + CurRela->r_addend;
        }
        else {
            NPLOG("Unsupported relocation!!\n");
            return -1;
        }
    }

    return 0;
}

/* sample ELF format
            +-------------------+
            | ELF header        |---+
+---------> +-------------------+   | e_shoff
|           |                   |<--+
| Section   | Section header 0  |
|           |                   |---+ sh_offset
| Header    +-------------------+   |
|           | Section header 1  |---|--+ sh_offset
| Table     +-------------------+   |  |
|           | Section header 2  |---|--|--+
+---------> +-------------------+   |  |  |
            | Section 0         |<--+  |  |
            +-------------------+      |  | sh_offset
            | Section 1         |<-----+  |
            +-------------------+         |
            | Section 2         |<--------+
            +-------------------+
*/
uint64_t RelocateImage(uint64_t ElfImage, uint64_t RelocationAddr) {
    Elf64_Ehdr* ElfHeader = (Elf64_Ehdr*)ElfImage;
    Elf64_Shdr* CurSheader;
    uint64_t Status = 0;

    for (uint32_t i = 0; i < ElfHeader->e_shnum; i++) {      //pp-n  e_shnum- # of section header entries
        
        /*CurSheader location = Elf_start + offset to section hdr table start + (section_number * size of a section hdr entry) */
        CurSheader = (Elf64_Shdr*)(ElfImage + ElfHeader->e_shoff + (uint64_t)i * ElfHeader->e_shentsize); 
        /*"e_shoff" sec hdr offset, "e_shentsize" size of sec hdr entry*/
        
        NPLOG("section header num: 0x%xtype: 0x%x", i, CurSheader->sh_type);
        if (CurSheader->sh_type == SHT_RELA) { /*section holds relocation entries*/
            NPLOG(" SHT_RELA");

            Status = RelocateSection(ElfImage, CurSheader, RelocationAddr);
            if (Status != 0) {
                return Status;
            }
        }
        NPLOG("\n");
    }

    return Status;
}