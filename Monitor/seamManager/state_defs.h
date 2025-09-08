#include <stdint.h>

/*from arch/x86/include/asm/desc_defs.h*/
/* 8 byte segment descriptor for GDT*/
struct desc_struct {
	uint16_t	limit0;
	uint16_t	base0;
	uint16_t	base1: 8,
				type: 4,	/*segment type?*/
				s: 1,		/*Descriptor type (0 = system?; 1 = code or data)*/
				dpl: 2,		/*descriptor privilege level*/
				p: 1;		/*segment present flag*/
	uint16_t	limit1: 4,
				avl: 1,		/*Available for use by system software?*/
				l: 1,		/*64-bit code segment (IA-32e mode only)*/
				d: 1,		/*Default operation size (0 = 16-bit segment; 1 = 32-bit segment)*/
				g: 1,		/*Granularity*/
				base2: 8;
} __attribute__((packed));

/*tss descriptor in 64 bit occupies 16 bytes in GDT*/
struct tss_dsec_struct {
	uint16_t	limit0;
	uint16_t	base0;
	uint16_t	base1: 8,
				type: 4,	/*segment type?*/
				s: 1,		/*Descriptor type (0 = system?; 1 = code or data)*/
				dpl: 2,		/*descriptor privilege level*/
				p: 1;		/*segment present flag*/
	uint16_t	limit1: 4,
				avl: 1,		/*Available for use by system software?*/
				l: 1,		/*64-bit code segment (IA-32e mode only)*/
				d: 1,		/*Default operation size (0 = 16-bit segment; 1 = 32-bit segment)*/
				g: 1,		/*Granularity*/
				base2: 8;

	/*following 8 bytes are also available in 64bit tss*/
	uint32_t 	base3;
	uint32_t 	reserved0: 8,
				some_val: 5,
				reserved1: 19;
} __attribute__((packed));

#define GDT_ENTRY_INIT(flags, base, limit)	\
{											\
	.limit0		= (uint16_t) (limit),		\
	.limit1		= ((limit) >> 16) & 0x0F,	\
	.base0		= (uint16_t) (base),		\
	.base1		= ((base) >> 16) & 0xFF,	\
	.base2		= ((base) >> 24) & 0xFF,	\
	.type		= (flags & 0x0f),			\
	.s			= (flags >> 4) & 0x01,		\
	.dpl		= (flags >> 5) & 0x03,		\
	.p			= (flags >> 7) & 0x01,		\
	.avl		= (flags >> 12) & 0x01,		\
	.l			= (flags >> 13) & 0x01,		\
	.d			= (flags >> 14) & 0x01,		\
	.g			= (flags >> 15) & 0x01,		\
}

struct idt_bits {
	uint16_t	ist	: 3,		/*interrupt stack table*/
				zero: 5,
				type: 5,		/*bits 0:3 is for type, bit 4 is 0*/
				dpl	: 2,		/*descriptor privilege level*/
				p	: 1;		/*segment present flag*/
} __attribute__((packed));

/*gate descriptor for IDT*/
struct gate_struct {
	uint16_t		offset_low;
	uint16_t		segment;		/*	bits 0:1 	-RPL, 
										bit  2 		-Table indicator: 0-GDT, 1-LDT
										bits 3:15 	-Index, */
	struct idt_bits	bits;
	uint16_t		offset_middle;
	uint32_t		offset_high;
	uint32_t		reserved;
} __attribute__((packed));

struct x86_hw_tss {
	uint32_t			reserved1;
	uint64_t			sp0;

	/*
	 * We store cpu_current_top_of_stack in sp1 so it's always accessible.
	 * Linux does not use ring 1, so sp1 is not otherwise needed.
	 */
	uint64_t			sp1;

	/*
	 * Since Linux does not use ring 2, the 'sp2' slot is unused by
	 * hardware.  entry_SYSCALL_64 uses it as scratch space to stash
	 * the user RSP value.
	 */
	uint64_t			sp2;

	uint64_t			reserved2;
	uint64_t			ist[7];
	uint32_t			reserved3;
	uint32_t			reserved4;
	uint16_t			reserved5;
	uint16_t			io_bitmap_base;

} __attribute__((packed));
/*---------------------------------------------------------------------------------------*/