#ifndef _TDX_LOCAL_DATA__
#define _TDX_LOCAL_DATA__

#include <stdint.h>

#define PACKED                  __attribute__((__packed__))
#define MAX_KEYHOLE_PER_LP_ 128


#ifndef __cplusplus

typedef uint8_t                  bool_t;

// Universal true and false values.
#ifndef true
#   define true  ((bool_t)1)
#endif
#ifndef false
#   define false ((bool_t)0)
#endif

#else
typedef bool                  bool_t;
#endif //__cplusplus

/**
 * @struct keyhole_entry_t
 *
 * @brief Holds physical to linear PTE mappings
 *
 * It implements an LRU list and a hash list entry.
 */
typedef struct PACKED tdxmod_keyhole_entry_s
{
    uint64_t  mapped_pa;  /**< mapped physical address of this keyhole entry */
    /**
     * lru_next and lru_prev present an LRU doubly linked-list.
     */
    uint16_t  lru_next;
    uint16_t  lru_prev;
    uint16_t  hash_list_next;  /**< next element in hash list */
    /**
     * state can be KH_ENTRY_FREE or KH_ENTRY_MAPPED or KH_ENTRY_CAN_BE_REMOVED.
     */
    uint8_t   state;
    bool_t    is_writable;  /**< is PTE set to be Read-only or RW */
    bool_t    is_wb_memtype; /**< is PTE should be with WB or UC memtype */

    uint64_t  ref_count; /** reference count of pages mapped in keyhole manager */
} tdxmod_keyhole_entry_t;

/**
 * @struct keyhole_state_t
 *
 * @brief Holds the state of the keyhole mappings for this lp
 *
 * It implements an LRU list and a hash list.
 */
typedef struct PACKED tdxmod_keyhole_state_s
{
    /**
     * Each index in the keyhole_array presents an offset of the mapped linear address.
     * The array also implement and LRU doubly linked-list.
     */
    tdxmod_keyhole_entry_t keyhole_array[MAX_KEYHOLE_PER_LP_];
    /**
     * A hash table, its index represents the index in the keyhole_array
     * that it is mapped to.
     */
    uint16_t  hash_table[MAX_KEYHOLE_PER_LP_];
    /**
     * lru_head and lru_tail present the index of the keyhole_array LRU
     * doubly linked-list.
     */
    uint16_t  lru_head;
    uint16_t  lru_tail;

    /**
     * total_ref_count counts the total amount of non-statically mapped linear addresses.
     * Incremented on map_pa and decremented on free_la
     */
    uint64_t  total_ref_count;
} tdxmod_keyhole_state_t;

#endif /*_TDX_LOCAL_DATA__*/
