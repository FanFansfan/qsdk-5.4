/* @File:   memory-mgmt.h
 * @Notes:  This Header file has data structure/enum declarations used by
 *          memory management abstraction library
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#ifndef QCA_SON_MEM_DBG_MEMORY_H
#define QCA_SON_MEM_DBG_MEMORY_H

#include "qca-son-mem-debug.h"
#include "common-lib.h"

/* Return status of filter management */
typedef enum return_status
{
    ENTRY_ADD_SUCCESS = 0,
    ENTRY_ALREADY_PRESENT = 1,
    ENTRY_ADD_MEM_FAILURE = 2,
    ENTRY_NOT_IGNORED = 3,
    ENTRY_REMOVE_SUCCESS = 4,
    ENTRY_NOT_FOUND = 5,
    FILE_OPEN_FAIL = 6
} return_status_e;

typedef enum filter_config
{
    FILTER_NOT_SET,
    BLACKLIST_ENTRY,
    WHITELIST_ENTRY
} filter_config_e;

/* debug data sent from SON applications(modules) during memory allocations */
typedef struct son_mem_dbg_data
{
    int mod;
    int smod;
    int cat;
    int line;
    const char *func;
    void* cdata;

} son_mem_dbg_data_t;

/* =================================
 * Detailed Memory usage information
 * =================================
 * To store memory allocation summary - Detailed Memory usage information
 */
typedef struct son_mem_summary
{
    uint32_t total_mem_usage;
    uint32_t peak_allocation;
    uint32_t total_alloc_count;     // Total allocations happened so far
    uint32_t total_free_count;      // Total frees happened so far
    uint32_t total_alloc_entry;     // Number of entries in allocation list at present

    uint32_t malloc_failure;
    uint32_t mem_alloc_mgmt_failure;    // Unable to manage this memory allocation due to mem failure
    uint32_t mem_free_mgmt_failure;     // Number of times, memory is freed that is not allocated/managed by this tool
    uint32_t mem_realloc_mgmt_failure;  // Number of times, Realloc management failed

#ifdef SON_MEM_DEBUG_FREE
    uint32_t total_free_entry;    // Number of entries in free list at present
#endif
} son_mem_summary_t;

/* To store detailed memory usage information about the memory allocation for debugging purpose */
typedef struct son_mem_info
{

    char            afnname[SON_FUNC_NAME_LENGTH];  // allocation function name
    uint32_t        aline;                          // allocation line number
//  uint32_t        category;                       // 0-Init, 1-Event Based, 2-AP Validity, 3-Station Validity...
    size_t          size;
    son_module_e    module;                         // HYD, WSPLCD, LIBSTORAGE ....
    struct timeval  alloc_time;
    void            *mem_addr;                      // allocated memory address
    struct son_mem_info *next;
    struct son_mem_info *prev;
/*  TBD
    union  {
        uint8_t bytes[MAC_ADDRESS_SIZE];
    } category_data;
*/
    // Freed Memory Information
#ifdef SON_MEM_DEBUG_FREE
    char            ffnname[SON_FUNC_NAME_LENGTH];  // free function name
    uint32_t        fline;                          // free line number
    struct timeval  free_time;
#endif

} son_mem_info_t;


typedef struct process_mem_status
{
    char *vmdata[MAX_VMDATA];

} process_mem_status_t;
/* ===================
 * Function prototypes
 * ===================
 */

void son_memory_debug(void *ptr, size_t size, const char *func, uint32_t line , enum son_module mod, enum son_mem_category cat, void *cdata );
uint32_t son_mem_dbg_add_entry_to_alloc_list( void *ptr, size_t size, const char *func, uint32_t line, enum son_module mod, enum son_mem_category cat, void *cdata);
uint8_t son_mem_dbg_remove_entry_from_list(enum son_module mod, void *ptr, const char *func, uint32_t line);
uint8_t find_and_update_mem_size(void *ptr, size_t newsize );

void display_struct_size_info();
uint32_t son_mem_debug_tool_memory_usage();
void son_mem_dbg_display_detailed_list_info();
void son_mem_dbg_display_minimal_list_info();
void update_peak_calculation(uint8_t mod_update, son_module_e mod);

void son_mem_info_free(son_mem_info_t **listptr);
void cleanup_all_tool_memory_usage();
void print_graph_output();

#ifdef SON_MEM_DEBUG_FREE
void son_mem_dbg_add_entry_to_free_list(son_mem_info_t *node, enum son_module mod);
#endif


#endif      /* QCA_SON_MEM_DBG_MEMORY_H */
