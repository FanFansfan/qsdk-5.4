/* @File:   filter-mgmt.h
 * @Notes:  This Header file has data structure/enum declarations of
 *          filter management function used by memory management abstraction
 *          library
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#ifndef QCA_SON_MEM_DBG_FILTER_H
#define QCA_SON_MEM_DBG_FILTER_H

/*====================
 * Minimal information
 *====================
 * List to store minimal information about the accepted(whitelist)/ignored(blacklist) functions
 */
typedef struct list_memory {
    size_t size;
    void *mem_addr;
    struct list_memory *next;
} list_memory_t;

//==========================================================================
//Stores functions names of accepted(whitelist)/ignored(blacklist) functions
//==========================================================================
// List to store pre-configured accepted/ignored function names
typedef struct list_data {
    const char* funcname;                                 // accepted/ignored function name
    struct list_data *next;
} list_data_t;


typedef enum son_module son_module_e;

uint32_t create_list_entry(const char *func );
uint32_t create_filter_list(FILE *file_ptr);
uint32_t add_to_filtered_meminfo_list(void *ptr, size_t size, son_module_e mod );
uint32_t check_and_add_to_filtered_mem_list(const char *func, void *ptr, size_t size, son_module_e mod);
uint32_t check_and_remove_from_filtered_list(void* ptr, son_module_e mod);
uint8_t search_meminfo_list_and_update_new_size(void *ptr, size_t newsize);
void display_filter_function_list();
void clean_up_filter_list();
uint32_t check_funcion_exists(const char *func);

void clean_up_filter_list();
void clean_up_filtered_data();

extern void print_graph_output();
extern void update_peak_calculation(uint8_t mod_update, son_module_e mod);

#endif      /* QCA_SON_MEM_DBG_FILTER_H */

