/* @File:   filter-mgmt.c
 * @Notes:  This C file has implementation to store filtered memory information
 *          Functionalities include:
 *              Create list of pre-configured function name to be used while filtering,
 *              Add/Remove/Search/update to filtered memory list
 *              display and cleanup functions
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include "common-lib.h"
#include "filter-mgmt.h"
#include "memory-mgmt.h"
#include <sys/file.h>
#include <fcntl.h>

// Memory usage information with minimal information (for memory profiling and also for debugging blacklist data)
list_data_t *g_list_data = NULL;     // contains accepted/ignored function names
list_memory_t *g_list_mem = NULL;    // contains ignored functions or audit only function
uint32_t list_data_count;
uint32_t list_data_tool_usage;
uint32_t list_data_mem_usage;
uint32_t list_mem_count;
filter_config_e g_blackorwhitelist = FILTER_NOT_SET; // Configure from SON application : Enable Blacklist filter or enable whitelist filter or disable filter

extern uint8_t g_enableloggingtofile;
extern uint32_t tool_debug;
extern FILE *wp, *dbg_op;

uint32_t check_function_exists(const char *func)
{
    list_data_t *list = g_list_data;
    while(list) {
        if (strcmp(list->funcname, func) == 0) {
            return ENTRY_ALREADY_PRESENT;
        }
        list=list->next;
    }
    return 0;
}

uint32_t create_list_entry(const char *func )
{
    if (g_list_data != NULL) {
        if (check_function_exists(func) ) {
            debug_printf("[%s]: Filter Entry already present!!!\n", func);
            return ENTRY_ALREADY_PRESENT;
        }
    }

    list_data_t *newnode = (list_data_t *) calloc (1, sizeof(list_data_t));
    if (newnode == NULL) {
        printf("[%s][%d]: Mem alloc failure [%s]!!!\n", __func__, __LINE__, func);
        return ENTRY_ADD_MEM_FAILURE;
    }
    newnode->funcname = func;
    newnode->next = NULL;

    if (g_list_data != NULL) {
        newnode->next = g_list_data;
    }
    g_list_data = newnode;
    return ENTRY_ADD_SUCCESS;
}

uint32_t create_filter_list(FILE *file_ptr)
{
    uint32_t func_len, read, ent_ret_status=0;
    size_t read_len = 0;
    char *str, *line, *line_end, *funcname;

    while ((read = getline(&str, &read_len , file_ptr)) != -1)
    {
        line = str;
        func_len=1;
        while ((*line == ' ') &&  (*line != EOF)) {     // discard leading whitespaces
            line++;
        }
        line_end = line;
        while ((*line_end != ' ')  &&  (*line_end != '\n') &&  (*line_end != EOF)) {  // discard trailing whitespaces
            func_len++;
            line_end++;
        }
        if ((funcname = (char*) calloc(1, func_len)) != NULL) {
            strlcpy(funcname, line, func_len-1);
            funcname[func_len] = '\0';
            ent_ret_status = create_list_entry(funcname);
            if (ent_ret_status == ENTRY_ADD_SUCCESS ) {
                list_data_tool_usage += func_len;
                list_data_count++;
            }
            else if (ent_ret_status == ENTRY_ALREADY_PRESENT) {
                free(funcname);
            }
            else if (ent_ret_status == ENTRY_ADD_MEM_FAILURE) {
                free(str);
                free(funcname);
                clean_up_filter_list();
                return ENTRY_ADD_MEM_FAILURE;
            }

        } else {
            free(str);
            printf("Mem alloc failure [%s][%d] !!!\n", __func__, __LINE__);
            clean_up_filter_list();
            return ENTRY_ADD_MEM_FAILURE;
        }
        if (str) {
            free(str);
            str=NULL;
        }
        read_len = 0;
    }
    return ent_ret_status;
}

uint32_t add_to_filtered_meminfo_list( void *ptr, size_t size, son_module_e mod)
{
    list_memory_t *newnode = (list_memory_t*) calloc (1, sizeof(list_memory_t));
    if (newnode == NULL) {
        return ENTRY_ADD_MEM_FAILURE;
    }
    newnode->size = size;
    newnode->mem_addr = ptr;
    newnode->next = NULL;
    list_data_mem_usage += size;
    update_peak_calculation(0, QCA_MOD_MAX );
    print_graph_output();

    if (g_list_mem != NULL) {
        dbg_print(dbg_op, "Added new node to min list !!!\n");
        newnode->next = g_list_mem;
    }
    else {
        dbg_print(dbg_op, "Added new FIRST node to min list!!!\n");
    }
    g_list_mem = newnode;

    fflush(dbg_op);
    list_mem_count++;

    return ENTRY_ADD_SUCCESS;
}

uint32_t check_and_add_to_filtered_mem_list(const char *func, void *ptr, size_t size, son_module_e mod)
{
    if (check_function_exists(func)) {
        if(g_blackorwhitelist == BLACKLIST_ENTRY) {
            return add_to_filtered_meminfo_list(ptr, size, mod);
        }
        else if (g_blackorwhitelist == WHITELIST_ENTRY) {
            return ENTRY_NOT_IGNORED;
        }
    } else {
        if (g_blackorwhitelist == WHITELIST_ENTRY) {
            return add_to_filtered_meminfo_list(ptr, size, mod);
        } else {
            return ENTRY_NOT_IGNORED;
        }
    }
    return ENTRY_NOT_IGNORED;
}

uint32_t check_and_remove_from_filtered_list(void* ptr, son_module_e mod)
{
    list_memory_t *list = g_list_mem;
    list_memory_t *prev = NULL;

    while(list) {
        if (list->mem_addr == ptr) {
            if (list == g_list_mem) {
                g_list_mem = list->next;
            } else {
                prev->next = list->next;
            }
            list_data_mem_usage -= list->size;
            update_peak_calculation(0, QCA_MOD_MAX );
            print_graph_output();
            free(list);
            list_mem_count--;
            return ENTRY_REMOVE_SUCCESS;
        }
        prev = list;
        list = list->next;
    }
    return ENTRY_NOT_FOUND;
}

uint8_t search_meminfo_list_and_update_new_size(void *ptr, size_t newsize)
{
    list_memory_t *listmem = g_list_mem;
    while (listmem) {
        if (listmem->mem_addr == ptr) {
            list_data_mem_usage -= listmem->size;
            listmem->size = newsize;
            list_data_mem_usage += newsize;
            update_peak_calculation(0, QCA_MOD_MAX );
            print_graph_output();
            return 0;
        }
        listmem = listmem->next;
    }
    return ENTRY_NOT_FOUND;
}

void display_filter_function_list()
{
    list_data_t *listdata = g_list_data;
    printf("Function added to Filter list:\n======================\n");
    while(listdata) {
        printf("Function name :[%s] \n", listdata->funcname);
        listdata = listdata->next;
    }
}

void clean_up_filter_list()
{
    list_data_t *list, *tempptr;
    list = g_list_data;
    while(list) {
        free((void*)list->funcname);
        tempptr = list;
        list = list->next;
        free(tempptr);
    }
    g_list_data = NULL;
}

void clean_up_filtered_data()
{
    list_memory_t *list, *tempptr;
    list = g_list_mem;
    while(list) {
        tempptr = list;
        list = list->next;
        free(tempptr);
    }
    g_list_mem = NULL;
}
