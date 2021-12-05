/* @File:   memory-mgmt.c
 * @Notes:  This C file has implementation to store allocated/freed memory information
 *          Functionalities include:
 *          Add Entry to list, Remove Entry to List, Search and update the entry in list,
 *          Retrieve process memory status (/proc/self/status), updating peak usage calculation,
 *          display collected statistics information & graph data points and other clean up functions
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include "common-lib.h"
#include "memory-mgmt.h"
#include "filter-mgmt.h"

/* This list stores Memory usage information with detailed information for each modules (for enhanced debugging)
 * -----------------
 *  Memory Management
 * -----------------
 */
uint32_t g_app_total;
son_mem_summary_t g_mem_summary[QCA_MOD_MAX];
son_mem_info_t *g_alloc_list[QCA_MOD_MAX];

#ifdef SON_MEM_DEBUG_FREE
uint32_t g_max_free_track;              // Configure from SON application : This stores maximum entries that can be stored in freed list (to save memory usage)
son_mem_info_t *g_free_list[QCA_MOD_MAX];   // this list stores the freed memory information for each modules
son_mem_info_t *last_node_in_free_list[QCA_MOD_MAX];    // pointer to point the end of the freed list, used in processing the list while maximum entry is reached
#endif
#define STR_DISPLAY_FORMAT "%-20s%-11s%-11s%-11s%-11s%-11s%-11s\n"
#define INT_DISPLAY_FORMAT "%-20s%-11d%-11d%-11d%-11d%-11d%-11d\n"

extern uint8_t g_enableloggingtofile;
extern pid_t processid;
extern uint8_t g_mem_dbg_enable;
extern uint8_t g_onlyAudit;
extern uint32_t g_disabled_module;
extern uint32_t app_peak_allocation;
extern const char *son_module_name[];
extern list_data_t *g_list_data;
extern filter_config_e g_blackorwhitelist;

/* -----------------
 *  Filter Management (filter-mgmt.c)
 * -----------------
 * This list stores Memory usage information with minimal information for memory profiling and also for blacklist/whitelist filter data)
 * Blacklisted functions are discarded for detailed memory usage tracking and stored as minimal information for tracking overall memory usage
 * Whitelisted functions are the only functions considered for tracking with detailed memory usage information and other memory allocation
 */
extern uint32_t list_data_mem_usage;
extern uint32_t list_data_count;
extern uint32_t list_mem_count;
extern uint32_t list_data_tool_usage;
extern list_memory_t *g_list_mem;   // contains ignored functions or audit only function

extern FILE *wp, *dbg_op, *graph_op;

extern uint32_t check_module_enabled_for_tracking(son_module_e mod);


char *vmname[MAX_VMDATA] = { "VmPeak", "VmSize", "VmHWM", "VmRSS", "VmData", "VmLib", "VmPTE", "VmPMD", "VmStk", "VmExe" };

uint32_t son_mem_dbg_add_entry_to_alloc_list( void *ptr, size_t size, const char *func, uint32_t line, son_module_e mod, son_mem_category_e cat, void *cdata)
{
    son_mem_info_t *newnode = (son_mem_info_t *) calloc (1, sizeof(son_mem_info_t));

    if (newnode == NULL) {
        printf("SON-MEM-DBG: Memory Mgmt (info) allocation failure\n");
        return ENTRY_ADD_MEM_FAILURE;
    }
    newnode->size = size;
    newnode->mem_addr = ptr;
    newnode->module = mod;
/*  TBD : copy category and category data based on category
    newnode->category = cat; */
    strlcpy( newnode->afnname, func, SON_FUNC_NAME_LENGTH );
    newnode->aline = line;
    gettimeofday(&newnode->alloc_time, NULL);

    newnode->next = newnode->prev = NULL;

    if (g_alloc_list[mod] == NULL) {
        g_alloc_list[mod] = newnode;
    }
    else {  // add new node to the front
        newnode->next = g_alloc_list[mod];
        newnode->prev = NULL;

        g_alloc_list[mod]->prev= newnode;
        g_alloc_list[mod] = newnode;
    }
    dbg_print(dbg_op, "Added new node to alloc list !!!\n");
    g_mem_summary[mod].total_alloc_entry++;
    return ENTRY_ADD_SUCCESS;
}

#ifdef SON_MEM_DEBUG_FREE

#if 0   // debugging
void display_freed_mem_info_in_module(son_module_e mod)
{
//  uint32_t entry = 1;
    son_mem_info_t *list = NULL;
    son_mem_summary_t *summ = NULL;
    summ = &g_mem_summary[mod];
    list = g_free_list[mod];

    if (list != NULL) {

        dbg_print(dbg_op, "Displaying Free list : Last %d Transactions \n", summ->total_free_entry);
        dbg_print(dbg_op, "========================================================\n");
        while(list != NULL) {
            dbg_print(dbg_op, "prev [%p] ptr [%p] next [%p]\n", list->prev, list, list->next);
//          dbg_print(dbg_op, "[%d]: ptr[%p] size[%zu] alloc_func[%s] alloc_line[%u] free_func[%s] free_line[%u]\n", entry++,
//              list->mem_addr, list->size, list->afnname, list->aline, list->ffnname, list->fline);
            list = list->next;
        }
        dbg_print(dbg_op, "========================================================\n\n");
           fflush(dbg_op);
    }
}
#endif

void son_mem_dbg_add_entry_to_free_list(son_mem_info_t *node, son_module_e mod)
{
    // Return freed memory tracking is set to zero
    if (g_max_free_track == 0) {
        free(node);
        return;
    }

    node->next = node->prev = NULL;
/*  display_freed_mem_info_in_module(mod); */
    if (g_free_list[mod] == NULL) {  // if list is empty, save new node(first node) as the last node
        g_free_list[mod] = node;
        last_node_in_free_list[mod] = node;
        g_mem_summary[mod].total_free_entry++;
        dbg_print(dbg_op, "Added new node into free list [%s] !!!\n", son_module_name[mod]);
        return;
    }

/*  Check for configured value for tracking free node before adding node to freelist
    If free_max is set to zero then save all the freed nodes */
    if ((g_max_free_track == 1) && (g_max_free_track == g_mem_summary[mod].total_free_entry)) {
        free(g_free_list[mod]);
        g_free_list[mod] = node;
    }
    else if ((g_max_free_track != 0) && (g_max_free_track == g_mem_summary[mod].total_free_entry)) {
        last_node_in_free_list[mod] = last_node_in_free_list[mod]->prev;
        node->next = g_free_list[mod];
        g_free_list[mod]->prev = node;
        g_free_list[mod] = node;
        free(last_node_in_free_list[mod]->next);
        last_node_in_free_list[mod]->next = NULL;
    } else {
        node->next = g_free_list[mod];
        g_free_list[mod]->prev = node;
        g_free_list[mod] = node;
        g_mem_summary[mod].total_free_entry++;
    }

}

#endif

uint8_t son_mem_dbg_remove_entry_from_list(son_module_e mod, void *ptr, const char *func, uint32_t line)
{
    son_mem_info_t *node = g_alloc_list[mod];
    while(node != NULL) {
        if (node->mem_addr == ptr) {
            if (node->next == NULL && node->prev == NULL) {    // this is the only node
                g_alloc_list[mod] = NULL;
            }
            else if (node->next != NULL && node->prev == NULL) {    // first node
                g_alloc_list[mod] = node->next;
                g_alloc_list[mod]->prev = NULL;
            }
            else if (node->next == NULL && node->prev != NULL) {    // last node
                node->prev->next = NULL;
            }
            else if (node->next != NULL && node->prev != NULL) {    // middle node
               node->prev->next = node->next;
               node->next->prev = node->prev;
            }

            // decrement from total memory usage
            g_mem_summary[mod].total_mem_usage -= node->size;
            g_app_total -= node->size;
            update_peak_calculation(1, mod);
            print_graph_output();

#ifdef SON_MEM_DEBUG_FREE
            node->fline = line;
            strlcpy( node->ffnname, func, SON_FUNC_NAME_LENGTH );
            gettimeofday(&node->free_time, NULL);

            son_mem_dbg_add_entry_to_free_list(node, mod);

            dbg_print(dbg_op, "Removed from alloc list and added to free list!!!\n");
#else
            free(node);
            dbg_print(dbg_op, "Removed from alloc list !!!\n");
#endif
            g_mem_summary[mod].total_alloc_entry--;
            return ENTRY_REMOVE_SUCCESS;
        }
        node = node->next;
    }
    return ENTRY_NOT_FOUND;
}

void son_memory_debug(void *ptr, size_t size, const char *func, uint32_t line ,
        son_module_e mod, son_mem_category_e cat, void *cdata )
{
    uint32_t ret_status = ENTRY_NOT_IGNORED, notify_failure = 0 ;

    if (!CHECK_BIT_ENABLED(g_mem_dbg_enable, ENABLE_FEATURE)) {
        return;
    }
    dbg_print(dbg_op, "[%s]: SON-MEM-DBG: module[%s] ptr[%p] size[%zu] func[%s] line[%u] \n", __func__, son_module_name[mod], ptr, size, func, line );

    if (ptr) {
        if (g_onlyAudit || (g_disabled_module && check_module_enabled_for_tracking(mod) ) ) {
            if ((ret_status = add_to_filtered_meminfo_list(ptr, size, mod)) == ENTRY_ADD_MEM_FAILURE) {
                notify_failure = 1;
            }
        }
        else {
            if ((g_blackorwhitelist != FILTER_NOT_SET) && g_list_data ) {
                if ((ret_status = check_and_add_to_filtered_mem_list(func, ptr, size, mod)) == ENTRY_ADD_MEM_FAILURE ) {
                    notify_failure = 1;
                }
            }

            if ( ret_status == ENTRY_NOT_IGNORED ) {
                if ((ret_status = son_mem_dbg_add_entry_to_alloc_list( ptr, size, func, line, mod, cat, cdata)) == ENTRY_ADD_MEM_FAILURE) {
                    notify_failure = 1;
                }
            }
        }
        if ( !g_onlyAudit && ret_status == ENTRY_ADD_SUCCESS && !check_module_enabled_for_tracking(mod)) {
                   // accumulate to total memory usage
                g_app_total += size;
                g_mem_summary[mod].total_mem_usage += size;
                    // compute peak allocation
                update_peak_calculation(1, mod);
                print_graph_output();
        }
        g_mem_summary[mod].total_alloc_count++;
        if (notify_failure) {
            printf("[%s]: SON-MEM-ERR: SON Memory Management Allocation failure !!!\n", __func__);
            g_mem_summary[mod].mem_alloc_mgmt_failure++;
            return;
        }
        fflush(dbg_op);
    } else {
        printf("[%s]: SON-MEM-ERR: MALLOC failure !!!\n", __func__);
        g_mem_summary[mod].malloc_failure++;
    }
}

void update_peak_calculation(uint8_t mod_update, son_module_e mod)
{
    if (mod_update) {
        if (g_mem_summary[mod].total_mem_usage > g_mem_summary[mod].peak_allocation) {
            g_mem_summary[mod].peak_allocation = g_mem_summary[mod].total_mem_usage;
        }
    }

    if (g_app_total > app_peak_allocation) {
        app_peak_allocation = g_app_total;
    }
}

void print_graph_output()
{
    if (g_onlyAudit) {
        graph_print(graph_op, "%d\n", list_data_mem_usage);
    }
    else {
        graph_print(graph_op, "%d\n", g_app_total + list_data_mem_usage);
    }
    fflush(graph_op);
}

uint8_t find_and_update_mem_size(void *ptr, size_t newsize )
{
    uint8_t ret = -1;
    son_module_e mod = QCA_MOD_WSPLCD;
    son_mem_info_t *list = NULL;

    if (!g_onlyAudit) {
        while(mod < QCA_MOD_MAX ) {
            list = g_alloc_list[mod];
            while(list) {
                if (list->mem_addr == ptr) {
                    g_app_total -= list->size;
                    g_mem_summary[mod].total_mem_usage -= list->size;
                    g_app_total += newsize;
                    g_mem_summary[mod].total_mem_usage += newsize;
                    list->size = newsize;
                    update_peak_calculation(1, mod);
                    print_graph_output();
                    ret = 0;
                }
                list = list->next;
            }
            mod++;
        }
        if (ret != 0) {
            ret = search_meminfo_list_and_update_new_size(ptr, newsize);
        }
    }
    return ret;
}

void son_mem_info_free(son_mem_info_t **listptr)
{
    son_module_e mod = QCA_MOD_WSPLCD;
    son_mem_info_t *tmpptr, *list;

    while(mod < QCA_MOD_MAX) {
        list = listptr[mod];
        while(list) {
            tmpptr = list;
            list = list->next;
            free(tmpptr);
        }
        mod++;
    }
}

void cleanup_all_tool_memory_usage()
{
    son_mem_info_free(g_alloc_list);

#ifdef SON_MEM_DEBUG_FREE
    son_mem_info_free(g_free_list);
#endif

    clean_up_filter_list();
    clean_up_filtered_data();

    fclose(wp);
    fclose(dbg_op);
    fclose(graph_op);

}

void display_struct_size_info()
{
    dbg_print(dbg_op, "struct son_mem_info : size: [%zu]\n", sizeof(son_mem_info_t));
    dbg_print(dbg_op, "struct son_mem_summary : size: [%zu]\n", sizeof(son_mem_summary_t));
    dbg_print(dbg_op, "struct list_memory : size: [%zu]\n", sizeof(list_memory_t));
    dbg_print(dbg_op, "struct list_data : size: [%zu]\n", sizeof(list_data_t));
    dbg_print(dbg_op, "struct son_mem_dbg_data : size: [%zu]\n", sizeof(son_mem_dbg_data_t));
}

/* total memory usage by mem debug tool */
uint32_t son_mem_debug_tool_memory_usage()
{
    uint32_t mem_total = 0;
    son_module_e mod = QCA_MOD_WSPLCD;

    while(mod < QCA_MOD_MAX ) {
        if (g_mem_summary[mod].total_alloc_entry == 0) {
            mod++;
            continue;
        }
        mem_total += g_mem_summary[mod].total_alloc_entry * sizeof(son_mem_info_t);
#ifdef SON_MEM_DEBUG_FREE
        mem_total += g_mem_summary[mod].total_free_entry * sizeof(son_mem_info_t);
#endif
        mod++;
    }
    mem_total += (list_data_count * sizeof (list_data_t));  // filter configuration list mem usage
    mem_total += (list_mem_count * sizeof (list_memory_t));     // min info list mem usage
    mem_total += list_data_tool_usage;  // filter function names total length
    return mem_total;
}

uint8_t read_process_mem_status(process_mem_status_t *stat, uint32_t *mem_usage)
{
    FILE *fmemstat = NULL;
    char memstatfile[PROC_CMD_LINE_FILE_LEN];
    char line[PROC_CMD_LINE_DATA_LEN];
    char *linecpy;
    uint8_t vmdatacount = 0, ret = -1;
    uint8_t entry = 0;

    while (entry < MAX_VMDATA) {
        stat->vmdata[entry] = NULL;
        entry++;
    }

    memset(stat, 0, sizeof(process_mem_status_t));
    snprintf(memstatfile, PROC_CMD_LINE_FILE_LEN, "/proc/%d/status", processid);

    fmemstat = fopen(memstatfile, "r");
    if (fmemstat == NULL) {
        return FILE_OPEN_FAIL;
    }

    while( fgets(line, PROC_CMD_LINE_DATA_LEN, fmemstat) != NULL)  {
        linecpy = strchr(line, '\n');
        if (linecpy != NULL) {
            *linecpy = '\0';
        }
        vmdatacount = 0;
        while (vmdatacount < MAX_VMDATA) {
            if (strstr (line, vmname[vmdatacount]) != NULL) {
                linecpy = line;
                while(!isdigit(*linecpy++));
                linecpy--;
                stat->vmdata[vmdatacount] = strdup(linecpy);
                *mem_usage += strlen(linecpy);
                if (ret) {
                    ret = 0;
                }
            }
            vmdatacount++;
        }
    }
    fclose (fmemstat);
    return ret;
}

void clean_up_process_mem_status(process_mem_status_t *stat)
{
    uint32_t entry = 0;

    while (entry < MAX_VMDATA) {
        if (stat->vmdata[entry]) {
            free(stat->vmdata[entry]);
        }
        entry++;
    }
}

void son_mem_dbg_display_detailed_list_info(FILE *wp)
{
    uint32_t entry = 0;
    uint32_t tool_usage = 0, tool_sanity = 0;
    struct timeval nowtime;
    son_mem_info_t *list = NULL;
    son_mem_summary_t *summ = NULL;
    list_memory_t *listmem = g_list_mem;
    son_module_e mod = QCA_MOD_WSPLCD;
    process_mem_status_t proc_stat;

    gettimeofday(&nowtime, NULL);
    print_mem_info(wp, "\n\nReport Date and Time:[%s]\n", ctime(&nowtime.tv_sec));

    print_mem_info(wp, STR_DISPLAY_FORMAT, "Module_Name", "Total_Mem", "Peak", "Tot_Alloc", "Tot_Free", "AllocEntry", "AllocFail" );

    while(mod < QCA_MOD_MAX ) {
        summ = &g_mem_summary[mod];
        if (summ->total_alloc_count == 0 ) { // this module has not been used for this application
            mod++;
            continue;
        }
        print_mem_info(wp, INT_DISPLAY_FORMAT, son_module_name[mod], summ->total_mem_usage, summ->peak_allocation, summ->total_alloc_count, summ->total_free_count, summ->total_alloc_entry, summ->malloc_failure);
        tool_sanity += summ->mem_alloc_mgmt_failure + summ->mem_realloc_mgmt_failure + summ->mem_free_mgmt_failure;
        mod++;
    }

    print_mem_info(wp, "Tool Sanity : [%d]\n", tool_sanity);

    tool_usage = son_mem_debug_tool_memory_usage(); // add tool usage
    if (read_process_mem_status(&proc_stat, &tool_usage) == 0) {
        print_mem_info(wp, "\n%-11s%-11s%-11s%-11s%-11s%-11s\n", "VmPeak", "VmSize", "VmHWM", "VmRSS", "VmData", "VmStk");
        print_mem_info(wp, "%-11s%-11s%-11s%-11s%-11s%-11s\n\n", proc_stat.vmdata[0] ? proc_stat.vmdata[0] : "0" , proc_stat.vmdata[1] ? proc_stat.vmdata[1] : "0",proc_stat.vmdata[2] ? proc_stat.vmdata[2] : "0",proc_stat.vmdata[3] ? proc_stat.vmdata[3] : "0",proc_stat.vmdata[4] ? proc_stat.vmdata[4] : "0",proc_stat.vmdata[8] ? proc_stat.vmdata[8] : "0");
        clean_up_process_mem_status(&proc_stat);

    }

    print_mem_info(wp, "Total SON Memory Usage = %d (in bytes), %f (in KB)\n", g_app_total+list_data_mem_usage, (float)(g_app_total+list_data_mem_usage)/1024);
    print_mem_info(wp, "Memory Debug Tool Usage = %d (in bytes), %f (in KB)\n", tool_usage, (float)tool_usage/1024);
    print_mem_info(wp, "Peak allocation: %d (in bytes), %f (in KB)\n\n", app_peak_allocation, (float)app_peak_allocation/1024);

    entry = 1;
    mod = QCA_MOD_WSPLCD;
    while(mod < QCA_MOD_MAX ) {

        summ = &g_mem_summary[mod];

        if (summ->total_alloc_count == 0 ) {
            mod++;
            continue;
        }

        list = g_alloc_list[mod];
        if (list != NULL && CHECK_BIT_ENABLED(g_mem_dbg_enable, DEBUG_ALLOC_LIST)) {

            print_mem_info(wp, "[%s]: Displaying Memory allocation list : Last %d Transactions \n", son_module_name[mod], summ->total_alloc_entry);
            print_mem_info(wp, "========================================================\n");
            while(list != NULL) {
                print_mem_info(wp, "[%d]: ptr[%p] size[%zu] alloc_func[%s] alloc_line[%u] \n", entry++,
                        list->mem_addr, list->size, list->afnname, list->aline);
                list = list->next;
            }
            print_mem_info(wp, "========================================================\n\n");
               fflush(wp);
        }
#ifdef SON_MEM_DEBUG_FREE
        entry = 1;
        list = g_free_list[mod];
        if (list != NULL && CHECK_BIT_ENABLED(g_mem_dbg_enable, DEBUG_FREE_LIST)) {

            print_mem_info(wp, "[%s]: Displaying Free list : Last %d Transactions \n", son_module_name[mod], summ->total_free_entry);
            print_mem_info(wp, "========================================================\n");
            while(list != NULL) {
                print_mem_info(wp, "[%d]: ptr[%p] size[%zu] alloc_func[%s] alloc_line[%u] free_func[%s] free_line[%u]\n", entry++,
                         list->mem_addr, list->size, list->afnname, list->aline, list->ffnname, list->fline);
                list = list->next;
            }
            print_mem_info(wp, "========================================================\n\n");
               fflush(wp);
        }
#endif
        entry = 1;
        mod++;
    }

    if (CHECK_BIT_ENABLED(g_mem_dbg_enable, DEBUG_FILTER_LIST)) {
        if (listmem != NULL) {
            print_mem_info(wp, "TOTAL FILTERED FUNCTION MEM USAGE = %d (in bytes), %f (in KB)\n", list_data_mem_usage, (float)list_data_mem_usage/1024);
            print_mem_info(wp, "Filtered Allocation Memory List : Total Entries [%d]\n", list_mem_count);
             print_mem_info(wp, "================================\n\n");
             while(listmem)
             {
                 print_mem_info(wp, "ptr [%p] size [%zu]\n", listmem->mem_addr, listmem->size);
                 listmem = listmem->next;
             }
        }
    }
      fflush(wp);
}

void son_mem_dbg_display_minimal_list_info(FILE *wp)
{
    uint32_t tool_usage = 0;
    process_mem_status_t proc_stat;

    if (read_process_mem_status(&proc_stat, &tool_usage) == 0 ) {
        print_mem_info(wp, "%-14d%-14d%-14d%-14d%-11s%-11s%-11s%-11s%-11s%-11s\n", list_mem_count, list_data_mem_usage, son_mem_debug_tool_memory_usage()+tool_usage, list_data_mem_usage+son_mem_debug_tool_memory_usage()+tool_usage, proc_stat.vmdata[0], proc_stat.vmdata[1], proc_stat.vmdata[2], proc_stat.vmdata[3], proc_stat.vmdata[4], proc_stat.vmdata[8]  );

        clean_up_process_mem_status(&proc_stat);
    }

    if (CHECK_BIT_ENABLED(g_mem_dbg_enable, DEBUG_FILTER_LIST)) {
        list_memory_t *list = g_list_mem;
        print_mem_info(wp, "Allocated Memory List :\n");
        print_mem_info(wp, "=======================\n");
        while(list) {
            print_mem_info(wp, "ptr [%p] size [%zu]\n", list->mem_addr, list->size);
            list = list->next;
        }
        print_mem_info(wp, "=======================\n");
    }
    fflush(wp);

}


