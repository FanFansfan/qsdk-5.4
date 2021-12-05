/* @File:   qca-son-mem-debug.h
 * @Notes:  This Header file has declaration for SON modules and Sub modules Identifier
 *          And also has declaration of Memory management debug APIs that can
 *          be used in SON applications
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#ifndef QCA_SON_MEM_DEBUG_H
#define QCA_SON_MEM_DEBUG_H

#include <stdint.h>
#define MEM_DBG_FILE_NAME_MAX_LEN 48

/* Modules present in SON applications */
typedef enum son_module
{
/* WSPLCD module */
    QCA_MOD_WSPLCD                  = 0,
/* SON Libraries */
    QCA_MOD_LIBSTORAGE              = 1,
    QCA_MOD_LIBHYFICOMMON           = 2,
    QCA_MOD_LIBWPA2                 = 3,
    QCA_MOD_LIBIEEE1905             = 4,
    QCA_MOD_LIBWIFISONCFG           = 5,
    QCA_MOD_LIBHYFI_BRIDGE          = 6,
/* HYD Modules */
    QCA_MOD_HYD_CORE                = 7,
    QCA_MOD_HYD_HYCTL               = 8,
    QCA_MOD_HYD_MANAGERS_MC         = 9,
    QCA_MOD_HYD_MANAGERS_PLC        = 10,
    QCA_MOD_HYD_MANAGERS_WLAN       = 11,
    QCA_MOD_HYD_MCFWDTBL_WLAN2G     = 12,
    QCA_MOD_HYD_MCFWDTBL_WLAN5G     = 13,
    QCA_MOD_HYD_MCFWDTBL_WLAN6G     = 14,
    QCA_MOD_HYD_PC_SERVICE          = 15,
    QCA_MOD_HYD_PS_SERVICE          = 16,
    QCA_MOD_HYD_PCW_SERVICE         = 17,
    QCA_MOD_HYD_PCE_SERVICE         = 18,
    QCA_MOD_HYD_PCP_SERVICE         = 19,
    QCA_MOD_HYD_HE_SERVICE          = 20,
    QCA_MOD_HYD_IEEE1905_SERVICE    = 21,
    QCA_MOD_HYD_TDSERVICE           = 22,
    QCA_MOD_HYD_LOGSERVICE          = 23,
    QCA_MOD_HYD_WLB_BANDMONMBSA     = 24,
    QCA_MOD_HYD_WLB_MONITOR         = 25,
    QCA_MOD_HYD_WLB_STEERALGMBSA    = 26,
    QCA_MOD_HYD_WLB_STEERMSG        = 27,
    QCA_MOD_HYD_WLB_WLANIF_MBSA     = 28,
/* LBD Modules */
    QCA_MOD_LBD_CORE                = 29,
    QCA_MOD_LBD_BANDMON             = 30,
    QCA_MOD_LBD_DIAGLOG             = 31,
    QCA_MOD_LBD_ESTIMATOR           = 32,
    QCA_MOD_LBD_PERSIST             = 33,
    QCA_MOD_LBD_STADB               = 34,
    QCA_MOD_LBD_STEERALG            = 35,
    QCA_MOD_LBD_STEEREXEC           = 36,
    QCA_MOD_LBD_WLANIF_ATH10K       = 37,
    QCA_MOD_LBD_WLANIF              = 38,
/* PLC SON */
    QCA_MOD_PLC_SON                 = 39,
/* MAP */
    QCA_MOD_MAP_SERVICE             = 40,
/* Non SON modules */
    QCA_NON_SON                     = 41,

    QCA_MOD_MAX = 42
} son_module_e;

/* Memory allocations are classified into following categories */
typedef enum son_mem_category
{
    CAT_DEFAULT = 0,    // Uncategorized
    CAT_INIT = 1,
    CAT_EVENT_BASED = 2
} son_mem_category_e;


typedef struct son_mem_dbg_data son_mem_dbg_data_t;
typedef enum son_mem_category son_mem_category_e;
typedef enum son_module son_module_e;

//===================
//Function prototypes
//===================
void son_initialize_mem_debug(uint8_t EnableFeature, uint8_t OnlyAuditing, uint64_t Disable_Module,
        uint32_t max_free_track, uint8_t WriteLogToFile,  uint8_t EnableFilter, FILE *list_file );
void *son_malloc_mem_debug(size_t size, son_mem_dbg_data_t *dbg_data);
void *son_malloc_debug(size_t size, const char *func, uint32_t line, son_module_e mod, son_mem_category_e cat, void *cdata);
void *son_calloc_debug(size_t nmemb, size_t size, const char *func, uint32_t line ,
        son_module_e mod, son_mem_category_e cat, void *cdata );
void *son_realloc_debug(void *oldptr, size_t newsize, const char *func, uint32_t line ,
        son_module_e mod, son_mem_category_e cat, void *cdata );
void son_free_debug(void *ptr, const char *func, uint32_t line, son_module_e mod, uint8_t is_realloc);
char *son_strdup_debug(const char *oldptr, const char *func, uint32_t line, son_module_e mod, son_mem_category_e cat, void *cdata);

void son_mem_dbg_display_list();    // call this function from SON applications to retrieve memory information

/*
Macro to be used for preparing debug-data, while calling the debug API "son_malloc_mem_debug"
*/
/*
#define prepare_son_mem_dbg_data(category, category_data)     \
    struct son_mem_dbg_data dbg_data =          \
    {                                           \
        .func = __func__,                       \
        .line = __LINE__,                       \
        .mod = QCA_MOD_WSPLCD,                  \
        .smod = QCA_MOD_LBD,                    \
        .cat = category,                        \
        .cdata = category_data                  \
    }
*/

#undef QCA_MOD_INPUT
#endif      /* QCA_SON_MEM_DEBUG_H */
