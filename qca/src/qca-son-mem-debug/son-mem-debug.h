/* @File:   son-mem-debug.h
 * @Notes:  This Header file has macro definition that replaces the standard library
 *          memory management API's with debug enabled SON Memory Management API's
 *          List of API's replaced is listed below,
 *              malloc  =>  son_malloc_debug
 *              calloc  =>  son_calloc_debug
 *              realloc =>  son_realloc_debug
 *              free    =>  son_free_debug
 *              strdup  =>  son_strdup_debug
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

/* IMPORTANT: Before including this header file, Please define QCA_MOD_INPUT using below macro
 * List of Modules and Submodules is defined in "qca-son-mem-debug.h" header file
 *
 * #define QCA_MOD_INPUT <required_mod>
 */

#undef malloc
#undef calloc
#undef realloc
#undef free
#undef strdup

#undef DEFAULT_MOD_DATA
#define DEFAULT_MOD_DATA __func__,__LINE__,QCA_MOD_INPUT,CAT_DEFAULT,NULL

#define malloc(x) son_malloc_debug(x, DEFAULT_MOD_DATA )
#define calloc(x,y) son_calloc_debug(x, y, DEFAULT_MOD_DATA)
#define realloc(x,y) son_realloc_debug(x, y, DEFAULT_MOD_DATA )
#define free(x) son_free_debug(x, __func__, __LINE__, QCA_MOD_INPUT, 0 )
#define strdup(x) son_strdup_debug(x, DEFAULT_MOD_DATA )

