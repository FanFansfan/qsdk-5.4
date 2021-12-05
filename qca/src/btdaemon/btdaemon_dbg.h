/* Copyright (c) 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef _BTD_DBG_H_
#define _BTD_DBG_H_

#define BTD_DBG_ERROR   0x00000001
#define BTD_DBG_INFO    0x00000002
#define BTD_DBG_TRACE   0x00000004

#define BTD_DBG_DEFAULT (BTD_DBG_ERROR)

extern unsigned int g_dbg_level;

#ifdef DEBUG
#define DPRINTF(_level, _x...)\
    do {\
        if (g_dbg_level & (_level))\
        {\
            fprintf(stderr, _x);\
        }\
    } while (0);

#else
#define DPRINTF(_level, x...)  do { } while (0);
#endif

#endif /* _BTD_DBG_H_ */
