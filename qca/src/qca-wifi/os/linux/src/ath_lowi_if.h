/*
 * Copyright (c) 2019 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <osdep.h>
#include "osif_private.h"

#ifndef _ATH_LOWI_IF_H__
#define _ATH_LOWI_IF_H__

#if ATH_SUPPORT_LOWI
#include "ol_if_athvar.h"

#define TARGET_OEM_CONFIGURE_WRU	0x80
#define TARGET_OEM_CONFIGURE_FTMRR	0x81

#define LOWI_LCI_REQ_WRU_OK             27
#define LOWI_FTMRR_OK                   28

#define LOWI_MESSAGE_WRU_POSITION          8
#define LOWI_MESSAGE_FTMRR_POSITION        8
#define LOWI_MESSAGE_REQ_ID_POSITION       4
void wifi_pos_register_cbs(struct wlan_objmgr_psoc *psoc);
#else
static inline void wifi_pos_register_cbs(struct wlan_objmgr_psoc *psoc)
{
}
#endif

#endif /* _ATH_LOWI_IF_H__*/
