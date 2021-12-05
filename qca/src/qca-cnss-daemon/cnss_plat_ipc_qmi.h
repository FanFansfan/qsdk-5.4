/*
 * Copyright (c) 2021 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */


#ifndef __CNSS_PLAT_IPC_QMI_H__
#define __CNSS_PLAT_IPC_QMI_H__

#ifdef CNSS_PLAT_IPC_QMI
int cnss_plat_ipc_qmi_init();
void cnss_plat_ipc_qmi_deinit();
void cnss_plat_ipc_qmi_msg_process();
int cnss_plat_ipc_qmi_get_fd();
#else
static inline
int cnss_plat_ipc_qmi_init()
{
	return 0;
}

static inline
void cnss_plat_ipc_qmi_deinit() {}

static inline
void cnss_plat_ipc_qmi_msg_process() {}

static inline
int cnss_plat_ipc_qmi_get_fd()
{
	return -1;
}
#endif

#endif
