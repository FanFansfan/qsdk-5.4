/*
 * @File: mcManager.h
 *
 * @Abstract: Multicast manager
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015, 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef mcManager__h
#define mcManager__h

/* initialization */
void mcManagerInit(void);
int mcManagerStart(const char *BrName);
int mcManagerStop(const char *BrName);
int mcManagerStopAll(void);
#endif
