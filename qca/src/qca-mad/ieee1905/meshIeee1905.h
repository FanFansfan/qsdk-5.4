/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.

*/

#ifndef mesh_ieee1905__h /*once only*/
#define mesh_ieee1905__h

int meshIeee1905ParseFrame(char *frame, u_int32_t frameLen);
int meshIeee1905Init(void);

#endif
