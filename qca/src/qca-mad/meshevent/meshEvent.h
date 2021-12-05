/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.

*/

#ifndef meshEvent__h /*once only*/
#define meshEvent__h

#define MESH_SERVER      "/var/run/mesh_server"
#define MESH_CLIENT      "/var/run/mesh_client"
#define MESH_FRAME_LEN_MAX 2048
#define MESH_EVENT_FRM_TYPE_IDX 0
#define SERVICE_TYPE_DE 2

#include "ieee1905_defs.h"

void meshEventRdbufRegister(void);
int meshEventRun(void);
int meshEventStart(void);
void meshEventRead(void *cookie);
int meshEventInit(void);
int meshEventSocketCreate(void);
void meshEventFini(void);
int meshEventSend(const char *buf, int NBytes);

enum MeshEventStatus
{
    MESH_EVENT_OK = 0,
    MESH_EVENT_NO_DATA,
    MESH_EVENT_SOCKET_ERROR,
};

enum MeshEventFrameType
{
    MESH_EVENT_FRAME_IEEE1905 = 1,
    MESH_EVENT_FRAME_DE = 2,
};

#endif
