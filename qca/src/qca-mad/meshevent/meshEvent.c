/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.

*/

/*-M- Mesh Event -- use for customer daemon for communication with HYD.
 *
 * */

/*===========================================================================*/
/*================= Includes and Configuration ==============================*/
/*===========================================================================*/


/* C and system library includes */
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <memory.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <net/ethernet.h>

/* Hyfi Common Dependencies */
#include <evloop.h>
#include <dbg.h>
#include <bufrd.h>
#include <cmd.h>

#include "ieee1905_defs.h"
#include "meshEvent.h"
#include "../ieee1905/meshIeee1905.h"
#include "../src/mesh_app.h"
#include "../dataelements/dataElementsHyd.h"

#define meshEventTrace() dbgf(dbgModule, DBGDEBUG, "Enter %s", __func__)

/*===========================================================================*/
/*================= HYD DEBUGGING FUNCTIONS - REMOVE LATER ==================*/
/*===========================================================================*/

static struct dbgModule *dbgModule;

/*===========================================================================*/
/*================= MESH API LAYER SOCKET AND FRAME PARSING =================*/
/*===========================================================================*/

struct meshEventState {
    int IsInit;
    int Socket;
    struct bufrd ReadBuf;           /* for reading from */
    struct evloopTimeout agingTimeout; /* evloop timer */
    struct dbgModule *DebugModule; /* debug message context */
} meshEventS;


static int SetFdNonBlocking(int iFd)
{
  int iIfFlags = 0;

  if((iIfFlags = fcntl(iFd, F_GETFL, 0)) < 0) {
      return MESH_NOK;
  }
  iIfFlags |= O_NONBLOCK;
  if((fcntl(iFd, F_SETFL, iIfFlags)) < 0) {
      return MESH_NOK;
  }
  return MESH_OK;
}

/**
 * Mesh API client Socket
 */
int meshEventSocketCreate(void)
{
    int meshSock_len;
    struct sockaddr_un client_addr = {
        AF_UNIX,
        MESH_CLIENT
    };
    int sockfd = -1;

    dbgf(dbgModule, DBGDEBUG,
         "%s: %d Create mesh api socket", __func__, __LINE__);
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    strlcpy(client_addr.sun_path, MESH_CLIENT, sizeof(client_addr.sun_path));
    meshSock_len = strlen(MESH_CLIENT);
    client_addr.sun_path[meshSock_len] = '\0';

    if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) == MESH_NOK) {
        dbgf(dbgModule, DBGERR,
             "%s: mesh socket create(%s) failed:%s",
             __func__, client_addr.sun_path, strerror (errno));
        return MESH_NOK;
    }
    if (unlink (client_addr.sun_path)) {
        if (errno != ENOENT) {
            dbgf(dbgModule, DBGERR,
                 "%s: mesh unlink(%s) failed: %s",
                 __func__, client_addr.sun_path, strerror (errno));
            close(sockfd);
            return MESH_NOK;
        }
    }
    if (bind (sockfd, (struct sockaddr *)(&client_addr), sizeof (client_addr)) == MESH_NOK) {
        dbgf(dbgModule, DBGERR,
             "%s: bind(%s) failed: %s", __func__,
             client_addr.sun_path, strerror (errno));
        close(sockfd);
        return MESH_NOK;
    }
    if (chmod (client_addr.sun_path, 0666) == MESH_NOK) {
        dbgf(dbgModule, DBGERR,
             "%s: chmod(%s) failed: %s", __func__,
             client_addr.sun_path, strerror (errno));
        close(sockfd);
        return MESH_NOK;
    }

    if (SetFdNonBlocking(sockfd) == MESH_NOK) {
        dbgf(dbgModule, DBGERR,
             "%s: SetFdNonBlocking(%s) failed: %s",
             __func__, client_addr.sun_path, strerror (errno));
        close(sockfd);
        return MESH_NOK;
    }

    return sockfd;
}

/**
 * Mesh API receive buffer
 */
void meshEventRead(void *cookie)
{
    int  frame_type = 0;

    struct bufrd *readBuf =  &meshEventS.ReadBuf;
    u_int32_t frameLen = bufrdNBytesGet(readBuf);

    char *frame = bufrdBufGet(readBuf);

    if (bufrdErrorGet(readBuf)) {
        dbgf(dbgModule, DBGDEBUG, "%s buffer read error", __func__);
        close(meshEventS.Socket);
        bufrdDestroy(&meshEventS.ReadBuf);
        meshEventS.Socket = meshEventSocketCreate();
        meshEventRdbufRegister();
        return;
    }

    if (!frameLen) {
        return;
    }

    /* Process received frame */
    frame_type = (int)frame[MESH_EVENT_FRM_TYPE_IDX];

    dbgf(dbgModule, DBGDEBUG,
         "%s frame type received from hyd = %d", __func__, frame_type);

    switch (frame_type) {
        case MESH_EVENT_FRAME_IEEE1905:
            dbgf(dbgModule, DBGDEBUG,
                 "%s frame identified as IEEE1905", __func__);
            if (meshIeee1905ParseFrame(frame, frameLen) == MESH_EVENT_NO_DATA) {
                dbgf(dbgModule, DBGINFO,
                     "%s No or incomplete data received in 1905 frame", __func__);
            }
            break;
        case MESH_EVENT_FRAME_DE:
            dbgf(dbgModule, DBGDEBUG,
                 "%s frame identified as DE", __func__);
            if (meshDEParseFrame(frame) == MESH_EVENT_NO_DATA) {
                dbgf(dbgModule, DBGINFO,
                     "%s No or incomplete data received in DE frame", __func__);
            }
            break;
        default:
            dbgf(dbgModule, DBGINFO,
                 "%s unidentified frame received", __func__);
            break;
    }

    bufrdConsume(readBuf, frameLen);
    dbgf(dbgModule, DBGDEBUG, "%s read complete", __func__);
    return;
}

int meshEventSend(const char *buf, int NBytes) {
    int meshSock_len;
    struct sockaddr_un server_addr;
    meshEventTrace();

    if (!buf) {
        fprintf(stdout, "%s: Invalid buffer to send \n",__func__);
        return MESH_NOK;
    }

    if (meshEventS.Socket == MESH_NOK) {
        dbgf(dbgModule, DBGERR, "%s Socket is down", __func__);
        return MESH_NOK;
    }

    if (NBytes > MESH_FRAME_LEN_MAX) {
        fprintf(stdout, "%s: Size greater than max size allowed", __func__);
        return MESH_NOK;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strlcpy(server_addr.sun_path, MESH_SERVER, sizeof(server_addr.sun_path));
    meshSock_len = strlen(MESH_SERVER);
    server_addr.sun_path[meshSock_len] = '\0';

    if (sendto(meshEventS.Socket, buf, NBytes, MSG_DONTWAIT,
                (const struct sockaddr *)&server_addr, sizeof(server_addr)) == MESH_NOK) {
        dbgf(dbgModule, DBGERR, "%s send to %s failed %s", __func__,
                server_addr.sun_path, strerror (errno));
        return MESH_NOK;
    }
    return MESH_OK;
}

void meshEventRdbufRegister(void)
{
    meshEventTrace();
    bufrdCreate(&meshEventS.ReadBuf, "meshEvent-rd",
            meshEventS.Socket,
            MESH_FRAME_LEN_MAX,
            meshEventRead /* callback */,
            NULL);
}

static void meshEventAgingTimeoutHandler(void *cookie) {
    evloopTimeoutRegister(&meshEventS.agingTimeout, 6, 0);
}

static const struct cmdMenuItem meshEventMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    CMD_MENU_END()
};

static const char *meshEventMenuHelp[] = {
    "event -- Mesh Application Layer event socket API",
    NULL
};

static const struct cmdMenuItem meshEventMenuItem = {
    "event",
    cmdMenu,
    (struct cmdMenuItem *)meshEventMenu,
    meshEventMenuHelp
};

static void meshEventMenuInit(void)
{
    cmdMainMenuAdd(&meshEventMenuItem);
}

int meshEventInit(void)
{
    meshEventTrace();
    if(meshEventS.IsInit)
        return MESH_NOK;

    memset(&meshEventS, 0, sizeof meshEventS);
    meshEventS.IsInit = 1;

    dbgModule = dbgModuleFind("event");
    meshEventS.DebugModule = dbgModule;
    meshEventS.DebugModule->Level = DBGINFO;

    /* create socket */
    meshEventS.Socket = meshEventSocketCreate();

    if (meshEventS.Socket == MESH_NOK) {
        dbgf(dbgModule, DBGERR,
             "%s : %d error in socket create", __func__, __LINE__);
        return meshEventS.Socket;
    }

    /* register read buffer */
    meshEventRdbufRegister();

    /* create evloop timer */
    evloopTimeoutCreate(&meshEventS.agingTimeout, "meshEventTimeout",
                        meshEventAgingTimeoutHandler, NULL);

    /* register evloop timeout */
    evloopTimeoutRegister(&meshEventS.agingTimeout, 6, 0);

    meshEventMenuInit();

    return meshEventS.Socket;
}

void meshEventFini(void)
{
    /* Close socket if valid */
    if (meshEventS.Socket != MESH_NOK) {
        close(meshEventS.Socket);
        meshEventS.Socket = MESH_NOK;
    }
    meshEventS.IsInit = 0;
}
