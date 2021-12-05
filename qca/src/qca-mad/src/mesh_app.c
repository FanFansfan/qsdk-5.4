/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/* C and system library includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <signal.h>

/* Hyfi Common Dependencies */
#include <evloop.h>
#include <csh.h>
#include <dbg.h>

/* Mesh Application includes */
#include <mesh_app.h>
#include <../meshevent/meshEvent.h>
#include <../ieee1905/meshIeee1905.h>
#include <../dataelements/dataElements.h>

static struct dbgModule *dbgModule;

/* State info for mesh app main level */
struct {
    int DoDaemonize;
    int Mode;
    struct dbgModule *DebugModule;
    int Port; /*telnet port used for debug output */
} meshAppS;

/* Debugging options */
const struct dbgInitOptions meshAppDbgInitOptions = {
    .ProgramName = "MESH",
    .EnvName = "MESH_DBG_LEVELS",
};

/**
 * @brief React to a signal to shut down the daemon by marking the event
 *        event loop as terminated.
 */
static void meshAppShutdownSignalHandler(int signal)
{
    evloopAbort();
}

/**
 * @brief Init Mesh Application
 */
int meshAppInits(void)
{
    int meshSockfd = 0;

    meshSockfd = meshEventInit();
    if (meshSockfd == MESH_NOK) {
        dbgf(dbgModule, DBGERR, "%s: mesh api socket create failed\n", __func__);
        return MESH_NOK;
    }
    dbgf(dbgModule, DBGDEBUG, "%s: mesh api socket created\n", __func__);

    if ( meshAppS.Mode & IEEE1905_MODE ) {
        dbgf(dbgModule, DBGINFO, "%s: IEEE1905 Init called\n", __func__);
        meshIeee1905Init();
    }
    if ( meshAppS.Mode & DE_MODE ) {
        dbgf(dbgModule, DBGINFO, "%s: DataElements Init called\n", __func__);
        dataElementsInit();
    }

    return MESH_OK;
}

/**
 * @brief Run Mesh Application forever
 */
void meshAppRun(void)
{
    evloopRunPrepare();

    /* Run forever */
    evloopRun();
}

/**
 * @brief Gracefully stop Mesh Application
 */
void meshAppFini(void)
{
    meshEventFini();
}

/**
 * @brief Print Mesh Application Version
 */
static void meshAppVersion(void)
{
    fprintf(stderr, "%s\n", MESH_API_VERSION_STR);
}

/**
 * @brief Mesh Application Usage
 */
void meshAppUsage()
{
    dbgf(dbgModule, DBGINFO, "Usage: mesh_app [-dhv] [-m mode] [-P Debug Output Port]");
    dbgf(dbgModule, DBGINFO, "       -d: Do Daemonize.");
    dbgf(dbgModule, DBGINFO, "       -m: Specify mode of operation.");
    dbgf(dbgModule, DBGINFO, "       -h: Show usage.");
    dbgf(dbgModule, DBGINFO, "       -v: Show version information.");
    dbgf(dbgModule, DBGINFO, "       -P: Debug Output Port.");
    exit(1);
}

/**
 * @brief Parse cmd line arguments
 */
void meshAppParseArgs(char **argv)
{
    char *Arg;

    argv++;     /* skip program name */
    while ((Arg = *argv++) != NULL) {
        if (!strcmp(Arg, "-d")) {
            meshAppS.DoDaemonize = 1;
        } else
        if (!strcmp(Arg, "-m")) { /* configuration file */
            Arg = *argv++;
            if (Arg == NULL)
                meshAppUsage();
            meshAppS.Mode = atoi(Arg);
        } else
        if (!strcmp(Arg, "-h")) { /* show usage */
            meshAppUsage();
        } else
        if (!strcmp(Arg, "-v")) { /* show Mesh App version */
            meshAppVersion();
        } else
        if (!strcmp(Arg, "-P")) { /* Debug output port */
            Arg = *argv++;
            if (Arg == NULL)
                meshAppUsage();
            meshAppS.Port = atoi(Arg);
        } else {
            dbgf(dbgModule ,DBGERR, "INVALID ARG: %s", Arg);
            meshAppUsage();
        }
    }
    return;
}

/**
 * The main function of Mesh Application
 */
int main(int argc, char **argv)
{
    meshAppS.Port = MESH_API_PORT;
    meshAppS.DoDaemonize = 0;

    /* Set Debug Options */
    dbgInit1(&meshAppDbgInitOptions);

    /* Register for debug messages from this file */
    dbgModule = dbgModuleFind("meshApp");
    meshAppS.DebugModule = dbgModule;
    meshAppS.DebugModule->Level = DBGINFO;

    meshAppParseArgs(argv);

    if (meshAppS.DoDaemonize) {
        if (daemon(0,0)) {
            perror("daemon");
            exit(1);
        }
    }

    dbgf(dbgModule, DBGDEBUG, "%s : %d start Mesh API Layer\n", __func__, __LINE__);

    /* Add debugging shell capability */
    cshInit(meshAppS.Port);

    if (meshAppInits() == MESH_NOK) {
        dbgf(dbgModule, DBGDEBUG, "%s: Mesh App Inits failed", __func__);
        return 0;
    }

    /* Register signal handlers for an orderly shutdown. */
    signal(SIGINT, meshAppShutdownSignalHandler);
    signal(SIGTERM, meshAppShutdownSignalHandler);

    /* Main event loop waits for things to happen */
    dbgf(dbgModule, DBGDEBUG, "%s: Entering evloop", __func__);
    meshAppRun();

    printf("Exiting mesh App\n");
    meshAppFini();

    return 0;
}
