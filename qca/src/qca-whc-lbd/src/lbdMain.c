/*
 * @File: lbdMain.c
 *
 * @Abstract: Load balancing daemon main
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2014-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011, 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#if CALLTRACE_SUPPORT
#include <libunwind.h>
#endif

#include <dbg.h>
#include <evloop.h>
#include <module.h>
#include <profile.h>
#include <split.h>

#include <lb_common.h>
#include <lbd_types.h>

#include <diaglog.h>
#include <wlanif.h>
#include <steerexec.h>
#include <stadb.h>
#include <bandmon.h>
#include <stamon.h>
#include <estimator.h>
#include <steeralg.h>
#include <persist.h>
#ifdef LBD_MODULE_SONEVENT
#include <soneventService.h>
#endif

#ifdef LBD_DBG_MENU
#include <csh.h>
#endif

#include "lbdMain.h"

#ifdef SON_MEMORY_DEBUG
#include "qca-son-mem-debug.h"
#endif

/* Debugging options */
/*private*/ const struct dbgInitOptions lbdDbgInitOptions = {
    .ProgramName = "LBDR",
    .EnvName = "LBDR_DBG_LEVELS",
};

struct profileElement lbdElementDefaultTable[] = {
    {"LoadBalancingInterfaces",     "ath0"  },
#ifdef SON_MEMORY_DEBUG
    {"EnableMemDebug",              "0" },
    {"MemDbgReportInterval",        "0" },
    {"MemDbgAuditingOnly",          "0" },
    {"MemDbgDisableModule",         "0" },
    {"MemDbgFreedMemCount",         "0" },
    {"MemDbgWriteLogToFile",        "0" },
    {"MemDbgEnableFilter",          "0" },
    {"MemDbgFilterFileName",        NULL },
#endif
    {NULL,                          NULL    }
};

/* State info for lbd main level */
/*private*/ struct {
    struct dbgModule *DebugModule;
    int DoDaemonize;    /* detach from parent */
    const char *ConfFile;
    int cfg80211; /* Flag to switch between wext/cfg80211 */

#ifdef SON_MEMORY_DEBUG
    int                 report_interval;  /* Configure report interval (seconds)  */
    struct evloopTimeout memdbgTimer;
#endif

} lbdS;

#define lbdDebug(level, ...) \
        dbgf(lbdS.DebugModule,(level),__VA_ARGS__)

#if CALLTRACE_SUPPORT
/**
 * @brief storing the calltrace info into a separate file
 */

FILE *fpLog;
int lbd_print(const char *fmt, ...)
{
    va_list ap;
    struct timeval curTime;

    va_start(ap, fmt);
    if (fpLog) {
        gettimeofday(&curTime, NULL);
        fprintf(fpLog, "[%lu.%lu] ", curTime.tv_sec, curTime.tv_usec);
        vfprintf(fpLog, fmt, ap);
        fflush(fpLog);
    } else {
        vprintf(fmt, ap);
    }
    va_end(ap);
    return 0;
}
#endif

/**
 * @brief Perform a clean shutdown of the daemon, terminating all of
 *        underlying components.
 */
static void lbdFini(void) {
    // Any errors are ignored as there is not much we can do at this point.
    // We're about to pull the plug.
    persist_fini();
    steeralg_fini();
    stamon_fini();
    estimator_fini();
    bandmon_fini();
    stadb_fini();
    steerexec_fini();
    wlanif_fini();
    diaglog_fini();
#ifdef LBD_MODULE_SONEVENT
    soneventservice_fini();
#endif
}

/**
 * @brief React to a signal to shut down the daemon by marking the event
 *        event loop as terminated.
 */
static void lbdShutdownSignalHandler(int signal) {
#if CALLTRACE_SUPPORT
    fpLog  = fopen("/tmp/lbdCrash_log.txt", "a");
    unw_cursor_t cursor;
    unw_context_t context;
    char sym[256];

    switch(signal)
    {
        case SIGSEGV:
            lbd_print("SIGSEGV : Segmentation Fault\n");
        break;
        case SIGTERM:
            lbd_print("SIGTERM : Terminate\n");
        break;
        case SIGQUIT:
            lbd_print("SIGQUIT : Quit\n");
        break;
        case SIGILL:
            lbd_print("SIGILL : Illegal Instruction\n");
        break;
        case SIGTRAP:
            lbd_print("SIGTRAP : Trap\n");
        break;
        case SIGABRT:
            lbd_print("SIGABRT : Abort\n");
        break;
        case SIGFPE:
            lbd_print("SIGFPE : Floating-point Exception\n");
        break;
        default:
            lbd_print("Default Case Detected ! \n");
        break;
    }
    unw_getcontext(&context);
    unw_init_local(&cursor, &context);
    lbd_print("Process id : %d\n", getpid());

    while (unw_step(&cursor) > 0) {
        unw_word_t offset, pc;
        unw_get_reg(&cursor, UNW_REG_SP, &pc);
        if (pc == 0)
            break;
        lbd_print("0x%x    ", pc);
        if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
            lbd_print("Symbol : (%s+0x%x)\n", sym, offset);
        } else {
            lbd_print(" -- error: unable to obtain symbol name for this frame\n");
        }
    }
    lbd_print ("\n\n\n\n");
    fclose(fpLog);
    exit(0);
#else
    evloopAbort();
    lbdDebug(DBGINFO, "%s Received signal %d", __func__,signal);
    lbdFini();
#endif

}

static void lbdRun(void) {
    mdInit();
    evloopRunPrepare();

    while(!evloopIsAbort()) {
        evloopOnce();
    }
}

static void lbdVersion(void)
{
    fprintf(stderr, "%s\n", lbd_version);
}

static void lbdUsage(void) {

    lbdDebug(DBGINFO, "Usage: lbd [-d] [-C conf-file]");
    lbdDebug(DBGINFO, "       -d: Do NOT fork into the background: run in debug mode.");
    lbdDebug(DBGINFO, "       -C: Specify configuration file.");
    lbdDebug(DBGINFO, "       -h: Show usage.");
    lbdDebug(DBGINFO, "       -v: Show version information.");

    exit(1);
}

static void lbdParseArgs(char **argv) {
    char *Arg;

    lbdS.DoDaemonize = 1;

    argv++;     /* skip program name */
    while ((Arg = *argv++) != NULL) {
        if (!strcmp(Arg, "-d")) {
            lbdS.DoDaemonize = 0;
        } else
        if (!strcmp(Arg, "-C")) { /* configuration file */
            Arg = *argv++;
            if (Arg == NULL)
                lbdUsage();

            if (!access(Arg, R_OK))
                lbdS.ConfFile = Arg;
            else
                lbdS.ConfFile = NULL;
        } else
        if (!strcmp(Arg, "-h")) { /* show usage */
            lbdUsage();
        } else
        if (!strcmp(Arg, "-v")) { /* show lbd version */
            lbdVersion();
        } else
        if (!strcmp(Arg, "-cfg80211")) {
            lbdS.cfg80211=1;
        } else {
            lbdDebug(DBGERR, "INVALID ARG: %s", Arg);
            lbdUsage();
        }
    }
    return;
}

static LBD_STATUS lbdInit(void) {
    if (diaglog_init() != LBD_OK ||
        wlanif_init() != LBD_OK ||
#ifdef LBD_MODULE_SONEVENT
        soneventservice_init() != LBD_OK ||
#endif
        steerexec_init() != LBD_OK ||
        stadb_init() != LBD_OK ||
        bandmon_init() != LBD_OK ||
        estimator_init() != LBD_OK ||
        stamon_init() != LBD_OK ||
        steeralg_init() != LBD_OK ||
        persist_init() != LBD_OK) {
        return LBD_NOK;
    }

    return LBD_OK;
}



#ifdef SON_MEMORY_DEBUG
/*
 * @brief display memory usage summary information for every periodic interval
 */
void lbdMemDebugPeriodicTimeoutHandler(void *Cookie)
{
    // call to qcasonmemdebug library
    son_mem_dbg_display_list();

    /* Re-arm evloop timeout */
    evloopTimeoutRegister(
            &lbdS.memdbgTimer,
            lbdS.report_interval,
            0);
}

/*
 * @brief Initialize SON Memory debugging library based on input configuration
 *         and start tracking all the dynamic memory allocation
 */
static void lbdSonMemoryDebugInitialization()
{
    int enable_mem_debug;           /* Enable/Disable SON Memory debug and also configure debug mode (BitMask- Bit0: Enable Memory debugging, Bit1: Display allocation
ist, Bit2: Display free list, Bit3: Display filter list ) */
    int log_write_to_file;          /* Enable/Disable writing log to file and also configure logging mode (BitMask- Bit0: Enable/Disable Logging to file, Bit1: Write D
tailed Memory summary information, Bit2: Write Graph data, Bit3: Memory debug tool debugging (for engineering purpose)   ) */
    int audit_only;                 /* Enable/Disable Only Auditing */
    int freed_entry;                /* Configure number of freed memory information to keeptrack*/
    int enable_filter;              /* 0: Disable Filter, 1: Enable Blacklist 2: Enable Whitelist */
    long int disable_module;        /* Disable debugging the selected module : BitMask- Each bit corresponds to one module  */
    const char *filter_file = NULL;       /* Filter Filename to filter selected functions */

    FILE *filterfileptr = NULL;

    enable_mem_debug = profileGetOptsInt(mdModuleID_Debug, "EnableMemDebug", lbdElementDefaultTable);
    disable_module = profileGetOptsInt(mdModuleID_Debug, "MemDbgDisableModule", lbdElementDefaultTable);
    log_write_to_file = profileGetOptsInt(mdModuleID_Debug, "MemDbgWriteLogToFile", lbdElementDefaultTable);
    audit_only = profileGetOptsInt(mdModuleID_Debug, "MemDbgAuditingOnly", lbdElementDefaultTable);
    freed_entry = profileGetOptsInt(mdModuleID_Debug, "MemDbgFreedMemCount", lbdElementDefaultTable);
    enable_filter = profileGetOptsInt(mdModuleID_Debug, "MemDbgEnableFilter", lbdElementDefaultTable);
    filter_file = profileGetOpts(mdModuleID_Debug, "MemDbgFilterFileName", lbdElementDefaultTable);

    lbdS.report_interval = profileGetOptsInt(mdModuleID_Debug, "MemDbgReportInterval", lbdElementDefaultTable);

    if (enable_mem_debug ) {

        if (filter_file && strlen(filter_file) > 0) {
            filterfileptr = fopen( filter_file, "r");
            if (filterfileptr) {
                lbdDebug(DBGERR, "MEM-DBG-ERR: filter file open failed!");
            }
        }

        son_initialize_mem_debug(enable_mem_debug, audit_only, disable_module, freed_entry, log_write_to_file, enable_filter, filterfileptr);

        if (lbdS.report_interval) {
            /* creat evloop timer */
            evloopTimeoutCreate(
                    &lbdS.memdbgTimer,
                    "MemoryDebugTimer",
                    lbdMemDebugPeriodicTimeoutHandler,
                    NULL);  /* Cookie */
            /* register evloop timeout */
            evloopTimeoutRegister(
                    &lbdS.memdbgTimer,
                    lbdS.report_interval,
                    0);
        }
    }

    if (filterfileptr != NULL) {
        fclose(filterfileptr);
    }
    if (filter_file) {
        free((char*) filter_file);
    }

}
#endif

void lbFatalShutdown(void) {
    lbdFini();
    exit(1);
}

/* The main function of lbd.
 * Usage: lbd [-d] [-C conf-file]
 * -d: Do NOT fork into the background: run in debug mode.
 * -C: Specify configuration file.
 */
int main(int argc, char **argv) {

    /* Make sure our debug options are set before any debugging! */
    dbgInit1(&lbdDbgInitOptions);

    /* Register for debug messages from this file */
    lbdS.DebugModule = dbgModuleFind("lbd");
    lbdS.DebugModule->Level = DBGDEBUG;

    lbdDebug(DBGDEBUG, "Entering main of lbd executive program");

    /* Now we can look at arguments */
    lbdParseArgs(argv);

    if (lbdS.DoDaemonize) {
        if (daemon(0,0)) {
            perror("daemon");
            exit(1);
        }
    }

    /* Make sure profile module initilized before other modules. */
    profileInit(lbdS.ConfFile);

    /* Initialize SON memory debugging feature */
#ifdef SON_MEMORY_DEBUG
    lbdSonMemoryDebugInitialization();
#endif

    // Register signal handlers for an orderly shutdown.
    signal(SIGINT, lbdShutdownSignalHandler);
    signal(SIGTERM, lbdShutdownSignalHandler);
#if CALLTRACE_SUPPORT
    signal(SIGSEGV,lbdShutdownSignalHandler);
    signal(SIGQUIT, lbdShutdownSignalHandler);
    signal(SIGILL, lbdShutdownSignalHandler);
    signal(SIGTRAP, lbdShutdownSignalHandler);
    signal(SIGABRT, lbdShutdownSignalHandler);
    signal(SIGFPE, lbdShutdownSignalHandler);
#endif
#ifdef LBD_SUPPORT_QSDK
    wlanif_setCfg80211(lbdS.cfg80211);
#endif

    if (lbdInit() != LBD_OK) {
        lbdDebug(DBGERR, "lbd init failed!");
        lbFatalShutdown();
    }

#ifdef LBD_DBG_MENU
    /* Add debugging shell capability */
    cshInit(LBD_DBG_PORT);
#endif

    /* must called after all initilization */
    mdDoListenInitCB();

    /* Main event loop waits for things to happen...
     * is the ONLY place we should EVER wait for anything to happen.
     */
    lbdDebug(DBGDEBUG, "Entering evloopRun");
    lbdRun();

    lbdFini();

    /* Probably won't get here... */
    lbdDebug(DBGDEBUG, "Leaving lbd executive program");

    return 0;
}
