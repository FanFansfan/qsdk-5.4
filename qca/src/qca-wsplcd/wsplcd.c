/* @File: wsplcd.c
 * @Notes:  IEEE1905 AP Auto-Configuration Daemon
 *          AP Enrollee gets wifi configuration from AP Registrar via
 *          authenticated IEEE1905 Interfaces
 *
 * Copyright (c) 2012, 2015-2018 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2012, 2015-2016 Qualcomm Atheros, Inc.
 *
 * Qualcomm Atheros Confidential and Proprietary.
 * All rights reserved.
 *
 */

/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "wsplcd.h"
#include "eloop.h"
#include "ucpk_hyfi20.h"
#include "apac_priv.h"
#include "apac_hyfi20_mib.h"
#include <sys/time.h>
#if MAP_ENABLED
#include "apac_map.h"
#endif
#include <signal.h>
#if CALLTRACE_SUPPORT
#include <libunwind.h>
#endif

#ifdef SON_MEMORY_DEBUG
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#endif

char g_log_file_path[APAC_CONF_FILE_NAME_MAX_LEN];

char g_cfg_file[APAC_CONF_FILE_NAME_MAX_LEN];
#if MAP_ENABLED
char g_map_cfg_file[APAC_CONF_FILE_NAME_MAX_LEN];
apacMapEProfileMatcherType_e g_map_cfg_file_format;
#endif

int debug_level = MSG_INFO;
apacLogFileMode_e logFileMode = APAC_LOG_FILE_INVALID;

FILE *pLogFile = NULL;

extern int wlanIfConfigInit(u32);
void wlanIfConfigExit(void);

int dprintf(int level, const char *fmt, ...)
{
    va_list ap = {0};
    struct timeval curTime;

    va_start(ap, fmt);
    if (level >= debug_level) {
        if (pLogFile) {
            gettimeofday(&curTime, NULL);
            fprintf(pLogFile, "[%lu.%lu] ", curTime.tv_sec, curTime.tv_usec);
            vfprintf(pLogFile, fmt, ap);
            fflush(pLogFile);
        } else {
            vprintf(fmt, ap);
        }
	}
	va_end(ap);
	return 0;
}

void shutdown_fatal(void)
{
    if (pLogFile) {
        fclose(pLogFile);
    }
    exit(1);
}

void apacHyfi20CheckArgList(int *argc, char **argv) {
    char tempArgvList[*argc][APAC_CONF_FILE_NAME_MAX_LEN];
    u_int8_t i, j = 0;

    for (i = 0; i < *argc; i++) {
        if (strlen(argv[i]) > 0) {
            memcpy(&tempArgvList[j++], &argv[i], strlen(argv[i]));
        }
    }

    for (i = 0; i < j; i++) {
        memcpy(&argv[i], &tempArgvList[i], strlen(tempArgvList[i]));
    }

    *argc = i;
}

#if CALLTRACE_SUPPORT
/**
 * @brief storing the calltrace info into a separate file
 */

FILE *fpLog;
int wsplcd_print(const char *fmt, ...)
{
    va_list ap = {0};
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

/**
 * @brief React to a signal to shut down the daemon by marking the event
 *        event loop as terminated.
 */

static void wsplcdShutdownSignalHandler(int signal) {
    fpLog  = fopen("/tmp/wsplcdCrash_log.txt", "a");
    unw_cursor_t cursor;
    unw_context_t context;
    char sym[256];

    switch(signal)
    {
      case SIGSEGV:
          wsplcd_print("SIGSEGV : Segmentation Fault\n");
      break;
      case SIGTERM:
          wsplcd_print("SIGTERM : Terminate\n");
      break;
      case SIGQUIT:
          wsplcd_print("SIGQUIT : Quit\n");
      break;
      case SIGILL:
          wsplcd_print("SIGILL : Illegal Instruction\n");
      break;
      case SIGTRAP:
          wsplcd_print("SIGTRAP : Trap\n");
      break;
      case SIGABRT:
          wsplcd_print("SIGABRT : Abort\n");
      break;
      case SIGFPE:
          wsplcd_print("SIGFPE : Floating-point Exception\n");
      break;
      default:
          wsplcd_print("Default Case Detected ! \n");
      break;
    }
    unw_getcontext(&context);
    unw_init_local(&cursor, &context);
    wsplcd_print("Process id : %d\n", getpid());

    while (unw_step(&cursor) > 0) {
        unw_word_t offset, pc;
        unw_get_reg(&cursor, UNW_REG_SP, &pc);
        if (pc == 0)
            break;
        wsplcd_print("0x%x    ", pc);
        if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
            wsplcd_print("Symbol : (%s+0x%x)\n", sym, offset);
        } else {
            wsplcd_print(" -- error: unable to obtain symbol name for this frame\n");
        }
    }
    wsplcd_print ("\n\n\n\n");
    fclose(fpLog);
    evloopAbort();
    exit(0);
 }
#endif

#ifdef SON_MEMORY_DEBUG

/*
 * @brief display memory usage summary information for every periodic interval
 */
static void apacSonMemDebugPeriodicTimeoutHandler(void *eloop_ctx, void *timeout_ctx)
{
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &(pData->config);
    son_mem_dbg_display_list();
    eloop_cancel_timeout(apacSonMemDebugPeriodicTimeoutHandler, pData, NULL);
    eloop_register_timeout(pConfig->report_interval, 0, apacSonMemDebugPeriodicTimeoutHandler, pData, NULL);
}

#endif

static void wsplcdMeshSignalHandler(int signal) {
    switch(signal)
    {
      case SIGTERM:
          dprintf(MSG_INFO, "SIGTERM : Terminate\n");
      break;
      case SIGQUIT:
          dprintf(MSG_INFO, "SIGQUIT : Quit\n");
      break;
      case SIGINT:
          dprintf(MSG_INFO, "SIGTERM : Terminate\n");
      break;
      default:
          dprintf(MSG_INFO, "Default Case Detected ! Signal:%d \n",signal);
      break;
    }

    exit(0);
}

int main(int argc, char **argv)
{
    apacInfo_t apacInfo;
#ifdef SON_MEMORY_DEBUG
    apacHyfi20Config_t *ptrConfig = &apacInfo.hyfi20.config;
#endif

    memset(&apacInfo, 0, sizeof(apacInfo_t));

    apacHyfi20CheckArgList(&argc, argv);
    apacHyfi20CmdLogFileModeName(argc, argv);

    if (logFileMode == APAC_LOG_FILE_APPEND) {
        pLogFile = fopen(g_log_file_path, "a");
    } else if (logFileMode == APAC_LOG_FILE_TRUNCATE) {
        pLogFile = fopen(g_log_file_path, "w");
    }

    /* enable command line configuration or read config file */
    optind = 0;
#if CALLTRACE_SUPPORT
    signal(SIGINT, wsplcdShutdownSignalHandler);
    signal(SIGTERM, wsplcdShutdownSignalHandler);
    signal(SIGSEGV, wsplcdShutdownSignalHandler);
    signal(SIGQUIT, wsplcdShutdownSignalHandler);
    signal(SIGILL, wsplcdShutdownSignalHandler);
    signal(SIGTRAP, wsplcdShutdownSignalHandler);
    signal(SIGABRT, wsplcdShutdownSignalHandler);
    signal(SIGFPE, wsplcdShutdownSignalHandler);
#endif


    signal(SIGINT, wsplcdMeshSignalHandler);
    signal(SIGTERM, wsplcdMeshSignalHandler);
    signal(SIGQUIT, wsplcdMeshSignalHandler);

    apacHyfi20CmdConfig(&apacInfo.hyfi20, argc, argv);

    if (wlanIfConfigInit(apacInfo.hyfi20.isCfg80211))
    {
        dprintf(MSG_INFO, "wlanIfConfigInit Failed\n");
        return -1;
    }

#if HYFI10_COMPATIBLE
    /* set up default configuration */
    wsplcd_hyfi10_init(&apacInfo.hyfi10);
#endif

    apacHyfi20ConfigInit(&apacInfo.hyfi20);

    /* Start wsplcd daemon */
    dprintf(MSG_INFO, "wsplcd daemon starting. cfg80211 config %d \n",apacInfo.hyfi20.isCfg80211);

    eloop_init(&apacInfo);

#ifdef SON_MEMORY_DEBUG
    if (ptrConfig->enable_mem_debug && ptrConfig->report_interval) {
        eloop_register_timeout(ptrConfig->report_interval, 0, apacSonMemDebugPeriodicTimeoutHandler, &apacInfo.hyfi20, NULL);
    }
#endif

    if (apacHyfi20Init(&apacInfo.hyfi20) <0)
    {
        dprintf(MSG_INFO, "%s, Failed to initialize\n", __func__);
        return -1;
    }

#if MAP_ENABLED
    if (!apacHyfiMapInit(HYFI20ToMAP(&apacInfo.hyfi20))) {
        if (!apacHyfiMapPfComplianceEnabled(HYFI20ToMAP(&apacInfo.hyfi20))) {
            dprintf(MSG_INFO, "%s: Failed to initialize EasyMesh\n", __func__);
            return -1;
        }
    }
#endif /* MAP_ENABLED */

    apacHyfi20ConfigDump(&apacInfo.hyfi20);

    apacHyfi20AtfConfigDump(&apacInfo.hyfi20);

#if MAP_ENABLED
    apacHyfiMapConfigDump(HYFI20ToMAP(&apacInfo.hyfi20));
#endif /* MAP_ENABLED */
    /* Restore QCA VAPIndependent flag*/
    if (apacInfo.hyfi20.config.manage_vap_ind)
    {
        apac_mib_set_vapind(&apacInfo.hyfi20, apacInfo.hyfi20.config.manage_vap_ind);
    }

    /* UCPK Init*/
    if (strlen(apacInfo.hyfi20.config.ucpk) > 0){
        char wpapsk[62+1];
        char plcnmk[32+1];
        if (ucpkHyfi20Init(apacInfo.hyfi20.config.ucpk,
            apacInfo.hyfi20.config.salt,
            apacInfo.hyfi20.config.wpa_passphrase_type,
            wpapsk,
            plcnmk) < 0)
        {
            dprintf(MSG_INFO, "%s :Invalid 1905.1 UCPK\n", __func__);
        }
        else
        {
            apac_mib_set_ucpk(&apacInfo.hyfi20, wpapsk, plcnmk);
        }
    }

    apacHyfi20Startup(&apacInfo.hyfi20);

#if HYFI10_COMPATIBLE
    /* check compatiblility with Hyfi-1.0 */
    if (apacInfo.hyfi20.config.hyfi10_compatible)
    {
        wsplcd_hyfi10_startup(&apacInfo.hyfi10);
    }
#endif

#if MAP_ENABLED
    if (apacInfo.mapData.vEnabled) {
        if (apacGetPIFMapCap(&apacInfo.hyfi20) < 0) {
            dprintf(MSG_INFO, "%s: Alert MAP Radio Basic Capability failed Aborting \n", __func__);
            return -1;
        }
    }
#endif

    eloop_run();
    eloop_destroy();

#if MAP_ENABLED
    if (apacInfo.mapData.vEnabled) {
        apacHyfiMapDInit(&apacInfo.mapData);
    }
#endif

#if HYFI10_COMPATIBLE
    if (apacInfo.hyfi20.config.hyfi10_compatible)
    {
        wsplcd_hyfi10_stop(&apacInfo.hyfi10);
    }
#endif

    wlanIfConfigExit();

    apacHyfi20DeinitSock(&apacInfo.hyfi20);

    if (pLogFile) {
        fclose(pLogFile);
    }

    /* Probably won't get here... */
    printf("Leaving wsplcd executive program\n");

    return 0;
}


