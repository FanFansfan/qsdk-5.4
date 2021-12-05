/*
 * @File: mcsMain.c
 *
 * @Abstract: Multicast snooping daemon main
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015, 2017, 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011, 2015, 2017 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>

#include <dbg.h>
#include <evloop.h>
#include <module.h>
#include <profile.h>
#include <split.h>
#include <interface.h>

#include "mcManager.h"
#include "internal.h"
#include "mcif.h"
#include "netd.h"

#ifdef MCS_MODULE_WLAN
#include "wlanManager.h"
#endif

#ifdef MCS_MODULE_PLC
#include "plcManager.h"
#endif

#ifdef MCS_MODULE_DBG
#include "dbgService.h"
#endif

#ifdef MCS_DBG_MENU
#include <csh.h>
#endif


#ifdef MCS_USE_PCD
#include <pcdapi.h>
#endif

#include "mcsMain.h"


/* Debugging options */
/*private*/ const struct dbgInitOptions dbgInitOptions = {
	.ProgramName = "MCSD",
	.EnvName = "MCSD_DBG_LEVELS",
};

/* State info for mcsd main level */
/*private*/ struct {
	struct dbgModule *DebugModule;
	int DoDaemonize;	/* detach from parent */
	const char *ConfFile;
} mcsS;

#define mcsDebug(level, ...) \
        dbgf(mcsS.DebugModule,(level),__VA_ARGS__)

/* Local declaration of pluginManager_init function.
 *
 */
extern void pluginManagerInit(void);

void mcsRun(void)
{
	mdInit();
	evloopRunPrepare();

	while (!evloopIsAbort()) {
		evloopOnce();
	}
}

void mcsUsage(void)
{
	mcsDebug(DBGINFO, "Usage: mcsd [-d] [-C conf-file]");
	mcsDebug(DBGINFO, "       -d: Do NOT fork into the background: run in debug mode.");
	mcsDebug(DBGINFO, "       -C: Specify configuration file.");

	exit(1);
}

static void mcHandleSignal(int signo)
{
	mcManagerStopAll();
	evloopAbort();
}

static void mcsSetupSignal(void)
{
	struct sigaction s;
	memset(&s, 0, sizeof(s));
	s.sa_handler = mcHandleSignal;
	s.sa_flags = 0;
	sigaction(SIGINT, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	sigaction(SIGUSR1, &s, NULL);
	sigaction(SIGUSR2, &s, NULL);
	s.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &s, NULL);
}

void mcsParseArgs(char **argv)
{
	char *Arg;

	mcsS.DoDaemonize = 1;

	argv++;			/* skip program name */
	while ((Arg = *argv++) != NULL) {
		if (!strcmp(Arg, "-d")) {
			mcsS.DoDaemonize = 0;
		} else if (!strcmp(Arg, "-C")) {	/* configuration file */
			Arg = *argv++;
			if (Arg == NULL)
				mcsUsage();

			mcsS.ConfFile = Arg;
		} else {
			mcsDebug(DBGERR, "INVALID ARG: %s", Arg);
			mcsUsage();
		}
	}
	return;
}

static MCS_STATUS mcsInitBridge(void)
{
	return MCS_OK;
}

int mcsInit(void)
{
	/* Initialize bridge interfaces */
	interface_init();

	/* Configure the bridge */
	mcsInitBridge();

	return 0;
}

/* The main function of mcsd.
 * Usage: mcsd [-d] [-C conf-file]
 * -d: Do NOT fork into the background: run in debug mode.
 * -C: Specify configuration file.
 */
int main(int argc, char **argv)
{
	openlog("mcastds", LOG_CONS, LOG_DAEMON);
	mcsSetupSignal();

#ifdef MCS_USE_PCD
	/* Register to the PCD's exception handlers, enable detailed crash report */
	PCD_API_REGISTER_EXCEPTION_HANDLERS();
#endif

	/* Make sure our debug options are set before any debugging! */
	dbgInit1(&dbgInitOptions);

	/* Register for debug messages from this file */
	mcsS.DebugModule = dbgModuleFind("mcsd");

	mcsDebug(DBGDEBUG, "Entering main of mcsd executive program");

	/* Now we can look at arguments */
	mcsParseArgs(argv);

	if (mcsS.DoDaemonize) {
		if (daemon(0, 0)) {
			perror("daemon");
			exit(1);
		}
	}

	/* Make sure profile module initilized before other modules. */
	profileInit(mcsS.ConfFile);

	mcsInit();

#ifdef MCS_MODULE_WLAN
	wlanManagerInit();
#endif

#ifdef MCS_MODULE_PLC
	plcManagerInit();
#endif

	mcManagerInit();

#ifdef MCS_MODULE_TEMPLATE
	templateManagerInit();
	templateServiceInit();
#endif

#ifdef MCS_MODULE_DBG
	dbgServiceInit();
#endif

#ifdef MCS_DBG_MENU
	/* Add debugging shell capability */
	cshInit(MCS_DBG_PORT);
#endif

	pluginManagerInit();
	/* must called after all initilization */
	mdDoListenInitCB();

	netdInit();

	/* Main event loop waits for things to happen...
	 * is the ONLY place we should EVER wait for anything to happen.
	 */
	syslog(LOG_NOTICE, "Entering evloopRun");
	mcsRun();

	/* Probably won't get here... */
	syslog(LOG_NOTICE, "Leaving mcsd executive program");
	closelog();

	return 0;
}
