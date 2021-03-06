// vim: set et sw=4 sts=4 cindent:
/*
 * @File: persist.c
 *
 * @Abstract: stadb persistence
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include "persist.h"

#include "stadb.h"
#include "stadbEntry.h"
#include "steerexec.h"
#include "module.h"
#include "profile.h"

#include <dbg.h>
#include <limits.h>
#include <evloop.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#undef QCA_MOD_INPUT
#define QCA_MOD_INPUT QCA_MOD_LBD_PERSIST
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement persistElementDefaultTable[] = {
    { PERSIST_FILE_KEY, "" },
    { PERSIST_PERIOD_KEY, "5"},
    { NULL, NULL }
};

// ====================================================================
// Type definitions
// ====================================================================

static struct persistState_t {
    struct dbgModule *dbgModule;
    struct evloopTimeout timer;
    const char *filename;
    char *tmpfile;
    int period;
} persistState;

// ====================================================================
// Forward decls
// ====================================================================


// ====================================================================
// Internal state
// ====================================================================

// ====================================================================
// Persistence logic
// ====================================================================
static void persistTimeoutHandler(void *cookie) {
    dbgf(persistState.dbgModule, DBGDEBUG, "%s: Persistence timer hit!",
         __func__);
    if (persistState.filename != NULL && strlen(persistState.filename) > 0 &&
            stadb_isDirty()) {
        dbgf(persistState.dbgModule, DBGDEBUG, "%s: Persisting to %s", __func__,
             persistState.tmpfile);
        stadb_persist(persistState.tmpfile, steerexec_jsonize);
        dbgf(persistState.dbgModule, DBGDEBUG, "%s: Renaming to %s", __func__,
             persistState.filename);
        if (rename(persistState.tmpfile, persistState.filename)) {
            dbgf(persistState.dbgModule, DBGERR,
                 "%s: Failed to rename to %s (%d)", __func__,
                 persistState.filename, errno);
        }
    } else if (stadb_isDirty()) {
        dbgf(persistState.dbgModule, DBGDEBUG, "%s: Persistence is disabled.",
             __func__);
    } else {
        dbgf(persistState.dbgModule, DBGDEBUG, "%s: stadb is clean.", __func__);
    }
    evloopTimeoutRegister(&persistState.timer, persistState.period, 0);
}

// ====================================================================
// Restore logic
// ====================================================================

LBD_STATUS persist_init(void) {
    size_t filename_len;

    persistState.dbgModule = dbgModuleFind("persist");
    persistState.filename = profileGetOpts(mdModuleID_Persist, PERSIST_FILE_KEY,
                                           persistElementDefaultTable);
    persistState.period = profileGetOptsInt(
        mdModuleID_Persist, PERSIST_PERIOD_KEY, persistElementDefaultTable);

    /* Use a tmp file with the form: /path/filename~ */
    if (persistState.filename != NULL) {
        filename_len = strlen(persistState.filename);

        /* overflow checking */
        if(filename_len + 2 >= PATH_MAX) {
            dbgf(persistState.dbgModule, DBGDEBUG,
                 "%s: Failed to allocate tmpfile, size overflow", __func__);
            return LBD_NOK;
        }

        persistState.tmpfile = malloc(PATH_MAX);
        if (persistState.tmpfile == NULL) {
            dbgf(persistState.dbgModule, DBGDEBUG,
                 "%s: Failed to allocate tmpfile", __func__);
            return LBD_NOK;
        }
        strlcpy(persistState.tmpfile, persistState.filename, PATH_MAX);
        persistState.tmpfile[filename_len] = '~';
        persistState.tmpfile[filename_len + 1] = 0;
    } else {
        persistState.tmpfile = NULL;
    }

    /* restore stadb state */
    dbgf(persistState.dbgModule, DBGDEBUG, "%s: Attempting restore stadb...",
         __func__);
    if (persistState.filename != NULL && strlen(persistState.filename) > 0) {
        dbgf(persistState.dbgModule, DBGINFO, "%s: Restoring stadb from %s",
             __func__, persistState.filename);
        stadb_restore(persistState.filename, steerexec_restore);
    }

    /* set timer to persist stadb state */
    evloopTimeoutCreate(&persistState.timer, "persistTimer",
            persistTimeoutHandler, NULL);
    evloopTimeoutRegister(&persistState.timer, persistState.period, 0);
    return LBD_OK;
}

void persist_fini(void) {
    if (stadb_isDirty()) {
        persistTimeoutHandler(NULL);
        dbgf(persistState.dbgModule, DBGINFO, "%s: flush state at finish\n", __func__);
    }
    evloopTimeoutUnregister(&persistState.timer);
    free(persistState.tmpfile);
}
