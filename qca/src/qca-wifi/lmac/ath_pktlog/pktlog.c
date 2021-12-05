/* Copyright (c) 2011-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */
/*
 * Copyright (c) 2000-2003, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */


#include <osdep.h>
#include "pktlog_i.h"
#include "pktlog_rc.h"
#include "if_llc.h"
#include <ieee80211_var.h>

#ifndef REMOVE_PKT_LOG

struct ath_pktlog_info *g_pktlog_info = NULL;
int g_pktlog_mode = PKTLOG_MODE_SYSTEM;

struct pl_arch_dep_funcs pl_funcs = {
    .pktlog_init = pktlog_init,
    .pktlog_enable = pktlog_enable,
};

struct pktlog_handle_t *get_pl_handle(ath_generic_softc_handle scn)
{
    struct pktlog_handle_t *pl_dev;
    if (!scn) {
        return NULL;
    }
    pl_dev = *((struct pktlog_handle_t **)
                                ((unsigned char*)scn +
                                 sizeof(struct ieee80211com)));
    return pl_dev;
}

void
pktlog_init(void *_scn)
{
    struct pktlog_handle_t *pl_dev = (struct pktlog_handle_t *)
                                                get_pl_handle(_scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;

    OS_MEMZERO(pl_info, sizeof(*pl_info));

    qdf_spinlock_create(&pl_info->log_lock);
    qdf_mutex_create(&pl_info->pktlog_mutex);

    if (pl_dev) {
        pl_dev->tgt_pktlog_enabled = false;
    }
    pl_info->buf_size = PKTLOG_DEFAULT_BUFSIZE;
    pl_info->buf = NULL;
    pl_info->log_state = 0;
    pl_info->sack_thr = PKTLOG_DEFAULT_SACK_THR;
    pl_info->tail_length = PKTLOG_DEFAULT_TAIL_LENGTH;
    pl_info->thruput_thresh = PKTLOG_DEFAULT_THRUPUT_THRESH;
    pl_info->per_thresh = PKTLOG_DEFAULT_PER_THRESH;
    pl_info->phyerr_thresh = PKTLOG_DEFAULT_PHYERR_THRESH;
    pl_info->trigger_interval = PKTLOG_DEFAULT_TRIGGER_INTERVAL;
    pl_info->pktlen = 0;
    pl_info->start_time_thruput = 0;
    pl_info->start_time_per = 0;
}

void
pktlog_cleanup(struct ath_pktlog_info *pl_info)
{
    pl_info->log_state = 0;
    qdf_spinlock_destroy(&pl_info->log_lock);
    qdf_mutex_destroy(&pl_info->pktlog_mutex);
}


static int
__pktlog_enable(ath_generic_softc_handle scn, int32_t log_state)
{
    struct pktlog_handle_t *pl_dev = get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;
    int error;

    if (!pl_info) {
        return 0;
    }

    pl_info->log_state = 0;

    if (log_state != 0) {
        if (!pl_dev) {
            if (g_pktlog_mode == PKTLOG_MODE_ADAPTER) {
                pktlog_disable_adapter_logging();
                g_pktlog_mode = PKTLOG_MODE_SYSTEM;
            }
        } else {
            if (g_pktlog_mode == PKTLOG_MODE_SYSTEM) {
                /* Currently the system wide logging is disabled */
                g_pktlog_info->log_state = 0;
                g_pktlog_mode = PKTLOG_MODE_ADAPTER;
            }
        }

        if (pl_info->buf == NULL) {
            error = pktlog_alloc_buf(scn ,pl_info);
            if (error != 0)
                return error;
            qdf_spin_lock(&pl_info->log_lock);
            pl_info->buf->bufhdr.version = CUR_PKTLOG_VER;
            pl_info->buf->bufhdr.magic_num = PKTLOG_MAGIC_NUM;
            pl_info->buf->wr_offset = 0;
            pl_info->buf->rd_offset = -1;
            qdf_spin_unlock(&pl_info->log_lock);
        }
	    pl_info->start_time_thruput = OS_GET_TIMESTAMP();
	    pl_info->start_time_per = pl_info->start_time_thruput;
    }
    pl_info->log_state = log_state;

    return 0;
}



int
pktlog_enable(ath_generic_softc_handle scn, int32_t log_state)
{
    struct pktlog_handle_t *pl_dev = get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;
    int status;

    if (!pl_info) {
        return 0;
    }
    qdf_mutex_acquire(&pl_info->pktlog_mutex);
    status = __pktlog_enable(scn, log_state);
    qdf_mutex_release(&pl_info->pktlog_mutex);

    return status;
}

static int
__pktlog_setsize(ath_generic_softc_handle scn,
                                int32_t size)
{

    struct pktlog_handle_t *pl_dev = (struct pktlog_handle_t *)
                                                get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;

    if (size < 0)
        return -EINVAL;

    if (size == pl_info->buf_size)
        return 0;

    if (pl_info->log_state) {
        qdf_nofl_info("Logging should be disabled before changing bufer size\n");
        return -EINVAL;
    }
    qdf_spin_lock(&pl_info->log_lock);
    if (pl_info->buf != NULL)
        pktlog_release_buf(pl_info); //remove NULL

    if (size != 0)
        pl_info->buf_size = size;
    qdf_spin_unlock(&pl_info->log_lock);

    return 0;
}


int
pktlog_setsize(ath_generic_softc_handle scn,
                                int32_t size)
{

    struct pktlog_handle_t *pl_dev = (struct pktlog_handle_t *)
                                                get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;
    int status;

    qdf_mutex_acquire(&pl_info->pktlog_mutex);
    status = __pktlog_setsize(scn, size);
    qdf_mutex_release(&pl_info->pktlog_mutex);

    return status;
}

static int
__pktlog_reset_buffer(ath_generic_softc_handle scn, int32_t reset)
{
    struct pktlog_handle_t *pl_dev = (struct pktlog_handle_t *)
                                                get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;

    if (pl_info->log_state) {
        qdf_nofl_info("Logging should be disabled before reseting bufer size\n");
        return -EINVAL;
    }

    qdf_spin_lock(&pl_info->log_lock);
    if (pl_info->buf != NULL) {
        qdf_nofl_info("Reseting pktlog buffer!\n");
        pktlog_release_buf(pl_info);
    }
    qdf_spin_unlock(&pl_info->log_lock);

    return 0;
}


int
pktlog_reset_buffer(ath_generic_softc_handle scn, int32_t reset)
{
    struct pktlog_handle_t *pl_dev = (struct pktlog_handle_t *)
                                                get_pl_handle(scn);
    struct ath_pktlog_info *pl_info = (pl_dev) ?
                                        pl_dev->pl_info : g_pktlog_info;
    int status;

    if(pl_info == NULL)
        return -EINVAL;

    if (reset != 1)
        return -EINVAL;

    qdf_mutex_acquire(&pl_info->pktlog_mutex);
    status = __pktlog_reset_buffer(scn, reset);
    qdf_mutex_release(&pl_info->pktlog_mutex);

    return status;
}

#endif /* REMOVE_PKT_LOG */
