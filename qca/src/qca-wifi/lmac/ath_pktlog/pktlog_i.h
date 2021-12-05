/*
 * Copyright (c) 2011, 2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _PKTLOG_INTERNAL_H
#define _PKTLOG_INTERNAL_H

#ifndef REMOVE_PKT_LOG

#include "pktlog.h"
#include "pktlog_rc.h"
#include "if_llc.h"

#define PKTLOG_DEFAULT_BUFSIZE (1024 * 1024)
#define PKTLOG_DEFAULT_SACK_THR 3
#define PKTLOG_DEFAULT_TAIL_LENGTH 100
#define PKTLOG_DEFAULT_THRUPUT_THRESH   (64 * 1024)
#define PKTLOG_DEFAULT_PER_THRESH   30
#define PKTLOG_DEFAULT_PHYERR_THRESH   300
#define PKTLOG_DEFAULT_TRIGGER_INTERVAL 500

extern struct ath_pktlog_rcfuncs *g_pktlog_rcfuncs;
extern struct ath_pktlog_funcs *g_pktlog_funcs;

#if ATH_PERF_PWR_OFFLOAD
extern struct ol_pl_os_dep_funcs *g_ol_pl_os_dep_funcs;
#endif

/*
 * internal pktlog API's (common to all OS'es)
 */
void pktlog_init(void *scn);
void pktlog_cleanup(struct ath_pktlog_info *pl_info);
int pktlog_enable(ath_generic_softc_handle scn, int32_t log_state);
int pktlog_setsize(ath_generic_softc_handle scn, int32_t size);
int pktlog_reset_buffer(ath_generic_softc_handle scn, int32_t reset);
struct pktlog_handle_t *get_pl_handle(ath_generic_softc_handle scn);

#define get_pktlog_state(_sc)  ((_sc)?(_sc)->pl_info->log_state: \
                                   g_pktlog_info->log_state)

#define get_pktlog_bufsize(_sc)  ((_sc)?(_sc)->pl_info->buf_size: \
                                     g_pktlog_info->buf_size)

/*
 * helper functions (OS dependent)
 */
extern void pktlog_disable_adapter_logging(void);
extern int pktlog_alloc_buf(ath_generic_softc_handle scn,
                            struct ath_pktlog_info *pl_info);
extern void pktlog_release_buf(struct ath_pktlog_info *pl_info);

#endif /* ifndef REMOVE_PKT_LOG */
#endif
