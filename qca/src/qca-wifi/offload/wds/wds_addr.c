/*
 * Copyright (c) 2013-2014,2017-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2011, Atheros Communications Inc.
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

#include "athdefs.h"
#include "a_types.h"
#include "a_osapi.h"
#include "a_debug.h"
#include "ol_if_athvar.h"
#include "ol_defines.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include <init_deinit_lmac.h>
#include "wmi_unified_api.h"
#include <pktlog_ac_api.h>
#include "wds_addr_api.h"
#include <ol_txrx_types.h>
#include <ol_txrx_peer_find.h>
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
#include <wlan_utility.h>

#if PERF_FIND_WDS_NODE

#define WDS_TABLE_SZ 32

static void
_wds_entry_delete(struct wds_table *table, struct wds_table_entry *wds)
{
    TAILQ_REMOVE(&table->wds_entry, wds, wds_list);
    LIST_REMOVE(wds, wds_entry_hash);
    qdf_mem_free(wds);
}

void
wds_table_init(struct wds_table *table)
{
    int i;

    rwlock_init(&table->wds_table_lock);
    TAILQ_INIT(&table->wds_entry);
    for (i = 0; i < WDS_TABLE_SZ; i++)
        LIST_INIT(&table->wds_table_hash[i]);
}

void
wds_table_uninit(struct wds_table *table)
{
    //unsigned long flags;
    struct wds_table_entry *wds, *next_wds;

    write_lock_bh(&table->wds_table_lock);
    TAILQ_FOREACH_SAFE(wds, &table->wds_entry, wds_list, next_wds) {
        _wds_entry_delete(table, wds);
    }
    write_unlock_bh(&table->wds_table_lock);
}

static struct wds_table_entry *
_wds_entry_find(struct wds_table *table, unsigned char *dest_mac)
{
    struct wds_table_entry *wds;
    int hash;

    hash = dest_mac[5] % WDS_TABLE_SZ;
    LIST_FOREACH(wds, &table->wds_table_hash[hash], wds_entry_hash) {
        if (!qdf_mem_cmp(wds->dest_mac, dest_mac, 6))
            return wds;
    }
    return NULL;
}

static int
wds_entry_find(struct wds_table *table, unsigned char *dest_mac, unsigned char *peer_mac, struct ieee80211vap **vap)
{
    struct wds_table_entry *wds;
    //unsigned long flags;
    int ret = 0;

    read_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (wds){
        qdf_mem_copy(peer_mac, wds->peer_mac, 6);
        *vap = wds->vap;
    } else
         ret = 1;
    read_unlock_bh(&table->wds_table_lock);
    return ret;
}

int
wds_find(struct ol_ath_softc_net80211 * scn, unsigned char *dest_mac, unsigned char *peer_mac, struct ieee80211vap **vap)
{
    return wds_entry_find(&((struct ol_ath_softc_net80211 *)scn)->scn_wds_table, dest_mac, peer_mac, vap);
}

#if QCA_PARTNER_PLATFORM
qdf_export_symbol(wds_find);
#endif

static int
wds_entry_delete(struct wds_table *table, unsigned char *dest_mac)
{
    struct wds_table_entry *wds;
    //unsigned long flags;
    int ret = 0;

    write_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (wds)
        _wds_entry_delete(table, wds);
    else
        ret = -1;
    write_unlock_bh(&table->wds_table_lock);
    return ret;
}

/**
 * wds_entry_add() - adds wds entry in wds table
 * @ic: pointer to ieee80211com
 * @table: pointer to wds table
 * @dest_mac: destination mac addr
 * @peer_mac: peer mac addr
 *
 * Return 0 on success, -1 on failure
 */
static int wds_entry_add(struct ieee80211com *ic, struct wds_table *table,
                         unsigned char *dest_mac, unsigned char *peer_mac)
{
    struct wds_table_entry *wds;
    int hash, ret = 0;
    struct ieee80211_node *ni;

    write_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (!wds) {
        wds = qdf_mem_malloc_atomic(sizeof(*wds));
        if (wds) {
            hash = dest_mac[5] % WDS_TABLE_SZ;
            qdf_mem_copy(wds->dest_mac, dest_mac, 6);
            TAILQ_INSERT_TAIL(&table->wds_entry, wds, wds_list);
            LIST_INSERT_HEAD(&table->wds_table_hash[hash], wds, wds_entry_hash);
        }
    }
    if (wds) {
        qdf_mem_copy(wds->peer_mac, peer_mac, 6);
        wds->vap = NULL;
        ni = ieee80211_find_node(ic, peer_mac, WLAN_WDS_ID);
        if (ni) {
            wds->vap = ni->ni_vap;
            ieee80211_unref_node(&ni, WLAN_WDS_ID);
        }
    } else
        ret = -1;
    write_unlock_bh(&table->wds_table_lock);
    return ret;
}

static int
pdev_wds_entry_list_event_handler(ol_scn_t sc, u_int8_t *datap, u_int32_t len)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t idx = 0;
    struct wdsentry wds_entry;
    struct wmi_unified *wmi_handle;
#ifdef BIG_ENDIAN_HOST
    int i = 0;
    u_int8_t *wds_table;
#endif

#ifdef BIG_ENDIAN_HOST
    /*Swap only wds table entries,
      Skip swapping reserved field and length field */
    wds_table = datap + (5 * sizeof(u_int32_t));
    for (i = 0; i < ((len / sizeof(u_int32_t))-5); i++, wds_table += sizeof(u_int32_t))
        *(u_int32_t *)wds_table = le32_to_cpu(*(u_int32_t *)wds_table);
#endif

    qdf_print("Printing wds entries");
    qdf_print("\n \tDA\t\tNext Hop\t\tflags\n\n ");
    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    while (wmi_extract_wds_entry(wmi_handle, datap, &wds_entry, idx) == QDF_STATUS_SUCCESS)
    {
        qdf_print("%s\t", ether_sprintf(wds_entry.wds_mac));
        qdf_print("%s\t", ether_sprintf(wds_entry.peer_mac));
        qdf_print("%d", wds_entry.flags);
        idx++;
    }
    return 0;
}

static int wds_peer_event_handler(ol_scn_t sc, uint8_t *datap, uint32_t len)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wds_addr_event_t wds_ev, *wds_addr_event;
    uint8_t *peer_mac, *dest_mac;
    struct wmi_unified *wmi_handle;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;
    struct wlan_objmgr_peer *peer_obj;
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211vap *vap;
    uint8_t pdev_id;
    struct ol_txrx_pdev_t *pdev_txrx_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (wmi_extract_wds_addr_event(wmi_handle, datap, len, &wds_addr_event)) {
        qdf_info("Unable to extract wds addr event");
        return -1;
    }

    pdev_id = wlan_get_pdev_id_from_vdev_id(soc->psoc_obj, wds_ev.vdev_id,
                                            WLAN_MLME_SB_ID);
    if (pdev_id >= WLAN_UMAC_MAX_PDEVS){
        qdf_info("pdev_id is out of index, return");
        return -1;
    }

    peer_obj = wlan_objmgr_get_peer(soc->psoc_obj, pdev_id, wds_ev.peer_mac,
                                    WLAN_MLME_SB_ID);
    if (!peer_obj) {
        qdf_info("Unable to find peer object");
        return -1;
    }

    vdev = wlan_peer_get_vdev(peer_obj);

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
        return -1;
    }

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    pdev_txrx_handle = (struct ol_txrx_pdev_t *)scn->pdev_txrx_handle;
    wds_addr_event = &wds_ev;
    peer_mac = wds_ev.peer_mac;
    dest_mac = wds_ev.dest_mac;
    if (wds_addr_event->event_type[0] == 1) {
        qdf_nofl_info(KERN_ERR "Adding WDS entry through "
                      "(%02x:%02x:%02x:%02x:%02x:%02x) "
                      "of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                      peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3],
                      peer_mac[4], peer_mac[5], dest_mac[0], dest_mac[1],
                      dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
        wds_entry_add(ic, &scn->scn_wds_table, dest_mac, peer_mac);
#if PEER_FLOW_CONTROL
        ol_txrx_ast_find_hash_add(pdev_txrx_handle, peer_mac, dest_mac,
                                  HTT_INVALID_PEER, 0);
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_pdev_add_wds_peer(scn, vdev_id,
                                peer_obj->macaddr, HTT_INVALID_PEER, dest_mac,
                                peer_mac, CDP_TXRX_AST_TYPE_NONE);
        }
#endif

    } else if (wds_addr_event->event_type[0] == 2) {
        qdf_nofl_info(KERN_ERR "Deleting WDS entry through "
                      "(%02x:%02x:%02x:%02x:%02x:%02x) "
                     "of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                     peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3],
                     peer_mac[4], peer_mac[5], dest_mac[0], dest_mac[1],
                     dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
       wds_entry_delete(&scn->scn_wds_table, dest_mac);
#if PEER_FLOW_CONTROL
        if (ol_txrx_ast_find_hash_remove(pdev_txrx_handle, dest_mac)) {
            wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
            return 0;
        }
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_pdev_del_wds_peer(scn, peer_mac,
                                dest_mac, CDP_TXRX_AST_TYPE_NONE, pdev_id);
        }
#endif
    } else {
        qdf_nofl_info(KERN_ERR "%s, invalid WMI event type %d\n",
                          __func__, wds_addr_event->event_type[0]);
    }
    wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
    return 0;
}

#else
#if PEER_FLOW_CONTROL

static int
pdev_wds_entry_list_event_handler(ol_scn_t sc, u_int8_t *datap, u_int32_t len)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t idx = 0;
    struct wdsentry wds_entry;
    struct wmi_unified *wmi_handle;
#ifdef BIG_ENDIAN_HOST
    int i = 0;
    u_int8_t *wds_table;
#endif

#ifdef BIG_ENDIAN_HOST
    /*Swap only wds table entries,
      Skip swapping reserved field and length field */
    wds_table = datap + (5 * sizeof(u_int32_t));
    for (i = 0; i < ((len / sizeof(u_int32_t))-5); i++, wds_table += sizeof(u_int32_t))
        *(u_int32_t *)wds_table = le32_to_cpu(*(u_int32_t *)wds_table);
#endif
    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    qdf_print("Printing wds entries");
    qdf_print("\n \tDA\t\tNext Hop\t\tflags\n\n ");
    while (wmi_extract_wds_entry(wmi_handle, datap, &wds_entry, idx) == QDF_STATUS_SUCCESS)
    {
        qdf_print("%s\t", ether_sprintf(wds_entry.wds_mac));
        qdf_print("%s\t", ether_sprintf(wds_entry.peer_mac));
        qdf_print("%d", wds_entry.flags);
        idx++;
    }
    return 0;
}

static int wds_peer_event_handler(ol_scn_t sc, uint8_t *datap, uint32_t len)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wds_addr_event_t wds_addr_event;
    uint8_t pdev_id;
    struct wmi_unified *wmi_handle;
    struct ol_txrx_psoc_t *soc_txrx_handle;
    struct ol_txrx_pdev_t *pdev_txrx_handle;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_peer *peer_obj;
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211vap *vap;
    struct ol_txrx_ast_entry_t *ast_entry;

    soc_txrx_handle =
                (struct ol_txrx_psoc_t *)wlan_psoc_get_dp_handle(soc->psoc_obj);
    if (!soc_txrx_handle)
        return -1;

    /* Extract pdev from pdev[0] since in Legacy there is only 1 pdev per soc */
    pdev_txrx_handle = (struct ol_txrx_pdev_t *)soc_txrx_handle->pdev[0];
    if (!pdev_txrx_handle)
        return -1;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_wds_addr_event(wmi_handle, datap, len, &wds_addr_event)) {
        qdf_info("Failed to extract wds addr event");
        return 0;
    }

    pdev_id = wlan_get_pdev_id_from_vdev_id(soc->psoc_obj,
                                            wds_addr_event.vdev_id,
                                            WLAN_MLME_SB_ID);
    if (pdev_id >= WLAN_UMAC_MAX_PDEVS) {
        qdf_info("pdev_id is out of index, return");
        return -1;
    }

    peer_obj = wlan_objmgr_get_peer(soc->psoc_obj, pdev_id,
                                    wds_addr_event.peer_mac, WLAN_MLME_SB_ID);
    if (!peer_obj) {
        qdf_info("Unable to find peer object");
        return -1;
    }

    vdev = wlan_peer_get_vdev(peer_obj);
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
        return -1;
    }

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211((vap->iv_ic));

    if (wds_addr_event.event_type[0] == 1) {
        if (pdev_txrx_handle->prof_trigger) {
            qdf_info("Adding WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x) "
                     "of mac(%02x:%02x:%02x:%02x:%02x:%02x)",
                     wds_addr_event.peer_mac[0], wds_addr_event.peer_mac[1],
                     wds_addr_event.peer_mac[2], wds_addr_event.peer_mac[3],
                     wds_addr_event.peer_mac[4], wds_addr_event.peer_mac[5],
                     wds_addr_event.dest_mac[0], wds_addr_event.dest_mac[1],
                     wds_addr_event.dest_mac[2], wds_addr_event.dest_mac[3],
                     wds_addr_event.dest_mac[4], wds_addr_event.dest_mac[5]);
        }
        ast_entry = ol_txrx_ast_find_hash_find(pdev_txrx_handle,
                                               wds_addr_event.dest_mac, 0);
        if (ast_entry) {
            if (ol_txrx_ast_find_hash_remove(pdev_txrx_handle,
                                             wds_addr_event.dest_mac)) {
                qdf_nofl_info("Hash Remove failed for ast_entry exist case\n");
                wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
                return -1;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_radio_ops) {
                ic->nss_radio_ops->ic_nss_ol_pdev_del_wds_peer(scn,
                                        (uint8_t *)wds_addr_event.peer_mac,
                                         (uint8_t *)wds_addr_event.dest_mac,
                                          CDP_TXRX_AST_TYPE_NONE, pdev_id);
            }
#endif
        }
        ol_txrx_ast_find_hash_add(pdev_txrx_handle, wds_addr_event.peer_mac,
                                  wds_addr_event.dest_mac, HTT_INVALID_PEER, 0);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_pdev_add_wds_peer(scn,
                wds_addr_event.vdev_id, peer_obj->macaddr, HTT_INVALID_PEER,
                (uint8_t *)wds_addr_event.dest_mac,
                 (uint8_t *)wds_addr_event.peer_mac, CDP_TXRX_AST_TYPE_NONE);
        }
#endif
    } else if (wds_addr_event.event_type[0] == 2) {
        if (pdev_txrx_handle->prof_trigger) {
            qdf_info("Deleting WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x)"
                     " of mac(%02x:%02x:%02x:%02x:%02x:%02x)",
                     wds_addr_event.peer_mac[0], wds_addr_event.peer_mac[1],
                     wds_addr_event.peer_mac[2], wds_addr_event.peer_mac[3],
                     wds_addr_event.peer_mac[4], wds_addr_event.peer_mac[5],
                     wds_addr_event.dest_mac[0], wds_addr_event.dest_mac[1],
                     wds_addr_event.dest_mac[2], wds_addr_event.dest_mac[3],
                     wds_addr_event.dest_mac[4], wds_addr_event.dest_mac[5]);
        }
        if (ol_txrx_ast_find_hash_remove(pdev_txrx_handle,
                                         wds_addr_event.dest_mac)) {
            wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
            return -1;
        }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_pdev_del_wds_peer(scn,
                                (uint8_t *)wds_addr_event.peer_mac,
                                 (uint8_t *)wds_addr_event.dest_mac,
                                  CDP_TXRX_AST_TYPE_NONE, pdev_id);
        }
#endif
    } else {
        qdf_info("invalid WMI event type %d", wds_addr_event.event_type[0]);
    }
    wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
    return 0;
}

#else /* PEER_FLOW_CONTROL */
static int
pdev_wds_entry_list_event_handler(ol_scn_t scn, u_int8_t *datap, u_int32_t len)
{
        return 0;//do nothing
}

static int wds_peer_event_handler(ol_scn_t sc, uint8_t *datap, uint32_t len)
{
        return 0;//do nothing
}

#endif /* PEER_FLOW_CONTROL */
#endif /* PERF_FIND_WDS_NODE */

void
wds_addr_init(wmi_unified_t wmi_handle)
{
    wmi_unified_register_event_handler(wmi_handle, wmi_wds_peer_event_id,
                                       wds_peer_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(wmi_handle, wmi_pdev_wds_entry_list_event_id,
                                      pdev_wds_entry_list_event_handler, WMI_RX_UMAC_CTX);
}
qdf_export_symbol(wds_addr_init);

void
wds_addr_detach(wmi_unified_t wmi_handle)
{
    wmi_unified_unregister_event_handler(wmi_handle, wmi_wds_peer_event_id);
    wmi_unified_unregister_event_handler(wmi_handle, wmi_pdev_wds_entry_list_event_id);
}
qdf_export_symbol(wds_addr_detach);
