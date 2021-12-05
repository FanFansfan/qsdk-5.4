/*
 * Copyright (c) 2016-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#include <ieee80211_var.h>
#include <ieee80211_objmgr_priv.h>

#include <wlan_mlme_dp_dispatcher.h>
#include <wlan_mlme_dbg.h>
#include <wlan_mlme_dispatcher.h>
#include <include/wlan_mlme_cmn.h>
#include "wlan_utility.h"
#if QLD
#include "qld_api.h"
#endif
#include <wlan_mlme_if.h>
#if DBDC_REPEATER_SUPPORT
#include <qca_multi_link.h>
#endif

extern struct mlme_ext_ops * mlme_get_global_ops(void);

#if QLD
extern unsigned int qld_max_list;
#endif

/* Translation table for conversion from IEEE80211 opmode to QDF mode */
uint8_t opmode2qdf_opmode[IEEE80211_OPMODE_MAX+1] = {
        QDF_IBSS_MODE,      /*  IEEE80211_M_IBSS,    */
        QDF_STA_MODE,       /*  IEEE80211_M_STA,     */
        QDF_WDS_MODE,       /*  IEEE80211_M_WDS,     */
        QDF_AHDEMO_MODE,     /*  IEEE80211_M_AHDEMO, */
        QDF_MAX_NO_OF_MODE,
        QDF_MAX_NO_OF_MODE,
        QDF_SAP_MODE,       /*  IEEE80211_M_HOSTAP,  */
        QDF_MAX_NO_OF_MODE,
        QDF_MONITOR_MODE,   /*  IEEE80211_M_MONITOR, */
        QDF_BTAMP_MODE,     /*  IEEE80211_M_BTAMP,   */
};

enum QDF_OPMODE ieee80211_opmode2qdf_opmode(enum ieee80211_opmode opmode)
{
   if (opmode >= IEEE80211_OPMODE_MAX)
            return QDF_MAX_NO_OF_MODE;

   return opmode2qdf_opmode[opmode];
}

QDF_STATUS wlan_mlme_peer_obj_create_handler(struct wlan_objmgr_peer *peer, void *arg)
{
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_pdev *pdev;
    wlan_if_t vap;
    struct ieee80211com *ic;
    struct ieee80211_node *ni =NULL;
    QDF_STATUS status;

    if(peer == NULL) {
        mlme_err("PEER is NULL");
        return QDF_STATUS_E_FAILURE;
    }
     /* get vdev from peer */
    vdev = wlan_peer_get_vdev(peer);
    if (vdev == NULL) {
        mlme_err("VDEV is NULL");
        return QDF_STATUS_E_FAILURE;
    }
      /* get vap pointer */
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
      /* get pdev pointer */
    pdev = wlan_vdev_get_pdev(vdev);
    if(pdev == NULL || vap == NULL) {
        mlme_err("vap or pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    /* get ic pointer */
    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if(!ic) {
        mlme_err("ic is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    status = QDF_STATUS_SUCCESS;

    if(wlan_peer_get_peer_type(peer) == WLAN_PEER_STA_TEMP) {
       if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
           (wlan_vdev_is_up(vdev) != QDF_STATUS_SUCCESS)) {
            mlme_err("AP VDEV is not in UP state, peer create skipped");
            return QDF_STATUS_E_FAILURE;
       }
       ni = ic->ic_node_alloc(vap, wlan_peer_get_macaddr(peer), TRUE, peer);
    }
    else {
       ni = ieee80211_alloc_node(&ic->ic_sta, vap, peer);
    }

    if(ni == NULL) {
       status = QDF_STATUS_E_FAILURE;
    } else {
         /* For non-TEMP nodes, back pointer is updated in
           ieee80211_alloc_node()*/
       if(wlan_peer_get_peer_type(peer) == WLAN_PEER_STA_TEMP) {
          ni->ni_vap = vap;
          ni->ni_ic = ic;
          ni->peer_obj = peer;
       }

       qdf_atomic_set(&(ni->ni_logi_deleted), 0);
       qdf_atomic_set(&(ni->getpn),1);
       ni->ni_set_max_rate = 0;
       ni->ni_ap_power_type = REG_INDOOR_AP;
       ni->ni_omn_chwidth = IEEE80211_CWM_WIDTHINVALID;
       /* Fill the power arrays (ni_eirp_limit, ni_eirp_psd_limit) with MAX
        * values. If the TPE is not received or if power values are absent in
        * the TPE, the arrays will continue to contain the MAX values. When
        * minimum of these power values and regulatory power values are
        * calculated the regulatory power values will limit the powers and
        * the new limited value. If the TPE power values are lower than
        * regulatory power values, TPE power values will limit the powers.
        */
       qdf_mem_set(ni->ni_eirp_limit, sizeof(ni->ni_eirp_limit), MAX_TX_POWER);
       qdf_mem_set(ni->ni_eirppsd_limit, sizeof(ni->ni_eirppsd_limit), MAX_TX_POWER);
       ni->ni_eirp_min_lim = MAX_TX_POWER;
       ni->ni_eirppsd_min_lim = MAX_TX_POWER;
    }

    wlan_objmgr_peer_component_obj_attach(peer,WLAN_UMAC_COMP_MLME,
                              (void *)ni,status);
    return status;
}

QDF_STATUS wlan_mlme_peer_obj_destroy_handler(struct wlan_objmgr_peer *peer, void *arg)
{
     wlan_node_t ni;

     if(peer == NULL) {
         QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                 "%s:PEER is NULL",__func__);
         return QDF_STATUS_E_FAILURE;
     }

     ni = wlan_peer_get_mlme_ext_obj(peer);
     if(ni != NULL) {
         wlan_objmgr_peer_component_obj_detach(peer,WLAN_UMAC_COMP_MLME,
                           (void *)ni);
         _ieee80211_free_node(ni);
     }

     return QDF_STATUS_SUCCESS;
}

void wlan_mlme_vdev_peer_free_notify_handler(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap) {
        mlme_err("vap is NULL");
        return;
    }

    mlme_vdev_sm_notify_peers_disconnected(vap);
}

#if SM_HIST_DEBUGFS_SUPPORT

static QDF_STATUS
sm_dbg_fs_open(qdf_debugfs_file_t m, void *arg)
{
   return wlan_mlme_sm_debugfs_history(m, arg);
}

static QDF_STATUS sm_dbg_fs_write(void *priv, const char *buf,
                                  qdf_size_t len)
{
   return QDF_STATUS_E_NOSUPPORT;
}

static struct qdf_debugfs_fops sm_dbg_buf_fops = {
   .show  = sm_dbg_fs_open,
   .write = sm_dbg_fs_write,
   .priv  = NULL,
};

qdf_dentry_t mlme_debugfs_entry;

static void wlan_sm_dbgfs_create(void)
{
    mlme_debugfs_entry = qdf_debugfs_create_dir("wlan_mlme", NULL);
    if (mlme_debugfs_entry) {
       if (!qdf_debugfs_create_file_simplified("vdev_sm_history",
                                               (QDF_FILE_USR_READ |
                                                QDF_FILE_GRP_READ |
                                                QDF_FILE_OTH_READ),
                                               mlme_debugfs_entry,
                                              &sm_dbg_buf_fops)) {
          qdf_err("debugfs entry creation failed!");
          return;
       }
    }
}

static void wlan_sm_dbgfs_remove(void)
{
     qdf_debugfs_remove_dir_recursive(mlme_debugfs_entry);
}
#endif

int wlan_mlme_init()
{
    QDF_STATUS status;

    status = wlan_objmgr_register_peer_create_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_create_handler, NULL);
    if (status != QDF_STATUS_SUCCESS)
        goto reg_peer_create_fail;

    status = wlan_objmgr_register_peer_destroy_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_destroy_handler, NULL);
    if (status != QDF_STATUS_SUCCESS)
        goto reg_peer_destroy_fail;

    status = wlan_objmgr_register_vdev_peer_free_notify_handler(
                WLAN_UMAC_COMP_MLME,
                wlan_mlme_vdev_peer_free_notify_handler);
    if (status != QDF_STATUS_SUCCESS)
        goto reg_peer_free_fail;

#if SM_HIST_DEBUGFS_SUPPORT
     wlan_sm_dbgfs_create();
#endif

#if DBDC_REPEATER_SUPPORT
    qca_multi_link_init_module();
#endif
    return status;

     /* On error, unregister the already registered handlers */
reg_peer_free_fail:
    wlan_objmgr_unregister_peer_destroy_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_destroy_handler, NULL);

reg_peer_destroy_fail:
    wlan_objmgr_unregister_peer_create_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_create_handler, NULL);

reg_peer_create_fail:
    return status;
}

void wlan_mlme_deinit()
{
#if DBDC_REPEATER_SUPPORT
    qca_multi_link_deinit_module();
#endif
#if SM_HIST_DEBUGFS_SUPPORT
     wlan_sm_dbgfs_remove();
#endif
    if (wlan_objmgr_unregister_vdev_peer_free_notify_handler(
                WLAN_UMAC_COMP_MLME,
                wlan_mlme_vdev_peer_free_notify_handler)
            != QDF_STATUS_SUCCESS) {
        return;
    }

    if (wlan_objmgr_unregister_peer_destroy_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_destroy_handler,NULL)
            != QDF_STATUS_SUCCESS) {
        return;
    }

    if(wlan_objmgr_unregister_peer_create_handler(WLAN_UMAC_COMP_MLME,
                wlan_mlme_peer_obj_create_handler,NULL)
            != QDF_STATUS_SUCCESS) {
        return;
    }
}

void mlme_set_ops_cb()
{
    mlme_set_ops_register_cb(mlme_get_global_ops);
}

int wlan_umac_init()
{
    if (wlan_mlme_init()) {
        QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                "%s: WLAN MLME init failed", __func__);
        return -EINVAL;
    }
#if QLD
    if (qld_max_list) {
        qld_list_init(qld_max_list);
    }
#endif
    return 0;
}

void wlan_umac_deinit()
{
#if QLD
    if (qld_max_list) {
        qld_list_deinit();
    }
#endif
    wlan_mlme_deinit();
}

static struct ieee80211_node *wlan_objmgr_alloc_node(struct ieee80211vap *vap,
                              enum wlan_peer_type peer_type, uint8_t *macaddr)
{
    struct ieee80211_node *ni;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_peer *peer;

    if(vap == NULL) {
         QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                 "%s:vap is NULL", __func__);
         return NULL;
    }

    vdev = vap->vdev_obj;
    if (vdev == NULL) {
         QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                 "%s:vdev is NULL", __func__);
         return NULL;
    }

    if ((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) &&
        (WLAN_ADDR_EQ(macaddr, wlan_vdev_mlme_get_macaddr(vdev))) &&
        (wlan_vdev_is_up(vdev) != QDF_STATUS_SUCCESS)) {
          obj_mgr_err("VDEV is not in up state");
          return NULL;
    }

    peer = wlan_objmgr_peer_obj_create(vdev, peer_type, macaddr);
    if(peer != NULL) {
        /* TODO wait is not needed for peer, since all peer dependent modules operate in
      same context */
        if(peer->obj_state != WLAN_OBJ_STATE_CREATED) {
            QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                    "%s:PEER (partial creation) failed", __func__);
            wlan_objmgr_peer_obj_delete(peer);
            return NULL;
        }
    }
    else {
        QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_DEBUG,
                "%s:PEER (creation) failed", __func__);
        return NULL;
    }
    ni = wlan_peer_get_mlme_ext_obj(peer);

    return ni;
}

struct ieee80211_node *wlan_objmgr_alloc_sta_node(struct ieee80211vap *vap, uint8_t *macaddr)
{
    return wlan_objmgr_alloc_node(vap, WLAN_PEER_STA, macaddr);
}

struct ieee80211_node *wlan_objmgr_alloc_ap_node(struct ieee80211vap *vap, uint8_t *macaddr)
{
    return wlan_objmgr_alloc_node(vap, WLAN_PEER_AP, macaddr);
}

struct ieee80211_node *wlan_objmgr_alloc_ibss_node(struct ieee80211vap *vap, uint8_t *macaddr)
{
    return wlan_objmgr_alloc_node(vap, WLAN_PEER_IBSS, macaddr);
}

struct ieee80211_node *wlan_objmgr_alloc_tmp_node(struct ieee80211vap *vap, uint8_t *macaddr)
{
    return wlan_objmgr_alloc_node(vap, WLAN_PEER_STA_TEMP,macaddr);
}

void wlan_objmgr_delete_node(struct ieee80211_node *ni)
{
    struct wlan_objmgr_peer *peer;

    if (ni == NULL) {
         return;
    }

    if (!(peer = ni->peer_obj)) {
        return;
    }

    if (!qdf_atomic_read(&(ni->ni_logi_deleted))) {
       qdf_atomic_set(&(ni->ni_logi_deleted), 1);
       wlan_dp_peer_detach(peer);
       wlan_objmgr_peer_obj_delete(peer);
    }
    else {
       ieee80211_free_node(ni, WLAN_MLME_OBJMGR_ID);
    }

    return;
}
qdf_export_symbol(wlan_objmgr_delete_node);

void wlan_objmgr_nt_soc_attach(struct ieee80211_node_table *nt)
{
   struct ieee80211com *ic;
   struct wlan_objmgr_pdev *pdev;

   ic = nt->nt_ic;
   pdev = ic->ic_pdev_obj;
   nt->psoc = wlan_pdev_get_psoc(pdev);
}

#if WLAN_OBJMGR_REF_ID_TRACE
struct ieee80211_node *wlan_objmgr_find_node_debug(struct ieee80211com *ic,
                                              uint8_t *macaddr, wlan_objmgr_ref_dbgid id,
                                              const char *func, int line)
{
   struct ieee80211_node *ni;
   struct wlan_objmgr_peer *peer;
   uint8_t pdev_id;
   struct wlan_objmgr_psoc *psoc;

   if (!ic || !(ic->ic_pdev_obj))
        return NULL;

   pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

   psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
   if (!psoc)
       return NULL;

   peer = wlan_objmgr_get_peer_debug(psoc, pdev_id, macaddr, id, func, line);
   if(peer == NULL) {
      return NULL;
   }

   ni = wlan_peer_get_mlme_ext_obj(peer);
   if(ni == NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
   }

   return ni;
}

void wlan_objmgr_ref_node_debug(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id,
                                              const char *func, int line)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_get_ref_debug(peer, id, func, line);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}
qdf_export_symbol(wlan_objmgr_ref_node_debug);

QDF_STATUS wlan_objmgr_try_ref_node_debug(struct ieee80211_node *ni,
                                    wlan_objmgr_ref_dbgid id,
                                    const char *func, int line)
{
    struct wlan_objmgr_peer *peer;

    if (ni == NULL) {
        goto out;
    }

    peer = ni->peer_obj;
    if (peer != NULL) {
        return wlan_objmgr_peer_try_get_ref_debug(peer, id, func, line);
    } else {
        QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                                   "%s: peer is NULL",__func__);
    }
out:
    return QDF_STATUS_E_FAILURE;
}
qdf_export_symbol(wlan_objmgr_try_ref_node_debug);

struct ieee80211_node *wlan_objmgr_find_node_by_mac_n_bssid_debug(
                                    struct ieee80211com *ic,
                                    uint8_t *macaddr,
                                    uint8_t *bssid, wlan_objmgr_ref_dbgid id,
                                    const char *func, int line)
{
   struct ieee80211_node *ni;
   struct wlan_objmgr_peer *peer;
   uint8_t pdev_id;
   struct wlan_objmgr_psoc *psoc;

   if (!ic || !(ic->ic_pdev_obj))
       return NULL;

   pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

   psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
   if (!psoc)
       return NULL;

   peer = wlan_objmgr_get_peer_by_mac_n_vdev_debug(psoc, pdev_id, bssid, macaddr,
                                                   id, func, line);
   if(peer == NULL) {
      return NULL;
   }
   ni = wlan_peer_get_mlme_ext_obj(peer);
   if(ni == NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
   }

   return ni;
}

void wlan_objmgr_unref_node_debug(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id,
                            const char *func, int line)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_release_ref_debug(peer, id, func, line);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}
qdf_export_symbol(wlan_objmgr_unref_node_debug);

void wlan_objmgr_free_node_debug(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id,
                                 const char *func, int line)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_release_ref_debug(peer, id, func, line);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}

qdf_list_t *wlan_objmgr_populate_logically_deleted_node_list_debug(struct ieee80211com *ic,
                                              uint8_t *macaddr, uint8_t *bssid, wlan_objmgr_ref_dbgid id,
                                              const char *func, int line)
{
    uint8_t pdev_id;
    struct wlan_objmgr_psoc *psoc;

    if (!ic || !(ic->ic_pdev_obj))
        return NULL;

    pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc)
        return NULL;


    return wlan_objmgr_populate_logically_deleted_peerlist_by_mac_n_vdev_debug(psoc, pdev_id, bssid, macaddr,
                                                                               id, func, line);
}
#else
struct ieee80211_node *wlan_objmgr_find_node(struct ieee80211com *ic,
                                              uint8_t *macaddr, wlan_objmgr_ref_dbgid id)
{
   struct ieee80211_node *ni;
   struct wlan_objmgr_peer *peer;
   uint8_t pdev_id;
   struct wlan_objmgr_psoc *psoc;

   if (!ic || !(ic->ic_pdev_obj))
       return NULL;

   pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

   psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
   if (!psoc)
       return NULL;

   peer = wlan_objmgr_get_peer(psoc, pdev_id, macaddr, id);
   if(peer == NULL) {
      return NULL;
   }

   ni = wlan_peer_get_mlme_ext_obj(peer);
   if(ni == NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
   }

   return ni;
}

void wlan_objmgr_ref_node(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_get_ref(peer, id);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}
qdf_export_symbol(wlan_objmgr_ref_node);

QDF_STATUS wlan_objmgr_try_ref_node(struct ieee80211_node *ni,
                                    wlan_objmgr_ref_dbgid id)
{
    struct wlan_objmgr_peer *peer;

    if (ni == NULL) {
        goto out;
    }

    peer = ni->peer_obj;
    if (peer != NULL) {
        return wlan_objmgr_peer_try_get_ref(peer, id);
    } else {
        QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
                                   "%s: peer is NULL",__func__);
    }
out:
    return QDF_STATUS_E_FAILURE;
}
qdf_export_symbol(wlan_objmgr_try_ref_node);

struct ieee80211_node *wlan_objmgr_find_node_by_mac_n_bssid(
                                    struct ieee80211com *ic,
                                    uint8_t *macaddr,
                                    uint8_t *bssid, wlan_objmgr_ref_dbgid id)
{
   struct ieee80211_node *ni;
   struct wlan_objmgr_peer *peer;
   uint8_t pdev_id;
   struct wlan_objmgr_psoc *psoc;

   if (!ic || !(ic->ic_pdev_obj))
       return NULL;

   pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

   psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
   if (!psoc)
       return NULL;

   peer = wlan_objmgr_get_peer_by_mac_n_vdev(psoc, pdev_id, bssid, macaddr, id);
   if(peer == NULL) {
      return NULL;
   }
   ni = wlan_peer_get_mlme_ext_obj(peer);
   if(ni == NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
   }

   return ni;
}

void wlan_objmgr_unref_node(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}
qdf_export_symbol(wlan_objmgr_unref_node);

void wlan_objmgr_free_node(struct ieee80211_node *ni, wlan_objmgr_ref_dbgid id)
{
    struct wlan_objmgr_peer *peer;

    if(ni == NULL) {
         return;
    }
    peer = ni->peer_obj;
    if(peer != NULL) {
       wlan_objmgr_peer_release_ref(peer, id);
    }
    else {
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_ERROR,
               "%s: peer is NULL",__func__);
    }
}

qdf_list_t *wlan_objmgr_populate_logically_deleted_node_list(struct ieee80211com *ic,
                                              uint8_t *macaddr, uint8_t *bssid, wlan_objmgr_ref_dbgid id)
{
    uint8_t pdev_id;
    struct wlan_objmgr_psoc *psoc;

    if (!ic || !(ic->ic_pdev_obj))
        return NULL;

    pdev_id =  wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc)
        return NULL;


    return wlan_objmgr_populate_logically_deleted_peerlist_by_mac_n_vdev(psoc, pdev_id, bssid, macaddr, id);
}
#endif

struct ieee80211com* wlan_vdev_get_ic(struct wlan_objmgr_vdev *vdev)
{
   struct wlan_objmgr_pdev *pdev;

   if (vdev == NULL) {
      return NULL;
   }
   pdev =  wlan_vdev_get_pdev(vdev);

   return wlan_pdev_get_mlme_ext_obj(pdev);
}
qdf_export_symbol(wlan_vdev_get_ic);

struct ieee80211vap* wlan_vdev_get_vap(struct wlan_objmgr_vdev *vdev)
{
   if (vdev == NULL) {
      return NULL;
   }

   return wlan_vdev_get_mlme_ext_obj(vdev);
}

qdf_export_symbol(wlan_vdev_get_vap);

void wlan_node_set_peer_state(struct ieee80211_node *ni,
                                    enum wlan_peer_state state)
{
    struct wlan_objmgr_peer *peer;

    peer = ni->peer_obj;
    if(peer != NULL) {
	wlan_peer_mlme_set_state(peer, state);
    }
}

enum wlan_peer_state wlan_node_get_peer_state(struct ieee80211_node *ni)
{
    struct wlan_objmgr_peer *peer;

    peer = ni->peer_obj;
    if(peer != NULL) {
	return wlan_peer_mlme_get_state(peer);
    }
    else {
        return -1;
    }
}

struct ieee80211_node *wlan_wbuf_get_peer_node(wbuf_t wbuf)
{
      return wlan_peer_get_mlme_ext_obj(__wbuf_get_peer(wbuf));
}
qdf_export_symbol(wlan_wbuf_get_peer_node);

void wlan_wbuf_set_peer_node(wbuf_t wbuf, struct ieee80211_node *ni)
{
   struct wlan_objmgr_peer *peer = NULL;

   if(ni != NULL) {
      peer = wlan_node_get_peer_obj(ni);
   }
   __wbuf_set_peer(wbuf,peer);
}
qdf_export_symbol(wlan_wbuf_set_peer_node);

void wlan_wbuf_set_peer(wbuf_t wbuf, struct wlan_objmgr_peer *peer)
{
   __wbuf_set_peer(wbuf,peer);
}
qdf_export_symbol(wlan_wbuf_set_peer);


void wlan_objmgr_delete_vap(struct ieee80211vap *vap)
{
   wlan_dp_vdev_detach(vap->vdev_obj);
   wlan_objmgr_vdev_obj_delete(vap->vdev_obj);
}

struct wlan_objmgr_pdev*
wlan_vap_get_pdev(wlan_if_t vap)
{
    struct ieee80211com *ic = NULL;

    if (!vap) {
        scan_err("null vap");
        return NULL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        scan_err("null ic");
        return NULL;
    }

    return (ic->ic_pdev_obj);
}

struct wlan_objmgr_psoc*
wlan_vap_get_psoc(wlan_if_t vap)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;

    pdev = wlan_vap_get_pdev(vap);
    if (!pdev) {
        scan_err("null pdev");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);

    return psoc;
}

QDF_STATUS wlan_objmgr_vap_alloc_tim_bitmap(struct wlan_objmgr_vdev *vdev)
{
   struct ieee80211vap *vap;

   if (!vdev)
      return QDF_STATUS_E_FAILURE;

   vap = wlan_vdev_get_mlme_ext_obj(vdev);
   if (!vap)
      return QDF_STATUS_E_FAILURE;
   if (vap->iv_alloc_tim_bitmap)
      return vap->iv_alloc_tim_bitmap(vap);

   return QDF_STATUS_E_FAILURE;
}

QDF_STATUS
wlan_objmgr_vap_alloc_aid_bitmap(struct wlan_objmgr_vdev *vdev, uint16_t value)
{
   struct ieee80211vap *vap;

   if (!vdev)
      return QDF_STATUS_E_FAILURE;

   vap = wlan_vdev_get_mlme_ext_obj(vdev);
   if (!vap)
      return QDF_STATUS_E_FAILURE;

   return wlan_node_alloc_aid_bitmap(vap, value);
}

void wlan_objmgr_print_ref_cnts(struct ieee80211com *ic)
{
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_psoc *psoc;

    psoc = wlan_pdev_get_psoc(pdev);

    wlan_objmgr_print_ref_all_objects_per_psoc(psoc);

}
qdf_export_symbol(wlan_objmgr_print_ref_cnts);

static void wlan_vdev_iter_update_txchainmask_op(struct wlan_objmgr_pdev *pdev,
        void *obj, void *args)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)obj;
    u_int8_t *txchainmask = (u_int8_t *)args;

    wlan_vdev_mlme_set_txchainmask(vdev, *txchainmask);
}

void
wlan_objmgr_update_txchainmask_to_allvdevs(wlan_dev_t ic)
{
    if (wlan_objmgr_pdev_try_get_ref(ic->ic_pdev_obj, WLAN_MLME_NB_ID) ==
                                     QDF_STATUS_SUCCESS) {
          wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                   wlan_vdev_iter_update_txchainmask_op,
                                   &ic->ic_tx_chainmask, 0, WLAN_MLME_NB_ID);
          wlan_objmgr_pdev_release_ref(ic->ic_pdev_obj, WLAN_MLME_NB_ID);
    }

    /* If we don't get a reference to pdev, then it indicates the pdev is being
     * deleted. Hence the corresponding wlan_dev_t too will be deleted and the
     * Tx chainmask will no longer be required anywhere.
     */
}
qdf_export_symbol(wlan_objmgr_update_txchainmask_to_allvdevs);

static void wlan_vdev_iter_update_rxchainmask_op(struct wlan_objmgr_pdev *pdev,
        void *obj, void *args)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)obj;
    u_int8_t *rxchainmask = (u_int8_t *)args;

    wlan_vdev_mlme_set_rxchainmask(vdev, *rxchainmask);
}

void
wlan_objmgr_update_rxchainmask_to_allvdevs(wlan_dev_t ic)
{
    if (wlan_objmgr_pdev_try_get_ref(ic->ic_pdev_obj, WLAN_MLME_NB_ID) ==
                                     QDF_STATUS_SUCCESS) {
          wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                   wlan_vdev_iter_update_rxchainmask_op,
                                   &ic->ic_rx_chainmask, 0, WLAN_MLME_NB_ID);
          wlan_objmgr_pdev_release_ref(ic->ic_pdev_obj, WLAN_MLME_NB_ID);
    }

    /* If we don't get a reference to pdev, then it indicates the pdev is being
     * deleted. Hence the corresponding wlan_dev_t too will be deleted and the
     * Tx chainmask will no longer be required anywhere.
     */
}
qdf_export_symbol(wlan_objmgr_update_rxchainmask_to_allvdevs);
