/*
* Copyright (c) 2011-2014,2017-2021 Qualcomm Innovation Center, Inc.
* All Rights Reserved
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
* 2011-2014 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*
* Copyright (c) 2010-2011, Atheros Communications Inc.
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
*
*/

#include "osif_private.h"
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include <dp_extap.h>
#include <ieee80211_acfg.h>
#include <acfg_drv_event.h>
#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#endif
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif
#include <qdf_nbuf.h> /* qdf_nbuf_map_single */
#include <qdf_platform.h>
#include <net/osif_net.h>

#include "wlan_osif_priv.h"
#include <qdf_perf.h>

#include "ath_netlink.h"

#include "scheduler_api.h"
#include "ieee80211_ev.h"

#include <linux/proc_fs.h>

#include <linux/seq_file.h>
#include "ieee80211_ioctl_acfg.h"
#include <ieee80211_vi_dbg.h>

#include <qdf_types.h>
#include <qdf_parse.h>
#if UMAC_SUPPORT_PROXY_ARP
int wlan_proxy_arp(wlan_if_t vap, wbuf_t wbuf);
#endif

#include <linux/ethtool.h>

#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_api.h>
#include <wlan_sa_api_utils_defs.h>
#endif

#include <ieee80211_nl.h>

#if ATH_SUPPORT_WRAP
#include "ieee80211_api.h"
#endif
#if ATH_PERF_PWR_OFFLOAD
#include <ol_cfg_raw.h>
#include <osif_rawmode.h>
#include <ol_if_athvar.h>
#endif /* ATH_PERF_PWR_OFFLOAD */
#include <target_type.h>
#include "ol_ath.h"
#include <linux/ethtool.h>
#include <osif_ol.h>
#include "dispatcher_init_deinit.h"
#include <ieee80211_objmgr_priv.h>
#include <qdf_threads.h>
#include <wlan_offchan_txrx_api.h>
#include <ieee80211_radiotap.h>
#include <ieee80211_ucfg.h>
#include <wlan_mlme_dp_dispatcher.h>
#include "cfg_ucfg_api.h"
#include "cfg_dispatcher.h"
#if ATH_SUPPORT_ZERO_CAC_DFS
#include <wlan_lmac_if_api.h>
#endif
#ifdef QCA_OL_TX_MULTIQ_SUPPORT
    #define OSIF_DP_NETDEV_TX_QUEUE_NUM 4
#else
    #define OSIF_DP_NETDEV_TX_QUEUE_NUM 1
#endif

#ifdef QCA_OL_RX_MULTIQ_SUPPORT
    #define OSIF_DP_NETDEV_RX_QUEUE_NUM 4
#else
    #define OSIF_DP_NETDEV_RX_QUEUE_NUM 1
#endif

#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif /* QCA_SUPPORT_CP_STATS */

#if QCA_SUPPORT_SON || QCA_SUPPORT_SSID_STEERING
#include <wlan_son_pub.h>
#endif /* QCA_SUPPORT_SON || QCA_SUPPORT_SSID_STEERING*/

#include <wlan_dfs_mlme_api.h>
#include <ieee80211_regdmn_dispatcher.h>
#include <wlan_reg_services_api.h>
#include <wlan_vdev_mlme_ser_if.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_vdev_mgr_ucfg_api.h>
#include <qal_notifier.h>
#include <wlan_mlme_if.h>
#include <wlan_psoc_mlme.h>
#include <wlan_psoc_mlme_main.h>
#include "ol_ratectrl_11ac_types.h"
#if DBDC_REPEATER_SUPPORT
#include <qca_multi_link.h>
#include <qca_multi_link_tbl.h>
#endif

#ifdef QCA_SUPPORT_WDS_EXTENDED
#include <cdp_txrx_cmn.h>
#endif /* QCA_SUPPORT_WDS_EXTENDED */

/* ahbskip usage  : Skip registering direct attach devices only when set to 1 */
unsigned int ahbskip = 0;
module_param(ahbskip, int, 0644);

#if QCA_SUPPORT_SON
struct chan_change_evt_t {
    u_int8_t channel;
    u_int16_t freq;
};
#endif

/*
 * fw_rec_dbg_mask usage: Downgrades the QDF debug print priority during FW
 * recovery
 */
int fw_rec_dbg_mask = 0;
qdf_declare_param(fw_rec_dbg_mask, int);

uint8_t used_mac_addr_byte[3] = { 0 };
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
#include "osif_wrap_private.h"
extern osif_dev * osif_wrap_wdev_vma_find(struct wrap_devt *wdt,unsigned char *mac);
#else
#include "dp_wrap.h"
#endif
#endif

extern int osif_delete_vap_wait_and_free(struct net_device *dev, int recover);
extern int ol_ath_ucfg_get_vap_info(struct ol_ath_softc_net80211 *scn,
                                    struct ieee80211_profile *profile);
extern int
wlan_get_vap_info(struct ieee80211vap *vap,
                  struct ieee80211vap_profile *vap_profile,
                  void *handle);
extern int
wlan_get_vdev_dp_stats(struct ieee80211vap *vap,
                       struct ieee80211_stats *vap_stats_usr,
                       struct ieee80211_mac_stats *ucast_stats_usr,
                       struct ieee80211_mac_stats *mcast_stats_usr);
#ifdef QCA_SUPPORT_WDS_EXTENDED
extern int
wlan_get_peer_dp_stats(struct ieee80211com *ic,
                       struct wlan_objmgr_peer *peer,
                       struct ieee80211_nodestats *ni_stats_user);
extern int
wlan_update_peer_cp_stats(struct ieee80211_node *ni,
                          struct ieee80211_nodestats *ni_stats_user);
#endif /* QCA_SUPPORT_WDS_EXTENDED */

extern int wlan_vap_delete_complete(struct ieee80211vap *vap);
static void ic_cancel_obss_nb_ru_tolerance_timer(struct ieee80211com *ic);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include "osif_nss_wifiol_if.h"
#include "osif_nss_wifiol_vdev_if.h"
#endif

#if QCA_PARTNER_DIRECTLINK_TX
#define QCA_PARTNER_DIRECTLINK_OSIF_UMAC 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OSIF_UMAC
#endif /* QCA_PARTNER_DIRECTLINK_TX */

#if ATH_PARAMETER_API
#include "ath_papi.h"
#endif

#if !PEER_FLOW_CONTROL_FORCED_MODE0
#define TXOVERFLOW_PRINT_LIMIT 100
#endif
#include <wlan_dfs_ucfg_api.h>
#include <wlan_utility.h>
#include <wlan_mlme_if.h>
#include <wlan_cm_api.h>
#include <osif_cm_util.h>

void ieee80211_proc_vattach(struct ieee80211vap *vap);
void ieee80211_proc_vdetach(struct ieee80211vap *vap);
#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

#if MESH_MODE_SUPPORT
void (*external_tx_complete)(struct sk_buff *skb) = NULL;
qdf_export_symbol(external_tx_complete);

#endif

struct ath_softc_net80211 *global_scn[GLOBAL_SCN_SIZE] = {NULL};
int num_global_scn = 0;

ol_ath_soc_softc_t *ol_global_soc[GLOBAL_SOC_SIZE] = {NULL};
int ol_num_global_soc = 0;

unsigned int enable_mesh_peer_cap_update = 0;
module_param(enable_mesh_peer_cap_update, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
qdf_export_symbol(enable_mesh_peer_cap_update);

#if QLD
/*
 * 0: means feature is disabled
 * Non zero: list size defined by qld_max_list
 */
unsigned int qld_max_list  = 0;
module_param(qld_max_list, uint, 0644);
qdf_export_symbol(qld_max_list);
#endif

unsigned int g_unicast_deauth_on_stop = 0;
module_param(g_unicast_deauth_on_stop, int, 0644);
qdf_export_symbol(g_unicast_deauth_on_stop);

/* module param to control max wait time for receiveing higher
 * channel width data frames. After time timeout, host will
 * stop checking rx frame bw to upgrade STA chan width.
 * Default is 60 seconds.
 */
unsigned int g_csa_max_rx_wait_time = 60000;
module_param(g_csa_max_rx_wait_time, int, 0644);
qdf_export_symbol(g_csa_max_rx_wait_time);

#ifdef QCA_WIFI_MODULE_PARAMS_FROM_INI
#define UMAC_PARAM_STR_LENGTH 40

extern uint32_t atf_mode;
extern uint32_t netlink_acfg;
extern uint32_t netlink_ath_ssid_event;
extern uint32_t enable_pktlog_support;
extern uint32_t netlink_band_steering_event;
extern uint32_t sa_api_mode;
extern uint32_t netlink_son_ald;

enum umac_num_module_param {
    PARAM_AHBSKIP,
    PARAM_G_UNICAST_DEAUTH_ON_STOP,
    PARAM_ATF_MODE,
    PARAM_NETLINK_ACFG,
    PARAM_ENABLE_MESH_PEER_CAP_UPDATE,
    PARAM_NETLINK_ATH_SSID_EVENT,
    PARAM_ENABLE_PKTLOG_SUPPORT,
    PARAM_NETLINK_BAND_STEERING_EVENT,
    PARAM_FW_REC_DBG_MASK,
    PARAM_QLD_MAX_LIST,
    PARAM_G_CSA_MAX_RX_WAIT_TIME,
    PARAM_SA_API_MODE,
    PARAM_NETLINK_SON_ALD,
    UMAC_PARAM_MAX,
};

static char umac_module_param[UMAC_PARAM_MAX][UMAC_PARAM_STR_LENGTH] = {
    "ahbskip",
    "g_unicast_deauth_on_stop",
    "atf_mode",
    "netlink_acfg",
    "enable_mesh_peer_cap_update",
    "netlink_ath_ssid_event",
    "enable_pktlog_support",
    "netlink_band_steering_event",
    "fw_rec_dbg_mask",
    "qld_max_list",
    "g_csa_max_rx_wait_time",
    "sa_api_mode",
    "netlink_son_ald",
};

/**
 * umac_module_param_handler() - update umac module param
 *
 * This function receives any one of umac module param and its value as input
 *
 * Return : QDF_STATUS_SUCCESS on Success
 */
QDF_STATUS umac_module_param_handler(void *context, const char *str_param, const char *str_value)
{
    QDF_STATUS status;
    uint16_t param=0;

    while ( param < UMAC_PARAM_MAX ) {
        if (qdf_str_eq(umac_module_param[param], str_param)) {
            switch(param) {
                case PARAM_AHBSKIP:
                    status = qdf_int32_parse(str_value, &ahbskip);
                    break;
                case PARAM_G_UNICAST_DEAUTH_ON_STOP:
                    status = qdf_int32_parse(str_value,
                                             &g_unicast_deauth_on_stop);
                    break;
                case PARAM_ATF_MODE:
#if QCA_AIRTIME_FAIRNESS
                    status = qdf_uint32_parse(str_value, &atf_mode);
#endif
                    break;
                case PARAM_NETLINK_ACFG:
#if UMAC_SUPPORT_ACFG
                    status = qdf_uint32_parse(str_value, &netlink_acfg);
#endif
                    break;
                case PARAM_ENABLE_MESH_PEER_CAP_UPDATE:
                    status = qdf_uint32_parse(str_value,
                                              &enable_mesh_peer_cap_update);
                    break;
                case PARAM_NETLINK_ATH_SSID_EVENT:
#if QCA_SUPPORT_SSID_STEERING
                            status = qdf_uint32_parse(str_value,
                            &netlink_ath_ssid_event);
#endif
                    break;
                case PARAM_ENABLE_PKTLOG_SUPPORT:
                    status = qdf_uint32_parse(str_value,
                                              &enable_pktlog_support);
                    break;
                case PARAM_NETLINK_BAND_STEERING_EVENT:
#if QCA_SUPPORT_SON
                    status = qdf_uint32_parse(str_value,
                                              &netlink_band_steering_event);
#endif
                    break;
                case PARAM_FW_REC_DBG_MASK:
                    status = qdf_int32_parse(str_value, &fw_rec_dbg_mask);
                    break;
                case PARAM_QLD_MAX_LIST:
                    status = qdf_uint32_parse(str_value, &qld_max_list);
                    break;
                case PARAM_G_CSA_MAX_RX_WAIT_TIME:
                    status = qdf_int32_parse(str_value,
                                             &g_csa_max_rx_wait_time);
                    break;
                case PARAM_SA_API_MODE:
#if UNIFIED_SMARTANTENNA
                    status = qdf_uint32_parse(str_value, &sa_api_mode);
#endif
                    break;
                case PARAM_NETLINK_SON_ALD:
#if QCA_SUPPORT_SON
                    status = qdf_uint32_parse(str_value, &netlink_son_ald);
#endif
                    break;
                default:
                    break;
            }
            if ( QDF_IS_STATUS_SUCCESS(status)) {
                return QDF_STATUS_SUCCESS;
            }
        }
        param++;
    }
    return QDF_STATUS_SUCCESS;
}

/**
 * initialize_umac_module_param_from_ini() - Update umac module params
 *
 *
 * Read the file which has wifi module params, parse and update
 * umac module params.
 *
 * Return: void
 */
void initialize_umac_module_param_from_ini(void)
{
    QDF_STATUS status;
    char *path = QDF_WIFI_MODULE_PARAMS_FILE;

    status = qdf_ini_parse(path, NULL, umac_module_param_handler, NULL);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_err("ERROR: Failed to parse *.ini file @ %s; status:%d",
                path, status);
        return;
    }
}
#endif

unsigned long ath_ioctl_debug = 0;      /* for run-time debugging of ioctl commands */
/* For storing LCI and LCR info for this AP */
u_int32_t ap_lcr[RTT_LOC_CIVIC_REPORT_LEN]={0};
int num_ap_lcr=0;
u_int32_t ap_lci[RTT_LOC_CIVIC_INFO_LEN]={0};
int num_ap_lci=0;
qdf_export_symbol(num_ap_lci);
qdf_export_symbol(ap_lci);
qdf_export_symbol(num_ap_lcr);
qdf_export_symbol(ap_lcr);
#if ATH_DEBUG
unsigned long ath_rtscts_enable = 0;
#endif
	A_UINT32 dscp_tid_map[WMI_HOST_DSCP_MAP_MAX] = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			5, 5, 5, 5, 5, 5, 5, 5,
			5, 5, 5, 5, 5, 5, 5, 5,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
	};
qdf_export_symbol(dscp_tid_map);

struct g_wifi_info g_winfo;
qdf_export_symbol(g_winfo);

qdf_spinlock_t asf_print_lock;

#ifdef OSIF_DEBUG
#define IEEE80211_ADD_MEDIA(_media, _s, _o) \
    do { \
        qdf_print("adding media word 0x%x ",IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0)); \
        ifmedia_add(_media, IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0), 0, NULL); \
    } while(0);
#else
#define IEEE80211_ADD_MEDIA(_media, _s, _o) \
        ifmedia_add(_media, IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0), 0, NULL);
#endif
#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef QCA_PARTNER_PLATFORM
#define PARTNER_ETHTOOL_SUPPORTED 0
#endif

struct global_ic_list ic_list = {
    .radio_list_lock = __SPIN_LOCK_UNLOCKED(ic_list.radio_list_lock),
};
qdf_export_symbol(ic_list);

extern QDF_STATUS wlan_mlme_vdev_notify_down_complete(
                                     struct wlan_objmgr_vdev *vdev);
void osif_mlme_notify_handler(wlan_if_t vap,
        enum wlan_serialization_cmd_type cmd_type);
#define OLE_HEADER_PADDING 2

#include <ieee80211.h>
#include <ieee80211_mlme_dfs_dispatcher.h>

#define IS_SNAP(_llc) ((_llc)->llc_dsap == LLC_SNAP_LSAP && \
                       (_llc)->llc_ssap == LLC_SNAP_LSAP && \
                       (_llc)->llc_control == LLC_UI)
void
transcap_nwifi_to_8023(qdf_nbuf_t msdu)
{
    struct ieee80211_frame_addr4 *wh;
    uint32_t hdrsize;
    struct llc *llchdr;
    struct ether_header *eth_hdr;
    uint16_t ether_type = 0;
    uint8_t a1[QDF_MAC_ADDR_SIZE], a2[QDF_MAC_ADDR_SIZE], a3[QDF_MAC_ADDR_SIZE], a4[QDF_MAC_ADDR_SIZE];
    uint8_t fc1;

    wh = (struct ieee80211_frame_addr4 *)qdf_nbuf_data(msdu);
    IEEE80211_ADDR_COPY(a1, wh->i_addr1);
    IEEE80211_ADDR_COPY(a2, wh->i_addr2);
    IEEE80211_ADDR_COPY(a3, wh->i_addr3);
    fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    /* Native Wifi header  give only 80211 non-Qos packets */
    if (fc1 == IEEE80211_FC1_DIR_DSTODS )
    {
        hdrsize = sizeof(struct ieee80211_frame_addr4);

        /* In case of WDS frames, , padding is enabled by default
         * in Native Wifi mode, to make ipheader 4 byte aligned
         */
        hdrsize = hdrsize + OLE_HEADER_PADDING;
    }
    else
    {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    llchdr = (struct llc *)(((uint8_t *)qdf_nbuf_data(msdu)) + hdrsize);

    if (IS_SNAP(llchdr) &&
            (llchdr->llc_un.type_snap.org_code[0] == RFC1042_SNAP_ORGCODE_0) &&
            (llchdr->llc_un.type_snap.org_code[1] == RFC1042_SNAP_ORGCODE_1) &&
            (llchdr->llc_un.type_snap.org_code[2] == RFC1042_SNAP_ORGCODE_2)) {
        ether_type = llchdr->llc_un.type_snap.ether_type;
        /*
         * Now move the data pointer to the beginning of the mac header :
         * new-header = old-hdr + (wifhdrsize + llchdrsize - ethhdrsize)
         */
        qdf_nbuf_pull_head(
                msdu, (hdrsize + sizeof(struct llc) - sizeof(struct ether_header)));

    } else if ((llchdr->llc_control == (LLC_PDU_TYPE | LLC_PDU_CMD_XID)) &&
            (llchdr->llc_fid == LLC_XID_FMTID)) {
        /* For Xid pkts keep the llc data */
        qdf_nbuf_pull_head(msdu,(hdrsize - sizeof(struct ether_header)));
        ether_type = htons(qdf_nbuf_len(msdu) - sizeof(struct ether_header));

    } else {
        /* For non snap pkts keep the llc data */
        qdf_nbuf_pull_head(msdu,(hdrsize - sizeof(struct ether_header)));
        ether_type = htons(qdf_nbuf_len(msdu) - sizeof(struct ether_header));
    }

    eth_hdr = (struct ether_header *)(qdf_nbuf_data(msdu));

    switch (fc1) {
    case IEEE80211_FC1_DIR_NODS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a1);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a2);
        break;
    case IEEE80211_FC1_DIR_TODS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a3);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a2);
        break;
    case IEEE80211_FC1_DIR_FROMDS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a1);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a3);
        break;
    case IEEE80211_FC1_DIR_DSTODS:
        IEEE80211_ADDR_COPY(a4, wh->i_addr4);
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a3);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a4);
        break;
    }
    eth_hdr->ether_type = ether_type;
}
qdf_export_symbol(transcap_nwifi_to_8023);

void bringup_vaps_event(void * data);
void bringup_sta_vaps_event(void * data);
void bringdown_ap_vaps_event(void * data);
void bring_down_up_ap_vaps(void * data);
void bringdown_sta_vaps_event(void * data);

static void osif_bringup_vap_iter_func(void *arg, wlan_if_t vap);
static void osif_restart_ap_vap_iter_func(void *arg, wlan_if_t vap);
#ifdef LIMIT_MTU_SIZE

static struct net_device __fake_net_device = {
    .hard_header_len    = ETH_HLEN
};

static struct rtable __fake_rtable = {
    .u = {
        .dst = {
            .__refcnt       = ATOMIC_INIT(1),
            .dev            = &__fake_net_device,
            .path           = &__fake_rtable.u.dst,
            .metrics        = {[RTAX_MTU - 1] = 1500},
        }
    },
    .rt_flags   = 0,
};
#else
#define __fake_rtable 0
#endif


#if UMAC_VOW_DEBUG
void update_vow_dbg_counters(osif_dev  *osifp, qdf_nbuf_t msdu, unsigned long *vow_counter, int rx, int peer);
#endif
void osif_check_pending_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
void osif_bring_down_vaps(wlan_dev_t comhandle, wlan_if_t vap);
static void osif_bringdown_vap_iter_func(void *arg, wlan_if_t vap);
extern void ol_notify_if_low_on_buffers(struct ath_softc_net80211 *scn, uint32_t free_buff);

extern void ieee80211_ioctl_vattach(struct net_device *dev);
extern void ieee80211_ioctl_vdetach(struct net_device *dev);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
extern int osif_wrap_attach(wlan_dev_t comhandle);
extern int osif_wrap_detach(wlan_dev_t comhandle);
extern int osif_wrap_dev_add(osif_dev *osdev);
extern void osif_wrap_dev_remove(osif_dev *osdev);
/* TODO -
 * These definitons should be removed and osif_wrap.h should be included */
extern void osif_wrap_dev_remove_vma(osif_dev *osdev);
#else
osif_dev *wlan_get_osdev(struct wlan_objmgr_vdev *vdev);
struct ieee80211vap *wlan_get_vap(struct wlan_objmgr_vdev *vdev);
#endif
#endif

#ifdef QCA_PARTNER_PLATFORM
extern void wlan_pltfrm_attach(struct net_device *dev);
extern void wlan_pltfrm_detach(struct net_device *dev);
extern void osif_pltfrm_receive (os_if_t osif, wbuf_t wbuf,
                        u_int16_t type, u_int16_t subtype,
                        ieee80211_recv_status *rs);
extern void osif_pltfrm_record_macinfor(unsigned char unit, unsigned char* mac);
extern bool osif_pltfrm_deliver_data(os_if_t osif, wbuf_t wbuf);
extern void osif_pltfrm_vap_init( struct net_device *dev );
extern void osif_pltfrm_vap_stop( osif_dev  *osifp );
#endif
#if QCA_NSS_PLATFORM
extern void osif_send_to_nss(os_if_t osif, struct sk_buff *skb, void *nss_redir_ctx,
                             struct net_device *dev);
#endif
#if defined (QCA_PARTNER_PLATFORM) || (QCA_NSS_PLATFORM)
extern void osif_pltfrm_create_vap(osif_dev *osifp);
extern void osif_pltfrm_delete_vap(osif_dev *osifp);
#ifdef QCA_SUPPORT_WDS_EXTENDED
extern void osif_pltfrm_create_ext_vap(osif_peer_dev *osifp);
extern void osif_pltfrm_delete_ext_vap(osif_peer_dev *osifp);
#endif
#endif

static void osif_bkscan_acs_event_handler(void *arg, wlan_chan_t channel);
QDF_STATUS osif_cmd_schedule_req(struct wlan_objmgr_vdev *vdev, enum osif_cmd_type cmd_type);

/* The code below is used to register a parent file in sysfs */
static ssize_t ath_parent_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    osif_dev  *osifp = ath_netdev_priv(net);
    struct net_device *parent = osifp->os_comdev;

    return snprintf(buf, IFNAMSIZ,"%s\n", parent->name);
}

/*Handler for sysfs entry cfg80211 xmlfile
  returns xml file that is used for vendor commands */
static ssize_t wifi_cfg80211_xmlfile_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    strlcpy(buf, "qcacommands_vap.xml", sizeof("qcacommands_vap.xml"));
    return strlen(buf);
}

/* Handler for sysfs entry cfg80211 htcaps
   returns htcaps supported that is usable for hostapd */
static ssize_t wifi_cfg80211_htcaps_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    osif_dev  *osdev = ath_netdev_priv(net);
    wlan_if_t vap = osdev->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    u_int16_t capinfo = ic->ic_htcap;
    uint32_t iv_ldpc;

    if ( !buf )
        return 0 ;

    buf[0]='\0';

    if ( !capinfo )
        return strlen(buf);

    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_LDPC, &iv_ldpc);
    /* configurable through IEEE80211_SUPPORT_LDPC param */
    if ((capinfo & IEEE80211_HTCAP_C_ADVCODING) && iv_ldpc)
        strlcat(buf, "[LDPC]", strlen(buf) + sizeof("[LDPC]") + 1);
    /* IEEE80211_HTCAP_C_CHWIDTH40 is configured  ucisn UCI scipts
       based on configuration */
    if ((capinfo & IEEE80211_HTCAP_C_SM_MASK) ==
            IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC)
        strlcat(buf, "[SMPS-STATIC]", strlen(buf) + sizeof("[SMPS-STATIC]") + 1);
    if ((capinfo & IEEE80211_HTCAP_C_SM_MASK) ==
            IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC)
        strlcat(buf, "[SMPS-DYNAMIC]", strlen(buf) + sizeof("[SMPS-DYNAMIC]") + 1);
    if (capinfo & IEEE80211_HTCAP_C_GREENFIELD)
        strlcat(buf, "[GF]", strlen(buf) + sizeof("[GF]") + 1);
    /* IEEE80211_HTCAP_C_SHORTGI20/40 configured using UCI scripts
       based on configuration
      */
    /* configurable through IEEE80211_SUPPORT_TX_STBC param */
    if ((capinfo & IEEE80211_HTCAP_C_TXSTBC) && vap->iv_tx_stbc)
        strlcat(buf, "[TX-STBC]", strlen(buf) + sizeof("[TX-STBC]") + 1);
    if ((capinfo & IEEE80211_HTCAP_C_RXSTBC)) {
        if (vap->iv_rx_stbc == 1)
            strlcat(buf, "[RX-STBC-1]", strlen(buf) + sizeof("[RX-STBC-1]") + 1);
        if (vap->iv_rx_stbc == 2)
            strlcat(buf, "[RX-STBC-12]", strlen(buf) + sizeof("[RX-STBC-12]") + 1);
        if (vap->iv_rx_stbc == 3)
            strlcat(buf, "[RX-STBC-123]", strlen(buf) + sizeof("[RX-STBC-123]") + 1);
        if (vap->iv_rx_stbc == 4)
            strlcat(buf, "[RX-STBC-1234]", strlen(buf) + sizeof("[RX-STBC-1234]") + 1);
    }
    if (capinfo & IEEE80211_HTCAP_C_DELAYEDBLKACK)
        strlcat(buf, "[DELAYED-BA]", strlen(buf) + sizeof("[DELAYED-BA]") + 1);
    if (capinfo & IEEE80211_HTCAP_C_MAXAMSDUSIZE)
        strlcat(buf, "[MAX-AMSDU-7935]", strlen(buf) + sizeof("[MAX-AMSDU-7935]") + 1);
    if (capinfo & IEEE80211_HTCAP_C_DSSSCCK40)
        strlcat(buf, "[DSSS_CCK-40]", strlen(buf) + sizeof("[DSSS_CCK-40]") + 1);
    if ((capinfo & IEEE80211_HTCAP_C_INTOLERANT40) && vap->iv_ht40_intolerant)
        strlcat(buf, "[40-INTOLERANT]", strlen(buf) + sizeof("[40-INTOLERANT]") + 1);
    if (capinfo & IEEE80211_HTCAP_C_LSIGTXOPPROT)
        strlcat(buf, "[LSIG-TXOP-PROT]", strlen(buf) + sizeof("[LSIG-TXOP-PROT]") + 1);

    return strlen(buf);
}

/* Handler for sysfs entry cfg80211 htcaps
   returns htcaps supported that is usable for hostapd */
static ssize_t wifi_cfg80211_vhtcaps_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
#define AMPDU_STRING_LEN 22
    struct net_device *net = to_net_dev(dev);
    osif_dev  *osdev = ath_netdev_priv(net);
    wlan_if_t vap = osdev->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
    u_int32_t vhtcap = ic->ic_vhtcap;
    u_int8_t ampdu_len_exponenet = 0,bf_antenna_max = 0;
    char ampdu_exponent_string[32];
    uint32_t txbf;

    if ( !buf )
        return 0 ;

    buf[0]='\0';

    /*
        [VHT160] [VHT160-80PLUS80] - add by UCI configuration
    */
    if (vhtcap & IEEE80211_VHTCAP_MAX_MPDU_LEN_7935)
        strlcat(buf, "[MAX-MPDU-7991]", strlen(buf) + sizeof("[MAX-MPDU-7991]") + 1 );
    if (vhtcap & IEEE80211_VHTCAP_MAX_MPDU_LEN_11454)
        strlcat(buf, "[MAX-MPDU-11454]", strlen(buf) + sizeof("[MAX-MPDU-11454]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160)
        strlcat(buf, "[VHT160]", strlen(buf) + sizeof("[VHT160]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160)
        strlcat(buf, "[VHT160-80PLUS80]", strlen(buf) + sizeof("[VHT160-80PLUS80]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_RX_LDPC)
        strlcat(buf, "[RXLDPC]", strlen(buf) + sizeof("[RXLDPC]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_SHORTGI_80)
        strlcat(buf, "[SHORT-GI-80]", strlen(buf) + sizeof("[SHORT-GI-80]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_SHORTGI_160)
        strlcat(buf, "[SHORT-GI-160]", strlen(buf) + sizeof("[SHORT-GI-160]") + 1);
    if ((vhtcap & IEEE80211_VHTCAP_TX_STBC) && vap->iv_tx_stbc)
        strlcat(buf, "[TX-STBC-2BY1]", strlen(buf) + sizeof("[TX-STBC-2BY1]") + 1);
    /* configurable through IEEE80211_SUPPORT_RX_STBC param */
    if ((vhtcap & IEEE80211_HTCAP_C_RXSTBC)) {
        if (vap->iv_rx_stbc == 1)
            strlcat(buf, "[RX-STBC1]", strlen(buf) + sizeof("[RX-STBC1]") + 1);
        if (vap->iv_rx_stbc == 2)
            strlcat(buf, "[RX-STBC12]", strlen(buf) + sizeof("[RX-STBC12]") + 1);
        if (vap->iv_rx_stbc == 3)
            strlcat(buf, "[RX-STBC123]", strlen(buf) + sizeof("[RX-STBC123]") + 1);
    }

    ucfg_wlan_vdev_mgr_get_param(vdev,
            WLAN_MLME_CFG_SUBFER, &txbf);
    if ((vhtcap & IEEE80211_VHTCAP_SU_BFORMER) && txbf) {
        strlcat(buf, "[SU-BEAMFORMER]", strlen(buf) + sizeof("[SU-BEAMFORMER]") + 1);
        ucfg_wlan_vdev_mgr_get_param(vdev,
                WLAN_MLME_CFG_SOUNDING_DIM, &txbf);
        /* IEEE80211_VHTCAP_SOUND_DIM */
        if ( txbf == 3)
            strlcat(buf, "[SOUNDING-DIMENSION-4]", strlen(buf) + sizeof("[SOUNDING-DIMENSION-4]") + 1);
        if ( txbf == 2)
            strlcat(buf, "[SOUNDING-DIMENSION-3]", strlen(buf) + sizeof("[SOUNDING-DIMENSION-3]") + 1);
        if ( txbf == 1)
            strlcat(buf, "[SOUNDING-DIMENSION-2]", strlen(buf) + sizeof("[SOUNDING-DIMENSION-2]") + 1);
    }

    ucfg_wlan_vdev_mgr_get_param(vdev,
            WLAN_MLME_CFG_SUBFEE, &txbf);
    if ((vhtcap & IEEE80211_VHTCAP_SU_BFORMEE) && txbf) {
        strlcat(buf, "[SU-BEAMFORMEE]", strlen(buf) + sizeof("[SU-BEAMFORMEE]") + 1);
        /* IEEE80211_VHTCAP_BF_MAX_ANT */
        bf_antenna_max = (vhtcap & IEEE80211_VHTCAP_BF_MAX_ANT) >> IEEE80211_VHTCAP_BF_MAX_ANT_S;
        if ( bf_antenna_max == 3)
            strlcat(buf, "[BF-ANTENNA-4]", strlen(buf) + sizeof("[BF-ANTENNA-4]") + 1);
        if ( bf_antenna_max == 2)
            strlcat(buf, "[BF-ANTENNA-3]", strlen(buf) + sizeof("[BF-ANTENNA-3]") + 1);
        if ( bf_antenna_max == 1)
            strlcat(buf, "[BF-ANTENNA-2]", strlen(buf) + sizeof("[BF-ANTENNA-2]") + 1);
    }

    /* IEEE80211_VHTCAP_MAX_AMPDU_LEN_FACTOR  */
    ampdu_len_exponenet = (vhtcap & IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP) >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;
    snprintf(ampdu_exponent_string, AMPDU_STRING_LEN,
            "[MAX-A-MPDU-LEN-EXP%d]", ampdu_len_exponenet);
    strlcat(buf, ampdu_exponent_string, strlen(buf) + AMPDU_STRING_LEN + 1);

    ucfg_wlan_vdev_mgr_get_param(vdev,
            WLAN_MLME_CFG_MUBFER, &txbf);
    if ((vhtcap & IEEE80211_VHTCAP_MU_BFORMER) && txbf)
        strlcat(buf, "[MU-BEAMFORMER]", strlen(buf) + sizeof("[MU-BEAMFORMER]") + 1);

    ucfg_wlan_vdev_mgr_get_param(vdev,
            WLAN_MLME_CFG_MUBFEE, &txbf);
    if ((vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) && txbf) {
        /* Not yet supported by hostapd */
    }
    if (vhtcap & IEEE80211_VHTCAP_TXOP_PS)
        strlcat(buf, "[VHT-TXOP-PS]", strlen(buf) + sizeof("[VHT-TXOP-PS]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_PLUS_HTC_VHT)
        strlcat(buf, "[HTC-VHT]", strlen(buf) + sizeof("[HTC-VHT]") + 1);
    /* IEEE80211_VHTCAP_LINK_ADAPT */

    /* RX/TX antenna pattern */
    if (vhtcap & IEEE80211_VHTCAP_RX_ANTENNA_PATTERN)
        strlcat(buf, "[RX-ANTENNA-PATTERN]", strlen(buf) + sizeof("[RX-ANTENNA-PATTERN]") + 1);
    if (vhtcap & IEEE80211_VHTCAP_TX_ANTENNA_PATTERN)
        strlcat(buf, "[TX-ANTENNA-PATTERN]", strlen(buf) + sizeof("[TX-ANTENNA-PATTERN]") + 1);

    return strlen(buf);
}

static DEVICE_ATTR(cfg80211_htcaps, S_IRUGO, wifi_cfg80211_htcaps_show, NULL);
static DEVICE_ATTR(cfg80211_vhtcaps, S_IRUGO, wifi_cfg80211_vhtcaps_show, NULL);
static DEVICE_ATTR(cfg80211_xmlfile, S_IRUGO, wifi_cfg80211_xmlfile_show, NULL);
static DEVICE_ATTR(parent, S_IRUGO, ath_parent_show, NULL);
static struct attribute *ath_device_attrs[] = {
    &dev_attr_parent.attr,
    &dev_attr_cfg80211_xmlfile.attr,
    &dev_attr_cfg80211_htcaps.attr,
    &dev_attr_cfg80211_vhtcaps.attr,
    NULL
};

static struct attribute_group ath_attr_group = {
    .attrs  = ath_device_attrs,
};

static void osif_acs_bk_scantimer_fn( void * arg );

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
static void osif_periodic_scan_start(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap;

    vap = osdev->os_if;

    if (osdev->os_periodic_scan_period){
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Start. %d msec \n",
                            __func__, osdev->os_periodic_scan_period);
        OS_SET_TIMER(&osdev->os_periodic_scan_timer, osdev->os_periodic_scan_period);
    }

    return;
}

static void osif_periodic_scan_stop(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap;

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Stop. \n", __func__);
    OS_CANCEL_TIMER(&osdev->os_periodic_scan_timer);

    return;
}

static OS_TIMER_FUNC(periodic_scan_timer_handler)
{
    osif_dev *osifp;
    wlan_if_t vap;
    struct net_device *dev;
    struct scan_start_request *scan_params = NULL;
    uint32_t chan[3];
    struct ieee80211com *ic;
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct wlan_objmgr_vdev *vdev = NULL;

    OS_GET_TIMER_ARG(osifp, osif_dev *);
    vap = osifp->os_if;
    ic  = vap->iv_ic;
    dev = OSIF_TO_NETDEV(osifp);

    if (!(dev->flags & IFF_UP)) {
        return;
    }

    vdev = osifp->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Go. \n", __func__);

    if ((wlan_vap_get_opmode(vap) == IEEE80211_M_STA) &&
         (vap->iv_bss && vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
         !(vap->iv_ic->ic_flags & IEEE80211_F_COEXT_DISABLE))  { /*do not trigger scan, if it disable coext is set */
        if (wlan_cm_is_vdev_connected(vdev) &&
            !wlan_scan_in_progress(vap)){

            scan_params = (struct scan_start_request*) qdf_mem_malloc(sizeof(*scan_params));
            if (!scan_params) {
                wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
                return;
            }

            /* Fill scan parameter */
            status = wlan_update_scan_params(vap,scan_params,IEEE80211_M_STA,true,false,true,true,0,NULL,1);
            if (status) {
                wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
                qdf_mem_free(scan_params);
                scan_err("scan param init failed with status: %d", status);
                return;
            }

            scan_params->scan_req.dwell_time_active = 120;
            scan_params->scan_req.idle_time = 610;
            scan_params->scan_req.repeat_probe_time = 0;
            scan_params->scan_req.max_scan_time = OSIF_PERIODICSCAN_MIN_PERIOD;
            scan_params->scan_req.scan_f_2ghz = true;
            scan_params->scan_req.scan_f_5ghz = true;
            scan_params->scan_req.scan_f_passive = false;
            scan_params->scan_req.scan_f_bcast_probe = true;

            if (osifp->os_scan_band != OSIF_SCAN_BAND_ALL) {
                scan_params->scan_req.scan_f_2ghz = false;
                scan_params->scan_req.scan_f_5ghz = false;
                if (osifp->os_scan_band == OSIF_SCAN_BAND_2G_ONLY)
                    scan_params->scan_req.scan_f_2ghz = true;
                else if (osifp->os_scan_band == OSIF_SCAN_BAND_5G_ONLY)
                    scan_params->scan_req.scan_f_5ghz = true;
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                            "%s: unknow scan band, scan all bands.\n", __func__);
                    scan_params->scan_req.scan_f_2ghz = true;
                    scan_params->scan_req.scan_f_5ghz = true;
                }
            }
#define CHAN_EXTENT_40MHz (6 * 5)
#define MAX_2_4_CHAN 15
            /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules
             */
            if(vap->iv_bsschan &&
                    (IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan) ||
                     IEEE80211_IS_CHAN_11AX_HE40(vap->iv_bsschan))) {
                int max_chan_freq, min_chan_freq, nchans;
                qdf_freq_t supp_chans[MAX_2_4_CHAN];

                /* Get the list of supported channel */
                nchans = wlan_get_channel_list(vap->iv_ic, BIT(REG_BAND_2G),
                                               supp_chans, MAX_2_4_CHAN);
                /* This is list is sorted already,
                 * Get Max and min supported chan */
                min_chan_freq = supp_chans[0];
                max_chan_freq = supp_chans[nchans > 0 ? (nchans-1) : 0];

                /* Get to the end of 40MHz chan span in case of HT40+ and
                 * then derive centre and start of extension channel for scan
                 * for e.g.,
                 * channel 1 uses 1 - 7 block.
                 * channel 1 + 6 = 7. 7 - 2 = 5 (centre) 7 - 4 = 3
                 * similarly in HT40-, it goes back to the start of the block and
                 * then derive centre and end of extn channel.
                 */
                if (IEEE80211_IS_FLAG_40PLUS(vap->iv_bsschan->ic_flags)) {
                    /* MIN of maximum channel num supported in the reg domain and end of block.
                     * to sure we are not scanning on channles not supported in reg domain */
                    chan[0] = MIN((vap->iv_bsschan->ic_freq + CHAN_EXTENT_40MHz),max_chan_freq);
                    chan[1] = chan[0] - 10;
                    chan[2] = chan[0] - 20;
                } else if (IEEE80211_IS_FLAG_40MINUS(vap->iv_bsschan->ic_flags)) {
                    /* MAX of minmum channel num supported in the reg domain and start of block.
                     * to be sure we are not passing negative channel num for scan */
                    chan[0] = MAX((vap->iv_bsschan->ic_freq - CHAN_EXTENT_40MHz),min_chan_freq);
                    chan[1] = chan[0] + 10;
                    chan[2] = chan[0] + 20;
                }
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                                  "%s: Curr chan freq = %d scan Chan freq= %d %d %d\n", __func__,
                                  vap->iv_bsschan->ic_freq, chan[0], chan[1], chan[2]);

                status = ucfg_scan_init_chanlist_params(scan_params, 3, chan, NULL);
                if (status) {
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
                    qdf_mem_free(scan_params);
                    scan_err("init chan list failed with status: %d", status);
                    return;
                }
            }

            status = wlan_ucfg_scan_start(vap, scan_params, osifp->scan_requestor,
                    SCAN_PRIORITY_LOW, &(osifp->scan_id), 0, NULL);
            if (status) {
                scan_err("scan_start failed with status: %d", status);
            }
        }

        /* restart the timer */
        osif_periodic_scan_start((os_if_t)osifp);
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
    return;
}
#endif

#if ATH_SUPPORT_WAPI
static void
osif_wapi_rekeytimer_start (os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
//  IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "%s: WAPI Rekeying Timer Start. \n", __func__);
    OS_SET_TIMER(&osdev->os_wapi_rekey_timer, osdev->os_wapi_rekey_period);

}

static void
osif_wapi_rekeytimer_stop (os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
//  IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "%s: WAPI Rekeying Timer Stop. \n", __func__);
    OS_CANCEL_TIMER(&osdev->os_wapi_rekey_timer);

}
static OS_TIMER_FUNC(osif_wapi_rekey_timeout )
{
    osif_dev *osifp;
    wlan_if_t vap;
    struct net_device *dev;

    OS_GET_TIMER_ARG(osifp, osif_dev *);
    vap = osifp->os_if;
    dev = OSIF_TO_NETDEV(osifp);

    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if ((wlan_vdev_mlme_is_active(vap->vdev_obj) == QDF_STATUS_SUCCESS) &&
		ieee80211_vap_wapi_is_set(vap))
    {
        if(vap->iv_wapi_urekey_pkts)
        {
            wlan_iterate_station_list(vap,
				(ieee80211_sta_iter_func)wlan_wapi_unicast_rekey, (void*)vap);
        }
        if(vap->iv_wapi_mrekey_pkts)
        {
            wlan_wapi_multicast_rekey(vap,vap->iv_bss);
         }
    }

    osif_wapi_rekeytimer_start((os_if_t)osifp);
    return;
}

#endif  /* ATH_SUPPORT_WAPI */

#if UMAC_SUPPORT_PROXY_ARP
int
do_proxy_arp(wlan_if_t vap, qdf_nbuf_t netbuf)
{
#if UMAC_SUPPORT_DGAF_DISABLE
    struct ether_header *eh = (struct ether_header *)netbuf->data;
#endif

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        if (qdf_unlikely(ieee80211_vap_proxyarp_is_set(vap))) {
            /* IEEE 802.11v Proxy ARP */
            if (wlan_proxy_arp(vap, netbuf))
                goto drop;
        }
#if UMAC_SUPPORT_DGAF_DISABLE
        if (qdf_unlikely(ieee80211_vap_dgaf_disable_is_set(vap))) {
            /* IEEE 802.11u DGAF Disable */
            if (IEEE80211_IS_MULTICAST(eh->ether_dhost)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_PROXYARP, "HS20 DGAF: "
                    "discard multicast packet from %s\n",
                    ether_sprintf(eh->ether_shost));
                goto drop;
            }
        }
#endif /* UMAC_SUPPORT_DGAF_DISABLE */
    }
    return 0;

drop:
    return 1;
}
#endif /* UMAC_SUPPORT_PROXY_ARP */

#if UMAC_VOW_DEBUG
void update_vow_dbg_counters(osif_dev  *osifp, qdf_nbuf_t msdu, unsigned long *vow_counter, int rx, int peer)
{
    u_int8_t *data, *l3_hdr, *bp;
    u_int16_t ethertype;
    u_int32_t len;
    int offset;
#define ETHERNET_ADDR_LEN 6 /* bytes */
    struct vow_dbg_ethernet_hdr_t {
        u_int8_t dest_addr[ETHERNET_ADDR_LEN];
        u_int8_t src_addr[ETHERNET_ADDR_LEN];
        u_int8_t ethertype[2];
    };

#ifndef ETHERNET_HDR_LEN
#define ETHERNET_HDR_LEN (sizeof(struct vow_dbg_ethernet_hdr_t))
#endif

#ifndef ETHERTYPE_IPV4
#define ETHERTYPE_IPV4  0x0800 /* Internet Protocol, Version 4 (IPv4) */
#endif
#define IPV4_ADDR_LEN 4 /* bytes */
    struct vow_dbg_ipv4_hdr_t {
        u_int8_t ver_hdrlen;       /* version and hdr length */
        u_int8_t tos;              /* type of service */
        u_int8_t len[2];           /* total length */
        u_int8_t id[2];
        u_int8_t flags_fragoff[2]; /* flags and fragment offset field */
        u_int8_t ttl;              /* time to live */
        u_int8_t protocol;
        u_int8_t hdr_checksum[2];
        u_int8_t src_addr[IPV4_ADDR_LEN];
        u_int8_t dst_addr[IPV4_ADDR_LEN];
    };

#define IP_PROTOCOL_UDP         0x11 /* User Datagram Protocol */
#define IPV4_HDR_OFFSET_PROTOCOL (offsetof(struct vow_dbg_ipv4_hdr_t, protocol))
#define IPV4_HDR_OFFSET_TOS (offsetof(struct vow_dbg_ipv4_hdr_t, tos))
#define EXT_HDR_OFFSET 54     /* Extension header offset in network buffer */
#define UDP_PDU_RTP_EXT  0x90   /* ((2 << 6) | (1 << 4)) RTP Version 2 + X bit */
#define IP_VER4_N_NO_EXTRA_HEADERS 0x45
#define RTP_HDR_OFFSET  42
    data = qdf_nbuf_data(msdu);

    len = qdf_nbuf_len(msdu);
    if ( len < (EXT_HDR_OFFSET + 5) )
        return;

    offset = ETHERNET_ADDR_LEN * 2;
    l3_hdr = data + ETHERNET_HDR_LEN - rx;
    ethertype = (data[offset] << 8) | data[offset+1];
    if (rx || ethertype == ETHERTYPE_IPV4) {
        if(osifp->vow_dbg_en == 2) {
            int tid;
#if ATH_SUPPORT_DSCP_OVERRIDE
            int tos = l3_hdr[IPV4_HDR_OFFSET_TOS];
            wlan_if_t vap = osifp->os_if;

            tid = vap->iv_ic->ic_dscp_tid_map[vap->iv_dscp_map_id][tos>>IP_DSCP_SHIFT] & 0x7;
#endif
            if ((tid == 4) || (tid == 5)) {
                *vow_counter = *vow_counter + 1;
            }
        } else {
            offset = IPV4_HDR_OFFSET_PROTOCOL;
            if ((l3_hdr[offset] == IP_PROTOCOL_UDP) && (l3_hdr[0] == IP_VER4_N_NO_EXTRA_HEADERS)) {
                bp = data+EXT_HDR_OFFSET - rx ;

                if ( (data[RTP_HDR_OFFSET - rx] == UDP_PDU_RTP_EXT) &&
                        (bp[0] == 0x12) &&
                        (bp[1] == 0x34) &&
                        (bp[2] == 0x00) &&
                        (bp[3] == 0x08)) {

                    *vow_counter = *vow_counter + 1;
                    if( !rx && (peer >=0 && peer < MAX_VOW_CLIENTS_DBG_MONITOR) )
                    {
                        unsigned long pkt_count;
                        pkt_count = ntohl(*((unsigned long*)(bp + 4)));
                        if( pkt_count & 0x80000000 )
                            pkt_count &= 0x7FFFFFFF;
                        if( osifp->tx_prev_pkt_count[peer] )
                        {
                            if ( pkt_count > (osifp->tx_prev_pkt_count[peer] + 1) )
                                ; //qdf_print("***TX-Gap identified for peer %d(%s) prev=%u curr=%u Gap = %d", peer, (peer < 3 ? "valid":"Unknown"),
                            //      tx_prev_pkt_count[peer], pkt_count, pkt_count - tx_prev_pkt_count[peer]);
                        }
                        osifp->tx_prev_pkt_count[peer] = pkt_count;
                    }
                }
            }
        }
    }
}
qdf_export_symbol(update_vow_dbg_counters);
#endif

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
static inline int wrap_rx_bridge(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb)
{
    /* Assuming native wifi or raw mode is not
     * enabled in beeliner, to be revisted later
     */
    struct ether_header *eh = (struct ether_header *) skb->data;
    wlan_if_t mpsta_vap, wrap_vap, vap = *rxvap, tvap;
    osif_dev *tx_osdev;
    int isolation = vap->iv_ic->ic_wrap_com->wc_isolation;
    int ret=0;
    mpsta_vap = vap->iv_ic->ic_mpsta_vap;
    wrap_vap = vap->iv_ic->ic_wrap_vap;

    if (isolation == 0) {

        /* Isolatio mode,Wired and wireless clients connected
         * to Qwrap Ap can talk through Qwrap bridge
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: Iso(%d)\n", __func__, isolation);
        if( ( vap->iv_mpsta==0 ) && ( vap->iv_psta ) && ( NULL != mpsta_vap ) ) {
             if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
                /*get mpsta vap , for qwrap bridge learning
                 * is always through main proxy sta
                 */
                 skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                 *dev = skb->dev;
                 *osif = mpsta_vap->iv_ifp;
             }
            ret=0;
        }
    } else {
        /* isolation mode enabled. Wired and wireless client
         * connected to Qwrap AP can talk through root AP
         */
        if(vap->iv_psta && !vap->iv_mpsta && vap->iv_wired_pvap) {
            /* Packets recevied through wired psta vap */

            if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE))) && (mpsta_vap != NULL)) {
                /* rx packets from wired psta should go through
                 * bridge . here qwrap bridge learning for wired proxy
                 * clients is always through main proxy sta
                 */
                skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                *dev = skb->dev;
                *osif = mpsta_vap->iv_ifp;
                ret=0;
        }
        } else if(vap->iv_psta && !vap->iv_mpsta && !vap->iv_wired_pvap && !(eh->ether_type == htons(ETHERTYPE_PAE)) &&
                  (wrap_vap != NULL)) {
            /* rx unicast from wireless proxy, client
             * should always xmit through wrap AP vap
             */
            wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
            ret=1;
        } else if ((vap->iv_wrap && !(eh->ether_type == htons(ETHERTYPE_PAE))) && (mpsta_vap != NULL)) {
            /* rx from wrap AP , since wrap not connected to
             * in isolation , should always xmit through
             * main proxy vap
             */
            mpsta_vap->iv_evtable->wlan_vap_xmit_queue(mpsta_vap->iv_ifp, skb);
            ret=1;
        } else if (vap->iv_mpsta && IEEE80211_IS_MULTICAST(eh->ether_dhost) && (mpsta_vap != NULL) && (wrap_vap != NULL)) {

            if((OS_MEMCMP(mpsta_vap->iv_myaddr,eh->ether_shost,6)==0))  {
                /* Multicast orginated from mpsta/bridge
             	* should always xmit through wrap AP vap
             	*/
            	wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
            	ret=1;
            } else {
                tx_osdev = osif_wrap_wdev_vma_find(&vap->iv_ic->ic_wrap_com->wc_devt,eh->ether_shost);
            	if (tx_osdev) {
                    tvap = tx_osdev->os_if;
                    if(tvap->iv_wired_pvap) {
                        /*Multicast received from wired clients , forward to wrap AP side */
                        wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
                        ret=1;
                    } else {
                        /*Multicast received from wireless clients , forward to bridge side */
                        skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                        *dev = skb->dev;
                        *osif = mpsta_vap->iv_ifp;
                        ret=0;
                    }
                } else  {
                    qdf_nbuf_t copy;
                    copy = qdf_nbuf_copy(skb);
                    /*Multicast received from clients behind root side forward to both wrap and bridge side */
                    if (copy) {
                        wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, copy);
                    } else {
                       qdf_print("Wrap nbuf copy failed ");
                    }
                    skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                    *dev = skb->dev;
                    *osif = mpsta_vap->iv_ifp;
                    ret=0;
                }
            }
        }
    }
    return ret;
}

int ol_wrap_rx_process (os_if_t *osif ,struct net_device **dev ,wlan_if_t vap, struct sk_buff *skb)
{
    if (qdf_unlikely(wlan_is_psta(vap)) || wlan_is_wrap(vap)) {
        vap->iv_wrap_mat_rx(vap, (wbuf_t)skb);
    }

    return wrap_rx_bridge(osif, dev, &vap, skb);
}
qdf_export_symbol(ol_wrap_rx_process);
#endif
#endif

#if DBDC_REPEATER_SUPPORT
static int
mcast_echo_check(struct ieee80211com *ic, u_int8_t *macaddr)
{
    struct ieee80211_node *ni = NULL;
    wlan_if_t other_ic_sta_vap = NULL;
#if ATH_SUPPORT_WRAP
    wlan_if_t tmpvap;
#endif
    int i;

    for (i = 0; i < MAX_RADIO_CNT-1; i++) {
        spin_lock(&ic->ic_lock);
	if (ic->other_ic[i] == NULL) {
	    spin_unlock(&ic->ic_lock);
	    continue;
	}
	other_ic_sta_vap = ic->other_ic[i]->ic_sta_vap;

	if (other_ic_sta_vap == NULL) {
	    spin_unlock(&ic->ic_lock);
	    continue;
	}

        spin_unlock(&ic->ic_lock);
	if(IEEE80211_ADDR_EQ(macaddr, other_ic_sta_vap->iv_myaddr)) {
	    return 1;
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
	} else if (wlan_is_mpsta(other_ic_sta_vap)) {
#else
	} else if (dp_wrap_vdev_is_mpsta(other_ic_sta_vap->vdev_obj)) {
#endif
	    TAILQ_FOREACH(tmpvap, &other_ic_sta_vap->iv_ic->ic_vaps, iv_next) {
#if WLAN_QWRAP_LEGACY
		if (wlan_is_psta(tmpvap)) {
#else
		if (dp_wrap_vdev_is_psta(tmpvap->vdev_obj)) {
#endif
		    if(IEEE80211_ADDR_EQ(macaddr, tmpvap->iv_myaddr)) {
			return 1;
		    }
		}
	    }
#endif
	} else {
	    ni = ieee80211_find_node(other_ic_sta_vap->iv_ic, macaddr, WLAN_MLME_SB_ID);
	    if (ni) {
                if (ni != other_ic_sta_vap->iv_bss) {
		    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
		    return 1;
                }
		ieee80211_free_node(ni, WLAN_MLME_SB_ID);
	    }
        }
    }
    return 0;
}

static int
dbdc_rx_bridge(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb)
{
    struct ether_header *eh;
    struct ieee80211vap *vap = *rxvap;
    struct ieee80211com *ic  = vap->iv_ic;
    bool is_mcast = 0;
    bool mcast_echo = 0;
    wlan_if_t max_priority_stavap_up = ic_list.max_priority_stavap_up;

    eh = (struct ether_header *) skb->data;
    if (!ic_list.is_dbdc_rootAP) {
       /*Loop is not yet detected*/
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if (is_mcast) {
           /*check for multicast echo packets*/
           mcast_echo = mcast_echo_check(ic, eh->ether_shost);
           if (mcast_echo) {
               GLOBAL_IC_LOCK_BH(&ic_list);
               ic_list.is_dbdc_rootAP = 1;
               GLOBAL_IC_UNLOCK_BH(&ic_list);
               qdf_print("Loop detected, Repeater connection is with DBDC RootAP");
               wbuf_free(skb);
               return 1;
           }
       }
       /* unicast/multicst data pkt received on secondary vap should be dropped when always_primary is set
	* This is to support always_primary in two separate ROOTAP configuration
	*/
       if (ic_list.always_primary && (vap != max_priority_stavap_up)) {
	   if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
               wbuf_free(skb);
               return 1;
           }
       }
    } else {
       /*Loop is detected, connection is with dbdc RootAP*/
       if (vap != max_priority_stavap_up) {
           is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
           if (is_mcast) {
               /* dropping mcast pkt in secondary radio */
               wbuf_free(skb);
               return 1;
           }

           if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
               /*
                * if not primary radio, bridge learning is always through other radio's sta vap
                */
               if ((max_priority_stavap_up == NULL) || (((osif_dev *)((os_if_t)max_priority_stavap_up->iv_ifp))->is_delete_in_progress))
               {
                   wbuf_free(skb);
                   return 1;
               }
               skb->dev = OSIF_TO_NETDEV(max_priority_stavap_up->iv_ifp);
               *dev = skb->dev;
               *osif = max_priority_stavap_up->iv_ifp;
           } else {
               skb->dev = *dev; /* pass on EAPOL to same interface */
           }
       } else {
           is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
           if (is_mcast) {
               /*check for multicast echo packets*/
               mcast_echo = mcast_echo_check(ic, eh->ether_shost);
               if (mcast_echo) {
                   wbuf_free(skb);
                   return 1;
               }
           }
       }
    }
    return 0;
}

static int
dbdc_tx_bridge(wlan_if_t *vap , osif_dev **osdev,  struct sk_buff *skb)
{
    struct ether_header *eh = (struct ether_header *) skb->data;
    struct ieee80211vap *tx_vap = *vap;
    struct ieee80211com *ic = tx_vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    struct ieee80211_node *other_ic_ni = NULL;
    struct ieee80211com *other_ic = NULL, *fastlane_ic = NULL;
    bool is_mcast = 0;
    bool is_bcast = 0;
    struct ieee80211vap *other_ic_stavap = NULL;
    struct ieee80211vap *fastlane_ic_stavap = NULL;
    wlan_if_t max_priority_stavap_up = ic_list.max_priority_stavap_up;
    uint8_t i;

    if (ic_list.is_dbdc_rootAP || ic_list.force_client_mcast_traffic || ic_list.always_primary) {
        if (ic_list.force_client_mcast_traffic && !ic_list.is_dbdc_rootAP) {
            is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
            if(!is_mcast) {
                 return 0;
            }
        }
	/* Scenarios
	   1. unicast : Alwaysprimary set - in general all unicast packets
	   2. unicast : after loop is detected - in general all unicast packets
	   3. Mcast packets
	 */
	if (tx_vap == max_priority_stavap_up) {
            if (ic_list.always_primary) {
               return 0;
            }
	    for (i=0;i<MAX_RADIO_CNT-1;i++) {
		spin_lock(&ic->ic_lock);
		other_ic = ic->other_ic[i];
		spin_unlock(&ic->ic_lock);


		/* TODO - For readability move the check based on fast lane to a common place for MCAST and ucast packets*/
		if (other_ic) {
		    other_ic_ni = ieee80211_find_node(other_ic,eh->ether_shost, WLAN_DBDC_ID);
		} else {
                    continue;
                }
		if (other_ic_ni) {
                    /* The sender is a client of a non-primary radio */
		    ieee80211_free_node(other_ic_ni, WLAN_DBDC_ID);
		    is_bcast = IEEE80211_IS_BROADCAST(eh->ether_dhost);
		    if (is_bcast && !(ic->fast_lane && other_ic->fast_lane)) {
			wbuf_free(skb);
			return 1;
		    }
		    spin_lock(&other_ic->ic_lock);
                    other_ic_stavap = other_ic->ic_sta_vap;
		    spin_unlock(&other_ic->ic_lock);

		    if (other_ic_stavap && wlan_is_connected(other_ic_stavap)) {
			if (((osif_dev *)((os_if_t)other_ic_stavap->iv_ifp))->is_delete_in_progress)
			{
			    wbuf_free(skb);
			    return 1;
			}
			other_ic_stavap->iv_evtable->wlan_vap_xmit_queue(other_ic_stavap->iv_ifp, skb);
			return 1;
		    }
		    if (other_ic->fast_lane && !ic->fast_lane) {
			/* If pkt is from fast lane radio, send it
                           on corresponding fast lane radio which is connected */
			fastlane_ic = other_ic->fast_lane_ic;

			if (!fastlane_ic)
				return 0;

			spin_lock(&fastlane_ic->ic_lock);
			fastlane_ic_stavap = fastlane_ic->ic_sta_vap;
			spin_unlock(&fastlane_ic->ic_lock);
			if (fastlane_ic_stavap && wlan_is_connected(fastlane_ic_stavap)) {
			    if (((osif_dev *)((os_if_t)fastlane_ic_stavap->iv_ifp))->is_delete_in_progress)
			    {
				wbuf_free(skb);
				return 1;
			    }
			    fastlane_ic_stavap->iv_evtable->wlan_vap_xmit_queue(fastlane_ic_stavap->iv_ifp, skb);
			    return 1;
			}

		    }
                    return 0;
		}
	    }
        } else {
            /* Scenarios
               1. unicast : Alwaysprimary set , only when primary sta vap just conneted
               2. unicast : after loop is detected, primary sta vap call this same vap_hard_start function for secondary radio clients
               3. Mcast packet
            */
            is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
	    if (ic_list.always_primary) {
		/* Send unicast pkt thru primary - do not drop
		 */
		if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
		    if (is_mcast) {
			wbuf_free(skb);
			return 1;
		    } else {
                        if (max_priority_stavap_up) {
                            if (((osif_dev *)((os_if_t)max_priority_stavap_up->iv_ifp))->is_delete_in_progress)
                            {
                               wbuf_free(skb);
                               return 1;
                            }
                            max_priority_stavap_up->iv_evtable->wlan_vap_xmit_queue(max_priority_stavap_up->iv_ifp, skb);
			    return 1;
			}
		    }
		}
	    }

            /* Check if this is from a client connected to my AP VAP
             * Or from a client connected to my fast lane AP
             */
	    if (is_mcast) {
		ni = ieee80211_find_node(ic,eh->ether_shost, WLAN_DBDC_ID);
		if (ni == NULL) {
		    if (ic->fast_lane && ic->fast_lane_ic) {
			fastlane_ic = ic->fast_lane_ic;
			ni = ieee80211_find_node(fastlane_ic,eh->ether_shost, WLAN_DBDC_ID);
			if (ni == NULL) {
			    wbuf_free(skb);
			    return 1;
			}
		    } else {
			wbuf_free(skb);
			return 1;
		    }
		}
                /*Drop the mcast frame if packet source mac address is same as that of Root AP mac address*/
                if (ni == tx_vap->iv_bss) {
                    ieee80211_free_node(ni, WLAN_DBDC_ID);
                    wbuf_free(skb);
                    return 1;
                }
                ieee80211_free_node(ni, WLAN_DBDC_ID);
            }
        }
    }
    return 0;
}

static int
drop_mcast_tx(wlan_if_t *vap , osif_dev **osdev,  struct sk_buff *skb)
{
    struct ether_header *eh = (struct ether_header *) skb->data;
    wlan_if_t tx_vap = *vap;
    struct ieee80211com *ic = tx_vap->iv_ic;
    bool is_mcast = 0;

    if ((tx_vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1) && !ic->ic_primary_radio && ic_list.drop_secondary_mcast) {
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if(is_mcast) {
           wbuf_free(skb);
           return 1;
       }
    }
    return 0;
}

static int
drop_mcast_rx(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb)
{
    struct ether_header *eh;
    wlan_if_t vap = *rxvap;
    struct ieee80211com *ic  = vap->iv_ic;
    bool is_mcast = 0;

    if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1) && !ic->ic_primary_radio && ic_list.drop_secondary_mcast) {
       eh = (struct ether_header *) skb->data;
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if (is_mcast) {
           wbuf_free(skb);
           return 1;
       }
    }
    return 0;
}

int dbdc_rx_process (os_if_t *osif ,struct net_device **dev , struct sk_buff *skb)
{
    osif_dev  *osdev = (osif_dev *)(*osif);
    wlan_if_t vap = osdev->os_if;
    if(ic_list.dbdc_process_enable) {
	if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1)) {
	    return dbdc_rx_bridge(osif, dev, &vap, skb);
	}
    } else {
        if(ic_list.delay_stavap_connection) {
            return drop_mcast_rx(osif, dev, &vap, skb);
        }
    }
    return 0;
}
qdf_export_symbol(dbdc_rx_process);

int dbdc_tx_process (wlan_if_t vap, osif_dev **osdev , struct sk_buff *skb)
{
    if(ic_list.dbdc_process_enable) {
	if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1)) {
	    return dbdc_tx_bridge(&vap, osdev, skb);
	}
    } else {
        if(ic_list.delay_stavap_connection) {
           return drop_mcast_tx(&vap, osdev, skb);
        }
    }
    return 0;
}
qdf_export_symbol(dbdc_tx_process);

#endif

#if ATH_SUPPORT_WRAP
/*
 * osif_ol_wrap_rx_process()
 *  wrap rx process
 */
int
osif_ol_wrap_rx_process(osif_dev **osifp, struct net_device **dev, wlan_if_t vap, struct sk_buff *skb)
{
#if !WLAN_QWRAP_LEGACY
    int rv = 0;
#endif
    if (vap == NULL) {
        qdf_nbuf_free(skb);
        return 1;
    }
#if WLAN_QWRAP_LEGACY
    return OL_WRAP_RX_PROCESS((os_if_t *)osifp, dev, vap, skb);
#else
    rv = dp_wrap_rx_process(dev,vap->vdev_obj, skb);
    if (qdf_likely(rv == 0)) {
        *osifp = ath_netdev_priv(*dev);
        return rv;
    } else if (rv < 0) {
        qdf_nbuf_free(skb);
        return 1;
    } else {
        return rv;
    }
#endif
}
qdf_export_symbol(osif_ol_wrap_rx_process);
#endif

#ifdef ATH_DIRECT_ATTACH
/* accept a single sk_buff at a time */
void
osif_deliver_data(os_if_t osif, struct sk_buff *skb)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
#if ATH_SUPPORT_WRAP
    osif_dev  *osdev = (osif_dev *)osif;
    wlan_if_t vap = osdev->os_if;
#if !WLAN_QWRAP_LEGACY
    int rv = 0;
#endif
#endif
    osif_dev  *osifp = (osif_dev *) osif;
#if ATH_RXBUF_RECYCLE
    struct net_device *comdev;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
#endif /* ATH_RXBUF_RECYCLE */
    skb->dev = dev;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)) && MIPS_TP_ENHC
    prefetch(skb->data);
    prefetch(&skb->protocol);
    prefetch(&skb->__pkt_type_offset);
#endif
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (OL_WRAP_RX_PROCESS(&osif, &dev, vap, skb))
        goto done;
#else
    rv = dp_wrap_rx_process(&dev,vap->vdev_obj, skb);
    if (qdf_likely(rv == 0)) {
        osif = (os_if_t )ath_netdev_priv(dev);
    } else if (rv < 0) {
        qdf_nbuf_free(skb);
        goto done;
    } else {
        goto done;
    }
#endif
#endif
#if DBDC_REPEATER_SUPPORT
    if (dbdc_rx_process(&osif, &dev, skb))
        goto done;
#endif

#ifdef QCA_PARTNER_PLATFORM
    if ( osif_pltfrm_deliver_data(osif, skb ) )
        goto done;
#endif

#if !QCA_NSS_PLATFORM
    skb->protocol = eth_type_trans(skb, dev);
#endif
#if ATH_RXBUF_RECYCLE
    comdev = ((osif_dev *)osif)->os_comdev;
    scn = ath_netdev_priv(comdev);
    sc = ATH_DEV_TO_SC(scn->sc_dev);
	/*
	 * Do not recycle the received mcast frame becasue it will be cloned twice
	 */
    if (sc->sc_osdev->rbr_ops.osdev_wbuf_collect && !(wbuf_is_cloned(skb))) {
        sc->sc_osdev->rbr_ops.osdev_wbuf_collect((void *)sc, (void *)skb);
    }
#endif /* ATH_RXBUF_RECYCLE */

#if ATH_SUPPORT_VLAN
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
    if ( osifp->vlanID != 0)
    {
        /* attach vlan tag */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        __vlan_hwaccel_put_tag(skb, osifp->vlanID);
#else
        __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), osifp->vlanID);
#endif
    }
#else
    if ( osifp->vlanID != 0 && osifp->vlgrp != NULL)
    {
        /* attach vlan tag */
        vlan_hwaccel_rx(skb, osifp->vlgrp, osifp->vlanID);
    }
    else
#endif
#endif

   skb_orphan(skb);
#if !QCA_NSS_PLATFORM
    nbuf_debug_del_record(skb);
    netif_rx(skb);
#else /*QCA_NSS_PLATFORM*/
    osifp = (osif_dev *)osif;
    osif_send_to_nss(osif, skb, osifp->nss_redir_ctx, OSIF_TO_NETDEV(osif));
#endif /*QCA_NSS_PLATFORM*/
#if (ATH_SUPPORT_WRAP || DBDC_REPEATER_SUPPORT)
done:
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) && !defined BUILD_X86
    dev->last_rx = jiffies;
#else
    return;
#endif
}
qdf_export_symbol(osif_deliver_data);
#endif /* ATH_DIRECT_ATTACH */

#define LEN_FIELD_SIZE     2

void transcap_dot3_to_eth2(struct sk_buff *skb)
{
    struct vlan_ethhdr *veh, veth_hdr;
    veh = (struct vlan_ethhdr *)skb->data;

    if (ntohs(veh->h_vlan_encapsulated_proto) >= IEEE8023_MAX_LEN)
        return;

    qdf_mem_copy(&veth_hdr, veh, sizeof(veth_hdr));
    qdf_nbuf_pull_head(skb, LEN_FIELD_SIZE);

    veh = (struct vlan_ethhdr *)skb->data;

    qdf_mem_copy(veh, &veth_hdr, (sizeof(veth_hdr) - LEN_FIELD_SIZE));
}

#if QCA_OL_VLAN_WAR
void
_ol_rx_vlan_war(struct sk_buff *skb, struct ol_ath_softc_net80211 *scn) {
    uint32_t target_type = scn->sc_ic.ic_get_tgt_type(&scn->sc_ic);
    struct ether_header *eh;

    /*
     * For chipstes (AR900B, QCA9984, QCA9888, IPQ4019 and QCA8074), enable VLAN
     * WAR only for 802.3 + VLAN packet. This WAR is not required QCA8074V2
     * onwards because of hardware support.
     */
    if ((target_type == TARGET_TYPE_QCA8074V2) ||
       (target_type == TARGET_TYPE_QCN9000) ||
       (target_type == TARGET_TYPE_QCN6122) ||
       (target_type == TARGET_TYPE_QCA5018) ||
       (target_type == TARGET_TYPE_QCA6018))
        return;

    eh = (struct ether_header *)(skb->data);
    if (htons(eh->ether_type) != ETH_P_8021Q)
        return;

    /*
     * For VLAN, remove the extra two bytes of length field inserted by OLE.
     * This is standard behavior for OLE RX any format that looks weird
     * it keeps it in 802.3 format as that preserves all the information.
     * Frame Format : {dst_addr[6], src_addr[6], 802.1Q header[4], EtherType[2], Payload}
     * Example :
     * Before Removal : xx xx xx xx xx xx xx xx xx xx xx xx 81 00 00 02 00 4e 08 00 45 00 00...
     * After Removal  : xx xx xx xx xx xx xx xx xx xx xx xx 81 00 00 02 08 00 45 00 00...
     */

     transcap_dot3_to_eth2(skb);
}
qdf_export_symbol(_ol_rx_vlan_war);

static int encap_eth2_to_dot3(qdf_nbuf_t msdu);

inline  int
_ol_tx_vlan_war(struct sk_buff **skb, struct ol_ath_softc_net80211 *scn){
    struct ether_header *eh = (struct ether_header *)((*skb)->data);
    struct ethervlan_header *evh = (struct ethervlan_header *) eh;
    if ((htons(eh->ether_type) == ETH_P_8021Q)) {
	if (scn->sc_ic.ic_get_tgt_type(&scn->sc_ic) == TARGET_TYPE_AR9888) {
	    /* For Peregrine, enable VLAN WAR irrespective of eth2 + VLAN packet or 802.3 + VLAN packet*/
	    *skb = qdf_nbuf_unshare(*skb);
	    if (*skb == NULL) {
		return 1;
	    }
	    if (encap_eth2_to_dot3(*skb)){
		return 1;
	    }
	} else {
	    /* For other OL chipstes (Beeliner, Cascade, Besra, Dakota and hawkeye v1), enable VLAN WAR only for 802.3 + VLAN packet*/
	    /* This WAR is not needed in future chipsets (hawkeye v2), if this HW issue got fixed*/
	    if (htons(evh->ether_type) < IEEE8023_MAX_LEN) {
		*skb = qdf_nbuf_unshare(*skb);
		if (*skb == NULL) {
		    return 1;
		}
		if (encap_eth2_to_dot3(*skb)){
		    return 1;
		}
	    }
	}
    }
    return 0;
}
qdf_export_symbol(_ol_tx_vlan_war);
#endif /* QCA_OL_VLAN_WAR */

#ifdef QCA_OL_DMS_WAR
inline bool
ol_check_valid_dms(struct sk_buff **skb, wlan_if_t vap, uint8_t *peer_addr)
{
    struct ether_header *eh = (struct ether_header *)((*skb)->data);
    struct dms_meta_hdr *dms_mhdr;
    struct sk_buff *skb_orig = NULL;

    if (IEEE80211_IS_MULTICAST(eh->ether_dhost) &&
        !IEEE80211_IS_BROADCAST(eh->ether_dhost)) {
        skb_orig = qdf_nbuf_unshare(*skb);
        if (skb_orig == NULL) {
            return false;
        }
        *skb = skb_orig;
        dms_mhdr = (struct dms_meta_hdr *)((*skb)->head);
        /* In case of invalid DMS ID, treat it as a normal mcast packet */
        if (dms_mhdr->dms_id == 0) {
            return false;
        }
        IEEE80211_ADDR_COPY(peer_addr, dms_mhdr->unicast_addr);
        return true;
    }
    return false;
}
qdf_export_symbol(ol_check_valid_dms);

#endif /* QCA_OL_DMS_WAR */

#if ATH_PERF_PWR_OFFLOAD

#if QCA_NSS_PLATFORM
#if UMAC_VOW_DEBUG || UMAC_SUPPORT_VI_DBG
extern int transcap_nwifi_hdrsize(qdf_nbuf_t msdu);
#endif

#endif /*QCA_NSS_PLATFORM*/

#if ATH_SUPPORT_WAPI
bool
osif_wai_check(os_if_t osif, struct sk_buff *skb_list_head, struct sk_buff *skb_list_tail)
{
#define TYPEORLEN(_skb) (*(u_int16_t *)((_skb)->data + QDF_MAC_ADDR_SIZE * 2))
#define WAI_TYPE_CHECK(_skb)  do { if(TYPEORLEN(_skb) == ETHERTYPE_WAI) return true; } while(0)

    struct sk_buff *skb;

    if(!skb_list_head) {
        return false;
    }

    do {
        skb = skb_list_head;
        skb_list_head = skb_list_head->next;
        WAI_TYPE_CHECK(skb);
    } while((skb != skb_list_tail) && !skb_list_head);

    return false;
}
qdf_export_symbol(osif_wai_check);
#endif /* ATH_SUPPORT_WAPI */

#endif /* ATH_PERF_PWR_OFFLOAD */


static void
osif_deliver_l2uf(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb;
    struct l2_update_frame *l2uf;
    struct ether_header *eh;

    vap = osdev->os_if;
    /* add 2 more bytes to meet minimum packet size allowed with LLC headers */
    skb = qdf_nbuf_alloc(NULL, sizeof(*l2uf) + 2, 0, 0, 0);
    if (!skb)
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT, "%s\n",
                            "ieee80211_deliver_l2uf: no buf available");
        return;
    }
    skb_put(skb, sizeof(*l2uf) + 2);
    l2uf = (struct l2_update_frame *)(skb->data);
    eh = &l2uf->eh;
    /* dst: Broadcast address */
    IEEE80211_ADDR_COPY(eh->ether_dhost, dev->broadcast);
    /* src: associated STA */
    IEEE80211_ADDR_COPY(eh->ether_shost, macaddr);
    eh->ether_type = htons(skb->len - sizeof(*eh));

    l2uf->dsap = 0;
    l2uf->ssap = 0;
    l2uf->control = IEEE80211_L2UPDATE_CONTROL;
    l2uf->xid[0] = IEEE80211_L2UPDATE_XID_0;
    l2uf->xid[1] = IEEE80211_L2UPDATE_XID_1;
    l2uf->xid[2] = IEEE80211_L2UPDATE_XID_2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif

    __osif_deliver_data(osif, skb);
}

#if DBDC_REPEATER_SUPPORT || UMAC_SUPPORT_SON
void
osif_hardstart_l2uf(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb;
    struct l2_update_frame *l2uf;
    struct ether_header *eh;

    vap = osdev->os_if;
    /* add 2 more bytes to meet minimum packet size allowed with LLC headers */
    skb = qdf_nbuf_alloc(NULL, sizeof(*l2uf) + 2, 0, 0, 0);
    if (!skb)
    {
        qdf_print( "%s",
                            "ieee80211_hardstart_l2uf: no buf available");
        return;
    }
    skb_put(skb, sizeof(*l2uf) + 2);
    l2uf = (struct l2_update_frame *)(skb->data);
    eh = &l2uf->eh;
    /* dst: Broadcast address */
    IEEE80211_ADDR_COPY(eh->ether_dhost, dev->broadcast);
    /* src: associated STA */
    IEEE80211_ADDR_COPY(eh->ether_shost, macaddr);
    eh->ether_type = htons(skb->len - sizeof(*eh));

    l2uf->dsap = 0;
    l2uf->ssap = 0;
    l2uf->control = IEEE80211_L2UPDATE_CONTROL;
    l2uf->xid[0] = IEEE80211_L2UPDATE_XID_0;
    l2uf->xid[1] = IEEE80211_L2UPDATE_XID_1;
    l2uf->xid[2] = IEEE80211_L2UPDATE_XID_2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif
    if (vap->iv_evtable) {
        vap->iv_evtable->wlan_vap_xmit_queue(vap->iv_ifp, skb);
    }
}
#endif

struct ol_ath_softc_net80211 *osif_validate_and_get_scn_from_dev(struct net_device *dev)
{
    struct ieee80211com *tmp_ic;
    struct ieee80211vap *tmp_vap;
    int i;

    if (!dev)
        return NULL;

    GLOBAL_IC_LOCK_BH(&ic_list);
    for (i = 0; i < MAX_RADIO_CNT; i++) {
        tmp_ic = ic_list.global_ic[i];
        if (tmp_ic) {
            IEEE80211_COMM_LOCK_BH(tmp_ic);
            TAILQ_FOREACH(tmp_vap, &tmp_ic->ic_vaps, iv_next) {
                osif_dev *osifp = (osif_dev *)wlan_vap_get_registered_handle(tmp_vap);
                if (osifp == NULL) {
                    IEEE80211_COMM_UNLOCK_BH(tmp_ic);
                    GLOBAL_IC_UNLOCK_BH(&ic_list);
                    return NULL;
                }
                if (osifp->netdev == dev) {
                    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(tmp_ic);
                    IEEE80211_COMM_UNLOCK_BH(tmp_ic);
                    GLOBAL_IC_UNLOCK_BH(&ic_list);
                    return scn;
                }
            }
            IEEE80211_COMM_UNLOCK_BH(tmp_ic);
        }
    }
    GLOBAL_IC_UNLOCK_BH(&ic_list);
    return NULL;
}

qdf_export_symbol(osif_validate_and_get_scn_from_dev);

static void osif_get_active_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev *osifp;
    u_int16_t *active_vaps = (u_int16_t *) arg;
    struct net_device *dev;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    dev = osifp->netdev;
    if (dev->flags & IFF_UP) {
        ++(*active_vaps);
    }
}

static void osif_get_running_vap_iter_func(void *arg, wlan_if_t vap)
{
    u_int16_t *running_vaps = (u_int16_t *) arg;

    if(!vap || !vap->vdev_obj) {
        return;
    }
    if (wlan_vdev_chan_config_valid(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
        ++(*running_vaps);
    }
}

u_int32_t osif_get_num_active_vaps( wlan_dev_t  comhandle)
{
    u_int16_t num_active_vaps=0;
    wlan_iterate_vap_list(comhandle,osif_get_active_vap_iter_func,(void *)&num_active_vaps);
    return num_active_vaps;
}
#if QCA_PARTNER_PLATFORM
qdf_export_symbol(osif_get_num_active_vaps);
#endif

u_int16_t osif_get_num_running_vaps( wlan_dev_t  comhandle)
{
    u_int16_t num_running_vaps=0;
    wlan_iterate_vap_list(comhandle,osif_get_running_vap_iter_func,(void *)&num_running_vaps);
    return num_running_vaps;
}

uint32_t promisc_is_active (struct ieee80211com *ic)
{
    struct ieee80211vap *vap = NULL;
    osif_dev  *osifp = NULL;
    struct net_device *netdev = NULL;
    uint32_t promisc_active = false;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap && (vap->iv_opmode == IEEE80211_M_MONITOR)) {
            osifp = (osif_dev *)vap->iv_ifp;
            netdev = osifp->netdev;
            promisc_active = ((netdev->flags & IFF_UP) ? true : false);
            if (promisc_active) {
                break;
            }
        }
    }
    return promisc_active;
}

#if QCA_LTEU_SUPPORT
static void
osif_nl_scan_evhandler(struct wlan_objmgr_vdev *vdev, struct scan_event *event, void *arg)
{
    struct ieee80211_nl_handle *nl_handle = (struct ieee80211_nl_handle *)arg;
    osif_dev *osdev;
    struct net_device *dev;
    union iwreq_data wreq;
    struct event_data_scan scan;
    u_int8_t scan_id;
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap) {
        qdf_err("NULL vap");
        return;
    }

    if (!nl_handle) {
        qdf_print("%s: Scan completion (type=%d reason=%d id=%d) but on non NL "
               "radio", __func__, event->type, event->reason, event->scan_id);
        return;
    }

    if (event->type != SCAN_EVENT_TYPE_COMPLETED ||
        event->reason == SCAN_REASON_CANCELLED) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Skip type=%d, "
                 "reason=%d\n", __func__, event->type, event->reason);
        return;
    }

    spin_lock_bh(&nl_handle->mu_lock);
    if (atomic_read(&nl_handle->scan_in_progress) == 0) {
        spin_unlock_bh(&nl_handle->mu_lock);
        qdf_print("%s: Scan completion id=%d (%d), but scan not active",
               __func__, event->scan_id, nl_handle->scanid);
        return;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Scan completion id=%d, expected=%d, "
             "type=%d, reason=%d, userid=%d\n", __func__, event->scan_id, nl_handle->scanid,
             event->type, event->reason, nl_handle->scan_id);
    scan_id = nl_handle->scan_id;
    atomic_set(&nl_handle->scan_in_progress, 0);
    spin_unlock_bh(&nl_handle->mu_lock);

    osdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = OSIF_TO_NETDEV(osdev);

    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_SCAN;
    wreq.data.length = sizeof(struct event_data_scan);
    wreq.data.length = sizeof(struct event_data_scan);
    scan.scan_req_id = scan_id;
    scan.scan_status = event->reason == SCAN_REASON_RUN_FAILED ?
                              SCAN_FAIL : SCAN_SUCCESS;
    if (event->reason == SCAN_REASON_RUN_FAILED)
        qdf_print("%s: notify scan failed, reason=%d, scanid=%d",
                __func__, event->reason, nl_handle->scan_id);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (void *)&scan);
}
#endif

/**
 *   ieee80211_update_assoc_ie: store assoc response ie
 *   @osdev : pointer to osdev.
 *   @wbuf  : assoc response frame.
 *
 *   returns NONE.
 */
void ieee80211_update_assoc_ie(struct net_device *dev, wbuf_t wbuf)
{
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
#define ASSOC_RESPONSE_FIXED_IE_LEN 6

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1] + ASSOC_RESPONSE_FIXED_IE_LEN;
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if(efrm <= frm)
        return;

    if(vap->iv_sta_assoc_resp_ie)
        qdf_mem_free(vap->iv_sta_assoc_resp_ie);

    vap->iv_sta_assoc_resp_ie = (u_int8_t *)qdf_mem_malloc(efrm - frm);

    if(!vap->iv_sta_assoc_resp_ie)
        return;

    vap->iv_sta_assoc_resp_len = efrm-frm;
    qdf_mem_copy(vap->iv_sta_assoc_resp_ie, frm, vap->iv_sta_assoc_resp_len);

#undef ASSOC_RESPONSE_FIXED_IE_LEN
}

void osif_send_assoc_resp_ies(struct net_device *dev)
{
    union iwreq_data wreq;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap          = osdev->os_if;
    char *buf;

    buf = (char *)qdf_mem_malloc(vap->iv_sta_assoc_resp_len);
    if (!buf) {
        qdf_info("%s: failed to allocate memory of size (%d)",__func__, vap->iv_sta_assoc_resp_len);
        return;
    }

    qdf_mem_zero(buf, vap->iv_sta_assoc_resp_len);
    wreq.data.flags = 0;
    wreq.data.length = vap->iv_sta_assoc_resp_len;
    qdf_mem_copy(buf, vap->iv_sta_assoc_resp_ie, vap->iv_sta_assoc_resp_len);

    WIRELESS_SEND_EVENT(dev, IWEVASSOCRESPIE, &wreq, buf);
    qdf_mem_free(buf);
    qdf_mem_free(vap->iv_sta_assoc_resp_ie);
    vap->iv_sta_assoc_resp_ie = NULL;
    vap->iv_sta_assoc_resp_len = 0;
}

void
osif_notify_scan_done(struct net_device *dev, enum scan_completion_reason reason)
{
    union iwreq_data wreq;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *ic;
    static int count = 1;
#endif

    vap = osdev->os_if;
#if DBDC_REPEATER_SUPPORT
    ic = vap->iv_ic;
    if (ic->ic_global_list->delay_stavap_connection && !(ic->ic_radio_priority ==1) && count) {
        count--;
        return;
    }
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s\n", "notify scan done");

    /* dispatch wireless event indicating scan completed */
    wreq.data.length = 0;
    wreq.data.flags = 0;
#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle) {
        if (reason == SCAN_REASON_RUN_FAILED) {
            wreq.data.flags = SCAN_REASON_RUN_FAILED;
            qdf_print("%s: notify scan failed , reason=%d",__func__,reason);
        } else {
            wreq.data.flags = SCAN_REASON_COMPLETED;
        }
    }
#else
    reason = reason; /* in case it warns for unused variable */
#endif
    WIRELESS_SEND_EVENT(dev, SIOCGIWSCAN, &wreq, NULL);
#if UMAC_SUPPORT_CFG80211
    if (osdev->scan_req) {
        if (reason == SCAN_REASON_COMPLETED) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
            struct cfg80211_scan_info info = {
                        .aborted = false,
            };
            cfg80211_scan_done(osdev->scan_req, &info); /* aborted false*/
#else
            cfg80211_scan_done(osdev->scan_req, false); /* aborted false*/
#endif
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
            struct cfg80211_scan_info info = {
                        .aborted = true,
            };
	    cfg80211_scan_done(osdev->scan_req, &info); /* aborted true */
#else
            cfg80211_scan_done(osdev->scan_req, true); /* aborted true */
#endif
        }
        osdev->scan_req = NULL;
    }
#endif
}

#if DBDC_REPEATER_SUPPORT
static
void osif_send_preferred_bssid_event (struct ieee80211vap *vap)
{
    osif_dev *osdev;
    struct net_device *dev;
    union iwreq_data wreq;
    struct ieee80211com *ic = vap->iv_ic;

    osdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = OSIF_TO_NETDEV(osdev);
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_PREFERRED_BSSID;
    wreq.data.length = QDF_MAC_ADDR_SIZE;
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, ic->ic_preferred_bssid);
}

#define SKIP_SCAN_ENTRIES 10000
/* Process the scan entries whose ssid matches with desired ssid */

static QDF_STATUS
osif_process_scan_entries(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) arg;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t *ssid, *bssid;
    u_int8_t ssid_len;
    bool des_ssid_found = 0;
    struct ieee80211_ie_extender *extender_ie;
    bool rptr_bssid_found = 0;
    int i;

    if (!IS_NULL_ADDR(ic->ic_preferred_bssid)) {
        return QDF_STATUS_SUCCESS;
    }
    ssid_len = util_scan_entry_ssid(se)->length;
    ssid = util_scan_entry_ssid(se)->ssid;
    bssid = util_scan_entry_bssid(se);
    des_ssid_found = ieee80211_vap_match_ssid((struct ieee80211vap *) vap, ssid, ssid_len);

    if (!des_ssid_found) {
        return QDF_STATUS_SUCCESS;
    }
    extender_ie = (struct ieee80211_ie_extender *) util_scan_entry_extenderie(se);
    if ((ic_list.extender_info & ROOTAP_ACCESS_MASK) != ROOTAP_ACCESS_MASK) {
       /* When this RE has no RootAP access*/
       if (extender_ie) {
           /* When one STAVAP is connected , don't allow further connection */
           if (ic_list.num_stavaps_up ==1 ) {
               return QDF_STATUS_SUCCESS;
           }
           if (ic_list.num_rptr_clients && ((extender_ie->extender_info & STAVAP_CONNECTION_MASK) == STAVAP_CONNECTION_MASK) && ((extender_ie->extender_info & ROOTAP_ACCESS_MASK) != ROOTAP_ACCESS_MASK)) {
               return QDF_STATUS_SUCCESS;
           }
       }
    } else {
       /* When this RE has RootAP access*/
       if (ic_list.ap_preferrence == 1) {
           /*Connect only to RootAP*/
           if (extender_ie) {
               return QDF_STATUS_SUCCESS;
           }
       } else if (ic_list.ap_preferrence == 2) {
           /*Connect to RE whose bssid matches with preferred mac list*/
           for(i=0;i<MAX_RADIO_CNT;i++) {
               if(OS_MEMCMP(bssid, &ic_list.preferred_list_stavap[i][0], QDF_MAC_ADDR_SIZE) == 0) {
                    rptr_bssid_found = 1;
                    break;
               }
           }
           if(!rptr_bssid_found) {
               return QDF_STATUS_SUCCESS;
           }
       }
    }
    OS_MEMCPY(ic->ic_preferred_bssid, bssid, QDF_MAC_ADDR_SIZE);
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
osif_get_rootap_bssid(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) arg;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t *ssid,*bssid;
    u_int8_t ssid_len;
    bool des_ssid_found = 0;
    u_int8_t *extender_ie;

    if (!IS_NULL_ADDR(ic->ic_preferred_bssid)) {
        return QDF_STATUS_SUCCESS;
    }
    ssid_len = util_scan_entry_ssid(se)->length;
    ssid = util_scan_entry_ssid(se)->ssid;
    bssid = util_scan_entry_bssid(se);
    des_ssid_found = ieee80211_vap_match_ssid((struct ieee80211vap *) vap, ssid, ssid_len);

    if (des_ssid_found) {
       extender_ie = util_scan_entry_extenderie(se);
       if (!extender_ie) {
           /*When RootAP is present, give preferrence to RootAP bssid*/
           bssid = util_scan_entry_bssid(se);
           OS_MEMCPY(ic->ic_preferred_bssid, bssid, QDF_MAC_ADDR_SIZE);
       }
    }
    return QDF_STATUS_SUCCESS;
}
#endif

/*
 * Function to store Last completed Scan Parameters
 */
static void osif_store_scan_params(struct ieee80211com *ic,struct scan_event *event)
{

    struct last_scan_params *scan_params = &ic->scan_params;
    struct scan_req_params *comp_scan_req = &event->scan_start_req->scan_req;

    /* Store Last scan finished parameters to display in proc */
    scan_params->dwell_time_passive = comp_scan_req->dwell_time_passive;
    scan_params->scan_f_passive = comp_scan_req->scan_f_passive;
    scan_params->scan_f_2ghz = comp_scan_req->scan_f_2ghz;
    scan_params->scan_f_5ghz = comp_scan_req->scan_f_5ghz;
    scan_params->scan_f_wide_band = comp_scan_req->scan_f_wide_band;
    scan_params->scan_f_continue_on_err = comp_scan_req->scan_f_continue_on_err;
    scan_params->scan_f_forced = comp_scan_req->scan_f_forced;
    scan_params->scan_f_bcast_probe = comp_scan_req->scan_f_bcast_probe;
    scan_params->dwell_time_passive = comp_scan_req->dwell_time_passive;
    scan_params->dwell_time_active = comp_scan_req->dwell_time_active;
    scan_params->scan_req_id = comp_scan_req->scan_req_id;
    scan_params->scan_id = comp_scan_req->scan_id;
    scan_params->max_scan_time = comp_scan_req->max_scan_time;
    scan_params->max_rest_time = comp_scan_req->max_rest_time;
    scan_params->min_rest_time = comp_scan_req->min_rest_time;
    scan_params->idle_time = comp_scan_req->idle_time;
    scan_params->chan_list = comp_scan_req->chan_list;
}

/*
 * Bringup vaps if cac was cancelled for scan
 */
void osif_restore_vaps(struct ieee80211com *ic, wlan_if_t vap)
{
    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_STA_VAP_STOP_START);
    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_PDEV_START);
}

/*
 * scan handler used by the ioctl.
 */
static void osif_scan_evhandler(struct wlan_objmgr_vdev *vdev, struct scan_event *event, void *arg)
{
    osif_dev  *osifp = (osif_dev *) arg;
    wlan_if_t scan_originator_vap = osifp->os_if;
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);
    struct ieee80211com *ic;
#if DBDC_REPEATER_SUPPORT
    static uint32_t last_scanid = 0;
#endif
    struct wlan_objmgr_pdev *pdev = NULL;
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    uint32_t dfs_region;
#endif
#if ATH_SUPPORT_ZERO_CAC_DFS
    struct wlan_objmgr_psoc *psoc = NULL;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops = NULL;
    bool is_precac_enabled = false;
    bool is_agile_precac_enabled = false;
    bool is_precac_running = false;

    psoc = wlan_vdev_get_psoc(vdev);
    if (psoc) {
        dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    }
#endif

    pdev = wlan_vdev_get_pdev(vdev);

    if (!vap) {
        qdf_err("NULL vap");
        return;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s scan_id %08X event %d reason %d requestor %X\n",
                      __func__, event->scan_id, event->type, event->reason, event->requester);

    ic = vap->iv_ic;
#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event SCAN_EVENT_TYPE_DEQUEUED.
     */
    ASSERT(0);

    if (osifp->scan_id != event->scan_id) {
        return;
    }
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    /* For offchan scan, event handling is not needed */
    if(ucfg_scan_from_offchan_requestor(vdev, event)) {
        return;
    }

    if (event->type == SCAN_EVENT_TYPE_COMPLETED) {
#if ATH_SUPPORT_ZERO_CAC_DFS
        /*
         * PreCAC timer will be stopped when scan initiated.
         * Start it here once scan completes.
         */
        if (pdev && dfs_rx_ops && dfs_rx_ops->dfs_get_legacy_precac_enable &&
             dfs_rx_ops->dfs_get_agile_precac_enable &&
            (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) == 0)) {
            dfs_rx_ops->dfs_get_legacy_precac_enable(pdev, &is_precac_enabled);
            dfs_rx_ops->dfs_get_agile_precac_enable(pdev,
                                                    &is_agile_precac_enabled);
            if ((is_precac_enabled || is_agile_precac_enabled) &&
                dfs_rx_ops->dfs_is_precac_timer_running) {
                dfs_rx_ops->dfs_is_precac_timer_running(pdev, &is_precac_running);
                if (!is_precac_running) {
                    if (is_precac_enabled &&
                        dfs_rx_ops->dfs_start_precac_timer)
                        dfs_rx_ops->dfs_start_precac_timer(pdev);
#if QCA_SUPPORT_AGILE_DFS
		    else if (is_agile_precac_enabled &&
                             dfs_rx_ops->dfs_agile_precac_start)
                        dfs_rx_ops->dfs_agile_sm_deliver_evt(pdev,
                                                             DFS_AGILE_SM_EV_AGILE_START);
#endif
                }
            }
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        }
#endif
        if (event->reason != SCAN_REASON_CANCELLED) {
            if (event->scan_start_req->scan_req.scan_id != ic->scan_params.scan_id)
               osif_store_scan_params(ic,event);


            if (event->requester == osifp->scan_requestor) {

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s SCAN DONE  reason %d \n",
                        __func__, event->reason);

                /* Reset Probe Response override flag */
                wlan_set_device_param(ic,
                        IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE, 1);

#if QCA_LTEU_SUPPORT
                if (ic->ic_nl_handle) {
                    spin_lock_bh(&ic->ic_nl_handle->mu_lock);
                    if (atomic_read(&ic->ic_nl_handle->scan_in_progress) == 0) {
                        spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
                        qdf_print("%s: Scan completion id=%d (%d), but scan not active",
                               __func__, event->scan_id, osifp->scan_id);
                        return;
                    }

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Scan completion id=%d, "
                         "expected=%d, type=%d, reason=%d\n", __func__, event->scan_id,
                          osifp->scan_id, event->type, event->reason);

                    atomic_set(&ic->ic_nl_handle->scan_in_progress, 0);
                    spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
                }
#endif

                osif_notify_scan_done(osifp->netdev, event->reason);
            }
        }
#if ATH_SUPPORT_DFS
        if(ic->ic_scan_over_cac && ic->ic_is_cac_cancelled_by_scan) {
            osif_restore_vaps(ic, vap);
            ic->ic_is_cac_cancelled_by_scan = 0;
        }
#endif
    }

    /* Check if a vap bringup was delayed because of scan in progress */
    if (event->type == SCAN_EVENT_TYPE_COMPLETED) {
        if (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND) &&
                ic->schedule_bringup_vaps) {
            if ((osifp->os_opmode == IEEE80211_M_HOSTAP) ||
                    /* sta-vap is ready */
                    ((osifp->os_opmode == IEEE80211_M_STA) && wlan_is_connected(vap))) {
                osif_check_pending_ap_vaps(wlan_vap_get_devhandle(vap), vap);
                ic->schedule_bringup_vaps = false;
            }
        }
    }

#if ATH_SUPPORT_ZERO_CAC_DFS
    /*
     * Stop PreCAC timer at the time of scan start/restart
     */
    if (event->type == SCAN_EVENT_TYPE_STARTED ||
        event->type == SCAN_EVENT_TYPE_RESTARTED) {
        if (pdev &&
            dfs_rx_ops && dfs_rx_ops->dfs_get_legacy_precac_enable &&
            dfs_rx_ops->dfs_get_agile_precac_enable &&
            (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) == 0)) {
            dfs_rx_ops->dfs_get_legacy_precac_enable(pdev, &is_precac_enabled);
            dfs_rx_ops->dfs_get_agile_precac_enable(pdev,
                                                    &is_agile_precac_enabled);
            if ((is_precac_enabled || is_agile_precac_enabled) &&
                dfs_rx_ops->dfs_is_precac_timer_running) {
                dfs_rx_ops->dfs_is_precac_timer_running(pdev, &is_precac_running);
                if (is_precac_running) {
                    if (is_precac_enabled && dfs_rx_ops->dfs_cancel_precac_timer)
                        dfs_rx_ops->dfs_cancel_precac_timer(pdev);
#if QCA_SUPPORT_AGILE_DFS
                    else if (is_agile_precac_enabled &&
                             dfs_rx_ops->dfs_agile_sm_deliver_evt)
                        dfs_rx_ops->dfs_agile_sm_deliver_evt(pdev,
                                                             DFS_AGILE_SM_EV_AGILE_STOP);
#endif
               }
            }
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        }
    }
#endif

    if (!wlan_is_connected(vap) &&
            (vap->iv_opmode == IEEE80211_M_STA) &&
            (vap == scan_originator_vap) &&
            (ieee80211_vap_reset_ap_vaps_is_set(vap)) &&
            (wlan_vdev_mlme_get_state(vap->vdev_obj) != WLAN_VDEV_S_DFS_CAC_WAIT) &&
            (event->type == SCAN_EVENT_TYPE_STARTED ||
            event->type == SCAN_EVENT_TYPE_RESTARTED) &&
            !wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND) &&
            !(vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
        osif_bring_down_vaps(wlan_vap_get_devhandle(vap), vap);
    }
#if DBDC_REPEATER_SUPPORT
    if ((ic_list.same_ssid_support) && (event->type == SCAN_EVENT_TYPE_COMPLETED)) {
        if (ic->ic_sta_vap == vap){
            if (last_scanid == event->scan_id) {
                return;
            }
            last_scanid = event->scan_id;
            OS_MEMSET(ic->ic_preferred_bssid, 0, QDF_MAC_ADDR_SIZE);
            ucfg_scan_db_iterate(wlan_vap_get_pdev(vap), osif_get_rootap_bssid, vap);
            if(!IS_NULL_ADDR(ic->ic_preferred_bssid)) {
                qdf_print("vap:%s sending event with preferred RootAP bssid:%s",vap->iv_netdev_name,ether_sprintf(ic->ic_preferred_bssid));
                osif_send_preferred_bssid_event(vap);
            } else {
                if ((ic_list.extender_info & ROOTAP_ACCESS_MASK) != ROOTAP_ACCESS_MASK) {
                    /* When this RE has no RootAP access
                       Skip scan entries for 10secs to propagate RootAP Access info
                       across all REs, because FW sending stopped event after 8 secs,
                       in case of beacon miss.
                       Ideally, it should be 5 * beacon interval, but beacon miss detection
                       is taking time, need to debug*/
                    systime_t current_time = OS_GET_TIMESTAMP();
                    if ((CONVERT_SYSTEM_TIME_TO_MS(current_time - ic_list.rootap_access_downtime)) < SKIP_SCAN_ENTRIES) {
                        return;
                    }
                }
                ucfg_scan_db_iterate(wlan_vap_get_pdev(vap), osif_process_scan_entries, vap);
                if(!IS_NULL_ADDR(ic->ic_preferred_bssid)) {
                    qdf_print("vap:%s sending event with preferred Repeater bssid:%s",vap->iv_netdev_name,ether_sprintf(ic->ic_preferred_bssid));
                    osif_send_preferred_bssid_event(vap);
                }
            }
        }
    }
#endif

    /* Consider a case where NOL channel added to scan channel list sent to FW
     * in FCC domain.In the subsequent scan start request from host, FW would
     * block the scan start request due to DFS violation. Following are the
     * action taken:
     * 1. Rebuild ic and master channel list to consist of only non-DFS channel.
     * 2. Notify cfg layer that scan has failed so that subsequent scan is
     * is triggered from the supplicant.
     */
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    ieee80211_regdmn_get_dfs_region(pdev, (enum dfs_reg *)&dfs_region);
    if (event->type == SCAN_EVENT_TYPE_START_FAILED &&
        event->reason == SCAN_REASON_DFS_VIOLATION) {
        QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_DEBUG,
                  "vap:%s Handling scan failure\n", vap->iv_netdev_name);
        ic->ic_is_dfs_scan_violation = true;
        dfs_mlme_handle_dfs_scan_violation(pdev);
        osif_notify_scan_done(osifp->netdev, event->reason);
    }
#endif

}

static int osif_acs_start_bss(wlan_if_t vap, wlan_chan_t channel)
{
    int error = 0;

    if ((error = wlan_mlme_start_bss(vap,0))!=0) {
        if (error == EAGAIN) {
            /* Radio resource is busy on scanning, try later */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme busy mostly scanning \n", __func__);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                              "%s : failed start bss with error code %d\n",
                              __func__, error);
        }
        wlan_mlme_vdev_notify_down_complete(vap->vdev_obj);
        return error;
    } else {
        wlan_mlme_connection_up(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s :vap up \n", __func__);
    }

    if (wlan_coext_enabled(vap))
    {
        wlan_determine_cw(vap, channel);
    }

    return error;
}

void osif_ht40_event_handler(void *arg, wlan_chan_t channel)
{
    int error;
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;

    if ( vap == NULL ) {
        int i;
        qdf_err("\n%s osif: (%pK) ", __func__, osifp);
        qdf_err("\nis_deleted: (%d),delete_in_prog: (%d) ",
                   osifp->is_deleted,
                    osifp->is_delete_in_progress);
        for ( i = 0; i < 25; i++ ) {
            qdf_err("\nosif [%d] 0x%pK",i,((char *)(osifp + i)));
        }
        return;
    }
    /* Do not process, if vap is in deletion or command is removed from queue */
    if ((osifp->is_delete_in_progress) ||
        (wlan_serialization_get_vdev_active_cmd_type(vap->vdev_obj) !=
                                          WLAN_SER_CMD_VDEV_START_BSS))
        goto done;

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC))
        goto done;

    vap->iv_needs_up_on_acs = 0;
    if ((error = osif_acs_start_bss(vap, channel))!=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme busy mostly scanning \n", __func__);
    } else {
        wlan_restore_vap_params(vap);
    }

done:
    wlan_autoselect_unregister_event_handler(vap,
            &osif_ht40_event_handler,
            osifp);
}

#if UMAC_SUPPORT_CFG80211
static void cfg80211_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int error = 0;

    if (!vap) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS, "%s : Received NULL vap\n", __func__);
        return;
    }

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC)) {
        goto done;
    }

    error = wlan_set_ieee80211_channel(vap, channel);
    if (error !=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s : failed to set channel with error code %d\n",
                        __func__, error);
    }
    wlan_cfg80211_acs_report_channel(vap, channel);
    vap->iv_cfg80211_acs_pending = 0;
done:
    if (!vap->iv_cfg80211_acs_pending) {
        wlan_autoselect_unregister_event_handler(vap, &cfg80211_acs_event_handler, (void *)arg);
    }
}

int wlan_cfg80211_start_acs_scan(wlan_if_t vap,
                        cfg80211_hostapd_acs_params *cfg_acs_params)
{

    vap->iv_cfg80211_acs_pending = 1;
    wlan_autoselect_register_event_handler(vap,
                               &cfg80211_acs_event_handler,
                               (void *)wlan_vap_get_registered_handle(vap));

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                     "%s: vap-%d needs acs\n", __func__, vap->iv_unit);

    return(wlan_autoselect_find_infra_bss_channel(vap, cfg_acs_params));
}
#endif /* UMAC_SUPPORT_CFG80211*/

/*
* Auto Channel Select handler used for interface up.
*/
void osif_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    uint32_t bcn_rate;
    uint32_t mgmt_rate;
    struct wlan_vdev_mgr_cfg mlme_cfg;

    if (osifp->is_delete_in_progress)
        goto done;

     /* In cases where ACS fails to derive the channel,
      * the acs event handler is called with IEEE80211_CHAN_ANYC,
      * we can start the monitor vap with the default channel.
      */
     if (!channel || channel == IEEE80211_CHAN_ANYC) {

        qdf_err("ACS event handler vdev[%d], channel: %pK",
                 wlan_vdev_get_id(vap->vdev_obj), channel);

        if (wlan_vdev_mlme_get_opmode(vap->vdev_obj) == QDF_MONITOR_MODE)
            wlan_mlme_start_monitor(vap);
        else
            wlan_mlme_release_vdev_req(vap->vdev_obj,
                                       WLAN_SER_CMD_VDEV_START_BSS, EINVAL);
        goto done;
    }

    error = wlan_set_ieee80211_channel(vap, channel);
    if (error !=0) {
        qdf_err("Failed to set channel with error code %d", error);
        wlan_mlme_release_vdev_req(vap->vdev_obj,
                                   WLAN_SER_CMD_VDEV_START_BSS, EINVAL);
        goto done;
    }

    if (wlan_vdev_mlme_get_opmode(vap->vdev_obj) == QDF_MONITOR_MODE) {
        wlan_mlme_start_monitor(vap);
        goto done;
    }
    vap->iv_needs_up_on_acs = 0;
    osif_acs_start_bss(vap, channel);

    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_BCN_TX_RATE, &bcn_rate);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_TX_MGMT_RATE, &mgmt_rate);

    /*setting mcast rate is defered */
    if (vap->iv_mcast_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_MCAST_RATE, vap->iv_mcast_rate);
        vap->iv_mcast_rate_config_defered = FALSE;
    }

    /*setting bcast rate is defered */
    if (vap->iv_bcast_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_BCAST_RATE, vap->iv_bcast_fixedrate);
        vap->iv_bcast_rate_config_defered = FALSE;
    }

    /*setting mgmt rate is defered */
    if (vap->iv_mgt_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_MGMT_RATE, mgmt_rate);
        vap->iv_mgt_rate_config_defered = FALSE;
    }

    /*Set default mgmt rate*/
    if (!ieee80211_rate_is_valid_basic(vap, mgmt_rate)){
        if(IEEE80211_IS_CHAN_5GHZ_6GHZ(channel)){
            mlme_cfg.value = DEFAULT_LOWEST_RATE_5G;
        } else if(IEEE80211_IS_CHAN_2GHZ(channel)){
            mlme_cfg.value = DEFAULT_LOWEST_RATE_2G;
        }
        ucfg_wlan_vdev_mgr_set_param(vap->vdev_obj,
                WLAN_MLME_CFG_TX_MGMT_RATE, mlme_cfg);
    }

    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_TX_MGMT_RATE, &mgmt_rate);

    /* if rates set, use previous rates */
    /* for offload radios, fw will reset rates to default everytime VAP bringup */
    if(mgmt_rate){
        wlan_set_param(vap, IEEE80211_MGMT_RATE, mgmt_rate);
    }
    if (vap->iv_disabled_legacy_rate_set) {
        wlan_set_param(vap, IEEE80211_RTSCTS_RATE, mgmt_rate);
    }
    if(vap->iv_bcast_fixedrate){
        wlan_set_param(vap, IEEE80211_BCAST_RATE, vap->iv_bcast_fixedrate);
    }
    if(vap->iv_mcast_fixedrate){
        wlan_set_param(vap, IEEE80211_MCAST_RATE, vap->iv_mcast_fixedrate);
    }

    if(bcn_rate) {
        wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP, bcn_rate);
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &osif_acs_event_handler, (void *)osifp);
}

void osif_start_acs_on_other_vaps(void *arg, wlan_if_t vap)
{
    wlan_if_t *orig_vap = ((wlan_if_t *)arg);
    wlan_chan_t chan    =  NULL;
    enum ieee80211_phymode des_mode;

    chan = wlan_get_current_channel(vap, false);
    des_mode = wlan_get_desired_phymode(vap);

    if (*orig_vap != vap) {
        if ((wlan_vdev_mlme_get_state(vap->vdev_obj) == WLAN_VDEV_S_INIT) &&
            vap->iv_needs_up_on_acs == 1) {
            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                wlan_autoselect_register_event_handler(vap,
                            &osif_acs_event_handler,
                            (void *)wlan_vap_get_registered_handle(vap));
                wlan_autoselect_find_infra_bss_channel(vap, NULL);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                            "%s: vap-%d needs acs\n", __func__, vap->iv_unit);
            } else if (ieee80211_is_phymode_g40(des_mode) &&
                       (wlan_coext_enabled(vap) &&
                       !vap->iv_ic->ic_obss_done_freq &&
                       (osif_get_num_running_vaps(vap->iv_ic) == 0))) {
                       wlan_autoselect_register_event_handler(
                            vap, &osif_ht40_event_handler,
                            (void *)wlan_vap_get_registered_handle(vap));
                       wlan_attempt_ht40_bss(vap);
            }
        }
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
            "%s: vap-%d brought down, acs not req.\n", __func__, vap->iv_unit);
    }
}

void preempt_scan(struct net_device *dev, int max_grace, int max_wait)
{
#define PREEMPT_SCAN_DELAY ((CONVERT_SEC_TO_SYSTEM_TIME(1)/1000) + 1) /* 1 msec */
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int total_delay = 0;
    int canceled = 0, ready = 0;
    struct wlan_objmgr_vdev *vdev = NULL;
    QDF_STATUS status;

    vdev = osifp->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return;
    }

    while (!ready && total_delay < max_grace + max_wait) {
        if (!wlan_vdev_scan_in_progress(vap->vdev_obj)) {
            ready = 1;
        } else {
            if (!canceled && total_delay > max_grace) {
                /*
                   Cancel any existing active scan, so that any new parameters
                   in this scan ioctl (or the defaults) can be honored, then
                   wait around a while to see if the scan cancels properly.
                 */
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                        "%s: cancel pending scan request\n", __func__);
                wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, 0,
                        WLAN_SCAN_CANCEL_VDEV_ALL, false);
                canceled = 1;
            }

            schedule_timeout_interruptible(PREEMPT_SCAN_DELAY);
            total_delay += 1;
        }
    }
    if (!ready) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                "%s: Timeout canceling current scan.\n",
                __func__);
    }
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
}

void delete_default_vap_keys(struct ieee80211vap *vap)
{
    int i;
    /*
     * delete any default keys, if the vap is to be deleted.
     */
     for (i=0;i<IEEE80211_WEP_NKID; ++i) {
        u_int8_t macaddr[] = {0xff,0xff,0xff,0xff,0xff,0xff };
        wlan_del_key(vap,i,macaddr);
     }
}

static void
osif_auth_complete_ap(os_handle_t osif, u_int8_t *macaddr, IEEE80211_STATUS status)
{

	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_AP, acfg_event);
#endif
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_COMPLETE_AP;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif

	return;
}

static void
osif_assoc_complete_ap(os_handle_t osif, IEEE80211_STATUS status,
						u_int16_t aid, wbuf_t wbuf)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_AP, acfg_event);
#endif
	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_COMPLETE_AP;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_deauth_complete_ap(os_handle_t osif, u_int8_t *macaddr,
							IEEE80211_STATUS status, u_int16_t associd, u_int16_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
	union iwreq_data wreq;
	u_int8_t *msg;
	union iwreq_data wrqu;
	struct ev_msg evmsg;
	wlan_if_t vap = ((osif_dev *)osif)->os_if;
	union iwreq_data staleave_wreq;
	struct ev_sta_leave staleave_ev;
#if ATH_SUPPORT_WAPI
	union iwreq_data wapi_wreq;
	u_int8_t *sta_msg;
	int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
#if QCA_SUPPORT_SON
	struct son_ald_assoc_event_info info;
#endif

	msg = NULL;
	/* fire off wireless event station leaving */
	memset(&wreq, 0, sizeof(wreq));
	IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
	wreq.addr.sa_family = ARPHRD_ETHER;
	WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);
#if QCA_SUPPORT_SON
	qdf_mem_zero(&info, sizeof(info));
	qdf_mem_copy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
	info.flag = ALD_ACTION_DISASSOC;
	info.reason = reason;
	son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif
#if ATH_SUPPORT_WAPI
	sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_STA_AGING);
	if (sta_msg) {
	    OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
	    wapi_wreq.data.length = msg_len;
	    wapi_wreq.data.flags = IEEE80211_EV_WAPI;
	    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
	    wlan_wapi_callback_end(sta_msg);
	}
	msg = sta_msg;
#endif
#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_AP, acfg_event);
#endif

	if(msg==NULL) {
	    evmsg.status = status;
	    IEEE80211_ADDR_COPY(evmsg.addr, macaddr);
	    memset(&wrqu, 0, sizeof(wrqu));
	    wrqu.data.flags = IEEE80211_EV_DEAUTH_COMPLETE_AP;
	    wrqu.data.length = sizeof(evmsg);
	    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
#if UMAC_SUPPORT_CFG80211
	if(vap->iv_cfg80211_create) {
	    cfg80211_del_sta(dev, macaddr, GFP_ATOMIC);
	}
#endif
	}
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif

	/* check for smart mesh configuration and send event */
	if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

	    OS_MEMZERO(&staleave_ev, sizeof(staleave_ev));

	    /* populate required fileds */
	    OS_MEMCPY(&(staleave_ev.mac_addr), macaddr, QDF_MAC_ADDR_SIZE);
	    staleave_ev.channel_num = vap->iv_bsschan->ic_ieee;
	    staleave_ev.assoc_id = IEEE80211_AID(associd);
	    staleave_ev.reason = reason;

	    /* prepare custom event */
	    staleave_wreq.data.flags = IEEE80211_EV_STA_LEAVE;
	    staleave_wreq.data.length = sizeof(staleave_ev);
	    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &staleave_wreq, (char *)&staleave_ev);

	}

	return;
}

static void
osif_auth_indication_ap(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_AP, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_IND_AP;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}
static void
osif_assoc_indication_ap(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t result, wbuf_t wbuf,
							wbuf_t resp_buf, bool reassoc)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
    struct ev_msg msg;

    if (osifp->os_opmode != IEEE80211_M_P2P_GO) {
        if (!wlan_get_param(vap, IEEE80211_TRIGGER_MLME_RESP))
        {
        	OS_MEMSET(&wreq, 0, sizeof(wreq));
	        IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
	        wreq.addr.sa_family = ARPHRD_ETHER;
        	WIRELESS_SEND_EVENT(dev, IWEVREGISTERED, &wreq, NULL);
        }
        IEEE80211_ADDR_COPY(msg.addr, macaddr);
        memset(&wreq, 0, sizeof(wreq));
        if(reassoc)
		wreq.data.flags = IEEE80211_EV_REASSOC_IND_AP;
        else
		wreq.data.flags = IEEE80211_EV_ASSOC_IND_AP;
        wreq.data.length = sizeof(msg);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&msg);

#if ATH_SUPPORT_WAPI
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_WAI_REQUEST);
        if (sta_msg) {
#if UMAC_SUPPORT_CFG80211
            if(vap->iv_cfg80211_create){
                u8 *ies = NULL;
                size_t ies_len = 0;
                struct station_info sinfo;
                struct ieee80211_node *ni = NULL;
                ni = ieee80211_find_node(vap->iv_ic, macaddr, WLAN_MLME_SB_ID);
                if(ni) {
                    ies = ni->ni_wpa_ie;
                    ies_len = ies[1] + 2;
                    memset(&sinfo, 0, sizeof(sinfo));
                    sinfo.assoc_req_ies = ies;
                    sinfo.assoc_req_ies_len = ies_len;
                    cfg80211_new_sta(dev, macaddr, &sinfo, GFP_KERNEL);
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                }
            }
            else
#endif
            {
                OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
                wapi_wreq.data.length = msg_len;
                wapi_wreq.data.flags = IEEE80211_EV_WAPI;
                WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
                wlan_wapi_callback_end(sta_msg);
            }
        }
#endif
    }
    else { /* For P2P supplicant needs entire stuff */
        char *concat_buf;
        int wbuf_len =  wbuf_get_pktlen(wbuf);

        concat_buf = OS_MALLOC(osifp->os_handle, wbuf_len + QDF_MAC_ADDR_SIZE,
                                GFP_ATOMIC);
        if (!concat_buf) {
            return;
        }
        OS_MEMSET(&wreq, 0, sizeof(wreq));
        wreq.data.length = wbuf_len + QDF_MAC_ADDR_SIZE;
        IEEE80211_ADDR_COPY(concat_buf, macaddr);
        OS_MEMCPY(concat_buf+QDF_MAC_ADDR_SIZE, wbuf_header(wbuf), wbuf_len);

        WIRELESS_SEND_EVENT(dev, IWEVGENIE, &wreq, concat_buf);
        OS_FREE(concat_buf);
    }

    /* Send TGf L2UF frame on behalf of newly associated station */
    osif_deliver_l2uf(osif, macaddr);

#if DBDC_REPEATER_SUPPORT || UMAC_SUPPORT_SON
    /* To send L2UF on same VAP, to which client connects */
    osif_hardstart_l2uf(osif, macaddr);
#endif

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = result;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_AP, acfg_event);
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void osif_deauth_indication_ap(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    u_int8_t *msg;
    union iwreq_data wrqu;
    struct ev_msg evmsg;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data staleave_wreq;
    struct ev_sta_leave staleave_ev;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif
#if QCA_SUPPORT_SON
    struct son_ald_assoc_event_info info;
#endif

    msg = NULL;
    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);
#if QCA_SUPPORT_SON
    qdf_mem_zero(&info, sizeof(info));
    qdf_mem_copy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
    info.flag = ALD_ACTION_DISASSOC;
    info.reason = reason;
    son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif
#if ATH_SUPPORT_WAPI
    sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_STA_AGING);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
    msg = sta_msg;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (acfg_event == NULL)
        return;

    acfg_event->reason = reason;
    IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
    acfg_event->downlink = 1;
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_AP, acfg_event);
#endif
    if (msg == NULL) {
        evmsg.reason = reason;
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_DEAUTH_IND_AP;
        wrqu.data.length = sizeof(evmsg);
        IEEE80211_ADDR_COPY(evmsg.addr, macaddr);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
#if UMAC_SUPPORT_CFG80211
	if(vap->iv_cfg80211_create) {
	    cfg80211_del_sta(dev, macaddr, GFP_ATOMIC);
	}
#endif
    }
#if UMAC_SUPPORT_ACFG
    qdf_mem_free(acfg_event);
#endif

    /* check for smart mesh configuration and send event */
    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        OS_MEMZERO(&staleave_ev, sizeof(staleave_ev));

        /* populate required fileds */
        OS_MEMCPY(&(staleave_ev.mac_addr), macaddr, QDF_MAC_ADDR_SIZE);
        staleave_ev.channel_num = vap->iv_bsschan->ic_ieee;
        staleave_ev.assoc_id = IEEE80211_AID(associd);
        staleave_ev.reason = reason;

        /* prepare custom event */
        staleave_wreq.data.flags = IEEE80211_EV_STA_LEAVE;
        staleave_wreq.data.length = sizeof(staleave_ev);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &staleave_wreq, (char *)&staleave_ev);

    }

    return;
}


static void
osif_auth_complete_sta(os_handle_t osif, u_int8_t *macaddr, IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg = {0};
	osif_dev *osifp = (osif_dev *)osif;
	wlan_if_t vap = osifp->os_if;

	if (vap->iv_cfg80211_create && vap->iv_roam.iv_roaming) {
		ieee80211_cfg80211_post_ft_event(osif);
	}

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_STA, acfg_event);
#endif

	msg.status = status;
	if (macaddr)
		IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_COMPLETE_STA;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_assoc_complete_sta_common(os_handle_t osif, IEEE80211_STATUS status,
		u_int16_t aid, wbuf_t wbuf, u_int8_t frame_subtype)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_CFG80211
	osif_dev *osifp = (osif_dev *)osif;
	wlan_if_t vap = osifp->os_if;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg = {0};
	struct ieee80211_frame *wh;

	/* mlme_cancel will send NULL wbuf*/
	if (wbuf)
		ieee80211_update_assoc_ie(dev, wbuf);
	if(!vap->iv_cfg80211_create) {
#if UMAC_SUPPORT_ACFG
		acfg_event_data_t *acfg_event = NULL;
		acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
		if (acfg_event == NULL)
			return;

		acfg_event->result = status;
		acfg_event->downlink = 0;
		acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_STA, acfg_event);
		qdf_mem_free(acfg_event);
#endif
	}
	if (wbuf) {
		/* Copy BSSID */
		wh = (struct ieee80211_frame *) wbuf_header(wbuf);
		IEEE80211_ADDR_COPY(msg.addr, wh->i_addr3);
	}
	msg.frame_subtype = frame_subtype;

	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_COMPLETE_STA;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
	return;
}

static void
osif_assoc_complete_sta(os_handle_t osif, IEEE80211_STATUS status,
		u_int16_t aid, wbuf_t wbuf)
{
	osif_assoc_complete_sta_common(osif, status, aid, wbuf,
					IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
}

static void
osif_reassoc_complete_sta(os_handle_t osif, IEEE80211_STATUS status,
		u_int16_t aid, wbuf_t wbuf)
{
	osif_assoc_complete_sta_common(osif, status, aid, wbuf,
					IEEE80211_FC0_SUBTYPE_REASSOC_RESP);
}

static void
osif_deauth_complete_sta(os_handle_t osif, u_int8_t *macaddr,
							IEEE80211_STATUS status, u_int16_t associd, u_int16_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

    memset(&wrqu, 0, sizeof(wrqu));
    IEEE80211_ADDR_COPY(wrqu.addr.sa_data, macaddr);
    wrqu.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wrqu, NULL);

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_STA, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DEAUTH_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_disassoc_complete_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int32_t reason,
							IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_STA, acfg_event);
#endif

	msg.status = status;
	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DISASSOC_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_auth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_STA, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_deauth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t associd, u_int16_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg = {0};

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_STA, acfg_event);
#endif

	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DEAUTH_IND_STA;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void
osif_unprotected_deauth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
                                       u_int16_t associd, u_int16_t reason,
                                       wbuf_t wbuf)
{
        struct net_device *dev = ((osif_dev *)osif)->netdev;
        union iwreq_data wrqu;
        struct ev_msg msg;
#if UMAC_SUPPORT_CFG80211
        int wbuf_len =  wbuf_get_pktlen(wbuf);
#endif

        msg.reason = reason;
        /* sa/ta addr / addr2 */
        IEEE80211_ADDR_COPY(msg.addr, macaddr);
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_UNPROTECTED_DEAUTH_IND_STA;
        wrqu.data.length = sizeof(struct ev_msg);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_CFG80211
        cfg80211_rx_unprot_mlme_mgmt(dev, wbuf_header(wbuf), wbuf_len);
#endif
        return;

}

static void
osif_assoc_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t result, wbuf_t wbuf,
							wbuf_t resp_buf, bool reassoc)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = result;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_STA, acfg_event);
#endif

	msg.status = result;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void osif_disassoc_indication_sta(os_handle_t osif,
									       u_int8_t *macaddr,
									       u_int16_t associd,
									       u_int32_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg = {0};
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_STA, acfg_event);
#endif

	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DISASSOC_IND_STA;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	qdf_mem_free(acfg_event);
#endif
	return;
}

static void osif_authorized_indication_sta(os_handle_t osif,
		u_int8_t *macaddr)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
	struct ev_msg msg = {0};
	union iwreq_data wrqu;

	if (macaddr)
		IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTHORIZED_IND_STA;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
	return;
}

#if UMAC_SUPPORT_RRM_MISC
static void  osif_nonerpcnt(os_handle_t osif, u_int8_t nonerpcnt)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_NONERP_JOINED;
    ath_adhoc_netlink_send(&event, (char *)&nonerpcnt, sizeof(u_int8_t));
    return;
}

static void  osif_bgjoin(os_handle_t osif, u_int8_t value)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_BG_JOINED;
    ath_adhoc_netlink_send(&event, (char *)&value, sizeof(u_int8_t));
    return;
}

static void  osif_cochannelap_cnt(os_handle_t osif, u_int8_t cnt)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_COCHANNEL_AP_CNT;
    ath_adhoc_netlink_send(&event, (char *)&cnt, sizeof(u_int8_t));
    return;
}
static void  osif_chload(os_handle_t osif, u_int8_t chload)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_CHLOAD;
    ath_adhoc_netlink_send(&event, (char *)&chload, sizeof(u_int8_t));
    return;
}
#endif
static void  osif_ch_hop_channel_change(os_handle_t osif, u_int8_t channel)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_CH_HOP_CHANNEL_CHANGE;
    ath_adhoc_netlink_send(&event, (char *)&channel, sizeof(u_int8_t));
    return;
}

static void osif_recv_probereq(os_handle_t osif, u_int8_t *mac_addr ,  u_int8_t *ssid_element)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
    struct ieee80211_node *ni = NULL;
    struct ieee80211_node *ni_bss = NULL;
    u_int8_t ssid_len = 0;
    struct ev_recv_probereq probe_ev;

    ssid_len = ssid_element[1];
    ni_bss = vap->iv_bss;

    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        if ((ssid_len == 0) || ((ssid_len == ni_bss->ni_esslen)
                                && (OS_MEMCMP((ssid_element)+2, ni_bss->ni_essid, ssid_len) == 0))) {
            ni = ieee80211_find_node(vap->iv_ic, mac_addr, WLAN_MLME_SB_ID);
            if (ni) {

                OS_MEMZERO(&probe_ev, sizeof(probe_ev));

                /* populate required fileds */
                OS_MEMCPY(&(probe_ev.mac_addr), ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
#ifdef QCA_SUPPORT_CP_STATS
                probe_ev.snr = peer_cp_stats_rx_mgmt_snr_get(ni->peer_obj);
                probe_ev.rate = peer_cp_stats_rx_mgmt_rate_get(ni->peer_obj);
#endif
                probe_ev.channel_num = ni->ni_chan->ic_ieee;

                /* prepare custom event */
                wreq.data.flags = IEEE80211_EV_RECV_PROBEREQ;
                wreq.data.length = sizeof(probe_ev);
                WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&probe_ev);

                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }

        }
    }
    return;
}

static void osif_recv_neighreq(os_handle_t osif, u_int8_t *macaddr, void *arg)
{
    ieee80211_rrm_nrreq_info_t *nrreq = (ieee80211_rrm_nrreq_info_t *)arg;
    struct ev_neigh_req_recv neighreq_ev;
    union iwreq_data wreq;
    struct net_device *dev = ((osif_dev *)osif)->netdev;

    IEEE80211_ADDR_COPY(neighreq_ev.mac_addr, macaddr);
    qdf_mem_copy(&neighreq_ev.nrreq, nrreq,
                 sizeof(ieee80211_rrm_nrreq_info_t));
    wreq.data.flags = IEEE80211_EV_NEIGH_REQ_RECV_AP;
    wreq.data.length = sizeof(neighreq_ev);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&neighreq_ev);
}

#if DBDC_REPEATER_SUPPORT
static void osif_dbdc_stavap_connection (os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    vap = osdev->os_if;
    qdf_print("Send layer2 update frame on vap:%s to detect loop",ether_sprintf(vap->iv_myaddr));
    osif_hardstart_l2uf(osif, vap->iv_myaddr);
}
#endif


static void osif_session_timeout(os_handle_t osif, u_int8_t *mac)
{
#if MESH_MODE_SUPPORT || UMAC_SUPPORT_ACFG
    struct net_device *dev = ((osif_dev *)osif)->netdev;
#endif

#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif

#if MESH_MODE_SUPPORT
    union iwreq_data  wrqu;
    struct ev_msg evmsg;
    evmsg.reason = IEEE80211_REASON_KICK_OUT;
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_MESH_PEER_TIMEOUT;
    IEEE80211_ADDR_COPY(evmsg.addr, mac);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
#endif

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->reason = ACFG_SESSION_TIMEOUT;
	IEEE80211_ADDR_COPY(acfg_event->addr, mac);
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_STA_SESSION, acfg_event);
	qdf_mem_free(acfg_event);
#endif
    return;
}
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
static void  osif_ssid_event(os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) VAP VALUE(%d)\n",
            __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

    son_send_ssid_steering_event(macaddr);
} /* void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif

static void  osif_assocdeny_event(os_handle_t osif, u_int8_t *macaddr)
{
    static const char *tag = "MLME-ASSOCDENIAL.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev        = ath_netdev_priv(dev);
    wlan_if_t vap          = osdev->os_if;
    union iwreq_data         wrqu;
    char *buf              = NULL;
#define BUF_SIZE           128
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%pM) VAP(%d) device %s\n",__func__, macaddr, vap->iv_unit, dev->name);
    if(NULL != (buf = OS_MALLOC(osif, BUF_SIZE, GFP_KERNEL))){
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        OS_MEMZERO(buf, BUF_SIZE);
        snprintf(buf, BUF_SIZE, "%s(macaddr=%pM, vap=%s)", tag, macaddr, dev->name);
        wrqu.data.length = strlen(buf);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
        OS_FREE(buf);
    } else
        qdf_print(KERN_ERR "%s: failed to allocate memory of size (%d)",__func__,BUF_SIZE);
#undef BUF_SIZE
} /* void (*assocdeny_event)(os_handle_t, u_int8_t *macaddr); */

static void osif_leave_indication_ap(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int32_t reason)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    u_int8_t *msg;
    union iwreq_data wrqu;
    struct ev_msg evmsg;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data staleave_wreq;
    struct ev_sta_leave staleave_ev;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif
#if QCA_SUPPORT_SON
    struct son_ald_assoc_event_info info;
#endif

    msg = NULL;
    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);
#if QCA_SUPPORT_SON
    qdf_mem_zero(&info, sizeof(info));
    qdf_mem_copy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
    info.flag = ALD_ACTION_DISASSOC;
    info.reason = reason;
    son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif
#if ATH_SUPPORT_WAPI
    sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_STA_AGING);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        qdf_print("%s size:%d *", __func__, wreq.data.length);
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
    msg = sta_msg;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (acfg_event == NULL)
        return;

    acfg_event->reason = reason;
    IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
    acfg_event->downlink = 1;
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_AP, acfg_event);
#endif
    if (msg == NULL) {
        evmsg.reason = reason;
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_DISASSOC_IND_AP;
        wrqu.data.length = sizeof(evmsg);
        IEEE80211_ADDR_COPY(evmsg.addr, macaddr);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
#if UMAC_SUPPORT_CFG80211
        if(vap->iv_cfg80211_create) {
            cfg80211_del_sta(dev, macaddr, GFP_ATOMIC);
        }
#endif
    }

#if UMAC_SUPPORT_ACFG
    qdf_mem_free(acfg_event);
#endif

    /* check for smart mesh configuration and send event */
    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        OS_MEMZERO(&staleave_ev, sizeof(staleave_ev));

        /* populate required fileds */
        OS_MEMCPY(&(staleave_ev.mac_addr), macaddr, QDF_MAC_ADDR_SIZE);
        staleave_ev.channel_num = vap->iv_bsschan->ic_ieee;
        staleave_ev.assoc_id = IEEE80211_AID(associd);
        staleave_ev.reason = reason;

        /* prepare custom event */
        staleave_wreq.data.flags = IEEE80211_EV_STA_LEAVE;
        staleave_wreq.data.length = sizeof(staleave_ev);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &staleave_wreq, (char *)&staleave_ev);

    }
    return;
}


static void  osif_disassoc_complete_ap(os_handle_t osif, u_int8_t *macaddr, u_int32_t reason, IEEE80211_STATUS status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
#if UMAC_SUPPORT_CFG80211
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
#endif
    struct ev_msg msg;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif

    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);

    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_DISASSOC_COMPLETE_AP;
    wreq.data.length = sizeof(wreq);
    msg.reason=reason;
    msg.status=status;
    WIRELESS_SEND_EVENT(dev,IWEVCUSTOM,&wreq, (char *)&msg);

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_AP, acfg_event);
	qdf_mem_free(acfg_event);
#endif

#if UMAC_SUPPORT_CFG80211
        if(vap->iv_cfg80211_create) {
            cfg80211_del_sta(dev, macaddr, GFP_ATOMIC);
        }
#endif
	return;
}

static void osif_node_authorized_indication_ap(os_handle_t osif, u_int8_t *mac_addr)
{

    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
    struct ieee80211_node *ni = NULL;
    struct ev_node_authorized authorize_ev;

    ni = ieee80211_find_node(vap->iv_ic, mac_addr, WLAN_MLME_SB_ID);
    if (ni) {

        OS_MEMZERO(&authorize_ev, sizeof(authorize_ev));

        /* populate required fileds */
        OS_MEMCPY(&(authorize_ev.mac_addr), ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
        authorize_ev.channel_num = ni->ni_chan->ic_ieee;
        authorize_ev.assoc_id = IEEE80211_AID(wlan_node_get_associd(ni));
        authorize_ev.phymode = wlan_node_get_mode(ni);
        authorize_ev.nss = wlan_node_get_nss(ni);
        authorize_ev.is_256qam   = wlan_node_get_256qam_support(ni);

        /* prepare custom event */
        wreq.data.flags = IEEE80211_EV_STA_AUTHORIZED;
        wreq.data.length = sizeof(authorize_ev);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&authorize_ev);

        ieee80211_free_node(ni, WLAN_MLME_SB_ID);
    }

    return;
}

#if ATH_SUPPORT_WAPI
static void osif_rekey_indication_ap(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;

    if (IEEE80211_IS_MULTICAST(macaddr))
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_MULTI_REKEY);
    else
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_UNICAST_REKEY);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
}
#endif

#if ATH_SUPPORT_MGMT_TX_STATUS
/*
 * Handler to provide TX status for MGMT frames
 */
void osif_mgmt_tx_status(os_handle_t osif, IEEE80211_STATUS status, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    int wbuf_len =  wbuf_get_pktlen(wbuf);
    char *concat_buf;

    concat_buf = OS_MALLOC(osifp->os_handle, wbuf_len + sizeof(IEEE80211_STATUS),
                                GFP_ATOMIC);
    if (!concat_buf) {
        return;
    }

    OS_MEMSET(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_TX_MGMT;
    wreq.data.length = wbuf_len + sizeof(IEEE80211_STATUS);
    *((IEEE80211_STATUS*)concat_buf) = status;
    OS_MEMCPY(concat_buf+sizeof(IEEE80211_STATUS), wbuf_header(wbuf), wbuf_len);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, concat_buf);
    OS_FREE(concat_buf);
}
#endif

#if ATH_PARAMETER_API
static void  osif_papi_event(os_handle_t osif,
                             PAPI_REPORT_TYPE type,
                             uint32_t len, const char *data)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    ath_netlink_papi_event_t  netlink_event;

    memset(&netlink_event, 0x0, sizeof(netlink_event));
    netlink_event.type = type;
    netlink_event.sys_index = dev->ifindex;
    if (len && data) {
        OS_MEMCPY(&(netlink_event.data), data, len);
    }

    ath_papi_netlink_send(&netlink_event);
    return;

}
#endif

static void osif_recv_beaconrpt(os_handle_t osif, void *arg, uint32_t len) {
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;

#if UMAC_SUPPORT_CFG80211
    if(vap->iv_cfg80211_create) {
        wlan_cfg80211_generic_event(vap->iv_ic,
                                    QCA_NL80211_VENDOR_SUBCMD_FWD_RRM_RPT,
                                    arg,
                                    len,
                                    osifp->netdev, GFP_ATOMIC);
    }
#endif /*UMAC_SUPPORT_CFG80211*/
}

static void osif_recv_bstm(os_handle_t osif, void *arg, uint32_t len) {
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;

#if UMAC_SUPPORT_CFG80211
    if(vap->iv_cfg80211_create) {
        wlan_cfg80211_generic_event(vap->iv_ic,
                                    QCA_NL80211_VENDOR_SUBCMD_FWD_BTM_RPT,
                                    arg,
                                    len,
                                    osifp->netdev, GFP_ATOMIC);
    }
#endif /*UMAC_SUPPORT_CFG80211*/
}

static void osif_recv_smpsupdate(os_handle_t osif, void *arg, uint32_t len) {
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;

#if UMAC_SUPPORT_CFG80211
    if(vap->iv_cfg80211_create) {
        wlan_cfg80211_generic_event(vap->iv_ic,
                                    QCA_NL80211_VENDOR_SUBCMD_SMPS_UPDATE,
                                    arg,
                                    len,
                                    osifp->netdev, GFP_ATOMIC);
    }
#endif /*UMAC_SUPPORT_CFG80211*/
}

static void osif_recv_opmodeupdate(os_handle_t osif, void *arg, uint32_t len) {
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;

#if UMAC_SUPPORT_CFG80211
    if(vap->iv_cfg80211_create) {
        wlan_cfg80211_generic_event(vap->iv_ic,
                                    QCA_NL80211_VENDOR_SUBCMD_OPMODE_UPDATE,
                                    arg,
                                    len,
                                    osifp->netdev, GFP_ATOMIC);
    }
#endif /*UMAC_SUPPORT_CFG80211*/
}

/*
 * handler called when the AP vap comes up asynchronously.
 * (happens only when resource  manager is present).
 */
static void  osif_create_infra_complete( os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    struct net_device *dev;

    dev = OSIF_TO_NETDEV(osifp);

	if(osifp->is_delete_in_progress)
		return;

    if(status == IEEE80211_STATUS_SUCCESS) {
        wlan_mlme_connection_up(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap-%d up\n", __func__, vap->iv_unit);
        wlan_restore_vap_params(vap);
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap-%d down, status=%d\n", __func__, vap->iv_unit, status);
        dev->flags &= ~IFF_RUNNING;
    }

}

/*
 * osif_cancel_acs_and_start_ap():
 * Cancel ACS for the given AP vap and report the STA VAP's iv_bsschan
 * back to hostapd.
 */
void osif_cancel_acs_and_start_ap(void *arg, struct ieee80211vap *vap)
{
    osif_dev *osifp = NULL;
    struct ieee80211vap *sta_vap = (struct ieee80211vap *)arg;

    if ((sta_vap == NULL) || (wlan_vap_get_opmode(sta_vap) != IEEE80211_M_STA)) {
        return;
    }

    if ((sta_vap->iv_bsschan == NULL) ||
        (sta_vap->iv_bsschan == IEEE80211_CHAN_ANYC)) {
        return;
    }

    /*
     * Cancel ACS only if the VAP is an AP and if ACS is still pending
     */
    if ((wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) ||
        !vap->iv_cfg80211_acs_pending) {
        return;
    }

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if (osifp == NULL) {
        return;
    }

    wlan_autoselect_unregister_event_handler(vap, &cfg80211_acs_event_handler,
                                             (void *)osifp);
    wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, 0,
                          WLAN_SCAN_CANCEL_VDEV_ALL, false);
    wlan_cfg80211_acs_report_channel(vap, sta_vap->iv_bsschan);
    vap->iv_cfg80211_acs_pending = 0;

    return;
}

static void bringup_ap_vaps(void *arg, wlan_if_t vap)
{

    if ((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
        (wlan_vap_get_opmode(vap) == IEEE80211_M_MONITOR)) {
        if(wlan_vdev_mlme_get_state(vap->vdev_obj) == WLAN_VDEV_S_INIT) {
            osif_bringup_vap_iter_func(NULL, vap);
#if MESH_MODE_SUPPORT
        } else if (vap->iv_mesh_vap_mode &&
                   (vap->iv_bsschan != vap->iv_ic->ic_curchan)) {
            /*
             * Since mesh mode operates independently, it will not
             * be in INIT state. But, mesh AP restart needs to be done
             * to ensure it moves to the new operating channel.
             */
            osif_restart_ap_vap_iter_func(NULL, vap);
#endif
        }
    }
}

static void bringup_sta_vaps(void *arg, wlan_if_t vap)
{

    if (!((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
        (wlan_vap_get_opmode(vap) == IEEE80211_M_MONITOR))) {
        wlan_mlme_cm_start(vap->vdev_obj, CM_OSIF_CONNECT);
    }
}

static void osif_bringup_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    struct net_device *dev;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    dev = OSIF_TO_NETDEV(osifp);
    if (dev == NULL) {
         return;
    }
    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(arg) {
        if(((struct ieee80211_vap_info *)arg)->chan) {
            vap->iv_des_chan[vap->iv_des_mode] = ((struct ieee80211_vap_info *)arg)->chan;
        }
        vap->iv_no_cac = ((struct ieee80211_vap_info *)arg)->no_cac;
    } else {
        vap->iv_no_cac = 0;
    }


    wlan_mlme_start_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
}

static void osif_restart_ap_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    struct net_device *dev;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    if(vap->iv_ic->recovery_in_progress) {
        /* recovery will bring down all VAPs.
         * reset here will modify the VAP list
         * which recovery is already using */
        return;
    }

    if((wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)) {
        return;
    }

    dev = OSIF_TO_NETDEV(osifp);
    if (dev == NULL) {
         return;
    }
    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(arg) {
        if(((struct ieee80211_vap_info *)arg)->chan) {
            vap->iv_des_chan[vap->iv_des_mode] = ((struct ieee80211_vap_info *)arg)->chan;
        }
        vap->iv_no_cac = ((struct ieee80211_vap_info *)arg)->no_cac;
    } else {
        vap->iv_no_cac = 0;
    }


    if (!osifp->is_delete_in_progress) {
        wlan_mlme_stop_start_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_MLME);
    }
}

static void osif_restart_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    struct net_device *dev;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    if(vap->iv_ic->recovery_in_progress) {
        /* recovery will bring down all VAPs.
         * reset here will modify the VAP list
         * which recovery is already using */
        return;
    }

    dev = OSIF_TO_NETDEV(osifp);
    if (dev == NULL) {
         return;
    }
    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(arg) {
        if(((struct ieee80211_vap_info *)arg)->chan) {
            vap->iv_des_chan[vap->iv_des_mode] = ((struct ieee80211_vap_info *)arg)->chan;
        }
        vap->iv_no_cac = ((struct ieee80211_vap_info *)arg)->no_cac;
    } else {
        vap->iv_no_cac = 0;
    }


    if (!osifp->is_delete_in_progress) {
        vap->iv_roam_inprogress = FALSE;
        wlan_mlme_stop_start_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_MLME);
    }
}

static void osif_bringdown_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    if(vap->iv_ic->recovery_in_progress) {
        /* recovery will bring down all VAPs.
         * bringing down here will modify the VAP list
         * which recovery is already using */
        return;
    }

    if (!((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
         (wlan_vap_get_opmode(vap) == IEEE80211_M_MONITOR)))
        return;

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode)
        return;
#endif

    wlan_mlme_stop_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
}

static void osif_bringdown_sta_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    if(vap->iv_ic->recovery_in_progress) {
        /* recovery will bring down all VAPs.
         * bringing down here will modify the VAP list
         * which recovery is already using */
        return;
    }

    if ((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
         (wlan_vap_get_opmode(vap) == IEEE80211_M_MONITOR))
        return;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    wlan_mlme_stacac_restore_defaults(vap);
#endif

    wlan_mlme_cm_stop(vap->vdev_obj, CM_OSIF_CFG_DISCONNECT,
                      REASON_STA_LEAVING, false);
}

static void osif_restart_start_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    struct net_device *dev;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    if(vap->iv_ic->recovery_in_progress) {
        /* recovery will bring down all VAPs.
         * reset here will modify the VAP list
         * which recovery is already using */
        return;
    }

    dev = OSIF_TO_NETDEV(osifp);
    if (dev == NULL) {
         return;
    }
    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(arg)
        vap->iv_des_chan[vap->iv_des_mode] = (struct ieee80211_ath_channel *)arg;

    if (vap->iv_opmode == IEEE80211_M_STA)
        wlan_mlme_cm_start(vap->vdev_obj, CM_OSIF_CONNECT);
    else
        wlan_mlme_start_vdev(vap->vdev_obj, 1, WLAN_MLME_NOTIFY_NONE);
}

static void osif_restart_start_ap_vap_iter_func(void *arg, wlan_if_t vap)
{
    if (!((wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
         (wlan_vap_get_opmode(vap) == IEEE80211_M_MONITOR))) {
        return;
    }

    if(arg)
        vap->iv_des_chan[vap->iv_des_mode] = (struct ieee80211_ath_channel *)arg;

    wlan_mlme_start_vdev(vap->vdev_obj, 1, WLAN_MLME_NOTIFY_NONE);
}

/*
 * osif_cmd_flush_cb(): cb function from scheduler context
 * @msg: scheduler msg data
 *
 * This cb will be called when a msg is being flushed from the scheduler queue
 *
 * Return: Success
 */
QDF_STATUS osif_cmd_flush_cb(struct scheduler_msg *msg)
{
    struct osif_cmd_sched_data *req = msg->bodyptr;

    wlan_objmgr_vdev_release_ref(req->vdev, WLAN_SCHEDULER_ID);
    qdf_mem_free(req);
    return QDF_STATUS_SUCCESS;
}

/*
 * osif_cmd_sched_cb(): cb function from scheduler context
 * @msg: scheduler msg data
 *
 * This is the cb from the scheduler context where MBSSID scenario
 * related vdev cmds are processed
 *
 * Return: Success if vdev cmd is processed else error.
 */
QDF_STATUS osif_cmd_sched_cb(struct scheduler_msg *msg)
{
    struct osif_cmd_sched_data *req = msg->bodyptr;
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(req->vdev);
    wlan_if_t tmpvap;
    wlan_dev_t comhandle;

    if (!vap) {
        qdf_err("NULL vap");
        wlan_objmgr_vdev_release_ref(req->vdev, WLAN_SCHEDULER_ID);
        qdf_mem_free(req);
        return QDF_STATUS_SUCCESS;
    }
    comhandle = vap->iv_ic;

    switch (req->cmd_type) {
    case OSIF_CMD_PDEV_START:
        bringup_vaps_event(comhandle);
        break;
    case OSIF_CMD_PDEV_STOP:
        bringdown_ap_vaps_event(comhandle);
        break;
    case OSIF_CMD_PDEV_STOP_START:
        bring_down_up_ap_vaps(comhandle);
        break;
    case OSIF_CMD_OTH_VDEV_STOP_START:
        TAILQ_FOREACH(tmpvap, &comhandle->ic_vaps, iv_next) {
            struct net_device *tmpvap_netdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            if ((tmpvap != vap) && IS_UP(tmpvap_netdev) &&
                    wlan_vdev_chan_config_valid(tmpvap->vdev_obj) == QDF_STATUS_SUCCESS) {
                osif_vap_init(tmpvap_netdev, RESCAN);
            }
        }
        break;
    case OSIF_CMD_VDEV_START:
        wlan_mlme_start_vdev(req->vdev, 0, WLAN_MLME_NOTIFY_NONE);
        break;
    case OSIF_CMD_STA_VAP_STOP:
        bringdown_sta_vaps_event(comhandle);
        break;
    case OSIF_CMD_STA_VAP_STOP_START:
        bringup_sta_vaps_event(comhandle);
        break;

    default:
        qdf_err("Unknown cmd type");
    }

    wlan_objmgr_vdev_release_ref(req->vdev, WLAN_SCHEDULER_ID);
    qdf_mem_free(req);
    return QDF_STATUS_SUCCESS;
}

/*
 * osif_cmd_schedule_req(): Form a scheduler msg to be posted for
 * vdev operations in MBSSID scenario
 * @vdev: Object manager vdev
 * @cmd_type: Serialization command type
 *
 * Return: Success if the request is posted to the scheduler, else error
 */
QDF_STATUS osif_cmd_schedule_req(struct wlan_objmgr_vdev *vdev,
        enum osif_cmd_type cmd_type)
{
    struct scheduler_msg msg = {0};
    struct osif_cmd_sched_data *req;
    QDF_STATUS ret = QDF_STATUS_E_FAILURE;

    if (!vdev)
        return QDF_STATUS_E_INVAL;

    req = qdf_mem_malloc(sizeof(*req));
    if (!req) {
        qdf_err("req is NULL");
        return ret;
    }

    ret = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SCHEDULER_ID);
    if (QDF_IS_STATUS_ERROR(ret)) {
        qdf_err("unable to get reference");
        goto sched_error;
    }

    req->vdev = vdev;
    req->cmd_type = cmd_type;

    msg.bodyptr = req;
    msg.callback = osif_cmd_sched_cb;
    msg.flush_callback = osif_cmd_flush_cb;

    ret = scheduler_post_message(QDF_MODULE_ID_OS_IF,
            QDF_MODULE_ID_OS_IF, QDF_MODULE_ID_OS_IF, &msg);
    if (QDF_IS_STATUS_ERROR(ret)) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
        qdf_err("failed to post scheduler_msg");
        goto sched_error;
    }
    return ret;

sched_error:
    qdf_mem_free(req);
    return ret;
}

static void osif_restart_stop_vap_iter_func(void *arg, wlan_if_t vap)
{
    vap->iv_roam_inprogress = FALSE;
    if (vap->iv_opmode == IEEE80211_M_STA)
        wlan_mlme_cm_stop(vap->vdev_obj,  CM_OSIF_CFG_DISCONNECT,
                          REASON_STA_LEAVING, false);
    else
        wlan_mlme_stop_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
}

void bringup_vaps_event(void *arg)
{
    wlan_dev_t comhandle = NULL;

    comhandle = (struct ieee80211com *)arg;
    wlan_iterate_vap_list(comhandle, bringup_ap_vaps, NULL);
}

void bringup_sta_vaps_event(void *arg)
{
    wlan_dev_t comhandle = NULL;

    comhandle = (struct ieee80211com *)arg;
    wlan_iterate_vap_list(comhandle, bringup_sta_vaps, NULL);
}

void osif_check_pending_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    if (!vap)
        return;

    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_PDEV_START);
}

void bringdown_ap_vaps_event(void *arg)
{
    wlan_dev_t comhandle = (struct ieee80211com *)arg;

    wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
}

void osif_bring_down_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    if (!vap)
        return;

    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_PDEV_STOP);
}

void bringdown_sta_vaps_event(void *arg)
{
    wlan_dev_t comhandle = (struct ieee80211com *)arg;

    wlan_iterate_vap_list(comhandle, osif_bringdown_sta_vap_iter_func, NULL);
}

void osif_bring_down_sta_vap(wlan_dev_t comhandle, wlan_if_t vap)
{
    if (!vap)
        return;

    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_STA_VAP_STOP);
}

void osif_restart_start_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    wlan_iterate_vap_list(comhandle, osif_restart_start_ap_vap_iter_func, NULL);
}

void osif_restart_stop_vaps(wlan_dev_t comhandle)
{
    wlan_iterate_vap_list(comhandle, osif_restart_stop_vap_iter_func, NULL);
}

void osif_restart_start_vaps(wlan_dev_t comhandle)
{
    wlan_iterate_vap_list(comhandle, osif_restart_start_vap_iter_func, NULL);
}

#if DBDC_REPEATER_SUPPORT
static void
osif_disconnect_repeater_clients(struct ieee80211com *ic)
{
    struct ieee80211com *tmp_ic;
    struct ieee80211vap *tmp_vap;
    u_int8_t only_rptr_clients = 0;
    int i;

    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK_BH(&ic_list);
        tmp_ic = ic_list.global_ic[i];
        GLOBAL_IC_UNLOCK_BH(&ic_list);
        if (tmp_ic) {
            TAILQ_FOREACH(tmp_vap, &tmp_ic->ic_vaps, iv_next) {
                if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                    (wlan_vdev_is_up(tmp_vap->vdev_obj) == QDF_STATUS_SUCCESS)) {
                    only_rptr_clients = 0x1;
                    wlan_iterate_station_list(tmp_vap, sta_disassoc, &only_rptr_clients);
                }
            }
        }
    }
    return;
}


/* This function is to avoid connection that happened due to race condition
   ie, both band sta vaps tries to scan and connect at same time*/
static int
osif_sta_vap_connection_validate(wlan_if_t vap, u_int8_t *bssid)
{
    struct ieee80211com *tmp_ic, *ic = vap->iv_ic;
    int i, flag=0;
    wlan_if_t tmp_stavap;

    if (!IS_NULL_ADDR(ic->ic_preferred_bssid) && OS_MEMCMP(ic->ic_preferred_bssid, bssid, QDF_MAC_ADDR_SIZE) != 0) {
        return 1;
    }
    if (((ic_list.extender_info & ROOTAP_ACCESS_MASK) != ROOTAP_ACCESS_MASK) && (ic_list.num_stavaps_up > 1)) {
        return 1;
    } else {
        if (!ic->ic_extender_connection) {
            /* When stavap connected to RootAP, clear preferred and denied mac list*/
            GLOBAL_IC_LOCK_BH(&ic_list);
            for (i=0; i < MAX_RADIO_CNT; i++) {
                OS_MEMZERO(&ic_list.preferred_list_stavap[i][0], QDF_MAC_ADDR_SIZE);
                OS_MEMZERO(&ic_list.denied_list_apvap[i][0], QDF_MAC_ADDR_SIZE);
            }
            GLOBAL_IC_UNLOCK_BH(&ic_list);
        }
        if (ic_list.ap_preferrence == 1) {
            /*make sure connecting to RootAP only*/
            if (ic->ic_extender_connection) {
                return 1;
            }
        } else if (ic_list.ap_preferrence == 2) {
            /* When first stavap connected to Repeater,
               and second stavap connected to RootAP,
               Then, disconnect first stavap, so that it will connect to RootAP*/
            if (!ic->ic_extender_connection) {
                GLOBAL_IC_LOCK_BH(&ic_list);
                ic_list.ap_preferrence = 1;
                GLOBAL_IC_UNLOCK_BH(&ic_list);
                for (i=0; i < MAX_RADIO_CNT; i++) {
                    GLOBAL_IC_LOCK_BH(&ic_list);
                    tmp_ic = ic_list.global_ic[i];
                    GLOBAL_IC_UNLOCK_BH(&ic_list);
                    if (tmp_ic && tmp_ic->ic_extender_connection) {
                        tmp_stavap = tmp_ic->ic_sta_vap;
                        IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(tmp_stavap, tmp_stavap->iv_bss->ni_macaddr, 0, IEEE80211_REASON_UNSPECIFIED);
                        osif_disconnect_repeater_clients(ic);
                    }
                }
                return 0;
            }
            /*make sure connecting to RE whose mac present in preferred bssid*/
            flag = 1;
            for (i=0; i < MAX_RADIO_CNT; i++) {
                if (OS_MEMCMP(vap->iv_bss->ni_macaddr, &ic_list.preferred_list_stavap[i][0], QDF_MAC_ADDR_SIZE) == 0) {
                    flag = 0;
                    break;
                }
            }
        }
    }
    return flag;
}
#endif

void bring_down_up_ap_vaps(void *arg)
{
    wlan_dev_t comhandle = (struct ieee80211com *)arg;

    wlan_iterate_vap_list(comhandle, osif_restart_ap_vap_iter_func, NULL);
}

void osif_bring_down_up_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    if (!vap)
        return;

    osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_PDEV_STOP_START);
}

static void osif_conn_sm_up_ev_hdl(os_if_t osif)
{
    osif_dev *osdev = (osif_dev *)osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
    wlan_dev_t ic = vap->iv_ic;
    union iwreq_data wreq;
    u_int8_t bssid[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
    enum ieee80211_phymode des_mode = wlan_get_desired_phymode(vap);
#if DBDC_REPEATER_SUPPORT
    int ret;
#endif

    qdf_mem_set(&wreq, sizeof(wreq), 0);
    wlan_vap_get_bssid(vap, bssid);

#if DBDC_REPEATER_SUPPORT
    if (ic_list.same_ssid_support && (vap == ic->ic_sta_vap)) {
        ret = osif_sta_vap_connection_validate(vap, bssid);
        if (ret) {
            wlan_mlme_connection_down(vap);
            return;
        }
    }
#endif

    wlan_mlme_connection_up(vap);
    if (ieee80211_ic_enh_ind_rpt_is_set(ic))
        wlan_determine_cw(vap, ic->ic_curchan);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap up ,connection up"
            " to bssid=%s, ifname=%s\n",
            __func__, ether_sprintf(bssid), dev->name);
    _netif_carrier_on(dev);

    if (!vap->iv_cfg80211_create)
        osif_send_assoc_resp_ies(dev);

    IEEE80211_ADDR_COPY(wreq.addr.sa_data, bssid);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
    /*
     * This flag is set to false during first association. This flag is used
     * in repeater mode and if this flag is set to flase, AP vaps are not brought
     * down from scan_ev_handler.
     */
    ieee80211_vap_reset_ap_vaps_clear(vap);

#if UMAC_SUPPORT_CFG80211
    if (vap->iv_cfg80211_create)
        ieee80211_cfg80211_send_connect_result(osdev, bssid, IEEE80211_STATUS_SUCCESS);
#endif
    /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
    /* No check required on pending AP VAPs for repeater move trigger by cloud */
    if ((!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
            !(ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {

#if DBDC_REPEATER_SUPPORT
        if (ieee80211_ic_rpt_max_phy_is_set(ic)) {
            qdf_debug("[rpt_max_phy]: delay bringing ap vaps up till node authorize");
        } else if (!ic_list.iface_mgr_up) {
            osif_check_pending_ap_vaps(ic, vap);
        }
#endif

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
        /* 11AX: Recheck future 802.11ax drafts (>D1.0) on coex rules
         */
        if ((wlan_vap_get_opmode(vap) == IEEE80211_M_STA ) && (vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
            ieee80211_is_phymode_g40(des_mode)) {
            if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
                if (!osdev->os_periodic_scan_period)
                    osdev->os_periodic_scan_period = OSIF_PERIODICSCAN_COEXT_PERIOD;
                osdev->os_scan_band = OSIF_SCAN_BAND_2G_ONLY;
                osif_periodic_scan_start(osif);
            } else {
                    osdev->os_periodic_scan_period = OSIF_PERIODICSCAN_DEF_PERIOD;
            }
        }
#endif
    }

    /* Update repeater move state to STOP once connection is up */
    if (ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)
        ic->ic_repeater_move.state = REPEATER_MOVE_STOP;
}

static void osif_conn_sm_down_ev_hdl(os_if_t osif,
        wlan_connection_sm_event *smevent)
{
    osif_dev *osdev = (osif_dev *)osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
    wlan_dev_t ic = vap->iv_ic;
    union iwreq_data wreq;
    u_int8_t bssid[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
    uint8_t auto_assoc = 0;
    int is_ap_cac_timer_running = 0;
#ifndef WLAN_CONV_CRYPTO_SUPPORTED
    u_int nmodes;
    ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :sta disconnected \n", __func__);

#if UMAC_SUPPORT_CFG80211
    auto_assoc = (vap->auto_assoc && !(vap->iv_cfg80211_create));
#else
    auto_assoc = vap->auto_assoc;
#endif

#if DBDC_REPEATER_SUPPORT
    if (ic_list.num_stavaps_up == 0)
        ic_list.rootap_access_downtime = OS_GET_TIMESTAMP();
#endif

    if (smevent->disconnect_reason == WLAN_CONNECTION_SM_ASSOC_REJECT) {
#if UMAC_SUPPORT_CFG80211
        if(vap->iv_cfg80211_create)
            ieee80211_cfg80211_send_connect_result(osdev, bssid, smevent->reasoncode);
#endif
    } else if (((smevent->disconnect_reason == WLAN_CONNECTION_SM_RECONNECT_TIMEDOUT) ||
                (smevent->disconnect_reason == WLAN_CONNECTION_SM_CONNECT_TIMEDOUT)) &&
            (auto_assoc || (osdev->authmode == IEEE80211_AUTH_AUTO))) {

        _netif_carrier_off(dev);
        /* Connection timed out - retry connection */
#if UMAC_SUPPORT_CFG80211
        if(vap->iv_cfg80211_create) {
#if UMAC_SUPPORT_WPA3_STA
            if (vap->iv_sta_external_auth_enabled) {
                ieee80211_cfg80211_send_connect_result(osdev, bssid, IEEE80211_STATUS_TIMEOUT);
                return;
            }
#endif
            ieee80211_cfg80211_disconnected(dev, WLAN_REASON_UNSPECIFIED);
        }
#endif

        if (osdev->authmode == IEEE80211_AUTH_AUTO) {
            /* If the auth mode is set to AUTO
             * switch between SHARED and AUTO mode
             */
            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, ((1 << WLAN_CRYPTO_AUTH_SHARED)))) {
                /*
                 *fix for CR#586870; The roaming should be set to
                 *AUTO so that the state machine is restarted
                 *for the connection to happen in OPEN mode.
                 */
                ieee80211com_set_roaming(ic, IEEE80211_ROAMING_AUTO);
                wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, 1 << WLAN_CRYPTO_AUTH_OPEN);
            } else {
                wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, 1 << WLAN_CRYPTO_AUTH_SHARED);
            }
        }

#if DBDC_REPEATER_SUPPORT
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
        /* Do not bring down VAPs for repeater move trigger by cloud */
        if ((!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
                !(ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
            /* Note: This should be moved to resource manager later */
            if (!ic_list.iface_mgr_up)
                osif_bring_down_vaps(ic, vap);
        }
#endif

        ucfg_dfs_is_ap_cac_timer_running(ic->ic_pdev_obj, &is_ap_cac_timer_running);
        if((ic->ic_roaming != IEEE80211_ROAMING_MANUAL) && (!is_ap_cac_timer_running))
            osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_VDEV_START);
    } else {
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
        /* Do not bring down VAPs for repeater move trigger by cloud */
        if ( (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
                !(ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
            /* Note: This should be moved to resource manager later */
#if DBDC_REPEATER_SUPPORT
            if (!ic_list.iface_mgr_up) {
                osif_bring_down_vaps(ic, vap);
            }
#endif
        }
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
        else {
            osif_periodic_scan_stop(osif);
        }
#endif
        /* bring down the vap only if it is not a restart */
        if (!osdev->is_restart) {
            memset(wreq.ap_addr.sa_data, 0, QDF_MAC_ADDR_SIZE);
            wreq.ap_addr.sa_family = ARPHRD_ETHER;
            WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
#if UMAC_SUPPORT_CFG80211
                /* Adding !vap->iv_roam_inprogress check for roaming to not to forward the
                   disconnect event to supplicant so that supplicant will not clear the
                   PMKID and it will be re-used in the reassociation with different AP.
                 */
                if(vap->iv_cfg80211_create && !vap->iv_roam_inprogress) {
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
                    if(vap->iv_psta) {
#else
                    if(dp_wrap_vdev_is_psta(vap->vdev_obj)) {
#endif
                            ucfg_scan_flush_results(vap->iv_ic->ic_pdev_obj, NULL);
                    }
#endif
                    ieee80211_cfg80211_disconnected(dev, WLAN_REASON_UNSPECIFIED);
               }
#endif
                _netif_carrier_off(dev);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            wlan_mlme_stacac_restore_defaults(vap);
#endif
            if (osdev->is_delete_in_progress) {
                OS_DELAY(5000);
                delete_default_vap_keys(vap);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : Keys Deleted \n",__func__);
            }
            vap->iv_needs_up_on_acs = 0;
        } else {
            osdev->is_restart = 0;
#if UMAC_SUPPORT_CFG80211
            if(vap->iv_cfg80211_create)
                ieee80211_cfg80211_disconnected(dev, WLAN_REASON_UNSPECIFIED);
#endif
            _netif_carrier_off(dev);
        }
    }
}

static void osif_conn_sm_lost_ev_hdlr(os_if_t osif)
{
    osif_dev *osdev = (osif_dev *)osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
#if DBDC_REPEATER_SUPPORT
    wlan_dev_t ic = vap->iv_ic;
#endif
    union iwreq_data wreq;

    qdf_mem_set(&wreq, sizeof(wreq), 0);
    /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
    if (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
        /* Note: This should be moved to resource manager later */
#if DBDC_REPEATER_SUPPORT
        if (!ic_list.iface_mgr_up) {
            osif_bring_down_vaps(ic, vap);
        }
#endif
    }
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    else {
        osif_periodic_scan_stop(osif);
    }
#endif

#ifdef __linux__
    if (wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
        qdf_mem_set(wreq.ap_addr.sa_data, QDF_MAC_ADDR_SIZE, 0);
        wreq.ap_addr.sa_family = ARPHRD_ETHER;
        WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
    }
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :connection lost \n", __func__);

}

static wlan_connection_sm_event_disconnect_reason
osif_cm_conn_to_sm_reason(enum wlan_cm_connect_fail_reason reason)
{
    switch (reason) {
    case CM_ASSOC_FAILED:
        return WLAN_CONNECTION_SM_ASSOC_REJECT;
        break;
    default:
        return WLAN_CONNECTION_SM_CONNECT_TIMEDOUT;
        break;
    }
}

static QDF_STATUS osif_cm_connect_complete(struct wlan_objmgr_vdev *vdev,
                                           struct wlan_cm_connect_resp *rsp,
                                           enum osif_cb_type type)
{
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);
    os_if_t osif;
    wlan_connection_sm_event smevent;

    if (!vap || !vap->iv_ifp)
        return QDF_STATUS_E_FAILURE;
    osif = vap->iv_ifp;

    if (type != OSIF_POST_USERSPACE_UPDATE)
        return QDF_STATUS_SUCCESS;

    if (QDF_IS_STATUS_SUCCESS(rsp->connect_status)) {
        /*
         * Connect success handler similar to connection_up
         * ASSOC_SUCCESS
         */
        osif_mlme_notify_handler(vap, WLAN_SER_CMD_VDEV_CONNECT);
        osif_conn_sm_up_ev_hdl(osif);
    } else {
        /*
         * Connect failure handler similar to connection_lost
         * NO CANDIDATE
         * JOIN_FAILED
         * AUTH_FAILED
         * AUTH_TIMEOUT
         * ASSOC_TIMEOUT
         * ASSOC_FAILED
         */
        osif_mlme_notify_handler(vap, WLAN_SER_CMD_VDEV_DISCONNECT);
        osif_conn_sm_lost_ev_hdlr(osif);

        /* Connect failure will also post down ev */
        smevent.reasoncode = rsp->status_code;
        smevent.disconnect_reason = osif_cm_conn_to_sm_reason(rsp->reason);
        osif_conn_sm_down_ev_hdl(osif, &smevent);
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS osif_cm_disconnect_complete(struct wlan_objmgr_vdev *vdev,
                                              struct wlan_cm_discon_rsp *rsp,
                                              enum osif_cb_type type)
{
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);
    os_if_t osif;
    wlan_connection_sm_event smevent;

    if (!vap || !vap->iv_ifp)
        return QDF_STATUS_E_FAILURE;
    osif = vap->iv_ifp;

    if (type != OSIF_POST_USERSPACE_UPDATE)
        return QDF_STATUS_SUCCESS;

    /*
     * Disconnect and connect failure handler similar to connection_down
     * OSIF_DISCONNECT
     * STA_KICKOUT
     * PEER_DISCONNECT
     */
    osif_mlme_notify_handler(vap, WLAN_SER_CMD_VDEV_DISCONNECT);

    smevent.reasoncode = rsp->req.req.reason_code;
    smevent.disconnect_reason = WLAN_CONNECTION_SM_DISCONNECT_REQUEST;

    osif_conn_sm_down_ev_hdl(osif, &smevent);

    return QDF_STATUS_SUCCESS;
}

struct osif_cm_ops osif_ops = {
    .connect_complete_cb = osif_cm_connect_complete,
    .disconnect_complete_cb = osif_cm_disconnect_complete,
};

static QDF_STATUS osif_cm_register_legacy_cb(void)
{
    osif_cm_set_legacy_cb(&osif_ops);
    return osif_cm_register_cb();
}

void
osif_replay_failure_indication(os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    static const char * tag = "MLME-REPLAYFAILURE.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frm;
    union iwreq_data wrqu;
    char buf[128];

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
        "%s: replay detected <keyix %d>\n",
        ether_sprintf(wh->i_addr2), keyix);

    /* TODO: needed parameters: count, keyid, key type, src address, TSC */
    snprintf(buf, sizeof(buf), "%s(keyid=%d %scast addr=%s)", tag,
        keyix, IEEE80211_IS_MULTICAST(wh->i_addr1) ?  "broad" : "uni",
        ether_sprintf(wh->i_addr1));
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
}
/*Event trigger when receive one packet with MIC error*/
void
osif_michael_failure_indication(os_handle_t osif, const uint8_t *ta_mac_addr,
        u_int keyix)
{
    static const char *tag = "MLME-MICHAELMICFAILURE.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    union iwreq_data wrqu;
    char buf[128];
    struct ev_msg msg;

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
        "%s: Michael MIC verification failed <keyix %d>",
        ether_sprintf(ta_mac_addr), keyix);

#if UMAC_SUPPORT_CFG80211
    if(vap && vap->iv_cfg80211_create) {
       cfg80211_michael_mic_failure(dev, ta_mac_addr, NL80211_KEYTYPE_PAIRWISE,
                                    keyix, NULL, GFP_KERNEL);
    }
    else
#endif
    {
       /* TODO: needed parameters: count, keyid, key type, src address, TSC */
       snprintf(buf, sizeof(buf), "%s(keyid=%d addr=%s)", tag,
                keyix, ether_sprintf(ta_mac_addr));
       memset(&wrqu, 0, sizeof(wrqu));
       wrqu.data.length = strlen(buf);
       wrqu.data.flags = 0;            /*hostapd use this event and expects this flags to be 0.*/
       WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);

       IEEE80211_ADDR_COPY(msg.addr, ta_mac_addr);
       memset(&wrqu, 0, sizeof(wrqu));
       wrqu.data.flags = IEEE80211_EV_MIC_ERR_IND_AP;    /*Sends two event for backward support.*/
       wrqu.data.length = sizeof(msg);
       WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu,(char*)&msg);
    }
}
/*Event trigger when WPA unicast key setting*/
void
osif_keyset_done_indication(os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    struct ev_msg msg;

    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_KEYSET_DONE_IND_AP;
    wrqu.data.length = sizeof(msg);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
}
/*Event trigger when received AUTH request from one STA and this STA is in the blacklist */
void
osif_blklst_sta_auth_indication(os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    struct ev_msg msg;
    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_BLKLST_STA_AUTH_IND_AP;
    wrqu.data.length = sizeof(msg);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static void osif_sta_cac_started (os_handle_t osif, u_int32_t frequency, u_int32_t timeout)
{
	static const char *tag = "CAC.started";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    char buf[128];

    /* TODO: needed parameters: count, keyid, key type, src address, TSC */
    snprintf(buf, sizeof(buf), "%s freq=%u timeout=%d", tag,
        frequency, timeout);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
}
#endif

void
osif_notify_push_button(osdev_t osdev, u_int32_t push_time)
{
    struct net_device *dev = osdev->netdev;
    static char *tag = "PUSH-BUTTON.indication";
    union iwreq_data wrqu;
    char buf[128];

#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;

	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;
#endif

    snprintf(buf, sizeof(buf), "%s Push dur=%d", tag, push_time);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
#if UMAC_SUPPORT_ACFG
	acfg_send_event(dev, osdev, WL_EVENT_TYPE_PUSH_BUTTON, acfg_event);
	qdf_mem_free(acfg_event);
#endif
}

int
ieee80211_load_module(const char *modname)
{
    request_module(modname);
    return 0;
}

static void osif_channel_change (os_handle_t osif, wlan_chan_t chan)
{
#if UMAC_SUPPORT_ACFG || QCA_SUPPORT_SON || UMAC_SUPPORT_CFG80211
    osif_dev  *osdev = (osif_dev *) osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
#endif

#if UMAC_SUPPORT_ACFG || UMAC_SUPPORT_CFG80211
    struct ieee80211com *ic = vap->iv_ic;
#endif

#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
    osdev_t  os_handle = ((osif_dev *)osif)->os_handle;
#endif
#if QCA_SUPPORT_SON
    union iwreq_data wreq;
    struct chan_change_evt_t chan_det;
#endif
#if UMAC_SUPPORT_CFG80211
    struct ieee80211_channel *nl_chan;
    uint16_t chan_freq = 0;
#endif

#if UMAC_SUPPORT_ACFG
    if (!os_handle) {
        return;
    }
	acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
	if (acfg_event == NULL)
		return;

    memset(acfg_event, 0, sizeof(acfg_event_data_t));

    if ((!chan) || (chan == IEEE80211_CHAN_ANYC))
        acfg_event->freqs[0] = 0;
    else
        acfg_event->freqs[0] = wlan_channel_frequency(chan);

    if(ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING){
        acfg_event->reason = ACFG_CHAN_CHANGE_DFS;
    }else{
        acfg_event->reason = ACFG_CHAN_CHANGE_NORMAL;
    }

    acfg_send_event(dev, os_handle, WL_EVENT_TYPE_CHAN, acfg_event);
	qdf_mem_free(acfg_event);
#endif

#if QCA_SUPPORT_SON
    // Band steering needs to be notified of channel change events so that
    // it can stop it and then re-enable once any ACS/CAC logic has completed.
    // Although this could have been done with a band steering event, a generic
    // link event seemed more consistent as a user-initiated channel change
    // already generates a link event (of type SIOCSIWFREQ).

    if(wlan_scan_in_progress(vap)) {
        return;
    }

    OS_MEMSET(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_CHAN_CHANGE;
    wreq.data.length = sizeof(chan_det);
    if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
        chan_det.channel = 0;
        chan_det.freq = 0;
    } else {
        chan_det.channel = wlan_channel_ieee(chan);
        chan_det.freq = wlan_channel_frequency(chan);
    }
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq,
                        (char *)&chan_det);
#endif

#if UMAC_SUPPORT_CFG80211
    if((vap->iv_cfg80211_create) && (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        if(wlan_scan_in_progress(vap)) {
            return;
        }
        if (chan) {
            chan_freq = wlan_channel_frequency(chan);
        }
        nl_chan = ieee80211_get_channel(ic->ic_wiphy, chan_freq);
        if (!nl_chan) {
            qdf_print("%s: ieee80211_get_channel Failed .....", __func__);
            return;
        }
        ieee80211_cfg80211_construct_chandef(&vap->chandef_notify, nl_chan, chan);
        qdf_sched_work(dev, &vap->cfg80211_channel_notify_workq);
    }
#endif
}

#if QCA_SUPPORT_SON
static void osif_buffull_warning (os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    vap = osdev->os_if;
    son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_BUFFULL, NULL);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: buffull \n", __func__);

}
#endif

static void osif_country_changed (os_handle_t osif, char *country)
{

}

static void osif_receive (os_if_t osif, wbuf_t wbuf,
                        u_int16_t type, u_int16_t subtype,
                        ieee80211_recv_status *rs)
{
    struct sk_buff *skb = (struct sk_buff *)wbuf;

    if (type != IEEE80211_FC0_TYPE_DATA) {
        if(wbuf_next(wbuf) != NULL) {
            wbuf_t wbx = wbuf;
            while (wbx) {
                wbuf = wbuf_next(wbx);
                wbuf_free(wbx);
                wbx = wbuf;
            }
        } else {
            wbuf_free(wbuf);
        }
        return;
    }
    /* deliver the data to network interface */
    __osif_deliver_data(osif, skb);
}

#if ATH_RX_INFO_EN
static void osif_send_mgmt_rx_info_event(os_handle_t osif, wbuf_t wbuf, ieee80211_recv_status *rs)
{
    osif_dev  *osdev = (osif_dev *) osif;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event;
#endif
    struct sk_buff *skb = (struct sk_buff *)wbuf;
    struct net_device *dev = osdev->netdev;
    acfg_mgmt_rx_info_t *mgmt_ri = NULL;
    int len = 0;
    static u_int32_t acfg_limit_print = 0;

    /*Drop event eariler here if acfg_event_list is full*/
    qdf_spin_lock_bh(&(osdev->os_handle->acfg_event_queue_lock));
    if(qdf_nbuf_queue_len(&(osdev->os_handle->acfg_event_list)) >= ACFG_EVENT_LIST_MAX_LEN){
        qdf_spin_unlock_bh(&(osdev->os_handle->acfg_event_queue_lock));
        if(!(acfg_limit_print % ACFG_EVENT_PRINT_LIMIT)){
        qdf_print("Work queue full, drop acfg event!");
        }
        ++acfg_limit_print;
        return;
    }
    qdf_spin_unlock_bh(&(osdev->os_handle->acfg_event_queue_lock));

#if UMAC_SUPPORT_ACFG
    acfg_event = OS_MALLOC(osdev->os_handle, sizeof(acfg_event_data_t), GFP_KERNEL);
    if (acfg_event == NULL){
        return;
    }
    OS_MEMZERO(acfg_event, sizeof(acfg_event_data_t));

    mgmt_ri = &(acfg_event->mgmt_ri);
    mgmt_ri->ri_channel = rs->rs_channel;
    mgmt_ri->ri_rssi = rs->rs_snr;
    mgmt_ri->ri_datarate = rs->rs_datarate;
    mgmt_ri->ri_flags = rs->rs_flags;
    len = ((skb->len)>MGMT_FRAME_MAX_SIZE) ? MGMT_FRAME_MAX_SIZE: skb->len;
    OS_MEMCPY(mgmt_ri->raw_mgmt_frame, skb->data, len);

    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_MGMT_RX_INFO, acfg_event);

    OS_FREE(acfg_event);
#endif
}
#endif

void
osif_update_dfs_info_to_app(struct ieee80211com *ic, char *buf)
{
    struct ieee80211vap *vap;
    union iwreq_data wrqu;
    struct net_device *dev = NULL;

    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
            continue;
        }
        if (vap->channel_switch_state) {
            continue;
        }

        dev = ((osif_dev *)vap->iv_ifp)->netdev;

        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.length = strlen(buf);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
    }
    IEEE80211_COMM_UNLOCK(ic);
}

/* From Atheros version:
* //depot/sw/releases/linuxsrc/src/802_11/madwifi/madwifi/net80211/ieee80211_input.c
*
* This is an entirely different approach which uses "wireless events"...
*/
#define GET_BE16(a) ((u16) (((a)[0] << 8) | (a)[1]))
#define ELEMENT_TYPE 0x1012

int push_method(const u_int8_t *frm)
{
     int len=6;
     int rc = 0;

     while ((len+4) < frm[1] ) {
        if((GET_BE16(frm+len) == ELEMENT_TYPE) && (frm[len+3] ==2)&& (GET_BE16(frm+len+4)== 0x0004))
        {
            rc = 1;
            qdf_print("wps pb detected");
            return rc;
        } else {
          len += frm[len+3]+4;
        }
     }
     return rc;
}

void osif_forward_mgmt_to_app(os_if_t osif, wbuf_t wbuf,
                                        u_int16_t type, u_int16_t subtype, ieee80211_recv_status *rs)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    struct sk_buff *skb = (struct sk_buff *)wbuf;
    osif_dev  *osifp = (osif_dev *) osif;
    wlan_if_t vap = osifp->os_if;

    int filter_flag =0;
#ifndef MGMT_FRAM_TAG_SIZE
#define MGMT_FRAM_TAG_SIZE 30 /* hardcoded in atheros_wireless_event_wireless_custom */
#endif
    char *tag=NULL;
    char *wps_tag = NULL;
    #if 0       /* should be, but IW_CUSTOM_MAX is only 256 */
    const int bufmax = IW_CUSTOM_MAX;
    #else       /* HACK use size for IWEVASSOCREQIE instead */
    const int bufmax = IW_GENERIC_IE_MAX;
    #endif

    /* forward only if app filter is enabled */
    if (!osifp->app_filter){
        return;
    }

    switch (subtype)
    {
    case IEEE80211_FC0_SUBTYPE_BEACON:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_BEACON;
        tag = "Manage.beacon";
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        /* HACK: Currently only WPS needs Probe reqs,
         * so forward WPS frames only */
        if (!wlan_frm_haswscie(wbuf) &&
            !wlan_get_param(vap, IEEE80211_TRIGGER_MLME_RESP)) {
            break;
        }
        if (!wlan_get_param(vap, IEEE80211_WPS_MODE) &&
            (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)) {
            break;
        }

        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_PROBE_REQ;
        tag = "Manage.prob_req";
        if(IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap))// && IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) /*orbi_ie*/)
        {
            struct ieee80211_frame *wh;
            u_int8_t *frm, *efrm;

            wh = (struct ieee80211_frame *) wbuf_header(wbuf);
            frm = (u_int8_t *)&wh[1];
            efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

            while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
                if (iswpsoui(frm) && push_method(frm))
                {
                    wps_tag = "Manage.prob_req_wps";
                    break;
                }
                else
                    wps_tag = NULL;
                frm += frm[1] + 2;
            }
        }
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_PROBE_RESP;
        tag = "Manage.prob_resp";
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ASSOC_REQ;
        tag = "Manage.assoc_req";
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ASSOC_RESP;
        tag = "Manage.assoc_resp";
        break;
    case IEEE80211_FC0_SUBTYPE_AUTH:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_AUTH;
        tag = "Manage.auth";
        break;
    case IEEE80211_FC0_SUBTYPE_DEAUTH:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_DEAUTH;
        tag = "Manage.deauth";
        break;
    case IEEE80211_FC0_SUBTYPE_DISASSOC:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_DISASSOC;
        tag = "Manage.disassoc";
        break;
    case IEEE80211_FC0_SUBTYPE_ACTION:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ACTION;
        tag = "Manage.action";
        break;
    default:
        break;
    }
    if (filter_flag)
    {
        union iwreq_data wrqu;
        char *buf;
        size_t bufsize = MGMT_FRAM_TAG_SIZE + skb->len;

        if(bufsize > bufmax) {
            qdf_print("FIXME:%s: Event length more than expected..dropping", __FUNCTION__);
            return;
        }
        buf = OS_MALLOC(osifp->os_handle, bufsize, GFP_KERNEL);
        if (buf == NULL) return;
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        wrqu.data.length = bufsize;
        OS_MEMZERO(buf, bufsize);
        snprintf(buf, MGMT_FRAM_TAG_SIZE, "%s %d", tag, skb->len);
        OS_MEMCPY(buf+MGMT_FRAM_TAG_SIZE, skb->data, skb->len);
        #if 0   /* the way it should? be */
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
        #else   /* HACK to get around 256 byte limit of IWEVCUSTOM */
        /* Note: application should treat IWEVASSOCREQIE same as IWEVCUSTOM
        * and should check for both.
        * IWEVASSOCREQIE is not used for anything (else) at least
        * not for Atheros chip driver.
        */

//        IEEE80211_DPRINTF(NULL, IEEE80211_MSG_IOCTL, "%s : filter_flag=%x, subtype=%x\n",
//                                      __func__,osifp->app_filter,subtype);
        WIRELESS_SEND_EVENT(dev, IWEVASSOCREQIE, &wrqu, buf);
        #endif
        OS_FREE(buf);

#if ATH_RX_INFO_EN
        if (rs)
            osif_send_mgmt_rx_info_event(osif, skb, rs);
#endif
    }

    if(wps_tag != NULL)
    {
        union iwreq_data wrqu;
        char *buf;
        size_t bufsize = MGMT_FRAM_TAG_SIZE + skb->len;

        if(bufsize > bufmax) {
            qdf_print("FIXME:%s: Event length more than expected..dropping", __FUNCTION__);
            return;
        }
        buf = OS_MALLOC(osifp->os_handle, bufsize, GFP_KERNEL);
        if (buf == NULL) return;
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        wrqu.data.length = bufsize;
        OS_MEMZERO(buf, bufsize);
        snprintf(buf, MGMT_FRAM_TAG_SIZE, "%s %d", wps_tag, skb->len);
        OS_MEMCPY(buf+MGMT_FRAM_TAG_SIZE, skb->data, skb->len);
        WIRELESS_SEND_EVENT(dev, IWEVASSOCREQIE, &wrqu, buf);
        OS_FREE(buf);

#if ATH_RX_INFO_EN
        if (rs)
            osif_send_mgmt_rx_info_event(osif, skb, rs);
#endif
    }

#undef  MGMT_FRAM_TAG_SIZE
}


static int  osif_receive_filter_80211 (os_if_t osif, wbuf_t wbuf,
                                        u_int16_t type, u_int16_t subtype,
                                        ieee80211_recv_status *rs)
{
#if UMAC_SUPPORT_CFG80211
    osif_dev *osifp = (osif_dev *)osif;
    struct sk_buff *skb = (struct sk_buff *)wbuf;
    bool result = true ;
    struct ieee80211_frame *wh;
    wlan_if_t vap = osifp->os_if;
#endif
    if (type == IEEE80211_FC0_TYPE_MGT && wbuf) {
        osif_forward_mgmt_to_app(osif, wbuf, type, subtype, rs);
#if UMAC_SUPPORT_CFG80211
        if(vap->iv_cfg80211_create) {
            wlan_vendor_fwd_mgmt_frame(vap, skb, subtype);
            wh = (struct ieee80211_frame *) wbuf_header(wbuf);
            switch(subtype ) {
                case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
                    /* HACK: Currently only WPS needs Probe reqs,
                     * so forward WPS frames only */

                    if (!wlan_get_param(vap, IEEE80211_WPS_MODE) ){
                        break;
                    }
                case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
                case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
                case IEEE80211_FC0_SUBTYPE_AUTH:
                case IEEE80211_FC0_SUBTYPE_ACTION:
                case IEEE80211_FC0_SUBTYPE_DISASSOC:
                case IEEE80211_FC0_SUBTYPE_DEAUTH:
                    /* Deliver to cfg80211 only if the netdevice is registered
                     * with Kernel */
                    if ( ieee80211_vap_registered_is_set(vap) ) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
                        result = cfg80211_rx_mgmt(&(osifp->iv_wdev),
                                rs?rs->rs_freq:vap->iv_ic->ic_curchan->ic_freq,
                                0, (u8 *)skb->data, skb->len, 0);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0))
                        result = cfg80211_rx_mgmt(&(osifp->iv_wdev),
                                rs?rs->rs_freq:vap->iv_ic->ic_curchan->ic_freq,
                                0, (u8 *)skb->data, skb->len, 0, GFP_ATOMIC);
#endif /* LINUX_VERSION_CODE */
                    }
                    if (!result) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_CFG80211,
                             "cfg80211_rx_mgmt for subtype:%0x to %s failed\n",
                              subtype,ether_sprintf(wh->i_addr2));
                        return 1;
                    }
                    break;
                default :
                    break;
            }
        }
#endif
    }
    return 0;
}

/*
 * osif_monitor_get_80211_header(): Function to retrieve IEEE80211 header
 * from received buffer in monitor mode
 * @wbuf: Received nbuf
 *
 * This function is called to retrieve IEEE80211 header from the received nbuf
 * in the monitor mode. This function is to be called only for the Lithium
 * family
 *
 * Return: Pointer to IEEE80211 header
 */
static
struct ieee80211_qosframe_addr4 *osif_monitor_get_80211_header(wbuf_t wbuf)
{
    struct ieee80211_qosframe_addr4 *qwh;

#ifdef DP_RX_MON_MEM_FRAG
    /**
     * Frag at index 0 gives IEEE80211 header if wbuf has frags attached
     * in monitor frag approach
     */
    if (qdf_nbuf_get_nr_frags(wbuf)) {
        qwh = (struct ieee80211_qosframe_addr4 *)qdf_nbuf_get_frag_addr(wbuf,0);
    } else
#endif
    {
        /* Get IEEE80211 header from wbuf header */
        u_int16_t radiotap_header_len;
        struct ieee80211_radiotap_header *t_rd_hdr1;

        t_rd_hdr1 = (struct ieee80211_radiotap_header *)wbuf_header(wbuf);
        radiotap_header_len = qdf_le16_to_cpu(t_rd_hdr1->it_len);
        qwh = (struct ieee80211_qosframe_addr4 *)(wbuf_header(wbuf) +
                                                  radiotap_header_len);
    }
    return qwh;
}

static int
mgmt_crypto_decap(wbuf_t wbuf, struct ieee80211com *ic,struct ieee80211vap *vap)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_crypto_rx_ops *crypto_rx_ops;
    struct ieee80211_frame *wh;

    pdev = ic->ic_pdev_obj;
    psoc = wlan_pdev_get_psoc(pdev);
    crypto_rx_ops = wlan_crypto_get_crypto_rx_ops(psoc);
    if (crypto_rx_ops && WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)) {
        if (WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)(vap->vdev_obj,
               wbuf, vap->mcast_encrypt_addr, 0) == QDF_STATUS_SUCCESS) {
               wh = (struct ieee80211_frame *)wbuf_header(wbuf);
               wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
        }
    }

    return 0;
}

void osif_receive_monitor_80211_base (os_if_t osif, wbuf_t wbuf, void *rs)
{
    osif_dev *osifp = (osif_dev *)osif;
    struct ieee80211vap *vap = osifp->os_if;
    struct sk_buff *skb;
    int found = 0;
    struct net_device *dev = osifp->netdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = &osifp->os_devstats;
#else
    struct rtnl_link_stats64 *stats = &osifp->os_devstats;
#endif
    struct ieee80211com *ic = wlan_vap_get_devhandle(vap);
    u_int32_t target_type = ic->ic_get_tgt_type(ic);
    u_int16_t radiotap_header_len = 0;
    struct ieee80211_radiotap_header *t_rd_hdr1 = NULL;

    /* Decryption of the packet is not required in specialvap(ap_monitor) mode */
    if(!vap->iv_special_vap_mode) {
        struct ieee80211_qosframe_addr4 *qwh;
        /*
         * For lithium targets, the radiotap header is present at the
         * wbuf_header. For non-lithium targets, it is added later below
         */
        if (target_type >= TARGET_TYPE_QCA8074) {
            t_rd_hdr1 = (struct ieee80211_radiotap_header *)wbuf_header(wbuf);
            radiotap_header_len = qdf_le16_to_cpu(t_rd_hdr1->it_len);
            qwh = osif_monitor_get_80211_header(wbuf);
        } else {
            qwh = (struct ieee80211_qosframe_addr4 *)wbuf_header(wbuf);
        }
        if (qdf_unlikely(qwh->i_fc[1] == (IEEE80211_FC1_DIR_DSTODS |  IEEE80211_FC1_WEP))) {
            if(IEEE80211_ADDR_IS_VALID(vap->mcast_encrypt_addr)){
                if (IEEE80211_ADDR_EQ(qwh->i_addr1,vap->mcast_encrypt_addr)) {
                    uint8_t *rtap_buf;
                    if (qdf_nbuf_is_nonlinear(wbuf) &&
                        qdf_nbuf_get_nr_frags(wbuf)) {
                        /* Make copy of wbuf to get nbuf with linear data */
                        qdf_nbuf_t nbuf_p = qdf_nbuf_copy(wbuf);
                        qdf_nbuf_free(wbuf);

                        if (!nbuf_p) {
                            qdf_err("NBUF copy failed");
                            return;
                        }
                        wbuf = nbuf_p;
                    }
                    rtap_buf = (uint8_t *)qdf_mem_malloc((sizeof(struct ieee80211_radiotap_header)) +
                               radiotap_header_len);
                    qdf_mem_copy(rtap_buf, qdf_nbuf_data(wbuf), radiotap_header_len);
                    qdf_nbuf_pull_head(wbuf, radiotap_header_len);
                    mgmt_crypto_decap(wbuf,ic,vap);
                    qdf_nbuf_push_head(wbuf, radiotap_header_len);
                    qdf_mem_copy(qdf_nbuf_data(wbuf), rtap_buf, radiotap_header_len);
                    qdf_mem_free(rtap_buf);
                }
            }
        }
    }
    skb = (struct sk_buff *)wbuf;

#if ATH_SUPPORT_NAC

    if (vap->iv_smart_monitor_vap) {
        int i,j;
        char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int max_addrlimit = NAC_MAX_CLIENT;
	uint16_t rtap_len;
	struct ieee80211_radiotap_header *radiotap_hdr = NULL;
        struct ieee80211_nac_info  *nac_list = vap->iv_nac.client;
        struct ieee80211_qosframe_addr4 *qwh = NULL;

        /* For non-lithium targets, radiotap is filled after this point
         * and nbuf has wireless header.
         * But for lithium targets, radiotap is already populated and
         * skb has payload starting from radiotap hdr. Hence we move skb
         * pointer by radiotap length offset to get to wireless header.
         */
        if (target_type >= TARGET_TYPE_QCA8074) {
            radiotap_hdr = (struct ieee80211_radiotap_header *)wbuf_header(skb);
            rtap_len = le16_to_cpu(radiotap_hdr->it_len);
            qwh = (struct ieee80211_qosframe_addr4 *)(wbuf_header(skb) + rtap_len);
        } else {
            qwh = (struct ieee80211_qosframe_addr4 *)wbuf_header(skb);
        }
        for(i=0,j=0; i < max_addrlimit && j < max_addrlimit; i++) {

            if (IEEE80211_IS_MULTICAST((char *)(nac_list +i)->macaddr) ||
                IEEE80211_ADDR_EQ((char *)(nac_list +i)->macaddr, nullmac)) {
                continue;
            }

            if(OS_MEMCMP(qwh->i_addr2 , (nac_list +i)->macaddr, QDF_MAC_ADDR_SIZE)==0) {
                if (target_type < TARGET_TYPE_QCA8074) {
                    (nac_list +i)->rssi = ((ieee80211_recv_status *)rs)->rs_snr;
                } else {
                    /* For lithium targets rs struct passed may be NULL or have different format
                     * therefore we retrieve rssi from DP's neighbour peer struct
                     */
                    vap->iv_neighbour_rx(vap , i, IEEE80211_NAC_PARAM_LIST, IEEE80211_NAC_MACTYPE_CLIENT, (nac_list +i)->macaddr);
                }
                // Calculating the moving average of RSSI samples
                if ((nac_list + i)->avg_rssi != 0) {
                    (nac_list + i)->avg_rssi =
                    ((nac_list + i)->avg_rssi -
                    (A_RSSI)(((A_UINT8)((nac_list + i)->avg_rssi)) >> 2)) +
                    (A_RSSI)(((A_UINT8)((nac_list + i)->rssi)) >> 2);
                } else {
                    // First sample
                    (nac_list + i)->avg_rssi = (nac_list + i)->rssi;
                }

                if ((nac_list + i)->avg_rssi != 0) {
                    (nac_list + i)->rssi_measured_time = OS_GET_TIMESTAMP();
                } else {
                    // Adding this check to prevent stale rssi time
                    // for invalid rssi value
                    (nac_list + i)->rssi_measured_time = 0;
                }
                break;
            }

            j++;
        }
    }
#endif

    IEEE80211_VAP_LOCK(vap);
    if ((ic->mon_filter_osif_mac == 1) && vap->mac_entries) {
        int hash;
        struct ieee80211_qosframe_addr4 *qwh = NULL;
        struct ieee80211_mac_filter_list *mac_en;

        if (target_type >= TARGET_TYPE_QCA8074) {
            qwh = osif_monitor_get_80211_header(wbuf);
        } else {
            qwh = (struct ieee80211_qosframe_addr4 *)wbuf_header(skb);
        }
        hash = MON_MAC_HASH(qwh->i_addr1);
        LIST_FOREACH(mac_en, &vap->mac_filter_hash[hash], mac_entry) {
            if (mac_en->mac_addr != NULL) {
                if (IEEE80211_ADDR_EQ(qwh->i_addr1, mac_en->mac_addr)){
                    found = 1;
                    break;
                }
            }
        }
    }
    IEEE80211_VAP_UNLOCK(vap);

    if (qdf_likely(ic->ic_mon_decoder_type == MON_DECODER_RADIOTAP)) {
        /* For non lithium targets radiotap hdr has to be added here */
        if (target_type < TARGET_TYPE_QCA8074)
            osif_mon_add_radiotap_header(osif, skb, ((ieee80211_recv_status *)rs));
        skb->protocol = __constant_htons(ETH_P_802_2);
    } else {
        /* For non lithium targets prism hdr has to be added here */
        if (target_type < TARGET_TYPE_QCA8074)
            osif_mon_add_prism_header(osif, skb, ((ieee80211_recv_status *)rs));
        skb->protocol = __constant_htons(ETH_P_80211_RAW);
    }

    skb->dev = dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif
    skb->ip_summed = CHECKSUM_NONE;
    skb->pkt_type = PACKET_OTHERHOST;

    skb_orphan(skb);
    if (ic->mon_filter_osif_mac == 1) {
        /*If osif MAC addr based filter enabled,*/
        /*only input pkts from specified MAC*/
        if (qdf_unlikely(found == 1)) {
            nbuf_debug_del_record(skb);
            stats->rx_packets++;
            stats->rx_bytes += skb->len;
            netif_rx(skb);
        } else {
            qdf_nbuf_free(skb);
        }
    }else{
        nbuf_debug_del_record(skb);
        stats->rx_packets++;
        stats->rx_bytes += skb->len;
        netif_rx(skb);
    }
}
qdf_export_symbol(osif_receive_monitor_80211_base);

void osif_receive_monitor_80211 (os_if_t osif, wbuf_t wbuf,
                                        ieee80211_recv_status *rs)
{
    /* This breaks for man reasons
     * 1. Doesnt handle the generic fraglist skb case
     * 2. Doesnt handled non FCS trailers like encryption
     * Change model to have lower layer call in with non-trailer added
     * packet length
     */
    ((struct sk_buff *) wbuf)->len -= 4;
    osif_receive_monitor_80211_base(osif, wbuf, rs);
}


#if ATH_SUPPORT_FLOWMAC_MODULE
int
dev_queue_status(struct net_device *dev, int margin)
{
	struct Qdisc *fifoqdisc;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    struct netdev_queue *txq;
#endif
    int qlen = 0;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    txq = netdev_get_tx_queue(dev, 0);
    ASSERT((txq != NULL));
    fifoqdisc = txq->qdisc;
#else
	fifoqdisc = rcu_dereference(dev->qdisc);
#endif

    qlen = skb_queue_len(&fifoqdisc->q);
    if ((dev->tx_queue_len > margin) &&
            (qlen > dev->tx_queue_len - margin)) {
        return -ENOBUFS;
    }
    return 0;
}
int
dev_queue_length(struct net_device *dev)
{
	struct Qdisc *fifoqdisc;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    struct netdev_queue *txq;
#endif
    int qlen = 0;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    txq = netdev_get_tx_queue(dev, 0);
    ASSERT((txq != NULL));
    fifoqdisc = txq->qdisc;
#else
	fifoqdisc = rcu_dereference(dev->qdisc);
#endif
    qlen = skb_queue_len(&fifoqdisc->q);
    return qlen;
}
#endif

/*
* hand over the wbuf to the com device (ath dev).
*/
static int
osif_dev_xmit_queue (os_if_t osif, wbuf_t wbuf)
{
    int err;
    struct net_device *comdev;
    struct sk_buff *skb = (struct sk_buff *)wbuf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    struct ieee80211_cb * cb = NULL;
#endif

    int rval=0;
    comdev = ((osif_dev *)osif)->os_comdev;

    skb->dev = comdev;
    /*
     * rval would be -ENOMEM if there are 1000-128 frames left in the backlog
     * queue. We return this value out to the caller. The assumption of
     * caller is to make sure that he stalls the queues just after this. If
     * we do not let this frame out, node_ref issues might show up.
     */
#if ATH_SUPPORT_FLOWMAC_MODULE
    rval = dev_queue_status(comdev, 128);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    cb = (struct ieee80211_cb *) qdf_nbuf_get_ext_cb(skb);
    cb->_u.context = wbuf_get_peer(skb);
#endif

    nbuf_debug_del_record(skb);
    err = dev_queue_xmit(skb);
#if ATH_SUPPORT_FLOWMAC_MODULE
    if (err == NET_XMIT_DROP) {
        /* TODO FIXME to stop the queue here with flow control enabled
        */
        rval = -ENOBUFS;
    }
    /* if there is no space left in below queue, make sure that we pause the
     * vap queue also
     */
    if (err == -ENOMEM) rval = -ENOBUFS;
#endif
    return rval;
}

DECLARE_N_EXPORT_PERF_CNTR(vap_xmit);


/*
* hand over the wbuf to the vap if (queue back into the umac).
*/
static void osif_vap_xmit_queue (os_if_t osif, wbuf_t wbuf)
{
    int err;
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb = (struct sk_buff *)wbuf;

    START_PERF_CNTR(vap_xmit, vap_xmit);

    vap = osdev->os_if;
    skb->dev = dev;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    skb->mac.raw = skb->data;
    skb->nh.raw = skb->data + sizeof(struct ether_header);
#else
    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ether_header));
#endif
    skb->protocol = __constant_htons(ETH_P_802_2);
    /* XXX inser`t vlan tage before queue it? */
    nbuf_debug_del_record(skb);
    err = dev_queue_xmit(skb);

    if (err != 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: wbuf xmit failed \n", __func__);
    }
    END_PERF_CNTR(vap_xmit);
}

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
static void wlan_wrap_vap_xmit_queue (struct net_device *dev, wbuf_t wbuf)
{
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    vap = osdev->os_if;
    osif_vap_xmit_queue(vap->iv_ifp,wbuf);
    return;
}
#endif
#endif

#if ATH_SUPPORT_FLOWMAC_MODULE
static void
osif_pause_queue (os_if_t osif, int pause, unsigned int pctl)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    struct ath_softc_net80211 *scn = ath_netdev_priv(((osif_dev*)osif)->os_comdev);
    /* if puase, call the pause other wise wake */

    if (!dev || !scn) return ;

    if (pause) {
        netif_stop_queue(dev);
        /* Literally we should have stopped the ethernet just over 2/3 queue
         * is full. But for this to happen this should get called through
         * network stack first. As soon as we stopped the queue, we would
         * not be getting any calls to hard_start. That way we never able to
         * pause the Ethernet effectivly. The only simple way is to let us
         * pause the both. Otherwise kernel code need to change, but that
         * becomes more non-portable code.
         * Or else, the vap should have queue of frames and when reaches
         * limit pause the Ethernet.
         */

        if (scn->sc_ops->flowmac_pause && pctl ) {
            scn->sc_ops->flowmac_pause(scn->sc_dev, 1);

        }


    } else {
        netif_wake_queue(dev);

        if (scn->sc_ops->flowmac_pause && pctl) {
            scn->sc_ops->flowmac_pause(scn->sc_dev, 0);

        }

    }
}

#endif

static void
osif_vap_scan_cancel(os_if_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct wlan_objmgr_vdev *vdev = NULL;
    QDF_STATUS status;

    vap = osdev->os_if;
    vdev = osdev->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return;
    }
    /* Cancel all vdev scans without waiting for completions */
    wlan_ucfg_scan_cancel(vap, osdev->scan_requestor, 0,
            WLAN_SCAN_CANCEL_VDEV_ALL, false);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
}

static void osif_bringup_ap_vaps(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t tmpvap = NULL, vap = osdev->os_if;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);

    TAILQ_FOREACH(tmpvap, &comhandle->ic_vaps, iv_next) {
        if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
            tmpvap->iv_des_chan[tmpvap->iv_des_mode] = comhandle->ic_curchan;
        }
    }
    osif_check_pending_ap_vaps(comhandle,vap);
}

#if ATH_SUPPORT_IWSPY

#define SNR_QUAL_MIN		1
#define SNR_QUAL_THRESH1	5
#define SNR_QUAL_THRESH2	30
#define SNR_QUAL_MAX		42
#define QUAL_VALUE_MIN		0
#define QUAL_VALUE_THRESH1	5
#define QUAL_VALUE_THRESH2	85
#define QUAL_VALUE_MAX	94

static void
osif_set_linkquality(struct iw_quality *iq, u_int snr)
{
    if(snr >= SNR_QUAL_MAX)
        iq->qual = QUAL_VALUE_MAX ;
    else if(snr >= SNR_QUAL_THRESH2)
        iq->qual = QUAL_VALUE_THRESH2 + ((QUAL_VALUE_MAX-QUAL_VALUE_THRESH2)*(snr-SNR_QUAL_THRESH2) + (SNR_QUAL_MAX-SNR_QUAL_THRESH2)/2) \
					/ (SNR_QUAL_MAX-SNR_QUAL_THRESH2) ;
    else if(snr >= SNR_QUAL_THRESH1)
        iq->qual = QUAL_VALUE_THRESH1 + ((QUAL_VALUE_THRESH2-QUAL_VALUE_THRESH1)*(snr-SNR_QUAL_THRESH1) + (SNR_QUAL_THRESH2-SNR_QUAL_THRESH1)/2) \
					/ (SNR_QUAL_THRESH2-SNR_QUAL_THRESH1) ;
    else if(snr >= SNR_QUAL_MIN)
        iq->qual = snr;
    else
        iq->qual = QUAL_VALUE_MIN;

    iq->noise = 161;        /* -95dBm */
    iq->level = iq->noise + snr ;
    iq->updated = 0xf;
}

/*
 * Call for the driver to update the spy data.
 * For now, the spy data is a simple array. As the size of the array is
 * small, this is good enough. If we wanted to support larger number of
 * spy addresses, we should use something more efficient...
 */
void osif_iwspy_update(os_if_t osif,
			 u_int8_t *address,
			 int8_t snr)
{
    osif_dev  *osifp = (osif_dev *) osif;
    struct iw_spy_data *spydata = &osifp->spy_data;
	int	                i;
	int                 match = -1;
    struct iw_quality   iq;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return;

	/* Update all records that match */
	for(i = 0; i < spydata->spy_number; i++)
		if(IEEE80211_ADDR_EQ(address, spydata->spy_address[i])) {
            osif_set_linkquality(&iq, snr);
			memcpy(&(spydata->spy_stat[i]), &iq, sizeof(struct iw_quality));
			match = i;
		}

#if 0 /* for SIOCSIWTHRSPY/SIOCGIWTHRSPY, not to implement now */
	/* Generate an event if we cross the spy threshold.
	 * To avoid event storms, we have a simple hysteresis : we generate
	 * event only when we go under the low threshold or above the
	 * high threshold. */
	if(match >= 0) {
		if(spydata->spy_thr_under[match]) {
			if(wstats->level > spydata->spy_thr_high.level) {
				spydata->spy_thr_under[match] = 0;
				iw_send_thrspy_event(dev, spydata,
						     address, wstats);
			}
		} else {
			if(wstats->level < spydata->spy_thr_low.level) {
				spydata->spy_thr_under[match] = 1;
				iw_send_thrspy_event(dev, spydata,
						     address, wstats);
			}
		}
	}
#endif
}
/*
 * Call for reset the spy data by mac address
 */
void osif_iwspy_reset_data(os_if_t osif,
			 u_int8_t *address)
{
    osif_dev  *osifp = (osif_dev *) osif;
    struct iw_spy_data *spydata = &osifp->spy_data;
	int	                i;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return;

	/* Reset all records that match */
	for(i = 0; i < spydata->spy_number; i++)
		if(!memcmp(address, spydata->spy_address[i], ETH_ALEN)) {
            memset(&(spydata->spy_stat[i]), 0x0, sizeof(struct iw_quality));
		}
}
#endif

static void osif_linkspeed(os_handle_t osif, u_int32_t rxlinkspeed, u_int32_t txlinkspeed)
{

}

static void osif_beacon_miss(os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;

    vap = osdev->os_if;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: beacon miss \n", __func__);
}

static void osif_device_error(os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    ieee80211_reset_request reset_req;

    reset_req.reset_mac=0;
    reset_req.type = IEEE80211_RESET_TYPE_INTERNAL;
    reset_req.no_flush=0;
    vap = osdev->os_if;
    wlan_reset_start(vap, &reset_req);
    wlan_reset(vap, &reset_req);
    wlan_reset_end(vap, &reset_req);

}


/*
 * caller gets first element of list. Caller must free the element.
 */
struct pending_rx_frames_list *osif_fetch_p2p_mgmt(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    unsigned long flags=0;
    struct pending_rx_frames_list *pending = NULL;

    spin_lock_irqsave(&osifp->list_lock, flags);
    if (!list_empty(&osifp->pending_rx_frames)) {
        pending = (void *) osifp->pending_rx_frames.next;
        list_del(&pending->list);
    }
    spin_unlock_irqrestore(&osifp->list_lock, flags);

    return pending;
}

#ifdef HOST_OFFLOAD
/*
 * Is the list of pending frames empty or not
 */
int osif_is_pending_frame_list_empty(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    unsigned long flags=0;
    int empty = 0;

    spin_lock_irqsave(&osifp->list_lock, flags);
    if (list_empty(&osifp->pending_rx_frames))
        empty = 1;
    spin_unlock_irqrestore(&osifp->list_lock, flags);

    return empty;
}
#endif

/*
 * queue a big event for later delivery to user space
 * Caller must provide event->u.rx_frame.frame_len and
 * event->u.rx_frame.frame_buf for the data to be queued for later delivery
 */
void osif_p2p_rx_frame_handler(osif_dev *osifp,
                               wlan_p2p_event *event,
                               int frame_type)
{
    struct pending_rx_frames_list *pending;
    unsigned long flags;

    pending = (struct pending_rx_frames_list *)OS_MALLOC(osifp->os_handle,
                                 sizeof(*pending) + event->u.rx_frame.frame_len,
                                 GFP_ATOMIC);
    if (pending) {
        pending->frame_type = frame_type;
        pending->rx_frame = event->u.rx_frame;

        memcpy(pending->extra, event->u.rx_frame.frame_buf,
                                event->u.rx_frame.frame_len);

        INIT_LIST_HEAD (&pending->list);
        spin_lock_irqsave(&osifp->list_lock, flags);
        list_add_tail(&pending->list, &osifp->pending_rx_frames);
        spin_unlock_irqrestore(&osifp->list_lock, flags);
    } else {
        qdf_print(KERN_CRIT "%s OS_MALLOC failed, frame lost", __func__);
    }
}

struct event_data_chan_start {
    u_int32_t freq;
    u_int32_t duration;
    u_int32_t req_id;
};

struct event_data_chan_end {
    u_int32_t freq;
    u_int32_t reason;
    u_int32_t duration;
    u_int32_t req_id;
};

static void osif_wlan_tx_overflow_event(os_handle_t osif)
{
#if UMAC_SUPPORT_ACFG
    osif_dev  *osdev = (osif_dev *) osif;
#if !PEER_FLOW_CONTROL_FORCED_MODE0
    wlan_if_t vap = osdev->os_if;
    static u_int32_t tx_overflow_limit_print = 0;
#endif
    struct net_device *dev = osdev->netdev;
    acfg_event_data_t *acfg_event = NULL;

    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (acfg_event == NULL)
        return;

    memset(acfg_event, 0, sizeof(acfg_event_data_t));
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_TX_OVERFLOW, acfg_event);
#if !PEER_FLOW_CONTROL_FORCED_MODE0
    if(!(tx_overflow_limit_print % TXOVERFLOW_PRINT_LIMIT))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: TX overflow event sent. \n", __func__);
    }
    tx_overflow_limit_print++;
#endif
    qdf_mem_free(acfg_event);
#endif
}

#if QCA_LTEU_SUPPORT
static void
osif_mu_report(wlan_if_t vap, struct event_data_mu_rpt *mu_rpt)
{
    osif_dev *osdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = OSIF_TO_NETDEV(osdev);
    union iwreq_data wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_MU_RPT;
    wreq.data.length = sizeof(struct event_data_mu_rpt);
    WIRELESS_SEND_EVENT(dev, IWEVGENIE, &wreq, (void *)mu_rpt);
}
#endif

static wlan_misc_event_handler_table sta_misc_evt_handler = {
    osif_channel_change,                   /* wlan_channel_change */
    osif_country_changed,                  /* wlan_country_changed */
    osif_linkspeed,                        /* wlan_linkspeed */
    osif_michael_failure_indication,       /* wlan_michael_failure_indication */
    osif_replay_failure_indication,        /* wlan_replay_failure_indication */
    osif_beacon_miss,                      /* wlan_beacon_miss_indication */
    NULL,                                  /* wlan_beacon_rssi_indication */
    osif_device_error,                     /* wlan_device_error_indication */
    NULL,                                  /* wlan_sta_clonemac_indication */
    NULL,                                  /* wlan_sta_scan_entry_update */
    NULL,                                  /* wlan_ap_stopped */
#if ATH_SUPPORT_WAPI
    NULL,                                  /*wlan_sta_rekey_indication*/
#endif
#if UMAC_SUPPORT_RRM_MISC
    NULL,				                   /* osif_chload */
    NULL,                                                  /* osif_nonerpcnt */
    NULL,				                   /* osif_bgjoin */
    NULL,				                   /* osif_cochannelap_cnt*/
#endif
#if QCA_SUPPORT_SON
   osif_buffull_warning,                                     /* wlan_buffull */
#endif
    NULL,                   /* wlan_session_timeout */
#if ATH_SUPPORT_MGMT_TX_STATUS
   NULL,
#endif
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
    NULL, /* ssid_event , void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif
    NULL,                                 /* assocdeny_event */
    NULL,                                 /*wlan_tx_overflow */
    NULL,                                 /*wlan_ch_hop_channel_change*/
    NULL,                                 /*  wlan_recv_probereq */
#if DBDC_REPEATER_SUPPORT
    osif_dbdc_stavap_connection,                /*stavap_connection*/
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    osif_sta_cac_started,                 /* wlan_sta_cac_started */
#endif
    NULL,				/*chan_util_event*/
    NULL,				/*wlan_keyset_done_indication*/
    NULL,				/*wlan_blklst_sta_auth_indication*/
#if ATH_PARAMETER_API
    NULL, /* papi_event ,  void (*papi_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
    NULL,                            /* bss node freed indication */
    NULL,                            /* wlan_recv_neighreq */
    NULL,                            /* wlan_recv_beaconrpt */
    NULL,                            /* wlan_recv_bstm */
    NULL,			     /* wlan_recv_smpsupdate */
    NULL,			     /* wlan_recv_opmodeupdate */
};

static wlan_event_handler_table common_evt_handler = {
    osif_receive,
    osif_receive_filter_80211,
    osif_receive_monitor_80211,
    osif_dev_xmit_queue,
    osif_vap_xmit_queue,
    NULL,
#if ATH_SUPPORT_IWSPY
	osif_iwspy_update,
#endif
#if ATH_SUPPORT_FLOWMAC_MODULE
    osif_pause_queue,
#endif
    osif_vap_scan_cancel,       /* wlan_vap_scan_cancel */
    osif_bringup_ap_vaps,       /* wlan_bringup_ap_vaps */
};
static void
osif_join_complete_infra_sta(os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap = osdev->os_if;
#if DBDC_REPEATER_SUPPORT
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);
    struct ieee80211_vap_info vap_info;
#endif

    if (status != IEEE80211_STATUS_SUCCESS) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                "%s: status: %d, return..\n", __func__, status);
        return;
    }

    if ( wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
#if DBDC_REPEATER_SUPPORT
        if (!ic_list.iface_mgr_up) {
            vap_info.chan = 0;
            vap_info.no_cac = 1;
            osif_check_pending_ap_vaps(comhandle, vap);
            vap_info.no_cac = 0;
        }
#endif
     }
}
#define IEEE80211_MSG_CSL_STR         "[CSL] "
static void osif_join_complete_infra_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_JOIN_COMPLETE_INFRA_EVENT");
}

static void osif_join_complete_adhoc_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_JOIN_COMPLETE_ADHOC_EVENT");
}

static void osif_auth_complete_csl (os_handle_t osif, u_int8_t *macaddr, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_AUTH_COMPLETE_EVENT");
}

static void osif_assoc_req_csl (os_handle_t osif, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_REQ_EVENT");
}

static void osif_assoc_complete_csl (os_handle_t osif, IEEE80211_STATUS status, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_COMPLETE_EVENT");
}

static void osif_reassoc_complete_csl (os_handle_t osif, IEEE80211_STATUS status, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REASSOC_COMPLETE_EVENT");
}

static void osif_deauth_complete_csl (os_handle_t osif, u_int8_t *macaddr, IEEE80211_STATUS status, u_int16_t associd, u_int16_t reason)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DEAUTH_COMPLETE_EVENT");
}

static void osif_disassoc_complete_csl (os_handle_t osif, u_int8_t *macaddr, u_int32_t reason, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DISASSOC_COMPLETE_EVENT");
}

static void osif_txchanswitch_complete_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_TXCHANSWITCH_COMPLETE_EVENT");
}

static void osif_repeater_cac_complete_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REPEATER_CAC_COMPLETE_EVENT");
}

static void osif_auth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_AUTH_INDICATION_EVENT");
}

static void osif_deauth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DEAUTH_INDICATION_EVENT");
}

static void osif_assoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result, wbuf_t wbuf, wbuf_t resp_wbuf, bool reassoc)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_INDICATION_EVENT");
}

static void osif_reassoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result, wbuf_t wbuf, wbuf_t resp_wbuf, bool reassoc)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REASSOC_INDICATION_EVENT");
}

static void osif_disassoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int32_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DISASSOC_INDICATION_EVENT");
}

static void osif_ibss_merge_start_indication_csl (os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_IBSS_MERGE_START_INDICATION_EVENT");
}

static void osif_ibss_merge_completion_indication_csl (os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_IBSS_MERGE_COMPLETION_INDICATION_EVENT");
}

static void osif_radar_detected_csl (os_handle_t osif, u_int32_t csa_delay)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_RADAR_DETECTED_EVENT");
}

static void osif_node_authorized_indication_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_NODE_AUTHORIZED_INDICATION_EVENT");
}

static void osif_unprotected_deauth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason_code, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_UNPROTECTED_DEAUTH_INDICATION_EVENT");
}

static void osif_channel_change_csl (os_handle_t osif, wlan_chan_t chan)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHANNEL_CHANGE_EVENT");
}

static void osif_country_changed_csl (os_handle_t osif, char *country)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "COUNTRY_CHANGED_EVENT");
}

static void osif_linkspeed_csl (os_handle_t osif, u_int32_t rxlinkspeed, u_int32_t txlinkspeed)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "LINKSPEED_EVENT");
}

static void osif_michael_failure_indication_csl (os_handle_t osif,
        const u_int8_t *ta_mac_addr, u_int keyix)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MICHAEL_FAILURE_INDICATION_EVENT");
}

static void osif_replay_failure_indication_csl (os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "REPLAY_FAILURE_INDICATION_EVENT");
}

static void osif_beacon_miss_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BEACON_MISS_INDICATION_EVENT");
}

static void osif_beacon_rssi_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BEACON_RSSI_INDICATION_EVENT");
}

static void osif_device_error_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "DEVICE_ERROR_INDICATION_EVENT");
}

static void osif_sta_clonemac_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_CLONEMAC_INDICATION_EVENT");
}

static void osif_sta_scan_entry_update_csl (os_handle_t osif, wlan_scan_entry_t scan_entry, bool flag)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_SCAN_ENTRY_UPDATE_EVENT");
}

static void osif_ap_stopped_csl (os_handle_t osif, ieee80211_ap_stopped_reason reason)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "AP_STOPPED_EVENT");
}

#if ATH_SUPPORT_WAPI

static void osif_sta_rekey_indication_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_REKEY_INDICATION_EVENT");
}
#endif

#if UMAC_SUPPORT_RRM_MISC

static void osif_channel_load_csl (os_handle_t osif, u_int8_t chload)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHANNEL_LOAD_EVENT");
}

static void osif_nonerpcnt_csl (os_handle_t osif, u_int8_t erpcnt)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "NONERPCNT_EVENT");
}

static void osif_bgjoin_csl (os_handle_t osif, u_int8_t val)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BGJOIN_EVENT");
}

static void osif_cochannelap_cnt_csl (os_handle_t osif, u_int8_t val)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "COCHANNELAP_CNT_EVENT");
}
#endif

#if QCA_SUPPORT_SON

static void osif_buffull_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BUFFULL_EVENT");
}
#endif

static void osif_session_timeout_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "SESSION_TIMEOUT_EVENT");
}

#if ATH_SUPPORT_MGMT_TX_STATUS

static void osif_mgmt_tx_status_csl (os_handle_t osif, IEEE80211_STATUS status, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MGMT_TX_STATUS_EVENT");
}
#endif

#if ATH_BAND_STEERING

static void osif_bsteering_event_csl (os_handle_t osif, ATH_BSTEERING_EVENT type, uint32_t eventlen, const char *data)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BSTEERING_EVENT");
}
#endif

#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)

static void osif_ssid_event_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "SSID_EVENT");
}
#endif


static void osif_assocdeny_event_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "ASSOCDENY_EVENT");
}


static void osif_tx_overflow_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "TX_OVERFLOW_EVENT");
}

static void osif_ch_hop_channel_change_csl (os_handle_t osif, u_int8_t channel)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CH_HOP_CHANNEL_CHANGE_EVENT");
}

static void osif_recv_probereq_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t *ssid_element)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note_mac(vap, IEEE80211_MSG_MLME, macaddr, IEEE80211_MSG_CSL_STR "RECV_PROBEREQ_EVENT");
}

static void osif_recv_neighreq_csl(os_handle_t osif, u_int8_t *macaddr, void *req)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "NEIGH REQ RECV");
}

static void osif_recv_beaconrpt_csl(os_handle_t osif, void *arg, uint32_t len)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "RECV_BEACONRPT_EVENT");
}

static void osif_recv_bstm_csl (os_handle_t osif, void *arg, uint32_t len)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "RECV_BSTMRPT_EVENT");
}

static void osif_recv_smpsupdate_csl (os_handle_t osif, void *arg, uint32_t len)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "RECV_SMPSUPDATE_EVENT");
}

static void osif_recv_opmodeupdate_csl (os_handle_t osif, void *arg, uint32_t len)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "RECV_OPMODEUPDATE_EVENT");
}

#if DBDC_REPEATER_SUPPORT

static void osif_stavap_connection_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STAVAP_CONNECTION_EVENT");
}
#endif

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS

static void osif_sta_cac_started_csl (os_handle_t osif, u_int32_t frequency, u_int32_t timeout)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_CAC_STARTED_EVENT");
}
#endif

static void osif_chan_util_event_csl (os_handle_t osif, u_int32_t self_util, u_int32_t obss_util)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHAN_UTIL_EVENT");
}

static void osif_keyset_done_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "KEYSET_DONE_INDICATION_EVENT");
}

static void osif_blklst_sta_auth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BLKLST_STA_AUTH_INDICATION_EVENT");
}

#if ATH_PARAMETER_API

static void osif_papi_event_csl (os_handle_t osif, PAPI_REPORT_TYPE type, uint32_t eventlen, const char *data)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "PARAMETER_API_EVENT");
}
#endif

static wlan_mlme_event_handler_table sta_mlme_evt_handler = {
    NULL,                           /* mlme_join_complete_set_country */
    osif_join_complete_infra_sta,
    NULL,
    osif_auth_complete_sta,
    NULL,
    osif_assoc_complete_sta,
    osif_reassoc_complete_sta,
    osif_deauth_complete_sta,
    osif_disassoc_complete_sta,
    NULL,                           /* mlme_txchanswitch_complete */
    NULL,                           /* mlme_repeater_cac_complete  */
    osif_auth_indication_sta,
    osif_deauth_indication_sta,
    osif_assoc_indication_sta,
    osif_assoc_indication_sta,
    osif_disassoc_indication_sta,
    NULL,
    NULL,
    NULL,                             /* wlan_radar_detected */
    osif_authorized_indication_sta,   /* wlan_node_authorized_indication */
    osif_unprotected_deauth_indication_sta,   /* unprotected deauth indication */
};

static wlan_mlme_event_handler_table ap_mlme_evt_handler = {
    NULL,                                  /* mlme_join_complete_set_country */
	osif_create_infra_complete,
    NULL,
    osif_auth_complete_ap,
    NULL,
    osif_assoc_complete_ap,
    osif_assoc_complete_ap,
    osif_deauth_complete_ap,
    osif_disassoc_complete_ap,
    NULL,                                 /* mlme_txchanswitch_complete */
    NULL,                                 /* mlme_repeater_cac_complete */
    osif_auth_indication_ap,
    osif_deauth_indication_ap,
    osif_assoc_indication_ap,
    osif_assoc_indication_ap,
    osif_leave_indication_ap,
    NULL,
    NULL,
    NULL,
    osif_node_authorized_indication_ap,   /* wlan_node_authorized_indication */
    NULL,                                 /* unprotected deauth indication */
} ;

static wlan_misc_event_handler_table ap_misc_evt_handler = {
    osif_channel_change,
    osif_country_changed,
    osif_linkspeed,
    osif_michael_failure_indication,
    osif_replay_failure_indication,
    NULL,
    NULL,                               /* wlan_beacon_rssi_indication */
    NULL,
    NULL,
    NULL,
    NULL,                               /* wlan_ap_stopped */
#if ATH_SUPPORT_WAPI
    osif_rekey_indication_ap,
#endif
#if UMAC_SUPPORT_RRM_MISC
    osif_chload,
    osif_nonerpcnt,
    osif_bgjoin,
    osif_cochannelap_cnt,
#endif
#if QCA_SUPPORT_SON
   osif_buffull_warning,                                     /* wlan_buffull */
#endif
    osif_session_timeout,                   /* wlan_session_timeout */
#if ATH_SUPPORT_MGMT_TX_STATUS
   osif_mgmt_tx_status,
#endif
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
    osif_ssid_event,   /* ssid_event , void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif
    osif_assocdeny_event,   /* assocdeny_event */
    osif_wlan_tx_overflow_event,            /* wlan_tx_overflow */
    osif_ch_hop_channel_change , /*wlan_ch_hop_channel_change*/
    osif_recv_probereq,     /*  wlan_recv_probereq */
#if DBDC_REPEATER_SUPPORT
    NULL,                /*stavap_connection*/
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    NULL,                 /* wlan_sta_cac_started */
#endif
    NULL,
    osif_keyset_done_indication,/*keyset_done_indication*/
    osif_blklst_sta_auth_indication, /*blklst_sta_auth_indication*/
#if ATH_PARAMETER_API
    osif_papi_event, /* papi_event ,  void (*papi_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
    NULL,
    osif_recv_neighreq, /* wlan_recv_neighreq */
    osif_recv_beaconrpt, /* wlan_recv_beaconrpt */
    osif_recv_bstm, /* wlan_recv_bstm */
    osif_recv_smpsupdate, /*wlan_recv_smpsupdate */
    osif_recv_opmodeupdate, /*wlan_recv_opmodeupdate */
};

static void osif_tx_lock(osif_dev *osifp)
{
    spin_lock_bh(&osifp->tx_lock);
}

static void osif_tx_unlock(osif_dev *osifp)
{
    spin_unlock_bh(&osifp->tx_lock);
}

static wlan_mlme_event_handler_table csl_mlme_evt_handler = {
    NULL,                           /* mlme_join_complete_set_country */
    osif_join_complete_infra_csl,
    osif_join_complete_adhoc_csl,
    osif_auth_complete_csl,
    osif_assoc_req_csl,
    osif_assoc_complete_csl,
    osif_reassoc_complete_csl,
    osif_deauth_complete_csl,
    osif_disassoc_complete_csl,
    osif_txchanswitch_complete_csl,
    osif_repeater_cac_complete_csl,
    osif_auth_indication_csl,
    osif_deauth_indication_csl,
    osif_assoc_indication_csl,
    osif_reassoc_indication_csl,
    osif_disassoc_indication_csl,
    osif_ibss_merge_start_indication_csl,
    osif_ibss_merge_completion_indication_csl,
    osif_radar_detected_csl,
    osif_node_authorized_indication_csl,
    osif_unprotected_deauth_indication_csl,
};

static wlan_misc_event_handler_table csl_misc_evt_handler = {
    osif_channel_change_csl,
    osif_country_changed_csl,
    osif_linkspeed_csl,
    osif_michael_failure_indication_csl,
    osif_replay_failure_indication_csl,
    osif_beacon_miss_indication_csl,
    osif_beacon_rssi_indication_csl,
    osif_device_error_indication_csl,
    osif_sta_clonemac_indication_csl,
    osif_sta_scan_entry_update_csl,
    osif_ap_stopped_csl,
#if ATH_SUPPORT_WAPI
    osif_sta_rekey_indication_csl,
#endif
#if UMAC_SUPPORT_RRM_MISC
    osif_channel_load_csl,
    osif_nonerpcnt_csl,
    osif_bgjoin_csl,
    osif_cochannelap_cnt_csl,
#endif
#if QCA_SUPPORT_SON
    osif_buffull_csl,
#endif
    osif_session_timeout_csl,
#if ATH_SUPPORT_MGMT_TX_STATUS
    osif_mgmt_tx_status_csl,
#endif
#if ATH_BAND_STEERING
    osif_bsteering_event_csl,
#endif
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
    osif_ssid_event_csl,
#endif
    osif_assocdeny_event_csl,
    osif_tx_overflow_csl,
    osif_ch_hop_channel_change_csl,
    osif_recv_probereq_csl,
#if DBDC_REPEATER_SUPPORT
    osif_stavap_connection_csl,
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    osif_sta_cac_started_csl,
#endif
    osif_chan_util_event_csl,
    osif_keyset_done_indication_csl,
    osif_blklst_sta_auth_indication_csl,
#if ATH_PARAMETER_API
    osif_papi_event_csl,
#endif
    NULL,
    osif_recv_neighreq_csl,
    osif_recv_beaconrpt_csl,
    osif_recv_bstm_csl,
    osif_recv_smpsupdate_csl,
    osif_recv_opmodeupdate_csl,
};

static wlan_misc_event_handler_table csl_probe_evt_handler = {0};

void wlan_csl_enable(struct ieee80211vap *vap, int csl_val)
{
    u_int64_t old = wlan_get_debug_flags(vap);
    csl_probe_evt_handler.wlan_recv_probereq = osif_recv_probereq_csl;

    if (csl_val & LOG_CSL_BASIC) {
        wlan_set_debug_flags (vap, old | (IEEE80211_MSG_CSL));
    } else {
        wlan_set_debug_flags (vap, old & ~(IEEE80211_MSG_CSL));
    }

    if (csl_val & LOG_CSL_MLME_EVENTS) {
        wlan_vap_register_mlme_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_mlme_evt_handler);
    } else {
        wlan_vap_unregister_mlme_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_mlme_evt_handler);
    }

    if (csl_val & LOG_CSL_MISC_EVENTS) {
        wlan_vap_unregister_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_probe_evt_handler);
        wlan_vap_register_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_misc_evt_handler);
    } else {
        wlan_vap_unregister_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_misc_evt_handler);

        /* Requirement is to log probe requests (misc event) when CSL config MLME is enabled
         * register csl_probe_evt_handler for only probe requests
         * in case CSL MISC config is disabled and CSL MLME config is enabled*/
        if (csl_val & LOG_CSL_MLME_EVENTS) {
            wlan_vap_register_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_probe_evt_handler);
        } else {
            wlan_vap_unregister_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_probe_evt_handler);
        }
    }

    vap->iv_csl_support = csl_val;
}

static void osif_vap_setup(wlan_if_t vap, struct net_device *dev,
                            enum ieee80211_opmode opmode)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    cm_ext_t *cm_ext_handle = NULL;

    osifp->osif_is_mode_offload = 1;
    vap->iv_netdev_name = dev->name;

#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle)
        ieee80211_nl_register_handler(vap, osif_mu_report, osif_nl_scan_evhandler);
#endif

    ieee80211_ic_doth_set(vap->iv_ic);
    switch(opmode) {
    case IEEE80211_M_STA:
    case IEEE80211_M_P2P_CLIENT:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)osifp,&sta_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)osifp,&sta_misc_evt_handler);
        wlan_mlme_cm_event_init(vap);
#if SM_ENG_HIST_ENABLE
        wlan_mlme_cm_action_history_init(vap);
#endif
        cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);
        if (!cm_ext_handle)
            QDF_ASSERT(0);
        else {
            cm_ext_handle->assoc_sm_handle = wlan_assoc_sm_create(osifp->os_handle, vap);
            if (!cm_ext_handle->assoc_sm_handle) {
                QDF_ASSERT(0);
                return;
            }
        }

#ifdef ATH_SUPPORT_P2P
        if (osifp->p2p_client_handle ) {
            wlan_p2p_client_register_event_handlers(osifp->p2p_client_handle, (void *)osifp, osif_p2p_dev_event_handler);
        }
#endif
        wlan_cm_set_max_connect_timeout(vap->vdev_obj, 60000);
        ieee80211_ic_2g_csa_set(vap->iv_ic);
#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
        dp_wrap_register_xmit_handler(osifp->ctrl_vdev, &wlan_wrap_vap_xmit_queue);
#endif
#endif
        break;

    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_P2P_GO:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)osifp,&ap_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)osifp,&ap_misc_evt_handler);
#ifdef ATH_SUPPORT_P2P
        if (osifp->p2p_go_handle) {
            wlan_p2p_GO_register_event_handlers(osifp->p2p_go_handle, (void *)osifp, osif_p2p_dev_event_handler);
        }
#endif
#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
        dp_wrap_register_xmit_handler(osifp->ctrl_vdev, &wlan_wrap_vap_xmit_queue);
#endif
#endif
        break;
#ifdef ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_DEVICE:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)dev,&ap_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)dev,&ap_misc_evt_handler);
        wlan_p2p_register_event_handlers(osifp->p2p_handle, osifp, osif_p2p_dev_event_handler);
        break;
#endif
    case IEEE80211_M_MONITOR:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        break;
    default:
        break;
    }

    /* For OL, these will be later overloaded with OL specific lock APIs */
    osifp->tx_dev_lock_acquire = osif_tx_lock;
    osifp->tx_dev_lock_release = osif_tx_unlock;

}

static void
osif_set_multicast_list(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    struct net_device *parent = osifp->os_comdev;
	wlan_if_t vap = osifp->os_if;
    wlan_if_t tmpvap;
	struct ieee80211com *ic = vap->iv_ic;
	int flags = 0;

    if (ic->recovery_in_progress) {
        return;
    }

    if (dev->flags & IFF_PROMISC)
    {
        parent->flags |= IFF_PROMISC;
    } else {
        parent->flags &= ~IFF_PROMISC;
    }
    if (dev->flags & IFF_ALLMULTI)
    {
        parent->flags |= IFF_ALLMULTI;
	} else {
	    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            os_if_t handle = wlan_vap_get_registered_handle(tmpvap);
            if (handle) {
                struct net_device *tmpdev = ((osif_dev *)handle)->netdev;
                if (tmpdev) {
			        flags |= tmpdev->flags;
                }
            }
	}
		if(!(flags & IFF_ALLMULTI))
			parent->flags &= ~IFF_ALLMULTI;
	}

    /* XXX merge multicast list into parent device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
    parent->netdev_ops->ndo_set_rx_mode(parent);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
    parent->netdev_ops->ndo_set_multicast_list(parent);
#else
    parent->set_multicast_list(parent);
#endif
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
uint16_t
osif_select_queue(struct net_device *dev, struct sk_buff *skb,
                   struct net_device *sb_dev)
#else
static uint16_t
osif_select_queue(struct net_device *dev, struct sk_buff *skb,
                    void *accel_priv, select_queue_fallback_t fallback)
#endif
{
    uint16_t cpu = get_cpu();
    put_cpu();
    return cpu;
}

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
/*
 * osif_nss_set_mtu()
 *	API for changing the MTU.
 */
static int32_t osif_nss_set_mtu(struct net_device *dev, int mtu)
{
    struct nss_ctx_instance *wifi_nss_ctx = NULL;
    nss_tx_status_t status;
    int32_t if_num;

    wifi_nss_ctx = nss_wifi_get_context();
    if (!wifi_nss_ctx) {
        qdf_print("NSS Context not found. Change MTU failed\n");
        return -ENOMEM;
    }

    if_num = nss_cmn_get_interface_number_by_dev(dev);
    if (if_num < 0) {
        qdf_print("%p: Invalid interface number\n", wifi_nss_ctx);
        return -ENODEV;
    }

   status = nss_if_change_mtu(wifi_nss_ctx, if_num, mtu);
   if (status != NSS_TX_SUCCESS) {
        qdf_print("%p: Unable to send the change MTU message to NSS: %u\n", wifi_nss_ctx, mtu);
        return -1;
    }

    return 0;
}

/*
 * osif_nss_set_mac_addr()
 *	API for changing the MAC address.
 */
static int32_t osif_nss_set_mac_addr(struct net_device *dev, uint8_t *mac_addr)
{
    struct nss_ctx_instance *wifi_nss_ctx = NULL;
    nss_tx_status_t status;
    uint32_t if_num;

    wifi_nss_ctx = nss_wifi_get_context();
    if (!wifi_nss_ctx) {
        qdf_print("NSS Context not found. PPE VP create failed\n");
        return -ENOMEM;
    }

    if_num = nss_cmn_get_interface_number_by_dev(dev);
    if (if_num < 0) {
        qdf_print("%p: Invalid interface number\n", wifi_nss_ctx);
        return -ENODEV;
    }

    status = nss_if_change_mac_addr(wifi_nss_ctx, if_num, mac_addr);
    if (status != NSS_TX_SUCCESS) {
        qdf_print("%p: Unable to send the change MAC address message to NSS\n", wifi_nss_ctx);
        return -1;
    }

    return 0;
}
#endif

static int
osif_change_mtu(struct net_device *dev, int mtu)
{
    if (!(IEEE80211_MTU_MIN < mtu && mtu <= IEEE80211_MTU_MAX))
        return -EINVAL;
    dev->mtu = mtu;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_set_mtu(dev, mtu);
#endif
    /* XXX coordinate with parent device */
    return 0;
}

static int
osif_change_mac_addr(struct net_device *dev, void *mac_addr)
{
    struct sockaddr *sock_addr = (struct sockaddr *)mac_addr;

    netdev_dbg(dev, "AddrFamily: %d, %0x:%0x:%0x:%0x:%0x:%0x\n",
            sock_addr->sa_family, sock_addr->sa_data[0], sock_addr->sa_data[1],
            sock_addr->sa_data[2], sock_addr->sa_data[3], sock_addr->sa_data[4],
            sock_addr->sa_data[5]);

    memcpy(dev->dev_addr, sock_addr->sa_data, ETH_ALEN);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPOT
    osif_nss_set_mac_addr(dev, sock_addr->sa_data);
#endif

    /* XXX coordinate with parent device */
    return 0;
}

#ifdef QCA_SUPPORT_WDS_EXTENDED
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
static void
    osif_wds_ext_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static struct rtnl_link_stats64*
    osif_wds_ext_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#else
static struct net_device_stats *
    osif_wds_ext_getstats(struct net_device *dev)
#endif
{
    osif_peer_dev *osifp = ath_netdev_priv(dev);
    osif_dev  *osdev = ath_netdev_priv(osifp->parent_netdev);
    wlan_if_t vap = osdev->os_if;
    struct ieee80211com    *ic = NULL;
    struct ieee80211req_sta_stats *peer_stats;
    struct ieee80211_nodestats *pstats;
    struct ieee80211_node *ni = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = &osifp->os_devstats;
    struct net_device_stats *stats64 = stats;
#else
    struct rtnl_link_stats64 *stats = &osifp->os_devstats;
#endif

    peer_stats = (struct ieee80211req_sta_stats *)qdf_mem_malloc(sizeof(struct ieee80211req_sta_stats));
    qdf_mem_zero(peer_stats, sizeof(struct ieee80211req_sta_stats));
    if (!peer_stats)
        goto getstats_fail;

    if (!vap || ((vap->iv_ic) && vap->iv_ic->recovery_in_progress)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
        memcpy(stats64, &osifp->os_devstats, sizeof(struct rtnl_link_stats64));
#endif
        goto getstats_fail;
    }

    ni = ieee80211_vap_find_node(vap, dev->dev_addr,
                                 WLAN_MLME_SB_ID);

    if (ni == NULL)
        goto getstats_fail;

    ic = vap->iv_ic;
#ifdef QCA_SUPPORT_CP_STATS
    if(wlan_update_peer_cp_stats(ni, &peer_stats->is_stats) != 0) {
       ieee80211_free_node(ni, WLAN_MLME_SB_ID);
       goto getstats_fail;
    }
#endif
    if (ic) {
        if (wlan_get_peer_dp_stats(ic,
                                   ni->peer_obj,
                                   &peer_stats->is_stats) != 0) {
            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            goto getstats_fail;
        }
    }

    ieee80211_free_node(ni, WLAN_MLME_SB_ID);

    pstats = &peer_stats->is_stats;

    stats->rx_packets = pstats->ns_rx_data +
                        pstats->ns_rx_ucast +
                        pstats->ns_rx_mcast +
                        pstats->ns_rx_mgmt +
                        pstats->ns_rx_ctrl;
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    stats->rx_bytes = pstats->ns_rx_bytes +
                      pstats->ns_rx_ucast_bytes +
                      pstats->ns_rx_mcast_bytes;
#endif
    stats->rx_errors = pstats->ns_rx_decap +
                       pstats->ns_rx_decryptcrc +
                       pstats->ns_rx_tkipicv +
                       pstats->ns_rx_wepfail +
                       pstats->ns_rx_ccmpmic +
                       pstats->ns_rx_wpimic;
    stats->rx_dropped = pstats->ns_rx_dup;
    stats->tx_packets = pstats->ns_tx_data +
                        pstats->ns_tx_ucast +
                        pstats->ns_tx_mcast +
                        pstats->ns_tx_bcast;
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    stats->tx_bytes = pstats->ns_tx_bytes +
                      pstats->ns_tx_ucast_bytes +
                      pstats->ns_tx_mcast_bytes +
                      pstats->ns_tx_bcast_bytes;
#endif
    stats->tx_errors = pstats->ns_is_tx_not_ok;
    stats->tx_dropped = pstats->ns_tx_discard;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    memcpy(stats64, stats, sizeof(struct rtnl_link_stats64));
#endif

getstats_fail:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    qdf_mem_free(peer_stats);
    return;
#else
    qdf_mem_free(peer_stats);
    return stats64;
#endif
}

static int
osif_wds_ext_dev_open(struct net_device *dev)
{
   osif_peer_dev *osifp  = ath_netdev_priv(dev);
   struct net_device *pdev = osifp->parent_netdev;
   osif_dev *osif_parent = ath_netdev_priv(pdev);
   wlan_if_t vap = osif_parent->os_if;
   struct wlan_objmgr_psoc *psoc = NULL;
   ol_txrx_soc_handle soc_txrx_handle;
   struct net_device *comdev = osif_parent->os_comdev;
   struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
   QDF_STATUS status;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   struct ieee80211com *ic = NULL;
#endif

   if (!vap) {
       qdf_err("vap is null");
       return -EINVAL;
   }

   psoc = wlan_vdev_get_psoc(vap->vdev_obj);
   if (!psoc) {
       qdf_err("psoc is null");
       return -EINVAL;
   }

   soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
   status = cdp_wds_ext_set_peer_rx(
                           soc_txrx_handle,
                           wlan_vdev_get_id(vap->vdev_obj),
                           dev->dev_addr,
                           scn->soc->wds_ext_osif_rx,
                           (ol_osif_peer_handle )osifp);

   if (status == QDF_STATUS_E_ALREADY)
       qdf_err("WDS ext peer callback already set");

   dev->flags |= IFF_RUNNING;

   /*
    * Open the NSS interface.
    */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   ic = vap->iv_ic;
   if (ic && ic->nss_ext_vops && ic->nss_radio_ops->ic_osif_nss_wifili_peer_set_4addr_cfg) {
       status = ic->nss_radio_ops->ic_osif_nss_wifili_peer_set_4addr_cfg(scn, dev->dev_addr,
                                            wlan_vdev_get_id(vap->vdev_obj), osifp->nss_ifnum);
       if (status != QDF_STATUS_SUCCESS) {
           qdf_err("4address peer configuration failed");
           return 0;
       }
   }

   if (ic && ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_up) {
       ic->nss_ext_vops->ic_osif_nss_ext_vdev_up(osifp);
   }
#endif
   return 0;
}

static int
osif_wds_ext_dev_stop(struct net_device *dev)
{
   osif_peer_dev *osifp  = ath_netdev_priv(dev);
   struct net_device *pdev = osifp->parent_netdev;
   osif_dev *osif_parent = ath_netdev_priv(pdev);
   wlan_if_t vap = osif_parent->os_if;
   struct wlan_objmgr_psoc *psoc = NULL;
   ol_txrx_soc_handle soc_txrx_handle;
   QDF_STATUS status;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   struct ieee80211com *ic = NULL;
#endif

   if (!vap) {
       qdf_err("vap is null");
       return -EINVAL;
   }

   /*
    * Close the NSS interface.
    */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   ic = vap->iv_ic;
   if (ic && ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_down) {
       ic->nss_ext_vops->ic_osif_nss_ext_vdev_down(osifp);
   }
#endif

   psoc = wlan_vdev_get_psoc(vap->vdev_obj);
   if (!psoc) {
       qdf_err("psoc is null");
       return -EINVAL;
   }

   soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
   dev->flags &= ~IFF_RUNNING;
   status = cdp_wds_ext_set_peer_rx(
                           soc_txrx_handle,
                           wlan_vdev_get_id(vap->vdev_obj),
                           dev->dev_addr, NULL, NULL);
   if (status == QDF_STATUS_E_ALREADY)
       qdf_err("WDS ext peer callback already unset");

   return 0;
}

static int osif_wds_ext_change_mac(struct net_device *dev, void *p)
{
   struct sockaddr *addr = p;
   osif_peer_dev *osifp  = ath_netdev_priv(dev);
   struct net_device *pdev = osifp->parent_netdev;
   osif_dev *osif_parent = ath_netdev_priv(pdev);
   wlan_if_t vap = osif_parent->os_if;
   struct wlan_objmgr_psoc *psoc = NULL;
   ol_txrx_soc_handle soc_txrx_handle;
   struct ieee80211com *ic = NULL;
   struct ieee80211_node *ni = NULL;

   memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

   if (!vap) {
       qdf_err("vap is null");
       return -EINVAL;
   }

   ic = vap->iv_ic;
   if (!ic) {
       qdf_err("ic is null");
       return -EINVAL;
   }

   ni = ieee80211_find_node(ic, dev->dev_addr, WLAN_MLME_SB_ID);

   if (!ni) {
       qdf_err("ni is null");
       return -EINVAL;
   }

   ic->ic_node_use_4addr(ni);

   if (ic->ic_node_wmi_send_wds_ext(ni)) {
       qdf_err("WMI send for node");
       ieee80211_free_node(ni, WLAN_MLME_SB_ID);
       return -EINVAL;
   }

   ieee80211_free_node(ni, WLAN_MLME_SB_ID);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   if (ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_change_mac_addr) {
       if (ic->nss_ext_vops->ic_osif_nss_ext_vdev_change_mac_addr(osifp, addr->sa_data)
              != QDF_STATUS_SUCCESS) {
           qdf_err("wds vap mac setup failed");
           return -EINVAL;
       }
   }
#endif

   psoc = wlan_vdev_get_psoc(vap->vdev_obj);
   if (!psoc) {
       qdf_err("psoc is null");
       return -EINVAL;
   }

   soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
   osifp->peer_id = cdp_wds_ext_get_peer_id(soc_txrx_handle,
                                            wlan_vdev_get_id(vap->vdev_obj),
                                            dev->dev_addr);
   /*
    * Send message to the extended vap to configure wds peer.
    */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   if (ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_cfg_wds_peer) {
       if (ic->nss_ext_vops->ic_osif_nss_ext_vdev_cfg_wds_peer(osifp, ic)
           != QDF_STATUS_SUCCESS) {
           qdf_err("Could not setup nss wds peer");
       }
   }
#endif

   return 0;
}
#endif

void osif_vap_acs_cancel(struct net_device *dev, u_int8_t wlanscan)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int acs_active_on_this_vap = 0;
    struct wlan_objmgr_vdev *vdev = NULL;
    QDF_STATUS status;

    if (!vap) {
        qdf_print("%s: Error: vap is NULL for osifp: 0x%pK [%s] ",
            __func__, osifp, dev->name);
        return;
    }

    vdev = osifp->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return;
    }

    if(wlan_autoselect_in_progress(vap)) {
        acs_active_on_this_vap = wlan_autoselect_cancel_selection(vap);
        /* unregister all event handlers as this vap is going down */
        wlan_autoselect_unregister_event_handler(vap,
                &osif_bkscan_acs_event_handler, (void *)osifp);
        wlan_autoselect_unregister_event_handler(vap,
                &osif_ht40_event_handler, osifp);
        wlan_autoselect_unregister_event_handler(vap,
                &osif_acs_event_handler, (void *)osifp);
#if UMAC_SUPPORT_CFG80211
        if (!vap->iv_cfg80211_acs_pending)
            wlan_autoselect_unregister_event_handler(vap,
                    &cfg80211_acs_event_handler, (void *)osifp);
#endif
        wlan_autoselect_unregister_event_handler(vap,
                &ieee80211_dcs_acs_event_handler, (void *)&osifp);
        /* cancel WLAN scan, if ACS was active on this vap and scan was requested */
        if (acs_active_on_this_vap) {
            if (wlanscan && wlan_vdev_scan_in_progress(vap->vdev_obj)) {
                qdf_print("%s: Scan in progress.. Cancelling it vap: 0x%pK", __func__, vap);
                wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, 0,
                        WLAN_SCAN_CANCEL_VDEV_ALL, true);
            }
        }
    }
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
}

wlan_if_t osif_get_vap(osif_dev *osifp)
{
    return osifp->os_if;
}
qdf_export_symbol(osif_get_vap);

static int os_if_cm_init(osif_dev *osdev)
{
    wlan_if_t vap = osdev->os_if;
    return osif_cm_osif_priv_init(vap->vdev_obj);
}

static int os_if_cm_deinit(osif_dev *osdev)
{
    wlan_if_t vap = osdev->os_if;
    return osif_cm_osif_priv_deinit(vap->vdev_obj);
}

void vap_wait_for_vdev_init_state(struct wlan_objmgr_psoc *psoc,
                                  struct wlan_objmgr_vdev *vdev)
{
    int waitcnt = 0;
    uint8_t psoc_id;
    qdf_event_t wait_event;
    enum wlan_serialization_cmd_type cmd_type;

    qdf_mem_zero(&wait_event, sizeof(wait_event));
    qdf_event_create(&wait_event);
    qdf_event_reset(&wait_event);

    cmd_type = wlan_serialization_get_vdev_active_cmd_type(vdev);
    while (((wlan_vdev_mlme_get_state(vdev) != WLAN_VDEV_S_INIT) ||
            (cmd_type == WLAN_SER_CMD_VDEV_START_BSS)) &&
        waitcnt < OSIF_MAX_DELETE_VAP_INIT_TIMEOUT) {
        qdf_wait_single_event(&wait_event, 1000);
        waitcnt++;
        cmd_type = wlan_serialization_get_vdev_active_cmd_type(vdev);
    }
    qdf_event_destroy(&wait_event);

    if (wlan_vdev_mlme_get_state(vdev) != WLAN_VDEV_S_INIT) {
        wlan_mlme_err("Timeout: vdev:%u SM state %d, subsate:%d",
                      wlan_vdev_get_id(vdev), wlan_vdev_mlme_get_state(vdev),
                      wlan_vdev_mlme_get_substate(vdev));
        psoc_id = wlan_psoc_get_id(psoc);
        wlan_mlme_print_vdev_sm_history(psoc, vdev, &psoc_id);
        wlan_ser_print_history(vdev, WLAN_SER_CMD_NONSCAN, WLAN_SER_CMD_NONSCAN);
        wlan_objmgr_psoc_check_for_peer_leaks(psoc);
        QDF_BUG(0);
    }
}

void vap_wait_for_peer_delete(struct wlan_objmgr_psoc *psoc,
                              struct wlan_objmgr_vdev *vdev)
{
    int waitcnt = 0;
    qdf_event_t wait_event;

    qdf_mem_zero(&wait_event, sizeof(wait_event));
    qdf_event_create(&wait_event);
    qdf_event_reset(&wait_event);

    /* Wait for Peers to be deleted */
    while (wlan_vdev_get_peer_count(vdev) &&
           waitcnt < OSIF_MAX_DELETE_VAP_TIMEOUT) {
        qdf_wait_single_event(&wait_event, 1000);
        waitcnt++;
    }
    qdf_event_destroy(&wait_event);

    if (wlan_vdev_get_peer_count(vdev)) {
        wlan_mlme_err("Peers(cnt %d) are not freed for vdev:%d",
                      wlan_vdev_get_peer_count(vdev), wlan_vdev_get_id(vdev));
        wlan_objmgr_psoc_check_for_peer_leaks(psoc);
        QDF_BUG(0);
    }
}

int
osif_delete_vap_wait_and_free(struct net_device *dev, int recover)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    struct ieee80211com *ic;
    wlan_if_t vap = osnetdev->os_if;
    osif_dev  *osifp;
    int waitcnt = 0;
    struct net_device *parent = NULL;
    int numvaps = 0;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *psoc_mlme;
    struct vdev_response_timer *vdev_rsp;
    uint8_t vdev_id;
    qdf_event_t wait_event;
    wlan_assoc_sm_t assoc_sm_hdl;
#if QCN_IE
    qdf_hrtimer_data_t *t_bpr_timer = &vap->bpr_timer;
#endif


    qdf_mem_zero(&wait_event, sizeof(wait_event));

    osifp = ath_netdev_priv(dev);
    parent = osifp->os_comdev;
    vdev = osifp->ctrl_vdev;
    vdev_id = wlan_vdev_get_id(vdev);
    psoc = wlan_vdev_get_psoc(vdev);

    ic = wlan_vap_get_devhandle(vap);
    vap_wait_for_vdev_init_state(psoc, vdev);
#if QCN_IE
   if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
       qdf_hrtimer_kill(t_bpr_timer);
    }
#endif
   wlan_vdev_mlme_ser_cancel_request(vdev,
                                     WLAN_SER_CMD_NONSCAN,
                                     WLAN_SER_CANCEL_VDEV_NON_SCAN_NB_CMD);

    /*
     * Wait until all non-scan active commands are also removed from the
     * serialization queue.
     */
    wlan_mlme_wait_for_cmd_completion(vdev);

    /*
     * Wait until all active and pending scan commands are also removed from
     * the serialization queue.
     */
    wlan_mlme_wait_for_scan_cmd_completion(vdev);

    wlan_vap_delete_complete(vap);
    if (vap->iv_bss) {
        /* always send individual peer delete for BSS peer */
        qdf_atomic_set(&(vap->iv_bss->ni_peer_del_req_enable), 1);
        ieee80211_sta_leave(vap->iv_bss);
    }

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    wlan_hmwds_reset_table(vap);
#endif
    ieee80211_node_vdetach(vap);
    vap_wait_for_peer_delete(psoc, vdev);

    if (vap->iv_opmode == IEEE80211_M_STA) {
        wlan_mlme_cm_event_deinit(vap);
#if SM_ENG_HIST_ENABLE
        wlan_mlme_cm_action_history_deinit(vap);
#endif
        assoc_sm_hdl = wlan_mlme_get_assoc_sm_handle(vdev);
        if (assoc_sm_hdl)
            wlan_assoc_sm_delete(assoc_sm_hdl);
    }

    os_if_cm_deinit(osifp);
    wlan_objmgr_delete_vap(vap);

    if (recover)
        return 0;

    waitcnt = 0;
    qdf_event_create(&wait_event);
    qdf_event_reset(&wait_event);

    while(!osifp->is_deleted && waitcnt < OSIF_MAX_DELETE_VAP_TIMEOUT) {
        qdf_wait_single_event(&wait_event, 1000);
        waitcnt++;
    }

    psoc_mlme = mlme_psoc_get_priv(psoc);
    vdev_rsp =  &psoc_mlme->psoc_vdev_rt[vdev_id];

    waitcnt = 0;
    while(qdf_atomic_test_bit(DELETE_RESPONSE_BIT, &vdev_rsp->rsp_status) &&
                    waitcnt < OSIF_MAX_DELETE_VAP_TIMEOUT) {
        qdf_wait_single_event(&wait_event, 1000);
        waitcnt++;

    }
    qdf_event_destroy(&wait_event);

    wlan_vap_set_registered_handle(osnetdev->os_if, NULL);
    osnetdev->os_if = NULL;

    /* If not set after waiting deinit vap from here*/
    if (!osifp->is_deleted) {
        msleep(2000);
        if (!osifp->is_deleted) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                    "WARNING: Waiting for VAP delete timedout!!! vdev id: %d\n", vap->iv_unit);
            if (vap->iv_ic->ic_print_peer_refs)
                vap->iv_ic->ic_print_peer_refs(vap->vdev_obj, false);
        }
    } else {
        ic->ic_vap_free(vap);
    }

    osnetdev->is_delete_in_progress = 0;
    if (TAILQ_EMPTY(&ic->ic_vaps)) {
        /* cancel ru_tolerance_timer (per pdev), if we are about to stop target */
        ic_cancel_obss_nb_ru_tolerance_timer(ic);
        wlan_stop(ic);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if(ic->ic_wrap_com)
        ic->ic_wrap_com->wc_isolation = WRAP_ISOLATION_DEFVAL;
#endif
#endif
    }

    numvaps = osif_get_num_active_vaps(ic);
    if((numvaps == 0) && (parent != NULL) && (parent->flags & IFF_RUNNING)){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
        dev_close(parent);
#else
        if(dev_close(parent))
            qdf_print("Unable to close parent Interface");
#endif
    }
    return 0;
}


int
osif_vap_roam(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int waitcnt;
    int is_ap_cac_timer_running = 0;
    struct net_device *parent = osifp->os_comdev;
    enum ieee80211_opmode opmode;
    struct wlan_objmgr_vdev *vdev;
    QDF_STATUS status;
    ieee80211_ssid ssid;
    int desired_bssid = 0;

    if (!vap)
        return -EINVAL;

    opmode = wlan_vap_get_opmode(vap);
    if (opmode != IEEE80211_M_STA)
        return 0;

    vdev = osifp->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return -EBUSY;
    }

    if ((dev->flags & IFF_RUNNING) == 0) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        return -EINVAL;
    }

    if (IS_UP(parent)) {
        osifp->os_if->iv_mlmeconnect=0;
        ssid.len=0;
        wlan_get_desired_ssidlist(vap,&ssid,1);
        desired_bssid = wlan_aplist_get_desired_bssid_count(vap);
        /* check if there is only one desired bssid and it is broadcast , ignore the setting if it is */
        if (desired_bssid == 1) {
            u_int8_t des_bssid[QDF_MAC_ADDR_SIZE];
            wlan_aplist_get_desired_bssidlist(vap, &des_bssid);
            if (IEEE80211_IS_BROADCAST(des_bssid)) {
                desired_bssid=0;
            }
        }
        if ((desired_bssid || ssid.len)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: desired bssid %d ssid len %d \n",__func__,
                    desired_bssid, ssid.len);

            /*If in TXCHANSWITCH then wait before roam */
            if (mlme_get_active_req_type(vap) == MLME_REQ_TXCSA) {
                schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT); /* atleast wait for one iteration */
                waitcnt = 0;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "%s: Tx ChanSwitch is happening\n", __func__);
                while(waitcnt < OSIF_TXCHANSWITCH_LOOPCOUNT) {
                    schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT);
                    waitcnt++;
                }
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "%s: Tx ChanSwitch is Completed\n", __func__);
            }

            ucfg_dfs_is_ap_cac_timer_running(vap->iv_ic->ic_pdev_obj, &is_ap_cac_timer_running);
            if(is_ap_cac_timer_running) {
                wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
                return -EINVAL;
            }
            if (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS) {
                vap->iv_roam_inprogress = TRUE;
            }
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                    "Did not roam : num desired_bssid %d ssid len %d \n",
                    desired_bssid, ssid.len);
            wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
            return -EINVAL;
        }
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);

    return 0;
}

int osif_vap_pre_init_ap(wlan_if_t vap, int forcescan)
{
#if ATH_SUPPORT_WAPI
    osif_dev* osifp = (osif_dev *)(vap->iv_ifp);
#endif
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_ssid ssid;

    /* do not start AP if no ssid is set */
    ssid.len = 0;
    wlan_get_desired_ssidlist(vap, &ssid, 1);
    if (!ssid.len)
        return 0;

    if (ic->recovery_in_progress) {
        qdf_err("FW Crash on vap %d ...returning", vap->iv_unit);
        return -EINVAL;
    }

#if QCN_IE
    vap->iv_next_beacon_tstamp =
        qdf_ktime_add_ns(qdf_ktime_get(), ic->ic_intval * QDF_NSEC_PER_MSEC);
#endif

#if ATH_SUPPORT_WAPI
    osif_wapi_rekeytimer_start((os_if_t)osifp);
#endif

    return 0;
}

int osif_vap_pre_init_sta(wlan_if_t vap, int forcescan)
{
    osif_dev* osifp = (osif_dev *)(vap->iv_ifp);
    ieee80211_ssid ssid;
    int desired_bssid = 0;
    u_int8_t des_bssid[QDF_MAC_ADDR_SIZE];

    ssid.len=0;
    wlan_get_desired_ssidlist(vap,&ssid,1);
    desired_bssid = wlan_aplist_get_desired_bssid_count(vap);
    if (desired_bssid == 1) {
        wlan_aplist_get_desired_bssidlist(vap, &des_bssid);
        if (IEEE80211_IS_BROADCAST(des_bssid))
            desired_bssid = 0;
    }

    if ((!desired_bssid && !ssid.len)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                "Did not start connection SM : num desired_bssid %d ssid len %d \n",
                desired_bssid, ssid.len);
        return -EAGAIN;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: desired bssid %d ssid len %d \n",
            __func__, desired_bssid, ssid.len);

    if (forcescan & RESCAN)
        osifp->is_restart = 1;

    vap->iv_roam_inprogress = FALSE;

    return 0;
}

int osif_vap_pre_init(struct net_device *dev, int forcescan)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    struct net_device *parent = osifp->os_comdev;
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t comhandle;
    int ret_val = 0;
    enum ieee80211_opmode opmode;
#if UMAC_VOW_DEBUG
    struct wlan_objmgr_psoc *psoc = NULL;
#endif

    if (!vap)
        return -EINVAL;

    opmode = wlan_vap_get_opmode(vap);
    comhandle = wlan_vap_get_devhandle(vap);
    if (comhandle->no_chans_available == 1) {
        qdf_err("%s: vap-%d(%s) channel is not available",
                __func__,vap->iv_unit,vap->iv_netdev_name);
        return -EINVAL;
    }

    IEEE80211_DPRINTF(vap,
            IEEE80211_MSG_STATE | IEEE80211_MSG_DEBUG,
            "%s, ifname=%s, opmode=%d\n", "start running", osifp->netdev->name, vap->iv_opmode);

    if ((dev->flags & IFF_RUNNING) == 0) {
        if (osif_get_num_active_vaps(comhandle) == 0 &&
                (parent->flags & IFF_RUNNING) == 0){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
            ret_val = dev_open(parent, NULL);
#else
            ret_val = dev_open(parent);
#endif
            if (ret_val)
                return ret_val;
        }
        dev->flags |= IFF_RUNNING;
    }

    /*
     * If the parent is up and running, then kick the 802.11 state machine
     * as appropriate. parent should always be up+running
     */
    if (!IS_UP(parent)) {
        QDF_ASSERT(0);
        return -EINVAL;
    }

    osifp->os_last_siwscan = 0;
    osifp->os_if->iv_mlmeconnect=0;
#if UMAC_VOW_DEBUG
    psoc = wlan_pdev_get_psoc(comhandle->ic_pdev_obj);
    osifp->carrier_vow_config = cfg_get(psoc, CFG_OL_CARRIER_VOW_CONFIG);
#endif

    switch (opmode) {
    case IEEE80211_M_STA:
        ret_val = osif_vap_pre_init_sta(vap, forcescan);
        break;
    case IEEE80211_M_MONITOR:
        /* No init config for monitor mode */
        break;
    default:
        ret_val = osif_vap_pre_init_ap(vap, forcescan);
        break;
    }

    return ret_val;
}

int osif_vap_init(struct net_device *dev, int forcescan)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
    int ret_val;

    ret_val = osif_vap_pre_init(dev, forcescan);
    if (ret_val)
        return ret_val;

    opmode = wlan_vap_get_opmode(vap);
    switch (opmode) {
    case IEEE80211_M_STA:
        if (wlan_cm_is_vdev_connected(vap->vdev_obj))
            wlan_mlme_cm_start(vap->vdev_obj, CM_OSIF_CONNECT);
        break;
    case IEEE80211_M_MONITOR:
        wlan_mlme_start_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
        break;
    default:
        wlan_mlme_stop_start_vdev(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_MLME);
        break;
    }

    return 0;
}

/* osif_vap_open_preprocess() - check for sanity and invoke platfrom vap init
 * @dev - net_device pointer
 *
 * Return: Zero on success
 *         Erroe code on failure
 */
static int osif_vap_open_preprocess(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
#ifdef ATH_BUS_PM
    struct net_device *comdev = osifp->os_comdev;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
#endif
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
    struct ieee80211com *ic = NULL;

    if (!vap)
        return -EINVAL;

    ic = vap->iv_ic;

#ifdef ATH_BUS_PM
    if (scn->sc_osdev->isDeviceAsleep)
	return -EPERM;
#endif /* ATH_BUS_PM */

    opmode = wlan_vap_get_opmode(vap);
#if UNIFIED_SMARTANTENNA
    if (opmode == IEEE80211_M_STA) {
        /* Initialise smart antenna with default param to help scanning */
        (vap->iv_ic)->sta_not_connected_cfg = TRUE;
    }
#endif
#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_vap_init( dev );
#endif
    return 0;
}

/* osif_vap_open_finish() - check for sanity and invoke vap init
 * @dev - net_device pointer
 *
 * Return: Zero on success
 *         Error code on failure
 */
static int osif_vap_open_main(struct net_device *dev)
{
    int err = 0;
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
    struct ieee80211com *ic = NULL;

    if (!vap)
        return -EINVAL;

    ic = vap->iv_ic;

    /* if first vap is a mesh/nawds vap, bring it up as a non-tx vap */
    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE) &&
        ieee80211_get_num_beaconing_ap_vaps_up(ic) == 1) {

        if (ieee80211_ucfg_reset_mesh_nawds_txvap(vap))
            return -EINVAL;
    }

    ieee80211_ucfg_set_txvap(vap);

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        if ((!ic->ic_mbss.transmit_vap) &&
           (ieee80211_mbss_is_beaconing_ap(vap))) {
          mbss_err("vap%d:Tx vap should be configured before bringup of first VAP",
                  vap->iv_unit);
          return -EOPNOTSUPP;
        }
    }

    if (!ieee80211_get_num_beaconing_ap_vaps_up(ic)) {
        if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            !(vap->iv_smart_monitor_vap ||  vap->iv_special_vap_mode)) {
            ic->ic_ema_config_init(ic);
        } else {
            mbss_debug("Skip calling ic_ema_config_init as vap%d is not an AP that is part of an MBSSID group",
                       vap->iv_unit);
        }
    }

    /*
     * Beacon interval is got as a part of cfg80211_ap_settings.
     * Include this block before calling osif_vap_init from start_ap.
     */

    opmode = wlan_vap_get_opmode(vap);

    wlan_vap_up_check_beacon_interval(vap,opmode);

    if (ic->ic_need_vap_reinit) {
        osif_pdev_restart_vaps(ic);
        ic->ic_need_vap_reinit = 0;
    }

    err = osif_vap_init(dev, 0);
    return err;
}

#if UMAC_SUPPORT_CFG80211
/* is_defer_vap_init_required: function decides to defer vap init
 * till hostpad call start_ap or bringup vap during dev_open.
 * @vap: vap pointer
 * Returns TRUE if vap_init need to be defered
           FALSE to bringup vap immediately
 */

bool is_defer_vap_init_required(wlan_if_t vap)
{
    /*
     * vap_init need to be defered if VAP is cfg80211 enabled and
     * vap mode is: AP/STA/WDS.
     * proprtiery VAP modes (iv_special_vap_mode, iv_mesh_vap_mode)
     * does not require hostpad to bringup vap so defer of vap_init is
     * not required.
     */
    if(vap->iv_cfg80211_create && ((vap->iv_opmode == IEEE80211_M_HOSTAP) ||
                (vap->iv_opmode == IEEE80211_M_STA) ||
                (vap->iv_opmode == IEEE80211_M_WDS)) &&
                (vap->iv_special_vap_mode == 0)
#if MESH_MODE_SUPPORT
                && (vap->iv_mesh_vap_mode == 0)
#endif
      )
    {
        return true;
    } else {
        return false;
    }
}
#endif

/* osif_vap_open() - Vap open
 * @dev - net_device pointer
 *
 * The functionality of vap open is split into 3 chunks
 * 1. osif_vap_open_preprocess() - Check for sanity and do platform vap init
 * 2. Check for cfg80211 configuration and return, for vap init will be taken care by hostapd
 * 3. osif_vap_open_main() - Check for sanity and invoke osif_vap_init()
 *
 * Return: Zero on success
 *         Error code on failure
 */
int
osif_vap_open(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct net_device *parent = osifp->os_comdev;
    wlan_dev_t comhandle = NULL;
    int status = 0;

    if (vap->iv_ic->recovery_in_progress) {
       return -EINVAL;
    }

    status = osif_vap_open_preprocess(dev);

    if (status != 0)
	    return status;

    comhandle = wlan_vap_get_devhandle(vap);
    if ((dev->flags & IFF_RUNNING) == 0) {
        if (osif_get_num_active_vaps(comhandle) == 0 &&
                (parent->flags & IFF_RUNNING) == 0){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
            status = dev_open(parent, NULL);
#else
            status = dev_open(parent);
#endif
            if (status != 0)
                return status;
        }
    }

    /*
     * if cfg80211 created vap and mode is AP
     * postpone osif_vap_init till start_ap
     */
#if UMAC_SUPPORT_CFG80211
    if (is_defer_vap_init_required(vap)) {

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_CFG80211,
        "%s : Vap is created using cfg80211, Hostapd/supplicant needs to call startap/connect \n",
        __func__);
        return 0;
    }
#endif
    return osif_vap_open_main(dev);
}

/*
 * osif_num_ap_up_vaps() - Set frequency to the radio
 * @ic: ic object handle
 *
 * This function gets the number of AP VAPs brought up by the user space
 *
 * Return: Number of AP VAPs brought up by the user space
 */
int osif_num_ap_up_vaps(struct ieee80211com *ic)
{
    wlan_if_t tmpvap;
    struct net_device *tmpdev;
    int cnt = 0;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if (IS_UP(tmpdev) && (tmpvap->iv_opmode == IEEE80211_M_HOSTAP)) {
            cnt++;
        }
    }
    return cnt;
}

int
osif_restart_for_config(struct ieee80211com *ic,
                        int (*config_callback)(struct ieee80211com *ic,
                                               struct ieee80211_ath_channel *new_chan),
                        struct ieee80211_ath_channel *new_chan)
{
    QDF_STATUS retval;
    int32_t err = 0;

    qdf_assert_always(ic != NULL);

    osif_restart_stop_vaps(ic);
    retval = wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_VDEVS);
    if (retval == QDF_STATUS_E_INVAL)
        return -EINVAL;

    if (config_callback) {
         err = config_callback(ic, new_chan);
         if (err)
             return -EINVAL;
    }

    osif_restart_start_vaps(ic);

    return 0;
}

int
osif_restart_vaps(struct ieee80211com *ic)
{

    qdf_assert_always(ic != NULL);

    wlan_iterate_vap_list(ic, osif_restart_vap_iter_func, NULL);

    return 0;
}

/*
* Return netdevice statistics.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
void
osif_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static struct rtnl_link_stats64*
    osif_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#else
static struct net_device_stats *
    osif_getstats(struct net_device *dev)
#endif
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211_mac_stats unimac_stats;
    struct ieee80211_mac_stats multimac_stats;
    struct ieee80211_stats *vapstats;
    const struct ieee80211_mac_stats *unimacstats;
    const struct ieee80211_mac_stats *multimacstats;
    struct ieee80211com    *ic = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = &osifp->os_devstats;
    struct net_device_stats *stats64 = stats;
#else
    struct rtnl_link_stats64 *stats = &osifp->os_devstats;
#endif

    vapstats = qdf_mem_malloc(sizeof (struct ieee80211_stats));
    if (!vapstats)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
        return;
#else
        return stats64;
#endif
    qdf_mem_zero(&unimac_stats, sizeof(unimac_stats));
    qdf_mem_zero(&multimac_stats, sizeof(multimac_stats));
    unimacstats = &unimac_stats;
    multimacstats = &multimac_stats;

    if (!vap || osifp->is_delete_in_progress || (vap->iv_opmode == IEEE80211_M_MONITOR)
        || ((vap->iv_ic) && vap->iv_ic->recovery_in_progress)
        || ((dev->flags & IFF_RUNNING) != IFF_RUNNING)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
        memcpy(stats64, &osifp->os_devstats, sizeof(struct rtnl_link_stats64));
#endif
        goto getstats_fail;
    }

#if QCA_PARTNER_DIRECTLINK_RX
    /* get netdevice statistics through partner API */
    if (qdf_unlikely(osifp->is_directlink)) {
            qdf_mem_free(vapstats);
	    return osif_getstats_partner(dev);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    ic = vap->iv_ic;
#ifdef QCA_SUPPORT_CP_STATS
    if (!wlan_mac_stats_from_cp_stats(vap, 0, &unimac_stats))
        goto getstats_fail;

    if (!wlan_mac_stats_from_cp_stats(vap, 1, &multimac_stats))
        goto getstats_fail;
#endif
    if (ic) {
        if (wlan_get_vdev_dp_stats(vap, vapstats, &unimac_stats,
                                   &multimac_stats) != 0) {
            goto getstats_fail;
        }
    }

    stats->rx_packets = (stats_t)(unimacstats->ims_rx_packets + multimacstats->ims_rx_packets);
    stats->tx_packets = (stats_t)vapstats->ims_tx_packets;

    /* XXX total guess as to what to count where */
    /* update according to private statistics */

    stats->tx_bytes = (stats_t)vapstats->ims_tx_bytes;

    stats->tx_errors = (stats_t)(vapstats->is_tx_nodefkey
        + vapstats->is_tx_noheadroom
        + vapstats->is_crypto_enmicfail
        + vapstats->is_tx_not_ok);

    stats->tx_dropped = (stats_t)(vapstats->is_tx_nobuf
        + vapstats->is_tx_nonode
        + vapstats->is_tx_unknownmgt
        + vapstats->is_tx_badcipher
        + vapstats->is_tx_nodefkey);

    stats->rx_bytes = (stats_t)(unimacstats->ims_rx_bytes+ multimacstats->ims_rx_bytes);

    stats->rx_errors = (stats_t)(vapstats->is_rx_tooshort
            + unimacstats->ims_rx_wepfail
            + multimacstats->ims_rx_wepfail
            + vapstats->is_rx_decap
            + vapstats->is_rx_nobuf
            + unimacstats->ims_rx_decryptcrc
            + multimacstats->ims_rx_decryptcrc
            + unimacstats->ims_rx_ccmpmic
            + multimacstats->ims_rx_ccmpmic
            + unimacstats->ims_rx_tkipmic
            + multimacstats->ims_rx_tkipmic
            + unimacstats->ims_rx_tkipicv
            + multimacstats->ims_rx_tkipicv
            + unimacstats->ims_rx_wpimic
            + multimacstats->ims_rx_wpimic);

    stats->rx_crc_errors = 0;
    stats->rx_dropped = (stats_t)stats->rx_errors;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    memcpy(stats64, stats, sizeof(struct rtnl_link_stats64));
#endif

getstats_fail:
    qdf_mem_free(vapstats);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    return;
#else
    return stats64;
#endif
}
qdf_export_symbol(osif_getstats);

static void osif_com_vap_event_handler(void *event_arg, wlan_dev_t devhandle, os_if_t osif, ieee80211_dev_vap_event event)
{
    osif_dev  *osifp = (osif_dev *) osif;
#if ACFG_NETLINK_TX
#if UMAC_SUPPORT_ACFG
    acfg_netlink_pvt_t *acfg_nl = NULL;
    wlan_if_t vap = osifp->os_if;
#endif
#endif

    switch(event) {
    case IEEE80211_VAP_CREATED:
        break;
    case IEEE80211_VAP_DELETED:
        osifp->is_deleted=1;
#if ACFG_NETLINK_TX
#if UMAC_SUPPORT_ACFG
        acfg_nl = (acfg_netlink_pvt_t *)vap->iv_ic->ic_acfg_handle;
        if (vap == acfg_nl->vap) {
            acfg_nl->vap = NULL;
        }
#endif
#endif
        break;
    case IEEE80211_VAP_STOPPED:
       break;
    case IEEE80211_VAP_STOP_ERROR:
        /* The requested STOP returned error.
         * Tasks waiting for is_stop_event_pending may not receive the Stop event.
         */
        /* TODO: handle this case in conjuction with is_stop_event_pending */
       break;
    default:
        break;
    }

}

static wlan_dev_event_handler_table com_evtable = {
    osif_com_vap_event_handler,
#if WLAN_SPECTRAL_ENABLE
    NULL,
#endif
#if UMAC_SUPPORT_ACFG
    osif_radio_evt_radar_detected_ap,           /*wlan_radar_event*/
#else
    NULL,
#endif
#if UMAC_SUPPORT_ACFG || UMAC_SUPPORT_ACFG_RECOVERY
     osif_radio_evt_watch_dog,                   /*wlan_wdt_event*/
#else
    NULL,
#endif
#if UMAC_SUPPORT_ACFG
    osif_radio_evt_dfs_cac_start,               /*wlan_cac_start_event*/
    osif_radio_evt_dfs_up_after_cac,            /*wlan_up_after_cac_event*/
    osif_radio_evt_chan_util,                   /*wlan_chan_util_event*/
#endif
};

void wlan_register_scantimer_handler(void * devhandle)
{
    wlan_autoselect_register_scantimer_handler(devhandle, osif_acs_bk_scantimer_fn , devhandle);
}

extern void ieee80211_dfs_non_dfs_chan_config(void *arg);

void osif_attach(struct net_device *comdev)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_device_register_event_handlers(devhandle,comdev,&com_evtable);
    wlan_register_scantimer_handler(devhandle);

#ifdef QCA_PARTNER_PLATFORM
    wlan_pltfrm_attach(comdev);
#endif /* QCA_PARTNER_PLATFORM */

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    osif_wrap_attach(devhandle);
#endif
#endif
}
qdf_export_symbol(osif_attach);

void osif_detach(struct net_device *comdev)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_device_unregister_event_handlers(devhandle,(void *)comdev,&com_evtable);

#ifdef QCA_PARTNER_PLATFORM
    wlan_pltfrm_detach(comdev);
#endif

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    osif_wrap_detach(devhandle);
#endif
#endif
#ifdef ATH_SUPPORT_DFS
    qdf_flush_work(&devhandle->dfs_cac_timer_start_work);
    qdf_disable_work(&devhandle->dfs_cac_timer_start_work);
#endif

    qdf_mem_free(devhandle->set_country);
    qdf_flush_work(&devhandle->assoc_sm_set_country_code);
    qdf_disable_work(&devhandle->assoc_sm_set_country_code);

    devhandle->set_country = NULL;
}
qdf_export_symbol(osif_detach);

#if QCA_OL_VLAN_WAR
#define MAC_ADDR_CPY(a,b)       \
    do {     \
        *(uint32_t *)&a[0] = *(uint32_t *)&b[0]; \
        a[4]=b[4]; \
        a[5]=b[5]; \
    } while (0);

static int encap_eth2_to_dot3(qdf_nbuf_t msdu)
{
    u_int16_t typeorlen;
    struct ether_header eth_hdr, *eh;
    struct llc *llcHdr;
    qdf_assert(msdu != NULL);
    if (qdf_nbuf_headroom(msdu) < sizeof(*llcHdr))
    {
        qdf_print("Encap: Don't have enough headroom");
        return 1;
    }

    eh = (struct ether_header *) qdf_nbuf_data(msdu);

    /*
     * Save addresses to be inserted later
     */
    MAC_ADDR_CPY(eth_hdr.ether_dhost, eh->ether_dhost);
    MAC_ADDR_CPY(eth_hdr.ether_shost, eh->ether_shost);
     /*** NOTE: REQUIRES NTOHS IF REFERENCED ***/
    typeorlen = eh->ether_type;

    /*
     * Make room for LLC + SNAP headers
     */
    if (qdf_nbuf_push_head(msdu, sizeof(*llcHdr)) == NULL){
        qdf_print("Encap: Failed to push LLC header");
        return 1;
    }

    eh = (struct ether_header *) qdf_nbuf_data(msdu);

    MAC_ADDR_CPY(eh->ether_dhost, eth_hdr.ether_dhost);
    MAC_ADDR_CPY(eh->ether_shost, eth_hdr.ether_shost);
    eh->ether_type = htons((uint16_t) (msdu->len - sizeof(eth_hdr)));

    llcHdr = (struct llc *)((u_int8_t *)eh + sizeof(eth_hdr));
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;
    return 0;
}
#endif

#if MESH_MODE_SUPPORT
void
os_if_tx_free_batch_ext(struct sk_buff *bufs, int tx_err)
{
    while (bufs) {
        struct sk_buff *next = bufs->next;
        if (external_tx_complete != NULL) {
            external_tx_complete(bufs);
        } else {
            qdf_nbuf_free(bufs);
        }
        bufs = next;
    }
}

void
os_if_tx_free_ext(struct sk_buff *skb)
{
    if (external_tx_complete != NULL) {
        nbuf_debug_del_record(skb);
        external_tx_complete(skb);
    } else {
        qdf_nbuf_free(skb);
    }
}
qdf_export_symbol(os_if_tx_free_ext);
#endif

/*
* Convert a media specification to an 802.11 phy mode.
*/
static int
media2mode(const struct ifmedia_entry *ime, enum ieee80211_phymode *mode)
{

    /* 11AX TODO (Phase II) - Add 11ax processing here if required based on
     * latest code status.
     */

    switch (IFM_MODE(ime->ifm_media)) {
    case IFM_IEEE80211_11A:
        *mode = IEEE80211_MODE_11A;
        break;
    case IFM_IEEE80211_11B:
        *mode = IEEE80211_MODE_11B;
        break;
    case IFM_IEEE80211_11G:
        *mode = IEEE80211_MODE_11G;
        break;
    case IFM_IEEE80211_FH:
        *mode = IEEE80211_MODE_FH;
        break;
        case IFM_IEEE80211_11NA:
                *mode = IEEE80211_MODE_11NA_HT20;
                break;
        case IFM_IEEE80211_11NG:
                *mode = IEEE80211_MODE_11NG_HT20;
                break;
    case IFM_AUTO:
        *mode = IEEE80211_MODE_AUTO;
        break;
    default:
        return 0;
    }

    if (ime->ifm_media & IFM_IEEE80211_HT40PLUS) {
            if (ieee80211_is_phymode_11na_ht20(*mode))
                    *mode = IEEE80211_MODE_11NA_HT40PLUS;
            else if (ieee80211_is_phymode_11ng_ht20(*mode))
                    *mode = IEEE80211_MODE_11NG_HT40PLUS;
            else
                    return 0;
    }

    if (ime->ifm_media & IFM_IEEE80211_HT40MINUS) {
            if (ieee80211_is_phymode_11na_ht20(*mode))
                    *mode = IEEE80211_MODE_11NA_HT40MINUS;
            else if (ieee80211_is_phymode_11ng_ht20(*mode))
                    *mode = IEEE80211_MODE_11NG_HT40MINUS;
            else
                    return 0;
    }

    return 1;
}

/*
 * convert IEEE80211 ratecode to ifmedia subtype.
 */
static int
rate2media(struct ieee80211vap *vap,int rate,enum ieee80211_phymode mode)
{
#define N(a)    (sizeof(a) / sizeof(a[0]))
    struct ieee80211com    *ic = wlan_vap_get_devhandle(vap);
    static const struct
    {
        u_int   m;      /* rate + mode */
        u_int   r;      /* if_media rate */
    } rates[] = {
                {   0x1b | IFM_IEEE80211_FH, IFM_IEEE80211_FH1 },
                {   0x1a | IFM_IEEE80211_FH, IFM_IEEE80211_FH2 },
                {   0x1b | IFM_IEEE80211_11B, IFM_IEEE80211_DS1 },
                {   0x1a | IFM_IEEE80211_11B, IFM_IEEE80211_DS2 },
                {   0x19 | IFM_IEEE80211_11B, IFM_IEEE80211_DS5 },
                {   0x18 | IFM_IEEE80211_11B, IFM_IEEE80211_DS11 },
                {   0x1a | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM2_25 },
                {   0x0b | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM6 },
                {   0x0f | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM9 },
                {   0x0a | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM12 },
                {   0x0e | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM18 },
                {   0x09 | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM24 },
                {   0x0d | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM36 },
                {   0x08 | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM48 },
                {   0x0c | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM54 },
                {   0x1b | IFM_IEEE80211_11G, IFM_IEEE80211_DS1 },
                {   0x1a | IFM_IEEE80211_11G, IFM_IEEE80211_DS2 },
                {   0x19 | IFM_IEEE80211_11G, IFM_IEEE80211_DS5 },
                {   0x18 | IFM_IEEE80211_11G, IFM_IEEE80211_DS11 },
                {   0x0b | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM6 },
                {   0x0f | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM9 },
                {   0x0a | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM12 },
                {   0x0e | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM18 },
                {   0x09 | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM24 },
                {   0x0d | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM36 },
                {   0x08 | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM48 },
                {   0x0c | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM54 },
                /* NB: OFDM72 doesn't realy exist so we don't handle it */
                /* 11AX TODO (Phase I) - Need to check if and what changes are
                 * required here.
                 */
        };
    u_int mask, i, phytype;

    mask = rate & IEEE80211_RATE_VAL;
    switch (mode)
    {
    case IEEE80211_MODE_11A:
    case IEEE80211_MODE_TURBO_A:
    case IEEE80211_MODE_11NA_HT20:
    case IEEE80211_MODE_11NA_HT40MINUS:
    case IEEE80211_MODE_11NA_HT40PLUS:
    case IEEE80211_MODE_11NA_HT40:
    case IEEE80211_MODE_11AC_VHT20:
    case IEEE80211_MODE_11AC_VHT40PLUS:
    case IEEE80211_MODE_11AC_VHT40MINUS:
    case IEEE80211_MODE_11AC_VHT40:
    case IEEE80211_MODE_11AC_VHT80:
    case IEEE80211_MODE_11AC_VHT160:
    case IEEE80211_MODE_11AC_VHT80_80:
    case IEEE80211_MODE_11AXA_HE20:
    case IEEE80211_MODE_11AXA_HE40PLUS:
    case IEEE80211_MODE_11AXA_HE40MINUS:
    case IEEE80211_MODE_11AXA_HE40:
    case IEEE80211_MODE_11AXA_HE80:
    case IEEE80211_MODE_11AXA_HE160:
    case IEEE80211_MODE_11AXA_HE80_80:
        mask |= IFM_IEEE80211_11A;
        break;
    case IEEE80211_MODE_11B:
        mask |= IFM_IEEE80211_11B;
        break;
    case IEEE80211_MODE_FH:
        mask |= IFM_IEEE80211_FH;
        break;
    case IEEE80211_MODE_AUTO:
        phytype = wlan_get_current_phytype(ic);

        if (phytype == IEEE80211_T_FH)
        {
            mask |= IFM_IEEE80211_FH;
            break;
        }
        /* NB: hack, 11g matches both 11b+11a rates */
        /* fall thru... */
    case IEEE80211_MODE_11G:
    case IEEE80211_MODE_TURBO_G:
    case IEEE80211_MODE_11NG_HT20:
    case IEEE80211_MODE_11NG_HT40MINUS:
    case IEEE80211_MODE_11NG_HT40PLUS:
    case IEEE80211_MODE_11NG_HT40:
    case IEEE80211_MODE_11AXG_HE20:
    case IEEE80211_MODE_11AXG_HE40PLUS:
    case IEEE80211_MODE_11AXG_HE40MINUS:
    case IEEE80211_MODE_11AXG_HE40:
        mask |= IFM_IEEE80211_11G;
        break;
    default:
        break;
    }
    for (i = 0; i < N(rates); i++) {
        if (rates[i].m == mask) {
            return rates[i].r;
     }
    }
    return IFM_AUTO;
#undef N
}


static int
osif_media_change(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_phymode newphymode;
    struct ifmedia_entry *ime = osifp->os_media.ifm_cur;

    /*
    * First, identify the phy mode.
    */
    if (!media2mode(ime, &newphymode))
        return EINVAL;
    if (newphymode != wlan_get_desired_phymode(vap)) {
        return wlan_set_desired_phymode(vap,newphymode);
    }
    return 0;
}

static const u_int mopts[] = {
        IFM_AUTO,
        IFM_IEEE80211_11A,
        IFM_IEEE80211_11B,
        IFM_IEEE80211_11G,
        IFM_IEEE80211_FH,
        IFM_IEEE80211_11A | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11G | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11NA,
        IFM_IEEE80211_11NG,
        IFM_IEEE80211_11NA | IFM_IEEE80211_HT40PLUS,
        IFM_IEEE80211_11NA | IFM_IEEE80211_HT40MINUS,
        IFM_IEEE80211_11NG | IFM_IEEE80211_HT40PLUS,
        IFM_IEEE80211_11NG | IFM_IEEE80211_HT40MINUS,
        0,
        0,
        IFM_IEEE80211_11AC,
        IFM_IEEE80211_11AC | IFM_IEEE80211_W40PLUS,
        IFM_IEEE80211_11AC | IFM_IEEE80211_W40MINUS,
        0,
        IFM_IEEE80211_11AC | IFM_IEEE80211_W80,
        IFM_IEEE80211_11AC | IFM_IEEE80211_W160,
        IFM_IEEE80211_11AC | IFM_IEEE80211_W80_80,
        IFM_IEEE80211_11AXA,
        IFM_IEEE80211_11AXG,
        IFM_IEEE80211_11AXA | IFM_IEEE80211_W40PLUS,
        IFM_IEEE80211_11AXA | IFM_IEEE80211_W40MINUS,
        IFM_IEEE80211_11AXG | IFM_IEEE80211_W40PLUS,
        IFM_IEEE80211_11AXG | IFM_IEEE80211_W40MINUS,
        0,
        0,
        IFM_IEEE80211_11AXA | IFM_IEEE80211_W80,
        IFM_IEEE80211_11AXA | IFM_IEEE80211_W160,
        IFM_IEEE80211_11AXA | IFM_IEEE80211_W80_80,
};

/*
* Common code to calculate the media status word
* from the operating mode and channel state.
*/
static int
media_status(enum ieee80211_opmode opmode, wlan_chan_t chan)
{
    int status;
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;    /* autoselect */

    status = IFM_IEEE80211;
    switch (opmode) {
    case IEEE80211_M_STA:
        break;
    case IEEE80211_M_IBSS:
        status |= IFM_IEEE80211_ADHOC;
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_P2P_GO:
        status |= IFM_IEEE80211_HOSTAP;
        break;
    case IEEE80211_M_MONITOR:
        status |= IFM_IEEE80211_MONITOR;
        break;
    case IEEE80211_M_AHDEMO:
    case IEEE80211_M_WDS:
        /* should not come here */
        break;
    default:
        break;
    }
    if (chan) {
        mode = wlan_channel_phymode(chan);
    }
    if (mode >= 0 && mode < (sizeof(mopts)/sizeof(mopts[0])) ) {
        status |= mopts[mode];
    }

    /* XXX else complain? */

    return status;
}

static void
osif_media_status(struct net_device *dev, struct ifmediareq *imr)
{

    int rate;
    osif_dev  *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    wlan_chan_t chan;
    enum ieee80211_phymode mode;

    imr->ifm_status = IFM_AVALID;
    if ((dev->flags & IFF_UP))
        imr->ifm_status |= IFM_ACTIVE;
    chan = wlan_get_current_channel(vap,true);
    if (chan != (wlan_chan_t)0 && chan != (wlan_chan_t)-1) {
        imr->ifm_active = media_status(osdev->os_opmode, chan);
    }

    if(wlan_is_connected(vap)) {
         mode = wlan_get_bss_phymode(vap);
    }
    else {
         mode = IEEE80211_MODE_AUTO;
    }

    rate = wlan_get_param(vap, IEEE80211_FIXED_RATE);
    if (rate != IEEE80211_FIXED_RATE_NONE)
    {
        /*
        * A fixed rate is set, report that.
        */
        imr->ifm_active &= ~IFM_TMASK;
        if ( rate & 0x80) {
            imr->ifm_active |= IFM_IEEE80211_HT_MCS;
        }
        else {
            imr->ifm_active |= rate2media(vap,rate,mode);
        }
    }
    else {
        imr->ifm_active |= IFM_AUTO;
    }
    imr->ifm_current = imr->ifm_active;
}


static int os_if_media_init(osif_dev *osdev)
{
    wlan_if_t vap;
    int i,mopt;
    u_int16_t nmodes;
    enum ieee80211_phymode modes[IEEE80211_MODE_MAX];
    struct ifmedia *media = &osdev->os_media;
    struct ifmediareq imr;
    ifmedia_init(media, 0, osif_media_change, osif_media_status);

    vap = osdev->os_if;
    if (wlan_get_supported_phymodes(osdev->os_devhandle,modes,
                                    &nmodes,IEEE80211_MODE_MAX) != 0 ) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : get_supported_phymodes failed \n", __func__);
        return -EINVAL;
    }
    for (i=0;i<nmodes;++i) {
        mopt = mopts[(u_int32_t)modes[i]];
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt); /* e.g. 11a auto */
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_ADHOC);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_HOSTAP);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_ADHOC | IFM_FLAG0);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_MONITOR);
    }

    osif_media_status(osdev->netdev, &imr);
    ifmedia_set(media, imr.ifm_active);
    return 0;
}

void osif_mlme_notify_handler(wlan_if_t vap,
        enum wlan_serialization_cmd_type cmd_type)
{
    osif_dev *osdev = (osif_dev *)vap->iv_ifp;
    struct ieee80211com *ic = vap->iv_ic;
    union iwreq_data wreq;
    enum ieee80211_opmode opmode;
    struct net_device *dev;
    wlan_if_t tmp_vap;

    opmode = wlan_vap_get_opmode(vap);
    dev = osdev->netdev;

    switch (cmd_type) {
    case WLAN_SER_CMD_VDEV_START_BSS:
    case WLAN_SER_CMD_VDEV_CONNECT:
        break;
    case WLAN_SER_CMD_VDEV_STOP_BSS:
    case WLAN_SER_CMD_VDEV_DISCONNECT:
#if UMAC_SUPPORT_CFG80211
        if (opmode == IEEE80211_M_HOSTAP && vap->iv_cfg80211_create) {
            if (osdev->scan_req) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
                struct cfg80211_scan_info info = {
                        .aborted = true,
                };
                cfg80211_scan_done(osdev->scan_req, &info); /* aborted*/
#else
                cfg80211_scan_done(osdev->scan_req, true); /* aborted*/
#endif
                osdev->scan_req = NULL;
            }
        }
#endif
        if (osdev->is_delete_in_progress) {
            OS_DELAY(5000);
            delete_default_vap_keys(vap);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : Keys Deleted \n",__func__);
        }

        if (opmode == IEEE80211_M_HOSTAP) {
#if ATH_SUPPORT_WAPI
            osif_wapi_rekeytimer_stop((os_if_t)osdev);
#endif
        }
        vap->iv_needs_up_on_acs = 0;
#if UNIFIED_SMARTANTENNA
        if (opmode == IEEE80211_M_STA) {
            QDF_STATUS status = wlan_objmgr_vdev_try_get_ref(vap->vdev_obj, WLAN_SA_API_ID);
            if (QDF_IS_STATUS_ERROR(status)) {
                qdf_err("unable to get reference");
            } else {
                wlan_sa_api_stop(vap->iv_ic->ic_pdev_obj, vap->vdev_obj, SMART_ANT_RECONFIGURE);
                wlan_sa_api_start(vap->iv_ic->ic_pdev_obj, vap->vdev_obj, SMART_ANT_STA_NOT_CONNECTED | SMART_ANT_RECONFIGURE);
                (vap->iv_ic)->sta_not_connected_cfg = TRUE;
                wlan_objmgr_vdev_release_ref(vap->vdev_obj, WLAN_SA_API_ID);
            }
        }
#endif
        ic->vap_down_in_progress = FALSE;

        wlan_vap_down_check_beacon_interval(vap, opmode);
        if (ic->ic_need_vap_reinit) {
            osif_cmd_schedule_req(vap->vdev_obj, OSIF_CMD_OTH_VDEV_STOP_START);
            ic->ic_need_vap_reinit = 0;
        }

        /* If there are only non-beaconing VAPs on this ic, then deliver CSA_COMPLETE,
         * as it might be stuck on CSA_RESTART state */
        if (!ieee80211_get_num_beaconing_vaps(ic)
            && vap->iv_opmode == IEEE80211_M_HOSTAP) {
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap != vap && (tmp_vap->iv_opmode == IEEE80211_M_MONITOR
                    || wlan_is_non_beaconing_ap_vap(tmp_vap)))
                    mlme_vdev_sm_deliver_csa_complete(tmp_vap->vdev_obj);
            }
        }

        memset(&wreq, 0, sizeof(wreq));
        wreq.data.flags = IEEE80211_EV_IF_NOT_RUNNING;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, NULL);
        break;
    default:
        break;
    }
}

int osif_vap_stop_ap(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
#if WLAN_SPECTRAL_ENABLE
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    bool is_spectral_active = false;
    enum spectral_scan_mode smode;
    struct wlan_lmac_if_tx_ops *tx_ops;
#endif /* WLAN_SPECTRAL_ENABLE */

    opmode = wlan_vap_get_opmode(vap);
    if (ieee80211_ucfg_bringdown_txvap(vap)) {
        /* If ucfg_bringdown fails, invoke bringdown sequence */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : stopping %s vap \n",
                __func__, opmode == IEEE80211_M_HOSTAP ? "AP" : "MONITOR");
        wlan_mlme_stop_vdev(vap->vdev_obj, WLAN_MLME_STOP_BSS_F_WAIT_RX_DONE |
                WLAN_MLME_STOP_BSS_F_NO_RESET, WLAN_MLME_NOTIFY_OSIF);
    }

#if WLAN_SPECTRAL_ENABLE
    /* If all the vaps are going down, stop spectral scan */
    pdev = ic->ic_pdev_obj;
    if (!pdev)
        return -EINVAL;

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc)
        return -EINVAL;

    tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
    if (!tx_ops) {
        qdf_err("tx_ops is NULL");
        return -EINVAL;
    }

    smode = SPECTRAL_SCAN_MODE_NORMAL;
    for (; smode < SPECTRAL_SCAN_MODE_MAX; smode++)
        is_spectral_active |= tx_ops->sptrl_tx_ops.
            sptrlto_is_spectral_active(pdev, smode);

    if (is_spectral_active) {
        size_t active_vdev_count = 0;

        active_vdev_count = osif_get_num_active_vaps(ic);
        if (active_vdev_count == 1) {
            enum spectral_cp_error_code err;

            smode = SPECTRAL_SCAN_MODE_NORMAL;
            for (; smode < SPECTRAL_SCAN_MODE_MAX; smode++)
                tx_ops->sptrl_tx_ops.
                    sptrlto_stop_spectral_scan(pdev, smode, &err);
        }
    }
#endif /* WLAN_SPECTRAL_ENABLE */
    return 0;
}

int osif_vap_stop_sta(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    return wlan_mlme_cm_stop(vap->vdev_obj, CM_OSIF_DISCONNECT,
                             REASON_STA_LEAVING, true);
}

int osif_vap_pre_stop_ap(struct net_device *dev)
{
    /* Do nothing */
    return 0;
}

int osif_vap_pre_stop_sta(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    qdf_info("Stopping STA vap");
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    if (osifp->os_opmode == IEEE80211_M_STA)
        wlan_mlme_stacac_restore_defaults(vap);
#endif

    vap->iv_roam_inprogress = FALSE;

    return 0;
}

int osif_vap_pre_stop(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic;
    struct net_device *comdev;
    enum ieee80211_opmode opmode;
    int ret = 0;

    if (!vap)
       return -EINVAL;

    ic = vap->iv_ic;
    comdev = osifp->os_comdev;

#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_vap_stop(osifp);
#endif

    wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, INVAL_SCAN_ID,
            WLAN_SCAN_CANCEL_VDEV_ALL, false);

#if UMAC_SUPPORT_CFG80211
    if (ic->ic_cfg80211_config)
        wlan_cfg80211_cleanup_scan_queue(ic->ic_pdev_obj, dev);
#endif

    if (dev->flags & IFF_RUNNING) {
        dev->flags &= ~IFF_RUNNING;
        if (osif_get_num_active_vaps(ic) == 0 &&
                comdev->flags & IFF_RUNNING) {
            dev_close(comdev);
        }
    }

    vap->iv_needs_up_on_acs = 0;
    vap->iv_cfg80211_acs_pending = 0;

    opmode = wlan_vap_get_opmode(vap);
    switch(opmode) {
    case IEEE80211_M_STA:
        ret = osif_vap_pre_stop_sta(dev);
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_MONITOR:
        ret = osif_vap_pre_stop_ap(dev);
    default:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : mode not suported \n",
                __func__);
        break;
    }

    return ret;
}


int osif_vap_stop(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
    int ret = 0;

    ret = osif_vap_pre_stop(dev);
    if (ret)
        return ret;

    opmode = wlan_vap_get_opmode(vap);
    switch(opmode) {
    case IEEE80211_M_STA:
        ret = osif_vap_stop_sta(dev);
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_MONITOR:
        ret = osif_vap_stop_ap(dev);
        break;
    default:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : mode not suported \n",
                __func__);
        break;
    }

    return ret;
}

int osif_pdev_restart(struct ieee80211vap *vap)
{
    return wlan_mlme_dev_restart(vap->vdev_obj, WLAN_SER_CMD_PDEV_RESTART);
}

int osif_vdev_restart(struct ieee80211vap *vap)
{
    return wlan_mlme_dev_restart(vap->vdev_obj, WLAN_SER_CMD_VDEV_RESTART);
}

int osif_pdev_stop_start_vaps(struct ieee80211com *ic)
{
    wlan_if_t tmpvap;
    struct net_device *tmpdev;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if (IS_UP(tmpdev) &&
            wlan_vdev_chan_config_valid(tmpvap->vdev_obj) == QDF_STATUS_SUCCESS)
            osif_vap_init(tmpdev, RESCAN);
    }
    return 0;
}

/*
 * osif_pdev_restart_vaps() - Multi-vdev restart
 * @ic: radio parameter
 *
 * Restart all vdevs belonging to this pdev.
 * Only one pdev restart command is added to the serialization queue of the
 * first vdev. On cmd activation, restart is triggered for all the vdev's of
 * this pdev
 *
 * Return: Success on adding cmd to vdev queue
 * */
int osif_pdev_restart_vaps(struct ieee80211com *ic)
{
    int retv = 0;
    wlan_if_t tmpvap;
    struct ieee80211_vap_opmode_count vap_opmode_count = { 0 };

    qdf_assert_always(ic);

    /*
     * If there are STA vaps belonging to this ic then use individual vdev
     * stop-start. Else use optimized pdev restart.
     */
    OS_MEMZERO(&vap_opmode_count, sizeof(struct ieee80211_vap_opmode_count));
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
    if ((vap_opmode_count.sta_count) || !vap_opmode_count.total_vaps) {
        retv = osif_pdev_stop_start_vaps(ic);
        return retv;
    }

    if (!ieee80211_get_num_active_vaps(ic)) {
        if (ic->ic_config_update)
            ic->ic_config_update(ic);
        return retv;
    }

    tmpvap = TAILQ_FIRST(&ic->ic_vaps);
    if (tmpvap)
        retv = osif_pdev_restart(tmpvap);
    else
        qdf_err("Invalid VAP");

    return retv;
}

static int osif_setup_vap( osif_dev *osifp, enum ieee80211_opmode opmode,
                            u_int32_t flags, char *bssid)
{
    wlan_dev_t devhandle = osifp->os_devhandle;
    int error;
    wlan_if_t vap;
    ieee80211_privacy_exemption privacy_filter;
    int scan_priority_mapping_base;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct vdev_osif_priv *vdev_osifp = NULL;
    struct wlan_vdev_create_params params;
    struct wlan_objmgr_psoc *psoc = NULL;
    uint16_t waitcnt;
    QDF_STATUS status;

    psoc = wlan_pdev_get_psoc(devhandle->ic_pdev_obj);
    switch (opmode) {
#ifdef  ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_GO:
        qdf_print(" %s: Creating NEW P2P GO interface", __func__);
        osifp->p2p_go_handle = wlan_p2p_GO_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_go_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_GO_get_vap_handle(osifp->p2p_go_handle);
        break;

    case IEEE80211_M_P2P_CLIENT:
        qdf_print(" %s: Creating NEW P2P Client interface", __func__);
        osifp->p2p_client_handle = wlan_p2p_client_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_client_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_client_get_vap_handle(osifp->p2p_client_handle);
        break;

    case IEEE80211_M_P2P_DEVICE:
        qdf_print(" %s: Creating NEW P2P Device interface", __func__);
        osifp->p2p_handle = wlan_p2p_create(devhandle, NULL);
        if (osifp->p2p_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_get_vap_handle(osifp->p2p_handle);
        break;
#endif
    default:
        qdf_print(" %s: Creating NEW DEFAULT interface", __func__);
        if (opmode == IEEE80211_M_STA) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        else if (opmode == IEEE80211_M_IBSS) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_IBSS_BASE;
        }
        else if (opmode == IEEE80211_M_HOSTAP) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_AP_BASE;
        }
        else if (opmode == IEEE80211_M_MONITOR) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        else {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }

        OS_MEMZERO(&params,sizeof(struct wlan_vdev_create_params));
        params.opmode = opmode;
        IEEE80211_ADDR_COPY(params.macaddr,bssid);
        params.flags = flags;
        params.size_vdev_priv = sizeof(struct vdev_osif_priv);
        params.legacy_osif = osifp;

        vdev = wlan_objmgr_vdev_obj_create(devhandle->ic_pdev_obj, &params);

        if(vdev != NULL) {
            vdev_osifp = wlan_vdev_get_ospriv(vdev);
            vdev_osifp->wdev = NULL;
            /* In sta mode when old bss node is freed, it is posted as an event to
             * connection state machine, which initiates creation of new bss peer.
             * At this point, unless the peer's destroy handler has been executed and
             * max peers per vap are decremented already, the creation of new bss peer
             * will fail. To handle this syncronization the max peers per vap are
             * increased from 2 to 3
             */
            if (opmode == IEEE80211_M_STA) {
                wlan_vdev_set_max_peer_count(vdev, 3);
            }
            waitcnt = 0;
            while((!((vdev->obj_state == WLAN_OBJ_STATE_CREATED) ||
                   (vdev->obj_state == WLAN_OBJ_STATE_CREATION_FAILED)) &&
                     (waitcnt < WLAN_VDEV_CREATE_TIMEOUT_CNT))) {
                qdf_sleep_us(WLAN_VDEV_CREATE_TIMEOUT*1000);
                waitcnt++;
            }
            if(vdev->obj_state == WLAN_OBJ_STATE_CREATION_FAILED) {
                qdf_print("VDEV (partial creation) failed ");
                vap = wlan_vdev_get_mlme_ext_obj(vdev);
                if (vap != NULL) {
                   wlan_vap_delete(vap);
                }
                else {
                   wlan_objmgr_vdev_obj_delete(vdev);
                }
                vdev = NULL;
            }
        }
        else {
            qdf_print("VDEV (creation) failed ");
        }

        break;
    }
    if (!vdev) {
        return ENOMEM;
    }
    vap = (wlan_if_t)wlan_vdev_get_mlme_ext_obj(vdev);
    if (vap) {
        /*
         * Update vdev chainmasks.
         *
         * Rather than obtain a lock for the vdev again at another place in this
         * function, we set the vdev's chainmasks right here while we hold the
         * lock.
         * But we need to do so only if vap is non-NULL.
         */
        wlan_vdev_mlme_set_txchainmask(vdev, devhandle->ic_tx_chainmask);
        wlan_vdev_mlme_set_rxchainmask(vdev, devhandle->ic_rx_chainmask);
    }

    if (!vap) {
        return ENOMEM;
    }

     /*TODO it is supposed to be done as part of creation, but this can be updated seperately */
    vap->iv_scan_priority_base = scan_priority_mapping_base;
    osifp->os_opmode = opmode;
    osifp->os_if = vap;            /* back pointer */
    osifp->ctrl_vdev = vdev;      /* storing vdev object pointer */
    osif_vap_setup(vap, osifp->netdev, opmode);

    if (opmode == IEEE80211_M_P2P_DEVICE)
       wlan_set_desired_phymode(vap,IEEE80211_MODE_11G);
    else
       wlan_set_desired_phymode(vap, IEEE80211_MODE_AUTO);

    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame */
    privacy_filter.ether_type = ETHERTYPE_PAE;
    privacy_filter.packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter.filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    wlan_set_privacy_filters(vap,&privacy_filter,1);
    do {
            ieee80211_cipher_type ctypes[1];
    error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, 1 << WLAN_CRYPTO_AUTH_OPEN);

            ctypes[0] = IEEE80211_CIPHER_NONE;
            osifp->uciphers[0] = osifp->mciphers[0] = IEEE80211_CIPHER_NONE;
            osifp->u_count = osifp->m_count = 1;
            error = wlan_set_ucast_ciphers(vap,ctypes,1);
            error = wlan_set_mcast_ciphers(vap,ctypes,1);
    } while(0);

    /* register scan event handler */
    /* Allocate requester ID without attaching callback function */
    osifp->scan_requestor = ucfg_scan_register_requester(wlan_vdev_get_psoc(vdev),
            (uint8_t*)"osif_umac", NULL, NULL);
    if (!osifp->scan_requestor) {
        scan_err("unable to allocate requester");
    }
    /* Register scan event callback with scan module */
    status = ucfg_scan_register_event_handler(wlan_vdev_get_pdev(vdev),
            &osif_scan_evhandler, (void*)osifp);
    if (status) {
        scan_err("unable to register scan event handler vap: 0x%pK status: %d", vap, status);
    }

    return 0;
}

static void osif_delete_vap(struct net_device *dev, int recover)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    struct wlan_objmgr_vdev *vdev = osifp->ctrl_vdev;
    struct ieee80211com *ic;
    wlan_if_t vap = NULL;

    wlan_objmgr_vdev_get_ref(vdev, WLAN_MLME_NB_ID);
    vap = (wlan_if_t)wlan_vdev_get_mlme_ext_obj(vdev);

    if(vap == NULL) {
        qdf_err("vap is NULL, vdev deletion failed ");
        return;
    }
#ifdef WLAN_OBJMGR_REF_ID_TRACE
    if (vap->iv_ref_leak_test_flag) {
        wlan_objmgr_vdev_get_ref(vdev, WLAN_MLME_NB_ID);
    }
#endif
    ic = wlan_vdev_get_ic(vdev);
    if(ic == NULL) {
        qdf_err("ic is NULL, vdev deletion failed ");
        return;
    }
#if QCA_LTEU_SUPPORT
    if (ic->ic_nl_handle)
        ieee80211_nl_unregister_handler(vap, osif_mu_report, osif_nl_scan_evhandler);
#endif
#if DBG_LVL_MAC_FILTERING
    dbgmac_peer_list_free(vap->dbgmac_peer_list);
#endif
    STA_VAP_DOWNUP_LOCK(ic);
    if(vap == ic->ic_sta_vap)
        ic->ic_sta_vap = NULL;
    if(vap == ic->ic_mon_vap)
    {
        ic->ic_mon_vap = NULL;
        wlan_pdev_set_mon_vdev(ic->ic_pdev_obj, NULL);
    }
    STA_VAP_DOWNUP_UNLOCK(ic);

#if DBDC_REPEATER_SUPPORT
    GLOBAL_IC_LOCK_BH(ic->ic_global_list);
    if (vap == ic->ic_global_list->max_priority_stavap_up) {
        ic->ic_global_list->max_priority_stavap_up = NULL;
    }
    GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
#endif
    /* Disable new scans on this vdev */
    ucfg_scan_vdev_set_disable(vdev, REASON_VDEV_DOWN);

    /* unregister scan event handler */
    ucfg_scan_unregister_event_handler(wlan_vap_get_pdev(vap), &osif_scan_evhandler, (void *)osifp);
    ucfg_scan_unregister_requester(wlan_vap_get_psoc(vap), osifp->scan_requestor);

    /* forcefully delete cfg80211 acs event handler registration and vap is getting deleted */
    wlan_autoselect_unregister_event_handler(vap,
                &cfg80211_acs_event_handler, (void *)osifp);
    vap->iv_cfg80211_acs_pending = 0;
    /* If ACS is in progress, unregister scan handlers in ACS */
    osif_vap_acs_cancel(dev, 0);

    wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, INVAL_SCAN_ID,
            WLAN_SCAN_CANCEL_VDEV_ALL, true);

    if ((osifp->os_opmode == IEEE80211_M_STA) && dp_is_extap_enabled(vdev)) {
        dp_extap_disable(vdev);
        if (ic->ic_miroot)
            mi_tbl_purge(&ic->ic_miroot);
        else
            dp_extap_mitbl_purge(dp_get_extap_handle(vdev));
    }

    osifp->is_deleted = 0;
    /*
    * flush the frames belonging to this vap from osdep queues.
    */
    // ath_flush_txqueue(osifp->os_devhandle, vap);
    switch( osifp->os_opmode) {
#ifdef  ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_GO:
        qdf_print(" Deleting  P2PGO vap ");
        wlan_p2p_GO_delete(osifp->p2p_go_handle);
        osifp->p2p_go_handle = NULL;
        break;

    case IEEE80211_M_P2P_CLIENT:
        qdf_print(" Deleting  P2P Client  ");
        wlan_mlme_cancel(vap);
        wlan_p2p_client_delete(osifp->p2p_client_handle);
        osifp->p2p_client_handle = NULL;
        break;

    case IEEE80211_M_P2P_DEVICE:
        qdf_print(" Deleting  P2P device  ");
        wlan_p2p_delete(osifp->p2p_handle);
        osifp->p2p_handle = NULL;
        break;
#endif
    case IEEE80211_M_MONITOR:
        if (vap->mac_entries)
            wlan_mon_flush_maclist(vap);
    default:
        if (recover) {
            ieee80211_flush_vap_mgmt_queue(vap, true);
            wlan_vap_recover(vap);
        } else {
            wlan_vap_delete(vap);
        }

        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);

        break;
    }
}

#if WLAN_SPECTRAL_ENABLE
int
osif_ioctl_eacs(struct net_device *dev, struct ifreq *ifr, osdev_t os_handle)
{

    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    struct scan_start_request *scan_params = NULL;
    ieee80211_ssid    ssid_list[IEEE80211_SCAN_MAX_SSID];
    int               n_ssid;
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct wlan_objmgr_vdev *vdev = NULL;

    if (!(dev->flags & IFF_UP)) {
        return -EINVAL;     /* XXX */
    }

    vdev = osifp->ctrl_vdev;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        scan_info("unable to get reference");
        return -EINVAL;
    }

    scan_params = (struct scan_start_request*) qdf_mem_malloc(sizeof(*scan_params));
    if (!scan_params) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        scan_err("unable to allocate scan request");
        return -ENOMEM;
    }

    if (wlan_vdev_scan_in_progress(vap->vdev_obj)) {
        wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, 0,
                WLAN_SCAN_CANCEL_VDEV_ALL, false);
        OS_DELAY(1000);
    }

    /* Fill scan parameter */
    n_ssid = wlan_get_desired_ssidlist(vap, ssid_list, IEEE80211_SCAN_MAX_SSID);

    status = wlan_update_scan_params(vap,scan_params,IEEE80211_M_HOSTAP,
            false,true,false,true,0,NULL,0);
    if (status) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        qdf_mem_free(scan_params);
        scan_err("scan param init failed with status: %d", status);
        return -EINVAL;
    }

    switch (opmode)
    {
        case IEEE80211_M_HOSTAP:
            scan_params->scan_req.scan_flags = 0;
            scan_params->scan_req.scan_f_passive = true;
            scan_params->scan_req.scan_f_2ghz = true;
            scan_params->scan_req.scan_f_5ghz = true;

            /* XXX tunables */
            scan_params->scan_req.dwell_time_passive = 300;
            break;

        default:break;
    }

    status = wlan_ucfg_scan_start(vap, scan_params, osifp->scan_requestor,
            SCAN_PRIORITY_LOW, &(osifp->scan_id), 0, NULL);
    if (status) {
        scan_err("scan_start failed with status: %d", status);
    }
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
    return 0;
}
qdf_export_symbol(osif_ioctl_eacs);
#endif

extern int ieee80211_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

/*
 * ndo_ops structure for 11AC fast path
 */


#ifdef WLAN_FEATURE_FASTPATH
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_11ac_fp_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
    .ndo_set_mac_address = osif_change_mac_addr,
};

static struct net_device_ops osif_11ac_wifi3_fp_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
    .ndo_set_mac_address = osif_change_mac_addr,
};
#endif
#endif /* WLAN_FEATURE_FASTPATH */

#ifdef QCA_SUPPORT_WDS_EXTENDED
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_wds_ext_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_wds_ext_getstats,
#else
    .ndo_get_stats = osif_wds_ext_getstats,
#endif
    .ndo_open = osif_wds_ext_dev_open,
    .ndo_stop = osif_wds_ext_dev_stop,
    .ndo_start_xmit = NULL,
    .ndo_set_mac_address = osif_wds_ext_change_mac,
};
#endif
#endif /* QCA_SUPPORT_WDS_EXTENDED */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
    .ndo_set_mac_address = osif_change_mac_addr,
};
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)) || PARTNER_ETHTOOL_SUPPORTED
static struct ethtool_ops osif_ethtool_ops;
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) */

static inline
void osif_dev_set_offload_tx_csum(struct net_device *dev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)
    dev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->vlan_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    dev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0)
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}


static inline
void osif_dev_set_tso(struct net_device *dev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) || PARTNER_ETHTOOL_SUPPORTED
    dev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    /*  dev->gso_max_size  not setting explicitly since our HW capable handling any size packet,
     *  No limitation for MAX Jumbo Pkt size */
    /* Folowing is required to have TSO support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    /* For Lower kernel versions TSO is enabled always,
     * when enabled in build using the option HOST_SW_TSO_SG_ENABLE */
    dev->features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0) || PARTNER_ETHTOOL_SUPPORTED
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}

static inline
void osif_dev_set_sg(struct net_device *dev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)
    dev->hw_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    /*  dev->gso_max_size  not setting explicitly since our HW capable handling any size packet,
     *  No limitation for MAX Jumbo Pkt size */
    /* Folowing is required to have TSO support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    /* For Lower kernel versions TSO is enabled always,
     * when enabled in build using the option HOST_SW_TSO_SG_ENABLE */
    dev->features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0)
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_nss_wifiol_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
    .ndo_set_mac_address = osif_change_mac_addr,
};
#endif

#ifdef QCA_SUPPORT_WDS_EXTENDED
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_nss_wds_ext_vdev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_wds_ext_getstats,
#else
    .ndo_get_stats = osif_wds_ext_getstats,
#endif
    .ndo_open = osif_wds_ext_dev_open,
    .ndo_stop = osif_wds_ext_dev_stop,
    .ndo_start_xmit = NULL,
    .ndo_set_mac_address = osif_wds_ext_change_mac,
};
#endif
#endif /* QCA_SUPPORT_WDS_EXTENDED */
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

#ifdef QCA_SUPPORT_WDS_EXTENDED
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
int osif_register_wds_ext_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    if (vap_hardstart == NULL)
        return -EINVAL;

    switch (netdev_type) {
    case OSIF_NETDEV_TYPE_OL_WIFI3:
        osif_wds_ext_dev_ops.ndo_start_xmit = vap_hardstart;
        break;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    case OSIF_NETDEV_TYPE_NSS_WIFIOL:
        osif_nss_wds_ext_vdev_ops.ndo_start_xmit = vap_hardstart;
        break;
#endif
    default:
        return -EINVAL;
    }

    return 0;
}
#else
int osif_register_wds_ext_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    return 0;
}
#endif
qdf_export_symbol(osif_register_wds_ext_dev_ops_xmit);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
int osif_register_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    if (vap_hardstart == NULL)
        return -EINVAL;

    switch (netdev_type) {
    case OSIF_NETDEV_TYPE_DA:
        osif_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
#ifdef WLAN_FEATURE_FASTPATH
    case OSIF_NETDEV_TYPE_OL:
        osif_11ac_fp_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
    case OSIF_NETDEV_TYPE_OL_WIFI3:
        osif_11ac_wifi3_fp_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    case OSIF_NETDEV_TYPE_NSS_WIFIOL:
        osif_nss_wifiol_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
#endif
    default:
        return -EINVAL;
        break;
    }
    return 0;
}
#else
int osif_register_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    return 0;
}
#endif
qdf_export_symbol(osif_register_dev_ops_xmit);

int
osif_create_vap_check(struct net_device *comdev,
        struct ieee80211_clone_params *cp)
{
    osdev_t os_handle = NULL;
    enum ieee80211_opmode opmode = cp->icp_opmode;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
    struct ieee80211com *ic = &scn->sc_ic;
    bool scan_radio_support;

    os_handle = ic->ic_osdev;
    if (!capable(CAP_NET_ADMIN))
        return -EINVAL;

    cp->icp_opmode = ieee80211_opmode2qdf_opmode(opmode);
    if(cp->icp_opmode >= QDF_MAX_NO_OF_MODE) {
        qdf_print("opmode(%d) is not supported", opmode);
        return -EINVAL;
    }

    scan_radio_support =
            wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                           WLAN_PDEV_FEXT_SCAN_RADIO);
    if (scan_radio_support && !((cp->icp_flags & IEEE80211_SPECIAL_VAP) &&
        !(cp->icp_flags & IEEE80211_SMART_MONITOR_VAP))) {
        qdf_err("only special vap type is allowed for scan radio pdev");
        return -EINVAL;
    }

#if QCA_LTEU_SUPPORT
    if (ic->ic_nl_handle && cp->icp_opmode != QDF_SAP_MODE) {
        qdf_print("Only AP mode %d is supported for NL, not %d", QDF_SAP_MODE, cp->icp_opmode);
        return -EINVAL;
    }
    if(QDF_IBSS_MODE == cp->icp_opmode)
    {
        /* IBSS is not supported in partial offload architecture in linux
           As wlanconfig does not know about arhictecure i.e.e DA or partial offload
           so it sets the mode which may result a crash of firmware
           so refining it here and making sure if mode is IBSS and architecture
           is peregrine then we should not create VAP */
        qdf_print("ADHOC Not enabled in partial offload ");
        return -EINVAL;
    }
#endif
    return 0;
}

osif_dev *
osif_recover_vap_netdev(struct ieee80211vap *vap)
{
    struct net_device *dev = NULL;
    osif_dev  *osifp = NULL;
    int unit;
#if UMAC_SUPPORT_CFG80211
    struct wireless_dev iv_wdev;
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    nss_if_num_t nss_ifnum;
    uint32_t recovery_state;
#endif
    void * ctrl_vdev;

    /* copy few things to restore down */
    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = osifp->netdev;
    unit = osifp->os_unit;
    ctrl_vdev = (void *)osifp->ctrl_vdev;

#if UMAC_SUPPORT_CFG80211
    memcpy(&iv_wdev, &osifp->iv_wdev, sizeof(iv_wdev));
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    nss_ifnum = osifp->nss_recov_if;
    recovery_state = osifp->nss_recov_mode;
#endif
    ieee80211_vap_deleted_clear(vap); /* clear the deleted */

    memset(osifp,0,sizeof(osif_dev));

    spin_lock_init(&osifp->list_lock);

    spin_lock_init(&osifp->tx_lock);

    osifp->os_unit = unit;
    osifp->os_if = vap;
    osifp->netdev = dev;
    osifp->ctrl_vdev = ctrl_vdev;

#if UMAC_SUPPORT_CFG80211
    memcpy(&osifp->iv_wdev, &iv_wdev, sizeof(osifp->iv_wdev));
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osifp->nss_recov_if = nss_ifnum;
    osifp->nss_recov_mode = recovery_state;
#endif
    return osifp;
}

int
osif_create_vap_netdev_free(struct net_device *dev, int unit)
{
    qdf_net_delete_wlanunit(unit);
    free_netdev(dev);

    return 0;
}

int
osif_create_vap_netdev_unregister(struct net_device *dev, int unit)
{
    qdf_net_delete_wlanunit(unit);
    unregister_netdevice(dev);

    return 0;
}

osif_dev *
osif_create_vap_netdev_alloc(struct ieee80211_clone_params *cp, uint8_t multiq_support_enabled)
{
    struct net_device *dev = NULL;
    char name[IFNAMSIZ];
    char unum[QCA_INTF_IDXSIZE];
    int error, unit;
    osif_dev  *osifp = NULL;

    error = qdf_net_ifc_name2unit(cp->icp_name, &unit);
    if (error) {
        qdf_err("Failed to extract unit number");
        return NULL;
    }

    /* Allocation is tricky here, so let's give a few explanation.
     * We are basically trying to handle two cases:
     * - if the number isn't specified by the user, we have to allocate one,
     *   in which case we need to make sure it's not already been allocated
     *   already. User says "ath" and we create "athN" with N being a new unit#
     * - if the number is specified, we just need to make sure it's not been
     *   allocated already, which we check using dev_get_by_name()
     */
    if (unit == -1) {
        unit = qdf_net_new_wlanunit();
        if (unit == -1) {
            qdf_err("Failed to allocate unit number");
            return NULL;
        }
        snprintf(name, sizeof(name), "%s", cp->icp_name);
        snprintf(unum, sizeof(unum), "%d", unit);
        if (strlen(name) < (IFNAMSIZ - QCA_INTF_IDXSIZE)) {
           if (strlcat(name, unum, sizeof(name))  >=  sizeof(name)) {
              qdf_err("source too long");
              return NULL;
           }
        }
    } else {
         int dev_exist = qdf_net_dev_exist_by_name(cp->icp_name);
         if (dev_exist) {
             qdf_err("%s net dev exists already", cp->icp_name);
             return NULL;
         }

        qdf_net_alloc_wlanunit(unit);
        if (strlcpy(name, cp->icp_name, sizeof(name)) >=  sizeof(name)) {
            qdf_print("source too long");
            return NULL;
        }
        name[IFNAMSIZ - 1] = '\0';
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    if (multiq_support_enabled)
        dev = alloc_netdev_mqs(sizeof(osif_dev), "wifi%d", 0, ether_setup,
                OSIF_DP_NETDEV_TX_QUEUE_NUM, OSIF_DP_NETDEV_RX_QUEUE_NUM);
    else
        dev = alloc_netdev(sizeof(osif_dev), "wifi%d", 0, ether_setup);
#else
    if (multiq_support_enabled)
        dev = alloc_netdev_mqs(sizeof(osif_dev), name, ether_setup,
                OSIF_DP_NETDEV_TX_QUEUE_NUM, OSIF_DP_NETDEV_RX_QUEUE_NUM);
    else
        dev = alloc_netdev(sizeof(osif_dev), name, ether_setup);
#endif
    if(dev == NULL) {
        qdf_net_delete_wlanunit(unit);
        return NULL;
    }
    if (name != NULL)   /* XXX */
        if (strlcpy(dev->name, name, sizeof(dev->name)) >= sizeof(dev->name)) {
            qdf_print("source too long");
            return NULL;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    dev->max_mtu = ATH_MAX_MTU;
#endif

    /*
    ** Clear and initialize the osif structure
    */
    osifp = ath_netdev_priv(dev);

    memset(osifp,0,sizeof(osif_dev));
    osifp->netdev = dev;

    spin_lock_init(&osifp->list_lock);

    spin_lock_init(&osifp->tx_lock);

    osifp->os_unit  = unit;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    /*
     * Initialize NSS recovery interface number for VAP.
     */
    osifp->nss_recov_if = -1;
    osifp->nss_recov_mode = false;
#endif
    return osifp;
}

int
osif_create_vap_bssid_free(struct ieee80211com *ic,
                   uint8_t *req_mac,
                   struct ieee80211_clone_params *cp)
{
    bool macreq_enabled = FALSE;

    macreq_enabled = ic->ic_is_macreq_enabled(ic);
    /* remove the bssid from vapid */
    if( (cp->icp_vapid != VAP_ID_AUTO) &&
        ((cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) &&
        (macreq_enabled == TRUE))
        {
            wlan_vap_free_mac_addr(ic, req_mac, cp);
        }

    return 0;
}

static bool
osif_mbssid_sanity_check(struct ol_ath_softc_net80211 *scn,
                         struct ieee80211_clone_params *cp)
{
    struct ieee80211com *ic = &scn->sc_ic;
    bool is_mbssid_enabled  = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool sanity_ok          = true;
    uint8_t lsb_of_last_user_bssid, i;
    /* Number of vaps in mbss-cache */
    uint8_t nvaps_in_cache;

    nvaps_in_cache = (is_mbssid_enabled) ?
                              ieee80211_mbssid_get_num_vaps_in_mbss_cache(ic) :
                              ieee80211_get_num_beacon_ap_vaps(ic);

    if (is_mbssid_enabled || ic->ic_wideband_capable) {
        if (cp->icp_opmode != QDF_SAP_MODE ||
            cp->icp_flags & IEEE80211_SMART_MONITOR_VAP ||
            cp->icp_flags & IEEE80211_SPECIAL_VAP) {
            mbss_err("mbssid sanity required for AP VAPs only");
            goto exit;
        }

        /* Fail sanity check if ema_ap_num_max_vaps no
         * of vaps are already created
         */
        if (nvaps_in_cache >= scn->soc->ema_ap_num_max_vaps) {
            mbss_err("mbssid_sanity failed - ema_ap_num_max_vaps"
                     " = %d vaps already created",
                     scn->soc->ema_ap_num_max_vaps);
            sanity_ok = false;
            goto exit;
        }

        if ((cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) {
            bool is_first_ap_vap = !nvaps_in_cache;
            if (is_first_ap_vap) {
                /* Overwrite the ref_bssid */
                IEEE80211_ADDR_COPY(ic->ic_mbss.ref_bssid, cp->icp_bssid);
            } else {
                /* Sanity check on 48-n MSB bits required */
                for (i = 0; i < IEEE80211_ADDR_LEN - 1; i++) {
                    if (cp->icp_bssid[i] != ic->ic_mbss.ref_bssid[i]) {
                        mbss_err("48-n MSB of bssid does not match"
                                 " with that of ref_bssid");
                        sanity_ok = false;
                        goto exit;
                    }
                }

                if ((cp->icp_bssid[ATH_BSSID_INDEX] &
                        ~(MBSSID_GROUP_SIZE(ic) - 1)) !=
                    (ic->ic_mbss.ref_bssid[ATH_BSSID_INDEX] &
                        ~(MBSSID_GROUP_SIZE(ic) - 1))) {
                    mbss_err("48-n MSB of bssid does not match"
                             " with that of ref_bssid");
                    sanity_ok = false;
                    goto exit;
                }

                lsb_of_last_user_bssid = ic->ic_mbss.lsb_of_last_user_bssid;

                /* Sequential bssid sanity if ema_ap_num_max_vaps
                 * < MBSSID_POOL_SIZE(ic) */
                if (scn->soc->ema_ap_num_max_vaps < MBSSID_GROUP_SIZE(ic)) {
                    /* n-bit nibble expected for the bssid of this vap
                     * is expected to be sequentially next of the n-bit
                     * nibble of the bssid of the last vap. Last octet
                     * of the bssid of the last vap created is saved in
                     * 'lsb_of_last_user_bssid'. Therefore,
                     * 1. n-bit nibble of the last bssid is
                     * x = lsb_of_last_user_bssid & (MBSSID_GROUP_SIZE(ic) - 1)
                     * 2. n-bit nibble expected for the bssid of this
                     * vap is (x + 1) % MBSSID_GROUP_SIZE(ic)
                     */
                    uint8_t expected_n_bit_nibble =
                                        ((lsb_of_last_user_bssid &
                                           (MBSSID_GROUP_SIZE(ic) - 1)) + 1) %
                                                MBSSID_GROUP_SIZE(ic);
                    mbss_info("expected_n_bit_nibble: 0x%x", expected_n_bit_nibble);

                    if (expected_n_bit_nibble !=
                            (cp->icp_bssid[ATH_BSSID_INDEX] &
                            (MBSSID_GROUP_SIZE(ic) -1 ))) {
                        mbss_err("bssids must be sequential when"
                                " ema_ap_num_max_vaps is less than"
                                " MBSSID group size");
                        sanity_ok = false;
                        goto exit;
                    } else {
                        lsb_of_last_user_bssid =
                            cp->icp_bssid[ATH_BSSID_INDEX];
                    }
                }
            } /* end check for first vap */
        } /* end check for clone_bssid */
    } /* check for mbssid feature enable */

exit:
    mbss_info("mbssid_sanity_ok: %s", sanity_ok ? "YES" : "NO");
    return sanity_ok;
}

static QDF_STATUS
osifp_create_wlan_vap_bss_status(struct ieee80211com *ic,
                                 struct ieee80211vap *vap)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    uint16_t waitcnt;
    qdf_event_t wait_event;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    qdf_mem_zero(&wait_event, sizeof(wait_event));
    qdf_event_create(&wait_event);
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (wlan_psoc_nif_feat_cap_get(psoc,
                                   WLAN_SOC_F_PEER_CREATE_RESP)) {
        waitcnt = 0;
        qdf_event_reset(&wait_event);

        while(!wlan_vap_get_bss_rsp_evt_status(vap) &&
              waitcnt < WLAN_VDEV_CREATE_TIMEOUT_CNT) {
              qdf_wait_single_event(&wait_event, (WLAN_VDEV_CREATE_TIMEOUT/2));
              waitcnt++;
        }

        if (!wlan_vap_get_bss_rsp_evt_status(vap) ||
            !wlan_vap_is_bss_created(vap)) {
            status = QDF_STATUS_E_FAILURE;
        }
    } else {
        wlan_vap_set_bss_status(vap, PEER_CREATED);
    }

    qdf_event_destroy(&wait_event);
    return status;
}

wlan_if_t
osifp_create_wlan_vap(struct ieee80211_clone_params *cp,
                     osif_dev *osifp,
                     struct net_device *comdev,
                     int cfg80211_create)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    bool macreq_enabled = FALSE;
    uint8_t bsta_fixed_idmask = 0xff;
    uint32_t prealloc_idmask;
    uint8_t req_mac[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
    uint8_t num_vdevs;
    int id = -1;
    uint16_t waitcnt;
    uint8_t id_used = 0;
    uint8_t vap_destroy;
    struct wlan_vdev_create_params params;
    struct vdev_osif_priv *vdev_osifp = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    int scan_priority_mapping_base;
    wlan_if_t vap;
    wlan_if_t tempvap;
#if UMAC_SUPPORT_CFG80211
    enum nl80211_iftype nl_type;
#endif
    uint8_t vap_addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
    struct net_device *dev = osifp->netdev;
    struct wlan_objmgr_psoc *psoc = NULL;
    int current_bssid_ix = 0;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE);

    macreq_enabled = ic->ic_is_macreq_enabled(ic);
    prealloc_idmask = ic->ic_get_mac_prealloc_idmask(ic);
    bsta_fixed_idmask = ic->ic_get_bsta_fixed_idmask(ic);

    if (!osif_mbssid_sanity_check(OL_ATH_SOFTC_NET80211(ic), cp)) {
        mbss_err("mbssid sanity failed - vap create failed");
        return NULL;
    }

    num_vdevs = ATH_BCBUF;
    if (macreq_enabled == TRUE) {
       if (cp->icp_vapid == VAP_ID_AUTO) {
           for(id = 0; id < ATH_MAX_PREALLOC_ID; id++)
           {
               if((prealloc_idmask & (1 << id)) == 0)
                   break;
           }
       }
       /* generate the bssid from vapid */
       if((cp->icp_vapid != VAP_ID_AUTO) &&
          (cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) {
            if((cp->icp_vapid >= ATH_MAX_PREALLOC_ID)) {
                /* Support for Higher vapids (8-15) logic is added. */
                cp->icp_vapid = (cp->icp_vapid - ATH_MAX_PREALLOC_ID);
            } else {
                /* Support for Lower vapids (0-7) logic is unchanged. */
                cp->icp_vapid = (cp->icp_vapid + ATH_MAX_PREALLOC_ID);
            }

            IEEE80211_ADDR_COPY(req_mac, ic->ic_my_hwaddr);

            if (is_mbssid_enabled) {
                IEEE80211_ADDR_COPY(req_mac, ic->ic_mbss.ref_bssid);
                MBSSID_ATH_SET_VAP_BSSID(req_mac,
                          ic->ic_my_hwaddr, cp->icp_vapid, cp->icp_opmode);
            } else {
                if (ic->ic_wideband_capable) {
                    IEEE80211_ADDR_COPY(req_mac, ic->ic_mbss.ref_bssid);
                }
                ATH_SET_VAP_BSSID(req_mac, ic->ic_my_hwaddr, cp->icp_vapid);
            }

            qdf_info("Requested VAP id %d and MAC %s",
                    cp->icp_vapid, ether_sprintf(req_mac));

            if (!is_mbssid_enabled && !ic->ic_wideband_capable) {
                if(wlan_vap_allocate_mac_addr(ic, req_mac) != -1)
                {
                   IEEE80211_ADDR_COPY(cp->icp_bssid, req_mac);
                } else {
                   qdf_info("%s: Invalid MAC requested", __func__);
                   return NULL;
                }
            }
        }
    }
    else {
       if ((cp->icp_flags & IEEE80211_CLONE_BSSID) &&
           cp->icp_opmode != IEEE80211_M_WDS) {
              for(id = 0; id < ATH_BCBUF; id++)
              {
                  if((prealloc_idmask & (1 << id)) == 0)
                      break;
              }
       }

#if ATH_SUPPORT_WRAP
       if (cp->icp_flags & IEEE80211_CLONE_MACADDR) {
            /* set the flag as non-MAIN sta, since MAC address need not be
               derived */
           if ((cp->icp_opmode == QDF_STA_MODE) &&
                    (IEEE80211_ADDR_IS_VALID(cp->icp_bssid))) {
              cp->icp_flags |= IEEE80211_WRAP_NON_MAIN_STA;
           }
           else {
              num_vdevs = ic->ic_get_qwrap_num_vdevs(ic);
              for (id = 0; id < num_vdevs; id++) {
                  /* get the first available slot */
                  if ((prealloc_idmask & (1 << id)) == 0)
                      break;
              }
           }
       } else
#endif
       if ((cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) {
           /* do not clone use the one passed in */
           qdf_info("No cloning");
           /*
            * Added proper logic to get vap id and bssid value.
            * when user pass BSSID MAC value through commandline using -bssid option, The
            * exsiting logic won't work to get proper vap id to create VAP
            */
       }
    }

    /* With MBSS/wideband enabled, BSSID is assigned from ref BSSID
     * of Tx VAP and id of sc_prealloc_idmask is not linked
     * to BSSID anymore, hence skip checking slot id
     * for MBSS/WB case. If user tries to create more than supported
     * VAP for MBSS/WB, obj mgr pdev max vap check will fail
     * and prevent that extra VAP creation attempt
     */
    if (!is_mbssid_enabled && !ic->ic_wideband_capable && (id == num_vdevs)) {
        qdf_info("%s: no dynamic vaps free", __func__);
        return NULL;
    }

    /* Allocate BSSID for valid vdev id */
    if(id != -1) {
       IEEE80211_ADDR_COPY(vap_addr, ic->ic_myaddr);

       if (is_mbssid_enabled && (cp->icp_opmode == QDF_SAP_MODE)) {
           IEEE80211_ADDR_COPY(vap_addr, ic->ic_mbss.ref_bssid);
           MBSSID_ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id, cp->icp_opmode);
       }
       else if ((bsta_fixed_idmask >= 0) && (bsta_fixed_idmask < num_vdevs) &&
                (cp->icp_opmode == QDF_STA_MODE)) {
           /* Multi AP requires STA mode to have consistent mac address for reboots or wifi load/unload */
           ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, bsta_fixed_idmask);
       }
       else {
           if (ic->ic_wideband_capable && (cp->icp_opmode == QDF_SAP_MODE)) {
               IEEE80211_ADDR_COPY(vap_addr, ic->ic_mbss.ref_bssid);
           }
           ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id);
       }
       IEEE80211_ADDR_COPY(cp->icp_bssid, vap_addr);

       if ((cp->icp_opmode != QDF_SAP_MODE) ||
           (!is_mbssid_enabled && !ic->ic_wideband_capable)) {
           ic->ic_set_mac_prealloc_id(ic, id, 1);
           id_used = 1;
       }
    }

    psoc = wlan_pdev_get_psoc(devhandle->ic_pdev_obj);
    switch (cp->icp_opmode) {
#ifdef ATH_SUPPORT_P2P
    case QDF_P2P_GO_MODE:
        qdf_print(" IEEE80211_M_P2P_GO created ");
        osifp->p2p_go_handle = wlan_p2p_GO_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_go_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_GO_get_vap_handle(osifp->p2p_go_handle);
        /* enable UAPSD by default for GO Vap */
        /*  wlan_set_param(vap, IEEE80211_FEATURE_UAPSD, 0x1); */
        break;

    case QDF_P2P_CLIENT_MODE:
        qdf_print(" IEEE80211_M_P2P_CLIENT created ");
        osifp->p2p_client_handle = wlan_p2p_client_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_client_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_client_get_vap_handle(osifp->p2p_client_handle);
        break;

    case QDF_P2P_DEVICE_MODE:
        qdf_print(" IEEE80211_M_P2P_DEVICE created ");
        osifp->p2p_handle = wlan_p2p_create(devhandle, NULL);
        if (osifp->p2p_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_get_vap_handle(osifp->p2p_handle);
        break;
#endif
    default:
        if (cp->icp_opmode == QDF_STA_MODE) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
#if UMAC_SUPPORT_CFG80211
            nl_type = NL80211_IFTYPE_STATION;
#endif
        }
        else if (cp->icp_opmode == QDF_IBSS_MODE) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_IBSS_BASE;
#if UMAC_SUPPORT_CFG80211
            nl_type = NL80211_IFTYPE_ADHOC;
#endif
        }
        else if (cp->icp_opmode == QDF_SAP_MODE) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_AP_BASE;
            if (cp->icp_flags & IEEE80211_SPECIAL_VAP){
                dev->type = ARPHRD_IEEE80211_RADIOTAP;
            }
#if UMAC_SUPPORT_CFG80211
            nl_type = NL80211_IFTYPE_AP;
#endif
        }
        else if (cp->icp_opmode == QDF_MONITOR_MODE) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
            dev->type = ARPHRD_IEEE80211_RADIOTAP;
#if UMAC_SUPPORT_CFG80211
            nl_type = NL80211_IFTYPE_MONITOR;
#endif
        }
        else {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
#if UMAC_SUPPORT_CFG80211
            nl_type = NL80211_IFTYPE_STATION;
#endif
        }

        params.opmode = cp->icp_opmode;
        IEEE80211_ADDR_COPY(params.macaddr, cp->icp_bssid);
        params.flags = cp->icp_flags;
        IEEE80211_ADDR_COPY(params.mataddr, cp->icp_mataddr);
        params.size_vdev_priv = sizeof(struct vdev_osif_priv);
        params.legacy_osif = osifp;

        TAILQ_FOREACH(tempvap, &ic->ic_vaps, iv_next) {
            if(!qdf_mem_cmp(tempvap->iv_myaddr, cp->icp_bssid, QDF_MAC_ADDR_SIZE)) {
                qdf_print("VAP Create Error. Vap macaddr %pM matches with already existing vap %s with ID %d", cp->icp_bssid, tempvap->iv_netdev_name, tempvap->iv_unit);
                WARN_ON(1);
                return NULL;
            }
        }
        qdf_info("VDEV Create %pM", cp->icp_bssid);

        /* Save the lsb of the bssid as lsb of the bssid of the
         * last user created vap in mbssid mode
         */
        if (is_mbssid_enabled || ic->ic_wideband_capable) {
            ic->ic_mbss.lsb_of_last_user_bssid = cp->icp_bssid[ATH_BSSID_INDEX];
        }
        vdev = wlan_objmgr_vdev_obj_create(devhandle->ic_pdev_obj, &params);
        if(vdev != NULL) {

            vdev_osifp = wlan_vdev_get_ospriv(vdev);

#if UMAC_SUPPORT_CFG80211
           if (cfg80211_create) {
               vdev_osifp->wdev = &(osifp->iv_wdev);
           }
           else {
              vdev_osifp->wdev = NULL;
           }
#endif

            waitcnt = 0;
            /* In sta mode when old bss node is freed, it is posted as an event to
             * connection state machine, which initiates creation of new bss peer.
             * At this point, unless the peer's destroy handler has been executed and
             * max peers per vap are decremented already, the creation of new bss peer
             * will fail. To handle this syncronization the max peers per vap are
             * increased from 2 to 3
             */
            if (cp->icp_opmode == QDF_STA_MODE) {
                wlan_vdev_set_max_peer_count(vdev, 3);
            }
            while((!((vdev->obj_state == WLAN_OBJ_STATE_CREATED) ||
                   (vdev->obj_state == WLAN_OBJ_STATE_CREATION_FAILED)) &&
                     (waitcnt < WLAN_VDEV_CREATE_TIMEOUT_CNT))) {
                qdf_sleep_us(WLAN_VDEV_CREATE_TIMEOUT*1000);
                waitcnt++;
            }
            if(vdev->obj_state == WLAN_OBJ_STATE_CREATION_FAILED) {
                qdf_print("VDEV (partial creation) failed ");
                /* If peer count is non-zero, means MLME has created peer,
                 * MLME should free the vap after reseeting the state
                 */
                vap = wlan_vdev_get_mlme_ext_obj(vdev);
                if (vap != NULL) {
                   wlan_vap_delete(vap);
                }
                else {
                   wlan_objmgr_vdev_obj_delete(vdev);
                }
                vdev = NULL;
            }
        }
        else {
            qdf_print("VDEV (creation) failed ");
        }

        break;
    }


    vap_destroy = 0;
    if (vdev == NULL) {
       vap_destroy = 1;
    }
    else {
       vap = (wlan_if_t)wlan_vdev_get_mlme_ext_obj(vdev);

       if (vap) {
           if (cp->icp_opmode == QDF_SAP_MODE &&
               (QDF_IS_STATUS_ERROR(osifp_create_wlan_vap_bss_status(ic, vap)))) {
               goto fail;
           }
           /*
            * Update vdev chainmasks.
            *
            * Rather than obtain a lock for the vdev again at another place in
            * this function, we set the vdev's chainmasks right here while we
            * hold the lock.
            * But we need to do so only if vap is non-NULL.
            */
           wlan_vdev_mlme_set_txchainmask(vdev, devhandle->ic_tx_chainmask);
           wlan_vdev_mlme_set_rxchainmask(vdev, devhandle->ic_rx_chainmask);
#if UNIFIED_SMARTANTENNA
           wlan_sa_api_start(vap->iv_ic->ic_pdev_obj, vdev, SMART_ANT_STA_NOT_CONNECTED | SMART_ANT_NEW_CONFIGURATION);
#endif

       }
       if(vap == NULL) {
           vap_destroy = 1;
       }
    }
    if(vap_destroy) {
      if(id_used == 1) {
        /* Reset the id slot */
        ic->ic_set_mac_prealloc_id(ic, id, 0);
      }
      return NULL;
    }

#if UMAC_SUPPORT_CFG80211
    /*
       1) Each netdevice have ieee80211_ptr which is of type wdev.
       2) Driver internal data struct ic and vap (for each  netdev) should contain one wdev
            a. net_dev->ieee80211_ptr = &ic->wdev;
       3) Internal wdev need to initilize with
           a. ic/vap->wdev.wiphy = registered cfg80211dev.
           b. ic/vap->wdev.netdev = our netdev.

    */
    if (cfg80211_create) {
        osifp->iv_wdev.wiphy = ic->ic_wdev.wiphy;
        osifp->iv_wdev.netdev = dev;
        osifp->iv_wdev.iftype = nl_type;
        dev->ieee80211_ptr = &osifp->iv_wdev;
        /* Create wokrQ cfg80211 events which nneed to be called in process context */
        qdf_create_work(0, &vap->cfg80211_channel_notify_workq,
                ieee80211_cfg80211_schedule_channel_notify, vap);
    }
    /*TODO it is supposed to be done as part of creation, but this can be updated seperately */
    vap->iv_scan_priority_base = scan_priority_mapping_base;
    vap->iv_cfg80211_create = cfg80211_create;

#endif

    /*
     * For wideband channel operation, VAP creation in co-hosted mode
     * requires a profile index assigned to the VAP in order to account
     * for the BSSIDs during VAP delete if EMA operation is not enabled.
     * If EMA operation is enabled, this profile index is reset during
     * the initial MBSSID setup routine.
     */
    if (ic->ic_wideband_capable && !is_mbssid_enabled && current_bssid_ix)
        vap->vdev_mlme->mgmt.mbss_11ax.profile_idx = current_bssid_ix;

    osifp->os_if = vap;
    osifp->ctrl_vdev = vdev;            /* back pointer to vdev object*/
    return vap;

fail:
    osifp->os_if = vap;
    osifp->ctrl_vdev = vdev;
    osifp->netdev = dev;
    wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
    osif_delete_vap(dev, 0);
    osif_delete_vap_wait_and_free(dev, 0);
    return NULL;
}

int
osif_create_vap_complete(struct net_device *comdev,
                         struct ieee80211_clone_params *cp,
                         osif_dev *osifp)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t *vap_macaddr;
    u_int32_t target_type;
    struct net_device *dev = osifp->netdev;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *parent_vap;
#ifdef QCA_SUPPORT_WDS_EXTENDED
    struct wlan_objmgr_psoc *psoc = NULL;
#endif /* QCA_SUPPORT_WDS_EXTENDED */
#if ATH_SUPPORT_WAPI
    /* for WAPI support, ETHERTYPE_WAPI should be added to the privacy filter */
    ieee80211_privacy_exemption privacy_filter[2];
#else
    ieee80211_privacy_exemption privacy_filter;
#endif
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
    osif_dev  *wrap_osdev = NULL;
    struct net_device *wrap_dev = NULL;
#if !WLAN_QWRAP_LEGACY
    u_int8_t *oma_addr= NULL;
    u_int8_t *vma_addr= NULL;
#endif
#endif
#if WLAN_SUPPORT_GREEN_AP
    struct wlan_objmgr_pdev *pdev = wlan_vap_get_pdev(vap);
    uint8_t apvaps_cnt = 0;
#endif
    int error;
    QDF_STATUS status;
    osdev_t os_handle = NULL;

    os_handle = ic->ic_osdev;

    memcpy(&vap->cp, cp, sizeof(vap->cp));

    INIT_LIST_HEAD(&osifp->pending_rx_frames);
    spin_lock_init(&osifp->list_lock);

    osifp->os_handle = os_handle;
    osifp->os_devhandle = devhandle;
    osifp->os_comdev = comdev;
    osifp->os_opmode = wlan_vap_get_opmode(vap);

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    osifp->os_periodic_scan_period = OSIF_PERIODICSCAN_DEF_PERIOD;
    OS_INIT_TIMER(os_handle, &(osifp->os_periodic_scan_timer), periodic_scan_timer_handler,
            (void *)osifp, QDF_TIMER_TYPE_WAKE_APPS);
#endif
    osifp->wlan_vendor_fwd_mgmt_mask = OSIF_VENDOR_FWD_MGMT_MASK_DEFAULT;
#ifdef ATH_SUPPORT_WAPI
    osifp->os_wapi_rekey_period = OSIF_WAPI_REKEY_TIMEOUT;
    OS_INIT_TIMER(os_handle, &(osifp->os_wapi_rekey_timer), osif_wapi_rekey_timeout,
            (void *)osifp, QDF_TIMER_TYPE_WAKE_APPS);
#endif
    osif_vap_setup(vap, dev, wlan_vap_get_opmode(vap));
#if ATH_NON_BEACON_AP
    if( (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) &&
            (cp->icp_flags & IEEE80211_NON_BEACON_AP) ){
        IEEE80211_VAP_NON_BEACON_ENABLE(vap);
    }
#endif
    vap_macaddr = wlan_vap_get_macaddr(vap);
    IEEE80211_ADDR_COPY(dev->dev_addr, vap_macaddr);

    ic_sta_vap_update(devhandle, vap);
    ic_mon_vap_update(devhandle, vap);

#ifdef WLAN_FEATURE_FASTPATH
    if (osifp->osif_is_mode_offload) {
        spin_lock_init(&osifp->nbuf_arr_lock);
        osifp->nbuf_arr = (qdf_nbuf_t *)qdf_mem_malloc(MSDUS_ARRAY_SIZE * sizeof(qdf_nbuf_t));
        if (!osifp->nbuf_arr) {
            return -EINVAL;
        }
    }
#endif

#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_record_macinfor(osifp->os_unit,dev->dev_addr);
#endif

    /* Note: Set the dev features flag to comdev features
     * before qdf_net_vlan_attach - otherwise
     * VLAN flag settings in qdf_net_vlan_attach gets
     * overwritten
     */
    dev->features = comdev->features;

    /* enable TSO/LRO only of HW Supports */
    if(osifp->osif_is_mode_offload) {
        if (ic->ic_offload_tx_csum_support) {
            osif_dev_set_offload_tx_csum(dev);
        }
        if (ic->ic_sg_support) {
            osif_dev_set_sg(dev);
        }
        if (ic->ic_sg_support) {
            osif_dev_set_sg(dev);
        }
        if (ic->ic_tso_support) {
            osif_dev_set_tso(dev);
        }
        qdf_info("TX Checksum:%d|SG:%d|TSO:%d|LRO:%d",
        ic->ic_offload_tx_csum_support, ic->ic_sg_support,
        ic->ic_tso_support, ic->ic_lro_support);

    }

// fixme where is this done in the new scheme?    dev->priv = vap;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
#ifdef WLAN_FEATURE_FASTPATH
    if (osifp->osif_is_mode_offload) {
        target_type = ic->ic_get_tgt_type(ic);
        if ((target_type == TARGET_TYPE_QCA8074) ||
                (target_type == TARGET_TYPE_QCA8074V2) ||
                (target_type == TARGET_TYPE_QCA6018) ||
                (target_type == TARGET_TYPE_QCA5018) ||
                (target_type == TARGET_TYPE_QCN6122) ||
                (target_type == TARGET_TYPE_QCN9000)) {
            dev->netdev_ops = &osif_11ac_wifi3_fp_dev_ops;
        } else {
            dev->netdev_ops = &osif_11ac_fp_dev_ops;
        }
    } else
#endif /* WLAN_FEATURE_FASTPATH*/
    {
        osif_dev_ops.ndo_start_xmit = os_handle->vap_hardstart;
        dev->netdev_ops = &osif_dev_ops;
    }

    /* Enable ndo_select_queue only when multiq is supported */
#ifdef WLAN_FEATURE_FASTPATH
    if (ic->multiq_support_enabled) {
        osif_11ac_fp_dev_ops.ndo_select_queue = osif_select_queue;
        osif_11ac_wifi3_fp_dev_ops.ndo_select_queue = osif_select_queue;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        osif_nss_wifiol_dev_ops.ndo_select_queue = osif_select_queue;
#endif
    }
#endif

    ((struct net_device_ops *) (dev->netdev_ops))->ndo_do_ioctl = ieee80211_ioctl;
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30) */
    dev->get_stats = osif_getstats;
    dev->open = osif_vap_open;
    dev->stop = osif_vap_stop;

    dev->hard_start_xmit = os_handle->vap_hardstart;
    dev->set_multicast_list = osif_set_multicast_list;
#if 0
    dev->set_mac_address = ieee80211_set_mac_address;
#endif
    dev->change_mtu = osif_change_mtu;
    dev->set_mac_address = osif_change_mac_addr;
#endif
    dev->tx_queue_len = 0;          /* NB: bypass queueing */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
    dev->priv_flags |= IFF_NO_QUEUE;
#endif
    dev->needed_headroom = comdev->needed_headroom;
    dev->hard_header_len = comdev->hard_header_len;


#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if ( osifp->osif_is_mode_offload && ic->nss_vops && osifp->nss_wifiol_ctx ) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
        dev->netdev_ops = &osif_nss_wifiol_dev_ops;
#else
        if(os_handle->vap_hardstart)
            dev->hard_start_xmit = os_handle->vap_hardstart;
#endif
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WLAN-NSS: VAP NSS ops initialized ");
    } else
#endif
    {
#if QCA_NSS_PLATFORM
#ifndef QCA_SINGLE_WIFI_3_0
        if (!(of_machine_is_compatible("qcom,ipq40xx"))) {
            osif_pltfrm_create_vap(osifp);
        }
#endif
#elif  defined(QCA_PARTNER_PLATFORM )
        osif_pltfrm_create_vap(osifp);
#endif
    }

    /*
     * qdf_net_vlan_attach() sets the vlan as a active feature in dev->features
     * and assigns vlan functions in dev->netdev_ops
     *
     * Should be called after final dev->netdev_ops is assigned to keep
     * dev->features flag and func pointers in dev->netdev_ops in a sync
     *
     */
#if ATH_SUPPORT_VLAN
    if (!ic->ic_no_vlan) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
    	qdf_net_vlan_attach(dev,(struct net_device_ops *) dev->netdev_ops);
#else
    	qdf_net_vlan_attach(dev);
#endif
    }
#endif

    /*
     * The caller is assumed to allocate the device with
     * alloc_etherdev or similar so we arrange for the
     * space to be reclaimed accordingly.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    /* in 2.4 things are done differently... */
    dev->features |= NETIF_F_DYNALLOC;
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,9))
    dev->needs_free_netdev = true;
#else
    dev->destructor = free_netdev;
#endif
#endif

    os_if_media_init(osifp);
    if (cp->icp_opmode == QDF_P2P_DEVICE_MODE)
        wlan_set_desired_phymode(vap, IEEE80211_MODE_11G);
    else
        wlan_set_desired_phymode(vap, IEEE80211_MODE_AUTO);

    /*
     * If a parent VAP exists, then copy the desired mode and if present, copy
     * the desired channel as well.
     */
    parent_vap = TAILQ_FIRST(&ic->ic_vaps);
    if (parent_vap != NULL && parent_vap != vap) {
        wlan_set_desired_phymode(vap, parent_vap->iv_des_mode);

        if (vap->iv_des_chan[vap->iv_des_mode] !=
                     parent_vap->iv_des_chan[parent_vap->iv_des_mode]) {
            qdf_info("Updating VAP%d channel for mode %d as per parent VAP%d",
                     vap->iv_unit, vap->iv_des_mode, parent_vap->iv_unit);
            vap->iv_des_chan[vap->iv_des_mode] =
                       parent_vap->iv_des_chan[parent_vap->iv_des_mode];
        }
    }

#if ATH_SUPPORT_WAPI
    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame and/or WAI frame for WAPI*/
    privacy_filter[0].ether_type = ETHERTYPE_PAE;
    privacy_filter[0].packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter[0].filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    privacy_filter[1].ether_type = ETHERTYPE_WAI;
    privacy_filter[1].packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter[1].filter_type =IEEE80211_PRIVACY_FILTER_ALLWAYS;
    wlan_set_privacy_filters(vap,privacy_filter,2);
#else
    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame */
    privacy_filter.ether_type = ETHERTYPE_PAE;
    privacy_filter.packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter.filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    wlan_set_privacy_filters(vap,&privacy_filter,1);
#endif /* ATH_SUPPORT_WAPI */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
    dev->do_ioctl = ieee80211_ioctl;
#endif

#if UMAC_SUPPORT_WEXT
    ieee80211_ioctl_vattach(dev);
    ieee80211_proc_vattach(vap);
#endif

    error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE,1 << WLAN_CRYPTO_AUTH_OPEN);

#if UMAC_PER_PACKET_DEBUG
    if (strlcpy(vap->iv_proc_fname,"pppdata",PROC_FNAME_SIZE) >= PROC_FNAME_SIZE) {
        qdf_print("source too long");
        return NULL;
    }
    strcat(vap->iv_proc_fname, dev->name);
    vap->iv_proc_entry = create_proc_entry(vap->iv_proc_fname, 0644, vap->iv_proc_root);
    if(vap->iv_proc_entry == NULL) {
        qdf_print(" iv null ");
    } else {
        vap->iv_proc_entry->data = (void *)vap;
        vap->iv_proc_entry->write_proc = osif_proc_pppdata_write;
    }
#endif
    /* register scan event handler */
    osifp->scan_requestor = ucfg_scan_register_requester(wlan_vap_get_psoc(vap),
            (u_int8_t*)"osif_umac", NULL, NULL);
    if (!osifp->scan_requestor) {
        scan_err("unable to allocate requester");
    }
    status = ucfg_scan_register_event_handler(wlan_vap_get_pdev(vap),
            &osif_scan_evhandler, (void *)osifp);
    if (status) {
        scan_err("unable to register scan event handler vap: 0x%pK status: %d", vap, status);
    }
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (wlan_is_psta(vap)) {
        osif_wrap_dev_add(osifp);
#else
    if (dp_wrap_vdev_is_wrap(vap->vdev_obj) || dp_wrap_vdev_is_psta(vap->vdev_obj)) {
        dp_wrap_vdev_set_netdev(vap->vdev_obj, dev);
    }
    if (dp_wrap_vdev_is_psta(vap->vdev_obj)) {
        dp_wrap_dev_add(vap->vdev_obj);
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (osifp->osif_is_mode_offload && osifp->nss_wifiol_ctx) {
            if (ic->nss_vops) {
                ic->nss_vops->ic_osif_nss_vdev_psta_add_entry(osifp);
            }
        }
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

#if DBDC_REPEATER_SUPPORT
        /*
         * Add Bridge entries with VMA of wireless PTAs
         * with the netdev being of wrap-ap vap.
         */
#if WLAN_QWRAP_LEGACY
        if (ic->ic_wrap_vap && !vap->iv_mpsta && !vap->iv_wired_pvap) {
            wrap_osdev = (osif_dev *)ic->ic_wrap_vap->iv_ifp;
            wrap_dev = OSIF_TO_NETDEV(wrap_osdev);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                "\n ***** Adding Wireless PSTA VMA FDB entry for oma %pM vma %pM *******\n",
                &osifp->osif_dev_oma[0], &osifp->osif_dev_vma[0]);
            qca_multi_link_tbl_add_or_refresh_entry(wrap_dev,
                &osifp->osif_dev_vma[0], QCA_MULTI_LINK_ENTRY_STATIC);
        }
#else
        if (dp_wrap_get_vdev(ic->ic_pdev_obj) && !dp_wrap_vdev_is_mpsta(vap->vdev_obj) && !dp_wrap_vdev_is_wired_psta(vap->vdev_obj)) {
            wrap_osdev = wlan_get_osdev(dp_wrap_get_vdev(ic->ic_pdev_obj));
            if (wrap_osdev) {
                oma_addr = dp_wrap_vdev_get_oma(vap->vdev_obj);
                vma_addr = dp_wrap_vdev_get_vma(vap->vdev_obj);
                wrap_dev = OSIF_TO_NETDEV(wrap_osdev);
                if (wrap_dev && oma_addr && vma_addr) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                            "\n ***** Adding Wireless PSTA VMA FDB entry for oma %pM vma %pM *******\n",
                            oma_addr, vma_addr);
                    qca_multi_link_tbl_add_or_refresh_entry(wrap_dev,
                            vma_addr, QCA_MULTI_LINK_ENTRY_STATIC);
                }
            }
        }

#endif
#endif

        /* disable power save for the PSTA VAPS*/
        wlan_set_powersave(vap, IEEE80211_PWRSAVE_NONE);
    }
#endif

#if WLAN_SUPPORT_GREEN_AP
    apvaps_cnt = ieee80211_get_apvaps_count(vap->iv_ic);
    if ((apvaps_cnt == 1) && (vap->iv_opmode == IEEE80211_M_HOSTAP) && (vap->iv_ic->ic_sta_vap == NULL)) {
        /* If it is a First APVAP and no STAVAP is created, start the Green AP feature */
         wlan_green_ap_start(pdev);
    }
    if (vap->iv_opmode == IEEE80211_M_STA) {
        /* If it is a STAVAP, stop the Green AP feature */
         wlan_green_ap_stop(pdev);
     }
#endif

#if QCA_PARTNER_DIRECTLINK_TX
    osifp->is_directlink = 0;
    if (osifp->osif_is_mode_offload) {
        if (ol_is_directlink(wlan_vdev_get_id(osifp->ctrl_vdev))) {
            osifp->is_directlink = 1;
            if (wlan_pltfrm_directlink_enable(osifp)) {
                qdf_print(KERN_ERR "%s: direct link unable to register device", dev->name);
            }
        }
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */

#if DBDC_REPEATER_SUPPORT
    if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
#if ATH_SUPPORT_WRAP
        /*
         * set sta_vdev to vdev only if its mpsta or a normal sta but not
         * psta
         */
#if WLAN_QWRAP_LEGACY
        if (vap->iv_mpsta || (!vap->iv_mpsta && !vap->iv_psta))
#else
        if (dp_wrap_vdev_is_mpsta(vap->vdev_obj) || (!dp_wrap_vdev_is_mpsta(vap->vdev_obj) && !dp_wrap_vdev_is_psta(vap->vdev_obj)))
#endif
#endif
            dp_lag_pdev_set_sta_vdev(ic->ic_pdev_obj, vap->vdev_obj);
    }
#endif

    /* If user has blocked channels from being selected from ACS,
     * the said channels are loaded into an ic structure as part
     * ol_ath_pdev_attach(). To ensure that the channels remain
     * blocked even through the SM, we are sending in the
     * blocked channels during VAP up.
     */
    if (ic->ic_pri20_cfg_blockchanlist.n_freq) {
        wlan_acs_block_channel_list(vap,
                            ic->ic_pri20_cfg_blockchanlist.freq,
                            ic->ic_pri20_cfg_blockchanlist.n_freq);
    }

#ifdef QCA_SUPPORT_WDS_EXTENDED
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (psoc && wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_WDS_EXTENDED)) {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops) {
            ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp,
                                                   OSIF_NSS_WIFI_VDEV_WDS_BACKHAUL_CFG);
        }
#endif
    }
#endif /* QCA_SUPPORT_WDS_EXTENDED */

    os_if_cm_init(osifp);
    return 0;
}

int
osif_create_vap_netdev_register(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    /* NB: rtnl is held on entry so don't use register_netdev */
    if (register_netdevice(dev)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to register device\n", dev->name);

        osif_vap_stop(dev);

        return -EINVAL;
    }

    /* Mark the VAP as registered with Kernel */
    ieee80211_vap_registered_set(vap);

    return 0;
}

int
osif_create_vap_recover(struct net_device *comdev,
                          struct ieee80211vap *vap,
                          osdev_t os_handle,
                          uint8_t is_mbss_tx_vdev)
{
    osif_dev  *osifp;
    int ret;
    struct ieee80211_clone_params cp;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
    struct ieee80211com *ic = &scn->sc_ic;
    struct net_device *dev;
#if UMAC_SUPPORT_CFG80211
    u_int8_t cfg80211_create;
#endif
    QDF_TRACE_LEVEL level;

    memcpy(&cp, &vap->cp, sizeof(cp));
#if UMAC_SUPPORT_CFG80211
    cfg80211_create = vap->iv_cfg80211_create;
#endif

    osifp = osif_recover_vap_netdev(vap);
    if (osifp == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: netdev failed\n", __FUNCTION__);
        goto fail0;
    }
    dev = osifp->netdev;
#if UMAC_SUPPORT_CFG80211
    vap = osifp_create_wlan_vap(&cp, osifp, comdev, cfg80211_create);
    if (vap == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap failed\n", __FUNCTION__);
        goto fail2;
    }
#endif

    ret = osif_create_vap_complete(comdev, &cp, osifp);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap compl failed\n", __FUNCTION__);
        goto fail3;
    }

    if (qdf_vfs_set_file_attributes((struct qdf_dev_obj *)&dev->dev.kobj,
                                    (struct qdf_vfs_attr *)&ath_attr_group)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: sysfs_create_group failed\n", __FUNCTION__);
    }

#if QCA_SUPPORT_SON
    ret = son_enable_disable_steering(osifp->ctrl_vdev, true);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: enabling son timer failed\n", __FUNCTION__);
    }
#endif /* QCA_SUPPORT_SON */

    /* Returning QDF prints to regular level */
    if (fw_rec_dbg_mask) {
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_ANY,
                                       QDF_TRACE_LEVEL_NONE, true);
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_DFS,
                                       QDF_TRACE_LEVEL_NONE, true);
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_TARGET_IF,
                                       QDF_TRACE_LEVEL_NONE, true);
        for (level = QDF_TRACE_LEVEL_FATAL; level <= QDF_TRACE_LEVEL_DEBUG; level++) {
            if (level <= ic->ic_fw_rec_dbg[QDF_MODULE_ID_ANY]) {
                qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_ANY,
                                               level, true);
            }
            if (level <= ic->ic_fw_rec_dbg[QDF_MODULE_ID_DFS]) {
                qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_DFS,
                                               level, true);
            }

            if (level <= ic->ic_fw_rec_dbg[QDF_MODULE_ID_TARGET_IF]) {
                qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_TARGET_IF,
                                               level, true);
            }
        }

        ic->ic_fw_rec_dbg[QDF_MODULE_ID_ANY] = 0;
        ic->ic_fw_rec_dbg[QDF_MODULE_ID_TARGET_IF] = 0;
        ic->ic_fw_rec_dbg[QDF_MODULE_ID_DFS] = 0;
    }

    /* Restore netdev register flag after recovery */
    ieee80211_vap_registered_set(vap);

    if ((wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE)) && is_mbss_tx_vdev) {
        ieee80211_ucfg_set_txvap(vap);
    }

    /* Start tx queue of the vdev */
    netif_start_queue(dev);

    return 0;

 fail3:
    osif_delete_vap(dev, 0);
    osif_delete_vap_wait_and_free(dev, 0);
#if UMAC_SUPPORT_CFG80211
 fail2:
#endif
    osif_create_vap_bssid_free(ic, cp.icp_bssid, &cp);
    osif_create_vap_netdev_unregister(osifp->netdev, osifp->os_unit);
 fail0:
    return -EINVAL;
}

static void wlan_util_get_vdev_ifname_cb(struct wlan_objmgr_psoc *psoc,
                                         void *obj, void *arg)
{
        char *name = NULL;
        osif_dev *osifp = NULL;
        struct wlan_objmgr_vdev *vdev = obj;
        struct wlan_find_vdev_filter *filter = arg;

        if (!vdev || !filter || filter->found_vdev)
            return;

        wlan_vdev_obj_lock(vdev);
        if (vdev->vdev_nif.osdev) {
#if UMAC_SUPPORT_CFG80211
            if (vdev->vdev_nif.osdev->wdev) {
                name = vdev->vdev_nif.osdev->wdev->netdev->name;
            } else {
#else
            {
#endif
                osifp = vdev->vdev_nif.osdev->legacy_osif_priv;
                if (osifp)
                    name = osifp->netdev->name;
            }
        }

        if (!name) {
             wlan_vdev_obj_unlock(vdev);
             return;
        }

        if (!qdf_str_cmp(name, filter->ifname))
            filter->found_vdev = vdev;

        wlan_vdev_obj_unlock(vdev);
}

struct wlan_objmgr_vdev *osif_get_vdev_by_ifname(
                struct wlan_objmgr_psoc *psoc, char *ifname,
                wlan_objmgr_ref_dbgid ref_id)
{
        QDF_STATUS status;
        struct wlan_find_vdev_filter filter = {0};

        filter.ifname = ifname;
        wlan_objmgr_iterate_obj_list(psoc, WLAN_VDEV_OP,
                                     wlan_util_get_vdev_ifname_cb,
                                     &filter, 0, ref_id);

        if (!filter.found_vdev)
            return NULL;

        status = wlan_objmgr_vdev_try_get_ref(filter.found_vdev, ref_id);
        if (QDF_IS_STATUS_ERROR(status))
            return NULL;

        return filter.found_vdev;
}


/*
* Create a virtual ap.  This is public as it must be implemented
* outside our control (e.g. in the driver).
*/
int
osif_ioctl_create_vap(struct net_device *comdev, struct ifreq *ifr,
                        struct ieee80211_clone_params *cp,
                        osdev_t os_handle)
{
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
    struct ieee80211com *ic = &scn->sc_ic;
    struct net_device *dev = NULL;
    dev = osif_create_vap(ic, comdev, cp, 0);
    if (dev !=NULL) {
        /* return name */
        if (strlcpy(ifr->ifr_name, cp->icp_name, IFNAMSIZ) >= IFNAMSIZ) {
            qdf_print("Source too long !");
            return -EINVAL;
        }
        qdf_print(KERN_ERR "VAP device %s created!",
                  cp->icp_name);
        return 0;
    } else  {
        return -EIO;
    }
}


struct net_device*
osif_create_vap(struct ieee80211com *ic, struct net_device *comdev, struct ieee80211_clone_params *cp, int cfg80211_create)
{
    osif_dev  *osifp;
    int ret;
    struct net_device *dev;
    struct ieee80211vap *vap;

    ret = osif_create_vap_check(comdev, cp);
    if (ret) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: check failed\n", __FUNCTION__);
        return NULL;
    }

    osifp = osif_create_vap_netdev_alloc(cp, ic->multiq_support_enabled);
    if (osifp == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:create netdev failed\n", __FUNCTION__);
        goto fail0;
    }

    vap = osifp_create_wlan_vap(cp, osifp, comdev, cfg80211_create);
    if (vap == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap failed\n", __FUNCTION__);
        goto fail2;
    }

    dev = osifp->netdev;

    ret = osif_create_vap_complete(comdev, cp, osifp);
    if (ret != 0) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap compl failed\n", __FUNCTION__);
        goto fail3;
    }

    ret = osif_create_vap_netdev_register(dev);
    if (ret != 0) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:register netdev failed\n", __FUNCTION__);
        goto fail3;
    }

    if (qdf_vfs_set_file_attributes((struct qdf_dev_obj *)&dev->dev.kobj,
                                    (struct qdf_vfs_attr *)&ath_attr_group)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: sysfs_create_group failed\n", __FUNCTION__);
    }

    QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VAP device %s created osifp: (%pK) os_if: (%pK)",
           dev->name, osifp, osifp->os_if);

    return dev;

 fail3:
    osif_delete_vap(dev, 0);
    osif_delete_vap_wait_and_free(dev, 0);
 fail2:
    osif_create_vap_bssid_free(ic, cp->icp_bssid, cp);
    osif_create_vap_netdev_free(osifp->netdev, osifp->os_unit);
 fail0:
    return NULL;
}
qdf_export_symbol(osif_ioctl_create_vap);

void
osif_delete_vap_unregister_nss(struct net_device *dev, int recover)
{
#if defined (QCA_PARTNER_PLATFORM) || (QCA_NSS_PLATFORM) || (QCA_NSS_WIFI_OFFLOAD_SUPPORT)
    osif_dev *osnetdev = ath_netdev_priv(dev);
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (osnetdev->nss_wifiol_ctx) {
        /*
         * When wifi offload is enabled, we could have NSS qdiscs configured
         * on the wifi interface. These need to be destroyed before we
         * can destroy the interface.
         */
        wlan_if_t vap = osnetdev->os_if;
        struct ieee80211com *ic = wlan_vap_get_devhandle(vap);
        if (recover) {
            dev_shutdown(dev);
        }
        if (ic->nss_vops) {
            ic->nss_vops->ic_osif_nss_vap_delete(osnetdev, recover);
        }
        osnetdev->nss_ifnum =  -1;
        return;
    } else
#endif
    {
#if QCA_NSS_PLATFORM
    if (!(of_machine_is_compatible("qcom,ipq40xx"))) {
        osif_pltfrm_delete_vap(osnetdev);
    }
#elif defined(QCA_PARTNER_PLATFORM )
    osif_pltfrm_delete_vap(osnetdev);
#endif
    }
}

int
osif_delete_vap_start(struct net_device *dev, int recover)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct ieee80211com *ic;
    osif_dev  *osifp;
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
    osif_dev  *wrap_osdev = NULL;
    struct net_device *wrap_dev = NULL;
#if !WLAN_QWRAP_LEGACY
    u_int8_t *oma_addr= NULL;
    u_int8_t *vma_addr= NULL;
#endif
#endif

    if (!vap) {
        return -EINVAL;
    }

    ic = wlan_vap_get_devhandle(vap);
    osnetdev->is_delete_in_progress=1;
    vap->iv_needs_up_on_acs = 0;

    ieee80211_proc_vdetach(vap);
    osifp = ath_netdev_priv(dev);

#if QCA_PARTNER_DIRECTLINK_TX
    if (qdf_unlikely(osifp->is_directlink)) {
        if (wlan_pltfrm_directlink_disable(osnetdev)) {
            qdf_print(KERN_ERR "%s: direct link unable to deregister device", dev->name);
        }
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */



#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    OS_FREE_TIMER(&(osnetdev->os_periodic_scan_timer));
#endif
#ifdef ATH_SUPPORT_WAPI
    OS_FREE_TIMER(&(osnetdev->os_wapi_rekey_timer));
#endif
    ifmedia_removeall(&osnetdev->os_media);
    /* unregister scan event handler */
        ucfg_scan_unregister_event_handler(wlan_vap_get_pdev(vap), &osif_scan_evhandler, (void *)osnetdev);
        ucfg_scan_unregister_requester(wlan_vap_get_psoc(vap), osnetdev->scan_requestor);
#if UMAC_PER_PACKET_DEBUG
    remove_proc_entry(vap->iv_proc_fname, vap->iv_proc_root);
#endif
    qdf_vfs_clear_file_attributes((struct qdf_dev_obj *)&dev->dev.kobj,
                                  (struct qdf_vfs_attr *)&ath_attr_group);

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (wlan_is_psta(vap)) {
#else
    if (dp_wrap_vdev_is_psta(vap->vdev_obj)) {
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (osnetdev->osif_is_mode_offload && osnetdev->nss_wifiol_ctx) {
            if (ic->nss_vops)
                ic->nss_vops->ic_osif_nss_vdev_psta_delete_entry(osnetdev);
        }
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

#if DBDC_REPEATER_SUPPORT
        /*
         * Delete Bridge entries created with VMA of wireless PTAs
         * with the netdev being of wrap-ap vap.
         */
#if WLAN_QWRAP_LEGACY
        if (ic->ic_wrap_vap && !vap->iv_mpsta && !vap->iv_wired_pvap) {
            wrap_osdev = (osif_dev *)ic->ic_wrap_vap->iv_ifp;
            wrap_dev = OSIF_TO_NETDEV(wrap_osdev);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                "\n ***** Deleting Wireless PSTA VMA FDB entry for oma %pM vma %pM *******\n",
                &osnetdev->osif_dev_oma[0], &osnetdev->osif_dev_vma[0]);
            qca_multi_link_tbl_delete_entry(wrap_dev, &osnetdev->osif_dev_vma[0]);
        }
#else
        if (dp_wrap_get_vdev(ic->ic_pdev_obj) && !dp_wrap_vdev_is_mpsta(vap->vdev_obj) && !dp_wrap_vdev_is_wired_psta(vap->vdev_obj)) {
            wrap_osdev = wlan_get_osdev(dp_wrap_get_vdev(ic->ic_pdev_obj));
            if (wrap_osdev) {
                oma_addr = dp_wrap_vdev_get_oma(vap->vdev_obj);
                vma_addr = dp_wrap_vdev_get_vma(vap->vdev_obj);
                wrap_dev = OSIF_TO_NETDEV(wrap_osdev);
                if (wrap_dev && oma_addr && vma_addr) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                            "\n ***** Adding Wireless PSTA VMA FDB entry for oma %pM vma %pM *******\n",
                            oma_addr, vma_addr);
                    qca_multi_link_tbl_delete_entry(wrap_dev, vma_addr);
                }
            }
        }
#endif
#endif

#if WLAN_QWRAP_LEGACY
        osif_wrap_dev_remove(osnetdev);
        osif_wrap_dev_remove_vma(osnetdev);
#else
        dp_wrap_dev_remove(vap->vdev_obj);
        dp_wrap_dev_remove_vma(vap->vdev_obj);

#endif
    }
#endif

    if (recover) {
        wlan_assoc_sm_msgq_drain(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj));

        /* Drain mgmt pkts before dev_change_flags, else node references are
         * not freed in osif_vap_stop called from dev_changes_flags
         */
        ieee80211_flush_vap_mgmt_queue(vap, true);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    dev_change_flags(dev, dev->flags & (~IFF_UP), NULL);
#else
    dev_change_flags(dev, dev->flags & (~IFF_UP));
#endif

#if ATH_SUPPORT_WRAP
    /* ProxySTA VAP has its own mac address and doesn't use mBSSID */
#if WLAN_QWRAP_LEGACY
    if (!vap->iv_psta)
#else
    if (!dp_wrap_vdev_is_psta(vap->vdev_obj))
#endif
        wlan_vap_free_mac_addr(ic, vap->iv_myaddr, &vap->cp);
#else
    /* free the MAC address */
    wlan_vap_free_mac_addr(ic, vap->iv_myaddr, &vap->cp);
#endif

    return 0;
}

int
osif_delete_vap_complete(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);

    osnetdev->is_delete_in_progress = 0;

    spin_lock_destroy(&osnetdev->list_lock);
    spin_lock_destroy(&osnetdev->tx_lock);

#ifdef WLAN_FEATURE_FASTPATH
        if (osnetdev->osif_is_mode_offload) {
            ASSERT(osnetdev->nbuf_arr);
            /* Free up the accumulated SKB's also */
            qdf_mem_free(osnetdev->nbuf_arr);
            osnetdev->nbuf_arr = NULL;
            spin_lock_destroy(&osnetdev->nbuf_arr_lock);
        }
#endif

#if UMAC_SUPPORT_WEXT
    ieee80211_ioctl_vdetach(dev);
#endif
    return 0;
}

void
osif_delete_vap_netdev_unregister(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    /* Mark the VAP as unregistered with Kernel */
    ieee80211_vap_registered_clear(vap);

    unregister_netdevice(dev);
}

int osif_delete_vap_netdev_unregister_complete(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);

    qdf_net_delete_wlanunit(osnetdev->os_unit);

    return 0;
}

int
osif_delete_vap_recover(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct ieee80211com *ic;
    struct ieee80211_profile *profile;
    struct ieee80211vap_profile *vap_profile = NULL;
    QDF_TRACE_LEVEL level;

#if QCA_SUPPORT_SON
    int ret;
    ret = son_enable_disable_steering(osnetdev->ctrl_vdev, false);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: disabling son timer failed\n", __FUNCTION__);
    }
#endif /* QCA_SUPPORT_SON */

    /* save the VAP's profile before deleting */
    ic = wlan_vap_get_devhandle(vap);
    profile = ic->profile;
    vap_profile = &profile->vap_profile[profile->num_vaps];
    wlan_get_vap_info(vap, vap_profile, NULL);
    profile->num_vaps++;

    /*
     * Disables excessive prints from showing up during firmware recovery
     * Only the following modules are disabled, but more can be added based
     * as needed - ANY, TIF, DFS
     * This downgrades the prints to value set in module param "fw_rec_dbg_mask"
     */
    if (fw_rec_dbg_mask) {
        for (level = QDF_TRACE_LEVEL_DEBUG; level >= QDF_TRACE_LEVEL_FATAL; level--) {
            if (!(ic->ic_fw_rec_dbg[QDF_MODULE_ID_ANY]) &&
                     qdf_print_is_verbose_enabled(qdf_get_pidx(), QDF_MODULE_ID_ANY,
                                                  level)) {
                ic->ic_fw_rec_dbg[QDF_MODULE_ID_ANY] = level;
            }

            if (!(ic->ic_fw_rec_dbg[QDF_MODULE_ID_DFS]) &&
                     qdf_print_is_verbose_enabled(qdf_get_pidx(), QDF_MODULE_ID_DFS,
                                                  level)) {
                ic->ic_fw_rec_dbg[QDF_MODULE_ID_DFS] = level;
            }

            if (!(ic->ic_fw_rec_dbg[QDF_MODULE_ID_TARGET_IF]) &&
                     qdf_print_is_verbose_enabled(qdf_get_pidx(), QDF_MODULE_ID_TARGET_IF,
                                                  level)) {
                ic->ic_fw_rec_dbg[QDF_MODULE_ID_TARGET_IF] = level;
            }
        }

        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_ANY,
                                       QDF_TRACE_LEVEL_NONE, true);
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_ANY,
                                       fw_rec_dbg_mask, true);

        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_DFS,
                                       QDF_TRACE_LEVEL_NONE, true);
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_DFS,
                                       fw_rec_dbg_mask, true);

        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_TARGET_IF,
                                       QDF_TRACE_LEVEL_NONE, true);
        qdf_print_set_category_verbose(qdf_get_pidx(), QDF_MODULE_ID_TARGET_IF,
                                       fw_rec_dbg_mask, true);
    }

    osif_delete_vap_start(dev, 1);

#ifndef QCA_SINGLE_WIFI_3_0
    osif_delete_vap_unregister_nss(dev, 1);
#endif

    osif_delete_vap(dev, 1);

    osif_delete_vap_wait_and_free(dev, 1);
    osif_delete_vap_complete(dev);

    return 0;
}
qdf_export_symbol(osif_delete_vap_recover);

int
osif_ioctl_delete_vap(struct net_device *dev)
{
#if UMAC_SUPPORT_CFG80211
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_psoc *psoc;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (psoc == NULL) {
        QDF_ASSERT(0);
        return 0;
    }

    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        if (!wlan_psoc_nif_fw_ext_cap_get(psoc,
                     WLAN_SOC_CEXT_MBSS_PARAM_IN_START) &&
            (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE) &&
            !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) &&
            !ic->ic_wifi_down_ind)) {
            qdf_warn("[MBSSID] Trying to delete a Transmitting VAP without"
                     "deleting non-transmitting VAPs first, Aborting VAP delete..\n");
            return 0;
        }
    }

#endif

    /*
     * unregister_netdev is done first and other clean up is done later by holding dev_hold()
     * Please maintain the current order
     * First - unregister_netdev()
     * next - nss vdev dealloc done osif_delete_vap_unregister_nss()
     */
    dev_hold(dev);
    osif_delete_vap_start(dev, 0);
    osif_delete_vap_netdev_unregister(dev);
#ifndef QCA_SINGLE_WIFI_3_0
    osif_delete_vap_unregister_nss(dev, 0);
#endif
#if UMAC_SUPPORT_CFG80211
    qdf_flush_work(&vap->cfg80211_channel_notify_workq);
    qdf_destroy_work(NULL, &vap->cfg80211_channel_notify_workq);
#endif
    osif_delete_vap(dev, 0);

    osif_delete_vap_wait_and_free(dev, 0);

    osif_delete_vap_complete(dev);
    osif_delete_vap_netdev_unregister_complete(dev);

    dev_put(dev);

    return 0;
}
qdf_export_symbol(osif_ioctl_delete_vap);

int
osif_ioctl_switch_vap(struct net_device *dev, enum ieee80211_opmode opmode)
{
        osif_dev *osifp = ath_netdev_priv(dev);
        wlan_if_t vap = osifp->os_if;
        u_int8_t *macaddr;
        u_int64_t msg_flags;

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : from %d to %d  \n",
                        __func__, osifp->os_opmode, opmode);


        if (osifp->os_opmode == opmode) {
            return 0;
        }

        macaddr = wlan_vap_get_macaddr(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : old mac addr %s   \n", __func__, ether_sprintf(macaddr));

        _netif_carrier_off(dev);
        msg_flags = wlan_get_debug_flags(vap);
        osifp->is_delete_in_progress = 1;
        osif_vap_stop(dev);
        osif_delete_vap(dev, 0);
        osif_delete_vap_wait_and_free(dev, 0);
        osifp->os_if = NULL;
        osif_setup_vap(osifp,opmode,IEEE80211_CLONE_BSSID,NULL);
        vap = osifp->os_if;
        if (!vap) {
           return -EINVAL;
        }
        wlan_set_debug_flags(vap, msg_flags);
        _netif_carrier_on(dev);
        macaddr = wlan_vap_get_macaddr(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : new mac addr %s   \n", __func__, ether_sprintf(macaddr));

        return 0;
}

int osif_recover_profile_alloc(struct ieee80211com *ic)
{
    struct ieee80211_profile *profile;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct net_device *dev = scn->sc_osdev->netdev;
    wlan_chan_t chan;

    if(ic->profile) {
        qdf_mem_free(ic->profile);
        ic->profile = NULL;
    }

    profile = (struct ieee80211_profile *)qdf_mem_malloc(
                  sizeof (struct ieee80211_profile));
    if (profile == NULL) {
        return -ENOMEM;
    }
    OS_MEMSET(profile, 0, sizeof (struct ieee80211_profile));

    if (strlcpy(profile->radio_name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long");
        return -ENOMEM;
    }
    wlan_get_device_mac_addr(ic, profile->radio_mac);
    profile->cc = (u_int16_t)wlan_get_device_param(ic,
                                IEEE80211_DEVICE_COUNTRYCODE);
    chan = wlan_get_dev_current_channel(ic);
    if (chan != NULL) {
        profile->channel = chan->ic_ieee;
        profile->freq = chan->ic_freq;
    }

    ic->profile = profile;

    return 0;
}
qdf_export_symbol(osif_recover_profile_alloc);

int osif_recover_profile_free(struct ieee80211com *ic)
{
    if(ic->profile)
        qdf_mem_free(ic->profile);
    ic->profile = NULL;

    return 0;
}

void
osif_recover_vap_create(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_profile *profile = ic->profile;
    struct ieee80211vap_profile *vap_profile = NULL;
    int i, ret = 0;

    if (!profile)
        return;

    for(i = 0; i < profile->num_vaps; i++) {
        vap_profile = &profile->vap_profile[i];
        ret = osif_create_vap_recover(scn->netdev,
                                vap_profile->vap,
                                (osdev_t) scn->sc_osdev,
                                vap_profile->txvap);

        vap_profile->vap->iv_des_mode = vap_profile->phymode;
        if (ret != 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "Warning: Vap %pK recovery failed, trying other vaps...\n",
                   vap_profile->vap);
        }

    }

    osif_recover_profile_free(ic);
}
qdf_export_symbol(osif_recover_vap_create);

int
wlan_get_vap_info(struct ieee80211vap *vap,
                    struct ieee80211vap_profile *vap_profile,
                    void *handle)
{
    ieee80211_keyval k;
    int kid;
    u_int8_t *macaddr;
    osif_dev *osif;
    int32_t cipher;
    int32_t authmode;
    wlan_crypto_auth_mode mode;

    osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    vap_profile->vap = vap;
    if (strlcpy(vap_profile->name, osif->netdev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long");
        return -1;
    }

    if ((wlan_pdev_nif_feat_cap_get(vap->iv_ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE)) &&
        !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
          vap_profile->txvap = 1;
    }
    wlan_get_vap_addr(vap, vap_profile->vap_mac);
    vap_profile->phymode = wlan_get_desired_phymode(vap);

    authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
    if ( authmode == -1 ) {
        qdf_err("crypto_err while getting authmode params\n");
        return -1;
    }

    if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_OPEN) | (1 << WLAN_CRYPTO_AUTH_SHARED)))
        vap_profile->sec_method = (uint32_t)((1 << WLAN_CRYPTO_AUTH_AUTO));
    else {
	for (mode = WLAN_CRYPTO_AUTH_NONE; mode <= WLAN_CRYPTO_AUTH_MAX; mode++) {
           if (authmode & (uint32_t)((1 << mode)))
              vap_profile->sec_method = mode;
        }
    }

    cipher = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER);
    if ( cipher == -1 ) {
        qdf_err("crypto_error while getting cipher params\n");
        return -1;
    }
    vap_profile->cipher = cipher;
    if (wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY))
    {
        vap_profile->cipher |= 1<<IEEE80211_CIPHER_WEP;
        kid = wlan_get_default_keyid(vap);
        if (kid == IEEE80211_KEYIX_NONE) {
            kid = 0;
        }
        if ((0 <= kid) && (kid < IEEE80211_WEP_NKID)) {
            macaddr = (u_int8_t *)ieee80211broadcastaddr;
            k.keydata = vap_profile->wep_key[kid];
            if (wlan_get_key(vap, kid, macaddr, &k, 64, GET_PN_ENABLE) == 0) {
                vap_profile->wep_key_len[kid] = k.keylen;
            }
        }
    } else {
        vap_profile->cipher &= ~(1<<IEEE80211_CIPHER_WEP);
    }
    return 0;
}
qdf_export_symbol(wlan_get_vap_info);

#if UMAC_SUPPORT_ACFG
int
osif_set_vap_vendor_param(struct net_device *dev, acfg_vendor_param_req_t *req)
{
    int status = 0, reinit = 0;

    /* vendors can add their commands here */
    switch(req->param)
    {
        case ACFG_VENDOR_PARAM_CMD_PRINT:
            qdf_print("Received user print data %s", (char *)&req->data);
            break;
        case ACFG_VENDOR_PARAM_CMD_INT:
            qdf_print("Received user int data %d", *(uint32_t *)&req->data);
            break;
        case ACFG_VENDOR_PARAM_CMD_MAC:
            qdf_print("Received user mac data %02x:%02x:%02x:%02x:%02x:%02x", req->data.data[0], \
                                                                             req->data.data[1], \
                                                                             req->data.data[2], \
                                                                             req->data.data[3], \
                                                                             req->data.data[4], \
                                                                             req->data.data[5]);
            break;
        default:
            qdf_print("ACFG driver unknown vendor param");
            status = -1;
    }
    /* If driver restart required, please set the "ENETRESET" flag in reinit variable */
    if(reinit == ENETRESET)
    {
        /* Reinit the wlan driver */
        return IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
    }
    return status;
}

int
osif_get_vap_vendor_param(struct net_device *dev, acfg_vendor_param_req_t *req)
{
    int status = 0;

    /* vendors can add their commands here */
    switch(req->param)
    {
        case ACFG_VENDOR_PARAM_CMD_PRINT:
            strlcpy((char *)&req->data, "QCA", sizeof(req->data));
            req->type = ACFG_TYPE_STR;
            qdf_print("Sending driver data %s type %d", (char *)&req->data, req->type);
            break;
        case ACFG_VENDOR_PARAM_CMD_INT:
            req->type = ACFG_TYPE_INT;
            *(uint32_t *)&req->data = 12345678;
            qdf_print("Sending driver data %d type %d", *(uint32_t *)&req->data, req->type);
            break;
        case ACFG_VENDOR_PARAM_CMD_MAC:
        {
            int i;
            req->type = ACFG_TYPE_MACADDR;
            for(i = 0; i < MAC_ADDR_LEN; i++)
                req->data.data[i] = i;
            qdf_print("Sending driver mac data %02x:%02x:%02x:%02x:%02x:%02x type %d", req->data.data[0], \
                                                                                      req->data.data[1], \
                                                                                      req->data.data[2], \
                                                                                      req->data.data[3], \
                                                                                      req->data.data[4], \
                                                                                      req->data.data[5], req->type);
            break;
        }
        default:
            qdf_print("ACFG driver invalid vendor param");
            status = -1;
    }
    return status;
}
#endif //UMAC_SUPPORT_ACFG

#if UMAC_PER_PACKET_DEBUG

int  osif_atoi_proc(char *buf) {
    int value=0;
    while(*buf) {
        value=(value << 3) + (value << 1) + (*buf - '0');
        buf++;
    }
    return value;
}


ssize_t osif_proc_pppdata_write(struct file *filp, const char __user *buff,
                        unsigned long len, void *data )
{
	struct ieee80211vap *vap;
    struct ieee80211com    *ic;
	char cmd[20], buf1[10], buf2[10];
	int filter,selevm;

	vap = (struct ieee80211vap *) data;
    ic = wlan_vap_get_devhandle(vap);
    sscanf(buff,"%s %s %s",cmd ,buf1 ,buf2);
    if (strcmp("rate_retry", cmd) == 0) {
	    vap->iv_userrate = osif_atoi_proc(buf1);
	    wlan_vdev_set_userrate(osif_atoi_proc(buf1));
      vap->iv_userretries = osif_atoi_proc(buf2);
	    wlan_vdev_set_userretries(osif_atoi_proc(buf2));
	} else if(strcmp("txchainmask", cmd) == 0) {
	    vap->iv_usertxchainmask = osif_atoi_proc(buf1);
	    wlan_vdev_set_usertxchainmask(osif_atoi_proc(buf1));
	} else if(strcmp("txpower", cmd) == 0) {
	    vap->iv_usertxpower = osif_atoi_proc(buf1);
	    wlan_vdev_set_usertxpower(osif_atoi_proc(buf1));
	} else if(strcmp("rxfilter", cmd) == 0) {
	    filter = osif_atoi_proc(buf1);
        ic->ic_set_rxfilter(ic->ic_pdev_obj, filter);
    } else if(strcmp("plcpheader", cmd) == 0) {
        selevm = osif_atoi_proc(buf1);
        ic->ic_set_rx_sel_plcp_header(ic, !selevm, 0);
    }
    return len;
}

#endif



static INLINE void
ieee80211_vap_resetdeschan(void *arg, struct ieee80211vap *vap, bool is_last_vap)
{
    vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;

}
extern void osif_ht40_event_handler(void *arg, wlan_chan_t channel);

static void
is_sta_connected(void *arg, wlan_node_t node)
{
    u_int32_t *is_valid = (u_int32_t *)arg;
    *is_valid =1;

}


static void osif_staconnected_check(void *arg, wlan_if_t vap)
{
    u_int32_t  *staconnected = (u_int32_t *) arg;
    u_int32_t is_valid = 0 ;

    wlan_iterate_station_list(vap, is_sta_connected, &is_valid);
    if(is_valid == 1){
        *staconnected= 1;
    }

}


/*
* Auto Channel Select handler used for interface up.
*/
static void osif_bkscan_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    struct ieee80211_vap_info vap_info;

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC))
        goto done;

    error = wlan_set_ieee80211_channel(vap, channel);
    if (error !=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s : failed to set channel with error code %d\n",
                        __func__, error);
        goto done;
    }

    vap_info.chan = vap->iv_des_chan[vap->iv_des_mode];
    vap_info.no_cac = 0;
    wlan_iterate_vap_list(wlan_vap_get_devhandle(vap), osif_bringup_vap_iter_func,
            &vap_info);

    if (wlan_coext_enabled(vap))
    {
        wlan_determine_cw(vap, channel);
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &osif_bkscan_acs_event_handler, (void *)osifp);
}

static void osif_acs_bk_scantimer_fn( void *arg )
{
    struct ieee80211com *ic = (struct ieee80211com *)arg ;
    struct ieee80211vap *vap;
    u_int32_t  staconnected = 0, num_vaps;
    int acs_ctrlflags = ic->ic_acs_ctrlflags;

    if(!osif_get_num_active_vaps(ic)){
        return;
    }

    /* Check if CW Interference is already been found and being handled */
    if (ic->cw_inter_found) {
        return;
    }
    if (acs_ctrlflags & (ACS_PEREODIC_OBSS_CHK | ACS_PEIODIC_SCAN_CHK))  {
        wlan_iterate_vap_list(ic,osif_staconnected_check,(void *)&staconnected);
        if(staconnected == 1)
            return;
    }

    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
#ifdef QCA_PARTNER_PLATFORM
            if (vap->iv_des_chan[vap->iv_des_mode] == IEEE80211_CHAN_ANYC)
            	return;
            if (!vap->iv_list_scanning)
#endif
            goto vapfound;
        }
    }

vapfound :
    if(vap == NULL)
        return;
    if(acs_ctrlflags & ACS_PEIODIC_SCAN_CHK){
        struct net_device *dev = OSIF_TO_NETDEV(vap->iv_ifp);
        osif_dev  *osifp = ath_netdev_priv(dev);
        ieee80211_iterate_vap_list_internal(ic, ieee80211_vap_resetdeschan,vap,num_vaps);
        osif_bring_down_vaps(ic, vap);
        vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;
        wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_VDEVS);
        wlan_autoselect_register_event_handler(vap,
                &osif_bkscan_acs_event_handler, (void *)osifp);
        wlan_autoselect_find_infra_bss_channel(vap, NULL);

    } else if(acs_ctrlflags & ACS_PEREODIC_OBSS_CHK){
        enum ieee80211_phymode des_mode = wlan_get_desired_phymode(vap);

        /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules */

        /* Check only for HE40/HT40 or HE20/HT20  do not change channel */
        if (ieee80211_is_phymode_g40(des_mode) && wlan_coext_enabled(vap)) {
#ifdef QCA_PARTNER_PLATFORM
        vap->iv_list_scanning = 1;
#endif
            ic->ic_obss_done_freq = 0;
            osif_bring_down_up_ap_vaps(ic, vap);
        }
    } else if(acs_ctrlflags & ACS_PEIODIC_BG_SCAN) {
        wlan_autoselect_find_infra_bss_channel(vap, NULL);
    }
}




static int
proc_clients_keys_show(struct seq_file *m, void *v)
{
    return 0;
}

#ifdef QCA_SUPPORT_WDS_EXTENDED
int
osif_wds_ext_delete_netdev(struct net_device *dev)
{
   osif_peer_dev *osifp = ath_netdev_priv(dev);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   wlan_if_t vap = NULL;
   struct ieee80211com *ic = NULL;
   osif_dev  *osdev = NULL;
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

   dev_hold(dev);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   osdev = ath_netdev_priv(osifp->parent_netdev);
   vap = osdev->os_if;
   ic = vap->iv_ic;
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    dev_change_flags(dev, dev->flags & (~IFF_UP), NULL);
#else
    dev_change_flags(dev, dev->flags & (~IFF_UP));
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    /*
     * Make the NSS interface down.
     */
    if (ic && ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_down)
        ic->nss_ext_vops->ic_osif_nss_ext_vdev_down(osifp);

    /*
     * Delete the NSS interface.
     */
    if (ic && ic->nss_ext_vops && ic->nss_ext_vops->ic_osif_nss_ext_vdev_delete)
        ic->nss_ext_vops->ic_osif_nss_ext_vdev_delete(osifp);
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

   /*
    * Release the reference on the parent interface.
    */
   if (osifp->parent_netdev)
       dev_put(osifp->parent_netdev);

#if QCA_NSS_PLATFORM
   osif_pltfrm_delete_ext_vap(osifp);
#endif

   unregister_netdevice(dev);
   dev_put(dev);

   return 0;
}
qdf_export_symbol(osif_wds_ext_delete_netdev);

static osif_peer_dev *
osif_create_wds_ext_netdev_alloc(struct ieee80211_clone_params *cp, uint8_t multiq_support_enabled)
{
    struct net_device *dev = NULL;
    struct net_device *parent_dev = NULL;
    char name[IFNAMSIZ];
    char parent_dev_name[IFNAMSIZ] = {0};
    int wds_ext_sta_unit = -1;
    int wds_ext_ath_unit = -1;
    int count = 0;
    osif_peer_dev  *osifp = NULL;

    /* AP vlan interface name will be in athX.staY (X=vap number, Y=sta aid) */
    sscanf(cp->icp_name, "ath%d.sta%d", &wds_ext_ath_unit, &wds_ext_sta_unit);

    if (wds_ext_sta_unit < 0) {
        qdf_err("Invalid AP VLAN number %s:%d", cp->icp_name, wds_ext_sta_unit);
        return NULL;
    } else {
         int dev_exist = qdf_net_dev_exist_by_name(cp->icp_name);
         if (dev_exist) {
             qdf_err("%s net dev exists already", cp->icp_name);
             return NULL;
         }

        if (strlcpy(name, cp->icp_name, sizeof(name)) >=  sizeof(name)) {
            qdf_err("source too long");
            return NULL;
        }
        name[IFNAMSIZ - 1] = '\0';
    }

    /* get parent interface */
    while(name[count] != '.') {
          parent_dev_name[count] = name[count];
          count++;
    }
    parent_dev = dev_get_by_name(&init_net, parent_dev_name);
    if (!parent_dev) {
        qdf_err("device %s not Found", parent_dev_name);
        return NULL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    if (multiq_support_enabled)
        dev = alloc_netdev_mqs(sizeof(osif_peer_dev), name, 0, ether_setup,
                OSIF_DP_NETDEV_TX_QUEUE_NUM, OSIF_DP_NETDEV_RX_QUEUE_NUM);
    else
        dev = alloc_netdev(sizeof(osif_peer_dev), name, 0, ether_setup);
#else
    if (multiq_support_enabled)
        dev = alloc_netdev_mqs(sizeof(osif_peer_dev), name, ether_setup,
                OSIF_DP_NETDEV_TX_QUEUE_NUM, OSIF_DP_NETDEV_RX_QUEUE_NUM);
    else
        dev = alloc_netdev(sizeof(osif_peer_dev), name, ether_setup);
#endif
    if(dev == NULL) {
        qdf_err("Failed to create netdevice for %s:%s", parent_dev_name, name);
        goto fail;
    }

    if (name != NULL)
        if (strlcpy(dev->name, name, sizeof(dev->name)) >= sizeof(dev->name)) {
            qdf_err("source too long");
            goto fail;
        }

    /*
    ** Clear and initialize the osif structure
    */
    osifp = ath_netdev_priv(dev);
    memset(osifp,0,sizeof(osif_peer_dev));
    osifp->netdev = dev;

    /* holding a ref on parent since pointer is stored
     * and will be released when child dev is deleted
     */
    osifp->parent_netdev = parent_dev;

    return osifp;
fail:
    if (parent_dev)
        dev_put(parent_dev);

    if (dev)
        free_netdev(dev);

    return NULL;
}

struct net_device *osif_create_wds_ext_netdev(struct ieee80211com *ic, struct ieee80211_clone_params *cp)
{
    struct net_device *peer_ndev;
    osif_peer_dev  *osifp;

    osifp = osif_create_wds_ext_netdev_alloc(cp, ic->multiq_support_enabled);
    if (osifp == NULL) {
        qdf_err("wds ext net dev allocation failed");
        return NULL;
    }
    osifp->dev_type = OSIF_NETDEV_TYPE_WDS_EXT;
    peer_ndev = osifp->netdev;
#if UMAC_SUPPORT_CFG80211
    osifp->wdev.wiphy = ic->ic_wdev.wiphy;
    osifp->wdev.netdev = peer_ndev;
    osifp->wdev.iftype = NL80211_IFTYPE_AP_VLAN;
    peer_ndev->ieee80211_ptr = &osifp->wdev;
#endif
    peer_ndev->netdev_ops = &osif_wds_ext_dev_ops;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    /*
     * Replace the netdev ops with the offlaod ops
     */
    if (!ic->nss_ext_vops) {
        goto register_netdev;
    }

    peer_ndev->netdev_ops = &osif_nss_wds_ext_vdev_ops;

    /*
     * Allocate the NSS interface.
     */
    osifp->nss_ifnum = ic->nss_ext_vops->ic_osif_nss_ext_vdev_alloc(osifp, ic);
    if (!NSS_IF_IS_TYPE_DYNAMIC(osifp->nss_ifnum)) {
	qdf_err("received invalid nss_ifnum(%d)", osifp->nss_ifnum);
        goto free_dev;
    }

    /*
     * Register the NSS interface. NSS dealloaction is taken care by the
     * register cb in case of failures. No need of external deallocation.
     */
    if (ic->nss_ext_vops->ic_osif_nss_ext_vdev_register(osifp, ic)) {
        qdf_err("NSS registration failed if_num(%d)", osifp->nss_ifnum);
        goto free_dev;
    }

register_netdev:
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

   /*
    * Create the NSS redirect interface.
    */
#if QCA_NSS_PLATFORM
    osif_pltfrm_create_ext_vap(osifp);
#endif

    /*
     * Register the netdevice. All previous failures need to free the device.
     */
    if (register_netdevice(peer_ndev)) {
        qdf_err("%s: unable to register device\n", osifp->netdev->name);
        goto free_dev;
    }

    return osifp->netdev;
free_dev:
    if (osifp->parent_netdev)
        dev_put(osifp->parent_netdev);

    free_netdev(peer_ndev);
    return NULL;
}

qdf_export_symbol(osif_create_wds_ext_netdev);
#endif

static int
proc_iv_config_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) m->private;
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t ldpc;
    uint32_t dtim_period;
    uint32_t rts_threshold;
    uint32_t frag_threshold;
    uint32_t inact_run;
    uint32_t nss;
#if QCA_LTEU_SUPPORT
    uint32_t scan_repeat_probe_time;
    uint32_t scan_probe_delay;
#endif
    uint32_t vhtbfsoundingdim;
    uint32_t vhtbfeestscap;
    uint32_t vhtsubfer;
    uint32_t vhtsubfee;
    uint32_t vhtmubfer;
    uint32_t vhtmubfee;
    uint32_t implicitbf;
#if WLAN_SUPPORT_MBSSSID
    uint32_t bssid_idx;
#endif
    uint32_t bcn_rate;
    uint32_t mgmt_rate;
    uint32_t amsdu_size;
    uint32_t ampdu_size;

    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_LDPC, &ldpc);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_DTIM_PERIOD, &dtim_period);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_NSS, &nss);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_SUBFER, &vhtsubfer);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_SUBFEE, &vhtsubfee);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_MUBFER, &vhtmubfer);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_MUBFEE, &vhtmubfee);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_IMLICIT_BF, &implicitbf);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_SOUNDING_DIM, &vhtbfsoundingdim);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_BFEE_STS_CAP, &vhtbfeestscap);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_RTS_THRESHOLD, &rts_threshold);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_FRAG_THRESHOLD, &frag_threshold);
#if QCA_LTEU_SUPPORT
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_PROBE_DELAY, &scan_probe_delay);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_REPEAT_PROBE_TIME, &scan_repeat_probe_time);
#endif
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME, &inact_run);
#if WLAN_SUPPORT_MBSSSID
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_PROFILE_IDX, &bssid_idx);
#endif
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_BCN_TX_RATE, &bcn_rate);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_TX_MGMT_RATE, &mgmt_rate);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_AMPDU, &ampdu_size);
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj,
            WLAN_MLME_CFG_AMSDU, &amsdu_size);

    seq_printf(m, "iv_myaddr: %s\n", ether_sprintf(vap->iv_myaddr));
    seq_printf(m, "iv_hw_addr: %s\n", ether_sprintf(wlan_vap_get_hw_macaddr(vap)));
    {
        int id = 0;
        wlan_objmgr_vdev_get_ref(vap->vdev_obj, WLAN_MLME_NB_ID);
        id = wlan_vdev_get_id(vap->vdev_obj);
        wlan_objmgr_vdev_release_ref(vap->vdev_obj, WLAN_MLME_NB_ID);
        seq_printf(m, "vap_id: %d\n", id);
    }
    seq_printf(m, "ic_my_hwaddr: %s\n", ether_sprintf(ic->ic_my_hwaddr));
    seq_printf(m, "ic_myaddr: %s\n", ether_sprintf(ic->ic_myaddr));

#define VAP_UINT_FIELD(x)   seq_printf(m, #x ": %u\n", vap->x)
#define VAP_UINT64_FIELD(x) seq_printf(m, #x ": %llu\n", vap->x)
#define VAP_ULONG_FIELD(x)  seq_printf(m, #x ": %lu\n", vap->x)
#define VAP_INT_FIELD(x)    seq_printf(m, #x ": %d\n", vap->x)

    VAP_UINT_FIELD(iv_unit);
    VAP_UINT_FIELD(iv_debug);
    VAP_UINT_FIELD(iv_opmode);
    VAP_UINT_FIELD(iv_scan_priority_base);
    VAP_UINT_FIELD(iv_create_flags);
    VAP_UINT_FIELD(iv_flags);
    VAP_UINT_FIELD(iv_flags_ext);
    VAP_UINT_FIELD(iv_flags_ext2);
    VAP_UINT_FIELD(iv_deleted);
    VAP_UINT_FIELD(iv_scanning);
    VAP_UINT_FIELD(iv_smps);
    VAP_UINT_FIELD(iv_standby);
    VAP_UINT_FIELD(iv_cansleep);
    VAP_UINT_FIELD(iv_sw_bmiss);
    VAP_UINT_FIELD(iv_copy_beacon);
    VAP_UINT_FIELD(iv_wapi);
    VAP_UINT_FIELD(iv_sta_fwd);
    VAP_UINT_FIELD(iv_dynamic_mimo_ps);
    VAP_UINT_FIELD(iv_doth);
    VAP_UINT_FIELD(iv_country_ie);
    VAP_UINT_FIELD(iv_wme);
    VAP_UINT_FIELD(iv_dfswait);
#if 0
    VAP_UINT_FIELD(iv_enable_when_dfs_clear);
#endif
    VAP_UINT_FIELD(iv_erpupdate);
    VAP_UINT_FIELD(iv_needs_scheduler);
    VAP_UINT_FIELD(iv_forced_sleep);
    VAP_UINT_FIELD(iv_qbssload);
    VAP_UINT_FIELD(iv_qbssload_update);
    VAP_UINT_FIELD(iv_rrm);
    VAP_UINT_FIELD(iv_wnm);
    VAP_UINT_FIELD(iv_proxyarp);
    VAP_UINT_FIELD(iv_dgaf_disable);
    VAP_UINT_FIELD(iv_ap_reject_dfs_chan);
    VAP_UINT_FIELD(iv_smartnet_enable);
    VAP_UINT_FIELD(iv_trigger_mlme_resp);
    VAP_UINT_FIELD(iv_mfp_test);
    VAP_UINT_FIELD(iv_sgi);
    VAP_UINT_FIELD(iv_he_sgi);
    VAP_UINT_FIELD(iv_data_sgi);
    VAP_UINT_FIELD(iv_he_data_sgi);
    seq_printf(m, "ldpc: %u\n", ldpc);
    VAP_UINT_FIELD(iv_ratemask_default);
    VAP_UINT_FIELD(iv_key_flag);
    VAP_UINT_FIELD(iv_list_scanning);
    VAP_UINT_FIELD(iv_vap_is_down);
#if ATH_SUPPORT_ZERO_CAC_DFS
    VAP_UINT_FIELD(iv_pre_cac_timeout_channel_change);
#endif
    VAP_UINT_FIELD(iv_needs_up_on_acs);
    VAP_UINT_FIELD(iv_quick_reconnect);
    VAP_UINT_FIELD(iv_256qam);
    VAP_UINT_FIELD(iv_11ng_vht_interop);
    VAP_UINT_FIELD(iv_mbo);
    VAP_UINT_FIELD(iv_ext_acs_inprogress);
    VAP_UINT_FIELD(iv_send_additional_ies);
    VAP_UINT_FIELD(vlan_set_flags);
    VAP_UINT_FIELD(iv_rawmode_pkt_sim);


#if 0
    VAP_UINT_FIELD(iv_one_mb_enabled);
    VAP_UINT_FIELD(iv_two_mb_enabled);
    VAP_UINT_FIELD(iv_five_mb_enabled);
#endif


    VAP_UINT_FIELD(iv_caps);
    VAP_UINT_FIELD(iv_ath_cap);
    VAP_UINT_FIELD(iv_chanchange_count);
    VAP_UINT_FIELD(iv_mcast_rate);
    VAP_UINT_FIELD(iv_mcast_fixedrate);
    VAP_UINT_FIELD(iv_mcast_rate_config_defered);

    seq_printf(m, "iv_node_count: %d\n", wlan_vdev_get_peer_count(vap->vdev_obj));
    VAP_UINT_FIELD(iv_unicast_counterm.mic_count_in_60s);
    VAP_UINT_FIELD(iv_unicast_counterm.timestamp);
    VAP_UINT_FIELD(iv_multicast_counterm.mic_count_in_60s);
    VAP_UINT_FIELD(iv_multicast_counterm.timestamp);
    VAP_UINT_FIELD(iv_max_aid);
    VAP_UINT_FIELD(iv_sta_assoc);
    VAP_UINT_FIELD(iv_ps_sta);
    VAP_UINT_FIELD(iv_ps_pending);
#if 0
    VAP_UINT_FIELD(iv_bad_count_ps_pending_underflow);
    VAP_UINT_FIELD(iv_bad_count_tim_bitmap_empty);
#endif

    seq_printf(m, "dtim_period: %u\n", dtim_period);
    VAP_UINT_FIELD(iv_dtim_count);
    VAP_UINT_FIELD(iv_atim_window);
    VAP_UINT_FIELD(iv_tim_len);
    VAP_UINT_FIELD(iv_rescan);
    VAP_UINT_FIELD(iv_fixed_rateset);
    VAP_UINT_FIELD(iv_fixed_retryset);
    VAP_UINT_FIELD(iv_legacy_ratemasklower32);
    VAP_UINT_FIELD(iv_ht_ratemasklower32);
    VAP_UINT_FIELD(iv_vht_ratemasklower32);
    VAP_UINT_FIELD(iv_vht_ratemaskhigher32);
#if ATH_SUPPORT_AP_WDS_COMBO
    VAP_UINT_FIELD(iv_no_beacon);
#endif
    VAP_ULONG_FIELD(iv_assoc_comeback_time);
    VAP_UINT_FIELD(iv_skip_pmf_reassoc_to_hostap);
    VAP_UINT_FIELD(iv_rsn_override);

    seq_printf(m, "rtsthreshold: %u\n", rts_threshold);
    seq_printf(m, "fragthreshold: %u\n", frag_threshold);
    VAP_UINT_FIELD(iv_def_txkey);
    VAP_UINT_FIELD(iv_num_privacy_filters);
    VAP_UINT_FIELD(iv_pmkid_count);
    VAP_UINT_FIELD(iv_wps_mode);
    VAP_UINT_FIELD(iv_wep_mbssid);

    VAP_UINT_FIELD(iv_des_mode);
    VAP_UINT_FIELD(iv_des_hw_mode);
    VAP_UINT_FIELD(iv_des_modecaps);
    VAP_UINT_FIELD(iv_cur_mode);
    VAP_UINT_FIELD(iv_des_ibss_chan_freq);
    VAP_UINT_FIELD(iv_des_cfreq2);
    VAP_UINT_FIELD(iv_rateCtrlEnable);
    VAP_UINT_FIELD(iv_rc_txrate_fast_drop_en);
    VAP_UINT_FIELD(iv_des_nssid);
    seq_printf(m, "iv_conf_des_bssid: %s\n", ether_sprintf(vap->iv_conf_des_bssid));

    VAP_UINT_FIELD(iv_bmiss_count);
    VAP_UINT_FIELD(iv_bmiss_count_for_reset);
    VAP_UINT_FIELD(iv_bmiss_count_max);
    VAP_ULONG_FIELD(iv_last_beacon_time);
    VAP_ULONG_FIELD(iv_last_directed_frame);
    VAP_ULONG_FIELD(iv_last_ap_frame);
    VAP_ULONG_FIELD(iv_last_traffic_indication);
    VAP_ULONG_FIELD(iv_lastdata);
    VAP_UINT64_FIELD(iv_txrxbytes);
    VAP_UINT_FIELD(iv_lastbcn_phymode_mismatch);
    VAP_UINT_FIELD(iv_beacon_copy_len);
    VAP_UINT_FIELD(iv_mlmeconnect);
    seq_printf(m, "ampdu_size: %u\n", ampdu_size);
    seq_printf(m, "amsdu_size: %u\n", amsdu_size);
    VAP_UINT_FIELD(iv_ratedrop);
    VAP_UINT_FIELD(iv_assoc_denial_notify);
    VAP_UINT_FIELD(iv_protmode);
    VAP_UINT_FIELD(dyn_bw_rts);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    VAP_UINT_FIELD(iv_psta);
    VAP_UINT_FIELD(iv_mpsta);
    VAP_UINT_FIELD(iv_wrap);
    VAP_UINT_FIELD(iv_mat);
    VAP_UINT_FIELD(iv_wired_pvap);
    seq_printf(m, "iv_mat_addr: %s\n", ether_sprintf(vap->iv_mat_addr));
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    VAP_UINT_FIELD(iv_nss_qwrap_en);
#endif
#endif
    VAP_UINT_FIELD(iv_beacon_info_count);
    VAP_UINT_FIELD(iv_esslen);
    seq_printf(m, "iv_essid: %s\n", ether_sprintf(vap->iv_essid));
    VAP_UINT_FIELD(iv_ibss_peer_count);
    VAP_UINT_FIELD(channel_change_done);
    VAP_UINT_FIELD(appie_buf_updated);
    VAP_UINT_FIELD(iv_doth_updated);
    VAP_UINT_FIELD(mixed_encryption_mode);
    VAP_UINT_FIELD(iv_ena_vendor_ie);
    VAP_UINT_FIELD(iv_update_vendor_ie);
    VAP_UINT_FIELD(iv_mgt_rate_config_defered);
#if WDS_VENDOR_EXTENSION
    VAP_UINT_FIELD(iv_wds_rx_policy);
#endif
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    VAP_UINT_FIELD(iv_sko_th);
#endif
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    VAP_UINT_FIELD(iv_chanutil_enab);
#endif
    VAP_UINT_FIELD(auto_assoc);
    VAP_UINT_FIELD(iv_inact_init);
    VAP_UINT_FIELD(iv_inact_auth);
    seq_printf(m, "inact_run: %u\n", inact_run);
    VAP_UINT_FIELD(iv_inact_probe);
    VAP_UINT_FIELD(iv_session);
    VAP_UINT_FIELD(iv_keep_alive_timeout);
    VAP_UINT_FIELD(iv_inact_count);
    VAP_UINT_FIELD(iv_smps_snrthresh);
    VAP_UINT_FIELD(iv_smps_datathresh);
#if ATH_SW_WOW
    VAP_UINT_FIELD(iv_sw_wow);
#endif
#ifdef ATH_SUPPORT_TxBF
    VAP_UINT_FIELD(iv_autocvupdate);
    VAP_UINT_FIELD(iv_cvupdateper);
#endif
    VAP_UINT_FIELD(iv_cswitch_rxd);
#if ATH_SUPPORT_WAPI
    VAP_UINT_FIELD(iv_wapi_urekey_pkts);
    VAP_UINT_FIELD(iv_wapi_mrekey_pkts);
#endif

#if ATH_SUPPORT_HS20
    seq_printf(m, "iv_hessid: %s\n", ether_sprintf(vap->iv_hessid));
    VAP_UINT_FIELD(iv_access_network_type);
    VAP_UINT_FIELD(iv_hotspot_xcaps);
    VAP_UINT_FIELD(iv_hotspot_xcaps2);
    VAP_UINT_FIELD(iv_hc_bssload);
    VAP_UINT_FIELD(iv_osen);
#endif
    VAP_UINT_FIELD(iv_wep_keycache);

#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    VAP_UINT_FIELD(iv_rejoint_attemp_time);
#endif

    VAP_UINT_FIELD(iv_send_deauth);
#if UMAC_SUPPORT_WNM
    VAP_UINT_FIELD(iv_wnmsleep_intval);
    VAP_UINT_FIELD(iv_wnmsleep_force);
#endif

#if ATH_SUPPORT_WRAP
    VAP_UINT_FIELD(iv_no_event_handler);
#endif
    VAP_UINT_FIELD(iv_is_started);
    VAP_UINT_FIELD(iv_is_up);

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    VAP_UINT_FIELD(iv_nopbn);
#endif

#if UMAC_PER_PACKET_DEBUG
    VAP_UINT_FIELD(iv_userrate);
    VAP_UINT_FIELD(iv_userretries);
    VAP_UINT_FIELD(iv_usertxpower);
    VAP_UINT_FIELD(iv_usertxchainmask);
#endif

    VAP_UINT_FIELD(iv_aponly);
    VAP_UINT_FIELD(iv_force_onetxchain);
    VAP_UINT_FIELD(iv_vht_fixed_mcs);
    VAP_UINT_FIELD(iv_he_fixed_mcs);
    seq_printf(m, "nss: %u\n", nss);
    VAP_UINT_FIELD(iv_tx_stbc);
    VAP_UINT_FIELD(iv_rx_stbc);
    VAP_UINT_FIELD(iv_opmode_notify);
    VAP_UINT_FIELD(iv_rtscts_enabled);
    VAP_UINT_FIELD(iv_rc_num_retries);
    VAP_UINT_FIELD(iv_bcast_fixedrate);
    VAP_UINT_FIELD(iv_bcast_rate_config_defered);
    VAP_UINT_FIELD(iv_vht_tx_mcsmap);
    VAP_UINT_FIELD(iv_vht_rx_mcsmap);
    VAP_UINT_FIELD(iv_disabled_legacy_rate_set);
    VAP_UINT_FIELD(iv_disable_htmcs);
    VAP_UINT_FIELD(iv_configured_vht_mcsmap);
    VAP_UINT_FIELD(iv_set_vht_mcsmap);
    VAP_UINT_FIELD(min_dwell_time_passive);
    VAP_UINT_FIELD(max_dwell_time_passive);

#if QCA_LTEU_SUPPORT
    seq_printf(m, "scan_repeat_probe_time: %u\n", scan_repeat_probe_time);
    VAP_UINT_FIELD(scan_rest_time);
    VAP_UINT_FIELD(scan_idle_time);
    seq_printf(m, "scan_probe_delay: %u\n", scan_probe_delay);
    VAP_UINT_FIELD(mu_start_delay);
    VAP_UINT_FIELD(wifi_tx_power);
#endif

    VAP_UINT_FIELD(iv_vht_sgimask);
    VAP_UINT_FIELD(iv_vht80_ratemask);

#if ATH_SUPPORT_DSCP_OVERRIDE
    VAP_UINT_FIELD(iv_dscp_map_id);
    VAP_UINT_FIELD(iv_vap_dscp_priority);
#endif
    VAP_UINT_FIELD(iv_pause_scan);

#if ATH_PERF_PWR_OFFLOAD
    VAP_UINT_FIELD(iv_tx_encap_type);
    VAP_UINT_FIELD(iv_rx_decap_type);
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    VAP_UINT_FIELD(iv_rawmodesim_txaggr);
    VAP_UINT_FIELD(iv_rawmodesim_debug_level);
    VAP_UINT_FIELD(iv_fixed_frm_cnt_flag);
    VAP_INT_FIELD(iv_num_encap_frames);
    VAP_INT_FIELD(iv_num_decap_frames);
#endif
#endif
    VAP_UINT_FIELD(mhdr_len);

#if MESH_MODE_SUPPORT
    VAP_UINT_FIELD(iv_mesh_vap_mode);
#endif
    VAP_UINT_FIELD(iv_mesh_mgmt_txsend_config);
    VAP_UINT_FIELD(iv_special_vap_mode);
    VAP_UINT_FIELD(iv_special_vap_is_monitor);
    VAP_UINT_FIELD(iv_smart_monitor_vap);
    seq_printf(m, "vhtbfeestscap: %u\n", vhtbfeestscap);
    seq_printf(m, "vhtbfsoundingdim: %u\n", vhtbfsoundingdim);

    VAP_UINT_FIELD(iv_novap_reset);
    seq_printf(m, "mcast_encrypt_addr: %s\n", ether_sprintf(vap->mcast_encrypt_addr));
    VAP_UINT_FIELD(mac_entries);
    VAP_UINT_FIELD(rtt_enable);
    VAP_UINT_FIELD(lci_enable);
    VAP_UINT_FIELD(lcr_enable);
    VAP_UINT_FIELD(iv_smart_mesh_cfg);

#if MESH_MODE_SUPPORT
    VAP_UINT_FIELD(mhdr);
    VAP_UINT_FIELD(mdbg);
    seq_printf(m, "bssid_mesh: %s\n", ether_sprintf(vap->bssid_mesh));
    VAP_UINT_FIELD(iv_mesh_cap);
#endif

#if ATH_DATA_RX_INFO_EN
    VAP_UINT_FIELD(rxinfo_perpkt);
#endif

    VAP_UINT_FIELD(iv_cfg_assoc_war_160w);
    VAP_UINT_FIELD(iv_rev_sig_160w);
    VAP_UINT_FIELD(channel_switch_state);
    VAP_UINT_FIELD(iv_disable_ht_tx_amsdu);
    VAP_UINT_FIELD(iv_cts2self_prot_dtim_bcn);
    VAP_UINT_FIELD(iv_enable_vsp);
    VAP_UINT_FIELD(iv_cfg_raw_dwep_ind);

#if UMAC_SUPPORT_ACFG
    VAP_UINT_FIELD(iv_diag_warn_threshold);
    VAP_UINT_FIELD(iv_diag_err_threshold);
#endif

#if QCA_LTEU_SUPPORT
    VAP_UINT_FIELD(scan_probe_spacing_interval);
#endif

    VAP_UINT_FIELD(watermark_threshold);
    VAP_UINT_FIELD(watermark_threshold_reached);
    VAP_UINT_FIELD(watermark_threshold_flag);
    VAP_UINT_FIELD(assoc_high_watermark);
    VAP_UINT_FIELD(assoc_high_watermark_time);
    VAP_UINT_FIELD(iv_cfg_nstscap_war);
    seq_printf(m, "beacon rate: %d\n", bcn_rate);
    VAP_UINT_FIELD(iv_csmode);
    VAP_UINT_FIELD(iv_enable_ecsaie);
    VAP_UINT_FIELD(iv_ecsa_opclass);

#if DYNAMIC_BEACON_SUPPORT
    VAP_UINT_FIELD(iv_dbeacon_snr_thr);
    VAP_UINT_FIELD(iv_dbeacon_timeout);
#endif

#if UMAC_SUPPORT_CFG80211
    VAP_UINT_FIELD(iv_cfg80211_create);
#endif
    VAP_UINT_FIELD(iv_scan_band);

    /* country ie data */
    VAP_UINT64_FIELD(iv_country_ie_chanflags);

    /* U-APSD Settings */
    VAP_UINT_FIELD(iv_uapsd);
    VAP_UINT_FIELD(iv_wmm_enable);
    VAP_UINT_FIELD(iv_wmm_power_save);

    VAP_UINT_FIELD(iv_disable_HTProtection);
    VAP_UINT_FIELD(iv_ht40_intolerant);
    VAP_UINT_FIELD(iv_chwidth);
    VAP_UINT_FIELD(iv_chextoffset);
    VAP_UINT_FIELD(iv_chscaninit);

    VAP_UINT_FIELD(iv_ccmpsw_seldec);
    seq_printf(m, "mgmt rate: %u\n", mgmt_rate);
#ifdef ATH_SUPPORT_TxBF
    VAP_UINT_FIELD(iv_txbfmode);
#endif

    seq_printf(m, "vhtsubfer: %u\n", vhtsubfer);
    seq_printf(m, "vhtsubfee: %u\n", vhtsubfee);
    seq_printf(m, "vhtmubfer: %u\n", vhtmubfer);
    seq_printf(m, "vhtmubfee: %u\n", vhtmubfee);
    seq_printf(m, "implicitbf: %u\n", implicitbf);
    /* HE Parameters */
    VAP_UINT_FIELD(iv_he_ctrl);
    VAP_UINT_FIELD(iv_he_twtreq);
    VAP_UINT_FIELD(iv_he_twtres);
    VAP_UINT_FIELD(iv_he_frag);
    VAP_UINT_FIELD(iv_he_max_frag_msdu);
    VAP_UINT_FIELD(iv_he_min_frag_size);
    VAP_UINT_FIELD(iv_he_multi_tid_aggr);
    VAP_UINT_FIELD(iv_he_link_adapt);
    VAP_UINT_FIELD(iv_he_all_ack);
    VAP_UINT_FIELD(iv_he_ul_mu_sched);
    VAP_UINT_FIELD(iv_he_actrl_bsr);
    VAP_UINT_FIELD(iv_he_32bit_ba);
    VAP_UINT_FIELD(iv_he_mu_cascade);
    VAP_UINT_FIELD(iv_he_omi);
    VAP_UINT_FIELD(iv_he_ofdma_ra);
    VAP_UINT_FIELD(iv_he_amsdu_frag);
    VAP_UINT_FIELD(iv_he_flex_twt);
    VAP_UINT_FIELD(iv_he_relaxed_edca);
    VAP_UINT_FIELD(iv_he_spatial_reuse);
    VAP_UINT_FIELD(iv_he_multi_bss);
    VAP_UINT_FIELD(iv_he_ul_mumimo);
    VAP_UINT_FIELD(iv_he_ul_muofdma);
    VAP_UINT_FIELD(iv_he_dl_muofdma);
    VAP_UINT_FIELD(iv_he_dl_muofdma_bfer);
    VAP_UINT_FIELD(iv_he_twt_required);
    VAP_UINT_FIELD(iv_he_rts_threshold);
    VAP_UINT_FIELD(iv_he_extended_range);
    VAP_UINT_FIELD(iv_he_dcm);
    VAP_UINT_FIELD(iv_bcn_offload_enable);
    VAP_UINT_FIELD(iv_oce);
    VAP_UINT_FIELD(iv_he_su_bfee);
    VAP_UINT_FIELD(iv_he_su_bfer);
    VAP_UINT_FIELD(iv_he_mu_bfee);
    VAP_UINT_FIELD(iv_he_mu_bfer);
    VAP_UINT_FIELD(iv_he_tx_mcsnssmap);
    VAP_UINT_FIELD(iv_he_rx_mcsnssmap);
    VAP_UINT_FIELD(iv_he_default_pe_durn);
    VAP_UINT_FIELD(iv_he_ltf);
    VAP_UINT_FIELD(iv_he_ar_gi_ltf);
    VAP_UINT_FIELD(iv_ext_nss_support);
    VAP_UINT_FIELD(iv_csl_support);
    VAP_UINT_FIELD(iv_lite_monitor);
    VAP_UINT_FIELD(iv_remove_csa_ie);
    VAP_UINT_FIELD(iv_refuse_all_addbas);
    VAP_UINT_FIELD(iv_ba_buffer_size);

#if ATH_ACL_SOFTBLOCKING
    VAP_UINT_FIELD(iv_softblock_wait_time);
    VAP_UINT_FIELD(iv_softblock_allow_time);
#endif
#if QCN_IE
    VAP_UINT_FIELD(iv_bpr_enable);
    VAP_UINT_FIELD(iv_bpr_delay);
    VAP_UINT_FIELD(iv_bpr_timer_start_count);
    VAP_UINT_FIELD(iv_bpr_timer_resize_count);
    VAP_UINT_FIELD(iv_bpr_callback_count);
    VAP_UINT_FIELD(iv_bpr_timer_cancel_count);
#endif

    VAP_UINT_FIELD(iv_htflags);
#ifdef QCA_OL_DMS_WAR
    VAP_UINT_FIELD(dms_amsdu_war);
#endif
    VAP_UINT64_FIELD(wmi_tx_mgmt);
    VAP_UINT64_FIELD(wmi_tx_mgmt_completions);
    VAP_UINT64_FIELD(wmi_tx_mgmt_sta);
    VAP_UINT64_FIELD(wmi_tx_mgmt_completions_sta);
    VAP_UINT_FIELD(iv_read_rxprehdr);
#if DYNAMIC_BEACON_SUPPORT
    VAP_UINT_FIELD(iv_dbeacon);
    VAP_UINT_FIELD(iv_dbeacon_runtime);
#endif
    VAP_UINT_FIELD(iv_sm_gap_ps);
    VAP_UINT_FIELD(iv_static_mimo_ps);

#if WLAN_SUPPORT_MBSSSID
    seq_printf(m, "bssid_idx: %u\n", bssid_idx);
#endif

    return 0;
}

int osif_print_scan_config(wlan_if_t vaphandle, struct seq_file *m)
{
    const char*sep;
    struct ieee80211com *ic = vaphandle->iv_ic;
    struct chan_list *chan_list;
    uint8_t ch;
    uint8_t band;
    int i;
    char s = ieee80211_get_vap_mode(vaphandle);

    seq_printf(m, "scanning: %d\n", ic->scan_params.scan_ev_completed ? 1 : 0);
    seq_printf(m, "channels: ");
    sep = "";

    chan_list = qdf_mem_malloc(sizeof(*chan_list));

    if (!chan_list) {
        qdf_err("chan_list is NULL");
        return -ENOMEM;
    }

    qdf_mem_copy(chan_list, &ic->scan_params.chan_list, sizeof(*chan_list));

    for (i = 0; i < chan_list->num_chan; i++) {
        ch = wlan_reg_freq_to_chan(ic->ic_pdev_obj, chan_list->chan[i].freq);
        band = wlan_reg_freq_to_band(chan_list->chan[i].freq);
        seq_printf(m, "%s%u:%u %c", sep, ch, band, s);
        sep = " ";
    }
    seq_printf(m, "\n");
    seq_printf(m, "flags: %s%s%s%s%s%s%s\n",
               (ic->scan_params.scan_f_passive) ? "passive " : "",
               (ic->scan_params.scan_f_2ghz) ? "2GHz " : "",
               (ic->scan_params.scan_f_5ghz) ? "5GHz " : "",
               (ic->scan_params.scan_f_wide_band) ? "allbands " : "",
               (ic->scan_params.scan_f_continue_on_err) ? "continuous " : "",
               (ic->scan_params.scan_f_forced) ? "forced " : "",
               (ic->scan_params.scan_f_bcast_probe) ? "bcast_probe " : "");

    seq_printf(m,
               "max rest time: %u\n"
               "min rest time: %u\n"
               "idle time: %u\n"
               "max scan time: %u\n"
               "dwell on active: %u\n"
               "dwell on passive: %u\n",
               ic->scan_params.max_rest_time,
               ic->scan_params.min_rest_time,
               ic->scan_params.idle_time,
               ic->scan_params.max_scan_time,
               ic->scan_params.dwell_time_active,
               ic->scan_params.dwell_time_passive);

    qdf_mem_free(chan_list);
    return 0;
}



static int
proc_scan_config_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) m->private;

    osif_print_scan_config(vap,m);
    seq_printf(m, "bg_scan_enabled: %d\n", (vap->iv_flags & IEEE80211_F_BGSCAN) ? 1 : 0);
    return 0;
}

static
void proc_clients_rates_show_iter_cb(void *arg, struct ieee80211_node *ni)
{
    struct seq_file *m = (struct seq_file *)arg;
    struct ieee80211_rateset *rs= &(ni->ni_rates);
    int i;

    seq_printf(m, "entry mac=%s\n", ether_sprintf(ni->ni_macaddr));
    seq_printf(m, "rate_info:\n");

    for (i = 0; i < (rs->rs_nrates); i++)
        seq_printf(m, " RateIndex[%d], %d\n", i,
                   rs->rs_rates[i] & IEEE80211_RATE_VAL);
}

static int
proc_clients_rates_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) (((uintptr_t) m->private) & ~0x3);

    IEEE80211_VAP_LOCK(vap);
    wlan_iterate_all_sta_list(vap, proc_clients_rates_show_iter_cb, (void *)m);
    IEEE80211_VAP_UNLOCK(vap);

    return 0;
}

struct osif_proc_info {
    const char *name;
    struct file_operations *ops;
    int extra;
};

#define PROC_FOO(func_base, extra) { #func_base, &proc_ieee80211_##func_base##_ops, extra }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define GENERATE_PROC_STRUCTS(func_base)				\
	static int proc_##func_base##_open(struct inode *inode, \
					   struct file *file)		\
	{								\
		struct proc_dir_entry *dp = PDE(inode);			\
		return single_open(file, proc_##func_base##_show, dp->data); \
	}								\
									\
	static struct file_operations proc_ieee80211_##func_base##_ops = { \
		.open		= proc_##func_base##_open,	\
		.read		= seq_read,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	};
#else
#define GENERATE_PROC_STRUCTS(func_base)				\
	static int proc_##func_base##_open(struct inode *inode, \
					   struct file *file)		\
	{								\
        return single_open(file, proc_##func_base##_show, PDE_DATA(inode)); \
    } \
									\
									\
	static struct file_operations proc_ieee80211_##func_base##_ops = { \
		.open		= proc_##func_base##_open,	\
		.read		= seq_read,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	};
#endif

GENERATE_PROC_STRUCTS(clients_keys);
GENERATE_PROC_STRUCTS(clients_rates);
GENERATE_PROC_STRUCTS(iv_config);
GENERATE_PROC_STRUCTS(scan_config);

const struct osif_proc_info osif_proc_infos[] = {
    PROC_FOO(clients_keys, 0),
    PROC_FOO(clients_rates, 0),
    PROC_FOO(iv_config, 0),
    PROC_FOO(scan_config, 0),
};

#define NUM_PROC_INFOS (sizeof(osif_proc_infos) / sizeof(osif_proc_infos[0]))

void
ieee80211_proc_vattach(struct ieee80211vap *vap)
{
    char *devname = NULL;

    /*
     * Reserve space for the device name outside the net_device structure
     * so that if the name changes we know what it used to be.
     */
    devname = qdf_mem_malloc((strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) * sizeof(char));
    if (devname == NULL) {
        qdf_print(KERN_ERR "%s: no memory for VAP name!", __func__);
        return;
    }
    if (strlcpy(devname, ((osif_dev *)vap->iv_ifp)->netdev->name,
            strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) >= strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) {
        qdf_print("source too long");
        return ;
    }
    vap->iv_proc = proc_mkdir(devname, NULL);
    if (vap->iv_proc) {
      	int i;
        for (i = 0; i < NUM_PROC_INFOS; ++i) {
            struct proc_dir_entry *entry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
            entry = proc_create_data(osif_proc_infos[i].name, 0644, vap->iv_proc,
                        (const struct file_operations *) osif_proc_infos[i].ops, (void *)vap);
#else
            entry = create_proc_entry(osif_proc_infos[i].name,
                                       0644, vap->iv_proc);
#endif
            if (entry == NULL) {
                qdf_print(KERN_ERR "%s: Proc Entry creation failed!", __func__);
                goto entry_creation_failed;
            }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
            entry->data = vap;
            entry->proc_fops = osif_proc_infos[i].ops;
#endif
        }
    }
entry_creation_failed:
    qdf_mem_free(devname);

}

void
ieee80211_proc_vdetach(struct ieee80211vap *vap)
{
    if (vap->iv_proc) {
        int i;
        for (i = 0; i < NUM_PROC_INFOS; ++i)
            remove_proc_entry(osif_proc_infos[i].name, vap->iv_proc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        remove_proc_entry(vap->iv_proc->name, vap->iv_proc->parent);
#else
        proc_remove(vap->iv_proc);
#endif
        vap->iv_proc = NULL;

    }
}

int
ath_get_radio_index(struct net_device *netdev)
{
    if (!qdf_mem_cmp(netdev->name, "wifi0", 5)) {
        return 0;
    } else if (!qdf_mem_cmp(netdev->name, "wifi1", 5)) {
        return 1;
    } else if (!qdf_mem_cmp(netdev->name, "wifi2", 5)) {
        return 2;
    } else {
        qdf_print("Error: Could not match the device name : %s", netdev->name);
        return -1;
    }
}
qdf_export_symbol(ath_get_radio_index);
int
asf_adf_attach(void)
{
    static int first = 1;

    /*
     * Configure the shared asf_print instances with ADF
     * function pointers for print.
     * (Do this initialization just once.)
     */
    if (first) {
        first = 0;

        qdf_spinlock_create(&asf_print_lock);
        asf_print_setup(
            (asf_vprint_fp)qdf_vprint,
            (asf_print_lock_fp)qdf_spin_lock_bh,
            (asf_print_unlock_fp)qdf_spin_unlock_bh,
            &asf_print_lock);
    }

    return EOK;
}
qdf_export_symbol(asf_adf_attach);

#ifndef REMOVE_PKT_LOG
struct ath_pktlog_funcs *g_pktlog_funcs = NULL;
struct ath_pktlog_rcfuncs *g_pktlog_rcfuncs = NULL;
struct ol_pl_os_dep_funcs *g_ol_pl_os_dep_funcs = NULL;

qdf_export_symbol(g_pktlog_funcs);
qdf_export_symbol(g_pktlog_rcfuncs);
qdf_export_symbol(g_ol_pl_os_dep_funcs);

void (*g_osif_hal_ani)(void *) = NULL;
/*
 * ath_pktlog module passes the ani func here.
 * This func is passed to HAL using the callback registered by qca_da in the below func.
 */
void osif_pktlog_log_ani_callback_register(void *pktlog_ani)
{
    if (g_osif_hal_ani) {
        g_osif_hal_ani(pktlog_ani);
    }
}
qdf_export_symbol(osif_pktlog_log_ani_callback_register);

/* qca_da module registers the HAL function here */
void osif_hal_log_ani_callback_register(void *hal_ani)
{
    g_osif_hal_ani = hal_ani;
}
qdf_export_symbol(osif_hal_log_ani_callback_register);
#endif

bool ieee80211_is_6g_valid_rate(struct ieee80211vap *vap, u_int32_t rate)
{
    if(IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan) &&
            ((rate >= IEEE80211_HE_6GHZ_RATE_LOW_THRES) &&
             (rate <= IEEE80211_HE_6GHZ_RATE_HIGH_THRES))) {
        /* Allow HE rate to be set when AP is operating in 6GHz band.
         */
        return 1;
    }

    return 0;
}
qdf_export_symbol(ieee80211_is_6g_valid_rate);

int
ieee80211_rate_is_valid_basic(struct ieee80211vap *vap, u_int32_t rate)
{
    enum ieee80211_phymode mode = wlan_get_desired_phymode(vap);
    struct ieee80211_rateset *op_rs = &(vap->iv_op_rates[mode]);
    int i;
    int rs_rate,basic_rate;

    if(ieee80211_is_6g_valid_rate(vap, rate)) {
        return 1;
    } else {
        /* Find all basic rates */
        for (i=0; i < op_rs->rs_nrates; i++) {
            rs_rate = op_rs->rs_rates[i];
            /* Added this check for 11ng. Since 6,12 and 24 Mbps rates are not showing as basic rate as per the current code*/
            if (vap->iv_disabled_legacy_rate_set) {
                basic_rate = rs_rate & IEEE80211_RATE_VAL;
            } else {
                basic_rate = rs_rate & IEEE80211_RATE_BASIC;
            }
            if (basic_rate) {
                if (rate == ((rs_rate & IEEE80211_RATE_VAL) * 1000)/2) {
                    return 1;
                }
            }
        }
    }

    return 0;
}
qdf_export_symbol(ieee80211_rate_is_valid_basic);

#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
void osif_set_primary_radio_event (struct ieee80211com *ic)
{
    osif_dev *osdev;
    struct net_device *dev;
    union iwreq_data wreq;
    wlan_if_t apvap;
#if WLAN_QWRAP_LEGACY
    if (ic->ic_mpsta_vap == NULL || !(ic->ic_wrap_vap)) {
       return;
    }
    apvap = ic->ic_wrap_vap;
#else
    if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_WRAP_EN) ) {
       return;
    }
    apvap = wlan_get_vap(dp_wrap_get_vdev(ic->ic_pdev_obj));
    if (!apvap) {
       return;
    }
#endif
    osdev = (osif_dev *)wlan_vap_get_registered_handle(apvap);
    dev = OSIF_TO_NETDEV(osdev);
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_PRIMARY_RADIO_CHANGED;
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, NULL);
}
#endif

int wlan_is_ap_cac_timer_running (struct ieee80211com *ic)
{
    struct wlan_objmgr_pdev *pdev;
    pdev = ic->ic_pdev_obj;
    return mlme_dfs_is_ap_cac_timer_running(pdev);
}

void ieee80211_mgmt_sta_send_csa_rx_nl_msg(
        struct ieee80211com                         *ic,
        struct ieee80211_node                       *ni,
        struct ieee80211_ath_channel                *chan,
        struct ieee80211_ath_channelswitch_ie       *chanie,
        struct ieee80211_extendedchannelswitch_ie   *echanie,
        struct ieee80211_ie_sec_chan_offset         *secchanoffsetie,
        struct ieee80211_ie_wide_bw_switch          *widebwie)
{
    struct ieee80211_csa_rx_ev csa_rx_ev = {0};
    union iwreq_data wreq = {{0}};
    struct net_device *dev;

    memcpy(csa_rx_ev.bssid, ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
    csa_rx_ev.valid = !!chan;

    if (chanie)
        csa_rx_ev.chan = chanie->newchannel;
    else if (echanie)
        csa_rx_ev.chan = echanie->newchannel;

    if (widebwie) {
        csa_rx_ev.cfreq2_mhz = widebwie->new_ch_freq_seg2;
        if (widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_2040) {
            csa_rx_ev.width_mhz = 40;
        } else if ((widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_80) ||
                   (widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) ||
                   (widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80)) {
            if (widebwie->new_ch_freq_seg2 == 0) {
                csa_rx_ev.width_mhz = 80;
            } else if ((widebwie->new_ch_freq_seg2 > 0) &&
                    abs(widebwie->new_ch_freq_seg2 - widebwie->new_ch_freq_seg1) > 16) {
                csa_rx_ev.width_mhz = 160;
            } else if ((widebwie->new_ch_freq_seg2 > 0) &&
                    abs(widebwie->new_ch_freq_seg2 - widebwie->new_ch_freq_seg1) == 8) {
                csa_rx_ev.width_mhz = 160;
            }
        } else if ((widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_160) ||
                   (widebwie->new_ch_width == IEEE80211_VHTOP_CHWIDTH_80_80)) {
            csa_rx_ev.width_mhz = 160;
        } else {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
                    "%s : Invalid wideband channel width %d specified\n",
                    __func__, widebwie->new_ch_width);
            return;
        }
    }

    if (secchanoffsetie) {
        switch (secchanoffsetie->sec_chan_offset) {
            case IEEE80211_SEC_CHAN_OFFSET_SCN:
                csa_rx_ev.secondary = 0;
                break;
            case IEEE80211_SEC_CHAN_OFFSET_SCA:
                csa_rx_ev.secondary = 1;
                break;
            case IEEE80211_SEC_CHAN_OFFSET_SCB:
                csa_rx_ev.secondary = -1;
                break;
        }
    }

    wreq.data.flags = IEEE80211_EV_CSA_RX;
    wreq.data.length = sizeof(csa_rx_ev);

    if (!ic){
        qdf_err("ic is null");
        return;
    }
    if (!ic->ic_osdev){
        qdf_err("ic->ic_osdev is null");
        return;
    }
    dev = (void *)ic->ic_osdev->netdev;
    if (!dev){
        qdf_err("dev is null");
        return;
    }

    qdf_info("valid=%d chan=%d width=%d sec=%d cfreq2=%d\n",
            csa_rx_ev.valid,
            csa_rx_ev.chan,
            csa_rx_ev.width_mhz,
            csa_rx_ev.secondary,
            csa_rx_ev.cfreq2_mhz);

    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (void *)&csa_rx_ev);
}

static QDF_STATUS umac_debug_panic_handler(void *data)
{
	wlan_mlme_print_all_sm_history();
	return QDF_STATUS_SUCCESS;
}

static void ic_cancel_obss_nb_ru_tolerance_timer(struct ieee80211com *ic)
{
    qdf_timer_sync_cancel(&ic->ic_obss_nb_ru_tolerance_timer);

    return;
}

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
osif_dev *
wlan_get_osdev(struct wlan_objmgr_vdev *vdev) {
    struct vdev_osif_priv *vdev_osifp = NULL;
    osif_dev *osifp = NULL;

    if (qdf_unlikely(!vdev))
        return NULL;

    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    if (qdf_unlikely(!vdev_osifp))
        return NULL;

    osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
    return osifp;
}
qdf_export_symbol(wlan_get_osdev);

struct ieee80211vap *
wlan_get_vap(struct wlan_objmgr_vdev *vdev) {
    struct vdev_osif_priv *vdev_osifp = NULL;
    osif_dev *osifp = NULL;

    if (qdf_unlikely(!vdev))
        return NULL;
    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    if (qdf_unlikely(!vdev_osifp))
        return NULL;

    osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
    return osifp->os_if;
}
qdf_export_symbol(wlan_get_vap);
#endif
#endif

int init_umac(void)
{
#ifdef QCA_WIFI_MODULE_PARAMS_FROM_INI
	initialize_umac_module_param_from_ini();
#endif
	mlme_set_ops_cb();

	/* Connection manager callback */
	osif_cm_register_legacy_cb();

	/* Global dispatcher init*/
	if(dispatcher_init() != 0) {
		return -ENOMEM;
	}

	/* Global dispatcher enable*/
	if(dispatcher_enable() != 0) {
		dispatcher_deinit();
		return -ENOMEM;
	}

	/* init UMAC */
	if(wlan_umac_init() != 0) {
		return -ENOMEM;
	}

	QDF_BUG(!cfg_parse("global.ini"));
	QDF_BUG(!cfg_parse_to_global_store("internal/global_i.ini"));

	/* Set the print ratelimting thresholds */
	qdf_rl_print_count_set(200);
	qdf_rl_print_time_set(2);

	/*
	 * Registering different module ID's
	 * for different message queue of the scheduler.
	 *
	 * When message are posted to this queues, thier
	 * handlers are executed in the scheduler context.
	 *
	 * The priotiry of the message queues
	 * is based on the order in whcih they
	 * are registered.
	 */
	scheduler_register_module(QDF_MODULE_ID_SYS,
			&scheduler_timer_q_mq_handler);
	scheduler_register_module(QDF_MODULE_ID_MLME,
			&scheduler_mlme_mq_handler);
	scheduler_register_module(QDF_MODULE_ID_SCAN,
			&scheduler_scan_mq_handler);
	scheduler_register_module(QDF_MODULE_ID_OS_IF,
			&scheduler_os_if_mq_handler);

	/* Set the threshold for scheduler timeout to 20 secs */
	scheduler_set_watchdog_timeout(20000);

    return 0;
}

void exit_umac(void)
{
     /* de init UMAC */
    wlan_umac_deinit();

    /* Global dispatcher disable*/
    dispatcher_disable();

    cfg_release();

   /* Global Deinit after PSOC removed */
    dispatcher_deinit();

}

#ifndef QCA_SINGLE_WIFI_3_0
module_init(init_umac);
module_exit(exit_umac);
#endif

MODULE_DESCRIPTION("Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

