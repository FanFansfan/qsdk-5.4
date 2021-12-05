/*
 * Copyright (c) 2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
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
/*
 * LMAC offload interface functions for UMAC - for power and performance offload model
 */
#include <ol_if_athvar.h>
#include <ol_if_pdev.h>
#include <ol_if_fips.h>
#include <ol_if_athpriv.h>
#include <ol_txrx_api_internal.h>
#include <osdep.h>
#include <hif.h>
#include <bmi.h>
#include <target_type.h>
#ifdef WIFI_TARGET_TYPE_2_0
#include <sw_version.h>
#endif
#include <targaddrs.h>
#include <ol_helper.h>
#include <cdp_txrx_cmn.h>
#include <qdf_lock.h>
#include <qdf_types.h>
#include <qdf_util.h>
#include <qdf_mem.h>
#include <qdf_trace.h>
#include <wmi_unified_api.h>
#include <wmi_unified_vdev_api.h>
#include <cdp_txrx_cmn_reg.h>
#include <wlan_lmac_if_def.h>
#include <wlan_lmac_if_api.h>
#include <wlan_mgmt_txrx_utils_api.h>
#include <cdp_txrx_ctrl.h>
#include <dp_extap.h>
#include <qwrap_structure.h>
#include <wlan_global_lmac_if_api.h>
#include <target_if.h>
#include <service_ready_util.h>
#include <wlan_scan.h>
#include <ol_cfg.h>
#include <wlan_cfg.h>
#include <pld_common.h>
#include <ieee80211_api.h>
#if ATH_ACS_DEBUG_SUPPORT
#include "acs_debug.h"
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
/* FIX THIS: the HL vs. LL selection will need to be done
 * at runtime rather than compile time
 */

#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"    /* TODO: check if we need a seperated config file */
#else
#include "wlan_tgt_def_config.h"
#endif

#if OBSS_PD
#include <ol_if_obss.h>
#endif
#include <fw_dbglog_api.h>
#include <ol_if_wow.h>
#include <a_debug.h>
#include <epping_test.h>
#include <pktlog_ac.h>
#include <ol_regdomain.h>

#if WLAN_SPECTRAL_ENABLE
#include "target_if_spectral.h"
#include <ol_if_spectral.h>
#endif

#include <ol_ath.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <ol_if_stats.h>
#include <wds_addr_api.h>
#include <qdf_atomic.h>
#include <ol_swap.h>
#include <ol_if_eeprom.h>

#if ATH_PERF_PWR_OFFLOAD

#include <ath_pci.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#ifndef __LINUX_POWERPC_ARCH__
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 24)
#include <asm/segment.h>
#endif
#endif
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <reg_struct.h>
#include <regtable.h>

#if UMAC_SUPPORT_ACFG || UMAC_SUPPORT_ACFG_RECOVERY
#include "ieee80211_acfg.h"
#include <acfg_event_types.h>   /* for ACFG_WDT_TARGET_ASSERT */
#endif

#if WIFI_MEM_MANAGER_SUPPORT
#include "mem_manager.h"
#endif

#include <osif_private.h>

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <dispatcher_init_deinit.h>
#if QCA_AIRTIME_FAIRNESS
#include <target_if_atf.h>
#endif
#if UNIFIED_SMARTANTENNA
#include <target_if_sa_api.h>
#endif /* UNIFIED_SMARTANTENNA */
#if WLAN_SPECTRAL_ENABLE
#include <wlan_spectral_ucfg_api.h>
#include <wlan_spectral_utils_api.h>
#endif
#include <init_event_handler.h>
#include <init_cmd_api.h>
#include <init_deinit_lmac.h>
#include <wlan_osif_priv.h>
#include <wlan_utility.h>

#include <reg_services_public_struct.h>
#include <wlan_reg_services_api.h>
#include <wlan_reg_channel_api.h>
#include <ieee80211_regdmn.h>
#include <ieee80211_ucfg.h>
#include <ol_regdomain_common.h>
#include <wlan_reg_ucfg_api.h>
#if DBDC_REPEATER_SUPPORT
#include <qca_multi_link.h>
#endif
#if WLAN_SUPPORT_MSCS && QCA_NSS_PLATFORM
#include <qca_mscs.h>
#endif

#if UMAC_SUPPORT_CBS
#include "ieee80211_cbs.h"
#endif

#if CONFIG_LEDS_IPQ
#include <drivers/leds/leds-ipq.h>
#endif
#ifdef WLAN_SUPPORT_FILS
#include <target_if_fd.h>
#endif

#include <target_if_dp.h>
#ifdef DIRECT_BUF_RX_ENABLE
#include <target_if_direct_buf_rx_main.h>
#endif
#include <cfg_ucfg_api.h>

#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#if WLAN_CFR_ENABLE
#include <wlan_cfr_utils_api.h>
#include <wlan_cfr_ucfg_api.h>
#endif
#include <dp_rate_stats.h>

#include <wlan_vdev_mgr_ucfg_api.h>
#include <wlan_cfg80211_scan.h>

#if QLD
#include "qld_api.h"
#endif

#ifdef CONFIG_CNSS2_SUPPORT
#include <net/cnss2.h>
#endif
#include <target_if_vdev_mgr_rx_ops.h>
#include <ol_if_twt.h>
#include <ol_if_led.h>
#include <wlan_gpio_tgt_api.h>
#include <dp_txrx.h>

#include <target_if_direct_buf_rx_api.h>

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
extern struct ieee80211vap *wlan_get_vap(struct wlan_objmgr_vdev *vdev);
#endif
#endif

static int ath_device_event(struct notifier_block *unused, unsigned long event, void *ptr);

struct notifier_block ath_device_notifier = {
	        .notifier_call = ath_device_event
};

struct qca_notifier_block qca_device_notifier = {
                .notifier = &ath_device_notifier
};

#ifdef QCA_PARTNER_PLATFORM
extern struct ol_txrx_ast_entry_t *
ol_txrx_ast_find_hash_find(
        ol_txrx_pdev_handle pdev,
        u_int8_t *peer_mac_addr,
        int mac_addr_is_aligned);
extern struct ol_txrx_peer_t *
ol_txrx_peer_find_by_id(
    ol_txrx_pdev_handle pdev,
    u_int16_t peer_id);
#endif
extern void tpc_config_event_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen);
extern void ol_ath_ifce_setup(struct ol_ath_softc_net80211 *scn,
                              ifce_status ifce_up);
extern int wlan_vap_omn_update(struct ieee80211com *ic);


#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#include "ol_ath_ucfg.h"
#endif

#if QCA_SUPPORT_SON
#include <wlan_son_pub.h>
#endif

#include <wlan_vdev_mgr_utils_api.h>
#define    PDEV_STATS_DEFAULT_TIMER  1000
#if QCN_IE
#define    IEEE80211_MACHDR_OFFSET  4
#endif
/* Beeliner Family specific routines */
extern int ol_target_init(ol_ath_soc_softc_t *soc, bool first);
extern struct g_wifi_info g_winfo;
int osif_recover_profile_alloc(struct ieee80211com *ic);
void ath_vdev_dump(struct wlan_objmgr_psoc *psoc, void *obj, void *args);
void osif_recover_vap_create(struct ieee80211com *ic);
int ath_netdev_open(struct net_device *dev);
int ath_netdev_stop(struct net_device *dev);
void ic_reset_params(struct ieee80211com *ic);
static u_int8_t
ol_ath_get_emiwar_80p80_defval(ol_ath_soc_softc_t *soc);
void son_buffull_handler(struct wlan_objmgr_pdev *pdev);
void wmi_proc_create(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id);
void wmi_proc_remove(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id);
int osif_ol_ll_vap_hardstart(struct sk_buff *skb, struct net_device *dev);
int osif_ol_vap_hardstart_wifi3(struct sk_buff *skb, struct net_device *dev);
bool ol_ath_net80211_is_mode_offload(struct ieee80211com *ic);
QDF_STATUS ol_ath_get_ah_devid(struct wlan_objmgr_pdev *pdev, uint16_t *devid);
void *ol_hif_open(struct device *dev, void *bdev, void *bid,
        enum qdf_bus_type bus_type, bool reinit, qdf_device_t qdf_dev);
#ifdef QCA_SUPPORT_WDS_EXTENDED
int osif_wds_ext_peer_hardstart_wifi3(struct sk_buff *skb, struct net_device *dev);
void osif_deliver_wds_ext_data_ol(ol_osif_peer_handle osif, struct sk_buff *skb_list);
#endif
#if UMAC_SUPPORT_WEXT
void ol_ath_iw_detach(struct net_device *dev);
void ol_ath_iw_attach(struct net_device *dev);
#endif
#define DEFAULT_MGMT_RETRY_LIMIT (4)
#if QLD
void qld_print_table(struct qld_event *dump_table);
#endif
#if defined(EPPING_TEST) && !defined(HIF_USB)
unsigned int eppingtest = 1;
unsigned int bypasswmi = 1;
#else
unsigned int eppingtest = 0;
unsigned int bypasswmi = 0;
#endif

#define FILE_PATH_LEN 128

#define LOW_MEM_SYSTEM_RAM              (131072) /* 131072Kb */

#define DEBUG_SNIFFER_TEST_TX_METADATA "TXMETA"
#define DEBUG_SNIFFER_TEST_RX_METADATA "RXMETA"
#define DEBUG_SNIFFER_TEST_TX_DATA     "TXDATA"
#define DEBUG_SNIFFER_TEST_RX_DATA     "RXDATA"
#define DEBUG_SNIFFER_TEST_TX_MGMT     "TXMGMT"
#define DEBUG_SNIFFER_TEST_RX_MGMT     "RXMGMT"
#define DEBUG_SNIFFER_SIGNATURE_LEN 6

int ol_ath_get_dp_config_param(struct cdp_ctrl_objmgr_psoc *psoc, enum cdp_cfg_param_type param_num);
void ol_reset_params(struct ol_ath_softc_net80211 *scn);

int ol_ath_get_dp_config_param(struct cdp_ctrl_objmgr_psoc *psoc, enum cdp_cfg_param_type param_num);
uint8_t ol_ath_freq_to_channel(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id, uint16_t freq);
uint8_t ol_ath_freq_to_band(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id, uint16_t freq);
int ol_ath_send_delba(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t vdev_id, uint8_t *peer_macaddr,
                      uint8_t tid, uint8_t reason_code);
int ol_peer_ast_flowid_map(struct cdp_ctrl_objmgr_psoc *scn_handle, uint16_t peer_id,
                      uint8_t vdev_id, uint8_t *peer_mac_addr);
int ol_ath_get_soc_nss_cfg(struct cdp_ctrl_objmgr_psoc *scn_handle);
QDF_STATUS ol_ath_nss_stats_clr(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t vdev_id);

static struct ol_if_ops  dp_ol_if_ops = {
    .peer_set_default_routing = target_if_peer_set_default_routing,
    .peer_rx_reorder_queue_setup = target_if_peer_rx_reorder_queue_setup,
    .peer_rx_reorder_queue_remove = target_if_peer_rx_reorder_queue_remove,
    .peer_add_wds_entry = ol_ath_node_add_wds_entry,
    .peer_update_wds_entry = ol_ath_node_update_wds_entry,
    .peer_del_wds_entry = ol_ath_node_del_wds_entry,
    .peer_unref_delete = ol_ath_peer_unref_delete,
#ifdef FEATURE_NAC_RSSI
    .rx_invalid_peer = ol_ath_rx_invalid_peer,
#endif
    .peer_map_event = ol_peer_map_event,
    .peer_unmap_event= ol_peer_unmap_event,
    .get_dp_cfg_param = ol_ath_get_dp_config_param,
    .lro_hash_config = target_if_lro_hash_config,
    .rx_mic_error= ol_ath_rx_mic_error,
    .freq_to_channel= ol_ath_freq_to_channel,
    .freq_to_band = ol_ath_freq_to_band,
#if ATH_SUPPORT_NAC_RSSI
    .config_fw_for_nac_rssi = ol_ath_config_fw_for_nac_rssi,
    .config_bssid_in_fw_for_nac_rssi = ol_ath_config_bssid_in_fw_for_nac_rssi,
#endif
    .peer_sta_kickout = ol_ath_peer_sta_kickout,
    .send_delba = ol_ath_send_delba,
    .peer_delete_multiple_wds_entries = ol_ath_node_delete_multiple_wds_entries,
    .pdev_update_lmac_n_target_pdev_id = ol_ath_pdev_update_lmac_n_target_pdev_id,
    .peer_ast_flowid_map = ol_peer_ast_flowid_map,
    /* TODO: Add any other control path calls required to OL_IF/WMA layer */
    .get_soc_nss_cfg = ol_ath_get_soc_nss_cfg,
    .get_device_name = ol_ath_get_pdev_dev_name,
    .nss_stats_clr = ol_ath_nss_stats_clr,
#ifdef QCA_SUPPORT_WDS_EXTENDED
    .rx_wds_ext_peer_learn = ol_ath_wds_ext_peer_learn,
#endif
    .peer_update_mesh_latency_params = ol_ath_peer_update_mesh_latency_params,
};

int ol_ath_pdev_tpc_config_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_gpio_input_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_nf_dbr_dbm_info_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_packet_power_info_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_generic_buffer_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_peer_mumimo_tx_count_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_peer_gid_userpos_list_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_pdev_caldata_version_check_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_pdev_ctl_failsafe_check_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_soc_hw_mode_change_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_cp_fwstats_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
int ol_ath_vdev_tsf_report_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
#ifdef CONFIG_DP_TRACE
static int ol_ath_dptrace_setparam(int cmd, int val1, int val2);
#endif

#if  QCN_ESP_IE
int ol_ath_esp_estimate_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen);
#endif

extern int whal_mcs_to_kbps(int, int, int, int);
#if ALL_POSSIBLE_RATES_SUPPORTED
    extern int whal_kbps_to_mcs(int, int, int);
    extern int whal_get_supported_rates(int, int, int **);
#else
    extern int whal_kbps_to_mcs(int, int, int, int, int);
    extern int whal_get_supported_rates(int, int, int, int, int **);
#endif
extern int whal_ratecode_to_kbps(uint8_t, uint8_t, uint8_t);
extern void ol_if_mgmt_drain(struct ieee80211_node *ni, int force,
                             enum ieee80211_mgmt_drain_mode drain_mode);
extern int32_t ol_ath_thermal_mitigation_detach(struct ol_ath_softc_net80211 *scn,
                                              struct net_device *dev);
extern int32_t ol_ath_thermal_mitigation_attach(struct ol_ath_softc_net80211 *scn,
                                              struct net_device *dev);

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
extern int ath_net80211_add_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
extern int ath_net80211_del_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
extern void ath_net80211_buffull_handler(struct ieee80211com *ic);
#endif

extern struct global_ic_list ic_list;

extern unsigned int testmode;

int ol_ath_target_stop(struct ieee80211com *ic, bool flush_wq);
extern int ath_get_radio_index(struct net_device *netdev);
extern int asf_adf_attach(void);

static QDF_STATUS ol_ath_register_crypto_ops_handler(
                        struct wlan_lmac_if_crypto_tx_ops *crypto_tx_ops);

/*
 * ol_ath_pri20_cfg_blockchanlist_parse:
 * Block channels listed in CFG from auto channel selection (ACS, ICM, ...)
 */
static void ol_ath_pri20_cfg_blockchanlist_parse(struct ieee80211com *ic,
                                                 const char *cfg_str);

/*
 * ol_ath_parse_wideband_support:
 * Set the support for wideband (5GHz-7GHz) along with CSA-specific flags.
 */
static void ol_ath_parse_wideband_support(struct ieee80211com *ic,
                                          const uint32_t cfg_wideband_csa_val);

static
int diag_fw_event_handler(ol_soc_t sc, uint8_t *data, uint32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wlan_objmgr_psoc *psoc;
    void *dbglog_handle;
    int ret;
    struct target_psoc_info *tgt_psoc_info;

    psoc = soc->psoc_obj;
    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return -EINVAL;
    }

    if (!(dbglog_handle = target_psoc_get_dbglog_hdl(tgt_psoc_info))) {
        qdf_err("dbglog_handle is null");
        return -EINVAL;
    }

    ret = fwdbg_fw_handler(dbglog_handle, soc, data, datalen);

    return ret;
}

static inline void ol_ath_dbglog_detach(ol_ath_soc_softc_t *soc)
{
        struct target_psoc_info *tgt_psoc_info;
        void *dbglog_handle = NULL;
        struct wmi_unified *wmi_handle = NULL;

        tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
        dbglog_handle = target_psoc_get_dbglog_hdl(tgt_psoc_info);

        wmi_handle = (struct wmi_unified *)target_psoc_get_wmi_hdl(tgt_psoc_info);
        if (!wmi_handle) {
            qdf_err("null wmi_handle");
            return;
        }
        wmi_unified_unregister_event_handler(wmi_handle, wmi_diag_event_id);
        target_psoc_set_dbglog_hdl(tgt_psoc_info, NULL);

        if (dbglog_handle) {
#ifdef OL_ATH_SMART_LOGGING
                fwdbg_smartlog_deinit(dbglog_handle, soc);
#endif /* OL_ATH_SMART_LOGGING */
                fwdbg_free(dbglog_handle, soc);
                if (soc->ol_if_ops->dbglog_detach)
                        soc->ol_if_ops->dbglog_detach(dbglog_handle);
        } else {
               qdf_err("dbglog_handle is null ");
        }
}

int
ol_ath_get_dp_config_param(struct cdp_ctrl_objmgr_psoc *psoc,
		enum cdp_cfg_param_type param_num)
{
	switch(param_num)
	{
		case  CDP_CFG_MAX_PEER_ID:
			return ol_cfg_max_peer_id((ol_soc_handle)psoc);
		case CDP_CFG_CCE_DISABLE:
			return ol_cfg_is_cce_disable((ol_soc_handle)psoc);
		default:
			return -EINVAL;
	}
}

int
ol_ath_get_soc_nss_cfg(struct cdp_ctrl_objmgr_psoc *psoc)
{
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    ol_ath_soc_softc_t *soc;
    struct wlan_objmgr_psoc *psoc_obj = (struct wlan_objmgr_psoc *)psoc;
    soc = lmac_get_psoc_feature_ptr(psoc_obj);

    if (!soc)
        return 0;

    return soc->nss_soc.nss_scfg;
#else
    return 0;
#endif
}

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
QDF_STATUS
ol_ath_nss_stats_clr(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t vdev_id)
{
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211vap *vap;
    QDF_STATUS ret = QDF_STATUS_E_INVAL;

    vdev = wlan_objmgr_get_vdev_by_id_from_psoc((struct wlan_objmgr_psoc *)psoc,
                                               vdev_id, WLAN_VDEV_TARGET_IF_ID);
    if (!vdev) {
        qdf_err("vdev is null");
        return ret;
    }

    vap = wlan_vdev_get_vap(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_VDEV_TARGET_IF_ID);
        return ret;
    }

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    ret = scn->sc_ic.nss_radio_ops->ic_nss_ol_nss_stats_clr(scn, vdev_id);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_VDEV_TARGET_IF_ID);
    return ret;
}
#else
QDF_STATUS
ol_ath_nss_stats_clr(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t vdev_id)
{
    return QDF_STATUS_SUCCESS;
}
#endif

void ol_ath_get_pdev_stats(void *arg)
{
#ifndef CONFIG_WIFI_EMULATION_WIFI_3_0
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)arg;
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    struct stats_request_params param;
    uint8_t addr[QDF_MAC_ADDR_SIZE];
    uint8_t *myaddr;
    wmi_unified_t pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(scn->sc_pdev);
    if (!pdev_wmi_handle) {
        qdf_err("WMI handle is NULL");
        return;
    }
    memset(&param, 0, sizeof(param));
    wlan_pdev_obj_lock(pdev);
    myaddr = wlan_pdev_get_hw_macaddr(pdev);
    IEEE80211_ADDR_COPY(addr, myaddr);
    wlan_pdev_obj_unlock(pdev);

    param.pdev_id = lmac_get_pdev_idx(pdev);
    param.stats_id = WMI_HOST_REQUEST_PDEV_STAT;
    wmi_unified_stats_request_send(pdev_wmi_handle, addr, &param);
    if (scn->is_scn_stats_timer_init) {
        qdf_timer_mod(&(scn->scn_stats_timer),scn->pdev_stats_timer);
    }
#else
    return;
#endif
}
qdf_export_symbol(ol_ath_get_pdev_stats);

void ol_tbtt_sync_timer_cb(void *arg)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)arg;
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    wlan_dev_t ic;
    wmi_unified_t pdev_wmi_handle;
    struct rnr_tbtt_multisoc_sync_param tbtt_multisoc_sync_param;


    if (!pdev) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "%s:%d: pdev is NULL!!", __func__, __LINE__);
        return;
    }
    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "%s:%d: ic is NULL!!", __func__, __LINE__);
        return;
    }
    if (ieee80211_get_num_ap_vaps_up(ic)) {
        pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(pdev);
        tbtt_multisoc_sync_param.cmd_type = WMI_HOST_PDEV_GET_TBTT_OFFSET;
        tbtt_multisoc_sync_param.pdev_id = WMI_HOST_PDEV_ID_SOC;
        tbtt_multisoc_sync_param.rnr_vap_count = 0;

        if (!pdev_wmi_handle) {
            QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "WMI handle is NULL");
            return;
        }
        wmi_unified_multisoc_tbtt_sync_cmd(pdev_wmi_handle, &tbtt_multisoc_sync_param);
    }
    qdf_timer_mod(&(scn->soc->tbtt_offset_sync_timer), DEFAULT_TBTT_SYNC_TIMER);

}

void ol_ath_clear_auth_cnt(void *arg)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)arg;
    qdf_atomic_init(&(scn->auth_cnt));
    qdf_timer_mod(&(scn->auth_timer), DEFAULT_AUTH_CLEAR_TIMER);
}

/*
 * ol_ath_pri20_cfg_blockchanlist_parse:
 * Parse the CFG string param containing channel numbers to block from
 * channel selection (ACS, ICM, ...)
 *
 * Arguments:
 * ic     : ic handle (containing channel lists)
 * cfg_str: CFG string parameter
 *
 * Return:
 * None
 */
static void ol_ath_pri20_cfg_blockchanlist_parse(struct ieee80211com *ic,
                                                 const char *cfg_str)
{
    uint8_t ix = 0;
    int offset = 0;
    const char *str_ptr = cfg_str;

    if (cfg_str == NULL || cfg_str[0] == '\0') {
        qdf_info("cfg block channel list is empty");
        return;
    }

    while (*str_ptr != '\0') {
        switch(*str_ptr) {
            case ',':
                if (ix == (ACS_MAX_CHANNEL_COUNT-1)) {
                    qdf_info("Max channel count reached, discarding cfg param");
                    qdf_mem_zero(&ic->ic_pri20_cfg_blockchanlist,
                                 sizeof(struct ieee80211_user_freq_list));
                    return;
                }
                ix++;
                str_ptr++;
                break;
            case ' ' :
            case '\"':
            case '\'':
                /* Skipping spaces, single and double-inverted commas */
                str_ptr++;
                continue;
            default :
                if (*str_ptr >= '0' && *str_ptr <= '9') {
                    if(!sscanf(str_ptr, "%hu %n",
                               &ic->ic_pri20_cfg_blockchanlist.freq[ix],
                               &offset)) {
                        qdf_info("Could not parse channel frequency from cfg param, discarding cfg param");
                        qdf_mem_zero(&ic->ic_pri20_cfg_blockchanlist,
                                     sizeof(struct ieee80211_user_freq_list));
                        return;
                    }
                    str_ptr += offset;
                    ic->ic_pri20_cfg_blockchanlist.n_freq++;
                    qdf_info("(%hu) channel frequency %hu blocked from cfg",
                             ic->ic_pri20_cfg_blockchanlist.n_freq,
                             ic->ic_pri20_cfg_blockchanlist.freq[ix]);
                    break;
                } else {
                    qdf_info("Invalid character in string, discarding cfg param");
                    qdf_mem_zero(&ic->ic_pri20_cfg_blockchanlist,
                                 sizeof(struct ieee80211_user_freq_list));
                    return;
                }
        }
    }

    return;
}

/*
 * ol_ath_parse_wideband_support:
 * Set the support for wideband (5GHz-7GHz) support and CSA-specific flags
 *
 * Arguments:
 * ic              : Pointer to the ic structure
 * cfg_wideband_val: CFG value
 */
static void ol_ath_parse_wideband_support(struct ieee80211com *ic,
                                          const uint32_t cfg_wideband_csa_val)
{
    bool is_5ghz_capable = false, is_6ghz_capable = false;

    if (!ic) {
        qdf_err("Invalid ic pointer");
        return;
    }

    is_5ghz_capable = wlan_reg_is_band_present(ic->ic_pdev_obj,
                                               REG_BAND_5G);
    is_6ghz_capable = wlan_reg_is_band_present(ic->ic_pdev_obj,
                                               REG_BAND_6G);

    ic->ic_wideband_capable = false;
    if (is_5ghz_capable && is_6ghz_capable) {
        ic->ic_wideband_capable = true;
    } else {
        qdf_debug("Radio does not support wideband. Disabling");
        ic->ic_wideband_csa_support = WIDEBAND_CSA_DISABLED;
        return;
    }

    /*
     * Support is defined as follows:
     * 0: Disable wideband CSA
     * 1: Enable  wideband CSA (compatibility mode)
     * 2: Enable  wideband CSA (forced mode)
     */

    switch(cfg_wideband_csa_val) {
        case WIDEBAND_CSA_DISABLED:
        case WIDEBAND_CSA_COMPATIBILITY:
        case WIDEBAND_CSA_FORCED:
            ic->ic_wideband_csa_support = cfg_wideband_csa_val;
        break;

        default:
            qdf_err("Invalid cfg_wideband_val. Keeping wideband CSA disabled");
            ic->ic_wideband_csa_support = WIDEBAND_CSA_DISABLED;
        break;
    }

    return;
}

bool
ol_ath_get_host_hybrid_mode(ol_ath_soc_softc_t *soc)
{
    return wlan_psoc_nif_fw_ext_cap_get(soc->psoc_obj,
                                   WLAN_SOC_CEXT_HYBRID_MODE);
}

/* host_interest_item_address required by only wifi2.0, but its been invoked
 * from shared code. Since this function using definitions from targaddr.h
 * firmware header which is same across 2.0 & 3.0 hence it is maintained here.
 */
__inline__
u_int32_t host_interest_item_address(u_int32_t target_type, u_int32_t item_offset)
{
    switch (target_type)
    {
        default:
            ASSERT(0);
        case TARGET_TYPE_AR6002:
            return (AR6002_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6003:
            return (AR6003_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6004:
            return (AR6004_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6006:
            return (AR6006_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR9888:
            return (AR9888_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6320:
            return (AR6320_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR900B:
            return (AR900B_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_QCA9984:
            return (QCA9984_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_QCA9888:
            return (QCA9888_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_IPQ4019:
            return (IPQ4019_HOST_INTEREST_ADDRESS + item_offset);
    }
}
qdf_export_symbol(host_interest_item_address);

#if UMAC_SUPPORT_ACFG
extern void acfg_offchan_cancel(struct ieee80211com *ic);
#endif

void wlan_pdev_operation(struct wlan_objmgr_psoc *psoc,
                              void *obj, void *args)
{
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_pdev *pdev;
    ol_txrx_soc_handle soc_txrx_handle;
    struct pdev_op_args *arg = (struct pdev_op_args *)args;
    struct wmi_unified *pdev_wmi_handle;
    struct ieee80211com *ic;
    ol_ath_soc_softc_t *soc;
    uint8_t i, pdev_id, sniffer_mode;
    int waitcnt;
    void *dp_pdev_ext_hdl;
    qdf_event_t wait_event;

    pdev = (struct wlan_objmgr_pdev *)obj;
    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

    scn = (struct ol_ath_softc_net80211*)lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
        qdf_err("scn is NULL");
        return;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL");
        return;
    }

    ic =  &scn->sc_ic;
    soc = scn->soc;

    switch (arg->type) {
       case PDEV_ITER_POWERUP:
       {
#if UMAC_SUPPORT_WEXT
           ol_ath_iw_attach(scn->netdev);
#endif
#if UMAC_SUPPORT_ACFG || UMAC_SUPPORT_ACFG_RECOVERY
           OSIF_RADIO_DELIVER_EVENT_WATCHDOG(ic, ACFG_WDT_REINIT_DONE);
#endif
           ic->recovery_in_progress = 0;
           break;
       }
       case PDEV_ITER_FATAL_SHUTDOWN:
       {
           ic->recovery_in_progress = 1;
           /* stop WMI so that no more WMI commands are sent
            * to target
            */
           if (pdev_wmi_handle)
               wmi_stop((wmi_unified_t)pdev_wmi_handle);
           break;
       }
       case PDEV_ITER_TARGET_ASSERT:
       {
           ic->recovery_in_progress = 1;
#if UMAC_SUPPORT_WEXT
           ol_ath_iw_detach(scn->netdev);
#endif
#if (UMAC_SUPPORT_ACFG && ACFG_NETLINK_TX)
           acfg_offchan_cancel(ic);
           OSIF_RADIO_DELIVER_EVENT_WATCHDOG(ic, ACFG_WDT_TARGET_ASSERT);
#endif
#ifdef QCA_SUPPORT_CP_STATS
           pdev_cp_stats_tgt_asserts_inc(ic->ic_pdev_obj, 1);
#endif
           break;
       }
       case PDEV_ITER_PCIE_ASSERT:
       {
#if UMAC_SUPPORT_ACFG
           OSIF_RADIO_DELIVER_EVENT_WATCHDOG(ic, ACFG_WDT_PCIE_ASSERT);
#endif
           break;
       }

       case PDEV_ITER_PDEV_ENTRY_ADD:
       {
           /* Max radios reached with earlier pdev attach */
           if (arg->ret_val == PDEV_ITER_STATUS_FAIL)
               break;

           i = g_winfo.num_radios;
           if (g_winfo.wifi_radios[i].sc == NULL) {
               g_winfo.wifi_radios[i].sc = (void *)scn;
               g_winfo.wifi_radios[i].wifi_radio_type = OFFLOAD;
               scn->wifi_num = i;
               arg->ret_val = PDEV_ITER_STATUS_OK;
               g_winfo.num_radios++;
               qdf_info("num_radios=%d, wifi_radios[%d].sc = %pK"
                       "wifi_radio_type = %d", g_winfo.num_radios,
                       i, g_winfo.wifi_radios[i].sc,
                       g_winfo.wifi_radios[i].wifi_radio_type);
               if (g_winfo.num_radios > NUM_MAX_RADIOS) {
                  qdf_info("Need to increase the NUM_MAX_RADIOS");
                  arg->ret_val = PDEV_ITER_STATUS_FAIL;
               }

           }
           break;
       }
       case PDEV_ITER_PDEV_ENTRY_DEL:
       {
           for(i=0;i < NUM_MAX_RADIOS;i++) {
                if (g_winfo.wifi_radios[i].sc == scn) {
                    g_winfo.wifi_radios[i].sc = NULL;
                    g_winfo.num_radios--;
                }
           }
           break;
       }
       case PDEV_ITER_RECOVERY_AHB_REMOVE:
       {
           /* stop WMI so that no more WMI commands are sent
            * to target
            */
           wmi_stop((wmi_unified_t)pdev_wmi_handle);
           /* Please do not add break, both cases should be executed */
       }
       case PDEV_ITER_RECOVERY_REMOVE:
       {
           if (osif_recover_profile_alloc(ic) != 0) {
               QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
                       QDF_TRACE_LEVEL_INFO, "[pdev id %d]ERROR: FW Recovery"
                       "profile alloc failed\n",
                       pdev_id);
               return;
           }
           break;
       }
       case PDEV_ITER_RECOVERY_WAIT:
       {
            waitcnt = 0;
            qdf_mem_zero(&wait_event, sizeof(wait_event));

            qdf_event_create(&wait_event);
            qdf_event_reset(&wait_event);

            while(wlan_pdev_get_vdev_count(pdev) &&
                          waitcnt <= OSIF_MAX_DELETE_VAP_TIMEOUT) {
               qdf_wait_single_event(&wait_event, 1000);
               waitcnt++;
            }
            qdf_event_destroy(&wait_event);

            if(waitcnt > OSIF_MAX_DELETE_VAP_TIMEOUT) {
                wlan_objmgr_iterate_obj_list_all(psoc, WLAN_VDEV_OP,
                         ath_vdev_dump, NULL, 1,
                         WLAN_MLME_NB_ID);
                if(ol_target_lithium(soc->psoc_obj)) {
                    /* Signal delayed BUG_ON to get q6 dump before it */
                    soc->delay_bug_on = true;
                }
            }
            break;
       }
       case PDEV_ITER_RECOVERY_STOP:
       {
           dev_close(scn->netdev);
           ic_reset_params(ic);
           break;
       }
       case PDEV_ITER_RECOVERY_PROBE:
       {
           osif_recover_vap_create(ic);
           break;
       }
#if OL_ATH_SUPPORT_LED
       case PDEV_ITER_LED_GPIO_STATUS:
       {
           struct ol_ath_softc_net80211 *scn_temp;

           scn_temp = (struct ol_ath_softc_net80211 *)arg->pointer;
           if ((scn != scn_temp) && (scn->scn_led_gpio == scn_temp->scn_led_gpio))
                arg->ret_val = PDEV_ITER_STATUS_OK;
           break;
       }
#endif
       case PDEV_ITER_PDEV_NETDEV_STOP:
       {
          ath_netdev_stop(scn->netdev);
          break;
       }
       case PDEV_ITER_PDEV_NETDEV_OPEN:
       {
          ath_netdev_open(scn->netdev);
          break;
       }
#if UMAC_SUPPORT_ACFG
       case PDEV_ITER_TARGET_FWDUMP:
       {
           OSIF_RADIO_DELIVER_EVENT_WATCHDOG(ic, ACFG_WDT_FWDUMP_READY);
           break;
       }
#endif
       case PDEV_ITER_SEND_SUSPEND:
       {
           struct suspend_params param;

           qdf_mem_set(&param, sizeof(param), 0);
           param.disable_target_intr = *((int *)arg->pointer);
           qdf_info("disable_target_intr val is %d",
                    param.disable_target_intr);

           wmi_unified_suspend_send(pdev_wmi_handle, &param,
                                    lmac_get_pdev_idx(pdev));
           break;
       }
       case PDEV_ITER_SEND_RESUME:
       {
           arg->ret_val = wmi_unified_resume_send(pdev_wmi_handle,
                                         lmac_get_pdev_idx(pdev));
           break;
       }
       case PDEV_ITER_PDEV_DEINIT_BEFORE_SUSPEND:
       {
           bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(pdev,
                                        WLAN_PDEV_FEXT_EMA_AP_ENABLE);
#if OL_ATH_SUPPORT_LED
           qdf_timer_sync_cancel(&scn->scn_led_blink_timer);
           qdf_timer_sync_cancel(&scn->scn_led_poll_timer);
           if(lmac_get_tgt_type(psoc) == TARGET_TYPE_IPQ4019) {
               ipq4019_wifi_led(scn, OL_LED_OFF);
           }
           if(scn->scn_led_gpio && lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA8074V2) {
               gpio_set_value_cansleep(scn->scn_led_gpio, OL_LED_OFF);
           }

#endif
           if (ol_target_lithium(psoc)) {
               qdf_timer_sync_cancel(&scn->scn_stats_timer);
           }
           qdf_timer_sync_cancel(&scn->auth_timer);
#ifdef QCA_SUPPORT_CP_STATS
           if (pdev_cp_stats_ap_stats_tx_cal_enable_get(pdev)) {
               scn->sc_ic.ic_ath_enable_ap_stats(ic, 0);
               pdev_cp_stats_ap_stats_tx_cal_enable_update(pdev, 1);
           }
#endif
           if (ol_ath_is_mcopy_enabled(ic)) {
               sniffer_mode = ic->ic_debug_sniffer;
               ol_ath_set_debug_sniffer(scn, SNIFFER_DISABLE);
               ol_ath_pdev_set_param(scn->sc_pdev,
                                     wmi_pdev_param_set_promisc_mode_cmdid, 0);
               /*To enable M_COPY after recovery if it was enabled before recovery*/
               if (scn->soc->recovery_in_progress)
                   ic->ic_debug_sniffer = sniffer_mode;
           }
#if ATH_DATA_TX_INFO_EN
           ol_ath_stats_detach(ic);
#endif
           ol_ath_thermal_mitigation_detach(scn, scn->netdev);

           /* reset current PP in case of ema ap mode */
           if (is_ema_ap_enabled)
               ic->ic_mbss.current_pp = 1;

           /* Stop wmi sequence check */
           wmi_interface_sequence_stop(pdev_wmi_handle);

           break;
       }
       case PDEV_ITER_PDEV_DETACH_OP:
       {
           soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

           qdf_info("soc_txrx_handle %pK dp_pdev id %d", soc_txrx_handle, pdev_id);
           cdp_pdev_detach(soc_txrx_handle, pdev_id, 0);

           break;
       }
       case PDEV_ITER_PDEV_DEINIT_OP:
       {
           soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
           dp_pdev_ext_hdl = cdp_pdev_get_dp_txrx_handle(soc_txrx_handle,
                                                         pdev_id);
#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
           if (dp_pdev_ext_hdl) {
               dp_wrap_detach(pdev);
           }
#endif
#endif
           if (dp_pdev_ext_hdl) {
               dp_extap_detach(pdev);
           }
           cdp_pdev_set_dp_txrx_handle(soc_txrx_handle, pdev_id, NULL);

           if (dp_pdev_ext_hdl)
               qdf_mem_free(dp_pdev_ext_hdl);

           cdp_pdev_deinit(soc_txrx_handle, pdev_id, 0);

           wmi_unified_remove_work((wmi_unified_t)pdev_wmi_handle);

           qdf_flush_work(&scn->sc_ic.dfs_cac_timer_start_work);

           qdf_flush_work(&scn->sc_ic.assoc_sm_set_country_code);

           if (ol_target_lithium(scn->soc->psoc_obj)) {
               if (scn->is_scn_stats_timer_init)
                   qdf_timer_sync_cancel(&scn->scn_stats_timer);
           }


#if WLAN_SPECTRAL_ENABLE
           spectral_unregister_dbr(scn->sc_pdev);
#endif /* WLAN_SPECTRAL_ENABLE */

#if WLAN_CFR_ENABLE
    /* pdev deinit to be done on Target Stop */
           cfr_deinitialize_pdev(scn->sc_pdev);
#endif

           ol_ath_mgmt_detach(ic);

           if (ic->recovery_in_progress)
                   ic->recovery_dfschan = ic->ic_curchan;
           else
                   ic->recovery_dfschan = NULL;

           break;
       }
       case PDEV_ITER_PDEV_RESET_PARAMS:
       {
           ol_reset_params(scn);
           break;
       }
       default:
       break;
     }
}
qdf_export_symbol(wlan_pdev_operation);

/* wow_nack is a param used by MCL's callback */
void
ol_target_send_suspend_complete(void *ctx, bool wow_nack)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *)ctx;

    soc->is_target_paused = TRUE;
    __ol_target_paused_event(soc);
}

#if QCA_SUPPORT_SON
void ol_notify_if_low_on_buffers(struct ol_ath_softc_net80211 *scn, uint32_t free_buff)
{
    struct ieee80211com *ic = &scn->sc_ic;
    if (!scn) {
        qdf_err("scn is NULL");
        return;
    }
    son_ald_record_set_free_descs(scn->soc->psoc_obj, free_buff);
    if (son_ald_record_get_buff_full_warn(scn->soc->psoc_obj) &&
        (son_ald_record_get_free_descs(scn->soc->psoc_obj) <= son_ald_record_get_buff_lvl(scn->soc->psoc_obj))) {
        son_buffull_handler(ic->ic_pdev_obj);
        son_ald_record_set_buff_full_warn(scn->soc->psoc_obj, 0);
    }
}
qdf_export_symbol(ol_notify_if_low_on_buffers);
#endif
/*
 * Routin to lock vap transmit
 *
 */
void ol_vap_tx_lock( void *vosdev)
{
#if !QCA_OL_TX_PDEV_LOCK && QCA_NSS_PLATFORM || (defined QCA_PARTNER_PLATFORM && QCA_PARTNER_SUPPORT_FAST_TX)
    osif_dev  *osdev = (osif_dev  *)vosdev;
    VAP_TX_SPIN_LOCK(&osdev->tx_lock);
#endif
    return;
}

/*
 * Routin to unlock vap transmit
 *
 */
void ol_vap_tx_unlock( void *vosdev)
{
#if !QCA_OL_TX_PDEV_LOCK && QCA_NSS_PLATFORM || (defined QCA_PARTNER_PLATFORM && QCA_PARTNER_SUPPORT_FAST_TX)
    osif_dev  *osdev = (osif_dev  *)vosdev;
    VAP_TX_SPIN_UNLOCK(&osdev->tx_lock);
#endif
    return;
}

A_STATUS HIF_USB_connect_service(ol_ath_soc_softc_t *soc)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct htc_service_connect_req connect;
    struct htc_service_connect_resp response;
    HTC_HANDLE htc_handle;

    htc_handle = lmac_get_htc_hdl(soc->psoc_obj);
    if (!htc_handle)
        return -1;

    A_MEMZERO(&connect,sizeof(connect));

    connect.EpCallbacks.EpSendFull        = NULL;
    connect.EpCallbacks.EpRecv            = NULL;
    connect.LocalConnectionFlags |= HTC_LOCAL_CONN_FLAGS_ENABLE_SEND_BUNDLE_PADDING;
    connect.MaxSendMsgSize = 1664;
    connect.service_id = WMI_DATA_BE_SVC;
    if ((status = htc_connect_service(htc_handle, &connect, &response)) !=
        QDF_STATUS_SUCCESS) {
        qdf_err("Failed to connect to Endpoint Ping BE svc, status:%d", status);
        return -1;
    } else {
        qdf_info("eppingtest BE endpoint:%d", response.Endpoint);
    }
    connect.service_id= WMI_DATA_BK_SVC;
    if ((status = htc_connect_service(htc_handle, &connect, &response)) !=
        EOK) {
        qdf_err("Failed to connect to Endpoint Ping BK svc, status:%d", status);
        return -1;
    } else {
        qdf_info("eppingtest BK endpoint:%d", response.Endpoint);
    }
    connect.service_id = WMI_DATA_VI_SVC;
    if ((status = htc_connect_service(htc_handle, &connect, &response))
            != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to connect to Endpoint Ping VI svc, status:%d", status);
        return -1;
    } else {
        qdf_info("eppingtest VI endpoint:%d", response.Endpoint);
    }
    connect.service_id = WMI_DATA_VO_SVC;
    if ((status = htc_connect_service(htc_handle, &connect, &response))
            != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to connect to Endpoint Ping VO svc, status:%d", status);
        return -1;
    } else {
        qdf_info("eppingtest VO endpoint:%d", response.Endpoint);
    }
    return EOK;
}

static void ol_ath_enable_pdev_map(ol_ath_soc_softc_t *soc)
{
    /* cmd_map is used to translate pdev id from host pdev id
     * to target pdev id.
     */
    uint32_t phyb_2g_pdev_cmd_map[WMI_HOST_MAX_PDEV] = {WMI_HOST_PDEV_ID_2,
                                       WMI_HOST_PDEV_ID_1, WMI_HOST_PDEV_ID_1};
    /* evt_map is used to translate pdev id from target pdev id
     * to host pdev id. Keep both 0th and 1st index as 0 since phyb mode only
     * has one pdev. So even if target sends 1 or 2 as tgt_pdev_id, it will
     * get translated to 0 host pdev id.
     */
    uint32_t phyb_2g_pdev_evt_map[WMI_HOST_MAX_PDEV] = {WMI_HOST_PDEV_ID_0,
                                       WMI_HOST_PDEV_ID_0, WMI_HOST_PDEV_ID_2};

    struct target_psoc_info *tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    uint32_t target_type = target_psoc_get_target_type(tgt_psoc_info);
    struct wmi_unified *wmi_handle = target_psoc_get_wmi_hdl(tgt_psoc_info);
    bool is_2g_phyb_enabled = cfg_get(soc->psoc_obj, CFG_OL_MODE_2G_PHYB);


    if (is_2g_phyb_enabled && target_type == TARGET_TYPE_QCA8074V2) {
        qdf_mem_copy(wmi_handle->cmd_pdev_id_map, phyb_2g_pdev_cmd_map,
            WMI_HOST_MAX_PDEV * sizeof(uint32_t));
        qdf_mem_copy(wmi_handle->evt_pdev_id_map, phyb_2g_pdev_evt_map,
            WMI_HOST_MAX_PDEV * sizeof(uint32_t));
        wmi_handle->soc->is_pdev_is_map_enable = true;
    }
}

static void wmi_change_htc_endpoint(ol_ath_soc_softc_t *soc)
{
    uint32_t target_type;
    struct wmi_unified *wmi_handle;
    struct target_psoc_info *tgt_psoc_info;
    uint32_t phyb_2g_svc_id_mapping[] = {WMI_CONTROL_SVC_WMAC1,
                                         WMI_CONTROL_SVC,
                                         WMI_CONTROL_SVC_WMAC2};
    bool is_2g_phyb_enabled;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    target_type = target_psoc_get_target_type(tgt_psoc_info);
    wmi_handle = target_psoc_get_wmi_hdl(tgt_psoc_info);

    is_2g_phyb_enabled = cfg_get(soc->psoc_obj, CFG_OL_MODE_2G_PHYB);

    if (is_2g_phyb_enabled && target_type == TARGET_TYPE_QCA8074V2)
            wmi_handle->soc->svc_ids = &phyb_2g_svc_id_mapping[0];
}

int ol_ath_connect_htc(ol_ath_soc_softc_t *soc)
{
    int status = QDF_STATUS_E_INVAL;
    struct htc_service_connect_req connect;
    struct target_psoc_info *tgt_psoc_info;
    struct wmi_unified *wmi_handle;
    HTC_HANDLE htc_handle;
    struct hif_opaque_softc *hif_handle;
    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        goto conn_fail;
    }

    wmi_handle = target_psoc_get_wmi_hdl(tgt_psoc_info);
    htc_handle = target_psoc_get_htc_hdl(tgt_psoc_info);
    hif_handle = target_psoc_get_hif_hdl(tgt_psoc_info);

    OS_MEMZERO(&connect,sizeof(connect));

    /* meta data is unused for now */
    connect.pMetaData = NULL;
    connect.MetaDataLength = 0;
    /* these fields are the same for all service endpoints */
    connect.EpCallbacks.pContext = soc;
    connect.EpCallbacks.EpTxCompleteMultiple = NULL /* Control path completion ar6000_tx_complete */;
    connect.EpCallbacks.EpRecv = NULL /* Control path rx */;
    connect.EpCallbacks.EpRecvRefill = NULL /* ar6000_rx_refill */;
    connect.EpCallbacks.EpSendFull = NULL /* ar6000_tx_queue_full */;

    wmi_change_htc_endpoint(soc);
    if (!bypasswmi) {
        if ((status = wmi_unified_connect_htc_service((wmi_unified_t)wmi_handle,
                            htc_handle)) != QDF_STATUS_SUCCESS)
             goto conn_fail;
    }
#if defined(EPPING_TEST) && !defined(HIF_USB)
    if (eppingtest){
        extern A_STATUS epping_connect_service(ol_ath_soc_softc_t *soc);
        if ((status = epping_connect_service(soc)) != EOK)
             goto conn_fail;
    }
#endif
    if (target_psoc_get_target_ver(tgt_psoc_info) == AR6004_VERSION_REV1_3) {
      if ((status = HIF_USB_connect_service(soc)) != EOK)
               goto conn_fail;
    }

    /*
     * Since cookies are used for HTC transports, they should be
     * initialized prior to enabling HTC.
     */
    ol_cookie_init((void *)soc);

    /*
     * Start HTC
     */
    if ((status = htc_start(htc_handle)) != QDF_STATUS_SUCCESS) {
        goto conn_fail;
    }

    if (!bypasswmi) {
        /*
         * Wait for WMI event to be ready
         */
        if (target_psoc_get_target_ver(tgt_psoc_info) == AR6004_VERSION_REV1_3) {
            target_psoc_set_wmi_ready(tgt_psoc_info, TRUE);
            target_psoc_set_wlan_init_status(tgt_psoc_info,
                             TARGET_INIT_STATUS_SUCCESS);
        } else {
            if ((status = __ol_ath_check_wmi_ready(soc)) != EOK) {
                goto conn_fail1;
            }
            qdf_info("WMI is ready");

            if (target_psoc_get_wlan_init_status(tgt_psoc_info) !=
                                        TARGET_INIT_STATUS_SUCCESS)
            {
              qdf_err("Target wmi init failed with status %d",
                      target_psoc_get_wlan_init_status(tgt_psoc_info));
              status = ENODEV;
              goto conn_fail1;
            }
        }
    }
    return EOK;

conn_fail1:
    hif_disable_isr((struct hif_opaque_softc *)hif_handle);
    htc_stop(htc_handle);
conn_fail:
    return status;
}

int
ol_ath_disconnect_htc(ol_ath_soc_softc_t *soc)
{
    HTC_HANDLE htc_handle;

    htc_handle = lmac_get_htc_hdl(soc->psoc_obj);
    if (htc_handle)
        htc_stop(htc_handle);
    return 0;
}

#ifdef CE_TASKLET_DEBUG_ENABLE
void ol_ath_enable_ce_latency_stats(struct ol_ath_soc_softc *soc, uint8_t val)
{
    struct target_psoc_info *tgt_psoc_info;
    struct hif_opaque_softc *hif_handle;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return;
    }

    hif_handle = target_psoc_get_hif_hdl(tgt_psoc_info);
    if (!hif_handle) {
        qdf_err("hif_handle is null");
        return;
    }

    hif_enable_ce_latency_stats(hif_handle, val);
}
#endif

static void
ol_ath_update_band_mapping(
                    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap,
                    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap)
{
    reg_cap->low_2ghz_chan  =  mac_phy_cap->reg_cap_ext.low_2ghz_chan;
    reg_cap->high_2ghz_chan =  mac_phy_cap->reg_cap_ext.high_2ghz_chan;
    reg_cap->low_5ghz_chan  =  mac_phy_cap->reg_cap_ext.low_5ghz_chan;
    reg_cap->high_5ghz_chan =  mac_phy_cap->reg_cap_ext.high_5ghz_chan;
}

static void
ol_ath_update_wireless_modes(struct ieee80211com *ic,
                             struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap,
                             struct wlan_psoc_host_mac_phy_caps *mac_phy_cap)
{
    uint32_t wireless_2G_modes = WIRELESS_MODES_2G;
    uint32_t wireless_5G_modes = WIRELESS_MODES_5G;
    uint32_t wireless_modes_before_update;

    qdf_info("wireless_modes = %x before update",
                    reg_cap->wireless_modes);
    wireless_modes_before_update = reg_cap->wireless_modes;
    if (!(mac_phy_cap->supported_bands & WMI_HOST_WLAN_5G_CAPABILITY)) {
        /* mac_phy cap indicates no support for 5G. Make sure 5G specific
         * modes are not present in wireless mode
         */
        reg_cap->wireless_modes &= ~(wireless_5G_modes);
    }
    if (!(mac_phy_cap->supported_bands & WMI_HOST_WLAN_2G_CAPABILITY)) {
        /* mac_phy cap indicates no support for 2G. Make sure 2G specific
         * modes are not present in wireless mode
         */
        reg_cap->wireless_modes &= ~(wireless_2G_modes);
    }

    qdf_info("Wireless_modes = %x after update",
                    reg_cap->wireless_modes);
    if (wireless_modes_before_update != reg_cap->wireless_modes) {
        ol_regdmn_update_pdev_wireless_modes(ic, reg_cap->wireless_modes);
        qdf_info("Wireless modes are updated in the regulatory pdev priv object");
    }
}

/* called in case of dynamic mode switch */
static void
ol_ath_update_wireless_modes_ext(
                      struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap,
                      struct wlan_psoc_host_mac_phy_caps *mac_phy_cap)
{
    uint32_t wireless_2G_modes       = WIRELESS_MODES_2G;
    uint32_t wireless_5G_modes       = WIRELESS_MODES_5G;

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
              QDF_TRACE_LEVEL_DEBUG,
              "wireless_modes = %x before update",
              reg_cap->wireless_modes);

    reg_cap->wireless_modes = mac_phy_cap->reg_cap_ext.wireless_modes;

    if (!(mac_phy_cap->supported_bands & WMI_HOST_WLAN_5G_CAPABILITY)) {
        /* mac_phy cap indicates no support for 5G. Make sure 5G specific
         * modes are not present in wireless mode
         */
        reg_cap->wireless_modes &= ~(wireless_5G_modes);
    }
    if (!(mac_phy_cap->supported_bands & WMI_HOST_WLAN_2G_CAPABILITY)) {
        /* mac_phy cap indicates no support for 2G. Make sure 2G specific
         * modes are not present in wireless mode
         */
        reg_cap->wireless_modes &= ~(wireless_2G_modes);
    }

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
              QDF_TRACE_LEVEL_DEBUG,
              "Wireless_modes = %x after update", reg_cap->wireless_modes);
}

static void
ol_ath_update_target_cap_from_mac_phy_cap(struct wlan_psoc_target_capability_info *cap,
                                struct wlan_psoc_host_mac_phy_caps *mac_phy_cap)
{
    /* If Radio supports both 2G and 5G, By default it will be brought up in 5G.
     * Update to @2G caps during band switch.
     */
    if (mac_phy_cap->supported_bands & WMI_HOST_WLAN_5G_CAPABILITY) {
        cap->ht_cap_info = mac_phy_cap->ht_cap_info_5G;
        cap->vht_cap_info = mac_phy_cap->vht_cap_info_5G;
        cap->vht_supp_mcs = mac_phy_cap->vht_supp_mcs_5G;
    } else if (mac_phy_cap->supported_bands & WMI_HOST_WLAN_2G_CAPABILITY) {
        cap->ht_cap_info = mac_phy_cap->ht_cap_info_2G;
        cap->vht_cap_info = mac_phy_cap->vht_cap_info_2G;
        cap->vht_supp_mcs = mac_phy_cap->vht_supp_mcs_2G;
    } else {
        qdf_info("No 2G OR 5G support set in ext service config");
    }
}

static inline void ol_ath_populate_chainmask(struct ieee80211com *ic,
        uint32_t tx_chain_mask, uint32_t rx_chain_mask)
{
    ieee80211com_set_num_rx_chain(ic, num_chain_from_chain_mask(rx_chain_mask));
    ieee80211com_set_num_tx_chain(ic, num_chain_from_chain_mask(tx_chain_mask));
    ieee80211com_set_tx_chainmask(ic, tx_chain_mask);
    ieee80211com_set_rx_chainmask(ic, rx_chain_mask);
    /*
     * Note that in the offload architecture chain_masks
     * and spatial_streams are synonymous
     */
    ieee80211com_set_spatialstreams(ic,
                       num_chain_from_chain_mask(rx_chain_mask));
    /* Update FW aDFS support based on the current chainmask */
    ol_ath_update_fw_adfs_support(ic, rx_chain_mask);
}

/**
 * ol_ath_update_chainmask() - updates tx/rx chainmask values
 * @ic: ic pointer
 * @cap: target capabilities
 * @mac_phy_cap: targets mac phy capabilities
 *
 * Return: none
 */
static inline void ol_ath_update_chainmask(struct ieee80211com *ic,
        struct wlan_psoc_target_capability_info *cap,
        struct wlan_psoc_host_mac_phy_caps *mac_phy_cap)
{
    struct target_psoc_info *tgt_psoc_info;
    struct wlan_objmgr_psoc *psoc = NULL;
    uint32_t chain_mask;
    int mode;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return;
    }

    mode = target_psoc_get_preferred_hw_mode(tgt_psoc_info);

   if (target_psoc_get_num_radios(tgt_psoc_info) == 1 &&
       mode != WMI_HOST_HW_MODE_2G_PHYB) {

       chain_mask = ((1 << cap->num_rf_chains) - 1);
       ol_ath_populate_chainmask(ic, chain_mask, chain_mask);
   } else {
       /* 5G is used by default if support for both 5G and 2G is present */
       if ((mac_phy_cap) &&
               (mac_phy_cap->supported_bands &
                WMI_HOST_WLAN_5G_CAPABILITY)) {
           ol_ath_populate_chainmask(ic, mac_phy_cap->tx_chain_mask_5G,
                   mac_phy_cap->rx_chain_mask_5G);
           cap->num_rf_chains = ic->ic_num_rx_chain;
       } else if ((mac_phy_cap) &&
               (mac_phy_cap->supported_bands &
               WMI_HOST_WLAN_2G_CAPABILITY)) {
           ol_ath_populate_chainmask(ic, mac_phy_cap->tx_chain_mask_2G,
               mac_phy_cap->rx_chain_mask_2G);
           cap->num_rf_chains = ic->ic_num_rx_chain;
       } else {
           qdf_info("No 2G OR 5G support set in ext service config");
       }
   }

#ifdef ATH_SUPPORT_WAPI

    if (target_psoc_get_target_type(tgt_psoc_info) == TARGET_TYPE_AR9888) {
    /*WAPI HW engine support upto 300 Mbps (MCS15h),
      limiting the chains to 2*/
      ic->ic_num_wapi_rx_maxchains = 2;
      ic->ic_num_wapi_tx_maxchains = 2;
    } else {
      ic->ic_num_wapi_rx_maxchains = ic->ic_num_rx_chain;
      ic->ic_num_wapi_tx_maxchains = ic->ic_num_tx_chain;
    }
#endif

}

/**
 * ol_ath_update_ht_caps() - updates iee80211 ht capabilities info
 * @ic: ic pointer
 * @ht_cap_info: targets ht capabilities information
 *
 * Return: none
 */
static void ol_ath_update_ht_caps(struct ieee80211com *ic, uint32_t ht_cap_info)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    uint16_t caps  = 0;

    if (ht_cap_info & WMI_HOST_HT_CAP_ENABLED) {
        ieee80211com_set_cap(ic, IEEE80211_C_HT);
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI40
                        | IEEE80211_HTCAP_C_CHWIDTH40
                        | IEEE80211_HTCAP_C_DSSSCCK40);
        if (ht_cap_info & WMI_HOST_HT_CAP_HT20_SGI)  {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI20);
        }
        if (ht_cap_info & WMI_HOST_HT_CAP_DYNAMIC_SMPS) {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC);
        } else {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED);
        }

        if (ht_cap_info & WMI_HOST_HT_CAP_IBF_BFER) {
            ic->ic_implicitbf = 1 ;
        }

        ieee80211com_set_htextcap(ic, IEEE80211_HTCAP_EXTC_TRANS_TIME_5000
                        | IEEE80211_HTCAP_EXTC_MCS_FEEDBACK_NONE);
        ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);

        /* Force this to 8usec for now, instead of checking min_pkt_size_enable */
        ieee80211com_set_mpdudensity(ic, cfg_get(psoc, CFG_TGT_MPDU_DENSITY));
        ic->ic_mpdudensityoverride = 0;

        IEEE80211_ENABLE_AMPDU(ic);

    }

    /* Tx STBC is a 2-bit mask. Convert to ieee definition. */
    caps = (ht_cap_info & WMI_HOST_HT_CAP_TX_STBC) >> WMI_HOST_HT_CAP_TX_STBC_MASK_SHIFT;
    ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_TXSTBC & (caps << IEEE80211_HTCAP_C_TXSTBC_S));


    /* Rx STBC is a 2-bit mask. Convert to ieee definition. */
    caps = (ht_cap_info & WMI_HOST_HT_CAP_RX_STBC) >> WMI_HOST_HT_CAP_RX_STBC_MASK_SHIFT;
    ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_RXSTBC & (caps << IEEE80211_HTCAP_C_RXSTBC_S));

    if (ht_cap_info & WMI_HOST_HT_CAP_LDPC) {
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_ADVCODING);
        if ((lmac_get_tgt_type(psoc) == TARGET_TYPE_AR900B) &&
             (lmac_get_tgt_revision(psoc) == AR900B_REV_1)) {
            /* disable LDPC capability for Beeliner 1.0 */
            ieee80211com_set_ldpccap(ic,IEEE80211_HTCAP_C_LDPC_NONE);
        } else {
            /* enable LDPC capability */
            ieee80211com_set_ldpccap(ic, IEEE80211_HTCAP_C_LDPC_TXRX);
        }
    } else {
        /* check if new method of LDPC flags are provided
         * RX capability should be announced by AP or STA
         * TX capability is based on what peer can receive and
         * what AP can transmit
         */
        if (ht_cap_info & (WMI_HOST_HT_CAP_RX_LDPC | WMI_HOST_HT_CAP_TX_LDPC)) {
            if (ht_cap_info & WMI_HOST_HT_CAP_RX_LDPC) {
                ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_ADVCODING);
                ieee80211com_set_ldpccap(ic, IEEE80211_HTCAP_C_LDPC_RX);
            }
            if (ht_cap_info & WMI_HOST_HT_CAP_TX_LDPC)
                ieee80211com_set_ldpccap(ic, IEEE80211_HTCAP_C_LDPC_TX);
        } else {
            ieee80211com_set_ldpccap(ic,IEEE80211_HTCAP_C_LDPC_NONE);
        }
    }
}

/**
 * ol_ath_update_vht_caps() - updates iee80211 vht capabilities info
 * @ic: ic pointer
 * @vht_cap_info: targets vht capabilities information
 * @vht_supp_mcs: mcs map supported in vht
 *
 * Return: none
 */
static void ol_ath_update_vht_caps(struct ieee80211com *ic,
                                   uint32_t vht_cap_info, uint32_t vht_supp_mcs)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    uint32_t ampdu_exp = 0;
    struct wmi_unified *wmi_handle;
    struct wmi_unified *pdev_wmi_handle;
    uint16_t basic_mcs = 0xfffc;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_11ac)) {

        /* Copy the VHT capabilities information */
        ieee80211com_set_vhtcap(ic, vht_cap_info);

        /* Adjust HT AMSDU len based on VHT MPDU len */
        if ((vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_7935) ||
            (vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_11454)) {
            ieee80211com_set_htcap(ic,IEEE80211_HTCAP_C_MAXAMSDUSIZE);
        } else {
            ieee80211com_clear_htcap(ic,IEEE80211_HTCAP_C_MAXAMSDUSIZE);
        }

        /* Adjust HT AMPDU len Exp  based on VHT MPDU len */
        ampdu_exp = vht_cap_info >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;
        switch (ampdu_exp) {
            case 0:
            case 1:
            case 2:
            case 3:
                ieee80211com_set_maxampdu(ic, ampdu_exp);
            break;

            default:
                ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);
            break;
        }

        /* Set the VHT rate information */
        /* 11ac spec states it is mandatory to support MCS 0-7 and NSS=1 */
        ol_ath_vht_rate_setup(ic, vht_supp_mcs, 0, basic_mcs);

        ic->ic_vht_ampdu = 64;
        /* The default max amsdu value in FW for Beeliner family is 4
         * and for Peregrine is 3. So init the values accordingly.
         */
        ic->ic_vht_amsdu = cfg_get(psoc, CFG_TGT_VHT_AMSDU);
        if (wmi_service_enabled(pdev_wmi_handle,
                                wmi_service_extended_nss_support)) {
            ic->ic_fw_ext_nss_capable = 1;
            ic->ic_ext_nss_capable = 1;
        }
    }
}

static void ol_ath_update_6g_band_caps(struct ieee80211com *ic)
{
    uint16_t *he_6g_bandcap = (uint16_t *)ic->ic_he.he6g_bandcap;
    uint16_t htcap          = ic->ic_htcap;
    uint32_t vhtcap         = ic->ic_vhtcap;

    *he_6g_bandcap |= (((vhtcap & IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP) >>
                                IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S) <<
                                IEEE80211_6G_BANDCAP_MAX_AMPDU_LEN_EXP_S);
    *he_6g_bandcap |= ((vhtcap & IEEE80211_VHTCAP_MAX_MPDU_LEN_MASK) <<
                                IEEE80211_6G_BANDCAP_MAX_MPDU_LEN_S);
    *he_6g_bandcap |= (((htcap & IEEE80211_HTCAP_C_SMPOWERSAVE_MASK) >>
                                IEEE80211_HTCAP_C_SMPOWERSAVE_S) <<
                                IEEE80211_6G_BANDCAP_SMPOWERSAVE_S);
    *he_6g_bandcap |= (((vhtcap & IEEE80211_VHTCAP_RX_ANTENNA_PATTERN) >>
                                IEEE80211_VHTCAP_RX_ANTENNA_PATTERN_S) <<
                                IEEE80211_6G_BANDCAP_RX_ANTENNA_PATTERN_S);
    *he_6g_bandcap |= (((vhtcap & IEEE80211_VHTCAP_TX_ANTENNA_PATTERN) >>
                                IEEE80211_VHTCAP_TX_ANTENNA_PATTERN_S) <<
                                IEEE80211_6G_BANDCAP_TX_ANTENNA_PATTERN_S);

}

/*
 * Return true if target has HW capability support
 * for smart monitor else return false.
 */
bool ol_tgt_lithium_hw_nac_supp(struct wlan_objmgr_psoc *psoc)
{
    switch (lmac_get_tgt_type(psoc)) {
        case TARGET_TYPE_QCA8074V2:
        case TARGET_TYPE_QCA6018:
        case TARGET_TYPE_QCA5018:
        case TARGET_TYPE_QCN9000:
        case TARGET_TYPE_QCN6122:
            return true;
    }

    return false;
}

#define DEFAULT_BURST_DURATION 8160
int ol_ath_pdev_set_burst(struct ol_ath_softc_net80211 *scn, bool value)
{
    struct wmi_unified *wmi_handle;
    int retval = 0;

    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if(!wmi_handle) {
        qdf_err("null wmi_handle");
        return -EINVAL;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_burst)) {
        /* Target is capable of burst mode. Therefore, enable the burst mode
         * in host and send WMI_PDEV_PARAM_BURST_ENABLE command to target.
         */
        retval = ol_ath_pdev_set_param(scn->sc_pdev,
                wmi_pdev_param_burst_enable, value);
        if (retval == EOK)
            scn->burst_enable = value;

        if (!scn->burst_dur) {
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                    wmi_pdev_param_burst_dur, DEFAULT_BURST_DURATION);
            if (retval == EOK)
                scn->burst_dur = DEFAULT_BURST_DURATION;
        }
    } else {
        retval = -EINVAL;
    }

    return retval;
}

/**
 * ol_ath_update_caps() - updates iee80211 capabilities/flags
 * @ic: ic pointer
 * @ev: target capabilities
 *
 * Return: none
 */
static void ol_ath_update_caps(struct ieee80211com *ic,
                               struct wlan_psoc_target_capability_info *ev)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    uint16_t ciphercap = 0;
    uint32_t target_type;
    struct wmi_unified *pdev_wmi_handle;
    ol_txrx_soc_handle soc_txrx_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    target_type = lmac_get_tgt_type(psoc);

    /* setup ieee80211 flags */
    ieee80211com_clear_cap(ic, -1);
    ieee80211com_clear_athcap(ic, -1);
    ieee80211com_clear_athextcap(ic, -1);
    ieee80211com_clear_ciphercap(ic, -1);
    ieee80211com_set_phytype(ic, IEEE80211_T_OFDM);
    ieee80211com_set_cap(ic,IEEE80211_C_SHPREAMBLE);

    ieee80211com_set_cap(ic,
                     IEEE80211_C_IBSS           /* ibss, nee adhoc, mode */
                     | IEEE80211_C_HOSTAP       /* hostap mode */
                     | IEEE80211_C_MONITOR      /* monitor mode */
                     | IEEE80211_C_SHSLOT       /* short slot time supported */
                     | IEEE80211_C_PMGT         /* capable of power management*/
                     | IEEE80211_C_WPA          /* capable of WPA1+WPA2 */
                     | IEEE80211_C_BGSCAN       /* capable of bg scanning */
                  );

    /* Setting cipher cap */
    ciphercap = ( (1 << IEEE80211_CIPHER_WEP) |
               (1 << IEEE80211_CIPHER_TKIP) |
               (1 << IEEE80211_CIPHER_AES_OCB) |
               (1 << IEEE80211_CIPHER_AES_CCM) |
               (1 << IEEE80211_CIPHER_WAPI) |
               (1 << IEEE80211_CIPHER_CKIP) |
               (1 << IEEE80211_CIPHER_AES_CMAC) |
               (1 << IEEE80211_CIPHER_AES_CCM_256) |
               (1 << IEEE80211_CIPHER_AES_GCM) |
               (1 << IEEE80211_CIPHER_AES_GCM_256) |
               (1 << IEEE80211_CIPHER_AES_GMAC) |
               (1 << IEEE80211_CIPHER_AES_GMAC_256) |
               (1 << IEEE80211_CIPHER_NONE)
             );
    /*
     * AR9888 Family of Chips do not support GCMP and CCMP-256
     */
    if ( (target_type == TARGET_TYPE_AR9888) ||
         (target_type == TARGET_TYPE_AR9888V2) )
    {
        ciphercap &= (~((1 << IEEE80211_CIPHER_AES_CCM_256) |
                        (1 << IEEE80211_CIPHER_AES_GCM) |
                        (1 << IEEE80211_CIPHER_AES_GCM_256) |
                        (1 << IEEE80211_CIPHER_AES_GMAC) |
                        (1 << IEEE80211_CIPHER_AES_GMAC_256)) & 0xffff);
    }

    ieee80211com_set_ciphercap(ic, ciphercap);
    ieee80211com_set_cap(ic, ciphercap);
    /* WMM enable */
    ieee80211com_set_cap(ic, IEEE80211_C_WME);

    ol_ath_pdev_set_burst(scn, true);

    if (wmi_service_enabled(pdev_wmi_handle, wmi_service_ap_uapsd)) {
        ieee80211com_set_cap(ic, IEEE80211_C_UAPSD);
        IEEE80211_UAPSD_ENABLE(ic);
    }

    /* Default 11h to start enabled  */
    ieee80211_ic_doth_set(ic);
#if UMAC_SUPPORT_WNM
    /* Default WNM enabled   */
    ieee80211_ic_wnm_set(ic);
    /* WNM needs PS state of STA, so enable it in the FW */
    ol_ath_pdev_set_param(scn->sc_pdev,
                          wmi_pdev_peer_sta_ps_statechg_enable, 1);
    scn->ps_report = 1;
#endif

    /* 11n Capabilities */
    ieee80211com_set_num_tx_chain(ic,1);
    ieee80211com_set_num_rx_chain(ic,1);
    ieee80211com_clear_htcap(ic, -1);
    ieee80211com_clear_htextcap(ic, -1);
    ol_ath_update_ht_caps(ic, ev->ht_cap_info);

    /* 11n configuration */
    ieee80211com_clear_htflags(ic, -1);

    /*
     * Indicate we need the 802.11 header padded to a
     * 32-bit boundary for 4-address and QoS frames.
     */
    IEEE80211_ENABLE_DATAPAD(ic);

    /* Check whether the hardware is VHT capable */
    ieee80211com_clear_vhtcap(ic, -1);
    ol_ath_update_vht_caps(ic, ev->vht_cap_info, ev->vht_supp_mcs);

    if (cfg_get(psoc, CFG_OL_ENABLE_MESH_SUPPORT) &&
                wmi_service_enabled(pdev_wmi_handle, wmi_service_mesh)) {
        qdf_info("Mesh Supported");
        ic->ic_mesh_vap_support = 1;
    }

    /* this should be updated from service bit map.
     * This change is added temporarily untill firmware support is added*/
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    ic->ic_promisc_support = 1;
    ic->ic_tso_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_TSO);
    ic->ic_lro_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_LRO);
    ic->ic_sg_support  =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_SG);
    ic->ic_gro_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_GRO);
    ic->ic_offload_tx_csum_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_OL_TX_CSUM);
    ic->ic_offload_rx_csum_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_OL_RX_CSUM);
    ic->ic_rawmode_support =
                cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_RAWMODE);
    ic->ic_peer_flow_control_support =
            cdp_get_dp_capabilities(soc_txrx_handle, CDP_CFG_DP_PEER_FLOW_CTRL);
    ic->ic_dynamic_grouping_support =
                                    cfg_get(psoc, CFG_TGT_DYN_GROUPING_SUPPORT);
    ic->ic_dpd_support            = cfg_get(psoc, CFG_TGT_DPD_SUPPORT);
    ic->ic_aggr_burst_support     = cfg_get(psoc, CFG_TGT_AGGR_BURST_SUPPORT);
    ic->ic_qboost_support         = cfg_get(psoc, CFG_TGT_QBOOST_SUPPORT);
    ic->ic_sifs_frame_support     = cfg_get(psoc, CFG_TGT_SIFS_FRAME_SUPPORT);
    ic->ic_block_interbss_support = cfg_get(psoc, CFG_TGT_BLK_INTERBSS_SUPPORT);
    ic->ic_disable_reset_support  = cfg_get(psoc, CFG_TGT_DIS_RESET_SUPPORT);
    ic->ic_msdu_ttl_support       = cfg_get(psoc, CFG_TGT_MSDU_TTL_SUPPORT);
    ic->ic_ppdu_duration_support  = cfg_get(psoc, CFG_TGT_PPDU_DUR_SUPPORT);
    ic->ic_burst_mode_support     = cfg_get(psoc, CFG_TGT_BURST_MODE_SUPPORT);
    ic->ic_wds_support            = cfg_get(psoc, CFG_TGT_WDS_SUPPORT);
    ic->ic_def_num_clients        = cfg_get(psoc, CFG_TGT_NUM_CLIENT);
    ic->ic_nac_client             = cfg_get(psoc, CFG_TGT_NAC_MAX_CLIENT);
    ic->ic_nac_bssid              = cfg_get(psoc, CFG_TGT_NAC_MAX_BSSID);

    /* Set smart monitor HW capability */
    if (ol_tgt_lithium_hw_nac_supp(psoc))
            ic->ic_hw_nac_monitor_support = 1;
    else
        qdf_err("Hw capability for nac is not supported");

    /* Set no bfee limit for all lithium targets and above.
     * Legacy targets will enable bfee based on total rx
     * streams and will not enable bfee by default.
     */
    ic->ic_no_bfee_limit = cfg_get(psoc, CFG_TGT_NO_BFEE_LIMIT_SUPPORT);
    ic->ic_he_target     = cfg_get(psoc, CFG_TGT_HE_TGT_SUPPORT);

    if (target_type >= TARGET_TYPE_QCA8074) {
        /* Set flag for ppdu_duration and burst_dur
         * HW requirement for Lithium based targets to support ppdu_duration
         * and burst_dur values greater than or equal to zero.
         */
        ic->ic_ppdu_min = 0;
        ic->ic_burst_min = 0;
    } else {
        ic->ic_ppdu_min = 100;
        ic->ic_burst_min = 1;
    }

    /* BA Buf Size will be initialized to 256 for HKv1/2, qca6018
     * and initialized to 64 for all other targets.
     */
    if (ol_target_lithium(psoc)) {
        ic->ic_he_default_ba_buf_size = IEEE80211_MAX_BA_BUFFER_SIZE;
    } else {
        ic->ic_he_default_ba_buf_size = IEEE80211_MIN_BA_BUFFER_SIZE;
    }

    /* The FW default for the UL PPDU Duration is 2000 usecs. */
    ic->ic_he_ul_ppdu_dur = 2000;

    /* ToDo, check ev->sys_cap_info for  WMI_SYS_CAP_ENABLE and WMI_SYS_CAP_TXPOWER when it is available from FW */
    ieee80211com_set_cap(ic, IEEE80211_C_TXPMGT);

    ieee80211_wme_initglobalparams(ic);
    /* Initialize MU EDCA parameters with defaults for the ic */
    ieee80211_muedca_initglobalparams(ic);

    /* For targets such HKv1 and lower, this is set to 0 */
    if (target_type >= TARGET_TYPE_QCA8074V2)
        ic->ic_he_ul_muofdma = 1;
}

static void dbg_print_wmi_service_11ac(ol_ath_soc_softc_t *soc,
                                                struct wlan_psoc_target_capability_info  *ev)
{
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_11ac)) {
	qdf_nofl_debug("num_rf_chain:0x%08x  ", ev->num_rf_chains);
	qdf_nofl_debug("ht_cap_info:0x%08x  ", ev->ht_cap_info);
	qdf_nofl_debug("vht_cap_info:0x%08x  ", ev->vht_cap_info);
	qdf_nofl_debug("vht_supp_mcs:0x%08x", ev->vht_supp_mcs);
    }
    else {
	qdf_nofl_debug("\n No WMI 11AC service event received");
    }
}

static void
ol_ath_update_ic_hecap_mcsnssmap_from_target_hecap_mcsnssmap(
                                    struct ieee80211_he_handle *ic_he,
                                    uint32_t target_hecap_mcsnssmap)
{
    /* Target sends HE MCS-NSS info for less than equal to 80MHz encoded
     * in the lower 16 bits */
    ic_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]    =
                    HECAP_TXRX_MCS_NSS_GET_LT80_INFO(target_hecap_mcsnssmap);
    /* Target sends HE MCS-NSS info for greater than 80MHz encoded in the
     * upper 16 bits */
    ic_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]   =
                    HECAP_TXRX_MCS_NSS_GET_GT80_INFO(target_hecap_mcsnssmap);
    /* Target sends HE MCS-NSS info for greater than 80MHz encoded in the
     * upper 16 bits */
    ic_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80] =
                    HECAP_TXRX_MCS_NSS_GET_GT80_INFO(target_hecap_mcsnssmap);
    /* Target is sending only rxmcsnss values. For the time being we consider
     * txmcsnss values to be same as those or rxmcsnss
     */
    ic_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]    =
                    HECAP_TXRX_MCS_NSS_GET_LT80_INFO(target_hecap_mcsnssmap);
    ic_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]   =
                    HECAP_TXRX_MCS_NSS_GET_GT80_INFO(target_hecap_mcsnssmap);
    ic_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80] =
                    HECAP_TXRX_MCS_NSS_GET_GT80_INFO(target_hecap_mcsnssmap);
}

static inline void ol_ath_populate_he_caps(struct ieee80211com *ic,
        uint32_t *he_cap_info, uint32_t *he_supp_mcs,
        uint32_t *he_cap_phy_info, uint8_t he_cap_phy_info_size,
        struct wlan_psoc_host_ppe_threshold *he_ppet,
        uint32_t *he_cap_info_internal)
{
    struct ieee80211_he_handle *ic_he;
    ic_he = &ic->ic_he;

    if (he_cap_phy_info[0] &
        IEEE80211_HECAP_LDPC_MASK) {
        ieee80211com_set_ldpccap(ic, IEEE80211_HECAP_C_LDPC_TXRX);
    }

    qdf_mem_copy(&ic_he->hecap_macinfo, he_cap_info,
            sizeof(ic_he->hecap_macinfo));
    qdf_mem_copy(ic_he->hecap_phyinfo, he_cap_phy_info,
            he_cap_phy_info_size);
    qdf_mem_copy(&ic_he->hecap_info_internal, he_cap_info_internal,
            sizeof(ic_he->hecap_info_internal));
    ol_ath_update_ic_hecap_mcsnssmap_from_target_hecap_mcsnssmap(
            ic_he, *he_supp_mcs);
    qdf_mem_copy(&ic_he->hecap_ppet, he_ppet,
            sizeof(*he_ppet));

}

static void
ol_ath_update_ext_caps(struct wlan_psoc_host_mac_phy_caps *mac_phy_cap,
                       struct ieee80211com *ic)
{

    if (!mac_phy_cap || !ic) {
        qdf_err("mac_phy_cap or ic is Null");
        return;
    }

    /* Populate 11ax caps to IC */
    if (mac_phy_cap->supports_11ax) {
        ieee80211com_set_cap_ext(ic, IEEE80211_CEXT_11AX);
        if (mac_phy_cap->supported_bands == WMI_HOST_WLAN_5G_CAPABILITY) {

            qdf_info("11ax 5G supported case");
            ol_ath_populate_he_caps(ic, mac_phy_cap->he_cap_info_5G,
                    &mac_phy_cap->he_supp_mcs_5G,
                    mac_phy_cap->he_cap_phy_info_5G, sizeof(mac_phy_cap->he_cap_phy_info_5G),
                    &mac_phy_cap->he_ppet5G, &mac_phy_cap->he_cap_info_internal);

        } else if (mac_phy_cap->supported_bands == WMI_HOST_WLAN_2G_CAPABILITY) {

            qdf_info("11ax 2G supported case");
            ol_ath_populate_he_caps(ic, mac_phy_cap->he_cap_info_2G,
                    &mac_phy_cap->he_supp_mcs_2G,
                    mac_phy_cap->he_cap_phy_info_2G, sizeof(mac_phy_cap->he_cap_phy_info_2G),
                    &mac_phy_cap->he_ppet2G, &mac_phy_cap->he_cap_info_internal);

        } else {
            qdf_info("Both bands supported case %x, default to populate \
               5G HE caps", mac_phy_cap->supported_bands);

            ol_ath_populate_he_caps(ic, mac_phy_cap->he_cap_info_5G,
                    &mac_phy_cap->he_supp_mcs_5G,
                    mac_phy_cap->he_cap_phy_info_5G, sizeof(mac_phy_cap->he_cap_phy_info_5G),
                    &mac_phy_cap->he_ppet5G, &mac_phy_cap->he_cap_info_internal);
        }
    } else {
        ieee80211com_clear_cap_ext(ic, IEEE80211_CEXT_11AX);
        qdf_info("11AX not supported ");
    }
}


uint32_t
ol_ath_get_host_pltfrm_mode(ol_ath_soc_softc_t *soc)
{
	uint32_t target_type;

	target_type = lmac_get_tgt_type(soc->psoc_obj);

	switch(target_type)
	{
	case TARGET_TYPE_AR6002:
	case TARGET_TYPE_AR6003:
	case TARGET_TYPE_AR6004:
	case TARGET_TYPE_AR6006:
	case TARGET_TYPE_AR9888:
	case TARGET_TYPE_AR6320:
		return HOST_PLATFORM_LOW_PERF;
#if PEER_FLOW_CONTROL_FORCED_MODE0
	case TARGET_TYPE_AR900B:
	case TARGET_TYPE_QCA9984:
	case TARGET_TYPE_QCA9888:
		return HOST_PLATFORM_LOW_PERF_NO_FETCH;
#elif MIPS_LOW_PERF_SUPPORT
	case TARGET_TYPE_AR900B:
	case TARGET_TYPE_QCA9984:
	case TARGET_TYPE_QCA9888:
		return HOST_PLATFORM_LOW_PERF;
#else
	case TARGET_TYPE_AR900B:
	case TARGET_TYPE_QCA9984:
	case TARGET_TYPE_QCA9888:
		return HOST_PLATFORM_HIGH_PERF;
#endif
	case TARGET_TYPE_IPQ4019:
		return HOST_PLATFORM_HIGH_PERF;
	default:
		qdf_err("!!! Invalid Target Type %d !!!", target_type);
		return -EINVAL;
	}
	return EOK;
}

int
ol_ath_service_ready_event(ol_scn_t sc, uint8_t *evt_buf, uint32_t len)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct target_psoc_info *tgt_hdl;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    struct ol_ath_target_cap target_cap;

    QDF_STATUS status = wlan_objmgr_psoc_try_get_ref(psoc, WLAN_MLME_SB_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_err("unable to get psoc reference");
        return -1;
    }
    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("psoc target hdl is null in service ready ev");
        wlan_objmgr_psoc_release_ref(psoc, WLAN_MLME_SB_ID);
        return -EINVAL;
    }

    target_cap.wlan_resource_config = tgt_hdl->info.wlan_res_cfg;

    /* call back into  os shim with the services bitmap and resource config to let
     * the os shim layer modify it according to its needs and requirements */
    if (soc->cfg_cb) {
        soc->cfg_cb(soc, &target_cap);
        tgt_hdl->info.wlan_res_cfg = target_cap.wlan_resource_config;
    }

    /* Dump service ready event for debugging */
    dbg_print_wmi_service_11ac(soc, &tgt_hdl->info.target_caps);

    wlan_objmgr_psoc_release_ref(psoc, WLAN_MLME_SB_ID);

    return 0;
}

/**
 * ol_ath_unified_event_handler() - Global master wmi service handler
 * for both ext and ext service ready events
 * @event_id: event_id
 * @scn_handle: scn handle
 * @event_data: event data
 * @length: event length
 *
 * Return: 0 for success, negative error code for failure
 */
int
ol_ath_unified_event_handler(uint32_t event_id,
                             void *scn_handle,
                             uint8_t *event_data,
                             uint32_t length)
{

    if (wmi_service_ready_event_id == event_id) {
        return ol_ath_service_ready_event(scn_handle, event_data, length);
    }

    return 0;
}

/**
 * register_legacy_wmi_service_ready_callback(void) - register wmi legacy callback
 *
 * Legacy wmi Callback registered globally to target_if ctx
 * for all offload based architectures
 *
 * Return: Success
 */
QDF_STATUS register_legacy_wmi_service_ready_callback(void)
{
    target_if_register_legacy_service_ready_cb(ol_ath_unified_event_handler);

    return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(register_legacy_wmi_service_ready_callback);

void ol_ath_self_recovery(void *psoc, enum qdf_hang_reason reason,
                          const char *func, const uint32_t line)
{
    wmi_unified_t wmi_handle;
    struct wlan_objmgr_psoc *psoc_obj = psoc;

    qdf_info("PSOC_%d: %s, reason:%d:%d", wlan_psoc_get_id(psoc_obj), func,
             reason, line);
    if (reason == QDF_WMI_EXCEED_MAX_PENDING_CMDS)
        QDF_DEBUG_PANIC("BUG ON due to QDF_WMI_EXCEED_MAX_PENDING_CMDS");

    wmi_handle = GET_WMI_HDL_FROM_PSOC(psoc);
    if (wmi_handle) {
        ol_ath_set_fw_hang(wmi_handle, 0);
    } else if (target_if_vdev_mgr_is_panic_on_bug()) {
        QDF_DEBUG_PANIC("Panic due to response timeout");
    }
}
qdf_export_symbol(ol_ath_self_recovery);

/*
 *  WMI API for setting fw hang.
 *  type parameter can be one of the 6 values defined in
 *  wmi_unified.h enumerated as RECOVERY_SIM_TYPE
 */
int
ol_ath_set_fw_hang(wmi_unified_t wmi_handle, u_int32_t delay_time_ms)
{
    struct crash_inject param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.delay_time_ms = delay_time_ms;
    param.type = 1; //RECOVERY_SIM_ASSERT

    wmi_tag_crash_inject(wmi_handle, true);

    return wmi_crash_inject(wmi_handle, &param);
}

static int
ol_ath_get_pn_event_handler(ol_scn_t sc, u_int8_t *evt_buf, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wmi_host_get_pn_event pn_ev;
    struct wlan_objmgr_vdev *vdev;
    uint8_t pdev_id;
    struct wlan_objmgr_peer *peer;
    struct wlan_crypto_key *key = NULL;
    struct ieee80211_node *ni;

    psoc = soc->psoc_obj;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi handle is NULL");
        return -EINVAL;
    }

    if (wmi_unified_extract_pn(wmi_handle, evt_buf, &pn_ev) !=
                               QDF_STATUS_SUCCESS) {
        qdf_err("Unable to extract PN event");
        return -1;
    }

    if ((vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, pn_ev.vdev_id,
                                                     WLAN_CRYPTO_ID)) == NULL) {
        qdf_err("vdev object (id: %d) is NULL", pn_ev.vdev_id);
        return -1;
    }

    if ((pdev = wlan_vdev_get_pdev(vdev)) == NULL) {
        qdf_err("pdev object is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_CRYPTO_ID);
        return -1;
    }

    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

    if ((peer = wlan_objmgr_get_peer(psoc, pdev_id, pn_ev.mac_addr,
                                     WLAN_CRYPTO_ID)) == NULL) {
        qdf_err("peer object is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_CRYPTO_ID);
        return -1;
    }

    key = wlan_crypto_peer_getkey(peer, WLAN_CRYPTO_KEYIX_NONE);

    if (key)
        key->keytsc = 0;

    if (key && key->cipher_type != WLAN_CRYPTO_CIPHER_WAPI_SMS4)
        qdf_mem_copy((uint8_t *)(&key->keytsc), (uint8_t *)(pn_ev.pn),
                     sizeof(key->keytsc));

    ni = wlan_peer_get_mlme_ext_obj(peer);
    if (ni)
        qdf_atomic_inc(&(ni->getpn));

    wlan_objmgr_peer_release_ref(peer, WLAN_CRYPTO_ID);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_CRYPTO_ID);
    return 0;
}

struct ieee80211_ath_channel *
ol_ath_find_full_channel(struct ieee80211com *ic, u_int32_t freq)
{
   return wlan_find_full_channel(ic, freq);
}

/* Offload Interface functions for UMAC */
static int
ol_ath_init(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static int
ol_ath_reset_start(struct ieee80211com *ic, bool no_flush)
{
    /* TBD */
    return 0;
}

static int
ol_ath_reset_end(struct ieee80211com *ic, bool no_flush)
{
    /* TBD */
    return 0;
}

static void
ol_set_beacon_interval(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

static int
ol_ath_reset(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static void ol_ath_kbps_to_mcs(ol_ath_soc_softc_t *soc, struct ieee80211com *ic)
{
    if(soc->ol_if_ops->kbps_to_mcs)
        ic->ic_whal_kbps_to_mcs = soc->ol_if_ops->kbps_to_mcs;
}

static void
ol_ath_ratecode_to_kbps(ol_ath_soc_softc_t *soc, struct ieee80211com *ic)
{
    if(soc->ol_if_ops->ratecode_to_kbps)
        ic->ic_whal_ratecode_to_kbps = soc->ol_if_ops->ratecode_to_kbps;
}

static void
ol_ath_get_supported_rates(ol_ath_soc_softc_t *soc, struct ieee80211com *ic)
{
    if(soc->ol_if_ops->get_supported_rates)
        ic->ic_get_supported_rates = soc->ol_if_ops->get_supported_rates;
}

static int
ol_ath_wmm_update(struct ieee80211com *ic, struct ieee80211vap *vap,
        bool muedca_enabled)
{
    struct wmm_update_params param;
    struct wmeParams *wmep = NULL;
    struct muedcaParams *muedcap = NULL;
    struct wmi_host_wme_vparams wmm_vparams[WME_NUM_AC] = {0};
    int ac = 0;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return -EINVAL;

    if (!wmi_service_enabled(pdev_wmi_handle, wmi_service_deprecated_replace)) {
        qdf_mem_set(&param, sizeof(param), 0);
        param.wmep_array = (struct wmi_host_wmeParams *)ic->ic_wme.wme_chanParams.cap_wmeParams;
        wmi_unified_wmm_update_cmd_send(pdev_wmi_handle, &param);
    } else {
        /* For lithium chips onwards */
        /* Fill values from ic_wme.wme_chanParams.cap_wmeParams to wmm_vparams */
        if(muedca_enabled) {
            for (ac = 0; ac < MUEDCA_NUM_AC; ac++) {
                muedcap = &(vap->iv_muedcastate.muedca_paramList[ac]);

                wmm_vparams[ac].acm = muedcap->muedca_acm;
                wmm_vparams[ac].aifs = muedcap->muedca_aifsn;
                wmm_vparams[ac].cwmin = ATH_EXPONENT_TO_VALUE(muedcap->muedca_ecwmin);
                wmm_vparams[ac].cwmax = ATH_EXPONENT_TO_VALUE(muedcap->muedca_ecwmax);
                wmm_vparams[ac].mu_edca_timer = muedcap->muedca_timer;
                wmm_vparams[ac].noackpolicy = 0;
            }

        }
        else {
            for (ac = 0; ac < WME_NUM_AC; ac++) {
                wmep = &(ic->ic_wme.wme_chanParams.cap_wmeParams[ac]);

                wmm_vparams[ac].acm = wmep->wmep_acm;
                wmm_vparams[ac].aifs = wmep->wmep_aifsn;
                wmm_vparams[ac].cwmin = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmin);
                wmm_vparams[ac].cwmax = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmax);
                wmm_vparams[ac].txoplimit = wmep->wmep_txopLimit;
                wmm_vparams[ac].noackpolicy = wmep->wmep_noackPolicy;
            }
        }
        wmi_unified_process_update_edca_param(pdev_wmi_handle,
                                              wlan_vdev_get_id(vap->vdev_obj),
                                              muedca_enabled, wmm_vparams);
    }

    return 0;
}


static u_int32_t
ol_ath_txq_depth(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_txq_depth_ac(struct ieee80211com *ic,int ac)
{
    /* TBD */
    return 0;
}

/**
 * ol_ath_ar900b_fw_test() - sends fw test cmds via wmi
 * @arg: cmd
 * @value: cmd value
 *
 * Return: none
 */
static void ol_ath_ar900b_fw_test(struct ieee80211com *ic,
                                  uint32_t arg, uint32_t value )
{
    struct set_fwtest_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.arg = arg;
    param.value = value;

#if !(QCA_TGT_FW_IRAM_DUMP_ENABLE)
#define QCA_WIFITOOL_IRAM_DUMP_COMMAND 164
    if (arg == QCA_WIFITOOL_IRAM_DUMP_COMMAND) {
        qdf_err("Command not supported");
        return;
    }
#endif

    wmi_unified_vdev_set_fwtest_param_cmd_send(pdev_wmi_handle, &param);

    return;
}

static void get_sta_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ppvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_STA == vap->iv_opmode) {
        *ppvap = vap;
    }

    return;
}

static void
ol_ath_net80211_enable_radar(struct ieee80211com *ic, int no_cac)
{
}

static int ol_ath_set_channel(struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *chan;
    uint32_t freq;
    ieee80211_vap_t vap = NULL;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_psoc *psoc = NULL;
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    chan = ieee80211_get_current_channel(ic);

    freq = ieee80211_chan2freq(ic, chan);
    if (!freq) {
        qdf_err("ERROR : INVALID Freq");
        return -1;
    }

    /* update max channel power to max regpower of current channel */
    ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);

    /* Update the channel for monitor mode path */
    cdp_set_curchan(soc_txrx_handle, pdev_id, freq);

    wlan_iterate_vap_list(ic, get_sta_mode_vap ,(void *)&vap );
    if (vap) {
        /* There is a active STA mode vap.
         * for STA mode channel change will happen through resmgr channnel change
         */
         return -1;
    }
    else {
        /* Call a new channel change WMI cmd for all VAPs in AP/monitor mode.  */
        /****************************************
        FIXME: better way is to restart all VAPs in osif layer resmgr_vap_start() path,
        with parameter restart=1, e.g. wlan_mlme_start_bss(vap,1)
        ****************************************/
        if((ic->ic_prevchan) && ((chan != ic->ic_prevchan))){
            /*If different channel, need to restart all VAPs.
              If channel numbers are same, but channel ic_flags are different,
              we still consider this as 'different' channel */

            wlan_pdev_mlme_vdev_sm_chan_change(ic->ic_pdev_obj, chan);
        }
    }

    /* Restore dcs state to previous state so that interference detection will work*/
    if (ic->ic_dcs_restore)
        ic->ic_dcs_restore(ic);

    if (ic->ic_cbs && ic->ic_cbs->cbs_enable)
        wlan_bk_scan(ic);

    return 0;
}

static void ol_ath_log_text(struct ieee80211com *ic, char *text)
{
    /* This function needs to be called from interrupt context. Temporarily
     * disabling this as this is getting called from different contexts
     */
    return;
}

static void
ol_ath_log_text_bh(struct ieee80211com *ic, char *text)
{
    /* This function needs to be called only from bottom half context */
#ifndef REMOVE_PKT_LOG
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if(scn->pl_dev)
        scn->pl_dev->pl_funcs->pktlog_text(scn,text);
#endif
    return;
}

static void
ol_ath_pwrsave_set_state(struct ieee80211com *ic, IEEE80211_PWRSAVE_STATE newstate)
{
    /* The host does not manage the HW power state with offload FW. This function
     * exists solely for completeness.
     */
}

uint8_t ol_ath_freq_to_channel(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id, uint16_t freq)
{
    uint8_t channel_number = 0;
    struct wlan_objmgr_pdev *pdev_obj = wlan_objmgr_get_pdev_by_id(
                                          (struct wlan_objmgr_psoc *)psoc,
                                          pdev_id,
                                          WLAN_MLME_SB_ID);

    if (!pdev_obj)
        return channel_number;

    channel_number = wlan_reg_freq_to_chan(pdev_obj, freq);
    wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_SB_ID);

    return channel_number;
}

uint8_t ol_ath_freq_to_band(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id, uint16_t freq)
{
    return wlan_reg_freq_to_band(freq);
}

static int16_t ol_ath_get_noisefloor (struct ieee80211com *ic, struct ieee80211_ath_channel *chan,
                                        int wait_time)
{
    /* TBD */
    return 0;
}

static int16_t ol_ath_net80211_get_cur_chan_noisefloor(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return scn->chan_nf;
}

static int16_t ol_ath_net80211_get_cur_hw_nf(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return scn->cur_hw_nf;
}

static void
ol_ath_get_chainnoisefloor(struct ieee80211com *ic, struct ieee80211_ath_channel *chan, int16_t *nfBuf)
{
    /* TBD */
    return;
}

#if UNIFIED_SMARTANTENNA
static void ol_ath_set_ant_switch_tbl(struct ieee80211com *ic,
                                      uint32_t ant_ctrl_common1,
                                      uint32_t ant_ctrl_common2)
{
    struct ant_switch_tbl_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ant_ctrl_common1 = ant_ctrl_common1;
    param.ant_ctrl_common2 = ant_ctrl_common2;

    (void)wmi_unified_set_ant_switch_tbl_cmd_send(pdev_wmi_handle, &param);
}
#endif

/*
 * Override the rate power table in EEPROM
 */
static void ol_ath_set_ratepwr_table(struct ieee80211com *ic,
                                     uint8_t *ratepwr_tbl, uint16_t ratepwr_len)
{
    struct ratepwr_table_params param;
    struct wmi_unified *pdev_wmi_handle;

    if (!ratepwr_tbl)
        return;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ratepwr_tbl = ratepwr_tbl;
    param.ratepwr_len = ratepwr_len;

    (void)wmi_unified_set_ratepwr_table_cmd_send(pdev_wmi_handle, &param);
}

/*
 * Get the rate power table in EEPROM
 */
static void ol_ath_get_ratepwr_table(struct ieee80211com *ic)
{
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    (void)wmi_unified_get_ratepwr_table_cmd_send(pdev_wmi_handle);
}

/*
 * EEPROM rate power table operations
 */
static void ol_ath_ratepwr_table_ops(struct ieee80211com *ic, uint8_t ops,
                                     uint8_t *ratepwr_tbl, uint16_t ratepwr_len)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (lmac_get_tgt_type(psoc) != TARGET_TYPE_AR9888) {
        qdf_info("rate power table override is only supported for AR98XX");
        return;
    }

    if (ops == WMI_HOST_RATEPWR_TABLE_OPS_SET) {
        QC98XX_EEPROM_RATETBL eep_tbl;

        qdf_mem_set((void *)&eep_tbl, sizeof(QC98XX_EEPROM_RATETBL), 0);
        /* convert user format to eeprom format */
        ol_if_ratepwr_usr_to_eeprom((uint8_t *)&eep_tbl,
                                    sizeof(QC98XX_EEPROM_RATETBL),
                                    ratepwr_tbl, ratepwr_len);

        ol_ath_set_ratepwr_table(ic, (uint8_t*)&eep_tbl,
                                 sizeof(QC98XX_EEPROM_RATETBL));
    } else if (ops == WMI_HOST_RATEPWR_TABLE_OPS_GET) {
        ol_ath_get_ratepwr_table(ic);
    } else {
        qdf_err("Unknown ratepwr table ops %d", ops);
    }
    return;
}

static void ol_ath_set_ctl_table(struct ieee80211com *ic,
                                 uint8_t *ctl_array, uint16_t ctl_len)
{
    struct ctl_table_params param;
    struct wmi_unified *pdev_wmi_handle;
    struct wlan_objmgr_psoc *psoc = NULL;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!ctl_array)
        return;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);

    qdf_mem_copy(&param.ctl_band, ctl_array, sizeof(uint32_t));
    param.ctl_array = ctl_array + sizeof(uint32_t);
    param.ctl_cmd_len = ctl_len;
    param.target_type = lmac_get_tgt_type(psoc);

    if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        param.is_2g = TRUE;
    else
        param.is_2g = FALSE;

    (void)wmi_unified_set_ctl_table_cmd_send(pdev_wmi_handle, &param);
}

static void
ol_ath_set_mimogain_table(struct ieee80211com *ic, uint8_t *array_gain,
                          uint16_t tbl_len, bool multichain_gain_bypass)
{
    struct mimogain_table_params param;
    struct wmi_unified *pdev_wmi_handle;

    if (!array_gain)
        return;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.array_gain = array_gain;
    param.tbl_len = tbl_len;
    param.multichain_gain_bypass = multichain_gain_bypass;

    (void)wmi_unified_set_mimogain_table_cmd_send(pdev_wmi_handle, &param);
}

static QDF_STATUS
ol_ath_set_peer_latency_param_config(struct ieee80211com *ic, uint8_t *peer_mac,
       uint32_t tid, uint8_t dl_ul_enable, uint32_t service_interval,
       uint32_t burst_size, uint32_t add_or_sub)
{
    struct wmi_peer_latency_config_params param;
    struct wmi_unified *pdev_wmi_handle;
    struct wlan_objmgr_pdev *pdev;
    uint8_t ac = WMI_HOST_AC_BE;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_INVAL;

    pdev = scn->sc_pdev;
    if (!pdev)
        return QDF_STATUS_E_INVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return QDF_STATUS_E_INVAL;

    param.pdev_id = lmac_get_pdev_idx(pdev);
    param.num_peer = 1;
    qdf_mem_copy(param.latency_info[0].peer_mac, peer_mac,
                      QDF_MAC_ADDR_SIZE);
    param.latency_info[0].latency_tid = tid;

    param.latency_info[0].dl_enable = 1;
    param.latency_info[0].ul_enable = 1;

    param.latency_info[0].service_interval = service_interval;
    param.latency_info[0].burst_size = burst_size;
    param.latency_info[0].add_or_sub = add_or_sub;
    ac = TID_TO_WME_AC(tid);
    param.latency_info[0].ac = ac;

    return wmi_unified_config_peer_latency_info_cmd_send(pdev_wmi_handle, &param);
}

static u_int8_t
ol_ath_get_common_power(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_getTSF32(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static int
ol_ath_getrmcounters(struct ieee80211com *ic, struct ieee80211_mib_cycle_cnts *pCnts)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* "ic->ic_mib_cycle_cnts" gets updated during a periodic stats event */
    pCnts->tx_frame_count = scn->mib_cycle_cnts.tx_frame_count;
    pCnts->rx_frame_count = scn->mib_cycle_cnts.rx_frame_count;
    pCnts->rx_clear_count = scn->mib_cycle_cnts.rx_clear_count;
    pCnts->rx_clear_ext_count = scn->mib_cycle_cnts.rx_clear_ext_count;
    pCnts->rx_clear_ext40_count = scn->mib_cycle_cnts.rx_clear_ext40_count;
    pCnts->rx_clear_ext80_count = scn->mib_cycle_cnts.rx_clear_ext80_count;
    pCnts->cycle_count = scn->mib_cycle_cnts.cycle_count;

    /* "is_rx_active" and "is_tx_active" not being used, but for safety, set it to 0 */
    pCnts->is_rx_active = 0;
    pCnts->is_tx_active = 0;

    return 0;
}

static u_int32_t
ol_ath_wpsPushButton(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static void
ol_ath_clear_phystats(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

static int ol_ath_set_macaddr(struct ieee80211com *ic, uint8_t *macaddr)
{
    struct macaddr_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return -EINVAL;

    qdf_mem_set(&param, sizeof(param), 0);
    param.macaddr = macaddr;

    if (wmi_unified_set_macaddr_cmd_send(pdev_wmi_handle, &param)) {
        return -1;
    }
    return 0;
}

static int
ol_ath_set_chain_mask(struct ieee80211com *ic, ieee80211_device_param type, u_int32_t mask)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_getmfpsupport(struct ieee80211com *ic)
{
    return IEEE80211_MFP_HW_CRYPTO;
}

static uint64_t ol_ath_get_tx_hw_retries(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    ol_txrx_soc_handle soc_txrx_handle;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    return cdp_ath_get_total_per(soc_txrx_handle,
                                 wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj));
}

static u_int64_t
ol_ath_get_tx_hw_success(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

/**
 * ol_ath_rate_node_update() - Update peer rate table
 * @ni: pointer to node
 * @isnew: peer association type
 *
 * Return: none
 */
static void ol_ath_rate_node_update(struct ieee80211_node *ni, int isnew)
{
    /* reuse the ASSOC_CMDID to perform the dynamic rate setting */
    ol_ath_send_peer_assoc(ni, isnew);
}

#ifdef BIG_ENDIAN_HOST
void swap_bytes(void *pv, size_t n)
{
       int noWords;
       int i;
       A_UINT32 *wordPtr;

       noWords =   n/sizeof(u_int32_t);
       wordPtr = (u_int32_t *)pv;
       for (i=0;i<noWords;i++)
       {
               *(wordPtr + i) = __cpu_to_le32(*(wordPtr + i));
       }
}
#define SWAPME(x, len) swap_bytes(&x, len);
#endif

#ifdef WLAN_SUPPORT_RF_CHARACTERIZATION
static int
ol_ath_chan_rf_characterization_info_event_handler(ol_soc_t  sc,
                                                   u_int8_t  *data,
                                                   u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_unified *wmi_handle = NULL;
    uint32_t num_rf_characterization_entries = 0;

    if (!soc) {
        qdf_err("Invalid soc");
        return -EINVAL;
    }

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("Invalid WMI handle");
        return -EINVAL;
    }

    /*
     * Retrieving the total number of TLVs (if any). If there are no TLVs
     * then we return without disrupting functionality.
     */
    wmi_extract_num_rf_characterization_entries(wmi_handle, data,
                                        &num_rf_characterization_entries);
    if (!num_rf_characterization_entries) {
        return 0;
    }

    /*
     * If there are already metrics present before handling this event,
     * they will be discarded and replaced by the metrics sent in this.
     */
    if (soc->rf_characterization_entries) {
        qdf_mem_free(soc->rf_characterization_entries);
        soc->num_rf_characterization_entries = 0;
        soc->rf_characterization_entries = NULL;
    }

    soc->num_rf_characterization_entries = num_rf_characterization_entries;
    soc->rf_characterization_entries = qdf_mem_malloc(
                                    sizeof(*soc->rf_characterization_entries) *
                                    soc->num_rf_characterization_entries);
    if (!soc->rf_characterization_entries) {
        soc->num_rf_characterization_entries = 0;
        return -EINVAL;
    }

    if (wmi_extract_rf_characterization_entries(wmi_handle, data,
                                         soc->num_rf_characterization_entries,
                                         soc->rf_characterization_entries)) {
        qdf_err("Failed to extract RF characterization metrics");
        qdf_mem_free(soc->rf_characterization_entries);
        soc->rf_characterization_entries = NULL;
        soc->num_rf_characterization_entries = 0;
        return -EINVAL;
    }

    return 0;
}
#endif

static int
ol_ath_debug_print_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
#ifdef BIG_ENDIAN_HOST
       char dbgbuf[500] = {0};
       memcpy(dbgbuf, data, datalen);
       SWAPME(dbgbuf, datalen);
       qdf_info("FIRMWARE:%s", dbgbuf);
       return 0;
#else
       qdf_info("FIRMWARE:%s", data);
       return 0;
#endif
}

static bool
ol_ath_set_config_enable(struct ieee80211vap* vap)
{
       struct wlan_objmgr_psoc *psoc;

       psoc = wlan_vdev_get_psoc(vap->vdev_obj);
       return ol_target_lithium(psoc);
}

static void
ol_ath_set_config(struct ieee80211vap* vap)
{
      /* Currently Not used for Offload */
}

static void
ol_ath_set_safemode(struct ieee80211vap* vap, int val)
{
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_vdev *vdev_obj = vap->vdev_obj;
    cdp_config_param_type value = {0};

    if (vdev_obj) {
        psoc = wlan_vdev_get_psoc(vdev_obj);
        value.cdp_vdev_param_safe_mode = val;
        cdp_txrx_set_vdev_param(wlan_psoc_get_dp_handle(psoc),
                         wlan_vdev_get_id(vdev_obj), CDP_SAFEMODE, value);
    }
    return;
}

static void
ol_ath_set_privacy_filters(struct ieee80211vap* vap)
{
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_vdev *vdev_obj = vap->vdev_obj;

    if (vdev_obj) {
        psoc = wlan_vdev_get_psoc(vdev_obj);
        cdp_set_privacy_filters(wlan_psoc_get_dp_handle(psoc),
                wlan_vdev_get_id(vdev_obj), vap->iv_privacy_filters, vap->iv_num_privacy_filters);
    }
    return;
}

/*
 * expected values for filter (val) 0, 1, 2, 4, 8
 * these values could be for FP, MO, or both by using first 16 bits.
 * i.e. 0x10004 (FP only enable with filter 4 on)
 */
static int ol_ath_set_rx_monitor_filter(struct ieee80211com *ic, uint32_t val)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    struct cdp_monitor_filter filter_val;
    ol_txrx_soc_handle soc_txrx_handle;
    uint32_t shift_val = FILTER_MODE(val);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    filter_val.mode = RX_MON_FILTER_PASS | RX_MON_FILTER_OTHER;

    if (shift_val == FILTER_PASS_ONLY)
        filter_val.mode = RX_MON_FILTER_PASS;
    else if (shift_val == MONITOR_OTHER_ONLY)
        filter_val.mode = RX_MON_FILTER_OTHER;

    if (filter_val.mode & RX_MON_FILTER_PASS) {
        filter_val.fp_mgmt = SET_MON_FILTER_MGMT(val);
        filter_val.fp_ctrl = SET_MON_FILTER_CTRL(val);
        filter_val.fp_data = SET_MON_FILTER_DATA(val);
    }
    if (filter_val.mode & RX_MON_FILTER_OTHER) {
        filter_val.mo_mgmt = SET_MON_FILTER_MGMT(val);
        filter_val.mo_ctrl = SET_MON_FILTER_CTRL(val);
        filter_val.mo_data = SET_MON_FILTER_DATA(val);
    }

    cdp_set_monitor_filter(soc_txrx_handle,
                wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj), &filter_val);

    return 0;
}

#if ATH_SUPPORT_IQUE
void ol_ath_set_acparams(struct ieee80211com *ic, uint8_t ac, uint8_t use_rts,
                         uint8_t aggrsize_scaling, uint32_t min_kbps)
{
    struct acparams_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ac = ac;
    param.aggrsize_scaling = aggrsize_scaling;

    wmi_unified_set_acparams_cmd_send(pdev_wmi_handle, &param);
    return;
}

void
ol_ath_set_rtparams(struct ieee80211com *ic, u_int8_t ac, u_int8_t perThresh,
                          u_int8_t probeInterval)
{
    /* TBD */
    return;
}

void
ol_ath_get_iqueconfig(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

void
ol_ath_set_hbrparams(struct ieee80211vap *iv, u_int8_t ac, u_int8_t enable, u_int8_t per)
{
    /* TBD */
    return;
}
#endif /*ATH_SUPPORT_IQUE*/

#ifdef ATH_SUPPORT_TxBF
static int
ol_ath_net80211_txbf_alloc_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return 0;
}

static void
ol_ath_net80211_txbf_set_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return;
}

static int
ol_ath_net80211_txbf_del_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return 0;
}

static void
ol_ath_net80211_init_sw_cv_timeout(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return;
}

static int
ol_ath_set_txbfcapability(struct ieee80211com *ic)
{
    return 0;
}

#ifdef TXBF_DEBUG
static void
ol_ath_net80211_txbf_check_cvcache(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return 0;
}
#endif

static void
ol_ath_net80211_v_cv_send(struct ieee80211_node *ni,
                       u_int8_t *data_buf,
                       u_int16_t buf_len)
{
    return;
}
static void
ol_ath_net80211_txbf_stats_rpt_inc(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    return;
}
static void
ol_ath_net80211_txbf_set_rpt_received(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    return;
}
#endif

QDF_STATUS
ol_is_mode_offload(struct wlan_objmgr_pdev *pdev, bool *is_offload)
{
    *is_offload = TRUE;
    return QDF_STATUS_SUCCESS;
}

bool
ol_ath_net80211_is_mode_offload(struct ieee80211com *ic)
{
    /*
     * If this function executes, it is offload mode
     */
    return TRUE;
}

QDF_STATUS ol_ath_get_ah_devid(struct wlan_objmgr_pdev *pdev,
        uint16_t *devid)
{
    /* devid is needed only for DA */
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_ath_get_phymode_info(struct wlan_objmgr_pdev *pdev,
        uint32_t chan_mode, uint32_t *mode_info, bool is_2gvht_en)
{
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;

    osif_priv = wlan_pdev_get_ospriv(pdev);

    if (!osif_priv) {
        qdf_err("osif_priv is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;

    *mode_info = ol_get_phymode_info_from_wlan_phymode(scn, chan_mode, is_2gvht_en);
    return QDF_STATUS_SUCCESS;
}

static bool
ol_ath_net80211_is_macreq_enabled(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return ((scn->macreq_enabled == 1) ? TRUE : FALSE);
}

static u_int32_t
ol_ath_net80211_get_mac_prealloc_idmask(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return scn->sc_prealloc_idmask;
}

static void
ol_ath_net80211_set_mac_prealloc_id(struct ieee80211com *ic, u_int8_t id,
                                                            u_int8_t set)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    if(set) {
        scn->sc_prealloc_idmask |= (1 << id);
    }
    else {
        scn->sc_prealloc_idmask &= ~(1 << id);
    }
}

static uint8_t
ol_ath_net80211_get_bsta_fixed_idmask(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return scn->sc_bsta_fixed_idmask;
}

static int
ol_ath_net80211_tr69_get_vdev_extd_stats(struct ieee80211vap *vap,
                                         uint32_t cmd,
                                         uint32_t *arg1)
{
    struct wlan_objmgr_psoc *psoc;
    ol_txrx_soc_handle soc_handle;
    wmi_host_vdev_extd_stats extd_stats;

    psoc = wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj);

    if (!psoc)
        return -ENOENT;

    soc_handle = wlan_psoc_get_dp_handle(psoc);

    cdp_get_vdev_extd_stats(soc_handle,
                            wlan_vdev_get_id(vap->vdev_obj),
                            &extd_stats);

    switch(cmd) {
        case IEEE80211_TR069_GET_FAIL_RETRANS_CNT:
             *arg1 = extd_stats.mpdu_fail_retry;
        break;
        case IEEE80211_TR069_GET_RETRY_CNT:
             *arg1 =  extd_stats.mpdu_suc_retry;
        break;
        case IEEE80211_TR069_GET_MUL_RETRY_CNT:
             *arg1 = extd_stats.mpdu_suc_multitry;
        break;
        case IEEE80211_TR069_GET_ACK_FAIL_CNT:
             *arg1 = extd_stats.ppdu_noack;
        break;
        case IEEE80211_TR069_GET_AGGR_PKT_CNT:
             *arg1 = extd_stats.ppdu_aggr_cnt;
        break;
        case IEEE80211_TR069_GET_CHAN_UTIL:
             *arg1 = 0;
        break;
        case IEEE80211_TR069_GET_RETRANS_CNT:
             *arg1 = extd_stats.mpdu_sw_requed;
        break;
    }

    return 0;
}

static int
ol_ath_net80211_tr69_get_sta_bytes_sent(struct ieee80211vap *vap, u_int32_t *bytessent, u_int8_t *dstmac)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    struct wlan_objmgr_psoc *psoc;
    cdp_peer_stats_param_t buf = {0};
    QDF_STATUS status;

    ni = ieee80211_find_node(ic, dstmac, WLAN_TR69_ID);
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!ni || !ni->peer_obj || !psoc) {
        status = QDF_STATUS_E_NOENT;
    } else {
        status = cdp_txrx_get_peer_stats_param(wlan_psoc_get_dp_handle(psoc),
                                 wlan_vdev_get_id(ni->peer_obj->peer_objmgr.vdev),
                                 ni->peer_obj->macaddr, cdp_peer_tx_ucast,
                                 &buf);
        *bytessent = buf.tx_ucast.bytes;
    }

    if (ni)
        ieee80211_free_node(ni, WLAN_TR69_ID);

    return qdf_status_to_os_return(status);
}

static int
ol_ath_net80211_tr69_get_sta_bytes_rcvd(struct ieee80211vap *vap, u_int32_t *bytesrcvd, u_int8_t *dstmac)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    struct wlan_objmgr_psoc *psoc;
    cdp_peer_stats_param_t buf  = {0};
    QDF_STATUS status;

    ni = ieee80211_find_node(ic, dstmac, WLAN_TR69_ID);
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!ni || !ni->peer_obj || !psoc) {
        status = QDF_STATUS_E_NOENT;
    } else {
        status = cdp_txrx_get_peer_stats_param(wlan_psoc_get_dp_handle(psoc),
                                 wlan_vdev_get_id(ni->peer_obj->peer_objmgr.vdev),
                                 ni->peer_obj->macaddr, cdp_peer_rx_ucast,
                                 &buf);
        *bytesrcvd = buf.rx_ucast.bytes;
    }

    if (ni)
        ieee80211_free_node(ni, WLAN_TR69_ID);

    return qdf_status_to_os_return(status);
}

static int
ol_ath_net80211_tr69_process_request(struct ieee80211vap *vap, int cmdid, void * arg1, void *arg2)
{
    //	struct ieee80211com *ic = vap->iv_ic;

	switch(cmdid){
#if 0
        case IEEE80211_TR069_GET_PLCP_ERR_CNT:
			ol_ath_net80211_tr69_get_plcp_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_FCS_ERR_CNT:
			ol_ath_net80211_tr69_get_fcs_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_PKTS_OTHER_RCVD:
			ol_ath_net80211_tr69_get_pkts_other_rcvd(dev, req);
            break;
#endif
        case IEEE80211_TR069_GET_FAIL_RETRANS_CNT:
        case IEEE80211_TR069_GET_RETRY_CNT:
        case IEEE80211_TR069_GET_MUL_RETRY_CNT:
        case IEEE80211_TR069_GET_ACK_FAIL_CNT:
        case IEEE80211_TR069_GET_AGGR_PKT_CNT:
        case IEEE80211_TR069_GET_CHAN_UTIL:
        case IEEE80211_TR069_GET_RETRANS_CNT:
             ol_ath_net80211_tr69_get_vdev_extd_stats(vap, cmdid, arg1);
        break;
        case IEEE80211_TR069_GET_STA_BYTES_SENT:
             ol_ath_net80211_tr69_get_sta_bytes_sent(vap, arg1, arg2);
            break;
        case IEEE80211_TR069_GET_STA_BYTES_RCVD:
             ol_ath_net80211_tr69_get_sta_bytes_rcvd(vap, arg1, arg2);
            break;
#if 0
        case IEEE80211_TR069_GET_DATA_SENT_ACK:
			ol_ath_net80211_tr69_get_data_sent_ack(dev, arg1);
            break;
        case IEEE80211_TR069_GET_DATA_SENT_NOACK:
			ol_ath_net80211_tr69_get_data_sent_noack(dev, req);
            break;
#endif
        default:
			break;
    }

    return 0;
}

/*default rate limit period - 60 sec*/
#define PEER_REF_PRINT_RATE_LIMIT_PERIOD (60*HZ)
/*default burst for rate limit */
#define PEER_REF_PRINT_RATE_LIMIT_BURST_DEFAULT   1
DEFINE_RATELIMIT_STATE(peer_refs_ratelimit,
        PEER_REF_PRINT_RATE_LIMIT_PERIOD,
        PEER_REF_PRINT_RATE_LIMIT_BURST_DEFAULT);

int print_peer_refs_ratelimit(void)
{
    return __ratelimit(&peer_refs_ratelimit);
}

bool ol_ath_wide_band_scan(struct ieee80211com *ic)
{
    bool ret_val;
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    /* return true if host and FW both support wide band scan.
     * false otherwise.
     */
    ret_val =(ic->ic_widebw_scan &&
              wlan_psoc_nif_fw_ext_cap_get(psoc,
                                           WLAN_SOC_CEXT_WIDEBAND_SCAN));

    return ret_val;
}

int
ol_ath_net80211_get_vap_stats(struct ieee80211vap *vap)
{
    struct wlan_objmgr_psoc *psoc;
    ol_txrx_soc_handle soc_handle;
    wmi_host_vdev_extd_stats vdev_extd_stats;

    psoc = wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj);

    if(!psoc)
        return -ENOENT;

    soc_handle = wlan_psoc_get_dp_handle(psoc);
    cdp_get_vdev_extd_stats(soc_handle,
                            wlan_vdev_get_id(vap->vdev_obj),
                            &vdev_extd_stats);
    qdf_info("-----VAP Stats------\n");
    qdf_info("\n");
    qdf_info("ppdu_aggr         = %d\n", vdev_extd_stats.ppdu_aggr_cnt);
    qdf_info("ppdu_nonaggr      = %d\n", vdev_extd_stats.ppdu_nonaggr_cnt);
    qdf_info("noack             = %d\n", vdev_extd_stats.ppdu_noack);
    qdf_info("mpdu_queued       = %d\n", vdev_extd_stats.mpdu_queued);
    qdf_info("mpdu_requeued     = %d\n", vdev_extd_stats.mpdu_sw_requed);
    qdf_info("mpdu_suc_retry    = %d\n", vdev_extd_stats.mpdu_suc_retry);
    qdf_info("mpdu_suc_multitry = %d\n", vdev_extd_stats.mpdu_suc_multitry);
    qdf_info("mpdu_fail_retry   = %d\n", vdev_extd_stats.mpdu_fail_retry);
    qdf_info("-----VAP Stats------\n");
    qdf_info("\n");

    return 0;
}

/* The below mapping is according the doc, which is as follows,

DSCP        TID     AC
000000      0       WME_AC_BE
001000      1       WME_AC_BK
010000      1       WME_AC_BK
011000      0       WME_AC_BE
100000      5       WME_AC_VI
101000      5       WME_AC_VI
110000      6       WME_AC_VO
111000      6       WME_AC_VO

*/

#if ATH_SUPPORT_DSCP_OVERRIDE
void
ol_ath_set_pdev_dscp_tid_map(struct ieee80211vap *vap, uint32_t tos)
{

    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    uint8_t map_id = vap->iv_dscp_map_id;
    uint8_t tid = vap->iv_ic->ic_dscp_tid_map[map_id][(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
    ol_txrx_soc_handle soc_txrx_handle;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);

    psoc = wlan_pdev_get_psoc(pdev);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    cdp_set_pdev_dscp_tid_map(soc_txrx_handle,
                              wlan_objmgr_pdev_get_pdev_id(pdev), map_id,
                              tos, tid);
}
void
ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type value = {0};

    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    if (!soc_txrx_handle) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                "%s : %d : soc_txrx_handle is NULL", __func__, __LINE__);
        return;
    }

    /* If Override is disabled: send default TID  else passed the intended tid value */
    if(!ic->ic_override_hmmc_dscp) {
        tid = 0xFF;                 //TBD::Replace it with proper macro
    }

    value.cdp_pdev_param_hmmc_tid = tid;
    cdp_txrx_set_pdev_param(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev), CDP_CONFIG_HMMC_TID_VALUE, value);

    ic->ic_dscp_hmmc_tid = tid;

    /* Send a message to NSS */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_radio_ops && ic->nss_radio_ops->ic_nss_ol_set_hmmc_dscp_tid) {
        ic->nss_radio_ops->ic_nss_ol_set_hmmc_dscp_tid(scn, tid);
    }
#endif
    return;
}

u_int32_t
ol_ath_get_hmmc_tid(struct ieee80211com *ic)
{
    return ic->ic_dscp_hmmc_tid;
}

void
ol_ath_set_hmmc_dscp_override(struct ieee80211com *ic , u_int32_t val)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type value = {0};

    /* If nothing to do just return */
    if(ic->ic_override_hmmc_dscp == val) {
        return;
    }
    ic->ic_override_hmmc_dscp = !!val;

    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    if (!soc_txrx_handle) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                "%s : %d : soc_txrx_handle is NULL", __func__, __LINE__);
        return;
    }

    value.cdp_pdev_param_hmmc_tid_ovrd = !!val;
    cdp_txrx_set_pdev_param(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                            CDP_CONFIG_HMMC_TID_OVERRIDE, value);

    /* Send a message to NSS */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_radio_ops && ic->nss_radio_ops->ic_nss_ol_set_hmmc_dscp_override) {
        ic->nss_radio_ops->ic_nss_ol_set_hmmc_dscp_override(scn, val);
    }
#endif
    return;
}

u_int32_t
ol_ath_get_hmmc_dscp_override(struct ieee80211com *ic)
{
    return ic->ic_override_hmmc_dscp;
}

#endif

void ol_wlan_txpow_mgmt(struct ieee80211vap *vap, uint8_t subtype)
{
    struct wlan_objmgr_psoc *psoc;
    int retval = EOK;

    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        retval = ol_ath_set_vap_beacon_tx_power(vap->vdev_obj,
            vap->iv_txpow_mgt_frm[(subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)]);
    }
    if (retval == EOK){
        psoc = wlan_vdev_get_psoc(vap->vdev_obj);
        cdp_set_mgmt_tx_power(wlan_psoc_get_dp_handle(psoc),
            wlan_vdev_get_id(vap->vdev_obj), subtype,
            vap->iv_txpow_mgt_frm[(subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)]);
    }
return;
}

#if ATH_PROXY_NOACK_WAR
#if WLAN_QWRAP_LEGACY
static OS_TIMER_FUNC(ol_proxy_ast_reserve_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (ic->proxy_ast_reserve_wait.blocking) {
         if(qdf_atomic_dec_and_test(&ic->ic_ast_reserve_event)) {
            ic->ic_ast_reserve_status=-2;
            qdf_semaphore_release(&(ic->proxy_ast_reserve_wait.sem_ptr));
         }
    }
}

static int ol_ath_pdev_proxy_ast_reserve(struct wlan_objmgr_pdev *pdev,
                                         uint8_t *macaddr)
{
    struct proxy_ast_reserve_params param;
    struct wmi_unified *pdev_wmi_handle;
    QDF_STATUS status;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    qdf_mem_set(&param, sizeof(param), 0);
    param.macaddr = macaddr;

    status = wmi_unified_proxy_ast_reserve_cmd_send(pdev_wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

int
ol_ath_pdev_proxy_ast_reserve_event_handler (ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_host_proxy_ast_reserve_param ev;
    struct ieee80211com *ic;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_pdev_reserve_ast_ev_param(wmi_handle, data, &ev))
        return -1;

    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(ev.pdev_id),
                                   WLAN_MLME_SB_ID);
    if (!pdev) {
         qdf_err("pdev object (id: %d) is NULL", PDEV_UNIT(ev.pdev_id));
         return -1;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("ic (id: %d) is NULL", PDEV_UNIT(ev.pdev_id));
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -1;
    }

    OS_CANCEL_TIMER(&(ic->ic_ast_reserve_timer));

    if (ic->proxy_ast_reserve_wait.blocking) {
        if (qdf_atomic_dec_and_test(&ic->ic_ast_reserve_event)) {
           ic->ic_ast_reserve_status = ev.result;
           qdf_info("Status received from FW: event->result = %d", ev.result);
           qdf_info("ic->ic_ast_reserve_status=%d", ic->ic_ast_reserve_status);
           qdf_semaphore_release(&(ic->proxy_ast_reserve_wait.sem_ptr));
        }
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    return 0;
}

int32_t ol_ioctl_get_proxy_noack_war(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int war_enable;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;

    if(scn->sc_proxy_noack_war) {
        war_enable = 1;
    } else {
        war_enable = 0;
    }
    qwrap_config->proxy_noack_war = war_enable;
    return 0;
}

int32_t ol_ioctl_reserve_proxy_macaddr(struct ol_ath_softc_net80211 *scn, caddr_t *param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int error = 0;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;
    struct {
        u8 addr[6];
        int status;
    } psta_addr_reserve;

    if (!scn->sc_proxy_noack_war)
        return -1;

    ic->ic_ast_reserve_status= -1;

    if (OS_CANCEL_TIMER(&(ic->ic_ast_reserve_timer))) {
        error = _copy_to_user((caddr_t)param , &psta_addr_reserve,
                              sizeof(psta_addr_reserve));
        return error;
    }

    qdf_info("mac_addr =%s", ether_sprintf(qwrap_config->addr));

    qdf_atomic_init(&(ic->ic_ast_reserve_event));

    qdf_atomic_inc(&(ic->ic_ast_reserve_event));

    OS_SET_TIMER(&ic->ic_ast_reserve_timer, TARGET_AST_RESERVE_TIMEOUT *2000);

    ol_ath_pdev_proxy_ast_reserve(ic->ic_pdev_obj, qwrap_config->addr);

    if (ic->proxy_ast_reserve_wait.blocking) {
       qdf_semaphore_acquire(&(ic->proxy_ast_reserve_wait.sem_ptr));
    }

    qwrap_config->status = ic->ic_ast_reserve_status;

    error = _copy_to_user((caddr_t)param , qwrap_config, sizeof(psta_addr_reserve));

    qdf_info("status=%d error = %d", qwrap_config->status, error);

    return error;
}
#endif
#endif

#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
void ol_ioctl_disassoc_clients(struct ol_ath_softc_net80211 *scn)
{
	struct ieee80211com *ic = &scn->sc_ic;
	struct ieee80211vap           *tmp_vap;
	struct ieee80211com           *tmp_ic;
	int i=0;

	for (i=0; i < MAX_RADIO_CNT; i++) {
		tmp_ic = ic->ic_global_list->global_ic[i];
		if (tmp_ic) {
			TAILQ_FOREACH(tmp_vap, &tmp_ic->ic_vaps, iv_next) {
				if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
				    (wlan_vdev_is_up(tmp_vap->vdev_obj) == QDF_STATUS_SUCCESS)) {
					wlan_iterate_station_list(tmp_vap, sta_disassoc, NULL);
				}
			}
		}
	}
}
#endif


#if  ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
int32_t ol_ioctl_get_primary_radio(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int primary_radio;
    struct ieee80211com *ic = &scn->sc_ic;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;

    if(ic->ic_primary_radio) {
        primary_radio = 1;
    } else {
        primary_radio = 0;
    }
    qwrap_config->primary_radio = primary_radio;
    return 0;
}

int32_t ol_ioctl_get_mpsta_mac_addr(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *mpsta_vap = NULL;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;
#if WLAN_QWRAP_LEGACY
    mpsta_vap = ic->ic_mpsta_vap;
#else
    mpsta_vap = wlan_get_vap(dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj));
#endif
    if (mpsta_vap == NULL)
    {
        return -EFAULT;
    }
    qdf_mem_copy(qwrap_config->addr, mpsta_vap->iv_myaddr, QDF_MAC_ADDR_SIZE);
    return 0;
}

int32_t ol_ioctl_get_force_client_mcast(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int force_client_mcast;
    struct ieee80211com *ic = &scn->sc_ic;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;

    if(ic->ic_global_list->force_client_mcast_traffic) {
        force_client_mcast = 1;
    } else {
        force_client_mcast = 0;
    }

    qwrap_config->force_client_mcast = force_client_mcast;
    return 0;
}

int32_t ol_ioctl_get_max_priority_radio(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    char wifi_iface[IFNAMSIZ];
    struct ieee80211com *ic = &scn->sc_ic;
    struct global_ic_list   *glist = ic->ic_global_list;
    struct ieee80211vap           *max_priority_stavap_up;
    struct ieee80211com *max_priority_ic;
    struct net_device *n_dev;
    struct qwrap_config_t *qwrap_config = (struct qwrap_config_t *)param;

    memset(&wifi_iface[0], 0, sizeof(wifi_iface));
    GLOBAL_IC_LOCK_BH(glist);
    max_priority_stavap_up = glist->max_priority_stavap_up;
    GLOBAL_IC_UNLOCK_BH(glist);
    if (max_priority_stavap_up &&
        (wlan_vdev_is_up(max_priority_stavap_up->vdev_obj) == QDF_STATUS_SUCCESS)) {
	max_priority_ic = max_priority_stavap_up->iv_ic;
	n_dev = max_priority_ic->ic_netdev;
	OS_MEMCPY(wifi_iface, n_dev->name, sizeof(wifi_iface));
	qdf_info("max priority radio:%s",wifi_iface);
    }
    memcpy(&qwrap_config->max_priority_radio, wifi_iface, IFNAMSIZ);
    return 0;
}

void ol_ioctl_iface_mgr_status(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct iface_config_t *iface_config = (struct iface_config_t *)param;
    u_int8_t iface_mgr_up = iface_config->iface_mgr_up;

    GLOBAL_IC_LOCK_BH(ic->ic_global_list);
    if ((iface_mgr_up) == 1) {
        ic->ic_global_list->iface_mgr_up = 1;
        qdf_info("setting iface_mgr_up to 1");
    } else {
        ic->ic_global_list->iface_mgr_up = 0;
        qdf_info("setting iface_mgr_up to 0");
    }
    GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
}
#endif

u_int8_t ol_ioctl_get_stavap_connection(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    u_int8_t stavap_up;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *stavap = ic->ic_sta_vap;
    struct iface_config_t *iface_config = (struct iface_config_t *)param;

    if (!stavap) {
        qdf_info("stavap not up for: %pK", scn);
        return -EINVAL;
    }

    if (wlan_vdev_is_up(stavap->vdev_obj) == QDF_STATUS_SUCCESS) {
        stavap_up = 1;
    } else {
        stavap_up = 0;
    }
    iface_config->stavap_up = stavap_up;
    return 0;
}

#if DBDC_REPEATER_SUPPORT
u_int16_t ol_ioctl_get_disconnection_timeout(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    u_int16_t timeout;
    struct ieee80211com *ic = &scn->sc_ic;
    struct iface_config_t *iface_config = (struct iface_config_t *)param;
    u_int16_t disconnect_timeout = ic->ic_global_list->disconnect_timeout;
    u_int16_t reconfiguration_timeout = ic->ic_global_list->reconfiguration_timeout;

    if (disconnect_timeout >= reconfiguration_timeout) {
        timeout = disconnect_timeout;
        qdf_info("disconnect_timeout:%d",disconnect_timeout);
    } else {
        timeout = reconfiguration_timeout;
        qdf_info("reconfiguration_timeout:%d",reconfiguration_timeout);
    }

    iface_config->timeout = timeout;
    return 0;
}

int32_t ol_ioctl_get_preferred_uplink(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int preferredUplink;
    struct ieee80211com *ic = &scn->sc_ic;
    struct iface_config_t *iface_config = (struct iface_config_t *)param;

    if(ic->ic_preferredUplink) {
        preferredUplink = 1;
    } else {
        preferredUplink = 0;
    }

    iface_config->is_preferredUplink = preferredUplink;
    return 0;
}
#endif

int32_t ol_ioctl_get_chan_vendorsurvey_info(struct ol_ath_softc_net80211 *scn,
        caddr_t param)
{
    int i;
    struct ieee80211com *ic = &scn->sc_ic;
    struct scan_chan_info *src_chan_info;
    struct extacs_chan_info *dest_chan_info = (struct extacs_chan_info *)param;
    struct external_acs_obj *extacs_handle = &ic->ic_extacs_obj;

    qdf_spin_lock(&extacs_handle->chan_info_lock);
    for (i = 0; i < NUM_MAX_CHANNELS; i++) {
        src_chan_info = &ic->ic_extacs_obj.chan_info[i];
        dest_chan_info->cycle_count = 0;
        dest_chan_info->channel_load = src_chan_info->chan_load;
        dest_chan_info->period = 0;
        dest_chan_info->noisefloor = src_chan_info->noise_floor;
        dest_chan_info->comp_usablity = 0;
        dest_chan_info->comp_usablity_sec80 = 0;
        dest_chan_info->max_regulatory_power = 0;
        dest_chan_info->max_regulatory_power_sec80 = 0;
        dest_chan_info->tx_power_tput = src_chan_info->tx_power_tput;
        dest_chan_info->tx_power_range = src_chan_info->tx_power_range;
        dest_chan_info++;
    }
    qdf_spin_unlock(&extacs_handle->chan_info_lock);

    return 0;
}

#if defined(WLAN_DISP_CHAN_INFO)
QDF_STATUS ol_ioctl_get_chan_info(struct ieee80211com *ic,
                                  struct ieee80211req_chaninfo_full *req_chan)
{
    struct ieee80211req_chaninfo *req_chan_info = &req_chan->req_chan_info;
    enum channel_dfs_state *dfs_ch_s =
        (enum channel_dfs_state *) req_chan->dfs_chan_state_arr;
    wlan_radio_get_chan_info(ic, true, req_chan_info->ic_chans, NULL,
                             &req_chan_info->ic_nchans);

    return utils_dfs_get_chan_dfs_state(ic->ic_pdev_obj, dfs_ch_s);
}
#endif /* WLAN_DISP_CHAN_INFO */

#if MESH_MODE_SUPPORT
extern void ieee80211_check_timeout_mesh_peer(void *arg, wlan_if_t vaphandle);
#endif

static void
ieee80211_reset_auth_fail_cnt(void *arg, wlan_if_t vaphandle)
{
    vaphandle->cont_auth_fail = 0;
}

/*
 * Per-ieee80211com timer callback.
 * used for checking any timeouts in the
 * COM device.
 */
static OS_TIMER_FUNC(ol_ath_timeout)
{
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_soc_softc *soc;
    wmi_unified_t pdev_wmi_handle;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (ic == NULL)
        return;

    /* Don't process timeout when recovery in progress */
    if (ic->recovery_in_progress) {
       return ;
    }

    ieee80211_session_timeout(ic);
    ieee80211_noassoc_sta_timeout(ic);
    ieee80211_vap_mlme_inact_erp_timeout(ic);
    scn =  OL_ATH_SOFTC_NET80211(ic);

    if (!scn || !scn->soc) {
        return;
    }
    soc = scn->soc;

    wlan_iterate_vap_list(ic, ieee80211_reset_auth_fail_cnt, NULL);
#if MESH_MODE_SUPPORT
    /* check & delete timed out mesh peers */
    wlan_iterate_vap_list(ic, ieee80211_check_timeout_mesh_peer, NULL);
#endif

    OS_SET_TIMER(&ic->ic_inact_timer, IEEE80211_SESSION_WAIT*1000);
    if (scn->scn_wmi_dis_dump && soc->soc_attached) {
        if (qdf_ktime_to_ms(qdf_ktime_get()) - scn->last_sent_time >
                                 (scn->scn_wmi_hang_wait_time*1000)) {
            pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
            ol_ath_set_fw_hang(pdev_wmi_handle,
                               scn->scn_wmi_hang_after_time*1000);
            scn->last_sent_time = qdf_ktime_to_ms(qdf_ktime_get());
        }
    }
}

static bool
ol_ath_support_phy_mode(struct ieee80211com *ic, enum ieee80211_phymode mode)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t cur_rx_mask = ieee80211com_get_rx_chainmask(ic);
    u_int8_t cur_tx_mask = ieee80211com_get_tx_chainmask(ic);
    bool rx_mask_is_valid = false;
    bool tx_mask_is_valid = false;
    uint32_t target_type;

    target_type = lmac_get_tgt_type(scn->soc->psoc_obj);

    /* For Lithium onwards */
    if (ol_target_lithium(scn->soc->psoc_obj)) {

        /* Validate TX & RX Chain mask for a given PHY mode */
        rx_mask_is_valid = ol_ath_validate_chainmask(scn, cur_rx_mask,
                VALIDATE_RX_CHAINMASK, mode);
        tx_mask_is_valid = ol_ath_validate_chainmask(scn, cur_tx_mask,
                VALIDATE_TX_CHAINMASK, mode);

        if (!rx_mask_is_valid || !tx_mask_is_valid)
            return false;
    } else {
        if (ieee80211_is_phymode_160_or_8080(mode)) {
            if (target_type == TARGET_TYPE_QCA9984) {
                /* Note: In case
                 * IEEE80211_MODE_11AXA_HE160/IEEE80211_MODE_11AXA_HE80_80 are used
                 * with TARGET_TYPE_QCA9984, then there is a separate code block
                 * which checks whether these modes are available for
                 * TARGET_TYPE_QCA9984 (via stubbing).
                 */

                /* 160 and 80+80 modes are allowed only with the following chainmasks
                 * in Cascade */
                switch (cur_rx_mask) {
                    case 0x5:
                    case 0x6:
                        /*
                         * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                         * QCA9984
                         */
                    case 0x7:
                    case 0x9:
                    case 0xa:
                    case 0xc:
                    case 0xf:
                        rx_mask_is_valid = true;
                        break;
                    default:
                        return false;
                }

                switch (cur_tx_mask) {
                    case 0x5:
                    case 0x6:
                        /*
                         * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                         * QCA9984
                         */
                    case 0x7:
                    case 0x9:
                    case 0xa:
                    case 0xc:
                    case 0xf:
                        if(rx_mask_is_valid)
                            return true;
                        else
                            return false;
                    default:
                        return false;
                }
            } else if (target_type == TARGET_TYPE_QCA9888 ) {
                switch (cur_rx_mask) {
                    /* 160 and 80+80 modes are allowed only with the following
                     * chainmasks in QCA9888 */
                    case 0x3:
                        return true;
                    default:
                        return false;
                }
            }
        }
    }
    /* Currently this function is used to validate 160/80+80 MHz vs. chainmask
     * compatibility for 160/80+80 MHz capable chipsets. Return true for other
     * cases.
     */
    return true;
}

static int
ol_ath_get_bw_nss_mapping(struct ieee80211vap *vap,
                          struct ieee80211_bwnss_map *nssmap, uint8_t chainmask)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    int error = 0;
    uint32_t target_type;
    enum ieee80211_phymode cur_mode;
    uint32_t iv_nss;

    target_type =  lmac_get_tgt_type(psoc);

    /* Enabling STA max caps (if enabled through the flag) */
    if (vap->iv_sta_max_ch_cap) {
        cur_mode = vap->iv_des_mode;
    } else {
        cur_mode = vap->iv_cur_mode;
    }

    if (ieee80211_is_phymode_160_or_8080(cur_mode)) {
        if (target_type == TARGET_TYPE_QCA9984) {
            /* 160 and 80+80 modes are allowed only with the following chainmasks
             * in QCA9984. */
            switch (chainmask) {
                case 0x5:
                case 0x6:
                /*
                 * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                 * QCA9984
                 */
                case 0x7:
                case 0x9:
                case 0xa:
                case 0xc:
                    nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_1x1;
                    break;
                case 0xf:
                    nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_2x2;
                    break;
                default:
                    error = -EINVAL;
            }
        } else if (target_type == TARGET_TYPE_QCA9888) {
            /* 160 and 80+80 modes are allowed only with the following chainmasks
             * in QCA9888.
             */
                switch (chainmask) {
                    case 0x3:
                        nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_1x1;
                        break;
                    default:
                        error = -EINVAL;
                }
        } else if ((target_type == TARGET_TYPE_QCA8074) ||
			(target_type == TARGET_TYPE_QCA8074V2) ||
			(target_type == TARGET_TYPE_QCN9000) ||
			(target_type == TARGET_TYPE_QCN6122) ||
			(target_type == TARGET_TYPE_QCA5018) ||
			(target_type == TARGET_TYPE_QCA6018)) {
            ieee80211_compute_nss(ic, chainmask, nssmap);
        } else {
            /* Currently this function is used to find valid 160MHz NSS map for
             * 160/80+80 MHz capable chipsets based on the rx_chainmask
             * configured. Return error for other cases */
            error = -EINVAL;
        }
    } else {
        /* Currently this function is used to find valid 160MHz NSS map for
         * 160/80+80 MHz capable chipsets based on the rx_chainmask configured.
         * Return error for other cases */
        error = -EINVAL;
    }

    wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
            WLAN_MLME_CFG_NSS, &iv_nss);
    if ((error != -EINVAL) && (iv_nss != 0)) {

#define IS_FACTOR_1_2_OF_MAX_NSS(x, y) ((8 * x) <= (5 * y))

        nssmap->bw_nss_160 = QDF_MIN(iv_nss, nssmap->bw_nss_160);
        if (nssmap->bw_nss_160 == iv_nss) {
            /* Same for all bandwidth */
            nssmap->flag = IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW;
        } else if(IS_FACTOR_1_2_OF_MAX_NSS(nssmap->bw_nss_160, iv_nss)) {
            /* 1/2 case */
            nssmap->bw_nss_160 = iv_nss >> 1;
            nssmap->flag = IEEE80211_NSSMAP_1_2_FOR_160_AND_80_80;
        } else {
            /* 3/4 case */
            nssmap->flag = IEEE80211_NSSMAP_3_4_FOR_160_AND_80_80;
        }
    }

    return error;
}

static int
ol_ath_net80211_addba_responsesetup(struct ieee80211_node *ni, uint8_t tidno,
                                    uint8_t *dialogtoken, uint16_t *statuscode,
                                    struct ieee80211_ba_parameterset *baparamset,
                                    uint16_t *batimeout)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_peer *peer = ni->peer_obj;
    struct wlan_objmgr_vdev *vdev = wlan_peer_get_vdev(peer);
    uint16_t buffersize;

    if (!(soc_txrx_handle = wlan_psoc_get_dp_handle(psoc)))
        return QDF_STATUS_E_CANCELED;

    baparamset->amsdusupported = IEEE80211_BA_AMSDU_SUPPORTED;

    if (ieee80211com_get_rx_amsdu(ic, tidno) == 0) {
        baparamset->amsdusupported = !IEEE80211_BA_AMSDU_SUPPORTED;
    }

    baparamset->bapolicy = IEEE80211_BA_POLICY_IMMEDIATE;
    baparamset->tid = tidno;
    if (cdp_addba_responsesetup(soc_txrx_handle, peer->macaddr, wlan_vdev_get_id(vdev),
              tidno, dialogtoken, statuscode, &buffersize, batimeout) != QDF_STATUS_SUCCESS)
        return QDF_STATUS_E_FAILURE;

    baparamset->buffersize = buffersize;
    return 0;
}

static int ol_ath_net80211_addba_resp_tx_completion(struct ieee80211_node *ni,
                                                    uint8_t tidno, int status)
{
    struct ieee80211com *ic = ni->ni_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_peer *peer = ni->peer_obj;
    struct wlan_objmgr_vdev *vdev = wlan_peer_get_vdev(peer);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    return cdp_addba_resp_tx_completion(soc_txrx_handle, peer->macaddr,
             wlan_vdev_get_id(vdev), tidno, status);
}

static int
ol_ath_net80211_addba_requestprocess(struct ieee80211_node *ni,
                                     uint8_t dialogtoken,
                                     struct ieee80211_ba_parameterset *baparamset,
                                     uint16_t batimeout,
                                     struct ieee80211_ba_seqctrl basequencectrl)
{
    struct ieee80211com *ic = ni->ni_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_peer *peer = ni->peer_obj;
    struct wlan_objmgr_vdev *vdev = wlan_peer_get_vdev(peer);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    return cdp_addba_requestprocess(soc_txrx_handle, peer->macaddr,
                                    wlan_vdev_get_id(vdev), dialogtoken,
                                    baparamset->tid, batimeout,
                                    baparamset->buffersize,
                                    basequencectrl.startseqnum);
}

static void
ol_ath_net80211_delba_process(struct ieee80211_node *ni,
                              struct ieee80211_delba_parameterset *delbaparamset,
                              uint16_t reasoncode)
{
    struct ieee80211com *ic = ni->ni_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_peer *peer = ni->peer_obj;
    struct wlan_objmgr_vdev *vdev = wlan_peer_get_vdev(peer);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    cdp_delba_process(soc_txrx_handle, peer->macaddr,  wlan_vdev_get_id(vdev),
                        delbaparamset->tid, reasoncode);
}

static int ol_ath_net80211_delba_tx_completion(struct ieee80211_node *ni,
                                               uint8_t tidno, int status)
{

    struct ieee80211com *ic = ni->ni_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_peer *peer = ni->peer_obj;
    struct wlan_objmgr_vdev *vdev = wlan_peer_get_vdev(peer);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    return cdp_delba_tx_completion(soc_txrx_handle, peer->macaddr,
                                   wlan_vdev_get_id(vdev), tidno, status);
}

static int ol_ath_get_target_phymode(struct ieee80211com *ic, uint32_t phymode,
                                     bool is_2gvht_en)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return ol_get_phymode_info(scn, phymode, is_2gvht_en);
}

#ifdef WLAN_SUPPORT_RF_CHARACTERIZATION
#if ATH_ACS_DEBUG_SUPPORT
static int
ol_ath_set_chan_grade_info(struct ieee80211com *ic,
                           void* channel_events, uint8_t nchan)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    struct acs_debug_chan_event_container *chan = (struct acs_debug_chan_event_container *)channel_events;
    uint8_t ix;

    if (!soc) {
        qdf_err("Invalid soc");
        return -EINVAL;
    }

    if (soc->rf_characterization_entries) {
        qdf_mem_free(soc->rf_characterization_entries);
        soc->num_rf_characterization_entries = 0;
    }

    /*
     * NOTE: Since the rf_characterization_entries is maintained outside the scope
     *       of the ACS debug framework, the responsibility to free it is left
     *       as is.
     */
    soc->num_rf_characterization_entries = nchan;
    soc->rf_characterization_entries = qdf_mem_malloc(soc->num_rf_characterization_entries *
                                       sizeof(*soc->rf_characterization_entries));

    if (!soc->rf_characterization_entries) {
        soc->num_rf_characterization_entries = 0;
        qdf_info("Could not allocate space for rf_characterization_entries");
        return -EINVAL;
    }

    qdf_mem_zero(soc->rf_characterization_entries,
                 soc->num_rf_characterization_entries * sizeof(*soc->rf_characterization_entries));

    for (ix = 0; ix < soc->num_rf_characterization_entries; ix++) {
        soc->rf_characterization_entries[ix].freq = chan->event[ix].channel_freq;
        /* Bandwidth is currently being set to zero by default*/
        soc->rf_characterization_entries[ix].bw = 0;
        soc->rf_characterization_entries[ix].chan_metric = chan->event[ix].channel_rf_characterization;
    }

    return 0;
}
#endif

static void
ol_ath_get_chan_grade_info(struct ieee80211com *ic, uint32_t *hw_chan_grade_list)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    uint16_t ieee_chan;
    int i;

    if (!soc) {
        qdf_err("Invalid soc");
        return;
    }

    if (!soc->rf_characterization_entries) {
        qdf_err("RF characterization entries is empty");
        return;
    }

    for (i = 0; i < soc->num_rf_characterization_entries; i++) {
        ieee_chan = ieee80211_acs_get_chan_idx(ic->ic_acs, soc->rf_characterization_entries[i].freq);

        if (soc->rf_characterization_entries[i].bw != WMI_HOST_CHAN_WIDTH_20) {
            /*
             * Channel metrics for bandwidths other than 20MHz are not
             * supported.
             */
            qdf_info("Skipping non-20MHz RF characterization entries");
            continue;
        }

        if (ieee_chan < IEEE80211_CHAN_MAX) {
            /* hw_chan_grade_list is an array of size IEE80211_CHAN_MAX */
            hw_chan_grade_list[ieee_chan] = soc->rf_characterization_entries[i].chan_metric;
        }
    }

    return;
}
#endif

static inline QDF_STATUS
ol_ath_config_full_mon_support(struct ol_ath_soc_softc *soc, uint8_t val)
{
    int target_type = lmac_get_tgt_type(soc->psoc_obj);

    if (target_type != TARGET_TYPE_QCN9000) {
        qdf_err("Full monitor mode is not suported for target_type: %d", target_type);
        return QDF_STATUS_SUCCESS;
    }

    if (!cfg_get(soc->psoc_obj, CFG_DP_FULL_MON_MODE)) {
        qdf_err("Full monitor is not supported");
        return QDF_STATUS_E_FAILURE;
    }

    if (val) {
       if (soc->full_mon_mode_support) {
           qdf_debug("Full monitor mode support is already enabled");
           return QDF_STATUS_E_FAILURE;
       }
    } else {
       if (!soc->full_mon_mode_support) {
           qdf_debug("Full monitor mode support is already disabled");
           return QDF_STATUS_E_FAILURE;
       }
    }
    soc->full_mon_mode_support = val;
    cdp_soc_config_full_mon_mode(wlan_psoc_get_dp_handle(soc->psoc_obj), val);
    qdf_info("Full monitor mode configured for qcn9000 target_type: %d val: %d ", target_type, val);

    return QDF_STATUS_SUCCESS;
}

static int ol_ath_set_stats_update_period(struct ieee80211vap *vap,
                                          uint32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    uint32_t target_version = lmac_get_tgt_version(soc->psoc_obj);

    if ((target_version == AR9887_REV1_VERSION) ||
        (target_version == AR9888_REV1_VERSION) ||
        (target_version == AR9888_REV2_VERSION) ||
        (target_version == AR9888_DEV_VERSION)  ||
        (target_version == QCA9984_DEV_VERSION)) {

        if ((val < PDEV_MIN_STATS_UPDATE_PERIOD && val != 0)
            || val > PDEV_DEFAULT_STATS_UPDATE_PERIOD) {
            qdf_err("Invalid update period, should be in range[%d,%d]",
                     PDEV_MIN_STATS_UPDATE_PERIOD,
                     PDEV_DEFAULT_STATS_UPDATE_PERIOD);
            return -EINVAL;
        }
        val = (val == 0)? PDEV_DEFAULT_STATS_UPDATE_PERIOD : val;
        /* set the pdev stats update period*/
        ol_ath_pdev_set_param(scn->sc_pdev,
                              wmi_pdev_param_pdev_stats_update_period, val);
    } else {
        qdf_err("Target not supported for this cmd");
        return -EINVAL;
    }

    return 0;
}

int
ol_ath_dev_attach(struct ol_ath_softc_net80211 *scn,
                   IEEE80211_REG_PARAMETERS *ieee80211_conf_parm)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ol_ath_soc_softc_t *soc = scn->soc;
    int error = 0;
    spin_lock_init(&ic->ic_lock);
    spin_lock_init(&ic->ic_main_sta_lock);
    spin_lock_init(&ic->ic_addba_lock);
    IEEE80211_STATE_LOCK_INIT(ic);
    spin_lock_init(&ic->ic_beacon_alloc_lock);

    spin_lock_init(&ic->ic_state_check_lock);
    spin_lock_init(&ic->ic_radar_found_lock);
    spin_lock_init(&ic->ic_radar_mode_switch_lock);
    /* attach channel width management */
    error = ol_ath_cwm_attach(scn);
    if (error) {
        qdf_err("ol_ath_cwm_attach failed");
        return error;
    }

    /* XXX not right but it's not used anywhere important */
    ieee80211com_set_phytype(ic, IEEE80211_T_OFDM);

    /*
     * Set the Atheros Advanced Capabilities from station config before
     * starting 802.11 state machine.
     */
     /* TBD */

    /* this matches the FW default value */
    scn->arp_override = WME_AC_VO;
    scn->igmpmld_override = 0;
    scn->igmpmld_tid = 0;

    /* set default mgmt retry limit */
    scn->scn_mgmt_retry_limit = DEFAULT_MGMT_RETRY_LIMIT;

    /* Set the mac address */

    /* Setup Min frame size */
    ic->ic_minframesize = sizeof(struct ieee80211_frame_min);

    ic->id_mask_vap_downed[VDEV_BITMAP_SLOT0] = 0;
    ic->id_mask_vap_downed[VDEV_BITMAP_SLOT1] = 0;

    /*
     * Setup some device specific ieee80211com methods
     */
    ic->ic_init = ol_ath_init;
    ic->ic_reset_start = ol_ath_reset_start;
    ic->ic_reset = ol_ath_reset;
    ic->ic_reset_end = ol_ath_reset_end;
    ic->ic_wme.wme_update = ol_ath_wmm_update;
    ic->ic_txq_depth = ol_ath_txq_depth;
    ic->ic_txq_depth_ac = ol_ath_txq_depth_ac;
    ic->ic_chwidth_change = ol_net80211_chwidth_change;
    ic->ic_nss_change = ol_net80211_nss_change;
    ic->ic_ext_nss_change = ol_net80211_ext_nss_change;
    ic->ic_frame_injector_config = ol_ath_frame_injector_config;
    ic->ic_ar900b_fw_test = ol_ath_ar900b_fw_test;
    ic->ic_fw_unit_test = ol_ath_fw_unit_test;
    ic->ic_coex_cfg = ol_ath_coex_cfg;
#if UNIFIED_SMARTANTENNA
    ic->ic_set_ant_switch = ol_ath_set_ant_switch_tbl;
#endif
    ic->ic_set_ctrl_table = ol_ath_set_ctl_table;
    ic->ic_set_beacon_interval = ol_set_beacon_interval;
    ic->ic_set_sta_fixed_rate = ol_net80211_set_sta_fixed_rate;
    ic->ic_support_phy_mode = ol_ath_support_phy_mode;
    ic->ic_get_bw_nss_mapping = ol_ath_get_bw_nss_mapping;

#if ATH_SUPPORT_VOW_DCS
	/* host side umac compiles with this flag, so we have no
	   option than writing this with flag, otherwise the other
	   drivers in oher OSes would fail*/
    ic->ic_disable_dcsim = ol_ath_disable_dcsim;
    ic->ic_enable_dcsim = ol_ath_enable_dcsim;
#endif
    ic->ic_disable_dcscw = ol_ath_disable_dcscw;
    ic->ic_dcs_restore = ol_ath_dcs_restore;
    ic->ic_fips_test = ol_ath_fips_test;
    /* Handles UTF commands from FTM daemon */
#if UMAC_SUPPORT_CFG80211
    ic->ic_ucfg_testmode_cmd = ol_ath_ucfg_utf_unified_cmd;
#endif
    ic->ic_set_peer_latency_param_config =
                      ol_ath_set_peer_latency_param_config;
    /* Attach twt */
    ol_ath_twt_attach(ic);
    ol_ath_kbps_to_mcs(soc, ic);
    ol_ath_ratecode_to_kbps(soc, ic);
    ol_ath_get_supported_rates(soc, ic);
    /* Attach resmgr module */
    ol_ath_resmgr_attach(ic);

    ol_ath_power_attach(ic);
    ic->ic_is_target_lithium = ol_target_lithium;

    /*
     * Attach ieee80211com object to net80211 protocal stack.
     */
    error = ieee80211_ifattach(ic, ieee80211_conf_parm);
    if (error) {
        qdf_err("ieee80211_ifattach failed error : %d", error);
        return error;
    }

    qdf_spinlock_create(&ic->ic_channel_stats.lock);
     /*
     * Complete device specific ieee80211com methods init
     */
    ic->ic_set_channel = ol_ath_set_channel;
    ic->ic_enable_radar = ol_ath_net80211_enable_radar;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    ic->ic_enable_sta_radar = NULL;
#endif

    ic->ic_pwrsave_set_state = ol_ath_pwrsave_set_state;
    ic->ic_get_noisefloor = ol_ath_get_noisefloor;
    ic->ic_get_chainnoisefloor = ol_ath_get_chainnoisefloor;
    ic->ic_set_txPowerLimit = ol_ath_setTxPowerLimit;
    ic->ic_get_common_power = ol_ath_get_common_power;
    ic->ic_get_TSF32        = ol_ath_getTSF32;
    ic->ic_rmgetcounters = ol_ath_getrmcounters;
    ic->ic_get_wpsPushButton = ol_ath_wpsPushButton;
    ic->ic_clear_phystats = ol_ath_clear_phystats;
    ic->ic_set_macaddr = ol_ath_set_macaddr;
    ic->ic_log_text = ol_ath_log_text;
    ic->ic_log_text_bh = ol_ath_log_text_bh;
    ic->ic_set_chain_mask = ol_ath_set_chain_mask;
    ic->ic_get_mfpsupport = ol_ath_getmfpsupport;
    ic->ic_set_hwmfpQos   = ol_ath_setmfpQos;
    ic->ic_get_tx_hw_retries  = ol_ath_get_tx_hw_retries;
    ic->ic_get_tx_hw_success  = ol_ath_get_tx_hw_success;
    ic->ic_rate_node_update = ol_ath_rate_node_update;
#if ATH_SUPPORT_IQUE
    ic->ic_set_acparams = ol_ath_set_acparams;
    ic->ic_set_rtparams = ol_ath_set_rtparams;
    ic->ic_get_iqueconfig = ol_ath_get_iqueconfig;
    ic->ic_set_hbrparams = ol_ath_set_hbrparams;
#endif
    ic->ic_set_config = ol_ath_set_config;
    ic->ic_set_config_enable = ol_ath_set_config_enable;
    ic->ic_set_safemode = ol_ath_set_safemode;
    ic->ic_set_privacy_filters = ol_ath_set_privacy_filters;
    /* rx monitor filter */
    ic->ic_set_rx_monitor_filter = ol_ath_set_rx_monitor_filter;

    ic->ic_addba_responsesetup = ol_ath_net80211_addba_responsesetup;
    ic->ic_addba_requestprocess = ol_ath_net80211_addba_requestprocess;
    ic->ic_addba_resp_tx_completion = ol_ath_net80211_addba_resp_tx_completion;
    ic->ic_delba_process = ol_ath_net80211_delba_process;
    ic->ic_delba_tx_completion = ol_ath_net80211_delba_tx_completion;
#ifdef ATH_SUPPORT_TxBF // For TxBF RC

#if WLAN_OBJMGR_REF_ID_TRACE
    ic->ic_ieee80211_find_node_debug = ieee80211_find_node_debug;
#else
    ic->ic_ieee80211_find_node = ieee80211_find_node;
#endif //WLAN_OBJMGR_REF_ID_TRACE
    ic->ic_v_cv_send = ol_ath_net80211_v_cv_send;
    ic->ic_txbf_alloc_key = ol_ath_net80211_txbf_alloc_key;
    ic->ic_txbf_set_key = ol_ath_net80211_txbf_set_key;
    ic->ic_txbf_del_key = ol_ath_net80211_txbf_del_key;
    ic->ic_init_sw_cv_timeout = ol_ath_net80211_init_sw_cv_timeout;
    ic->ic_set_txbf_caps = ol_ath_set_txbfcapability;
#ifdef TXBF_DEBUG
	ic->ic_txbf_check_cvcache = ol_ath_net80211_txbf_check_cvcache;
#endif
    ic->ic_txbf_stats_rpt_inc = ol_ath_net80211_txbf_stats_rpt_inc;
    ic->ic_txbf_set_rpt_received = ol_ath_net80211_txbf_set_rpt_received;
#endif
    ic->ic_get_cur_chan_nf = ol_ath_net80211_get_cur_chan_noisefloor;
    ic->ic_get_cur_hw_nf = ol_ath_net80211_get_cur_hw_nf;
    ic->ic_set_rxfilter = ol_ath_set_rxfilter;
    ic->ic_set_ctl_table = ol_ath_set_ctl_table;
    ic->ic_set_mimogain_table = ol_ath_set_mimogain_table;
    ic->ic_ratepwr_table_ops = ol_ath_ratepwr_table_ops;
    ic->ic_set_mgmt_retry_limit = ol_ath_set_mgmt_retry_limit;
    ic->ic_tr69_request_process = ol_ath_net80211_tr69_process_request;
    ic->wide_band_scan_enabled = ol_ath_wide_band_scan;
    ic->ic_get_target_phymode = ol_ath_get_target_phymode;
    if (ol_target_lithium(soc->psoc_obj))
        ic->ic_print_peer_refs = ol_ath_print_peer_refs;
    else
        ic->ic_print_peer_refs = NULL;
#if ATH_SUPPORT_DFS && QCA_DFS_NOL_VAP_RESTART
    ic->ic_pause_stavap_scan = 0;
#endif

    /*
     * In Offload case 'inactivity' is handled in the firmware.
     * So override the default function with a different one to handle other timeouts.
     */
    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_inact_timer), ol_ath_timeout,
            (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);

    ic->ic_nl_handle = NULL;
#if QCA_LTEU_SUPPORT
    ol_ath_nl_attach(ic);
#endif

    /*
     * pktlog scn initialization
     */
#ifndef REMOVE_PKT_LOG
    if(enable_pktlog_support)
        ol_pktlog_attach(scn);
#endif

#ifdef QCA_PARTNER_PLATFORM
    ic->partner_com_params.ipc_ol_txrx_ast_find_hash_find = ol_txrx_ast_find_hash_find;
    ic->partner_com_params.ipc_ol_txrx_peer_find_by_id = ol_txrx_peer_find_by_id;
    ic->partner_com_params.ipc_ol_ath_getvap = ol_ath_getvap;
#endif
#ifdef CONFIG_DP_TRACE
    ic->ic_dptrace_set_param = ol_ath_dptrace_setparam;
#endif

    ol_if_eeprom_attach(ic);

    ol_ath_wow_attach(ic);
#if  ATH_DATA_TX_INFO_EN
    ol_ath_stats_attach(ic);
#endif

#if ATH_OL_FAST_CHANNEL_RESET_WAR
    ol_ath_fast_chan_change(scn->sc_pdev);
#endif

    ic->ic_no_vlan = 0;
    ic->ic_atf_logging = 0;
    ic->ic_set_pcp_tid_map = ol_ath_set_vap_pcp_tid_map;
    ic->ic_set_tidmap_tbl_id = ol_ath_set_vap_tidmap_tbl_id;
    ic->ic_set_tidmap_prty = ol_ath_set_vap_tidmap_prty;
#ifdef WLAN_SUPPORT_RF_CHARACTERIZATION
#if ATH_ACS_DEBUG_SUPPORT
    ic->ic_set_chan_grade_info = ol_ath_set_chan_grade_info;
#endif
    ic->ic_get_chan_grade_info = ol_ath_get_chan_grade_info;
#endif
    ic->ic_set_stats_update_period = ol_ath_set_stats_update_period;
    ic->ic_assemble_ratecode = ol_ath_assemble_ratecode;
    return EOK;
}

int
ol_asf_adf_attach(ol_ath_soc_softc_t *soc)
{
    asf_adf_attach();
    return EOK;
}

int
ol_asf_adf_detach(ol_ath_soc_softc_t *soc)
{
    return EOK;
}

#ifdef MU_CAP_WAR_ENABLED
static OS_TIMER_FUNC(ieee80211_mu_cap_mode_switch)
{
    struct     ieee80211com *ic;
    struct     ieee80211vap *vap = NULL;
    DEDICATED_CLIENT_MAC *dedicated, *temp;
    u_int8_t   i = 0;
    u_int16_t  associd;
    u_int16_t  total_mu_clients;

    MU_CAP_CLIENT_TYPE mu_type;
    ATH_LIST_HEAD(,DEDICATED_CLIENT_MAC)deauth_list;
    MU_CAP_WAR *war;
    LIST_INIT(&deauth_list);

    OS_GET_TIMER_ARG(vap, struct ieee80211vap *);

    /*mu_cap timer enrty*/
    ic = vap->iv_ic;
    war = &vap->iv_mu_cap_war;
    qdf_spin_lock_bh(&war->iv_mu_cap_lock);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,"IN Dedicated client TIMER\n");
    if (!war->mu_cap_war) {
        /*
         * Kicking out the dedicated SU Clients is
         * the only valid timer action
         * when the WAR is disabled.
         * You would never want to kick out
         * Dedicated-MU enabled client when WAR is
         * disabled!!
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "In timer while MUCAP-WAR is disabled\n");
        war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS;
    }


    total_mu_clients = war->mu_cap_client_num[MU_CAP_CLIENT_NORMAL] +
        war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT] +
        war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT];

    if ((war->mu_timer_cmd == MU_CAP_TIMER_CMD_KICKOUT_DEDICATED) &&
            ((total_mu_clients != 1) ||
             (war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT] != 1))) {
        /*
         * Even thought the timer was started with the
         * purpose of kicking out MU-1X1 clients,
         * now, the conditions are not correct for kicking
         * out this MU-1X1 client,
         * possibly because other MU-Capable client(s) have joined
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "Kick-out to SU-Capable 2x2 not possible now\n");
        goto end_of_timer;
    }

    switch(war->mu_timer_cmd)
    {
        case MU_CAP_TIMER_CMD_KICKOUT_DEDICATED:
            {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "KICKOUT-DEDICATED-MU-CLIENT\n");
                mu_type = MU_CAP_DEDICATED_MU_CLIENT;
                break;
            }
        case MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS:
            {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "KICKOUT-ALL-DEDICATED-SU-CLIENTS\n");
                mu_type = MU_CAP_DEDICATED_SU_CLIENT;
                break;
            }
        default:
            {
                goto end_of_timer;
            }
    }


    /*
     * Copy the clients which meet the kick-out conditions
     * to a local table, then deauth them
     * outside of the iv_mu_cap_lock
     * This way the function ieee80211_mu_cap_client_leave can be
     * put inside iv_mu_cap_lock again
     */
    for(i=0;i<total_mu_clients;i++)
    {
        if (war->mu_cap_client_flag[i] == mu_type)
        {
            dedicated =
            OS_MALLOC(ic->ic_osdev, sizeof(struct DEDICATED_CLIENT_MAC), 0);
            if (dedicated == NULL) {
                ieee80211_note(vap, IEEE80211_MSG_ANY, "ERROR!! Memory "
                    "allocation failed in %s\n", __func__);
                continue;
            }
            OS_MEMCPY(dedicated->macaddr, war->mu_cap_client_addr[i],
                      QDF_MAC_ADDR_SIZE);
            LIST_INSERT_HEAD(&deauth_list, dedicated, list);
        }

    }

end_of_timer:
    war->iv_mu_timer_state = MU_TIMER_STOP;
    qdf_spin_unlock_bh(&war->iv_mu_cap_lock);

    /*
     * We now release the lock and call the
     * deauth function. The lock will be acquired later on
     * when the deauth function results in ieee80211_mu_cap_client_leave
     */
    /*De-assoc each dedicated clients*/
    LIST_FOREACH_SAFE(dedicated, &deauth_list, list, temp) {
        struct ieee80211_node *ni = ieee80211_find_node(ic, dedicated->macaddr, WLAN_MLME_SB_ID);
        LIST_REMOVE(dedicated, list);
        OS_FREE(dedicated);
        if (!ni) {
            ieee80211_note(vap, IEEE80211_MSG_ANY,
                    "NI IS NULL AFTER MU-CAP-WAR TIMER LOCK! %s\n",
                    ether_sprintf(dedicated->macaddr));
            continue;
        }
        if (ni->ni_associd != 0 )
        {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "MUCAPWAR TIMER: Kicking out %s\n",
                            ether_sprintf(ni->ni_macaddr));
            associd = ni->ni_associd;
            wlan_mlme_deauth_request(ni->ni_vap,ni->ni_macaddr,
                    IEEE80211_REASON_UNSPECIFIED);
            IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(ni->ni_vap,
                    ni->ni_macaddr, associd, IEEE80211_REASON_UNSPECIFIED);
        }
        ieee80211_free_node(ni, WLAN_MLME_SB_ID);
    }
}

void ieee80211_mucap_vattach(struct ieee80211vap *vap) {
   struct ieee80211com *ic = vap->iv_ic;
   int cnt;
   MU_CAP_WAR *war = &vap->iv_mu_cap_war;
   osdev_t os_handle = ic->ic_osdev;
   war->iv_mu_timer_state = MU_TIMER_STOP;

   OS_INIT_TIMER(os_handle, &war->iv_mu_cap_timer,
           ieee80211_mu_cap_mode_switch, vap, QDF_TIMER_TYPE_WAKE_APPS);

   qdf_spinlock_create(&war->iv_mu_cap_lock);
   war->mu_cap_timer_period = MU_TIMER_PERIOD;

   for(cnt=0;cnt<ARRAY_SIZE(war->dedicated_client_list);cnt++) {
       LIST_INIT(&war->dedicated_client_list[cnt]);
   }
   war->dedicated_client_number = 0;

   /* Disable MU-CAP-WAR by default */
   war->modify_probe_resp_for_dedicated =
   war->mu_cap_war = 0;
}

void ieee80211_mucap_vdetach(struct ieee80211vap *vap) {

   struct DEDICATED_CLIENT_MAC *dedicated_mac=NULL, *temp=NULL;
   int cnt;
   MU_CAP_WAR *war = &vap->iv_mu_cap_war;
   qdf_spin_lock_bh(&war->iv_mu_cap_lock);
   if (war->iv_mu_timer_state == MU_TIMER_PENDING)
      war->iv_mu_timer_state = MU_TIMER_STOP;
   OS_FREE_TIMER(&war->iv_mu_cap_timer);
   qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
   for(cnt=0;cnt<ARRAY_SIZE(war->dedicated_client_list);cnt++) {
       LIST_FOREACH_SAFE(dedicated_mac, &war->dedicated_client_list[cnt],
                         list, temp) {

           war->dedicated_client_number--;
           LIST_REMOVE(dedicated_mac,list);
           OS_FREE(dedicated_mac);
       }
   }
   qdf_spinlock_destroy(&war->iv_mu_cap_lock);
}
#endif

static void ol_swap_seg_free(ol_ath_soc_softc_t *soc, struct swap_seg_info *seg_info, u_int64_t *cpuaddr, int type)
{
    if(cpuaddr) {
#if WIFI_MEM_MANAGER_SUPPORT
        wifi_cmem_free(soc->soc_idx, 0, (CM_CODESWAP + type), seg_info->seg_cpuaddr[0]);
#else
        dma_free_coherent(soc->sc_osdev->device, seg_info->seg_size, seg_info->seg_cpuaddr[0] , (dma_addr_t)seg_info->seg_busaddr[0]);
#endif
        qdf_dev_release_mem((struct qdf_dev *)soc->sc_osdev->device,
                            (struct qdf_devm *)seg_info);
    }
}
void
ol_codeswap_detach (ol_ath_soc_softc_t *soc) {
    ol_swap_seg_free(soc, soc->target_otp_codeswap_seginfo, soc->target_otp_codeswap_cpuaddr, ATH_TARGET_OTP_CODE_SWAP);
    ol_swap_seg_free(soc, soc->target_otp_dataswap_seginfo, soc->target_otp_dataswap_cpuaddr, ATH_TARGET_OTP_DATA_SWAP);
    ol_swap_seg_free(soc, soc->target_bin_codeswap_seginfo, soc->target_bin_codeswap_cpuaddr, ATH_TARGET_BIN_CODE_SWAP);
    ol_swap_seg_free(soc, soc->target_bin_dataswap_seginfo, soc->target_bin_dataswap_cpuaddr, ATH_TARGET_BIN_DATA_SWAP);
    ol_swap_seg_free(soc, soc->target_bin_utf_codeswap_seginfo, soc->target_bin_utf_codeswap_cpuaddr,ATH_TARGET_BIN_UTF_CODE_SWAP);
    ol_swap_seg_free(soc, soc->target_bin_utf_dataswap_seginfo, soc->target_bin_utf_dataswap_cpuaddr,ATH_TARGET_BIN_UTF_DATA_SWAP);
}

int
ol_mempools_attach(ol_ath_soc_softc_t *soc)
{
    if(qdf_mempool_init(soc->qdf_dev, &soc->mempool_ol_ath_vap,
         soc->max_vaps, sizeof(struct ol_ath_vap_net80211), 0)) {
         soc->mempool_ol_ath_vap = NULL;
         qdf_err("ol_ath_vap memory pool init failed");
         goto fail1;
     }

    if(qdf_mempool_init(soc->qdf_dev, &soc->mempool_ol_ath_node,
        (CFG_MAX_TMPNODES + soc->max_vaps + soc->max_clients), sizeof(struct ol_ath_node_net80211), 0)) {
        soc->mempool_ol_ath_node = NULL;
        qdf_err("ol_ath_node memory pool init failed");
        goto fail2;
    }

    return 0;

fail2:
    qdf_mempool_destroy(soc->qdf_dev, soc->mempool_ol_ath_vap);
fail1:
    return -ENOMEM;
}

void
ol_mempools_detach(ol_ath_soc_softc_t *soc)
{
    qdf_mempool_destroy(soc->qdf_dev, soc->mempool_ol_ath_peer);
    qdf_mempool_destroy(soc->qdf_dev, soc->mempool_ol_ath_node);
    qdf_mempool_destroy(soc->qdf_dev, soc->mempool_ol_ath_vap);
}

/* Get default value of 80+80 EMI WAR enabled status based on chipset ID */
static u_int8_t
ol_ath_get_emiwar_80p80_defval(ol_ath_soc_softc_t *soc)
{
    u_int8_t defval=0;
    u_int32_t target_type = lmac_get_tgt_type(soc->psoc_obj);

    if (!IS_EMIWAR_80P80_APPLICABLE(target_type)) {
        return 0;
    }

    switch(target_type)
    {
        case TARGET_TYPE_QCA9984:
            defval = EMIWAR_80P80_DEFVAL_QCA9984;
            break;
        case TARGET_TYPE_QCA9888:
            defval = EMIWAR_80P80_DEFVAL_QCA9888;
            break;
        default:
            defval = 0;
            break;
    }

    return defval;
}

QDF_STATUS
ol_ath_get_wmi_target_type(ol_ath_soc_softc_t *soc, enum wmi_target_type *target)
{
    uint32_t target_type;

    target_type = lmac_get_tgt_type(soc->psoc_obj);

	switch(target_type)
	{
		case TARGET_TYPE_AR6002:
		case TARGET_TYPE_AR6003:
		case TARGET_TYPE_AR6004:
		case TARGET_TYPE_AR6006:
		case TARGET_TYPE_AR9888:
		case TARGET_TYPE_AR6320:
		case TARGET_TYPE_AR900B:
		case TARGET_TYPE_QCA9984:
		case TARGET_TYPE_QCA9888:
		case TARGET_TYPE_IPQ4019:
			*target = WMI_NON_TLV_TARGET;
			break;
#ifdef QCA_WIFI_QCA8074
		case TARGET_TYPE_QCA8074:
		case TARGET_TYPE_QCA8074V2:
			*target = WMI_TLV_TARGET;
			break;
#endif
#ifdef QCA_WIFI_QCA6018
		case TARGET_TYPE_QCA6018:
			*target = WMI_TLV_TARGET;
			break;
#endif
#ifdef QCA_WIFI_QCN9000
		case TARGET_TYPE_QCN9000:
			*target = WMI_TLV_TARGET;
			break;
#endif
#ifdef QCA_WIFI_QCN6122
		case TARGET_TYPE_QCN6122:
			*target = WMI_TLV_TARGET;
			break;
#endif
#ifdef QCA_WIFI_QCA5018
		case TARGET_TYPE_QCA5018:
			*target = WMI_TLV_TARGET;
			break;
#endif
		default:
			qdf_err("!!! Invalid Target Type %d !!!", target_type);
			return QDF_STATUS_E_INVAL;
	}
	return QDF_STATUS_SUCCESS;
}

static inline void ol_ath_configure_wmi_services(ol_ath_soc_softc_t *soc)
{
    uint8_t wmi_ep_count = 1;
    uint32_t target_type;
    struct target_psoc_info *tgt_psoc_info;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return;
    }
    target_type = target_psoc_get_target_type(tgt_psoc_info);

    /* qca8074 supports upto 3 macs and hence one ep per wmi.
     * But is preferred mode is DBS, then there is no need to connect to
     * all three WMI eps
     */
    if ((target_type == TARGET_TYPE_QCA8074) ||
		    (target_type == TARGET_TYPE_QCA8074V2) ||
		    (target_type == TARGET_TYPE_QCA6018) ||
		    (target_type == TARGET_TYPE_QCA5018) ||
		    (target_type == TARGET_TYPE_QCN6122) ||
		    (target_type == TARGET_TYPE_QCN9000)) {
        switch (target_psoc_get_preferred_hw_mode(tgt_psoc_info)) {
            case WMI_HOST_HW_MODE_SINGLE:
                wmi_ep_count = 1;
                break;
            case WMI_HOST_HW_MODE_DBS:
                wmi_ep_count = 2;
                break;
            case WMI_HOST_HW_MODE_DBS_OR_SBS:
                wmi_ep_count = 2;
                break;
            case WMI_HOST_HW_MODE_DBS_SBS:
                wmi_ep_count = 3;
                break;
            default:
                wmi_ep_count = 3;
                break;
        }
    }

    htc_set_wmi_endpoint_count(target_psoc_get_htc_hdl(tgt_psoc_info),
                            wmi_ep_count);
}

int htc_wmi_init(ol_ath_soc_softc_t *soc)
{
    struct htc_init_info htcInfo;
    struct target_psoc_info *tgt_psoc_info;
    HTC_HANDLE htc_handle;
    void *hif_hdl;
    /*
     * 5. Create HTC
     */
    OS_MEMZERO(&htcInfo,sizeof(htcInfo));
    htcInfo.pContext = soc;
    htcInfo.target_psoc = soc;
    if (soc->ol_if_ops->target_failure)
        htcInfo.TargetFailure = soc->ol_if_ops->target_failure;
    htcInfo.TargetSendSuspendComplete = ol_target_send_suspend_complete;
    htc_global_credit_flow_disable();

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return -EIO;
    }

    hif_hdl = lmac_get_ol_hif_hdl(soc->psoc_obj);
    if ((htc_handle = htc_create(hif_hdl, &htcInfo, soc->qdf_dev,0)) == NULL)
    {
        return -EIO;
    }
    qdf_info("HT Create . %pK", htc_handle);

    target_psoc_set_htc_hdl(tgt_psoc_info, htc_handle);

    ol_ath_configure_wmi_services(soc);

    if (!hif_needs_bmi(hif_hdl)) {
        qdf_info("Skipping BMI Done");
    } else {
#ifdef WLAN_FEATURE_BMI
        /*
         * 6. Complete BMI phase
         */
        if (soc->bmi_handle) {
            if (soc->bmi_handle->bmi_done) {
                if (soc->bmi_handle->bmi_done(hif_hdl, soc->bmi_handle,soc->sc_osdev)
                                              != A_OK)
                {
                    return -EIO;
                }
            }
        }
#endif
    }

    if (!bypasswmi) {
        /*
         * 7. Initialize WMI
         */

        /* initialize default target config */
        if (lmac_is_target_ar900b(soc->psoc_obj)) {
            /* Beeliner supports HW IP header alignment,
             * so native WIFI support is disabled and host receives 802.3 packets
             * with IP header aligned to 4-byte boundary.
             */
            wlan_psoc_nif_feat_cap_clear(soc->psoc_obj,
                                    WLAN_SOC_F_HOST_80211_ENABLE);
        }

        else if (target_psoc_get_target_type(tgt_psoc_info) == TARGET_TYPE_AR9888) {
            /* Peregrine does not support HW IP header alignment,
             * so native WIFI support should be enabled as IP header is always aligned
             * to 4-byte boundary in this mode.
             */
#if PERE_IP_HDR_ALIGNMENT_WAR
            wlan_psoc_nif_feat_cap_set(soc->psoc_obj,
                                    WLAN_SOC_F_HOST_80211_ENABLE);
#else
            wlan_psoc_nif_feat_cap_clear(soc->psoc_obj,
                                    WLAN_SOC_F_HOST_80211_ENABLE);
#endif
        }
    }

    qdf_info("host_enable %d",
              wlan_psoc_nif_feat_cap_get(soc->psoc_obj, WLAN_SOC_F_HOST_80211_ENABLE));
    target_if_set_default_config(soc->psoc_obj, tgt_psoc_info);

    return 0;
}

int ol_target_init_complete(ol_ath_soc_softc_t *soc)
{
    int status = 0;
    struct target_psoc_info *tgt_psoc_info;
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    HTC_HANDLE htc_handle;
    void *hif_hdl;
    dp_soc_txrx_handle_t *dp_ext_hdl = NULL;
    void *dbglog_handle = NULL;
    struct wmi_unified *wmi_handle = NULL;
    uint8_t num_radios;
    cdp_config_param_type val = {0};

    if (htc_wmi_init(soc))
        goto attach_failed;

    htc_handle = lmac_get_htc_hdl(soc->psoc_obj);
    if (!htc_handle)
        goto attach_failed;

    hif_hdl = lmac_get_ol_hif_hdl(soc->psoc_obj);
    if (!hif_hdl)
        goto attach_failed;

    soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);
#ifdef WLAN_FEATURE_FASTPATH
    hif_enable_fastpath(hif_hdl);
#endif

    if (htc_wait_target(htc_handle) != QDF_STATUS_SUCCESS) {
        status = -EIO;
        goto attach_failed;
    }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
        soc->nss_soc.ops->nss_soc_ce_post_recv_buffer(soc);
    }
#endif

    if (soc->ol_if_ops->cdp_soc_init) {
        soc_txrx_handle =
            soc->ol_if_ops->cdp_soc_init(wlan_psoc_get_dp_handle(soc->psoc_obj),
                                         soc->device_id, hif_hdl,
                                         (void *)soc->psoc_obj, htc_handle,
                                           (void *)soc->qdf_dev, &dp_ol_if_ops);
        if (!soc_txrx_handle) {
            qdf_err("soc attach failed");
            status = -EIO;
            goto attach_failed;
        }
        wlan_psoc_set_dp_handle(soc->psoc_obj, soc_txrx_handle);
    }

    dp_ext_hdl = qdf_mem_malloc(sizeof(dp_soc_txrx_handle_t));
    if (!dp_ext_hdl) {
        qdf_err("soc attach - dp_ext_hdl alloc failed");
        status = -EIO;
        cdp_soc_set_dp_txrx_handle(soc_txrx_handle, NULL);
        goto attach_failed;
    }

    cdp_soc_set_dp_txrx_handle(soc_txrx_handle, dp_ext_hdl);
    dp_ext_hdl->lag_hdl.soc = soc_txrx_handle;
    ol_ath_soc_rate_stats_attach(soc);

    qdf_info("CDP soc attach success");

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
        soc->nss_soc.ops->nss_soc_wifi_set_cfg(soc, soc->nss_soc.nss_scfg);
    }
    qdf_info("Soc attach success NSS config %d ",
                cfg_get(soc->psoc_obj, CFG_NSS_WIFILI_OL));
#endif

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        goto attach_failed;
    }

    val.cdp_psoc_param_preferred_hw_mode =
            target_psoc_get_preferred_hw_mode(tgt_psoc_info);
    cdp_txrx_set_psoc_param(soc_txrx_handle, CDP_SET_PREFERRED_HW_MODE,
                            val);

    if (!bypasswmi) {
        if (soc->ol_if_ops->dbglog_attach) {
            dbglog_handle = soc->ol_if_ops->dbglog_attach();
        }

        if (dbglog_handle) {
            target_psoc_set_dbglog_hdl(tgt_psoc_info, dbglog_handle);
            fwdbg_init(dbglog_handle, soc);
            soc->dbg_log_init = 1;
            wmi_handle = (struct wmi_unified *)target_psoc_get_wmi_hdl(tgt_psoc_info);
            if (wmi_handle) {
                wmi_unified_register_event_handler(wmi_handle, wmi_diag_event_id,
                        diag_fw_event_handler, WMI_RX_DIAG_WORK_CTX);
            } else {
                qdf_err("null wmi_handle");
            }

        } else {
            qdf_err("dbglog attach Failed");
        }
    }

    if ((status = ol_ath_connect_htc(soc)) != A_OK)
    {
        qdf_info("connect_htc failed");
        goto attach_failed;
    }

    num_radios = target_psoc_get_num_radios(tgt_psoc_info);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
        if ((status = soc->nss_soc.ops->nss_soc_wifi_attach(soc))) {
            qdf_err("nss_soc_wifi_attach failed");
            goto attach_failed;
        }
        if (soc->nss_soc.nss_nxthop && (status = soc->nss_soc.ops->nss_soc_wifi_set_default_nexthop(soc))) {
            qdf_err("nss_nxthop configuration failed");
            goto attach_failed;
        }
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL))
#else
    if (target_psoc_get_target_type(tgt_psoc_info) != TARGET_TYPE_AR9888)
#endif
        soc->num_tx_desc = cfg_get(soc->psoc_obj, CFG_DP_TX_DESC);

    if (lmac_get_tgt_version(soc->psoc_obj) != AR6004_VERSION_REV1_3) {
        if ((status = cdp_soc_attach_target(soc_txrx_handle)) != A_OK) {
            qdf_err("txrx soc attach failed");
            goto attach_failed;
        }
    }

    if ((lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA8074V2) ||
        (lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA6018) ||
        (lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA5018) ||
        (lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCN9000) ||
        (lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCN6122)) {
        dp_ext_hdl->lag_hdl.ast_override_support = true;
    }

    return 0;
attach_failed:
    if (dp_ext_hdl) {
        qdf_mem_free(dp_ext_hdl);
        cdp_soc_set_dp_txrx_handle(soc_txrx_handle, NULL);
    }
    return status;
}

/* This function is to be used by components to populate
 * the OL function pointers (tx_ops) required by the component
 * for UMAC-LMAC interaction, with the appropriate handler */
QDF_STATUS olif_register_umac_tx_ops(struct wlan_lmac_if_tx_ops *tx_ops)
{
    ol_ath_register_crypto_ops_handler(&tx_ops->crypto_tx_ops);
#ifdef WLAN_SUPPORT_FILS
    tx_ops->mgmt_txrx_tx_ops.fd_action_frame_send = target_if_fd_send;
#endif
    tx_ops->mgmt_txrx_tx_ops.mgmt_tx_send = ol_if_mgmt_send;
    tx_ops->mgmt_txrx_tx_ops.beacon_send = ol_ath_mgmt_beacon_send;
    tx_ops->scan.set_chan_list = ol_scan_set_chan_list;
    /* DFS function pointers */
#if ATH_SUPPORT_DFS
    tx_ops->dfs_tx_ops.dfs_enable = ol_if_dfs_enable;
    tx_ops->dfs_tx_ops.dfs_get_caps = ol_dfs_get_caps;
    tx_ops->dfs_tx_ops.dfs_gettsf64 = ol_if_get_tsf64;
    tx_ops->dfs_tx_ops.dfs_get_thresholds = ol_if_dfs_get_thresholds;
    tx_ops->dfs_tx_ops.dfs_disable = ol_if_dfs_disable;
    tx_ops->dfs_tx_ops.dfs_get_ext_busy = ol_if_dfs_get_ext_busy;
    tx_ops->dfs_tx_ops.dfs_get_target_type = lmac_get_pdev_target_type;
    tx_ops->dfs_tx_ops.dfs_get_ah_devid = ol_ath_get_ah_devid;
    tx_ops->dfs_tx_ops.dfs_get_phymode_info = ol_ath_get_phymode_info;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    tx_ops->dfs_tx_ops.dfs_host_dfs_check_support =
        ol_if_is_host_dfs_check_support_enabled;
#endif /* HOST_DFS_SPOOF_TEST */
    tx_ops->dfs_tx_ops.dfs_check_mode_switch_state =
        ol_if_hw_mode_switch_state;
#endif /* ATH_SUPPORT_DFS */

    /* Regulatory tx ops */
    tx_ops->reg_ops.fill_umac_legacy_chanlist = ol_ath_fill_umac_legacy_chanlist;
    tx_ops->reg_ops.set_country_failed = ol_ath_set_country_failed;
    tx_ops->mops.get_wifi_iface_id = ol_ath_get_interface_id;

    return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(olif_register_umac_tx_ops);

static QDF_STATUS ol_defaultkey(struct wlan_objmgr_vdev *vdev,
                                uint8_t keyidx, uint8_t *macaddr)
{
    if (!vdev) {
        qdf_err("vdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    ol_ath_wmi_send_vdev_param(vdev, wmi_vdev_param_def_keyid, keyidx);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_deletekey(struct wlan_objmgr_vdev *vdev,
                               struct wlan_crypto_key *key, uint8_t *macaddr,
                               uint32_t keytype)
{
    struct wlan_objmgr_pdev *pdev;
    struct pdev_osif_priv *osif_priv;
    struct ieee80211vap *vap;
    struct wlan_objmgr_psoc *psoc;
    uint8_t bssid_mac[IEEE80211_ADDR_LEN] = {0,0,0,0,0,0};

    if (!vdev) {
        qdf_err("vdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    pdev = wlan_vdev_get_pdev(vdev);

    if (!pdev) {
        qdf_err("pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    osif_priv = wlan_pdev_get_ospriv(pdev);

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    psoc = wlan_pdev_get_psoc(pdev);

    if (psoc && ol_target_lithium(psoc)) {
        if (IS_MULTICAST(macaddr)) {
            qdf_mem_copy(bssid_mac, wlan_vdev_mlme_get_macaddr(vdev),
                         IEEE80211_ADDR_LEN);
            ol_ath_vdev_install_key_send(vap, key, bssid_mac, 0, 1, keytype);
        } else {
            ol_ath_vdev_install_key_send(vap, key, macaddr, 0, 0, keytype);
        }
    } else {
        ol_ath_vdev_install_key_send(vap, key, macaddr, 0, 1, keytype);
    }
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_setkey(struct wlan_objmgr_vdev *vdev,
                            struct wlan_crypto_key *key,
                            uint8_t *macaddr,  uint32_t keytype){

    struct wlan_objmgr_pdev *pdev;
    struct pdev_osif_priv *osif_priv;
    struct ieee80211vap *vap;
#if ATH_SUPPORT_WRAP
    struct ol_ath_vap_net80211 *avn;
#endif

    if (!vdev) {
        qdf_err("vdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    pdev = wlan_vdev_get_pdev(vdev);

    if (!pdev) {
        qdf_err("pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    osif_priv = wlan_pdev_get_ospriv(pdev);

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }
#if ATH_SUPPORT_WRAP
    avn = OL_ATH_VAP_NET80211(vap);
#if WLAN_QWRAP_LEGACY
    if (avn->av_is_psta && !(avn->av_is_mpsta) && (key->flags & WLAN_CRYPTO_KEY_GROUP)) {
#else
    if (dp_wrap_vdev_is_psta(vap->vdev_obj) && !(dp_wrap_vdev_is_mpsta(vap->vdev_obj)) && (key->flags & WLAN_CRYPTO_KEY_GROUP)) {
#endif
        qdf_info("Ignore set group key for psta");
        return QDF_STATUS_SUCCESS;
    }
#endif

    ol_ath_vdev_install_key_send(vap, key, macaddr,
                                 (key->flags & WLAN_CRYPTO_KEY_DEFAULT), 0,
                                  keytype);
    return QDF_STATUS_SUCCESS;
}
static QDF_STATUS ol_allockey(struct wlan_objmgr_vdev *vdev,
                              struct wlan_crypto_key *key,
                              uint8_t *macaddr,  uint32_t keytype){
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_getpn(struct wlan_objmgr_vdev *vdev,
                            uint8_t *macaddr,  uint32_t keytype){

    struct wlan_objmgr_pdev *pdev;
    struct pdev_osif_priv *osif_priv;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211vap *vap;
    QDF_STATUS ret = QDF_STATUS_SUCCESS;

    if (!vdev) {
        qdf_err("vdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    pdev = wlan_vdev_get_pdev(vdev);

    if (!pdev) {
        qdf_err("pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    osif_priv = wlan_pdev_get_ospriv(pdev);

    scn = (struct ol_ath_softc_net80211 *)(osif_priv->legacy_osif_priv);

    if (!scn) {
        qdf_err("scn is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    vap = wlan_vdev_get_mlme_ext_obj(vdev);

    ret = ol_ath_vdev_getpn(vap, scn, wlan_vdev_get_id(vdev), macaddr, keytype);
    return ret;
}



/* OL callback to register crypto_ops handlers*/
static QDF_STATUS ol_ath_register_crypto_ops_handler(
                           struct wlan_lmac_if_crypto_tx_ops *crypto_tx_ops){

    crypto_tx_ops->setkey = ol_setkey;
    crypto_tx_ops->delkey = ol_deletekey;
    crypto_tx_ops->defaultkey = ol_defaultkey;
    crypto_tx_ops->allockey = ol_allockey;
    crypto_tx_ops->getpn = ol_getpn;

    return QDF_STATUS_SUCCESS;
}

static
int unit_test_handler(ol_soc_t sc, uint8_t *data, uint32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_unit_test_event *unit_test;

    /*
     * Maximum buffer size from WMI is 2K
     */
    const uint32_t MAX_COPY_SIZE = 2048;
    const uint32_t MAX_BUFFER_SIZE = MAX_COPY_SIZE + sizeof(*unit_test);

    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_vdev *vdev;
    wlan_if_t vap;
    struct ieee80211req_athdbg_event *dbg_event;
    osif_dev *osifp;
    struct wmi_unified *wmi_handle;

    psoc = soc->psoc_obj;

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return 0;
    }

    unit_test = qdf_mem_malloc(sizeof(*unit_test)+MAX_BUFFER_SIZE);
    if (!unit_test) {
        QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                "%s: Memory allocation failed for wmi_unit_test_event\n",
                __func__);
        return 0;
    }
    wmi_extract_unit_test(wmi_handle, data, unit_test, MAX_COPY_SIZE);
    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, unit_test->vdev_id,
            WLAN_DEBUG_ID);
    if (!vdev) {
        QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                FL("vdev object NULL"));
        goto cleanup1;
    }
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                FL("vap object NULL"));
        goto cleanup2;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    dbg_event =
        qdf_mem_malloc(sizeof(*dbg_event) +
                unit_test->buffer_len);
    if (dbg_event == NULL) {
        QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                "%s: Memory allocation failed for ieee80211req_athdbg_event\n",
                __func__);
        goto cleanup2;
    }
    dbg_event->cmd = IEEE80211_DBGREQ_FW_UNIT_TEST;
    dbg_event->fw_unit_test.hdr.module_id = unit_test->module_id;
    dbg_event->fw_unit_test.hdr.flag = unit_test->flag;
    dbg_event->fw_unit_test.hdr.diag_token = unit_test->diag_token;
    dbg_event->fw_unit_test.hdr.payload_len = unit_test->payload_len;
    dbg_event->fw_unit_test.hdr.buffer_len = unit_test->buffer_len;
    qdf_mem_copy(dbg_event->fw_unit_test.buffer, unit_test->buffer,
            unit_test->buffer_len);
#if UMAC_SUPPORT_CFG80211
    wlan_cfg80211_generic_event(vap->iv_ic,
            QCA_NL80211_VENDOR_SUBCMD_DBGREQ, dbg_event,
            sizeof(*dbg_event) + (unit_test->buffer_len-1),
            osifp->netdev, GFP_KERNEL);
#endif
    qdf_mem_free(dbg_event);

cleanup2:
    wlan_objmgr_vdev_release_ref(vdev, WLAN_DEBUG_ID);
cleanup1:
    qdf_mem_free(unit_test);
    return 0;
}

static inline
bool tso_vdev_bit_status(struct ol_ath_soc_softc *soc)
{
    return !qdf_bitmap_empty(soc->tso_vdev_bitmap,
                             QDF_CHAR_BIT * sizeof(soc->tso_vdev_bitmap));
}

/*
 * Handle changes in state of network device.
 *
 */
static int ath_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#else
    struct net_device *dev = ptr;
#endif
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    uint8_t vdev_id;

    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    switch (event) {
        case NETDEV_FEAT_CHANGE:

            /* This api loops through all the vaps.
               Hence to avoid unnecessary handling of unrelated events
               this is called inside the event case
            */
            if (!(scn = osif_validate_and_get_scn_from_dev(dev))) {
                return NOTIFY_DONE;
            }

            vdev_id = wlan_vdev_get_id(vap->vdev_obj);
            soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

            if (!soc_txrx_handle)
                return 0;

            if (dev->features & NETIF_F_TSO) {
                if (!tso_vdev_bit_status(scn->soc))
                    cdp_tso_soc_attach(soc_txrx_handle);
                qdf_set_bit(vdev_id, scn->soc->tso_vdev_bitmap);
            } else if (!(dev->features & NETIF_F_TSO)) {
                qdf_clear_bit(vdev_id, scn->soc->tso_vdev_bitmap);
                if (!tso_vdev_bit_status(scn->soc))
                    cdp_tso_soc_detach(soc_txrx_handle);
            }
            break;
        default:
            break;

    }
    return NOTIFY_DONE;
}

/**
 * ol_ath_hw_mode_check_pdev_map(): Check if new pdev mapping is
 * possible or not for dynamic mode switch between DBS_SBS and DBS
 * @soc: soc handle
 *
 * return: QDF_STATUS_SUCCESS in case of success and
 * QDF_STATUS_E_INVAL otherwise
 */
static QDF_STATUS ol_ath_hw_mode_check_pdev_map(ol_ath_soc_softc_t *soc)
{
    struct wlan_objmgr_psoc *psoc        = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t    *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info *tgt_hdl;
    struct wlan_objmgr_pdev *pdev;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    bool mac_phy_pdev_mapped[WMI_HOST_MAX_PDEV] = { 0 };
    int num_pdev_map = 0;
    uint8_t num_radios;
    int status = QDF_STATUS_E_INVAL;
    int i;
    int j;

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        goto exit;
    }

    mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode(tgt_hdl, hw_mode_ctx->target_mode);
    if (!mac_phy_cap) {
        qdf_err("mac_phy_cap is null");
        goto exit;
    }

    num_radios = target_psoc_get_num_radios_for_mode(tgt_hdl, hw_mode_ctx->target_mode);

    for (i = 0; i < WMI_HOST_MAX_PDEV; i++) {
        pdev = wlan_objmgr_get_pdev_by_id(psoc, i, WLAN_MLME_NB_ID);
        if (!pdev) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("pdev object (id: %d) is NULL"), i);
            continue;
        }

        scn = (struct ol_ath_softc_net80211 *)
                                lmac_get_pdev_feature_ptr(pdev);
        if (!scn) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR, FL("scn is NULL"));

            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
            continue;
        }

        ic = &(scn->sc_ic);
        for (j = 0; j < num_radios; j++) {
            if (mac_phy_pdev_mapped[j])
                continue;

            if (hw_mode_ctx->target_mode == WMI_HOST_HW_MODE_DBS) {
                /* Map based on primary vs secondary interface and band capability */
                if ((pdev == hw_mode_ctx->primary_pdev) &&
                    (ic->ic_supported_bands & WMI_HOST_WLAN_5G_CAPABILITY) &&
                    (mac_phy_cap[j].supported_bands & WMI_HOST_WLAN_5G_CAPABILITY)) {
                    hw_mode_ctx->next_pdev_map[i] = mac_phy_cap[j].tgt_pdev_id;
                    mac_phy_pdev_mapped[j] = true;
                    break;
                } else if ((ic->ic_supported_bands & WMI_HOST_WLAN_2G_CAPABILITY) &&
                           (mac_phy_cap[j].supported_bands & WMI_HOST_WLAN_2G_CAPABILITY)) {
                    hw_mode_ctx->next_pdev_map[i] = mac_phy_cap[j].tgt_pdev_id;
                    mac_phy_pdev_mapped[j] = true;
                    break;
                }
            } else if (hw_mode_ctx->target_mode == WMI_HOST_HW_MODE_DBS_SBS) {
                /* Map based on operating frequency */
                if ((ic->ic_curchan->ic_freq >= mac_phy_cap[j].reg_cap_ext.low_5ghz_chan) &&
                    (ic->ic_curchan->ic_freq <= mac_phy_cap[j].reg_cap_ext.high_5ghz_chan) &&
                    (mac_phy_cap[j].supported_bands & WMI_HOST_WLAN_5G_CAPABILITY)) {
                    hw_mode_ctx->next_pdev_map[i] = mac_phy_cap[j].tgt_pdev_id;
                    mac_phy_pdev_mapped[j] = true;
                    break;
                } else if ((ic->ic_supported_bands & WMI_HOST_WLAN_2G_CAPABILITY) &&
                           (mac_phy_cap[j].supported_bands & WMI_HOST_WLAN_2G_CAPABILITY)) {
                    hw_mode_ctx->next_pdev_map[i] = mac_phy_cap[j].tgt_pdev_id;
                    mac_phy_pdev_mapped[j] = true;
                    break;
                }
            }
        }
        if (j == num_radios) {
            hw_mode_ctx->next_pdev_map[i] = WMI_HOST_PDEV_ID_INVALID;
            /* Map to a remaining pdev_id to avoid any crash due to invalid pdev_id */
            if (hw_mode_ctx->target_mode == WMI_HOST_HW_MODE_DBS) {
                hw_mode_ctx->next_pdev_map[i] = num_radios + 1;
            }
        }

        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
    }

    for (i = 0; i < WMI_HOST_MAX_PDEV; i++) {
        if (hw_mode_ctx->next_pdev_map[i] != WMI_HOST_PDEV_ID_INVALID)
            num_pdev_map++;
    }
    if (num_pdev_map < num_radios) {
        qdf_err("Couldn't map pdevs successfully num_pdev_map=%d num_radios=%d",
                num_pdev_map, num_radios);
        goto exit;

    }
    status = QDF_STATUS_SUCCESS;

exit:
    return status;
}

/**
 * ol_ath_hw_mode_apply_pdev_map(): Apply new pdev mapping
 * for dynamic mode switch between DBS_SBS and DBS
 * @soc: soc handle
 *
 * return: QDF_STATUS_SUCCESS in case of success and
 * QDF_STATUS_E_INVAL otherwise
 */
static QDF_STATUS ol_ath_hw_mode_apply_pdev_map (ol_ath_soc_softc_t *soc)
{
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    struct wmi_unified *wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    struct wlan_objmgr_pdev *pdev;
    uint8_t num_radios;
    int phy_idx;
    int lmac_id;
    int status = QDF_STATUS_E_INVAL;
    int i;

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        goto exit;
    }

    mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode(tgt_hdl, hw_mode_ctx->target_mode);
    if (!mac_phy_cap) {
        qdf_err("mac_phy_cap is null");
        goto exit;
    }

    num_radios  = target_psoc_get_num_radios_for_mode(tgt_hdl, hw_mode_ctx->target_mode);
    for (i = 0; i < WMI_HOST_MAX_PDEV; i++) {

        /* Update pdev_id mapping for WMI */
        hw_mode_ctx->pdev_map[i] = hw_mode_ctx->next_pdev_map[i];

        pdev = wlan_objmgr_get_pdev_by_id(psoc, i, WLAN_MLME_NB_ID);
        if (!pdev) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR,
                    FL("pdev object (id: %d) is NULL"), i);
            continue;
        }

        if (hw_mode_ctx->pdev_map[i] != WMI_HOST_PDEV_ID_INVALID) {
            /* Derive target phy_idx from mapped target pdev_id */
            phy_idx = hw_mode_ctx->pdev_map[i] - 1;
            /* Update wmi_handle in target_pdev_info */
            target_pdev_set_wmi_handle(
                wlan_pdev_get_tgt_if_handle(pdev),
                wmi_handle->soc->wmi_pdev[phy_idx]);
            /* Update phy_idx in target_pdev_info */
            target_pdev_set_phy_idx(
                wlan_pdev_get_tgt_if_handle(pdev),
                phy_idx);
            /* Derive target lmac_id from mapped target phy_idx */
            lmac_id = (phy_idx < num_radios)? mac_phy_cap[phy_idx].lmac_id : num_radios - 1;
            /* Update pdev_id mapping for DP */
            if (wlan_psoc_get_dp_handle(psoc)) {
		cdp_soc_handle_mode_change(wlan_psoc_get_dp_handle(psoc), i, lmac_id);
            }

            target_if_dbr_update_pdev_for_hw_mode_change(pdev, phy_idx);
        }

        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
    }

    /* Update pdev_id conversion table */
    wmi_pdev_id_conversion_enable((wmi_unified_t)wmi_handle, hw_mode_ctx->pdev_map, WMI_HOST_MAX_PDEV);

    status = QDF_STATUS_SUCCESS;
exit:
    return status;
}

/**
  * ol_ath_allow_wmi_cmds(): Block WMI commands during a
  * HW mode change or allow WMI commands after the mode change.
  * @wmi_hdl: WMI handle of pdev
  * @allow: boolean to specify allow/block
  **/
static inline void ol_ath_allow_wmi_cmds(wmi_unified_t wmi_hdl, bool allow)
{
    /* stop or start based on 'allow' */
    if (wmi_hdl) {
        if (allow) {
	    wmi_start(wmi_hdl);
	} else {
	    wmi_stop(wmi_hdl);
	}
    }
}

int
ol_ath_soc_hw_mode_change_event_handler (ol_scn_t sc,
                                         u_int8_t *data,
                                         u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc           = (ol_ath_soc_softc_t *) sc;
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &soc->hw_mode_ctx;
    struct wmi_unified *wmi_handle;
    uint32_t fw_resp_status;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);

    if (wmi_handle) {
        /* Process return value from FW by extracting
         * response event params from "data". If SUCCESS,
         * set event. If FAILURE, don't set event and
         * command will time out.
         */
        if (wmi_unified_extract_hw_mode_resp(wmi_handle,
                    data, &fw_resp_status)
                        == QDF_STATUS_SUCCESS) {
            /*
             * FW status represents following values:
             *  0 - OK; command successful
             *  1 - EINVAL; Requested invalid hw_mode
             *  2 - ECANCELED; HW mode change canceled
             *  3 - ENOTSUP; HW mode not supported
             *  4 - EHARDWARE; HW mode change prevented by hardware
             *  5 - EPENDING; HW mode change is pending
             *  6 - ECOEX; HW mode change conflict with Coex
             *
             *  But host will have boolean interpretation
             *  of above. 0 means failure. 1 means success.
             *
             *  Note: In case FW sends EPENDING we will not
             *  release the event below and hw_mode_change
             *  handler will remain waiting till timeout.
             */
            hw_mode_ctx->is_fw_resp_success = !fw_resp_status;
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO,
                      FL("Received response from FW with"""
                         """ status %s"),
                      hw_mode_ctx->is_fw_resp_success ? "PASS": "FAIL");
            if (fw_resp_status)
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                          QDF_TRACE_LEVEL_ERROR,
                          FL("fw_resp_status: %d"), fw_resp_status);

            if (hw_mode_ctx->is_fw_resp_success &&
                (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST)) {
                /* Apply pdev mapping */
                ol_ath_hw_mode_apply_pdev_map(soc);
                /* Re-start WMI cmd tx on primary pdev */
                ol_ath_allow_wmi_cmds(hw_mode_ctx->prev_wmi_hdl, true);
            }

            qdf_event_set(&hw_mode_ctx->event);
        }
    }

    return 0;
}

static void ol_ath_set_pdevid_to_phyid_map(ol_ath_soc_softc_t *soc)
{
    bool is_2g_phyb_enabled;
    struct target_psoc_info *tgt_psoc_info;
    uint32_t target_type;
    uint8_t phy_id_map[PSOC_MAX_PHY_REG_CAP] = {1, 0, 0};

    is_2g_phyb_enabled = cfg_get(soc->psoc_obj, CFG_OL_MODE_2G_PHYB);
    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    target_type = target_psoc_get_target_type(tgt_psoc_info);

    if (is_2g_phyb_enabled && target_type == TARGET_TYPE_QCA8074V2) {
	    target_psoc_set_pdev_id_to_phy_id_map(tgt_psoc_info, phy_id_map);
    }
}

static void ol_ath_sanitize_ema_vendor_ie_config(ol_ath_soc_softc_t *soc)
{
    uint8_t i;
    uint8_t ven_ie_size_nibble;
    uint16_t vendor_ie_size = 0;
    uint32_t *p_ema_ap_vendor_ie_config;
    uint32_t vendor_ie_size_limit;

    if (soc->ema_ap_ext_enabled)
        vendor_ie_size_limit = IEEE80211_MAX_VENDOR_IE_SIZE_LIMIT_EXT_ENABLED;
    else
        vendor_ie_size_limit = IEEE80211_MAX_VENDOR_IE_SIZE_LIMIT;

    /* masking out the higher bits */
    if (soc->ema_ap_num_max_vaps <= IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) {
        soc->ema_ap_vendor_ie_config_low &=
                        (1 << ((soc->ema_ap_num_max_vaps - 1) * 4)) - 1;
        soc->ema_ap_vendor_ie_config_high = 0;
    } else {
        soc->ema_ap_vendor_ie_config_high &=
                        (1 << ((soc->ema_ap_num_max_vaps -
                         IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX - 1) * 4)) - 1;
    }

    for (i = 0; i < soc->ema_ap_num_max_vaps - 1; i++) {
        if (i < IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) {
            ven_ie_size_nibble =
                ((soc->ema_ap_vendor_ie_config_low >> (i << 2)) & 0xf);
        } else {
            ven_ie_size_nibble =
                ((soc->ema_ap_vendor_ie_config_high >>
                  ((i - IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) << 2)) & 0xf);
        }

        if (soc->ema_ap_support_wps_6ghz) {
            vendor_ie_size = (1 << ven_ie_size_nibble);
            /* Reserved space exclusively for WPS IE. This
             * will get overidden with
             * IEEE80211_EMA_VENDOR_IE_SECTION_BOUND_WITH_WPS
             * in case of ema-ext enabled
             */
            vendor_ie_size += IEEE80211_EMA_WPS_IE_OCTET_RESERVATION_BOUND;
            vendor_ie_size = qdf_get_pwr2(vendor_ie_size);
            ven_ie_size_nibble = ilog2(vendor_ie_size);
        }

        mbss_info("vendor_ie_size: %d ven_ie_size_nibble: %d",
                vendor_ie_size, ven_ie_size_nibble);

        if (ven_ie_size_nibble > ilog2(vendor_ie_size_limit))
            ven_ie_size_nibble = ilog2(vendor_ie_size_limit);

        if (i < IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) {
            p_ema_ap_vendor_ie_config = &soc->ema_ap_vendor_ie_config_low;
        } else {
            p_ema_ap_vendor_ie_config = &soc->ema_ap_vendor_ie_config_high;
        }

        *p_ema_ap_vendor_ie_config &= ~(0xf << (i << 2));
        *p_ema_ap_vendor_ie_config |= (ven_ie_size_nibble & 0xf) << (i << 2);
    }

    mbss_debug("ema_ap_vendor_ie_config_low: 0x%x",
                    soc->ema_ap_vendor_ie_config_low);
    mbss_debug("ema_ap_vendor_ie_config_high: 0x%x",
                    soc->ema_ap_vendor_ie_config_high);
}

static void ol_ath_sanitize_ema_optional_ie_config(ol_ath_soc_softc_t *soc)
{
    int i, max_ven_ie_size = 0, ven_ie_size;
    int ema_max_opt_ie_size;

    if (soc->ema_ap_ext_enabled) {
        if (!soc->ema_ap_support_wps_6ghz) {
            for (i = 0; i < soc->ema_ap_num_max_vaps - 1; i++) {
                if (i < IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) {
                    ven_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                    soc->ema_ap_vendor_ie_config_low, i);
                } else {
                    ven_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                    soc->ema_ap_vendor_ie_config_high,
                                    (i - IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX));
                }
                if (ven_ie_size > max_ven_ie_size) {
                    max_ven_ie_size = ven_ie_size;
                }
            }
        } else {
            max_ven_ie_size = IEEE80211_EMA_VENDOR_IE_SECTION_BOUND_WITH_WPS;
        }

        /* Get max optional IE section size for a non-tx vap */
        ema_max_opt_ie_size = soc->ema_ap_max_non_tx_size - max_ven_ie_size -
                              IEEE80211_MAX_NON_TX_PROFILE_SIZE_WITH_RSN;
        if (ema_max_opt_ie_size < 0) {
            ema_max_opt_ie_size = 0;
        }

        if (soc->ema_ap_optional_ie_size > ema_max_opt_ie_size) {
            soc->ema_ap_optional_ie_size = ema_max_opt_ie_size;
        }
    } else {
        soc->ema_ap_optional_ie_size = 0;
    }

    mbss_debug("ema_ap_optional_ie_config_size: 0x%x",
                    soc->ema_ap_optional_ie_size);
}

int
ol_ath_pdev_get_dpd_status_event_handler(ol_soc_t sc,
                                         u_int8_t *data,
                                         u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_host_pdev_get_dpd_status_event event = {0};
    struct wmi_unified *wmi_handle;
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_pdev *pdev;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("null wmi_handle");
        return -EINVAL;
    }

    if (wmi_extract_dpd_status_ev_param(wmi_handle, data, &event)) {
        qdf_err("Failed to extract dpd status event");
        return -1;
    }

    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj,
                                      event.pdev_id,
                                      WLAN_MLME_NB_ID);
    if (!pdev) {
        qdf_err("pdev object (id: %d) is NULL", event.pdev_id);
        return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
        qdf_err("scn obj is NULL");
        return -1;
    }

    if (event.dpd_status)
        scn->dpdenable = CLI_DPD_STATUS_PASS;
    else
        scn->dpdenable = CLI_DPD_STATUS_FAIL;

    return 0;
}

int
ol_ath_soc_attach(ol_ath_soc_softc_t *soc,
                  IEEE80211_REG_PARAMETERS *ieee80211_conf_parm,
                  ol_ath_update_fw_config_cb cfg_cb)
{
    int status = 0;
    QDF_STATUS ret = QDF_STATUS_SUCCESS;
    struct mgmt_txrx_mgmt_frame_cb_info rx_cb_info;
    struct target_psoc_info *tgt_psoc_info = NULL;
    void *wmi_handle = NULL;
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    void *dp_ext_hdl = NULL;
    struct wmi_unified_attach_params wmi_params = {0};
    HTC_HANDLE htc_handle;
#if WLAN_SPECTRAL_ENABLE
    struct spectral_wmi_ops wmi_ops;
    struct spectral_tgt_ops tgt_ops;
#endif /* WLAN_SPECTRAL_ENABLE */
    uint8_t tgt_type = 0;

    wmi_params.osdev = soc->sc_osdev;
    wmi_params.psoc = soc->psoc_obj;
    wmi_params.use_cookie = 0;
    wmi_params.max_commands = cfg_get(soc->psoc_obj, CFG_OL_MAX_WMI_CMDS);
    wmi_params.soc_id = soc->soc_idx;
    wmi_params.is_async_ep = 1;

    soc->cfg_cb = cfg_cb;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        goto attach_failed;
    }

    /* detect low memory system */
    if (!cfg_get(soc->psoc_obj, CFG_OL_LOW_MEM_SYSTEM)) {
        if ((qdf_get_totalramsize() < LOW_MEM_SYSTEM_RAM) &&
                (target_psoc_get_target_type(tgt_psoc_info) == TARGET_TYPE_IPQ4019)) {
            //  low_mem_system is true
            soc->low_mem_system = true;
        }
    }

    if (soc->ol_if_ops->target_init) {
        status = soc->ol_if_ops->target_init(soc, true);
	if (status != EOK) {
            goto attach_failed;
        }
    }

    /* Get the WMI target type - TLV or Non-TLV based on target */
    if (ol_ath_get_wmi_target_type(soc, &wmi_params.target_type)) {
                status = -1;
                goto attach_failed;
    }

    /* Event handlers and extract APIs and init cmd use soc->wmi_handle
     * and other commands uses pdev_scn->wmi_handle
     * basically, events are recieved on single CE and hence it is all mapped to
     * soc's wmi_handle...this is same as first pdev's wmi_handle.
     */
    if ((wmi_handle = wmi_unified_attach(soc, &wmi_params)) == NULL) {
        qdf_err("Failed to initialize WMI");
        status = -1;
        goto attach_failed;
    }

    target_psoc_set_wmi_hdl(tgt_psoc_info, wmi_handle);

    soc->wmi_diag_version = 0;
    qdf_info("WMI attached. wmi_handle %pK ", wmi_handle);
    /* Enable pdev_id conversion in WMI */
    wmi_pdev_id_conversion_enable((wmi_unified_t)wmi_handle, NULL, 0);

#if WMI_RECORDING
    wmi_proc_create(wmi_handle, soc->wmi_proc_entry, soc->soc_idx);
#endif

    if (dispatcher_psoc_open(soc->psoc_obj)) {
        qdf_err("Dispatcher open failed");
        status = -1;
        goto attach_failed;
    }

#if WLAN_SPECTRAL_ENABLE
    wmi_ops.wmi_spectral_configure_cmd_send  = wmi_unified_vdev_spectral_configure_cmd_send;
    wmi_ops.wmi_spectral_enable_cmd_send     = wmi_unified_vdev_spectral_enable_cmd_send;
    wmi_ops.wmi_spectral_crash_inject        = wmi_crash_inject;
    wmi_ops.wmi_extract_pdev_sscan_fw_cmd_fixed_param   = wmi_extract_pdev_sscan_fw_cmd_fixed_param;
    wmi_ops.wmi_extract_pdev_sscan_fft_bin_index = wmi_extract_pdev_sscan_fft_bin_index;
    wmi_ops.wmi_unified_register_event_handler   = wmi_unified_register_event_handler;
    wmi_ops.wmi_unified_unregister_event_handler   = wmi_unified_unregister_event_handler;
    wmi_ops.wmi_service_enabled = wmi_service_enabled;
    wlan_register_spectral_wmi_ops(soc->psoc_obj, &wmi_ops);

    tgt_ops.tgt_get_psoc_from_scn_hdl   = target_if_get_psoc_from_scn_hdl;
    wlan_register_spectral_tgt_ops(soc->psoc_obj, &tgt_ops);
#endif /* WLAN_SPECTRAL_ENABLE */

    init_deinit_register_tgt_psoc_ev_handlers(soc->psoc_obj);
    ol_ath_enable_pdev_map(soc);

#ifdef WLAN_SUPPORT_RF_CHARACTERIZATION
    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle,
                            wmi_chan_rf_characterization_info_event_id,
                            ol_ath_chan_rf_characterization_info_event_handler,
                            WMI_RX_UMAC_CTX);
#endif

    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle, wmi_debug_print_event_id,
                                            ol_ath_debug_print_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle, wmi_peer_tx_pn_response_event_id,
                                           ol_ath_get_pn_event_handler, WMI_RX_UMAC_CTX);

    /* Initialize FIPS WMI Event */
    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle, wmi_pdev_fips_event_id,
                                           ol_ath_fips_event_handler, WMI_RX_UMAC_CTX);

    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle, wmi_vdev_encrypt_decrypt_data_rsp_event_id,
                                           ol_ath_encrypt_decrypt_data_rsp_event_handler, WMI_RX_UMAC_CTX);

    wmi_unified_register_event_handler((wmi_unified_t)wmi_handle, wmi_tt_stats_event_id,
                          ol_ath_thermal_stats_event_handler, WMI_RX_UMAC_CTX);

    if (ol_target_lithium(soc->psoc_obj)) {
        osif_register_dev_ops_xmit(osif_ol_vap_hardstart_wifi3, OSIF_NETDEV_TYPE_OL_WIFI3);
#ifdef QCA_SUPPORT_WDS_EXTENDED
        if ((lmac_get_tgt_type(soc->psoc_obj) != TARGET_TYPE_QCA8074) &&
            cfg_get(soc->psoc_obj, CFG_OL_WDS_EXTENDED)) {
#if ATH_SUPPORT_WRAP
            if (!wlan_psoc_nif_feat_cap_get(soc->psoc_obj,
                                            WLAN_SOC_F_QWRAP_ENABLE))
#endif /* ATH_SUPPORT_WRAP */
                {
                wlan_psoc_nif_feat_cap_set(soc->psoc_obj,
                                           WLAN_SOC_F_WDS_EXTENDED);
                /* set TX handle */
                osif_register_wds_ext_dev_ops_xmit(osif_wds_ext_peer_hardstart_wifi3, OSIF_NETDEV_TYPE_OL_WIFI3);
                /* set RX handle */
                soc->wds_ext_osif_rx = (ol_txrx_rx_fp)osif_deliver_wds_ext_data_ol;
                qdf_info("WDS Extended is enabled");
                }
#if ATH_SUPPORT_WRAP
            else
                qdf_err("WDS Ext can't be enabled along with qwrap");
#endif
            }
#endif /* QCA_SUPPORT_WDS_EXTENDED */
    } else {
        osif_register_dev_ops_xmit(osif_ol_ll_vap_hardstart, OSIF_NETDEV_TYPE_OL);
    }

    if (soc->ol_if_ops->cdp_soc_attach) {
        soc_txrx_handle = soc->ol_if_ops->cdp_soc_attach(soc->device_id,
                         lmac_get_ol_hif_hdl(soc->psoc_obj),
                         (struct cdp_ctrl_objmgr_psoc *)soc->psoc_obj,
                         lmac_get_htc_hdl(soc->psoc_obj),
                         (void *)soc->qdf_dev, &dp_ol_if_ops);
        if (!soc_txrx_handle) {
            qdf_err("soc attach failed");
            status = -EIO;
            goto attach_failed;
        }
        wlan_psoc_set_dp_handle(soc->psoc_obj, soc_txrx_handle);
    }

    /* Read configurations relevant to ema ap. Following params
     * will be required for calculating ema ap related resource
     * config in INIT cmd and need to be read prior to
     * ol_target_init_complete() call
     */
    soc->ema_ap_beacon_common_part_size = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_BEACON_COMMON_PART_SIZE);

    soc->ema_ap_rnr_field_size_limit = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_RNR_FIELD_SIZE_LIMIT);

    soc->ema_ap_num_max_vaps = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_NUM_MAX_VAPS);

    soc->disable_6ghz_mbssid = false;

    soc->ema_ap_feature_config = cfg_get(soc->psoc_obj,
                                         CFG_OL_MBSS_IE_ENABLE);

    soc->ema_ap_vendor_ie_config_low  = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_VENDOR_IE_SIZE_LOW);
    soc->ema_ap_vendor_ie_config_high = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_VENDOR_IE_SIZE_HIGH);

    soc->ema_ap_optional_ie_size =
        cfg_get(soc->psoc_obj, CFG_OL_EMA_AP_OPTIONAL_IE_SIZE);

    /* For WPS support in EMA in 6Ghz */
    soc->ema_ap_support_wps_6ghz = cfg_get(soc->psoc_obj,
                                        CFG_OL_EMA_AP_SUPPORT_WPS_IN_6GHZ);

#if QCA_SUPPORT_EMA_EXT
    /* Get ema-ext feature support bit from INI */
    soc->ema_ap_ext_enabled = cfg_get(soc->psoc_obj,
                                    CFG_OL_ENABLE_EMA_EXT);

    soc->mbss_split_profile_enabled = cfg_get(soc->psoc_obj, CFG_OL_SPLIT_NON_TX_PROFILE_ENABLED);
#else
    soc->ema_ap_ext_enabled = 0;
    soc->mbss_split_profile_enabled = 0;
#endif

    /* Limit ema_ap_num_max_vaps by CFG_OL_EMA_AP_NUM_MAX_VAPS_WITH_WPS
     * if ema_ap_support_wps_6ghz is true
     */
    if (soc->ema_ap_support_wps_6ghz) {
        if (soc->ema_ap_num_max_vaps >
                cfg_get(soc->psoc_obj, CFG_OL_EMA_AP_NUM_MAX_VAPS_WITH_WPS)) {
            soc->ema_ap_num_max_vaps =
                cfg_get(soc->psoc_obj, CFG_OL_EMA_AP_NUM_MAX_VAPS_WITH_WPS);
        }
        mbss_info("WPS support with EMA enabled in 6Ghz");
        mbss_info("Total ema vaps configured: %d", soc->ema_ap_num_max_vaps);
    }

    /* Promote soc->ema_ap_num_max_vaps to next power of 2 if not
     * already so. The rotation factor logic used in relation to
     * change of Tx-vap is dependent on the assumption that this
     * ema-param is power of 2
     */
    if (!QDF_IS_PWR2(soc->ema_ap_num_max_vaps))
        soc->ema_ap_num_max_vaps = roundup_pow_of_two(soc->ema_ap_num_max_vaps);

    /* Max space available for a non-tx vap in a single beacon or
     * probe response frame
     */
    soc->ema_ap_max_non_tx_size = IEEE80211_MAX_MGMT_SIZE_LIMIT -
                                 (soc->ema_ap_beacon_common_part_size +
                                  soc->ema_ap_rnr_field_size_limit +
                                  IEEE80211_EMA_MAX_HEADROOM_SIZE);

    /* Initialize max-pp to 1 */
    soc->ema_ap_max_pp = 1;

    /* Sanitize user configured vendor-ie config with respect
     * to number of vaps and allowed limit
     */
    ol_ath_sanitize_ema_vendor_ie_config(soc);

    /* Sanitize user configured optional-ie config with
     * respect to number of vaps and size remaining
     * after sanitizing vendor ies
     */
    ol_ath_sanitize_ema_optional_ie_config(soc);

    /* Read configuration for overriding default RNR advertisement
     * behavior (default is selective advertisement only)
     */
    soc->rnr_6ghz_adv_override = cfg_get(soc->psoc_obj,
                                 CFG_OL_6GHZ_RNR_ADV_OVERRIDE);

    ol_ath_set_pdevid_to_phyid_map(soc);

    soc->max_rnr_ie_allowed = cfg_get(soc->psoc_obj, CFG_OL_MAX_RNR_IE_ALLOWED);

    if (ol_target_init_complete(soc)) {
        status = -1;
        goto target_init_failed;
    }

    if (lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA8074 ||
            lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCN6122 ||
            lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA8074V2 ||
            lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA5018 ||
            lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCN9000 ||
            lmac_get_tgt_type(soc->psoc_obj) == TARGET_TYPE_QCA6018) {
        if (qca_register_netdevice_notifier(&qca_device_notifier))
            goto target_init_failed;
    }

    /* Register scan entry update callback */
    ucfg_scan_register_bcn_cb(soc->psoc_obj,
        wlan_scan_cache_update_callback, SCAN_CB_TYPE_UPDATE_BCN);

    /* UMAC Disatcher enable/start all components under PSOC */
    ret = dispatcher_psoc_enable(soc->psoc_obj);
    if (QDF_STATUS_SUCCESS != ret) {
        goto target_init_failed;
    }

#ifdef DIRECT_BUF_RX_ENABLE
    if (direct_buf_rx_target_attach(soc->psoc_obj,
                          hif_get_hal_handle(lmac_get_hif_hdl(soc->psoc_obj)),
                          soc->qdf_dev) != QDF_STATUS_SUCCESS) {
        qdf_err("Direct Buffer Rx Target Attach Failed");
    }
#endif

    /*
     * 8. Connect Services to HTC
     */
    qdf_info("connect HTC");
    qdf_info("bypasswmi : %d",bypasswmi);
    if (!bypasswmi) {

        soc->max_clients = cfg_get(soc->psoc_obj, CFG_OL_MAX_CLIENTS);
        soc->max_vaps    = cfg_get(soc->psoc_obj, CFG_OL_MAX_VAPS);

#ifdef QVIT
        ol_ath_qvit_attach(soc);
#endif

        if(soc->ol_if_ops->wds_addr_init) {
            soc->ol_if_ops->wds_addr_init((wmi_unified_t)wmi_handle);
        }

        wmi_unified_register_event_handler(wmi_handle, wmi_unit_test_event_id,
                unit_test_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_wlan_profile_data_event_id,
                                                ol_ath_wlan_profile_data_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_tpc_config_event_id,
                                                ol_ath_pdev_tpc_config_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_gpio_input_event_id,
                                                ol_ath_gpio_input_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_nfcal_power_all_channels_event_id,
                                                ol_ath_nf_dbr_dbm_info_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_tpc_event_id,
                                                ol_ath_packet_power_info_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_generic_buffer_event_id,
                                                ol_ath_generic_buffer_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_peer_tx_mu_txmit_count_event_id,
                                                ol_ath_peer_mumimo_tx_count_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_peer_gid_userpos_list_event_id,
                                                ol_ath_peer_gid_userpos_list_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_check_cal_version_event_id,
                                                ol_ath_pdev_caldata_version_check_event_handler, WMI_RX_UMAC_CTX);
#if QCN_ESP_IE
        wmi_unified_register_event_handler(wmi_handle, wmi_esp_estimate_event_id,
                                                ol_ath_esp_estimate_event_handler, WMI_RX_UMAC_CTX);
#endif
        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_ctl_failsafe_check_event_id,
                                                ol_ath_pdev_ctl_failsafe_check_event_handler, WMI_RX_UMAC_CTX);

        if (ol_ath_is_dynamic_hw_mode_enabled(soc)) {
            wmi_unified_register_event_handler(wmi_handle, wmi_pdev_set_hw_mode_rsp_event_id,
                                                ol_ath_soc_hw_mode_change_event_handler, WMI_RX_UMAC_CTX);
        }

        wmi_unified_register_raw_event_handler(wmi_handle, wmi_pdev_cp_fwstats_eventid,
                                               ol_ath_cp_fwstats_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(wmi_handle, wmi_vdev_tsf_report_event_id,
                                           ol_ath_vdev_tsf_report_event_handler, WMI_RX_UMAC_CTX);
        wmi_unified_register_event_handler(wmi_handle, wmi_pdev_get_dpd_status_event_id,
                                           ol_ath_pdev_get_dpd_status_event_handler, WMI_RX_UMAC_CTX);

        ol_ath_soc_twt_attach(soc);
        ol_ath_soc_dcs_attach(soc);

        ol_ath_node_soc_attach(soc);
        ol_ath_phyerr_attach(soc);
        ol_ath_stats_soc_attach(soc);
        ol_ath_soc_chan_info_attach(soc);
        ol_ath_vap_soc_attach(soc);
        ol_ath_wow_soc_attach(soc);
        ol_ath_beacon_soc_attach(soc);
        ol_ath_mgmt_soc_attach(soc);
    }

   tgt_type = lmac_get_tgt_type(soc->psoc_obj);

#if WLAN_SUPPORT_MSCS && QCA_NSS_PLATFORM
  /*
   * Initialize MSCS module
   */
    if (tgt_type == TARGET_TYPE_QCA8074 ||
            tgt_type == TARGET_TYPE_QCA8074V2 ||
            tgt_type == TARGET_TYPE_QCA5018 ||
            tgt_type == TARGET_TYPE_QCN9000 ||
            tgt_type == TARGET_TYPE_QCA6018) {
        qca_mscs_module_init(soc);
    }
#endif

    qdf_info("UMAC attach");

    /*
     * Register Rx callback with mgmt_txrx layer for receiving
     * mgmt frames.
     */
    rx_cb_info.frm_type = MGMT_FRAME_TYPE_ALL;
    rx_cb_info.mgmt_rx_cb = ieee80211_mgmt_input;
    wlan_mgmt_txrx_register_rx_cb(soc->psoc_obj, WLAN_UMAC_COMP_MLME,
                                       &rx_cb_info, 1);

#if QLD
    qdf_event_create(&soc->qld_wait);
#endif

#if QCA_11AX_STUB_SUPPORT
    if (1 == OL_ATH_IS_11AX_STUB_ENABLED(soc)) {
        qdf_info("%s: 802.11ax stubbing enabled",
                soc->sc_osdev->netdev->name);
    }
#endif /* QCA_11AX_STUB_SUPPORT */

    return EOK;

target_init_failed:
    dispatcher_psoc_close(soc->psoc_obj);

attach_failed:
    qdf_err("error status %d", status);

#if WLAN_SUPPORT_MSCS && QCA_NSS_PLATFORM
  /*
   * De-Init MSCS module
   */
    if (tgt_type == TARGET_TYPE_QCA8074 ||
            tgt_type == TARGET_TYPE_QCA8074V2 ||
            tgt_type == TARGET_TYPE_QCA5018 ||
            tgt_type == TARGET_TYPE_QCN9000 ||
            tgt_type == TARGET_TYPE_QCA6018) {
        qca_mscs_module_deinit(soc);
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
        qdf_info("nss-wifi: detach -zero delay ");
        soc->nss_soc.ops->nss_soc_wifi_detach(soc, 0);
    }
#endif
    init_deinit_free_num_units(soc->psoc_obj, tgt_psoc_info);

    htc_handle=target_psoc_get_htc_hdl(tgt_psoc_info);
    if (htc_handle) {
        htc_destroy(htc_handle);
        target_psoc_set_htc_hdl(tgt_psoc_info, NULL);
    }

#ifdef WLAN_FEATURE_BMI
    if (soc->bmi_handle) {
        if (soc->bmi_handle->bmi_cleanup)
            soc->bmi_handle->bmi_cleanup(soc->bmi_handle,soc->sc_osdev);
        if (soc->bmi_handle->bmi_free)
            soc->bmi_handle->bmi_free(soc->bmi_handle);
    }
#endif
    if (!bypasswmi) {
        if ((wmi_unified_t)wmi_handle) {
            wmi_unified_detach((wmi_unified_t)wmi_handle);
#if WMI_RECORDING
            wmi_proc_remove((wmi_unified_t)wmi_handle, soc->wmi_proc_entry, soc->soc_idx);
#endif
            wmi_handle = NULL;
            target_psoc_set_wmi_hdl(tgt_psoc_info, NULL);

        }
        soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);
        if (soc_txrx_handle) {
            cdp_txrx_intr_detach(soc_txrx_handle);
            dp_ext_hdl = cdp_soc_get_dp_txrx_handle(soc_txrx_handle);
            cdp_soc_set_dp_txrx_handle(soc_txrx_handle, NULL);

            if (dp_ext_hdl)
                qdf_mem_free(dp_ext_hdl);

            wlan_psoc_set_dp_handle(soc->psoc_obj, NULL);
            cdp_soc_detach(soc_txrx_handle);
#ifdef WLAN_FEATURE_FASTPATH
            soc->htt_handle = NULL;
#endif
        }

	if (soc->dbg_log_init) {
	    ol_ath_dbglog_detach(soc);
	    soc->dbg_log_init = 0;
	}
    }
#ifdef AH_CAL_IN_FLASH_PCI
#ifndef ATH_CAL_NAND_FLASH
    if (soc->cal_mem) {
        A_IOUNMAP(soc->cal_mem);
        soc->cal_mem = 0;
    }
#endif
    soc->cal_in_flash = 0;
#endif
    soc->cal_in_file = 0;
    soc->soc_lp_iot_vaps_mask = 0;

    return status;
}

static int ol_ath_pdev_regdmn_init(struct ol_ath_softc_net80211 *scn,
                                IEEE80211_REG_PARAMETERS *ieee80211_conf_param)
{
    ol_ath_soc_softc_t *soc = scn->soc;
    uint8_t pdev_idx;
    struct ieee80211com *ic;
    int status = 0;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    struct target_pdev_info *tgt_pdev;
    struct target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;
    struct wlan_psoc_target_capability_info *target_cap;
    struct wmi_unified *wmi_handle;
    uint8_t reg_cap_phy_idx;

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("target hdl is null");
        return -EINVAL;
    }

    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(pdev);
    if (!tgt_pdev) {
        target_if_err("target_pdev_info is null");
        return -EINVAL;
    }

    pdev_idx = target_pdev_get_pdev_idx(tgt_pdev);
    if (pdev_idx < 0) {
        qdf_err("pdev idx is invalid");
        return -EINVAL;
    }

    reg_cap_phy_idx = target_pdev_get_phy_idx(tgt_pdev);
    if (reg_cap_phy_idx < 0) {
        qdf_err("reg_cap_phy_idx is invalid");
        return -EINVAL;
    }

    target_cap  = target_psoc_get_target_caps(tgt_hdl);
    mac_phy_cap = target_psoc_get_mac_phy_cap(tgt_hdl);
    reg_cap     = ucfg_reg_get_hal_reg_cap(psoc);

    if (!reg_cap)
        return -EINVAL;

    if (!mac_phy_cap)
        qdf_err("mac_phy_cap is NULL");

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle)
        return -EINVAL;

    ic = &scn->sc_ic;

    /* If extended service ready is supported by firmware, Use mac_phy
     * capabilities provided by extended service ready event instead of
     * service ready event. Extended service ready will override caps
     * recieved in service ready
     */
    if (wmi_service_enabled(wmi_handle, wmi_service_ext_msg) && mac_phy_cap) {
        target_if_info(" phy id = %d Modes supported", pdev_idx);
        target_if_info(" 11b = %d 11g = %d 11a = %d 11n = %d 11ac = %d 11ax = %d",
                mac_phy_cap[pdev_idx].supports_11b,
                mac_phy_cap[pdev_idx].supports_11g,
                mac_phy_cap[pdev_idx].supports_11a,
                mac_phy_cap[pdev_idx].supports_11n,
                mac_phy_cap[pdev_idx].supports_11ac,
                mac_phy_cap[pdev_idx].supports_11ax);

        target_if_info(" Reg cap - phy_id = %d supp_bnd = %x, modes = %x, "
                "lo_2g = %d, hi_2g = %d lo_g5 = %d, hi_5g = %d", pdev_idx,
                mac_phy_cap[pdev_idx].supported_bands,
                reg_cap[reg_cap_phy_idx].wireless_modes,
                reg_cap[reg_cap_phy_idx].low_2ghz_chan,
                reg_cap[reg_cap_phy_idx].high_2ghz_chan,
                reg_cap[reg_cap_phy_idx].low_5ghz_chan,
                reg_cap[reg_cap_phy_idx].high_5ghz_chan);

        ol_ath_update_wireless_modes(ic, &reg_cap[reg_cap_phy_idx], &mac_phy_cap[pdev_idx]);

        ol_ath_update_target_cap_from_mac_phy_cap(target_cap,
                                      &mac_phy_cap[pdev_idx]);
        ol_ath_update_ext_caps(&mac_phy_cap[pdev_idx], ic);
        /* update supprted bands from mac_phy_cap */
        ic->ic_supported_bands = mac_phy_cap[pdev_idx].supported_bands;
        ic->ic_tgt_defined_nss_ratio_enabled = mac_phy_cap[pdev_idx].nss_ratio_enabled;
        ic->ic_tgt_defined_nss_ratio = mac_phy_cap[pdev_idx].nss_ratio_info;
    }

    ol_ath_update_caps(ic, target_cap);

    ol_ath_update_6g_band_caps(ic);

    if (mac_phy_cap) {
        if (mac_phy_cap->supported_bands == WMI_HOST_WLAN_5G_CAPABILITY) {
           if ((mac_phy_cap[pdev_idx].he_cap_phy_info_5G[0]) &
               IEEE80211_HECAP_LDPC_MASK)
               ieee80211com_set_ldpccap(ic, IEEE80211_HECAP_C_LDPC_TXRX);
           else
               qdf_info("LDPC not supported in 5G HE CAP");
        } else if (mac_phy_cap->supported_bands == WMI_HOST_WLAN_2G_CAPABILITY) {
           if ((mac_phy_cap[pdev_idx].he_cap_phy_info_2G[0]) &
               IEEE80211_HECAP_LDPC_MASK)
               ieee80211com_set_ldpccap(ic, IEEE80211_HECAP_C_LDPC_TXRX);
           else
               qdf_info("LDPC not supported in 2G HE CAP");
        } else
           qdf_info("Band 2G or 5G check failed. LDPC is not updated. Supported bands = %x",
                         mac_phy_cap->supported_bands);
    }

    if (mac_phy_cap)
        ol_ath_update_chainmask(ic, target_cap, &mac_phy_cap[pdev_idx]);
    else
        ol_ath_update_chainmask(ic, target_cap, NULL);

    scn->max_tx_power = target_cap->hw_max_tx_power;
    scn->min_tx_power = target_cap->hw_min_tx_power;

    scn->txpowlimit2G = scn->max_tx_power;
    scn->txpowlimit5G = scn->max_tx_power;
    scn->txpower_scale = WMI_HOST_TP_SCALE_MAX;

    ieee80211com_set_txpowerlimit(ic, scn->max_tx_power);

    ol_regdmn_attach(scn);

    ol_regdmn_set_regdomain(scn->ol_regdmn_handle, reg_cap[reg_cap_phy_idx].eeprom_reg_domain);
    ol_regdmn_set_regdomain_ext(scn->ol_regdmn_handle, reg_cap[reg_cap_phy_idx].eeprom_reg_domain_ext);
#if QCA_11AX_STUB_SUPPORT
    if (1 == OL_ATH_IS_11AX_STUB_ENABLED(soc)) {
        ol_regdmn_stub_add_11ax_modes(scn->ol_regdmn_handle);
    }
#endif /* QCA_11AX_STUB_SUPPORT */
    if (target_psoc_get_target_ver(tgt_hdl) == AR6004_VERSION_REV1_3) {
        /*
           It's Hard code for HAL capability and We don't use this branch for McKinley.
           Because McKinley don't support WMI UNIFIED SERVICE READY,
           */
        reg_cap[reg_cap_phy_idx].eeprom_reg_domain = 0;
        reg_cap[reg_cap_phy_idx].eeprom_reg_domain_ext = 0x1f;
        reg_cap[reg_cap_phy_idx].high_2ghz_chan = 0xaac;
        reg_cap[reg_cap_phy_idx].high_5ghz_chan = 0x17d4;
        reg_cap[reg_cap_phy_idx].low_2ghz_chan = 0x908;
        reg_cap[reg_cap_phy_idx].low_5ghz_chan = 0x1338;
        reg_cap[reg_cap_phy_idx].regcap1 = 7;
        reg_cap[reg_cap_phy_idx].regcap2 = 0xbc0;
        reg_cap[reg_cap_phy_idx].wireless_modes = 0x1f9001;
        ol_regdmn_attach(scn);
        ol_regdmn_set_regdomain(scn->ol_regdmn_handle, reg_cap[reg_cap_phy_idx].eeprom_reg_domain);
        ol_regdmn_set_regdomain_ext(scn->ol_regdmn_handle, reg_cap[reg_cap_phy_idx].eeprom_reg_domain_ext);
    }
    if (wmi_service_enabled(wmi_handle, wmi_service_restrt_chnl_support)) {
        ic->ic_rch_params.restrict_channel_support = 1;
        ic->ic_rch_params.low_5ghz_chan  = reg_cap[reg_cap_phy_idx].low_5ghz_chan;
        ic->ic_rch_params.high_5ghz_chan = reg_cap[reg_cap_phy_idx].high_5ghz_chan;

        qdf_info("low_5ghz: %d  high_5gh: %d",
                 reg_cap[reg_cap_phy_idx].low_5ghz_chan,
                 reg_cap[reg_cap_phy_idx].high_5ghz_chan);
    } else {
        ic->ic_rch_params.restrict_channel_support = 0;
    }

    ic->ic_emiwar_80p80 = ol_ath_get_emiwar_80p80_defval(soc);

    ic->ic_reg_parm = *ieee80211_conf_param;
    if (!(wmi_service_enabled(wmi_handle, wmi_service_regulatory_db)))
        ol_regdmn_start(scn->ol_regdmn_handle, ieee80211_conf_param);

    return status;
}

static bool ol_ath_is_master_radio(struct ol_ath_softc_net80211 *scn)
{
    struct  wlan_objmgr_psoc *psoc    = scn->soc->psoc_obj;
    struct  wlan_objmgr_pdev *pdev    = scn->sc_pdev;
    struct  ieee80211com     *ic      = &(scn->sc_ic);
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &scn->soc->hw_mode_ctx;
    struct  tgt_info         *info    = NULL;
    bool    is_master_radio           = false;
    struct  wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    struct  target_pdev_info *tgt_pdev;
    struct  target_psoc_info *tgt_hdl;
    uint8_t idx, num_hw_modes, num_radios, num_tx_chain;
    int32_t pdev_idx = -1;
    uint32_t supported_bands;

    /* not a master radio if feature not supported */
    if (!ol_ath_is_dynamic_hw_mode_enabled(scn->soc))
        goto exit;

    /* not a master radios if the radio does not support
     * target-band
     */
    if (!(hw_mode_ctx->target_band & ic->ic_supported_bands))
        goto exit;

    /* Master 5G radio has the capability to switch
     * between 8x8 and 4x4
     */
    /* identify the radio with IEEE80211_MAX_TX_CHAINS */

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("target hdl is null");
        goto exit;
    }

    info = &(tgt_hdl->info);

    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(pdev);
    if (!tgt_pdev) {
        target_if_err("target_pdev_info is null");
        goto exit;
    }

    pdev_idx = target_pdev_get_pdev_idx(tgt_pdev);
    if (pdev_idx < 0) {
        target_if_err("pdev idx is invalid");
        goto exit;
    }

    num_hw_modes = info->hw_modes.num_modes;

    /* check if the pdev corresponding to 'pdev_idx'
     * has max tx chain capacity for any of the modes
     */
    for (idx = 0; idx < num_hw_modes; idx++) {
        num_radios  = target_psoc_get_num_radios_for_mode
                        (tgt_hdl, info->hw_modes.hw_mode_ids[idx]);
        mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode
                         (tgt_hdl, info->hw_modes.hw_mode_ids[idx]);

        if (pdev_idx < num_radios && mac_phy_cap) {
            supported_bands = mac_phy_cap[pdev_idx].supported_bands;

            if (supported_bands & WMI_HOST_WLAN_5G_CAPABILITY) {
                num_tx_chain = num_chain_from_chain_mask(
                                    mac_phy_cap[pdev_idx].tx_chain_mask_5G);

            } else if (supported_bands & WMI_HOST_WLAN_2G_CAPABILITY) {
                num_tx_chain =  num_chain_from_chain_mask(
                                    mac_phy_cap[pdev_idx].tx_chain_mask_2G);
            } else {
                /* Code required if band support extended in
                 * future. For now initialize num_tx_chain to
                 * 0.
                 */
                num_tx_chain = 0;
            }

            if (num_tx_chain == IEEE80211_MAX_TX_CHAINS) {
                is_master_radio = true;
                break;
            }
        } /* end if (pdev_idx < num_radios) */
    } /* end for */

exit:
    if (pdev_idx >= 0)
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_INFO,
                  FL("pdev_idx: %d is_master_radio: %s"),
                  pdev_idx, is_master_radio ? "YES" : "NO");
    return is_master_radio;
}

uint8_t ol_ath_get_max_supported_radios(ol_ath_soc_softc_t *soc)
{
    struct  wlan_objmgr_psoc *psoc    = soc->psoc_obj;
    struct  tgt_info         *info    = NULL;
    uint8_t max_num_radios            = 0;
    struct  target_psoc_info *tgt_hdl;
    uint8_t idx, num_hw_modes, num_radios;

    /* return default if feature not supported */
    if (!ol_ath_is_dynamic_hw_mode_enabled(soc))
        goto exit;

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("target hdl is null");
        goto exit;
    }

    info = &(tgt_hdl->info);

    num_hw_modes = info->hw_modes.num_modes;

    for (idx = 0; idx < num_hw_modes; idx++) {
        num_radios = target_psoc_get_num_radios_for_mode
                        (tgt_hdl, info->hw_modes.hw_mode_ids[idx]);

        if (num_radios > max_num_radios)
            max_num_radios = num_radios;
    }

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
              QDF_TRACE_LEVEL_INFO,
              FL("max_num_radios: %d"), max_num_radios);

exit:
    return max_num_radios;
}

static int ol_ath_reconfig_pdev_post_hw_mode_switch(
        struct ol_ath_softc_net80211 *scn)
{
    ol_ath_soc_softc_t *soc           = scn->soc;
    uint8_t pdev_idx;
    struct ieee80211com *ic;
    struct wlan_objmgr_psoc *psoc     = soc->psoc_obj;
    struct wlan_objmgr_pdev *pdev     = scn->sc_pdev;
    struct target_pdev_info *tgt_pdev;
    struct target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;
    struct wlan_psoc_target_capability_info *target_cap;
    struct wmi_unified *wmi_handle;
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &soc->hw_mode_ctx;
    int status = 0;

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        status = -EINVAL;
        goto exit;
    }

    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(pdev);
    if (!tgt_pdev) {
        qdf_err("target_pdev_info is null");
        status = -EINVAL;
        goto exit;
    }

    pdev_idx = target_pdev_get_phy_idx(tgt_pdev);
    if (pdev_idx < 0) {
        qdf_err("pdev idx is invalid");
        status = -EINVAL;
        goto exit;
    }

    target_cap = target_psoc_get_target_caps(tgt_hdl);
    mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode(tgt_hdl, hw_mode_ctx->target_mode);

    if (!mac_phy_cap)
        qdf_err("mac phy cap is NULL");

    reg_cap = ucfg_reg_get_hal_reg_cap(psoc);
    if (!reg_cap) {
        qdf_err("invalid reg_cap");
        status = -EINVAL;
        goto exit;
    }

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("invalid wmi_handle");
        status = -EINVAL;
        goto exit;
    }

    ic = &scn->sc_ic;

    /* If extended service ready is supported by firmware, Use mac_phy
     * capabilities provided by extended service ready event instead of
     * service ready event. Extended service ready will override caps
     * received in service ready
     */
    if (wmi_service_enabled(wmi_handle, wmi_service_ext_msg) && mac_phy_cap) {
        ol_ath_update_band_mapping(&reg_cap[pdev_idx], &mac_phy_cap[pdev_idx]);

        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_DEBUG,
                  "phy id = %d Modes supported", pdev_idx);

        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_DEBUG,
                  " 11b = %d 11g = %d 11a = %d 11n = %d 11ac = %d 11ax = %d",
                  mac_phy_cap[pdev_idx].supports_11b,
                  mac_phy_cap[pdev_idx].supports_11g,
                  mac_phy_cap[pdev_idx].supports_11a,
                  mac_phy_cap[pdev_idx].supports_11n,
                  mac_phy_cap[pdev_idx].supports_11ac,
                  mac_phy_cap[pdev_idx].supports_11ax);

        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_DEBUG,
                  " Reg cap - phy_id = %d supp_bnd = %x, modes = %x, "
                  "lo_2g = %d, hi_2g = %d lo_g5 = %d, hi_5g = %d",
                  pdev_idx,
                  mac_phy_cap[pdev_idx].supported_bands,
                  reg_cap[pdev_idx].wireless_modes,
                  reg_cap[pdev_idx].low_2ghz_chan,
                  reg_cap[pdev_idx].high_2ghz_chan,
                  reg_cap[pdev_idx].low_5ghz_chan,
                  reg_cap[pdev_idx].high_5ghz_chan);

        ol_ath_update_wireless_modes_ext(&reg_cap[pdev_idx], &mac_phy_cap[pdev_idx]);
        ol_ath_update_target_cap_from_mac_phy_cap(target_cap,
                                  &mac_phy_cap[pdev_idx]);
        ol_ath_update_ext_caps(&mac_phy_cap[pdev_idx], ic);
        /* update supprted bands from mac_phy_cap */
        ic->ic_supported_bands = mac_phy_cap[pdev_idx].supported_bands;
    }

    ol_ath_update_caps(ic, target_cap);

    if (mac_phy_cap)
        ol_ath_update_chainmask(ic, target_cap, &mac_phy_cap[pdev_idx]);
    else
        ol_ath_update_chainmask(ic, target_cap, NULL);

    scn->max_tx_power  = target_cap->hw_max_tx_power;
    scn->min_tx_power  = target_cap->hw_min_tx_power;

    scn->txpowlimit2G  = scn->max_tx_power;
    scn->txpowlimit5G  = scn->max_tx_power;
    scn->txpower_scale = WMI_HOST_TP_SCALE_MAX;

    ieee80211com_set_txpowerlimit(ic, scn->max_tx_power);

exit:
    return status;
}

static void ol_ath_update_phymode_caps(struct ieee80211com *ic, enum ieee80211_phymode mode)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    struct target_pdev_info *tgt_pdev;
    struct target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap_arr;
    int32_t pdev_idx;
    struct wmi_unified *wmi_handle;

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("target handle is null");
        return;
    }

    tgt_pdev = wlan_pdev_get_tgt_if_handle(pdev);
    if (!tgt_pdev) {
        target_if_err("target_pdev_info is null");
        return;
    }

    pdev_idx = target_pdev_get_pdev_idx(tgt_pdev);
    if (pdev_idx < 0) {
        qdf_info("pdev idx is invalid ");
        return;
    }
    QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_DEBUG,
            "pdev id is %d \n",pdev_idx);

    wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);

    if (wmi_service_enabled(wmi_handle,
                wmi_service_ext_msg)) {

        struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;

        mac_phy_cap_arr = target_psoc_get_mac_phy_cap(tgt_hdl);
        if (!mac_phy_cap_arr) {
            qdf_info("mac phy cap is NULL ");
            return;
        }

        mac_phy_cap = &mac_phy_cap_arr[pdev_idx];

        if (ieee80211_is_phymode_2g(mode)) {
            ieee80211com_clear_htcap(ic, -1);
            ieee80211com_clear_vhtcap(ic, -1);
            ol_ath_update_ht_caps(ic, mac_phy_cap->ht_cap_info_2G);
            ol_ath_update_vht_caps(ic, mac_phy_cap->vht_cap_info_2G,
                    mac_phy_cap->vht_supp_mcs_2G);
            ol_ath_populate_he_caps(ic, mac_phy_cap->he_cap_info_2G,
                    &mac_phy_cap->he_supp_mcs_2G,
                    mac_phy_cap->he_cap_phy_info_2G, sizeof(mac_phy_cap->he_cap_phy_info_2G),
                    &mac_phy_cap->he_ppet2G, &mac_phy_cap->he_cap_info_internal);
        } else if (ieee80211_is_phymode_5g_or_6g(mode)) {
            /*
             * 6GHz: no separate 6G handling required as 6G phy will not
             * report ht_cap_info_5G, vht_cap_info_5G.
             */
            ieee80211com_clear_htcap(ic, -1);
            ieee80211com_clear_vhtcap(ic, -1);
            ol_ath_update_ht_caps(ic, mac_phy_cap->ht_cap_info_5G);
            ol_ath_update_vht_caps(ic, mac_phy_cap->vht_cap_info_5G,
                    mac_phy_cap->vht_supp_mcs_5G);
            ol_ath_populate_he_caps(ic, mac_phy_cap->he_cap_info_5G,
                    &mac_phy_cap->he_supp_mcs_5G,
                    mac_phy_cap->he_cap_phy_info_5G, sizeof(mac_phy_cap->he_cap_phy_info_5G),
                    &mac_phy_cap->he_ppet5G, &mac_phy_cap->he_cap_info_internal);
        } else {
            qdf_debug("Error Mode %d not 2G or 5G", mode);
        }
    }
}

/**
 * ol_ath_is_dynamic_hw_mode_enabled(): Checks if FW supports
 * dynamic_hw_mode feature and if it is enabled in host
 * @soc: soc handle
 *
 * return: true if supported, false otherwise
 */
bool ol_ath_is_dynamic_hw_mode_enabled(ol_ath_soc_softc_t *soc)
{
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    bool fw_support               = wlan_psoc_nif_fw_ext_cap_get(psoc,
                                    WLAN_SOC_CEXT_DYNAMIC_HW_MODE);
    bool feature_support          = wlan_psoc_nif_feat_cap_get(psoc,
                                    WLAN_SOC_F_DYNAMIC_HW_MODE);
    bool is_enabled               = fw_support & feature_support;

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
            FL("is_enabled: %d fw_support: %d feature_support: %d"),
            is_enabled, fw_support, feature_support);

    return is_enabled;
}

/**
 * ol_ath_handle_dbs_sbs_to_dbs_switch_in_dp(): Handles DP-
 * impact of switching from DBS_SBS to DBS mode
 * @ic: ic pointer
 *
 * Return: none
 */
static void ol_ath_handle_dbs_sbs_to_dbs_switch_in_dp(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    ol_txrx_soc_handle soc_txrx_handle;

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    cdp_txrx_set_pdev_status_down(soc_txrx_handle,
                        wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj), true);
}

/**
 * ol_ath_handle_dbs_to_dbs_sbs_switch_in_dp(): Handles DP-
 * impact of switching from DBS to DBS_SBS mode
 * @ic: ic pointer
 *
 * Return: none
 */
static void ol_ath_handle_dbs_to_dbs_sbs_switch_in_dp(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    ol_txrx_soc_handle soc_txrx_handle;

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    cdp_txrx_set_pdev_status_down(soc_txrx_handle,
                        wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj), false);
}

/**
 * ol_ath_hw_mode_config_primary_pdev(): Config primary pdev
 * during dynamic mode switch between DBS_SBS and DBS
 * @soc : soc handle
 * @up  : bool to indicate up or down
 *
 * return: QDF_STATUS_SUCCESS in case of success and
 * QDF_STATUS_E_INVAL otherwise
 */
static QDF_STATUS ol_ath_hw_mode_config_primary_pdev(ol_ath_soc_softc_t *soc,
                                                     bool up)
{
    struct wlan_objmgr_psoc *psoc        = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &soc->hw_mode_ctx;
    struct wlan_objmgr_pdev *pdev = hw_mode_ctx->primary_pdev;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;
    struct ieee80211vap *vap;
    bool pdev_reconfig_success;
    int status = QDF_STATUS_SUCCESS;
    ol_txrx_soc_handle soc_txrx_handle;

    if (!pdev) {
        status = QDF_STATUS_E_ABORTED;
        goto exit;
    }

    scn = (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                QDF_TRACE_LEVEL_ERROR, FL("scn is NULL"));
        status = QDF_STATUS_E_ABORTED;
        goto exit;
    }
    ic = &(scn->sc_ic);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (up) {
        if (hw_mode_ctx->is_fw_resp_success) {
            /* copy curchan params */
            ol_ath_copy_curchan_params(ic, hw_mode_ctx);

            pdev_reconfig_success =
                !ol_ath_reconfig_pdev_post_hw_mode_switch(scn);

            /* regulatory re-init */
            ol_regdmn_reinit_post_hw_mode_switch(ic);

            /* Reinit ic and vap channel structures */
            status = ol_ath_reinit_channel_params(ic, hw_mode_ctx);
            if (status != QDF_STATUS_SUCCESS) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                          QDF_TRACE_LEVEL_ERROR,
                          FL("Cannot reinit channel structures for pri.pdev!"));
                goto exit;
            }

            /* DFS Reinit. */
            status = ol_if_reinit_dfs_for_mode_switch_fast(scn,
                             hw_mode_ctx->target_mode);
            if (status != QDF_STATUS_SUCCESS) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                          QDF_TRACE_LEVEL_ERROR,
                          FL("Cannot reinit DFS after mode switch!"));
                goto exit;
            }

            /* set up rates */
            ol_ath_setup_rates(ic);

            TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
                /* reconfig vap params as-per new ic-caps */
                ol_ath_update_vap_caps(vap, ic);
            }
            wlan_vap_omn_update(ic);

            /* Mode switch is complete, if a monitor VAP exists,
               bring it back up. */
            if(ic->ic_mon_vap &&
               (wlan_vdev_mlme_is_active(ic->ic_mon_vap->vdev_obj) ==
                QDF_STATUS_SUCCESS)) {

                cdp_set_monitor_mode(soc_txrx_handle,
                                     wlan_vdev_get_id(ic->ic_mon_vap->vdev_obj), 0);
            }
        } else {
            /* If modeswitch fails copy back the NOL from psoc to pdevs. */
            ol_if_dfs_reinit_nol(scn, hw_mode_ctx->target_mode);
        }
    } else {
#if WLAN_SPECTRAL_ENABLE
        enum spectral_scan_mode smode;
        struct spectral_cp_request sscan_req;

        /* Stop spectral scan if it's on-going */
        for (smode = SPECTRAL_SCAN_MODE_NORMAL; smode < SPECTRAL_SCAN_MODE_MAX; smode++) {
            sscan_req.ss_mode = smode;
            sscan_req.req_id = SPECTRAL_STOP_SCAN;

            status = ucfg_spectral_control(pdev, &sscan_req);
            if (QDF_IS_STATUS_ERROR(status)) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("Cannot stop SPECTRAL scan for primary pdev!"));
                goto exit;
            }

        } /* for */
#endif
        /* stop active scan */
        if (wlan_pdev_scan_in_progress(pdev)) {
            wlan_abort_scan(pdev,
                            wlan_objmgr_pdev_get_pdev_id(pdev),
                            INVAL_VDEV_ID, INVAL_SCAN_ID, true);
            if (QDF_IS_STATUS_ERROR(status)) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("aborting the existing scan is unsuccessful"));
                goto exit;
            }
        }

        /* DFS Deinit. */
        status = ol_if_deinit_dfs_for_mode_switch_fast(scn, hw_mode_ctx);
        if (status != QDF_STATUS_SUCCESS) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                      QDF_TRACE_LEVEL_ERROR,
                      FL("Cannot deinit DFS before mode switch!"));
            goto exit;
        }

        /* Mode switch is starting, bring down monitor VAP as FW
           will not retain the filter settings. After mode switch
           completion, bring up monitor VAP if needed */
        if(ic->ic_mon_vap &&
           (wlan_vdev_mlme_is_active(ic->ic_mon_vap->vdev_obj) ==
            QDF_STATUS_SUCCESS)) {

            cdp_reset_monitor_mode(soc_txrx_handle,
                                   wlan_objmgr_pdev_get_pdev_id(pdev), 0);
        }
    }
exit:
    return status;
}

/**
 * ol_ath_hw_mode_config_secondary_pdev(): Config secondary pdev
 * during dynamic mode switch between DBS_SBS and DBS
 * @soc : soc handle
 * @up  : bool to indicate up or down
 *
 * return: QDF_STATUS_SUCCESS in case of success and
 * QDF_STATUS_E_INVAL otherwise
 */
static QDF_STATUS ol_ath_hw_mode_config_secondary_pdev(ol_ath_soc_softc_t *soc, bool up)
{
    struct wlan_objmgr_psoc *psoc        = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t    *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info *tgt_hdl;
    struct wlan_objmgr_pdev      *pdev;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com           *ic;
    uint8_t num_radios;
    struct ieee80211vap *vap;
    struct wlan_objmgr_vdev *vdev;
    int waitcnt = 0;
    int status = QDF_STATUS_SUCCESS;
    uint8_t i;

    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);
    num_radios = target_psoc_get_num_radios(tgt_hdl);

    for (i = 0; i < num_radios; i++) {
        pdev = wlan_objmgr_get_pdev_by_id(psoc, i, WLAN_MLME_NB_ID);
        if (!pdev) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR,
                    FL("pdev object (id: %d) is NULL"), i);
            continue;
        }

        scn = (struct ol_ath_softc_net80211 *) lmac_get_pdev_feature_ptr(pdev);
        if (!scn) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR, FL("scn is NULL"));
            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
            continue;
        }

        ic = &(scn->sc_ic);
        if ((pdev == hw_mode_ctx->primary_pdev) ||
            ((hw_mode_ctx->target_band & ic->ic_supported_bands) == 0)) {
            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
            continue;
        }

        switch(hw_mode_ctx->target_mode) {
        case WMI_HOST_HW_MODE_DBS:
            if (up) {
                if (!hw_mode_ctx->is_fw_resp_success) {
                    /* Bring up (back) secondary interface */
                    ol_ath_ifce_setup(scn, UP);
                }
            } else {
                /* Bring down secondary interface */
                ol_ath_ifce_setup(scn, DOWN);
                TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
                    vdev = vap->vdev_obj;
                    while ((wlan_vdev_mlme_get_state(vdev) != WLAN_VDEV_S_INIT) &&
                                      waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                        schedule_timeout_interruptible(CONVERT_SEC_TO_SYSTEM_TIME(1)/100);
                        waitcnt++;
                    }

                    if (wlan_vdev_mlme_get_state(vdev) != WLAN_VDEV_S_INIT) {
                        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
                        status = QDF_STATUS_E_ABORTED;
                        goto exit;
                    }
                }

                waitcnt = 0;
                while (qdf_atomic_read(&scn->mgmt_ctx.mgmt_pending_completions) &&
                       waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                    schedule_timeout_interruptible(CONVERT_SEC_TO_SYSTEM_TIME(1)/100);
                    waitcnt++;
                }
            }
            break;
        case WMI_HOST_HW_MODE_DBS_SBS:
            if (up) {
                /* Bring up secondary interface */
                ol_ath_ifce_setup(scn, UP);
            }
            break;
        }

        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
    }

exit:
    return status;
}

/**
 * ol_ath_init_hw_mode_switch(): Reset hw_mode_ctx and perform
 * sanity check before proceeding with hw-mode change. Following
 * aret the sanity checks:
 * 	1. Is dynamic hw-mode switch supported by fw and if the
 * 	feature is enabled in host?
 * 	2. Is recovery in progress?
 * 	3. Is tgt_hdl retrieval success?
 * 	4. Is wmi_handle retrieval success?
 * 	5. Is current_mode equal to requested mode?
 *  6. Is the request issued in a 2G wifi interface?
 * @scn: scn handle
 * @mode: requested target mode
 *
 * return: status - value zero in case of success and non-zero
 * otherwise
 */
static int ol_ath_init_hw_mode_switch(struct ol_ath_softc_net80211 *scn,
                                      uint32_t mode)
{
    ol_ath_soc_softc_t       *soc         = scn->soc;
    struct wlan_objmgr_psoc  *psoc        = soc->psoc_obj;
    struct ieee80211com      *ic          = &scn->sc_ic;
    struct ieee80211com      *primary_ic  = NULL;
    ol_ath_hw_mode_ctx_t     *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info  *tgt_hdl     = NULL;
    struct wmi_unified       *wmi_handle  = NULL;
    struct ieee80211vap      *vap;
    int status                            = -EINVAL;
    int i;
#if WLAN_CFR_ENABLE
    enum cfr_capt_status cfr_status = PEER_CFR_CAPTURE_DISABLE;
#endif

    if (!ol_ath_is_dynamic_hw_mode_enabled(soc)) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Feature not supported"));
        goto exit;
    }

    if (soc->recovery_in_progress) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Recovery in-progress. Try again "
                                      "after recovery-complete"));
        goto exit;
    }

    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("target hdl is null"));
        goto exit;
    }

    wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);
    if (!wmi_handle) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Invalid WMI handle"));
        goto exit;
    }

    /* reset relevant fields in hw_mode_ctx */

    if (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        struct ol_ath_softc_net80211 *primary_scn =
                (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(
                 hw_mode_ctx->primary_pdev);
        if (primary_scn)
            primary_ic = &primary_scn->sc_ic;
    }
    if (primary_ic)
        IEEE80211_RADAR_MODE_SWITCH_LOCK(primary_ic);
    /* set mode_switch flag */
    hw_mode_ctx->is_switch_in_progress      = true;
    if (primary_ic)
        IEEE80211_RADAR_MODE_SWITCH_UNLOCK(primary_ic);
    /* assign target_mode as the requested mode */
    hw_mode_ctx->target_mode                = mode;
    /* reset fw_resp_status */
    hw_mode_ctx->is_fw_resp_success         = false;
    /* bw reduction during dms flag */
    hw_mode_ctx->is_bw_reduced_during_dms   = false;
    /* reset event */
    qdf_event_reset(&hw_mode_ctx->event);
    for (i = 0; i < WMI_HOST_MAX_PDEV; i++) {
        hw_mode_ctx->next_pdev_map[i] = WMI_HOST_PDEV_ID_INVALID;
    }

    if (hw_mode_ctx->current_mode == mode) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Current mode == Requested mode"));
        goto exit;
    }

    if (!(hw_mode_ctx->target_band & ic->ic_supported_bands)) {
        /* The space in the following print will be filled
         * in future if 'target_band' becomes configurable
         * supporting the feature in bands other than 5G
         */
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Feature not supported in this radio."
            "<Does not support target_band> %s"),
            (hw_mode_ctx->target_band == WMI_HOST_WLAN_5G_CAPABILITY) ?
            "5GHz" : " ");
        goto exit;
    }

    if (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        /* Make sure none of ACS/CAC/CSA is in progress */
        scn = (struct ol_ath_softc_net80211 *) lmac_get_pdev_feature_ptr(
            hw_mode_ctx->primary_pdev);
        if (scn) {
            ic = &scn->sc_ic;
            if ((ic->ic_flags & IEEE80211_F_CHANSWITCH) ||
                wlan_is_ap_cac_timer_running(ic)) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR,
                    FL("Can't switch mode - either CSA or CAC Timer is in progress"));
                goto exit;
            }
            TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
                if (wlan_get_param(vap,IEEE80211_GET_ACS_STATE) ||
                    wlan_get_param(vap,IEEE80211_GET_CAC_STATE)) {
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("Can't switch mode - either ACS or CAC is in progress"));
                    goto exit;
                }
                if ((vap->iv_opmode == IEEE80211_M_STA) || (vap->iv_opmode ==  IEEE80211_M_WDS)) {
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("Can't switch mode - %s is not in AP mode!"), vap->iv_netdev_name);
                    goto exit;
                }
            }
        }

        /* return if CFR capture was started */
#if WLAN_CFR_ENABLE
        ucfg_cfr_get_capture_status(hw_mode_ctx->primary_pdev, &cfr_status);
        if (cfr_status == PEER_CFR_CAPTURE_ENABLE) {
            qdf_err("CFR capture in progress, abort HW mode change!!");
            goto exit;
        }
#endif
        if (ol_ath_hw_mode_check_pdev_map(soc)) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                QDF_TRACE_LEVEL_ERROR,
                FL("Can't switch mode - pdev mapping infeasible"));
            goto exit;
        }

        hw_mode_ctx->ts_start = qdf_ktime_to_ns(qdf_ktime_get());
        hw_mode_ctx->cnt_attempt++;

        /* Clear recover_mode now as it's tried */
        if (hw_mode_ctx->recover_mode) {
            hw_mode_ctx->recover_mode = 0;
        }

        status = ol_ath_hw_mode_config_secondary_pdev(soc, false);
        if (status != EOK)
            goto exit;
        status = ol_ath_hw_mode_config_primary_pdev(soc, false);
        if (status != EOK)
            goto exit;
    }
    status = EOK;

exit:
    return status;
}

/**
 * ol_ath_prepare_hw_mode_switch(): Prepare host for mode switch
 * before sending hw_mode_cmd to FW
 * @soc: soc handle
 *
 * return: status - value zero in case of success and non-zero
 * otherwise
 */
static int ol_ath_prepare_hw_mode_switch(ol_ath_soc_softc_t *soc)
{
    struct wlan_objmgr_psoc  *psoc          = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t       *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info  *tgt_hdl       = NULL;
    int status                              = -EINVAL;
    uint8_t num_radios, pdev_id;

    /* retrieve tgt_hdl */
    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);

    /* derive number of pdevs (radios) for current hw-mode
     */
    num_radios = target_psoc_get_num_radios(tgt_hdl);

    /*------------------Start: prepare mode switch--------------------*/
    for (pdev_id = 0; pdev_id < num_radios; pdev_id++) {
        struct wlan_objmgr_pdev *pdev  = NULL;
        struct ol_ath_softc_net80211     *scn;
        struct ieee80211com               *ic;

        pdev = wlan_objmgr_get_pdev_by_id(psoc, pdev_id, WLAN_MLME_NB_ID);
        if (!pdev) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR,
                    FL("pdev object (id: %d) is NULL"), pdev_id);
            continue;
        }

        scn = (struct ol_ath_softc_net80211 *) lmac_get_pdev_feature_ptr(pdev);
        if (!scn) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR, FL("scn is NULL"));

            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
            continue;
        }

        ic = &(scn->sc_ic);

        /* Currently, FW advertises mac_phy_cap[pdev_x].supported_bands as
         * either 5G or 2G capable. Host code handles the possibility of
         * each phy being either 5G or 2G capble. Following logic of checking
         * if the target band is supported by this ic/phy or not is based on
         * the above fact. In future, phys may be capable of supporting mulitple
         * bands. In which case mac_phy_cap[pdev_x].supported_bands will reflect
         * the same and host code (including cmn_dev) needs to scale to support
         * that. Following condition will need change in similar lines.
         */
        if (hw_mode_ctx->target_band & ic->ic_supported_bands) {
            /* Unregister wext and cfg handlers for the radio
             * and vaps (in that radio) ifces. It will also
             * bring down the radio ifce
             */
            ol_ath_ifce_setup(scn, DOWN);

            /* call dfs de-init */
            ol_if_dfs_pdev_deinit_pre_hw_mode_switch(scn);

            /* as a serialization requirement for the hw_mode_switch_cmd
             * to fw we must wait for all vdevs to reach init state which
             * will be brought down in above step
             */
            if (wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_VDEVS)) {
                QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_ERROR,
                    FL("Failed to bring down all vaps for pdev id: %d"),
                    pdev_id);
                if (pdev)
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
                goto exit;
            }
        }

        if (pdev)
            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);

    } /* for loop */
    ol_if_dfs_psoc_deinit_pre_hw_mode_switch(psoc);
    /*------------------End: prepare mode switch--------------------*/

    status = EOK;

exit:
    return status;
}

/**
 * ol_ath_accomplish_hw_mode_switch(): Accomplish hw-mode switch
 * in host post receiving FW response for hw_mode_switch command
 * @scn: scn handle
 *
 * return: status - value zero in case of success and non-zero
 * otherwise
 */
static int ol_ath_accomplish_hw_mode_switch(struct ol_ath_softc_net80211 *scn)
{
    ol_ath_soc_softc_t       *soc         = scn->soc;
    struct wlan_objmgr_psoc  *psoc        = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t     *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info  *tgt_hdl     = NULL;
    int status                            = -EINVAL;
    uint8_t num_radios, pdev_id;

    /* retrieve tgt_hdl */
    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);

    /* derive max number of pdevs (radios) supported in the soc */
    num_radios = ol_ath_get_max_supported_radios(soc);

    /* Accomplish mode-switch step happens irrespective of
     * success/fail FW response. Following steps need
     * to execute for all radios as failure recovery is
     * handled here as well
     */
    /*------------------Start: accomplish mode switch---------------*/
    for (pdev_id = 0; pdev_id < num_radios; pdev_id++) {
        struct wlan_objmgr_pdev *pdev    = NULL;
        target_resource_config *tgt_cfg  = NULL;
        struct ol_ath_softc_net80211       *scn;
        struct ieee80211com                 *ic;
        struct ieee80211vap                *vap;
        bool pdev_reconfig_success       = false;

        pdev = wlan_objmgr_get_pdev_by_id(psoc, pdev_id, WLAN_MLME_NB_ID);
        if (!pdev) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR,
                        FL("pdev object (id: %d) is NULL"), pdev_id);
            continue;
        }

        scn = (struct ol_ath_softc_net80211 *)
                                lmac_get_pdev_feature_ptr(pdev);
        if (!scn) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                        QDF_TRACE_LEVEL_ERROR, FL("scn is NULL"));

            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
            continue;
        }

        ic      = &(scn->sc_ic);
        psoc    = scn->soc->psoc_obj;
        tgt_cfg = target_psoc_get_wlan_res_cfg(tgt_hdl);

        if (hw_mode_ctx->target_band & ic->ic_supported_bands) {
            if (hw_mode_ctx->is_fw_resp_success) {
                /* Reconfig mac-phy-cap, reg-cap etc. as per
                 * corresponding pdev in target-mode. The following
                 * function returns 0 for success and non-0 value
                 * for failure. Hence, a '!' of the return value
                 * is assigned to 'pdev_reconfig_success' status
                 * variable
                 */
                pdev_reconfig_success =
                    !ol_ath_reconfig_pdev_post_hw_mode_switch(scn);
            }

            switch(hw_mode_ctx->target_mode) {
                case WMI_HOST_HW_MODE_DBS:
                    /* pdev-level regulatory/dfs re-init is required for
                     * non-master radios only if pdev_reconfig failed
                     * as this particular case is handling an attempt
                     * to switch from dbs_sbs to dbs mode and a pdev_
                     * reconfig failure needs regulatory/dfs recovery
                     * to previous state (before attempting the switch)
                     * for non-master radios along with the master radio
                     */
                    if (ic->ic_master_radio || !pdev_reconfig_success) {
                        /* regulatory re-init */
                        ol_regdmn_reinit_post_hw_mode_switch(ic);
                        /* dfs re-init */
                        ol_if_dfs_pdev_reinit_post_hw_mode_switch(ic);
                    }
                    if (hw_mode_ctx->is_fw_resp_success) {
                        if (!ic->ic_master_radio) {
                            ol_ath_handle_dbs_sbs_to_dbs_switch_in_dp(ic);
                        } else {
                            ol_ath_ifce_setup(scn, UP);
                        }
                    } else {
                        ol_ath_ifce_setup(scn, UP);
                    }
                break;
                case WMI_HOST_HW_MODE_DBS_SBS:
                    /* pdev-level regulatory/dfs re-init required for
                     * non-master radios only if pdev_reconfig succeeded
                     * as this particular case is handling an attempt
                     * to switch from dbs to dbs_sbs mode and a pdev_
                     * reconfig success needs regulatory/dfs re-init
                     * as per the regulatory capabilities in the attempted
                     * hw-mode. In case of a pdev_reconfig failure,
                     * regulatory/dfs re-init will only happen for master
                     * radio to previous state (before attempting the
                     * switch) as only the master radio was relevant in
                     * dbs mode before this hw-mode switch-attempt
                     */
                    if (ic->ic_master_radio || pdev_reconfig_success) {
                        /* regulatory re-init */
                        ol_regdmn_reinit_post_hw_mode_switch(ic);
                        /* dfs re-init */
                        ol_if_dfs_pdev_reinit_post_hw_mode_switch(ic);
                    }
                    if (hw_mode_ctx->is_fw_resp_success) {
                        if (!ic->ic_master_radio) {
                            ol_ath_handle_dbs_to_dbs_sbs_switch_in_dp(ic);
                        }

                        ol_ath_ifce_setup(scn, UP);
                    } else {
                        if (ic->ic_master_radio) {
                            ol_ath_ifce_setup(scn, UP);
                        }
                    }
                break;
                default:
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                            QDF_TRACE_LEVEL_ERROR, FL("Unhandled mode"));
                    if (pdev)
                        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
                    goto exit;
            }

            if (hw_mode_ctx->is_fw_resp_success) {
                if (ic->ic_master_radio) {
                    /* Set max peers supported for each PDEV */
                    wlan_pdev_set_max_peer_count(scn->sc_pdev,
                        wlan_psoc_get_max_peer_count(psoc)/
                        target_psoc_get_num_radios(tgt_hdl));

                    /* set up rates */
                    ol_ath_setup_rates(ic);

                    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
                        /* reset vap params as-per new ic-caps
                         */
                        ieee80211_dynamic_vap_setup(ic, vap, vap->vdev_mlme);
                    }
                }
            }
        } /* band satisfiability */

        if (pdev)
            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);

    } /* for loop */
    /*------------------End: accomplish mode switch---------------*/
    status = EOK;

exit:
    return status;
}

/**
 * ol_ath_deinit_hw_mode_switch(): Perform reset and de-init steps
 * post hw-mode switch. This function performs following de-init steps:
 * 1. Sets current_hw_mode to requested mode if the mode switch succeeded.
 * It also sets the preferred_hw_mode in case of success.
 * 2. Sends success/fail acfg event
 * 3. Resets is_switch_in_progress
 * @scn: scn handle
 * @status: status reflecting hw-mode swithc attempt
 *
 * return: status - value zero in case of success and non-zero otherwise
 */
static int ol_ath_deinit_hw_mode_switch(struct ol_ath_softc_net80211 *scn,
                                        int status)
{
    ol_ath_soc_softc_t       *soc           = scn->soc;
    struct wlan_objmgr_psoc  *psoc          = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t       *hw_mode_ctx = &soc->hw_mode_ctx;
    struct target_psoc_info  *tgt_hdl       = NULL;
    int avg_len;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event           = NULL;
#endif

    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);

    if (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        ol_ath_hw_mode_config_primary_pdev(soc, true);
    }

    if ((status == EOK && hw_mode_ctx->is_fw_resp_success) &&
            !soc->recovery_in_progress) {
        hw_mode_ctx->current_mode = hw_mode_ctx->target_mode;
        target_psoc_set_preferred_hw_mode(tgt_hdl, hw_mode_ctx->current_mode);
    }

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
              QDF_TRACE_LEVEL_DEBUG, FL("current_mode: %s"),
              (hw_mode_ctx->current_mode == 1) ? "DBS":
              (hw_mode_ctx->current_mode == 4) ? "DBS_SBS": "Invalid mode");

#if UMAC_SUPPORT_ACFG
    if (!hw_mode_ctx->is_boot_in_progress) {
        acfg_event = (acfg_event_data_t *)
                                qdf_mem_malloc( sizeof(acfg_event_data_t));
        if (acfg_event != NULL) {
            if (soc->recovery_in_progress) {
                /* if recover in-progress then always claim fialure */
                acfg_event->result = false;
            } else {
                acfg_event->result = hw_mode_ctx->is_fw_resp_success;
            }

            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                    QDF_TRACE_LEVEL_DEBUG, FL("Send ACFG event"));
            acfg_send_event(scn->sc_osdev->netdev,
            scn->sc_osdev, WL_EVENT_TYPE_HW_MODE_CHANGE_STATUS, acfg_event);
            qdf_mem_free(acfg_event);
        }
    }
#endif

    hw_mode_ctx->is_switch_in_progress = false;
    if (soc->hw_mode_ctx.dynamic_hw_mode != WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        /* release wait on vap ifce_up */
        qdf_event_set(&hw_mode_ctx->event);
    } else {
        if ((status == QDF_STATUS_SUCCESS) || (status == QDF_STATUS_E_ABORTED))
            ol_ath_hw_mode_config_secondary_pdev(soc, true);

        /* Update stats only if operation is attempted */
        if (hw_mode_ctx->cnt_attempt >
            (hw_mode_ctx->cnt_success + hw_mode_ctx->cnt_failure)) {
            if ((status == QDF_STATUS_SUCCESS) && hw_mode_ctx->is_fw_resp_success)
                hw_mode_ctx->cnt_success++;
            else
                hw_mode_ctx->cnt_failure++;

            hw_mode_ctx->ts_end = qdf_ktime_to_ns(qdf_ktime_get());
            if (hw_mode_ctx->ts_end > hw_mode_ctx->ts_start) {
                hw_mode_ctx->time_last = qdf_do_div(
                    hw_mode_ctx->ts_end - hw_mode_ctx->ts_start,
                    QDF_NSEC_PER_MSEC);
            } else {
                hw_mode_ctx->time_last = 0;
            }
            if (hw_mode_ctx->time_last) {
                avg_len = (hw_mode_ctx->cnt_success < MOVING_AVG_LENGTH) ?
                    hw_mode_ctx->cnt_success : MOVING_AVG_LENGTH;
                hw_mode_ctx->time_avg = qdf_do_div(
                    hw_mode_ctx->time_avg * (avg_len - 1) + hw_mode_ctx->time_last,
                    avg_len);
            }

            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("-----------------------"));
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("cnt_attempt : %d"), hw_mode_ctx->cnt_attempt);
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("cnt_success : %d"), hw_mode_ctx->cnt_success);
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("cnt_failure : %d"), hw_mode_ctx->cnt_failure);
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("time_last   : %d (ms)"), hw_mode_ctx->time_last);
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_DEBUG,
                      FL("time_avg    : %d (ms)"), hw_mode_ctx->time_avg);
        }
    }

    return status;
}

/**
 * ol_ath_set_hw_mode_omn_timer(): Set the OMN (Op-Mode Notification) timer
 *                                 for hw-mode change
 * @scn: scn handle
 * @omn_timeout: How long in milliseconds,
 *               will the new OMN IE included in beacon after hw-mode change
 *
 * return: EOK
 * otherwise
 */
int ol_ath_set_hw_mode_omn_timer(struct ol_ath_softc_net80211 *scn,
        uint32_t omn_timeout)
{
    struct ieee80211com     *ic = &scn->sc_ic;

    if (ic->ic_omn_cxt.omn_timeout == omn_timeout) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_WARN,
                "Error!! OMN-TIMER is already set to %d\n", omn_timeout);
        return -EINVAL;
    }
    ic->ic_omn_cxt.omn_timeout = omn_timeout;
    return EOK;
}

/**
 * ol_ath_set_hw_mode_omn_enable(): Enable Opmode notification after
 *                                  hw-mode change
 * @scn: scn handle
 * @enable: Opmode notification enable(1) or disable(0)
 *
 * return: EOK
 * otherwise
 */
int ol_ath_set_hw_mode_omn_enable(struct ol_ath_softc_net80211 *scn,
				  int enable)
{
    struct ieee80211com     *ic = &scn->sc_ic;

    if ((!ic->ic_omn_cxt.omn_enable) == (!enable)) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_WARN,
                "Error!! OMN-TIMER is already in  %d state\n", (!(!enable)));
        return -EINVAL;
    }
    ic->ic_omn_cxt.omn_enable = (!(!enable));
    return EOK;
}

/**
 * @scn: scn handle
 * @is_primary: indicate that interface is primary (only '1' is allowed)
 */
QDF_STATUS ol_ath_set_hw_mode_primary_if(struct ol_ath_softc_net80211 *scn,
                                         unsigned int is_primary)
{
    ol_ath_soc_softc_t *soc = scn->soc;
    ol_ath_hw_mode_ctx_t *hw_mode_ctx = &soc->hw_mode_ctx;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct ieee80211com *ic;
    QDF_STATUS status = QDF_STATUS_E_INVAL;

    if (!ol_ath_is_dynamic_hw_mode_enabled(soc)) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("Feature not supported"));
        return status;
    }

    if (hw_mode_ctx->is_switch_in_progress) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR,
                  "ERROR! Cannot change primary interface when "
                  "hw-mode switch is in progress\n");
        return status;
    }

    if (is_primary != 1) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR,
                "ERROR! Only 1 is a valid parameter\n"
                "The command for ol_ath_set_hw_mode_primary_if will make "
                "the handler interface as the primary and only '1' is a "
                "valid parameter for this\n");
        return status;
    }

    pdev = scn->sc_pdev;
    if (hw_mode_ctx->primary_pdev == pdev) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO,
                 "INFO! Interface is already primary pdev\n"
                 "Not doing anything\n");
        return status;
    }

    ic = &(scn->sc_ic);
    if (!(ic->ic_supported_bands & WMI_HOST_WLAN_5G_CAPABILITY)) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                QDF_TRACE_LEVEL_ERROR, "ERROR!! Interface is not 5G capable\n");
        return status;
    }

    hw_mode_ctx->primary_pdev = pdev;
    return QDF_STATUS_SUCCESS;
}

/**
 * ol_ath_handle_hw_mode_switch(): Handle hw-mode swtich request
 * @scn: scn handle
 * @mode: requested target mode
 *
 * return: status - value zero in case of success and non-zero
 * otherwise
 */
int ol_ath_handle_hw_mode_switch(struct ol_ath_softc_net80211 *scn,
                                 uint32_t mode)
{
    ol_ath_soc_softc_t       *soc           = scn->soc;
    struct wlan_objmgr_psoc  *psoc          = soc->psoc_obj;
    ol_ath_hw_mode_ctx_t     *hw_mode_ctx   = &soc->hw_mode_ctx;
    struct target_psoc_info  *tgt_hdl       = NULL;
    struct wmi_unified       *wmi_handle    = NULL;
    int status;

    /* init and sanitize */
    status = ol_ath_init_hw_mode_switch(scn, mode);
    if (status != EOK)
        goto exit;

    /* retrieve tgt_hdl */
    tgt_hdl = (struct target_psoc_info *) wlan_psoc_get_tgt_if_handle(psoc);
    /* retrieve wmi_handle */
    wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);

    if (soc->hw_mode_ctx.dynamic_hw_mode != WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        /* prepare mode-switch */
        status = ol_ath_prepare_hw_mode_switch(soc);
        if (status != EOK)
            goto exit;
    }

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO,
              "Switching to HW mode %d..",
              mode);

    /* make a call to target_if to send hw_mode_switch wmi
     * as blocking call */
    if (wmi_unified_soc_set_hw_mode_cmd(wmi_handle, mode)
            == QDF_STATUS_SUCCESS) {
        if (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) {
            /*  Block WMI cmds on primary pdev during mode switch */
           hw_mode_ctx->prev_wmi_hdl =
                   lmac_get_pdev_wmi_handle(hw_mode_ctx->primary_pdev);
            ol_ath_allow_wmi_cmds(hw_mode_ctx->prev_wmi_hdl, false);
        }

        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_DEBUG, FL("hw_mode_cmd sent to FW"));

        /* wait for response event from FW */
        if (qdf_wait_for_event_completion(&hw_mode_ctx->event,
                MAX_HW_MODE_FW_RESP_TIME)) {
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                QDF_TRACE_LEVEL_ERROR, FL("Timed out waiting on FW response"));
            hw_mode_ctx->is_fw_resp_success = false;
        }

        if (!hw_mode_ctx->is_fw_resp_success &&
            (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST)) {
            /*  Allow WMI cmds on primary pdev */
            ol_ath_allow_wmi_cmds(hw_mode_ctx->prev_wmi_hdl, true);
        }
    } else {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("WMI send failed for hw_mode_cmd"));
    }

    if (soc->hw_mode_ctx.dynamic_hw_mode != WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        /* accomplish mode-switch */
        if (ol_ath_accomplish_hw_mode_switch(scn)) goto exit;
    }

    status = EOK;
exit:
    return ol_ath_deinit_hw_mode_switch(scn, status);
}

void ol_ath_assign_mbssid_ref_bssid(void *i_scn, bool partially_random)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *) i_scn;
    uint8_t *myaddr;
    uint32_t random_bytes;
    struct ieee80211com *ic = &scn->sc_ic;
    uint8_t *ref_bssid = (uint8_t *) &ic->ic_mbss.ref_bssid;

    wlan_pdev_obj_lock(scn->sc_pdev);
    myaddr = wlan_pdev_get_hw_macaddr(scn->sc_pdev);
    IEEE80211_ADDR_COPY(ref_bssid, myaddr);
    wlan_pdev_obj_unlock(scn->sc_pdev);

    /* 1. Make ref_bssid a locally administered bssid
     * as 48-n MSBs of all the 2^n bssids in a MBSSID
     * group must be same
     * 2. If caller requests partially_random ref_bssid
     * then randomize the last octet of the same. This
     * may be relevant in the following scenario. If
     * MBSSID (or EMA) is enabled in multiple radios,
     * randomizing the last octet will enable to have
     * unique set of bssids across all the radios irr-
     * espctive of whether thse radios are across diff-
     * erent SOCs or not
     *
     * Currently, one octet should suffice as n is
     * expected to be less than or equal to 8 for all
     * practical purposes for a forseeable future
     */

    if (partially_random) {
        OS_GET_RANDOM_BYTES(&random_bytes, sizeof(random_bytes));
        ref_bssid[ATH_BSSID_INDEX] =
                    (random_bytes + OS_GET_TICKS()) % ((1 << OCTET) - 1);
    }
    ref_bssid[0] |= IEEE802_MAC_LOCAL_ADMBIT;

    mbss_info("MBSSID reference bssid is %s soc: %s pdev: %s",
                ether_sprintf(ref_bssid), scn->soc->sc_osdev->netdev->name,
                scn->netdev->name);
}

int ol_ath_pdev_attach(struct ol_ath_softc_net80211 *scn,
		IEEE80211_REG_PARAMETERS *ieee80211_conf_parm,
		uint8_t phy_id)
{
    ol_ath_soc_softc_t *soc = scn->soc;
    struct ieee80211com     *ic = &scn->sc_ic;
    int status = 0;
    osdev_t osdev = scn->sc_osdev;
    uint32_t host_num_peers_psoc = 0;
    uint32_t host_num_peers_pdev = 0;
    uint32_t max_peers = 0;
#if DBDC_REPEATER_SUPPORT
    int i,j,k;
    struct ieee80211com     *tmp_ic;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    int map_id;
#endif
    struct wlan_objmgr_psoc *psoc = NULL;
    struct target_psoc_info *tgt_hdl;
    target_resource_config *tgt_cfg;
    uint32_t target_type;
    uint32_t max_target_connected_peers;
    uint32_t target_version;
    uint8_t *myaddr;
    struct wmi_unified *wmi_handle;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#endif /* HOST_DFS_SPOOF_TEST */
    uint8_t num_radios;
    ol_txrx_soc_handle soc_txrx_handle;
#if OL_ATH_SUPPORT_LED
    bool led_gpio_enable_8074 = cfg_get(soc->psoc_obj, CFG_OL_LED_GPIO_ENABLE_8074);
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap = ucfg_reg_get_hal_reg_cap(scn->soc->psoc_obj);
    uint8_t pdev_idx = lmac_get_pdev_idx(scn->sc_pdev);
#endif
    bool is_prealloc_disabled;

    psoc = soc->psoc_obj;
    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        return -EINVAL;
    }
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

#if defined(QCA_OL_TX_MULTIQ_SUPPORT) || defined(QCA_OL_RX_MULTIQ_SUPPORT)
    /* Enable multiq support for lithium */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
    ic->multiq_support_enabled = cfg_get(psoc, CFG_TGT_MULTIQ_SUPPORT);
#endif
#endif

    tgt_cfg = target_psoc_get_wlan_res_cfg(tgt_hdl);
    target_type = target_psoc_get_target_type(tgt_hdl);
    target_version = target_psoc_get_target_ver(tgt_hdl);
    wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);
    num_radios = target_psoc_get_num_radios(tgt_hdl);
#if QCA_SUPPORT_SON
    son_ald_record_set_buff_lvl(soc->psoc_obj, 75);
    son_ald_record_set_buff_full_warn(scn->soc->psoc_obj, 0);
#endif

    /**
     * Update edge channel deprioritize value based on the target type.
     * Currently, all lithium targets except TARGET_TYPE_QCN9000 and TARGET_TYPE_QCN6122
     * will be undergoing edge channel deprioritization.
     * More target types can be added to whitelist as needed.
     */
    if (ol_target_lithium(psoc) && (target_type != TARGET_TYPE_QCN9000)) {
        ic->ic_edge_ch_dep_applicable = true;
    } else {
        ic->ic_edge_ch_dep_applicable = false;
    }

    ic->interface_id = scn->radio_id;
    qdf_info("interface_id %d", ic->interface_id);

    ic->ic_auth_tx_xretry = 0;
#if ATH_SUPPORT_DSCP_OVERRIDE
    /* Initializing tid-map parameters to default vaules. */
    for (map_id = 0; map_id < NUM_DSCP_MAP; map_id++) {
        OS_MEMCPY(ic->ic_dscp_tid_map[map_id],dscp_tid_map, sizeof(uint32_t) * WMI_HOST_DSCP_MAP_MAX);
    }
    ic->ic_override_dscp = 0x00;
    ic->ic_dscp_hmmc_tid = 0x00;
    ic->ic_override_hmmc_dscp = 0x00;
#endif
    ic->ic_consider_obss_long_slot = CONSIDER_OBSS_LONG_SLOT_DEFAULT;

    /* init IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_init(ic);

    if (!bypasswmi) {
        // Use attach_failed1 for failures beyond this
        /*
         * 9. WLAN/UMAC initialization
         */
        ic->ic_get_num_clients = ol_ath_get_num_clients;
        ic->ic_if_mgmt_drain = ol_if_mgmt_drain;
        ic->ic_is_macreq_enabled = ol_ath_net80211_is_macreq_enabled;
        ic->ic_get_mac_prealloc_idmask = ol_ath_net80211_get_mac_prealloc_idmask;
        ic->ic_set_mac_prealloc_id = ol_ath_net80211_set_mac_prealloc_id;
        ic->ic_get_bsta_fixed_idmask = ol_ath_net80211_get_bsta_fixed_idmask;
        ic->ic_update_target_caps = ol_ath_update_phymode_caps;
        ic->ic_config_update = ol_ath_pdev_config_update;
        ic->ic_osdev = osdev;
        ic->ic_qdf_dev = soc->qdf_dev;
        ic->ic_netdev = scn->netdev;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
        ic->ic_is_host_dfs_check_enabled = ol_if_is_host_dfs_check_support_enabled;
#endif /* HOST_DFS_SPOOF_TEST */

        /* register bcn_tx_status_event_handler */
        ic->ic_register_beacon_tx_status_event_handler =
                        ol_ath_mgmt_register_offload_beacon_tx_status_event;
        ic->ic_config_bsscolor_offload                 =
                                ol_ath_config_bss_color_offload;
        ic->ic_is_ifce_allowed_in_dynamic_mode         =
                                ol_ath_is_ifce_allowed_in_dynamic_hw_mode;
        ic->ic_assign_mbssid_ref_bssid                 =
                                ol_ath_assign_mbssid_ref_bssid;

        /* Update the peer count variable
         * The peer count configured is expected to be the max number
         * of client peers connected excluding the number of self & bss peers
         */
        max_target_connected_peers = tgt_cfg->num_peers - tgt_cfg->num_vdevs;
        max_peers = cfg_get(soc->psoc_obj, CFG_OL_MAX_PEERS);
        if(max_peers) {
            if (max_peers < num_radios) {
                qdf_info("Very low max peers configured. Setting max_peers to %d",
                       num_radios);
                host_num_peers_psoc = num_radios;
            }
            else {
                 host_num_peers_psoc = QDF_MIN(max_peers, max_target_connected_peers);
            }
        }
        else {
            host_num_peers_psoc = max_target_connected_peers;
        }
        qdf_atomic_set(&scn->peer_count, 0);
        qdf_atomic_inc(&scn->peer_count);

        /* This is required to make sure object manager psoc
         * peer count has room for connected peers as
         * well as bss peers*2 for vdevs.
         * We need 2 times the number of bss_peers
         * since during bss reset, a new peer is created
         * and then old peer is removed.
        */
#define MAX_BSS_PER_PER_VDEV 2
        if(max_peers) {
            wlan_psoc_set_max_peer_count(psoc,
            host_num_peers_psoc + (tgt_cfg->num_vdevs * MAX_BSS_PER_PER_VDEV));
        }
#if ATH_SUPPORT_WRAP
        /* This adjustment is made so that the number of peers
         * in host and FW become equal. Host is not sending a peer
         * create event when creating a sta which leads to mismatch
         * in peer count between host and FW */
        if (wlan_psoc_nif_feat_cap_get(soc->psoc_obj, WLAN_SOC_F_QWRAP_ENABLE)) {
            host_num_peers_psoc = host_num_peers_psoc - 1;
        }
#endif
        host_num_peers_pdev = (host_num_peers_psoc/num_radios);

        qdf_atomic_add(host_num_peers_pdev, &scn->peer_count);

        ol_ath_pdev_regdmn_init(scn, ieee80211_conf_parm);
        wlan_pdev_obj_lock(scn->sc_pdev);
        myaddr = wlan_pdev_get_hw_macaddr(scn->sc_pdev);
        IEEE80211_ADDR_COPY(ic->ic_myaddr, myaddr);
        IEEE80211_ADDR_COPY(ic->ic_my_hwaddr, myaddr);
        wlan_pdev_obj_unlock(scn->sc_pdev);
        /* Do not request partially random ref_bssid at init
         */
        ol_ath_assign_mbssid_ref_bssid(scn, false);

        ol_ath_setup_rates(ic);
        ieee80211com_set_cap_ext(ic, IEEE80211_CEXT_PERF_PWR_OFLD);

        ic->ic_dprintf_ic = IEEE80211_DPRINTF_IC;
        ic->ru26_tolerant = true;

        status = ol_ath_dev_attach(scn, ieee80211_conf_parm);
        if (status) {
            qdf_err("ol_ath_dev_attach failed status %d", status);
            return status;
        }
        ic->ic_find_channel = ieee80211_find_channel;

#if UMAC_SUPPORT_CFG80211
        ic->ic_cfg80211_radio_attach = ieee80211_cfg80211_radio_attach;
        ic->ic_cfg80211_radio_detach = ieee80211_cfg80211_radio_detach;
        ic->ic_cfg80211_update_channel_list = wlan_cfg80211_update_channel_list;

        ic->ic_cfg80211_radio_handler.setcountry = ol_ath_ucfg_set_country ;
        ic->ic_cfg80211_radio_handler.getcountry = ol_ath_ucfg_get_country ;
        ic->ic_cfg80211_radio_handler.sethwaddr = ol_ath_ucfg_set_mac_address ;
        ic->ic_cfg80211_radio_handler.gethwaddr = NULL ;
        ic->ic_cfg80211_radio_handler.setparam = ol_ath_ucfg_setparam ;
        ic->ic_cfg80211_radio_handler.getparam = ol_ath_ucfg_getparam ;
        ic->ic_cfg80211_radio_handler.extended_commands = ol_ath_extended_commands;

#if UNIFIED_SMARTANTENNA
        ic->ic_cfg80211_radio_handler.set_saparam = ol_ath_ucfg_set_smart_antenna_param;
        ic->ic_cfg80211_radio_handler.get_saparam = ol_ath_ucfg_get_smart_antenna_param;
#endif

#if ATH_SUPPORT_DSCP_OVERRIDE
        ic->ic_cfg80211_radio_handler.setdscp_tid_map = NULL ;
        ic->ic_cfg80211_radio_handler.getdscp_tid_map = NULL ;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        ic->ic_cfg80211_radio_handler.ald_getStatistics = NULL ;
#endif

#if PEER_FLOW_CONTROL
        ic->ic_cfg80211_radio_handler.txrx_peer_stats = ol_ath_ucfg_txrx_peer_stats;
#endif

#if QCA_AIRTIME_FAIRNESS
        ic->ic_cfg80211_radio_handler.set_atf_sched_dur = ol_ath_ucfg_set_atf_sched_dur ;
#endif

        ic->ic_cfg80211_radio_handler.get_aggr_burst = ol_ath_iw_get_aggr_burst;
        ic->ic_cfg80211_radio_handler.set_aggr_burst = ol_ath_ucfg_set_aggr_burst;
        ic->ic_cfg80211_radio_handler.ucfg_phyerr = ol_ath_ucfg_phyerr;
        ic->ic_cfg80211_radio_handler.get_ath_stats = ol_ath_ucfg_get_ath_stats;
        ic->ic_cfg80211_radio_handler.get_dp_fw_peer_stats = ol_ath_get_dp_fw_peer_stats;
        ic->ic_cfg80211_radio_handler.get_dp_htt_stats = ol_ath_get_dp_htt_stats;
        ic->ic_cfg80211_radio_handler.get_cp_wmi_stats = ol_ath_get_cp_wmi_stats;
        ic->ic_cfg80211_radio_handler.get_target_pdev_id = ol_ath_get_target_pdev_id;
        ic->ic_cfg80211_radio_handler.set_ba_timeout = ol_ath_set_ba_timeout;
        ic->ic_cfg80211_radio_handler.get_ba_timeout = ol_ath_get_ba_timeout;
        ic->ic_cfg80211_radio_handler.set_pcp_tid_map = ol_ath_ucfg_set_pcp_tid_map;
        ic->ic_cfg80211_radio_handler.get_pcp_tid_map = ol_ath_ucfg_get_pcp_tid_map;
        ic->ic_cfg80211_radio_handler.set_tidmap_prty = ol_ath_ucfg_set_tidmap_prty;
        ic->ic_cfg80211_radio_handler.get_tidmap_prty = ol_ath_ucfg_get_tidmap_prty;
        ic->ic_cfg80211_radio_handler.set_btcoex_duty_cycle = ol_ath_ucfg_btcoex_duty_cycle;
        ic->ic_cfg80211_radio_handler.set_muedca_mode = ol_ath_ucfg_set_muedca_mode;
        ic->ic_cfg80211_radio_handler.get_muedca_mode = ol_ath_ucfg_get_muedca_mode;
        ic->ic_cfg80211_radio_handler.set_non_ht_dup = ol_ath_ucfg_set_non_ht_dup;
        ic->ic_cfg80211_radio_handler.get_non_ht_dup = ol_ath_ucfg_get_non_ht_dup;
        ic->ic_cfg80211_radio_handler.set_col_6ghz_rnr = ol_ath_ucfg_set_col_6ghz_rnr;
        ic->ic_cfg80211_radio_handler.get_col_6ghz_rnr = ol_ath_ucfg_get_col_6ghz_rnr;
#if DBG_LVL_MAC_FILTERING
        ic->ic_cfg80211_radio_handler.set_dbglvlmac = ol_ath_ucfg_set_dbglvlmac;
        ic->ic_cfg80211_radio_handler.get_dbglvlmac = ol_ath_ucfg_get_dbglvlmac;
#endif /* DBG_LVL_MAC_FILTERING */
#endif
        ic->ic_num_mcast_tbl_elements = ol_ath_num_mcast_tbl_elements;
        ic->ic_num_mcast_grps = ol_ath_num_mcast_grps;
        ic->ic_is_target_ar900b = ol_ath_is_target_ar900b;
        ic->ic_get_tgt_type = ol_ath_get_tgt_type;
#if UMAC_SUPPORT_CFG80211
        ic->ic_cfg80211_radio_handler.set_he_mesh_config = ol_ath_ucfg_set_he_mesh_config;
        ic->ic_cfg80211_radio_handler.get_he_mesh_config = ol_ath_ucfg_get_he_mesh_config;
#ifdef WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG
        ic->ic_cfg80211_radio_handler.ic_set_rx_pkt_protocol_tagging = ol_ath_ucfg_set_rx_pkt_protocol_tagging;
#ifdef WLAN_SUPPORT_RX_TAG_STATISTICS
        ic->ic_cfg80211_radio_handler.ic_dump_rx_pkt_protocol_tag_stats = ol_ath_ucfg_dump_rx_pkt_protocol_tag_stats;
#endif /* WLAN_SUPPORT_RX_TAG_STATISTICS */
#endif /* WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG */
#ifdef WLAN_SUPPORT_RX_FLOW_TAG
        ic->ic_cfg80211_radio_handler.ic_rx_flow_tag_op = ol_ath_ucfg_rx_flow_tag_op;
#endif /* WLAN_SUPPORT_RX_FLOW_TAG */
        ic->ic_cfg80211_radio_handler.set_nav_override_config = ol_ath_ucfg_set_nav_override_config;
        ic->ic_cfg80211_radio_handler.get_nav_override_config = ol_ath_ucfg_get_nav_override_config;
#if defined(WLAN_TX_PKT_CAPTURE_ENH) || defined(WLAN_RX_PKT_CAPTURE_ENH)
        ic->ic_cfg80211_radio_handler.ic_set_peer_pkt_capture_params = ol_ath_ucfg_set_peer_pkt_capture;
#endif /* WLAN_TX_PKT_CAPTURE_ENH || WLAN_RX_PKT_CAPTURE_ENH */
#endif /* UMAC_SUPPORT_CFG80211 */
#if OBSS_PD
        ic->ic_cfg80211_radio_handler.set_he_sr_config = ol_ath_ucfg_set_he_sr_config;
        ic->ic_cfg80211_radio_handler.get_he_sr_config = ol_ath_ucfg_get_he_sr_config;
        ic->ic_cfg80211_radio_handler.set_he_srg_bitmap = ol_ath_ucfg_set_he_srg_bitmap;
        ic->ic_cfg80211_radio_handler.get_he_srg_bitmap = ol_ath_ucfg_get_he_srg_bitmap;
        ic->ic_cfg80211_radio_handler.set_sr_self_config = ol_ath_ucfg_set_sr_self_config;
        ic->ic_cfg80211_radio_handler.get_sr_self_config = ol_ath_ucfg_get_sr_self_config;
#endif /* OBSS PD */

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
        ic->ic_primary_chanlist = NULL;
        ic->ic_primary_allowed_enable = false;
#endif

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
        qdf_spinlock_create(&scn->sc_mpsta_vap_lock);
#endif
#endif

        ol_ath_vap_attach(ic);

        if ((status = ol_ath_node_attach(scn, ic))) {
            qdf_err("ol_ath_node_attach failed");
            return status;
        };

        ol_ath_beacon_attach(ic);
        ol_ath_mgmt_attach(ic);

        ol_ath_chan_info_attach(ic);
        /* attach the dcs functionality */
        ol_ath_dcs_attach(ic);
        /* As of now setting ic with all ciphers assuming
         * hardware will support, eventually to query
         * the hardware to figure out h/w crypto support.
         */
        ieee80211com_set_cap(ic, IEEE80211_C_WEP);
        ieee80211com_set_cap(ic, IEEE80211_C_AES);
        ieee80211com_set_cap(ic, IEEE80211_C_AES_CCM);
        ieee80211com_set_cap(ic, IEEE80211_C_CKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIPMIC);
        if (wmi_service_enabled(wmi_handle, wmi_service_11ac)) {
            ieee80211com_set_cap_ext(ic, IEEE80211_CEXT_11AC);
        }

        if (ieee80211_conf_parm->wmeEnabled) {
            ieee80211com_set_cap(ic, IEEE80211_C_WME);
        }

#if ATH_SUPPORT_WAPI
        ieee80211com_set_cap(ic, IEEE80211_C_WAPI);
#endif
        wlan_scan_update_channel_list(ic);

#if OL_ATH_SUPPORT_LED
        if (target_version == AR9888_REV2_VERSION || target_version == AR9887_REV1_VERSION) {
            scn->scn_led_gpio = PEREGRINE_LED_GPIO ;
        } else if (target_version ==  AR900B_DEV_VERSION) {
            scn->scn_led_gpio = BEELINER_LED_GPIO ;
        } else if (target_version ==  QCA9984_DEV_VERSION) {
            scn->scn_led_gpio = CASCADE_LED_GPIO ;
        } else if (target_version ==  QCA9888_DEV_VERSION) {
            scn->scn_led_gpio = BESRA_LED_GPIO ;
        } else if (led_gpio_enable_8074 && target_type == TARGET_TYPE_QCA8074V2 && reg_cap) {
            if (reg_cap[pdev_idx].wireless_modes & WIRELESS_MODES_2G) {
                scn->scn_led_gpio = IPQ8074_2G_LED_GPIO ;
            } else {
                scn->scn_led_gpio = IPQ8074_5G_LED_GPIO ;
            }
        }

        if(target_type == TARGET_TYPE_IPQ4019) {
            scn->scn_led_gpio = 0; //will get initialized later
            ipq4019_wifi_led_init(scn);
        }

#if QCA_LTEU_SUPPORT
        if (wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_LTEU_SUPPORT)) {
            tgt_gpio_config(psoc, scn->scn_led_gpio, 1, WMI_HOST_GPIO_PULL_DOWN, WMI_HOST_GPIO_INTMODE_RISING_EDGE, 0, 0, 0);
        } else {
#endif
            ol_ath_led_init(soc, scn, target_type);
#if QCA_LTEU_SUPPORT
        }
#endif
#endif /* OL_ATH_SUPPORT_LED */
    }

    /*
     * Single vdev restart feature is used for run time configuration change
     * of some of the vdev parameters like hide_ssid etc..
     * Else, full vdev stop - start sequence is used for such configuration
     * changes.
     */
    ic->ic_is_vdev_restart_sup = true;

    is_prealloc_disabled = qdf_prealloc_disabled_config_get();
    if(is_prealloc_disabled) {
        ic->ic_scan_entry_max_count = ATH_SCANENTRY_MAX;
    } else {
        ic->ic_scan_entry_max_count = ATH_MAX_SCAN_ENTRIES;
    }
    ic->ic_scan_entry_timeout = ATH_SCANENTRY_TIMEOUT;
    ic->ic_rx_amsdu = 0xff;
    /* unless user prefers not to allow the frames between different vaps, let frames route through*/
    scn->scn_block_interbss = 0;

    /* Mask Value to set fixed mac addr for Backhaul STA. Default 255 */
    scn->sc_bsta_fixed_idmask = 0xff;

#if ATH_DATA_TX_INFO_EN
    /*Alloc buffer for data TX info*/
    scn->tx_status_buf = qdf_mem_malloc(sizeof(struct ieee80211_tx_status));
#endif

#if ATH_PROXY_NOACK_WAR
#if WLAN_QWRAP_LEGACY
    if(target_type == TARGET_TYPE_AR900B) {
        /* WAR is required only for Beeliner*/
        scn->sc_proxy_noack_war = 1;
        OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_ast_reserve_timer), ol_proxy_ast_reserve_timeout,
                (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    } else {
        /* Peregrine/Swift/Cascade/Dakota/Besra - Don't need this QWRAP WAR */
        scn->sc_proxy_noack_war = 0;
    }
#endif
#endif

    /* Add ic to global list */
    GLOBAL_IC_LOCK_BH(&ic_list);
    ic_list.global_ic[ic_list.num_global_ic++] = ic;
    qdf_info("Set global_ic[%d], ptr:%pK", ic_list.num_global_ic,&ic_list);
    ic->ic_global_list = &ic_list;
#if DBDC_REPEATER_SUPPORT
    ic_list.dbdc_process_enable = 1;
    ic_list.force_client_mcast_traffic = 0;

    qca_multi_link_set_dbdc_enable(true);
    qca_multi_link_set_force_client_mcast(true);
    if (ol_target_lithium(psoc)) {
        dp_lag_soc_enable(ic->ic_pdev_obj, 0);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_enable_dbdc_process(ic, 1);
        }
#endif
    }
    ic_list.delay_stavap_connection = cfg_get(psoc, CFG_TGT_DBDC_TIME_DELAY);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_radio_ops)
        ic->nss_radio_ops->ic_nss_ol_set_force_client_mcast_traffic(ic, ic_list.force_client_mcast_traffic);
#endif
    ic_list.num_stavaps_up = 0;
    ic_list.is_dbdc_rootAP = 0;
    ic_list.iface_mgr_up = 0;
    ic_list.disconnect_timeout = 10;
    ic_list.reconfiguration_timeout = 60;
    ic_list.always_primary = 0;
    ic_list.same_ssid_disable = 0;
    ic_list.num_fast_lane_ic = 0;
    ic_list.max_priority_stavap_up = NULL;
    ic_list.drop_secondary_mcast = 0;
    ic_list.num_rptr_clients = 0;
    ic_list.same_ssid_support = 0;
    ic_list.ap_preferrence = 0;
    ic_list.extender_info = 0;
    ic_list.rootap_access_downtime = 0;
    ic_list.num_l2uf_retries = 0;
    for (i=0; i < MAX_RADIO_CNT; i++) {
        memset(&ic_list.preferred_list_stavap[i][0], 0, QDF_MAC_ADDR_SIZE);
        memset(&ic_list.denied_list_apvap[i][0], 0, QDF_MAC_ADDR_SIZE);
    }
#endif
    GLOBAL_IC_UNLOCK_BH(&ic_list);

    if (soc->hw_mode_ctx.dynamic_hw_mode != WMI_HOST_DYNAMIC_HW_MODE_FAST)
        ic->ic_master_radio = ol_ath_is_master_radio(scn);

#if DBDC_REPEATER_SUPPORT
    spin_lock(&ic->ic_lock);
    if (ic_list.num_global_ic) {
        /* In case of DBDC repeater configuration, pass Multicast/Broadcast and
         ethernet client traffic through this radio */
        ic->ic_radio_priority = ic_list.num_global_ic;
        dp_lag_pdev_set_priority(ic->ic_pdev_obj, ic->ic_radio_priority);
        ic->ic_primary_radio = 0;
        dp_lag_pdev_set_primary_radio(ic->ic_pdev_obj, ic->ic_primary_radio);
    }
    ic->fast_lane = 0;
    ic->fast_lane_ic = NULL;
    ic->ic_extender_connection = 0;
    OS_MEMZERO(ic->ic_preferred_bssid, QDF_MAC_ADDR_SIZE);
    spin_unlock(&ic->ic_lock);

    k = 0;
    /*update other_ic list on each radio*/
    for (i=0; i < MAX_RADIO_CNT; i++) {
    GLOBAL_IC_LOCK_BH(&ic_list);
    tmp_ic = ic_list.global_ic[i];
    GLOBAL_IC_UNLOCK_BH(&ic_list);
    if (tmp_ic && (tmp_ic != ic) && (k < MAX_RADIO_CNT-1)) {
        spin_lock(&ic->ic_lock);
        ic->other_ic[k++] = tmp_ic;
        spin_unlock(&ic->ic_lock);
        for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
        if (tmp_ic->other_ic[j] == NULL) {
            spin_lock(&tmp_ic->ic_lock);
            tmp_ic->other_ic[j] = ic;
            spin_unlock(&tmp_ic->ic_lock);
            break;
        }
        }
    }
    }

#endif
#if QCN_IE
    ic->ic_rept_clients = 0;
#endif
    /*Set default monitor VAP filter to enable all input*/
    ic->mon_filter_osif_mac = 0;
    ic->ic_non_doth_sta_cnt = 0;

    ic->ic_stop = ol_ath_target_stop;

    if (wmi_service_enabled(wmi_handle,
                wmi_service_multiple_vdev_restart)) {
        wlan_pdev_nif_feat_cap_set(ic->ic_pdev_obj,
                                   WLAN_PDEV_F_MULTIVDEV_RESTART);
    } else {
        wlan_pdev_nif_feat_cap_clear(ic->ic_pdev_obj,
                                     WLAN_PDEV_F_MULTIVDEV_RESTART);
    }

    if (wmi_service_enabled(wmi_handle,
                            wmi_service_vdev_delete_all_peer)) {
        wlan_pdev_nif_feat_cap_set(ic->ic_pdev_obj,
                                   WLAN_PDEV_F_DELETE_ALL_PEER);
    } else {
        wlan_pdev_nif_feat_cap_clear(ic->ic_pdev_obj,
                                     WLAN_PDEV_F_DELETE_ALL_PEER);
    }

    if (wmi_service_enabled(wmi_handle,
                            wmi_beacon_protection_support)) {
        wlan_pdev_nif_feat_cap_set(ic->ic_pdev_obj,
                                   WLAN_PDEV_F_BEACON_PROTECTION);
    } else {
        wlan_pdev_nif_feat_cap_clear(ic->ic_pdev_obj,
                                     WLAN_PDEV_F_BEACON_PROTECTION);
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_radio.nss_rctx)
        ic->nss_vops->ic_osif_nss_wifi_monitor_set_filter(ic, MON_FILTER_ALL_DISABLE);
#endif

    ol_ath_twt_enable_command(scn);
#ifdef QVIT
    ol_ath_pdev_qvit_attach(scn);
#endif


    if (dispatcher_pdev_open(scn->sc_pdev)) {
        qdf_err("Dispatcher pdev open failed");
        return -EINVAL;
    }

    ol_ath_pdev_dfs_phyerr_offload_en(scn->sc_pdev);
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    ic->ic_rebuilt_chanlist = 0;
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops) {
        if(dfs_rx_ops->dfs_reset_spoof_test)
            dfs_rx_ops->dfs_reset_spoof_test(scn->sc_pdev);
    }
#endif /* HOST_DFS_SPOOF_TEST */
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(WLAN_DFS_SYNTHETIC_RADAR)
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops && dfs_rx_ops->dfs_allow_hw_pulses)
        dfs_rx_ops->dfs_allow_hw_pulses(scn->sc_pdev, true);
#endif /* WLAN_DFS_PARTIAL_OFFLOAD && WLAN_DFS_SYNTHETIC_RADAR*/
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    /* Resetting the scan violation status on wifi. */
    ic->ic_is_dfs_scan_violation = false;
#endif
    if (ol_target_lithium(psoc)) {
        scn->is_scn_stats_timer_init = 1;
	scn->pdev_stats_timer = PDEV_STATS_DEFAULT_TIMER;
        qdf_timer_init(soc->qdf_dev, &(scn->scn_stats_timer), ol_ath_get_pdev_stats, (void *)scn, QDF_TIMER_TYPE_SW);
    }

#ifdef WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG
    ic->rx_pkt_protocol_tag_mask = 0;
    ol_ath_set_protocol_tagging(ic->ic_pdev_obj, RX_PKT_TAG_OPCODE_ADD,
		                RECV_PKT_TYPE_EAP, 3232);
#endif //WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG

#if OBSS_PD
    ol_ath_pdev_sr_init(scn);
#endif

    /* FW dynamic selection of Muedca param by default */
    ic->ic_muedca_mode_state = HEMUEDCA_FW_DYNAMIC_MODE;
    qdf_atomic_init(&(scn->auth_cnt));
    qdf_timer_init(soc->qdf_dev, &(scn->auth_timer), ol_ath_clear_auth_cnt, (void *)scn, QDF_TIMER_TYPE_SW);


    scn->max_auth = MAX_AUTH_REQUEST;
    scn->tx_ack_timeout = DEFAULT_TX_ACK_TIMEOUT;
    scn->is_ani_enable = DEFAULT_ANI_ENABLE_STATUS;

    /* Check for channels to be blocked for automatic channel selection (ACS, ICM, ...)*/
    ol_ath_pri20_cfg_blockchanlist_parse(ic, cfg_get(soc->psoc_obj, CFG_OL_PRI20_CFG_BLOCKCHANLIST));

    /* Enable support for wideband (5GHz-7GHz) support and CSA-specific flags */
    ol_ath_parse_wideband_support(ic, cfg_get(soc->psoc_obj, CFG_OL_WIDEBAND_CSA));

    ic->ic_offchan_dwell_time = cfg_get(soc->psoc_obj, CFG_OL_OFFCHAN_SCAN_DWELL_TIME);

    ic->ic_omn_cxt.omn_timeout = OMN_DEFAULT_UPDATE_TIME;
    qdf_timer_init(NULL, &ic->ic_omn_cxt.notify_timer, wlan_omn_timer_callback, (void *)ic, QDF_TIMER_TYPE_WAKE_APPS);

    if (ol_target_lithium(psoc)) {
        /* By default,Set driver mode for RNR advertisement */
        WLAN_6GHZ_RNR_DRIVER_MODE_SET(ic->ic_6ghz_rnr_enable);
    }

    if (!soc->tbtt_offset_sync_timer_init) {
        qdf_timer_init(soc->qdf_dev, &(soc->tbtt_offset_sync_timer),
                       ol_tbtt_sync_timer_cb, (void *)scn,
                       QDF_TIMER_TYPE_WAKE_APPS);
	soc->tbtt_offset_sync_timer_init = 1;
    }

    if (cfg_get(psoc, CFG_OL_EXTERNALACS_ENABLE))
        ieee80211_ic_externalacs_enable_set(ic);
    else
        ieee80211_ic_externalacs_enable_clear(ic);

    return EOK;
}

void ol_ath_target_deinit(ol_ath_soc_softc_t *soc, int force)
{
    ol_txrx_soc_handle soc_txrx_handle;
    void *dp_ext_hdl;
    struct target_psoc_info *tgt_psoc_info;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return;
    }

    soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);

    if (!bypasswmi) {
        if (soc_txrx_handle) {
            cdp_txrx_intr_detach(soc_txrx_handle);
            dp_ext_hdl = cdp_soc_get_dp_txrx_handle(soc_txrx_handle);
            cdp_soc_set_dp_txrx_handle(soc_txrx_handle, NULL);

            if (dp_ext_hdl)
                qdf_mem_free(dp_ext_hdl);

            ol_ath_soc_rate_stats_detach(soc);

            cdp_soc_deinit(soc_txrx_handle);
#ifdef WLAN_FEATURE_FASTPATH
            soc->htt_handle = NULL;
#endif
        }

        if (soc->dbg_log_init) {
            ol_ath_dbglog_detach(soc);
            soc->dbg_log_init = 0;
        }
    }
}

void ol_ath_target_deinit_complete(ol_ath_soc_softc_t *soc)
{
   HTC_HANDLE htc_handle;
   void *hif_hdl;
   struct target_psoc_info *tgt_hdl;

   tgt_hdl = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
   htc_handle = lmac_get_htc_hdl(soc->psoc_obj);
   hif_hdl = lmac_get_ol_hif_hdl(soc->psoc_obj);

   if (htc_handle) {
        htc_destroy(htc_handle);
        lmac_set_htc_hdl(soc->psoc_obj, NULL);
    }

    /* Cleanup BMI */
#ifdef WLAN_FEATURE_BMI
    if (soc->bmi_handle != NULL) {
        if (soc->bmi_handle->bmi_cleanup)
            soc->bmi_handle->bmi_cleanup(soc->bmi_handle,soc->sc_osdev);
        if (soc->bmi_handle->bmi_free)
            soc->bmi_handle->bmi_free(soc->bmi_handle);
    }
#endif
    if (hif_hdl != NULL) {
        ol_hif_close(hif_hdl);
	target_psoc_set_hif_hdl(tgt_hdl, NULL);
	hif_hdl = NULL;
    }
}

int
ol_ath_soc_detach(ol_ath_soc_softc_t *soc, int force)
{
    int status = 0;
    struct mgmt_txrx_mgmt_frame_cb_info rx_cb_info;
    struct target_psoc_info *tgt_psoc_info;
    struct wmi_unified *wmi_handle;
    struct hif_opaque_softc *hif_hdl;
    struct pdev_op_args oper;
    ol_txrx_soc_handle soc_txrx_handle = NULL;
	uint8_t tgt_type = 0;

    if (ol_target_lithium(soc->psoc_obj)) {
        qca_unregister_netdevice_notifier(&qca_device_notifier);
    }

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return -EINVAL;
    }

    wmi_handle = target_psoc_get_wmi_hdl(tgt_psoc_info);
    if (!wmi_handle)
        return -EINVAL;

#if OL_ATH_SUPPORT_LED
    if (
#if QCA_LTEU_SUPPORT
        !(wlan_psoc_nif_feat_cap_get(soc->psoc_obj, WLAN_SOC_F_LTEU_SUPPORT)) &&
#endif
        !bypasswmi) {
            soc->led_blink_rate_table = NULL;
    }
#endif /* OL_ATH_SUPPORT_LED */

    if(soc->ol_if_ops->wds_addr_detach)
    	soc->ol_if_ops->wds_addr_detach((wmi_unified_t)wmi_handle);

    ol_mempools_detach(soc);

    ol_ath_phyerr_detach(soc);
    ol_ath_soc_chan_info_detach(soc);
#if  ATH_DATA_TX_INFO_EN
    ol_ath_stats_soc_detach(soc);
#endif
    ol_ath_wow_soc_detach(soc);

   tgt_type = lmac_get_tgt_type(soc->psoc_obj);

#if WLAN_SUPPORT_MSCS && QCA_NSS_PLATFORM
  /*
   * De-Init MSCS module
   */
    if (tgt_type == TARGET_TYPE_QCA8074 ||
            tgt_type == TARGET_TYPE_QCA8074V2 ||
            tgt_type == TARGET_TYPE_QCA5018 ||
            tgt_type == TARGET_TYPE_QCN9000 ||
            tgt_type == TARGET_TYPE_QCA6018) {
        qca_mscs_module_deinit(soc);
    }
#endif

    /* UMAC Disatcher disable/stop all components under PSOC */
    dispatcher_psoc_disable(soc->psoc_obj);

    if (!(soc->down_complete)) {
        ol_ath_disconnect_htc(soc);
        ol_ath_target_deinit(soc, force);
    } else if (ol_target_lithium(soc->psoc_obj)) {
        oper.type = PDEV_ITER_PDEV_DETACH_OP;
        wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
                wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
        soc->nss_soc.ops->nss_soc_desc_pool_free(soc);
    }
#endif

    soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);

    wlan_psoc_set_dp_handle(soc->psoc_obj, NULL);
    cdp_soc_detach(soc_txrx_handle);

#ifdef QVIT
    ol_ath_qvit_detach(soc);
#endif

    if (!bypasswmi) {
        if (soc->dbg_log_init) {
            ol_ath_dbglog_detach(soc);
            soc->dbg_log_init = 0;
        }
    }

    if (!(soc->down_complete)) {
    	hif_hdl = target_psoc_get_hif_hdl(tgt_psoc_info);
        hif_disable_isr((struct hif_opaque_softc *)hif_hdl);
        ol_ath_target_deinit_complete(soc);
    }
    dispatcher_psoc_close(soc->psoc_obj);

    if (!bypasswmi) {
        if (wmi_handle) {
            wmi_unified_detach((wmi_unified_t)wmi_handle);
#if WMI_RECORDING
            wmi_proc_remove((wmi_unified_t)wmi_handle, soc->wmi_proc_entry, soc->soc_idx);
#endif
            wmi_handle =NULL;
        }
    }

    ol_codeswap_detach(soc);

#ifdef AH_CAL_IN_FLASH_PCI
#ifndef ATH_CAL_NAND_FLASH
    if (soc->cal_mem) {
        A_IOUNMAP(soc->cal_mem);
        soc->cal_mem = 0;
    }
#endif
    soc->cal_in_flash = 0;
#endif
#if QLD
    qdf_event_destroy(&soc->qld_wait);
#endif
    soc->cal_in_file = 0;

    /* Deregister MgMt TxRx handler */
    rx_cb_info.frm_type = MGMT_FRAME_TYPE_ALL;
    rx_cb_info.mgmt_rx_cb = ieee80211_mgmt_input;
    wlan_mgmt_txrx_deregister_rx_cb(soc->psoc_obj, WLAN_UMAC_COMP_MLME,
                                       &rx_cb_info, 1);

    if (!(soc->down_complete)) {
         init_deinit_free_num_units(soc->psoc_obj, tgt_psoc_info);
    }

#ifdef WLAN_SUPPORT_RF_CHARACTERIZATION
    if (soc->rf_characterization_entries) {
        qdf_mem_free(soc->rf_characterization_entries);
        soc->num_rf_characterization_entries = 0;
        soc->rf_characterization_entries = NULL;
    }
#endif

    /* No Target accesses of any kind after this point */
    return status;
}

int ol_ath_pdev_detach(struct ol_ath_softc_net80211 *scn, int force)
{
    struct ieee80211com     *ic = &scn->sc_ic;
    ol_ath_soc_softc_t *soc = scn->soc;
    int status = 0;
    struct ieee80211com     *tmp_ic;
#if DBDC_REPEATER_SUPPORT
    int j;
#endif
    int i = 0;

#if ATH_DATA_TX_INFO_EN
    /*Free buffer for data TX info*/
    qdf_mem_free(scn->tx_status_buf);
    scn->tx_status_buf = NULL;
#endif

    if (ol_target_lithium(scn->soc->psoc_obj)) {
            if (scn->is_scn_stats_timer_init)
                qdf_timer_sync_cancel(&scn->scn_stats_timer);
    }

#if  ATH_DATA_TX_INFO_EN
    if (!(scn->soc->down_complete)) {
        ol_ath_stats_detach(ic);
    }
#endif
    if (ol_target_lithium(soc->psoc_obj))
            qdf_timer_sync_cancel(&scn->scn_stats_timer);

    qdf_timer_sync_cancel(&(scn->auth_timer));

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    qdf_spinlock_destroy(&scn->sc_mpsta_vap_lock);
#endif
#endif

    ol_ath_wow_detach(ic);

    /* deregister IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_deregister(ic);


    if (!bypasswmi) {
        ieee80211_stop_running(ic);

        /*
         * NB: the order of these is important:
         * o call the 802.11 layer before detaching the hal to
         *   insure callbacks into the driver to delete global
         *   key cache entries can be handled
         * o reclaim the tx queue data structures after calling
         *   the 802.11 layer as we'll get called back to reclaim
         *   node state and potentially want to use them
         * o to cleanup the tx queues the hal is called, so detach
         *   it last
         * Other than that, it's straightforward...
         */
        ieee80211_ifdetach(ic);
    }

    ol_regdmn_detach(scn->ol_regdmn_handle);
    ol_ath_mgmt_detach(ic);

#if WLAN_SPECTRAL_ENABLE
    /* Unregister spectral event handlers with DDMA */
    spectral_unregister_dbr(ic->ic_pdev_obj);
#endif /* WLAN_SPECTRAL_ENABLE */

#if WLAN_CFR_ENABLE
    /* pdev deinit to be done on Target Stop */
    cfr_deinitialize_pdev(ic->ic_pdev_obj);
#endif

    qdf_event_destroy(&ic->ic_wait_for_init_cc_response);

#if QCA_LTEU_SUPPORT
    ol_ath_nl_detach(ic);
#endif

#ifndef REMOVE_PKT_LOG
    if (scn->pl_dev){
        ol_pktlog_detach(scn);
    ol_pl_freehandle(scn->pl_dev);
        scn->pl_dev = NULL;
    }
#endif

#if ATH_PROXY_NOACK_WAR
#if WLAN_QWRAP_LEGACY
    if (scn->sc_proxy_noack_war) {
        OS_FREE_TIMER(&(ic->ic_ast_reserve_timer));
    }
#endif
#endif

    /* Remove ic from global list */
    for (i=0; i < MAX_RADIO_CNT; i++) {
        tmp_ic = ic_list.global_ic[i];
        if (tmp_ic && (ic == tmp_ic)) {
            GLOBAL_IC_LOCK_BH(&ic_list);
            ic_list.global_ic[i] = NULL;
            ic_list.num_global_ic--;
            qdf_info("remove global_ic[%d]..gloabl_ic ptr:%pK",
                     ic_list.num_global_ic, &ic_list);
            GLOBAL_IC_UNLOCK_BH(&ic_list);
        }
    }
#if DBDC_REPEATER_SUPPORT
    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK_BH(&ic_list);
        tmp_ic = ic_list.global_ic[i];
        GLOBAL_IC_UNLOCK_BH(&ic_list);
        if (tmp_ic && (tmp_ic != ic)) {
            for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
                if (tmp_ic->other_ic[j] == ic) {
                    spin_lock(&tmp_ic->ic_lock);
                    tmp_ic->other_ic[j] = NULL;
                    spin_unlock(&tmp_ic->ic_lock);
                    break;
                }
            }
        }
    }

    /*
     * The removal of radio is done here as wiphy structure
     * is freed inside ic_cfg80211_radio_detach function.
     */
    if (ic->ic_wiphy) {
        qca_multi_link_remove_radio(ic->ic_wiphy);
    }

#endif

#if UMAC_SUPPORT_CFG80211
    if (ic->ic_cfg80211_config) {
      if(ic->ic_cfg80211_radio_detach) {
        ic->ic_cfg80211_radio_detach(ic);
      }
    }
#endif

#ifdef QVIT
    ol_ath_pdev_qvit_detach(scn);
#endif

#if OL_ATH_SUPPORT_LED
    if (
#if QCA_LTEU_SUPPORT
        !(wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_LTEU_SUPPORT)) &&
#endif
        !bypasswmi) {
            qdf_timer_sync_cancel(&scn->scn_led_blink_timer);
            qdf_timer_sync_cancel(&scn->scn_led_poll_timer);
            if(lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_IPQ4019) {
                    ipq4019_wifi_led_deinit(scn);
	    }
    }
#endif /* OL_ATH_SUPPORT_LED */

#if OS_SUPPORT_ASYNC_Q
    OS_MESGQ_DRAIN(&scn->sc_osdev->async_q,NULL);
    OS_MESGQ_DESTROY(&scn->sc_osdev->async_q);
#endif
#if !defined(BUILD_X86) && !defined(CONFIG_X86)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 24)
    qcom_pcie_deregister_event(&soc->pcie_event);
#endif
#endif

    qdf_timer_free(&ic->ic_omn_cxt.notify_timer);
    if (soc->tbtt_offset_sync_timer_init) {
        qdf_timer_free(&(soc->tbtt_offset_sync_timer));
        soc->tbtt_offset_sync_timer_init = 0;
    }

    return status;
}

void ol_reset_params(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;

    /* should always be equal to define DEFAULT_LOWEST_RATE_IN_5GHZ 0x03  6 Mbps  in firmware */
    scn->ol_rts_cts_rate                    = 0x03;
#if WDI_EVENT_ENABLE
    scn->scn_user_peer_invalid_cnt          = 0;/* By default we will send one deauth in 10 msec in response to rx_peer_invalid */
#endif
    scn->dyngroup                           = 0;
    scn->dpdenable                          = CLI_DPD_NA_STATE;
    scn->scn_amsdu_mask                     = 0xffff;
    scn->scn_amsdu_mask                     = 0xffff;
    scn->txpower_scale                      = 0;
    scn->powerscale                         = 0;

    ol_ath_reset_dcs_params(scn);

    scn->burst_dur                          = 0;
    scn->burst_enable                       = 0;
    scn->is_ani_enable                      = DEFAULT_ANI_ENABLE_STATUS;
    scn->dtcs                               = 0; /* Dynamic Tx Chainmask Selection enabled/disabled */
    scn->vow_extstats                       = 0;
    scn->sc_arp_dbg_conf                    = 0;
#ifdef QCA_SUPPORT_CP_STATS
    pdev_cp_stats_ap_stats_tx_cal_enable_update(ic->ic_pdev_obj, 0);
#endif
    scn->macreq_enabled                     = 0; /* user mac request feature enable/disable */
    scn->sc_bsta_fixed_idmask               = 0xff; /* Mask Value to set fixed mac addr for Backhaul STA. Default 255 */
    scn->arp_override                       = WME_AC_VO;
    scn->igmpmld_override                   = 0;
    scn->igmpmld_tid                        = 0;
#if ATH_RX_LOOPLIMIT_TIMER
    scn->rx_looplimit_timeout               = 1;           /* 1 ms by default */
    scn->rx_looplimit_valid                 = true;          /* set to valid after initilization */
    scn->rx_looplimit                       = false;
#endif
    scn->sc_prealloc_idmask                 = 0;
    scn->sc_is_blockdfs_set                 = false;
    scn->scn_qboost_enable                  = 0;
    scn->scn_sifs_frmtype                   = 0;
    scn->scn_sifs_uapsd                     = 0;
    scn->scn_block_interbss                 = 0;
    scn->txbf_sound_period                  = 100;
    scn->scn_promisc                        = 0;
    scn->enable_statsv2                     = 0;
#if ATH_SUPPORT_WRAP
    scn->mcast_bcast_echo                   = 0;
#endif
#if ATH_DATA_TX_INFO_EN
    scn->enable_perpkt_txstats              = 0;
#endif
    scn->tx_ack_timeout                     = DEFAULT_TX_ACK_TIMEOUT;
#ifdef QCA_SUPPORT_CP_STATS
    pdev_cp_stats_wmi_tx_mgmt_update(ic->ic_pdev_obj, 0);
    pdev_cp_stats_wmi_tx_mgmt_completions_update(ic->ic_pdev_obj, 0);
    pdev_cp_stats_wmi_tx_mgmt_completion_err_update(ic->ic_pdev_obj, 0);
#endif

    /*
     * CCK is enabled by default in the firmware for all the chipsets.
     */
    ic->cck_tx_enable = true;

    return;
}

int ol_ath_soc_stop(struct ol_ath_soc_softc *soc, bool flush_wq)
{
    struct net_device *dev;
    struct pci_dev *pcidev;
    int target_paused = TRUE;
    uint32_t target_type;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_service_ext_param *ext_param = NULL;
    struct hif_opaque_softc *hif_hdl;
    ol_txrx_soc_handle soc_txrx_handle;
    struct pdev_op_args oper;

    psoc = soc->psoc_obj;
    target_type = lmac_get_tgt_type(psoc);
    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        return -EINVAL;
    }

    hif_hdl = target_psoc_get_hif_hdl(tgt_hdl);
    ext_param = &(tgt_hdl->info.service_ext_param);

    dev = soc->sc_osdev->netdev;
    pcidev = (struct pci_dev *)soc->sc_osdev->bdev;

    if (qdf_atomic_test_and_set_bit(SOC_RESET_IN_PROGRESS_BIT,
                                    &soc->reset_in_progress)) {
        qdf_info("Reset in progress, return");
        return -EBUSY;
    }

    if (soc->down_complete) {
        /*
         * Target has already been stopped, return success.
         */
        goto out;
    }

     /* To avoid PCI register access after pci unmap,
      * flush any pending pci_reconnect_work */
    if (flush_wq) {
        qdf_flush_work(&soc->pci_reconnect_work);
    }

    soc->soc_attached = 0;
#if OL_ATH_SUPPORT_LED
    soc->led_blink_rate_table = NULL;
#endif

    if (ol_ath_is_dynamic_hw_mode_enabled(soc) &&
        (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) &&
        (soc->hw_mode_ctx.current_mode == WMI_HOST_HW_MODE_DBS)) {
        struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
        int i;

        /* Save current_mode for SSR recovery and switch to DBS_SBS mode
         * for clean up
         */
        soc->hw_mode_ctx.recover_mode = soc->hw_mode_ctx.current_mode;
        soc->hw_mode_ctx.target_mode = WMI_HOST_HW_MODE_DBS_SBS;

        mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode(
                          tgt_hdl, WMI_HOST_HW_MODE_DBS_SBS);
        if (mac_phy_cap) {
            for (i = 0; i < WMI_HOST_MAX_PDEV; i++) {
                soc->hw_mode_ctx.next_pdev_map[i] = mac_phy_cap[i].tgt_pdev_id;
            }

            ol_ath_hw_mode_config_primary_pdev(soc, false);
            ol_ath_hw_mode_apply_pdev_map(soc);
            ol_ath_hw_mode_config_primary_pdev(soc, true);
            ol_ath_hw_mode_config_secondary_pdev(soc, true);
        }
    }

    oper.type = PDEV_ITER_PDEV_DEINIT_BEFORE_SUSPEND;
    wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
              wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);
    /* Suspend Target if not recovering */
    if (soc->recovery_in_progress == 0) {
        qdf_info("Suspending Target  soc=%pK", soc);
        if (!ol_ath_suspend_target(soc, 1)) {
            u_int32_t  timeleft;
            qdf_info("waiting for target paused event from target");
            /* wait for the event from Target*/
            timeleft = wait_event_interruptible_timeout(soc->sc_osdev->event_queue,
                (soc->is_target_paused == TRUE),
                PDEV_SUSPEND_TIMEOUT);
            if (!timeleft || signal_pending(current)) {
            qdf_info("ERROR: Failed to receive target paused event soc=%pK ", soc);
            target_paused = FALSE;
            }
            /*
             * reset is_target_paused and host can check that in next time,
             * or it will always be TRUE and host just skip the waiting
             * condition, it causes target assert due to host already suspend
             */
            soc->is_target_paused = FALSE;
        }
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
            qdf_info("nss-wifi: detach soc->soc_idx: %d - 100 delay ", soc->soc_idx);
            soc->nss_soc.ops->nss_soc_wifi_detach(soc, 100);
    }
#endif

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    qdf_info("disable dp interrupts:: soc: %pK", soc_txrx_handle);
    hif_disable_isr((struct hif_opaque_softc *)hif_hdl);
    cdp_txrx_intr_detach(soc_txrx_handle);

    ol_ath_disconnect_htc(soc);
    oper.type = PDEV_ITER_PDEV_DEINIT_OP;
    wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
            wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);

    ol_ath_target_deinit(soc, 1);

    ol_ath_target_deinit_complete(soc);
    if (ext_param) {
        /* free chain mask table */
        init_deinit_chainmask_table_free(ext_param);
    }

    init_deinit_dbr_ring_cap_free(tgt_hdl);
    init_deinit_spectral_scaling_params_free(tgt_hdl);
    init_deinit_scan_radio_cap_free(tgt_hdl);

    if((target_type !=  TARGET_TYPE_IPQ4019) &&
       (target_type !=  TARGET_TYPE_QCN6122) &&
       (target_type !=  TARGET_TYPE_QCN9000) &&
       (target_type !=  TARGET_TYPE_QCA8074) &&
       (target_type != TARGET_TYPE_QCA8074V2) &&
       (target_type !=  TARGET_TYPE_QCA5018) &&
       (target_type != TARGET_TYPE_QCA6018)) {
        pci_set_drvdata(pcidev, dev);
    }

    init_deinit_free_num_units(soc->psoc_obj, tgt_hdl);
    target_psoc_set_wmi_ready(tgt_hdl, FALSE);
    target_psoc_set_wmi_service_ready(tgt_hdl, FALSE);
    wlan_psoc_nif_op_flag_clear(psoc, WLAN_SOC_OP_VHT_INVALID_CAP);
    soc->dbg.print_rate_limit = DEFAULT_PRINT_RATE_LIMIT_VALUE;

    oper.type = PDEV_ITER_PDEV_RESET_PARAMS;
    wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
                 wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);

    ol_ath_diag_user_agent_fini(soc);

    /* re-init hw_mode_ctx->current_mode */
    soc->hw_mode_ctx.current_mode = WMI_HOST_HW_MODE_MAX;

    soc->down_complete = true;

out:
    qdf_atomic_clear_bit(SOC_RESET_IN_PROGRESS_BIT, &soc->reset_in_progress);
    return 0;
}

/* Suspend and unload the firmware during the last vap removal */
int ol_ath_target_stop(struct ieee80211com *ic, bool flush_wq)
{
    struct ol_ath_softc_net80211 *scn;
    struct ol_ath_soc_softc *soc;
    struct platform_device *pdev;
#ifdef CONFIG_CNSS2_SUPPORT
    struct pci_dev *pcidev = NULL;
#endif
    int tgt_type = 0;

    /* get the soc struct from scn */
    scn =  OL_ATH_SOFTC_NET80211(ic);
    soc = scn->soc;
    pdev = (struct platform_device *)soc->sc_osdev->bdev;
    tgt_type = lmac_get_tgt_type(soc->psoc_obj);

    ol_ath_soc_stop(soc, flush_wq);

#ifdef CONFIG_CNSS2_SUPPORT

    if ((tgt_type == TARGET_TYPE_QCA8074) ||
        (tgt_type == TARGET_TYPE_QCA8074V2) ||
        (tgt_type == TARGET_TYPE_QCA6018) ||
        (tgt_type == TARGET_TYPE_QCA5018) ||
        (tgt_type == TARGET_TYPE_QCN6122) ||
        (tgt_type == TARGET_TYPE_QCN9000)) {
        /* pld_wlan_disable is called inside hif_wlan_disable */
        if ((tgt_type == TARGET_TYPE_QCA8074) ||
            (tgt_type == TARGET_TYPE_QCA8074V2) ||
            (tgt_type == TARGET_TYPE_QCA5018) ||
            (tgt_type == TARGET_TYPE_QCN6122) ||
            (tgt_type == TARGET_TYPE_QCA6018)) {
                pld_subsystem_put(&pdev->dev);
        }
        if (tgt_type == TARGET_TYPE_QCN9000) {
                pcidev = (struct pci_dev *)pdev;
                pld_subsystem_put(&pcidev->dev);
        }
    }
#endif
    return 0;
}
qdf_export_symbol(ol_ath_target_stop);

uint16_t ol_ath_get_num_clients(struct wlan_objmgr_pdev *pdev)
{
    uint16_t num_peers = wlan_pdev_get_max_peer_count(pdev);
    uint8_t num_vdevs = wlan_pdev_get_max_vdev_count(pdev);

    /* If num_peers is less than num_vdevs then use num_peers as it is without
     * removing bss peers.
     */
    if (num_vdevs > num_peers)
        return num_peers;
    else
        return (num_peers - num_vdevs);
}

int ol_ath_soc_start(struct ol_ath_soc_softc *soc)
{
    struct net_device *netdev;
    struct platform_device *pdev;
    uint32_t pdev_idx;
    struct pci_dev *pcidev;
    struct _NIC_DEV *drv;
    int i, retval = 0, sniffer_mode;
#ifdef CONFIG_CNSS2_SUPPORT
    struct device *dev = NULL;
#endif
    struct target_psoc_info *tgt_hdl;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    uint32_t target_type;
    uint32_t target_version;
    struct wlan_psoc_target_capability_info *target_cap;
    ol_txrx_soc_handle soc_txrx_handle;
    void *hif_hdl;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#endif /* HOST_DFS_SPOOF_TEST */
    uint8_t num_radios;
    struct ol_ath_softc_net80211 *scn;

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target handle is null");
        goto fail;
    }
    target_cap = target_psoc_get_target_caps(tgt_hdl);
    mac_phy_cap = target_psoc_get_mac_phy_cap(tgt_hdl);
    target_type = target_psoc_get_target_type(tgt_hdl);
    target_version = target_psoc_get_target_ver(tgt_hdl);

    pdev = (struct platform_device *)soc->sc_osdev->bdev;
    pcidev = (struct pci_dev *)soc->sc_osdev->bdev;
    netdev = soc->sc_osdev->netdev;
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

#ifdef CONFIG_CNSS2_SUPPORT
    if ((target_type == TARGET_TYPE_QCA8074) ||
		    (target_type == TARGET_TYPE_QCA8074V2) ||
		    (target_type == TARGET_TYPE_QCA5018) ||
		    (target_type == TARGET_TYPE_QCN6122) ||
		    (target_type == TARGET_TYPE_QCA6018)) {
        dev = &pdev->dev;
    } else {
        dev = &pcidev->dev;
    }

    pld_wait_for_fw_ready(dev);
#endif

    drv = soc->qdf_dev->drv;

    OS_MEMSET(soc->qdf_dev, 0, sizeof(*(soc->qdf_dev)));

    soc->qdf_dev->drv = drv;

    if((target_type == TARGET_TYPE_IPQ4019) ||
       (target_type == TARGET_TYPE_QCA8074) ||
       (target_type == TARGET_TYPE_QCA8074V2) ||
       (target_type == TARGET_TYPE_QCN6122) ||
       (target_type == TARGET_TYPE_QCA5018) ||
       (target_type == TARGET_TYPE_QCA6018)) {
        soc->qdf_dev->dev = &pdev->dev; /* device */
        soc->qdf_dev->drv_hdl = NULL; /* bus handle */
        hif_hdl = ol_hif_open(&pdev->dev, pdev, (void *)soc->platform_devid, QDF_BUS_TYPE_AHB, 0,soc->qdf_dev);
    } else {
        soc->qdf_dev->dev = &pcidev->dev; /* device */
        soc->qdf_dev->drv_hdl = pcidev; /* bus handle */
        if (target_type != TARGET_TYPE_QCN9000) {
                pci_set_drvdata(pcidev, NULL);
        }
        hif_hdl = ol_hif_open(&pcidev->dev, pcidev, (void *)soc->platform_devid, QDF_BUS_TYPE_PCI, 0,soc->qdf_dev);
        if (target_type != TARGET_TYPE_QCN9000) {
                pci_set_drvdata(pcidev, netdev);
        }
    }

    wlan_psoc_set_qdf_dev(psoc, soc->qdf_dev);
    if (!hif_hdl) {
        goto fail;
    }
    target_psoc_set_hif_hdl(tgt_hdl, hif_hdl);
    soc->targetdef = hif_get_targetdef(hif_hdl);

    /* set up dynamic_hw_mode switch if supported */
    if (cfg_get(psoc, CFG_OL_DYNAMIC_HW_MODE)) {
        soc->hw_mode_ctx.target_mode =
                        target_psoc_get_preferred_hw_mode(tgt_hdl);
        target_psoc_set_preferred_hw_mode(tgt_hdl,
                                          WMI_HOST_HW_MODE_DETECT);
    }

    target_psoc_set_total_mac_phy_cnt(tgt_hdl, 0);
    target_psoc_set_num_radios(tgt_hdl, 0);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (soc->nss_soc.ops) {
            if (soc->nss_soc.ops->nss_soc_wifi_init(soc)) {
                    goto fail;
            }
    }
#endif

    if (soc->ol_if_ops->target_init) {
        if (soc->ol_if_ops->target_init(soc, true))
            goto fail;
    }

    if (ol_target_init_complete(soc))
        goto fail;

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (!soc_txrx_handle) {
        qdf_err("psoc dp handle is null");
        goto fail;
    }

#ifdef DIRECT_BUF_RX_ENABLE
    if (direct_buf_rx_target_attach(soc->psoc_obj,
                          hif_get_hal_handle(lmac_get_hif_hdl(soc->psoc_obj)),
                          soc->qdf_dev) != QDF_STATUS_SUCCESS) {
        qdf_err("Direct Buffer Rx Target Attach Failed");
    }
#endif

    num_radios = target_psoc_get_num_radios(tgt_hdl);

    for (i = 0; i < num_radios; i++) {
        struct net_device *pdev_netdev;
        struct ieee80211com *ic;
        struct wlan_objmgr_pdev *pdev_obj;
        uint8_t pdev_id;

        pdev_obj = wlan_objmgr_get_pdev_by_id(psoc, i, WLAN_MLME_NB_ID);
        if (!pdev_obj) {
             qdf_err("pdev object (id: %d) is NULL", i);
             goto fail;
        }

        scn = lmac_get_pdev_feature_ptr(pdev_obj);
        ic = &scn->sc_ic;
        pdev_idx = lmac_get_pdev_idx(scn->sc_pdev);
        pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev_obj);

        pdev_netdev = scn->netdev;
        if (!bypasswmi) {
            if ((target_type != TARGET_TYPE_QCA8074) &&
			    (target_type != TARGET_TYPE_QCA8074V2) &&
			    (target_type != TARGET_TYPE_QCA6018) &&
			    (target_type != TARGET_TYPE_QCA5018) &&
			    (target_type != TARGET_TYPE_QCN6122) &&
			    (target_type != TARGET_TYPE_QCN9000)) {
                if (target_version != AR6004_VERSION_REV1_3) {
                    if (cdp_pdev_attach_target(soc_txrx_handle,
                        pdev_id) != A_OK) {
                        qdf_err("txrx pdev attach target failed");
                        wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_NB_ID);
                        goto fail;
                    }
                }
            } else {
                qdf_info("Skip txrx_pdev_attach_target");
            }
        }

        if ((target_type != TARGET_TYPE_QCA8074) &&
            (target_type != TARGET_TYPE_QCA8074V2) &&
            (target_type != TARGET_TYPE_QCN9000) &&
            (target_type != TARGET_TYPE_QCN6122) &&
            (target_type != TARGET_TYPE_QCA5018) &&
            (target_type != TARGET_TYPE_QCA6018)) {
            cdp_config_param_type val = {0};

            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                              pdev_id, CDP_FILTER_UCAST_DATA, val);
            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                              pdev_id, CDP_FILTER_MCAST_DATA, val);
            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                            pdev_id,CDP_FILTER_NO_DATA, val);
        }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if ((target_type != TARGET_TYPE_QCA8074) &&
            (target_type != TARGET_TYPE_QCA8074V2) &&
            (target_type != TARGET_TYPE_QCN9000) &&
            (target_type != TARGET_TYPE_QCN6122) &&
            (target_type != TARGET_TYPE_QCA5018) &&
            (target_type != TARGET_TYPE_QCA6018)) {
            qdf_info("nss-wifi: update radio nss context with soc context for legay radio");
            scn->nss_radio.nss_rctx = soc->nss_soc.nss_sctx;
            scn->nss_radio.nss_rifnum = soc->nss_soc.nss_sifnum;
            scn->nss_radio.nss_idx = soc->nss_soc.nss_sidx;
        }
#endif
        /*
         * Enable Bursting by default for pre-ES2 release only. Tobe removed Later
         */
        {
            int ac, duration, retval;
            ac = 0, retval = 0;
            duration = AGGR_BURST_DURATION;
            qdf_info("BURSTING enabled by default");
            for (ac = 0; ac <= 3; ac++) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                            wmi_pdev_param_aggr_burst,
                            (ac & AGGR_BURST_AC_MASK) << AGGR_BURST_AC_OFFSET |
                             (AGGR_BURST_DURATION_MASK & duration));
            }
            if (EOK == retval)
                 scn->aggr_burst_dur[0] = duration;

            ol_ath_pdev_set_param(scn->sc_pdev,
                                  wmi_pdev_param_set_ppdu_duration_cmdid,
                                  AGGR_PPDU_DURATION);
        }

        ol_ath_twt_enable_command(scn);
        /* Enable beacon bursting by default */
        retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                       wmi_pdev_param_beacon_tx_mode,
                                       scn->bcn_mode);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        SET_MODULE_OWNER(pdev_netdev);
#endif

        /* Don't leave arp type as ARPHRD_ETHER as this is no eth device */
        pdev_netdev->type = ARPHRD_IEEE80211;

#if PERF_FIND_WDS_NODE
        wds_table_init(&scn->scn_wds_table);
#endif

        ic->ic_num_clients = ol_ath_get_num_clients(ic->ic_pdev_obj);

#if WLAN_SPECTRAL_ENABLE
        spectral_register_dbr(ic->ic_pdev_obj);
#endif /* WLAN_SPECTRAL_ENABLE */

#if WLAN_CFR_ENABLE
    /* pdev init to be done on Target Start */
        cfr_initialize_pdev(ic->ic_pdev_obj);
#endif
        ol_ath_mgmt_attach(ic);
#if  ATH_DATA_TX_INFO_EN
        ol_ath_stats_attach(ic);
#endif

#if OBSS_PD
        /* Init Spatial Reuse */
        ol_ath_pdev_sr_init(scn);
#endif

#ifdef QCA_SUPPORT_CP_STATS
        if (pdev_cp_stats_ap_stats_tx_cal_enable_get(ic->ic_pdev_obj)) {
            scn->sc_ic.ic_ath_enable_ap_stats(&scn->sc_ic, 1);
            pdev_cp_stats_ap_stats_tx_cal_enable_update(ic->ic_pdev_obj, 0);
        }
#endif
	ol_ath_set_protocol_tagging(ic->ic_pdev_obj, RX_PKT_TAG_OPCODE_ADD,
			            RECV_PKT_TYPE_EAP, 3232);
        /*Enable M_COPY after recovery if it was enabled before recovery*/
        if ((ol_ath_is_mcopy_enabled(ic)) &&
            soc->recovery_in_progress) {
            sniffer_mode = ic->ic_debug_sniffer;
            ic->ic_debug_sniffer = 0;
            ol_ath_set_debug_sniffer(scn, sniffer_mode);
            ol_ath_pdev_set_param(scn->sc_pdev,
                                  wmi_pdev_param_set_promisc_mode_cmdid, 1);
        }
        ieee80211com_set_cap(ic, IEEE80211_C_WEP);
        ieee80211com_set_cap(ic, IEEE80211_C_AES);
        ieee80211com_set_cap(ic, IEEE80211_C_AES_CCM);
        ieee80211com_set_cap(ic, IEEE80211_C_CKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIPMIC);

#if ATH_SUPPORT_WAPI
        ieee80211com_set_cap(ic, IEEE80211_C_WAPI);
#endif

        wlan_scan_update_channel_list(ic);

        /* Initialize tx packet capture feature flag */
        ic->ic_tx_pkt_capture = 0;
#ifdef ATH_SUPPORT_WAPI
        if ((target_type == TARGET_TYPE_QCA9984)
            || (target_type == TARGET_TYPE_QCA9888)
            || (target_type == TARGET_TYPE_IPQ4019)) {
            A_UINT8 bit_loc;
            ATH_VAP_ID_BIT_LOC(bit_loc);
            qdf_info("WAPI MBSSID %d", bit_loc);
            ol_ath_pdev_set_param(scn->sc_pdev,
                                  wmi_pdev_param_wapi_mbssid_offset, bit_loc);
        }
#endif
        if (ol_ath_thermal_mitigation_attach(scn, scn->netdev)) {
            wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_NB_ID);
            goto fail;
        }

#if OL_ATH_SUPPORT_LED
        if (!bypasswmi) {
#if QCA_LTEU_SUPPORT
          if (wlan_psoc_nif_feat_cap_get(soc->psoc_obj, WLAN_SOC_F_LTEU_SUPPORT)) {
              tgt_gpio_config(psoc, scn->scn_led_gpio, 1, WMI_HOST_GPIO_PULL_DOWN, WMI_HOST_GPIO_INTMODE_RISING_EDGE, 0, 0, 0);
          } else {
#endif /* QCA_LTEU_SUPPORT */

              ol_ath_led_init(soc, scn, target_type);
#if QCA_LTEU_SUPPORT
          }
#endif /* QCA_LTEU_SUPPORT */
        }
#endif /* OL_ATH_SUPPORT_LED */
        wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_NB_ID);

        ol_ath_update_chainmask(ic, target_cap, &mac_phy_cap[pdev_idx]);
        ol_ath_pdev_dfs_phyerr_offload_en(scn->sc_pdev);
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
        ic->ic_rebuilt_chanlist = 0;
        dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
        if (dfs_rx_ops) {
            if(dfs_rx_ops->dfs_reset_spoof_test)
                dfs_rx_ops->dfs_reset_spoof_test(scn->sc_pdev);
        }
#endif /* HOST_DFS_SPOOF_TEST */

#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(WLAN_DFS_SYNTHETIC_RADAR)
        dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
        if (dfs_rx_ops && dfs_rx_ops->dfs_allow_hw_pulses)
                dfs_rx_ops->dfs_allow_hw_pulses(scn->sc_pdev, true);
#endif /* WLAN_DFS_PARTIAL_OFFLOAD && WLAN_DFS_SYNTHETIC_RADAR*/

#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
        /* Resetting the scan violation status on FW restart. */
        ic->ic_is_dfs_scan_violation = false;
#endif

#ifdef OL_ATH_SMART_LOGGING
        {
            struct wmi_unified *wmi_handle;

            wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);
            if (wmi_service_enabled(wmi_handle,
                                    wmi_service_smart_logging_support)) {
                void *dbglog_handle = target_psoc_get_dbglog_hdl(tgt_hdl);

                if (dbglog_handle && !ic->smart_logging)
                    fwdbg_smartlog_init(dbglog_handle, ic);
            }
	}
#endif /* OL_ATH_SMART_LOGGING */

        if (lmac_is_target_ar900b(soc->psoc_obj)) {
           /* HIF subscribe */
#ifndef REMOVE_PKT_LOG
           if (soc->ol_if_ops->hif_pktlog_subscribe) {
		if (soc->ol_if_ops->hif_pktlog_subscribe(scn) != QDF_STATUS_SUCCESS) {
		    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
				QDF_TRACE_LEVEL_INFO,
				"Unable to subscribe to the HIF %s\n",__FUNCTION__);
		}
           }
#endif
        }
        ol_ath_configure_cong_ctrl_max_msdus(scn);

#if DBDC_REPEATER_SUPPORT
	/*
	 * the below parameters are also set in pdev_attach for wifi load
	 * and here for wifi up
	 */
	dp_lag_pdev_set_priority(ic->ic_pdev_obj, ic->ic_radio_priority);
	dp_lag_pdev_set_primary_radio(ic->ic_pdev_obj, ic->ic_primary_radio);
#endif
        ol_ath_pdev_set_burst(scn, true);
    } /* for loop */

    ol_ath_diag_user_agent_init(soc);

    if (soc->hw_mode_ctx.dynamic_hw_mode == WMI_HOST_DYNAMIC_HW_MODE_FAST) {
        /* Setup hw mode switch context */
        ol_ath_hw_mode_setup_ctx(soc);
    } else {
        /* check and reconfigure HW mode to target mode */
        soc->hw_mode_ctx.is_boot_in_progress = true;
        ol_ath_check_and_reconfig_hw_mode(soc);
        soc->hw_mode_ctx.is_boot_in_progress = false;
    }

    soc->down_complete = false;
    soc->soc_attached = 1;
    return 0;

fail:
   qdf_assert_always(0);
   hif_disable_isr(hif_hdl);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
   if (soc->nss_soc.ops) {
       qdf_info("nss-wifi: detach - zero delay");
       soc->nss_soc.ops->nss_soc_wifi_detach(soc, 0);
   }
#endif

    /* Unlikely case.
     * Flush pending pci_reconnect_work
     */
    qdf_flush_work(&soc->pci_reconnect_work);
    ol_ath_disconnect_htc(soc);
    ol_ath_target_deinit(soc, 1);
    ol_ath_target_deinit_complete(soc);
    if((target_type !=  TARGET_TYPE_IPQ4019) &&
       (target_type != TARGET_TYPE_QCA8074) &&
       (target_type != TARGET_TYPE_QCA8074V2) &&
       (target_type != TARGET_TYPE_QCN9000) &&
       (target_type != TARGET_TYPE_QCN6122) &&
       (target_type != TARGET_TYPE_QCA5018) &&
       (target_type != TARGET_TYPE_QCA6018)) {
        pci_set_drvdata(pcidev, soc->sc_osdev->netdev);
    }

    init_deinit_free_num_units(soc->psoc_obj, tgt_hdl);
    target_psoc_set_wmi_ready(tgt_hdl, FALSE);
    target_psoc_set_wmi_service_ready(tgt_hdl, FALSE);
    wlan_psoc_nif_op_flag_clear(psoc, WLAN_SOC_OP_VHT_INVALID_CAP);
    soc->down_complete = true;
    return -1;
}

/* Load the firmware and enable interrupts during the first vap creation
 * or before sending any WMI command to the target.
 */
extern const struct of_device_id ath_wifi_of_match[];
#define IPQ4019_DEVICE_ID (0x12ef)
int ol_ath_target_start(struct ol_ath_soc_softc *soc)
{
    struct platform_device *pdev;
    int ret;
#ifdef CONFIG_CNSS2_SUPPORT
    void *subhandle = NULL;
    struct pci_dev *pcidev = NULL;
    int target_type = lmac_get_tgt_type(soc->psoc_obj);
#endif

    pdev = (struct platform_device *)soc->sc_osdev->bdev;

    if (qdf_atomic_test_and_set_bit(SOC_RESET_IN_PROGRESS_BIT,
                                    &soc->reset_in_progress)) {
        qdf_info("Reset in progress, return");
        return -EBUSY;
    }

    if (!(soc->down_complete)) {
        /*
         * Target has already been started, return success.
         */
        ret = 0;
        goto out;
    }

#ifdef CONFIG_CNSS2_SUPPORT
    if ((target_type == TARGET_TYPE_QCA8074) ||
        (target_type == TARGET_TYPE_QCA8074V2) ||
        (target_type == TARGET_TYPE_QCA6018) ||
        (target_type == TARGET_TYPE_QCA5018) ||
        (target_type == TARGET_TYPE_QCN6122) ||
        (target_type == TARGET_TYPE_QCN9000)) {
        if ((target_type == TARGET_TYPE_QCA8074) ||
                (target_type == TARGET_TYPE_QCA8074V2) ||
                (target_type == TARGET_TYPE_QCN6122) ||
                (target_type == TARGET_TYPE_QCA5018) ||
                (target_type == TARGET_TYPE_QCA6018)) {
            subhandle = pld_subsystem_get(&pdev->dev, soc->device_id);
        }

        if(target_type == TARGET_TYPE_QCN9000) {
            /* this pcidev would have got removed during subsystem put */
            pcidev = (struct pci_dev *) pdev;
            subhandle = pld_subsystem_get(&pcidev->dev, soc->device_id);
        }
        if(IS_ERR_OR_NULL(subhandle)) {
            qdf_err("subsystem get error %d",IS_ERR_OR_NULL(subhandle));
            subhandle = NULL;
            ret = -EINVAL;
            goto out;
        } else {
            qdf_info("subsystem_get success");
        }
    }
#endif //CONFIG_CNSS2_SUPPORT

    ret = ol_ath_soc_start(soc);

out:
    qdf_atomic_clear_bit(SOC_RESET_IN_PROGRESS_BIT, &soc->reset_in_progress);
    return ret;
}
qdf_export_symbol(ol_ath_target_start);

int
ol_ath_resume(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com     *ic;

    ic = &scn->sc_ic;
    /*
     * ignore if already resumed.
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 0, 1) == 1) {
    return 0;
    }
    ieee80211_stop_running(ic);

    ieee80211_start_running(ic);

    return 0;
}

int
ol_ath_suspend(struct ol_ath_softc_net80211 *scn)
{
    /*
     * ignore if already suspended;
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 1, 0) == 0) {
        return 0;
    }

    ieee80211_stop_running(&scn->sc_ic);

    return 0;
}

void
ol_ath_target_status_update(ol_ath_soc_softc_t *soc, ol_target_status status)
{
    /* target lost, host needs to recover/reattach */
    soc->target_status = status;
}

void
ol_ath_suspend_resume_attach(struct ol_ath_softc_net80211 *scn)
{
}


int
ol_ath_suspend_target(ol_ath_soc_softc_t *soc, int disable_target_intr)
{
    struct pdev_op_args oper;

    oper.pointer = (void *)&disable_target_intr;
    oper.type = PDEV_ITER_SEND_SUSPEND;
    wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
             wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);

    return 0;
}

int
ol_ath_resume_target(ol_ath_soc_softc_t *soc)
{
    struct pdev_op_args oper;

    oper.type = PDEV_ITER_SEND_RESUME;
    wlan_objmgr_iterate_obj_list(soc->psoc_obj, WLAN_PDEV_OP,
             wlan_pdev_operation, &oper, 0, WLAN_MLME_NB_ID);

    return oper.ret_val;
}

/*
 * reg_xxx - All the variables are contents of the corresponding
 *  		register contents
 * xxx_delta - computed difference between previous cycle and c
 * 		    current cycle
 * reg_xxx_cu	- Computed channel utillization in %,
 *  		computed through register statistics
 *
 * FIXME ideally OL and non-OL layers can re-use the same code.
 * But this is done differently between OL and non-OL paths.
 * We may need to rework this completely for both to work with single
 * piece of code. The non-OL path also need lot of rework. All
 * stats need to be taken to UMAC layer. That seems to be too
 * much of work to do at this point of time. Right now host code
 * is limited to one below function, and this function alone
 * need to go UMAC. Given that function is small, tend to keep
 * only here here. If this gets any bigger we shall try doing it
 * in umac, and merge entire code ( ol and non-ol to umac ).
 */
void
ol_ath_wlan_interference_handler(struct ol_ath_softc_net80211 * scn,
                                 wmi_host_dcs_im_tgt_stats_t *curr_stats,
                                 uint32_t interference_type)
{
	wmi_host_dcs_im_tgt_stats_t *prev_stats;

	u_int32_t reg_tsf_delta = 0;                /* prev-tsf32  - curr-tsf32 */
	u_int32_t rxclr_delta = 0;                  /* prev-RXCLR - curr-RXCLR */
	u_int32_t rxclr_ext_delta = 0;              /* prev-RXEXTCLR - curreent RXEXTCLR, most of the time this is zero, chip issue ?? */
	u_int32_t cycle_count_delta = 0;            /* prev CCYCLE - curr CCYCLE */
	u_int32_t tx_frame_delta = 0;               /* prev TFCT - curr TFCNT */
	u_int32_t rx_frame_delta = 0;               /* prev RFCNT - curr RFCNT */
	u_int32_t reg_total_cu = 0; 				/* total channel utilization in %*/
	u_int32_t reg_tx_cu = 0;					/* transmit channel utilization in %*/
    u_int32_t reg_rx_cu = 0;					/* receive channel utilization in %*/
	u_int32_t reg_unused_cu = 0;                /* unused channel utillization */
	u_int32_t rx_time_cu=0;						/* computed rx time*/
	u_int32_t reg_ofdm_phyerr_delta = 0;		/* delta ofdm errors */
	u_int32_t reg_cck_phyerr_delta = 0;			/* delta cck errors*/
	u_int32_t reg_ofdm_phyerr_cu = 0;			/* amount utilization by ofdm errors*/
	u_int32_t ofdm_phy_err_rate = 0;			/* rate at which ofdm errors are seen*/
	u_int32_t cck_phy_err_rate=0;				/* rate at which cck errors are seen*/
	u_int32_t max_phy_err_rate = 0;
    u_int32_t max_phy_err_count = 0;
	u_int32_t total_wasted_cu = 0;
	u_int32_t wasted_tx_cu = 0;
	u_int32_t tx_err = 0;
	int too_many_phy_errors = 0;

	if (!scn || !curr_stats) {
		qdf_info("DCS: scn is NULL");
		return;
	}
    prev_stats =  &scn->scn_dcs.scn_dcs_im_stats.prev_dcs_im_stats;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        wlan_dcs_im_print_stats(prev_stats, curr_stats);
    }

    /* counters would have wrapped. Ideally we should be able to figure this
     * out, but we never know how many times counters wrapped. just ignore
     */
	if ((curr_stats->mib_stats.listen_time <= 0) ||
        (curr_stats->reg_tsf32 <= prev_stats->reg_tsf32)) {

		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
            qdf_info("DCS: ignoring due to negative TSF value");
        }
        /* copy the current stats to previous stats for next run */
		wlan_dcs_im_copy_stats(prev_stats, curr_stats);
		return;
	}

	reg_tsf_delta = curr_stats->reg_tsf32 - prev_stats->reg_tsf32;

	/* do nothing if current stats are not seeming good, probably
	 * a reset happened on chip, force cleared
	 */
	if (prev_stats->mib_stats.reg_rxclr_cnt > curr_stats->mib_stats.reg_rxclr_cnt) {
		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
            qdf_info("DCS: ignoring due to negative rxclr count");
        }

        /* copy the current stats to previous stats for next run */
		wlan_dcs_im_copy_stats(prev_stats, curr_stats);
		return;
	}

	rxclr_delta = curr_stats->mib_stats.reg_rxclr_cnt - prev_stats->mib_stats.reg_rxclr_cnt;
	rxclr_ext_delta = curr_stats->mib_stats.reg_rxclr_ext_cnt -
								prev_stats->mib_stats.reg_rxclr_ext_cnt;
	tx_frame_delta = curr_stats->mib_stats.reg_tx_frame_cnt -
								prev_stats->mib_stats.reg_tx_frame_cnt;

	rx_frame_delta = curr_stats->mib_stats.reg_rx_frame_cnt -
								prev_stats->mib_stats.reg_rx_frame_cnt;

	cycle_count_delta = curr_stats->mib_stats.reg_cycle_cnt -
								prev_stats->mib_stats.reg_cycle_cnt;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        qdf_info(",rxclr_delta,%u,rxclr_ext_delta,%u,tx_frame_delta,%u,rx_frame_delta,%u,cycle_count_delta,%u",
                rxclr_delta , rxclr_ext_delta , tx_frame_delta,
                rx_frame_delta , cycle_count_delta );
    }

    if(0 == (cycle_count_delta >>8)) {
        wlan_dcs_im_copy_stats(prev_stats, curr_stats);
        if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE))
            qdf_info(" cycle count NULL---Investigate--");
        return;
    }

	/* total channel utiliztaion is the amount of time RXCLR is
	 * counted. RXCLR is counted, when 'RX is NOT clear', please
	 * refer to mac documentation. It means either TX or RX is ON
     *
     * Why shift by 8 ? after multiplication it could overflow. At one
     * second rate, neither cycle_count_celta, nor the tsf_delta would be
     * zero after shift by 8 bits
	 */
	reg_total_cu = ((rxclr_delta >> 8) * 100) / (cycle_count_delta >>8);
	reg_tx_cu = ((tx_frame_delta >> 8 ) * 100) / (cycle_count_delta >> 8);
	reg_rx_cu = ((rx_frame_delta >> 8 ) * 100) / (cycle_count_delta >> 8);
	rx_time_cu = ((curr_stats->rx_time >> 8) * 100 ) / (reg_tsf_delta >> 8);

    /**
     * Amount of the time AP received cannot go higher than the receive
     * cycle count delta. If at all it is, there should have been a
     * compution error, ceil it to receive_cycle_count_diff
     */
	if (rx_time_cu > reg_rx_cu) {
		rx_time_cu = reg_rx_cu;
	}

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        qdf_info(",reg_total_cu,%u,reg_tx_cu,%u,reg_rx_cu,%u,rx_time_cu,%u",
                    reg_total_cu, reg_tx_cu, reg_rx_cu, rx_time_cu);
    }

	/* Unusable channel utilization is amount of time that we
	 * spent in backoff or waiting for other transmit/receive to
	 * complete. If there is interference it is more likely that
	 * we overshoot the limit. In case of multiple stations, we
	 * still see increased channel utilization.  This assumption may
	 * not be true for the VOW scenario where either multicast or
	 * unicast-UDP is used ( mixed traffic would still cause high
	 * channel utilization).
     */
	wasted_tx_cu = ((curr_stats->tx_waste_time >> 8) * 100 ) / (reg_tsf_delta >> 8);

    /**
     * transmit channel utilization cannot go higher than the amount of time
     * wasted, if so cap the wastage to transmit channel utillzation. This
     * could happen to compution error.
     */
	if (reg_tx_cu < wasted_tx_cu) {
		wasted_tx_cu = reg_tx_cu;
	}

	tx_err = (reg_tx_cu  && wasted_tx_cu) ? (wasted_tx_cu * 100 )/reg_tx_cu : 0;

    /**
     * The below actually gives amount of time we are not using, or the
     * interferer is active.
     * rx_time_cu is what computed receive time *NOT* rx_cycle_count
     * rx_cycle_count is our receive+interferer's transmit
     * un-used is really total_cycle_counts -
     *      (our_rx_time(rx_time_cu)+ our_receive_time)
     */
	reg_unused_cu = (reg_total_cu >= (reg_tx_cu + rx_time_cu)) ?
							(reg_total_cu - (reg_tx_cu + rx_time_cu)) : 0;

    /* if any retransmissions are there, count them as wastage
     */
	total_wasted_cu = reg_unused_cu + wasted_tx_cu;

	/* check ofdm and cck errors */
    if (unlikely(curr_stats->mib_stats.reg_ofdm_phyerr_cnt  <
            prev_stats->mib_stats.reg_ofdm_phyerr_cnt)) {
        reg_ofdm_phyerr_delta = curr_stats->mib_stats.reg_ofdm_phyerr_cnt ;
    } else {
        reg_ofdm_phyerr_delta = curr_stats->mib_stats.reg_ofdm_phyerr_cnt -
                                    prev_stats->mib_stats.reg_ofdm_phyerr_cnt;
    }

	if (unlikely(curr_stats->mib_stats.reg_cck_phyerr_cnt  <
            prev_stats->mib_stats.reg_cck_phyerr_cnt)) {
        reg_cck_phyerr_delta = curr_stats->mib_stats.reg_cck_phyerr_cnt;
    } else {
        reg_cck_phyerr_delta = curr_stats->mib_stats.reg_cck_phyerr_cnt -
                                    prev_stats->mib_stats.reg_cck_phyerr_cnt;
    }

	/* add the influence of ofdm phy errors to the wasted channel
	 * utillization, this computed through time wasted in errors,
	 */
	reg_ofdm_phyerr_cu = reg_ofdm_phyerr_delta * scn->scn_dcs.phy_err_penalty ;
	total_wasted_cu += (reg_ofdm_phyerr_cu > 0) ?  (((reg_ofdm_phyerr_cu >> 8) * 100) / (reg_tsf_delta >> 8)) : 0;

	ofdm_phy_err_rate = (curr_stats->mib_stats.reg_ofdm_phyerr_cnt * 1000) /
                                curr_stats->mib_stats.listen_time;
	cck_phy_err_rate = (curr_stats->mib_stats.reg_cck_phyerr_cnt * 1000) /
                                curr_stats->mib_stats.listen_time;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        qdf_info(",reg_unused_cu,%u,reg_ofdm_phyerr_delta,%u,reg_cck_phyerr_delta,%u,reg_ofdm_phyerr_cu,%u",
                    reg_unused_cu , reg_ofdm_phyerr_delta , reg_cck_phyerr_delta , reg_ofdm_phyerr_cu);
        qdf_info(",total_wasted_cu,%u,ofdm_phy_err_rate,%u,cck_phy_err_rate,%u",
                    total_wasted_cu , ofdm_phy_err_rate , cck_phy_err_rate );
        qdf_info(",new_unused_cu,%u,reg_ofdm_phy_error_cu,%u",
                reg_unused_cu, (curr_stats->mib_stats.reg_ofdm_phyerr_cnt*100)/
                                        curr_stats->mib_stats.listen_time);
    }

	/* check if the error rates are higher than the thresholds*/
	max_phy_err_rate = MAX(ofdm_phy_err_rate, cck_phy_err_rate);

	max_phy_err_count = MAX(curr_stats->mib_stats.reg_ofdm_phyerr_cnt,
                                curr_stats->mib_stats.reg_cck_phyerr_cnt);

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        qdf_info(",max_phy_err_rate,%u, max_phy_err_count,%u",max_phy_err_rate , max_phy_err_count);
    }

	if (((max_phy_err_rate >= scn->scn_dcs.phy_err_threshold) &&
				(max_phy_err_count > scn->scn_dcs.phy_err_threshold)) ||
         (curr_stats->phyerr_cnt > scn->scn_dcs.radar_err_threshold)) {
		too_many_phy_errors = 1;
	}

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
		qdf_info("\nDCS: total_cu %u ,tx_cu %u ,rx_cu %u ,rx_time_cu %u, unused cu %u ",reg_total_cu, reg_tx_cu, reg_rx_cu, rx_time_cu, reg_unused_cu);
                qdf_info("\nDCS: phyerr %u ,total_wasted_cu %u ,phyerror_cu %u ,wasted_cu %u, reg_tx_cu %u ,reg_rx_cu %u",too_many_phy_errors, total_wasted_cu, reg_ofdm_phyerr_cu, wasted_tx_cu, reg_tx_cu, reg_rx_cu);
                qdf_info("\nDCS: tx_err %u",tx_err);
	}

	if (reg_unused_cu >= scn->scn_dcs.coch_intr_thresh) {
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt+=2; /* quickly reach to decision*/
	} else if (too_many_phy_errors &&
			   (((total_wasted_cu > (scn->scn_dcs.coch_intr_thresh+10)) &&
					((reg_tx_cu + reg_rx_cu) > scn->scn_dcs.user_max_cu)) ||
                            ((reg_tx_cu > DCS_TX_MAX_CU) && (tx_err >= scn->scn_dcs.tx_err_thresh)) )){
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt++;
	}

	if (scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt >= scn->scn_dcs.intr_detection_threshold) {

        if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
            qdf_info("interference threshould exceeded");
            qdf_info(",unused_cu,%u,too_any_phy_errors,%u,total_wasted_cu,%u,reg_tx_cu,%u,reg_rx_cu,%u\n",
                    reg_unused_cu, too_many_phy_errors, total_wasted_cu,reg_tx_cu, reg_rx_cu);
        }

		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
		scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
        /* once the interference is detected, change the channel, as on
         * today this is common routine for wirelesslan and non-wirelesslan
         * interference. Name as such kept the same because of the DA code,
         * which is using the same function.
         */
		ol_ath_dcs_generic_interference_handler(scn, NULL, interference_type);
	} else if (!scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt ||
				scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt >= scn->scn_dcs.intr_detection_window) {
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
		scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
	}

	/* count the current run too*/
	scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt++;

    /* copy the stats for next cycle */
	wlan_dcs_im_copy_stats(prev_stats, curr_stats);

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        qdf_info(",intr_count,%u,sample_count,%d",
                 scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt,
                 scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt);
    }
}

int
ol_ath_periodic_chan_stats_config (struct ol_ath_softc_net80211 * scn,
                                        bool enable,
                                        u_int32_t stats_period)
{
	struct periodic_chan_stats_params param;
	struct wmi_unified *pdev_wmi_handle;

	if (!scn || !(scn->periodic_chan_stats)) {
		return -EINVAL;
	}

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
	if (!pdev_wmi_handle)
		return -EINVAL;

	qdf_mem_set(&param, sizeof(param), 0);
  	param.stats_period = stats_period;
  	param.enable = enable;
	param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);
  	return wmi_unified_send_periodic_chan_stats_config_cmd(pdev_wmi_handle,&param);
}

int
ol_ath_pdev_ctl_failsafe_check_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_host_pdev_ctl_failsafe_event ctl_failsafe = {0};
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("null wmi_handle");
        return -EINVAL;
    }

    if (wmi_extract_ctl_failsafe_check_ev_param(wmi_handle, data, &ctl_failsafe)) {
        return -1;
    }

    if (ctl_failsafe.ctl_failsafe_status != 0)
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
        "%s: CTL FAILSAFE Algorithm invoked when computing CTL table",__func__);

    return 0;
}

int
ol_ath_pdev_caldata_version_check_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_pdev_check_cal_version_event cal, *calInfo = &cal;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_pdev_caldata_version_check_ev_param(wmi_handle, data, calInfo)) {
        return -1;
    }

    qdf_info("****************** CAl DATA Version Details ********************");
    if (calInfo->cal_ok != WMI_HOST_NO_FEATURE){
        qdf_info("Current Meta Cal Version               : 0x%x ",
                                              calInfo->software_cal_version);

        qdf_info("Board (MCN : %s) Cal Version           : 0x%x ",
                       calInfo->board_mcn_detail, calInfo->board_cal_version);

        if (calInfo->cal_ok == WMI_HOST_CALIBRATION_OK){
            qdf_info("Calibration Status: OK ");
        } else { /* calInfo->cal_ok  CALIBRATION_NOT_OK */
            qdf_info("Calibration Status: NOT OK ");
        }
        qdf_info("Note: Please cross check board's MCN ");
    } else {
        qdf_info("Board was not calibrated with this feature ");
    }

    return 0;
}

int
ol_ath_cp_fwstats_event_handler (ol_soc_t sc, u_int8_t *evt_buf, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t more_flag = 0;
    struct wmi_unified *wmi_handle;
    struct ieee80211com *ic = NULL;
    struct wmi_raw_event_buffer *raw_buf;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    raw_buf = (struct wmi_raw_event_buffer *)evt_buf;
    if (wmi_unified_extract_cp_stats_more_pending(wmi_handle, raw_buf->evt_processed_buf, &more_flag) !=
                                    QDF_STATUS_SUCCESS) {
            qdf_err("Unable to extract cp_fwstats event");
            return -1;
    }
    ic = soc->cp_stats_ic;
    if (!ic) {
        qdf_err("ic is NULL \n");
        return -1;
    }
#if UMAC_SUPPORT_CFG80211
    wlan_cfg80211_wifi_fwstats_event(ic, raw_buf->evt_raw_buf, datalen);
#endif
    if (!more_flag)
        soc->cp_stats_ic = NULL;
    return 0;
}

int
ol_ath_vdev_tsf_report_event_handler(ol_soc_t sc, u_int8_t *data,
                                     u_int32_t datalen)
{
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_vdev *vdev;
    struct wmi_host_tsf_event param;
    wlan_if_t vap;

    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    psoc = soc->psoc_obj;

    wmi_handle = lmac_get_wmi_hdl(psoc);

    if (!wmi_handle) {
        qdf_err("wmi_handle is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    if (wmi_extract_vdev_tsf_report_event(wmi_handle, data, &param)) {
        qdf_err("Failed to extract vdev_tsf_report_event");
        return QDF_STATUS_E_FAILURE;
    }

    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, param.vdev_id,
            WLAN_DEBUG_ID);
    if (!vdev) {
        qdf_err("vdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_DEBUG_ID);
        return QDF_STATUS_E_FAILURE;
    }
    vap->iv_tsf = param.tsf;
    qdf_atomic_inc(&(vap->vap_tsf_event));
    wlan_objmgr_vdev_release_ref(vdev, WLAN_DEBUG_ID);

    return QDF_STATUS_SUCCESS;
}

int
ol_ath_pdev_tpc_config_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    if (soc->ol_if_ops->tpc_config_handler)  {
        soc->ol_if_ops->tpc_config_handler(sc, data, datalen);
    }

    return 0;
}

int ol_ath_packet_power_info_get(struct wlan_objmgr_pdev *pdev,
                                 struct packet_power_info_params *arg)
{
    struct packet_power_info_params param;
    struct wmi_unified *pdev_wmi_handle;
    QDF_STATUS status;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -1;

    qdf_mem_set(&param, sizeof(param), 0);
    param.chainmask = arg->chainmask;
    param.chan_width = arg->chan_width;
    param.rate_flags = arg->rate_flags;
    param.su_mu_ofdma = arg->su_mu_ofdma;
    param.nss = arg->nss;
    param.preamble = arg->preamble;
    param.hw_rate = arg->hw_rate;

    status = wmi_unified_packet_power_info_get_cmd_send(pdev_wmi_handle,
                                                        &param);
    return qdf_status_to_os_return(status);
}


int
ol_ath_btcoex_duty_cycle(ol_ath_soc_softc_t *soc, u_int32_t period, u_int32_t duration)
{
    struct btcoex_cfg_params param;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.period = period;
    param.wlan_duration = duration ;
    param.btcoex_param_flags = WMI_HOST_BTCOEX_PARAM_FLAGS_DUTY_CYCLE_BIT;
    return wmi_unified_send_btcoex_duty_cycle_cmd(wmi_handle, &param);
}

int
ol_ath_btcoex_wlan_priority(ol_ath_soc_softc_t *soc, u_int32_t wlan_priority)
{
    struct btcoex_cfg_params param;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.btcoex_wlan_priority_bitmap = wlan_priority;
    param.btcoex_param_flags = WMI_HOST_BTCOEX_PARAM_FLAGS_WLAN_PRIORITY_BITMAP_BIT;
    return wmi_unified_send_btcoex_wlan_priority_cmd(wmi_handle, &param);
}
int
ol_ath_gpio_input_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t gpio_num;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_gpio_input_ev_param(wmi_handle, data, &gpio_num)) {
        return -1;
    }
    qdf_info("GPIO Input Event on Num %d", gpio_num);

#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (!acfg_event)
        return 0;

    acfg_event->gpio_num = gpio_num;
    /*MULTI-RADIO TODO - is it SoC or we need pdev here?*/
    acfg_send_event(soc->sc_osdev->netdev, soc->sc_osdev, WL_EVENT_TYPE_GPIO_INPUT, acfg_event);
    qdf_mem_free(acfg_event);
#endif
    return 0;
}

#define MAX_NUM_CHAINS 8
int
ol_ath_nf_dbr_dbm_info_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    u_int32_t i, j;
    wmi_host_pdev_nfcal_power_all_channels_event event, *ev = &event;
#if UMAC_SUPPORT_ACFG
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_pdev *pdev;
    acfg_event_data_t *acfg_event = NULL;
#endif
    struct wmi_unified *wmi_handle;
    u_int8_t num_per_nfdbr_dbm;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_nfcal_power_ev_param(wmi_handle, data, ev)) {
        return -1;
    }

    if ((ev->num_freq == 0) || (ev->num_freq > WMI_HOST_RXG_CAL_CHAN_MAX) ||
        (ev->num_nfdbr_dbm > WMI_HOST_MAX_NUM_CHAINS * WMI_HOST_RXG_CAL_CHAN_MAX)) {
        return -1;
    }

    num_per_nfdbr_dbm = ev->num_nfdbr_dbm / ev->num_freq;
    qdf_info("nfdBr\tnfdBm num_freq %d num_nfdbr_dbm %d\n", ev->num_freq, num_per_nfdbr_dbm);
    for(j = 0; j < ev->num_freq; j++)
    {
        qdf_info("Freq=%d \n", ev->freqnum[j]);
        for(i = 0; i < num_per_nfdbr_dbm; i++) {
            qdf_info("%d\t%d\n",
                    (int8_t)ev->nfdbr[j*num_per_nfdbr_dbm+i],
                    (int8_t)ev->nfdbm[j*num_per_nfdbr_dbm+i]);
	}
    }
#if UMAC_SUPPORT_ACFG
    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(ev->pdev_id),
                                   WLAN_MLME_SB_ID);
    if (!pdev) {
         qdf_err("pdev object (id: %d) is NULL", PDEV_UNIT(ev->pdev_id));
         return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
         qdf_info("scn(id: %d) is NULL", PDEV_UNIT(ev->pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }


    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (!acfg_event) {
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return 0;
    }

    memcpy(acfg_event->nf_dbr_dbm.nfdbr, ev->nfdbr, sizeof((acfg_event->nf_dbr_dbm.nfdbr)));
    memcpy(acfg_event->nf_dbr_dbm.nfdbm, ev->nfdbm, sizeof(acfg_event->nf_dbr_dbm.nfdbm));
    memcpy(acfg_event->nf_dbr_dbm.freqNum, ev->freqnum, sizeof(acfg_event->nf_dbr_dbm.freqNum));
    acfg_send_event(scn->netdev, scn->sc_osdev, WL_EVENT_TYPE_NF_DBR_DBM_INFO, acfg_event);
    qdf_mem_free(acfg_event);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
#endif

    return 0;
}

#undef MAX_NUM_CHAINS

int
ol_ath_packet_power_info_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_pdev_tpc_event event, *ev = &event;
#if UMAC_SUPPORT_ACFG
    struct ol_ath_softc_net80211 *scn;
    struct wlan_objmgr_pdev *pdev;
    acfg_event_data_t *acfg_event = NULL;
#endif
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_pdev_tpc_ev_param(wmi_handle, data, ev)) {
        return -1;
    }
    qdf_info("Max packet power = %d, Min pkt power: %d",
            ev->tpc[WMI_HOST_TX_POWER_MAX], ev->tpc[WMI_HOST_TX_POWER_MIN]);
#if UMAC_SUPPORT_ACFG
    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(ev->pdev_id),
                                   WLAN_MLME_SB_ID);
    if (!pdev) {
         qdf_err("pdev object (id: %d) is NULL", PDEV_UNIT(ev->pdev_id));
         return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
         qdf_err("scn(id: %d) is NULL", PDEV_UNIT(ev->pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }

    acfg_event = (acfg_event_data_t *)qdf_mem_malloc_atomic(sizeof(acfg_event_data_t));
    if (!acfg_event) {
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return 0;
    }

    memcpy(&(acfg_event->packet_power), ev->tpc, sizeof(ev->tpc));
    acfg_send_event(scn->netdev, scn->sc_osdev, WL_EVENT_TYPE_PACKET_POWER_INFO, acfg_event);
    qdf_mem_free(acfg_event);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
#endif
    return 0;
}

int
ol_ath_generic_buffer_event_handler (ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_pdev_generic_buffer_event event, *ev = &event;
#ifdef BIG_ENDIAN_HOST
    u_int8_t i;
#endif
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_pdev_generic_buffer_ev_param(wmi_handle, data, ev)) {
        return -1;
    }
    qdf_info("Generic buffer received: type=%d len=%d frag_id=%d, more_frag=%d",
            ev->buf_type, ev->buf_len, ev->frag_id, ev->more_frag);

#ifdef BIG_ENDIAN_HOST
    {
        u_int32_t *destp, *srcp;
        u_int32_t len;

        srcp = &ev->buf_info[0];
        destp = &ev->buf_info[0];
        len = ev->buf_len;
        for(i=0; i < (roundup(len, sizeof(u_int32_t))/4); i++) {
            *destp = le32_to_cpu(*srcp);
            destp++; srcp++;
        }
    }
#endif

    if (ev->buf_type == WMI_HOST_BUFFER_TYPE_RATEPWR_TABLE) {
        ol_if_ratepwr_recv_buf((u_int8_t *)(&ev->buf_info[0]), ev->buf_len,
                                ev->frag_id, ev->more_frag);
    } else if (ev->buf_type == WMI_HOST_BUFFER_TYPE_CTL_TABLE) {
        /* TODO */
    }
    return 0;
}

int ol_ath_peer_mumimo_tx_count_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_peer_txmu_cnt_event event, *ev = &event;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_mumimo_tx_count_ev_param(wmi_handle, data, ev)) {
        return -1;
    }
    qdf_info("MUMIMO tx for this peer %u",ev->tx_mu_transmitted);
    return 0;
}

int ol_ath_peer_gid_userpos_list_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_peer_gid_userpos_list_event event, *ev = &event;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_peer_gid_userpos_list_ev_param(wmi_handle, data, ev)) {
        return -1;
    }
   qdf_info("User poistion list for GID 1->15:[%u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u]",
       ev->usr_list[0], ev->usr_list[1], ev->usr_list[2], ev->usr_list[3], ev->usr_list[4], ev->usr_list[5],
       ev->usr_list[6], ev->usr_list[7], ev->usr_list[8], ev->usr_list[9], ev->usr_list[10],ev->usr_list[11],
       ev->usr_list[12], ev->usr_list[13], ev->usr_list[14]);
   return 0;
}

u_int8_t ol_scn_vow_extstats(ol_pdev_handle pdev)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *) pdev;
    return scn->vow_extstats;
}
qdf_export_symbol(ol_scn_vow_extstats);

u_int32_t ol_scn_vow_get_rxstats(ol_pdev_handle pdev, u_int32_t *phy_err_count, u_int32_t *rx_clear_count, u_int32_t *rx_cycle_count)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    *phy_err_count = scn->chan_stats.phy_err_cnt;
    *rx_clear_count = scn->mib_cycle_cnts.rx_clear_count;
    *rx_cycle_count = scn->mib_cycle_cnts.cycle_count;
    return 0;
}
qdf_export_symbol(ol_scn_vow_get_rxstats);

uint32_t
ol_get_phymode_info(struct ol_ath_softc_net80211 *scn, uint32_t chan_mode,
                    bool is_2gvht_en) {
    /* We define a non-const modeflags array in order to enable stubbing based
     * simulation. Such simulation would involve an override of the host mode to
     * FW mode mapping.
     */
    static uint32_t modeflags[] = {
        0,                            /* IEEE80211_MODE_AUTO            */
        WMI_HOST_MODE_11A,            /* IEEE80211_MODE_11A             */
        WMI_HOST_MODE_11B,            /* IEEE80211_MODE_11B             */
        WMI_HOST_MODE_11G,            /* IEEE80211_MODE_11G             */
        0,                            /* IEEE80211_MODE_FH              */
        0,                            /* IEEE80211_MODE_TURBO_A         */
        0,                            /* IEEE80211_MODE_TURBO_G         */
        WMI_HOST_MODE_11NA_HT20,      /* IEEE80211_MODE_11NA_HT20       */
        WMI_HOST_MODE_11NG_HT20,      /* IEEE80211_MODE_11NG_HT20       */
        WMI_HOST_MODE_11NA_HT40,      /* IEEE80211_MODE_11NA_HT40PLUS   */
        WMI_HOST_MODE_11NA_HT40,      /* IEEE80211_MODE_11NA_HT40MINUS  */
        WMI_HOST_MODE_11NG_HT40,      /* IEEE80211_MODE_11NG_HT40PLUS   */
        WMI_HOST_MODE_11NG_HT40,      /* IEEE80211_MODE_11NG_HT40MINUS  */
        WMI_HOST_MODE_11NG_HT40,      /* IEEE80211_MODE_11NG_HT40       */
        WMI_HOST_MODE_11NA_HT40,      /* IEEE80211_MODE_11NA_HT40       */
        WMI_HOST_MODE_11AC_VHT20,     /* IEEE80211_MODE_11AC_VHT20      */
        WMI_HOST_MODE_11AC_VHT40,     /* IEEE80211_MODE_11AC_VHT40PLUS  */
        WMI_HOST_MODE_11AC_VHT40,     /* IEEE80211_MODE_11AC_VHT40MINUS */
        WMI_HOST_MODE_11AC_VHT40,     /* IEEE80211_MODE_11AC_VHT40      */
        WMI_HOST_MODE_11AC_VHT80,     /* IEEE80211_MODE_11AC_VHT80      */
        WMI_HOST_MODE_11AC_VHT160,    /* IEEE80211_MODE_11AC_VHT160     */
        WMI_HOST_MODE_11AC_VHT80_80,  /* IEEE80211_MODE_11AC_VHT80_80   */
        WMI_HOST_MODE_11AX_HE20,      /* IEEE80211_MODE_11AXA_HE20      */
        WMI_HOST_MODE_11AX_HE20_2G,   /* IEEE80211_MODE_11AXG_HE20      */
        WMI_HOST_MODE_11AX_HE40,      /* IEEE80211_MODE_11AXA_HE40PLUS  */
        WMI_HOST_MODE_11AX_HE40,      /* IEEE80211_MODE_11AXA_HE40MINUS */
        WMI_HOST_MODE_11AX_HE40_2G,   /* IEEE80211_MODE_11AXG_HE40PLUS  */
        WMI_HOST_MODE_11AX_HE40_2G,   /* IEEE80211_MODE_11AXG_HE40MINUS */
        WMI_HOST_MODE_11AX_HE40,      /* IEEE80211_MODE_11AXA_HE40      */
        WMI_HOST_MODE_11AX_HE40_2G,   /* IEEE80211_MODE_11AXG_HE40      */
        WMI_HOST_MODE_11AX_HE80,      /* IEEE80211_MODE_11AXA_HE80      */
        WMI_HOST_MODE_11AX_HE160,     /* IEEE80211_MODE_11AXA_HE160     */
        WMI_HOST_MODE_11AX_HE80_80,   /* IEEE80211_MODE_11AXA_HE80_80   */
    };
    uint32_t temp_phymode;
    enum wmi_target_type wmi_tgt_type;

    qdf_assert_always(NULL != scn);

#if QCA_11AX_STUB_SUPPORT
    if (1 == OL_ATH_IS_11AX_STUB_ENABLED(scn->soc)) {
        /* We re-map 802.11ax modes to equivalent 802.11n/ac modes. */
        modeflags[IEEE80211_MODE_11AXA_HE20] = WMI_HOST_MODE_11AC_VHT20;
        modeflags[IEEE80211_MODE_11AXG_HE20] = WMI_HOST_MODE_11NG_HT20;
        modeflags[IEEE80211_MODE_11AXA_HE40PLUS] = WMI_HOST_MODE_11AC_VHT40;
        modeflags[IEEE80211_MODE_11AXA_HE40MINUS] = WMI_HOST_MODE_11AC_VHT40;
        modeflags[IEEE80211_MODE_11AXG_HE40PLUS] = WMI_HOST_MODE_11NG_HT40;
        modeflags[IEEE80211_MODE_11AXG_HE40MINUS] = WMI_HOST_MODE_11NG_HT40;
        modeflags[IEEE80211_MODE_11AXA_HE40] = WMI_HOST_MODE_11AC_VHT40;
        modeflags[IEEE80211_MODE_11AXG_HE40] = WMI_HOST_MODE_11NG_HT40;
        modeflags[IEEE80211_MODE_11AXA_HE80] = WMI_HOST_MODE_11AC_VHT80;
        modeflags[IEEE80211_MODE_11AXA_HE160] = WMI_HOST_MODE_11AC_VHT160;
        modeflags[IEEE80211_MODE_11AXA_HE80_80] = WMI_HOST_MODE_11AC_VHT80_80;
    }
#endif /* QCA_11AX_STUB_SUPPORT */

    /* Assert if the chan mode is invalid */
    qdf_assert_always(chan_mode < IEEE80211_MODE_MAX);

    temp_phymode = modeflags[chan_mode];
    if (ol_ath_get_wmi_target_type(scn->soc, &wmi_tgt_type) != QDF_STATUS_SUCCESS) {
        qdf_info("Not able to get wmi target type");
        return temp_phymode;
    }

    if ((wmi_tgt_type == WMI_TLV_TARGET) && (is_2gvht_en == true)) {
        switch(chan_mode) {
            case IEEE80211_MODE_11NG_HT20:
                temp_phymode = WMI_HOST_MODE_11AC_VHT20_2G;
                break;

            case IEEE80211_MODE_11NG_HT40PLUS:
            case IEEE80211_MODE_11NG_HT40MINUS:
            case IEEE80211_MODE_11NG_HT40:
                temp_phymode = WMI_HOST_MODE_11AC_VHT40_2G;
                break;
        }
    }
    return temp_phymode;
}

uint32_t
ol_get_phymode_info_from_wlan_phymode(struct ol_ath_softc_net80211 *scn,
        uint32_t chan_mode,
        bool is_2gvht_en) {

    static uint32_t conv_phy_mode_to_wmi_phy_mode[] = {
        WMI_HOST_MODE_UNKNOWN,        /* WLAN_PHYMODE_AUTO            */
        WMI_HOST_MODE_11A,            /* WLAN_PHYMODE_11A             */
        WMI_HOST_MODE_11B,            /* WLAN_PHYMODE_11B             */
        WMI_HOST_MODE_11G,            /* WLAN_PHYMODE_11G             */
        WMI_HOST_MODE_11GONLY,        /* WLAN_PHYMODE_11G_ONLY        */
        WMI_HOST_MODE_11NA_HT20,      /* WLAN_PHYMODE_11NA_HT20       */
        WMI_HOST_MODE_11NG_HT20,      /* WLAN_PHYMODE_11NG_HT20       */
        WMI_HOST_MODE_11NA_HT40,      /* WLAN_PHYMODE_11NA_HT40       */
        WMI_HOST_MODE_11NG_HT40,      /* WLAN_PHYMODE_11NG_HT40PLUS   */
        WMI_HOST_MODE_11NG_HT40,      /* WLAN_PHYMODE_11NG_HT40MINUS  */
        WMI_HOST_MODE_11NG_HT40,      /* WLAN_PHYMODE_11NG_HT40       */
        WMI_HOST_MODE_11AC_VHT20,     /* WLAN_PHYMODE_11AC_VHT20      */
        WMI_HOST_MODE_11AC_VHT20_2G,  /* WLAN_PHYMODE_11AC_VHT20_2G   */
        WMI_HOST_MODE_11AC_VHT40,     /* WLAN_PHYMODE_11AC_VHT40      */
        WMI_HOST_MODE_11AC_VHT40_2G,  /* WLAN_PHYMODE_11AC_VHT40PLUS_2G  */
        WMI_HOST_MODE_11AC_VHT40_2G,  /* WLAN_PHYMODE_11AC_VHT40MINUS_2G */
        WMI_HOST_MODE_11AC_VHT40_2G,  /* WLAN_PHYMODE_11AC_VHT40_2G      */
        WMI_HOST_MODE_11AC_VHT80,     /* WLAN_PHYMODE_11AC_VHT80      */
        WMI_HOST_MODE_11AC_VHT80_2G,  /* WLAN_PHYMODE_11AC_VHT80_2G   */
        WMI_HOST_MODE_11AC_VHT160,    /* WLAN_PHYMODE_11AC_VHT160     */
        WMI_HOST_MODE_11AC_VHT80_80,  /* WLAN_PHYMODE_11AC_VHT80_80   */
        WMI_HOST_MODE_11AX_HE20,      /* WLAN_PHYMODE_11AXA_HE20      */
        WMI_HOST_MODE_11AX_HE20_2G,   /* WLAN_PHYMODE_11AXG_HE20      */
        WMI_HOST_MODE_11AX_HE40,      /* WLAN_PHYMODE_11AXA_HE40      */
        WMI_HOST_MODE_11AX_HE40_2G,   /* WLAN_PHYMODE_11AXG_HE40PLUS  */
        WMI_HOST_MODE_11AX_HE40_2G,   /* WLAN_PHYMODE_11AXG_HE40MINUS */
        WMI_HOST_MODE_11AX_HE40_2G,   /* WLAN_PHYMODE_11AXG_HE40      */
        WMI_HOST_MODE_11AX_HE80,      /* WLAN_PHYMODE_11AXA_HE80      */
        WMI_HOST_MODE_11AX_HE80,      /* WLAN_PHYMODE_11AXG_HE80      */
        WMI_HOST_MODE_11AX_HE160,     /* WLAN_PHYMODE_11AXA_HE160     */
        WMI_HOST_MODE_11AX_HE80_80,   /* WLAN_PHYMODE_11AXA_HE80_80   */
    };
    uint32_t temp_phymode;
    enum wmi_target_type wmi_tgt_type;

    qdf_assert_always(NULL != scn);

#if QCA_11AX_STUB_SUPPORT
    if (1 == OL_ATH_IS_11AX_STUB_ENABLED(scn->soc)) {
        /* We re-map 802.11ax modes to equivalent 802.11n/ac modes. */
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXA_HE20] = WMI_HOST_MODE_11AC_VHT20;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXG_HE20] = WMI_HOST_MODE_11NG_HT20;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXG_HE40PLUS] = WMI_HOST_MODE_11NG_HT40;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXG_HE40MINUS] = WMI_HOST_MODE_11NG_HT40;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXA_HE40] = WMI_HOST_MODE_11AC_VHT40;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXG_HE40] = WMI_HOST_MODE_11NG_HT40;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXA_HE80] = WMI_HOST_MODE_11AC_VHT80;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXA_HE160] = WMI_HOST_MODE_11AC_VHT160;
        conv_phy_mode_to_wmi_phy_mode[WLAN_PHYMODE_11AXA_HE80_80] = WMI_HOST_MODE_11AC_VHT80_80;
    }
#endif /* QCA_11AX_STUB_SUPPORT */

    if(chan_mode < WLAN_PHYMODE_11A || chan_mode > WLAN_PHYMODE_11AXA_HE80_80) {
        temp_phymode = WMI_HOST_MODE_UNKNOWN;
        return temp_phymode;
    }

    if (ol_ath_get_wmi_target_type(scn->soc, &wmi_tgt_type) != QDF_STATUS_SUCCESS) {
        qdf_print("Not able to get wmi target type");
        temp_phymode = WMI_HOST_MODE_UNKNOWN;
        return temp_phymode;
    }
    temp_phymode = conv_phy_mode_to_wmi_phy_mode[chan_mode];

    if ((wmi_tgt_type == WMI_TLV_TARGET) && (is_2gvht_en == true)) {
        switch(chan_mode) {
            case WLAN_PHYMODE_11NG_HT20:
                temp_phymode = WMI_HOST_MODE_11AC_VHT20_2G;
                break;

            case WLAN_PHYMODE_11NG_HT40PLUS:
            case WLAN_PHYMODE_11NG_HT40MINUS:
            case WLAN_PHYMODE_11NG_HT40:
                temp_phymode = WMI_HOST_MODE_11AC_VHT40_2G;
                break;
        }
    }
    return temp_phymode;
}

#define _HT_SGI_PRESENT 0x80

static inline
void set_rate_a(struct mon_rx_status *rx_status)
{
    switch (rx_status->mcs) {
    case CDP_LEGACY_MCS0:
	rx_status->rate = CDP_11A_RATE_0MCS;
	break;
    case CDP_LEGACY_MCS1:
	rx_status->rate = CDP_11A_RATE_1MCS;
	break;
    case CDP_LEGACY_MCS2:
	rx_status->rate = CDP_11A_RATE_2MCS;
	break;
    case CDP_LEGACY_MCS3:
	rx_status->rate = CDP_11A_RATE_3MCS;
	break;
    case CDP_LEGACY_MCS4:
	rx_status->rate = CDP_11A_RATE_4MCS;
	break;
    case CDP_LEGACY_MCS5:
	rx_status->rate = CDP_11A_RATE_5MCS;
	break;
    case CDP_LEGACY_MCS6:
	rx_status->rate = CDP_11A_RATE_6MCS;
	break;
    case CDP_LEGACY_MCS7:
	rx_status->rate = CDP_11A_RATE_7MCS;
	break;
    default:
	break;
    }
}

static inline
void set_rate_b(struct mon_rx_status *rx_status)
{
    switch (rx_status->mcs) {
    case CDP_LEGACY_MCS0:
	rx_status->rate = CDP_11B_RATE_0MCS;
	break;
    case CDP_LEGACY_MCS1:
	rx_status->rate = CDP_11B_RATE_1MCS;
	break;
    case CDP_LEGACY_MCS2:
	rx_status->rate = CDP_11B_RATE_2MCS;
	break;
    case CDP_LEGACY_MCS3:
	rx_status->rate = CDP_11B_RATE_3MCS;
	break;
    case CDP_LEGACY_MCS4:
	rx_status->rate = CDP_11B_RATE_4MCS;
	break;
    case CDP_LEGACY_MCS5:
	rx_status->rate = CDP_11B_RATE_5MCS;
	break;
    case CDP_LEGACY_MCS6:
	rx_status->rate = CDP_11B_RATE_6MCS;
	break;
    default:
	break;
    }
}

static inline
void radiotap_vht_setup(struct cdp_tx_indication_info *tx_info,
			struct mon_rx_status *rx_status)
{
    struct cdp_tx_completion_ppdu *ppdu_desc = tx_info->ppdu_desc;
    struct cdp_tx_completion_ppdu_user *user;
    uint8_t usr_idx;

    usr_idx = tx_info->mpdu_info.usr_idx;
    user = &ppdu_desc->user[usr_idx];

    rx_status->ldpc = user->ldpc;
    rx_status->vht_flag_values5 = user->mu_group_id;
    rx_status->is_stbc = user->stbc;
    rx_status->nss = user->nss + 1;

    rx_status->vht_flag_values3[0] = (((rx_status->mcs) << 4)
		                      | rx_status->nss);
    rx_status->vht_flag_values2 = rx_status->bw;
    rx_status->vht_flag_values4 = rx_status->ldpc; //ldpc same as su_mu_conding
    rx_status->beamformed = user->txbf ? 1 : 0;
}

static inline
void radiotap_he_setup(struct cdp_tx_indication_info *tx_info,
		    struct mon_rx_status *rx_status)
{
    struct cdp_tx_completion_ppdu *ppdu_desc = tx_info->ppdu_desc;
    struct cdp_tx_completion_ppdu_user *user;
    uint32_t value;
    uint8_t usr_idx = 0;
    usr_idx = tx_info->mpdu_info.usr_idx;
    user = &ppdu_desc->user[usr_idx];

    if(user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_SU) {
	rx_status->he_data1 = (user->he_re) ?
		QDF_MON_STATUS_HE_EXT_SU_FORMAT_TYPE :
		QDF_MON_STATUS_HE_SU_FORMAT_TYPE;
    } else if (user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_MU_MIMO ||
               user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_MU_OFDMA ||
	       user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_MU_MIMO_OFDMA) {
        rx_status->he_data1 = QDF_MON_STATUS_HE_MU_FORMAT_TYPE;
    } else if (user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_UL_TRIG) {
        rx_status->he_data1 = QDF_MON_STATUS_HE_TRIG_FORMAT_TYPE;
    }

    if(rx_status->he_data1 != QDF_MON_STATUS_HE_MU_FORMAT_TYPE) {
        /* radiotap he_data 1 */
        rx_status->he_data1 |= QDF_MON_STATUS_HE_BSS_COLOR_KNOWN |
		               QDF_MON_STATUS_HE_BEAM_CHANGE_KNOWN |
			       QDF_MON_STATUS_HE_DL_UL_KNOWN |
			       QDF_MON_STATUS_HE_MCS_KNOWN |
			       QDF_MON_STATUS_HE_DCM_KNOWN |
			       QDF_MON_STATUS_HE_CODING_KNOWN |
			       QDF_MON_STATUS_HE_STBC_KNOWN |
			       QDF_MON_STATUS_HE_DATA_BW_RU_KNOWN |
			       QDF_MON_STATUS_HE_DOPPLER_KNOWN;

        /* radiotap he_data 2 */
	rx_status->he_data2 = QDF_MON_STATUS_HE_GI_KNOWN;
        rx_status->he_data2 |=
		QDF_MON_STATUS_TXBF_KNOWN |
		QDF_MON_STATUS_LTF_SYMBOLS_KNOWN;
    } else {
        /* radiotap he_data 1 */
        rx_status->he_data1 |=
		QDF_MON_STATUS_HE_BSS_COLOR_KNOWN |
		QDF_MON_STATUS_HE_DL_UL_KNOWN |
		QDF_MON_STATUS_HE_MCS_KNOWN |
		QDF_MON_STATUS_HE_CODING_KNOWN |
		QDF_MON_STATUS_HE_STBC_KNOWN |
		QDF_MON_STATUS_HE_DATA_BW_RU_KNOWN |
		QDF_MON_STATUS_HE_DOPPLER_KNOWN;

        /* radiotap he_data 2 */
	rx_status->he_data2 = QDF_MON_STATUS_HE_GI_KNOWN;
	rx_status->he_data2 |= QDF_MON_STATUS_LTF_SYMBOLS_KNOWN;
    }

    /* radiotap he_data 3 */
    value = ppdu_desc->bss_color; // bss color host value
    rx_status->he_data3 = value;
    value = ppdu_desc->beam_change; // beam change fw value
    rx_status->he_data3 |= value << QDF_MON_STATUS_BEAM_CHANGE_SHIFT;
    value = 0; // UL/DL... DL value
    rx_status->he_data3 |= value << QDF_MON_STATUS_DL_UL_SHIFT;
    value = user->mcs; // mcs fw value
    rx_status->he_data3 |= value  << QDF_MON_STATUS_TRANSMIT_MCS_SHIFT;
    value = user->dcm; // dcm fw value
    rx_status->he_data3 |= value  << QDF_MON_STATUS_DCM_SHIFT;
    value = user->ldpc; // ldpc fw value
    rx_status->he_data3 |= value << QDF_MON_STATUS_CODING_SHIFT;
    value = user->stbc; // stbc fw value
    rx_status->he_data3 |= value << QDF_MON_STATUS_STBC_SHIFT;

    /* radiotap he_data 4 */
    if(user->ppdu_type == CDP_PPDU_STATS_PPDU_TYPE_SU)
        rx_status->he_data4 = ppdu_desc->spatial_reuse;

    /* radiotap he_data 5 */
    rx_status->he_data5 = user->bw;
    value = user->gi;
    rx_status->he_data5 |= value << QDF_MON_STATUS_GI_SHIFT;
    value = user->ltf_size;
    rx_status->he_data5 |= value << QDF_MON_STATUS_HE_LTF_SIZE_SHIFT;
    value = user->txbf;
    rx_status->he_data5 |= value << QDF_MON_STATUS_TXBF_SHIFT;

    /* radiotap he_data 6 */
    rx_status->he_data6 = user->nss + 1;
    value = ppdu_desc->doppler;
    rx_status->he_data6 |= value << QDF_MON_STATUS_DOPPLER_SHIFT;
}

/**
 * convert_tx_to_rx_stats(): Function to update mpdu info
 * from ppdu_desc
 * @ppdu_id: ppdu_id
 * @mpdu_info: cdp_tx_indication_mpdu_info
 * @user: cdp_tx_completion_ppdu_user
 *
 * return: void
 */
static inline
QDF_STATUS convert_tx_to_rx_stats(struct cdp_tx_indication_info *tx_info,
                                  struct mon_rx_status *rx_status)
{
    struct cdp_tx_indication_mpdu_info *m_info = &tx_info->mpdu_info;
    uint8_t usr_idx = 0;

    usr_idx = m_info->usr_idx;
    rx_status->tsft = m_info->ppdu_start_timestamp;
    rx_status->chan_num = m_info->channel_num;
    rx_status->chan_freq = m_info->channel;
    rx_status->ppdu_id = m_info->ppdu_id;
    rx_status->rssi_comb = m_info->ack_rssi;
    rx_status->tid = m_info->tid;
    rx_status->frame_control_info_valid = m_info->frame_ctrl;
    rx_status->nss = m_info->nss;
    rx_status->sgi = m_info->gi;
    rx_status->mcs = m_info->mcs;
    rx_status->preamble_type = m_info->preamble;
    rx_status->bw = m_info->bw;
    rx_status->beamformed = m_info->txbf;
    rx_status->ldpc = m_info->ldpc;
    rx_status->ofdm_flag = 1;

    if ((rx_status->preamble_type != DOT11_A) &&
        (rx_status->preamble_type != DOT11_B)) {
        if(tx_info->ppdu_desc->user[usr_idx].is_ampdu == 1)
            rx_status->rs_flags |= IEEE80211_AMPDU_FLAG;
    }

    switch(rx_status->preamble_type) {
    case DOT11_B:
	rx_status->ofdm_flag = 0;
	rx_status->cck_flag = 1;
	set_rate_b(rx_status);
    break;
    case DOT11_N:
        rx_status->ht_flags = 1;
        rx_status->rtap_flags |= _HT_SGI_PRESENT;
    break;
    case DOT11_AC:
        rx_status->vht_flags = 1;
	radiotap_vht_setup(tx_info, rx_status);
    break;
    case DOT11_AX:
        rx_status->he_flags = 1;
	radiotap_he_setup(tx_info, rx_status);
    break;
    default:
	set_rate_a(rx_status);
    break;
    };

    return QDF_STATUS_SUCCESS;
}

/* size of struct rx_pkt_tlv */
#define RX_PADDING_SIZE 384
/**
 * ol_ath_process_tx_frames() - Callback registered for WDI_EVENT_TX_DATA
 * @pdev_hdl: pdev pointer
 * @event:   WDi event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * The MSDU payload is appended with a tx capture identifier containing ppdu_id,
 * tx and rx address and is sent to this function.
 *
 * @Return: None
 */
static void ol_ath_process_tx_frames(void *pdev_hdl, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = NULL;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211vap *vap;
    osif_dev  *osifp;
    struct cdp_tx_indication_info *ptr_tx_info;
    struct mon_rx_status rx_status = {0};

    ptr_tx_info = (struct cdp_tx_indication_info *)data;

    if (!ptr_tx_info->mpdu_nbuf)
        return;

    if (!ic) {
        qdf_nbuf_free(ptr_tx_info->mpdu_nbuf);
        qdf_debug("ic is NULL");
        return;
    }

    vap = (struct ieee80211vap *)ic->ic_mon_vap;
    if (!vap) {
        qdf_nbuf_free(ptr_tx_info->mpdu_nbuf);
	ptr_tx_info->mpdu_nbuf = NULL;
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
        return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
        qdf_nbuf_free(ptr_tx_info->mpdu_nbuf);
	ptr_tx_info->mpdu_nbuf = NULL;
        return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    QDF_TRACE(QDF_MODULE_ID_DP_TX_CAPTURE, QDF_TRACE_LEVEL_INFO,
        "%s: %d ppdu_id[%d] frm_type[%d] [%p]sending to stack!!!!\n",
        __func__, __LINE__,
        ptr_tx_info->mpdu_info.ppdu_id, ptr_tx_info->mpdu_info.frame_type,
        ptr_tx_info->mpdu_nbuf);

    skb = ptr_tx_info->mpdu_nbuf;

    if (!ptr_tx_info->mpdu_nbuf) {
        QDF_TRACE(QDF_MODULE_ID_DP_TX_CAPTURE, QDF_TRACE_LEVEL_ERROR,
            "mpdu_nbuf is NULL!!!!\n");
        return;
    }

    ptr_tx_info->mpdu_nbuf = NULL;
    /* update radiotap header */
    convert_tx_to_rx_stats(ptr_tx_info, &rx_status);
    qdf_nbuf_update_radiotap(&rx_status, skb, RX_PADDING_SIZE);

    osif_deliver_tx_capture_data(osifp, skb);

    return;
}


/**
 * ol_ath_process_tx_data_frames() - Callback registered for WDI_EVENT_TX_DATA
 * @pdev_hdl: pdev pointer
 * @event:   WDi event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * The MSDU payload is appended with a tx capture identifier containing ppdu_id,
 * tx and rx address and is sent to this function.
 *
 * @Return: None
 */
static void ol_ath_process_tx_data_frames(void *pdev_hdl, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211vap *vap;
    osif_dev  *osifp;
    char *buf = NULL;

    if (!ic) {
      qdf_nbuf_free(skb);
      qdf_debug("ic is NULL");
      return;
    }

    vap = ic->ic_mon_vap;
    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
            qdf_nbuf_free(skb);
            return;
    }

    /* Free buffer if only tx_lat_capture is enabled */
    if (qdf_likely(((ic->ic_debug_sniffer != SNIFFER_M_COPY_MODE) &&
                   (ic->ic_debug_sniffer != SNIFFER_TX_CAPTURE_MODE))
                   && ic->ic_capture_latency)) {
        qdf_nbuf_free(skb);
        return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    if ((buf = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN))) {
        qdf_mem_copy(buf, DEBUG_SNIFFER_TEST_TX_DATA, DEBUG_SNIFFER_SIGNATURE_LEN);
    }

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_tx_capture_data(osifp, skb);
}

/**
 * ol_ath_process_rx_data_frames() - Callback registered for WDI_EVENT_RX_DATA
 * @pdev_hdl: pdev pointer
 * @event:   WDi event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * The MSDU payload is appended with a rx capture identifier containing 16bits ppdu_id,
 * and reserved field and is sent to this function.
 *
 * @Return: None
 */
static void ol_ath_process_rx_data_frames(void *pdev_hdl, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211vap *vap;
    osif_dev  *osifp;
    char *buf = NULL;

    if (!ic) {
      qdf_nbuf_free(skb);
      qdf_debug("ic is NULL");
      return;
    }

    vap = ic->ic_mon_vap;

    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
            qdf_nbuf_free(skb);
            return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    if ((buf = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN))) {
        qdf_mem_copy(buf, DEBUG_SNIFFER_TEST_RX_DATA, DEBUG_SNIFFER_SIGNATURE_LEN);
    }

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_tx_capture_data(osifp, skb);
}

#ifdef WLAN_RX_PKT_CAPTURE_ENH
QDF_STATUS convert_mpdu_info_to_stats(struct cdp_rx_indication_mpdu_info *mpdu_info, struct mon_rx_status *rx_status)
{
    A_MEMZERO(rx_status,sizeof(struct mon_rx_status));
    rx_status->tsft = mpdu_info->timestamp;
    rx_status->rs_fcs_err = mpdu_info->fcs_err;
    rx_status->chan_num = mpdu_info->channel;
    rx_status->chan_freq = mpdu_info->chan_freq;
    rx_status->ppdu_id = mpdu_info->ppdu_id;
    rx_status->rssi_comb = mpdu_info->rssi_comb;
    rx_status->chan_noise_floor = mpdu_info->nf;

    rx_status->rate = mpdu_info->rate;
    rx_status->nss = mpdu_info->nss;
    rx_status->sgi = mpdu_info->gi;
    rx_status->mcs = mpdu_info->mcs;
    rx_status->preamble_type = mpdu_info->preamble;
    rx_status->bw = mpdu_info->bw;
    rx_status->ldpc = mpdu_info->ldpc;

	/*testing pupose*/
    if (mpdu_info->preamble == DOT11_N ||
        mpdu_info->preamble == DOT11_AC ||
        mpdu_info->preamble == DOT11_AX) {
        rx_status->ht_flags = 1;
        rx_status->ht_mcs = rx_status->mcs;
        rx_status->rtap_flags |= 0x80;
    }
    rx_status->l_sig_a_info = mpdu_info->preamble |
        rx_status->ppdu_id << 16;
    rx_status->l_sig_b_info = mpdu_info->ppdu_type;
    rx_status->device_id = rx_status->nss |
	mpdu_info->mu_ul_info_valid << 8 |
	mpdu_info->ofdma_ru_start_index << 16 |
	mpdu_info->ofdma_ru_width << 24;
    return QDF_STATUS_SUCCESS;
}

static inline void ol_if_process_rx_mpdu(struct ol_ath_softc_net80211 *scn, enum WDI_EVENT event,
        void *data, u_int16_t peer_id)
{
    struct ieee80211com *ic  = &scn->sc_ic;
    struct ieee80211vap *vap = NULL;
    osif_dev  *osifp         = NULL;
    struct cdp_rx_indication_mpdu *rx_ind_mpdu = (struct cdp_rx_indication_mpdu *)data;
    qdf_nbuf_t mpdu_ind;
    struct cdp_rx_indication_mpdu_info *mpdu_info = &rx_ind_mpdu->mpdu_info;
    struct mon_rx_status rx_status;

    mpdu_ind = rx_ind_mpdu->nbuf;

    if (!mpdu_ind)
        return;

    if (!ic) {
      qdf_nbuf_free(mpdu_ind);
      qdf_info("ic is NULL");
      return;
    }

    vap = ic->ic_mon_vap;

    if (!vap) {
      qdf_nbuf_free(mpdu_ind);
      return;
    }

    convert_mpdu_info_to_stats(mpdu_info, &rx_status);
    qdf_nbuf_update_radiotap(&rx_status, mpdu_ind, RADIOTAP_HEADER_LEN);

    osifp = (osif_dev *)vap->iv_ifp;

    skb_reset_mac_header(mpdu_ind);
    mpdu_ind->dev       = osifp->netdev;
    mpdu_ind->pkt_type  = PACKET_USER;
    mpdu_ind->ip_summed = CHECKSUM_UNNECESSARY;
    mpdu_ind->protocol  = qdf_cpu_to_le16(ETH_P_802_2);
    netif_rx(mpdu_ind);
}

void process_rx_mpdu(void *pdev, enum WDI_EVENT event, void *data, u_int16_t peer_id, enum htt_cmn_rx_status status)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;

    ol_if_process_rx_mpdu(scn, event, data, peer_id);
}
#endif

/**
 * ol_ath_process_tx_metadata() - Callback registered for WDI_EVENT_TX_PPDU_DESC
 * @pdev_hdl: pdev pointer
 * @event:   WDi event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * @Return: None
 */
void ol_ath_process_tx_metadata(struct ieee80211com *ic, void *data)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct ieee80211vap *vap = ic->ic_mon_vap;
    osif_dev  *osifp = NULL;
    char *buf = NULL;

    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
            qdf_nbuf_free(skb);
            return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    if ((buf = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN))) {
        qdf_mem_copy(buf, DEBUG_SNIFFER_TEST_TX_METADATA, DEBUG_SNIFFER_SIGNATURE_LEN);
    }

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_tx_capture_data(osifp, skb);
}

/**
 * ol_ath_process_rx_metadata() - Callback registered for WDI_EVENT_RX_PPDU_DESC
 * @pdev_hdl: pdev pointer
 * @event:   WDi event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * @Return: None
 */
void ol_ath_process_rx_metadata(struct ieee80211com *ic, void *data)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct ieee80211vap *vap = ic->ic_mon_vap;
    osif_dev  *osifp = NULL;
    char *buf = NULL;

    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
            qdf_nbuf_free(skb);
            return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    if ((buf = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN))) {
        qdf_mem_copy(buf, DEBUG_SNIFFER_TEST_RX_METADATA, DEBUG_SNIFFER_SIGNATURE_LEN);
    }

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_tx_capture_data(osifp, skb);
}

/**
 * ol_ath_process_rx_nondata_frames() - Callback registered for recvd. mgmt. pkt processing
 * @pdev_hdl: pdev pointer
 * @event:   WDI event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * @Return: None
 */
static void ol_ath_process_rx_nondata_frames(void *pdev_hdl, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211vap *vap;
    osif_dev  *osifp = NULL;
#ifdef DP_RX_MON_MEM_FRAG
    uint32_t num_frags;
    unsigned int frag_size;
    qdf_nbuf_t last_nbuf, ext_list;
#endif
    qdf_frag_t buf_addr;

    if (!ic) {
      qdf_nbuf_free(skb);
      qdf_debug("ic is NULL");
      return;
    }

    vap = ic->ic_mon_vap;

    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
#ifndef DP_RX_MON_MEM_FRAG
    if (qdf_nbuf_is_nonlinear(skb)) {
        qdf_nbuf_free(skb);
        return;
    }
#endif

    if ((!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic)))) {
            qdf_nbuf_free(skb);
            return;
    }

    osifp = (osif_dev *)vap->iv_ifp;

    /**
     * IF feature is enabled then add string to the last frag of last skb.
     * Last DEBUG_SNIFFER_SIGNATURE_LEN bytes data from last frag of last
     * skb will be overwritten.
     */
#ifdef DP_RX_MON_MEM_FRAG
    ext_list = qdf_nbuf_get_ext_list(skb);
    last_nbuf = skb;
    while (ext_list) {
        last_nbuf = ext_list;
        ext_list = qdf_nbuf_queue_next(ext_list);
    }

    num_frags = qdf_nbuf_get_nr_frags(last_nbuf);
    if (!num_frags) {
        qdf_nbuf_free(skb);
        return;
    }
    buf_addr = qdf_nbuf_get_frag_addr(last_nbuf, num_frags - 1 );
    if (!buf_addr) {
        qdf_nbuf_free(skb);
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,
               "%s: SKB FRAG with address NULL is not expected \n",
               __func__);
        return;
    }
    frag_size = qdf_nbuf_get_frag_size_by_idx(last_nbuf, num_frags - 1);

    /**
     * Overwrite last 6 bytes of data with signature string.
     * If length of string is < 6, then write singature from initial
     * boundry.
     */
    if (frag_size >= DEBUG_SNIFFER_SIGNATURE_LEN)
        buf_addr = (char *)buf_addr + frag_size - DEBUG_SNIFFER_SIGNATURE_LEN;
#else
    /**
     * IF feature is disabled then add string to the tail room of skb.
     * In this case, we will have space available in tailroom and hence
     * last DEBUG_SNIFFER_SIGNATURE_LEN bytes string signature will be
     * appended and not overwritten.
     */
    buf_addr = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN);
#endif

    if (buf_addr)
        qdf_mem_copy(buf_addr, DEBUG_SNIFFER_TEST_RX_MGMT, DEBUG_SNIFFER_SIGNATURE_LEN);

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_lite_mon_data(osifp, skb);
}

#if QCN_IE
/**
 * ol_ath_process_offload_beacon() - Callback registered for WDI_EVENT_TX_BEACON
 * @pdev_hdl: pdev pointer
 * @event:   WDI event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * @Return: None
 */
static void ol_ath_process_offload_beacon(void *pdev_hdl, enum WDI_EVENT event, void *data,
                               u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211_node *ni;
    struct ieee80211vap *vap = NULL;
    qdf_hrtimer_data_t *bpr_hrtimer = NULL;
    struct ieee80211_frame *hdr;
    uint8_t *frm = NULL;

    if (!ic) {
      qdf_nbuf_free(skb);
      qdf_debug(" ic is NULL");
      return;
    }
    frm = (uint8_t *)qdf_nbuf_data(skb);
    /* Add IEEE80211_MACHDR_OFFSET to frm to point to ieee80211 beacon flags*/
    frm = frm + IEEE80211_MACHDR_OFFSET;
    hdr = (struct ieee80211_frame *)frm;
    if ((hdr->i_fc[0] & (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK)) == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON)) {
        ni = ieee80211_find_node(ic, hdr->i_addr2, WLAN_MLME_SB_ID);
        if (ni) {
            vap = ni->ni_vap;
            if (!vap) {
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                if (ic->ic_debug_sniffer == SNIFFER_DISABLE &&
                    ic->ic_tx_pkt_capture == TX_ENH_PKT_CAPTURE_DISABLE) {
                    qdf_nbuf_free(skb);
                }
                return;
            }
            if (ni == vap->iv_bss) {
                bpr_hrtimer = &vap->bpr_timer;
                if (qdf_hrtimer_active(bpr_hrtimer)) {

                    /* Cancel the timer as beacon is sent instead of a broadcast response */
                    qdf_hrtimer_cancel(bpr_hrtimer);
                    vap->iv_bpr_timer_cancel_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                    "Cancel timer: %s| %d | Delay: %d | Current time: %lld | Next beacon tstamp: %lld | "
                    "beacon interval: %d ms | Timer cb: %d | Enqueued: %d\n", \
                    __func__, __LINE__, vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp), \
                    ic->ic_intval, qdf_hrtimer_callback_running(bpr_hrtimer), qdf_hrtimer_is_queued(bpr_hrtimer));
                }

                /* Calculate the next beacon timestamp */
                vap->iv_next_beacon_tstamp = qdf_ktime_add_ns(qdf_ktime_get(), ic->ic_intval * QDF_NSEC_PER_MSEC);
            }
            /**
             * We are currently freeing the buffer based on vap->iv_lite_monitor flag.
             * In monitor mode, the buffer will be handeled by ol_ath_process_tx_nondata_frames.
             */
            if (ic->ic_debug_sniffer == SNIFFER_DISABLE &&
                ic->ic_tx_pkt_capture == TX_ENH_PKT_CAPTURE_DISABLE) {
                qdf_nbuf_free(skb);
            }

            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
        } else {
            if (ic->ic_debug_sniffer == SNIFFER_DISABLE &&
                ic->ic_tx_pkt_capture == TX_ENH_PKT_CAPTURE_DISABLE) {
                qdf_nbuf_free(skb);
            }
        }
    } else {
        if (ic->ic_debug_sniffer == SNIFFER_DISABLE &&
            ic->ic_tx_pkt_capture == TX_ENH_PKT_CAPTURE_DISABLE) {
            qdf_nbuf_free(skb);
        }
    }
}
#endif

/**
 * ol_ath_process_tx_nondata_frames() - Callback registered for WDI_EVENT_TX_MGMT_CTRL
 * @pdev_hdl: pdev pointer
 * @event:   WDI event
 * @data:    skb received
 * @peer_id: peer_id
 * @status:  status from event
 *
 * @Return: None
 */
static void ol_ath_process_tx_nondata_frames(void *pdev_hdl, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status)
{
    qdf_nbuf_t skb = (qdf_nbuf_t)data;
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) pdev_hdl;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    struct ieee80211vap *vap;
    osif_dev  *osifp = NULL;
    char *buf = NULL;

    if (!ic) {
      qdf_nbuf_free(skb);
      qdf_debug("ic is NULL");
      return;
    }

    vap = ic->ic_mon_vap;
    if (!vap) {
      qdf_nbuf_free(skb);
      QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,"%s: No monitor vap created, to dump skb\n",__func__);
      return;
    }

    /**
     * We are currently forwarding the buffer to user space or freeing the
     * buffer based on the feature.
     * Have callback here to extract the data if required.
     */
    if (!vap->iv_lite_monitor && (ol_ath_is_mcopy_enabled(ic))) {
            qdf_nbuf_free(skb);
            return;
    }
    osifp = (osif_dev *)vap->iv_ifp;

    if ((buf = (char *)qdf_nbuf_put_tail(skb, DEBUG_SNIFFER_SIGNATURE_LEN))) {
        qdf_mem_copy(buf, DEBUG_SNIFFER_TEST_TX_MGMT, DEBUG_SNIFFER_SIGNATURE_LEN);
    }

    /* Ensure to free the skb here if not being sent to upper layer */
    osif_deliver_tx_capture_data(osifp, skb);
}

static void ol_ath_process_tx_nondata_frames_wrapper(struct ieee80211com *ic, qdf_nbuf_t payload)
{
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *) ic->ic_pdev_obj;
    ol_ath_process_tx_nondata_frames(pdev_obj, 0, (void *)payload, 0, 0);
}

void ol_ath_subscribe_ppdu_desc_info(struct ol_ath_softc_net80211 *scn, uint8_t context)
{
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    struct ieee80211com *ic = &scn->sc_ic;

    if ((context == PPDU_DESC_DEBUG_SNIFFER) ||
            (context == PPDU_DESC_SMART_ANTENNA) ||
            (context == PPDU_DESC_ATF_STATS) ||
            ((context == PPDU_DESC_ENHANCED_STATS))) {
        if (qdf_atomic_read(&scn->tx_metadata_ref) == 0) {
            scn->stats_tx_subscriber.callback = ol_ath_process_ppdu_stats;
            scn->stats_tx_subscriber.context = scn->sc_pdev;
            if (cdp_wdi_event_sub(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                    &scn->stats_tx_subscriber, WDI_EVENT_TX_PPDU_DESC)) {
                return;
            }
        }
        qdf_atomic_inc(&scn->tx_metadata_ref);
    }

    if ((context == PPDU_DESC_ENHANCED_STATS) ||
        (context == PPDU_DESC_SMART_ANTENNA) ||
        (context == PPDU_DESC_CFR_RCC) ||
        (ol_ath_is_mcopy_enabled(ic))) {
        if (qdf_atomic_read(&scn->rx_metadata_ref) == 0) {
            scn->stats_rx_subscriber.callback = ol_ath_process_ppdu_stats;
            scn->stats_rx_subscriber.context = scn->sc_pdev;
            if (cdp_wdi_event_sub(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                    &scn->stats_rx_subscriber, WDI_EVENT_RX_PPDU_DESC)) {
                return;
            }
        }
        qdf_atomic_inc(&scn->rx_metadata_ref);
    }
}

void ol_ath_unsubscribe_ppdu_desc_info(struct ol_ath_softc_net80211 *scn, uint8_t context)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

    if ((context == PPDU_DESC_DEBUG_SNIFFER) ||
         (context == PPDU_DESC_SMART_ANTENNA) ||
         ((context == PPDU_DESC_ENHANCED_STATS) )) {
        if (qdf_atomic_dec_and_test(&scn->tx_metadata_ref)) {
            if (cdp_wdi_event_unsub(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                                &scn->stats_tx_subscriber, WDI_EVENT_TX_PPDU_DESC))
                return;
        }
    }

    if ((context == PPDU_DESC_ENHANCED_STATS) ||
        (context == PPDU_DESC_SMART_ANTENNA) ||
        (context == PPDU_DESC_CFR_RCC) ||
        (ol_ath_is_mcopy_enabled(ic))) {
        if (qdf_atomic_dec_and_test(&scn->rx_metadata_ref)) {
                if (cdp_wdi_event_unsub(soc_txrx_handle,
                        wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                        &scn->stats_rx_subscriber,
                        WDI_EVENT_RX_PPDU_DESC))
                    return;
        }
    }
}

int ol_ath_subscribe_tx_data_frames(struct ol_ath_softc_net80211 *scn)
{
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

    scn->stats_tx_data_subscriber.callback = ol_ath_process_tx_data_frames;
    scn->stats_tx_data_subscriber.context = scn->sc_pdev;

    if (qdf_atomic_read(&scn->tx_data_frame_ref) == 0) {
        if (cdp_wdi_event_sub(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
            &scn->stats_tx_data_subscriber, WDI_EVENT_TX_DATA)) {
            return A_ERROR;
        }
    }
    qdf_atomic_inc(&scn->tx_data_frame_ref);
    return A_OK;
}

int ol_ath_unsubscribe_tx_data_frames(struct ol_ath_softc_net80211 *scn)
{
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

    if (qdf_atomic_dec_and_test(&scn->tx_data_frame_ref)) {
        if (cdp_wdi_event_unsub(soc_txrx_handle,
                                wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                                &scn->stats_tx_data_subscriber, WDI_EVENT_TX_DATA))
            return A_ERROR;
    }
    return A_OK;
}

int ol_ath_set_capture_latency(struct ol_ath_softc_net80211 *scn, int val)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type value = {0};

    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    if (val) {
        if (ic->ic_capture_latency) {
            qdf_info("Capture_latency already enabled. Disable it first");
            return A_ERROR;
        }

        /* register subscriber */
        if (ol_ath_subscribe_tx_data_frames(scn)) {
            qdf_err("Subscription for tx_lat_capture failed.");
            return A_ERROR;
        }

        value.cdp_pdev_param_cptr_latcy = val;
        cdp_txrx_set_pdev_param(soc_txrx_handle,
                                wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                                CDP_CONFIG_CAPTURE_LATENCY, value);
        ic->ic_capture_latency = val;
    } else {
        if (!ic->ic_capture_latency) {
            qdf_info("Capture_latency already disabled. Enable it first");
            return A_ERROR;
        }

        ic->ic_capture_latency = val;

        /* Unregister Subscriber */
        if (ol_ath_unsubscribe_tx_data_frames(scn)) {
            qdf_err("Unsubscription for tx_lat_capture failed.");
            /* Resetting tx_lat_capture as unsubscription failed */
            ic->ic_capture_latency = 1;
            return A_ERROR;
        }
        value.cdp_pdev_param_cptr_latcy = 0;
        cdp_txrx_set_pdev_param(soc_txrx_handle,
                                wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                                CDP_CONFIG_CAPTURE_LATENCY, value);
    }

    return 0;
}

#if QCN_IE
int ol_ath_set_bpr_wifi3(struct ol_ath_softc_net80211 *scn, int val)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
    cdp_config_param_type value = {0};

    if (ol_ath_is_beacon_offload_enabled(scn->soc)) {
        soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
        if (val) {
            if (qdf_atomic_inc_return(&ic->ic_bpr_enable) == 1) {
                scn->stats_bpr_subscriber.callback = ol_ath_process_offload_beacon;
                scn->stats_bpr_subscriber.context = scn->sc_pdev;
                if (cdp_wdi_event_sub(soc_txrx_handle,
                                pdev_id,
                                &scn->stats_bpr_subscriber,
                                WDI_EVENT_TX_BEACON))
                    return A_ERROR;
                value.cdp_pdev_param_bpr_enable = val;
                cdp_txrx_set_pdev_param(soc_txrx_handle,
                                pdev_id,
                                CDP_CONFIG_BPR_ENABLE, value);
            }
        }
        else {
            if (qdf_atomic_dec_return(&ic->ic_bpr_enable) == 0) {
                if (cdp_wdi_event_unsub(soc_txrx_handle,
                                pdev_id,
                                &scn->stats_bpr_subscriber,
                                WDI_EVENT_TX_BEACON))
                    return A_ERROR;
                value.cdp_pdev_param_bpr_enable = val;
                cdp_txrx_set_pdev_param(soc_txrx_handle,
                                pdev_id,
                                CDP_CONFIG_BPR_ENABLE, value);
            }
        }
    }
    return 0;
}
#endif

int ol_ath_set_debug_sniffer(struct ol_ath_softc_net80211 *scn,  int val)
{
    ol_txrx_soc_handle soc_txrx_handle;
    struct ieee80211com *ic = &scn->sc_ic;
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
    cdp_config_param_type value = {0};
    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

    if ((val == SNIFFER_TX_CAPTURE_MODE) || (val == SNIFFER_M_COPY_MODE) ||
        (val == SNIFFER_EXT_M_COPY_MODE)) {
	if (!ic->ic_debug_sniffer) {
            ic->ic_debug_sniffer = val;
	} else {
            qdf_info("Sniffer/AM copy mode already enabled. Disable it first");
            return A_ERROR;
	}

        ic->ic_process_nondata_tx_frames = ol_ath_process_tx_nondata_frames_wrapper;

        if (val == SNIFFER_M_COPY_MODE || val == SNIFFER_EXT_M_COPY_MODE) {
            scn->stats_rx_data_subscriber.callback = ol_ath_process_rx_data_frames;
            scn->stats_rx_data_subscriber.context = scn->sc_pdev;

             if (cdp_wdi_event_sub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_rx_data_subscriber,
                        WDI_EVENT_RX_DATA))
                return A_ERROR;

            scn->stats_rx_nondata_subscriber.callback = ol_ath_process_rx_nondata_frames;
            scn->stats_rx_nondata_subscriber.context = scn->sc_pdev;
             if (cdp_wdi_event_sub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_rx_nondata_subscriber,
                        WDI_EVENT_RX_MGMT_CTRL))
                return A_ERROR;
	}

        ic->ic_tx_capture = 1;
        scn->stats_nondata_subscriber.callback = ol_ath_process_tx_nondata_frames;
        scn->stats_nondata_subscriber.context = scn->sc_pdev;

        if (ol_ath_subscribe_tx_data_frames(scn))
            return A_ERROR;



        if (cdp_wdi_event_sub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_nondata_subscriber,
                        WDI_EVENT_TX_MGMT_CTRL))
            return A_ERROR;

        ol_ath_subscribe_ppdu_desc_info(scn, PPDU_DESC_DEBUG_SNIFFER);

        value.cdp_pdev_param_dbg_snf = val;
        cdp_txrx_set_pdev_param(soc_txrx_handle,
			pdev_id,
			CDP_CONFIG_DEBUG_SNIFFER, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (scn->sc_ic.nss_radio_ops)
                scn->sc_ic.nss_radio_ops->ic_nss_ol_wifi_tx_capture_set(scn, val);
#endif
    } else if (val == SNIFFER_TX_MONITOR_MODE) {
        if (ic->ic_tx_pkt_capture != TX_ENH_PKT_CAPTURE_DISABLE) {
            scn->stats_tx_data_subscriber.callback = ol_ath_process_tx_frames;
            scn->stats_tx_data_subscriber.context = scn->sc_pdev;

            if (cdp_wdi_event_sub(soc_txrx_handle,
                            pdev_id,
                            &scn->stats_tx_data_subscriber,
                            WDI_EVENT_TX_PKT_CAPTURE))
                return A_ERROR;
        } else {
            if (cdp_wdi_event_unsub(soc_txrx_handle,
                            pdev_id,
                            &scn->stats_tx_data_subscriber,
                            WDI_EVENT_TX_PKT_CAPTURE))
                return A_ERROR;
        }
    } else {
        if(ic->ic_debug_sniffer == 0) {
            qdf_err("Sniffer mode is disabled. Enable it first");
            return A_ERROR;
        }

        /* Unregister Subscriber */
        ic->ic_tx_capture = 0;
        if (ol_ath_unsubscribe_tx_data_frames(scn))
            return A_ERROR;

        if (cdp_wdi_event_unsub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_rx_data_subscriber,
                        WDI_EVENT_RX_DATA))
            return A_ERROR;

        if (cdp_wdi_event_unsub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_nondata_subscriber,
                        WDI_EVENT_TX_MGMT_CTRL))
            return A_ERROR;

        if (cdp_wdi_event_unsub(soc_txrx_handle,
                        pdev_id,
                        &scn->stats_rx_nondata_subscriber,
                        WDI_EVENT_RX_MGMT_CTRL))
            return A_ERROR;

        ol_ath_unsubscribe_ppdu_desc_info(scn, PPDU_DESC_DEBUG_SNIFFER);

        ic->ic_debug_sniffer = 0;
        ic->ic_process_nondata_tx_frames = NULL;

        value.cdp_pdev_param_dbg_snf = SNIFFER_DISABLE;
        cdp_txrx_set_pdev_param(soc_txrx_handle,
				pdev_id,
				CDP_CONFIG_DEBUG_SNIFFER, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (scn->sc_ic.nss_radio_ops)
                scn->sc_ic.nss_radio_ops->ic_nss_ol_wifi_tx_capture_set(scn, SNIFFER_DISABLE);
#endif
	}
    return 0;
}

int ol_ath_set_tx_capture (struct ol_ath_softc_net80211 *scn, int val) {
#ifndef REMOVE_PKT_LOG
    u_int32_t tx_capture;
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    uint32_t pdev_id = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
    cdp_config_param_type value = {0};
    tx_capture = scn->pl_dev->pl_info->tx_capture_enabled;

#ifdef OL_ATH_SMART_LOGGING
    /* We use scn->pl_dev->tgt_pktlog_enabled inline with existing design for
     * this call. However, if access semantics for
     * scn->pl_dev->tgt_pktlog_enabled are changed for this call, then change
     * below accordingly.
     */
    if ((val == 1) && (!tx_capture)) {
        /* We intend to enable Tx capture. But if
         * scn->pl_dev->tgt_pktlog_enabled is true due to smart log FW initiated
         * packetlog, we have to get it out of the way.
         */
        if (scn->pl_dev->tgt_pktlog_enabled) {
            /* If smart log FW initiated packetlog is responsible for
             * scn->pl_dev->tgt_pktlog_enabled being true, then it will stop the
             * packetlog and block itself resulting in
             * scn->pl_dev->tgt_pktlog_enabled becoming false. These call
             * semantics are necessary for preserving locking requirements
             * within the smart log FW initiated packetlog module.
             *
             * We set the block_only_if_started argument to true so that if
             * scn->pl_dev->tgt_pktlog_enabled is true but smart log FW
             * initiated packetlog is not responsible, then the previous host
             * module caller's decision to not block FW initiated packetlog
             * remains in effect.
             */
            if (scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_stop_and_block &&
                   (scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_stop_and_block(
                        scn, ATH_PKTLOG_TX_CAPTURE_ENABLE, true) !=
                     QDF_STATUS_SUCCESS)) {
                return -1;
            }
        } else {
             /* Since we are the first to block smart log FW initiated
              * packetlog, we block it under all circumstances.
              */
             if (scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_stop_and_block &&
                   (scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_stop_and_block(
                        scn, ATH_PKTLOG_TX_CAPTURE_ENABLE, false) !=
                     QDF_STATUS_SUCCESS)) {
                return -1;
            }
        }
    }
#endif /* OL_ATH_SMART_LOGGING */

    if ((val == 1) && ((!scn->pl_dev->tgt_pktlog_enabled) && (!tx_capture))) {
           if (scn->pl_dev->pl_funcs->pktlog_enable(scn, ATH_PKTLOG_TX_CAPTURE_ENABLE) == 0) {
               qdf_info("Enabled Tx Capture");
               scn->pl_dev->pl_info->tx_capture_enabled = 1;
               value.cdp_pdev_param_tx_capture = val;
               cdp_txrx_set_pdev_param(soc_txrx_handle,
                                       pdev_id, CDP_CONFIG_TX_CAPTURE, value);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (scn->sc_ic.nss_radio_ops)
                scn->sc_ic.nss_radio_ops->ic_nss_ol_wifi_tx_capture_set(scn, val);
#endif
            return 0;
        }
    } else if ((val == 0) && (tx_capture)) {
        if (scn->pl_dev->pl_funcs->pktlog_enable(scn, 0) == 0) {
            qdf_info("Disabled Tx Capture");
            scn->pl_dev->pl_info->tx_capture_enabled = 0;
            value.cdp_pdev_param_tx_capture = val;
            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                    pdev_id, CDP_CONFIG_TX_CAPTURE, value);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (scn->sc_ic.nss_radio_ops)
                scn->sc_ic.nss_radio_ops->ic_nss_ol_wifi_tx_capture_set(scn, val);
#endif
#ifdef OL_ATH_SMART_LOGGING
            if (scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_unblock)
                scn->pl_dev->pl_sl_funcs.smart_log_fw_pktlog_unblock(scn);
#endif /* OL_ATH_SMART_LOGGING */
            return 0;
        }
    }
#endif
    return -1;
}

/*
 * Return true if target is a lithium target. else return false
 */
bool ol_target_lithium(struct wlan_objmgr_psoc *psoc)
{
    switch (lmac_get_tgt_type(psoc)) {
        case TARGET_TYPE_QCA8074:
        case TARGET_TYPE_QCA8074V2:
        case TARGET_TYPE_QCA6018:
        case TARGET_TYPE_QCA5018:
        case TARGET_TYPE_QCN9000:
        case TARGET_TYPE_QCN6122:
            return true;
    }

    return false;
}
qdf_export_symbol(ol_target_lithium);

#ifdef CONFIG_DP_TRACE
static int
ol_ath_dptrace_setparam(int cmd, int val1, int val2)
{
    switch (cmd) {
        case IEEE80211_DBG_DPTRACE_PROTO_BITMAP:
            qdf_dp_set_proto_bitmap(val1);
            return 0;
        case IEEE80211_DBG_DPTRACE_VERBOSITY:
            qdf_dp_trace_set_verbosity(val1);
            return 0;
        case IEEE80211_DBG_DPTRACE_NO_OF_RECORD:
            qdf_dp_set_no_of_record(val1);
            return 0;
        case IEEE80211_DBG_DPTRACE_DUMPALL:
            qdf_dp_trace_dump_all(val1, val2);
            return 0;
        case IEEE80211_DBG_DPTRACE_CLEAR:
            qdf_dp_trace_clear_buffer();
            return 0;
        case IEEE80211_DBG_DPTRACE_LIVEMODE_ON:
            qdf_dp_trace_enable_live_mode();
            return 0;
        case IEEE80211_DBG_DPTRACE_LIVEMODE_OFF:
            qdf_dp_trace_disable_live_mode();
            return 0;
        default:
            return -1;
    }
}
#endif


inline u_int32_t ol_if_peer_get_rate(struct wlan_objmgr_peer *peer, u_int8_t type)
{
    struct wlan_objmgr_psoc *psoc;
    ol_txrx_soc_handle soc;
    QDF_STATUS status;
    cdp_peer_stats_param_t buf = {0};
    uint8_t vdev_id;

    if (!peer)
        return 0;

    psoc = wlan_peer_get_psoc(peer);
    if (!psoc)
        return 0;

    vdev_id = wlan_vdev_get_id(peer->peer_objmgr.vdev);
    soc = wlan_psoc_get_dp_handle(psoc);
    switch (type) {
        case IEEE80211_RATE_TX:
             status = cdp_txrx_get_peer_stats_param(soc, vdev_id, peer->macaddr,
                                                    cdp_peer_tx_rate, &buf);
             if (QDF_IS_STATUS_ERROR(status))
                 return 0;

             return buf.tx_rate;
        case IEEE80211_RATE_RX:
             status = cdp_txrx_get_peer_stats_param(soc, vdev_id, peer->macaddr,
                                                    cdp_peer_rx_rate, &buf);
             if (QDF_IS_STATUS_ERROR(status))
                 return 0;

             return buf.rx_rate;
        case IEEE80211_RATECODE_TX:
             status = cdp_txrx_get_peer_stats_param(soc, vdev_id, peer->macaddr,
                                                    cdp_peer_tx_ratecode, &buf);
             if (QDF_IS_STATUS_ERROR(status))
                 return 0;

             return buf.tx_ratecode;
        case IEEE80211_RATEFLAGS_TX:
             status = cdp_txrx_get_peer_stats_param(soc, vdev_id, peer->macaddr,
                                                    cdp_peer_tx_flags, &buf);
             if (QDF_IS_STATUS_ERROR(status))
                 return 0;

             return buf.tx_flags;
        default:
             return 0;
    }
}

QDF_STATUS ol_ath_set_country_failed(struct wlan_objmgr_pdev *pdev)
{
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;
    struct ieee80211com *ic;

    osif_priv = wlan_pdev_get_ospriv(pdev);

    if (!osif_priv) {
        qdf_err("osif_priv is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;
    ic = &scn->sc_ic;
    ic->ic_set_country_failed = true;
    qdf_event_set(&ic->ic_wait_for_init_cc_response);

    return QDF_STATUS_SUCCESS;
}

uint32_t ol_ath_get_interface_id(struct wlan_objmgr_pdev *pdev)
{
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;

    osif_priv = wlan_pdev_get_ospriv(pdev);

    if (!osif_priv) {
        qdf_err("osif_priv is NULL");
        return (uint32_t)-1;
    }

    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;

    return scn->radio_id;
}

uint8_t ol_ath_is_bcn_mode_burst(struct wlan_objmgr_pdev *pdev)
{
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;

    if (!pdev) {
        qdf_err("pdev is null!");
        return 0;
    }

    osif_priv = wlan_pdev_get_ospriv(pdev);
    if (!osif_priv) {
        qdf_err("osif_priv is NULL");
        return 0;
    }
    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;
    if (!scn) {
        qdf_err("scn is NULL");
        return 0;
    }

    return ((scn->bcn_mode == BEACON_TX_MODE_BURST)? 1 : 0);
}

void ol_ath_init_and_enable_radar_table(struct ieee80211com *ic)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wmi_unified *wmi_handle;

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null");
        return;
    }

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops) {
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                                         QDF_STATUS_SUCCESS) {
            return;
        }

        if (!wmi_service_enabled(wmi_handle, wmi_service_dfs_phyerr_offload) &&
                dfs_rx_ops->dfs_get_radars)
            dfs_rx_ops->dfs_get_radars(pdev);

        if (dfs_rx_ops->dfs_radar_enable)
            dfs_rx_ops->dfs_radar_enable(pdev, 0, ic->ic_opmode, true);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    }
}

uint32_t ol_ath_num_mcast_tbl_elements(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    target_resource_config *tgt_cfg;

    tgt_cfg = lmac_get_tgt_res_cfg(psoc);
    if (!tgt_cfg) {
        qdf_err("psoc target res cfg is null");
        return 0;
    }

    return tgt_cfg->num_mcast_table_elems;
}

uint32_t ol_ath_num_mcast_grps(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    target_resource_config *tgt_cfg;

    tgt_cfg = lmac_get_tgt_res_cfg(psoc);
    if (!tgt_cfg) {
        qdf_err("psoc target res cfg is null");
        return 0;
    }

    return tgt_cfg->num_mcast_groups;
}

bool ol_ath_is_target_ar900b(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    return lmac_is_target_ar900b(psoc);
}

uint32_t ol_ath_get_tgt_type(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    return lmac_get_tgt_type(psoc);
}

#if QCN_ESP_IE
int32_t ol_ath_esp_estimate_event_handler(ol_soc_t sc, uint8_t *data, uint32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct esp_estimation_event event, *ev = &event;
    struct ieee80211com *ic;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle || wmi_extract_esp_estimate_ev_param(wmi_handle, data, ev))
        return -1;

    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(ev->pdev_id),
                                      WLAN_MLME_SB_ID);
    if (!pdev) {
        qdf_err("pdev object (id: %d) is NULL", PDEV_UNIT(ev->pdev_id));
        return -1;
    }
    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (ic) {
        ic->ic_fw_esp_air_time = ev->ac_airtime_percentage;
        ic->ic_esp_flag = 1;
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);

    return 0;
}
#endif /* QCN_ESP_IE */

int ol_ath_send_delba(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t vdev_id, uint8_t *peer_macaddr,
                      uint8_t tid, uint8_t reason_code)
{
    struct ieee80211_node *ni;
    struct ieee80211_action_mgt_args actionargs;
    struct wlan_objmgr_peer *peer;
    struct wlan_objmgr_vdev *vdev =  wlan_objmgr_get_vdev_by_id_from_psoc(
                                     (struct wlan_objmgr_psoc *)psoc, vdev_id, WLAN_MLME_SB_ID);

    if (!vdev)
        return -1;

    peer = wlan_objmgr_vdev_find_peer_by_mac(vdev, peer_macaddr, WLAN_MLME_SB_ID);

    if (!peer) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
        return -1;
    }

    ni = wlan_peer_get_mlme_ext_obj(peer);

    if (!ni) {
        wlan_objmgr_peer_release_ref(peer, WLAN_MLME_SB_ID);
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
        return -1;
    }

    IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ACTION, ni,
                "[%s]: Sending delba- node:0x%pK(%s) Tid: %d\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr), tid);

    actionargs.category     = IEEE80211_ACTION_CAT_BA;
    actionargs.action       = IEEE80211_ACTION_BA_DELBA;
    actionargs.arg1         = tid;
    actionargs.arg2         = 0;
    actionargs.arg3         = reason_code;
    ieee80211_send_action(ni, &actionargs, NULL);

    wlan_objmgr_peer_release_ref(peer, WLAN_MLME_SB_ID);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);

    return 0;
}

uint8_t ol_ath_fill_umac_radio_band_info(struct wlan_objmgr_pdev *pdev)
{
    enum channel_state state;
    struct regulatory_channel *curr_chan_list;
    uint8_t i, num_valid_chan = 0;
    uint32_t low_5g = 0, high_5g = 0;
    uint8_t radio_band = NO_BAND_INFORMATION_AVAILABLE;
    uint32_t fiveg_channel[NUM_CHANNELS];
    int status = 0;

    curr_chan_list = qdf_mem_malloc
        (NUM_CHANNELS*sizeof(struct regulatory_channel));

    if (!curr_chan_list) {
        QDF_TRACE(QDF_MODULE_ID_SON, QDF_TRACE_LEVEL_ERROR,"%s: fail to alloc",
                  __func__);
        return NO_BAND_INFORMATION_AVAILABLE;
    }

    status = ucfg_reg_get_current_chan_list (pdev, curr_chan_list);

    if (QDF_IS_STATUS_ERROR(status)) {
        QDF_TRACE(QDF_MODULE_ID_SON, QDF_TRACE_LEVEL_ERROR,
                  "Couldn't get current chan list");
        qdf_mem_free(curr_chan_list);
        return NO_BAND_INFORMATION_AVAILABLE;
    }

    for (i=0; i<NUM_CHANNELS; i++) {
        state = curr_chan_list[i].state;
        if (state!= CHANNEL_STATE_DISABLE && state!= CHANNEL_STATE_INVALID
            && curr_chan_list[i].center_freq > MAX_FREQ_IN_TWOG) {
            fiveg_channel[num_valid_chan++]  = curr_chan_list[i].center_freq;
        }
    }

    if (!num_valid_chan) {
        qdf_mem_free(curr_chan_list);
        return NON_5G_RADIO;
    }

    low_5g = fiveg_channel[0];
    high_5g = fiveg_channel[num_valid_chan-1];
    if ( low_5g >= regdmn_get_min_6ghz_chan_freq() &&
         high_5g <= regdmn_get_max_6ghz_chan_freq() )
        radio_band = BAND_6G_RADIO;
    else if ( low_5g >= regdmn_get_min_5ghz_chan_freq() &&
              high_5g <= regdmn_get_max_6ghz_chan_freq() &&
              high_5g > regdmn_get_max_5ghz_chan_freq() )
        radio_band = BAND_5G_6G_RADIO;
    else if (low_5g >= LOW_BAND_MIN_FIVEG_FREQ && high_5g <= LOW_BAND_MAX_FIVEG_FREQ)
        radio_band = LOW_BAND_RADIO;
    else if (low_5g > LOW_BAND_MAX_FIVEG_FREQ)
        radio_band = HIGH_BAND_RADIO;
    else if (low_5g >= LOW_BAND_MIN_FIVEG_FREQ && high_5g > LOW_BAND_MAX_FIVEG_FREQ)
        radio_band = FULL_BAND_RADIO;

    qdf_mem_free(curr_chan_list);
    return radio_band;
}

/**
 * ol_ath_punctured_band_setting_check() - User input validity check for
 *                                         Preamble Puncturing
 * @ic - ic pointer
 * @value - user input
 *
 * Return: EINVAL - Failure
 *         0      - Success
 */
int ol_ath_punctured_band_setting_check(struct ieee80211com *ic, uint32_t value)
{
/* Preamble Puncturing is currently supported only for 80MHz BW setting.
 * The command takes bitmap input where each bit corresponds to a 20MHz band.
 * As per above, only B0-B3 are valid bits for preamble puncturing config for 80MHz.
 */
#define PUNCTURED_BAND_INVALID_MASK             0xFFF0
/* Currently only 20MHz band puncturing is supported */
#define NUM_20MHZ_PUNCTURED_BAND_SUPPORTED      1
    uint8_t puncture_bw_count = 0, primary20mhz_idx = 0;
    uint32_t puncture_bw_setting = value;
    uint16_t starting_freq = 0;

    if (value & PUNCTURED_BAND_INVALID_MASK) {
        qdf_err("Punctured band only supported for 80MHz");
        return -EINVAL;
    }

    while (puncture_bw_setting) {
        /* Determine number of bands punctured by user.
         */
        puncture_bw_setting &= (puncture_bw_setting - 1);
        puncture_bw_count++;
    }

    if (puncture_bw_count > NUM_20MHZ_PUNCTURED_BAND_SUPPORTED) {
        qdf_err("Puncturing supported for 20MHz band only");
        return -EINVAL;
    }

    /* Check if user is puncturing primary 20MHz band.
     * Calculate the Primary 20MHz channel index based on center
     * frequency and starting frequency setting.
     */
    starting_freq = (ic->ic_curchan->ic_vhtop_freq_seg1 - BW_40_MHZ);
    primary20mhz_idx = (ic->ic_curchan->ic_freq - starting_freq)/BW_20_MHZ;

    if(BIT(primary20mhz_idx) & value) {
        qdf_err("Primary 20MHz band cannot be punctured\n"
                "Punctured band index: %d", primary20mhz_idx);
        return -EINVAL;
    }

    return 0;
}

int ol_ath_get_ofdma_max_users(struct ol_ath_soc_softc *soc)
{
    struct target_psoc_info *tgt_psoc_info;
    struct target_mu_caps mu_caps;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return 0;
    }

    target_psoc_get_mu_max_users(tgt_psoc_info, &mu_caps);

    return (mu_caps.ofdma_ul << 16) | mu_caps.ofdma_dl;
}

int ol_ath_get_mumimo_max_users(struct ol_ath_soc_softc *soc)
{
    struct target_psoc_info *tgt_psoc_info;
    struct target_mu_caps mu_caps;

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
    if (!tgt_psoc_info) {
        qdf_err("target_psoc_info is null");
        return 0;
    }

    target_psoc_get_mu_max_users(tgt_psoc_info, &mu_caps);

    return (mu_caps.mumimo_ul << 16) | mu_caps.mumimo_dl;
}

#if QLD
/**
 * qld_generate_table() - function to generate qld table
 * @req: request structure
 *
 * Return: 0 - OK -EINVAL - On failure
 */
int qld_generate_table(void *req, struct qld_entry *entry)
{
    struct qld_event  *q_event = NULL;
    struct ol_qld_entry *q_entry = NULL;
    struct ol_qld_entry *start = NULL;
    struct qldinforeq *qld_req = NULL;

    if (!req || !entry) {
        qdf_err("QLD: Request or Node is NULL");
        return -EINVAL;
    }
    qld_req = (struct qldinforeq *)req;
    q_event = qld_req->qld_event_buf;
    start   = &q_event->qld_buffer[0];

    /* Position to current entry to copy */
    q_entry = &start[qld_req->index];
    q_entry->addr = entry->addr;
    q_entry->size = entry->size;
    qdf_snprintf(q_entry->name, sizeof(q_entry->name), "%s", entry->name);
    qld_req->index++;
    return 0;
}

/**
 * qld_send_event() - function to send event to userspace
 * @ic          : ic structure
 * @dev         : netdevice
 * @q_header    : qld_event
 * @total_count : total list count
 * @len         : length of event with header
 * @last_event  : flag to indicate if its last or only event
 *
 * @Return: 0 on success
 */
int qld_send_event(struct ieee80211com *ic, struct net_device *dev, \
                   struct qld_event *q_header, uint32_t total_count,  \
                   uint32_t len,bool last_event)
{
    /*Added header meta data*/
    q_header->cmd = IEEE80211_DBGREQ_GET_QLD_DUMP_TABLE;
    q_header->total_list_count = total_count;
    q_header->current_event_size = len;

    /* modify the flag if its last event*/
    if (last_event)
        q_header->flags = q_header->flags|QLD_END_EVENT;
    /* Send Data to userspace */
    wlan_cfg80211_generic_event(ic,
            QCA_NL80211_VENDOR_SUBCMD_DBGREQ, q_header, len, dev, GFP_ATOMIC);
    return 0;
}

#define QLD_LIST_ALLOC_SIZE (3 * 1024)   /*max size for qld msg */

/**
 * qld_submit_table() - function to submit table
 * @ic   : ic structure
 * @req  : req structure
 *
 * Return: 0 - OK -EINVAL - On failure
 */
int qld_submit_table(struct ieee80211com *ic ,void * req)
{
    struct qld_event  *q_event = NULL;
    struct net_device *dev;
    struct qldinforeq *qld_req = NULL;
    struct qld_event *q_event_header;
    uint32_t entry_size;
    uint8_t *send_msg;
    uint32_t len = 0;
    uint32_t total_len = 0;
    uint32_t total_count = 0;

    if (!req) {
        qdf_err("QLD: Request is NULL");
        return -EINVAL;
    }

    if ((qld_get_list_count(&total_count) != 0) || (total_count == 0)) {
        qdf_err("QLD: Invalid list count");
        return -EINVAL;
    }

    qld_req = req;
    q_event = (struct qld_event *)qld_req->qld_event_buf;
    entry_size = sizeof(struct ol_qld_entry);
    dev = ic->ic_netdev;
    q_event_header = q_event;
    send_msg = (uint8_t*)&q_event->qld_buffer[0];

    /* Give offset initially for header compensation*/
    len = sizeof(struct qld_event);
    total_len = len;

    q_event_header->flags = QLD_START_EVENT;
    qdf_err("QLD: Total list count %d", total_count);
    while (total_len < qld_req->space) {

        if (((len + entry_size) < QLD_LIST_ALLOC_SIZE)) {
            /* Keep moving the till we reach size that buffer can't hold*/
            len +=  entry_size;
            total_len += entry_size;
            send_msg += entry_size;
        } else {
            qdf_err("QLD:cmdid %d:current_size %d: flags %x",
                    q_event_header->cmd, q_event_header->current_event_size,
                    q_event_header->flags);
            qld_send_event(ic, dev, q_event_header, total_count, len, false);
            /*Reset the header ,we use the previous  memory to add header
              info so that we can send continous memory to user space
            |q_event header | q_entry [0] | q_entry[1] ... |
            |sent data ..| q_event_header | q_entry[1] ... |
            */
            /*Header is piggybacked */
            q_event_header  = (struct qld_event*) (send_msg - sizeof(struct qld_event));
            q_event_header->flags = QLD_MORE_EVENT;
            len = sizeof(struct qld_event);
        }
    }

    /* Send Remaining data! */
    qdf_err("QLD: Sending final chunk %d to userspace", len);
    if (len != 0) {
        qld_send_event(ic, dev, q_event_header, total_count, len, true);
        qdf_err("QLD:cmdid %d:current_size %d: flags %x",q_event_header->cmd,
                q_event_header->current_event_size,q_event_header->flags);
    }
    return 0;
}

/**
 * qld_dump_wait() - wait till upper layer finish
 * @soc   : soc structure
 *
 * Return: 0 - OK -EINVAL - On failure
 */
int qld_dump_wait(struct ol_ath_soc_softc *soc)
{
    if (!soc)
        return -EINVAL;

    qdf_err("QLD:Start waiting from application to finish");
    qdf_wait_single_event(&soc->qld_wait, QLD_WAIT_TIMEOUT_COUNT);
    qdf_err("QLD:Finished waiting from application");
    return 0;
}
qdf_export_symbol(qld_dump_wait);

/**
 * qld_process_list() - processing qld list
 * @soc   : soc structure
 *
 * Return: 0 - OK -EINVAL -ENOMEM - On failure
 */
int qld_process_list(struct ol_ath_soc_softc *soc)
{
    struct wlan_objmgr_pdev *pdev_obj;
    struct ieee80211com *ic;
    struct qldinforeq req;
    struct qld_event *q_event = NULL;
    uint32_t total_count = 0;
    uint32_t total_size;

    if (!soc)
        return -EINVAL;

    if ((qld_get_list_count(&total_count) != 0) || (total_count == 0)) {
        qdf_err("QLD: Invalid list count");
        return -EINVAL;
    }

    pdev_obj = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, 0, WLAN_MLME_SB_ID);

    if (!pdev_obj) {
        qdf_err("pdev object is NULL in FATAL_SHUTDOWN");
        return -EINVAL;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);

    if (!ic) {
      qdf_err("QLD:ic is NULL");
      wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_SB_ID);
      return -EINVAL;
    }

    /* Total size(bytes) including size of  qld_event header */
    total_size = sizeof(struct qld_event) + \
                       (total_count * sizeof(struct ol_qld_entry));
    /* Allocate total memory for qld table*/
    q_event = (struct qld_event *) qdf_mem_malloc_atomic(total_size);
    if (!q_event) {
        qdf_err("QLD: Memory allocation failed");
        wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_SB_ID);
        return -ENOMEM;
    }

    /*Zero out memory*/
    qdf_mem_set(q_event,total_size, 0);
    qdf_mem_set(&req,sizeof(req), 0);
    q_event->total_list_count = total_count;
    req.qld_event_buf = q_event;
    req.space = total_size;

    /*Iterate list to generate table*/
    qld_iterate_list(&qld_generate_table, &req);
    qdf_err("QLD: Printing table before transmit");
    qld_print_table(q_event);
    qdf_err("QLD: Calling submit command to transmit table");
    qld_submit_table(ic,&req);
    qdf_event_reset(&soc->qld_wait);
    qdf_mem_free(q_event);
    wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MLME_SB_ID);
    return 0;
}
qdf_export_symbol(qld_process_list);

/*
 * @qld_print_talbe () - Print qld table
 * @ dump_table        : qld_event pointer
 *
 * Return: None
 */
void qld_print_table(struct qld_event *dump_table)
{
    uint32_t index = 0;
    uint32_t total_list_count;
    struct ol_qld_entry *q_entry;
    struct ol_qld_entry *start;

    if (!is_qld_enable())
        return;

    if (!dump_table) {
        qdf_err("dump_table handle is NULL");
        return;
    }
    total_list_count = dump_table->total_list_count;
    start = &dump_table->qld_buffer[0];
    qdf_err("TOTAL entries are %d", total_list_count);
    while (index < total_list_count) {
        /* Position to current entry to copy */
        q_entry = &start[index];
        qdf_err("Current entry name=%s, addr=%llx, size=%d",
                q_entry->name, q_entry->addr, q_entry->size);
        index++;
    }
    qdf_err("ALL entries printed");
}
qdf_export_symbol(qld_print_table);
#endif /* QLD */
#endif
