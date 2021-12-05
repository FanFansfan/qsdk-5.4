/*
 * Copyright (c) 2011-2014,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * copyright (c) 2011 Atheros Communications Inc.
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
 * LMAC VAP specific offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include <ol_if_athpriv.h>
#include "wmi_unified_api.h"
#include "ieee80211_api.h"
#include "ieee80211_var.h"
#include "ieee80211_channel.h"
#include "umac_lmac_common.h"
#include "osif_private.h"
#include "wlan_osif_priv.h"
#include "qdf_mem.h"
#include "target_if.h"
#include "qdf_module.h"
#include "cfg_ucfg_api.h"
#include <qdf_types.h>
#include "wlan_vdev_mgr_ucfg_api.h"
#include "wlan_vdev_mgr_utils_api.h"
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_utility.h>
#include <init_deinit_ops.h>
#include <ol_if_utility.h>
#include <ol_if_led.h>

#if ATH_SUPPORT_WRAP
#include "ol_if_mat.h"
#endif

#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

#if OBSS_PD
#include <ol_if_obss.h>
#endif

#include <cdp_txrx_cmn.h>
#include <cdp_txrx_ctrl.h>
#include <cdp_txrx_wds.h>
#include <dp_txrx.h>
#include <ol_txrx_api_internal.h>
#include <ol_if_ath_api.h>

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_lmac_if_api.h>
//PRAVEEN: check two lines below
#include <wlan_tgt_def_config.h>
#include <init_deinit_lmac.h>

#include <wlan_son_pub.h>

#include "target_type.h"
#ifdef WLAN_SUPPORT_FILS
#include <target_if_fd.h>
#endif
#include <wlan_gpio_tgt_api.h>
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
#include <rawsim_api_defs.h>
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

#define RC_2_RATE_IDX(_rc)        ((_rc) & 0x7)
#ifndef HT_RC_2_STREAMS
#define HT_RC_2_STREAMS(_rc)    ((((_rc) & 0x78) >> 3) + 1)
#endif

#define ONEMBPS 1000
#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif

/*
 * WMI_ADD_CIPHER_KEY_CMDID
 */
typedef enum {
    PAIRWISE_USAGE      = 0x00,
    GROUP_USAGE         = 0x01,
    TX_USAGE            = 0x02,     /* default Tx Key - Static WEP only */
} KEY_USAGE;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
enum {
    NSS_CIPHER_UNICAST   = 0x00,
    NSS_CIPHER_MULTICAST = 0x01,
};
#endif
#define  TX_MIC_LENGTH    8
#define  RX_MIC_LENGTH    8

#define  WMI_CIPHER_NONE     0x0  /* clear key */
#define  WMI_CIPHER_WEP      0x1
#define  WMI_CIPHER_TKIP     0x2
#define  WMI_CIPHER_AES_OCB  0x3
#define  WMI_CIPHER_AES_CCM  0x4
#define  WMI_CIPHER_WAPI     0x5
#define  WMI_CIPHER_CKIP     0x6
#define  WMI_CIPHER_AES_CMAC 0x7
#define  WMI_CIPHER_ANY      0x8
#define  WMI_CIPHER_AES_GCM  0x9
#define  WMI_CIPHER_AES_GMAC 0xa

/* Enable value for bcast probe
 * response in FILS enable WMI
 */
#ifdef WLAN_SUPPORT_FILS
#define WMI_FILS_FLAGS_BITMAP_BCAST_PRB_RSP 0x1
#endif /* WLAN_SUPPORT_FILS */

extern ol_ath_soc_softc_t *ol_global_soc[GLOBAL_SOC_SIZE];
extern int ol_num_global_soc;

#define CTS2SELF_DTIM_ENABLE 0x1
#define CTS2SELF_DTIM_DISABLE 0x0

#if ATH_DEBUG
#define MODE_CTS_TO_SELF 0x32
#define MODE_RTS_CTS     0x31
#endif

#define DISA_CIPHER_SUITE_CCMP 0x04
#define DISA_KEY_LENGTH_128 16

extern int ol_ath_set_pdev_dscp_tid_map(struct ieee80211vap *vap, uint32_t val);
extern int ol_ath_ucfg_get_peer_mumimo_tx_count(wlan_if_t vaphandle,
                                                uint32_t aid);
static int wlan_get_peer_mumimo_tx_count(wlan_if_t vaphandle, uint32_t aid)
{
    return ol_ath_ucfg_get_peer_mumimo_tx_count(vaphandle, aid);
}
extern int ol_ath_ucfg_get_user_position(wlan_if_t vaphandle, uint32_t aid);
static int wlan_get_user_position(wlan_if_t vaphandle, uint32_t aid)
{
    return ol_ath_ucfg_get_user_position(vaphandle, aid);
}
extern int ieee80211_rate_is_valid_basic(struct ieee80211vap *, u_int32_t);

extern void ieee80211_vi_dbg_print_stats(struct ieee80211vap *vap);
extern int ol_ath_ucfg_reset_peer_mumimo_tx_count(wlan_if_t vaphandle,
                                                  uint32_t aid);
extern int ol_ath_net80211_get_vap_stats(struct ieee80211vap *vap);
#if MESH_MODE_SUPPORT
extern void ol_txrx_set_mesh_mode(struct cdp_vdev *vdev, u_int32_t val);
#endif
extern int ol_ath_target_start(ol_ath_soc_softc_t *soc);
extern void ol_wlan_txpow_mgmt(struct ieee80211vap *vap,u_int8_t val);
#if ATH_PERF_PWR_OFFLOAD
extern void osif_vap_setup_ol (struct ieee80211vap *vap, osif_dev *osifp);

/**
 * ol_ath_set_vap_cts2self_prot_dtim_bcn() - Enable/Disable dtim cts2self
 * @vdev: vdev object
 *
 * Return: none
 */
static void ol_ath_set_vap_cts2self_prot_dtim_bcn(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;

    if (!vdev)
        return;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return;

    /* Enable CTS-to-self */
    if (vap->iv_cts2self_prot_dtim_bcn) {
        ol_ath_wmi_send_vdev_param(vdev, wmi_vdev_param_dtim_enable_cts,
                                   CTS2SELF_DTIM_ENABLE);
    }
    else {
        ol_ath_wmi_send_vdev_param(vdev, wmi_vdev_param_dtim_enable_cts,
                                   CTS2SELF_DTIM_DISABLE);
    }
}

#if ATH_DEBUG
extern unsigned long ath_rtscts_enable;
/**
 * set_rtscts_enable() - Enables cts2self or rtscts
 * @osdev: pointer to osif dev
 *
 * Return: none
 */
void set_rtscts_enable(osif_dev *osdev)
{
    struct net_device *comdev = osdev->os_comdev;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211*)ath_netdev_priv(comdev);
    wlan_if_t vap = osdev->os_if;

    unsigned int val = ath_rtscts_enable;

    if (!vap)
        return;

    if (val != scn->rtsctsenable) {
        scn->rtsctsenable = val;
        if (val == 1) {
            /* Enable CTS-to-self */
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_enable_rtscts,
                                       MODE_CTS_TO_SELF);
        } else if(val == 2) {
            /* Enable RTS-CTS */
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_enable_rtscts,
                                       MODE_RTS_CTS);
        }
    }
}
qdf_export_symbol(set_rtscts_enable);
#endif

int ol_ath_set_vap_beacon_tx_power(struct wlan_objmgr_vdev *vdev,
                                   uint8_t tx_power)
{
    int ret = -1;

    if (vdev) {
        ret = ol_ath_wmi_send_vdev_param(vdev,
                                         wmi_vdev_param_mgmt_tx_power,
                                         tx_power);
        if (ret != EOK){
            qdf_err("Set Tx Power for beacon failed, status %d vapid %u",
                    ret, wlan_vdev_get_id(vdev));
            ret = -1;
        }
    }
    return ret;
}

int ol_ath_set_vap_pcp_tid_map(struct wlan_objmgr_vdev *vdev, uint32_t pcp,
                               uint32_t tid)
{
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic = NULL;
    QDF_STATUS ret;

    if (!vdev)
        return -EINVAL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !vap->iv_ic)
        return -EINVAL;

    ic = vap->iv_ic;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (!soc_txrx_handle)
        return -EINVAL;

    ret = cdp_set_vdev_pcp_tid_map(soc_txrx_handle,
                                   wlan_vdev_get_id(vdev),
                                   pcp, tid);
    return qdf_status_to_os_return(ret);
}

int ol_ath_set_vap_tidmap_tbl_id(struct wlan_objmgr_vdev *vdev, uint32_t mapid)
{
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic = NULL;
    cdp_config_param_type value = {0};
    QDF_STATUS ret;

    if (!vdev)
        return -EINVAL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !vap->iv_ic)
        return -EINVAL;

    ic = vap->iv_ic;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (!soc_txrx_handle)
        return -EINVAL;

    value.cdp_vdev_param_tidmap_tbl_id = mapid;
    ret = cdp_txrx_set_vdev_param(soc_txrx_handle,
                                  wlan_vdev_get_id(vdev),
                                  CDP_TIDMAP_TBL_ID, value);
    return qdf_status_to_os_return(ret);
}

int ol_ath_set_vap_tidmap_prty(struct wlan_objmgr_vdev *vdev, uint32_t val)
{
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic = NULL;
    cdp_config_param_type value = {0};
    QDF_STATUS ret;

    if (!vdev)
        return -EINVAL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !vap->iv_ic)
        return -EINVAL;

    ic = vap->iv_ic;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (!soc_txrx_handle)
        return -EINVAL;

    value.cdp_vdev_param_tidmap_prty = val;
    ret = cdp_txrx_set_vdev_param(soc_txrx_handle,
                                  wlan_vdev_get_id(vdev),
                                  CDP_TID_VDEV_PRTY, value);
    return qdf_status_to_os_return(ret);
}

int ol_ath_vdev_disa(struct wlan_objmgr_vdev *vdev,
                     struct ath_fips_cmd *fips_buf)
{
    struct disa_encrypt_decrypt_req_params param;
    struct wmi_unified *wmi_handle = NULL;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    uint8_t fc[2], i_qos[2];
    QDF_STATUS status;

    if (!vdev)
        return -EINVAL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !vap->iv_ic)
        return -EINVAL;

    ic = vap->iv_ic;

    wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!wmi_handle)
        return -EINVAL;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vdev);
    param.key_idx = fips_buf->key_idx;
    param.key_cipher = fips_buf->key_cipher;
    param.key_len = fips_buf->key_len;
    param.data_len = fips_buf->data_len;
    if ((param.key_cipher == DISA_CIPHER_SUITE_CCMP) &&
        (param.key_len == DISA_KEY_LENGTH_128))
        param.key_txmic_len = 8;
    else
        param.key_txmic_len = 16;

    fc[1] = *(fips_buf->header);
    fc[0] = *(fips_buf->header + 1);
    if (((fc[0] & 0x03) != 0x03) && (fc[1] & 0x80)) {

        const struct ieee80211_qosframe_addr4* tmp;
        qdf_info("3 addr QOS frame");

        /* Convert to 4addr format as expected by WMI */
        tmp = (const struct ieee80211_qosframe_addr4 *)(fips_buf->header);
        i_qos[1] = *(uint8_t *)(tmp->i_addr4 + 1);
        i_qos[0] = *(uint8_t *)(tmp->i_addr4);
        qdf_mem_set((uint8_t *)(tmp->i_addr4), sizeof(tmp->i_addr4), 0);
        qdf_mem_copy((uint8_t *)tmp->i_qos, i_qos, sizeof(i_qos));
        fips_buf->header_len = 32;
    }

    qdf_mem_copy(param.key_data, fips_buf->key, param.key_len);
    qdf_mem_copy(param.mac_header, fips_buf->header, fips_buf->header_len);
    qdf_mem_copy(param.pn, fips_buf->pn, fips_buf->pn_len);
    param.data = (uint8_t *)fips_buf->data;

    status = wmi_unified_encrypt_decrypt_send_cmd(wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

static inline void ol_ath_populate_bsscolor_in_vdev_param_heop(
        struct ieee80211com *ic,
        uint32_t *heop) {
#if SUPPORT_11AX_D3
            if (ic->ic_he_bsscolor_override) {
                *heop |= (((ic->ic_he_bsscolor <<
                         IEEE80211_HEOP_BSS_COLOR_S) &
                         IEEE80211_HEOP_BSS_COLOR_MASK) << HEOP_PARAM_S);
            } else {
                *heop |= (((ic->ic_bsscolor_hdl.selected_bsscolor <<
                       IEEE80211_HEOP_BSS_COLOR_S) &
                       IEEE80211_HEOP_BSS_COLOR_MASK) << HEOP_PARAM_S);
            }

            *heop |= (ic->ic_he.heop_bsscolor_info &
                    ~(IEEE80211_HEOP_BSS_COLOR_MASK
                        << IEEE80211_HEOP_BSS_COLOR_S)) << HEOP_PARAM_S;
#else
            if (ic->ic_he_bsscolor_override) {
                *heop |= ((ic->ic_he_bsscolor <<
                        IEEE80211_HEOP_BSS_COLOR_S) &
                        IEEE80211_HEOP_BSS_COLOR_MASK);
            } else {
                *heop |=((ic->ic_bsscolor_hdl.selected_bsscolor <<
                       IEEE80211_HEOP_BSS_COLOR_S) &
                       IEEE80211_HEOP_BSS_COLOR_MASK);;
            }
#endif
}

#if ATH_SUPPORT_NAC_RSSI
int
ol_ath_config_fw_for_nac_rssi(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id,
                uint8_t vdev_id, enum cdp_nac_param_cmd cmd, char *bssid, char *client_macaddr,
                uint8_t chan_num)
{
    struct vdev_scan_nac_rssi_params param;
    wmi_unified_t pdev_wmi_handle;
    QDF_STATUS status;
    struct wlan_objmgr_pdev *pdev =
           wlan_objmgr_get_pdev_by_id((struct wlan_objmgr_psoc *)psoc,
                                       pdev_id, WLAN_VDEV_TARGET_IF_ID);

    if (!pdev) {
        qdf_err("pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    qdf_mem_zero(&param, sizeof(param));
    param.vdev_id = vdev_id;

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("WMI handle is NULL");
        status = QDF_STATUS_E_FAILURE;
    } else if (CDP_NAC_PARAM_LIST == cmd) {
        struct stats_request_params list_param = {0};
        u_int8_t macaddr[QDF_MAC_ADDR_SIZE] = {0};

        list_param.vdev_id = vdev_id;
        list_param.stats_id = WMI_HOST_REQUEST_NAC_RSSI;
        status =  wmi_unified_stats_request_send(pdev_wmi_handle, macaddr, &list_param);
    } else {
        param.action = cmd;
        param.chan_num = chan_num;

        qdf_mem_copy(&param.bssid_addr, bssid,QDF_MAC_ADDR_SIZE);
        qdf_mem_copy(&param.client_addr, client_macaddr,QDF_MAC_ADDR_SIZE);
        status = wmi_unified_vdev_set_nac_rssi_send(pdev_wmi_handle, &param);
    }

    wlan_objmgr_pdev_release_ref(pdev, WLAN_VDEV_TARGET_IF_ID);

    return status;
}

int ol_ath_config_bssid_in_fw_for_nac_rssi(struct cdp_ctrl_objmgr_psoc *psoc, uint8_t pdev_id,
                                           uint8_t vdev_id, enum cdp_nac_param_cmd cmd,
                                           char *bssid, char *client_macaddr)
{
    void *pdev_wmi_handle;
    struct set_neighbour_rx_params param;
    struct ieee80211com *ic = NULL;
    QDF_STATUS status = QDF_STATUS_E_FAILURE;
    struct wlan_objmgr_pdev *pdev =
            wlan_objmgr_get_pdev_by_id((struct wlan_objmgr_psoc *)psoc,
                                        pdev_id, WLAN_VDEV_TARGET_IF_ID);

    if (!pdev) {
        qdf_err("pdev is NULL");
        return status;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        goto end;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = vdev_id;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("WMI handle is NULL");
        status = QDF_STATUS_E_FAILURE;
        goto end;
    }

    param.idx = 1;
    param.action = cmd;
    if (ic->ic_hw_nac_monitor_support) {
        param.type = IEEE80211_NAC_MACTYPE_CLIENT;
        status = wmi_unified_vdev_set_neighbour_rx_cmd_send(pdev_wmi_handle, client_macaddr, &param);
    } else {
        param.type = IEEE80211_NAC_MACTYPE_BSSID;
        status = wmi_unified_vdev_set_neighbour_rx_cmd_send(pdev_wmi_handle, bssid, &param);
    }
end:
    wlan_objmgr_pdev_release_ref(pdev, WLAN_VDEV_TARGET_IF_ID);
    return status;
}
#endif

static int
ol_ath_validate_tx_encap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        qdf_print("Configuration capability not provided for this chipset");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        qdf_print("Configuration capability available only for AP mode");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        qdf_print("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        qdf_print("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid", val);
        return 0;
    }
}

static int
ol_ath_validate_rx_decap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    /* Though the body of this function is the same as
     * ol_ath_validate_tx_encap_type(), it is kept separate for future
     * flexibility.
     */

    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        qdf_print("Configuration capability not provided for this chipset");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        qdf_print("Configuration capability available only for AP mode");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        qdf_print("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        qdf_print("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid", val);
        return 0;
    }
}

static void ol_ath_vap_iter_sta_wds_disable(void *arg, wlan_if_t vap)
{

    struct ieee80211com *ic = vap->iv_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_psoc *psoc;
    uint8_t vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)) {
        cdp_config_param_type val = {0};
        cdp_txrx_set_vdev_param(soc_txrx_handle,
           vdev_id, CDP_ENABLE_WDS, val);
        cdp_txrx_set_vdev_param(soc_txrx_handle,
           vdev_id, CDP_ENABLE_MEC, val);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops) {
            ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp, OSIF_NSS_VDEV_AST_OVERRIDE_CFG);
        }
#endif
    }
}

int ol_ath_wmi_send_sifs_trigger(struct wlan_objmgr_vdev *vdev,
                                 uint32_t param_value)
{
    struct sifs_trigger_param sparam;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;

    if (!vdev) {
        qdf_err("vdev is NULL!");
        return -EINVAL;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is NULL!");
        return -EINVAL;
    }


    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL!");
        return -EINVAL;
    }

    qdf_mem_set(&sparam, sizeof(sparam), 0);
    sparam.vdev_id = wlan_vdev_get_id(vdev);
    sparam.param_value = param_value;

    return wmi_unified_sifs_trigger_send(pdev_wmi_handle, &sparam);
}

int ol_ath_wmi_send_vdev_param(struct wlan_objmgr_vdev *vdev,
                               wmi_conv_vdev_param_id param_id,
                               uint32_t param_value)
{
    struct vdev_set_params vparam;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    QDF_STATUS status;

    if (!vdev) {
        qdf_err("vdev is NULL!");
        return -EINVAL;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is NULL!");
        return -EINVAL;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL!");
        return -EINVAL;
    }

    qdf_mem_set(&vparam, sizeof(vparam), 0);
    vparam.vdev_id = wlan_vdev_get_id(vdev);
    vparam.param_id = param_id;
    vparam.param_value = param_value;
    status = wmi_unified_vdev_set_param_send(pdev_wmi_handle, &vparam);
    return qdf_status_to_os_return(status);
}

/**
 * ol_ath_vap_sifs_trigger() - Sends sifs trigger value to fw
 * @vap: pointer to ieee80211 vap
 * @val: sifs parameter value
 *
 * Return: 0 if success, other value on failure
 */
static int ol_ath_vap_sifs_trigger(struct ieee80211vap *vap, uint32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_psoc *psoc;
    int retval = 0;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!(ol_target_lithium(psoc))) {
        vap->iv_sifs_trigger_time = val;
        retval = ol_ath_wmi_send_sifs_trigger(vap->vdev_obj, val);
    } else {
        return -EPERM;
    }
    return retval;
}

#ifdef WLAN_SUPPORT_FILS
/**
 * ol_ath_wmi_send_vdev_bcast_prbrsp_param() - configures fils parameter value
 * @pdev: pointer to pdev object
 * @vdev_id: vdev id
 * @param_value: fils parameter value
 *
 * Return: 0 if success, other value on failure
 */
static int
ol_ath_wmi_send_vdev_bcast_prbrsp_param(struct wlan_objmgr_pdev *pdev,
                                        uint8_t vdev_id,
                                        uint32_t param_value)
{
    struct config_fils_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = vdev_id;
    param.fd_period = param_value;
    if (param_value)
        param.send_prb_rsp_frame = WMI_FILS_FLAGS_BITMAP_BCAST_PRB_RSP;
    else
        param.send_prb_rsp_frame = 0;
    return wmi_unified_fils_vdev_config_send_cmd(pdev_wmi_handle, &param);
}

static QDF_STATUS ol_ath_fd_tmpl_update(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    QDF_STATUS ret = 0;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn)
        return QDF_STATUS_E_FAILURE;

    qdf_spin_lock_bh(&avn->avn_lock);
    ret = target_if_fd_tmpl_update(vdev);
    qdf_spin_unlock_bh(&avn->avn_lock);

    if (ret < 0)
        qdf_debug("FD template update failed");

    return ret;
}
#endif /* WLAN_SUPPORT_FILS */

/* Assemble rate code in lithium format from legacy rate code */
static inline uint32_t asemble_ratecode_lithium(uint32_t rate_code)
{
    uint8_t preamble, nss, rix;

    rix = rate_code & RATECODE_V1_RIX_MASK;
    nss = (rate_code >> RATECODE_V1_NSS_OFFSET) &
                                RATECODE_V1_NSS_MASK;
    preamble = rate_code >> RATECODE_V1_PREAMBLE_OFFSET;

    return ASSEMBLE_RATECODE_V1(rix, nss, preamble);
}

/* Assemble rate code in legacy format */
static inline uint32_t assemble_ratecode_legacy(uint32_t rate_code)
{
    uint8_t preamble, nss, rix;

    rix = rate_code & RATECODE_LEGACY_RIX_MASK;
    nss = (rate_code >> RATECODE_LEGACY_NSS_OFFSET) &
                                RATECODE_LEGACY_NSS_MASK;
    preamble = rate_code >> RATECODE_LEGACY_PREAMBLE_OFFSET;

    return ASSEMBLE_RATECODE_LEGACY(rix, nss, preamble);
}

uint32_t ol_ath_assemble_ratecode(struct ieee80211vap *vap,
                                  struct ieee80211_ath_channel *cur_chan,
                                  uint32_t rate)
{
    struct wlan_objmgr_psoc *psoc;
    int value;
    psoc = wlan_vdev_get_psoc(vap->vdev_obj);

    if (!cur_chan)
        return 0;

    value = ol_get_rate_code(cur_chan, rate);
    if (value == EINVAL)
       return  0;

    if (ol_target_lithium(psoc))
        return asemble_ratecode_lithium(value);
    else
        return assemble_ratecode_legacy(value);
}

/**
 * ol_ath_vap_set_qdepth_thresh: Send MSDUQ depth threshold values
 * to the firmware through the WMI interface
 * @vap: Pointer to the vap
 * @mac_addr: Pointer to the MAC address array
 * @tid: TID number
 * @update_mask: amsduq update mask
 * @thresh_val: qdepth threshold value
 *
 * Return: 0 on success, other values on failure
 */
static int
ol_ath_vap_set_qdepth_thresh(struct ieee80211vap *vap,
                             uint8_t *mac_addr, uint32_t tid,
                             uint32_t update_mask, uint32_t thresh_val)
{
    struct set_qdepth_thresh_params param = {0};
    struct wmi_unified *pdev_wmi_handle;
    struct wlan_objmgr_pdev *pdev = NULL;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -EINVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -EINVAL;
    }

    param.pdev_id = lmac_get_pdev_idx(pdev);
    param.vdev_id  = wlan_vdev_get_id(vap->vdev_obj);
    qdf_mem_copy(param.mac_addr, mac_addr, QDF_MAC_ADDR_SIZE);
    param.update_params[0].tid_num = tid;
    param.update_params[0].msduq_update_mask = update_mask;
    param.update_params[0].qdepth_thresh_value = thresh_val;
    /* Sending in one update */
    param.num_of_msduq_updates = 1;

    status = wmi_unified_vdev_set_qdepth_thresh_cmd_send(pdev_wmi_handle,
                                                         &param);
    return qdf_status_to_os_return(status);
}

/**
 * ol_ath_vap_config_tid_latency_param: Send tid latency params
 * to the firmware through the WMI interface
 * @vap: Pointer to the vap
 * @service_interval: Service interval in miliseconds
 * @burst_size: Burst size in bytes
 * @latency_tid: TID number associated with latency parameters
 * @dl_ul_enable: This flag indicates DL or UL TID to enable
 *
 * Return: 0 on success, other values on failure
 */
int
ol_ath_vap_config_tid_latency_param(struct ieee80211vap *vap,
                                    uint32_t service_interval,
                                    uint32_t burst_size,
                                    uint32_t latency_tid,
                                    uint8_t dl_ul_enable)
{
    struct wmi_vdev_tid_latency_config_params param = {0};
    struct wmi_unified *pdev_wmi_handle;
    struct wlan_objmgr_pdev *pdev = NULL;
    QDF_STATUS status;
    uint8_t ac;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -EINVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -EINVAL;
    }

    param.pdev_id = lmac_get_pdev_idx(pdev);
    param.vdev_id  = wlan_vdev_get_id(vap->vdev_obj);
    param.latency_info[0].service_interval= service_interval;
    param.latency_info[0].burst_size = burst_size;
    param.latency_info[0].latency_tid = latency_tid;
    if (dl_ul_enable == WLAN_LATENCY_OPTIMIZED_DL_TID_SCHEDULING) {
        param.latency_info[0].dl_enable = 1;
    } else if (dl_ul_enable == WLAN_LATENCY_OPTIMIZED_UL_TID_SCHEDULING) {
        param.latency_info[0].ul_enable = 1;
    }

    ac = TID_TO_WME_AC(latency_tid);
    param.latency_info[0].ac = ac;

   /* Sending in one vdev update */
    param.num_vdev = 1;

    status = wmi_unified_config_vdev_tid_latency_info_cmd_send(
                               pdev_wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

/* Vap interface functions */
static int
ol_ath_vap_set_param(struct ieee80211vap *vap,
                     ieee80211_param param, uint32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_psoc *psoc;
    int retval = 0;
    struct wlan_vdev_mgr_cfg mlme_cfg;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    uint8_t vdev_id;
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);
#if UMAC_VOW_DEBUG
    int ii;
#endif
    uint32_t iv_nss;
    uint8_t sniffer_mode = 0;
    cdp_config_param_type value = {0};

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    /* Set the VAP param in the target */
    switch (param) {

        case IEEE80211_ATIM_WINDOW:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_atim_window,
                                                val);
        break;
        case IEEE80211_BMISS_COUNT_RESET:
         /* this is mainly under assumsion that if this number of  */
         /* beacons are not received then HW is hung anf HW need to be resett */
         /* target will use its own method to detect and reset the chip if required. */
            retval = 0;
        break;

        case IEEE80211_BMISS_COUNT_MAX:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_bmiss_count_max,
                                                val);
        break;
        case IEEE80211_FEATURE_WMM:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_feature_wmm,
                                                val);
        break;
        case IEEE80211_FEATURE_WDS:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_wds, val);

            if (retval == EOK) {
                /* For AP mode, keep WDS always enabled */
                if ((ieee80211vap_get_opmode(vap) != IEEE80211_M_HOSTAP)) {
                    cdp_config_param_type value = {0};

                    value.cdp_vdev_param_wds = val;
                    cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                                            CDP_ENABLE_WDS, value);
                    value.cdp_vdev_param_mec = val;
                    cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                                            CDP_ENABLE_MEC, value);
               /* DA_WAR is enabled by default within DP in AP mode,
                * for Hawkeye v1.x
                */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                    if (ic->nss_vops)
                        ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)
                                                               vap->iv_ifp,
                                                               OSIF_NSS_VDEV_WDS_CFG);
#endif
                }
            }
        break;
        case IEEE80211_CHWIDTH:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_chwidth, val);
        break;
        case IEEE80211_SIFS_TRIGGER_RATE:
            if (!(ol_target_lithium(psoc))) {
                vap->iv_sifs_trigger_rate = val;
                ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                           wmi_vdev_param_sifs_trigger_rate,
                                           val);
            } else {
                 return -EPERM;
            }
        break;
        case IEEE80211_FIXED_RATE:
            {
                u_int8_t preamble, nss, rix;
                /* Note: Event though val is 32 bits, only the lower 8 bits matter */
                if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_NONE) {
                    val = WMI_HOST_FIXED_RATE_NONE;
                }
                else {
                    rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);
                    if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_MCS) {
                        preamble = WMI_HOST_RATE_PREAMBLE_HT;
                        nss = HT_RC_2_STREAMS(vap->iv_fixed_rateset) -1;
                    }
                    else {
                        nss = 0;
                        rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);

                        if (vap->iv_fixed_rateset & 0x10) {
                            if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                                preamble = WMI_HOST_RATE_PREAMBLE_CCK;
                                if(rix != 0x3)
                                    /* Enable Short preamble always for CCK except 1mbps*/
                                    rix |= 0x4;
                            }
                            else {
                                qdf_err("Invalid, 5G does not support CCK");
                                return -EINVAL;
                            }
                        }
                        else {
                            preamble = WMI_HOST_RATE_PREAMBLE_OFDM;
                        }
                    }

                    if (ol_target_lithium(psoc)) {
                        val = ASSEMBLE_RATECODE_V1(rix, nss, preamble);
                        qdf_info("Legacy/HT fixed rate value: 0x%x", val);
                    } else {
                        val = ASSEMBLE_RATECODE_LEGACY(rix, nss, preamble);
                    }

                }
                retval =
                    ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                               wmi_vdev_param_fixed_rate, val);
           }
        break;
        case IEEE80211_FIXED_VHT_MCS:
            if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_VHT) {
                wlan_util_vdev_mlme_get_param(vdev_mlme,
                        WLAN_MLME_CFG_NSS, &iv_nss);
                if (ol_target_lithium(psoc)) {
                    val = ASSEMBLE_RATECODE_V1(vap->iv_vht_fixed_mcs, iv_nss-1,
                          WMI_HOST_RATE_PREAMBLE_VHT);
                    qdf_info("VHT fixed rate value: 0x%x", val);
                } else {
                    val = ASSEMBLE_RATECODE_LEGACY(vap->iv_vht_fixed_mcs,
                                                 (iv_nss - 1),
                                                 WMI_HOST_RATE_PREAMBLE_VHT);
                }
            } else {
                 /* Note: Even though val is 32 bits, only the lower 8 bits matter */
                 val = WMI_HOST_FIXED_RATE_NONE;
            }
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_fixed_rate, val);
        break;
        case IEEE80211_FIXED_HE_MCS:
            if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_HE) {
                wlan_util_vdev_mlme_get_param(vdev_mlme,
                        WLAN_MLME_CFG_NSS, &iv_nss);
                val = ASSEMBLE_RATECODE_V1(vap->iv_he_fixed_mcs, iv_nss-1,
                                           WMI_HOST_RATE_PREAMBLE_HE);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE , "%s : HE Fixed Rate %d \n",
                                    __func__, val);
            }
            else {
                /* Note: Even though val is 32 bits, only lower 8 bits matter */
                val = WMI_HOST_FIXED_RATE_NONE;
            }

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_fixed_rate, val);
        break;
        case IEEE80211_FEATURE_APBRIDGE:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_intra_bss_fwd,
                                                val);
            if (retval == EOK) {
                value.cdp_vdev_param_ap_brdg_en = val;
                if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_ENABLE_AP_BRIDGE, value)
                                            != QDF_STATUS_SUCCESS)
                    return -1;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_vops) {
                    ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp, OSIF_NSS_VDEV_AP_BRIDGE_CFG);
                }
#endif
            }
        break;

        case IEEE80211_SHORT_GI:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_sgi, val);
            qdf_info("Setting SGI value: %d", val);
        break;

        case IEEE80211_SECOND_CENTER_FREQ :
            if (ic->ic_modecaps &
                    ((1 << IEEE80211_MODE_11AC_VHT80_80) |
                     (1ULL << IEEE80211_MODE_11AXA_HE80_80))) {
                if (ieee80211_is_phymode_8080(vap->iv_des_mode)) {
                    vap->iv_des_cfreq2 = val;

                    qdf_print("Desired cfreq2 is %d. Please set primary 20 MHz "
                              "channel for cfreq2 setting to take effect",
                              vap->iv_des_cfreq2);
                } else {
                    qdf_print("Command inapplicable for this mode");
                    return -EINVAL;
                }
            } else {
                qdf_print("Command inapplicable because 80+80 MHz capability "
                          "is not available");
                return -EINVAL;
            }

        break;

        case IEEE80211_SUPPORT_TX_STBC:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_tx_stbc, val);
        break;

        case IEEE80211_SUPPORT_RX_STBC:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_rx_stbc, val);
        break;

        case IEEE80211_CONFIG_HE_UL_SHORTGI:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_shortgi, val);
        break;

        case IEEE80211_CONFIG_HE_UL_LTF:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_he_ltf, val);
        break;

        case IEEE80211_CONFIG_HE_UL_NSS:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_nss, val);
        break;

        case IEEE80211_CONFIG_HE_UL_PPDU_BW:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_ppdu_bw, val);
        break;

        case IEEE80211_CONFIG_HE_UL_LDPC:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_ldpc, val);
        break;

        case IEEE80211_CONFIG_HE_UL_STBC:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_stbc, val);
        break;

        case IEEE80211_CONFIG_HE_UL_FIXED_RATE:
            val = ASSEMBLE_RATECODE_V1(vap->iv_he_ul_fixed_rate, vap->iv_he_ul_nss-1,
                                       WMI_HOST_RATE_PREAMBLE_HE);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE , "%s : HE UL Fixed Rate %d \n",
                              __func__, val);
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_ul_fixed_rate,
                                                val);
        break;

        case IEEE80211_DEFAULT_KEYID:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_def_keyid, val);
        break;
#if UMAC_SUPPORT_PROXY_ARP
        case IEEE80211_PROXYARP_CAP:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_mcast_indicate,
                                                val);
            retval |= ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                 wmi_vdev_param_dhcp_indicate,
                                                 val);
        break;
#endif /* UMAC_SUPPORT_PROXY_ARP */
        case IEEE80211_MCAST_RATE:
        {
            struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mcast_rate_config_defered = TRUE;
                qdf_info("Configuring MCAST RATE is deffered as channel is not yet set for VAP");
                break;
            }
            if (IEEE80211_IS_CHAN_5GHZ_6GHZ(chan) && (val < 6000)) {
                qdf_err("MCAST RATE should be at least 6000(kbps) for 5G");
                retval = -EINVAL;
                break;
            }

            if (!ieee80211_rate_is_valid_basic(vap,val)) {
                qdf_err("rate %d is not valid.",val);
                retval = EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if (value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            if (ol_target_lithium(psoc)) {
                value = asemble_ratecode_lithium(value);
            }
            else {
                value = assemble_ratecode_legacy(value);
            }

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_mcast_data_rate,
                                                value);
            if (!retval) {
                vap->iv_mcast_rate_config_defered = FALSE;
                qdf_info("Now supported MCAST RATE %d(kbps), rate code: 0x%x",
                         val, value);
            }
        }
        break;
        case IEEE80211_BCAST_RATE:
        {
            struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_bcast_rate_config_defered = TRUE;
                qdf_info("Configuring BCAST RATE is deffered as channel is not yet set for VAP");
                break;
            }
            if (IEEE80211_IS_CHAN_5GHZ_6GHZ(chan) && (val < 6000)) {
                qdf_err("BCAST RATE should be at least 6000(kbps) for 5G");
                retval = -EINVAL;
                break;
            }

            if (!ieee80211_rate_is_valid_basic(vap,val)) {
                qdf_err("rate %d is not valid.",val);
                retval = EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            if (ol_target_lithium(psoc)) {
                value = asemble_ratecode_lithium(value);
            }
            else {
                value = assemble_ratecode_legacy(value);
            }

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_bcast_data_rate,
                                                value);
            if (!retval) {
                vap->iv_bcast_rate_config_defered = FALSE;
                qdf_info("Now supported BCAST RATE is %d(kbps) rate code: 0x%x",
                         val, value);
            }
        }
        break;
        case IEEE80211_MGMT_RATE:
        {
            struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mgt_rate_config_defered = TRUE;
                qdf_info("Configuring MGMT RATE is deffered as channel is not yet set for VAP");
                break;
            }
            if (IEEE80211_IS_CHAN_5GHZ_6GHZ(chan) && (val < 6000)) {
                qdf_err("MGMT RATE should be at least 6000(kbps) for 5G");
                retval = EINVAL;
                break;
            }
            if (!ieee80211_rate_is_valid_basic(vap,val)) {
                qdf_err("rate %d is not valid", val);
                retval = EINVAL;
                break;
            }
            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = EINVAL;
                break;
            }
            if (ol_target_lithium(psoc)) {
                value = asemble_ratecode_lithium(value);
            }
            else {
                value = assemble_ratecode_legacy(value);
            }

            mlme_cfg.value = value;
            retval = vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_TX_MGMT_RATE_CODE, mlme_cfg);
            if (qdf_status_to_os_return(retval) == 0) {
                vap->iv_mgt_rate_config_defered = FALSE;
                QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_INFO,
                          "vdev[%d]: Mgt Rate:%d(kbps)",
                          wlan_vdev_get_id(vap->vdev_obj), val);
            }
#ifdef WLAN_SUPPORT_FILS
            if((retval >= 0) && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
                !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                retval = ol_ath_fd_tmpl_update(vap->vdev_obj);
            }
#endif /* WLAN_SUPPORT_FILS */
        }
        break;
        case IEEE80211_RTSCTS_RATE:
        {
            struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int rtscts_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                qdf_print("Configuring  RATE for RTS and CTS is deffered as channel is not yet set for VAP ");
                break;
            }

            if (!ieee80211_rate_is_valid_basic(vap,val)) {
                qdf_err("Rate %d is not valid. ", val);
                retval = EINVAL;
                break;
            }
            rtscts_rate = ol_get_rate_code(chan, val);
            if (rtscts_rate == EINVAL) {
                retval = EINVAL;
                break;
            }
            if (ol_target_lithium(psoc)) {
                rtscts_rate = asemble_ratecode_lithium(rtscts_rate);
            }
            else {
                rtscts_rate = assemble_ratecode_legacy(rtscts_rate);
            }
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_rts_fixed_rate,
                                                rtscts_rate);
            if (!retval)
                qdf_info("Now supported CTRL RATE is:%d kbps, rate code:0x%x",
                         val, rtscts_rate);
        }
        break;
        case IEEE80211_NON_BASIC_RTSCTS_RATE:
        {
            struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int rtscts_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                qdf_info("Configuring  RATE for RTS and CTS is deffered as channel is not yet set for VAP ");
                break;
            }

            rtscts_rate = ol_get_rate_code(chan, val);
            if (rtscts_rate == EINVAL) {
                retval = EINVAL;
                break;
            }
            if (ol_target_lithium(psoc)) {
                rtscts_rate = asemble_ratecode_lithium(rtscts_rate);
            }
            else {
                rtscts_rate = assemble_ratecode_legacy(rtscts_rate);
            }
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_rtscts_rate,
                                                rtscts_rate);
            if (!retval)
                qdf_info("Now supported RTS/CTS RATE is:%d kbps, rate code:0x%x",
                         val, rtscts_rate);
        }
        break;
        case IEEE80211_BEACON_RATE_FOR_VAP:
        {
            struct ieee80211_ath_channel *chan = vap->iv_bsschan;
            int beacon_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                qdf_print("Configuring Beacon Rate is deffered as channel is not yet set for VAP ");
                retval = EINVAL;
                break;
            }

            beacon_rate = ol_get_rate_code(chan, val);
            if(beacon_rate == EINVAL) {
                retval = EINVAL;
                break;
            }

            if (ol_target_lithium(psoc)) {
                /* convert beacon's rate code for 8074 */
                beacon_rate = asemble_ratecode_lithium(beacon_rate);
            }
            else {
                beacon_rate = assemble_ratecode_legacy(beacon_rate);
            }
            mlme_cfg.value = beacon_rate;
            retval = vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_BCN_TX_RATE_CODE, mlme_cfg);
        }
        break;

        case IEEE80211_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
		break;
        case IEEE80211_VHT_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
        break;

        case IEEE80211_VHT_SUBFEE:
        case IEEE80211_VHT_MUBFEE:
        case IEEE80211_VHT_SUBFER:
        case IEEE80211_VHT_MUBFER:
        case IEEE80211_VHT_BF_STS_CAP:
        case IEEE80211_SUPPORT_IMPLICITBF:
        case IEEE80211_VHT_BF_SOUNDING_DIM:
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_TXBF_CAPS, mlme_cfg);
        break;
#if ATH_SUPPORT_IQUE
        case IEEE80211_ME:

        value.cdp_vdev_param_mcast_en = val;
        {
            if (val != MC_AMSDU_ENABLE) {
                value.cdp_vdev_param_igmp_mcast_en = 0;

                qdf_info("Implicitly disabling dependant feature igmp ME");
                if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                    CDP_ENABLE_IGMP_MCAST_EN, value) == QDF_STATUS_SUCCESS) {
                    dp_set_igmp_me_mode(soc_txrx_handle, vdev_id, 0, NULL);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                    if (ic->nss_vops) {
                        ic->nss_vops->ic_osif_nss_vdev_set_cfg(vap->iv_ifp, OSIF_NSS_VDEV_ENABLE_IGMP_ME);
                    }
#endif
                    break;
                }
            }
#if ATH_MCAST_HOST_INSPECT
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_mcast_indicate,
                                                val);
#endif/*ATH_MCAST_HOST_INSPECT*/
        }
	break;

        case IEEE80211_IGMP_ME:

        value.cdp_vdev_param_mcast_en = 0;
	retval = EINVAL;

	if (val == 1) {
            if (dp_get_me_mode(soc_txrx_handle, vdev_id) != MC_AMSDU_ENABLE) {
                qdf_err("Unable to enable feature igmp ME as mcastenhance value is not 6");
	        break;
	    }
	} else if (val != 0) {
                qdf_err("Only values 1 and 0 are acceptable");
	        break;
	}

        value.cdp_vdev_param_igmp_mcast_en = val;

        cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_ENABLE_IGMP_MCAST_EN, value);
        dp_set_igmp_me_mode(soc_txrx_handle, vdev_id, val, vap->iv_myaddr);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops) {
                ic->nss_vops->ic_osif_nss_vdev_set_cfg(vap->iv_ifp, OSIF_NSS_VDEV_ENABLE_IGMP_ME);
        }
#endif
	retval = 0;

        break;
#endif /* ATH_SUPPORT_IQUE */

        case IEEE80211_ENABLE_RTSCTS:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_enable_rtscts, val);
        break;
        case IEEE80211_RC_NUM_RETRIES:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_rc_num_retries,
                                       vap->iv_rc_num_retries);
        break;
#if WDS_VENDOR_EXTENSION
        case IEEE80211_WDS_RX_POLICY:
            if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
                (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)) {
                if (cdp_set_wds_rx_policy(soc_txrx_handle,
                                      vdev_id, val & WDS_POLICY_RX_MASK) != QDF_STATUS_SUCCESS)
                    return -EINVAL;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_radio_ops) {
                    struct wlan_objmgr_peer *peer =
                                wlan_objmgr_vdev_try_get_bsspeer(vap->vdev_obj, WLAN_MLME_NB_ID);
                    /*
                     * Send the WDS vendor policy configuration to NSS FW
                     */
                    if (!peer) {
                        qdf_err("Cound not find bss peer for vdev %pK", vap->vdev_obj);
                        return -EINVAL;
                    }
                    ic->nss_radio_ops->ic_nss_ol_wds_extn_peer_cfg_send(scn, peer->macaddr, vdev_id);
                    wlan_objmgr_peer_release_ref(peer, WLAN_MLME_NB_ID);
                }
#endif
            }
        break;
#endif
        case IEEE80211_FEATURE_HIDE_SSID:
             if(val) {
                 if(!IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_ENABLE(vap);

                     /* node corresponding to this vap may need an update
                      * for the ssid field
                      */
                     mbss_debug("setting non_tx_profile_change to true"
                                " for vdev: %d", vap->iv_unit);
                     vap->iv_mbss.non_tx_profile_change = true;
                     ieee80211_mbssid_update_mbssie_cache_entry(vap,
                             MBSS_CACHE_ENTRY_SSID);
                 }
             } else {
                 if(IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_DISABLE(vap);

                     /* node corresponding to this vap may need an update
                      * for the ssid field
                      */
                     mbss_debug("setting non_tx_profile_change to true"
                                " for vdev: %d", vap->iv_unit);
                     vap->iv_mbss.non_tx_profile_change = true;
                     ieee80211_mbssid_update_mbssie_cache_entry(vap,
                             MBSS_CACHE_ENTRY_SSID);
                 }
             }

             retval = 0;
             break;
        case IEEE80211_FEATURE_PRIVACY:
             if(val) {
                 if(!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_ENABLE(vap);
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
                     wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
                 }
             } else {
                 if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_DISABLE(vap);
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
                     wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
                 }
             }

             retval = 0;
             break;
        case IEEE80211_FEATURE_DROP_UNENC:
             if(val) {
                if(!IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_ENABLE(vap);
                }
             } else {
                if(IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_DISABLE(vap);
                }
             }
             mlme_cfg.value = val;
             value.cdp_vdev_param_drop_unenc = val;
             if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_DROP_UNENC, value)
                 != QDF_STATUS_SUCCESS) {
                 retval = EINVAL;
                 break;
             }
             wlan_util_vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_DROP_UNENCRY,
                     mlme_cfg);
             retval = 0;
             break;
        case IEEE80211_SHORT_PREAMBLE:
            if (val) {
                if (!IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                    IEEE80211_ENABLE_SHPREAMBLE(ic);
                }
            } else {
                if (IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                    IEEE80211_DISABLE_SHPREAMBLE(ic);
                }
            }
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_preamble,
                                       (val) ? WMI_HOST_VDEV_PREAMBLE_SHORT :
                                        WMI_HOST_VDEV_PREAMBLE_LONG);
            retval = 0;
            break;
        case IEEE80211_PROTECTION_MODE:
            if (val)
                IEEE80211_ENABLE_PROTECTION(ic);
            else
                IEEE80211_DISABLE_PROTECTION(ic);
            ic->ic_protmode = val;
            ieee80211_set_protmode(ic);
            retval = 0;
            break;
        case IEEE80211_SHORT_SLOT:
            mlme_cfg.value = !!val;
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_SLOT_TIME, mlme_cfg);
            ieee80211_set_shortslottime(ic, mlme_cfg.value);
            wlan_pdev_beacon_update(ic);
            retval = 0;
            break;

        case IEEE80211_SET_CABQ_MAXDUR:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_cabq_maxdur, val);
        break;

        case IEEE80211_FEATURE_MFP_TEST:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_mfptest_set, val);
        break;

        case IEEE80211_VHT_SGIMASK:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_vht_sgimask, val);
        break;

        case IEEE80211_VHT80_RATEMASK:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_vht80_ratemask, val);
        break;

        case IEEE80211_VAP_RX_DECAP_TYPE:
        {
            if (!ol_ath_validate_rx_decap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                mlme_cfg.value = val;
                retval = wlan_util_vdev_mlme_set_param(vdev_mlme,
                                         WLAN_MLME_CFG_RX_DECAP_TYPE, mlme_cfg);

                if (retval == 0) {
                    vap->iv_rx_decap_type = val;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
                    wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
                } else
                    qdf_print("Error %d setting param "
                           "WMI_VDEV_PARAM_RX_DECAP_TYPE with val %u",
                           retval,
                           val);
                }
        }
        break;

        case IEEE80211_VAP_TX_ENCAP_TYPE:
        {
            if (!ol_ath_validate_tx_encap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                mlme_cfg.value = val;
                retval = wlan_util_vdev_mlme_set_param(vdev_mlme,
                                         WLAN_MLME_CFG_TX_ENCAP_TYPE, mlme_cfg);

                if (retval == 0) {
                    vap->iv_tx_encap_type = val;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
                    wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
                } else {
                    qdf_print("Error %d setting param "
                           "WMI_VDEV_PARAM_TX_ENCAP_TYPE with val %u",
                           retval,
                           val);
                }
            }
        }
        break;

        case IEEE80211_BW_NSS_RATEMASK:
            ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                       wmi_vdev_param_bw_nss_ratemask, val);
        break;

        case IEEE80211_RX_FILTER_MONITOR:
             value.cdp_pdev_param_fltr_ucast = ic->mon_filter_ucast_data;
             cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_UCAST_DATA, value);
             value.cdp_pdev_param_fltr_mcast = ic->mon_filter_mcast_data;
             cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_MCAST_DATA, value);
             value.cdp_pdev_param_fltr_none = ic->mon_filter_non_data;
             cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_NO_DATA, value);
        break;

#if ATH_SUPPORT_NAC
        case IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR:
             value.cdp_pdev_param_fltr_neigh_peers = val;
             cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_NEIGH_PEERS, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
             if (ic->nss_radio_ops)
                 ic->nss_radio_ops->ic_nss_set_cmd(scn, OSIF_NSS_WIFI_FILTER_NEIGH_PEERS_CMD);
#endif
             IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s: Monitor Invalid Peers Filter Set Val=%d \n", __func__, val);
        break;
#endif
        case IEEE80211_TXRX_VAP_STATS:
        {
            qdf_nofl_info("Get vap stats\n");
            ol_ath_net80211_get_vap_stats(vap);
            break;
        }
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_CLR_RAWMODE_PKT_SIM_STATS:
        wlan_rawsim_api_clear_stats
                (dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id));
	break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    case IEEE80211_TXRX_DBG_SET:
        cdp_debug(soc_txrx_handle, vdev_id, val);
        break;
    case IEEE80211_PEER_MUMIMO_TX_COUNT_RESET_SET:
        if (val <= 0) {
            qdf_err("Invalid AID value");
            return -EINVAL;
        }
        retval = ol_ath_ucfg_reset_peer_mumimo_tx_count(vap, val);
        break;
    case IEEE80211_RATE_DROPDOWN_SET:
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                  "%s:Rate Control Logic Hex Value: 0x%X\n", __func__, val);
        retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                            wmi_vdev_param_rate_dropdown_bmap,
                                            val);
        break;
    case IEEE80211_TX_PPDU_LOG_CFG_SET:
        if (cdp_fw_stats_cfg(soc_txrx_handle, vdev_id, HTT_DBG_CMN_STATS_TX_PPDU_LOG, val)
                             != QDF_STATUS_SUCCESS)
            return -EINVAL;

        break;
    case IEEE80211_TXRX_FW_STATS:
        {
            struct ol_txrx_stats_req req = {0};
            wlan_dev_t ic = vap->iv_ic;
            struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
            uint32_t target_type = lmac_get_tgt_type(scn->soc->psoc_obj);
#if (UMAC_SUPPORT_VI_DBG || UMAC_VOW_DEBUG)
            osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
#endif
            /*Dont pass to avoid TA */
            if ((lmac_is_target_ar900b(scn->soc->psoc_obj) == false) &&
                    (val > TXRX_FW_STATS_VOW_UMAC_COUNTER) &&
                    (target_type != TARGET_TYPE_QCA8074) &&
                    (target_type != TARGET_TYPE_QCA8074V2) &&
                    (target_type != TARGET_TYPE_QCA6018) &&
                    (target_type != TARGET_TYPE_QCA5018) &&
                    (target_type != TARGET_TYPE_QCN6122) &&
                    (target_type != TARGET_TYPE_QCN9000)) {
                     qdf_print("Not supported.");
                     return -EINVAL;
                }

            req.print.verbose = 1; /* default */

            /*
             * Backwards compatibility: use the same old input values, but
             * translate from the old values to the corresponding new bitmask
             * value.
             */
            if (val <= TXRX_FW_STATS_RX_RATE_INFO) {
                req.stats_type_upload_mask = 1 << (val - 1);
                if (val == TXRX_FW_STATS_TXSTATS) {
                    /* mask 17th bit as well to get extended tx stats */
                    req.stats_type_upload_mask |= (1 << 17);
                }
            } else if (val == TXRX_FW_STATS_PHYSTATS) {
                qdf_nofl_info("Value 4 for txrx_fw_stats is obsolete \n");
                break;
            } else if (val == TXRX_FW_STATS_PHYSTATS_CONCISE) {
                /*
                 * Stats request 5 is the same as stats request 4,
                 * but with only a concise printout.
                 */
                req.print.concise = 1;
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_PHYSTATS - 1);
            }
            else if (val == TXRX_FW_STATS_TX_RATE_INFO) {
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_RATE_INFO - 2);
            }
            else if (val == TXRX_FW_STATS_TID_STATE) { /* for TID queue stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TID_STATE - 2);
            }
            else if (val == TXRX_FW_STATS_TXBF_INFO) { /* for TxBF stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TXBF_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_ERROR_INFO) { /* for TxRx error stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_ERROR_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
            }
            else if (val == TXRX_FW_SIFS_RESP_INFO) { /* for SIFS RESP stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_SIFS_RESP_INFO - 7);
            }
            else if (val == TXRX_FW_RESET_STATS) { /*for  Reset stats info*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_RESET_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_WDOG_STATS) { /*for  wdog stats info*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_WDOG_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_DESC_STATS) { /*for fw desc stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_DESC_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_FETCH_MGR_STATS) { /*for fetch mgr stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_FETCH_MGR_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_PREFETCH_MGR_STATS) { /*for prefetch mgr stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_PREFETCH_MGR_STATS - 7);
            } else if (val  == TXRX_FW_COEX_STATS) { /* for coex stats */
                req.stats_type_upload_mask = 1 << (TXRX_FW_COEX_STATS - 8);
            } else if (val == TXRX_FW_HALPHY_STATS) { /*for fetch halphy stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_HALPHY_STATS - 8);
            }


#ifdef WLAN_FEATURE_FASTPATH
            /* Get some host stats */
            /* Piggy back on to fw stats command */
            /* TODO : Separate host / fw commands out */
            if (val == TXRX_FW_STATS_HOST_STATS) {
                cdp_host_stats_get(soc_txrx_handle, vdev_id, &req);
            } else if (val == TXRX_FW_STATS_CLEAR_HOST_STATS) {
                if (cdp_host_stats_clr(soc_txrx_handle, vdev_id) != QDF_STATUS_SUCCESS)
                    return -EINVAL;
            } else if (val == TXRX_FW_STATS_CE_STATS) {
                qdf_nofl_info("Value 10 for txrx_fw_stats is obsolete \n");
                break;
#if ATH_SUPPORT_IQUE
            } else if (val == TXRX_FW_STATS_ME_STATS) {
                cdp_host_me_stats(soc_txrx_handle, vdev_id);
#endif
            } else if (val <= TXRX_FW_MAC_PREFETCH_MGR_STATS || val <= TXRX_FW_COEX_STATS)
#endif /* WLAN_FEATURE_FASTPATH */
                {
                    cdp_fw_stats_get(soc_txrx_handle, vdev_id, &req, PER_RADIO_FW_STATS_REQUEST, 0);
#if PEER_FLOW_CONTROL
                    /* MSDU TTL host display */
                    if(val == 1) {
                        if (cdp_host_msdu_ttl_stats(soc_txrx_handle, vdev_id, &req) != QDF_STATUS_SUCCESS)
                            return -EINVAL;
                    }
#endif
                }

            if (val == TXRX_FW_STATS_DURATION_INFO) {
               scn->tx_rx_time_info_flag = 1;
               ic->ic_ath_bss_chan_info_stats(ic, 1);
               break;
            }

            if (val == TXRX_FW_STATS_DURATION_INFO_RESET) {
               scn->tx_rx_time_info_flag = 1;
               ic->ic_ath_bss_chan_info_stats(ic, 2);
               break;
            }

#if UMAC_SUPPORT_VI_DBG
            if( osifp->vi_dbg) {
                if(val == TXRX_FW_STATS_VOW_UMAC_COUNTER)
                    {
                        ieee80211_vi_dbg_print_stats(vap);
                    }
            }
#elif UMAC_VOW_DEBUG

            if( osifp->vow_dbg_en) {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                osif_nss_vdev_get_vow_dbg_stats(osifp);
#endif
                if(val == TXRX_FW_STATS_RXSTATS)
                    {
                        qdf_nofl_info(" %lu VI/mpeg streamer pkt Count recieved at umac\n", osifp->umac_vow_counter);
                    }
                else if( val == TXRX_FW_STATS_VOW_UMAC_COUNTER ) {

                    for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
                        {
                            qdf_nofl_info(" %lu VI/mpeg stream pkt txed at umac for peer %d[%02X:%02X]\n",
                                   osifp->tx_dbg_vow_counter[ii], ii, osifp->tx_dbg_vow_peer[ii][0], osifp->tx_dbg_vow_peer[ii][1]);
                        }

                }
            }
#endif
            break;
        }
    case IEEE80211_PEER_TX_COUNT_SET:
        if (val <= 0) {
            qdf_err("Invalid AID value");
            return -EINVAL;
        }
        retval = wlan_get_peer_mumimo_tx_count(vap, val);
        break;
    case IEEE80211_CTSPROT_DTIM_BCN_SET:
        ol_ath_set_vap_cts2self_prot_dtim_bcn(vap->vdev_obj);
        break;
    case IEEE80211_PEER_POSITION_SET:
        if (val <= 0) {
            qdf_err("Invalid AID value");
            return -EINVAL;
        }
        retval = wlan_get_user_position(vap, val);
        break;
    case IEEE80211_VAP_TXRX_FW_STATS:
    {
        struct ol_txrx_stats_req req = {0};
        if ((lmac_is_target_ar900b(scn->soc->psoc_obj) == false) &&
                 (val > TXRX_FW_STATS_VOW_UMAC_COUNTER)) { /* Wlan F/W doesnt like this */
              qdf_print("Not supported.");
              return -EINVAL;
        }

        req.print.verbose = 1; /* default */
        if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
        } else {
            /*
             * The command iwpriv athN vap_txrx_stats is used to get per vap
             * sounding info, selfgen info and tx mu stats only.
             */
            qdf_print("Vap specific stats is implemented only for stats type 14 16 and 17");
            return -EINVAL;
        }
        cdp_fw_stats_get(soc_txrx_handle, vdev_id, &req, PER_VDEV_FW_STATS_REQUEST, 0);
    break;
    }
    case IEEE80211_TXRX_FW_MSTATS:
    {
        struct ol_txrx_stats_req req = {0};
        req.print.verbose = 1;
        req.stats_type_upload_mask = val;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops) {
            qdf_err("Not supported with WiFi Offload mode enabled ");
            return -EINVAL;
        }
#endif
        cdp_fw_stats_get(soc_txrx_handle, vdev_id, &req, PER_RADIO_FW_STATS_REQUEST, 0);
        break;
    }

   case IEEE80211_VAP_TXRX_FW_STATS_RESET:
    {
        struct ol_txrx_stats_req req = {0};
#if UMAC_VOW_DEBUG
        osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
#endif
        if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
        } else {
            /*
             * The command iwpriv athN vap_txrx_st_rst is used to reset per vap
             * sounding info, selfgen info and tx mu stats only.
             */
            qdf_print("Vap specific stats reset is implemented only for stats type 14 16 and 17");
            return -EINVAL;
        }
        cdp_fw_stats_get(soc_txrx_handle, vdev_id, &req, PER_VDEV_FW_STATS_REQUEST, 0);
#if UMAC_VOW_DEBUG
        if(osifp->vow_dbg_en)
        {
            for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
            {
                 osifp->tx_dbg_vow_counter[ii] = 0;
            }
            osifp->umac_vow_counter = 0;
        }
#endif
        break;
    }

    case IEEE80211_TXRX_FW_STATS_RESET:
    {
        struct ol_txrx_stats_req req = {0};
        struct cdp_txrx_stats_req cdp_req = {0};
#if UMAC_VOW_DEBUG
        osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
#endif
        req.stats_type_reset_mask = val;
        cdp_fw_stats_get(soc_txrx_handle, vdev_id, &req, PER_RADIO_FW_STATS_REQUEST, 0);
#if UMAC_VOW_DEBUG
        if(osifp->vow_dbg_en)
        {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_vops)
                ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_VOW_DBG_RST_STATS);
#endif
            for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
            {
                 osifp->tx_dbg_vow_counter[ii] = 0;
            }
            osifp->umac_vow_counter = 0;

        }
#endif
        cdp_req.stats = CDP_TXRX_STATS_0;
        cdp_req.param0 = val;
        cdp_req.param1 = 0x1;
        cdp_txrx_stats_request(soc_txrx_handle, vdev_id, &cdp_req);
        break;
    }
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_DSCP_MAP_ID:
    {
        ol_ath_set_vap_dscp_tid_map(vap);
        break;
    }
    case IEEE80211_DP_DSCP_MAP:
    {
        ol_ath_set_pdev_dscp_tid_map(vap, val);
#if ATH_SUPPORT_HS20
        vap->iv_hotspot_xcaps2 |= IEEE80211_EXTCAPIE_QOS_MAP;
#endif
        wlan_vdev_beacon_update(vap);
        break;
    }
#endif /* ATH_SUPPORT_DSCP_OVERRIDE */

    case IEEE80211_CONFIG_VAP_TXPOW_MGMT:
    {
        ol_wlan_txpow_mgmt(vap,(u_int8_t)val);
    }
    break;

    case IEEE80211_CONFIG_MCAST_RC_STALE_PERIOD:
    {
        retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                            wmi_vdev_param_mcast_rc_stale_period,
                                            val);
        if (retval == EOK)
            vap->iv_mcast_rc_stale_period = val;
    }
    break;

    case IEEE80211_CONFIG_ENABLE_MCAST_RC:
    {
        retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                            wmi_vdev_param_enable_mcast_rc,
                                            !!val);
        if (retval == EOK)
            vap->iv_enable_mcast_rc = !!val;
    }
    break;
#ifdef WLAN_SUPPORT_FILS
    case IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP:
    {
        retval = ol_ath_wmi_send_vdev_bcast_prbrsp_param(scn->sc_pdev,
                                        wlan_vdev_get_id(vap->vdev_obj), val);
    }
    break;
#endif
    case IEEE80211_CONFIG_VAP_TXPOW:
    {
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_TX_POWER,
                mlme_cfg);
    }
    break;

    case IEEE80211_CONFIG_TX_CAPTURE:
    {
#if ATH_PERF_PWR_OFFLOAD
        struct ol_ath_soc_softc *soc;
        struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif

#if ATH_DATA_TX_INFO_EN
        if (scn->enable_perpkt_txstats) {
            qdf_print("Disable data_txstats before enabling debug sniffer");
            retval = -EINVAL;
            break;
        }
#endif

        soc = scn->soc;
#ifdef QCA_SUPPORT_RDK_STATS
        if (soc->rdkstats_enabled) {
            qdf_err("Disable peer rate stats before enabling debug sniffer");
            retval = -EINVAL;
            break;
        }
#endif
            /* To handle case when M-copy is enabled through monitor vap */
        if (!val && (ol_ath_is_mcopy_enabled(ic))) {
            retval = -EINVAL;
            break;
        }
        retval = ol_ath_set_debug_sniffer(scn, val);
        if (!ol_target_lithium(psoc)){
            retval = ol_ath_set_tx_capture(scn, val);

            if (!retval)
                ic->ic_tx_capture = val;
        }
    }
    break;

    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT:
        cdp_set_vdev_peer_protocol_count(soc_txrx_handle, vdev_id, val);
        break;
    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK:
        cdp_set_vdev_peer_protocol_drop_mask(soc_txrx_handle, vdev_id, val);
        break;

#if MESH_MODE_SUPPORT
    case IEEE80211_CONFIG_MESH_MCAST:
        qdf_info("Mesh param param:%u value:%u", param, val);

        retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                       wmi_pdev_param_mesh_mcast_enable, val);
     break;

    case IEEE80211_CONFIG_RX_MESH_FILTER:
        qdf_info("Mesh filter param:%u value:%u", param, val);
        value.cdp_vdev_param_mesh_rx_filter = val;
        if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_MESH_RX_FILTER, value) != QDF_STATUS_SUCCESS)
            retval = EINVAL;

     break;
#endif

        case IEEE80211_CONFIG_HE_EXTENDED_RANGE:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                    wmi_vdev_param_he_range_ext_enable, val);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
                              "%s : HE Extended Range %d \n",__func__, val);
        break;
        case IEEE80211_CONFIG_HE_DCM:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_he_dcm_enable,
                                                val);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
                              "%s : HE DCM %d \n",__func__, val);
        break;
        case IEEE80211_TXRX_DP_STATS:
        {
            struct cdp_txrx_stats_req req = {0,};
            req.stats = val;
            cdp_txrx_stats_request(soc_txrx_handle, vdev_id, &req);
            break;
        }
        case IEEE80211_CONFIG_HE_BSS_COLOR:
        {
            uint32_t he_bsscolor = 0;

            if (!val) {
                val = ic->ic_bsscolor_hdl.prev_bsscolor;
                WMI_HOST_HEOPS_BSSCOLOR_DISABLE_SET(he_bsscolor, true);
            }
            WMI_HOST_HEOPS_BSSCOLOR_SET(he_bsscolor, val);

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_he_bss_color,
                                                he_bsscolor);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                 "%s : HE BSS Color  %d \n",__func__, val);
        }
        break;
        case IEEE80211_CONFIG_HE_SU_BFEE:
        case IEEE80211_CONFIG_HE_SU_BFER:
        case IEEE80211_CONFIG_HE_MU_BFEE:
        case IEEE80211_CONFIG_HE_MU_BFER:
        case IEEE80211_CONFIG_HE_UL_MU_OFDMA:
        case IEEE80211_CONFIG_HE_DL_MU_OFDMA:
        case IEEE80211_CONFIG_HE_DL_MU_OFDMA_BFER:
        case IEEE80211_CONFIG_HE_UL_MU_MIMO:
        {
            uint32_t he_bf_cap =0;

            qdf_info("VDEV params:"
                      "HE su_bfee:%d|su_bfer:%d|"
                      "mu_bfee:%d|mu_bfer:%d|"
                      "dl_muofdma:%d|ul_muofdma:%d|"
                      "ul_mumimo:%d|dl_muofdma_bfer:%d",
                    vap->iv_he_su_bfee, vap->iv_he_su_bfer, vap->iv_he_mu_bfee,
                    vap->iv_he_mu_bfer, vap->iv_he_dl_muofdma, vap->iv_he_ul_muofdma,
                    vap->iv_he_ul_mumimo, vap->iv_he_dl_muofdma_bfer);

            WMI_HOST_HE_BF_CONF_SU_BFEE_SET(he_bf_cap, vap->iv_he_su_bfee);
            WMI_HOST_HE_BF_CONF_SU_BFER_SET(he_bf_cap, vap->iv_he_su_bfer);
            WMI_HOST_HE_BF_CONF_MU_BFEE_SET(he_bf_cap, vap->iv_he_mu_bfee);
            WMI_HOST_HE_BF_CONF_MU_BFER_SET(he_bf_cap, vap->iv_he_mu_bfer);
            WMI_HOST_HE_BF_CONF_DL_OFDMA_SET(he_bf_cap, vap->iv_he_dl_muofdma);
            WMI_HOST_HE_BF_CONF_UL_OFDMA_SET(he_bf_cap, vap->iv_he_ul_muofdma);
            WMI_HOST_HE_BF_CONF_UL_MUMIMO_SET(he_bf_cap, vap->iv_he_ul_mumimo);

            HE_SET_BITS(he_bf_cap, HE_BF_CONF_DL_OFDMA_BFER_BIT_POS,
                HE_BF_CONF_DL_OFDMA_BFER_NUM_BITS, vap->iv_he_dl_muofdma_bfer);

            qdf_info("he_bf_cap=0x%x", he_bf_cap);

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_set_hemu_mode,
                                                he_bf_cap);
        }
        break;
        case IEEE80211_CONFIG_HE_SOUNDING_MODE:
        {
            qdf_info("VDEV params: AC/VHT sounding mode:%s|"
                     "SU/MU sounding mode:%s|"
                     "Trig/Non-Trig sounding mode:%s",
                     WMI_HOST_HE_VHT_SOUNDING_MODE_GET(val) ? "HE" : "VHT",
                     WMI_HOST_SU_MU_SOUNDING_MODE_GET(val) ? "MU" : "SU",
                     WMI_HOST_TRIG_NONTRIG_SOUNDING_MODE_GET(val) ? "Trigged" :
                     "Non-Trigged");

            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                    wmi_vdev_param_set_he_sounding_mode, val);
        }
        break;
        case IEEE80211_CONFIG_HE_LTF:
        {
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_set_he_ltf, val);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                     "%s : HE LTF %d \n",__func__, val);
        }
        break;
        case IEEE80211_CONFIG_HE_AR_GI_LTF:
        {
            if (vap->iv_he_ar_ldpc == IEEE80211_HE_AR_LDPC_DEFAULT) {
              val = vap->iv_he_ar_gi_ltf;
            } else {
              val = vap->iv_he_ar_gi_ltf |
                    (vap->iv_he_ar_ldpc << IEEE80211_HE_AR_LDPC_SHIFT);
            }
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_autorate_misc_cfg,
                                                val);

            qdf_info("HE AUTORATE GI LTF 0x%x", vap->iv_he_ar_gi_ltf);
        }
        break;
        case IEEE80211_CONFIG_HE_AR_LDPC:
        {
            val = vap->iv_he_ar_gi_ltf |
                  (vap->iv_he_ar_ldpc << IEEE80211_HE_AR_LDPC_SHIFT);
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_autorate_misc_cfg,
                                                val);
            qdf_info("HE AUTORATE LDPC 0x%x", vap->iv_he_ar_ldpc);
        }
        break;
        case IEEE80211_CONFIG_HE_OP:
        {
            mlme_cfg.value = val;
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_HE_OPS, mlme_cfg);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                     "%s : HE OP %d \n",__func__, val);
        }
        break;
        case IEEE80211_CONFIG_HE_RTSTHRSHLD:
        {
            uint32_t heop = 0;
            struct ieee80211com *ic = vap->iv_ic;

            ol_ath_populate_bsscolor_in_vdev_param_heop(ic, &heop);
#if SUPPORT_11AX_D3
            heop |= (ic->ic_he.heop_param |
                    ((val << IEEE80211_HEOP_RTS_THRESHOLD_S) &
                     IEEE80211_HEOP_RTS_THRESHOLD_MASK));
#else
            heop |= ((ic->ic_he.heop_param &
                ~(IEEE80211_HEOP_BSS_COLOR_MASK << IEEE80211_HEOP_BSS_COLOR_S))
                 |((val << IEEE80211_HEOP_RTS_THRESHOLD_S) &
                 IEEE80211_HEOP_RTS_THRESHOLD_MASK));
#endif
            mlme_cfg.value = heop;
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_HE_OPS, mlme_cfg);

            /* Increment the TIM update beacon count to indicate change in
             * HEOP parameter */
            ic->ic_is_heop_param_updated = true;
            wlan_vdev_beacon_update(vap);
            ic->ic_is_heop_param_updated = false;

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                     "%s : HE RTS THRSHLD %d \n",__func__, val);
            break;
        }

        case IEEE80211_FEATURE_DISABLE_CABQ:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_disable_cabq,
                                                val);
        break;

        case IEEE80211_CONFIG_M_COPY:
            if (val && ic->ic_debug_sniffer) {
                qdf_err("Monitor/M_COPY is already enabled");
                retval = -EINVAL;
                break;
            }
            if (val) {
                if (val == MODE_M_COPY || val == MODE_EXT_M_COPY) {
                    if (val == MODE_M_COPY)
                        sniffer_mode = SNIFFER_M_COPY_MODE;
                    else
                        sniffer_mode = SNIFFER_EXT_M_COPY_MODE;

                    if (ol_ath_set_debug_sniffer(scn, sniffer_mode) == 0)
                        ol_ath_pdev_set_param(scn->sc_pdev,
                                    wmi_pdev_param_set_promisc_mode_cmdid, 1);
                    else
                        qdf_info("Error in enabling m_copy mode");
                } else {
                   qdf_info("Invalid value, expected 1 for m_copy mode and 2 for ext_m_copy mode");
                }
            } else {
                if (ol_ath_set_debug_sniffer(scn, SNIFFER_DISABLE) == 0)
                    ol_ath_pdev_set_param(scn->sc_pdev,
                                wmi_pdev_param_set_promisc_mode_cmdid, 0);
                else
                    qdf_print("Error in disabling m_copy mode");
            }
            break;
#if QCN_IE
        case IEEE80211_CONFIG_BCAST_PROBE_RESPONSE:
            ol_ath_set_bpr_wifi3(scn, val);
            break;
#endif

        case IEEE80211_CONFIG_CAPTURE_LATENCY_ENABLE:
            ol_ath_set_capture_latency(scn, val);
            break;

        case IEEE80211_CONFIG_ADDBA_MODE:
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_set_ba_mode,
                                                val);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                     "%s : BA MODE %d \n",__func__, val);
            break;
        case IEEE80211_CONFIG_BA_BUFFER_SIZE:
        {
        /* Map the user set value 0/1 to 2/3 to configure the BA buffer size
         * VDEV PARAM for BA MODE has been extended to configure the BA buffer
         * size along with setting the ADDBA mode. The values 2(buffer size 64)
         * and 3(buffer size 255) are for the BA MODE to configure the BA buffer
         * size. The values 0(Auto mode) and 1(Manual mode) for BA MODE VDEV
         * PARAM will configure the ADDBA mode. */
            val += IEEE80211_BA_MODE_BUFFER_SIZE_OFFSET;
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_set_ba_mode,
                                                val);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE ,
                    "%s : BA Buffer size  %d \n",__func__,
                    (val - IEEE80211_BA_MODE_BUFFER_SIZE_OFFSET));
        }
        break;
        case IEEE80211_CONFIG_READ_RXPREHDR:
        {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
            if (osifp->nss_wifiol_ctx && ic->nss_vops) {
                ic->nss_vops->ic_osif_nss_vdev_set_read_rxprehdr(osifp, (uint32_t)val);
            }
#endif
        }
        break;
        case IEEE80211_UPDATE_DEV_STATS:
        {
           struct cdp_dev_stats cdp_stats;
           cdp_ath_getstats(soc_txrx_handle, vdev_id, &cdp_stats,
                            UPDATE_VDEV_STATS);
        }
        break;
        case IEEE80211_CONFIG_RU26:
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_ru26_allowed, val);
        break;
        case IEEE80211_BSTEER_EVENT_ENABLE:
        {
#if DBDC_REPEATER_SUPPORT
            uint32_t target_type = lmac_get_tgt_type(scn->soc->psoc_obj);
            /*Disable WDS on STA vaps on secondary radio*/
            if ((target_type == TARGET_TYPE_QCA8074) && (!ic->ic_primary_radio)) {
                wlan_iterate_vap_list(ic, ol_ath_vap_iter_sta_wds_disable, NULL);
            }
#endif
            break;
        }
        case IEEE80211_CONFIG_RAWMODE_OPEN_WAR:
        {
            uint32_t target_type = lmac_get_tgt_type(scn->soc->psoc_obj);

            if (target_type == TARGET_TYPE_QCA8074) {
                retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                        wmi_vdev_param_rawmode_open_war, val);
            } else {
                qdf_err("Not supported!!");
                return -EINVAL;
            }
        }
        break;
        case IEEE80211_CONFIG_INDICATE_FT_ROAM:
            retval = ol_ath_send_ft_roam_start_stop(vap, val);
        break;
	case IEEE80211_FEATURE_EXTAP:
	{
	    /* DISABLE DA LEARN at SOC level if extap is enabled on any VAP */
	    if (val) {
                value.cdp_vdev_param_da_war = 0;
                if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                                            CDP_ENABLE_DA_WAR, value) != QDF_STATUS_SUCCESS)
                    return -EINVAL;
	    } else {
                value.cdp_vdev_param_da_war = 1;
                if (cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                                            CDP_ENABLE_DA_WAR, value) != QDF_STATUS_SUCCESS)
                    return -EINVAL;
	    }
	}
	break;

        case IEEE80211_CONFIG_ENABLE_MULTI_GROUP_KEY:
            if (ol_target_lithium(psoc)) {
                vap->enable_multi_group_key = val ? 1:0 ;
                mlme_cfg.value = val;
                retval = wlan_util_vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_ENABLE_MULTI_GROUP_KEY, mlme_cfg);
                value.cdp_vdev_param_update_multipass = val;
                if (cdp_txrx_set_vdev_param(soc_txrx_handle,
                        vdev_id,
                        CDP_UPDATE_MULTIPASS, value) != QDF_STATUS_SUCCESS)
                    return -EINVAL;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_vops) {
                    ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp, OSIF_NSS_WIFI_VDEV_CFG_MULTIPASS);
                }
#endif
            }
        break;

        case IEEE80211_CONFIG_MAX_GROUP_KEYS:
            if (ol_target_lithium(psoc) && (val < MAX_VLAN)) {
                vap->max_group_keys = val;
                mlme_cfg.value = val;
                retval = wlan_util_vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_MAX_GROUP_KEYS, mlme_cfg);
            }
        break;
        case IEEE80211_CONFIG_MAX_MTU_SIZE:
        {
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_max_mtu_size,
                                                val);
        }
        break;

#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
        case IEEE80211_CONFIG_CFR_RCC:
        {
            uint8_t pdev_id;

            pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

            if ((val == 1) && !cdp_get_cfr_rcc(soc_txrx_handle, pdev_id)) {
                ol_ath_subscribe_ppdu_desc_info(scn,
                                                PPDU_DESC_CFR_RCC);
            } else if ((!val && cdp_get_cfr_rcc(soc_txrx_handle, pdev_id))
                       || (val == 2)) {
                ol_ath_unsubscribe_ppdu_desc_info(scn,
                                                  PPDU_DESC_CFR_RCC);
            }
        }
	    break;
#endif
        case IEEE80211_CONFIG_6GHZ_NON_HT_DUP:
        {
            uint32_t mgt_rate = 0;
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                                wmi_vdev_param_6ghz_params,
                                                val);

            if((retval >= 0) && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
#ifdef WLAN_SUPPORT_FILS
                retval = ol_ath_fd_tmpl_update(vap->vdev_obj);
#endif /* WLAN_SUPPORT_FILS */
                /* By default 6GHz AP is configured to use HE rates for all
                 * mgmt frames. To enable non-HT duplicate frames,
                 * mgmt rates should be set to legacy(non-HT) rates.
                 */
                if(vap->iv_disabled_legacy_rate_set) {
                    wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
                            WLAN_MLME_CFG_TX_MGMT_RATE, &mgt_rate);
                    retval = wlan_set_param(vap, IEEE80211_MGMT_RATE, mgt_rate);
                } else {
                    retval = wlan_set_param(vap, IEEE80211_MGMT_RATE,
                                        IEEE80211_HE_6GHZ_NON_HT_RATE);
                }
            }
        }
        break;

        default:
            /*qdf_print("%s: VAP param unsupported param:%u value:%u", __func__,
                         param, val);*/
        break;
    }

    return(retval);
}

static int ol_ath_vap_set_ru26_tolerant(struct ieee80211com *ic, bool val)
{
    if (!ic)
        return -1;

    return ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                 wmi_pdev_param_ru26_allowed, val);
}

static int16_t ol_ath_vap_dyn_bw_rts(struct ieee80211vap *vap, int param)
{
    int retval = 0;

    retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                        wmi_vdev_param_disable_dyn_bw_rts,
                                        param);
    return retval;
}

void ol_ath_get_min_and_max_power(struct ieee80211com *ic, int8_t *max_tx_power,
                                  int8_t *min_tx_power)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    struct wlan_psoc_target_capability_info *target_cap;
    struct target_psoc_info *tgt_hdl;

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        target_if_err("%s: target_psoc_info is null", __func__);
        return;
    }
    target_cap = target_psoc_get_target_caps(tgt_hdl);
    *max_tx_power = target_cap->hw_max_tx_power;
    *min_tx_power = target_cap->hw_min_tx_power;
}

uint32_t ol_ath_get_modeSelect(struct ieee80211com *ic)
{
    uint32_t wMode;
    uint32_t netBand;

    wMode = WMI_HOST_REGDMN_MODE_ALL;

    if (!(wMode & HOST_REGDMN_MODE_11A)) {
        wMode &= ~(HOST_REGDMN_MODE_TURBO |
                HOST_REGDMN_MODE_108A |
                HOST_REGDMN_MODE_11A_HALF_RATE);
    }

    if (!(wMode & HOST_REGDMN_MODE_11G)) {
        wMode &= ~(HOST_REGDMN_MODE_108G);
    }

    netBand = WMI_HOST_REGDMN_MODE_ALL;

    if (!(netBand & HOST_REGDMN_MODE_11A)) {
        netBand &= ~(HOST_REGDMN_MODE_TURBO |
                HOST_REGDMN_MODE_108A |
                HOST_REGDMN_MODE_11A_HALF_RATE);
    }

    if (!(netBand & HOST_REGDMN_MODE_11G)) {
        netBand &= ~(HOST_REGDMN_MODE_108G);
    }
    wMode &= netBand;

    return wMode;
}

/* Vap interface functions */
static int
ol_ath_vap_get_param(struct ieee80211vap *vap,
                              ieee80211_param param)
{
    int retval = 0;
    struct ieee80211com *ic = vap->iv_ic;
    ol_txrx_soc_handle soc_txrx_handle;
    uint8_t vdev_id;
    struct wlan_objmgr_psoc *psoc;
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);
    cdp_config_param_type value = {0};

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    /* Set the VAP param in the target */
    switch (param) {
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
        case IEEE80211_RAWMODE_PKT_SIM_STATS:
            wlan_rawsim_api_print_stats
                    (dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id));
            break;
#endif
#if HOST_SW_TSO_SG_ENABLE
        case IEEE80211_TSO_STATS_RESET_GET:
            cdp_tx_rst_tso_stats(soc_txrx_handle, vdev_id);
            break;

        case IEEE80211_TSO_STATS_GET:
            cdp_tx_print_tso_stats(soc_txrx_handle, vdev_id);
            break;
#endif /* HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_SG_ENABLE
        case IEEE80211_SG_STATS_GET:
            cdp_tx_print_sg_stats(soc_txrx_handle, vdev_id);
            break;
        case IEEE80211_SG_STATS_RESET_GET:
            cdp_tx_rst_sg_stats(soc_txrx_handle, vdev_id);
            break;
#endif /* HOST_SW_SG_ENABLE */
#if RX_CHECKSUM_OFFLOAD
        case IEEE80211_RX_CKSUM_ERR_STATS_GET:
            cdp_print_rx_cksum_stats(soc_txrx_handle, vdev_id);
	    break;
        case IEEE80211_RX_CKSUM_ERR_RESET_GET:
            cdp_rst_rx_cksum_stats(soc_txrx_handle, vdev_id);
            break;
#endif /* RX_CHECKSUM_OFFLOAD */
        case IEEE80211_RX_FILTER_MONITOR:
           cdp_txrx_get_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_UCAST_DATA, &value);
           retval = value.cdp_pdev_param_fltr_ucast ? 0 : MON_FILTER_TYPE_UCAST_DATA;
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                     "ucast data filter=%d\n", value.cdp_pdev_param_fltr_ucast);

           cdp_txrx_get_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_MCAST_DATA, &value);
           retval |= value.cdp_pdev_param_fltr_mcast ? 0 : MON_FILTER_TYPE_MCAST_DATA;
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                      "mcast data filter=%d\n", value.cdp_pdev_param_fltr_mcast);

           cdp_txrx_get_pdev_param(soc_txrx_handle, pdev_id, CDP_FILTER_NO_DATA, &value);
           retval |= value.cdp_pdev_param_fltr_none ? 0 : MON_FILTER_TYPE_NON_DATA;
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                     "Non data(mgmt/action etc.) filter=%d\n", value.cdp_pdev_param_fltr_none);

           break;
        case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT:
            retval = cdp_is_vdev_peer_protocol_count_enabled(soc_txrx_handle,
                                                         vdev_id);
            break;
        case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK:
            retval = cdp_get_peer_protocol_drop_mask(soc_txrx_handle, vdev_id);
            break;

        case IEEE80211_IGMP_ME:
            retval = dp_get_igmp_me_mode(soc_txrx_handle, vdev_id);
            break;
        case IEEE80211_VDEV_TSF:
        {
            struct wmi_unified *wmi_handle;

            wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
            if (!wmi_handle) {

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "%s: wmi_handle NULL\n", __func__);
                return QDF_STATUS_E_FAILURE;
            }
            retval = wmi_unified_send_vdev_tsf_tstamp_action_cmd(wmi_handle,
                                                                 vdev_id);
        }
            break;
        default:
            /*qdf_nofl_info("%s: VAP param unsupported param:%u value:%u\n", __func__,
                    param, val);*/
            break;
    }

    return(retval);
}

static int
ol_ath_vap_set_ratemask(struct ieee80211vap *vap, u_int8_t preamble,
                        u_int32_t mask_lower32, u_int32_t mask_higher32,
                        u_int32_t mask_lower32_2)
{
    /* higher 32 bit is reserved for beeliner*/
    switch (preamble) {
        case IEEE80211_LEGACY_PREAMBLE:
            vap->iv_ratemask_default = 0;
            vap->iv_legacy_ratemasklower32 = mask_lower32;
            break;
        case IEEE80211_HT_PREAMBLE:
            vap->iv_ratemask_default = 0;
            vap->iv_ht_ratemasklower32 = mask_lower32;
            break;
        case IEEE80211_VHT_PREAMBLE:
            vap->iv_ratemask_default = 0;
            vap->iv_vht_ratemasklower32 = mask_lower32;
            vap->iv_vht_ratemaskhigher32 = mask_higher32;
            vap->iv_vht_ratemasklower32_2 = mask_lower32_2;
            break;
        case IEEE80211_HE_PREAMBLE:
            vap->iv_ratemask_default = 0;
            vap->iv_he_ratemasklower32 = mask_lower32;
            vap->iv_he_ratemaskhigher32 = mask_higher32;
            vap->iv_he_ratemasklower32_2 = mask_lower32_2;
            break;
        default:
            return EINVAL;
            break;
    }
    return ENETRESET;
}

int
ol_ath_vdev_getpn(struct ieee80211vap *vap, struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
                  u_int8_t *macaddr,
                  uint32_t keytype)
{
    struct peer_request_pn_param pn_param;
    struct wmi_unified *pdev_wmi_handle;
    int ret;
    struct wlan_objmgr_peer *peer;
    struct wlan_objmgr_psoc *psoc;
    uint8_t pdev_id;
    struct wlan_objmgr_vdev *vdev;
    int waitcnt = 0;
    struct ieee80211_node *ni;

    static const uint32_t wmi_ciphermap[] = {
        WMI_CIPHER_WEP,
        WMI_CIPHER_TKIP,
        WMI_CIPHER_AES_OCB,
        WMI_CIPHER_AES_CCM,
#if ATH_SUPPORT_WAPI
        WMI_CIPHER_WAPI,
#else
        0xff,
#endif
        WMI_CIPHER_CKIP,
        WMI_CIPHER_AES_CMAC,
        WMI_CIPHER_AES_CCM,
        WMI_CIPHER_AES_CMAC,
        WMI_CIPHER_AES_GCM,
        WMI_CIPHER_AES_GCM,
        WMI_CIPHER_AES_GMAC,
        WMI_CIPHER_AES_GMAC,
        WMI_CIPHER_NONE,
    };

    psoc = scn->soc->psoc_obj;

    if ((vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, if_id,
        WLAN_CRYPTO_ID)) == NULL) {
         qdf_err("vdev object is NULL");
         return -1;
    }

    pdev_id = wlan_objmgr_pdev_get_pdev_id(wlan_vdev_get_pdev(vdev));

    if ((peer = wlan_objmgr_get_peer(psoc, pdev_id, macaddr,
        WLAN_CRYPTO_ID)) == NULL) {
        qdf_err("peer object is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_CRYPTO_ID);
        return -1;
    }

    if ((ni = wlan_peer_get_mlme_ext_obj(peer)) == NULL) {
        ret = -1;
        qdf_atomic_init(&(ni->getpn));
        goto bad;
    }

    pn_param.vdev_id = if_id;
    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev Wmi handle is null");
        return -EINVAL;
    }

    qdf_mem_copy(pn_param.peer_macaddr, macaddr, 6);

    pn_param.key_type  = wmi_ciphermap[keytype];
    /*
     * In Lithium target, WMI_CIPHER_ANY is introduced after
     * WMI_CIPHER_AES_CMAC. which makes legacy chip is not compatible
     * with new wmi defination. To compensate this new enum addition
     * in legacy, we will decrement the cipher value by one.
     * so it would match with legacy enum values.
     */
    if ((pn_param.key_type > WMI_CIPHER_AES_CMAC) && (ol_target_lithium(scn->soc->psoc_obj) == false)) {
        qdf_print("%s[%d] WAR cipher value will be reduced by 1 %d",
                                 __func__, __LINE__, pn_param.key_type);
        pn_param.key_type--;
    }

    qdf_atomic_init(&(ni->getpn));
    ret = wmi_unified_get_pn_send_cmd(pdev_wmi_handle, &pn_param);

#define PEER_PN_TIMEOUTCNT 5
#define PEER_PN_TIMEOUT 300
    while ( (waitcnt < PEER_PN_TIMEOUTCNT) && (qdf_atomic_read(&(ni->getpn)) == 0)) {
        schedule_timeout_interruptible(qdf_system_msecs_to_ticks(PEER_PN_TIMEOUT));
        waitcnt++;
    }
#undef PEER_PN_TIMEOUTCNT
#undef PEER_PN_TIMEOUT
    if (qdf_atomic_read(&(ni->getpn)) != 1) {
        ret = -1;
        qdf_atomic_init(&(ni->getpn));
        goto bad;
    }

bad:
    wlan_objmgr_peer_release_ref(peer, WLAN_CRYPTO_ID);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_CRYPTO_ID);
    return ret;
}

static QDF_STATUS ol_if_configure_peer_hw_vlan(wlan_if_t vap,
                                               struct ieee80211_node *ni)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wmi_unified *pdev_wmi_handle;
    struct peer_vlan_config_param v_param;
    QDF_STATUS status;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return QDF_STATUS_E_FAILURE;

    qdf_mem_set(&v_param, sizeof(struct peer_vlan_config_param), 0);

    /* Enabling hw vlan acceleration in Rx path through wmi */
    v_param.rx_cmd = 1;
    /* Enabling Rx_insert_inner_vlan_tag */
    v_param.rx_insert_c_tag = 1;
    v_param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    /* Send Wmi Command */
    status = wmi_unified_peer_vlan_config_send(pdev_wmi_handle, ni->ni_macaddr,
                                               &v_param);
    if (status == QDF_STATUS_E_FAILURE)
        return QDF_STATUS_E_FAILURE;

    return QDF_STATUS_SUCCESS;
}

int ol_ath_vdev_install_key_send(struct ieee80211vap *vap,
                                 struct wlan_crypto_key *key, uint8_t *macaddr,
                                 uint8_t def_keyid, bool force_none,
                                 uint32_t keytype)
{
    struct set_key_params param;
    struct ieee80211_node *ni = NULL;
    int ret = 0;
    uint32_t pn[4] = {0,0,0,0};
    uint32_t michael_key[2];
    enum cdp_sec_type sec_type = cdp_sec_type_none;
    bool unicast = true;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    struct ieee80211com *ic = NULL;
    uint32_t nss_cipher_idx = 0;
#endif
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev = NULL;
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    uint8_t vdev_id;

    static const uint8_t wmi_ciphermap[] = {
        WMI_CIPHER_WEP,
        WMI_CIPHER_TKIP,
        WMI_CIPHER_AES_OCB,
        WMI_CIPHER_AES_CCM,
#if ATH_SUPPORT_WAPI
        WMI_CIPHER_WAPI,
#else
        0xff,
#endif
        WMI_CIPHER_CKIP,
        WMI_CIPHER_AES_CMAC,
        WMI_CIPHER_AES_CCM,
        WMI_CIPHER_AES_CMAC,
        WMI_CIPHER_AES_GCM,
        WMI_CIPHER_AES_GCM,
        WMI_CIPHER_AES_GMAC,
        WMI_CIPHER_AES_GMAC,
        WMI_CIPHER_NONE,
    };
    struct wmi_unified *pdev_wmi_handle;
    cdp_config_param_type val = {0};

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    qdf_mem_zero(&param, sizeof(param));
    psoc = wlan_pdev_get_psoc(pdev);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.vdev_id = vdev_id;
    param.key_len = key->keylen;

    if (force_none == 1) {
        param.key_cipher = WMI_CIPHER_NONE;
    } else if ((key->flags & IEEE80211_KEY_SWCRYPT) == 0) {
        KASSERT(keytype < (sizeof(wmi_ciphermap)/sizeof(wmi_ciphermap[0])),
                ("invalid cipher type %u", keytype));
        param.key_cipher  = wmi_ciphermap[keytype];
    } else {
        param.key_cipher = WMI_CIPHER_NONE;
    }

    switch(param.key_cipher)
    {
        case WMI_CIPHER_TKIP:
            sec_type = cdp_sec_type_tkip;
            break;

        case WMI_CIPHER_AES_CCM:
            sec_type = cdp_sec_type_aes_ccmp;
            break;

        case WMI_CIPHER_WAPI:
            sec_type = cdp_sec_type_wapi;
            break;

        case WMI_CIPHER_AES_GCM:
            sec_type = cdp_sec_type_aes_gcmp;
            break;

        case WMI_CIPHER_WEP:
                /*
                 * All eapol rekey frames are in open mode when 802.1x with dynamic wep is used.
                 * Mark Peer is WEP type, so that, when open+eapol frames received,
                 * DP can check and pass the frames to higher layers
                */

            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_8021X)))
            {
                sec_type = cdp_sec_type_wep104;
            }
            break;

        default:
            sec_type = cdp_sec_type_none;
    }

     qdf_mem_copy(param.peer_mac,macaddr,QDF_MAC_ADDR_SIZE);
     param.key_idx = key->keyix;
     /* First 8 keyix are used for ucast + igtk + bigtk*/
     if (key->keyix >= 8) {
         param.group_key_idx = ((key->keyix -8)/2) + 1;
         if( key->keyix % 2)
             param.key_idx = 2;
         else
             param.key_idx = 1 ;
     }
     param.key_rsc_counter = key->keyrsc;
     param.key_tsc_counter = key->keytsc;
#if defined(ATH_SUPPORT_WAPI)
     qdf_mem_copy(param.rx_iv, key->recviv, sizeof(key->recviv));
     qdf_mem_copy(param.tx_iv, key->txiv, sizeof(key->txiv));
#endif
     qdf_mem_copy(param.key_data, key->keyval, key->keylen);

     /* Mapping ieee key flags to WMI key flags */
    if (key->flags & WLAN_CRYPTO_KEY_GROUP) {
         param.key_flags |= GROUP_USAGE;
         unicast = false;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
         nss_cipher_idx |= NSS_CIPHER_MULTICAST;
#endif
    }
    if (def_keyid)
         param.key_flags |= TX_USAGE;

    if (vap->iv_opmode == IEEE80211_M_MONITOR) {
         if (key->flags & (IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT | IEEE80211_KEY_SWCRYPT))
            param.key_flags |= PAIRWISE_USAGE;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            nss_cipher_idx |= NSS_CIPHER_UNICAST;
#endif
    }
    else {
         if (key->flags & (WLAN_CRYPTO_KEY_RECV | WLAN_CRYPTO_KEY_XMIT)) {
            param.key_flags |= PAIRWISE_USAGE;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            nss_cipher_idx |= NSS_CIPHER_UNICAST;
#endif
         }
     }

    if ((keytype == IEEE80211_CIPHER_TKIP)
         || (keytype == IEEE80211_CIPHER_WAPI)) {
        param.key_rxmic_len = RX_MIC_LENGTH;
        param.key_txmic_len = TX_MIC_LENGTH;
        qdf_mem_copy(michael_key, param.key_data + param.key_len - RX_MIC_LENGTH, RX_MIC_LENGTH);
    }

    /* Target expects key_idx 0 for unicast
       other than static wep cipher.
       For vlan group keyix can be greater base keyix.
       For BIGTK keyix can be 6 or 7 */
    if ((param.key_idx >= (IEEE80211_WEP_NKID + 1)) && !param.group_key_idx ) {
        if (!(wlan_pdev_nif_feat_cap_get(vap->iv_ic->ic_pdev_obj,WLAN_PDEV_F_BEACON_PROTECTION)
                            && ((param.key_idx == 6) || (param.key_idx == 7))))
           param.key_idx = 0;
    }

    qdf_debug("Keyix=%d Keylen=%d Keyflags=%x Cipher=%x ",param.key_idx,param.key_len,param.key_flags,param.key_cipher);
    qdf_debug("macaddr %s",ether_sprintf(macaddr));
    /*
     * In Lithium target, WMI_CIPHER_ANY is introduced after
     * WMI_CIPHER_AES_CMAC. which makes legacy chip is not compatible
     * with new wmi defination. To compensate this new enum addition
     * in legacy, we will decrement the cipher value by one.
     * so it would match with legacy enum values.
     */
    if ((param.key_cipher > WMI_CIPHER_AES_CMAC) &&
        (ol_target_lithium(psoc) == false)) {
        qdf_info("WAR cipher value will be reduced by 1 %d", param.key_cipher);
        param.key_cipher--;
    }

    val.cdp_vdev_param_cipher_en = sec_type;
    cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id,
                               CDP_ENABLE_CIPHER, val);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    ic = vap->iv_ic;
    if (ic->nss_vops) {
        ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp, OSIF_NSS_VDEV_SECURITY_TYPE_CFG);
    }
#endif

    cdp_txrx_peer_flush_frags (soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj), macaddr);
    ret = wmi_unified_setup_install_key_cmd(pdev_wmi_handle, &param);
    ni = ieee80211_vap_find_node(vap,macaddr,WLAN_MLME_SB_ID);
    if((!ni) || (sec_type == cdp_sec_type_none))
       goto err_ignore_pn;

    /* Need to handle rx_pn for WAPI  */

    if ((opmode == IEEE80211_M_STA) || (ni != vap->iv_bss)) {
        cdp_set_pn_check(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj), ni->ni_macaddr, sec_type, pn);
        cdp_set_key_sec_type(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj), ni->ni_macaddr,sec_type, unicast);

        /* set MIC key for dp layer TKIP defrag */
        if (sec_type == cdp_sec_type_tkip)
            cdp_set_key(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj), ni->ni_macaddr,
                        unicast, michael_key);

        if ((ni->ni_associd) && (ni->is_ft_reauth)) {
            wmi_unified_peer_ft_roam_send(pdev_wmi_handle, ni->ni_macaddr, vap->iv_unit);
            ni->is_ft_reauth = 0;
        }
    }

    if (vap->enable_multi_group_key && ni->vlan_id) {
        /* HW supports insert in Rx for lithium HW and sending the same for
         * legacy targets is no op. So sending configuration unconditionally */
        if (ol_if_configure_peer_hw_vlan(vap, ni) != QDF_STATUS_SUCCESS)
            qdf_err("Failed to configure vlan hw acceleration support for Rx");

        cdp_peer_set_vlan_id(soc_txrx_handle,  wlan_vdev_get_id(vap->vdev_obj),
                macaddr, ni->vlan_id);
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_radio_ops) {
       ic->nss_radio_ops->ic_nss_ol_set_peer_sec_type(scn, macaddr, wlan_vdev_get_id(vap->vdev_obj),
                                         nss_cipher_idx, sec_type, (uint8_t *) michael_key);

       if (vap->enable_multi_group_key && ni->vlan_id)
           ic->nss_radio_ops->ic_nss_ol_peer_set_vlan_id(scn, wlan_vdev_get_id(vap->vdev_obj),
                                                         macaddr, ni->vlan_id);
    }
#endif
err_ignore_pn:
    if(ni)
        ieee80211_free_node(ni, WLAN_MLME_SB_ID);

    /* Zero-out local key variables */
    qdf_mem_zero(&param, sizeof(struct set_key_params));
    return ret;
}

static int
ol_ath_vap_listen(struct ieee80211vap *vap)
{
    /* Target vdev will be in listen state once it is created
     * No need to send any command to target
     */
    return 0;
}

/* No Op for Perf offload */
static int ol_ath_vap_dfs_cac(struct ieee80211vap *vap)
{
    struct wlan_objmgr_psoc *psoc;
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    psoc = scn->soc->psoc_obj;
    if (!psoc)
        return -1;

#if OL_ATH_SUPPORT_LED
#if QCA_LTEU_SUPPORT
    if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_LTEU_SUPPORT)) {
#endif
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->soc->led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, LED_POLL_TIMER);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_ON_START;
        if(lmac_get_tgt_type(psoc) == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, OL_LED_OFF);
        } else if (lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA8074V2 && scn->scn_led_gpio) {
            gpio_set_value_cansleep(scn->scn_led_gpio, OL_LED_OFF);
        } else {
            tgt_gpio_output(psoc, scn->scn_led_gpio, 0);
        }
        if (scn->soc->led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#if QCA_LTEU_SUPPORT
    }
#endif
#endif /* OL_ATH_SUPPORT_LED */

    if (ol_target_lithium(psoc) && scn->is_scn_stats_timer_init)
        qdf_timer_mod(&(scn->scn_stats_timer), scn->pdev_stats_timer);


    return 0;
}

static int ol_ath_root_authorize(struct ieee80211vap *vap, uint32_t authorize)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = vap->iv_bss;
    ol_txrx_soc_handle soc_txrx_handle;

    if (!ic || !ni)
        return -EINVAL;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    cdp_peer_authorize(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj),
                       ni->peer_obj->macaddr, authorize);
    return ol_ath_node_set_param(ic->ic_pdev_obj, ni->ni_macaddr,
                                 WMI_HOST_PEER_AUTHORIZE, authorize,
                                 wlan_vdev_get_id(vap->vdev_obj));
}

static int ol_ath_enable_radar_table(struct ieee80211com *ic,
                                     struct ieee80211vap *vap, uint8_t precac,
                                     uint8_t i_dfs)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    bool is_precac_timer_running = false;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    uint32_t ignore_dfs = 0;
#endif

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return -1;
    }
    psoc = wlan_pdev_get_psoc(pdev);

    if (precac) {
         dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
         if (dfs_rx_ops && dfs_rx_ops->dfs_is_precac_timer_running) {
             if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                     QDF_STATUS_SUCCESS) {
                 return -1;
             }
             dfs_rx_ops->dfs_is_precac_timer_running(pdev,
                     &is_precac_timer_running);
             wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
         }
    }
    /* use the vap bsschan for dfs configure */
    if ((IEEE80211_IS_CHAN_DFS(vap->iv_bsschan) ||
         ((IEEE80211_IS_CHAN_160MHZ(vap->iv_bsschan) ||
           IEEE80211_IS_CHAN_80_80MHZ(vap->iv_bsschan))
          && IEEE80211_IS_CHAN_DFS_CFREQ2(vap->iv_bsschan))) ||
        (is_precac_timer_running)) {
        if ((ic->ic_opmode == IEEE80211_M_HOSTAP ||
             ic->ic_opmode == IEEE80211_M_IBSS ||
             (ic->ic_opmode == IEEE80211_M_STA
#if ATH_SUPPORT_STA_DFS
             && ieee80211com_has_cap_ext(ic, IEEE80211_CEXT_STADFS)
#endif
             ))) {
           if (i_dfs) {
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
              dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
              if (dfs_rx_ops && dfs_rx_ops->dfs_is_radar_enabled)
                  dfs_rx_ops->dfs_is_radar_enabled(pdev, &ignore_dfs);

              if (!ignore_dfs)
                  ol_ath_init_and_enable_radar_table(ic);
#else
              ol_ath_init_and_enable_radar_table(ic);
#endif /* HOST_DFS_SPOOF_TEST */
           }
           else {
               ol_ath_init_and_enable_radar_table(ic);
           }
        }
    }

    return 0;
}

/**
 * ol_ath_vdev_param_capabilities_set() - set vdev param capabilities
 * @scn: pointer to ath soft context
 * @vap: pointer to ieee80211 vap
 * @value: vdev param capabilities
 *
 * Return: 0 if success, -1 on failure
 */
static int ol_ath_vdev_param_capabilities_set(struct ol_ath_softc_net80211 *scn,
                                              struct ieee80211vap *vap,
                                              uint32_t value)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    if (!avn) {
        qdf_err("AVN is NULL");
        return -1;
    }

    value |= avn->vdev_param_capabilities;
    if (EOK == ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                                          wmi_vdev_param_capabilities,
                                          value)) {
        avn->vdev_param_capabilities = value;
        return 0;
    }
    return -1;
}

static QDF_STATUS ol_ath_send_prb_rsp_tmpl(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn || !avn->av_pr_rsp_wbuf)
        return QDF_STATUS_E_FAILURE;

    qdf_spin_lock_bh(&avn->avn_lock);
    ol_ath_prb_resp_tmpl_send(wlan_vdev_get_id(vap->vdev_obj), vap);
    qdf_spin_unlock_bh(&avn->avn_lock);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_ath_send_bcn_tmpl(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn)
        return QDF_STATUS_E_FAILURE;

    qdf_spin_lock_bh(&avn->avn_lock);
    ol_ath_bcn_tmpl_send(wlan_vdev_get_id(vap->vdev_obj), vap);
    qdf_spin_unlock_bh(&avn->avn_lock);
    return QDF_STATUS_SUCCESS;
}

#if WLAN_SUPPORT_FILS
static QDF_STATUS ol_ath_send_fd_tmpl(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn)
        return QDF_STATUS_E_FAILURE;

    qdf_spin_lock_bh(&avn->avn_lock);
    target_if_fd_offload(vdev);
    qdf_spin_unlock_bh(&avn->avn_lock);

    return QDF_STATUS_SUCCESS;
}

#endif /* WLAN_SUPPORT_FILS */

void ol_ath_prb_rsp_alloc(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = NULL;

    if (!vap || !vap->iv_ic) {
        qdf_err("VAP or IC is NULL");
        return;
    }

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn) {
        qdf_err("AVN is NULL");
        return;
    }

    qdf_spin_lock_bh(&avn->avn_lock);
    ol_ath_20tu_prb_rsp_alloc(vap->iv_ic, (int)wlan_vdev_get_id(vap->vdev_obj));
    qdf_spin_unlock_bh(&avn->avn_lock);
}

static void ol_ath_vap_is_2gvht_en(struct wlan_objmgr_pdev *pdev,
                                   void *obj, void *arg)
{
    struct wlan_objmgr_vdev *vdev = obj;
    struct ieee80211vap *vap;
    struct vdev_mlme_obj *vdev_mlme = NULL;
    uint8_t *is_2gvht_en = (uint8_t *)arg;

    if (!vdev)
        return;

    vdev_mlme = wlan_objmgr_vdev_get_comp_private_obj(
                                vdev, WLAN_UMAC_COMP_MLME);
    if (!vdev_mlme)
        return;

    vap = vdev_mlme->ext_vdev_ptr;
    if (!vap)
        return;

    if (ieee80211_vap_256qam_is_set(vap))
        *is_2gvht_en = 1;
}

static int ol_ath_update_phy_mode(struct mlme_channel_param *ch_param,
                                  struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *c = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct wlan_objmgr_pdev *pdev;
    uint8_t is_2gvht_en = 0;

    scn = OL_ATH_SOFTC_NET80211(ic);
    pdev = ic->ic_pdev_obj;
    c = ic->ic_curchan;
    if (!c || !scn || !pdev)
        return -1;

    if (c->ic_freq < 3000) {
        ch_param->phy_mode = WMI_HOST_MODE_11G;
    } else {
        ch_param->phy_mode = WMI_HOST_MODE_11A;
    }

    if (IEEE80211_IS_CHAN_11AXA_HE80_80(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE80_80;
    else if (IEEE80211_IS_CHAN_11AXA_HE160(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE160;
    else if (IEEE80211_IS_CHAN_11AXA_HE80(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE80;
    else if (IEEE80211_IS_CHAN_11AXA_HE40(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE40;
    else if (IEEE80211_IS_CHAN_11AXA_HE20(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE20;
    else if (IEEE80211_IS_CHAN_11AC_VHT80_80(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT80_80;
    else  if (IEEE80211_IS_CHAN_11AC_VHT160(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT160;
    else if (IEEE80211_IS_CHAN_11AC_VHT80(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT80;
    else if (IEEE80211_IS_CHAN_11AC_VHT40(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT40;
    else if (IEEE80211_IS_CHAN_11AC_VHT20(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT20;
    else if (IEEE80211_IS_CHAN_11NA_HT40(c))
        ch_param->phy_mode = WMI_HOST_MODE_11NA_HT40;
    else if (IEEE80211_IS_CHAN_11NA_HT20(c))
        ch_param->phy_mode = WMI_HOST_MODE_11NA_HT20;
    else if (IEEE80211_IS_CHAN_11AXG_HE40(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE40_2G;
    else if (IEEE80211_IS_CHAN_11AXG_HE20(c))
        ch_param->phy_mode = WMI_HOST_MODE_11AX_HE20_2G;
    else if (IEEE80211_IS_CHAN_11NG_HT40(c))
        ch_param->phy_mode = WMI_HOST_MODE_11NG_HT40;
    else if (IEEE80211_IS_CHAN_11NG_HT20(c))
        ch_param->phy_mode = WMI_HOST_MODE_11NG_HT20;

    wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                      ol_ath_vap_is_2gvht_en,
                                      &is_2gvht_en, 0, WLAN_VDEV_TARGET_IF_ID);

    if (is_2gvht_en) {
        if (ol_target_lithium(scn->soc->psoc_obj)) {
            switch(ch_param->phy_mode) {
                case WMI_HOST_MODE_11NG_HT20:
                    ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT20_2G;
                    break;
                case WMI_HOST_MODE_11NG_HT40:
                    ch_param->phy_mode = WMI_HOST_MODE_11AC_VHT40_2G;
                    break;
                default:
                    break;
            }
        }
    }
    return 0;
}

static void ol_ath_increment_peeer_count(struct ieee80211com *ic, void * an)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_t wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    struct ieee80211_node *ni = (struct ieee80211_node *)an;
    if (!wmi_handle) {
        qdf_err("WMI handle is null");
        return;
    }

    /* If peer delete response is not enabled, the peer count
     * is handled in htt peer unmap event handler.
     */
    if (wmi_service_enabled(wmi_handle, wmi_service_sync_delete_cmds)) {
        if ((ni->ni_ext_flags & IEEE80211_NODE_TGT_PEER_VALID)) {
            qdf_atomic_inc(&scn->peer_count);
            ni->ni_ext_flags &= ~IEEE80211_NODE_TGT_PEER_VALID;
        }
    }
}

void wlan_tbtt_sync_timer_start_stop(enum tbtt_sync_timer val)
{
    uint8_t soc_idx;
    ol_ath_soc_softc_t *soc;

    for (soc_idx = 0; soc_idx < ol_num_global_soc; soc_idx++) {
        soc = ol_global_soc[soc_idx];
        if (soc && ol_target_lithium(soc->psoc_obj)) {
            switch(val) {
            case TBTT_SYNC_TIMER_START:
                if (!soc->tbtt_offset_sync_timer_running) {
                    qdf_timer_start(&(soc->tbtt_offset_sync_timer),
                                    DEFAULT_TBTT_SYNC_TIMER);
                    soc->tbtt_offset_sync_timer_running = 1;
                } else {
                    QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                              "%s: Tbtt sync timer is running", __func__);
                }
                break;
            case TBTT_SYNC_TIMER_STOP:
                if (soc->tbtt_offset_sync_timer_running) {
                    qdf_timer_stop(&(soc->tbtt_offset_sync_timer));
                    soc->tbtt_offset_sync_timer_running = 0;
                }
                break;
            default: /* No Op */
                break;
            }
        }
    }
}

static QDF_STATUS ol_ath_vap_up_complete(struct wlan_objmgr_vdev *vdev)
{
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);
    enum ieee80211_opmode opmode;
    struct ieee80211vap *tempvap;
    bool is_fw_cfgd_for_collision_detcn = false;
    bool enable_sta_coll_detn, enable_ap_coll_detn;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    bool is_mbssid_enabled;

    if (!psoc)
        return QDF_STATUS_E_FAILURE;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    opmode = ieee80211vap_get_opmode(vap);
    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                   WLAN_PDEV_F_MBSS_IE_ENABLE);

    enable_sta_coll_detn = ic->ic_he_target ?
        cfg_get(psoc, CFG_OL_STA_BSS_COLOR_COLLISION_DETECTION) : false;
    enable_ap_coll_detn = ic->ic_he_target ?
        cfg_get(psoc, CFG_OL_AP_BSS_COLOR_COLLISION_DETECTION) : false;

    if (is_mbssid_enabled)
        enable_ap_coll_detn = false;

    switch (vap->iv_opmode) {
            case IEEE80211_M_HOSTAP:
                /* if user has configured to enable bss color
                 * collision detection by available INI then
                 * only configure FW for bss color detection
                 * on AP
                 */
                if (enable_ap_coll_detn) {
                   /* go throught the vap list to see if we have
                    * already configured fw for color detection
                    */
                    TAILQ_FOREACH(tempvap, &ic->ic_vaps, iv_next) {
                        if(tempvap->iv_he_bsscolor_detcn_configd_vap) {
                            is_fw_cfgd_for_collision_detcn = true;
                            break;
                        }
                    }

                   /* if collision detection in fw is not already
                    * configured then do configuration for this vap
                    */
                    if (!is_fw_cfgd_for_collision_detcn) {
                        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                                  QDF_TRACE_LEVEL_INFO,
                                  "Configuring fw for AP mode bsscolor "
                                  "collision detection for vdev-id: 0x%x",
                                  wlan_vdev_get_id(vap->vdev_obj));

                        /* configure fw for bsscolor collision detection */
                        ol_ath_config_bss_color_offload(vap, false);
                        /* register for bsscolor collision detection event */
                        ol_ath_mgmt_register_bss_color_collision_det_config_evt(ic);

                        /* mark the vap for which collision detection
                         * has been configured
                         */
                        vap->iv_he_bsscolor_detcn_configd_vap = true;
                    }
                }

            break;
            case IEEE80211_M_STA:
                /* if user has configured to enable bss color
                 * collision detection by available INI then
                 * only configure FW for bss color detection
                 * on STA
                 */
                if (enable_sta_coll_detn) {
                    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                              QDF_TRACE_LEVEL_INFO,
                              "Configuring fw for STA mode bsscolor "
                              "collision detection for vdev-id: 0x%x",
                              wlan_vdev_get_id(vap->vdev_obj));

                    /* configure fw for bsscolor collision detection
                     * and for handling bsscolor change announcement
                     */
                    ol_ath_config_bss_color_offload(vap, false);
                }
            break;
            default:
                QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                        "Non-ap/non-sta mode of operation. "
                        "No configuration required for BSS Color");
            break;
        }

#if QCA_LTEU_SUPPORT
    if (!wlan_psoc_nif_feat_cap_get(psoc,
                                    WLAN_SOC_F_LTEU_SUPPORT)) {
#endif
#if OL_ATH_SUPPORT_LED
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->soc->led_blink_rate_table ) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, LED_POLL_TIMER);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        if ((lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA8074) ||
            (lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA8074V2 && scn->scn_led_gpio == 0) ||
            (lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA5018) ||
            (lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA6018)) {
            scn->scn_blinking = OL_BLINK_DONE;
        } else {
            scn->scn_blinking = OL_BLINK_ON_START;
        }

        if(lmac_get_tgt_type(psoc) == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, OL_LED_OFF);
        } else if (lmac_get_tgt_type(psoc) == TARGET_TYPE_QCA8074V2 && scn->scn_led_gpio) {
            gpio_set_value_cansleep(scn->scn_led_gpio, OL_LED_OFF);
        } else {
            tgt_gpio_output(psoc, scn->scn_led_gpio, 0);
        }
        if (scn->soc->led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#endif /* OL_ATH_SUPPORT_LED */
#if QCA_LTEU_SUPPORT
    }
#endif

#if WLAN_SUPPORT_FILS
    if (vap->iv_he_6g_bcast_prob_rsp) {
        /* Send broadcast probe response config to FW */
        ol_ath_wmi_send_vdev_bcast_prbrsp_param(ic->ic_pdev_obj,
                                           wlan_vdev_get_id(vap->vdev_obj),
                                           vap->iv_he_6g_bcast_prob_rsp_intval);
    } else {
        /* allocate fils discovery buffer and send FILS config to FW */
        target_if_fd_reconfig(vap->vdev_obj);
    }
#endif

    if (ol_target_lithium(psoc) && scn->is_scn_stats_timer_init)
        qdf_timer_mod(&(scn->scn_stats_timer), scn->pdev_stats_timer);

    if (opmode == IEEE80211_M_HOSTAP) {
        qdf_timer_mod(&(scn->auth_timer), DEFAULT_AUTH_CLEAR_TIMER);
    }

    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
        opmode == IEEE80211_M_HOSTAP &&
        !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        wlan_tbtt_sync_timer_start_stop(TBTT_SYNC_TIMER_START);
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
ol_ath_hostap_up_pre_init(struct wlan_objmgr_vdev *vdev, bool restart)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211_node *ni = NULL;
    struct ol_ath_vap_net80211 *tx_avn;
    bool is_nontx_vap = false;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ni = vap->iv_bss;
    if (!ni)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    if (vap->iv_special_vap_mode) {
        if(!vap->iv_smart_monitor_vap &&
           lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_AR9888) {
            /* Set Rx decap to RAW mode */
            vap->iv_rx_decap_type = htt_cmn_pkt_type_raw;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_vops) {
                ic->nss_vops->ic_osif_nss_vdev_set_cfg(
                                              (osif_dev *)vap->iv_ifp,
                                              OSIF_NSS_VDEV_DECAP_TYPE);
            }
#endif
            if (ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_rx_decap_mode,
                                      htt_cmn_pkt_type_raw) != EOK)
                qdf_err("Error setting rx decap mode to RAW");
        }

        return QDF_STATUS_E_CANCELED;
    }

    if (vap->iv_enable_vsp) {
        ol_ath_vdev_param_capabilities_set(scn, vap,
                                           WMI_HOST_VDEV_VOW_ENABLED);
    }

    is_nontx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        int value = 0;
        int status = 0;

        if (!is_nontx_vap) {
            /* If this is a mesh vap and Beacon is enabled for it,
             * send WMI capabiltiy to FW to enable Beacon */
            value = 0;
            if (vap->iv_mesh_cap & MESH_CAP_BEACON_ENABLED) {
                qdf_info("Enabling Beacon on Mesh Vap (vdev id: %d)",
                         wlan_vdev_get_id(vap->vdev_obj));
                value = WMI_HOST_VDEV_BEACON_SUPPORT;
            }

            ol_ath_vdev_param_capabilities_set(scn, vap, value);
        } else {
            /* If mesh vap a non tx vap then based on mesh capablities
             * invoke mbssid beacon control api with corresponding command */
            if (vap->iv_mesh_cap & MESH_CAP_BEACON_ENABLED) {
                status = ieee80211_mbssid_beacon_control(vap,
                                                         MBSS_BCN_ENABLE);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                                  "%s: Mesh non_tx beacon ctrl status = %d\n",
                                  __func__, status);
            }
        }
    }
#endif

    /**
     * For non-offload beacon, free previous deferred beacon buffers
     * in RESTART
     */
    if (restart && !vap->iv_bcn_offload_enable)
        ol_ath_beacon_free(vap);

    /* allocate beacon buffer */
#if MESH_MODE_SUPPORT
    /* invoke beacon alloc only for mesh vap is legacy or tx-vap */
    if (!vap->iv_mesh_vap_mode || !is_nontx_vap)
#endif
    ol_ath_beacon_alloc(vap);

    /**
     * For offload beacon, free previous deferred beacon buffers
     * in RESTART
     */
    if (restart && vap->iv_bcn_offload_enable)
        ol_ath_beacon_free(vap);

    /* The VAP is brought down if ie_overflow is set or for a
     * nonTx VAP, if non_tx_pfl_ie_pool is NULL
     *
     * ie_overflow flag will be set
     *     1. When profile size is overflown for nonTx VAP
     *        subelement profile in MBSS IE, OR
     *     2. When common IE size is overflown for TxVAP.
     */
    if (IS_MBSSID_EMA_EXT_ENABLED(ic)) {
        if (vap->iv_mbss.ie_overflow ||
            (is_nontx_vap && !vap->iv_mbss.non_tx_pfl_ie_pool)) {
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (is_nontx_vap) {
        /* If vap coming up is Non Tx vap (in Mbssid set)
         * and if the bcast probe resp buffer is already
         * present and bcast prb rsp is enabled by user,
         * call ieee80211_prb_rsp_alloc_init with Tx vaps
         * avn to update it with this non tx vap info.
         * After updating, send the template.
         */
        if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            struct ieee80211vap *tx_vap;

            tx_vap = ic->ic_mbss.transmit_vap;
            tx_avn = OL_ATH_VAP_NET80211(tx_vap);

            /* Sanity check for prb rsp buffer, the buffer should be
             * created by Tx vap.
             */
            if (tx_vap && tx_avn &&
                tx_vap->iv_he_6g_bcast_prob_rsp &&
                tx_avn->av_pr_rsp_wbuf) {
                tx_avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(ni,
                                         &tx_avn->av_prb_rsp_offsets);
                if (tx_avn->av_pr_rsp_wbuf) {
                   if (QDF_STATUS_SUCCESS != ic->ic_prb_rsp_tmpl_send(tx_vap->vdev_obj))
                       qdf_err("20TU prb rsp send failed");
                }
            }
#ifdef WLAN_SUPPORT_FILS
            if (tx_vap && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                if (QDF_STATUS_SUCCESS !=
                    ol_ath_fd_tmpl_update(tx_vap->vdev_obj))
                    qdf_debug("FILS template update failed");
            }
#endif /* WLAN_SUPPORT_FILS */
        }
    } else { /* If Tx Vap */
        if (vap->iv_he_6g_bcast_prob_rsp) {
            tx_avn = OL_ATH_VAP_NET80211(vap);
            if (tx_avn) {
                tx_avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(ni,
                                     &tx_avn->av_prb_rsp_offsets);
                if (tx_avn->av_pr_rsp_wbuf) {
                    if (QDF_STATUS_SUCCESS != ic->ic_prb_rsp_tmpl_send(vap->vdev_obj))
                        qdf_err("20TU prb rsp send failed");
                }
            }
        }
    }
#if WLAN_SUPPORT_FILS
    /* allocate fils discovery buffer */
    if (restart)
        target_if_fd_free(vdev);

    target_if_fd_alloc(vdev);
#endif
    ic->ic_vap_set_param(vap, IEEE80211_VHT_SUBFEE, 0);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_ath_vap_down(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
#if ATH_SUPPORT_DFS
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#endif

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT

    /*
    * Avoid NSS call for non existing vops
    */
    if (ic->nss_vops) {
        ic->nss_vops->ic_osif_nss_vap_down((osif_dev *)vap->iv_ifp);
    }
#endif

    if(!ieee80211_get_num_vaps_up(ic)) {
#if ATH_SUPPORT_DFS
        dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);

        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) ==
                                         QDF_STATUS_SUCCESS) {
            if (dfs_rx_ops && dfs_rx_ops->dfs_reset_dfs_prevchan)
                dfs_rx_ops->dfs_reset_dfs_prevchan(pdev);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
       }
#endif
        if (ol_target_lithium(scn->soc->psoc_obj) &&
            scn->is_scn_stats_timer_init) {

            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                                             QDF_STATUS_SUCCESS)
                    return QDF_STATUS_E_FAILURE;

            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            ol_if_dfs_reset_agile_cac(ic);
            qdf_timer_sync_cancel(&(scn->scn_stats_timer));
        }
    }

    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            vap->iv_opmode == IEEE80211_M_HOSTAP) {
                wlan_tbtt_sync_timer_start_stop(TBTT_SYNC_TIMER_STOP);
        }
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_ath_get_restart_target_status(
                                     struct wlan_objmgr_vdev *vdev,
                                     int restart)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    if (scn->soc->target_status == OL_TRGET_STATUS_EJECT ||
        scn->soc->target_status == OL_TRGET_STATUS_RESET) {
        qdf_info("Target recovery in progress");
        if (!restart)
            wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                               WLAN_VDEV_SM_EV_START_REQ_FAIL,
                                               0, NULL);
        else
            wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                               WLAN_VDEV_SM_EV_RESTART_REQ_FAIL,
                                               0, NULL);

        return QDF_STATUS_E_CANCELED;
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_ath_vap_stop_pre_init(struct wlan_objmgr_vdev *vdev)
{
    enum ieee80211_opmode opmode;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    ol_txrx_soc_handle soc_txrx_handle;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    opmode = ieee80211vap_get_opmode(vap);
    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn)
        return QDF_STATUS_E_FAILURE;

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    /*
     * free any pending nbufs in the flow control queue
     */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if(!scn->nss_radio.nss_rctx)
#endif
    {
        cdp_tx_flush_buffers(soc_txrx_handle, wlan_vdev_get_id(vdev));
    }

    /* NOTE: Call the ol_ath_beacon_stop always before sending vdev_stop
     * to Target. ol_ath_beacon_stop puts the beacon buffer to
     * deferred_bcn_list and this beacon buffer gets freed,
     * when stopped event recieved from target. If the ol_ath_beacon_stop
     * called after wmi_unified_vdev_stop_send, then Target could
     * respond with vdev stopped event immidiately and deferred_bcn_list
     * is still be empty and the beacon buffer is not freed.
     */
    ol_ath_beacon_stop(avn);
    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
        ol_ath_prb_rsp_stop(avn);

#if WLAN_SUPPORT_FILS
    /* puts fd buffer to deferred_fd_list which gets freed when
     * stopped event is received from target.
     */
    target_if_fd_stop(vdev);
#endif

    /*
     * Start the timer for vap stopped event after ol_ath_beacon_stop
     * puts the beacon buffer in to deferred_bcn_list
     */
    if ((scn->soc->target_status == OL_TRGET_STATUS_EJECT) ||
        (scn->soc->target_status == OL_TRGET_STATUS_RESET)) {
        /* target ejected/reset,  so generate the stopped event */
        wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                           WLAN_VDEV_SM_EV_STOP_RESP,
                                           0, NULL);
        return QDF_STATUS_E_CANCELED;
    }

#if QCA_LTEU_SUPPORT
    if (!wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj,
                                    WLAN_SOC_F_LTEU_SUPPORT)) {
#endif
#if OL_ATH_SUPPORT_LED
        ol_ath_clear_led_params(scn);
#endif
#if QCA_LTEU_SUPPORT
    }
#endif

    return QDF_STATUS_SUCCESS;
}

#if WLAN_SUPPORT_FILS
static void ol_ath_vap_cleanup(struct ieee80211vap *vap)
{
    target_if_fd_free(vap->vdev_obj);
}
#endif


static void ol_ath_vap_iter_bcn_stats(void *arg, struct ieee80211vap *vap)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    struct stats_request_params param;
    uint8_t addr[QDF_MAC_ADDR_SIZE];
    wmi_unified_t pdev_wmi_handle;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
        return;

    if (CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TICKS() - vap->vap_bcn_stats_time) < 2000)
        return;

    qdf_atomic_init(&(vap->vap_bcn_event));
    vap->vap_bcn_stats_time = 0;

    qdf_mem_set(&param, sizeof(param), 0);
    qdf_ether_addr_copy(addr, vap->iv_myaddr);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);
    param.stats_id = WMI_HOST_REQUEST_BCN_STAT;

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(scn->sc_pdev);

    if (pdev_wmi_handle) {
        wmi_unified_stats_request_send(pdev_wmi_handle, addr, &param);
    } else {
        qdf_err("WMI handle is NULL");
    }
}

static void ol_ath_get_vdev_bcn_stats(struct ieee80211vap *vap)
{
    wlan_iterate_vap_list(vap->iv_ic, ol_ath_vap_iter_bcn_stats, NULL);
}

static void ol_ath_reset_vdev_bcn_stats(struct ieee80211vap *vap)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    struct stats_request_params param;
    uint8_t addr[QDF_MAC_ADDR_SIZE];
    wmi_unified_t pdev_wmi_handle;

    qdf_mem_set(&param, sizeof(param), 0);
    qdf_ether_addr_copy(addr, vap->iv_myaddr);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);
    param.stats_id = WMI_HOST_REQUEST_BCN_STAT_RESET;

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(scn->sc_pdev);

    if (pdev_wmi_handle) {
        wmi_unified_stats_request_send(pdev_wmi_handle, addr, &param);
    } else {
        qdf_err("WMI handle is NULL");
    }
}

static void ol_ath_get_vdev_prb_fils_stats(struct ieee80211vap *vap)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    struct stats_request_params param;
    uint8_t addr[QDF_MAC_ADDR_SIZE];
    wmi_unified_t pdev_wmi_handle;

    qdf_mem_set(&param, sizeof(param), 0);
    qdf_ether_addr_copy(addr, vap->iv_myaddr);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);
    param.stats_id = WMI_HOST_REQUEST_VDEV_PRB_FILS_STAT;

    qdf_debug("request vdev_prb_fils stats V:%d P:%d Stats_id:%d\n",
              param.vdev_id, param.pdev_id, param.stats_id);

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(scn->sc_pdev);

    if (pdev_wmi_handle) {
        wmi_unified_stats_request_send(pdev_wmi_handle, addr, &param);
    } else {
        qdf_err("WMI handle is NULL");
    }
}

/**
 * ol_vdev_add_dfs_violated_chan_to_nol() - Add dfs violated channel to NOL.
 * If an AP vap tries to come up on a NOL channel, FW sends a failure in
 * vap's start response (DFS_VIOLATION) and this channel is added to NOL.
 * @ic: Pointer to radio object.
 * @chan:Pointer to the ic channel structure.
 */
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
void
ol_vdev_add_dfs_violated_chan_to_nol(struct ieee80211com *ic,
                                     struct ieee80211_ath_channel *chan)
{
    struct wlan_objmgr_pdev *pdev;

    pdev = ic->ic_pdev_obj;
    ieee80211_dfs_channel_mark_radar(ic, chan);
}
#endif

/**
 * ol_vdev_pick_random_chan_and_restart() - Find a random channel and restart
 * vap. This is the action taken when FW sends a dfs violation failure in start
 * response of the vap. A random non-DFS channel is preferred first. If it
 * fails, a random DFS channel is chosen. Irrespective of the state of the
 * vap, all the vaps created are restarted.
 *
 * @vap: Pointer to vap object.
 */

void ol_vdev_pick_random_chan_and_restart(wlan_if_t vap)
{
    struct ieee80211com  *ic;

    ic = vap->iv_ic;
    IEEE80211_CSH_NONDFS_RANDOM_ENABLE(ic);
    ieee80211_dfs_action(vap, NULL, true);
    vap->vap_start_failure = false;
    IEEE80211_CSH_NONDFS_RANDOM_DISABLE(ic);
}

static QDF_STATUS
ol_ath_vap_start_response_event_handler(struct vdev_start_response *rsp,
                                        struct vdev_mlme_obj *vdev_mlme)
{
    struct ieee80211com  *ic;
    wlan_if_t vaphandle;
    struct ol_ath_vap_net80211 *avn;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    uint32_t dfs_region;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    struct ieee80211_ath_channel *chan = NULL;
    struct wlan_channel *des_chan;
#endif
    uint16_t vdev_id;

    vdev = vdev_mlme->vdev;
    vaphandle = wlan_vdev_get_mlme_ext_obj(vdev);
    if(!vaphandle)
       return QDF_STATUS_E_FAILURE;

    psoc = wlan_vdev_get_psoc(vdev);
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (!dfs_rx_ops)
       return QDF_STATUS_E_FAILURE;

    avn = OL_ATH_VAP_NET80211(vaphandle);
    ic = vaphandle->iv_ic;
    vdev_id = wlan_vdev_get_id(vdev);

    pdev = wlan_vdev_get_pdev(vdev);

    switch (vaphandle->iv_opmode) {

        case IEEE80211_M_MONITOR:
               /* Handle same as HOSTAP */
        case IEEE80211_M_HOSTAP:
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
           /* FW to send CHAN_BLOCKED error code in start resp if host comes
            * up in a DFS channel after spoof test failure. In this case,
            * rebuild ic chan list and restart the vaps with non-DFS chan.
            */
            if (rsp->status == WLAN_MLME_HOST_VDEV_START_CHAN_BLOCKED) {
                if (!ic->ic_rebuilt_chanlist) {
                    if (!ieee80211_dfs_rebuild_chan_list_with_non_dfs_channels(ic)) {
                        ol_vdev_pick_random_chan_and_restart(vaphandle);
                        return QDF_STATUS_E_AGAIN;
                    } else {
                        return QDF_STATUS_E_CANCELED;
                    }
                }
                else {
                    qdf_err("****** channel list is rebuilt ***");
                }
                return QDF_STATUS_E_AGAIN;
            }
#endif
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
            reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);

            if (!reg_rx_ops) {
                vaphandle->channel_switch_state = 0;
                return QDF_STATUS_E_FAILURE;
            }

            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                                                          QDF_STATUS_SUCCESS) {
                vaphandle->channel_switch_state = 0;
                return QDF_STATUS_E_FAILURE;
            }
            reg_rx_ops->get_dfs_region(pdev, &dfs_region);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

            if (rsp->status == WLAN_MLME_HOST_VDEV_START_CHAN_DFS_VIOLATION) {
                /* Firmware response states: Channel is invalid due to
                 * DFS Violation.  Following are the action taken:
                 * 1) Add the violated channel to NOL.
                 * 2) Restart vaps with a random channel.
                 * In case of multiple vaps, ensure that action is taken only
                 * once during the first vap's start failure. Remember the
                 * failure event and bypass the action if failure event is
                 * received for other vaps.
                 */
                QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                          "Error %s : failed vdev start vap %d "
                          "status %d\n", __func__,
                          vdev_id, rsp->status);

                /* As we return from vap's start response, release
                 * all the acquired references and locks.
                 */
                vaphandle->channel_switch_state = 0;

                if (!vaphandle->vap_start_failure_action_taken) {
                    /* Why should the following variables be set or reset here?
                     * 1.channel_switch_state: Consider a case where user
                     * tries to send CSA on a NOL channel.This variable will
                     * be set in beacon update and will be cleared only on
                     * successful vap start response. As it is a failure here,
                     * it will not be reset. If not reset, subsequent CSA will
                     * fail in beacon update assuming that the previous CSA is
                     * still in progress.
                     *
                     * 2.vap_start_failure: To mark the state that vap start
                     * has failed so that vdev restart action is done in
                     * dfs_action not via CSA as a CSA in NOL chan is a
                     * violation.
                     */

                    vaphandle->vap_start_failure = true;
                    ieee80211com_clear_flags(ic, IEEE80211_F_DFS_CHANSWITCH_PENDING);
                    des_chan = wlan_vdev_mlme_get_des_chan(vdev);
                    if (!des_chan) {
                        qdf_err("(vdev-id:%d) desired channel not found", wlan_vdev_get_id(vdev));
                        return QDF_STATUS_E_FAILURE;
                    }

                    chan = ieee80211_find_dot11_channel(ic, des_chan->ch_freq,
                                                        des_chan->ch_cfreq2,
                                                        wlan_vdev_get_ieee_phymode(des_chan->ch_phymode));
                    if (!chan) {
                        qdf_err("(vdev-id:%d) des chan(%d) is NULL",
                                wlan_vdev_get_id(vdev), des_chan->ch_ieee);
                        return QDF_STATUS_E_FAILURE;
                    }

                    ol_vdev_add_dfs_violated_chan_to_nol(ic, chan);
                    ol_vdev_pick_random_chan_and_restart(vaphandle);
                } else {
                    QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_ERROR,
                              "%s: Vap start failure action taken. "
                              "Ignore the error\n", __func__);
                }
                return QDF_STATUS_E_AGAIN;
            }
#endif

#ifdef QCA_SUPPORT_AGILE_DFS
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                                             QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
            if (dfs_rx_ops->dfs_agile_sm_deliver_evt)
                dfs_rx_ops->dfs_agile_sm_deliver_evt(pdev,
                        DFS_AGILE_SM_EV_AGILE_START);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
#endif /* QCA_SUPPORT_AGILE_DFS */

            break;
        default:
            break;
    }

    return QDF_STATUS_SUCCESS;
}

/* WMI event handler for Roam events */
static int
ol_ath_vdev_roam_event_handler(
    ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_roam_event evt;
    struct ieee80211vap *vap;
    struct wlan_objmgr_vdev *vdev;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if(wmi_extract_vdev_roam_param(wmi_handle, data, &evt)) {
        return -1;
    }
    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj, evt.vdev_id, WLAN_MLME_SB_ID);
    if (!vdev) {
        qdf_err("Unable to find vdev for %d vdev_id", evt.vdev_id);
        return -EINVAL;
    }
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (vap) {
        switch (evt.reason) {
            case WMI_HOST_ROAM_REASON_BMISS:
                ASSERT(vap->iv_opmode == IEEE80211_M_STA);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_ASSOC,
                        "%s : BMISS event received from FW for STA vdev = %pK\n",
                        __func__, vdev);
                ieee80211_mlme_sta_bmiss_ind(vap);
                break;
            case WMI_HOST_ROAM_REASON_BETTER_AP:
                /* FIX THIS */
            default:
                break;
        }
    }
    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);

    return 0;
}

/* Device Interface functions */
static void ol_ath_vap_iter_vap_create(void *arg, wlan_if_t vap)
{

    struct ieee80211com *ic = vap->iv_ic;
    u_int32_t *pid_mask = (u_int32_t *) arg;
    u_int8_t myaddr[QDF_MAC_ADDR_SIZE];
    u_int8_t id = 0;
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    /* Proxy STA VAP has its own mac address */
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    if (avn->av_is_psta)
#else
    if (dp_wrap_vdev_is_psta(vap->vdev_obj))
#endif
        return;
#endif
    ieee80211vap_get_macaddr(vap, myaddr);
    ATH_GET_VAP_ID(myaddr, ic->ic_myaddr, id);
    (*pid_mask) |= (1 << id);
}

#if ATH_SUPPORT_NAC
int ol_ath_neighbour_rx(struct ieee80211vap *vap, uint32_t idx,
                        enum ieee80211_nac_param nac_cmd,
                        enum ieee80211_nac_mactype nac_type,
                        uint8_t macaddr[QDF_MAC_ADDR_SIZE])
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t action = nac_cmd;
    uint32_t type = nac_type;
    struct set_neighbour_rx_params param;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wmi_unified *pdev_wmi_handle;
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -1;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    if (IEEE80211_IS_MULTICAST((uint8_t *)macaddr) ||
        IEEE80211_ADDR_EQ((uint8_t *)macaddr, nullmac)) {
        qdf_info("NAC client / BSSID is invalid");
        return -1;
    }
    /* For NAC client, we send the client addresses to FW for all platforms.
     * Legacy and HKv2 FW can handle it. For HKv1 FW ignores this command and
     * does not use this address.
     */
    if (type == IEEE80211_NAC_MACTYPE_CLIENT) {
        soc_txrx_handle = wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(ic->ic_pdev_obj));
        if (nac_cmd == IEEE80211_NAC_PARAM_LIST) {
#if ATH_SUPPORT_NAC_RSSI
            cdp_vdev_get_neighbour_rssi(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj),
                                        macaddr, &vap->iv_nac.client[idx].rssi);
#endif
        } else {
            qdf_mem_set(&param, sizeof(param), 0);
            param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
            param.idx = idx;
            param.action = action;
            param.type = type;
            if (!pdev_wmi_handle) {
                qdf_err("Wmi handle is NULL!!");
                return -1;
            }
            if (wmi_unified_vdev_set_neighbour_rx_cmd_send(pdev_wmi_handle,
                                                           macaddr, &param)) {
                qdf_err("Unable to send NAC to target");
                return -1;
            }
            cdp_update_filter_neighbour_peers(soc_txrx_handle,
                                              wlan_vdev_get_id(vap->vdev_obj),
                                              nac_cmd, macaddr);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC,
                    "%s :vdev =%x, idx=%x, action=%x, macaddr[0][5]=%2x%2x",
                    __func__, param.vdev_id, idx, action, macaddr[0],macaddr[5]);
          }
    } else if (type == IEEE80211_NAC_MACTYPE_BSSID){

	qdf_mem_set(&param, sizeof(param), 0);
	param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	param.idx = idx;
	param.action = action;
	param.type = type;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC,
            "%s :vdev =%x, idx=%x, action=%x, macaddr[0][5]=%2x%2x",
            __func__, param.vdev_id, idx, action, macaddr[0],macaddr[5]);

        if (wmi_unified_vdev_set_neighbour_rx_cmd_send(pdev_wmi_handle, macaddr,
                                                       &param)) {
            qdf_err("Unable to send neighbor rx command to target");
            return -1;
    	}
    }
    /* assuming wmi will be always success */
    return 1;
}

int ol_ath_neighbour_get_max_addrlimit(struct ieee80211vap *vap,
                                       enum ieee80211_nac_mactype nac_type)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (!scn || !scn->soc || !scn->soc->psoc_obj)
        return 0;

    if (nac_type == IEEE80211_NAC_MACTYPE_BSSID)
        return ic->ic_nac_bssid;
    else if (nac_type == IEEE80211_NAC_MACTYPE_CLIENT)
        return ic->ic_nac_client;
    else
        return 0;
}
#endif
#if ATH_SUPPORT_WRAP
static inline uint8_t ol_ath_get_qwrap_num_vdevs(struct ieee80211com *ic)
{
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_psoc *psoc;

    if (!pdev) {
        qdf_err("null pdev");
        return 0;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("null psoc");
        return 0;
    }

    if (cfg_get(psoc, CFG_OL_QWRAP_ENABLE)) {
        return init_deinit_get_qwrap_vdevs_for_pdev_id(psoc,
                lmac_get_pdev_idx(pdev));
    } else {
        return init_deinit_get_total_vdevs_for_pdev_id(psoc,
                lmac_get_pdev_idx(pdev));
    }
}
#endif

#if ATH_SUPPORT_NAC_RSSI
static int ol_ath_config_for_nac_rssi(struct ieee80211vap *vap,
                                      enum ieee80211_nac_rssi_param nac_cmd,
                                      uint8_t bssid_macaddr[QDF_MAC_ADDR_SIZE],
                                      uint8_t client_macaddr[QDF_MAC_ADDR_SIZE],
                                      uint8_t chan_num)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    ol_txrx_soc_handle soc_txrx_handle;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -1;

    psoc = wlan_pdev_get_psoc(pdev);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    if (nac_cmd == IEEE80211_NAC_RSSI_PARAM_LIST) {
        if (!cdp_vdev_get_neighbour_rssi(soc_txrx_handle,
                                         wlan_vdev_get_id(vap->vdev_obj),
                                         client_macaddr,
                                         &vap->iv_nac_rssi.client_rssi))
            vap->iv_nac_rssi.client_rssi_valid = 1;
    } else {
        if (cdp_vdev_config_for_nac_rssi(soc_txrx_handle,
                                         wlan_vdev_get_id(vap->vdev_obj),
                                         nac_cmd, bssid_macaddr,
                                         client_macaddr, chan_num)) {
            qdf_nofl_info("Unable to send the scan nac rssi command to target \n");
            return -1;
        }
    }

   return 1;
}
#endif

wlan_if_t osif_get_vap(osif_dev *osifp);

/* ol_ath_get_vendor_ie_size_from_soc: helper function to get the default
 * value for vendor IE size from soc level variable. The default value is
 * stored in nibble corresponding to bssidx - 1 for that vap. This is
 * because index bssidx 0 is reserved for Tx-VAP so non-Tx VAP 1 corresponds
 * to bssidx 1, which is nibble 0 of soc level config.
 * @soc: soc struct handle
 * @ic: ic struct handle
 * @idx: index corresponding to bssidx_i + 1
 * Return: cur_vendor_ie_size, the vendor IE size to use for configuration
 */
static int ol_ath_get_vendor_ie_size_from_soc(struct ieee80211com *ic, int idx)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ic;
    ol_ath_soc_softc_t *soc = scn->soc;
    int cur_vendor_ie_size = 0;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                        WLAN_PDEV_F_MBSS_IE_ENABLE);

    if(!is_mbssid_enabled) {
        qdf_info("MBSSID Disabled, no non-Tx vendor IE profile info present, using default size of %d",
                 cur_vendor_ie_size);
        return cur_vendor_ie_size;
    }

    if (!soc) {
        qdf_info("NULL soc, choosing vendor IE size of %d", cur_vendor_ie_size);
        return cur_vendor_ie_size;
    }

    /* bssid_idx starts at 1, with idx 0 reserved for Tx-VAP,
     * so reject idx 0 here.
     */
    if (idx <= 0 || idx > soc->ema_ap_num_max_vaps) {
        qdf_info("idx must be 0 < idx (%d) <= soc->ema_ap_num_max_vaps (%d), using default vendor IE size of %d",
                idx, soc->ema_ap_num_max_vaps, cur_vendor_ie_size);
        return cur_vendor_ie_size;
    }

    /* Since BSS idx of Tx-VAP is 0, non-Tx VAPs use indices [1,15].
     * So, idx of first non-Tx VAP is 1, which corresponds to nibble
     * 0 of config_low. To account for this, check BSS idx 1-8 to map
     * to config_low 0-7. Same logic applies for config_high. The
     * config_high indices 8-15 map to BSS idx 9-16.
     */
    if (idx < IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX + 1) {
        cur_vendor_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                soc->ema_ap_vendor_ie_config_low, (idx - 1));
    } else  {
        cur_vendor_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                soc->ema_ap_vendor_ie_config_high,
                                (idx - IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX - 1));
    }
    return cur_vendor_ie_size;
}

/* ol_ath_update_max_pp_and_beacon_pos: function to update the max profile
 * periodicity and mapping from non-Tx profiles to beacons. This function
 * is only called once, when the first vap is brought up (regardless of if
 * the vap brought up is Tx VAP or not). Note, Tx VAP must be set for this
 * function to work properly.
 * @ic: handle for ic struct
 * Return: 0 on success or error val upon error
 */
static int ol_ath_update_max_pp_and_beacon_pos(struct ieee80211com *ic)
{
    int i, total_profile_size = 0, cur_profile_size = 0, cur_pos = 0;
    int max_pp = 1, bssidx_i, is_bssidx_i_assigned = 0, nodeidx_i;
    uint8_t node_idx_tx_vap;
    struct ieee80211vap *vap;
    struct wlan_objmgr_vdev *vdev;
    int cur_vendor_ie_size = 0, cur_optional_ie_size = 0;
    struct ieee80211_mbss_ie_cache_node *node = NULL;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ic;
    ol_ath_soc_softc_t *soc = scn->soc;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                        WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    if(!is_mbssid_enabled) {
        qdf_info("MBSSID Disabled, no non-Tx profile info to update");
        return -EINVAL;
    }

    /* Tx-VAP is set before calling this function so if this value is
     * NULL, an unexpected case has been hit, from which recovery is
     * not possible.
     */
    QDF_ASSERT((ic->ic_mbss.transmit_vap != NULL));
    if (ic->ic_mbss.transmit_vap == NULL) {
        return -EINVAL;
    }

    /* In case where MBSSID is enabled and EMA is disabled, update
     * the max number of non-Tx VAPs for a single profile based on
     * user configured values by reseting the count and incrementing
     * for each profile that fits in first beacon
     */
    if (is_mbssid_enabled && !is_ema_ap_enabled) {
        ic->ic_mbss.max_non_transmit_vaps = 0;
    }

    qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

    /* Initialize max_pp to soc level value */
    ic->ic_mbss.max_pp = soc->ema_ap_max_pp;

    /* node_idx(tx-vap) = f(ema_max_ap, rf)
     *                  = ema_max_ap  – rf – 1
     */
    node_idx_tx_vap = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                                    scn->soc->ema_ap_num_max_vaps);
    /* ic->ic_mbss.mbss_offset[cur] provides the offset to the
     * first node of MBSS-cache in the beacon-position signified
     * by 'cur'.
     *
     * Beacon position 0 is assigned to the non-Tx vap residing
     * in the node immediately next to the current Tx-vap. This
     * is true as beacon-position 0 is assigned to the non-Tx
     * vap with bssidx 1 and non-Tx vap with bssidx 1 is always
     * placed in the node immediately next to the Tx-vap in MBSS
     * cache. In case the current Tx-vap is at the last node of
     * the MBSS-cache, the first node in the cache will occupy
     * beacon-position 0.
     *
     * nodeidx_i below is the node-idx of the first node with
     * beacon_position 0
     */
    nodeidx_i = (node_idx_tx_vap + 1) % (scn->soc->ema_ap_num_max_vaps);
    qdf_debug("node-idx first node with beacon-position 0: %d", nodeidx_i);
    /* Retrieve first node at beacon-position 0 */
    node      = &((struct ieee80211_mbss_ie_cache_node *)
                             ic->ic_mbss.mbss_cache)[nodeidx_i];
    ic->ic_mbss.mbss_offset[cur_pos] = (uint8_t *)node -
                            (uint8_t *) ic->ic_mbss.mbss_cache;

    for (i = 0; i < soc->ema_ap_num_max_vaps - 1; ++i) {
        bssidx_i = i + 1;
        is_bssidx_i_assigned =
                ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX]
                & (unsigned long)(1 << i);

        /* node_idx(non-tx vap) = f(node_idx_tx_vap, bssidx)
         *                      = (node_idx_tx_vap + bssidx) % ema_max_ap
         *                      = (ema_max_ap – rf – 1 + bssidx) % ema_max_ap
         */
        nodeidx_i = (soc->ema_ap_num_max_vaps - ic->ic_mbss.rot_factor +
                     bssidx_i - 1) % soc->ema_ap_num_max_vaps;
        node = &((struct ieee80211_mbss_ie_cache_node *)
                 ic->ic_mbss.mbss_cache)[nodeidx_i];

        if (is_bssidx_i_assigned) {
            if (node->used) {
                vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev,
                                                            node->vdev_id,
                                                            WLAN_MLME_NB_ID);
                if (!vdev) {
                    qdf_err("vdev is NULL");
                    goto set_def_assignments;
                }

                vap = wlan_vdev_mlme_get_ext_hdl(vdev);
                if (!vap) {
                    qdf_err("VAP is NULL");
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
                    goto set_def_assignments;
                }

                if (!IEEE80211_EMA_MBSS_FLAGS_GET(vap->iv_mbss.flags,
                     IEEE80211_EMA_MBSS_FLAGS_USER_CONFIGD_RSRC_PFL)) {
                    vap->iv_mbss.total_vendor_ie_size =
                            ol_ath_get_vendor_ie_size_from_soc(ic, bssidx_i);
                    vap->iv_mbss.total_optional_ie_size =
                            soc->ema_ap_optional_ie_size;
                }

                cur_vendor_ie_size = vap->iv_mbss.total_vendor_ie_size;
                cur_optional_ie_size = vap->iv_mbss.total_optional_ie_size;

                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
            } else {
                /* if bssidx_i is assigned but the corresponding node
                 * is not marked as used, we have hit irrecoverable case
                 * and something has gone drastically wrong
                 */
                QDF_ASSERT(0);
                qdf_debug("bssidx_i: %d is assigned but corresponding node_idx: %d is not used",
                          bssidx_i, nodeidx_i);
                goto set_def_assignments;
            }
        } else {
set_def_assignments:
            qdf_debug("No vap assigned to bssidx:%d. Using defaults", bssidx_i);
            cur_vendor_ie_size = ol_ath_get_vendor_ie_size_from_soc(ic, bssidx_i);
            cur_optional_ie_size = soc->ema_ap_optional_ie_size;
        }

        cur_profile_size = IEEE80211_MAX_NON_TX_PROFILE_SIZE_WITH_RSN +
                           cur_vendor_ie_size +
                           cur_optional_ie_size;

        if (soc->ema_ap_max_non_tx_size -
                total_profile_size < cur_profile_size) {
            /* In the case where MBSSID is enabled and EMA disabled,
             * if no more non-Tx profiles can fit in this beacon, then
             * break from the loop and do not count any more profiles.
             */
            if (is_mbssid_enabled && !is_ema_ap_enabled) {
                break;
            }
            ++max_pp;
            ++cur_pos;
            total_profile_size = cur_profile_size;
            ic->ic_mbss.mbss_offset[cur_pos] = (uint8_t *)node -
                                        (uint8_t *) ic->ic_mbss.mbss_cache;
        } else {
            /* In the case where MBSSID is enabled and EMA disabled,
             * set the max_non_transmit_vaps cnt to the max number
             * of non-Tx profiles that can fit in a single beacon.
             */
            if (is_mbssid_enabled && !is_ema_ap_enabled) {
                ++(ic->ic_mbss.max_non_transmit_vaps);
            }
            total_profile_size += cur_profile_size;
        }
        qdf_debug("nodeidx: %d, bssidx_i: %d, cur_pos: %d mbss_offset: 0x%x",
                nodeidx_i, bssidx_i, cur_pos, ic->ic_mbss.mbss_offset[cur_pos]);
        node->pos = cur_pos;
    } /* end num_max_vaps for loop */

    /* If odd then icrement by 1 */
    if ((max_pp > IEEE80211_ALLOWED_MAX_ODD_MAX_PP) && (max_pp & 1)) {
        /* ema_max_pp algorithm requires max pp to be even
         * value so that intermediate current PP values can
         * be determined based on factors of max pp
         */
        qdf_info("odd ema_ap_max_pp: %d. move to a even value"
                 " as per ema max_pp algorithm requirement",
                 max_pp);
        max_pp++;
    }
    qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
    ic->ic_mbss.max_pp = max_pp;
    qdf_info("max_pp: %d", max_pp);

    return 0;
}

/* ol_ath_init_ema_config: wrapper function which does sanity and then calls
 * the main function, ol_ath_update_max_pp_and_beacon_pos.
 * @ic: ic struct handle
 * Return: 0 on success and QDF_STATUS_E_FAILURE upon error
 */
static QDF_STATUS ol_ath_init_ema_config(struct ieee80211com *ic)
{
    bool is_mbssid_enabled =
        wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);

    if(!is_mbssid_enabled) {
        qdf_debug("MBSSID Disabled, no max-pp calc or beacon pos mapping necessary");
        return QDF_STATUS_E_FAILURE;
    }

    if (ol_ath_update_max_pp_and_beacon_pos(ic)) {
        qdf_err("Error in updating max_pp and beacon pos mappings");
        return QDF_STATUS_E_FAILURE;
    }

    return 0;
}

static QDF_STATUS ol_ath_nss_vap_destroy(struct wlan_objmgr_vdev *vdev)
{
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct vdev_osif_priv *vdev_osifp = wlan_vdev_get_ospriv(vdev);
    void *osifp_handle;
    nss_if_num_t nss_if;
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    osifp_handle = vdev_osifp->legacy_osif_priv;
    nss_if = ((osif_dev *)osifp_handle)->nss_ifnum;

    if (nss_if && (nss_if != -1) && (nss_if != NSS_PROXY_VAP_IF_NUMBER)) {
        osif_nss_vdev_dealloc(osifp_handle, nss_if);
    }

    if (opmode == QDF_STA_MODE) {
        /* For STAVAP, self peer will get created on FW
         * for accountability, decrement peer count here
         */
        qdf_atomic_inc(&scn->peer_count);
    }
#endif
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_ath_nss_vap_create(struct vdev_mlme_obj *vdev_mlme)
{
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ieee80211vap *vap = vdev_mlme->ext_vdev_ptr;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);
    struct vdev_osif_priv *vdev_osifp = wlan_vdev_get_ospriv(vdev);
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);
    void *osifp_handle;
    nss_if_num_t nss_if;

    osifp_handle = vdev_osifp->legacy_osif_priv;
    if (ic->nss_vops) {
        nss_if = ((osif_dev *)osifp_handle)->nss_ifnum;
        qdf_debug("nss-wifi:#0 VAP# vdev_id %d vap %pK osif %pK nss_if %d ",
                  wlan_vdev_get_id(vdev), vap, osifp_handle, nss_if);
        /*
         * For 11ax radio monitor vap creation in NSS should be avoided
         */
        if (opmode == QDF_MONITOR_MODE && ol_target_lithium(psoc)) {
            ((osif_dev *)osifp_handle)->nss_ifnum = NSS_PROXY_VAP_IF_NUMBER;
        } else {
            if (ic->nss_vops->ic_osif_nss_vap_create(vap, osifp_handle, nss_if) == -1) {
                qdf_err("NSS WiFi Offload Unabled to attach vap");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
#endif
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS ol_ath_vap_create_init(struct vdev_mlme_obj *vdev_mlme)
{
    uint32_t target_type;
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    struct ieee80211vap *vap = vdev_mlme->ext_vdev_ptr;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    nss_if_num_t nss_if;
    struct vdev_osif_priv *vdev_osifp = wlan_vdev_get_ospriv(vdev);
    void *osifp_handle;
#endif

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        goto ol_ath_vap_create_init_end;

    scn = OL_ATH_SOFTC_NET80211(ic);
    avn = OL_ATH_VAP_NET80211(vap);
    if (!scn || !avn) {
        qdf_err("Invalid input to OL create init");
        goto ol_ath_vap_create_init_end;
    }

    target_type = lmac_get_tgt_type(psoc);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    scn->sc_nwrapvaps = ic->ic_nwrapvaps;
    scn->sc_nscanpsta = ic->ic_nscanpsta;
    scn->sc_npstavaps = ic->ic_npstavaps;

    avn->av_is_wrap = vap->iv_wrap;
    avn->av_is_mpsta= vap->iv_mpsta;
    avn->av_is_psta = vap->iv_psta;
    avn->av_use_mat = vap->iv_mat;
    if (vap->iv_mat)
        OS_MEMCPY(avn->av_mat_addr, vap->iv_mat_addr, QDF_MAC_ADDR_SIZE);

    if (vap->iv_psta) {
        if (avn->av_is_mpsta) {
            OS_MEMCPY(avn->av_mat_addr, vap->iv_myaddr, QDF_MAC_ADDR_SIZE);
        }
    }
    if (vap->iv_mpsta) {
        qdf_spin_lock_bh(&scn->sc_mpsta_vap_lock);
        scn->sc_mcast_recv_vap = vap;
        qdf_spin_unlock_bh(&scn->sc_mpsta_vap_lock);
    }
#endif
    /*
     * This is only needed for Peregrine, remove this once we have HW CAP bit added
     * for enhanced ProxySTA support.
     */
    if (target_type == TARGET_TYPE_AR9888) {
        /* enter ProxySTA mode when the first WRAP or PSTA VAP is created */
#if WLAN_QWRAP_LEGACY
        if (ic->ic_nwrapvaps + ic->ic_npstavaps == 1)
#else
        if ((dp_wrap_vdev_get_nwrapvaps(pdev) + dp_wrap_vdev_get_npstavaps(pdev)) == 1)
#endif
            ol_ath_pdev_set_param(scn->sc_pdev,
                                  wmi_pdev_param_proxy_sta_mode, 1);
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops) {
        if (opmode == QDF_MONITOR_MODE && ol_target_lithium(psoc)) {
            /*
             * Avoid NSS interface allocation for 11ax radio in monitor mode.
             *  Monitor mode handled in host.
             */
            nss_if = NSS_PROXY_VAP_IF_NUMBER;
        } else {
            osifp_handle = vdev_osifp->legacy_osif_priv;
            nss_if = ic->nss_vops->ic_osif_nss_vdev_alloc(scn, vap,
                                                          osifp_handle);
#if DBDC_REPEATER_SUPPORT
            /*
             * Register notifier with bridge for Add/Del/Update bridge fdb entries.
             */
            if (target_type == TARGET_TYPE_QCA8074 ||
                    target_type == TARGET_TYPE_QCA8074V2 ||
                    target_type == TARGET_TYPE_QCA6018 ||
                    target_type == TARGET_TYPE_QCA5018 ||
                    target_type == TARGET_TYPE_QCN9000) {

                /*
                 * Registration required only for DBDC case.
                 */
                if (ic->ic_global_list->dbdc_process_enable) {
                    osif_nss_br_fdb_notifier_register();
                    osif_nss_br_fdb_update_notifier_register();
                }
            }
#endif

            qdf_debug("nss-wifi:#0 VAP# vap %pK  nss_if %d ", vap, nss_if);
            if (nss_if == -1) {
                goto ol_ath_vap_create_init_end;
            }

            ((osif_dev *)osifp_handle)->nss_ifnum = nss_if;
        }
    }
#endif

    if (opmode == QDF_STA_MODE) {
        /* For STAVAP, self peer will get created on FW
         * for accountability, decrement peer count here
         */
        qdf_atomic_dec(&scn->peer_count);
    }

    return QDF_STATUS_SUCCESS;

ol_ath_vap_create_init_end:
    if (avn) {
        qdf_spinlock_destroy(&avn->avn_lock);
    }
    return QDF_STATUS_E_FAILURE;
}

static struct ieee80211vap *
ol_ath_vap_create_pre_init(struct vdev_mlme_obj *vdev_mlme, int flags)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211* avn = NULL;
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;
    target_resource_config *tgt_cfg;
    uint32_t target_type;
    uint8_t vlimit_exceeded = false;
    enum QDF_OPMODE opmode;
    void *osifp_handle;
    struct vdev_osif_priv *vdev_osifp = NULL;
    uint8_t max_monitor_count = 0;

    vdev = vdev_mlme->vdev;
    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is null");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null");
        return NULL;
    }

    opmode = wlan_vdev_mlme_get_opmode(vdev);
    tgt_cfg = lmac_get_tgt_res_cfg(psoc);
    if (!tgt_cfg) {
        qdf_err("psoc target res cfg is null");
        return NULL;
    }
    target_type = lmac_get_tgt_type(psoc);

    osif_priv = wlan_pdev_get_ospriv(pdev);
    if (!osif_priv) {
        qdf_err("osif_priv is NULL");
        return NULL;
    }

    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;
    if (ol_ath_target_start(scn->soc)) {
        qdf_err("failed to start the firmware");
        return NULL;
    }

    max_monitor_count = wlan_pdev_get_max_monitor_vdev_count(pdev);

    qdf_spin_lock_bh(&scn->scn_lock);
    if (opmode == QDF_MONITOR_MODE) {
        scn->mon_vdev_count++;
        if (scn->mon_vdev_count > max_monitor_count) {
            qdf_spin_unlock_bh(&scn->scn_lock);
            goto ol_ath_vap_create_pre_init_err;
        }
    } else {
        if (scn->special_ap_vap && !(scn->smart_ap_monitor)) {
            scn->vdev_count++;
            qdf_spin_unlock_bh(&scn->scn_lock);
            goto ol_ath_vap_create_pre_init_err;
        } else {
            if (flags & IEEE80211_SPECIAL_VAP) {

                if ((flags & IEEE80211_SMART_MONITOR_VAP) &&
                    !(scn->smart_ap_monitor)) {
                    scn->smart_ap_monitor = 1;
                } else if ((scn->vdev_count != 0) ||
                           (scn->mon_vdev_count != 0) ) {
                    scn->vdev_count++;
                    qdf_spin_unlock_bh(&scn->scn_lock);
                    goto ol_ath_vap_create_pre_init_err;
                }
                scn->special_ap_vap = 1;
            }
        }
        scn->vdev_count++;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        goto ol_ath_vap_create_pre_init_err;

    /* AR988X supports at max 16 vaps and all these can be in AP mode */
    if (target_type == TARGET_TYPE_AR9888) {
        if ((scn->vdev_count + scn->mon_vdev_count) > tgt_cfg->num_vdevs) {
            vlimit_exceeded = true;
        }
    } else if (scn->vdev_count > (wlan_pdev_get_max_vdev_count(pdev) - max_monitor_count)) {
	    vlimit_exceeded = true;
    }

    if (vlimit_exceeded) {
        goto ol_ath_vap_create_pre_init_err;
    }

    /* allocate memory for vap structure
     * check if we are recovering or creating the VAP
     *
     * This code should be moved to legacy mlme after avn
     * dependencies are handle
     */
    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    osifp_handle = vdev_osifp->legacy_osif_priv;
    vap = osif_get_vap(osifp_handle);
    if(!vap) {
       /* create the corresponding VAP */
       avn = (struct ol_ath_vap_net80211 *)qdf_mempool_alloc(scn->soc->qdf_dev,
                                                 scn->soc->mempool_ol_ath_vap);
       if (!avn) {
           qdf_err("Can't allocate memory for ath_vap");
           goto ol_ath_vap_create_pre_init_err;
       }
       wlan_minidump_log(avn, sizeof(*avn), psoc,
                         WLAN_MD_CP_EXT_VDEV, "ol_ath_vap_net80211");
    } else {
       avn = OL_ATH_VAP_NET80211(vap);
    }

    OS_MEMZERO(avn, sizeof(struct ol_ath_vap_net80211));
    qdf_spinlock_create(&avn->avn_lock);
    TAILQ_INIT(&avn->deferred_bcn_list);
    TAILQ_INIT(&avn->deferred_prb_rsp_list);
    vap = &avn->av_vap;

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if ((opmode == QDF_STA_MODE) && (flags & IEEE80211_CLONE_MACADDR)) {
        if (!(flags & IEEE80211_WRAP_NON_MAIN_STA)) {
            qdf_spin_lock_bh(&scn->sc_mpsta_vap_lock);
            scn->sc_mcast_recv_vap = vap;
            qdf_spin_unlock_bh(&scn->sc_mpsta_vap_lock);
        }
    }
#endif
#endif

    if (opmode == QDF_MONITOR_MODE) {
        if (flags & IEEE80211_MONITOR_LITE_VAP) {
            vap->iv_lite_monitor = 1;
            ol_ath_set_debug_sniffer(scn, SNIFFER_M_COPY_MODE);
        }
    }

    return vap;

ol_ath_vap_create_pre_init_err:
    qdf_spin_lock_bh(&scn->scn_lock);
    if (opmode == QDF_MONITOR_MODE) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);
    return NULL;
}

static QDF_STATUS
ol_ath_vap_create_post_init(struct vdev_mlme_obj *vdev_mlme, int flags)
{
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    struct ieee80211vap *vap = vdev_mlme->ext_vdev_ptr;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    uint32_t target_type;
    struct vdev_osif_priv *vdev_osifp = NULL;
    void *osifp_handle;
    osif_dev *osdev_priv;
    int retval = 0;
    struct wmi_unified *pdev_wmi_handle;

#ifdef QCA_PEER_EXT_STATS
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    cdp_config_param_type value = {0};
#endif

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        return QDF_STATUS_E_FAILURE;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_FAILURE;

    psoc = wlan_vdev_get_psoc(vdev);
    vap = vdev_mlme->ext_vdev_ptr;
    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
#if ATH_SUPPORT_WRAP
    scn->sc_nstavaps = ic->ic_nstavaps;
#endif

     /*
     * If BMISS offload is supported, we disable the SW Bmiss timer on host for STA vaps.
     * The timer is initialised only for STA vaps.
     */
    if (wmi_service_enabled(pdev_wmi_handle, wmi_service_bcn_miss_offload) &&
        (opmode == QDF_STA_MODE)) {
        u_int32_t tmp_id;
        int8_t tmp_name[] = "tmp";

        tmp_id = ieee80211_mlme_sta_swbmiss_timer_alloc_id(vap, tmp_name);
        ieee80211_mlme_sta_swbmiss_timer_disable(vap, tmp_id);
    }

#ifdef MU_CAP_WAR_ENABLED
    ieee80211_mucap_vattach(vap);
#endif

    /* Intialize VAP interface functions */
    vap->iv_hostap_up_pre_init = ol_ath_hostap_up_pre_init;
    vap->iv_up_complete = ol_ath_vap_up_complete;
    vap->iv_down = ol_ath_vap_down;
    vap->iv_stop_pre_init = ol_ath_vap_stop_pre_init;
    vap->iv_get_restart_target_status = ol_ath_get_restart_target_status;
    vap->iv_get_phymode = ol_ath_get_phymode;
#if OBSS_PD
    vap->iv_send_obss_spatial_reuse_param = ol_ath_send_obss_spatial_reuse_param;
#endif
    vap->iv_vap_start_rsp_handler = ol_ath_vap_start_response_event_handler;
    vap->iv_dfs_cac = ol_ath_vap_dfs_cac;
    vap->iv_peer_rel_ref = ol_ath_rel_ref_for_logical_del_peer;
    vap->iv_root_authorize = ol_ath_root_authorize;
    vap->iv_enable_radar_table = ol_ath_enable_radar_table;
#if WLAN_SUPPORT_FILS
    vap->iv_cleanup = ol_ath_vap_cleanup;
#endif
    vap->iv_config_bss_color_offload = ol_ath_config_bss_color_offload;
#if ATH_SUPPORT_NAC
    vap->iv_neighbour_rx = ol_ath_neighbour_rx;
    vap->iv_neighbour_get_max_addrlimit = ol_ath_neighbour_get_max_addrlimit;
#endif
#if ATH_SUPPORT_NAC_RSSI
    vap->iv_scan_nac_rssi = ol_ath_config_for_nac_rssi;
#endif
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    vap->iv_wrap_mat_tx = ol_if_wrap_mat_tx;
    vap->iv_wrap_mat_rx = ol_if_wrap_mat_rx;
#endif
#endif
    if (ol_target_lithium(psoc)) {
        vap->get_vdev_bcn_stats = ol_ath_get_vdev_bcn_stats;
        vap->reset_bcn_stats = ol_ath_reset_vdev_bcn_stats;
        vap->get_vdev_prb_fils_stats = ol_ath_get_vdev_prb_fils_stats;
    } else {
        vap->get_vdev_bcn_stats = NULL;
        vap->reset_bcn_stats = NULL;
        vap->get_vdev_prb_fils_stats = NULL;
    }

    target_type = lmac_get_tgt_type(psoc);
    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    osifp_handle = vdev_osifp->legacy_osif_priv;
    osdev_priv = (osif_dev *)osifp_handle;

    /* Send Param indicating LP IOT vap as requested by FW */
    if (opmode == QDF_SAP_MODE) {
        if (flags & IEEE80211_LP_IOT_VAP) {
            if (ol_ath_wmi_send_vdev_param(vdev,
                                           wmi_vdev_param_sensor_ap, 1)) {
                qdf_err("Unable to send param LP IOT");
            }
        }
        /* If Beacon offload service enabled */
        if (ol_ath_is_beacon_offload_enabled(scn->soc)) {
            vap->iv_bcn_offload_enable = 1;
        }
    }


    /*
     * Don't set promiscuous bit in smart monitor vap
     * Smar monitor vap - filters specific to other
     * configured neighbour AP BSSID & its associated clients
     */
    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                       wmi_pdev_param_set_promisc_mode_cmdid,
                                       1);
        if (retval)
            qdf_err("Unable to send param promisc_mode");
    }
#if ATH_SUPPORT_DSCP_OVERRIDE
    if (vap->iv_dscp_map_id) {
        ol_ath_set_vap_dscp_tid_map(vap);
    }
#endif

    osdev_priv->wifi3_0_fast_path = 0;

    if ((opmode == QDF_SAP_MODE))
        osdev_priv->wifi3_0_fast_path = 1;

    if ((target_type != TARGET_TYPE_QCA8074V2) &&
        (target_type != TARGET_TYPE_QCA6018) &&
        (target_type != TARGET_TYPE_QCA5018) &&
        (target_type != TARGET_TYPE_QCN6122) &&
        (target_type != TARGET_TYPE_QCN9000)) {
            osdev_priv->wifi3_0_fast_path = 0;
    }

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (vap->iv_wrap) {
#else
    if (dp_wrap_vdev_is_wrap(vap->vdev_obj)) {
#endif
        osdev_priv->wifi3_0_fast_path = 0;
    }
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        osdev_priv->wifi3_0_fast_path = 0;
    }
#endif

#if ATH_SUPPORT_NAC
    if (vap->iv_smart_monitor_vap) {
        osdev_priv->wifi3_0_fast_path = 0;
    }
#endif

    if (vap->iv_special_vap_mode) {
        osdev_priv->wifi3_0_fast_path = 0;
    }

#ifdef QCA_PEER_EXT_STATS
    cdp_txrx_get_psoc_param(soc_txrx_handle, CDP_CFG_PEER_EXT_STATS, &value);
    if (value.cdp_psoc_param_pext_stats) {
        osdev_priv->wifi3_0_fast_path = 0;
    }
#endif /* QCA_PEER_EXT_STATS */

#if OBSS_PD
    /* Pass on the radio level SRP IE configuration to the VAP */
    vap->iv_he_srctrl_sr15_allowed = ic->ic_he_srctrl_sr15_allowed;
    vap->iv_he_srctrl_psr_disallowed = ic->ic_he_srctrl_psr_disallowed;
    vap->iv_he_srctrl_non_srg_obsspd_disallowed =
            ic->ic_he_srctrl_non_srg_obsspd_disallowed;
    vap->iv_he_srctrl_srg_info_present = ic->ic_he_srctrl_srg_info_present;
    vap->iv_he_srp_ie_non_srg_obsspd_max_offset =
            ic->ic_he_non_srg_obsspd_max_offset;
    vap->iv_he_srp_ie_srg_obsspd_min_offset =
            ic->ic_he_srctrl_srg_obsspd_min_offset;
    vap->iv_he_srp_ie_srg_obsspd_max_offset =
            ic->ic_he_srctrl_srg_obsspd_max_offset;
    vap->iv_he_srp_ie_srg_bss_color_bitmap[0] =
            ic->ic_he_srp_ie_srg_bss_color_bitmap[0];
    vap->iv_he_srp_ie_srg_bss_color_bitmap[1] =
            ic->ic_he_srp_ie_srg_bss_color_bitmap[1];
    vap->iv_he_srp_ie_srg_partial_bssid_bitmap[0] =
            ic->ic_he_srp_ie_srg_partial_bssid_bitmap[0];
    vap->iv_he_srp_ie_srg_partial_bssid_bitmap[1] =
            ic->ic_he_srp_ie_srg_partial_bssid_bitmap[1];

    /* Self SR configuration */
    vap->iv_obss_pd_thresh = ic->ic_ap_obss_pd_thresh;
    set_obss_pd_enable_bit(&vap->iv_obss_pd_thresh, SR_TYPE_SRG_OBSS_PD,
                           IEEE80211_VDEV_SELF_SRG_OBSS_PD_ENABLE);
    set_obss_pd_enable_bit(&vap->iv_obss_pd_thresh, SR_TYPE_NON_SRG_OBSS_PD,
                           IEEE80211_VDEV_SELF_NON_SRG_OBSS_PD_ENABLE);

    set_sr_per_ac(&vap->iv_self_sr_enable_per_ac, SR_TYPE_OBSS_PD,
                  IEEE80211_VDEV_SELF_OBSS_PD_PER_AC);
    set_sr_per_ac(&vap->iv_self_sr_enable_per_ac, SR_TYPE_PSR,
                  IEEE80211_VDEV_SELF_PSR_PER_AC);

    vap->iv_psr_tx_enable = IEEE80211_VDEV_SELF_PSR_TX_ENABLE;

#endif /* OBSS_PD */
    osif_vap_activity_update(vap);
    /*
     * Register the vap setup functions for offload
     * functions here. */
    osif_vap_setup_ol(vap, osifp_handle);

    return QDF_STATUS_SUCCESS;
}

static void ol_ath_update_vdev_restart_param(struct ieee80211vap *vap,
                                             bool reset,
                                             bool restart_success)
{
    struct ol_ath_vap_net80211 *avn = NULL;
    struct ieee80211com *ic = vap->iv_ic;

    avn = OL_ATH_VAP_NET80211(vap);

    if (restart_success)
        avn->av_ol_resmgr_chan = ic->ic_curchan;
}

/*
 * VAP free
 */
static void ol_ath_vap_free(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);

    wlan_minidump_remove(avn, sizeof(*avn), scn->soc->psoc_obj,
                         WLAN_MD_CP_EXT_VDEV, "ol_ath_vap_net80211");
    qdf_mempool_free(scn->soc->qdf_dev, scn->soc->mempool_ol_ath_vap, avn);
}

/*
 * VAP delete
 */
static void ol_ath_vap_post_delete(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if(ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
        qdf_atomic_inc(&scn->peer_count);
    }

    if (vap->iv_lite_monitor) {
        vap->iv_lite_monitor = 0;
        ol_ath_set_debug_sniffer(scn, SNIFFER_DISABLE);
    }

#if QCN_IE
    if (vap->iv_bpr_enable) {
        vap->iv_bpr_enable = 0;
        ol_ath_set_bpr_wifi3(scn, vap->iv_bpr_enable);
    }
#endif

    /* detach VAP from the procotol stack */
#ifdef MU_CAP_WAR_ENABLED
    ieee80211_mucap_vdetach(vap);
#endif
    ieee80211_vap_detach(vap);
    qdf_spin_lock_bh(&scn->scn_lock);
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);
}

static void
ol_ath_vap_delete(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    uint32_t target_type;
#if ATH_SUPPORT_IQUE
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    uint8_t pdev_id;
    uint8_t vdev_id;
#endif

    if (!vdev)
        return;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return;

    ic = vap->iv_ic;
    if (!ic)
        return;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return;

    target_type = lmac_get_tgt_type(scn->soc->psoc_obj);

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    scn->sc_nwrapvaps = ic->ic_nwrapvaps;
    scn->sc_npstavaps = ic->ic_npstavaps;
    scn->sc_nscanpsta = ic->ic_nscanpsta;
    if (vap->iv_psta) {
        qdf_spin_lock_bh(&scn->sc_mpsta_vap_lock);
        if (scn->sc_mcast_recv_vap == vap) {
            scn->sc_mcast_recv_vap = NULL;
        }
        qdf_spin_unlock_bh(&scn->sc_mpsta_vap_lock);
    }
#endif
    /* exit ProxySTA mode when the last WRAP or PSTA VAP is deleted */
    if (target_type == TARGET_TYPE_AR9888) {
        /* Only needed for Peregrine */
#if WLAN_QWRAP_LEGACY
        if (vap->iv_wrap || vap->iv_psta) {
            if (ic->ic_nwrapvaps + ic->ic_npstavaps == 0) {
#else
        if (dp_wrap_vdev_is_wrap(vap->vdev_obj) || dp_wrap_vdev_is_psta(vap->vdev_obj)) {
            if ((dp_wrap_vdev_get_nwrapvaps(ic->ic_pdev_obj) + dp_wrap_vdev_get_npstavaps(ic->ic_pdev_obj)) == 0) {
#endif
                ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_proxy_sta_mode, 0);
            }
        }
    }
#endif

#if ATH_SUPPORT_NAC
    if (vap->iv_smart_monitor_vap) {
        scn->smart_ap_monitor = 0;
    }
#endif

#if ATH_SUPPORT_IQUE
    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    if (!soc_txrx_handle) {
        qdf_err("soc_txrx_handle is NULL\n");
        return;
    }
    pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);
    vdev_id = wlan_vdev_get_id(vdev);
    if (dp_get_me_mode(soc_txrx_handle, vdev_id)) {
            cdp_tx_me_free_descriptor(soc_txrx_handle, pdev_id);
    }
#endif

}

/*
 * pre allocate a mac address and return it in bssid
 */
static int
ol_ath_vap_alloc_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int id = 0, id_mask = 0;
    int nvaps = 0;
    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ol_ath_vap_iter_vap_create,(void *) &id_mask);

    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */


    if (IEEE80211_ADDR_IS_VALID(bssid) ) {
        /* request to preallocate a specific address */
        /* check if it is valid and it is available */
        u_int8_t tmp_mac2[QDF_MAC_ADDR_SIZE];
        u_int8_t tmp_mac1[QDF_MAC_ADDR_SIZE];
        IEEE80211_ADDR_COPY(tmp_mac1, ic->ic_my_hwaddr);
        IEEE80211_ADDR_COPY(tmp_mac2, bssid);

        if (ic->ic_is_macreq_enabled(ic)) {
            /* Ignore locally/globally administered bits */
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac1);
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac2);
        } else {
            tmp_mac1[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (QDF_MAC_ADDR_SIZE - 1))
                tmp_mac1[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );

            tmp_mac1[0] |= IEEE802_MAC_LOCAL_ADMBIT ;
            tmp_mac2[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (QDF_MAC_ADDR_SIZE - 1))
                tmp_mac2[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );
        }
        if (!IEEE80211_ADDR_EQ(tmp_mac1,tmp_mac2) ) {
            qdf_err("Invalid mac address requested %s", ether_sprintf(bssid));
            return -1;
        }
        ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);

        if ((id_mask & (1 << id)) != 0) {
            qdf_err("mac address already allocated %s", ether_sprintf(bssid));
            return -1;
        }
     }
     else {

        for (id = 0; id < ATH_BCBUF; id++) {
             /* get the first available slot */
             if ((id_mask & (1 << id)) == 0)
                 break;
        }
        if (id == ATH_BCBUF) {
            /* no more ids left */
            qdf_err("No more free slots left");
            return -1;
        }

    }

    /* set the allocated id in to the mask */
    scn->sc_prealloc_idmask |= (1 << id);

    return 0;
}

/*
 * free a  pre allocateed  mac addresses.
 */
static int ol_ath_vap_free_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    int id = 0;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);

    /* reset the allocated id in to the mask */
    scn->sc_prealloc_idmask &= ~(1 << id);

    return 0;
}

void ol_ath_vap_soc_attach(ol_ath_soc_softc_t *soc)
{
    wmi_unified_t wmi_handle;

    wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
    /* Register WMI event handlers */
    wmi_unified_register_event_handler(wmi_handle, wmi_roam_event_id,
                                       ol_ath_vdev_roam_event_handler, WMI_RX_UMAC_CTX);
#if ATH_PROXY_NOACK_WAR
#if WLAN_QWRAP_LEGACY
    wmi_unified_register_event_handler(wmi_handle, wmi_pdev_reserve_ast_entry_event_id,
                                    ol_ath_pdev_proxy_ast_reserve_event_handler, WMI_RX_UMAC_CTX);
#endif
#endif

}

QDF_STATUS ol_ath_vap_20tu_prb_init(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(vap->iv_bss,
                                    &avn->av_prb_rsp_offsets);

    if (!avn->av_pr_rsp_wbuf) {
        qdf_debug("20TU prb buffer is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    return QDF_STATUS_SUCCESS;
}

int ol_ath_wmi_send_lcr_cmd(struct wlan_objmgr_pdev *pdev,
        struct ieee80211_wlanconfig_lcr *lcr)
{
    struct wmi_unified *wmi_handle;
    struct ieee80211com *ic;
    struct wmi_wifi_pos_lcr_info lcr_info = {0};
    QDF_STATUS status;

    wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!wmi_handle) {
        qdf_err("null wmi handle");
        return -EINVAL;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("null ic");
        return -EINVAL;
    }

    lcr_info.pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    lcr_info.req_id = lcr->req_id;
    lcr_info.civic_len = lcr->civic_len;
    qdf_mem_copy(&lcr_info.country_code, lcr->country_code, COUNTRY_CODE_LEN);
    qdf_mem_copy(&lcr_info.civic_info, lcr->civic_info, lcr_info.civic_len);

    status = wmi_unified_send_lcr_cmd(wmi_handle, &lcr_info);

    return qdf_status_to_os_return(status);
}

int ol_ath_wmi_send_lci_cmd(struct wlan_objmgr_pdev *pdev,
        struct ieee80211_wlanconfig_lci *lci)
{
    struct wmi_unified *wmi_handle = NULL;
    struct wifi_pos_lci_info lci_info = {0};
    struct ieee80211com *ic;
    QDF_STATUS status;

    wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!wmi_handle) {
        qdf_err("null wmi handle");
        return -EINVAL;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("null ic");
        return -EINVAL;
    }

    lci_info.pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    lci_info.req_id = lci->req_id;
    lci_info.latitude = lci->latitude;
    lci_info.longitude = lci->longitude;
    lci_info.altitude = lci->altitude;
    lci_info.latitude_unc = lci->latitude_unc;
    lci_info.longitude_unc = lci->longitude_unc;
    lci_info.altitude_unc = lci->altitude_unc;
    lci_info.motion_pattern = lci->motion_pattern;
    lci_info.floor = lci->floor;
    lci_info.height_above_floor = lci->height_above_floor;
    lci_info.height_unc = lci->height_unc;

    /* Set usage_rules to 1 by default */
    lci_info.usage_rules = 0x1;

    status = wmi_unified_send_lci_cmd(wmi_handle, &lci_info);

    return qdf_status_to_os_return(status);
}

/* Intialization functions */
void ol_ath_vap_attach(struct ieee80211com *ic)
{
    ic->ic_vap_create_pre_init = ol_ath_vap_create_pre_init;
    ic->ic_vap_create_init = ol_ath_vap_create_init;
    ic->ic_vap_create_post_init = ol_ath_vap_create_post_init;
    ic->ic_nss_vap_create = ol_ath_nss_vap_create;
    ic->ic_nss_vap_destroy = ol_ath_nss_vap_destroy;
    ic->ic_vap_delete = ol_ath_vap_delete;
    ic->ic_vap_post_delete = ol_ath_vap_post_delete;
    ic->ic_vap_free = ol_ath_vap_free;
    ic->ic_vap_alloc_macaddr = ol_ath_vap_alloc_macaddr;
    ic->ic_vap_free_macaddr = ol_ath_vap_free_macaddr;
    ic->ic_vap_set_param = ol_ath_vap_set_param;
    ic->ic_vap_sifs_trigger = ol_ath_vap_sifs_trigger;
    ic->ic_vap_set_ratemask = ol_ath_vap_set_ratemask;
    ic->ic_vap_dyn_bw_rts = ol_ath_vap_dyn_bw_rts;
    ic->ic_ol_net80211_set_mu_whtlist = ol_net80211_set_mu_whtlist;
    ic->ic_vap_get_param = ol_ath_vap_get_param;
    ic->ic_vap_set_qdepth_thresh = ol_ath_vap_set_qdepth_thresh;
    ic->ic_vap_20tu_prb_rsp_init = ol_ath_vap_20tu_prb_init;
#if ATH_SUPPORT_WRAP
    ic->ic_get_qwrap_num_vdevs = ol_ath_get_qwrap_num_vdevs;
#endif
#if OBSS_PD
    ic->ic_spatial_reuse = ol_ath_send_derived_obsee_spatial_reuse_param;
    ic->ic_is_spatial_reuse_enabled = ol_ath_is_spatial_reuse_enabled;
#endif
    ic->ic_set_ru26_tolerant = ol_ath_vap_set_ru26_tolerant;
    ic->ic_bcn_tmpl_send = ol_ath_send_bcn_tmpl;
#if WLAN_SUPPORT_FILS
    ic->ic_fd_tmpl_send = ol_ath_send_fd_tmpl;
    ic->ic_fd_tmpl_update = ol_ath_fd_tmpl_update;
#endif /* WLAN_SUPPORT_FILS */
    ic->ic_update_phy_mode = ol_ath_update_phy_mode;
    ic->ic_incr_peer_count = ol_ath_increment_peeer_count;
    ic->ic_update_restart_param = ol_ath_update_vdev_restart_param;
    ic->ic_prb_rsp_tmpl_send = ol_ath_send_prb_rsp_tmpl;
    ic->ic_prb_rsp_tmpl_alloc = ol_ath_prb_rsp_alloc;
#if OBSS_PD
    ic->ic_vap_set_self_sr_config = ol_ath_vap_set_self_sr_config;
    ic->ic_vap_get_self_sr_config = ol_ath_vap_get_self_sr_config;
    ic->ic_vap_set_he_sr_config = ol_ath_vap_set_he_sr_config;
    ic->ic_vap_get_he_sr_config = ol_ath_vap_get_he_sr_config;
    ic->ic_vap_set_he_srg_bitmap = ol_ath_vap_set_he_srg_bitmap;
    ic->ic_vap_get_he_srg_bitmap = ol_ath_vap_get_he_srg_bitmap;
#endif
    ic->ic_send_lcr_cmd = ol_ath_wmi_send_lcr_cmd;
    ic->ic_send_lci_cmd = ol_ath_wmi_send_lci_cmd;
    ic->ic_vap_config_tid_latency_param = ol_ath_vap_config_tid_latency_param;
    ic->ic_ema_config_init = ol_ath_init_ema_config;
}

/*
 * This API retrieves the vap pointer from object manager
 * it increments the ref count on finding vap. The caller
 * has to decrement ref count with ol_ath_release_vap()
 */
struct ieee80211vap *
ol_ath_pdev_vap_get(struct wlan_objmgr_pdev *pdev, u_int8_t vdev_id)
{

    struct wlan_objmgr_vdev *vdev = NULL;
    struct ieee80211vap *vap;

    if (!pdev) {
        qdf_err("pdev is NULL");
        return NULL;
    }
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_MLME_SB_ID) !=
                                             QDF_STATUS_SUCCESS) {
       return NULL;
    }
    vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id, WLAN_MLME_SB_ID);
    if (!vdev) {
       wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_INFO_LOW, "%s:vdev is not found (id:%d) \n", __func__, vdev_id);
       return NULL;
    }
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    if (!vap)
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    return vap;
}
qdf_export_symbol(ol_ath_pdev_vap_get);

/*
 * This API retrieves the vap pointer from object manager
 * it increments the ref count on finding vap. The caller
 * has to decrement ref count with ol_ath_release_vap()
 */
struct ieee80211vap *
ol_ath_vap_get(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct ieee80211vap *vap;

    if (!scn) {
        qdf_info ("scn is NULL");
        return NULL;
    }
    pdev = scn->sc_pdev;

    if (!pdev) {
        qdf_err("pdev is NULL");
        return NULL;
    }
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_MLME_SB_ID) !=
                                             QDF_STATUS_SUCCESS) {
       return NULL;
    }
    vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id, WLAN_MLME_SB_ID);
    if (!vdev) {
       wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
       QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_INFO_LOW, "%s:vdev is not found (id:%d) \n", __func__, vdev_id);
       return NULL;
    }
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    if (!vap)
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    return vap;
}
qdf_export_symbol(ol_ath_vap_get);

/*
 * Returns the corresponding vap based on vdev
 * Doest not involve looping through vap list to compare the vdevid to get the vap and doesnt
 * consume more CPU cycles.
 * TODO: Try to avoid using ol_ath_vap_get and switch over to ol_ath_getvap to get the vap information.
 */
struct ieee80211vap *
ol_ath_getvap(osif_dev *osdev)
{
    struct ieee80211vap *vap;

    if (!osdev->ctrl_vdev)
        return NULL;

    vap = wlan_vdev_get_mlme_ext_obj(osdev->ctrl_vdev);

    return vap;
}
qdf_export_symbol(ol_ath_getvap);

u_int8_t ol_ath_vap_get_myaddr(struct ol_ath_softc_net80211 *scn,
                               u_int8_t vdev_id, u_int8_t *macaddr)
{
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    struct wlan_objmgr_vdev *vdev = NULL;

    if (!pdev)
       return 0;

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_MLME_SB_ID) !=
                                            QDF_STATUS_SUCCESS) {
       return 0;
    }
    vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id, WLAN_MLME_SB_ID);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    if (!vdev)
       return 0;

    IEEE80211_ADDR_COPY(macaddr, wlan_vdev_mlme_get_macaddr(vdev));

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);

    return 1;
}
qdf_export_symbol(ol_ath_vap_get_myaddr);

void ol_ath_release_vap(struct ieee80211vap *vap)
{
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;

    if (!vdev) {
       qdf_err("vdev can't be NULL");
       QDF_ASSERT(0);
       return;
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
}
qdf_export_symbol(ol_ath_release_vap);

bool ol_ath_is_regulatory_offloaded(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return false;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_regulatory_db))
        return true;
    else
        return false;
}

int ol_ath_send_ft_roam_start_stop(struct ieee80211vap *vap, uint32_t start)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = vap->iv_bss;

    if (!ic || !ni)
        return -EINVAL;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return -EINVAL;

    return ol_ath_node_set_param(scn->sc_pdev, ni->ni_macaddr,
                                 WMI_HOST_PEER_PARAM_ENABLE_FT, start,
                                 wlan_vdev_get_id(vap->vdev_obj));
}

QDF_STATUS ol_ath_set_pcp_tid_map(ol_txrx_vdev_handle vdev, uint32_t mapid)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    struct vap_pcp_tid_map_params params;
    struct wmi_unified *wmi_hndl;
    osif_dev *osifp = (osif_dev *)vdev;

    vap = ol_ath_getvap(osifp);
    if (!vap)
        return QDF_STATUS_E_INVAL;

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_INVAL;

    wmi_hndl = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (!wmi_hndl)
        return QDF_STATUS_E_INVAL;

    params.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    if (mapid)
        params.pcp_to_tid_map = vap->iv_pcp_tid_map;
    else
        params.pcp_to_tid_map = ic->ic_pcp_tid_map;

    return wmi_unified_vdev_pcp_tid_map_cmd_send(wmi_hndl, &params);
}
qdf_export_symbol(ol_ath_set_pcp_tid_map);

QDF_STATUS ol_ath_set_tidmap_prty(ol_txrx_vdev_handle vdev, uint32_t prec_val)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    struct vap_tidmap_prec_params params;
    struct wmi_unified *wmi_hndl;
    osif_dev *osifp = (osif_dev *)vdev;

    vap = ol_ath_getvap(osifp);
    if (!vap)
        return QDF_STATUS_E_INVAL;

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn)
        return QDF_STATUS_E_INVAL;

    wmi_hndl = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (!wmi_hndl)
        return QDF_STATUS_E_INVAL;

    params.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    /* Target expects the value to be 1-based */
    params.map_precedence = (prec_val + 1);
    return wmi_unified_vdev_tidmap_prec_cmd_send(wmi_hndl, &params);
}

qdf_export_symbol(ol_ath_set_tidmap_prty);

void ol_ath_update_vap_caps(struct ieee80211vap *vap, struct ieee80211com *ic)
{
    vap->vdev_mlme->proto.generic.nss = ieee80211_getstreams(ic, ic->ic_tx_chainmask);

    vap->iv_he_ul_nss = ieee80211_getstreams(ic, ic->ic_rx_chainmask);

    vap->iv_he_max_nc = HECAP_PHY_MAX_NC_GET_FROM_IC
        ((&(ic->ic_he.hecap_phyinfo
        [IC_HECAP_PHYDWORD_IDX0])));

}

int32_t
ol_ath_fw_unit_test(struct wlan_objmgr_vdev *vdev,
                    struct ieee80211_fw_unit_test_cmd *fw_unit_test_cmd)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct wmi_unit_test_cmd param;
    uint32_t i;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is NULL");
        return -EINVAL;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vdev);
    param.module_id = fw_unit_test_cmd->module_id;
    param.num_args = fw_unit_test_cmd->num_args;
    param.diag_token = fw_unit_test_cmd->diag_token;
    for(i = 0; i < fw_unit_test_cmd->num_args; i++)
        param.args[i] = fw_unit_test_cmd->args[i];

    status = wmi_unified_unit_test_cmd(pdev_wmi_handle, &param);

    return qdf_status_to_os_return(status);
}

int ol_ath_coex_cfg(struct wlan_objmgr_vdev *vdev, uint32_t type, uint32_t *arg)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct coex_config_params param;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is NULL");
        return -EINVAL;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vdev);
    param.config_type = type;
    param.config_arg1 = arg[0];
    param.config_arg2 = arg[1];
    param.config_arg3 = arg[2];
    param.config_arg4 = arg[3];
    param.config_arg5 = arg[4];
    param.config_arg6 = arg[5];

    status = wmi_unified_send_coex_config_cmd(pdev_wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

int ol_ath_frame_injector_config(struct wlan_objmgr_vdev *vdev,
                                 uint32_t frametype, uint32_t enable,
                                 uint32_t inject_period, uint32_t duration,
                                 uint8_t *dstmac)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct wmi_host_injector_frame_params param;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("pdev is NULL");
        return -EINVAL;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vdev);
    param.enable = enable;
    param.frame_type = frametype;
    param.frame_inject_period = inject_period;
    param.frame_duration = duration;
    memcpy(param.dstmac, dstmac, sizeof(param.dstmac));

    status = wmi_unified_send_injector_frame_config_cmd(pdev_wmi_handle,
                                                        &param);
    return qdf_status_to_os_return(status);
}

void ol_ath_print_peer_refs(struct wlan_objmgr_vdev *vdev, bool assert)
{
    struct ol_ath_softc_net80211 *scn;
    bool do_fw_assert = false;
    bool too_many_prints = true;
    wmi_unified_t pdev_wmi_handle;
    struct ieee80211vap *vap = wlan_vdev_get_mlme_ext_obj(vdev);
    struct ieee80211com *ic;
#ifdef QCA_SUPPORT_CP_STATS
    uint64_t peer_del_req = 0;
    uint64_t peer_del_resp = 0;
    uint64_t peer_del_all_req = 0;
    uint64_t peer_del_all_resp = 0;
#endif

    if (!vap) {
        qdf_err("vap is NULL");
        return;
    }

    if (print_peer_refs_ratelimit())
        too_many_prints = false;

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!too_many_prints) {
        qdf_warn("dumping psoc object references");
        wlan_objmgr_print_ref_cnts(ic);
    }

    qdf_warn("vap: 0x%pK, id: %d, opmode: %d, peer_cnt: %d",
             vap, vap->iv_unit, vap->iv_opmode,
             wlan_vdev_get_peer_count(vdev));

#ifdef QCA_SUPPORT_CP_STATS
    qdf_warn("[PDEV] mgmt: tx: %llu, comp: %llu, err: %llu "
              "mgmt_pending_completions: %d",
            pdev_cp_stats_wmi_tx_mgmt_get(ic->ic_pdev_obj),
            pdev_cp_stats_wmi_tx_mgmt_completions_get(ic->ic_pdev_obj),
            pdev_cp_stats_wmi_tx_mgmt_completion_err_get(ic->ic_pdev_obj),
            qdf_atomic_read(&scn->mgmt_ctx.mgmt_pending_completions));
#endif

    qdf_warn("[VDEV] mgmt: tx: %llu, comp: %llu",
            vap->wmi_tx_mgmt, vap->wmi_tx_mgmt_completions);

    qdf_warn("[VDEV] sta mgmt: tx: %llu, comp: %llu",
            vap->wmi_tx_mgmt_sta, vap->wmi_tx_mgmt_completions_sta);

#ifdef QCA_SUPPORT_CP_STATS
    peer_del_req = vdev_cp_stats_peer_delete_req_get(vdev);
    peer_del_resp = vdev_cp_stats_peer_delete_resp_get(vdev);
    qdf_warn("[VDEV] peer_delete: req: %llu, resp: %llu",
             peer_del_req, peer_del_resp);

    peer_del_all_req = vdev_cp_stats_peer_delete_all_req_get(vdev);
    peer_del_all_resp = vdev_cp_stats_peer_delete_all_resp_get(vdev);
    qdf_warn("[VDEV] peer_delete_all: req: %llu, resp: %llu",
             peer_del_all_req, peer_del_all_resp);
#endif

    if (assert && !too_many_prints) {
#ifdef QCA_SUPPORT_CP_STATS
        if ((peer_del_req - peer_del_resp) > 0) {
            do_fw_assert = true;
            qdf_warn("Missing peer delete responses on SOC");
        }

        if ((peer_del_all_req - peer_del_all_resp) > 0) {
            do_fw_assert = true;
            qdf_warn("Missing peer delete all responses on SOC");
        }
#endif

        if (((int)(vap->wmi_tx_mgmt_sta -
                    vap->wmi_tx_mgmt_completions_sta)) > 0) {
            do_fw_assert = true;
            qdf_warn("Missing Mgmt completions for STA peers on VDEV");
        }

        if (do_fw_assert && wlan_vdev_get_peer_count(vdev) > 1) {
#if UMAC_SUPPORT_ACFG
            OSIF_RADIO_DELIVER_EVENT_WATCHDOG(ic, ACFG_WDT_VAP_STOP_FAILED);
#endif
            /* system shall recover from SSR path */
            qdf_warn("Asserting Target...");

            pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
            if (!pdev_wmi_handle) {
                qdf_err("pdev_wmi_handle is NULL");
                return;
            }

            ol_ath_set_fw_hang(pdev_wmi_handle, 0);
        }
    }
}

int ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct vap_dscp_tid_map_params param;
    QDF_STATUS status;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_dev* osifp = (osif_dev *)(vap->iv_ifp);
    struct ieee80211com *ic = vap->iv_ic;
#endif
    ol_txrx_soc_handle soc_txrx_handle;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev) {
        qdf_err("pdev is NULL");
        return -EINVAL;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is NULL");
        return -EINVAL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    qdf_mem_set(&param, sizeof(param), 0);
#if ATH_SUPPORT_DSCP_OVERRIDE
    if(vap->iv_dscp_map_id) {
        /* Send updated copy of the TID-Map */
        param.dscp_to_tid_map =
                        vap->iv_ic->ic_dscp_tid_map[vap->iv_dscp_map_id];
    }
    else {
        param.dscp_to_tid_map = dscp_tid_map;
    }
#endif
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops)
        ic->nss_vops->ic_osif_nss_vdev_set_dscp_tid_map(osifp,
                                                        param.dscp_to_tid_map);
#endif
    qdf_debug("Setting dscp for vap id: %d", param.vdev_id);

    if (ol_target_lithium(psoc)) {
#if ATH_SUPPORT_DSCP_OVERRIDE
        cdp_set_vdev_dscp_tid_map(soc_txrx_handle,
                                  wlan_vdev_get_id(vap->vdev_obj),
                                  vap->iv_dscp_map_id);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops)
        ic->nss_vops->ic_osif_nss_vdev_set_dscp_tid_map_id(osifp,
                                                           vap->iv_dscp_map_id);
#endif
#endif
        return 0;
    } else {
        status = wmi_unified_set_vap_dscp_tid_map_cmd_send(pdev_wmi_handle,
                                                           &param);
        return qdf_status_to_os_return(status);
    }
}
#endif
