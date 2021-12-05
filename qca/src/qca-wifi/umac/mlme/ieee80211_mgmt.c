/*
 * Copyright (c) 2011-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

/*
 *  management processing code common for all opmodes.
 */
#include "ieee80211_mlme_priv.h"
#include "ieee80211_wds.h"
#include <ieee80211_admctl.h>
#include "osif_private.h"
#include <ol_if_athvar.h>
#include <wlan_dfs_ioctl.h>
#include "ieee80211_mlme_dfs_dispatcher.h"

#include <wlan_cmn.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>
#include "wlan_mgmt_txrx_utils_api.h"
#include <wlan_son_pub.h>
#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"

#if WLAN_SUPPORT_SPLITMAC
#include <wlan_splitmac.h>
#endif

#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_utils_api.h>
#endif
#include <wlan_utility.h>

#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#include <wlan_offchan_txrx_api.h>
#include <wlan_vdev_mlme.h>
#include <wlan_vdev_mgr_utils_api.h>

#if WLAN_SUPPORT_GREEN_AP
#include <wlan_green_ap_api.h>
#endif

/*
 * xmit management processing code.
 */

/*
 * Set the direction field and address fields of an outgoing
 * non-QoS frame.  Note this should be called early on in
 * constructing a frame as it sets i_fc[1]; other bits can
 * then be or'd in.
 */
void
ieee80211_send_setup(
    struct ieee80211vap *vap,
    struct ieee80211_node *ni,
    struct ieee80211_frame *wh,
    u_int8_t type,
    const u_int8_t *sa,
    const u_int8_t *da,
    const u_int8_t *bssid)
{
#define WH4(wh)((struct ieee80211_frame_addr4 *)wh)

    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | type;
    if ((type & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
        switch (vap->iv_opmode) {
        case IEEE80211_M_STA:
            wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
            IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr2, sa);
            IEEE80211_ADDR_COPY(wh->i_addr3, da);
            break;
        case IEEE80211_M_AHDEMO:
            wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
            IEEE80211_ADDR_COPY(wh->i_addr1, da);
            IEEE80211_ADDR_COPY(wh->i_addr2, sa);
            IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
            break;
        case IEEE80211_M_HOSTAP:
            wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
            IEEE80211_ADDR_COPY(wh->i_addr1, da);
            IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr3, sa);
            break;
        default:/* NB: to quiet compiler */
            break;
        }
    } else {
        wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
        IEEE80211_ADDR_COPY(wh->i_addr1, da);
        IEEE80211_ADDR_COPY(wh->i_addr2, sa);
        IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
    }
    *(u_int16_t *)&wh->i_dur[0] = 0;
    /* NB: use non-QoS tid */
    /* to avoid sw generated frame sequence the same as H/W generated frame,
     * the value lower than min_sw_seq is reserved for HW generated frame */
    if ((ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]& IEEE80211_SEQ_MASK) < MIN_SW_SEQ){
        ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] = MIN_SW_SEQ;
    }
    *(u_int16_t *)&wh->i_seq[0] =
        htole16(ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] << IEEE80211_SEQ_SEQ_SHIFT);
    ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]++;
#undef WH4
}

/* If there is an uplink connection then propagate the Subchannels to be
 * added to NOL and update your NOL, else just update NOL
 */

bool ieee80211_process_nol_ie_bitmap(struct ieee80211_node *ni,
        struct vendor_add_to_nol_ie *nol_el)
{
    struct ieee80211com  *ic = ni->ni_ic;
    struct wlan_objmgr_pdev *pdev;
    bool is_nol_ie_processed;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        IEEE80211_DPRINTF(ic->ic_sta_vap, IEEE80211_MSG_MLME,
            "%s : pdev is null", __func__);
        return false;
    }

    is_nol_ie_processed =
    mlme_dfs_process_nol_ie_bitmap(pdev, nol_el->bandwidth,
                                   le16toh(nol_el->startfreq), nol_el->bitmap);

    if (!is_nol_ie_processed)
    {
        IEEE80211_DPRINTF(ic->ic_sta_vap, IEEE80211_MSG_MLME,
            "%s: Could not add external radar information in NOL\n",__func__);
    }
    return is_nol_ie_processed;
}

/* If there is an uplink connection then propagate the RCSA
 * else behave as if radar is detected and send CSA
 */
void
ieee80211_process_external_radar_detect(struct ieee80211_node *ni, bool is_nol_ie_recvd,
        bool is_rcsa_ie_recvd)
{
    struct ieee80211com  *ic = ni->ni_ic;
    struct wlan_objmgr_pdev *pdev;
    int err;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return;
    }

    if (!IEEE80211_IS_CHAN_SWITCH_STARTED(ic))
    {
        struct ieee80211vap *stavap = NULL;

        IEEE80211_CHAN_SWITCH_START(ic);
        STA_VAP_DOWNUP_LOCK(ic);
        stavap = ic->ic_sta_vap;
        if(stavap && (wlan_vdev_is_up(stavap->vdev_obj) == QDF_STATUS_SUCCESS)) {
        /* The flags to propagate RCSA and NOL IE are set in DFS structure */
            mlme_dfs_set_rcsa_flags(pdev, is_rcsa_ie_recvd, is_nol_ie_recvd);

            /* Propagate RCSA */
            IEEE80211_DPRINTF(stavap, IEEE80211_MSG_MLME,
                    "%s: Uplink is present so send it to uplink\n",__func__);
            ieee80211_dfs_rx_rcsa(ic);
        } else {
            /* Simulate RADAR and send CSA */
            if(is_nol_ie_recvd) {
            /* you have recieved addtoNOL ie, do not do bangradar, do only
             * channel change, channel will be added to NOL already.
             */
                ieee80211_mark_dfs(ic, ic->ic_curchan->ic_ieee,
                    ic->ic_curchan->ic_freq,
                    ic->ic_curchan->ic_vhtop_ch_num_seg2,
                    ic->ic_curchan->ic_flags);
            }
            else {
                struct dfs_bangradar_params pe;
                void *indata = &pe;
                uint32_t insize = sizeof(struct dfs_bangradar_params);

                /* you have not recieved NOL IE, hence do bangradar internally
                 * which will add all subchannels to NOL and then change channel
                 */
                IEEE80211_DPRINTF(stavap, IEEE80211_MSG_MLME,
                    "%s: Uplink NOT  present This must be a root simulate a "
                    "local radar detect\n",__func__);
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                    QDF_STATUS_SUCCESS) {
                    return;
                }
                pe.bangradar_type = DFS_BANGRADAR_FOR_ALL_SUBCHANS;
                pe.seg_id = 0;
                pe.is_chirp = 0;
                pe.freq_offset = 0;
                pe.detector_id = 0;
                mlme_dfs_control(pdev, DFS_BANGRADAR, indata, insize, NULL, NULL, &err);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
        }
        STA_VAP_DOWNUP_UNLOCK(ic);
    }
}

wbuf_t
ieee80211_getmgtframe(struct ieee80211_node *ni, int subtype, u_int8_t **frm, u_int8_t isboardcast)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t broadcast_addr[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return NULL;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    if (isboardcast) {
        subtype = IEEE80211_FC0_SUBTYPE_ACTION;
        ieee80211_send_setup(vap, ni, wh, IEEE80211_FC0_TYPE_MGT | subtype,
                             vap->iv_myaddr, broadcast_addr, ni->ni_bssid);
    } else {
        ieee80211_send_setup(vap, ni, wh, IEEE80211_FC0_TYPE_MGT | subtype,
                             vap->iv_myaddr, ni->ni_macaddr, ni->ni_bssid);
    }
    *frm = (u_int8_t *)&wh[1];
    return wbuf;
}

int
ieee80211_send_mgmt(struct ieee80211vap *vap,struct ieee80211_node *ni, wbuf_t wbuf, bool force_send)
{
    u_int8_t  subtype;
    u_int8_t  fc_type;
    int retval;
    struct ieee80211_frame *wh;

    ni = ieee80211_try_ref_node(ni, WLAN_MGMT_TX_ID);
    if (!ni) {
        wbuf_complete(wbuf);
        return EOK;
    } else {
        wlan_wbuf_set_peer_node(wbuf, ni);
    }

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    fc_type = wh->i_fc[0];

    /*
     * if forced sleep is set then turn on the powersave
     * bit on all management except for the probe request.
     */
    if (ieee80211_vap_forced_sleep_is_set(vap)) {
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if (subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            wh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
            wbuf_set_pwrsaveframe(wbuf);
        }
    }

    /*
     * call registered function to add any additional IEs.
     */
    if (vap->iv_output_mgmt_filter) {
        if (vap->iv_output_mgmt_filter(wbuf)) {
            /*
             * filtered out and freed by the filter function,
             * nothing to do, just return.
             */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                              "[%s] frame filtered out; do not send\n",
                              __func__);
            ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                    IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
            ieee80211_free_node(ni, WLAN_MGMT_TX_ID);
            return EOK;
        }
    }
    vap->iv_lastdata = OS_GET_TIMESTAMP();

#if 0
if (wbuf_is_keepalive(wbuf)){
        if (force_send)
        qdf_nofl_info("\n the force_send is set\n");
        if(ieee80211node_has_flag(ni,IEEE80211_NODE_PWR_MGT)){
            qdf_nofl_info("\n powersave node\n");
            for (int i = 0; i < 6; i++) {
                qdf_nofl_info("%02x:", ni->ni_macaddr[i]);
            }

            }
    }
#endif
    /*
     * do not sent the frame is node is in power save (or) if the vap is paused
     * and the frame is is not marked as special force_send frame, and if the node
     * is temporary, don't do pwrsave
     */
    if (!force_send &&
          (ieee80211node_is_paused(ni)) &&
          !ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) {
#if !LMAC_SUPPORT_POWERSAVE_QUEUE
        wlan_wbuf_set_peer_node(wbuf, NULL);
#endif
        ieee80211node_pause(ni); /* pause it to make sure that no one else unpaused it after the node_is_paused check above, pause operation is ref counted */
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
        ieee80211node_unpause(ni); /* unpause it if we are the last one, the frame will be flushed out */
#if !LMAC_SUPPORT_POWERSAVE_QUEUE
        ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
        ieee80211_free_node(ni, WLAN_MGMT_TX_ID);
        return EOK;
#endif
    }
    /*
     * if the vap is not ready drop the frame.
     */
    if (!(vap->iv_opmode == IEEE80211_M_HOSTAP && vap->iv_is_up) &&
        (wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) &&
        !vap->iv_special_vap_mode &&
        !vap->iv_dpp_vap_mode) {
        struct ieee80211_tx_status ts;
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries=0;
        /*
         * complete buf will decrement the pending count.
         */
        ieee80211_complete_wbuf(wbuf,&ts);
        return EOK;
    }
#ifdef QCA_SUPPORT_CP_STATS
    peer_cp_stats_tx_mgmt_inc(ni->peer_obj, 1);
    vdev_ucast_cp_stats_tx_mgmt_inc(vap->vdev_obj, 1);
#endif
    if ((wh->i_fc[0] == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) ||
             (wh->i_fc[0] == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_REASSOC_RESP))) {
        wbuf_set_complete_handler(wbuf, ieee80211_mlme_frame_complete_handler, ni);
    }

    /* Hand over the wbuf to the mgmt_txrx infrastructure. */
    retval = wlan_mgmt_txrx_mgmt_frame_tx(ni->peer_obj, NULL, wbuf, NULL,
                                          ieee80211_mgmt_complete_wbuf,
                                          WLAN_UMAC_COMP_MLME, NULL);

    if(QDF_IS_STATUS_ERROR(retval))
    {
        struct ieee80211_tx_status ts;
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries=0;
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_tx_not_ok_inc(vap->vdev_obj, 1);
#endif
        if ((fc_type == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) ||
            (fc_type == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_REASSOC_RESP))) {
#ifdef QCA_SUPPORT_CP_STATS
            WLAN_PEER_CP_STAT(ni, tx_assoc_fail);
#endif
        }
#ifdef QCA_SUPPORT_CP_STATS
        peer_cp_stats_tx_mgmt_dec(ni->peer_obj, 1);
#endif
        ieee80211_complete_wbuf(wbuf,&ts);
    }
    else if ((fc_type == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) ||
             (fc_type == (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_REASSOC_RESP))) {
        if (ni->ni_assocstatus == IEEE80211_STATUS_SUCCESS) {
#ifdef QCA_SUPPORT_CP_STATS
            WLAN_PEER_CP_STAT(ni, tx_assoc);
#endif
        } else {
#ifdef QCA_SUPPORT_CP_STATS
            WLAN_PEER_CP_STAT(ni, tx_assoc_fail);
#endif
        }
    }

    return -retval;
}

/*
 * Send a null data frame to the specified node.
 */
int ieee80211_send_nulldata(struct ieee80211_node *ni, int pwr_save)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    if (ieee80211_chan2freq(ic,ieee80211_get_home_channel(vap)) !=
          ieee80211_chan2freq(ic,ieee80211_get_current_channel(ic)))
	{

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
				  "%s[%d] cur chan freq %d flags 0x%llx  is not same as home chan freq %d flags 0x%llx \n",
				  __func__, __LINE__,
                          ieee80211_chan2freq(ic, ic->ic_curchan),ieee80211_chan_flags(ic->ic_curchan),
                          ieee80211_chan2freq(ic, vap->iv_bsschan), ieee80211_chan_flags(vap->iv_bsschan));
		return EOK;
	}

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_frame));
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_NODATA,
                         vap->iv_myaddr, ieee80211_node_get_macaddr(ni),
                         ieee80211_node_get_bssid(ni));
    wbuf_set_qosnull(wbuf);
    /* NB: power management bit is never sent by an AP */
    if (pwr_save &&
        vap->iv_opmode == IEEE80211_M_STA) {
        wh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
        wbuf_set_pwrsaveframe(wbuf);
    }

    if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_vperf_pause){
        vap->iv_ccx_evtable->wlan_ccx_vperf_pause(vap->iv_ccx_arg, pwr_save);
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DUMPPKTS,
                      "[%s] send null data frame on channel %u freq %d, pwr mgt %s\n",
                      ether_sprintf(ni->ni_macaddr),
                      ieee80211_chan2ieee(ic, ic->ic_curchan),
                      ieee80211_chan2freq(ic, ic->ic_curchan),
                      wh->i_fc[1] & IEEE80211_FC1_PWR_MGT ? "ena" : "dis");

#if QCA_SUPPORT_SON
    if (wlan_peer_mlme_flag_get(ni->peer_obj,
                WLAN_PEER_F_BSTEERING_CAPABLE)) {
        wbuf_set_bsteering(wbuf);
    }

    wlan_peer_mlme_flag_clear(ni->peer_obj,
                  WLAN_PEER_F_BSTEERING_CAPABLE);
#endif

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame));
    wbuf_set_priority(wbuf, WME_AC_VO);
    wbuf_set_tid(wbuf, WME_AC_TO_TID(WME_AC_VO));

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    {
       if (vap->iv_opmode == IEEE80211_M_STA) {
           /* force send null data */
           return ieee80211_send_mgmt(vap,ni, wbuf, true);
       }
       else {
           /* allow power save for null data */
           return ieee80211_send_mgmt(vap,ni, wbuf, false);
       }
    }
}


/*
 * Send a probe request frame with the specified ssid
 * and any optional information element data.
 */
int
ieee80211_send_probereq(
    struct ieee80211_node *ni,
    const u_int8_t        *sa,
    const u_int8_t        *da,
    const u_int8_t        *bssid,
    const u_int8_t        *ssid,
    const u_int32_t       ssidlen,
    const void            *optie,
    const size_t          optielen)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    enum ieee80211_phymode mode;
    struct ieee80211_frame *wh;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t *frm;
#if QCN_IE
    u_int16_t ie_len;
#endif /* QCN_IE */
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_REQ,
                         sa, da, bssid);
    frm = (u_int8_t *)&wh[1];

    /*
     * prreq frame format
     *[tlv] ssid
     *[tlv] supported rates
     *[tlv] extended supported rates
     *[tlv] HT Capabilities
     *[tlv] VHT Capabilities
     *[tlv] user-specified ie's
     */
    frm = ieee80211_add_ssid(frm, ssid, ssidlen);
    mode = ieee80211_get_current_phymode(ic);
    /* XXX: supported rates or operational rates? */
    frm = ieee80211_add_rates(vap, frm, &vap->iv_op_rates[mode]);
    frm = ieee80211_add_xrates(vap, frm, &vap->iv_op_rates[mode]);

     /* 11ac or  11n  and ht allowed for this vap */
    if ((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
         ieee80211vap_htallowed(vap)) {

        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);

        if (IEEE80211_IS_HTVIE_ENABLED(ic)) {
            frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);
        }

        frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);
    } else if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);
    }

    if ((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
                           ieee80211vap_vhtallowed(vap)) {
        /* Add VHT capabilities IE */
        frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_REQ, NULL, NULL);
    }
    /* Add Bandwidth-NSS Mapping in Probe*/
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }

    if (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        /* Add HE capabilities IE */
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_REQ);
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            /* Add HE 6GHz Band Capabilities IE */
            frm = ieee80211_add_6g_bandcap(frm, ni, ic,
                            IEEE80211_FC0_SUBTYPE_PROBE_REQ);
        }
    }

    if (optie != NULL) {
        qdf_mem_copy(frm, optie, optielen);
        frm += optielen;
    }

    IEEE80211_VAP_LOCK(vap);
    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBEREQ, frm);
    IEEE80211_VAP_UNLOCK(vap);
#if DBDC_REPEATER_SUPPORT
    if (ic_list->same_ssid_support && (vap == ic->ic_sta_vap)) {
        /* Add the Extender IE */
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_PROBEREQ, frm);
    }
#endif
#if QCN_IE
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
#endif

    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if (!frm)
        return -EINVAL;

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    /*
     * send the frame out even if the vap is opaused.
     */
    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

#define AUTH_TX_XRETRY_THRESHOLD 10
static void ieee80211_mgmt_frame_complete_handler(wlan_if_t vap, wbuf_t wbuf,void *arg,
        u_int8_t *dst_addr, u_int8_t *src_addr, u_int8_t *bssid,
        ieee80211_xmit_status *ts)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)arg;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;;

    if (ni &&(vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            ((subtype == IEEE80211_FC0_SUBTYPE_AUTH) && (ts->ts_flags == IEEE80211_TX_XRETRY)) &&
            !ieee80211node_has_flag(ni, IEEE80211_NODE_LEAVE_ONGOING)) {
        if(vap->iv_ic->ic_auth_tx_xretry  < AUTH_TX_XRETRY_THRESHOLD) {
            vap->iv_ic->ic_auth_tx_xretry++;
            ni->ni_node_esc = true;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s : ni = 0x%pK ni->ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                    __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s : ni = 0x%pK ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                    __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
            IEEE80211_NODE_LEAVE(ni);
        }
    }

    if (ni &&(vap->iv_opmode == IEEE80211_M_HOSTAP) && (subtype == IEEE80211_FC0_SUBTYPE_AUTH)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s : AUTH frame completion handler for ni = 0x%pK ni->ni_macaddr = %s\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr));
        qdf_atomic_set(&(ni->ni_auth_tx_completion_pending), 0);
    }
    return;
}


/*
 * Send a authentication frame
 */
int
ieee80211_send_auth(
    struct ieee80211_node *ni,
    u_int16_t seq,
    u_int16_t status,
    u_int8_t *challenge_txt,
    u_int8_t challenge_len,
    struct ieee80211_app_ie_t* optie
    )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    int32_t authmode = 0;
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                          "[%s] send auth frmae \n ", ether_sprintf(ni->ni_macaddr));

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH,
                         vap->iv_myaddr, ni->ni_macaddr, ni->ni_bssid);
    frm = (u_int8_t *)&wh[1];

    /*
     * auth frame format
     *[2] algorithm
     *[2] sequence
     *[2] status
     *[tlv*] challenge
     */
    // MP
    // Regardless of iv_opmode, we should always take iv_rsn
    // because of iv_rsn is our configuration. so commenting
    // below line and correct code in next line
    // rsn = (vap->iv_opmode == IEEE80211_M_STA) ? &vap->iv_rsn : &vap->iv_bss->ni_rsn;

    /* when auto auth is set in ap dont send shared auth response
     * for open auth request. In sta mode send shared auth response
     *  only mode is shared and ni == vap->iv_bss
     */
    authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
    if ( authmode == -1 ) {
        qdf_err("crypto_err while getting authmode params\n");
        return -1;
    }
    if ((authmode & (1 << WLAN_CRYPTO_AUTH_SHARED)) && (ni == vap->iv_bss || ni->ni_authmode == IEEE80211_AUTH_SHARED)) {
        *((u_int16_t *)frm) = htole16(IEEE80211_AUTH_ALG_SHARED);
        frm += 2;
    }
    else if (vap->iv_roam.iv_roaming && vap->iv_roam.iv_ft_roam) {
        *((u_int16_t *)frm) = htole16(IEEE80211_AUTH_ALG_FT);
        frm += 2;
    } else {
        *((u_int16_t *)frm) = htole16(ni->ni_authalg);
        frm += 2;
    }
    *((u_int16_t *)frm) = htole16(seq); frm += 2;
    *((u_int16_t *)frm) = htole16(status); frm += 2;
    if (challenge_txt != NULL && challenge_len != 0) {
        *((u_int16_t *)frm) = htole16((challenge_len << 8) | IEEE80211_ELEMID_CHALLENGE);
        frm += 2;
        OS_MEMCPY(frm, challenge_txt, challenge_len);
        frm += challenge_len;

        if (seq == IEEE80211_AUTH_SHARED_RESPONSE) {
            /* We also need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }

    IEEE80211_VAP_LOCK(vap);

    /* Add the application IEs */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_AUTH, frm);
    IEEE80211_VAP_UNLOCK(vap);

    /*
     * Add the optional IE passed to  AP
     */
    if ((optie != NULL) && optie->length) {
        qdf_mem_copy(frm, optie->ie,
                  optie->length);
        frm += optie->length;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    /* register complete handler for offload alone as ts argument can be null for DA callback */
    ieee80211_vap_set_complete_buf_handler(wbuf,ieee80211_mgmt_frame_complete_handler,(void *)ni);
    qdf_atomic_set(&(ni->ni_auth_tx_completion_pending), 1);

    if (status == IEEE80211_STATUS_SUCCESS) {
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_mlme_auth_success_inc(vap->vdev_obj, 1);
#endif
    }

    return ieee80211_send_mgmt(vap,ni, wbuf,false);
}

/*
 * Copy required statistics to an external struct
 */
int wlan_disassoc_ind_stats_prepare(struct cdp_peer_stats *peer_stats,
                                    struct bs_sta_stats_ind *disassoc)
{
    disassoc->peer_stats[disassoc->peer_count].rssi = peer_stats->rx.snr;
    disassoc->peer_stats[disassoc->peer_count].per = peer_stats->tx.last_per;
    disassoc->peer_stats[disassoc->peer_count].tx_byte_count = peer_stats->tx.tx_success.bytes;
    disassoc->peer_stats[disassoc->peer_count].tx_packet_count = peer_stats->tx.tx_success.num;
    disassoc->peer_stats[disassoc->peer_count].tx_error_packets = peer_stats->tx.tx_failed;
    disassoc->peer_stats[disassoc->peer_count].tx_retrans = peer_stats->tx.retry_count;
    disassoc->peer_stats[disassoc->peer_count].rx_byte_count = peer_stats->rx.to_stack.bytes;
    disassoc->peer_stats[disassoc->peer_count].rx_packet_count = peer_stats->rx.to_stack.num;
    disassoc->peer_stats[disassoc->peer_count].rx_error_packets = peer_stats->rx.rx_discard;
    disassoc->peer_stats[disassoc->peer_count].tx_rate = peer_stats->tx.tx_rate;
    disassoc->peer_stats[disassoc->peer_count].ack_rssi = peer_stats->tx.last_ack_rssi;
    disassoc->peer_stats[disassoc->peer_count].is_disassoc_stats = 1;
    disassoc->peer_count++;

    return EOK;
}

/*
 * Get statistics of the the node getting disassociated
 */
int wlan_node_get_disassoc_stats(struct ieee80211vap *vap,
                                 struct wlan_objmgr_peer *peer,
                                 struct bs_sta_stats_ind *disassoc)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    struct cdp_peer_stats *peer_stats;
    QDF_STATUS status;

    if (!vap) {
        qdf_err("vap is null");
        return -EINVAL;
    }
    if (!peer) {
        qdf_err("peer is null");
        return -EINVAL;
    }
    psoc = wlan_vdev_get_psoc(vap->vdev_obj);
    if (!psoc) {
        qdf_err("psoc is null");
        return -EINVAL;
    }

    if (!(peer_stats = qdf_mem_malloc(sizeof(struct cdp_peer_stats)))) {
        return -ENOMEM;
    }

    status = cdp_host_get_peer_stats(wlan_psoc_get_dp_handle(psoc),
                                     wlan_vdev_get_id(peer->peer_objmgr.vdev),
                                     peer->macaddr, peer_stats);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_mem_free(peer_stats);
        qdf_debug("peer_stats is null");
        return -EINVAL;
    }

    qdf_mem_copy(disassoc->peer_stats[disassoc->peer_count].client_addr, peer->macaddr,
                 QDF_MAC_ADDR_SIZE);
    wlan_vap_get_bssid(vap, (uint8_t *)&disassoc->peer_stats[disassoc->peer_count].bssid);
    wlan_disassoc_ind_stats_prepare(peer_stats, disassoc);

    qdf_mem_free(peer_stats);
    return EOK;
}

int
ieee80211_send_injector_frame_deauth(struct ieee80211vap *vap, u_int8_t *dstmac,
                                        u_int16_t reason, uint8_t protected)
{
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    int ret = 0;
    u_int8_t *frm, *da;
    u_int8_t broadcast_addr[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int32_t   frlen=0;
    ni = ieee80211_vap_find_node(vap, dstmac, WLAN_MLME_HANDLER_ID);
    if (ni == NULL) {
        if(vap->iv_opmode == IEEE80211_M_STA){
            if(!wlan_vap_is_pmf_enabled(vap)){
                return -ENOMEM;
            }
        } else {
            if (!IEEE80211_ADDR_EQ(dstmac, IEEE80211_GET_BCAST_ADDR(vap->iv_ic)))
            {
                return-EIO;
            }
        }

        ni = ieee80211_try_ref_node(vap->iv_bss, WLAN_MLME_HANDLER_ID);
        if (!ni) {
            return -EFAULT;
        }

    }
    ic = ni->ni_ic;

    if (OS_MEMCMP(ni->ni_macaddr, vap->iv_myaddr, QDF_MAC_ADDR_SIZE) != 0) {
        da = ni->ni_macaddr;
    } else {
        da = broadcast_addr;
    }

    if (protected && ieee80211_is_pmf_enabled(vap, ni) &&
        (IEEE80211_IS_BROADCAST(da) || IEEE80211_IS_MULTICAST(da))) {
        frlen = sizeof(struct ieee80211_ath_mmie);
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, (sizeof(struct ieee80211_frame)+frlen));
    if (wbuf == NULL) {
        ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
        return -ENOMEM;
    }

#if ATH_SUPPORT_WAPI
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (ieee80211_vap_wapi_is_set(vap)) {
            /* clear the WAPI flag in vap */
            ieee80211_vap_wapi_clear(vap);
        }
    }
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DEAUTH,
                         vap->iv_myaddr, da, ni->ni_bssid);

    if (((ni != vap->iv_bss) && protected &&
            !(ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) &&
            (ieee80211_vap_mfp_test_is_set(vap) ||
          ieee80211_is_pmf_enabled(vap, ni)))){
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
            /* MFP is enabled and a key is established. */
            /* We need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
            wbuf_set_incorrect_pmf_key(wbuf);
        }
    }
    frm = (u_int8_t *)&wh[1];
    *(u_int16_t *)frm = htole16(reason);
    frm += 2;

    wbuf_set_complete_handler(wbuf, ieee80211_mlme_frame_complete_handler, ni);

    if ((IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
                                 wlan_vap_is_pmf_enabled(vap) && protected) {
        u8 *res;
        /* This is a broadcast/Multicast Deauth pkt and MFP is enabled so insert MMIE */
        res = ieee80211_add_mmie(vap,
                           (u_int8_t *)wbuf_header(wbuf),
                           (frm - (u_int8_t *)wbuf_header(wbuf)));
        if (res != NULL) {
            frm = res;
            frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
        }
    } else {
        frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    }

    frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    wbuf_set_pktlen(wbuf, frlen);

    if (vap->iv_vap_is_down)
        ret = ieee80211_send_mgmt(vap, ni, wbuf, true);
    else
        ret = ieee80211_send_mgmt(vap, ni, wbuf, false);

    /* claim node immediately */
    ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
    return ret;
}

int
ieee80211_inject_mgmt_frame(struct ieee80211vap *vap, uint8_t protected,
                                    uint8_t subtype, uint8_t *dstmac)
{
    uint8_t sub_type = (subtype << IEEE80211_FC0_SUBTYPE_SHIFT);
    struct ieee80211_node *ni;
    int retval;

    switch(sub_type) {
        case IEEE80211_FC0_SUBTYPE_DEAUTH:
            switch(protected) {
                case IEEE80211_PROTECTED_CORRECT_KEY_FRAME:
                    ni = ieee80211_vap_find_node(vap, dstmac,
                                                    WLAN_MLME_HANDLER_ID);
                    if(ni == NULL) {
                        qdf_err("Node not found");
                        return -EINVAL;
                    }
                    ieee80211_try_mark_node_for_delayed_cleanup(ni);

                    retval = wlan_mlme_deauth_request(vap, dstmac,
                        IEEE80211_REASON_DISASSOC_LOW_ACK);

                    ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
                    break;

                case IEEE80211_UNPROTECTED_FRAME:
                case IEEE80211_PROTECTED_INCORRECT_KEY_FRAME:
                    return ieee80211_send_injector_frame_deauth(vap, dstmac,
                            IEEE80211_REASON_DISASSOC_LOW_ACK, protected);
                    break;

                default:
                    qdf_err("Protected argument should be less than %d ",
                                    IEEE80211_PROTECTED_FRAME_TYPE_MAX);
                    break;
            }
        break;

        default:
            qdf_err("Subtype %d not supported", subtype);
            return -EINVAL;
        break;
    }

    return 0;
}
/*
 * Send a deauth frame
 */
int
ieee80211_send_deauth(struct ieee80211_node *ni, u_int16_t reason)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *da;
    u_int8_t broadcast_addr[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int32_t   frlen=0;
    wlan_vap_complete_buf_handler tx_compl_handler = NULL;
#if QCA_SUPPORT_SON
    struct bs_client_disconnect_ind event_data = {0};
#endif

    if (OS_MEMCMP(ni->ni_macaddr, vap->iv_myaddr, QDF_MAC_ADDR_SIZE) != 0) {
        da = ni->ni_macaddr;
    } else {
        da = broadcast_addr;
    }

    if (ieee80211_is_pmf_enabled(vap, ni)) {
        frlen = sizeof(struct ieee80211_ath_mmie);
    }

#if QCA_SUPPORT_SON
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        qdf_mem_copy(event_data.disconnect_event_data.client_addr, da, QDF_MAC_ADDR_SIZE);
        event_data.disconnect_event_data.source = BSTEERING_SOURCE_LOCAL;
        event_data.disconnect_event_data.type = BSTEERING_DEAUTH;
        event_data.disconnect_event_data.reason = reason;
        wlan_node_get_disassoc_stats(vap, ni->peer_obj, &event_data.sta_stats_event_data);
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_CLIENT_DISCONNECTED, &event_data);
    }
#endif

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, (sizeof(struct ieee80211_frame)+frlen));
    if (wbuf == NULL) {
        ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
        return -ENOMEM;
    }

#if ATH_SUPPORT_WAPI
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (ieee80211_vap_wapi_is_set(vap)) {
            /* clear the WAPI flag in vap */
            ieee80211_vap_wapi_clear(vap);
        }
    }
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DEAUTH,
                         vap->iv_myaddr, da, ni->ni_bssid);

    if ((ni != vap->iv_bss) &&
            !(ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) &&
            (ieee80211_vap_mfp_test_is_set(vap) ||
            wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj))) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
            /* MFP is enabled and a key is established. */
            /* We need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }

    frm = (u_int8_t *)&wh[1];
    *(u_int16_t *)frm = htole16(reason);
    frm += 2;

    if (ieee80211node_has_flag(ni, IEEE80211_NODE_DELAYED_CLEANUP)) {
        /* install tx completion handler callback to free this node */
        tx_compl_handler = ieee80211_mlme_frame_complete_handler;
        ni->ni_reason_code = reason;
        wbuf_set_complete_handler(wbuf, tx_compl_handler, ni);
    }

    if ((IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
                                             wlan_vap_is_pmf_enabled(vap)) {
        u8 *res;
        /* This is a broadcast/Multicast Deauth pkt and MFP is enabled so insert MMIE */
        res = ieee80211_add_mmie(vap,
                           (u_int8_t *)wbuf_header(wbuf),
                           (frm - (u_int8_t *)wbuf_header(wbuf)));
        if (res != NULL) {
            frm = res;
            frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
        }
    } else {
        frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    }

    frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    wbuf_set_pktlen(wbuf, frlen);

    if (vap->iv_vap_is_down)
        return ieee80211_send_mgmt(vap, ni, wbuf, true);
    else
        return ieee80211_send_mgmt(vap, ni, wbuf, false);
}

/*
 * Send a disassociate frame
 */
int
ieee80211_send_disassoc(struct ieee80211_node *ni, u_int16_t reason)
{
    int retval;
    retval = ieee80211_send_disassoc_with_callback(ni, reason, NULL, NULL);
    return retval;
}

int ieee80211_send_disassoc_with_callback(struct ieee80211_node *ni, u_int16_t reason,
                                          wlan_vap_complete_buf_handler handler,
                                          void *arg)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *da;
    u_int8_t broadcast_addr[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int32_t   frlen=0;
#if QCA_SUPPORT_SON
    struct bs_client_disconnect_ind event_data = {0};
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_mgmt_txsend_config && vap->iv_mesh_vap_mode) {
        /* Drop disassoc frames in mesh vap */
        ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
        return -EINVAL;
    }
#endif

    if (OS_MEMCMP(ni->ni_macaddr, vap->iv_myaddr, QDF_MAC_ADDR_SIZE) != 0) {
        da = ni->ni_macaddr;
    } else {
        da = broadcast_addr;
        if (ieee80211_is_pmf_enabled(vap, ni)) {
            frlen = sizeof(struct ieee80211_ath_mmie);
        }
    }

#if QCA_SUPPORT_SON
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        qdf_mem_copy(event_data.disconnect_event_data.client_addr, da, QDF_MAC_ADDR_SIZE);
        event_data.disconnect_event_data.source = BSTEERING_SOURCE_LOCAL;
        event_data.disconnect_event_data.type = BSTEERING_DISASSOC;
        event_data.disconnect_event_data.reason = reason;
        wlan_node_get_disassoc_stats(vap, ni->peer_obj, &event_data.sta_stats_event_data);
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_CLIENT_DISCONNECTED, &event_data);
    }
#endif

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        ieee80211node_test_set_delayed_node_cleanup_fail(ni,
                IEEE80211_NODE_DELAYED_CLEANUP_FAIL);
        return -ENOMEM;
    }

#if ATH_SUPPORT_WAPI
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (ieee80211_vap_wapi_is_set(vap)) {
            /* clear the WAPI flag in vap */
            ieee80211_vap_wapi_clear(vap);
        }
    }
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DISASSOC,
                         vap->iv_myaddr, da, ni->ni_bssid);


    if (ieee80211_vap_mfp_test_is_set(vap) ||
         wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj)) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
            /* MFP is enabled and a key is established. */
            /* We need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }
    frm = (u_int8_t *)&wh[1];
    *(u_int16_t *)frm = htole16(reason);
    frm += 2;

    if ((IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
         (wlan_vap_is_pmf_enabled(vap))){
        u8 *res;
        // This is a broadcast/Multicast Deauth pkt and MFP is enabled so insert MMIE
        res = ieee80211_add_mmie(vap,
                           (u_int8_t *)wbuf_header(wbuf),
                           (frm - (u_int8_t *)wbuf_header(wbuf)));
        if (res != NULL) {
            frm = res;
        }
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    if (handler) {
        ni->ni_reason_code = reason;
        ieee80211_vap_set_complete_buf_handler(wbuf, handler, arg);
    }
    /* Flush frames from backlog queue */
    ieee80211_flush_peer_mgmt_queue(ni);
    if (vap->iv_vap_is_down)
        return ieee80211_send_mgmt(vap, ni, wbuf, true);
    else
        return ieee80211_send_mgmt(vap, ni, wbuf, false);
}

int ieee80211_is_robust_action_frame(u_int8_t category)
{
    switch (category) {
        case IEEE80211_ACTION_CAT_SPECTRUM:          /* Spectrum management */
        case IEEE80211_ACTION_CAT_QOS:               /* IEEE QoS  */
        case IEEE80211_ACTION_CAT_DLS:               /* DLS */
        case IEEE80211_ACTION_CAT_BA:                /* BA */
        case IEEE80211_ACTION_CAT_SA_QUERY:          /* SA Query per IEEE802.11w, PMF */
        case IEEE80211_ACTION_CAT_WNM:               /* WNM */
        case IEEE80211_ACTION_CAT_WMM_QOS:           /* QoS from WMM specification */
        case IEEE80211_ACTION_CAT_PROT_DUAL:         /* Protected Dual of Public Action Frames */
        case IEEE80211_ACTION_CAT_FAST_BSS_TRNST:    /* Fsat bss transition action frame */
        case IEEE80211_ACTION_CAT_ROBUST_AV_STREAM:
        /* TODO: add all robust action categories */
            return 1;
        default:
            return 0;
    }
}

int
ieee80211_send_action(
    struct ieee80211_node *ni,
    struct ieee80211_action_mgt_args *actionargs,
    struct ieee80211_action_mgt_buf  *actionbuf
    )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    int error = EOK;

    switch (actionargs->category) {
    case IEEE80211_ACTION_CAT_SPECTRUM: {
        switch(actionargs->action) {
        case IEEE80211_ACTION_CHAN_SWITCH:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 1);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            *frm++ = actionargs->category;
            *frm++ = actionargs->action;
            frm = ieee80211_mgmt_add_chan_switch_ie(frm, ni,
                          IEEE80211_FC0_SUBTYPE_ACTION, ic->ic_chanchange_tbtt);
            break;
        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid spectrum action mgt frame", __func__);
            error = -EINVAL;
            break;
        }

        break;
    }
    case IEEE80211_ACTION_CAT_ROBUST_AV_STREAM: {
        switch(actionargs->action) {
        case IEEE80211_ACTION_MSCS_RESPONSE:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            *frm++ = actionargs->category;
            *frm++ = actionargs->action;
            *frm++ = actionargs->arg1;
            *frm++ = actionargs->arg2 & 0x000000ff;
            *frm++ = (actionargs->arg2 & 0x0000ff00) >> 8;
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid robust streaming action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_QOS:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: QoS action mgt frames not supported", __func__);
        error = -EINVAL;
        break;

    case IEEE80211_ACTION_CAT_BA: {
        struct ieee80211_action_ba_addbarequest *addbarequest;
        struct ieee80211_action_ba_addbaresponse *addbaresponse;
        struct ieee80211_action_ba_delba *delba;
        struct ieee80211_ba_parameterset baparamset;
        struct ieee80211_ba_seqctrl basequencectrl;
        struct ieee80211_delba_parameterset delbaparamset;
        u_int16_t batimeout;
        u_int16_t statuscode;
        u_int16_t reasoncode;
        u_int16_t buffersize;
        u_int8_t tidno;
        u_int16_t temp;
        int result = 0;

        /* extract TID */
        tidno = actionargs->arg1;
        switch (actionargs->action) {
        case IEEE80211_ACTION_BA_ADDBA_REQUEST:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            addbarequest = (struct ieee80211_action_ba_addbarequest *)frm;
            frm += sizeof(struct ieee80211_action_ba_addbarequest);

            addbarequest->rq_header.ia_category     = IEEE80211_ACTION_CAT_BA;
            addbarequest->rq_header.ia_action       = actionargs->action;
            addbarequest->rq_dialogtoken            = tidno + 1;
            buffersize                              = actionargs->arg2;

            ic->ic_addba_requestsetup(ni, tidno,
                                      &baparamset,
                                      &batimeout,
                                      &basequencectrl,
                                      buffersize);
            /* "struct ieee80211_action_ba_addbarequest" is annotated __packed,
               if accessing fields, like rq_baparamset or rq_basequencectrl,
               by using u_int16_t* directly, it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            temp = htole16(*(u_int16_t *)&baparamset);
            OS_MEMCPY(&addbarequest->rq_baparamset, &temp, sizeof(u_int16_t));
            addbarequest->rq_batimeout = htole16(batimeout);
            temp =htole16(*(u_int16_t *)&basequencectrl);
            OS_MEMCPY(&addbarequest->rq_basequencectrl, &temp, sizeof(u_int16_t));

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA request action mgt frame. TID %d, buffer size %d",
                           __func__, tidno, baparamset.buffersize);
            break;

        case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            addbaresponse = (struct ieee80211_action_ba_addbaresponse *)frm;
            frm += sizeof(struct ieee80211_action_ba_addbaresponse);

            addbaresponse->rs_header.ia_category    = IEEE80211_ACTION_CAT_BA;
            addbaresponse->rs_header.ia_action      = actionargs->action;


            if (!(ic->ic_addba_mode == ADDBA_MODE_MANUAL &&
                    vap->iv_refuse_all_addbas)) {
                result = ic->ic_addba_responsesetup(ni, tidno,
                                       &addbaresponse->rs_dialogtoken,
                                       &statuscode,
                                       &baparamset,
                                       &batimeout);
                if(result) {
                    error = -ENOMEM;
                    break;
                }

                if (!wlan_vdev_mlme_feat_cap_get(vap->vdev_obj, WLAN_VDEV_FEXT_AMSDU)) {
                    qdf_print("AMSDU in AMPDU support disabled");
                    baparamset.amsdusupported = !IEEE80211_BA_AMSDU_SUPPORTED;
                }

                temp = htole16(*(u_int16_t *)&baparamset);
            }
            else {
                /* In case user choses to refuse all ADD BA request
                 * we overwrite the statuscode here
                 */
                qdf_print("ADD BA is rejected in associd: %d tid: %d",
                                                    ni->ni_associd, tidno);
                temp                          = 0;
                batimeout                     = 0;
                statuscode                    = IEEE80211_STATUS_REFUSED;
                addbaresponse->rs_dialogtoken = 0;
                baparamset.buffersize         = 0;
            }

            /* "struct ieee80211_action_ba_addbaresponse" is annotated __packed,
               if accessing fields, like rs_baparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&addbaresponse->rs_baparamset, &temp, sizeof(u_int16_t));
            addbaresponse->rs_batimeout  = htole16(batimeout);
            addbaresponse->rs_statuscode = htole16(statuscode);

            if(actionargs->arg2) {
                frm = ieee80211_add_addba_ext(frm, vap, actionargs->arg3);
            }

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA response action mgt frame. TID %d, buffer size %d, status %d",
                           __func__, tidno, baparamset.buffersize, statuscode);
            break;

        case IEEE80211_ACTION_BA_DELBA:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            delba = (struct ieee80211_action_ba_delba *)frm;
            frm += sizeof(struct ieee80211_action_ba_delba);

            delba->dl_header.ia_category = IEEE80211_ACTION_CAT_BA;
            delba->dl_header.ia_action = actionargs->action;

            delbaparamset.reserved0 = 0;
            delbaparamset.initiator = actionargs->arg2;
            delbaparamset.tid = tidno;
            reasoncode = actionargs->arg3;
            /* "struct ieee80211_action_ba_delba" is annotated __packed,
               if accessing fields, like dl_delbaparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            temp = htole16(*(u_int16_t *)&delbaparamset);
            OS_MEMCPY(&delba->dl_delbaparamset, &temp, sizeof(u_int16_t));
            delba->dl_reasoncode = htole16(reasoncode);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: DELBA action mgt frame. TID %d, initiator %d, reason %d, macaddr (%s)",
                           __func__, tidno, delbaparamset.initiator,
                           reasoncode, ether_sprintf(ni->ni_macaddr));
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid BA action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
        break;
    }
    case IEEE80211_ACTION_CAT_HT: {
        struct ieee80211_action_ht_txchwidth *txchwidth;
        struct ieee80211_action_ht_smpowersave *smpsframe;
        switch (actionargs->action) {
        case IEEE80211_ACTION_HT_TXCHWIDTH:
            {
                enum ieee80211_cwm_width cw_width = ic->ic_cwm_get_width(ic);
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT txchwidth action mgt frame. Width %d",
                        __func__, cw_width);

            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            txchwidth = (struct ieee80211_action_ht_txchwidth *)frm;
            frm += sizeof(struct ieee80211_action_ht_txchwidth);

            txchwidth->at_header.ia_category = IEEE80211_ACTION_CAT_HT;
            txchwidth->at_header.ia_action  = IEEE80211_ACTION_HT_TXCHWIDTH;
                txchwidth->at_chwidth =  (cw_width == IEEE80211_CWM_WIDTH40) ?
                IEEE80211_A_HT_TXCHWIDTH_2040 : IEEE80211_A_HT_TXCHWIDTH_20;
            }
            break;
        case IEEE80211_ACTION_HT_SMPOWERSAVE:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT mimo pwr save action mgt frame", __func__);

            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            smpsframe = (struct ieee80211_action_ht_smpowersave *)frm;
            frm += sizeof(struct ieee80211_action_ht_smpowersave);

            smpsframe->as_header.ia_category = IEEE80211_ACTION_CAT_HT;
            smpsframe->as_header.ia_action 	 = IEEE80211_ACTION_HT_SMPOWERSAVE;
            smpsframe->as_control =  (actionargs->arg1 << 0) | (actionargs->arg2 << 1);

            /* Mark frame for appropriate action on completion */
            wbuf_set_smpsactframe(wbuf);
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid HT action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
    }
    break;

    case IEEE80211_ACTION_CAT_VHT: {
        struct ieee80211_action_vht_opmode *opmode_frame;
        enum ieee80211_cwm_width cw_width = ic->ic_cwm_get_width(ic);
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: VHT Op Mode Notify action frame. Width %d Nss = %d",
                            __func__, cw_width, vap->vdev_mlme->proto.generic.nss);
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }
        opmode_frame = (struct ieee80211_action_vht_opmode *)frm;
        opmode_frame->at_header.ia_category = IEEE80211_ACTION_CAT_VHT;
        opmode_frame->at_header.ia_action  = IEEE80211_ACTION_VHT_OPMODE;
        ieee80211_add_opmode((u_int8_t *)&opmode_frame->at_op_mode, ni, ic, IEEE80211_ACTION_CAT_VHT);
        frm += sizeof(struct ieee80211_action_vht_opmode);
    }
    break;

    case IEEE80211_ACTION_CAT_WMM_QOS: {
        struct ieee80211_action_wmm_qos *tsframe;
        struct ieee80211_wme_tspec *tsdata = (struct ieee80211_wme_tspec *) &actionbuf->buf;
        struct ieee80211_frame *wh;
        u_int8_t    tsrsiev[16];
        u_int8_t    tsrsvlen = 0;
        u_int32_t   minphyrate;

        /* TSPEC action mamangement frames */
        switch (actionargs->action) {
        case IEEE80211_WMM_QOS_ACTION_SETUP_REQ:
        case IEEE80211_WMM_QOS_ACTION_SETUP_RESP:
        case IEEE80211_WMM_QOS_ACTION_TEARDOWN:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            wh = (struct ieee80211_frame*)wbuf_header(wbuf);

            tsframe = (struct ieee80211_action_wmm_qos *)frm;
            tsframe->ts_header.ia_category = actionargs->category;
            tsframe->ts_header.ia_action = actionargs->action;
            tsframe->ts_dialogtoken = actionargs->arg1;
            tsframe->ts_statuscode = actionargs->arg2;
            /* fill in the basic structure for tspec IE */
            frm = ieee80211_add_wmeinfo((u_int8_t *) &tsframe->ts_tspecie, ni,
                                        WME_TSPEC_OUI_SUBTYPE, (u_int8_t *) &tsdata->ts_tsinfo,
                                        sizeof (struct ieee80211_wme_tspec) - offsetof(struct ieee80211_wme_tspec, ts_tsinfo));
            if (vap->iv_opmode != IEEE80211_M_STA) {
                break;
            }
            if (actionargs->action == IEEE80211_WMM_QOS_ACTION_SETUP_REQ) {
                /* Save the tspec to be used in next assoc request */
                if (((struct ieee80211_tsinfo_bitmap *)(&tsdata->ts_tsinfo))->tid == IEEE80211_WMM_QOS_TSID_SIG_TSPEC)
                    OS_MEMCPY(&ic->ic_sigtspec, (u_int8_t *) &tsframe->ts_tspecie, sizeof(struct ieee80211_wme_tspec));
                else
                    OS_MEMCPY(&ic->ic_datatspec, (u_int8_t *) &tsframe->ts_tspecie, sizeof(struct ieee80211_wme_tspec));
#if AH_UNALIGNED_SUPPORTED
                /*
                 * Get unaligned data
                 */
                minphyrate = __get32(&tsdata->ts_min_phy[0]);
#else
                minphyrate = *((u_int32_t *) &tsdata->ts_min_phy[0]);
#endif
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_fill_tsrsie) {
                    vap->iv_ccx_evtable->wlan_ccx_fill_tsrsie(vap->iv_ccx_arg,
                         ((struct ieee80211_tsinfo_bitmap *) &tsdata->ts_tsinfo[0])->tid,
                         minphyrate, &tsrsiev[0], &tsrsvlen);
                }
                if (tsrsvlen > 0) {
                    *frm++ = IEEE80211_ELEMID_VENDOR;
                    *frm++ = tsrsvlen;
                    OS_MEMCPY(frm, &tsrsiev[0], tsrsvlen);
                    frm += tsrsvlen;
                }
            } else if (actionargs->action == IEEE80211_WMM_QOS_ACTION_TEARDOWN) {
                /* if sending DELTS, wipeout stored TSPECs unconditionally */
                OS_MEMZERO(&ic->ic_sigtspec, sizeof(struct ieee80211_wme_tspec));
                OS_MEMZERO(&ic->ic_datatspec, sizeof(struct ieee80211_wme_tspec));
                /* Disable QoS handling internally */
                wlan_set_tspecActive(vap, 0);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                    vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 0);
                }
            }
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid WMM QOS action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
    }
        break;

    case IEEE80211_ACTION_CAT_PUBLIC: {
        if (vap->iv_opmode == IEEE80211_M_STA)
        {
            switch(actionargs->action)
            {
            case 0:
                if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT 2040 coexist action mgt frame.",__func__);

                    do {
                        struct ieee80211_action *header;
                        struct ieee80211_ie_bss_coex *coexist;
                        struct ieee80211_ie_intolerant_report *intolerantchanreport;
                        u_int8_t *p;
                        u_int32_t i;

                        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
                        if (wbuf == NULL) {
                            error = -ENOMEM;
                            break;
                        }

                        header = (struct ieee80211_action *)frm;
                        header->ia_category = IEEE80211_ACTION_CAT_PUBLIC;
                        header->ia_action = actionargs->action;

                        frm += sizeof(struct ieee80211_action);

                        coexist = (struct ieee80211_ie_bss_coex *)frm;
                        OS_MEMZERO(coexist, sizeof(struct ieee80211_ie_bss_coex));
                        coexist->elem_id = IEEE80211_ELEMID_2040_COEXT;
                        coexist->elem_len = 1;
                        coexist->ht20_width_req = actionargs->arg1;

                        frm += sizeof(struct ieee80211_ie_bss_coex);

                        intolerantchanreport = (struct ieee80211_ie_intolerant_report*)frm;

                        intolerantchanreport->elem_id = IEEE80211_ELEMID_2040_INTOL;
                        intolerantchanreport->elem_len = actionargs->arg3 + 1;
                        intolerantchanreport->reg_class = actionargs->arg2;
                        p = intolerantchanreport->chan_list;
                        for (i=0; i<actionargs->arg3; i++) {
                            *p++ = actionbuf->buf[i];
                        }

                        frm += intolerantchanreport->elem_len + 2;
                    } while (FALSE);

                } else {
                    error = -EINVAL;
                }
                break;
            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: action mgt frame has invalid action %d", __func__, actionargs->action);
                error = -EINVAL;
                break;
            }
        } else {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
               "%s: action mgt frame has Invalid opmode %d", __func__, actionargs->action);
            error = -EINVAL;
        }
    }
    break;

    case IEEE80211_ACTION_CAT_SA_QUERY: {
        struct ieee80211_action_sa_query    *saQuery;
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }

        saQuery = (struct ieee80211_action_sa_query*)frm;
        frm += sizeof(*saQuery);
        saQuery->sa_header.ia_category = actionargs->category;
        saQuery->sa_header.ia_action = actionargs->action;
        saQuery->sa_transId = actionargs->arg1;

    }
    break;

    case IEEE80211_ACTION_CAT_VENDOR: {
        struct ieee80211_action_vendor_specific *ven;
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }
        ven = (struct ieee80211_action_vendor_specific*)frm;
        ven->ia_category = actionargs->category;
        ven->vendor_oui[0] = 0x00;
        ven->vendor_oui[1] = 0x03;
        ven->vendor_oui[2] = 0x7f;
        frm += sizeof(struct ieee80211_action_vendor_specific);

        switch(actionargs->action) {
        case IEEE80211_ACTION_CHAN_SWITCH: {
            /* Send Either RCSA IE alone or RCSA and NOL IE. */
            struct ieee80211_ath_channelswitch_ie   *csa_element;
            csa_element = (struct ieee80211_ath_channelswitch_ie *) frm;
            csa_element->ie             = IEEE80211_ELEMID_CHANSWITCHANN;
            csa_element->len            = sizeof(struct ieee80211_ath_channelswitch_ie)
                                         - sizeof(struct ieee80211_ie_header);
            csa_element->switchmode     = 1;
            csa_element->newchannel     = 36; /* ic->ic_chanchange_chan; */
            csa_element->tbttcount      = ic->ic_rcsa_count;
            frm += sizeof(struct ieee80211_ath_channelswitch_ie);
            if (actionargs->arg1)
                frm = ieee80211_add_nol_ie(frm, vap, ic);
        }
        break;

        case IEEE80211_ELEMID_VENDOR: {
            /* Send NOL IE alone. */
            frm = ieee80211_add_nol_ie(frm, vap, ic);
        }
        break;

        default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: vendor specifi action mgt frame has invalid type %d", __func__, actionargs->category);
        error = -EINVAL;
        break;
        }
    }
    break;

    default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: action mgt frame has invalid category %d", __func__, actionargs->category);
        error = -EINVAL;
        break;
    }

    if (error == EOK) {
        ASSERT(wbuf != NULL);
        ASSERT(frm != NULL);

        if (ieee80211_is_robust_action_frame(actionargs->category) &&
            ((ieee80211_vap_mfp_test_is_set(vap) ||
               wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj)) &&
               ieee80211_node_is_authorized(ni))) {
            struct ieee80211_frame *wh;
            wh = (struct ieee80211_frame*)wbuf_header(wbuf);
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }

        wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));

        error = ieee80211_send_mgmt(vap,ni, wbuf,false);
    }

    return error;
}

/*
 * Send a self-CTS frame
 */
int
ieee80211_send_cts(struct ieee80211_node *ni, int flags)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame_cts *cts;

    /*
     * It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    cts = (struct ieee80211_frame_cts *)wbuf_header(wbuf);
    cts->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    cts->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CTS;
    IEEE80211_ADDR_COPY(cts->i_ra, ni->ni_macaddr);

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame_cts));

    if (flags & IEEE80211_CTS_SMPS)
        wbuf_set_smpsframe(wbuf);

    return ieee80211_send_mgmt(vap, ni, wbuf, true);
}

/*
 * Return a prepared QoS NULL frame.
 */
void
ieee80211_prepare_qosnulldata(struct ieee80211_node *ni, wbuf_t wbuf, int ac)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_qosframe *qwh;
    int tid;

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    ieee80211_send_setup(vap, ni, (struct ieee80211_frame *)qwh,
        IEEE80211_FC0_TYPE_DATA,
        vap->iv_myaddr, /* SA */
        ni->ni_macaddr, /* DA */
        ni->ni_bssid);

    qwh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA |
        IEEE80211_FC0_SUBTYPE_QOS_NULL;

    if (IEEE80211_VAP_IS_SLEEPING(ni->ni_vap) || ieee80211_vap_forced_sleep_is_set(vap)) {
        wbuf_set_pwrsaveframe(wbuf);
        qwh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
    }

    /* map from access class/queue to 11e header priority value */
    tid = WME_AC_TO_TID(ac);
    qwh->i_qos[0] = tid & IEEE80211_QOS_TID;
    if (vap->iv_opmode != IEEE80211_M_STA) {
                qwh->i_qos[0] |= IEEE80211_QOS_EOSP;
    }

    if (wbuf_is_offchan_tx(wbuf))
    {
        qwh->i_qos[0] |= (1 << IEEE80211_QOS_ACKPOLICY_S) & IEEE80211_QOS_ACKPOLICY;
    }

    if (ic->ic_wme.wme_wmeChanParams.cap_wmeParams[ac].wmep_noackPolicy)
    {
        qwh->i_qos[0] |= (1 << IEEE80211_QOS_ACKPOLICY_S) & IEEE80211_QOS_ACKPOLICY;
    }

    qwh->i_qos[1] = 0;
}

/*
 * send a QoSNull frame
 */
int ieee80211_send_qosnulldata(struct ieee80211_node *ni, int ac, int pwr_save)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_qosframe *qwh;
    u_int32_t   hdrsize;

    if (ieee80211_get_home_channel(vap) !=
           ieee80211_get_current_channel(ic))
	{
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
				  "%s[%d] cur chan freq %d is not same as home chan freq %d\n",
				  __func__, __LINE__,
				  ieee80211_chan2freq(ic, ic->ic_curchan),ieee80211_chan2freq(ic, vap->iv_bsschan));
		return EOK;
	}

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_qosframe));
    if (wbuf == NULL)
        return -ENOMEM;

    ieee80211_prepare_qosnulldata(ni, wbuf, ac);

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    hdrsize = sizeof(struct ieee80211_qosframe);

    if (ic->ic_flags & IEEE80211_F_DATAPAD) {
        /* add padding if required and zero out the padding */
        u_int8_t pad = roundup(hdrsize, sizeof(u_int32_t)) - hdrsize;
        OS_MEMZERO( (u_int8_t *) ((u_int8_t *) qwh + hdrsize), pad);
        hdrsize += pad;
    }
    wbuf_set_pktlen(wbuf, hdrsize);

#if QCA_SUPPORT_SON
    if( wlan_peer_mlme_flag_get(ni->peer_obj,
                WLAN_PEER_F_BSTEERING_CAPABLE)) {
        wbuf_set_bsteering(wbuf);
    }

    wlan_peer_mlme_flag_clear(ni->peer_obj,
                  WLAN_PEER_F_BSTEERING_CAPABLE);
#endif

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] send qos null data frame \n",__func__);
       return ieee80211_send_mgmt(vap,ni, wbuf,true);
    }
}

/*
 * receive management processing code.
 */


enum ieee80211_phymode
ieee80211_get_phy_type (
    struct ieee80211com               *ic,
    u_int8_t                          *rates,
    u_int8_t                          *xrates,
    struct ieee80211_ie_htcap_cmn     *htcap,
    struct ieee80211_ie_htinfo_cmn    *htinfo,
    struct ieee80211_ie_vhtcap        *vhtcap,
    struct ieee80211_ie_vhtop         *vhtop,
    struct ieee80211_ie_hecap         *hecap,
    struct ieee80211_ie_heop          *heop,
    struct ieee80211_ath_channel      *bcn_recv_chan
    )
{
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    u_int16_t    htcapabilities = 0;
    struct ieee80211_ath_channel  *nc = NULL;
    u_int32_t    vhtcapinfo = 0;
    uint16_t freq = bcn_recv_chan->ic_freq;
    uint64_t band_flag = ieee80211_get_band_flag(freq);
    struct heop_6g_param *heop_6g = NULL;
    uint32_t he_width_mask;
    uint8_t *hecap_phy_info, width_set;

    /*
     * Determine BSS phyType
     */

    if (htcap != NULL) {
        htcapabilities = le16toh(htcap->hc_cap);
    }
    if (vhtcap != NULL) {
        vhtcapinfo = le32toh(vhtcap->vht_cap_info);
    }

    if (IEEE80211_IS_CHAN_6GHZ(bcn_recv_chan)) {
        if (!hecap || !heop) {
            qdf_debug("HE IEs not present");
            phymode = IEEE80211_MODE_11AXA_HE20;
            return phymode;
        }
        if ((hecap || heop)  &&
                (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE20) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40PLUS) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40MINUS) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160) ||
                 IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80_80))) {

            hecap_phy_info = (uint8_t *) &(hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
            he_width_mask = HECAP_PHY_CBW_GET_FROM_IE(&hecap_phy_info);
            heop_6g = ieee80211_get_he_6g_opinfo(heop);

            if (heop_6g == NULL) {
                qdf_debug("heop 6g not present");
                phymode = IEEE80211_MODE_11AXA_HE20;
                return phymode;
            }

            switch (heop_6g->channel_width) {
                case IEEE80211_6GOP_CHWIDTH_160_80_80:
                    width_set = he_width_mask & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;
                    if ((width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) &&
                        IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80_80)) {
                        phymode = IEEE80211_MODE_11AXA_HE80_80;
                    } else if ((width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) &&
                               IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160)) {
                        phymode = IEEE80211_MODE_11AXA_HE160;
                    } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                        phymode = IEEE80211_MODE_11AXA_HE80;
                    } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                        if ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_HE40PLUS))) != NULL) {
                            phymode = IEEE80211_MODE_11AXA_HE40PLUS;
                        } else {
                            phymode = IEEE80211_MODE_11AXA_HE40MINUS;
                        }
                    } else {
                        phymode = IEEE80211_MODE_11AXA_HE20;
                    }
                    break;
                case IEEE80211_6GOP_CHWIDTH_80:
                    if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                        phymode = IEEE80211_MODE_11AXA_HE80;
                    } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                        if ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_HE40PLUS))) != NULL) {
                            phymode = IEEE80211_MODE_11AXA_HE40PLUS;
                        } else {
                            phymode = IEEE80211_MODE_11AXA_HE40MINUS;
                        }
                    } else {
                        phymode = IEEE80211_MODE_11AXA_HE20;
                    }
                    break;
                case IEEE80211_6GOP_CHWIDTH_40:
                    if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                        if ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_HE40PLUS))) != NULL) {
                            phymode = IEEE80211_MODE_11AXA_HE40PLUS;
                        } else {
                            phymode = IEEE80211_MODE_11AXA_HE40MINUS;
                        }
                    } else {
                        phymode = IEEE80211_MODE_11AXA_HE20;
                    }
                    break;
                case IEEE80211_6GOP_CHWIDTH_20:
                    phymode = IEEE80211_MODE_11AXA_HE20;
                    break;

                default:
                    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                            "%s : Received Bad Chwidth", __func__);
                    break;
            }
        } else {
            phymode = IEEE80211_MODE_11AXA_HE20;
        }
    } else if (IEEE80211_IS_CHAN_5GHZ(bcn_recv_chan)) {
        if (htcap && htinfo) {

            /* Check for HE capability only if we as well support
             * VHT & HT mode.  11AX TODO (Phase II) change later
             * on HE CAP or OP check to && check as spec evolves
             */
            if ((hecap || heop )&& vhtcap && vhtop &&
                 (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE20) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40PLUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40MINUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80_80))) {

                switch (vhtop->vht_op_chwidth) {
                    case IEEE80211_VHTOP_CHWIDTH_2040 :
                        if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40PLUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) &&
                            ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_HE40PLUS))) != NULL)) {
                                phymode = IEEE80211_MODE_11AXA_HE40PLUS;
                        } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40MINUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) &&
                            ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_HE40MINUS))) != NULL)) {
                                phymode = IEEE80211_MODE_11AXA_HE40MINUS;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE20) &&
                                ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_VHT20))) != NULL)) {
                            phymode = IEEE80211_MODE_11AXA_HE20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80 :
                    if ((ic->ic_ext_nss_capable && peer_ext_nss_capable(vhtcap) && extnss_80p80_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo))
                         || IS_REVSIG_VHT80_80(vhtop)) {
                        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80_80)) {
                            phymode = IEEE80211_MODE_11AXA_HE80_80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160)) {
                            phymode = IEEE80211_MODE_11AXA_HE160;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                            phymode = IEEE80211_MODE_11AXA_HE80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                            phymode = IEEE80211_MODE_11AXA_HE40;
                        } else {
                            phymode = IEEE80211_MODE_11AXA_HE20;
                        }
                    } else if (ic->ic_ext_nss_capable && peer_ext_nss_capable(vhtcap) &&
                               extnss_160_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo) &&
                               IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160)) {
                            phymode = IEEE80211_MODE_11AXA_HE160;
                    } else if (IS_REVSIG_VHT160(vhtop) && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160)) {
                            phymode = IEEE80211_MODE_11AXA_HE160;
                    }
                        else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                            phymode = IEEE80211_MODE_11AXA_HE80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                            phymode = IEEE80211_MODE_11AXA_HE40;
                        } else {
                            phymode = IEEE80211_MODE_11AXA_HE20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_160 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                             phymode = IEEE80211_MODE_11AXA_HE160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                             phymode = IEEE80211_MODE_11AXA_HE80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                             phymode = IEEE80211_MODE_11AXA_HE40;
                         } else {
                             phymode = IEEE80211_MODE_11AXA_HE20;
                         }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80_80 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80_80)) {
                             phymode = IEEE80211_MODE_11AXA_HE80_80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE160)) {
                             phymode = IEEE80211_MODE_11AXA_HE160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE80)) {
                             phymode = IEEE80211_MODE_11AXA_HE80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXA_HE40)) {
                             phymode = IEEE80211_MODE_11AXA_HE40;
                         } else {
                             phymode = IEEE80211_MODE_11AXA_HE20;
                         }
                    break;
                    default:
                        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                               "%s : Received Bad Chwidth", __func__);
                    break;
                }

            /* See section 10.39.1 of the VHT specification Table 10-19a */
            } else if (vhtcap && vhtop &&
                 (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT20) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40PLUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40MINUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80))) {

                switch (vhtop->vht_op_chwidth) {
                    case IEEE80211_VHTOP_CHWIDTH_2040 :
                        if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40PLUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) &&
                            ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_VHT40PLUS))) != NULL)) {
                                phymode = IEEE80211_MODE_11AC_VHT40PLUS;
                        } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40MINUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) &&
                            ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_VHT40MINUS))) != NULL)) {
                                phymode = IEEE80211_MODE_11AC_VHT40MINUS;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT20) &&
                                ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, (band_flag | IEEE80211_CHAN_VHT20))) != NULL)) {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80 :
                    if ((ic->ic_ext_nss_capable && peer_ext_nss_capable(vhtcap) && extnss_80p80_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo))
                            || IS_REVSIG_VHT80_80(vhtop)){
                        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80_80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                            phymode = IEEE80211_MODE_11AC_VHT40;
                        } else {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    } else if (ic->ic_ext_nss_capable && peer_ext_nss_capable(vhtcap) &&
                               extnss_160_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo) &&
                               IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                    } else if (IS_REVSIG_VHT160(vhtop) && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                            phymode = IEEE80211_MODE_11AC_VHT40;
                        } else {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_160 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                             phymode = IEEE80211_MODE_11AC_VHT160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                             phymode = IEEE80211_MODE_11AC_VHT40;
                         } else {
                             phymode = IEEE80211_MODE_11AC_VHT20;
                         }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80_80 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80_80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                             phymode = IEEE80211_MODE_11AC_VHT160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                             phymode = IEEE80211_MODE_11AC_VHT40;
                         } else {
                             phymode = IEEE80211_MODE_11AC_VHT20;
                         }
                    break;
                    default:
                        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                               "%s : Received Bad Chwidth", __func__);
                    break;
                }
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40PLUS)) {
                phymode = IEEE80211_MODE_11NA_HT40PLUS;
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                       (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                       IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40MINUS)) {
                phymode = IEEE80211_MODE_11NA_HT40MINUS;
            } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20)) {
                phymode = IEEE80211_MODE_11NA_HT20;
            } else {
                phymode = IEEE80211_MODE_11A;
            }
        } else {
            phymode = IEEE80211_MODE_11A;
        }
    } else {
        /* Check for HE capability only if we as well support
         * HT mode.  11AX TODO (Phase II) change later
         * on HE CAP or OP check to && check as spec evolves
         */
        if (htcap && htinfo && (hecap || heop) && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXG_HE20)) {
            if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AXG_HE40PLUS)) {
                phymode = IEEE80211_MODE_11AXG_HE40PLUS;
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                       (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                       IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40MINUS)) {
                phymode = IEEE80211_MODE_11AXG_HE40MINUS;
            } else {
                phymode = IEEE80211_MODE_11AXG_HE20;
            }
        }
        /* Check for HT capability only if we as well support HT mode */
        else if (htcap && htinfo && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
            if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40PLUS)) {
                phymode = IEEE80211_MODE_11NG_HT40PLUS;
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                       (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                       IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40MINUS)) {
                phymode = IEEE80211_MODE_11NG_HT40MINUS;
            } else {
                phymode = IEEE80211_MODE_11NG_HT20;
            }
        } else if (xrates != NULL) {
            /*
             * XXX: This is probably the most reliable way to tell the difference
             * between 11g and 11b beacons.
             */
            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)) {
                phymode = IEEE80211_MODE_11G;
            } else {
                phymode = IEEE80211_MODE_11B;
            }
        }
        else {
            /* Some mischievous g-only APs do not set extended rates */
            if (rates != NULL) {
                u_int8_t    *tmpPtr  = rates + 2;
                u_int8_t    tmpSize = rates[1];
                u_int8_t    *tmpPtrTail = tmpPtr + tmpSize;
                int         found11g = 0;

                for (; tmpPtr < tmpPtrTail; tmpPtr++) {
                    found11g = ieee80211_find_puregrate(*tmpPtr);
                    if (found11g)
                        break;
                }

                if (found11g) {
                    if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)) {
                        phymode = IEEE80211_MODE_11G;
                    } else {
                        phymode = IEEE80211_MODE_11B;
                    }
                } else {
                    phymode = IEEE80211_MODE_11B;
                }
            } else {
                phymode = IEEE80211_MODE_11B;
            }
        }
    }

    return phymode;
}

static int
bss_intol_channel_check(struct ieee80211_node *ni,
                        struct ieee80211_ie_intolerant_report *intol_ie)
{
    struct ieee80211com *ic = ni->ni_ic;
    int i, j;
    u_int8_t intol_chan  = 0;
    u_int8_t *chan_list = &intol_ie->chan_list[0];
    enum wlan_band_id chan_band;

    /*
    ** Determine the reg band the node is operating in currently
    */

    chan_band = reg_wifi_band_to_wlan_band_id(wlan_reg_freq_to_band(ni->ni_chan->ic_freq));

    if (intol_ie->elem_len <= 1)
        return 0;

    /*
    ** Check the report against the channel list.
    */

    for (i = 0; i < intol_ie->elem_len-1; i++) {
        intol_chan = *chan_list++;

        /*
        ** If the intolarant channel is not in my band, ignore
        */

        if( (intol_chan > 15 && chan_band == WLAN_BAND_2GHZ) || (intol_chan < 16 && chan_band == WLAN_BAND_5GHZ))
            continue;

        /*
        ** Check against the channels supported by the "device"
        ** (note: Should this be limited by "WIRELESS_MODE"
        */

        for (j = 0; j < ic->ic_nchans; j++) {
            if (intol_chan == ic->ic_channels[j].ic_ieee) {
                IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Found intolerant channel %d freq %d",
                               __func__, intol_chan,
                              wlan_reg_chan_band_to_freq(ic->ic_pdev_obj,
                                     intol_chan,
                                     wlan_band_id_to_reg_wifi_band(chan_band)));
                              return 1;
            }
        }
    }
    return 0;
}

#if MESH_MODE_SUPPORT
static u_int32_t cal_ie_checksum(struct ie_list *se_ie_list)
{
    u_int32_t sum = 0;
    u_int32_t ie_len = 0;
    u_int8_t *rates=NULL, *htcap=NULL, *vhtcap=NULL, *vhtop=NULL, *hecap=NULL, *heop=NULL;

    rates = se_ie_list->rates;
    ie_len = *(rates+1);
    sum = csum_partial(rates, ie_len, 0);

    htcap = se_ie_list->htcap;
    if(htcap!=NULL){
        ie_len = *(htcap+1);
        sum = csum_partial(htcap, ie_len, sum);
    }

    vhtcap = se_ie_list->vhtcap;
    if(vhtcap!=NULL){
        ie_len = *(vhtcap+1);
        sum = csum_partial(vhtcap, ie_len, sum);
    }

    vhtop = se_ie_list->vhtop;
    if(vhtop!=NULL){
        ie_len = *(vhtop+1);
        sum = csum_partial(vhtop, ie_len, sum);
    }

    hecap = se_ie_list->hecap;
    if(hecap!=NULL){
        ie_len = *(hecap+1);
        sum = csum_partial(hecap, ie_len, sum);
    }

    heop = se_ie_list->heop;
    if(heop!=NULL){
        ie_len = *(heop+1);
        sum = csum_partial(heop, ie_len, sum);
    }

    return (sum);
}

static struct ieee80211_node *
ieee80211_find_mesh_peer(struct ieee80211com *ic, u_int8_t *mac)
{
    struct ieee80211_node *ni_mesh = NULL, *ni = NULL;

    ni = ieee80211_find_node(ic, mac, WLAN_MGMT_HANDLER_ID);
    if (ni) {
        if (ni->ni_ext_flags & IEEE80211_LOCAL_MESH_PEER) {
            ni_mesh = ni;
        } else {
            ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);
        }
    }
    return ni_mesh;
}

#if MESH_PEER_DYNAMIC_UPDATE
extern unsigned int enable_mesh_peer_cap_update;
extern int ieee80211_beacon_intersect(struct ieee80211_node *ni, u_int8_t *bcn_frm_body,
                                      u_int16_t bcn_body_len, struct ieee80211_frame *wh);
#endif
static void ieee80211_beacon_mesh_process(struct ieee80211com *ic,
                                   struct ieee80211vap *vap,
                                   ieee80211_scan_entry_t scan_entry,
                                   wbuf_t wbuf,
                                   struct ieee80211_frame *wh)
{
    struct ieee80211_node *ni_mesh = NULL;
#if MESH_PEER_DYNAMIC_UPDATE
    u_int32_t   bcn_ie_chksum = 0;
    int         intersect_ret = 0;
#endif
    u_int32_t ie_size = 0;

    /* Check if current scan_entry is the mesh VAP */
    ni_mesh = ieee80211_find_mesh_peer(ic, (u_int8_t *)&scan_entry->mac_addr);
    if (!ni_mesh) {
        return;
    }
    ie_size = wbuf_get_pktlen(wbuf) - sizeof(struct wlan_frame_hdr);
    ni_mesh->ni_meshpeer_timeout_cnt = 0;
#if MESH_PEER_DYNAMIC_UPDATE
    if (enable_mesh_peer_cap_update == 1) {
        if(ni_mesh->ni_mesh_bcn_ie_chksum == 0){
            bcn_ie_chksum = cal_ie_checksum(&(scan_entry->ie_list));
            ni_mesh->ni_mesh_bcn_ie_chksum = bcn_ie_chksum;
        }
        if(!(ni_mesh->ni_mesh_flag&IEEE80211_SE_FLAG_INTERSECT_DONE)){
            /*first time intersect*/
            if (ni_mesh->ni_ext_flags&IEEE80211_LOCAL_MESH_PEER) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MESH,
                "%s: [%s] first time mesh peer cap intersection ...\n",
                __func__, ether_sprintf(ni_mesh->ni_macaddr));

                intersect_ret = ieee80211_beacon_intersect(ni_mesh,
                                                           (uint8_t *)&wh[1],
                                                           ie_size, wh);
                if(intersect_ret != 0) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MESH,
                    "%s: [%s] first intersection failed..., err code %d\n",
                    __func__, ether_sprintf(ni_mesh->ni_macaddr), intersect_ret);
                } else {
                    ni_mesh->ni_mesh_flag  |= IEEE80211_SE_FLAG_INTERSECT_DONE;
                }
            }
        } else  {
            bcn_ie_chksum = cal_ie_checksum(&(scan_entry->ie_list));
            if (ni_mesh->ni_mesh_bcn_ie_chksum != bcn_ie_chksum) {
                ni_mesh->ni_mesh_bcn_ie_chksum = bcn_ie_chksum;
                 IEEE80211_DPRINTF(vap, IEEE80211_MSG_MESH,
                 "%s: [%s] mesh peer cap changed, do intersection...\n",
                 __func__, ether_sprintf(ni_mesh->ni_macaddr));
                intersect_ret = ieee80211_beacon_intersect(ni_mesh,
                                                           (uint8_t *)&wh[1],
                                                           ie_size, wh);
                if(intersect_ret != 0) {
                     IEEE80211_DPRINTF(vap, IEEE80211_MSG_MESH,
                     "%s: [%s] first intersection failed..., err code %d\n",
                     __func__, ether_sprintf(ni_mesh->ni_macaddr), intersect_ret);
                } else {
                     ni_mesh->ni_mesh_flag  |= IEEE80211_SE_FLAG_INTERSECT_DONE;
                }
            }
        }
    }
#endif /*MESH_PEER_DYNAMIC_UPDATE*/
    /* free reference */
    ieee80211_free_node(ni_mesh, WLAN_MGMT_HANDLER_ID);
}
#endif /*MESH_MODE_SUPPORT*/


ieee80211_scan_entry_t
ieee80211_update_beacon(struct ieee80211_node      *ni,
                        wbuf_t                     wbuf,
                        struct ieee80211_frame     *wh,
                        int                        subtype,
                        struct ieee80211_rx_status *rs)
{
    ieee80211_scan_entry_t    scan_entry = NULL;
    struct ieee80211vap       *vap = ni->ni_vap;
    struct mgmt_rx_event_params rx_param;
    struct wlan_objmgr_pdev *pdev = NULL;
    qdf_list_t *bcn_list = NULL;
    qdf_list_node_t *se_list = NULL;
    qdf_list_node_t *peek_list = NULL;
    struct scan_cache_node *se_node = NULL;
    QDF_STATUS status = QDF_STATUS_E_FAILURE;
    u_int8_t *ssid;

    rx_param.channel = rs->rs_channel;
    rx_param.chan_freq = rs->rs_freq;
    rx_param.rssi = rs->rs_rssi;
    rx_param.snr = rs->rs_snr;
    rx_param.tsf_delta = 0;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev) {
        qdf_print("pdev is null");
        return NULL;
    }

    bcn_list = util_scan_unpack_beacon_frame(pdev, (uint8_t *)wh, wbuf_get_pktlen(wbuf),
            subtype, &rx_param);

    if (!bcn_list)
        return NULL;

    if ( qdf_list_size(bcn_list) > 1) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Found MBSSID beacon with %d beacons.",
               __func__, qdf_list_size(bcn_list));
    }


    status = qdf_list_peek_front(bcn_list, &se_list);
    while ( QDF_IS_STATUS_SUCCESS(status) ) {
        status = qdf_list_remove_front(bcn_list, &se_list);

        if (QDF_IS_STATUS_ERROR(qdf_list_peek_front(bcn_list, &peek_list)) || !peek_list) {
            break;
        }

        if ( QDF_IS_STATUS_SUCCESS(status) && se_list) {
            se_node = qdf_container_of(se_list, struct scan_cache_node, node);
            scan_entry = se_node->entry;

            if (scan_entry != NULL) {
            /* fill channel information */
                wlan_scan_cache_update_callback(pdev, scan_entry);

                IEEE80211_DELIVER_EVENT_STA_SCAN_ENTRY_UPDATE(vap, scan_entry, false);

                ssid = util_scan_entry_ssid(scan_entry)->ssid;
                vap->iv_esslen = util_scan_entry_ssid(scan_entry)->length;

                if (vap->iv_esslen  != 0) {
                    if(vap->iv_esslen < sizeof(vap->iv_essid)) {
                        OS_MEMCPY(vap->iv_essid, ssid, vap->iv_esslen);
                    }
                 }

#if MESH_MODE_SUPPORT
                if (vap->iv_mesh_vap_mode) {
                    ieee80211_beacon_mesh_process(ni->ni_ic, vap, scan_entry, wbuf, wh);
                }
#endif

                if (vap->iv_opmode == IEEE80211_M_STA) {
                    ieee80211_recv_beacon_sta(ni,wbuf,subtype,rs,scan_entry);
                 }
            }

            util_scan_free_cache_entry(se_node->entry);
            qdf_mem_free(se_node);
        } else {
           se_list = NULL;
           scan_entry = NULL;
           break;
        }
    }

    if (se_list) {
        se_node = qdf_container_of(se_list, struct scan_cache_node, node);
        scan_entry = se_node->entry;
        qdf_mem_free(se_node);
    }
    if (scan_entry != NULL) {
        /* fill channel information */
        wlan_scan_cache_update_callback(pdev, scan_entry);
#if MESH_MODE_SUPPORT
        if (vap->iv_mesh_vap_mode) {
            ieee80211_beacon_mesh_process(ni->ni_ic, vap, scan_entry, wbuf, wh);
        }
#endif
    }

    ucfg_scan_purge_results(bcn_list);
    return scan_entry;
}

static void
ieee80211_mgmt_update_bcn_snr(struct ieee80211_node *ni, u_int8_t snr)
{
#define MAX_BCN_SNR_AGE 0xff
    unsigned long age;

    if (snr & 0x80)
        return;

    age = jiffies - ni->ni_last_bcn_jiffies;
    age = jiffies_to_msecs(age);

    if (age > MAX_BCN_SNR_AGE)
        age = MAX_BCN_SNR_AGE;

    ni->ni_last_bcn_snr = (ni->ni_last_bcn_snr << 8) | snr;
    ni->ni_last_bcn_age = (ni->ni_last_bcn_age << 8) | age;
    ni->ni_last_bcn_jiffies = jiffies;
    ni->ni_last_bcn_cnt = ni->ni_last_bcn_cnt + 1;
}

static int
ieee80211_recv_beacon(struct ieee80211_node *ni, wbuf_t wbuf, int subtype, struct ieee80211_rx_status *rs)
{
    struct ieee80211vap                          *vap = ni->ni_vap;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    struct ieee80211_frame                       *wh;
    ieee80211_scan_entry_t                       scan_entry = NULL;
    u_int8_t                                     *ssid;
    u_int8_t nullbssid[QDF_MAC_ADDR_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00};
    struct ieee80211_mlme_priv                   *mlme_priv = vap->iv_mlme_priv;

    ieee80211_mgmt_update_bcn_snr(ni, rs->rs_snr);

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    if((IEEE80211_FC0_SUBTYPE_BEACON == subtype) && (unlikely(!IEEE80211_IS_BROADCAST(wh->i_addr1))))
        return EOK;
    /*If bssid is NULL drop the frame*/
    if(!OS_MEMCMP(wh->i_addr3,nullbssid,QDF_MAC_ADDR_SIZE))
    {
        return -EINVAL;
    }

    if ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) && (IEEE80211_M_STA == vap->iv_opmode)
            && (mlme_priv->im_request_type == MLME_REQ_JOIN_INFRA)) {

        if (( ni == vap->iv_bss ) && ( 0 == ni->ni_associd )) {
            if ((!IEEE80211_ADDR_EQ(wh->i_addr3, ieee80211_node_get_bssid(ni))) &&
                (!IEEE80211_ADDR_EQ(wh->i_addr3, vdev_mlme->mgmt.mbss_11ax.trans_bssid))) {
                IEEE80211_DPRINTF(vap,IEEE80211_MSG_MLME,
                    "%s Unmatch Proberesp during STA join,skip scan entry update addr3:%02X:%02X:%02X:%02X:%02X:%02X\n",__func__,
                    wh->i_addr3[0],wh->i_addr3[1],wh->i_addr3[2],wh->i_addr3[3],wh->i_addr3[4],wh->i_addr3[5]);
                return EOK;
            } else {
                IEEE80211_DPRINTF(vap,IEEE80211_MSG_MLME,
                    "%s Unmatch Proberesp during STA join,allow for MBSSID non-TX VAP addr3:%02X:%02X:%02X:%02X:%02X:%02X\n",__func__,
                    wh->i_addr3[0],wh->i_addr3[1],wh->i_addr3[2],wh->i_addr3[3],wh->i_addr3[4],wh->i_addr3[5]);
            }
        }
    }

    scan_entry = ieee80211_update_beacon(ni, wbuf, wh, subtype, rs);

    if (!scan_entry) {
        return EOK;
    }

    /* IEEE80211_DELIVER_EVENT_STA_SCAN_ENTRY_UPDATE is just a place holder
     * as wlan_sta_scan_entry_update is assigned as NULL.
     * In case this function gets defined, third argument to macro
     * IEEE80211_DELIVER_EVENT_STA_SCAN_ENTRY_UPDATE must be calculated properly
     */
    IEEE80211_DELIVER_EVENT_STA_SCAN_ENTRY_UPDATE(vap, scan_entry, false);

    ssid = util_scan_entry_ssid(scan_entry)->ssid;
    vap->iv_esslen = util_scan_entry_ssid(scan_entry)->length;

    if (vap->iv_esslen  != 0) {
        if(vap->iv_esslen < sizeof(vap->iv_essid)) {
            OS_MEMCPY(vap->iv_essid, ssid, vap->iv_esslen);
        }
    }
    /*
     * The following code MUST be SSID independant.
     */
    switch (vap->iv_opmode) {
        case IEEE80211_M_STA:
            ieee80211_recv_beacon_sta(ni,wbuf,subtype,rs,scan_entry);
            break;

        case IEEE80211_M_HOSTAP:
            ieee80211_recv_beacon_ap(ni,wbuf,subtype,rs,scan_entry);
            break;

        default:
            break;
    }

    util_scan_free_cache_entry(scan_entry);
    return EOK;
}

struct delete_node_if_ra_vap_found_arg {
    uint8_t *ra;
    struct ieee80211_node *ni;
    struct ieee80211vap *ra_vap;
    struct ieee80211com *recv_ic;
};
/*
 * Find VAP based on RA(addr1).
 * This is required to handle case where node is found on TA search but RA is not
 * matching with the node vap's mac address. This means, AUTH is recieved for a
 * different VAP.
 */
static void ieee80211_auth_find_node_on_ra_vap(struct wlan_objmgr_psoc *psoc,
        void *obj, void *args)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)obj;
    struct delete_node_if_ra_vap_found_arg *vap_arg = (struct delete_node_if_ra_vap_found_arg *)args;
    struct ieee80211vap *tmpvap, *ni_vap;

    if (vap_arg->ra_vap)
        return;

    tmpvap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!tmpvap)
        return;

    if(IEEE80211_ADDR_EQ(vap_arg->ra, tmpvap->iv_myaddr) &&
            (tmpvap->iv_opmode == IEEE80211_M_HOSTAP) &&
            (tmpvap->iv_ic == vap_arg->recv_ic)) {
        ni_vap = vap_arg->ni->ni_vap;
        if (vap_arg->ni != ni_vap->iv_bss) {
            if (wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SB_ID) ==
                                             QDF_STATUS_SUCCESS) {
                 vap_arg->ra_vap = tmpvap;
            }
        }
    }
}

static int
ieee80211_recv_auth(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                    struct ieee80211_rx_status *rs)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t algo, seq, status;
    u_int8_t *challenge = NULL, challenge_len = 0;
    int deref_reqd = 0;
    int ret_val = EOK;
    struct ieee80211com  *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (qdf_atomic_read(&(scn->auth_cnt)) > scn->max_auth)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                "Err: auth_cnt %d bigger than max_auth %d\n",
                (unsigned int)qdf_atomic_read(&(scn->auth_cnt)), scn->max_auth);
        return -EINVAL;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    /*
     * can only happen for HOST AP mode .
     */
    if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
        u_int8_t broadcast_addr[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        struct ieee80211com       *ic = ni->ni_ic;
        struct wlan_objmgr_pdev *pdev;
        struct wlan_objmgr_psoc *psoc;
        struct wlan_lmac_if_crypto_rx_ops *crypto_rx_ops;

        pdev = ic->ic_pdev_obj;
        if(pdev == NULL) {
            qdf_print("%s[%d]pdev is NULL", __func__, __LINE__);
            return -1;
        }
        psoc = wlan_pdev_get_psoc(pdev);
        if(psoc == NULL) {
            qdf_print("%s[%d]psoc is NULL", __func__, __LINE__);
            return -1;
        }

        crypto_rx_ops = wlan_crypto_get_crypto_rx_ops(psoc);
        if(crypto_rx_ops && WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)) {
            WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)(vap->vdev_obj, wbuf, broadcast_addr, 16);
            wh = (struct ieee80211_frame *) wbuf_header(wbuf);
        }
    }

    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP && ni == vap->iv_bss)
            && IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr))
    {
        struct ieee80211_node *temp_node=NULL;
        struct ieee80211com       *ic = ni->ni_ic;
        struct wlan_objmgr_peer *peer;

        peer = ieee80211_lookup_peer_by_mac(ic, wh->i_addr2);
        if(peer != NULL) {
            temp_node = wlan_peer_get_mlme_ext_obj(peer);
            if (temp_node != NULL && ni != temp_node) {
                /* Node is present on another VAP and possibly on different radio.
                 * Use this ni and vap so that subsequent logic will handle this
                 * scenario as expected
                 */

                IEEE80211_NOTE(vap, IEEE80211_MSG_MLME, ni,
                        "%s", "Found node on different VAP\n");

                if (ieee80211_is_pmf_enabled(vap,temp_node)) {
                    IEEE80211_NOTE(vap, IEEE80211_MSG_MLME, ni,
                        "%s", "Ignore auth in PMF case when found node on different VAP\n");
                    wlan_objmgr_peer_release_ref(peer, WLAN_MGMT_HANDLER_ID);
                    return -1;
                }

                ni = temp_node;
                vap = ni->ni_vap;

                deref_reqd = 1;
            } else if(ni == temp_node) {
                /* free extra ref taken during find node*/
                ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);
            } else if(temp_node == NULL) {
                wlan_objmgr_peer_release_ref(peer, WLAN_MGMT_HANDLER_ID);
            }
        }
    }
    /*
     * XXX bug fix 89056: Station Entry exists in the node table,
     * But the node is associated with the other vap, so we are
     * deleting that node and creating the new node
     *
     */
    if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {

        struct delete_node_if_ra_vap_found_arg vap_arg;
        struct ieee80211com *ic = ni->ni_ic;
        struct wlan_objmgr_pdev *pdev;
        struct wlan_objmgr_psoc *psoc;

        pdev = ic->ic_pdev_obj;
        if(pdev == NULL) {
            qdf_print("%s[%d]pdev is NULL", __func__, __LINE__);
            return -1;
        }
        psoc = wlan_pdev_get_psoc(pdev);
        if(psoc == NULL) {
            qdf_print("%s[%d]psoc is NULL", __func__, __LINE__);
            return -1;
        }

        vap_arg.ra = wh->i_addr1;
        vap_arg.ni = ni;
        vap_arg.ra_vap = NULL;
        vap_arg.recv_ic = rs->rs_ic;
        /* Search on soc to include vaps from other radio also */
        wlan_objmgr_iterate_obj_list(psoc, WLAN_VDEV_OP, ieee80211_auth_find_node_on_ra_vap,
                &vap_arg, false, WLAN_MLME_NB_ID);

        /* If node found in another VAP, it will be returned in vap_arg.ra_vap.
         * Check and use that for further processing
         */
        if (vap_arg.ra_vap) {
            uint16_t associd = 0;
            struct wlan_objmgr_vdev *ra_vdev;


            ra_vdev = vap_arg.ra_vap->vdev_obj;


            IEEE80211_NOTE(vap, IEEE80211_MSG_MLME, vap_arg.ni,
                    "%s", "Removing the node from the station node list\n");
            if (!ieee80211_try_ref_node(vap_arg.ni, WLAN_MGMT_HANDLER_ID)) {
                wlan_objmgr_vdev_release_ref(ra_vdev, WLAN_MLME_SB_ID);
                ret_val = -EINVAL;
                IEEE80211_DPRINTF(vap_arg.ra_vap, IEEE80211_MSG_AUTH,
                    "Err: vap%d failed to get ref\n",vap_arg.ra_vap->iv_unit);
                goto exit;
            }
            associd = vap_arg.ni->ni_associd;
            if(IEEE80211_NODE_LEAVE(vap_arg.ni)) {
                /* Call MLME indication handler if node is in associated state */
                IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(vap,
                        vap_arg.ni->ni_macaddr, associd,
                        IEEE80211_REASON_ASSOC_LEAVE);
            }
            ieee80211_free_node(vap_arg.ni, WLAN_MGMT_HANDLER_ID);

            if(deref_reqd) {
                   ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);
                   deref_reqd = 0;
            }

            if(vap_arg.ra_vap->iv_vap_is_down) {
                ret_val = -EINVAL;
                wlan_objmgr_vdev_release_ref(ra_vdev, WLAN_MLME_SB_ID);
                goto exit;
            }

            /* Referencing the BSS node */
            ni = ieee80211_try_ref_bss_node(vap_arg.ra_vap, WLAN_MGMT_HANDLER_ID);

            /* Note that ieee80211_ref_bss_node must have a */
            /* corresponding ieee80211_free_bss_node        */

            if(ni != NULL) {
                deref_reqd = 1;
                vap = ni->ni_vap;
            } else {
                ret_val = -EINVAL;
                wlan_objmgr_vdev_release_ref(ra_vdev, WLAN_MLME_SB_ID);
                goto exit;
            }
            wlan_objmgr_vdev_release_ref(ra_vdev, WLAN_MLME_SB_ID);
        }
    }


    /*
     * XXX: when we're scanning, we may receive auth frames
     * of other stations in the same BSS.
     */
    if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr) ||
        !IEEE80211_ADDR_EQ(wh->i_addr3, (ni)->ni_bssid)) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
        wh, ieee80211_mgt_subtype_name[subtype >>
        IEEE80211_FC0_SUBTYPE_SHIFT],
        "%s", "frame not for me");
        ret_val = -EINVAL;
        goto exit;
    }

    /*
     * auth frame format
     *  [2] algorithm
     *  [2] sequence
     *  [2] status
     *  [tlv*] challenge
     */
    if ((efrm - frm) < 6) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
        wh, ieee80211_mgt_subtype_name[subtype >>
        IEEE80211_FC0_SUBTYPE_SHIFT],
        "%s", "ie too short\n");
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        ret_val = -EINVAL;
        goto exit;
    }

    algo = le16toh(*(u_int16_t *)frm); frm += 2;
    seq = le16toh(*(u_int16_t *)frm); frm += 2;
    status = le16toh(*(u_int16_t *)frm); frm += 2;

    /* Validate challenge TLV if any */
    if (algo == IEEE80211_AUTH_ALG_SHARED) {
        if (seq > IEEE80211_AUTH_SHARED_PASS) {
            IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
                                  ni->ni_macaddr, "invalid seq",
                                  "seq num: %d not supported for algo %s", seq, IEEE80211_AUTH_ALG_SHARED);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
            ret_val = -EINVAL;
            goto exit;
        }
        if (frm + 1 < efrm) {
            if ((frm[1] + 2) > (efrm - frm)) {
                IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
                                      ni->ni_macaddr, "shared key auth",
                                      "ie %d/%d too long",
                                      frm[0], (frm[1] + 2) - (efrm - frm));
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
                ret_val = -EINVAL;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                    "Err:VAP%d is down, dropping auth\n",vap->iv_unit);
                goto exit;
            }
            if (frm[0] == IEEE80211_ELEMID_CHALLENGE) {
                challenge = frm + 2;
                challenge_len = frm[1];
            }
        }

        if (seq == IEEE80211_AUTH_SHARED_CHALLENGE ||
            seq == IEEE80211_AUTH_SHARED_RESPONSE) {
            if ((challenge == NULL || challenge_len == 0) && (status == 0)) {
                IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
                                      ni->ni_macaddr, "shared key auth",
                                      "%s", "no challenge");
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
                ret_val = -EINVAL;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                    "Err:bss node ref failed for ra_vap\n");
                goto exit;
            }
        }
    }

    if ((vap->iv_ic->ic_flags & IEEE80211_F_CHANSWITCH) && vap->iv_csa_interop_auth) {
        ret_val = -EBUSY;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
            "Err:VAP %d in CSA\n", vap->iv_unit);
        ieee80211_send_auth(ni, seq + 1, IEEE80211_STATUS_REJECT_TEMP, NULL, 0, NULL);
        goto exit;
    }

    ret_val = ieee80211_mlme_recv_auth(ni, algo, seq, status, challenge, challenge_len,wbuf,rs);

    if(!ret_val && (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
         qdf_atomic_inc(&(scn->auth_cnt));
    }

exit:
    /* Note that ieee80211_ref_bss_node must have a */
    /* corresponding ieee80211_free_bss_node        */

    if (deref_reqd)
        ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);
    return ret_val;
}

static int
ieee80211_recv_deauth(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t reason;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
        IEEE80211_VERIFY_ADDR(ni);

        /*
         * deauth frame format
         *  [2] reason
         */
        IEEE80211_VERIFY_LENGTH(efrm - frm, 2);
    }
    reason = le16toh(*(u_int16_t *)frm);

     if ((wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
          ieee80211_node_is_authorized(ni)) &&
          !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) ||
            !ieee80211_is_mmie_valid(vap, ni, (u_int8_t *)wh, efrm)) {
            /*
             * Check if MFP is enabled for connection.
             */
            IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                              wh, ieee80211_mgt_subtype_name[
                                  subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                              "%s", "deauth frame is not encrypted");
            if ((reason != IEEE80211_REASON_NOT_AUTHED) &&
                (reason != IEEE80211_REASON_NOT_ASSOCED)) {
                ieee80211_send_qosnulldata(ni, WME_AC_BE, false);
            }
            IEEE80211_DELIVER_EVENT_MLME_UNPROTECTED_DEAUTH_INDICATION(ni->ni_vap,
                                   (wh->i_addr2), ni->ni_associd, reason, wbuf);
            return -EINVAL;
        }
    }

    IEEE80211_NOTE(vap, IEEE80211_MSG_AUTH, ni,
                   "Received Deauth with reason %d", reason);

    ieee80211_mlme_recv_deauth(ni, reason);

    return EOK;
}

static int
ieee80211_recv_disassoc(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t reason;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
        IEEE80211_VERIFY_ADDR(ni);

        /*
         * disassoc frame format
         *  [2] reason
         */
        IEEE80211_VERIFY_LENGTH(efrm - frm, 2);
    }
    reason = le16toh(*(u_int16_t *)frm);
    if ((wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
         ieee80211_node_is_authorized(ni)) &&
         !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) ||
            !ieee80211_is_mmie_valid(vap, ni, (u_int8_t *)wh, efrm)) {
            /*
             * Check if MFP is enabled for connection.
             */
            IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                              wh, ieee80211_mgt_subtype_name[
                                  subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                              "%s", "disassoc frame is not encrypted");
            return -EINVAL;
        }
    }

    IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                   "Received Disassoc with reason %d", reason);

    ieee80211_mlme_recv_disassoc(ni, reason);

    return EOK;
}

static int
ieee80211_recv_action(struct ieee80211_node *ni, wbuf_t wbuf, int subtype, struct ieee80211_rx_status *rs, bool* action_taken)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    struct ieee80211_action *ia;
    bool fgActionForMe = FALSE, fgBCast = FALSE, fgMcast = FALSE;
#if WLAN_SUPPORT_SPLITMAC
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
#endif

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    /*
     * 802.11 frame header format for HE-TB PPDU:
     *
     *    2-bytes   2-bytes    6-bytes   6-bytes   6-bytes   2-bytes    4-bytes
     *  -------------------------------------------------------------------------
     *  |  Frame  |          |         |         |         |          |         |
     *  | Control | Duration |  Addr1  |  Addr2  |  Addr3  | Sequence |   HT    |
     *  |  Field  |          |   RA    |   TA    |  BSSID  |  Number  | Control |
     *  -------------------------------------------------------------------------
     *  <---------------struct ieee80211_frame(wh[0])----------------->
     *
     * Take into account the HT control field to decode the frame contents,
     * in case the Action frame from the peer is transmitted using HE-TB PDDU.
     */
    frm = IEEE80211_IS_HTC_PRESENT(wh) ?
            ((u_int8_t *)&wh[1] + IEEE80211_HT_CTRL_LEN) : (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
    ia = (struct ieee80211_action *) frm;

    /* Do not filter public action frame when Addr3 matches BSSID or WildCard */
    if (ia->ia_category == IEEE80211_ACTION_CAT_PUBLIC &&
       (IEEE80211_ADDR_EQ(wh->i_addr3, ni->ni_bssid) ||
       IEEE80211_IS_BROADCAST(wh->i_addr3)) &&
       !((ni->ni_flags & IEEE80211_NODE_NAWDS))) {
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
            "%s: action mgt frame (cat %d, act %d addr3 %s)\n",
            __func__, ia->ia_category, ia->ia_action, ether_sprintf(wh->i_addr3));
    }
    else if (!(IEEE80211_ADDR_EQ(wh->i_addr3, ni->ni_bssid)) &&
#if MESH_MODE_SUPPORT
                !vap->iv_mesh_vap_mode &&
#endif
                !((ni->ni_flags & IEEE80211_NODE_NAWDS))) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              IEEE80211_FC0_SUBTYPE_ACTION >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "action frame not in same BSS");
       return -EINVAL;
    }

    if ((wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) &&
        (vap->iv_opmode != IEEE80211_M_STA) &&
        (vap->iv_mgmt_offchan_current_req.request_type != IEEE80211_OFFCHAN_RX)) {
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

    if (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
        fgActionForMe = TRUE;
    }
    else if(IEEE80211_ADDR_EQ(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic)))
    {
        fgBCast = TRUE;
    }
    else if(IEEE80211_IS_MULTICAST(wh->i_addr1)) {
        fgMcast = TRUE;
    }

    IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action));
#ifdef QCA_SUPPORT_CP_STATS
    vdev_cp_stats_rx_action_inc(vap->vdev_obj, 1);
#endif
    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: action mgt frame (cat %d, act %d)\n",__func__, ia->ia_category, ia->ia_action);
    if (ia->ia_category == IEEE80211_ACTION_CAT_WNM &&
            (ia->ia_action == IEEE80211_ACTION_FMS_RESP)) {
        /* FMS unsolicited responses are sent to multicast group addr */
        if (!(fgMcast || fgActionForMe)) {
            return -EINVAL;
        }
    }
    else if ((ia->ia_category == IEEE80211_ACTION_CAT_SPECTRUM &&
         (ia->ia_action == IEEE80211_ACTION_CHAN_SWITCH ||
          ia->ia_action == IEEE80211_ACTION_MEAS_REPORT)) ||
         (ia->ia_category == IEEE80211_ACTION_CAT_VHT) ||
         (ia->ia_category == IEEE80211_ACTION_CAT_HT) ||
         (ia->ia_category == IEEE80211_ACTION_CAT_PUBLIC)
       ) {
        if (!(fgBCast || fgActionForMe)) {
            /* CSA action frame and VHT OP mode notify could be broadcast */
            return -EINVAL;
        }
        if ((ia->ia_category == IEEE80211_ACTION_CAT_VHT) && !IEEE80211_IS_CHAN_VHT(ic->ic_curchan) &&
                   (!(IEEE80211_IS_CHAN_11NG(ic->ic_curchan) && ieee80211vap_vhtallowed(vap)))) {
            /*cat vht action frames is not supposed to be received if the vhtcap is not set*/
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif /*QCA_SUPPORT_CP_STATS*/
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: action frames are dropped (cat %u, act %u IsChanVht :%u)\n",__func__, ia->ia_category, ia->ia_action, IEEE80211_IS_CHAN_VHT(ic->ic_curchan));
            return -EINVAL;
        }
    }
    else{

        if (!fgActionForMe) {
            return -EINVAL;
        }
    }

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (vap->iv_bss == ni)) {
        switch (ia->ia_category) {
            case IEEE80211_ACTION_CAT_PUBLIC:
                break;
            default:
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Dropping action frame with ia_category %d recevied in self peer\n",ia->ia_category);
                return -EINVAL;
        }
    }

    switch (ia->ia_category) {
    case IEEE80211_ACTION_CAT_SPECTRUM:
        switch (ia->ia_action) {
            case IEEE80211_ACTION_CHAN_SWITCH:
                if (ieee80211_num_apvap_running(ic) && !ieee80211_ic_doth_is_set(ic))
                    return -EINVAL;

                if (ieee80211_process_csa_ecsa_ie(ni,  ia, (efrm -frm)) != EOK) {
                    /*
                     * If failed to switch the channel, mark the AP as radar detected and disconnect from the AP.
                     */
                    ieee80211_mlme_recv_csa(ni, IEEE80211_RADAR_DETECT_DEFAULT_DELAY,true);
                }
#if WLAN_SUPPORT_SPLITMAC
                if (splitmac_is_enabled(vdev)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "Forward chan switch action mgt "\
                        "frame with category 0x%2X type 0x%2X\n", ia->ia_category, ia->ia_action );
                    *action_taken = FALSE;
                }
#endif
                break;

            default:
                *action_taken = FALSE;
                break;
        }
 	break;
    case IEEE80211_ACTION_CAT_RM:
#if QCA_LTEU_SUPPORT
        /* Check if radio is in LTEu mode */
        if (ic->ic_nl_handle) {
            ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm));
            *action_taken = FALSE; // libaplink : action_taken set to false so that frame can be forwarded to user space.
        } else {
            if (ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
                *action_taken = FALSE;
        }
#else
        if (ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
            *action_taken = FALSE;
#endif
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_ACTION_CAT_WNM:
        ieee80211_wnm_forward_action_app(vap, ni, wbuf, subtype, rs, ia);

        if (ieee80211_wnm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
            *action_taken = FALSE;
        break;
#endif /* UMAC_SUPPORT_WNM */
    case IEEE80211_ACTION_CAT_QOS:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: QoS action mgt frames not supported", __func__);
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        *action_taken = FALSE;
        break;

    case IEEE80211_ACTION_CAT_WMM_QOS:
        /* WiFi WMM QoS TSPEC action management frames */
        IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_wmm_qos));
        if (ic->ic_qos_acfrm_config & QOS_ACTION_FRAME_FRWD_TO_STACK) {
            *action_taken = FALSE;
        }
        if ((ic->ic_qos_acfrm_config & QOS_ACTION_FRAME_MASK) == QOS_ACTION_FRAME_MASK) {
            break;
        }
        switch (ia->ia_action) {
        case IEEE80211_WMM_QOS_ACTION_SETUP_REQ:
            /* ADDTS received by AP */
            ieee80211_recv_addts_req(ni, &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie,
                ((struct ieee80211_action_wmm_qos *)ia)->ts_dialogtoken);
            break;

        case IEEE80211_WMM_QOS_ACTION_SETUP_RESP: {
            /* ADDTS response from AP */
            struct ieee80211_wme_tspec *tspecie;
            if ((vap->iv_opmode == IEEE80211_M_STA) && !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
                /*
                 * Check if MFP is enabled for connection.
                 */
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: QoS action mgt frame is not encrypted", __func__);
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
                break;
            }

            if (((struct ieee80211_action_wmm_qos *)ia)->ts_statuscode != 0) {
                /* tspec was not accepted */
                /* Indicate to CCX and break. */
                /* AP will send us a disassoc anyway if we try assoc */
                wlan_set_tspecActive(vap, 0);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                    vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 0);
                }
                /* Trigger Roam for unspecified QOS-related reason. */
                //Sta11DeauthIndication(vap->iv_mlme_arg, ni->ni_macaddr, IEEE80211_REASON_QOS);
                //StaCcxTriggerRoam(vap->iv_mlme_arg, IEEE80211_REASON_QOS);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_trigger_roam) {
                    vap->iv_ccx_evtable->wlan_ccx_trigger_roam(vap->iv_ccx_arg, IEEE80211_REASON_QOS);
                }
                break;
            }
            tspecie = &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie;
            ieee80211_parse_tspecparams(vap, (u_int8_t *) tspecie);
            wlan_set_tspecActive(vap, 1);
            if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 1);
            }
            break;
        }

        case IEEE80211_WMM_QOS_ACTION_TEARDOWN: {
            ieee80211_recv_delts_req(ni, &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie);
            break;
        }

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid WME action mgt frame", __func__);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            *action_taken = FALSE;
        }
        break;
#if WLAN_SUPPORT_MSCS
    case IEEE80211_ACTION_CAT_ROBUST_AV_STREAM:
        switch(ia->ia_action) {
          case IEEE80211_ACTION_MSCS_REQUEST:
            /* Add MSCS Request recv function */
            if (vap->iv_mscs) {
                ieee80211_recv_mscs_req(ni,(struct ieee80211_action_mscs*)frm);
            } else {
                qdf_info("MSCS Procedure is not supported");
            }
            break;

          default:
            break;
        }
        break;
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_ACTION_CAT_DLS:
        switch (ia->ia_action) {
        case IEEE80211_ACTION_DLS_REQUEST:
            if (IEEE80211_VAP_IS_NOBRIDGE_ENABLED(vap)) {
                struct ieee80211_dls_response *resp;
                struct ieee80211_dls_request *req = (struct ieee80211_dls_request *)ia;
                char dhost[32];
                wbuf_t wbuf;
                u_int8_t *frm1 = NULL;
                struct ieee80211_frame *wh1;

                wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm1, 1);
                if (wbuf == NULL)
                    return -ENOMEM;

                wh1 = (struct ieee80211_frame *)wbuf_header(wbuf);
                memcpy(wh1->i_addr1, wh->i_addr2, QDF_MAC_ADDR_SIZE);

                /* Send DLS response w/ status code: not allowed by policy */
                resp = (struct ieee80211_dls_response *)frm1;
                resp->hdr.ia_category   = IEEE80211_ACTION_CAT_DLS;
                resp->hdr.ia_action     = IEEE80211_ACTION_DLS_RESPONSE;
                resp->statuscode        = htole16(IEEE80211_STATUS_DLS_NOT_ALLOWED);
                memcpy(resp->dst_addr, req->src_addr, QDF_MAC_ADDR_SIZE);
                memcpy(resp->src_addr, req->dst_addr, QDF_MAC_ADDR_SIZE);
                wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame) +
                                      sizeof(struct ieee80211_dls_response));
                if (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
                    ieee80211_node_is_authorized(ni)) {
                    /* MFP is enabled, so we need to set Privacy bit */
                    wh1->i_fc[1] |= IEEE80211_FC1_WEP;
                }

                memcpy(dhost, ether_sprintf(req->dst_addr), 32);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_L2TIF, "HS20 L2TIF: "
                        "DLS request %s -> %s is not allowed by local policy\n",
                        ether_sprintf(req->src_addr), dhost);

                if (ieee80211_send_mgmt(ni->ni_vap, ni, wbuf, false) != EOK)
                    *action_taken = FALSE;
            }
            break;

        case IEEE80211_ACTION_DLS_RESPONSE:
        case IEEE80211_ACTION_DLS_TEARDOWN:
        default:
            *action_taken = FALSE;
            break;
        }
        break;
#endif

    case IEEE80211_ACTION_CAT_BA: {
        struct ieee80211_action_ba_addbarequest *addbarequest;
        struct ieee80211_action_ba_addbaresponse *addbaresponse;
        struct ieee80211_ba_addbaext *addbaextension;
        struct ieee80211_action_ba_delba *delba;
        struct ieee80211_ba_seqctrl basequencectrl;
        struct ieee80211_ba_parameterset baparamset;
        struct ieee80211_delba_parameterset delbaparamset;
        struct ieee80211_action_mgt_args actionargs;
        u_int16_t statuscode;
        u_int16_t batimeout;
        u_int16_t reasoncode;
        u_int8_t he_frag = 0;
        int result = QDF_STATUS_SUCCESS;
        bool addbaext_present = 0;

        switch (ia->ia_action) {
        case IEEE80211_ACTION_BA_ADDBA_REQUEST:
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_addbarequest));
            addbarequest = (struct ieee80211_action_ba_addbarequest *) frm;

            /* "struct ieee80211_action_ba_addbarequest" is annotated __packed,
               if accessing fields, like rq_baparamset or rq_basequencectrl,
               by using u_int16_t* directly, it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&baparamset, &addbarequest->rq_baparamset, sizeof(baparamset));
            *(u_int16_t *)&baparamset = le16toh(*(u_int16_t*)&baparamset);
            batimeout = le16toh(addbarequest->rq_batimeout);
            OS_MEMCPY(&basequencectrl, &addbarequest->rq_basequencectrl, sizeof(basequencectrl));
            *(u_int16_t *)&basequencectrl = le16toh(*(u_int16_t*)&basequencectrl);

            frm += sizeof(struct ieee80211_action_ba_addbarequest);
            addbaextension = (struct ieee80211_ba_addbaext *)frm;
            if(IEEE80211_IS_ADDBA_EXT_PRESENT(efrm - frm)) {
                addbaext_present = 1;
                he_frag = addbaextension->he_fragmentation;
            }

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA request action mgt frame. TID %d, buffer size %d",
                           __func__, baparamset.tid, baparamset.buffersize);

            /*
             * NB: The user defined ADDBA response status code is overloaded for
             * non HT capable node and WDS node
             */
            if (!IEEE80211_NODE_ISAMPDU(ni)) {
                /* The node is not HT capable - set the ADDBA status to refused */
                ic->ic_addba_setresponse(ni, baparamset.tid, IEEE80211_STATUS_REFUSED);
            }

            /* If buffersize is 0, use 64 as default buffer size */
            if (baparamset.buffersize == 0)
                baparamset.buffersize = DEFAULT_SELF_BA_SIZE;

            /* Cap the BA Buffer Size to current BA Buffer size in self */
            if (baparamset.buffersize >
                    IEEE80211_ABSOLUTE_BA_BUFFERSIZE(
                     wlan_get_current_phymode(vap), vap->iv_ba_buffer_size)) {
                baparamset.buffersize =
                    IEEE80211_ABSOLUTE_BA_BUFFERSIZE(
                     wlan_get_current_phymode(vap), vap->iv_ba_buffer_size);
            }
            /* Process ADDBA request and save response in per TID data structure */
            if (!(ic->ic_addba_mode == ADDBA_MODE_MANUAL &&
                vap->iv_refuse_all_addbas) && ic->ic_addba_requestprocess) {
                result = ic->ic_addba_requestprocess(ni,
                         addbarequest->rq_dialogtoken, &baparamset,
                         batimeout, basequencectrl);
            }

            if (result == QDF_STATUS_SUCCESS) {
                /* Send ADDBA response */
                actionargs.category     = IEEE80211_ACTION_CAT_BA;
                actionargs.action       = IEEE80211_ACTION_BA_ADDBA_RESPONSE;
                actionargs.arg1         = baparamset.tid;
                actionargs.arg2         = addbaext_present;
                actionargs.arg3         = he_frag;

                ieee80211_send_action(ni, &actionargs, NULL);
            }
            break;

        case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
            if (!IEEE80211_NODE_USE_HT(ni)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: ADDBA response frame ignored for non-HT association)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_addbaresponse));
            addbaresponse = (struct ieee80211_action_ba_addbaresponse *) frm;

            statuscode = le16toh(addbaresponse->rs_statuscode);
            /* "struct ieee80211_action_ba_addbaresponse" is annotated __packed,
               if accessing fields, like rs_baparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&baparamset, &addbaresponse->rs_baparamset, sizeof(baparamset));
            *(u_int16_t *)&baparamset = le16toh(*(u_int16_t*)&baparamset);
            batimeout = le16toh(addbaresponse->rs_batimeout);

            spin_lock(&ic->ic_addba_lock);
            if (ic->ic_addba_responseprocess)
                ic->ic_addba_responseprocess(ni, statuscode, &baparamset, batimeout);
            spin_unlock(&ic->ic_addba_lock);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA response action mgt frame. TID %d, buffer size %d",
                           __func__, baparamset.tid, baparamset.buffersize);
            break;

        case IEEE80211_ACTION_BA_DELBA:
            if (!IEEE80211_NODE_USE_HT(ni)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: DELBA frame ignored for non-HT association)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_delba));

            delba = (struct ieee80211_action_ba_delba *) frm;
            /* "struct ieee80211_action_ba_delba" is annotated __packed,
               if accessing fields, like dl_delbaparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&delbaparamset, &delba->dl_delbaparamset, sizeof(delbaparamset));
            *(u_int16_t *)&delbaparamset= le16toh(*(u_int16_t*)&delbaparamset);
            reasoncode = le16toh(delba->dl_reasoncode);

            spin_lock(&ic->ic_addba_lock);
            if (ic->ic_delba_process)
                ic->ic_delba_process(ni, &delbaparamset, reasoncode);
            spin_unlock(&ic->ic_addba_lock);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: DELBA action mgt frame. TID %d, initiator %d, reason code %d",
                           __func__, delbaparamset.tid, delbaparamset.initiator, reasoncode);
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid BA action mgt frame", __func__);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_PROT_DUAL: {
        struct son_act_frm_info info;

        switch (ia->ia_action) {
            case IEEE80211_ACTION_GAS_INITIAL_REQUEST:
                qdf_mem_zero(&info, sizeof(info));
                info.ia = ia;
                info.ald_info = 1;
                qdf_mem_copy(info.data.macaddr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
                son_update_mgmt_frame(vap->vdev_obj, NULL, subtype, wbuf_header(wbuf),
                                      wbuf_get_pktlen(wbuf), &info);
                *action_taken = FALSE;
                break;

            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: invalid public action mgt frame", __func__);
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
                *action_taken = FALSE;
                break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_PUBLIC: {
        struct son_act_frm_info info;
        switch (ia->ia_action) {
            case IEEE80211_ACTION_BSS_COEX_FRAME: {
                struct ieee80211_action_bss_coex_frame *iabsscoex;
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Received Coex Category, action %d\n",
                               __func__, ia->ia_action);

                /* Only process coex action frame if this VAP is in AP and the
                * associated node is in HE/HT mode.
                * 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules
                */
                if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
                    (ni->ni_flags & IEEE80211_NODE_HT || IEEE80211_NODE_USE_HE(ni))) {
                    /* Check frame length for mandatory fields only */
                    IEEE80211_VERIFY_LENGTH(efrm - frm, (sizeof(struct ieee80211_action_bss_coex_frame) -
                                                         sizeof(struct ieee80211_ie_intolerant_report)));
                    iabsscoex = (struct ieee80211_action_bss_coex_frame *) frm;
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                                   "%s: Element 0\n"
                                   "inf request = %d\t"
                                   "40 intolerant = %d\t"
                                   "20 width req = %d\t"
                                   "obss exempt req = %d\t"
                                   "obss exempt grant = %d\n", __func__,
                                   iabsscoex->coex.inf_request,
                                   iabsscoex->coex.ht40_intolerant,
                                   iabsscoex->coex.ht20_width_req,
                                   iabsscoex->coex.obss_exempt_req,
                                   iabsscoex->coex.obss_exempt_grant);

                    if ((((efrm - frm) >= sizeof(struct ieee80211_action_bss_coex_frame)) &&
                          bss_intol_channel_check(ni, &iabsscoex->chan_report)) ||
                         iabsscoex->coex.ht40_intolerant ||
                         iabsscoex->coex.ht20_width_req) {

                        /* If RSSI greater than/equal threshold then only do CW change */
                        if (rs->rs_snr >= ic->obss_rx_snr_threshold) {
                            ieee80211node_set_flag(ni, IEEE80211_NODE_REQ_20MHZ);
                        }
                    } else {
                        ieee80211node_clear_flag(ni, IEEE80211_NODE_REQ_20MHZ);
                    }

                    ieee80211_change_cw(ic);
                } else {
                    *action_taken = FALSE;
                }
                break;
            }

            case IEEE80211_ACTION_GAS_INITIAL_REQUEST:
                qdf_mem_zero(&info, sizeof(info));
                info.ia = ia;
                info.ald_info = 1;
                qdf_mem_copy(info.data.macaddr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
                son_update_mgmt_frame(vap->vdev_obj, NULL, subtype, wbuf_header(wbuf),
                                      wbuf_get_pktlen(wbuf), &info);
                *action_taken = FALSE;
                break;

            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: invalid public action mgt frame", __func__);
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
                *action_taken = FALSE;
                break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_HT: {
        struct ieee80211_action_ht_txchwidth *iachwidth;
        enum ieee80211_cwm_width  chwidth = IEEE80211_CWM_WIDTH20;
        struct ieee80211_action_ht_smpowersave *iasmpowersave;

        if (!IEEE80211_NODE_ISAMPDU(ni)) {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT action mgt frame ignored for non-HT association)", __func__);
            break;
        }
        switch (ia->ia_action) {
        case IEEE80211_ACTION_HT_TXCHWIDTH:
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ht_txchwidth));

            iachwidth = (struct ieee80211_action_ht_txchwidth *) frm;

            /*
             * iachwidth->at_chwidth == 0 - 20 MHz channel width
             * iachwidth->at_chwidth == 1 - Any channel width in the STA’s
             *                              Supported Channel Width Set subfield
             *
             */
            if (iachwidth->at_chwidth == IEEE80211_A_HT_TXCHWIDTH_2040) {
            /*
             * choose MAX supported channel width.
             *
             */
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    chwidth = IEEE80211_CWM_WIDTH20;
                } else {
                    /* Channel width needs to be set to 40MHz for both 40MHz and 80MHz mode */
                    if (ic->ic_cwm_get_width(ic) != IEEE80211_CWM_WIDTH20) {
                        chwidth = IEEE80211_CWM_WIDTH40;
                    }
                }
            } else {
                chwidth = IEEE80211_CWM_WIDTH20;
            }

            /* Check for channel width change */
            if (chwidth != ni->ni_chwidth) {
                u_int32_t  rxlinkspeed, txlinkspeed; /* bits/sec */

                 /* update node's recommended tx channel width */
                ni->ni_chwidth = chwidth;
                ic->ic_chwidth_change(ni);

                mlme_get_linkrate(ni, &rxlinkspeed, &txlinkspeed);
                IEEE80211_DELIVER_EVENT_LINK_SPEED(vap, rxlinkspeed, txlinkspeed);
            }

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT txchwidth action mgt frame. Width %d",
                           __func__, chwidth);
            break;

        case IEEE80211_ACTION_HT_SMPOWERSAVE:
            if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: HT SM pwrsave request ignored for non-AP)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ht_smpowersave));

            iasmpowersave = (struct ieee80211_action_ht_smpowersave *) frm;

            if (iasmpowersave->as_control & IEEE80211_A_HT_SMPOWERSAVE_ENABLED) {
                if (iasmpowersave->as_control & IEEE80211_A_HT_SMPOWERSAVE_MODE) {
                    if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                        IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC) {
                        /*
                         * Station just enabled dynamic SM power save therefore
                         * we should precede each packet we send to it with an RTS.
                         */
                        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Station just enabled dynamic SM pwr save", __func__);
                        ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                        ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC;
                        ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_DYN;
                    }
                } else {
                    if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                        IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) {
                        /*
                         * Station just enabled static SM power save therefore
                         * we can only send to it at single-stream rates.
                         */
#if WLAN_SUPPORT_GREEN_AP
                        if (!ic_is_sta_vap(ic) && ieee80211_vap_sm_gap_ps_is_set(vap)) {
                            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Station just enabled static SM pwr save, sending multistream del", __func__);
                            if(wlan_node_get_max_nss(ni) > 1)
                                wlan_green_ap_del_multistream_sta(ic->ic_pdev_obj);
                        }
#endif
                        ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                        ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC;
                        ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_STAT;
                    }
                }
            } else {
                if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                    IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED) {
                    /*
                     * Station just disabled SM Power Save therefore we can
                     * send to it at full SM/MIMO.
                     */
#if WLAN_SUPPORT_GREEN_AP
                    if (!ic_is_sta_vap(ic) && ieee80211_vap_sm_gap_ps_is_set(vap)) {
                        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: SM pwr save is disabled sending multistream add", __func__);
                        if(wlan_node_get_max_nss(ni) > 1)
                            wlan_green_ap_add_multistream_sta(ic->ic_pdev_obj);
                    }
#endif
                    ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                    ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED;
                    ni->ni_updaterates = IEEE80211_NODE_SM_EN;
                }
            }
            if (ni->ni_updaterates) {
                ni->ni_updaterates |= IEEE80211_NODE_RATECHG;
            }
            /* Update MIMO powersave flags and node rates */
            ieee80211_update_noderates(ni);

            break;
#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_ACTION_HT_NONCOMP_BF:
    case IEEE80211_ACTION_HT_COMP_BF:
#ifdef TXBF_DEBUG
        ic->ic_txbf_check_cvcache(ic, ni);
#endif
        /* report received , cancel timer */
        OS_CANCEL_TIMER(&ni->ni_report_timer);

        ni->ni_cvtstamp = rs->rs_rpttstamp;
        ic->ic_txbf_set_rpt_received(ic, ni);
        ic->ic_txbf_stats_rpt_inc(ic, ni);

        /* skip action header and mimo control field*/
        frm += sizeof(struct ieee80211_action_ht_txbf_rpt);

        /* EV 78384 CV/V report generated by osprey will be zero at some case,
        when it happens , it should get another c/cv report immediately to overwrite
        wrong one*/
        if ((frm[0] == 0) && (frm[1] ==0) && (frm[2]==0)){
            ni->ni_bf_update_cv = 1;    // request to update CV cache
        }
        break;
#endif
        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid HT action mgt frame", __func__);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            break;
        }
        *action_taken = FALSE; // set to false so that it is forwarded to hostapd
        break;
    }

    case IEEE80211_ACTION_CAT_VHT: {

        switch (ia->ia_action) {
            case IEEE80211_ACTION_VHT_OPMODE:
                {
                    struct ieee80211_action_vht_opmode *ia_opmode = (struct ieee80211_action_vht_opmode *)frm;

                    ieee80211_parse_opmode(ni, (u_int8_t *)&ia_opmode->at_op_mode, subtype);
                }
                break;
            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                        "%s: Unhandled OR invalid VHT action code - %d", __func__, ia->ia_action);
                *action_taken = FALSE; // set to false so that it is forwarded to hostapd
                break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_SA_QUERY: {
        struct ieee80211_action_sa_query *saQuery;
        saQuery = (struct ieee80211_action_sa_query *)frm;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "Received SA_Query action "\
            "frame with action 0x%2X id 0x%2X\n", saQuery->sa_header.ia_action, saQuery->sa_transId);

        /* Hostapd takes care of Req/Resp for SA_QUERY in AP mode */

        if ((vap->iv_opmode == IEEE80211_M_STA) &&
            (saQuery->sa_header.ia_action == IEEE80211_ACTION_SA_QUERY_REQUEST)) {
            struct ieee80211_action_mgt_args actionargs;
            actionargs.category     = IEEE80211_ACTION_CAT_SA_QUERY;
            actionargs.action       = IEEE80211_ACTION_SA_QUERY_RESPONSE;
            actionargs.arg1         = saQuery->sa_transId;
            actionargs.arg2         = 0;
            actionargs.arg3         = 0;

            ieee80211_send_action(ni, &actionargs, NULL);
        } else {
           * action_taken = FALSE;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_VENDOR: {
        struct ieee80211_action_vendor_specific *ven;
        bool is_rcsa_ie_recvd = false;
        bool is_nol_ie_recvd = false;

        ven = (struct ieee80211_action_vendor_specific*)frm;
        /* Check if the vendor_OUI is Atheros */
        if(ven->vendor_oui[0] == 0x00
           && ven->vendor_oui[1] == 0x03
           && ven->vendor_oui[2] == 0x7f) {
            struct ieee80211_ie_header  *info_element;
            struct vendor_add_to_nol_ie *nol_el = NULL;
            frm += sizeof(struct ieee80211_action_vendor_specific);
            info_element = (struct ieee80211_ie_header *)frm;
            switch(info_element->element_id) {

                case IEEE80211_ELEMID_CHANSWITCHANN:
                {
                    /* The STA has (probably) detected RADAR and
                     * wants the AP to move to a different channel.
                     */
                    if (!((efrm-frm) < sizeof(struct ieee80211_ath_channelswitch_ie))) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                            "%s: Received vendor-chanswitch action frame\n",__func__);
                        if (IEEE80211_IS_CSH_PROCESS_RCSA_ENABLED(ic)) {
                            is_rcsa_ie_recvd = true;
                            frm += sizeof(struct ieee80211_ath_channelswitch_ie);
                            if (!((efrm - frm) < sizeof(struct vendor_add_to_nol_ie))) {
                                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                                    "%s: Received vendor-addtoNOL action frame\n",__func__);
                                nol_el = (struct vendor_add_to_nol_ie *)frm;
                                is_nol_ie_recvd =
                                    ieee80211_process_nol_ie_bitmap(ni, nol_el);
                            }
                        }
                    }
                }
                break;

                case IEEE80211_ELEMID_VENDOR:
                {
                        /* Add to NOL IE recieved, parse and add
                         * sub channels to NOL
                         */

                    if (IEEE80211_IS_CSH_PROCESS_RCSA_ENABLED(ic)) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                            "%s: Received vendor-addtoNOL action frame\n",__func__);
                        nol_el = (struct vendor_add_to_nol_ie *)frm;
                        is_nol_ie_recvd = ieee80211_process_nol_ie_bitmap(ni, nol_el);
                    } else {
                        *action_taken = FALSE;
                    }
                }
                break;

                default:
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: Vendor Specific Action frame has unknown IE id=%02X",
                       __func__,info_element->element_id);
                break;
                }

            if ((IEEE80211_IS_CSH_PROCESS_RCSA_ENABLED(ic) ||
                 IEEE80211_IS_CSH_RCSA_TO_UPLINK_ENABLED(ic))  &&
                (is_nol_ie_recvd || is_rcsa_ie_recvd)) {
                ieee80211_process_external_radar_detect(ni, is_nol_ie_recvd, is_rcsa_ie_recvd);
            }

        } else {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: Action mgt frame has non-Atheros OUI %d", __func__, ia->ia_category);
        }
    }
    break;

    default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: action mgt frame has invalid category %d", __func__, ia->ia_category);
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        *action_taken = FALSE;
        break;
    }

    return EOK;
}

int
ieee80211_recv_mgmt(struct ieee80211_node *ni,
                    wbuf_t wbuf,
                    int subtype,
                    struct ieee80211_rx_status *rs)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    int    is_bcast, forward_to_filter = 1;
    int    i;
    int    eq=0, ret = 0;
    struct ieee80211vap *tmpvap = NULL;
    bool action_taken = true;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && vap->iv_vap_is_down) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                "AP vap_is_down. drop frame subtype: %d, TA:%s\n", subtype,
                ether_sprintf(wh->i_addr2));
        return -EINVAL;
    }

    /* Make sure this is not a rogue frame carrying source address
     * same as some active vap on underlying radio.
     * If yes, do not process this frame and drop it.
     */
    TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next) {
        if (IEEE80211_ADDR_EQ(wh->i_addr2, tmpvap->iv_myaddr)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                "%s: WARN: Rx frame subtype:%d on vap:%d from mac:%s(matching vap:%d)\n",
                __func__, subtype, vap->iv_unit, ether_sprintf(wh->i_addr2),
                tmpvap->iv_unit);
            return -EINVAL;
        }
    }

    if (IEEE80211_IS_MULTICAST(wh->i_addr2) ||
        IS_NULL_ADDR(wh->i_addr2)) {
        /* Drop the management and control frames originated with invalid
         * address, viz., multicast or zero address
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
            "%s: Invalid SA:%s in received mgmt frm - ignore silently",
            __func__, ether_sprintf(wh->i_addr2));
                return 0;
    }

    /* check for ACL policy if smart mesh is enabled */
    if ((vap->iv_smart_mesh_cfg & SMART_MESH_ACL_ENHANCEMENT)) {

        if (!ieee80211_acl_check(vap, wh->i_addr2)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                    "[%s] MGMT subtype:%d, disallowed by ACL \n", ether_sprintf(ni->ni_macaddr), subtype);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_acl_inc(vap->vdev_obj, 1);
#endif
            return -EINVAL;
        }
    }

#if UMAC_SUPPORT_WNM
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm) &&
            ni != ni->ni_bss_node) {
        ieee80211_wnm_bssmax_updaterx(ni, IEEE80211_IS_MFP_FRAME(wh));
    }
#endif

    if(subtype ==  IEEE80211_FC0_SUBTYPE_AUTH ||
       subtype ==  IEEE80211_FC0_SUBTYPE_ASSOC_REQ||
       subtype ==  IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
        if (ni != ni->ni_vap->iv_bss) {
            wds_clear_wds_table(ni,&ic->ic_sta, wbuf);
        }
    }

    is_bcast = IEEE80211_IS_BROADCAST(wh->i_addr1) ? 1:0;
    if (IEEE80211_IS_MFP_FRAME(wh)) {
        struct wlan_objmgr_pdev *pdev;
        struct wlan_objmgr_psoc *psoc;
        struct wlan_lmac_if_crypto_rx_ops *crypto_rx_ops;

        pdev = ic->ic_pdev_obj;
        if(pdev == NULL) {
            qdf_print("%s[%d]pdev is NULL", __func__, __LINE__);
            return -1;
        }
        psoc = wlan_pdev_get_psoc(pdev);
        if(psoc == NULL) {
            qdf_print("%s[%d]psoc is NULL", __func__, __LINE__);
            return -1;
        }
       IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Received MFP frame with Subtype 0x%2X\n", subtype);
       /*
       * There are two reasons that a received MFP frame must be dropped:
       * 1) decryption error
       * 2) MFP is not negociated
       */
    crypto_rx_ops = wlan_crypto_get_crypto_rx_ops(psoc);
    if ((crypto_rx_ops && WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops) &&
              (WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)(vap->vdev_obj,
                                       wbuf, ni->ni_macaddr, 16) != 0))
                    || (!ieee80211_is_pmf_enabled(vap, ni)) || (rs->rs_flags)){
              /* Increment rx decrypt errors in peer stats */
#ifdef QCA_SUPPORT_CP_STATS
              peer_cp_stats_rx_decryptcrc_inc(ni->peer_obj, 1);
#endif

              IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Decrypt Error MFP frame with Subtype 0x%2X\n", subtype);
              return -EINVAL;
        } else {
#ifdef QCA_SUPPORT_CP_STATS
       is_bcast ? vdev_mcast_cp_stats_rx_decryptok_inc(vap->vdev_obj, 1):
                  vdev_ucast_cp_stats_rx_decryptok_inc(vap->vdev_obj, 1);
#endif
        }
        /* recalculate wh pointer, header may shift after decap */
        wh = (struct ieee80211_frame *) wbuf_header(wbuf);
        /* NB: We clear the Protected bit later */
    }
    else {
        u_int8_t *frm = (u_int8_t *)&wh[1];
        u_int8_t *efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
        struct ieee80211_action *ia;

        IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action));
        ia = (struct ieee80211_action *)frm;

        if (ieee80211_is_pmf_enabled(vap, ni) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ACTION)) {
            switch(ia->ia_category) {
                case IEEE80211_ACTION_CAT_SPECTRUM:
                case IEEE80211_ACTION_CAT_QOS:
                case IEEE80211_ACTION_CAT_DLS:
                case IEEE80211_ACTION_CAT_BA:
                case IEEE80211_ACTION_CAT_RADIO:
                case IEEE80211_ACTION_CAT_SA_QUERY:
                case IEEE80211_ACTION_CAT_PROT_DUAL:
                case IEEE80211_ACTION_CAT_WNM:
                case IEEE80211_ACTION_CAT_WMM_QOS:
                case IEEE80211_ACTION_CAT_FST:
                    /* unprotected action frame that must be protected, drop it */
                    IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "mfp frame is not protected");
                    return -EINVAL;
                default:
                    break;
            }
        }
    }

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (vap->iv_bss == ni)) {
       switch (subtype) {
           case IEEE80211_FC0_SUBTYPE_BEACON:
           case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
           case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
           case IEEE80211_FC0_SUBTYPE_AUTH:
           case IEEE80211_FC0_SUBTYPE_ATIM:
           case IEEE80211_FC0_SUBTYPE_ACTION:
           case IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK:
               break;
           default:
               IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Dropping mgmt frame with subtype %d recevied in self peer\n",subtype);
               return -EINVAL;
        }
    }

#ifdef QCA_SUPPORT_CP_STATS
    is_bcast ? vdev_mcast_cp_stats_rx_mgmt_inc(vap->vdev_obj, 1):
               vdev_ucast_cp_stats_rx_mgmt_inc(vap->vdev_obj, 1);
#endif

    switch (subtype) {
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
    case IEEE80211_FC0_SUBTYPE_BEACON:
        ieee80211_recv_beacon(ni, wbuf, subtype, rs);
        /*store all received beacon info*/
        if(vap->iv_beacon_info_count>=100)
        {
            vap->iv_beacon_info_count=0;
        }
        eq=0;
        if(vap->iv_beacon_info_count)
        {
            for(i=0;i<vap->iv_beacon_info_count;i++)
            {
                if(!OS_MEMCMP(vap->iv_beacon_info[i].essid,vap->iv_essid,vap->iv_esslen))
                {
                    eq=1;
                    vap->iv_beacon_info[i].snr_ctl_0=rs->rs_snrctl[0];
                    vap->iv_beacon_info[i].snr_ctl_1=rs->rs_snrctl[1];
                    vap->iv_beacon_info[i].snr_ctl_2=rs->rs_snrctl[2];
                    break;
                }
            }
            if(!eq)
            {
                OS_MEMCPY(vap->iv_beacon_info[vap->iv_beacon_info_count].essid, vap->iv_essid,vap->iv_esslen);
                vap->iv_beacon_info[vap->iv_beacon_info_count].esslen = vap->iv_esslen;
                vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_0=rs->rs_snrctl[0];
                vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_1=rs->rs_snrctl[1];
                vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_2=rs->rs_snrctl[2];
                vap->iv_beacon_info[vap->iv_beacon_info_count].numchains=rs->rs_numchains;
                vap->iv_beacon_info_count++;
            }
        }
        else
        {
            OS_MEMCPY(vap->iv_beacon_info[vap->iv_beacon_info_count].essid, vap->iv_essid,vap->iv_esslen);
            vap->iv_beacon_info[vap->iv_beacon_info_count].esslen = vap->iv_esslen;
            vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_0=rs->rs_snrctl[0];
            vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_1=rs->rs_snrctl[1];
            vap->iv_beacon_info[vap->iv_beacon_info_count].snr_ctl_2=rs->rs_snrctl[2];
            vap->iv_beacon_info[vap->iv_beacon_info_count].numchains=rs->rs_numchains;
            vap->iv_beacon_info_count++;
         }

        /*store ibss peer info*/
        if(!OS_MEMCMP(vap->iv_essid, vap->iv_des_ssid[0].ssid,vap->iv_des_ssid[0].len))
        {
            if(vap->iv_ibss_peer_count>=8)
            {
                vap->iv_ibss_peer_count=0;
            }
            eq=0;
            if(vap->iv_ibss_peer_count)
            {
                for(i=0;i<vap->iv_ibss_peer_count;i++)
                {
                    if(IEEE80211_ADDR_EQ(vap->iv_ibss_peer[i].bssid,wh->i_addr2))
                    {
                        eq=1;
                        break;
                    }
                }
                if(!eq)
                {
                    IEEE80211_ADDR_COPY(vap->iv_ibss_peer[vap->iv_ibss_peer_count].bssid, wh->i_addr2);
                    vap->iv_ibss_peer_count++;
                }
                break;
            }
            else
            {
                IEEE80211_ADDR_COPY(vap->iv_ibss_peer[vap->iv_ibss_peer_count].bssid, wh->i_addr2);
                vap->iv_ibss_peer_count++;
                break;
            }
        }

        break;

    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to probe req for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        if(ieee80211_recv_probereq(ni, wbuf, subtype, rs) < 0) {
                ret = -EINVAL;
                forward_to_filter = 0;
        }
        break;

    case IEEE80211_FC0_SUBTYPE_AUTH:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to auth for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        if(ieee80211_recv_auth(ni, wbuf, subtype, rs) < 0) {
            ret = -EINVAL;
           forward_to_filter = 0;
	}
        break;

    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        ieee80211_recv_asresp(ni, wbuf, subtype);
        break;

    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to auth for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        /*
         *  Update RSSI information for mgmt frame also
         *  This will be used in OBSS coexistance improvements
         */
        ni->ni_snr = rs->rs_snr;
        ni->ni_snr_min = rs->rs_snr;
        ni->ni_snr_max = rs->rs_snr;

        /* OCE based assoc-reject logic related ot poor-channel condition
         * is based on an average rssi value of auth and assoc frame. But
         * according to spec the same condition for 6Ghz band is based only
         * on (re)assoc frame
         */
        if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            ni->ni_abs_rssi = rs->rs_abs_rssi;
        } else if (ieee80211_vap_oce_check(vap) && ni->ni_abs_rssi) {
            /* Calculate average RSSI with Auth and Assoc msg */
            ni->ni_abs_rssi = (ni->ni_abs_rssi + rs->rs_abs_rssi) >> 1;
        }

#if WLAN_SUPPORT_FILS
        /* decrypt the Assoc Request Frame */
        /* TO DO : Decision on when to call decrypt function */
        if (wlan_fils_is_enable(vap->vdev_obj) &&
            wlan_crypto_get_peer_fils_aead(ni->peer_obj) &&
            (ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK ||
            ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK_PFS ||
            ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_PK)) {
            struct wlan_objmgr_psoc *psoc = NULL;
            struct wlan_lmac_if_crypto_rx_ops *crypto_rx_ops = NULL;

            psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
            if (!psoc) {
                qdf_print("%s[%d] psoc is NULL!", __func__, __LINE__);
                ret = -EINVAL;
                break;
            }
            crypto_rx_ops = wlan_crypto_get_crypto_rx_ops(psoc);
            if (crypto_rx_ops && WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)) {
                ret = WLAN_CRYPTO_RX_OPS_DECAP(crypto_rx_ops)(
                                      vap->vdev_obj, wbuf, ni->ni_macaddr, 16);
                if (ret != QDF_STATUS_SUCCESS) {
                    qdf_print("%s[%d] FILS decap failed!!",
                                                    __func__, __LINE__);
                    ret = -EINVAL;
                    break;
                }
            }
        }
#endif
        if (ieee80211_recv_asreq(ni, wbuf, subtype)) {
            ret = -EINVAL;
            forward_to_filter = 0;
        }
        break;

    case IEEE80211_FC0_SUBTYPE_DEAUTH:
        ret = ieee80211_recv_deauth(ni, wbuf, subtype);
        if(ret){
            /*Something wrong, don't fwd to filter*/
           forward_to_filter = 0;
        }
        break;

    case IEEE80211_FC0_SUBTYPE_DISASSOC:
        ret = ieee80211_recv_disassoc(ni, wbuf, subtype);
        if(ret){
            /*Something wrong, don't fwd to filter*/
           forward_to_filter = 0;
        }
        break;

    case IEEE80211_FC0_SUBTYPE_ACTION:
    case IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK:
        ret = ieee80211_recv_action(ni, wbuf, subtype, rs, &action_taken);
        /*
         * if ret value is negative
         * or frame is already processed in host driver,
         * then don't forward the frame to user space
         */
        if (ret || action_taken) {
            /*something wrong, don't fwd to filter*/
            forward_to_filter = 0;
        }
        break;

    default:
        break;
    }

    /*
     * deliver 802.11 frame if the OS is interested in it and
     * we have decided to forward it. (Some processed Action frames are not forwarded
     * to hostapd to avoid getting another response)
     */
    if (ieee80211_vap_registered_is_set(vap) && forward_to_filter && vap->iv_evtable && vap->iv_evtable->wlan_receive_filter_80211) {
        ret = vap->iv_evtable->wlan_receive_filter_80211(vap->iv_ifp, wbuf, IEEE80211_FC0_TYPE_MGT, subtype, rs);
        if (ret && (subtype == IEEE80211_FC0_SUBTYPE_AUTH)) {
            ni = ieee80211_vap_find_node(vap, wh->i_addr2, WLAN_MGMT_RX_ID);
            if(ni && (ni != vap->iv_bss)) {
                IEEE80211_NODE_LEAVE(ni) ;
            }
            if(ni) {
                ieee80211_free_node(ni, WLAN_MGMT_RX_ID);
	    }
        }
    }

    return ret;
}

int
ieee80211_recv_ctrl(struct ieee80211_node *ni,
                    wbuf_t wbuf,
                    int subtype,
                    struct ieee80211_rx_status *rs)
{
     struct ieee80211vap    *vap = ni->ni_vap;
     switch (vap->iv_opmode) {
     case IEEE80211_M_HOSTAP:
          ieee80211_recv_ctrl_ap(ni,wbuf,subtype);
          break;
     default:
          break;
     }
    return EOK;
}

/*
 * send an action frame.
 * @param vap      : vap pointer.
 * @param dst_addr : destination address.
 * @param src_addr : source address.(most of the cases vap mac address).
 * @param bssid    : BSSID or %NULL to use default
 * @param data     : data buffer conataining the action frame including action category  and type.
 * @param data_len : length of the data buffer.
 * @param handler  : hanlder called when the frame transmission completes.
 * @param arg      : opaque pointer passed back via the handler.
 * @ returns 0 if success, -ve if failed.
 */
int ieee80211_vap_send_action_frame(struct ieee80211vap *vap,const u_int8_t *dst_addr,const  u_int8_t *src_addr, const u_int8_t *bssid,
                                    const u_int8_t *data, u_int32_t data_len, ieee80211_vap_complete_buf_handler handler, void *arg)
{
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni=NULL;
    struct ieee80211com *ic = vap->iv_ic;

    /*
     * sanity check the data length.
     */
    if ( (data_len + sizeof(struct ieee80211_frame)) >= MAX_TX_RX_PACKET_SIZE) {
        return  -ENOMEM;
    }

    if (wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) {
        /* if vap is not active then return an error */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"%s: Error: vap is not set\n", __func__);
        return  -EINVAL;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);

    if (wbuf == NULL) {
        return  -ENOMEM;
    }

    /*
     * if a node exist with the given address already , use it.
     * if not use bss node.
     */
    ni = ieee80211_find_txnode(vap, dst_addr, WLAN_MGMT_HANDLER_ID);
    if (ni == NULL) {
        if ((ni = ieee80211_try_ref_node(vap->iv_bss, WLAN_MGMT_HANDLER_ID)) == NULL) {
            wbuf_release(ic->ic_osdev, wbuf);
            return -EINVAL;
        }
    }
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    ieee80211_send_setup(vap, vap->iv_bss, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ACTION,
                         src_addr, dst_addr, bssid ? bssid : ni->ni_bssid);
    frm = (u_int8_t *)&wh[1];
    /*
     * copy the data part into the data area.
     */
    OS_MEMCPY(frm,data,data_len);

    if (ieee80211_is_robust_action_frame(*data) &&
        ((ieee80211_vap_mfp_test_is_set(vap) ||
         wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj)) &&
         ieee80211_node_is_authorized(ni))) {
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    wbuf_set_pktlen(wbuf, data_len + (u_int32_t)sizeof(struct ieee80211_frame));
    if (handler) {
        ieee80211_vap_set_complete_buf_handler(wbuf,handler,arg);
    }

    {
#if UMAC_SUPPORT_WNM
        /* force the WNMSLEEP_RESP action frame to be send even when sta is in ps mode */
        bool force_send = false;
	  if (ieee80211_is_robust_action_frame(*data) &&
            wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
            ieee80211_node_is_authorized(ni)) {
            /* MFP is enabled, so we need to set Privacy bit */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }

    if (*data == IEEE80211_ACTION_CAT_WNM && *(data+1) == IEEE80211_ACTION_WNMSLEEP_RESP)
            force_send = true;
        if (ieee80211_send_mgmt(vap,ni, wbuf,force_send) != EOK) {
#else
        if (ieee80211_send_mgmt(vap,ni, wbuf,false) != EOK) {
#endif
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                              "[%s] failed to send management frame\n",__func__);
        }
    }
    ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);

    return EOK;
}
bool
ieee80211_is_mmie_valid(struct ieee80211vap *vap, struct ieee80211_node *ni, u_int8_t* frm, u_int8_t* efrm)
{
    return wlan_crypto_is_mmie_valid(vap->vdev_obj, frm, efrm);
}

static void
wlan_ready_on_channel(wlan_if_t vap,
                      struct ieee80211_offchan_req *offchan_req)
{
    osif_dev *osifp;
    struct ieee80211com *ic;
    struct ieee80211_channel chan;

    ic = vap->iv_ic;
    osifp = (osif_dev *)vap->iv_ifp;

    if (!offchan_req)
        return;

    chan.center_freq = offchan_req->freq;

    cfg80211_ready_on_channel(&osifp->iv_wdev,
                offchan_req->cookie,
                &chan, offchan_req->dwell_time, GFP_KERNEL);
}

static void
wlan_remain_on_channel_expired(wlan_if_t vap)
{
    osif_dev *osifp;
    struct ieee80211com *ic;
    struct ieee80211_channel chan;

    ic = vap->iv_ic;
    osifp = (osif_dev *)vap->iv_ifp;

    if (vap->iv_mgmt_offchan_current_req.freq &&
        vap->iv_mgmt_offchan_current_req.cookie)
    {
        chan.center_freq = vap->iv_mgmt_offchan_current_req.freq;
        cfg80211_remain_on_channel_expired(&osifp->iv_wdev,
                    vap->iv_mgmt_offchan_current_req.cookie,
                    &chan, GFP_KERNEL);
    }
}

extern void
wlan_offchan_mgmt_tx_handler(struct wlan_objmgr_vdev *vdev,
                                struct offchan_tx_status *status,
                                struct offchan_stats *stats);


static
int wlan_offchan_mgmt_tx_scan_req(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct offchan_tx_req req = { 0 };
    struct ieee80211_offchan_list *offchan_list = NULL;

    /*
     * For off channel TX/RX without active WLAN feature, VAP UP/RUN state
     * is not mandatory.
     */


    qdf_nbuf_queue_init(&req.offchan_tx_list);

    qdf_spin_lock_bh(&vap->iv_mgmt_offchan_tx_lock);

    if (!qdf_list_empty(&vap->iv_mgmt_offchan_req_list)) {
            qdf_list_node_t *tnode = NULL;

        if (qdf_list_remove_front(
                           &vap->iv_mgmt_offchan_req_list, &tnode) == QDF_STATUS_SUCCESS) {
                offchan_list = qdf_container_of(tnode, struct ieee80211_offchan_list, next_request);
        }
    }

    qdf_spin_unlock_bh(&vap->iv_mgmt_offchan_tx_lock);

    if (!offchan_list)
        return -1;

    if (offchan_list->offchan_tx_frm)
        qdf_nbuf_queue_add(&req.offchan_tx_list, offchan_list->offchan_tx_frm);

    req.chan = offchan_list->req.freq;
    req.dwell_time = offchan_list->req.dwell_time;
    req.offchan_rx = false;
    req.complete_dwell_tx = true;
    req.dequeue_rate = 1;
    req.tx_comp = wlan_offchan_mgmt_tx_handler;
    req.rx_ind = NULL;
    req.req_nbuf_ontx_comp = true;
    req.high_priority = true;

    qdf_mem_copy(&vap->iv_mgmt_offchan_current_req, &offchan_list->req, sizeof(struct ieee80211_offchan_req));
    if (ucfg_offchan_tx_request(vap->vdev_obj, &req) != QDF_STATUS_SUCCESS) {
        qdf_atomic_dec(&vap->iv_mgmt_offchan_cmpl_pending);
        qdf_mem_free(offchan_list);
        return -EINVAL;
    }
    ieee80211_ic_offchanscan_set(ic);
    qdf_atomic_dec(&vap->iv_mgmt_offchan_cmpl_pending);

    if (offchan_list->req.request_type == IEEE80211_OFFCHAN_RX)
         wlan_ready_on_channel(vap, &offchan_list->req);

    qdf_mem_free(offchan_list);
    return 0;
}

void
wlan_offchan_mgmt_tx_handler(struct wlan_objmgr_vdev *vdev,
                                struct offchan_tx_status *status,
                                struct offchan_stats *stats)
{
    struct ieee80211vap *vap;
    osif_dev *osifp;
    uint8_t i;
    qdf_nbuf_t buf;
    struct ieee80211com *ic;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if(!vap) {
        return;
    }
    ic = vap->iv_ic;
    osifp = (osif_dev *)vap->iv_ifp;
    if (!osifp)
        return;

    if (vap->iv_mgmt_offchan_current_req.request_type == IEEE80211_OFFCHAN_TX) {
        for (i = 0; i < status->count; i++) {
            if (!qdf_nbuf_is_queue_empty(&status->offchan_txcomp_list)) {
                buf = qdf_nbuf_queue_remove(&status->offchan_txcomp_list);
                if(vap->iv_cfg80211_create && buf) {
                    qdf_info("MGMT_OFF_TX :: status %d\n", status->status[i]);
                    cfg80211_mgmt_tx_status(&osifp->iv_wdev, vap->iv_mgmt_offchan_current_req.cookie, qdf_nbuf_data(buf), qdf_nbuf_len(buf),
                                            (status->status[i] != OFFCHAN_TX_STATUS_SUCCESS) ? false : true, GFP_ATOMIC);
                }
                if (buf)
                    wbuf_free(buf);
            }
        }
    } else if (vap->iv_mgmt_offchan_current_req.request_type == IEEE80211_OFFCHAN_RX) {
        wlan_remain_on_channel_expired(vap);
    }
    qdf_mem_zero(&vap->iv_mgmt_offchan_current_req, sizeof(struct ieee80211_offchan_req));
    ieee80211_ic_offchanscan_clear(vap->iv_ic);
    if (qdf_atomic_read(&vap->iv_mgmt_offchan_cmpl_pending) != 0) {
        wlan_offchan_mgmt_tx_scan_req(vap);
    }
}

static
int wlan_offchan_mgmt_tx_add(wlan_if_t vap_handle, const u_int8_t *dst_addr,
                             const u_int8_t *src_addr, const u_int8_t *bssid,
                             const u_int8_t *data, u_int32_t data_len,
                             struct ieee80211_offchan_req *offchan_req)
{
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni=NULL;
    struct ieee80211vap *vap = vap_handle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_offchan_list *offchan_list;
    /*
     * sanity check the data length.
     */
    if ( (data_len + sizeof(struct ieee80211_frame)) >= MAX_TX_RX_PACKET_SIZE) {
        return  -ENOMEM;
    }

    if ((wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) &&
       (vap->iv_opmode != IEEE80211_M_STA) &&
       (vap->iv_mgmt_offchan_current_req.request_type != IEEE80211_OFFCHAN_RX)) {
        /* if vap is not active then return an error */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"%s: Error: vap is not set\n", __func__);
        return  -EINVAL;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);


    if (wbuf == NULL) {
        return  -ENOMEM;
    }

    /*
     * if a node exist with the given address already , use it.
     * if not use bss node.
     */
    ni = ieee80211_find_txnode(vap, dst_addr, WLAN_OFFCHAN_TX_ID);

    if (ni == NULL) {
        ni = ieee80211_ref_node(vap->iv_bss, WLAN_OFFCHAN_TX_ID);
    }

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ACTION,
                         src_addr, dst_addr, bssid ? bssid : ni->ni_bssid);
    frm = (u_int8_t *)&wh[1];

    /*
     * copy the data part into the data area.
     */

    OS_MEMCPY(frm, data, data_len);
    wbuf_set_pktlen(wbuf, data_len + sizeof(struct ieee80211_frame));

    wlan_wbuf_set_peer_node(wbuf, ni);
    ieee80211_free_node(ni, WLAN_OFFCHAN_TX_ID);

    /* force with NONPAUSE_TID */
    wbuf_set_tid(wbuf, EXT_TID_NONPAUSE);
    wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3,
                ic->ic_he_target);

    offchan_list = qdf_mem_malloc(sizeof(struct ieee80211_offchan_list));

    if (!offchan_list)
        return  -ENOMEM;

    qdf_atomic_inc(&vap_handle->iv_mgmt_offchan_cmpl_pending);
    qdf_spin_lock_bh(&vap_handle->iv_mgmt_offchan_tx_lock);
    qdf_list_insert_back(&vap->iv_mgmt_offchan_req_list, &offchan_list->next_request);
    offchan_list->offchan_tx_frm = wbuf;
    qdf_mem_copy(&offchan_list->req, offchan_req, sizeof(struct ieee80211_offchan_req));

    qdf_spin_unlock_bh(&vap_handle->iv_mgmt_offchan_tx_lock);
    qdf_info("MGMT_OFF_TX \n");
    return 0;
}

static
void wlan_offchan_mgmt_tx_send(struct ieee80211vap *vap)
{
    wbuf_t wbuf = NULL;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni;
    struct ieee80211com *ic = vap->iv_ic;
    int retval;

    qdf_spin_lock_bh(&vap->iv_mgmt_offchan_tx_lock);

    if (!qdf_list_empty(&vap->iv_mgmt_offchan_req_list)) {
        struct ieee80211_offchan_list *offchan_list;
        qdf_list_node_t *tnode = NULL;
        if (qdf_list_remove_front(
                          &vap->iv_mgmt_offchan_req_list, &tnode) == QDF_STATUS_SUCCESS) {
            offchan_list = qdf_container_of(tnode, struct ieee80211_offchan_list, next_request);

        wbuf = offchan_list->offchan_tx_frm;
        qdf_mem_free(offchan_list);
        qdf_atomic_dec(&vap->iv_mgmt_offchan_cmpl_pending);
        qdf_spin_unlock_bh(&vap->iv_mgmt_offchan_tx_lock);

            if (wbuf) {
                uint32_t mgmt_rate;

                /* send the pkt */
                wh = (struct ieee80211_frame *)wbuf_header(wbuf);
                ni = ieee80211_find_txnode(vap, wh->i_addr1, WLAN_OFFCHAN_TX_ID);

                if (ni == NULL) {
                    ni = ieee80211_ref_node(vap->iv_bss, WLAN_OFFCHAN_TX_ID);
                }
                wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
                        WLAN_MLME_CFG_TX_MGMT_RATE, &mgmt_rate);
                if (IEEE80211_IS_CHAN_2GHZ(vap->iv_ic->ic_curchan) && mgmt_rate) {
                    if (mgmt_rate == 6000)       /* 6 Mbps */
                        wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3, ic->ic_he_target);
                    else if (mgmt_rate == 5500)  /* 5.5 Mbps */
                        wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 1, ic->ic_he_target);
                    else if (mgmt_rate == 2000)  /* 2 Mbps */
                        wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 2, ic->ic_he_target);
                    else                                  /* 1 Mbps */
                        wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 3, ic->ic_he_target);
                }
                wbuf_set_tid(wbuf, EXT_TID_NONPAUSE/*19*/);
                wbuf_set_complete_handler(wbuf, ieee80211_mlme_frame_complete_handler, ni);

                if (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
                    ieee80211_node_is_authorized(ni)) {
                    /* MFP is enabled, so we need to set Privacy bit */
                    wh->i_fc[1] |= IEEE80211_FC1_WEP;
                }

                retval = ieee80211_send_mgmt(vap, ni, wbuf, true);
                ieee80211_free_node(ni, WLAN_OFFCHAN_TX_ID);
            }
        } else {
            qdf_spin_unlock_bh(&vap->iv_mgmt_offchan_tx_lock);
        }
    } else {
        qdf_spin_unlock_bh(&vap->iv_mgmt_offchan_tx_lock);
    }
}

int wlan_offchan_mgmt_tx_start(wlan_if_t vap_handle, const u_int8_t *dst_addr,
                               const u_int8_t *src_addr, const u_int8_t *bssid,
                               const u_int8_t *data, u_int32_t data_len,
                               struct ieee80211_offchan_req *offchan_req)
{
    struct ieee80211vap *vap = vap_handle;
    u_int32_t freq = vap->iv_mgmt_offchan_current_req.freq;
    struct ieee80211com *ic = vap_handle->iv_ic;

    if (!freq)
        freq = ieee80211_chan2freq(ic,ic->ic_curchan);

    if (offchan_req->freq != 0 && offchan_req->freq != freq &&
        ieee80211_ic_offchanscan_is_set(vap_handle->iv_ic)) {
        /* Cancel current scan and send tx failures for all queued packets */
        ucfg_offchan_tx_cancel(vap->vdev_obj);
    }
    if (!wlan_offchan_mgmt_tx_add(vap_handle,dst_addr, src_addr,
        bssid, data, data_len, offchan_req)) {
        if (offchan_req->freq != 0 && offchan_req->freq == freq &&
            (!(vap->iv_opmode == IEEE80211_M_STA)))
            wlan_offchan_mgmt_tx_send(vap);
        else if (!ieee80211_ic_offchanscan_is_set(vap_handle->iv_ic))
            wlan_offchan_mgmt_tx_scan_req(vap_handle);
        else if (ieee80211_ic_offchanscan_is_set(vap_handle->iv_ic) &&
            vap->iv_mgmt_offchan_current_req.request_type == IEEE80211_OFFCHAN_RX)
            wlan_offchan_mgmt_tx_send(vap);
        return 0;
    }
    /* add or sending the frame failed */
    return -1;
}

int wlan_remain_on_channel(wlan_if_t vap,
                           struct ieee80211_offchan_req *offchan_req)
{
    struct ieee80211com *ic = vap->iv_ic;
    int ret = 0;
    struct ieee80211_offchan_list *offchan_list;

    vap->iv_mgmt_offchan_current_req.freq = offchan_req->freq;
    vap->iv_mgmt_offchan_current_req.request_type = IEEE80211_OFFCHAN_RX;

    if (offchan_req->freq != 0 && offchan_req->freq !=  ieee80211_chan2freq(ic,ic->ic_curchan)) {
        ucfg_offchan_tx_cancel(vap->vdev_obj);
        offchan_list = qdf_mem_malloc(sizeof(struct ieee80211_offchan_list));
        if (!offchan_list)
            return  -ENOMEM;

        offchan_list->req.request_type = offchan_req->request_type;
        offchan_list->req.freq = offchan_req->freq;
        offchan_list->req.dwell_time = offchan_req->dwell_time;
        offchan_list->req.cookie = offchan_req->cookie;

        qdf_atomic_inc(&vap->iv_mgmt_offchan_cmpl_pending);
        qdf_spin_lock_bh(&vap->iv_mgmt_offchan_tx_lock);
        qdf_list_insert_back(&vap->iv_mgmt_offchan_req_list, &offchan_list->next_request);

        qdf_spin_unlock_bh(&vap->iv_mgmt_offchan_tx_lock);

        if (!ieee80211_ic_offchanscan_is_set(vap->iv_ic))
            ret = wlan_offchan_mgmt_tx_scan_req(vap);

        if (ret == 0)
            ieee80211_ic_offchanscan_set(vap->iv_ic);
    }

    return ret;
}

int wlan_cancel_remain_on_channel(wlan_if_t vap)
{
    if (ieee80211_ic_offchanscan_is_set(vap->iv_ic) &&
        vap->iv_mgmt_offchan_current_req.request_type == IEEE80211_OFFCHAN_RX) {
        /* Cancel current scan and send tx failures for all queued packets */
        ucfg_offchan_tx_cancel(vap->vdev_obj);
    }

    if(vap->iv_mgmt_offchan_current_req.cookie &&
        vap->iv_mgmt_offchan_current_req.freq)
        wlan_remain_on_channel_expired(vap);

    return 0;
}


/**
* send action management frame.
* @param freq     : channel to send on (only to validate/match with current channel)
* @param arg      : arg (will be used in the mlme_action_send_complete)
* @param dst_addr : destination mac address
* @param src_addr : source mac address
* @param bssid    : bssid
* @param data     : includes total payload of the action management frame.
* @param data_len : data len.
* @returns 0 if succesful and -ve if failed.
* if the radio is not on the passedf in freq then it will return an error.
* if returns 0 then mlme_action_send_complete will be called with the status of
* the frame transmission.
*/
int wlan_vap_send_action_frame(wlan_if_t vap_handle, u_int32_t freq,
                               wlan_action_frame_complete_handler handler, void *arg,const u_int8_t *dst_addr,
                               const u_int8_t *src_addr, const u_int8_t *bssid, const u_int8_t *data, u_int32_t data_len)
{
    struct ieee80211com *ic = vap_handle->iv_ic;
    /* send action frame */
    if (freq) {
        if(freq !=  ieee80211_chan2freq(ic,ic->ic_curchan)) {
            /* frequency does not match */
            IEEE80211_DPRINTF(vap_handle, IEEE80211_MSG_ANY,
                              "%s: Error: frequency does not match. req=%d, curr=%d\n",
                              __func__, freq, ieee80211_chan2freq(ic,ic->ic_curchan));
            return -EINVAL;
        }
    }
    return ieee80211_vap_send_action_frame(vap_handle,dst_addr,src_addr,bssid,data,data_len,
                    handler,arg);
}

#if ATH_SUPPORT_CFEND
/*
 *  Allocate a CF-END frame and fillin the appropriate bits.
 *  */
wbuf_t
ieee80211_cfend_alloc(struct ieee80211com *ic)
{
    wbuf_t cfendbuf;
    struct ieee80211_ctlframe_addr2 *wh;
    const u_int8_t macAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    cfendbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_CTL, sizeof(struct ieee80211_ctlframe_addr2));
    if (cfendbuf == NULL) {
        return cfendbuf;
    }

    wbuf_append(cfendbuf, sizeof(struct ieee80211_ctlframe_addr2));
    wh = (struct ieee80211_ctlframe_addr2*) wbuf_header(cfendbuf);

    *(u_int16_t *)(&wh->i_aidordur) = htole16(0x0000);
    wh->i_fc[0] = 0;
    wh->i_fc[1] = 0;
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
        IEEE80211_FC0_SUBTYPE_CF_END;

    IEEE80211_ADDR_COPY(wh->i_addr1, macAddr);
    IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_my_hwaddr);

    /*if( vap->iv_opmode == IEEE80211_M_HOSTAP ) {
        wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
    } else {
        wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
    }*/
    return cfendbuf;
}
#endif

void
wlan_addba_request_handler(void *arg, wlan_node_t node)
{
    struct ieee80211_addba_delba_request *ad = arg;
    struct ieee80211_node *ni = node;
    struct ieee80211com *ic = ad->ic;
    int ret;

    if (ni->ni_associd == 0 ||
        IEEE80211_AID(ni->ni_associd) != ad->aid) {
        return;
    }

    switch (ad->action)
    {
    default:
        return;
    case ADDBA_SEND:
        ret = ic->ic_addba_send(ni, ad->tid, ad->arg1);
        if (ret != 0)  {
            qdf_nofl_info("ADDBA send failed: recipient is not a 11n node\n");
        }
        break;
    case ADDBA_STATUS:
        ic->ic_addba_status(ni, ad->tid, &(ad->status));
        break;
    case DELBA_SEND:
        ic->ic_delba_send(ni, ad->tid, ad->arg1, ad->arg2);
        break;
    case ADDBA_RESP:
        ic->ic_addba_setresponse(ni, ad->tid, ad->arg1);
        break;
    case SINGLE_AMSDU:
        ic->ic_send_singleamsdu(ni, ad->tid);
        break;
    }
}

int
wlan_send_delts(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_node *ni;
    struct ieee80211_action_mgt_args delts_args;
    struct ieee80211_action_mgt_buf  delts_buf;
    struct ieee80211_tsinfo_bitmap *tsflags;
    struct ieee80211_wme_tspec *tspec;

    ni = ieee80211_find_txnode(vap, macaddr, WLAN_MGMT_HANDLER_ID);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                          "%s: could not send DELTS, no node found for %s\n",
                          __func__, ether_sprintf(macaddr));
        return -EINVAL;
    }

    /*
     * ieee80211_action_mgt_args is a generic structure. TSPEC IE
     * is filled in the buf area.
     */
    delts_args.category = IEEE80211_ACTION_CAT_WMM_QOS;
    delts_args.action   = IEEE80211_WMM_QOS_ACTION_TEARDOWN;
    delts_args.arg1     = IEEE80211_WMM_QOS_DIALOG_TEARDOWN; /* dialogtoken */
    delts_args.arg2     = 0; /* status code */
    delts_args.arg3     = sizeof(struct ieee80211_wme_tspec);

    tspec = (struct ieee80211_wme_tspec *) &delts_buf.buf;
    tsflags = (struct ieee80211_tsinfo_bitmap *) &(tspec->ts_tsinfo);
    tsflags->direction = tsinfo->direction;
    tsflags->psb = tsinfo->psb;
    tsflags->dot1Dtag = tsinfo->dot1Dtag;
    tsflags->tid = tsinfo->tid;
    tsflags->reserved3 = tsinfo->aggregation;
    tsflags->one = tsinfo->acc_policy_edca;
    tsflags->zero = tsinfo->acc_policy_hcca;
    tsflags->reserved1 = tsinfo->traffic_type;
    tsflags->reserved2 = tsinfo->ack_policy;

    *((u_int16_t *) &tspec->ts_nom_msdu) = htole16(tsinfo->norminal_msdu_size);
    *((u_int16_t *) &tspec->ts_max_msdu) = htole16(tsinfo->max_msdu_size);
    *((u_int32_t *) &tspec->ts_min_svc) = htole32(tsinfo->min_srv_interval);
    *((u_int32_t *) &tspec->ts_max_svc) = htole32(tsinfo->max_srv_interval);
    *((u_int32_t *) &tspec->ts_inactv_intv) = htole32(tsinfo->inactivity_interval);
    *((u_int32_t *) &tspec->ts_susp_intv) = htole32(tsinfo->suspension_interval);
    *((u_int32_t *) &tspec->ts_start_svc) = htole32(tsinfo->srv_start_time);
    *((u_int32_t *) &tspec->ts_min_rate) = htole32(tsinfo->min_data_rate);
    *((u_int32_t *) &tspec->ts_mean_rate) = htole32(tsinfo->mean_data_rate);
    *((u_int32_t *) &tspec->ts_max_burst) = htole32(tsinfo->max_burst_size);
    *((u_int32_t *) &tspec->ts_min_phy) = htole32(tsinfo->min_phy_rate);
    *((u_int32_t *) &tspec->ts_peak_rate) = htole32(tsinfo->peak_data_rate);
    *((u_int32_t *) &tspec->ts_delay) = htole32(tsinfo->delay_bound);
    *((u_int16_t *) &tspec->ts_surplus) = htole16(tsinfo->surplus_bw);
    *((u_int16_t *) &tspec->ts_medium_time) = htole16(tsinfo->medium_time);

    ieee80211_send_action(ni, &delts_args, &delts_buf);
    ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);    /* reclaim node */
    return 0;
}

/*
 * ieee80211_update_ni_chwidth:
 * Updates the channel width of the node
 *
 * Parameters:
 * @chwidth: AP channel width
 * @ni     : Handle to the node structure of the given peer
 * @vap    : Handle to the VAP structure
 *
 * Return:
 * None
 */
void
ieee80211_update_ni_chwidth(uint8_t chwidth, struct ieee80211_node *ni,
                            struct ieee80211vap *vap)
{
   uint32_t he_width_mask;
   uint8_t *hecap_phy_info, width_set;

   if (!ni) {
       qdf_err("Invalid node");
       return;
   }

   if (!vap) {
       qdf_err("Invalid vap");
       return;
   }

   if (IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
       /*
        * For 6GHz, find the ni_chwidth using HECAPs due to absense of HT
        * and VHT caps.
        */
       hecap_phy_info = (uint8_t *) &(ni->ni_he.hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
       he_width_mask = HECAP_PHY_CBW_GET_FROM_IE(&hecap_phy_info);
   }

   switch(chwidth) {
       case IEEE80211_CWM_WIDTH20:
           ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
       break;

       case IEEE80211_CWM_WIDTH40:
           if (IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
               width_set = he_width_mask & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_MASK;
               if(width_set) {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
               } else {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
               }
           } else if (ni->ni_vhtcap &&
                      IEEE80211_IS_CHAN_5GHZ(vap->iv_ic->ic_curchan)) {
               if (ni->ni_omn_chwidth == IEEE80211_CWM_WIDTH20)
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
               else
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
           } else if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
           } else {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
           }
       break;

       case IEEE80211_CWM_WIDTH80:
           if (IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
               width_set = he_width_mask & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_MASK;
               if(width_set) {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
               } else {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
               }
           } else if (ni->ni_vhtcap) {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
           } else if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
           } else if (!(ni->ni_vhtcap)) {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
           } else {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
           }
       break;

       case IEEE80211_CWM_WIDTH160:
           if (IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
               width_set = he_width_mask & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;
               if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
               } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
               } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80) {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
               } else {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
               }
           } else if (!(ni->ni_vhtcap)) {
               if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40))
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
               else
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
           } else {
               if (ieee80211_is_phymode_8080(vap->iv_cur_mode)) {
                   if (vap->iv_ext_nss_support) {
                       if (ni->ni_ext_nss_capable && ext_nss_80p80_supported(&ni->ni_vhtcap)){
                           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                       } else {
                           ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                       }
                   } else if(ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160) {
                       ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                   } else {
                       ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                   }
               } else if (ieee80211_is_phymode_160(vap->iv_cur_mode)) {
                   if (vap->iv_ext_nss_support) {
                       if (ni->ni_ext_nss_capable &&
                            (ext_nss_160_supported(&ni->ni_vhtcap) ||
                              ext_nss_80p80_supported(&ni->ni_vhtcap))){
                           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                       } else {
                           ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                       }
                   } else if((ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160) || (ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160)) {
                       ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                   } else {
                       ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                   }
               } else {
                   ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
               }
           }

       break;

       default:
        /* Do nothing */
       break;
  }
}

/* Update HT-VHT Phymode  */
void
ieee80211_update_ht_vht_he_phymode(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    enum ieee80211_phymode cur_mode = ni->ni_vap->iv_cur_mode;

    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        if (ni->ni_ext_flags & IEEE80211_NODE_HE) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE40;
                break;

                case IEEE80211_CWM_WIDTH80:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE80;
                break;
                case IEEE80211_CWM_WIDTH160:
                    ni->ni_phymode = cur_mode;
                break;
                default:
                   /* Do nothing */
                break;
            }
        } else {
            qdf_err("HE not enabled for 6 GHz operation");
        }
    } else if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
        if (ni->ni_ext_flags & IEEE80211_NODE_HE) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE40;
                break;

                case IEEE80211_CWM_WIDTH80:
                    ni->ni_phymode = IEEE80211_MODE_11AXA_HE80;
                break;
                case IEEE80211_CWM_WIDTH160:
                    ni->ni_phymode = cur_mode;
                break;
                default:
                   /* Do nothing */
                break;
            }
        } else if (ni->ni_flags & IEEE80211_NODE_VHT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT40;
                break;

                case IEEE80211_CWM_WIDTH80:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT80;
                break;
                case IEEE80211_CWM_WIDTH160:
                    if (ieee80211_is_phymode_160(cur_mode)) {
                        ni->ni_phymode = IEEE80211_MODE_11AC_VHT160;
                    } else if (ieee80211_is_phymode_8080(cur_mode)) {
                        ni->ni_phymode = IEEE80211_MODE_11AC_VHT80_80;
                    } else {
                        /* XXX This is an unexpected condition. We should assert
                         * at this point. However there could be random blocker
                         * occurrences of this condition. Se we tentatively
                         * print a warning instead and proceed until this is
                         * root caused.
                         *
                         * To be on par with older behaviour and facilitate root
                         * causing in a controlled manner, we set ni_phymode
                         * to cur_mode, but do not set ni_chwidth to our
                         * iv_chwidth.
                         */
                        qdf_print("%s: Warning: Unexpected negotiated "
                                  "ni_chwidth=%d for cur_mode=%d. Investigate! "
                                  "The system may no longer function "
                                  "correctly.",
                                  __func__, ni->ni_chwidth, cur_mode);
                        ni->ni_phymode = cur_mode;
                    }
                break;
                default:
                   /* Do nothing */
                break;
            }
        } else if (ni->ni_flags & IEEE80211_NODE_HT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11NA_HT20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11NA_HT40;
                break;

                default:
                   /* Do nothing */
                break;
           }
        }
    } else {
        if (ni->ni_ext_flags & IEEE80211_NODE_HE) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20 :
                    ni->ni_phymode = IEEE80211_MODE_11AXG_HE20;
                break;

                case IEEE80211_CWM_WIDTH40 :
                    ni->ni_phymode = IEEE80211_MODE_11AXG_HE40;
                break;

                default:
                   /* Do nothing */
                break;
            }
        } else if (ni->ni_flags & IEEE80211_NODE_HT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20 :
                    ni->ni_phymode = IEEE80211_MODE_11NG_HT20;
                break;

                case IEEE80211_CWM_WIDTH40 :
                    ni->ni_phymode = IEEE80211_MODE_11NG_HT40;
                break;

                default:
                   /* Do nothing */
                break;
            }
        }
    }
}

/* Update target with Short GI setting */
void
ieee80211_update_vap_shortgi(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    if((!(ni->ni_he.hecap_info_internal &
        (IEEE80211_HE_0DOT4US_IN_2XLTF_SUPP_BITS |
          IEEE80211_HE_0DOT4US_IN_1XLTF_SUPP_BITS))) && (ic->ic_vap_set_param)
            && ieee80211_is_phymode_11ax(ni->ni_phymode)) {
        ic->ic_vap_set_param(vap, IEEE80211_SHORT_GI, vap->iv_he_data_sgi);
    }
}
/*
 * ieee80211_parse_vhtop, ieee80211_parse_hecap would have set the channel
 * width based on APs operating mode/channel. If vap is forced to operate
 * in a different lower mode than what AP is operating in, then set the
 * channel width based on the forced channel/phy mode .
 */
void
ieee80211_readjust_chwidth(struct ieee80211_node *ni,
        struct ieee80211_ie_vhtop *ap_vhtop,
        struct ieee80211_ie_htinfo_cmn *ap_htinfo,
        struct ieee80211_ie_vhtcap *ap_vhtcap)
{
    struct ieee80211vap          *vap = ni->ni_vap;
    struct ieee80211com          *ic = ni->ni_ic;

    if (!ieee80211_is_phymode_auto(vap->iv_des_mode))
    {
        switch(ieee80211_chan2mode(ni->ni_chan))
        {
            case IEEE80211_MODE_11A          :
            case IEEE80211_MODE_11B          :
            case IEEE80211_MODE_11G          :
            case IEEE80211_MODE_11NA_HT20    :
            case IEEE80211_MODE_11NG_HT20    :
            case IEEE80211_MODE_11AC_VHT20   :
            case IEEE80211_MODE_11AXA_HE20   :
            case IEEE80211_MODE_11AXG_HE20   :
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                break;
            case IEEE80211_MODE_11NA_HT40PLUS:
            case IEEE80211_MODE_11NA_HT40MINUS:
            case IEEE80211_MODE_11NG_HT40PLUS :
            case IEEE80211_MODE_11NG_HT40MINUS:
            case IEEE80211_MODE_11AC_VHT40PLUS:
            case IEEE80211_MODE_11AC_VHT40MINUS:
            case IEEE80211_MODE_11AXA_HE40PLUS:
            case IEEE80211_MODE_11AXA_HE40MINUS:
            case IEEE80211_MODE_11AXG_HE40PLUS:
            case IEEE80211_MODE_11AXG_HE40MINUS:
                if(ni->ni_chwidth > IEEE80211_CWM_WIDTH40) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
                break;
            case IEEE80211_MODE_11AC_VHT80:
            case IEEE80211_MODE_11AXA_HE80:
                if(ni->ni_chwidth > IEEE80211_CWM_WIDTH80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                }
                break;
            case IEEE80211_MODE_11AC_VHT160:
            case IEEE80211_MODE_11AXA_HE160:
                if(ni->ni_chwidth > IEEE80211_CWM_WIDTH160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                }

                if (IEEE80211_IS_CHAN_5GHZ(ni->ni_chan)) {
                    if(ap_vhtop != NULL && ap_htinfo != NULL) {
                        if ((ic->ic_ext_nss_capable &&
                             peer_ext_nss_capable(ap_vhtcap) &&
                             extnss_80p80_validate_and_seg2_indicate(&ni->ni_vhtcap, ap_vhtop, ap_htinfo)) ||
                            IS_REVSIG_VHT80_80(ap_vhtop) ||
                            (ap_vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_80_80)) {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                        }
                    } else {
                        qdf_err("Unrecognized channel width, falling back to 20 MHz. Investigate..");
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                    }
                } else if (IEEE80211_IS_CHAN_6GHZ(ni->ni_chan)) {
                    if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH80_80))
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    qdf_err("Unrecognized channel width, falling back to 20 MHz. Investigate..");
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                }

                break;
            case IEEE80211_MODE_11AC_VHT80_80:
            case IEEE80211_MODE_11AXA_HE80_80:
                if(ni->ni_chwidth > IEEE80211_CWM_WIDTH160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                }
                break;
            default :
                break;

        }
    }

}

void wlan_omn_timer_callback(void* data)
{
    struct ieee80211com *ic = (struct ieee80211com *)data;
    struct ieee80211vap *vap;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_mbssid_enabled        = wlan_pdev_nif_feat_cap_get(pdev,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_non_tx_vap            = false;

    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO, "OMN timer callback\n");

    if(!ic->ic_omn_cxt.omn_in_progress) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO, "OMN cb: OMN not in progress\n");
        /* Nothing to do */
        return;
    }

    /* in case of mbssid following is required
     * only for a tx vap
     */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (is_mbssid_enabled)
            is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

        if (vap && !is_non_tx_vap) {
            if (is_mbssid_enabled && vap != ic->ic_mbss.transmit_vap) {
                mbss_err("tx-vap pointer mismatch!!!");
                IEEE80211_VAP_LOCK(vap);
                vap->appie_buf_updated = 0;
                IEEE80211_VAP_UNLOCK(vap);
                return;
            }

            if (vap->vie_handle) {
                IEEE80211_VAP_LOCK(vap);
                vap->appie_buf_updated = 1;
                IEEE80211_VAP_UNLOCK(vap);

                /* Remove the IE from VAP */
                wlan_mlme_app_ie_delete_id(vap->vie_handle, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_OP_MODE_NOTIFY);
                wlan_mlme_app_ie_delete_id(vap->vie_handle, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_OP_MODE_NOTIFY);
                wlan_mlme_app_ie_delete_id(vap->vie_handle, IEEE80211_FRAME_TYPE_ASSOCRESP, IEEE80211_ELEMID_OP_MODE_NOTIFY);

                wlan_vdev_beacon_update(vap);
            }
        }
    }
    ic->ic_omn_cxt.omn_in_progress = 0;
}
qdf_export_symbol(wlan_omn_timer_callback);

int wlan_vap_omn_update(struct ieee80211com *ic)
{
    struct ieee80211_node *ni;
    struct ieee80211vap *vap;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_mbssid_enabled        = wlan_pdev_nif_feat_cap_get(pdev,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_non_tx_vap            = false;

    if(ic->ic_omn_cxt.omn_in_progress) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO, "OMN in progress\n");

        /* Previous OMN update in progress, stop the timer and remove the IEs */
        qdf_timer_stop(&ic->ic_omn_cxt.notify_timer);
        wlan_omn_timer_callback((void*)ic);
    }

    /* If OM notification is enabled, start the timer. Once timer fires
      OMN IE will no longer be added to beacon */
    if(ic->ic_omn_cxt.omn_enable && ic->ic_omn_cxt.omn_timeout) {
        /* in case of mbssid following is required
         * only for a tx vap
         */
        TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
            if (is_mbssid_enabled)
                is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

            if (vap && !is_non_tx_vap) {
                if (is_mbssid_enabled && vap != ic->ic_mbss.transmit_vap) {
                    mbss_err("tx-vap pointer mismatch!!!");
                    IEEE80211_VAP_LOCK(vap);
                    vap->appie_buf_updated = 0;
                    IEEE80211_VAP_UNLOCK(vap);
                    return QDF_STATUS_E_FAILURE;
                }

                ni = vap->iv_bss;

                /* Create the OMN IE for beacon/probe response*/
                ieee80211_add_opmode_notify((u_int8_t*)&ic->ic_omn_cxt.omn_ie, ni, ic, IEEE80211_FRAME_TYPE_BEACON);

                /* Create the OMN IE for assoc response*/
                ieee80211_add_opmode_notify((u_int8_t*)&ic->ic_omn_cxt.omn_assoc_ie, ni, ic, IEEE80211_FRAME_TYPE_ASSOCRESP);

                IEEE80211_VAP_LOCK(vap);
                vap->appie_buf_updated = 1;
                IEEE80211_VAP_UNLOCK(vap);

                if(wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*)&ic->ic_omn_cxt.omn_ie,
                    sizeof(struct ieee80211_ie_op_mode_ntfy), IEEE80211_ELEMID_OP_MODE_NOTIFY) != 0) {
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR, "Error adding OMN IE to beacon for VAP\n");
                    IEEE80211_VAP_LOCK(vap);
                    vap->appie_buf_updated = 0;
                    IEEE80211_VAP_UNLOCK(vap);
                    return QDF_STATUS_E_FAILURE;
                }
                if(wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBERESP, (u_int8_t*)&ic->ic_omn_cxt.omn_ie,
                    sizeof(struct ieee80211_ie_op_mode_ntfy), IEEE80211_ELEMID_OP_MODE_NOTIFY) != 0) {
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR, "Error adding IE to probe resp for VAP\n");

                    /* Delete previously added IE */
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*)&ic->ic_omn_cxt.omn_ie);

                    IEEE80211_VAP_LOCK(vap);
                    vap->appie_buf_updated = 0;
                    IEEE80211_VAP_UNLOCK(vap);
                    return QDF_STATUS_E_FAILURE;
                }

                if(wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, (u_int8_t*)&ic->ic_omn_cxt.omn_assoc_ie,
                    sizeof(struct ieee80211_ie_op_mode_ntfy), IEEE80211_ELEMID_OP_MODE_NOTIFY) != 0) {
                    QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR, "Error adding IE to assoc resp for VAP\n");

                    /* Delete previously added IE */
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*)&ic->ic_omn_cxt.omn_ie);
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_PROBERESP, (u_int8_t*)&ic->ic_omn_cxt.omn_ie);

                    IEEE80211_VAP_LOCK(vap);
                    vap->appie_buf_updated = 0;
                    IEEE80211_VAP_UNLOCK(vap);
                    return QDF_STATUS_E_FAILURE;
                }
            }
        } /* TAILQ_FOREACH */

        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_INFO, "Starting timer\n");

        qdf_timer_start(&ic->ic_omn_cxt.notify_timer, ic->ic_omn_cxt.omn_timeout);
        ic->ic_omn_cxt.omn_in_progress = 1;
        return QDF_STATUS_SUCCESS;
    }
    return QDF_STATUS_E_FAILURE;
}
qdf_export_symbol(wlan_vap_omn_update);
