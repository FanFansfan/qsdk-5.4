/*
 * Copyright (c) 2011,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.

 */

#ifndef _ATH_STA_IEEE80211_PROTO_H
#define _ATH_STA_IEEE80211_PROTO_H

#include <wlan_cmn_ieee80211.h>
#include <include/wlan_vdev_mlme.h>
/*
 * 802.11 protocol implementation definitions.
 */


#define IEEE80211_ACTION_BUF_SIZE 256

#ifdef TARGET_SUPPORT_TSF_TIMER
typedef void (*defer_function)(void *arg);
typedef struct ieee80211_recv_defer_args {
    TAILQ_ENTRY(ieee80211_recv_defer_args) mlist;
    defer_function defer_fuc;
    void *arg;
}ieee80211_recv_defer_args_t;
#define IEEE80211_DEFER_LOCK_INIT(_ic)         spin_lock_init(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK_BH(_ic)           spin_lock_bh(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_UNLOCK_BH(_ic)         spin_unlock_bh(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK(_ic)           spin_lock(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_UNLOCK(_ic)         spin_unlock(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK_DESTROY(_ic)      spin_lock_destroy(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_CREATE(_ic, _func)     INIT_WORK(&_ic->ic_defer_work, _func, _ic)
#define IEEE80211_DEFER_DESTROY(_ic)
#define IEEE80211_DEFER_SCHEDULE(_ic)          schedule_work(&_ic->ic_defer_work)
#define IEEE80211_DEFER_DISABLE(_ic)
#define IEEE80211_TAILQ_INIT(_ic)              TAILQ_INIT(&_ic->ic_defer_data)
#endif

struct ieee80211_action_mgt_args {
    u_int8_t    category;
    u_int8_t    action;
    u_int32_t   arg1;
    u_int32_t   arg2;
    u_int32_t   arg3;
    u_int8_t    *arg4;
};

struct ieee80211_action_mgt_buf {
    u_int8_t    buf[IEEE80211_ACTION_BUF_SIZE];
};

typedef struct  _ieee80211_vap_state_info {
    u_int32_t     iv_state;
    spinlock_t    iv_state_lock; /* lock to serialize access to vap state machine */
    bool          iv_sm_running; /* indicates that the VAP SM is running */
}ieee80211_vap_state_info;

/* Any extra context information that might need to be considered in some
 * specific situations while creating a protocol frame.
 */
struct ieee80211_framing_extractx {
    bool    fectx_assocwar160_reqd;    /* Whether 160 MHz width association WAR
                                          is required. */
    bool    fectx_nstscapwar_reqd;     /* Whether STSCAP MBP WAR required */
    int     datarate;                  /* tx rate */
    int     retry;                     /* retry count */
    bool    oce_sta;                   /* Whether OCE STA or not */
    bool    fils_sta;                  /* Whether FILS STA or not */
    u_int8_t ssid_len;
    u_int8_t ssid[IEEE80211_NWID_LEN+1];
    bool    is_broadcast_req;
};

extern const char *ieee80211_mgt_subtype_name[];
extern const char *ieee80211_wme_acnames[];
/*
 * flags for ieee80211_send_cts
 */
#define IEEE80211_CTS_SMPS 1

void ath_vap_iter_cac(void *arg, wlan_if_t vap);

void ieee80211_proto_attach(struct ieee80211com *ic);
void ieee80211_proto_detach(struct ieee80211com *ic);

void ieee80211_proto_vattach(struct ieee80211vap *vap);
void ieee80211_proto_vdetach(struct ieee80211vap *vap);

int ieee80211_parse_wmeparams(struct ieee80211vap *vap, u_int8_t *frm, u_int8_t *qosinfo, int forced_update);
int ieee80211_parse_wmeinfo(struct ieee80211vap *vap, u_int8_t *frm, u_int8_t *qosinfo);
int ieee80211_parse_wmeie(u_int8_t *frm, const struct ieee80211_frame *wh, struct ieee80211_node *ni);
int ieee80211_parse_muedcaie(struct ieee80211vap *vap, u_int8_t *frm);

/* Unpack the Maximum Channel Switch Time from max_chan_switch_time info_element
 * which is parsed from scan_entry.
 *
 * @mcst_ie - Pointer to max_chan_switch_time ie structure variable which contains
 *             the Maximum channel switch time.
 */
uint32_t ieee80211_get_max_chan_switch_time(struct ieee80211_max_chan_switch_time_ie *mcst_ie);

int ieee80211_parse_tspecparams(struct ieee80211vap *vap, u_int8_t *frm);
u_int8_t ieee80211_parse_mpdudensity(u_int32_t mpdudensity);

/*
 * ieee80211_parse_htcap:
 * Parse HT capability IEs from Rx management frames.
 *
 * Parameters:
 * @ni: Pointer to the peer node structure
 * @ie: Pointer to the IE buffer
 * @peer_update_required: Pointer to the peer_update_required flag
 * NOTE: peer_update_required is to be checked only once the caps have been
 * updated in the peer node's structure.
 *
 * Return:
 * 1: Success
 * 0: Failure
 */
int ieee80211_parse_htcap(struct ieee80211_node *ni, u_int8_t *ie, bool *peer_update_required);
void ieee80211_parse_htinfo(struct ieee80211_node *ni, u_int8_t *ie);

int ieee80211_parse_wpa(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
int ieee80211_parse_rsn(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
int ieee80211_parse_timeieparams(struct ieee80211vap *vap, u_int8_t *frm);

void ieee80211_process_athextcap_ie(struct ieee80211_node *ni, u_int8_t *ie);

/*
 * ieee80211_parse_vhtcap:
 * Parse VHT capability IEs from Rx management frames.
 *
 * Parameters:
 * @ni: Pointer to the peer node structure
 * @ie: Pointer to the IE buffer
 * @peer_update_required: Pointer to the peer_update_required flag
 * NOTE: peer_update_required is to be checked only once the caps have been
 * updated in the peer node's structure.
 *
 * Return:
 * None
 */
void ieee80211_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie, bool *peer_update_required);
int ieee80211_check_mu_client_cap(struct ieee80211_node *ni, u_int8_t *ie);
void ieee80211_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t *htinfo_ie);
void ieee80211_parse_opmode(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);
void ieee80211_parse_opmode_notify(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);
void ieee80211_parse_extcap(struct ieee80211_node *ni, uint8_t *ie);
void ieee80211_add_opmode(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype);
u_int8_t *ieee80211_add_addba_ext(u_int8_t *frm, struct ieee80211vap *vap,
                                    u_int8_t he_frag);
u_int8_t *ieee80211_add_opmode_notify(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype);
int ieee80211_process_asresp_elements(struct ieee80211_node *ni,
                                  u_int8_t *frm,
                                  u_int32_t ie_len);
void ieee80211_prepare_qosnulldata(struct ieee80211_node *ni, wbuf_t wbuf, int ac);

int ieee80211_send_qosnulldata(struct ieee80211_node *ni, int ac, int pwr_save);
int ieee80211_send_qosnull_probe(struct ieee80211_node *ni, int ac, int pwr_save, void *wifiposdata);
int ieee80211_send_null_probe(struct ieee80211_node *ni, int pwr_save, void *wifiposdata);

int ieee80211_send_nulldata(struct ieee80211_node *ni, int pwr_save);

int ieee80211_send_cts(struct ieee80211_node *ni, int flags);

int ieee80211_send_probereq(struct ieee80211_node *ni,
                            const u_int8_t        *sa,
                            const u_int8_t        *da,
                            const u_int8_t        *bssid,
                            const u_int8_t        *ssid,
                            const u_int32_t       ssidlen,
                            const void            *optie,
                            const size_t          optielen);

int ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                            const void            *optie,
                            const size_t          optielen,
                            struct ieee80211_framing_extractx *extractx);

int ieee80211_send_auth( struct ieee80211_node *ni, u_int16_t seq,
                         u_int16_t status, u_int8_t *challenge_txt,
                         u_int8_t challenge_len,
                         struct ieee80211_app_ie_t *appie);
int ieee80211_send_deauth(struct ieee80211_node *ni, u_int16_t reason);
int ieee80211_send_injector_frame_deauth(struct ieee80211vap *vap, u_int8_t *dstmac, u_int16_t reason, uint8_t protected);
int ieee80211_inject_mgmt_frame(struct ieee80211vap *vap, u_int8_t subtype, u_int8_t protected, u_int8_t *dstmac);
int ieee80211_send_disassoc(struct ieee80211_node *ni, u_int16_t reason);
int ieee80211_send_disassoc_with_callback(struct ieee80211_node *ni, u_int16_t reason,
                                          wlan_vap_complete_buf_handler handler,
                                          void *arg);
int ieee80211_send_assoc(struct ieee80211_node *ni,
                         int reassoc, u_int8_t *prev_bssid);
int ieee80211_send_assocresp(struct ieee80211_node *ni,
                             u_int8_t reassoc, u_int16_t reason,
                             struct ieee80211_app_ie_t *optie);
wbuf_t ieee80211_setup_assocresp(struct ieee80211_node *ni, wbuf_t wbuf,
                                 u_int8_t reassoc, u_int16_t reason,
                                 struct ieee80211_app_ie_t *optie);
void ieee80211_process_external_radar_detect(struct ieee80211_node *ni,
                                             bool is_nol_ie_recvd,
                                             bool is_rcsa_ie_recvd);
bool ieee80211_process_nol_ie_bitmap(struct ieee80211_node *ni,
                                     struct vendor_add_to_nol_ie *nol_el);
wbuf_t ieee80211_getmgtframe(struct ieee80211_node *ni, int subtype, u_int8_t **frm, u_int8_t isboardcast);
int ieee80211_send_mgmt(struct ieee80211vap *vap,struct ieee80211_node *ni, wbuf_t wbuf, bool force_send);

int ieee80211_is_robust_action_frame(u_int8_t category);
int ieee80211_send_action( struct ieee80211_node *ni,
                           struct ieee80211_action_mgt_args *actionargs,
                           struct ieee80211_action_mgt_buf  *actionbuf );

int ieee80211_recv_mgmt(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs);
#ifdef  ATH_HTC_MII_RXIN_TASKLET
void ieee80211_recv_mgmt_defer(void *arg);
#endif

int ieee80211_recv_ctrl(struct ieee80211_node *ni, wbuf_t wbuf,
						int subtype, struct ieee80211_rx_status *rs);

ieee80211_scan_entry_t ieee80211_update_beacon(struct ieee80211_node *ni, wbuf_t wbuf,
                                               struct ieee80211_frame *wh, int subtype,
                                               struct ieee80211_rx_status *rs);

void ieee80211_reset_erp(struct ieee80211com *,
                         enum ieee80211_phymode,
                         enum ieee80211_opmode);
void ieee80211_set_shortslottime(struct ieee80211com *, int onoff);
void ieee80211_set_protmode(struct ieee80211com *);


void ieee80211_dump_pkt(struct wlan_objmgr_pdev *pdev,
                   const u_int8_t *buf, int len, int rate, int rssi);
void ieee80211_change_cw(struct ieee80211com *ic);


struct ieee80211_beacon_offsets;
#if UMAC_SUPPORT_WNM
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                        int mcast, u_int32_t nfmsq_mask);
int
ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                        int mcast, u_int32_t nfmsq_mask);
#else
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                        int mcast);
int
ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                        int mcast);
#endif

void ieee80211_send_chanswitch_complete_event(struct ieee80211com *ic);
wbuf_t ieee80211_beacon_alloc(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo);
wbuf_t ieee80211_prb_rsp_alloc_init(struct ieee80211_node *ni,
                                    struct ieee80211_beacon_offsets *bo);

bool ieee80211_is_cac_required_in_rep_ap(
        struct ieee80211vap *vap,
        struct ieee80211_ath_channel *c);

void ieee80211_mbssid_del_profile(struct ieee80211vap *vap);
#if OBSS_PD
void ieee80211_sr_ie_reset(struct ieee80211vap *vap);
#endif /* OBSS PD */

u_int32_t ieee80211_construct_shortssid(u_int8_t *ssid, u_int8_t ssid_len);

struct ieee80211_bcn_prb_info;

/* Beacon template update APIs per vdev and pdev */
void wlan_vdev_beacon_update(struct ieee80211vap *vap);
void wlan_pdev_beacon_update(struct ieee80211com *ic);

/*
 * Return the size of the 802.11 header for a management or data frame.
 */
INLINE static int
ieee80211_hdrsize(const void *data)
{
    const struct ieee80211_frame *wh = (const struct ieee80211_frame *)data;
    int size = sizeof(struct ieee80211_frame);

    /* NB: we don't handle control frames */
    KASSERT((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL,
            ("%s: control frame", __func__));
    if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
        size += QDF_MAC_ADDR_SIZE;

    if (IEEE80211_QOS_HAS_SEQ(wh)){
        size += sizeof(u_int16_t);
#ifdef ATH_SUPPORT_TxBF
        /* Qos frame with Order bit set indicates an HTC frame */
        if (wh->i_fc[1] & IEEE80211_FC1_ORDER) {
            size += sizeof(struct ieee80211_htc);
        }
#endif
    }
    return size;
}

/*
 * Like ieee80211_hdrsize, but handles any type of frame.
 */
static INLINE int
ieee80211_anyhdrsize(const void *data)
{
    const struct ieee80211_frame *wh = (const struct ieee80211_frame *)data;

    if ((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
        switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
            case IEEE80211_FC0_SUBTYPE_CTS:
            case IEEE80211_FC0_SUBTYPE_ACK:
                return sizeof(struct ieee80211_frame_ack);
        }
        return sizeof(struct ieee80211_frame_min);
    } else
        return ieee80211_hdrsize(data);
}

typedef struct wme_phyParamType {
    u_int8_t aifsn;
    u_int8_t logcwmin;
    u_int8_t logcwmax;
    u_int16_t txopLimit;
    u_int8_t acm;
} wmeParamType;

struct wmeParams {
    u_int8_t    wmep_acm;           /* ACM parameter */
    u_int8_t    wmep_aifsn;         /* AIFSN parameters */
    u_int8_t    wmep_logcwmin;      /* cwmin in exponential form */
    u_int8_t    wmep_logcwmax;      /* cwmax in exponential form */
    u_int16_t   wmep_txopLimit;     /* txopLimit */
    u_int8_t    wmep_noackPolicy;   /* No-Ack Policy: 0=ack, 1=no-ack */
};

#define IEEE80211_EXPONENT_TO_VALUE(_exp)  (1 << (u_int32_t)(_exp)) - 1

struct chanAccParams{
    /* XXX: is there any reason to have multiple instances of cap_info??? */
    u_int8_t            cap_info;                   /* U-APSD flag + ver. of the current param set */
    struct wmeParams    cap_wmeParams[WME_NUM_AC];  /* WME params for each access class */
};

struct ieee80211_wme_state {
    u_int32_t   wme_flags;
#define	WME_F_AGGRMODE          0x00000001              /* STATUS: WME agressive mode */
#define WME_F_BSSPARAM_UPDATED  0x00000010              /* WME params broadcasted to STAs was updated */

    u_int       wme_hipri_traffic;              /* VI/VO frames in beacon interval */
    u_int       wme_hipri_switch_thresh;        /* agressive mode switch thresh */
    u_int       wme_hipri_switch_hysteresis;    /* agressive mode switch hysteresis */

    struct chanAccParams    wme_wmeChanParams;  /* configured WME parameters applied to itself */
    struct chanAccParams    wme_wmeBssChanParams;   /* configured WME parameters broadcasted to STAs */
    struct chanAccParams    wme_chanParams;     /* channel parameters applied to itself */
    struct chanAccParams    wme_bssChanParams;  /* channel parameters broadcasted to STAs */

    /* update hardware tx params after wme state change */
    int	(*wme_update)(struct ieee80211com *, struct ieee80211vap *,
            bool muedca_enabled);
};

void ieee80211_wme_initparams(struct ieee80211vap *);
void ieee80211_wme_initparams_locked(struct ieee80211vap *);
void ieee80211_wme_updateparams(struct ieee80211vap *);
void ieee80211_wme_updateinfo(struct ieee80211vap *);
void ieee80211_wme_updateparams_locked(struct ieee80211vap *);
void ieee80211_wme_updateinfo_locked(struct ieee80211vap *);
void ieee80211_wme_initglobalparams(struct ieee80211com *ic);

struct muedcaParams {
    uint8_t     muedca_ecwmin;       /* CWmin in exponential form */
    uint8_t     muedca_ecwmax;       /* CWmax in exponential form */
    uint8_t     muedca_aifsn;       /* AIFSN parameter */
    uint8_t     muedca_acm;         /* ACM parameter */
    uint8_t     muedca_timer;       /* MU EDCA timer value */
};

#define IEEE80211_MUEDCA_STATE_ENABLE 1

struct ieee80211_muedca_state {
    uint8_t muedca_param_update_count;                  /* Count to track
                                                         * whenever a MUEDCA
                                                         * param is changed */
    uint8_t mu_edca_dynamic_state;                      /* HE Dynamic Algo state
                                                         * Bit 0 is enable/disable
                                                         * Bit 1 has state of dynamic
                                                         * selection active/non-active
                                                         * at run time
                                                         */
    struct muedcaParams muedca_paramList[MUEDCA_NUM_AC];/* MU EDCA param list
                                                         * for the different
                                                         * Access Categories */
};

void ieee80211_muedca_initparams(struct ieee80211vap *vap);
void ieee80211_muedca_initglobalparams(struct ieee80211com *ic);

/*
 * Beacon frames constructed by ieee80211_beacon_alloc
 * have the following structure filled in so drivers
 * can update the frame later w/ minimal overhead.
 */
struct ieee80211_beacon_offsets {
    u_int16_t   bo_tim_len; /* atim/dtim length in bytes */
    u_int16_t   bo_chanswitch_trailerlen;
    u_int16_t   bo_tim_trailerlen;    /* trailer length in bytes */
    u_int16_t   bo_mbssid_ie_len; /* MBSS IE length */
    u_int16_t   bo_ecsa_trailerlen;
    u_int16_t   bo_vhtchnsw_trailerlen; /* trailer length in bytes */
    u_int16_t   bo_bcca_trailerlen;
    u_int16_t   bo_whc_apinfo_len; /* WHC ap info element length */
    u_int16_t   bo_appie_buf_len;
    u_int16_t   bo_secchanoffset_trailerlen; /* number of bytes in beacon following bo_secchanoffset */
    u_int16_t   bo_mcst_trailerlen;
    u_int16_t   *bo_caps; /* 3. Capability Information */
    u_int8_t    *bo_rates; /* 5. Supported Rates */
    u_int8_t    *bo_cf_params; /* 7. CF Parameter Set */

    u_int8_t    *bo_tim; /* 9. Traffic indication map (TIM) */
    u_int8_t    *bo_tim_trailer; /* Tim trailer */

    u_int8_t    *bo_pwrcnstr; /* 11. Power constraint */

    u_int8_t    *bo_chanswitch; /* 12. Channel Switch Announcement */

    u_int8_t    *bo_quiet; /* 13. Quiet */

    u_int8_t    *bo_tpcreport; /* 14. TPC Report */
    u_int8_t    *bo_erp; /* 15. ERP */
    u_int8_t    *bo_xrates; /* 16.Extended Supported Rates */
    u_int8_t    *bo_rsn; /* 17. RSN */
    u_int8_t    *bo_qbssload; /* 18. QBSS Load */
    u_int8_t    *bo_edca; /* 19. EDCA Parameter Set */
    u_int8_t    *bo_qos_cap; /* 20. QoS Capability */
    u_int8_t    *bo_ap_chan_rpt; /* 21. AP Channel Report */
    u_int8_t    *bo_bss_avg_delay; /* 22. BSS Average Access Delay */
    u_int8_t    *bo_antenna; /* 23. Antenna */
    u_int8_t    *bo_bss_adm_cap; /* 24. BSS Available Admission Capacity */
#if !ATH_SUPPORT_WAPI
    u_int8_t    *bo_bss_ac_acc_delay; /* 25. BSS AC Access Delay */
#endif
    u_int8_t    *bo_msmt_pilot_tx; /* 26. Measurement Pilot Transmissions */

    u_int8_t    *bo_mbssid_ie; /* 27. Multiple BSSID */

    u_int8_t    *bo_rrm; /* 28. RM Enabled Capabilities (RRM) */
    u_int8_t    *bo_mob_domain; /* 29. Mobility domain */
    u_int8_t    *bo_dse_reg_loc; /* 30. DSE Registered Location */

    u_int8_t    *bo_ecsa; /* 31. Extended Channel Switch Announcement */

    u_int8_t    *bo_opt_class; /* 32. Supported Operating Classes */
    u_int8_t    *bo_htcap; /* 33. HT Capabilities */
    u_int8_t    *bo_htinfo; /* 34. HT Info/Opertaion */
    u_int8_t    *bo_2040_coex; /* 35. 20/40 BSS Coexistence */
    u_int8_t    *bo_obss_scan; /* 36. Overlapping BSS Scan Parameters */
    u_int8_t    *bo_extcap; /* 37. Extended Capabilities */

    u_int8_t    *bo_chan_usage; /* Channel Usage (Probe response) */
    u_int8_t    *bo_time_zone; /* Time Zone (Probe response) */

#if UMAC_SUPPORT_WNM
    u_int16_t   bo_fms_len; /* FMS desc length in bytes */
    u_int16_t   bo_fms_trailerlen; /* FMS desc trailer length in bytes */
    u_int8_t    *bo_fms_desc; /* 38. FMS Descriptor */
    u_int8_t    *bo_fms_trailer; /* FMS desc trailer */
#endif

    u_int8_t    *bo_qos_traffic; /* 39. QoS Traffic Capability */
    u_int8_t    *bo_time_adv; /* 40. Time Advertisement */
    u_int8_t    *bo_interworking; /* 41. Interworking */
    u_int8_t    *bo_adv_proto; /* 42. Advertisement protocol */
    u_int8_t    *bo_roam_consortium; /* 43. Roaming consortium */
    u_int8_t    *bo_emergency_id; /* 44. Emergency Alert Identifier */
    u_int8_t    *bo_mesh_id; /* 45. Mesh ID */
    u_int8_t    *bo_mesh_conf; /* 46. Mesh Configuration */
    u_int8_t    *bo_mesh_awake_win; /* 47. Mesh Awake window */
    u_int8_t    *bo_beacon_time; /* 48. Beacon Timing */
    u_int8_t    *bo_mccaop_adv_ov; /* 49. MCCAOP Advertisement Overview */
    u_int8_t    *bo_mccaop_adv; /* 50. MCCAOP Advertisement */
    u_int8_t    *bo_mesh_cs_param; /* 51. Mesh Channel Switch Parameters */
    u_int8_t    *bo_qmf_policy; /* 52. QMF Policy */
    u_int8_t    *bo_qload_rpt; /* 53. QLoad Report */
    u_int8_t    *bo_hcca_upd_cnt; /* 54. HCCA TXOP Update Count */
    u_int8_t    *bo_multiband; /* 55. Multi-band */

    u_int8_t    *bo_dmg_cap; /* DMG Capabilities (Probe response) */
    u_int8_t    *bo_dmg_op; /* DMG Operation (Probe response) */
    u_int8_t    *bo_mul_mac_sub; /* Multiple MAC Sublayers (Probe response) */
    u_int8_t    *bo_ant_sec_id; /* Antenna Sector ID Pattern (Probe response) */

    u_int8_t    *bo_vhtcap; /* 56. VHT capability element */
    u_int8_t    *bo_vhtop; /* 57. VHT operational element */
    u_int8_t    *bo_vhttxpwr; /* 58. VHT Tx power Envelope element */

    u_int8_t    *bo_vhtchnsw; /* 59. VHT Channel switch wrapper element */

    u_int8_t    *bo_ext_bssload; /* 60. Extended BSS Load element */
    u_int8_t    *bo_quiet_chan; /* 61. Quiet Channel */
    u_int8_t    *bo_opt_mode_note; /* 62. Operating Mode Notification */
    u_int8_t    *bo_rnr; /* 63. Reduced Neighbor Report */
    u_int8_t    *bo_rnr2; /*63. Reduced neighbor report 2nd IE */
    u_int8_t    *bo_tvht; /* 64. TVHT Operation */

#if QCN_ESP_IE
    u_int8_t    *bo_esp_ie; /* 65. Estimated Service Parameters */
    u_int16_t   bo_esp_ie_len; /* Lenght of ESP */
#endif

    u_int8_t    *bo_relay_cap; /* Relay Capabilities (Probe Response) */

    u_int8_t    *bo_future_chan; /* 66. Future Channel Guidance */
    u_int8_t    *bo_cag_num; /* 67. Common Advertisement Group (CAG) Number */
    u_int8_t    *bo_fils_ind; /* 68. FILS Indication */
    u_int8_t    *bo_ap_csn; /* 69. AP-CSN */
    u_int8_t    *bo_diff_init_lnk; /* 70. Differentiated Initial Link Setup */

    u_int8_t    *bo_rps; /* RPS (Probe response) */
    u_int8_t    *bo_page_slice; /* Page Slice (Probe Response) */
    u_int8_t    *bo_chan_seq; /* Channel Sequence (Probe response) */
    u_int8_t    *bo_tsf_timer_acc; /* TSF Timer Accuracy (Probe response) */
    u_int8_t    *bo_s1g_relay_disc; /* S1G Relay Discovery (Probe response) */
    u_int8_t    *bo_s1g_cap; /* S1G Capabilities (Probe response) */
    u_int8_t    *bo_s1g_op; /* S1G Operation (Probe response) */
    u_int8_t    *bo_mad; /* MAD (Probe response) */
    u_int8_t    *bo_short_bcn_int; /* Short Beacon Interval (Probe response) */
    u_int8_t    *bo_s1g_openloop_idx; /* S1G Open-loop Link Margin Index (Probe response) */
    u_int8_t    *bo_s1g_relay; /* S1G Relay (Probe response) */
    u_int8_t    *bo_cdmg_cap; /* CDMG Capabilities (Probe response) */
    u_int8_t    *bo_ext_cluster_rpt; /* Extended Cluster Report (Probe response) */
    u_int8_t    *bo_cmmg_cap; /* CMMG Capabilities (Probe response) */
    u_int8_t    *bo_cmmg_op; /* CMMG Operation (Probe response) */

    u_int8_t    *bo_service_hint; /* 73. Service Hint */
    u_int8_t    *bo_service_hash; /* 74. Service Hash */
    u_int8_t    *bo_mbssid_config; /* 76. MBSSID Config */
    u_int8_t    *bo_hecap; /* 77. HE Capabilities */
    u_int8_t    *bo_heop; /* 78. HE Operation */
    u_int8_t    *bo_twt; /* 79. TWT */

#if ATH_SUPPORT_UORA
    u_int8_t    *bo_uora_param; /* 80. UORA Parameter Set */
#endif

    u_int8_t    *bo_bcca; /* 81. BSS Color Change Announcement*/

#if OBSS_PD
    u_int8_t    *bo_srp_ie; /* 82. Spatial Reuse Parameter (SRP) set */
    u_int16_t   bo_srp_ie_len; /* SRP_IE length */
#endif

    u_int8_t    *bo_muedca; /* 83. MU EDCA parameter set */
    u_int8_t    *bo_ess_rpt; /* 84. ESS Report */
    u_int8_t    *bo_ndp_rpt_param; /* 85. NDP Feedback Report Parameter */
    u_int8_t    *bo_he_bss_load; /* 86. HE BSS Load */
    u_int8_t    *bo_he_6g_bandcap; /* 87. HE 6GHz Band Capability element */

    u_int8_t    *bo_mcst; /* Max Chan Switch Time */

    u_int8_t    *bo_secchanoffset; /* Secondary Channel Offset element */

    u_int8_t    *bo_rsnx; /* RSNX element */

    u_int8_t    *bo_htinfo_vendor_specific; /* LAST. vendor specific HT Info element */

    u_int8_t    *bo_appie_buf; /* LAST. APP IE buf */

    u_int8_t    *bo_ath_caps; /* LAST. Ath caps */
    u_int8_t    *bo_interop_vhtcap; /* LAST. VHT Interop capability element */

    u_int8_t    *bo_xr; /* LAST. xr element (SON) */
    u_int8_t    *bo_whc_apinfo; /* LAST. WHC ap info element (SON) */

    u_int8_t    *bo_bwnss_map; /* LAST. Bandwidth NSS map element */
    u_int8_t    *bo_apriori_next_channel; /* LAST. Next channel element */
    u_int8_t    *bo_software_version_ie; /* LAST. Software version ie */
    u_int8_t    *bo_mbo_cap; /* LAST. MBO capability */

#if QCN_IE
    u_int8_t    *bo_qcn_ie; /* LAST. QCN info element(vendor IE) */
    u_int16_t   bo_qcn_ie_len; /* QCN info element length */
#endif

    u_int8_t    *bo_extender_ie; /* LAST. Extender ie info element(vendor IE) */
    u_int8_t    *bo_wme; /* LAST. WME parameters */

    u_int8_t    *bo_htinfo_pre_ana; /* pre ana HT Info element */
    u_int8_t    *bo_generic_vendor_capabilities; /* generic vendor capabilities IE */
};

struct ieee80211_bcn_prb_info {
    u_int16_t	caps;		/* capabilities */
    u_int8_t    erp;            /* ERP */
    /* TBD: More elements to follow */
};

struct ieee80211_bwnss_map {
    u_int8_t bw_nss_160; /* Tx NSS for 160/80+80 MHz */
    u_int8_t bw_rxnss_160; /* Rx NSS for 160/80+80 MHz */
    u_int8_t bw_nss_80; /* Rx NSS for 160/80+80 MHz */
    /* TODO: SADFS need to added by DFS module */
#define IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW    0x01 /* NSS used for all available BW will be same */
#define IEEE80211_NSSMAP_1_2_FOR_160_AND_80_80  0x02 /* NSS used for 160 & 80 MHz BW will be half of max nss  */
#define IEEE80211_NSSMAP_3_4_FOR_160_AND_80_80  0x03 /* NSS used for 160 & 80 MHz BW will be 3/4th of max nss */
    u_int8_t flag; /* flag to indicate ext nss special cases */
};

/* XXX exposed 'cuz of beacon code botch */
u_int8_t *ieee80211_add_rates(struct ieee80211vap *, u_int8_t *, const struct ieee80211_rateset *);
u_int8_t *ieee80211_add_xrates(struct ieee80211vap *, u_int8_t *, const struct ieee80211_rateset *);
u_int8_t *ieee80211_add_ssid(u_int8_t *frm, const u_int8_t *ssid, u_int len);
u_int8_t *ieee80211_add_erp(u_int8_t *, struct ieee80211com *);
u_int8_t *ieee80211_add_athAdvCap(u_int8_t *, u_int8_t, u_int16_t);
u_int8_t *ieee80211_add_athextcap(u_int8_t *, u_int16_t, u_int8_t);


u_int8_t *ieee80211_add_wmeinfo(u_int8_t *frm, struct ieee80211_node *ni,
                                u_int8_t wme_subtype, u_int8_t *wme_info, u_int8_t info_len);
u_int8_t *ieee80211_add_timeout_ie(u_int8_t *frm, struct ieee80211_node *ni,
                                size_t ie_len, u_int32_t tsecs);
u_int8_t *ieee80211_add_wme_param(u_int8_t *, struct ieee80211_wme_state *,
								  int uapsd_enable);
u_int8_t *ieee80211_add_muedca_param(u_int8_t *,
                                    struct ieee80211_muedca_state *);

#if ATH_SUPPORT_UORA
u_int8_t *ieee80211_add_uora_param(u_int8_t *, u_int8_t);
#endif

u_int8_t *ieee80211_add_country(u_int8_t *, struct ieee80211vap *vap);
u_int8_t *ieee80211_add_doth(u_int8_t *frm, struct ieee80211vap *vap);
u_int8_t *ieee80211_add_htcap(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htcap_pre_ana(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htcap_vendor_specific(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htinfo(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_htinfo_pre_ana(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_htinfo_vendor_specific(u_int8_t *, struct ieee80211_node *);
void ieee80211_update_htinfo_cmn(struct ieee80211_ie_htinfo_cmn *ie, struct ieee80211_node *ni);
void ieee80211_update_obss_scan(struct ieee80211_ie_obss_scan *, struct ieee80211_node *);
u_int8_t *ieee80211_add_obss_scan(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_extcap(u_int8_t *, struct ieee80211_node *, uint8_t subtype);
u_int8_t *ieee80211_add_bw_nss_maping(u_int8_t *frm, struct ieee80211_bwnss_map *bw_nss_mapping);
u_int8_t *ieee80211_add_next_channel(u_int8_t *frm, struct ieee80211_node *ni, struct ieee80211com *ic, int subtype);
u_int8_t *ieee80211_add_sw_version_ie(u_int8_t *frm, struct ieee80211com *ic);
u_int8_t *ieee80211_add_generic_vendor_capabilities_ie(u_int8_t *frm, struct ieee80211com *ic);
u_int8_t *ieee80211_add_tpc_ie(u_int8_t *, struct ieee80211vap *vap, uint8_t subtype);
void ieee80211_adjust_bos_for_bsscolor_change_ie(
        struct ieee80211_beacon_offsets *bo, uint8_t offset);
uint8_t *ieee80211_mbss_add_profile(u_int8_t *frm, struct ieee80211_mbss_ie_cache_node *node,
                                    const struct ieee80211com *ic,
                                    uint16_t offset, u_int8_t subtype);

#if ATH_SUPPORT_HS20
u_int8_t *ieee80211_add_qosmapset(u_int8_t *frm, struct ieee80211_node *);
#endif
void ieee80211_add_capability(u_int8_t * frm, struct ieee80211_node *ni);

#if OBSS_PD
uint8_t *ieee80211_add_srp_ie(struct ieee80211vap *vap, uint8_t *frm);
void ieee80211_parse_srpie(struct ieee80211_node *ni, u_int8_t *ie);
#endif

u_int8_t *ieee80211_setup_rsn_ie(struct ieee80211vap *vap, u_int8_t *ie);
u_int8_t *ieee80211_setup_wpa_ie(struct ieee80211vap *vap, u_int8_t *ie);
#if ATH_SUPPORT_WAPI
u_int8_t *ieee80211_setup_wapi_ie(struct ieee80211vap *vap, u_int8_t *ie);
int ieee80211_parse_wapi(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
#endif

void osif_restart_start_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
void ieee80211_build_countryie(struct ieee80211vap *vap, uint8_t *country_iso);

struct ieee80211_ath_channel * ieee80211_get_new_sw_chan (
            struct ieee80211_node *ni, struct ieee80211_ath_channelswitch_ie *chanie,
            struct ieee80211_extendedchannelswitch_ie *echanie, struct ieee80211_ie_sec_chan_offset *secchanoffsetie,
            struct ieee80211_ie_wide_bw_switch *widebwie,
            u_int8_t *cswarp
);

void ieee80211_dfs_proc_cac(struct ieee80211com *ic);

int ieee80211_dfs_action(struct ieee80211vap *vap,
                         struct ieee80211_ath_channelswitch_ie *pcsaie,
                         bool chan_failure);

void ieee80211_bringup_ap_vaps(struct ieee80211com *ic);

int ieee80211_process_csa_ecsa_ie( struct ieee80211_node *ni, struct ieee80211_action *pia, uint32_t frm_len);

u_int8_t * ieee80211_add_mmie(struct ieee80211vap *vap, u_int8_t *bfrm, u_int32_t len);
u_int8_t * ieee80211_add_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx,
                     u_int8_t *macaddr);
u_int8_t * ieee80211_add_interop_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype);
u_int8_t * ieee80211_add_vhtop(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx);
u_int8_t *
ieee80211_add_tpe_info(u_int8_t *frm, u_int8_t count, u_int8_t interpretation,
                        u_int8_t category, u_int8_t *tx_pwr);
u_int8_t *
ieee80211_add_lower_band_tpe(u_int8_t *frm, struct ieee80211com *ic,
                                struct ieee80211_ath_channel *channel);
u_int8_t *
ieee80211_add_6g_tpe(u_int8_t *frm, struct ieee80211com *ic,
                    struct ieee80211vap *vap,
                    struct ieee80211_ath_channel *channel,
                    u_int8_t client_type);
int8_t ieee80211_get_tpe_count(u_int8_t txpwr_intrpt, u_int8_t txpwr_cnt);
u_int8_t *
ieee80211_add_vht_txpwr_envlp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t is_subelement);
u_int8_t *
ieee80211_add_chan_switch_wrp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t extchswitch);

void ieee80211_add_max_chan_switch_time(struct ieee80211vap *vap, uint8_t *frm);

u_int8_t * ieee80211_add_mbssid_config(struct ieee80211vap *vap,
                    uint8_t subtype, uint8_t *frm);

u_int8_t * ieee80211_add_hecap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype);

u_int8_t * ieee80211_add_6g_bandcap(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic, u_int8_t subtype);

u_int8_t * ieee80211_add_heop(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx);

void
ieee80211_add_he_bsscolor_change_ie(struct ieee80211_beacon_offsets *bo,
                     wbuf_t wbuf, struct ieee80211_node *ni,
                     uint8_t subtype, int *len_changed);
#if SUPPORT_11AX_D3
uint8_t ieee80211_get_he_bsscolor_info(struct ieee80211vap *vap);
uint32_t ieee80211_get_heop_param(struct ieee80211vap *vap);
#else
struct he_op_param ieee80211_get_heop_param(struct ieee80211vap *vap);
#endif

void ieee80211_update_basic_bss_mcs_nss_req(struct ieee80211_node *ni, u_int8_t *ie);

void ieee80211_parse_hecap(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);

void ieee80211_parse_he_6g_bandcap(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);

void ieee80211_parse_heop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype, uint8_t *update_beacon);

struct heop_6g_param * ieee80211_get_he_6g_opinfo(struct ieee80211_ie_heop *heop);

void
ieee80211_add_6g_op_info(uint8_t *opinfo_6g, struct ieee80211_node *ni, struct ieee80211com *ic);

uint32_t ieee80211_add_mbss_ie(uint8_t *frm, struct ieee80211_node *ni, uint8_t frm_subtype,
                               bool is_broadcast_req, void *optie);

#if WLAN_SUPPORT_MSCS
int ieee80211_parse_mscs_ie(struct ieee80211_node *ni, struct ieee80211_mscs_descriptor *mscs_ie);
u_int8_t* ieee80211_add_mscs_ie(struct ieee80211_mscs_data *mscs_control_data, u_int8_t *frm);
#endif
int ieee80211_parse_tclas_mask_elem(struct ieee80211_mscs_data *mscs_tuple, struct ieee80211_tclas_mask_elem *tclas_mask, u_int8_t request_type);
void ieee80211_process_pwrcap_ie(struct ieee80211_node *ni, u_int8_t *ie);
void ieee80211_process_supp_chan_ie(struct ieee80211_node *ni, u_int8_t *ie);
#if ATH_SUPPORT_CFEND
wbuf_t ieee80211_cfend_alloc(struct ieee80211com *ic);
#endif
/* unaligned little endian access */
#ifndef LE_READ_1
#define LE_READ_1(p)                            \
    ((u_int8_t)                                 \
    ((((const u_int8_t *)(p))[0]      )))
#endif

#ifndef LE_READ_2
#define LE_READ_2(p)                            \
    ((u_int16_t)                                \
    ((((const u_int8_t *)(p))[0]      ) |       \
    (((const u_int8_t *)(p))[1] <<  8)))
#endif

#ifndef LE_READ_4
#define LE_READ_4(p)                            \
    ((u_int32_t)                                \
    ((((const u_int8_t *)(p))[0]      ) |       \
    (((const u_int8_t *)(p))[1] <<  8) |        \
    (((const u_int8_t *)(p))[2] << 16) |        \
    (((const u_int8_t *)(p))[3] << 24)))
#endif

#ifndef BE_READ_4
#define BE_READ_4(p)                            \
    ((u_int32_t)                                \
     ((((const u_int8_t *)(p))[0] << 24) |      \
      (((const u_int8_t *)(p))[1] << 16) |      \
      (((const u_int8_t *)(p))[2] <<  8) |      \
      (((const u_int8_t *)(p))[3]      )))
#endif

__inline static int
iswpaoui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((WPA_OUI_TYPE<<24)|WPA_OUI)));
}
__inline static int
isatheros_extcap_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_EXTCAP_TYPE<<24)|ATH_OUI)));
}

__inline static int
isdedicated_cap_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((DEDICATE_OUI_CAP_TYPE<<24)|DDT_OUI)));
}

__inline static int
isbwnss_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_BW_NSS_MAP_TYPE<<24)|ATH_OUI)));
}

INLINE static int
isatherosoui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_TYPE<<24)|ATH_OUI)));
}

#if QCN_IE
INLINE static int
isqcn_oui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCN_OUI_TYPE<<24)|QCA_OUI)));

}
INLINE static int
isfils_req_parm(u_int8_t *frm)
{
    /* For FILS Request Parameters Element ID extension is 0x02 */
    return ((frm[1] > 2) && (LE_READ_1(frm+2) == 0x02));

}
#endif

INLINE static int
is_next_channel_oui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCA_OUI_NC_TYPE<<24)|QCA_OUI)));
}

INLINE static int
iswmeoui(u_int8_t *frm, u_int8_t wme_subtype)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
               (*(frm+6) == wme_subtype));
}
INLINE static int
ismbooui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((MBO_OUI_TYPE<<24)|MBO_OUI)));
}

INLINE static int
iswmeparam(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_PARAM_OUI_SUBTYPE));
}

INLINE static int
isinterop_vht(u_int8_t *frm)
{
    return ((frm[1] > 12) && (BE_READ_4(frm+2) == ((VHT_INTEROP_OUI << 8)|VHT_INTEROP_TYPE)) &&
        ((*(frm + 6) == VHT_INTEROP_OUI_SUBTYPE) || (*(frm + 6) == VHT_INTEROP_OUI_SUBTYPE_VENDORSPEC)));
}

/* STNG TODO: move ieee80211_p2p_proto.h out of umac\p2p directory and into this directory. Then we can
 * include ieee80211_p2p_proto.h file instead of defining here */
#ifndef  IEEE80211_P2P_WFA_OUI
  #define IEEE80211_P2P_WFA_OUI     { 0x50,0x6f,0x9a }
#endif
#ifndef  IEEE80211_P2P_WFA_VER
  #define IEEE80211_P2P_WFA_VER     0x09                 /* ver 1.0 */
#endif
#define IEEE80211_WSC_OUI       { 0x00,0x50,0xF2 }      /* Microsoft WSC OUI bytes */

INLINE static int
isp2poui(const u_int8_t *frm)
{
    const u_int8_t      wfa_oui[3] = IEEE80211_P2P_WFA_OUI;

    return ((frm[1] >= 4) &&
            (frm[2] == wfa_oui[0]) &&
            (frm[3] == wfa_oui[1]) &&
            (frm[4] == wfa_oui[2]) &&
            (frm[5] == IEEE80211_P2P_WFA_VER));
}

INLINE static int
iswmeinfo(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_INFO_OUI_SUBTYPE));
}
INLINE static int
iswmetspec(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_TSPEC_OUI_SUBTYPE));
}

INLINE static int
ishtcap(u_int8_t *frm)
{
    return ((frm[1] > 3) && (BE_READ_4(frm+2) == ((VENDOR_HT_OUI<<8)|VENDOR_HT_CAP_ID)));
}

INLINE static int
iswpsoui(const u_int8_t *frm)
{
    return frm[1] > 3 && BE_READ_4(frm+2) == WSC_OUI;
}


INLINE static int
ishtinfo(u_int8_t *frm)
{
    return ((frm[1] > 3) && (BE_READ_4(frm+2) == ((VENDOR_HT_OUI<<8)|VENDOR_HT_INFO_ID)));
}

INLINE static int
isssidl(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((SSIDL_OUI_TYPE<<24)|WPS_OUI)));
}

INLINE static int
issfaoui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((SFA_OUI_TYPE<<24)|SFA_OUI)));
}

INLINE static int
iswcnoui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((WCN_OUI_TYPE<<24)|WCN_OUI)));
}

int  ieee80211_intersect_extnss_160_80p80(struct ieee80211_node *ni);
u_int8_t extnss_160_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
u_int8_t  retrieve_seg2_for_extnss_80p80(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
u_int8_t extnss_80p80_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
bool ext_nss_160_supported(u_int32_t *vhtcap);
bool ext_nss_80p80_supported(u_int32_t *vhtcap);
bool validate_extnss_vhtcap(u_int32_t *vhtcap);
bool peer_ext_nss_capable(struct ieee80211_ie_vhtcap * vhtcap);
#if DBDC_REPEATER_SUPPORT
u_int8_t *ieee80211_add_extender_ie(struct ieee80211vap *vap, ieee80211_frame_type ftype, u_int8_t *frm);
void ieee80211_process_extender_ie(struct ieee80211_node *ni, const u_int8_t *ie, ieee80211_frame_type ftype);
#endif
uint8_t *ieee80211_mgmt_add_chan_switch_ie(uint8_t *frm, struct ieee80211_node *ni,
                uint8_t subtype, uint8_t chanchange_tbtt);

/* Copy source to destination in-memory and advance destination "size" bytes,
 * and update the "len" variable
 */
#define IE_MEM_COPY_MOVE_DESTN_UPD_LEN(dest, src, size, len) ({\
            qdf_mem_copy(dest, src, size);\
            dest += size;\
            len += size;\
        })

/**
 * ieee80211_add_or_retrieve_ie_from_app_opt_ies: Add all vendor IEs
 *                                                or Retrieve an IE from the IE buffer or list
 *
 * @vap       : logical representation of Virtual Access Point
 * @ftype     : Type of frame to which IEs are to be added
 * @element_id: Element ID of the IE to be added
 * @sub_id    : Second level ID for Extension IEs
 *              For Vendor IEs:
 *                  0 for all Vendor IEs
 *                  1 for WPA
 * @frm       : Address of frm pointer to add IEs in-place
 * @type      : Type of buffer from which IEs are added
 * @optie     : Opt IE Buffer passed to ieee80211_send_assocresp
 * @retrieve  : true if specific IE is to be added,
 *              false if multiple IEs (vendor) to be added
 *
 * Return: the number of bytes (length) frm has moved
 */
uint8_t ieee80211_add_or_retrieve_ie_from_app_opt_ies(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, uint8_t element_id, uint8_t sub_id,
        uint8_t **frm, uint8_t type, struct ieee80211_app_ie_t *optie, bool retrieve);

/*
 * Note: Do NOT call this function directly without VAP lock. This function is
 * an internal function called by ieee80211_add_or_retrieve_ie_from_app_opt_ies
 * with proper locks
 */
uint8_t __ieee80211_add_or_retrieve_ie_from_app_opt_ies(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, uint8_t element_id, uint8_t sub_id,
        uint8_t **frm, uint8_t type, bool retrieve);
/*
 * ieee80211_prb_add_rsn_ie: Add RSN IE in the frame
 * @vap   : VAP handle
 * @frm   : frm pointer to add the IE
 * @po    : Probe offsets to mark IEs' start address
 * @optie : Optional IE buffer (local buffer)
 *
 * Return: frm pointer after adding, if RSN IE is added,
 *         NULL elsewhere
 */
uint8_t *ieee80211_prb_add_rsn_ie(struct ieee80211vap *vap,
        uint8_t *frm, struct ieee80211_beacon_offsets **po,
        struct ieee80211_app_ie_t *optie);

/*
 * ieee80211_prb_add_vht_ies: Add VHT cap, op, power envelope, CS Wrapper
 *                        and EBSS load IEs in the frame
 *
 * @ni       : Node information handle
 * @frm      : frm pointer to add IEs
 * @macaddr  : MAC address of the STA
 * @extractx : Extra Context information
 * @po       : Probe offsets to mark IEs' start address
 *
 * Return: frm pointer after adding IEs
 */
uint8_t *ieee80211_prb_add_vht_ies(struct ieee80211_node *ni,
        uint8_t *frm, uint8_t *macaddr,
        struct ieee80211_framing_extractx *extractx,
        struct ieee80211_beacon_offsets **po);

#if QCA_SUPPORT_EMA_EXT
uint8_t *ieee80211_prb_adjust_pos_for_context(struct ieee80211com *ic,
        uint8_t *frm, struct ieee80211_beacon_offsets *po, uint16_t offset,
        ieee80211_ie_offset_context_t offset_context);

#define IEEE80211_ADJUST_FRAME_OFFSET(x, y, z) ({\
    if (x->y)\
        x->y += z;\
})

int ieee80211_check_and_add_tx_cmn_ie(struct ieee80211vap *vap, uint8_t *old_frm,
        uint8_t **frm, int32_t *remaining_space, ieee80211_frame_type ftype);
#endif

/*
 * @brief: Timer callback for OMN timer. Removes OMN IE from beacon.
 *
 * @data: Pointer to callback parameter
 */
void wlan_omn_timer_callback(void* data);

/*
 * @brief: Configure Operating Mode notification timer. Add the OMN IE
 *         to each VAP. Should be called from
 *         mode change state machine before updating VAP capabilities.
 * @ic: Pointer to ieee80211com
 */
int wlan_vap_omn_update(struct ieee80211com *ic);

/* Check if TxVAP common part size check enabled or not
 * Condition: If MBSSID enabled and EMA Ext feature enabled
 */
#define IS_MBSSID_EMA_EXT_ENABLED(ic) ((wlan_pdev_nif_feat_cap_get((ic)->ic_pdev_obj, \
                                                 WLAN_PDEV_F_MBSS_IE_ENABLE)) &&     \
                                            ((ic)->ic_mbss.ema_ext_enabled))

#define IEEE80211_IS_COUNTRYIE_AND_DOTH_ENABLED(ic, vap) \
    (IEEE80211_IS_COUNTRYIE_ENABLED(ic) && \
     ieee80211_vap_country_ie_is_set(vap) \
     && ieee80211_ic_doth_is_set(ic) && \
     (ic->ic_pdev_is_2ghz_supported(ic) || ieee80211_vap_doth_is_set(vap)))

#endif  /* end of _ATH_STA_IEEE80211_PROTO_H */
