/*
 *  Copyright (c) 2014,2020-2021 Qualcomm Innovation Center, Inc.
 *  All Rights Reserved
 *  Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 *  2014 Qualcomm Atheros, Inc.  All rights reserved.
 *
 *  Qualcomm is a trademark of Qualcomm Technologies Incorporated, registered in the United
 *  States and other countries.  All Qualcomm Technologies Incorporated trademarks are used with
 *  permission.  Atheros is a trademark of Qualcomm Atheros, Inc., registered in
 *  the United States and other countries.  Other products and brand names may be
 *  trademarks or registered trademarks of their respective owners.
 */

#ifndef _IEEE80211_RRM_H_
#define _IEEE80211_RRM_H_

#define IEEE80211_RRM_CHAN_MAX            255
#define IEEE80211_MAX_REQ_IE              255
#define IEEE80211_BCNREQUEST_VALIDSSID_REQUESTED   0x01
#define IEEE80211_BCNREQUEST_NULLSSID_REQUESTED    0x02
#define IEEE80211_MAX_NR_COUNTRY_CODE 3
#define IEEE80211_MAX_NR_MCS_SET     16
#define IEEE80211_NR_RM_CAP_LEN 5
#define IEEE80211_NR_HTOP_LEN 5

#define IEEE80211_RRM_NUM_CHANREQ_MAX 16
#define IEEE80211_RRM_NUM_CHANREP_MAX 2
#define IEEE80211_RRM_RPI_SIZE 8
#define IEEE80211_MAX_VENDOR_OUI 5
#define IEEE80211_MAX_VENDOR_BUF 32
#define IEEE80211_NUM_REGCLASS 5

/**
 * Number of RRM beacon reports in a single OTA message can be conveyed in
 * in single event up to user space. Multiple events will be sent if more
 * than this number of reports is included in a single OTA message.
 */
#define IEEE80211_RRM_NUM_BCNRPT_MAX 8

/**
 * Radio Resource Managmenet report types
 *
 * Note that these types are only used between user space and driver, and
 * not in sync with the OTA types defined in 802.11k spec.
 */
typedef enum {
    /* Indication of a beacon report. */
    RRM_TYPE_BCNRPT,
    RRM_TYPE_INVALID
} RRM_TYPE;

struct ieee80211_beaconreq_chaninfo {
    u_int8_t regclass;
    u_int8_t numchans;
    u_int8_t channum[IEEE80211_RRM_NUM_CHANREQ_MAX];
};

struct ieee80211_beaconreq_wb_chan {
    u_int8_t chan_width;
    u_int8_t centerfreq0;
    u_int8_t centerfreq1;
}__packed;

struct ieee80211_beaconreq_vendor {
    u_int8_t oui[IEEE80211_MAX_VENDOR_OUI];
    u_int8_t buf[IEEE80211_MAX_VENDOR_BUF];
};

typedef struct ieee80211_rrm_beaconreq_info_s {
#define MAX_SSID_LEN 32
    u_int16_t   num_rpt;
    u_int8_t    num_regclass;
    u_int8_t    regclass[IEEE80211_NUM_REGCLASS];
    u_int8_t    channum;
    u_int16_t   random_ivl;
    u_int16_t   duration;
    u_int8_t    reqmode;
    u_int8_t    reqtype;
    u_int8_t    bssid[6];
    u_int8_t    mode;
    u_int8_t    req_ssid;
    u_int8_t    rep_cond;
    u_int8_t    rep_thresh;
    u_int8_t    rep_detail;
    u_int8_t    req_ie;
    u_int8_t    lastind;
    u_int8_t    num_chanrep;
    struct ieee80211_beaconreq_chaninfo
              apchanrep[IEEE80211_RRM_NUM_CHANREP_MAX];
    u_int8_t   ssidlen;
    u_int8_t   ssid[MAX_SSID_LEN];
    u_int8_t   req_ielen;
    u_int8_t   req_iebuf[IEEE80211_MAX_REQ_IE];
    u_int8_t   extreq_ielen;
    u_int8_t   extreq_ie[IEEE80211_MAX_REQ_IE];
    u_int8_t   req_extie;
    u_int8_t   req_bcnrpt_disabled;
    u_int8_t   req_rptdetail_disabled;
    u_int8_t   req_wbandchan;
    u_int8_t   req_vendor;
    u_int8_t   vendor_oui_len;
    u_int8_t   vendor_buf_len;
    struct     ieee80211_beaconreq_wb_chan wb_chan;
    struct     ieee80211_beaconreq_vendor vendor_info;
#undef MAX_SSID_LEN
}ieee80211_rrm_beaconreq_info_t;

/**
 * struct ieee80211_nr_resp_tsf - TSF information subelement
 * @tsf_offset: TSF Offset
 * @bcn_int:    beacon interval
 */
struct ieee80211_nr_resp_tsf {
    u_int16_t tsf_offset;
    u_int16_t bcn_int;
}__packed;

/**
 * struct ieee80211_nr_resp_country - Condensed Country String subelement
 * @country_string: Country code
 */
struct ieee80211_nr_resp_country {
    u_int8_t country_string[IEEE80211_MAX_NR_COUNTRY_CODE];
}__packed;

/**
 * struct ieee80211_nr_cand_pref - BSS Transition candidate Preference subelement
 * @preference: Network Preference
 */
struct ieee80211_nr_cand_pref {
    u_int8_t preference;
}__packed;

/**
 * struct ieee80211_nr_term_duration - BSS Termination Duration subelement
 * @tsf: TSF time of the BSS transmitting the neighbor report
 * @duration: Number of minutes for which BSS is not present
 */
struct ieee80211_nr_term_duration {
    u_int64_t tsf;
    u_int16_t duration;
}__packed;

/**
 * struct ieee80211_nr_bearing - Bearing subelement
 * @bearing:  Relative Direction of the neighbor
 * @distance: Relative Distance of the neighbor
 * @height:   Relative Height in meters
 *
 */
struct ieee80211_nr_bearing {
    u_int16_t bearing;
    u_int32_t distance;
    u_int16_t height;
}__packed;

/**
 * struct ieee80211_nr_htcap - HT capabilities subelement
 * htcap_info: HT capability information
 * ampdu_param: AMPDU parameters
 * mcs: supported MCS set
 * ht_extcap: HT extended capabilities
 * txbeam_caps: Tx beamforming capabilities
 * asel_caps: ASEL capabilities
 */
struct ieee80211_nr_htcap {
    u_int16_t htcap_info;
    u_int8_t ampdu_param;
    u_int8_t mcs[IEEE80211_MAX_NR_MCS_SET];
    u_int16_t ht_extcap;
    u_int32_t txbeam_caps;
    u_int8_t asel_caps;
}__packed;

/**
 * struct ieee80211_nr_vhtcap - VHT capabilities subelement
 * Supported VHT-MCS and NSS Set field is 64 bits long.
 * Breaking it to four, 16 bit fields.
 * @vhtcap_info:     VHT capabilities info
 * @mcs:             Supported VHT-MCS & NSS set
 * @rx_highest_rate: Supported VHT-MCS & NSS set
 * @tx_vht_mcs:      Supported VHT-MCS & NSS set
 * @tx_highest_rate: Supported VHT-MCS & NSS set
 */
struct ieee80211_nr_vhtcap {
    u_int32_t vhtcap_info;
    u_int16_t mcs;
    u_int16_t rx_highest_rate;
    u_int16_t tx_vht_mcs;
    u_int16_t tx_highest_rate;
}__packed;

/**
 * struct ieee80211_nr_vhtop - VHT Operation subelement
 * @vhtop_info: vht operation information
 * @vht_mcs_nss: Basic VHT-MCS & NSS set
 */
struct ieee80211_nr_vhtop {
    struct ieee80211_beaconreq_wb_chan vhtop_info;
    uint16_t vht_mcs_nss;
}__packed;

/**
 * struct ieee80211_nr_htop - HT Operation subelement
 * @chan:      Primary channel
 * @htop_info: HT operation information
 * @htop_mcs:  Basic HT MCS set
 */
struct ieee80211_nr_htop {
    u_int8_t chan;
    u_int8_t htop_info[IEEE80211_NR_HTOP_LEN];
    u_int8_t htop_mcs[IEEE80211_MAX_NR_MCS_SET];
}__packed;

/**
 * struct ieee80211_nr_meas_pilot - Measurement Pilot Transmission subelement
 * @pilot: Number of TUs between measurement pilot
 * @vendor: Subelement
 */
struct ieee80211_nr_meas_pilot {
    u_int8_t pilot;
    struct ieee80211_beaconreq_vendor vendor;
}__packed;

/**
 * struct ieee80211_nr_rm_en_caps - RM Enabled capabilities subelement
 * @rm_cap: RM Enabled capabilities
 */
struct ieee80211_nr_rm_en_caps {
    u_int8_t rm_cap[IEEE80211_NR_RM_CAP_LEN];
}__packed;

/**
 * struct ieee80211_nr_sec_chan - Secondary channel offset subelement
 * @sec_chan_offset: Position of sec. channel relative to primary
 */
struct ieee80211_nr_sec_chan {
    u_int8_t sec_chan_offset;
}__packed;

/* Bitmap to indicate presence of optional subelements
 * in RRM Neighbor report response */
#define IEEE80211_NR_SUBIE_PRES_TSF               0x00000001
#define IEEE80211_NR_SUBIE_PRES_COUNTRY           0x00000002
#define IEEE80211_NR_SUBIE_PRES_CAND_PREF         0x00000004
#define IEEE80211_NR_SUBIE_PRES_TERM_DUR          0x00000008
#define IEEE80211_NR_SUBIE_PRES_BEARING           0x00000010
#define IEEE80211_NR_SUBIE_PRES_WIDEBAND          0x00000020
#define IEEE80211_NR_SUBIE_PRES_HT_CAPS           0x00000040
#define IEEE80211_NR_SUBIE_PRES_HT_OP             0x00000080
#define IEEE80211_NR_SUBIE_PRES_SEC_CHAN_OFFSET   0x00000100
#define IEEE80211_NR_SUBIE_PRES_MEAS_PILOT        0x00000200
#define IEEE80211_NR_SUBIE_PRES_RM_EN_CAPS        0x00000400
#define IEEE80211_NR_SUBIE_PRES_VHT_CAPS          0x00000800
#define IEEE80211_NR_SUBIE_PRES_VHT_OP            0x00001000
#define IEEE80211_NR_SUBIE_PRES_VENDOR            0x00002000

/* Neighbor Report response BSS Info Fields */
#define IEE80211_NR_BSSINFO_APREACH_MASK	  0x00000003
#define IEE80211_NR_BSSINFO_SEC_MASK              0x00000004
#define IEE80211_NR_BSSINFO_KEYSCOPE_MASK         0x00000008
#define IEE80211_NR_BSSINFO_CAP_SPEC_MASK         0x00000010
#define IEE80211_NR_BSSINFO_CAP_QOS_MASK          0x00000020
#define IEE80211_NR_BSSINFO_CAP_APSD_MASK         0x00000040
#define IEE80211_NR_BSSINFO_CAP_RRM_MASK          0x00000080
#define IEE80211_NR_BSSINFO_CAP_DBA_MASK          0x00000100
#define IEE80211_NR_BSSINFO_CAP_IBA_MASK          0x00000200
#define IEE80211_NR_BSSINFO_MDOMAIN_MASK          0x00000400
#define IEE80211_NR_BSSINFO_HT_MASK               0x00000800
#define IEE80211_NR_BSSINFO_VHT_MASK              0x00001000
#define IEE80211_NR_BSSINFO_FTM_MASK              0x00002000

/**
 * struct ieee80211_nr_resp_info_s - Custom Neighbor report response
 * @bssid[6]:            BSSID of the BSS being reported
 * @bssi_info:           BSSID Information field
 * @regclass:            Operating class
 * @channum:             Last known primary channel
 * @phy_type:            Phy type of AP indicated
 * @subie_pres:          Bitmap indicating presence of subelements
 * @nr_tsf:              TSF Information subelement   (optional)
 * @nr_country:	         Condensed country string subelement (optional)
 * @nr_cand_pref:        BSS Transition candidate preference (optional)
 * @nr_term_duration:    BSS Termination duration (optional)
 * @nr_bearing:          Bearing subelement (optional)
 * @nr_wb_chan:          Wide bandwidth Channel (optional)
 * @nr_ht_cap:           HT Capabilities subelement (optional)
 * @nr_ht_op:            HT Operation subelement (optional)
 * @nr_sec_chan:         Secondary channel offset subelement (optional)
 * @nr_meas_pilot:       Measurement pilot Transmission  (optional)
 * @nr_rm_en_caps:       RM enabled capabilities  (optional)
 * @nr_vhtcaps:          VHT Capabilities (optional)
 * @nr_vht_op:           VHT Operation (optional)
 * @nr_vendor:           Vendor Specific (optional)
 *
 */
typedef struct ieee80211_nr_resp_info_s {
    u_int8_t  bssid[6];
    u_int32_t bssi_info;
    u_int8_t  regclass;
    u_int8_t  channum;
    u_int8_t  phy_type;
    u_int32_t subie_pres;
    u_int8_t pilot_vndroui_len;
    u_int8_t pilot_vndrbuf_len;
    u_int8_t vendor_oui_len;
    u_int8_t vendor_buf_len;
    struct ieee80211_nr_resp_tsf  nr_tsf;
    struct ieee80211_nr_resp_country  nr_country;
    struct ieee80211_nr_cand_pref  nr_cand_pref;
    struct ieee80211_nr_term_duration nr_term_duration;
    struct ieee80211_nr_bearing nr_bearing;
    struct ieee80211_beaconreq_wb_chan nr_wb_chan;
    struct ieee80211_nr_htcap nr_ht_cap;
    struct ieee80211_nr_htop nr_ht_op;
    struct ieee80211_nr_sec_chan nr_sec_chan;
    struct ieee80211_nr_meas_pilot nr_meas_pilot;
    struct ieee80211_nr_rm_en_caps nr_rm_en_caps;
    struct ieee80211_nr_vhtcap nr_vhtcaps;
    struct ieee80211_nr_vhtop nr_vht_op;
    struct ieee80211_beaconreq_vendor nr_vendor;
}__packed ieee80211_cust_nrresp_info_t;

typedef struct ieee80211_user_nr_rep_r {
    u_int32_t num_report;
    u_int8_t  dialog_token;
    ieee80211_cust_nrresp_info_t *custom_nrresp_info;
}ieee80211_user_nrresp_info_t;

typedef struct ieee80211_rrm_cca_info_s{
    u_int16_t num_rpts;
    u_int8_t dstmac[6];
    u_int8_t chnum;
    u_int64_t tsf;
    u_int16_t m_dur;
}ieee80211_rrm_cca_info_t;

typedef struct ieee80211_rrm_rpihist_info_s{
    u_int16_t num_rpts;
    u_int8_t dstmac[6];
    u_int8_t chnum;
    u_int64_t tsf;
    u_int16_t m_dur;
}ieee80211_rrm_rpihist_info_t;

typedef struct ieee80211_rrm_chloadreq_info_s{
    u_int8_t dstmac[6];
    u_int16_t num_rpts;
    u_int8_t regclass;
    u_int8_t chnum;
    u_int16_t r_invl;
    u_int16_t m_dur;
    u_int8_t cond;
    u_int8_t c_val;
}ieee80211_rrm_chloadreq_info_t;

typedef struct ieee80211_rrm_nhist_info_s{
    u_int16_t num_rpts;
    u_int8_t dstmac[6];
    u_int8_t regclass;
    u_int8_t chnum;
    u_int16_t r_invl;
    u_int16_t m_dur;
    u_int8_t cond;
    u_int8_t c_val;
}ieee80211_rrm_nhist_info_t;

typedef struct ieee80211_rrm_frame_req_info_s{
    u_int8_t dstmac[6];
    u_int8_t peermac[6];
    u_int16_t num_rpts;
    u_int8_t regclass;
    u_int8_t chnum;
    u_int16_t r_invl;
    u_int16_t m_dur;
    u_int8_t ftype;
}ieee80211_rrm_frame_req_info_t;

typedef struct ieee80211_rrm_lcireq_info_s
{
    u_int8_t dstmac[6];
    u_int16_t num_rpts;
    u_int8_t location;
    u_int8_t lat_res;
    u_int8_t long_res;
    u_int8_t alt_res;
    u_int8_t azi_res;
    u_int8_t azi_type;
}ieee80211_rrm_lcireq_info_t;

typedef struct ieee80211_rrm_stastats_info_s{
    u_int8_t dstmac[6];
    u_int16_t num_rpts;
    u_int16_t m_dur;
    u_int16_t r_invl;
    u_int8_t  gid;
}ieee80211_rrm_stastats_info_t;

typedef struct ieee80211_rrm_tsmreq_info_s {
    u_int16_t   num_rpt;
    u_int16_t   rand_ivl;
    u_int16_t   meas_dur;
    u_int8_t    reqmode;
    u_int8_t    reqtype;
    u_int8_t    tid;
    u_int8_t    macaddr[6];
    u_int8_t    bin0_range;
    u_int8_t    trig_cond;
    u_int8_t    avg_err_thresh;
    u_int8_t    cons_err_thresh;
    u_int8_t    delay_thresh;
    u_int8_t    meas_count;
    u_int8_t    trig_timeout;
}ieee80211_rrm_tsmreq_info_t;

typedef struct ieee80211_rrm_nrreq_info_s {
    u_int8_t dialogtoken;
    u_int8_t ssid[32];
    u_int8_t ssid_len;
    u_int8_t* essid;
    u_int8_t essid_len;
    u_int8_t meas_count; /* Request for LCI/LCR may come in any order */
    u_int8_t meas_token[2];
    u_int8_t meas_req_mode[2];
    u_int8_t meas_type[2];
    u_int8_t loc_sub[2];
}ieee80211_rrm_nrreq_info_t;

struct ieee80211_rrmreq_info {
    u_int8_t rm_dialogtoken;
    u_int8_t rep_dialogtoken;
    u_int8_t bssid[6];
    u_int8_t ssid[32];
    u_int8_t ssid_len;
    u_int16_t duration;
    u_int8_t chnum;
    u_int8_t regclass;
    u_int8_t gid;
    u_int8_t location; /* Location of requesting/reporting station */
    u_int8_t lat_res;  /* Latitute resolution */
    u_int8_t long_res; /* Longitude resolution */
    u_int8_t alt_res;  /* Altitude resolution */
    u_int8_t reject_type;
    u_int8_t reject_mode;
};

typedef struct ieee80211_rrm_lci_data_s
{
  u_int8_t id;
  u_int8_t len;
  u_int8_t lat_res;
  u_int8_t alt_type;
  u_int8_t long_res;
  u_int8_t alt_res;
  u_int8_t azi_res;
  u_int8_t alt_frac;
  u_int8_t datum;
  u_int8_t azi_type;
  u_int16_t lat_integ;
  u_int16_t long_integ;
  u_int16_t azimuth;
  u_int32_t lat_frac;
  u_int32_t long_frac;
  u_int32_t alt_integ;
}ieee80211_rrm_lci_data_t;

typedef struct ieee80211_rrm_statsgid10_s{
    u_int8_t ap_avg_delay;
    u_int8_t be_avg_delay;
    u_int8_t bk_avg_delay;
    u_int8_t vi_avg_delay;
    u_int8_t vo_avg_delay;
    u_int16_t st_cnt;
    u_int8_t ch_util;
}ieee80211_rrm_statsgid10_t;

typedef struct ieee80211_rrm_statsgid0_s{
    u_int32_t txfragcnt;
    u_int32_t mcastfrmcnt;
    u_int32_t failcnt;
    u_int32_t rxfragcnt;
    u_int32_t mcastrxfrmcnt;
    u_int32_t fcserrcnt;
    u_int32_t txfrmcnt;
}ieee80211_rrm_statsgid0_t;

typedef struct ieee80211_rrm_statsgid1_s{
    u_int32_t rty;
    u_int32_t multirty;
    u_int32_t frmdup;
    u_int32_t rtsuccess;
    u_int32_t rtsfail;
    u_int32_t ackfail;
}ieee80211_rrm_statsgid1_t;

typedef struct ieee80211_rrm_statsgidupx_s {
    u_int32_t qostxfragcnt;
    u_int32_t qosfailedcnt;
    u_int32_t qosrtycnt;
    u_int32_t multirtycnt;
    u_int32_t qosfrmdupcnt;
    u_int32_t qosrtssuccnt;
    u_int32_t qosrtsfailcnt;
    u_int32_t qosackfailcnt;
    u_int32_t qosrxfragcnt;
    u_int32_t qostxfrmcnt;
    u_int32_t qosdiscadrfrmcnt;
    u_int32_t qosmpdurxcnt;
    u_int32_t qosrtyrxcnt;
}ieee80211_rrm_statsgidupx_t;

typedef struct ieee80211_rrm_tsm_data_s
{
    u_int8_t tid;
    u_int8_t brange;
    u_int8_t mac[6];
    u_int32_t tx_cnt;
    u_int32_t discnt;
    u_int32_t multirtycnt;
    u_int32_t cfpoll;
    u_int32_t qdelay;
    u_int32_t txdelay;
    u_int32_t bin[6];
}ieee80211_rrm_tsm_data_t;

typedef struct ieee80211_frmcnt_data_s
{
    u_int8_t phytype;
    u_int8_t arcpi;
    u_int8_t lrsni;
    u_int8_t lrcpi;
    u_int8_t antid;
    u_int8_t ta[6];
    u_int8_t bssid[6];
    u_int16_t frmcnt;
}ieee80211_rrm_frmcnt_data_t;

typedef struct ieee80211_rrm_lm_data_s
{
    u_int8_t tx_pow;
    u_int8_t lmargin;
    u_int8_t rxant;
    u_int8_t txant;
    u_int8_t rcpi;
    u_int8_t rsni;
}ieee80211_rrm_lm_data_t;

typedef struct ieee80211_rrm_cca_data_s
{
    u_int8_t cca_busy;
}ieee80211_rrm_cca_data_t;

typedef struct ieee80211_rrm_rpi_data_s
{
    u_int8_t rpi[IEEE80211_RRM_RPI_SIZE];
}ieee80211_rrm_rpi_data_t;

typedef struct ieee80211_rrm_noise_data_s
{
    u_int8_t antid;
    int8_t anpi;
    u_int8_t ipi[11];
}ieee80211_rrm_noise_data_t;

typedef struct ieee80211_rrm_node_stats_s
{
    ieee80211_rrm_statsgid0_t   gid0;
    ieee80211_rrm_statsgid1_t   gid1;
    ieee80211_rrm_statsgidupx_t gidupx[8]; /* from 0 to seven */
    ieee80211_rrm_statsgid10_t  gid10;
    ieee80211_rrm_tsm_data_t    tsm_data;

    /* as per specification length can maximum be 228 */
    ieee80211_rrm_frmcnt_data_t frmcnt_data[12];
    ieee80211_rrm_lm_data_t     lm_data;
    ieee80211_rrm_lci_data_t    ni_rrm_lciinfo; /* RRM LCI information of this node */
    ieee80211_rrm_lci_data_t    ni_vap_lciinfo; /* RRM LCI information of VAP wrt this node */
}ieee80211_rrm_node_stats_t;


/* RRM statistics */
typedef struct ieee80211_rrmstats_s
{
    u_int8_t                    chann_load[IEEE80211_RRM_CHAN_MAX];
    ieee80211_rrm_noise_data_t  noise_data[IEEE80211_RRM_CHAN_MAX];
    ieee80211_rrm_cca_data_t    cca_data[IEEE80211_RRM_CHAN_MAX];
    ieee80211_rrm_rpi_data_t    rpi_data[IEEE80211_RRM_CHAN_MAX];
    ieee80211_rrm_node_stats_t  ni_rrm_stats;
}ieee80211_rrmstats_t;

// Moving to band_steering_api.h
// to resolve build dependencies
#if 0
/* to user level */
typedef struct ieee80211_bcnrpt_s {
    u_int8_t bssid[6];
    u_int8_t rsni;
    u_int8_t rcpi;
    u_int8_t chnum;
    u_int8_t more;
}ieee80211_bcnrpt_t;
#endif

typedef struct ieee80211req_rrmstats_s {
    u_int32_t index;
    u_int32_t data_size;
    void *data_addr;
}ieee80211req_rrmstats_t;

#define IEEE80211_RRM_MEASRPT_MODE_SUCCESS         0x00
#define IEEE80211_RRM_MEASRPT_MODE_BIT_LATE        0x01
#define IEEE80211_RRM_MEASRPT_MODE_BIT_INCAPABLE   0x02
#define IEEE80211_RRM_MEASRPT_MODE_BIT_REFUSED     0x04

/* Enumeration for 802.11k beacon report request measurement mode,
 * as defined in Table 7-29e in IEEE Std 802.11k-2008 */
typedef enum {
    IEEE80211_RRM_BCNRPT_MEASMODE_PASSIVE = 0,
    IEEE80211_RRM_BCNRPT_MEASMODE_ACTIVE = 1,
    IEEE80211_RRM_BCNRPT_MEASMODE_BCNTABLE = 2,

    IEEE80211_RRM_BCNRPT_MEASMODE_RESERVED
} IEEE80211_RRM_BCNRPT_MEASMODE;

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

/* Radio Measurement capabilities (from RM Enabled Capabilities element)
 * IEEE Std 802.11-2016, 9.4.2.45, Table 9-157 */
/* byte 1 (out of 5) */
#define IEEE80211_RRM_CAPS_LINK_MEASUREMENT		BIT(0)
#define IEEE80211_RRM_CAPS_NEIGHBOR_REPORT		BIT(1)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_PASSIVE	BIT(4)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_ACTIVE		BIT(5)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_TABLE		BIT(6)
/* byte 2 (out of 5) */
#define IEEE80211_RRM_CAPS_LCI_MEASUREMENT 		BIT(4)
/* byte 5 (out of 5) */
#define IEEE80211_RRM_CAPS_FTM_RANGE_REPORT 		BIT(2)

/**
 * Enumeration for 802.11 regulatory class as defined in Annex E of
 * 802.11-Revmb/D12, November 2011
 *
 * It currently includes a subset of global operating classes as defined in Table E-4.
 */
typedef enum {
    IEEE80211_RRM_REGCLASS_81 = 81,
    IEEE80211_RRM_REGCLASS_82 = 82,
    IEEE80211_RRM_REGCLASS_112 = 112,
    IEEE80211_RRM_REGCLASS_115 = 115,
    IEEE80211_RRM_REGCLASS_118 = 118,
    IEEE80211_RRM_REGCLASS_121 = 121,
    IEEE80211_RRM_REGCLASS_124 = 124,
    IEEE80211_RRM_REGCLASS_125 = 125,
    IEEE80211_RRM_REGCLASS_131 = 131,
    IEEE80211_RRM_REGCLASS_136 = 136,
    IEEE80211_RRM_REGCLASS_RESERVED
} IEEE80211_RRM_REGCLASS;

/* as per 802.11mc spec anex C, used in Radio resource mgmt reprots */
enum ieee80211_phytype_mode {
    IEEE80211_PHY_TYPE_UNKNOWN = 0,
    IEEE80211_PHY_TYPE_FHSS = 1,	/* 802.11 2.4GHz 1997 */
    IEEE80211_PHY_TYPE_DSSS = 2,	/* 802.11 2.4GHz 1997 */
    IEEE80211_PHY_TYPE_IRBASEBAND = 3,
    IEEE80211_PHY_TYPE_OFDM  = 4,	/* 802.11ag */
    IEEE80211_PHY_TYPE_HRDSSS  = 5,	/* 802.11b 1999 */
    IEEE80211_PHY_TYPE_ERP  = 6,	/* 802.11g 2003 */
    IEEE80211_PHY_TYPE_HT   = 7,  	/* 802.11n */
    IEEE80211_PHY_TYPE_DMG  = 8,   	/* 802.11ad */
    IEEE80211_PHY_TYPE_VHT  = 9,   	/* 802.11ac */
    IEEE80211_PHY_TYPE_TVHT  = 10,   	/* 802.11af */
    IEEE80211_PHY_TYPE_S1G  = 11,
    IEEE80211_PHY_TYPE_CDMG  = 12,
    IEEE80211_PHY_TYPE_CMMG  = 13,
    IEEE80211_PHY_TYPE_HE  = 14,   	/* 802.11ax */
};

struct ev_rrm_report_data {
    u_int32_t bcnrpt_count;
    u_int8_t rrm_type;
    u_int8_t dialog_token;
    u_int8_t mode;
    u_int8_t macaddr[6];
    u_int8_t bcnrpt[1];
};

#endif /* _IEEE80211_RRM_H_ */
