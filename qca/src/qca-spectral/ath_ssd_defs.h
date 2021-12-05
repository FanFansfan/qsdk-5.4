/*
 * =====================================================================================
 *
 *       Filename:  ath_ssd_defs.h
 *
 *    Description:  Atheros Spectral Daemon Definitions
 *
 *        Version:  1.0
 *        Created:  12/13/2011 04:00:15 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012, 2017-2021 Qualcomm Technologies, Inc.
 *
 *        All Rights Reserved.
 *        Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 *        2012 Qualcomm Atheros, Inc.
 *
 *        All Rights Reserved.
 *        Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 */

#ifndef _ATH_SSD_DEFS_H_
#define _ATH_SSD_DEFS_H_

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>
#include <netinet/if_ether.h>
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include "spectral_ioctl.h"
#include "spectral_data.h"
#include "classifier.h"
#include "spec_msg_proto.h"
#ifndef _BYTE_ORDER
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _BYTE_ORDER _LITTLE_ENDIAN
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define _BYTE_ORDER _BIG_ENDIAN
#endif
#endif  /* _BYTE_ORDER */
#include "ieee80211_external.h"

#include "if_athioctl.h"
#include "classifier.h"
#include "spectral_data.h"
#include "spec_msg_proto.h"
#include "spectral.h"
#ifdef SPECTRAL_SUPPORT_CFG80211
#include "nl80211_copy.h"
#include "cfg80211_nlwrapper_api.h"
#include <netlink/genl/genl.h>
#include <linux/version.h>
#include <qca_vendor.h>
#include <cfg80211_external.h>
#endif /* SPECTRAL_SUPPORT_CFG80211 */

#define ATHSSD_ASSERT(expr)       assert((expr))

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif /* MIN */

#ifndef NETLINK_GENERIC
    #define NETLINK_GENERIC 16
#endif  /* NETLINK_GENERIC */

/* IFNAMSIZ definition */
#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif

#define line()          printf("----------------------------------------------------\n")
#define not_yet()       printf("TODO : %s : %d\n", __func__, __LINE__)
#define here()          printf("%s : %d\n", __func__, __LINE__)
#define streq(a, b)     ((strcasecmp(a, b) == 0))
#define IS_DBG_ENABLED()    (debug?1:0)

#define info(fmt, args...) do {\
    printf("athssd: %s (%4d) : " fmt "\n", __func__, __LINE__, ## args); \
    } while (0)

#define HT40_MAX_BIN_COUNT      (128)

#define TRUE                    (1)
#define FALSE                   !(TRUE)
#define SUCCESS                 (1)
#define FAILURE                 !(SUCCESS)
#define NUM_MAXIMUM_CHANNELS    11
#define MAX_PAYLOAD             1024
#define ATHPORT                 8001
#define BACKLOG                 10
#define CMD_BUF_SIZE            256
#define ENABLE_CLASSIFIER_PRINT 1
#define MSG_PACE_THRESHOLD      1
#define INVALID_FD              (-1)
#define PATH_SYSNET_DEV         "/sys/class/net/"
#define MAX_PATH_LEN            (100)
#define WIFI_STR                "wifi"

#define INVALID_CHANNEL         0

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#ifndef NETLINK_GENERIC
    #define NETLINK_GENERIC 16
#endif  /* NETLINK_GENERIC */

typedef enum channels {
    CHANNEL_01 = 1,
    CHANNEL_02,
    CHANNEL_03,
    CHANNEL_04,
    CHANNEL_05,
    CHANNEL_06,
    CHANNEL_07,
    CHANNEL_08,
    CHANNEL_09,
    CHANNEL_10,
    CHANNEL_11,
    MAX_CHANNELS,
}channels_t;

typedef enum sock_type {
    SOCK_TYPE_TCP,
    SOCK_TYPE_UDP,
}sock_type_t;

/* Maximum percentage of free memory we allow ourselves to approximately utilize
 * while setting socket receive buffer size. This is a value in the range of
 * 0 - 100.
 *
 * Note that the kernel may double the value we request for, to account for
 * bookkeeping overhead. This needs to be taken into account when changing the
 * value.
 *
 * This value we actually request may be bound by other limitations as well.
 */
#define ATHSSD_MAX_FREEMEM_UTIL_PERCENT       (30U)

/* This is the factor by which spectral netlink socket rx buffers are increased
 * from the default rx buffer size. This is based on experiments with some
 * low memory/slow CPU platforms.
 */
#define ATHSSD_SPECTRAL_SOCK_RX_BUFF_MULTIPLICATION_FACTOR   (5)

/*
 * Spetral param data structure with sane names for data memembers
 * XXX : This is copy of what is present in ah.h
 * Can't avoid this dupication now as the app and kernel share
 * this data structure and I do not want to make the build infrastruture
 * as simple as possible
 */
#ifndef MAX_CHAINS
#define MAX_CHAINS  4
#endif
#define HAL_PHYERR_PARAM_NOVAL  65535
#define HAL_PHYERR_PARAM_ENABLE 0x8000

#define CHANNEL_NORMAL_DWELL_INTERVAL   1
#define CHANNEL_CLASSIFY_DWELL_INTERVAL 10

#ifndef BAND_2_4GHZ_FREQ_MIN
#define BAND_2_4GHZ_FREQ_MIN              (2412)
#endif /* BAND_2_4GHZ_FREQ_MIN */

#ifndef BAND_2_4GHZ_FREQ_MAX
#define BAND_2_4GHZ_FREQ_MAX              (2484)
#endif /* BAND_2_4GHZ_FREQ_MAX */

#ifndef BAND_5GHZ_FREQ_MIN
#define BAND_5GHZ_FREQ_MIN                (5180)
#endif /* BAND_5GHZ_FREQ_MIN */

#ifndef BAND_5GHZ_FREQ_MAX
#define BAND_5GHZ_FREQ_MAX                (5920)
#endif /* BAND_5GHZ_FREQ_MAX */

#ifndef BAND_6GHZ_FREQ_MIN
#define BAND_6GHZ_FREQ_MIN                (5935)
#endif /* BAND_6GHZ_FREQ_MIN */

#ifndef BAND_6GHZ_FREQ_MAX
#define BAND_6GHZ_FREQ_MAX                (7115)
#endif /* BAND_6GHZ_FREQ_MAX */

typedef enum config_mode_type {
    CONFIG_IOCTL = 0,
    CONFIG_CFG80211 = 1,
    CONFIG_INVALID = 2,
} config_mode_type;

typedef struct ath_ssd_inet {
    int listener;
    int on;
    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    socklen_t addrlen;
    sock_type_t type;
}ath_ssd_inet_t;

typedef struct ath_ssd_nlsock {
    struct sockaddr_nl  src_addr;
    struct sockaddr_nl  dst_addr;
    int spectral_fd;
}ath_ssd_nlsock_t;

typedef struct ath_ssd_config {
    int ch_dwell_time;
    int max_hold_interval;
}ath_ssd_config_t;

#define MAX_INTERF_COUNT 10
typedef struct ath_ssd_interf_info {
    int count;
    struct interf_rsp interf_rsp[MAX_INTERF_COUNT];
}ath_ssd_interf_info_t;

typedef struct chan_stats {
    unsigned long long sent_msg;
    int interf_count;
}chan_stats_t;

typedef struct ath_ssd_stats {
    chan_stats_t ch[MAX_CHANNELS];
}ath_ssd_stats_t;

typedef struct ath_ssd_spectral_info {
    struct ath_diag atd;
    struct ifreq ifr;
}ath_ssd_spectral_info_t;

/**
 * struct spectral_param - Spectral control path data structure which
 * contains parameter and its value
 * @id: Parameter ID
 * @value: Single parameter value
 * @value1: First value in a pair
 * @value2: Second value in a pair
 */
struct spectral_param {
    uint32_t id;
    union {
        u_int32_t value;
        struct {
            u_int32_t value1;
            u_int32_t value2;
        };
    };
};

typedef struct ath_ssd_info {
    /* Spectral mode */
    enum spectral_scan_mode spectral_mode;

    /* Whether to carry out standalone scan */
    bool do_standalone_scan;

    int current_channel;                            /* current home channel */

    /*
     * Spectral frequency. Currently this parameter is applicable only for Agile
     * mode (the normal mode will use the current home channel).
     * Center frequency (in MHz) of the span of interest
     * OR
     * For convenience, center frequency (in MHz) of any channel in the span of
     * interest.
     */
    struct spectral_config_frequency spectral_frequency;

    int dwell_interval;                             /* channel dwell interval */
    int init_classifier;                            /* classifier needs initialization */
    enum wlan_band_id current_band;                 /* current operating band */
    int *channel_list;                              /* points to the current channel list */
    int max_channels;                               /* current max channels */
    int channel_index;                              /* points to current channel index */
    u_int16_t log_mode;                             /* Log mode to be used */

    sock_type_t sock_type;                          /* use tcp or udp */

    ath_ssd_inet_t inet_sock_info;                  /* inet socket information */
    ath_ssd_nlsock_t nl_sock_info;                  /* netlink socket information */
    ath_ssd_config_t config;                        /* config parameters */
    ath_ssd_interf_info_t  interf_info;             /* interference info */
    ath_ssd_stats_t stats;                          /* stats info */

    ath_ssd_spectral_info_t sinfo;                  /* will hold info related spectral */

    struct ss lwrband;                              /* lower band classifier information */
    struct ss uprband;                              /* upper band classifier information */

    char radio_ifname[IFNAMSIZ];                    /* interface name */
    u_int8_t radio_macaddr[ETH_ALEN];               /* radio MAC address */
    char dev_ifname[IFNAMSIZ];                      /* device ifname */
    char *filename;                                 /* Play SAMP data from this file */
    int replay;                                     /* Whether it is the `replay` mode */
#ifdef SPECTRAL_SUPPORT_CFG80211
    wifi_cfg80211_context cfg80211_sock_ctx;        /* cfg80211 socket context */
    config_mode_type cfg_flag;                      /* cfg flag */

    /* Array mapping Spectral internal parameters to cfg80211 attributes */
    int sparams_to_cfg80211_attrs[\
        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX];
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    struct spectral_config prev_spectral_params;    /* Previous Spectral config */
    bool prev_spectral_params_valid;                /* Whether previous Spectral
                                                       config is valid */
    /* command line option to scale or not, given by user */
    bool enable_gen3_linear_scaling;                /* enable gen3 linear scaling */
    struct spectral_config cur_spectral_params;     /* previous spectral config */
    struct spectral_caps caps;
    /* User given scan priority. Default is High priority */
    enum spectral_scan_priority spectral_scan_priority;
    /* Number of socket receive buffer errors */
    uint16_t num_rbuff_errors;
    int rbuff_sz_def;
}ath_ssd_info_t;

#ifdef SPECTRAL_SUPPORT_CFG80211
/**
 * struct ath_ssd_spectral_err_ctx - athssd Spectral error context
 * @is_spectral_err_valid: Whether the Spectral error code is valid
 * @spectral_err: Spectral error code
 */
typedef struct ath_ssd_spectral_err_ctx {
    bool is_spectral_err_valid;
    enum qca_wlan_vendor_spectral_scan_error_code spectral_err;
} ath_ssd_spectral_err_ctx_t;
#endif /* SPECTRAL_SUPPORT_CFG80211 */

#define GET_ADDR_OF_INETINFO(p)     (&(p)->inet_sock_info)
#define GET_ADDR_OF_NLSOCKINFO(p)   (&(p)->nl_sock_info)
#define GET_ADDR_OF_CFGSOCKINFO(p)  (&(p)->cfg80211_sock_ctx)
#define GET_ADDR_OF_STATS(p)        (&(p)->stats)
#define CONFIGURED_SOCK_TYPE(p)     ((p)->sock_type)
#define IS_BAND_2GHZ(p)              (((p)->current_band == WLAN_BAND_2GHZ) ? 1 : 0)
#define IS_BAND_5GHZ(p)              (((p)->current_band == WLAN_BAND_5GHZ) ? 1 : 0)
#define IS_BAND_6GHZ(p)              (((p)->current_band == WLAN_BAND_6GHZ) ? 1 : 0)
#define IS_CFG80211_ENABLED(p)       (((p)->cfg_flag == CONFIG_CFG80211)?1:0)

/* Default value for whether gen3 linear format bin scaling is enabled */
#define ATH_SSD_ENAB_GEN3_LINEAR_SCALING_DEFAULT   (TRUE)

/* order of data in outfile */
enum spectral_outfile_feilds {
    SPECTRAL_OUTFILE_START_POS = 0,
    SPECTRAL_OUTFILE_HEADER_START_POS = 0,
    SPECTRAL_OUTFILE_VERSION_POS = 0,
    SPECTRAL_OUTFILE_MODE_POS,
    SPECTRAL_OUTFILE_PRIMARY_FREQUENCY_POS,
    SPECTRAL_OUTFILE_CFREQ1_POS,
    SPECTRAL_OUTFILE_CFREQ2_POS,
    SPECTRAL_OUTFILE_AGILE_FREQUENCY1_POS,
    SPECTRAL_OUTFILE_AGILE_FREQUENCY2_POS,
    SPECTRAL_OUTFILE_CHANNEL_WIDTH_POS,
    SPECTRAL_OUTFILE_AGILE_CHANNEL_WIDTH_POS,
    SPECTRAL_OUTFILE_MAC_ADDRESS_POS,
    SPECTRAL_OUTFILE_GEN3_LINEAR_SCALING_EN_POS,
    SPECTRAL_OUTFILE_165MHZ_OPERATION_POS,
    SPECTRAL_OUTFILE_LB_EXTRA_EDGEBINS_POS,
    SPECTRAL_OUTFILE_RB_EXTRA_EDGEBINS_POS,
    SPECTRAL_OUTFILE_HEADER_END_POS =
                SPECTRAL_OUTFILE_RB_EXTRA_EDGEBINS_POS,
    SPECTRAL_OUTFILE_SPECTRAL_CAPS_HEADER_POS,
    SPECTRAL_OUTFILE_SPECTRAL_CAPS_START_POS,
    SPECTRAL_OUTFILE_PHYDIAG_CAP_POS =
        SPECTRAL_OUTFILE_SPECTRAL_CAPS_START_POS,
    SPECTRAL_OUTFILE_RADAR_CAP_POS,
    SPECTRAL_OUTFILE_SPECTRAL_CAP_POS,
    SPECTRAL_OUTFILE_ADV_SPECTRAL_CAP_POS,
    SPECTRAL_OUTFILE_HW_GENERATION_POS,
    SPECTRAL_OUTFILE_SCALING_PARAMS_VALID_POS,
    SPECTRAL_OUTFILE_SCALING_FORMULA_ID_POS,
    SPECTRAL_OUTFILE_LOW_LEVEL_OFFSET_POS,
    SPECTRAL_OUTFILE_HIGH_LEVEL_OFFSET_POS,
    SPECTRAL_OUTFILE_RSSI_THRSH_POS,
    SPECTRAL_OUTFILE_DEFAULT_AGC_MAX_GAIN_POS,
    SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_POS,
    SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_160_POS,
    SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_80P80_POS,
    SPECTRAL_OUTFILE_NUM_DETECTORS_20_MHZ_POS,
    SPECTRAL_OUTFILE_NUM_DETECTORS_40_MHZ_POS,
    SPECTRAL_OUTFILE_NUM_DETECTORS_80_MHZ_POS,
    SPECTRAL_OUTFILE_NUM_DETECTORS_160_MHZ_POS,
    SPECTRAL_OUTFILE_NUM_DETECTORS_80P80_MHZ_POS,
    SPECTRAL_OUTFILE_SPECTRAL_CAPS_END_POS =
                SPECTRAL_OUTFILE_NUM_DETECTORS_80P80_MHZ_POS,
    SPECTRAL_OUTFILE_SPECTRAL_PARAMS_HEADER_POS,
    SPECTRAL_OUTFILE_NUM_PARAMS_POS,
    SPECTRAL_OUTFILE_END_POS,
};

/* order of data in outfile */
enum spectral_outfile_params_non_advanced {
    SPECTRAL_NON_ADVANCED_PARAM_START,
    SPECTRAL_NON_ADVANCED_PARAM_FFT_PERIOD_POS =
            SPECTRAL_NON_ADVANCED_PARAM_START,
    SPECTRAL_NON_ADVANCED_PARAM_SCAN_PERIOD_POS,
    SPECTRAL_NON_ADVANCED_PARAM_SCAN_COUNT_POS,
    SPECTRAL_NON_ADVANCED_PARAM_SHORT_REPORT_POS,
    SPECTRAL_NON_ADVANCED_PARAM_SPECT_PRI_POS,
    SPECTRAL_NON_ADVANCED_PARAM_MAX,
};

/* order of data in outfile */
enum spectral_outfile_params_advanced {
    SPECTRAL_ADVANCED_PARAM_START,
    SPECTRAL_ADVANCED_PARAM_SCAN_PERIOD_POS =
            SPECTRAL_ADVANCED_PARAM_START,
    SPECTRAL_ADVANCED_PARAM_SCAN_COUNT_POS,
    SPECTRAL_ADVANCED_PARAM_SPECT_PRI_POS,
    SPECTRAL_ADVANCED_PARAM_FFT_SIZE_POS,
    SPECTRAL_ADVANCED_PARAM_GC_ENA_POS,
    SPECTRAL_ADVANCED_PARAM_RESTART_ENA_POS,
    SPECTRAL_ADVANCED_PARAM_NOISE_FLOOR_REF_POS,
    SPECTRAL_ADVANCED_PARAM_INIT_DELAY_POS,
    SPECTRAL_ADVANCED_PARAM_NB_TONE_THR_POS,
    SPECTRAL_ADVANCED_PARAM_STR_BIN_THR_POS,
    SPECTRAL_ADVANCED_PARAM_WB_RPT_MODE_POS,
    SPECTRAL_ADVANCED_PARAM_RSSI_RPT_MODE_POS,
    SPECTRAL_ADVANCED_PARAM_RSSI_THR_POS,
    SPECTRAL_ADVANCED_PARAM_PWR_FORMAT_POS,
    SPECTRAL_ADVANCED_PARAM_RPT_MODE_POS,
    SPECTRAL_ADVANCED_PARAM_BIN_SCALE_POS,
    SPECTRAL_ADVANCED_PARAM_DBM_ADJ_POS,
    SPECTRAL_ADVANCED_PARAM_CHN_MASK_POS,
    SPECTRAL_ADVANCED_PARAM_FREQUENCY1_POS,
    SPECTRAL_ADVANCED_PARAM_FREQUENCY2_POS,
    SPECTRAL_ADVANCED_PARAM_MAX,
};

enum spectral_sample_offset {
    SPECTRAL_SAMPLE_PRI80_OFFSET =0,
    SPECTRAL_SAMPLE_SEC80_OFFSET,
    SPECTRAL_SAMPLE_5MHZ_OFFSET,
    SPECTRAL_SAMPLE_OFFSET_MAX,
};

extern int init_inet_sockinfo(ath_ssd_info_t *pinfo);
extern int init_nl_sockinfo(ath_ssd_info_t *pinfo);
extern int accept_new_connection(ath_ssd_info_t *pinfo);
extern int accept_new_connection(ath_ssd_info_t *pinfo);
extern int handle_spectral_data(ath_ssd_info_t *pinfo);
extern int handle_client_data(ath_ssd_info_t *pinfo, int fd);

extern void process_spectral_msg(ath_ssd_info_t *pinfo, struct spectral_samp_msg* msg);
extern void update_next_channel(ath_ssd_info_t *pinfo);
extern void stop_spectral_scan(ath_ssd_info_t *pinfo);
extern void switch_channel(ath_ssd_info_t *pinfo);
extern void start_spectral_scan(ath_ssd_info_t *pinfo);
extern void run_state(ath_ssd_info_t *pinfo);
extern void cleanup(ath_ssd_info_t *pinfo);
extern void alarm_handler(ath_ssd_info_t *pinfo);
extern void signal_handler(int signal);
extern void print_usage(void);
extern void init_bandinfo(struct ss *plwrband, struct ss *puprband, int print_enable);
extern void ms_init_classifier(struct ss *lwrband, struct ss *uprband, struct spectral_classifier_params *cp);
extern void classifier(struct ss *bd, int timestamp, int last_capture_time, int rssi, int narrowband, int peak_index);
extern void print_spectral_SAMP_msg(struct spectral_samp_msg* ss_msg);
extern void add_interference_report(ath_ssd_info_t *pinfo, struct interf_src_rsp *rsp);
extern int update_interf_info(ath_ssd_info_t *pinfo, struct ss *bd);
extern void clear_interference_info(ath_ssd_info_t *pinfo);
extern void print_ssd_stats(ath_ssd_info_t *pinfo);
extern void print_interf_details(ath_ssd_info_t *pinfo, eINTERF_TYPE type);
extern void new_process_spectral_msg(ath_ssd_info_t *pinfo, struct spectral_samp_msg* msg, bool enable_gen3_linear_scaling);
extern void start_classifiy_spectral_scan(ath_ssd_info_t *pinfo);
extern const char* ether_sprintf(const u_int8_t *mac);
extern int ath_ssd_init_spectral(ath_ssd_info_t* pinfo);
extern int ath_ssd_start_spectral_scan(ath_ssd_info_t* pinfo);
extern int ath_ssd_stop_spectral_scan(ath_ssd_info_t* pinfo);
extern int ath_ssd_set_spectral_param(ath_ssd_info_t* pinfo, struct spectral_param *param);
extern int get_channel_width(ath_ssd_info_t* pinfo);
extern int ath_ssd_get_spectral_param(ath_ssd_info_t* pinfo, struct spectral_config* sp);
extern int ath_ssd_get_spectral_capabilities(ath_ssd_info_t* pinfo,
                struct spectral_caps *caps);
extern int get_vap_priv_int_param(ath_ssd_info_t* pinfo, const char *ifname,
        int param, int *value);
extern int ath_sssd_get_current_band(ath_ssd_info_t *pinfo, const char *ifname,
                                     enum wlan_band_id *cur_band);
extern enum wlan_band_id ath_ssd_get_band_from_freq(u_int32_t freq);
extern int get_radio_priv_int_param(ath_ssd_info_t* pinfo, const char *ifname,
        int param, int *value);
extern int save_spectral_configuration(void);
extern void restore_spectral_configuration(void);
extern int athssd_set_channel(ath_ssd_info_t* pinfo, const char *ifname, int channel, enum wlan_band_id band);
extern int finish_handler(struct nl_msg *msg, void *arg);
extern int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
extern int ack_handler(struct nl_msg *msg, void *arg);
#endif /* _ATH_SSD_DEFS_H_ */
