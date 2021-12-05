/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TEST INTERNAL

GENERAL DESCRIPTION
  This file contains the headers for LOWI TEST

 Copyright (c) 2014-2021 Qualcomm Technologies, Inc.
 All Rights Reserved.
 Confidential and Proprietary - Qualcomm Technologies, Inc
=============================================================================*/
#ifndef __LOWI_TEST_INTERNAL_H__
#define __LOWI_TEST_INTERNAL_H__

#include <stdio.h>

#if CONFIG_SUPPORT_LIBROXML
#include <sys/mman.h>
#include <sys/stat.h>
#else
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif
#include <sys/timerfd.h>
#include "lowi_test_defines.h"
#include "lowi_mac_address.h"
#include "lowi_response.h"
#include <map>

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_SUPPORT_LIBROXML
#include <roxml.h>
#endif

#if CONFIG_SUPPORT_LIBROXML
#define MAX_NAME_LEN 50
#define MAX_PAYLOAD_LEN 256
#endif


//LOWI Test Version
#define LOWI_TEST_VERSION "LTST_1.5.0"

// Default value of measurement age filter
#define LOWI_TEST_MEAS_AGE_FILTER_SEC 10

using namespace qc_loc_fw;

#if CONFIG_SUPPORT_LIBROXML
typedef char xmlChar;
#endif
/**
 * Struct to store AP Mac address and Frequency
 */
struct LowiTestApInfo
{
  LOWIMacAddress mac;
  uint32         frequency;
  unsigned char  ssid[32];
  int            ssid_length;
  uint32         rtt_feat_of_ap;
  LowiTestApInfo() : frequency (0), ssid_length(0), rtt_feat_of_ap(0)
  {
    memset(ssid, 0, 32);
  }
  LowiTestApInfo(LOWIMacAddress addr, uint32 freq) : mac(addr), frequency (freq) { }
  LowiTestApInfo(const uint8 * pAddr, uint32 freq) : mac(pAddr), frequency (freq) { }
  LowiTestApInfo(LOWIMacAddress addr, uint32 freq, LOWISsid in_ssid,
                 uint32 rtt_feat) : mac(addr), frequency (freq)
  {
    memset(ssid, 0, 32);
    in_ssid.getSSID(ssid, &ssid_length);
    rtt_feat_of_ap = rtt_feat;
  }

  ~LowiTestApInfo()
  {

  }

};

/* Max BSSIDs for stats reporting */
#define MAX_BSSIDS_STATS  100

/* Timeout for scan response */
#define LOWI_SCAN_TIMEOUT_MS 75000
#define LOWI_ASYNC_SCAN_TIMEOUT_MS 60000 // 1 minutes
#define LOWI_BATCHING_SCAN_TIMEOUT_MS 600000 // 10 minutes
#define LOWI_CAPABILITY_SUBS_TIMEOUT_MS 60000 // 1 minutes
#define NSECS_PER_SEC 1000000000
#define MSECS_PER_SEC 1000
#define NSECS_PER_MSEC (NSECS_PER_SEC/MSECS_PER_SEC)

/* Max Buffer length for Command */
#define LOWI_MAX_CMD_LEN 200

#define LOWI_TEST_DEFAULT_RTT_MEAS 5

/* Message Macros */
#define QUIPC_DBG_ERROR(...)  log_error(LOG_TAG, __VA_ARGS__);
#define QUIPC_DBG_HIGH(...)   log_info(LOG_TAG, __VA_ARGS__);
#define QUIPC_DBG_MED(...)    log_debug(LOG_TAG, __VA_ARGS__);
#define QUIPC_DBG_LOW(...)    log_verbose(LOG_TAG, __VA_ARGS__);


/*--------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 * -----------------------------------------------------------------------*/

/* Macro for bounds check on input */
#define LOWI_APPLY_LIMITS(value, lower, upper)  (((value) < (lower)) ? (lower) : \
         (((value) > (upper)) ? (upper) : (value)))


const xmlChar XML_NODE_RANGING[]              = "ranging";
const xmlChar XML_NODE_DISCOVERY[]            = "discovery";
const xmlChar XML_NODE_SUMMARY[]              = "summary";
const xmlChar XML_NODE_AP[]                   = "ap";
const xmlChar XML_NODE_MAC[]                  = "mac";
const xmlChar XML_NODE_BAND[]                 = "band";
const xmlChar XML_NODE_CH[]                   = "ch";
const xmlChar XML_NODE_CHAN[]                 = "chan";
const xmlChar XML_NODE_FREQUENCY[]            = "frequency";
const xmlChar XML_NODE_BAND_CENTER_FREQ1[]    = "center_freq1";
const xmlChar XML_NODE_BAND_CENTER_FREQ2[]    = "center_freq2";
const xmlChar XML_NODE_RTT_TYPE[]             = "rttType";
const xmlChar XML_NODE_NUM_FRAMES_PER_BURST[] = "numFrames";
const xmlChar XML_NODE_RANGING_TX_BW[]        = "bw";
const xmlChar XML_NODE_RANGING_RX_BW[]        = "rxbw";
const xmlChar XML_NODE_RANGING_PREAMBLE[]     = "preamble";
const xmlChar XML_NODE_PEER_TYPE[]            = "peerType";
const xmlChar XML_NODE_SSID[]                 = "ssid";
const xmlChar XML_NODE_PHYMODE[]              = "phymode";
const xmlChar XML_NODE_TRUE_DISTANCE[]        = "trueDistanceInCm";
const xmlChar XML_NODE_2P4_DELAY_PS[]         = "DelayPicoSec2g";
const xmlChar XML_NODE_5G_DELAY_PS[]          = "DelayPicoSec5g";
const xmlChar XML_NODE_SKIP_FIRT_MEAS[]       = "skipFirstMeas";
const xmlChar XML_NODE_REPORTTYPE[]           = "reporttype";
const xmlChar XML_NODE_INTERFACE[]            = "interface";

/* FTM Params*/
const xmlChar XML_NODE_FTM_RANGING_ASAP[]           = "asap";
const xmlChar XML_NODE_FTM_RANGING_LCI[]            = "lci";
const xmlChar XML_NODE_FTM_RANGING_LOC_CIVIC[]      = "civic";
const xmlChar XLM_NODE_FTM_PTSF_TIMER_NO_PREF[]     = "ptsftimer";
const xmlChar XML_NODE_FTM_RANGING_NUM_BURSTS_EXP[] = "burstsexp";
const xmlChar XML_NODE_FTM_RANGING_BURST_DURATION[] = "burstduration";
const xmlChar XML_NODE_FTM_RANGING_BURST_PERIOD[]   = "burstperiod";
const xmlChar XML_NODE_FTM_USE_LEG_ACK_ONLY[]       = "forceLegAck";
const xmlChar XML_NODE_FTM_FORCE_QCA_PEER[]         = "forceQcaPeer";

const xmlChar XML_NODE_FTM_PARAM_CONTROL[]          = "paramControl";

/* LCI Information*/
const xmlChar XML_NODE_LCI[]                = "lci_info";
const xmlChar XML_NODE_LCI_LAT[]            = "latitude";
const xmlChar XML_NODE_LCI_LON[]            = "longitude";
const xmlChar XML_NODE_LCI_ALT[]            = "altitude";
const xmlChar XML_NODE_LCI_LAT_UNC[]        = "latitude_unc";
const xmlChar XML_NODE_LCI_LON_UNC[]        = "longitude_unc";
const xmlChar XML_NODE_LCI_ALT_UNC[]        = "altitude_unc";
const xmlChar XML_NODE_LCI_MOTION_PATTERN[] = "motion_pattern";
const xmlChar XML_NODE_LCI_FLOOR[]          = "floor";
const xmlChar XML_NODE_LCI_HEIGHT[]         = "height_above_floor";
const xmlChar XML_NODE_LCI_HEIGHT_UNC[]     = "height_unc";

/* LCR Information*/
const xmlChar XML_NODE_LCR[]        = "lcr_info";
const xmlChar XML_NODE_LCR_CC[]     = "country_code";
const xmlChar XML_NODE_LCR_CIVIC[]  = "civic_address";

/* FTMRR Node Information*/
const xmlChar XML_NODE_FTMRR[]                = "ftmrr";
const xmlChar XML_NODE_FTMRR_ELM[]            = "element";
const xmlChar XML_NODE_FTMRR_ELM_BSSID[]      = "bssid";
const xmlChar XML_NODE_FTMRR_ELM_BSSID_INFO[] = "info_bssid";
const xmlChar XML_NODE_FTMRR_ELM_PHY_TYPE[]   = "phy_type";
const xmlChar XML_NODE_FTMRR_ELM_OP_CLASS[]   = "op_class";
const xmlChar XML_NODE_FTMRR_ELM_CH[]         = "ch";
const xmlChar XML_NODE_FTMRR_ELM_CENTER_CH1[] = "center_ch1";
const xmlChar XML_NODE_FTMRR_ELM_CENTER_CH2[] = "center_ch2";
const xmlChar XML_NODE_FTMRR_ELM_CH_WIDTH[]   = "width_ch";

/* Log Config Request Information*/
const xmlChar XML_NODE_CONFIG[]                  = "configuration";
const xmlChar XML_NODE_CONFIG_LOG[]              = "logConfig";
const xmlChar XML_NODE_CONFIG_LOG_INFO[]         = "loginfo";
const xmlChar XML_NODE_CONFIG_LOG_MODULE_ID[]    = "moduleid";
const xmlChar XML_NODE_CONFIG_LOG_LEVEL[]        = "logLevel";
const xmlChar XML_NODE_CONFIG_GLOBAL_LOG_LEVEL[] = "globalloglevel";
/*--------------------------------------------------------------------------
 * Local Data Definitions
 * -----------------------------------------------------------------------*/

/* Scan type local to LOWI Test module */
typedef enum
{
  LOWI_DISCOVERY_SCAN,
  LOWI_RTS_CTS_SCAN,
  LOWI_BOTH_SCAN,
  LOWI_ASYNC_DISCOVERY_SCAN,
  LOWI_BATCHING,
  LOWI_ANQP_REQ,
  LOWI_NR_REQ,
  LOWI_UART_TEST_REQ, /* UART Test Request */
  LOWI_WSQ_REQ, /* WLAN STATE QUERY Request */
  LOWI_SET_LCI,
  LOWI_SET_LCR,
  LOWI_WRU_REQ,
  LOWI_FTMR_REQ,
  LOWI_CONFIG_REQ,
  LOWI_START_RESP_MEAS,
  LOWI_STOP_RESP_MEAS,
  LOWI_MAX_SCAN
} t_lowi_scan;

struct result_data
{
  int  rtt;//Store rtt pico sec values
  enum eRangingBandwidth tx_bw;
  enum eRangingBandwidth rx_bw;
  /* used rx chain number, if fwr do not fill it then set it -1 */
  int8 rx_chain_no;
  /* used tx chain number, if fwr do not fill it then set it -1 */
  int8 tx_chain_no;
  uint32 seq_no;
  result_data()
  {
    tx_chain_no = rx_chain_no = -1;
    rtt = 0;
    tx_bw = rx_bw = BW_20MHZ;
    seq_no = 0;
  }

  void reset_result_data()
  {
    tx_chain_no = rx_chain_no = -1;
    rtt = 0;
    tx_bw = rx_bw = BW_20MHZ;
    seq_no = 0;
  }

  ~result_data()
  {
  }

};

/**
 * Basically for LOWIPostProcessNode rtt_cache is filled from
 * CSV file and hence it is not treated as meta data.
 * Rest of all field are treated as meta data.
 */
struct LOWIPostProcessNode
{
  LOWIMacAddress bssid;
  int true_dist;
  int delay_ps_2p4;
  int delay_ps_5g;
  bool forceLegAck;
  bool skip_first;
  int total_cnt;
  vector <struct result_data> rtt_cache;
  enum eRangingBandwidth req_tx_bw;
  enum eRangingBandwidth req_rx_bw;
  int band;
  int frame_per_burst;

  // default initialization
  LOWIPostProcessNode()
  {
    bssid.setMac(0, 0);
    true_dist = 0;
    delay_ps_2p4 = 0;
    delay_ps_5g = 0;
    forceLegAck = false;
    skip_first = 0;
    total_cnt = 0;
    frame_per_burst = 0;
    req_tx_bw = BW_20MHZ;
    req_rx_bw = BW_20MHZ;
    band = -1;
  }
  // Reste Meta Data to defaul values
  void resetNodeMetaData();
  // Copy this node meta data in to output node (op_node)
  void getNodeMetaData( struct LOWIPostProcessNode& op_node );
  // Copy the RTT cache of this node into the out put node
  void getRttCacheVec(  struct LOWIPostProcessNode& op_node );

  ~LOWIPostProcessNode()
  {
    rtt_cache.flush();
  }
};

struct LowiPostProcessInfo
{
  vector <LOWIPostProcessNode> node_cache;

  ~LowiPostProcessInfo()
  {
    node_cache.flush();
  }
};

enum e_chain_bit
{
  CHAIN_0_BIT = 0,
  CHAIN_1_BIT = 1,
};

enum e_chain_mask
{
  CHAIN_0  = 1 << CHAIN_0_BIT,
  CHAIN_1  = 1 << CHAIN_1_BIT,
  CHAIN_01 = (CHAIN_0 | CHAIN_1),

  CHAIN_MAX,
};

// Rtt stats
struct s_rtt_stats
{
  int32 min;
  int32 max;
  int32 sum;
  int32 mean;
  int32 median;
  int32 std_dev;
  uint32 total_no_meas;
  e_chain_mask chain_no;

  s_rtt_stats()
  {
    min = max = median = sum = mean = std_dev = 0.0;
    total_no_meas = 0;
    chain_no = CHAIN_0;
  }
};

// Distance Stats
struct s_dist_stats
{
  float min;
  float max;
  float median;
  float sum;
  float mean;
  float stddev;
  uint32 total_no_meas;
  e_chain_mask chain_no;

  s_dist_stats()
  {
    min = max = median = sum = mean = stddev = 0.0;
    total_no_meas = 0;
    chain_no = CHAIN_0;
  }
};

struct cep_per_chain
{
  float    cep68;
  float    cep90;
  float    cep99;
  float    max_err;
  uint32   total_meas;
  e_chain_mask chain_no;

  cep_per_chain()
  {
    cep68 = cep90 = cep99 = max_err = 0.0;
    total_meas = 0;
    chain_no = CHAIN_0;
  }
};

struct p2p_per_chain
{
  float p2p68;
  float p2p90;
  float p2p99;
  uint32   total_meas;
  e_chain_mask chain_no;

  p2p_per_chain()
  {
    p2p68 = p2p90 = p2p99 = 0.0;
    total_meas = 0;
    chain_no = CHAIN_0;
  }
};

struct rtt_per_chain_info
{
  int rtt_chain0;
  int rtt_chain1;
  int rtt_final;

  rtt_per_chain_info()
  {
    rtt_chain0 = rtt_chain1 = rtt_final = 0;
  }
};

typedef std::pair<struct LOWIPostProcessNode,
        struct rtt_per_chain_info> per_burst_value_pair;

/** per_burst_map will hold
  * KEY   --> SEQ_NO
  * VALUE --> PAIR OF <POST PROCESS NODE, RTT_PER_CHAIN_INFO>
  */
typedef std::map <uint32, per_burst_value_pair> per_burst_map;

typedef vector <struct rtt_node_data> csv_row_db;

/* Function pointer for calling lowi_test functions */
typedef int (*lowi_test_func)(const uint32);

/* Scan command for LOWI test module */
struct t_lowi_test_cmd
{
  t_lowi_scan             cmd;
  LOWIDiscoveryScanRequest::eBand     band;             // 0: 2.4Ghz, 1: 5 Ghz, 2: All
  LOWIDiscoveryScanRequest::eScanType scan_type;        // discovery scans - 0: active 1: passive
  uint16                  num_requests;                 // number of times to repeat the request
  uint16                  delay;                        // delay between successive requests
  uint32                  timeout_offset;               // Timeout offset in seconds
  uint32                  meas_age_filter_sec;          // Measurement age filter
  uint32                  fallback_tolerance;           // Fallback tolerance
  eRttType                rttType;                      // Ranging type to be done
  eRangingBandwidth       ranging_bandwidth;            // BW to be used for Ranging request
  uint8                   subscribe_batching;           // Subscribe/Unsubscribe from batching
  uint32                  threshold_batching;           // Report threshold
  uint8                   flush_buffer_batching;        // Flush batching buffer
  uint32                  max_results_batching;         // Max results/APs to retrieve from batching
  vector <LOWIPeriodicNodeInfo> rttNodes;               // Nodes for RTT
  uint8                   fullBeaconResponse;           // Is full beacon required in the response
  vector <LOWIChannelInfo> chList;                      // For discovery scan channels supplied via xml
  vector <LOWIMacAddress> discoveryBssids;              // Vector of BSSIDs needed for unicast discovery scan
  vector <LOWISsid>       discoverySsids;               // Vector of SSIDs needed for directed probe discovery scan
  vector <LowiTestApInfo> ap_info;                      // AP info saved for stats
  vector <LOWIMacAddress> summary_aps;                  // Summary generated for AP's in this array only
  LOWILciInformation*     lci_info;
  LOWILcrInformation*     lcr_info;
  vector<LOWIFTMRRNodeInfo> ftmrr_info;
  uint16                  rand_inter;
  LOWIConfigRequest*      lowiconfigrequest;
  bool                    need_post_processing;
  struct LowiPostProcessInfo post_process_info;
  uint32                  kpi_mask;                     // KPI STAT DUMP MASK on console
  uint32                  kpi_fs_mask;                  // Mask for controlling logs on FS
  uint32                  trueDist;                     // True distance for all ap in this list
  int32                   req_tx_bw;                    // Requested TX BW for rtt test mode
  int32                   req_rx_bw;                    // Requested RX BW for rtt test mode
  int                     delay_ps_2p4;                 // Expected cable delay in picoseconds for 2.4GHz
  int                     delay_ps_5g;                  // Expected cable delay in picoseconds for 5GHz
  bool                    forceLegAck;                  // Legacy ack for FTM req
  bool                    skip_bw_check;                // Skip req bw check
  //In this mode CSV file will be used for filling
  //the RTT data structure and test the generated O/P.
  bool                    rtt_test_mode;
  uint32                  reportType;
  int                     reportType_cmdline;
  uint32                  max_seq_no_in_csv;
  std::string             interface;

  // default initialization
  t_lowi_test_cmd()
  {
    cmd                   = LOWI_MAX_SCAN;
    band                  = LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ;
    scan_type             = LOWIDiscoveryScanRequest::PASSIVE_SCAN;
    num_requests          = 1;
    delay                 = 3000;
    timeout_offset        = 0;
    meas_age_filter_sec   = LOWI_TEST_MEAS_AGE_FILTER_SEC;
    fallback_tolerance    = 0;            // Do not care as long as it is 0
    rttType               = RTT2_RANGING; // Default Ranging is RTT V2
    ranging_bandwidth     = BW_20MHZ;     // Default 20 Mhz
    subscribe_batching    = 1;            // Default enabled
    threshold_batching    = 50;           // Default 50 %
    flush_buffer_batching = 1;            // Default flush
    max_results_batching  = 100;          // Default 100 APs
    fullBeaconResponse    = 0;            // Default no Full beacon response
    lci_info              = NULL;
    lcr_info              = NULL;
    rand_inter            = 0;
    lowiconfigrequest     = NULL;
    need_post_processing  = FALSE;
    trueDist              = 0;
    kpi_mask              = 0;
    kpi_fs_mask           = 0;
    req_tx_bw             = -1;
    req_rx_bw             = -1;
    delay_ps_2p4          = 0;
    delay_ps_5g           = 0;
    forceLegAck           = false;
    rtt_test_mode         = 0;
    skip_bw_check         = false;
    reportType            = RTT_AGGREGATE_REPORT_NON_CFR;
    reportType_cmdline    = -1;
    max_seq_no_in_csv     = 0;
    interface             = "wifi0";
  }
  ~t_lowi_test_cmd()
  {
    delete lci_info;
    delete lcr_info;
    delete lowiconfigrequest;
    ftmrr_info.flush();
  }
};

/* Statistics data structure */
// For discovery scan
typedef struct
{
  int32 low;
  int32 high;
  float total;
  int32 cnt;
} t_scan_stats;

#define MAX_NUM_RTT_MEASUREMENTS_PER_AP 6
// For ranging scan
typedef struct
{
  int32 rssi_low;
  int32 rssi_high;
  float rssi_total;
  int32 rtt_low;
  int32 rtt_high;
  float rtt_total;
  int32 meas_cnt[MAX_NUM_RTT_MEASUREMENTS_PER_AP];


                     // eg: meas_cnt[5] will record down the number of occurences
                     // that this AP comes back with 5 RTT measurements
  int32 total_meas_cnt; // total RTT measurement cnt for this AP
                        // for exmaple, if in one scan request, there are 4 RTT measurements
                        // come back, then total_meas_cnt will be increased by 4
  int32 total_meas_set_cnt; // cnt of RTT scan attempts with any RTT measurement come back
                            // for example, if in one scan request, if there are one or more
                            // RTT measurements come back for this AP, total_meas_set_cnt for
                            // this AP will be increased by 1
  int32 total_attempt_cnt;  // number of attempts that RTT scan was requested by this AP
                            // in case of -pr option, this number may be different for each AP
                            // as RTT scan is only attempted for APs that were found in
                            // previous discovery scan
} t_rtt_scan_stats;

/* Maintaining RSSI and RTT stats */
typedef struct
{
  t_scan_stats     rssi;
  t_rtt_scan_stats rtt;
  double           total_rssi_mw;     // rssi total in mw for this AP found in discovery scan
  double           total_rtt_rssi_mw; // rssi total in mw for AP found in ranging scan
} t_ap_scan_stats;

/* Local data */
struct t_lowi_test
{
  pthread_mutex_t mutex;
  pthread_cond_t  ps_cond;
  pthread_cond_t  rs_cond;
  uint32          seq_no;         /* Scan Seq # */
  uint32          avg_ps_rsp_ms;  /* Avg discovery scan response time in ms */
  uint32          avg_rs_rsp_ms;  /* Avg ranging scan response time in ms */
  int             clock_id;       /* Clock Id used for timekeeping */
  int64           scan_start_ms;  /* Ms at start of scan */
  int64           scan_end_ms;    /* ms at end of scan */
  FILE *          out_fp;         /* Output FILE */
  FILE *          out_cfr_fp;         /* Output CFR FILE */
  FILE *          summary_fp;     /* Summary output file */
  FILE *          kpi_log_fp;
  int             timerFd;
  bool            dynamic_cap_resp_received; /* Dynamic capability response successfully received*/
  bool            uart_test_success;         /* UART test success or failure*/
  bool            config_test_success;       /* Config test success or failure*/
  bool            scan_success;              /* Scan was success or not*/
  vector<LOWIScanMeasurement> recentMeas;

  //Contructor to set default values
  t_lowi_test()
  {
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&ps_cond, NULL);
    pthread_cond_init(&rs_cond, NULL);
    /* Sequence number to tag the measurements */
    seq_no = 1;
    avg_ps_rsp_ms  = 0;
    avg_rs_rsp_ms  = 0;
#ifdef CLOCK_BOOTTIME
    struct timespec ts;
    clock_id       = ( clock_gettime(CLOCK_BOOTTIME_ALARM, &ts) == 0 ?
                       CLOCK_BOOTTIME_ALARM : CLOCK_REALTIME );
#else
    clock_id       = CLOCK_REALTIME;
#endif
    scan_start_ms  = 0;
    scan_end_ms    = 0;
    out_fp         = NULL;
    out_cfr_fp     = NULL;
    summary_fp     = NULL;
    timerFd        = timerfd_create(clock_id, 0);
    dynamic_cap_resp_received = FALSE;
    uart_test_success         = FALSE;
    config_test_success       = FALSE;
    scan_success              = FALSE;
  }

  ~t_lowi_test()
  {
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&ps_cond);
    pthread_cond_destroy(&rs_cond);
    if (out_fp != NULL)
    {
      fclose(out_fp);
    }
    if (out_cfr_fp != NULL)
    {
      fclose(out_cfr_fp);
    }
    if (summary_fp != NULL)
    {
      fclose(summary_fp);
    }
    if (timerFd != -1)
    {
      close(timerFd);
    }
    if (kpi_log_fp != NULL)
    {
      fclose(kpi_log_fp);
    }
  }
};

/* ModuleId represents the different modules in LOWI,
 * which will be sent as part of xml in  "lowi_test -c <config.xml>"
 * command.
 * Each Enum value has a corresponding array of tags which will
 * be sent as part of LOWIConfigRequest vector LOWILogInfo to set
 * the loglevel for those tags */
enum eModuleId
{
  /* lowi engine related tags,
   * array LOWI_ENGINE_TAGS will be used */
  LOWI_ENGINE = 1,
  /* array LOWI_COMMON_INFO_TAGS, common info
   * like diag and utils */
  LOWI_COMMON_INFO,
  /* array LOWI_CLIENT_INFO_TAGS, tags related to
   * client */
  LOWI_CLIENT_INFO,
  /* array LOWI_SCAN_INFO_TAGS, tags related to
   * scans */
  LOWI_SCANS_INFO,
  /* array LOWI_WIFI_INFO_TAGS, tags related to
   * basic wifi info */
  LOWI_WIFI_INFO,
  /* array LOWI_WIFIDRIVER_INFO_TAGS, tags related to
   * wifidriver and wifidriver interface */
  LOWI_WIFIDRIVER_INFO,
  /* array LOWI_WIFIHAL_INFO_TAGS, tags related to
   * wifihal interface */
  LOWI_WIFIHAL_INFO,
  /* array LOWI_RANGING_INFO_TAGS, tags related to
   * ranging */
  LOWI_RANGING_INFO,
  /* array LOWI_FSM_INFO_TAGS, tags related to
   * state machine */
  LOWI_FSM_INFO,
  /* array LOWI_WIGIG_RANGING_INFO_TAGS, tags related to
   * wigig ranging*/
  LOWI_WIGIG_RANGING_INFO
};

/* struct to hold the moduleid and corresponding log level */
struct LOWIModuleInfo
{
  eModuleId moduleid;
  uint8 log_level;
};

/*=============================================================================
 * lowi_wait_for_passive_scan_results
 *
 * Description:
 *    Wait for passive scan results until timeout
 *
 * Return value:
 *   1 if results were received
 *   0 if timed out waiting for response
 ============================================================================*/
int lowi_wait_for_passive_scan_results(uint32 timeout);

/*=============================================================================
 * lowi_test_extn_response_callback
 *
 * Description:
 *    handle response callback
 *
 * Return value:
 *   0: Success
 ============================================================================*/
extern int lowi_test_extn_response_callback(LOWIResponse *response);

/*=============================================================================
 * lowi_test_get_time_ms
 *
 * Description:
 *    Get the time and convert to ms.
 *
 * Parameters:
 *    None
 *
 * Return value:
 *    Time in ms
 ============================================================================*/
extern int64 lowi_test_get_time_ms(void);

/*=============================================================================
 * lowi_test_log_time_ms_to_string
 *
 * Description:
 *   Convert time in ms to a charater string and fraction of day
 *
 * Parameters:
 *   char*: Pointer to character buffer to store string
 *   int: Buffer size
 *   double*: Pointer to store the time in number of days
 *   uint64: time in ms
 *
 * Return value:
 *   None
 ============================================================================*/
extern void lowi_test_log_time_ms_to_string(char* p_buf, int buf_sz,
                                            double *p_day, uint64 time_ms);

/*=============================================================================
 * lowi_test_log_meas_results
 *
 * Description:
 *   Log the measurement results
 *
 * Return value:
 *   void
 ============================================================================*/
extern void lowi_test_log_meas_results(LOWIResponse::eResponseType rspType,
                                       vector <LOWIScanMeasurement*> &scanMeas);

/*=============================================================================
 * lowi_test_do_passive_scan
 *
 * Description:
 *    Start the Passive Scan
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_passive_scan(const uint32 seq_no);

/*=============================================================================
 * lowi_test_do_rtt_scan
 *
 * Description:
 *    Do the RTS/CTS Scan
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_rtt_scan(const uint32 seq_no);

/*=============================================================================
 * lowi_test_do_combo_scan
 *
 * Description:
 *    Do a discovery Scan followed by ranging Scan
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_combo_scan(const uint32 seq_no);

/*=============================================================================
 * lowi_test_do_async_discovery_scan
 *
 * Description:
 *    Starts the async discovery scan
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_async_discovery_scan(const uint32 seq_no);

/*=============================================================================
 * lowi_test_do_neighbor_report_request
 *
 * Description:
 *    Do Neighbor Report Request
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_neighbor_report_request(const uint32 seq_no);

/*=============================================================================
 * lowi_test_do_wlan_state_query_request
 *
 * Description:
 *    Do Neighbor Report Request
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_do_wlan_state_query_request(const uint32 seq_no);

/*=============================================================================
 * lowi_test_set_lci
 *
 * Description:
 *    This function sets the LCI information.
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_set_lci(const uint32 seq_no);

/*=============================================================================
 * lowi_test_set_lcr
 *
 * Description:
 *    This function sets the LCR information.
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_set_lcr(const uint32 seq_no);

/*=============================================================================
 * lowi_test_where_are_you
 *
 * Description:
 *    This function requests the where are you information.
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_where_are_you(const uint32 seq_no);

/*=============================================================================
 * lowi_test_ftmrr
 *
 * Description:
 *    This function requests the FTM Ranging measurements.
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_ftmrr(const uint32 seq_no);
/*=============================================================================
 * lowi_test_config_req
 *
 * Description:
 *    This function requests the Config request
 *    currently only Log config is supported..
 *
 * Return value:
 *   0: Success
 ============================================================================*/
int lowi_test_config_req(const uint32 seq_no);
int lowi_test_start_responder_meas_req(const uint32 seq_no);
int lowi_test_stop_responder_meas_req(const uint32 seq_no);

#define TIME_STR_LEN 24

struct rtt_node_data
{
  char time[TIME_STR_LEN];
  char time_days [TIME_STR_LEN];
  int scan_type;
  unsigned char mac[6];
  char mac_str[TIME_STR_LEN];
  unsigned int seq_no;
  unsigned int channel;
  int rssi;
  int rtt;
  int rsp_time;
  int meas_age;
  char ssid[34];
  unsigned int rtt_type;
  unsigned int phy_mode;
  unsigned int tx_preamble;
  unsigned int tx_nss;
  unsigned int tx_bw;
  unsigned int tx_mcs;
  unsigned int tx_bit_rate;
  unsigned int rx_preamble;
  unsigned int rx_nss;
  unsigned int rx_bw;
  unsigned int rx_mcs;
  unsigned int rx_bit_rate;
  int tx_chain;
  int rx_chain;
  int burst_rtt;

  rtt_node_data()
  {
    scan_type = 0;
    seq_no = channel = 0;
    rssi = 0;
    rtt = rtt_type = burst_rtt = 0;
    meas_age = rsp_time = 0;
    phy_mode = 0;
    tx_preamble = tx_nss = tx_bw = tx_mcs = tx_bit_rate = 0;
    rx_preamble = rx_nss = rx_bw = rx_mcs = rx_bit_rate = 0;
    tx_chain = rx_chain = -1;
    memset(mac, 0, 6);
    memset(time, 0, TIME_STR_LEN);
    memset(time_days, 0, TIME_STR_LEN);
    memset(mac_str, 0, TIME_STR_LEN);
    memset(ssid, 0, 34);
  }

  ~rtt_node_data()
  {
  }

};

enum RTT_COL_KEY
{
  KEY_TIME          = 0x0,
  KEY_TIME_DAYS,
  KEY_SCAN_TYPE,
  KEY_MAC,
  KEY_SEQ_NO,
  KEY_CHANNEL,
  KEY_RSSI,
  KEY_RTT,
  KEY_RSP_TIME,
  KEY_MEAS_AGE,
  KEY_SSID,
  KEY_RTT_TYPE,
  KEY_PHY_MODE,
  KEY_TX_PREAM,
  KEY_TX_NSS,
  KEY_TX_BW = 0xf,
  KEY_TX_MCS,
  KEY_TX_BIT_RATE,
  KEY_RX_PREAM,
  KEY_RX_NSS,
  KEY_RX_BW,
  KEY_RX_MCS,
  KEY_RX_BIT_RATE,
  KEY_TX_CHAIN,
  KEY_RX_CHAIN,
  KEY_RTT_PER_BURST,
  //Max Key
  KEY_MAX
};

void lowi_read_csv_file(csv_row_db &all_meas_db, const char* path);
void lowi_fill_node_from_dict(csv_row_db &all_meas_db);
void lowi_process_node_dict(void);
void lowi_process_node(struct LOWIPostProcessNode* ap_node);
void lowi_calculate_kpi(const char* path);

#ifdef __cplusplus
}
#endif

#endif /* __LOWI_TEST_INTERNAL_H__ */
