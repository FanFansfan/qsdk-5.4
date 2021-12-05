/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

         LOWI Wireless Scan Service Test Module (LOWI Test)

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Test. It exercises the LOWI
  module.

Copyright (c) 2010, 2013-2021 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2013, 2014 Qualcomm Atheros, Inc.
All Rights Reserved.
Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

/*--------------------------------------------------------------------------
 * Include Files
 * -----------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/param.h>
#include "lowi_defines.h"
#include "lowi_wrapper.h"
#include "lowi_request.h"
#include "lowi_utils.h"
#include "lowi_response.h"
#include "lowi_request_extn.h"
#include "lowi_response_extn.h"
#include "lowi_test_internal.h"
#include <algorithm>
#include <numeric>
#include <cstdlib>
#include <cmath>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <map>

#undef LOG_TAG
#define LOG_TAG LOWI_TEST_VERSION

using namespace qc_loc_fw;

/* for LOWI_ENGINE moduleId */
static const char* LOWI_ENGINE_TAGS[] =
{
  "LOWIController",
  "LOWIControllerExtn",
  "LOWIScheduler",
  "LOWIEventDispatcher",
  "LOWIEventReceiver",
  "LOWIBackgroundScanMgr"
};

/* for LOWI_COMMON_INFO moduleId */
static const char* LOWI_COMMON_INFO_TAGS[] =
{
  "LOWIDiagLog",
  "LOWIUtils",
  "LOWIUtilsExtn",
  "LOWISsid",
  "LOWIMacAddress",
  "LOWICacheManager",
  "LOWIScanMeasurement",
  "LOWIFullBeaconScanMeasurement",
  "LOWIRequest",
  "LOWIResponse",
  "LOWICapabilities",
  "LOWIInternalMessage",
  "LOWILocalMsg",
  "LOWIMeasurementResultBase",
  "LOWIWpaInterface"
};

/* for LOWI_CLIENT_INFO moduleId */
static const char* LOWI_CLIENT_INFO_TAGS[] =
{
  "LOWIClient",
  "LOWIClientReceiver",
  "LOWIClientListener",
  "LOWIQMIClient"
};

/* for LOWI_SCANS_INFO  moduleId */
static const char* LOWI_SCANS_INFO_TAGS[] =
{
  "LOWI-Scan",
  "LOWIScanRequestSender",
  "LOWIScanResultReceiver",
  "LOWIDiscoveryScanResultReceiver",
  "LOWILPScanResultReceiver",
  "LOWIRangingScanResultReceiver",
  "LOWIBgScanResultReceiver",
  "LOWIMeasurementResult",
  "LOWIWigigRangingSicanResultReceiver",
  "LOWIBackgroundScanMgr"
};

/* for LOWI_WIFI_INFO  moduleId */
static const char* LOWI_WIFI_INFO_TAGS[] =
{
  "LOWINetlinkSocketReceiver",
  "LOWIController"
};

/* for LOWI_WIFIDRIVER_INFO  moduleId */
static const char* LOWI_WIFIDRIVER_INFO_TAGS[] =
{
  "LOWIWifiDriverInterface",
  "LOWIAR6KWifiDriver",
  "LOWIExternalWifiDriver",
  "LOWIFakeWifiDriver",
  "LOWIHeliumWifiDriver",
  "LOWIProntoWifiDriver",
  "LOWIRivaWifiDriver",
  "LOWIROMEWifiDriver",
};

/* for LOWI_WIFIHAL_INFO  moduleId */
static const char* LOWI_WIFIHAL_INFO_TAGS[] =
{
  "LOWI_WIFI_HAL",
  "LowiWifiHal"
};

/* for LOWI_RANGING_INFO  moduleId */
static const char* LOWI_RANGING_INFO_TAGS[] =
{
  "LOWIRangingScanResultReceiver",
  "LOWI-HELIUM-RTT",
  "LOWI-P2P-RTT",
  "LOWI-ROME-RTT",
  "LOWIDynBuffer",
  "LOWITlv",
  "LOWIWifiTlvHandler",
  "LOWISparrowRanging",
  "LOWINetlinkMsg"
};

/* for LOWI_FSM_INFO  moduleId */
static const char* LOWI_FSM_INFO_TAGS[] =
{
  "LOWIRangingFSM",
  "LOWIRangingHeliumFSM",
  "LOWIRangingProntoFSM"
};

/* for LOWI_WIGIG_RANGING_INFO  moduleId */
static const char* LOWI_WIGIG_RANGING_INFO_TAGS[] =
{
  "LOWIWigigRangingScanResultReceiver",
  "LOWIWigigNetLinkInf",
  "LOWISparrowWigigDriver",
  "LOWIRangingSparrowFSM"
};

// Holds the command line arguments
t_lowi_test_cmd *lowi_cmd = NULL;

t_lowi_test_cmd rtt_scan_cmd;

t_lowi_test lowi_test;

t_ap_scan_stats scan_stats[MAX_BSSIDS_STATS];

#define INTERFACE_MAX_LENGTH 64
/* KPI DUMP MASK on console -kdm */
#define DUMP_KPI_EXT  0x0001 // Mask for VENDORS ( default value)
#define DUMP_KPI_INT  0x0010 // Mask for dumping complete kpi

#define CAN_DUMP_INT_KPI_STATS(mask) (mask & DUMP_KPI_INT)
#define CAN_DUMP_EXT_KPI_STATS(mask) (mask & DUMP_KPI_EXT)

/* KPI FS Log MASK -kfm */
enum kpi_fs_log_mask
{
  LM_HIGH = 0x0001,
  LM_MED  = 0x0002,
  LM_LOW  = 0x0004
};

// Print on kpi_log_fp files aka LOWI_KPI_LOG_FILE
static void print_kpi_fs(enum kpi_fs_log_mask mask, const char *fmt, ...)
{
  if (lowi_cmd->kpi_fs_mask & mask)
  {
    va_list args;
    va_start (args, fmt);
    if (lowi_test.kpi_log_fp != NULL)
    {
      vfprintf(lowi_test.kpi_log_fp, fmt, args);
    }
    va_end (args);
  }
}

#define lowi_pr_kpi_fs print_kpi_fs
#define pr_kpi_fs(log_level, format, args...) \
        lowi_pr_kpi_fs(log_level, format, ## args)

#define pr_kpi_fs_high(params...) pr_kpi_fs(LM_HIGH, ## params)
#define pr_kpi_fs_med(params...)  pr_kpi_fs(LM_MED, ## params)
#define pr_kpi_fs_low(params...)  pr_kpi_fs(LM_LOW, ## params)

/* String representation of Scan types */
const char * scan_type_str[LOWI_MAX_SCAN] = { "DISCOVERY", "RANGING",
  "BOTH - DISCOVERY & RANGING",  "ASYNC DISCOVERY", "BATCHING",
  "ANQP", "NEIGHBOR REPORT", "UART TEST", "WLAN STATE QUERY", "SET LCI REQUEST",
  "SET LCR REQUEST", "WRU REQUEST", "FTMR REQUEST", "CONFIG REQUEST"};


extern lowi_test_func lowi_test_function[LOWI_MAX_SCAN];
ERROR_LEVEL lowi_test_debug_level = EL_WARNING;
/*--------------------------------------------------------------------------
 * Function Definitions
 * -----------------------------------------------------------------------*/
extern int clock_nanosleep(int clock_id, int flags, const struct timespec *req,
                           struct timespec *rem);

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
int64 lowi_test_get_time_ms(void)
{
  struct timespec ts;

  clock_gettime(lowi_test.clock_id, &ts);
  QUIPC_DBG_HIGH ("TIME Read = %ld.%09ld = %" PRId64 "msec", ts.tv_sec, ts.tv_nsec,
        (((int64)ts.tv_sec) * MSECS_PER_SEC) + ts.tv_nsec/NSECS_PER_MSEC);

  return (((int64)ts.tv_sec) * MSECS_PER_SEC) + ts.tv_nsec/NSECS_PER_MSEC;


}

static void lowi_test_start_timer(const uint16 duration_ms)
{
  struct itimerspec its;
  int64 start_time_ms;

  its.it_value.tv_sec  = duration_ms/MSECS_PER_SEC;
  its.it_value.tv_nsec = (duration_ms%MSECS_PER_SEC) * NSECS_PER_MSEC;
  its.it_interval.tv_sec  = 0;
  its.it_interval.tv_nsec = 0;
  int ret = timerfd_settime(lowi_test.timerFd, 0, &its, NULL);

  if(ret != 0)
  {
      QUIPC_DBG_HIGH("timerfd_settime failed ret = %d %d, %s",
            ret, errno, strerror(errno));
  }

  start_time_ms = lowi_test_get_time_ms();
  QUIPC_DBG_HIGH ("Timer Set at %" PRId64 " ms for %d ms",
                  start_time_ms, duration_ms);

}

static void lowi_test_wait( const uint16 duration_ms )
{
  int        ret_val;
  int64      end_time_ms;
  uint64     exp; /* this variable will be greater than or equal to one if timer
                     expires,otherwise it will be returned zero at timefd read call   */

  if (duration_ms == 0)
  {
    return;
  }
  do
  {
    LOWI_TEST_REL_WAKE_LOCK;
    ret_val = read (lowi_test.timerFd, &exp, sizeof (exp));
    LOWI_TEST_REQ_WAKE_LOCK;

    if(ret_val < 0)
    {
        QUIPC_DBG_HIGH ("lowi_test_wait: read of timerFd failed %s",strerror(errno));
        return;
    }

    if (exp >= 1)
    {
      end_time_ms = lowi_test_get_time_ms();
      QUIPC_DBG_HIGH ("timer ends at %" PRId64 " ms", end_time_ms);
      break;
    }
  }
  while (1);

}

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
void lowi_test_log_time_ms_to_string(char* p_buf, int buf_sz,
                                     double *p_day, uint64 time_ms)
{
  uint64 seconds = time_ms/1000;
  uint64 ms = time_ms - (seconds*1000);

  struct tm* time = localtime((time_t*)&seconds);
  if (NULL != time)
  {
    snprintf(p_buf, buf_sz,
        "%d/%d/%d %d:%d:%d.%03" PRIu64,
        time->tm_year + 1900,
        time->tm_mon + 1,
        time->tm_mday,
        time->tm_hour,
        time->tm_min,
        time->tm_sec,
        ms
    );
    if (p_day != NULL)
    {
      *p_day = time->tm_sec +  (double)ms/1000.0; /* In seconds */
      *p_day = time->tm_min +  (*p_day)/60.0;     /* In minutes */
      *p_day = time->tm_hour + (*p_day)/60.0;     /* In hours */
      *p_day = time->tm_mday + (*p_day)/24.0;     /* In days  */
    }
  }
}

/*=============================================================================
 * rssi_total_in_watt
 *
 * Description:
 *    Total the RSSI in milliWatts
 *
 * Return value:
 *   void
 ============================================================================*/
void rssi_total_in_watt(const t_lowi_scan scan_type,
                        t_ap_scan_stats *const ap_stat_ptr,
                        const int32 rssi_0p5dBm)
{
  double rssi_mwatt = pow(10, (double)rssi_0p5dBm/20);

  if (ap_stat_ptr == NULL)
  {
    return;
  }

  if (scan_type == LOWI_DISCOVERY_SCAN)
  {
    ap_stat_ptr->total_rssi_mw += rssi_mwatt;
  }
  else if (scan_type == LOWI_RTS_CTS_SCAN)
  {
    ap_stat_ptr->total_rtt_rssi_mw += rssi_mwatt;
  }
  else
  {
    QUIPC_DBG_HIGH ("Unexpected scan type %d in scan stats", scan_type);
  }
}

/*=============================================================================
 * add_data_to_stat
 *
 * Description:
 *    Add current results to statictics data set
 *    For discovery scan, rssi is processed.
 *    For ranging scan, both rssi and rtt is processed.
 *
 * Return value:
 *   void
 ============================================================================*/
void add_data_to_stat(t_lowi_scan scan_type,
                      t_ap_scan_stats *const ap_stat_ptr,
                      const int32 new_data,
                      const int32 rtt_new_data)
{
  if (ap_stat_ptr == NULL)
  {
    return;
  }

  if (scan_type == LOWI_DISCOVERY_SCAN)
  {
    if (ap_stat_ptr->rssi.cnt == 0)
    {
      ap_stat_ptr->rssi.low  = new_data;
      ap_stat_ptr->rssi.high = new_data;
    }
    else
    {
      // we allow input rssi to be 0, so we can catch it for debug
      if (new_data < ap_stat_ptr->rssi.low)
      {
        ap_stat_ptr->rssi.low = new_data;
      }
      if (new_data > ap_stat_ptr->rssi.high)
      {
        ap_stat_ptr->rssi.high = new_data;
      }
    }
    ap_stat_ptr->rssi.total += new_data;
    ap_stat_ptr->rssi.cnt++;
  }
  else if (scan_type == LOWI_RTS_CTS_SCAN)
  {
    // we allow input rssi and rtt to be 0,
    // so we can catch it for debug
    if (ap_stat_ptr->rtt.total_meas_cnt == 0)
    {
      ap_stat_ptr->rtt.rssi_low  = new_data;
      ap_stat_ptr->rtt.rssi_high = new_data;
      ap_stat_ptr->rtt.rtt_low   = rtt_new_data;
      ap_stat_ptr->rtt.rtt_high  = rtt_new_data;
    }
    else
    {
      if (new_data < ap_stat_ptr->rtt.rssi_low)
      {
        ap_stat_ptr->rtt.rssi_low = new_data;
      }
      if (new_data > ap_stat_ptr->rtt.rssi_high)
      {
        ap_stat_ptr->rtt.rssi_high = new_data;
      }

      if (rtt_new_data < ap_stat_ptr->rtt.rtt_low)
      {
        ap_stat_ptr->rtt.rtt_low = rtt_new_data;
      }
      if (rtt_new_data > ap_stat_ptr->rtt.rtt_high)
      {
        ap_stat_ptr->rtt.rtt_high = rtt_new_data;
      }
    }

    ap_stat_ptr->rtt.rssi_total += new_data;
    ap_stat_ptr->rtt.rtt_total  += rtt_new_data;
    ap_stat_ptr->rtt.total_meas_cnt++;
  }
  else
  {
    QUIPC_DBG_HIGH ("combined scan type in scan result, not supported in lowi test\n");
  }
}

/*=============================================================================
 * lowi_printf
 *
 * Description:
 *    Print data to stream pointed by fp and also stdout
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_printf(FILE * fp, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  if (fp != NULL)
  {
    vfprintf(fp, fmt, args);
  }
  vprintf (fmt, args);
  va_end (args);
}

void LOWIPostProcessNode::resetNodeMetaData()
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

void LOWIPostProcessNode::getNodeMetaData( struct LOWIPostProcessNode& out_node )
{
  memset(&out_node.bssid, 0, 6);
  out_node.bssid = bssid;
  out_node.true_dist = true_dist;
  out_node.delay_ps_2p4 = delay_ps_2p4;
  out_node.delay_ps_5g =  delay_ps_5g;
  out_node.forceLegAck  = forceLegAck;
  out_node.skip_first = skip_first;
  out_node.total_cnt = total_cnt;
  out_node.req_tx_bw = req_tx_bw;
  out_node.req_rx_bw = req_rx_bw;
  out_node.frame_per_burst = frame_per_burst;
  out_node.band = band;
}

void LOWIPostProcessNode::getRttCacheVec( struct LOWIPostProcessNode& out_node )
{
  for (uint32 count = 0; count < this->rtt_cache.getNumOfElements(); count++)
  {
    out_node.rtt_cache.push_back(this->rtt_cache[count]);
  }
}

bool lowi_test_is_ap_in_list(LOWIMacAddress mac, vector <LOWIMacAddress>& list)
{
  bool found = false;
  for (vector <LOWIMacAddress>::Iterator it = list.begin();
       it != list.end(); ++it)
  {
    if (mac.compareTo(*it) == 0)
    {
      found = true;
      break;
    }
  }
  return found;
}

#define HUGE_STD_DEV (0x80000000) //0x80000000
//Computes the std dev of the numbers in the vector passed in
static int compute_stddev_int(vector <int> ip)
{
  int size = ip.getNumOfElements();
  vector <int> d2list;
  float variance;

  if (size)
  {
    int sum = std::accumulate(ip.begin(), ip.end(), 0);
    int mean = sum/size;
    for (int item = 0; item < size; item++)
    {
      int d2 = pow((ip[item] - mean), 2);
      d2list.push_back(d2);
    }
    if (d2list.getNumOfElements() && (d2list.begin() != NULL))
      variance= std::accumulate(d2list.begin(), d2list.end(), 0.0)/d2list.getNumOfElements();
    else
      variance = 0.0;
    return int(sqrt(variance));
  }
  return HUGE_STD_DEV;
}

static float compute_stddev_float(vector <float> ip)
{
  uint32 size = ip.getNumOfElements();
  vector <float> d2list;
  float variance;

  if (size)
  {
    float sum = std::accumulate(ip.begin(), ip.end(), 0.0);
    float mean = sum/size;
    for (uint32 item = 0; item < size; item++)
    {
      float d2 = pow((ip[item] - mean), 2);
      d2list.push_back(d2);
    }
    if (d2list.getNumOfElements() && (d2list.begin() != NULL))
      variance= std::accumulate(d2list.begin(), d2list.end(), 0.0)/d2list.getNumOfElements();
    else
      variance = 0.0;
    return float(sqrt(variance));
  }
  return (int)HUGE_STD_DEV;
}

static int compute_median_int(vector <int> ip)
{
  int size = ip.getNumOfElements();

  std::sort(ip.begin(), ip.end());
  if (size % 2 != 0)
  {
    return (ip[size / 2]);
  }
  else
  {
    int num1 = ip[size/ 2];
    int num2 = ip[size/2 -  1];
    return (num1+num2)/2;
  }
}

static float compute_median_float(vector <float> ip)
{
  int size = ip.getNumOfElements();

  std::sort(ip.begin(), ip.end());
  if (size % 2 != 0)
  {
    return (ip[size / 2]);
  }
  else
  {
    float num1 = ip[size/ 2];
    float num2 = ip[size/2 -  1];
    return (num1+num2)/2;
  }
}

/*
 * Packet BW (MHz)  OTARangeErrorSTDKPI(m)  RTT KPI (ns)  Recommended STD Th (ns)
 * 80+80            0.84                    5.60          28.00 (5.60 * 5 )
 * 80               1.05                    7.00          35.00 ( 7 * 5 )
 * 40               1.39                    9.27          46.33 (9.27 * 5 )
 * 20               3.15                    21.00         105.00 ( 21 * 5 )
 *
 * standard deviation of 6m, 3m, 1.5m, 1m for different bandwidths.
 * Values are in nano sec's
 */
const float RTT_STDDEV[qc_loc_fw::BW_MAX] =
  {21.00, 9.27, 7.00, 5.60};

static int mStdDevMult = 5;

// Convert literal Constant define/Enum name to string
#define TESTCONST2STR(x) case x: return #x
char const * to_string(e_chain_mask a)
{

  switch ( a)
  {
    case CHAIN_0: return "chain_0";
    case CHAIN_1: return "chain_1";
    case CHAIN_01: return "chain_both";
    default: return "CHAIN_UNKNOWN";
  }
}

static float lowi_compute_float_mean(vector <int> &rtt_ps_cache)
{

  float sum, mean = 0.0;
  vector <float> rtt_ns;

  if (rtt_ps_cache.getNumOfElements() == 0)
   return 0.0;

  for (uint32 item = 0; item < rtt_ps_cache.getNumOfElements(); item++)
  {
    rtt_ns.push_back(rtt_ps_cache[item]/1000.0);
  }

  if (rtt_ns.getNumOfElements() && (rtt_ns.begin() != NULL))
  {
    sum = std::accumulate(rtt_ns.begin(), rtt_ns.end(), 0.0);
    mean = sum/rtt_ns.getNumOfElements();
  }

  return mean;
}

static float lowi_compute_float_median(vector <struct result_data> &rtt_ps_chain)
{
  if (rtt_ps_chain.getNumOfElements() == 0)
  {
    pr_kpi_fs_high ("\n%s: For there is no measurement hence skip it", __func__);
    return 0.0;
  }

  // Convert RTT PSec to Nsec
  vector <float> rtt_ns;
  for (uint32 item = 0; item < rtt_ps_chain.getNumOfElements(); item++)
  {
    rtt_ns.push_back(rtt_ps_chain[item].rtt/1000.0);
  }

  return compute_median_float(rtt_ns);
}

static void lowi_filter_vector(vector <struct result_data> &rtt_ps_chain,
    vector <int> &fil_rtt_ps_chain, e_chain_mask chain, float meas_median)
{

  if (rtt_ps_chain.getNumOfElements() == 0)
  {
    pr_kpi_fs_high ("\n%s: For chain_no_%s there is no meas hence skip it",
       __func__, to_string(chain));
    return;
  }

  float highThresh, lowThresh, rtt_ns = 0.0;
  uint8 bw = 0;

  for (uint32 item = 0; item < rtt_ps_chain.getNumOfElements(); item++)
  {
    bw = MIN(rtt_ps_chain[item].rx_bw, rtt_ps_chain[item].tx_bw);
    if (bw < qc_loc_fw::BW_20MHZ || bw > qc_loc_fw::BW_160MHZ)
      bw = qc_loc_fw::BW_20MHZ;
    highThresh = meas_median + mStdDevMult*RTT_STDDEV[bw];
    lowThresh  = meas_median - mStdDevMult*RTT_STDDEV[bw];
    rtt_ns = rtt_ps_chain[item].rtt/1000.0;
    if ((rtt_ns > highThresh) || (rtt_ns < lowThresh))
    {
      pr_kpi_fs_high("\n%s: Removed outlier at %d val %d",
         __FUNCTION__, item, rtt_ns);
      continue;
    }
    fil_rtt_ps_chain.push_back(rtt_ps_chain[item].rtt);
  }

}

#define HYPEN_LINE "\n----------------------------------------------"

static void lowi_print_dist_stats(
    struct s_dist_stats &dist_stats, bool forFirst)
{
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  if (forFirst)
    lowi_printf(lowi_test.summary_fp,
                  "\nPost filtering stats first measurements");

  lowi_printf(lowi_test.summary_fp,
              "\nDistance stats...(cm) from total measurements (%u)",
              dist_stats.total_no_meas);

  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
    lowi_printf(lowi_test.summary_fp,
                "\n mean(%5.1f) median(%5.1f) stddev(%5.1f) max(%5.1f) min(%5.1f)",
                float(dist_stats.mean), float(dist_stats.median),
                float(dist_stats.stddev), float(dist_stats.max),
                float(dist_stats.min));
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
    lowi_printf(lowi_test.summary_fp,
                "\n median(%5.1f)", float(dist_stats.median));
}

static struct s_dist_stats compute_dist_stat(vector <int> &rtt_cache)
{
  struct s_dist_stats dist_stat;
  //convert rtt to dist in cm
  vector <float> distcm;
  float dist;

  if (rtt_cache.getNumOfElements() == 0)
  {
    pr_kpi_fs_high("\nNo measurements in ap_node_cache for distance stats");
    return dist_stat;
  }

  for (uint32 item = 0; item < rtt_cache.getNumOfElements(); item++)
  {
    dist = 0.5 * 30.0 * (float(rtt_cache[item])/1000.0);
    distcm.push_back(dist);
  }

  dist_stat.total_no_meas = distcm.getNumOfElements();
  if (distcm.getNumOfElements() && (distcm.begin() != NULL))
  {
    dist_stat.min = *std::min_element(distcm.begin(), distcm.end());
    dist_stat.max = *std::max_element(distcm.begin(), distcm.end());
    dist_stat.sum = std::accumulate(distcm.begin(), distcm.end(), 0.0);
    dist_stat.mean = dist_stat.sum/distcm.getNumOfElements();
    dist_stat.median = compute_median_float(distcm);
    dist_stat.stddev = compute_stddev_float(distcm);
  }

  return dist_stat;
}

static void lowi_split_rtt_per_chain_wise(
    struct LOWIPostProcessNode* ap_node,
    e_chain_mask chain_mask,
    vector <struct result_data> &rtt_ps_vec)
{
  uint8 bw = 0;
  pr_kpi_fs_high("\n%s: requested %s, Total measurments for this ap_node %d",
                __func__, to_string(chain_mask),
                ap_node->rtt_cache.getNumOfElements());
  for (uint32 item = 0; item < ap_node->rtt_cache.getNumOfElements(); item++)
  {
    // consider Rx bandwidth, if it is lesser then
    // request Bw then discard this measurement.
    if (!lowi_cmd->skip_bw_check &&
        ((ap_node->rtt_cache[item].rx_bw != ap_node->req_rx_bw) ||
        (ap_node->rtt_cache[item].tx_bw != ap_node->req_tx_bw)))
    {
      pr_kpi_fs_high ("\n\tDrop RTT meas %d as Tx(%d)/rx(%d) BW mismatch from req Tx(%d) Rx(%d) BW",
                     ap_node->rtt_cache[item].rtt,
                     ap_node->rtt_cache[item].tx_bw,
                     ap_node->rtt_cache[item].rx_bw,
                     ap_node->req_tx_bw,  ap_node->req_rx_bw);
      continue;
    }

    bw = MIN(ap_node->rtt_cache[item].rx_bw, ap_node->rtt_cache[item].tx_bw);
    if (bw >= BW_MAX)
    {
      pr_kpi_fs_high("\n\tDrop this RTT meas %d due to invalid bandwidth %d",
                    ap_node->rtt_cache[item].rtt, bw);
      continue;
    }

    // We need to convert rx_chain_no in to chain mask
    // and then ORed with input chain mank
    int rx_chain_mask = (ap_node->rtt_cache[item].rx_chain_no == -1) ? -1 :
                         (1 << ap_node->rtt_cache[item].rx_chain_no);
    pr_kpi_fs_low("\n\tRTT Meas rx %s in rx_chain_no %d ",
                  to_string((e_chain_mask)rx_chain_mask),
                  ap_node->rtt_cache[item].rx_chain_no);
    if ((rx_chain_mask != -1) && (rx_chain_mask & chain_mask))
    {
       rtt_ps_vec.push_back(ap_node->rtt_cache[item]);
    }
    else
    {
      pr_kpi_fs_low("\n\tDrop this RTT meas %d due to wrong RX %s",
                    ap_node->rtt_cache[item].rtt,
                    to_string((e_chain_mask)rx_chain_mask));
    }
  }

  pr_kpi_fs_high("\n\tTotal no RTT meas %d for this rx %s",
                 rtt_ps_vec.getNumOfElements(), to_string(chain_mask));
}

static struct s_dist_stats
lowi_dist_stats_of_ap_node(struct LOWIPostProcessNode* ap_node)
{
  pr_kpi_fs_high("\n***Process distance stats from raw data for ap_node");
  struct s_dist_stats dist_data;
  vector <struct s_dist_stats> dist_chain_db;
  vector <struct result_data> rtt_ps_vec;
  vector <int> flt_rtt_ps_vec; //filtered data
  float median = 0.0;

  for (uint32 chain_no = CHAIN_0; chain_no < CHAIN_MAX; chain_no++)
  {
    rtt_ps_vec.flush();
    flt_rtt_ps_vec.flush();
    lowi_split_rtt_per_chain_wise(ap_node, (e_chain_mask)chain_no, rtt_ps_vec);
    median = lowi_compute_float_median(rtt_ps_vec);
    lowi_filter_vector(rtt_ps_vec,
                       flt_rtt_ps_vec, (e_chain_mask)chain_no, median);
    pr_kpi_fs_low("\nNon filter RTT meas count %d filtered meas count %d",
       rtt_ps_vec.getNumOfElements(), flt_rtt_ps_vec.getNumOfElements());
    if (flt_rtt_ps_vec.getNumOfElements())
    {
      dist_data = compute_dist_stat(flt_rtt_ps_vec);
      dist_data.chain_no = (e_chain_mask)chain_no;
      dist_chain_db.push_back(dist_data);
      pr_kpi_fs_high("\nDist mean %d of chain %d", dist_data.mean, chain_no);
    }
  }

  struct s_dist_stats ret_stats;
  if (dist_chain_db.getNumOfElements())
  {
    ret_stats = dist_chain_db[0];
    for (uint32 cnt = 1; cnt <dist_chain_db.getNumOfElements(); cnt++)
    {
      if (ret_stats.mean == 0)
        ret_stats = dist_chain_db[cnt];
      else if ((dist_chain_db[cnt].mean > 0) &&
          (ret_stats.mean > dist_chain_db[cnt].mean))
      {
        ret_stats = dist_chain_db[cnt];
      }
    }
  }
  return ret_stats;
}

//Compute CEP68, CEP90 and CEP99
static struct cep_per_chain  compute_cep_true_dist(int true_dist,
    vector <int> &flt_rtt_ps)
{

  float cep68, cep90, cep99, sum = 0.0;
  vector <float> errDiffs;
  float dist = 0.0;//distance in cm
  struct cep_per_chain cep_data;

  pr_kpi_fs_high ("\n%s:enter ", __func__);
  memset(&cep_data, 0, sizeof(struct cep_per_chain));
  cep_data.total_meas = flt_rtt_ps.getNumOfElements();

  if (true_dist)
  {
    for (uint32 item = 0; item < flt_rtt_ps.getNumOfElements(); item++)
    {
      dist = 0.5 * 30.0 * (float(flt_rtt_ps[item])/1000.0);
      errDiffs.push_back(std::abs(dist - true_dist));
      pr_kpi_fs_low("\n\tDistance %f err diff %f",
                         dist, std::abs(dist - true_dist));
    }
    if(errDiffs.getNumOfElements())
      std::sort(errDiffs.begin(), errDiffs.end());
    else
      goto out;
    // calculate CEP68, CEP90 and CEP99
    cep68 = int(std::ceil(errDiffs.getNumOfElements() * .68))-1;
    cep90 = int(std::ceil(errDiffs.getNumOfElements() * .90))-1;
    cep99 = int(std::ceil(errDiffs.getNumOfElements() * .99))-1;
    cep_data.cep68 = errDiffs[cep68];
    cep_data.cep90 = errDiffs[cep90];
    cep_data.cep99 = errDiffs[cep99];
    if (errDiffs.begin())
        cep_data.max_err = *std::max_element(errDiffs.begin(), errDiffs.end());
  }

out:
  pr_kpi_fs_high ("\n%s:exit ", __func__);
  return cep_data;

}

static void lowi_print_cep_true_dist_of_all_meas(
    vector <struct cep_per_chain> &cep_chain_db)
{
  // This is for internal purpose so we can dump all KPI info
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    for (uint32 item = 0; item < cep_chain_db.getNumOfElements(); item++)
    {
      if (cep_chain_db[item].total_meas)
      {
        lowi_printf(lowi_test.summary_fp,
                    "\n === CEP trueDistance for %s (%lu measurements)===",
                    to_string(cep_chain_db[item].chain_no),
                    cep_chain_db[item].total_meas);
        lowi_printf(lowi_test.summary_fp,
                    "\n cep68(%6.2f) cep90(%6.2f) cep99(%6.2f)",
                    cep_chain_db[item].cep68,
                    cep_chain_db[item].cep90, cep_chain_db[item].cep99);
        lowi_printf(lowi_test.summary_fp,
                    "\n (maxErr: %f)", cep_chain_db[item].max_err);
      }
      else
      {
        pr_kpi_fs_high ("\n%s: For %s there is no measurement hence skip it",
                        __func__, to_string(cep_chain_db[item].chain_no));
        lowi_printf(lowi_test.summary_fp,
                    "\n ===  CEP trueDistance for %s === ",
                    to_string(cep_chain_db[item].chain_no));
        lowi_printf(lowi_test.summary_fp, "\n cep68:0   cep90:0  cep99: 0");
      }
    }
  }
  // This is for oem purpose so we need to dump only CEP of both chain
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    for (uint32 item = 0; item < cep_chain_db.getNumOfElements(); item++)
    {
      if (cep_chain_db[item].chain_no == CHAIN_01)
      {
        lowi_printf(lowi_test.summary_fp, "\n cep90(%6.2f)",
                    cep_chain_db[item].cep90);
      }
    }
  }
}

static void lowi_print_cep_true_dist_of_per_burst(
          struct cep_per_chain cep_chain_db)
{
  // This is for internal purpose so we can dump all KPI info
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    if (cep_chain_db.total_meas)
    {
      lowi_printf(lowi_test.summary_fp,
          "\n === CEP trueDistance from per burst RTT (%lu measurements)===",
          cep_chain_db.total_meas);
      lowi_printf(lowi_test.summary_fp,
          "\n cep68(%6.2f) cep90(%6.2f) cep99(%6.2f)",
          cep_chain_db.cep68, cep_chain_db.cep90, cep_chain_db.cep99);
      lowi_printf(lowi_test.summary_fp,
          "\n (maxErr: %f)", cep_chain_db.max_err);
    }
    else
    {
      pr_kpi_fs_high ("\n%s: For %s there is no measurement hence skip it",
          __func__, to_string(cep_chain_db.chain_no));
      lowi_printf(lowi_test.summary_fp,
          "\n === CEP trueDistance is 0 as no meas from per burst data=== ");
      lowi_printf(lowi_test.summary_fp, "\n cep68:0   cep90:0  cep99: 0");
    }
  }
  // This is for oem purpose so we need to dump only CEP of both chain
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    lowi_printf(lowi_test.summary_fp, "\n cep90(%6.2f)", cep_chain_db.cep90);
  }
}

static void lowi_cep_true_distance(struct LOWIPostProcessNode* ap_node,
    vector  <struct cep_per_chain> &cep_chain_db)
{
  pr_kpi_fs_high("\n***Process cep stats from raw data for ap_node");

  vector <struct result_data> rtt_ps_vec;
  vector <int> flt_rtt_ps_vec; //filtered data
  struct cep_per_chain cep_data;
  float median = 0.0;

  for (uint32 chain_mask = CHAIN_0; chain_mask < CHAIN_MAX; chain_mask++)
  {
    rtt_ps_vec.flush();
    flt_rtt_ps_vec.flush();
    lowi_split_rtt_per_chain_wise(ap_node,
       (e_chain_mask)chain_mask, rtt_ps_vec);
    pr_kpi_fs_high("\nTotal RTT meas %u in %s ",
                  rtt_ps_vec.getNumOfElements(),
                  to_string((e_chain_mask)chain_mask));
    median = lowi_compute_float_median(rtt_ps_vec);
    lowi_filter_vector(rtt_ps_vec, flt_rtt_ps_vec,
       (e_chain_mask)chain_mask, median);
    if (flt_rtt_ps_vec.getNumOfElements())
    {
      cep_data = compute_cep_true_dist(ap_node->true_dist, flt_rtt_ps_vec);
      cep_data.chain_no = (e_chain_mask) chain_mask;
      cep_chain_db.push_back(cep_data);
    }
  }
}

//compute peak-to-peak variation
static struct p2p_per_chain compute_cep_peek_to_peek(
    vector <int> &rtt_cache, float mean)
{

  float p2p68, p2p90, p2p99, sum = 0.0;
  struct p2p_per_chain p2p_chain_db;

  float highThresh, lowThresh, rtt_ns = 0.0;
  uint8 bw = 0;
  vector <float> errDiffs_p2p;

  pr_kpi_fs_high ("\n%s:enter ", __func__);
  memset(&p2p_chain_db, 0, sizeof(struct p2p_per_chain));
  p2p_chain_db.total_meas = rtt_cache.getNumOfElements();

  for (uint32 item = 0; item < rtt_cache.getNumOfElements(); item++)
  {
    errDiffs_p2p.push_back(std::abs(rtt_cache[item]/1000.0-mean));
    pr_kpi_fs_low("\n\t%s:push in error %f",
       __func__, std::abs(rtt_cache[item]/1000.0-mean));
  }

  if(errDiffs_p2p.getNumOfElements())
    std::sort(errDiffs_p2p.begin(), errDiffs_p2p.end());
  else
    goto out;

  // calculate CEP68, CEP90 and CEP99
  p2p68 = int(std::ceil(errDiffs_p2p.getNumOfElements() * .68))-1;
  p2p90 = int(std::ceil(errDiffs_p2p.getNumOfElements() * .90))-1;
  p2p99 = int(std::ceil(errDiffs_p2p.getNumOfElements() * .99))-1;

  p2p_chain_db.p2p68 = errDiffs_p2p[p2p68]*( 0.5 * 30.0);//convert nsec to cm
  p2p_chain_db.p2p90 = errDiffs_p2p[p2p90]*( 0.5 * 30.0);//convert nsec to cm
  p2p_chain_db.p2p99 = errDiffs_p2p[p2p99]*( 0.5 * 30.0);//convert nsec to cm

out:
  pr_kpi_fs_high ("\n%s:exit ", __func__);
  return p2p_chain_db;
}

static void lowi_print_cep_p2p_of_all_meas(
    vector <struct p2p_per_chain> &p2p_chain_db)
{
  float p2p_chain_0 = 0.0;
  float p2p_chain_1 = 0.0;

  // This is for internal purpose so we can dump all KPI info
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    for (uint32 item = 0; item < p2p_chain_db.getNumOfElements(); item++)
    {
      if (p2p_chain_db[item].total_meas)
      {
        lowi_printf(lowi_test.summary_fp,
            "\n ===== P2P PeakToPeak for %s (%d measurements) ===",
             to_string(p2p_chain_db[item].chain_no),
             p2p_chain_db[item].total_meas);
        lowi_printf(lowi_test.summary_fp,
             "\n p2p68(%6.2f cm) p2p90(%6.2f cm) p2p99(%6.2f cm)",
             p2p_chain_db[item].p2p68,  p2p_chain_db[item].p2p90,
             p2p_chain_db[item].p2p99);
      }
      else
      {
        pr_kpi_fs_high ("\n%s: For %s there is no measurement hence skip it",
                        __func__, to_string(p2p_chain_db[item].chain_no));
        lowi_printf(lowi_test.summary_fp, "\n ===   PeakToPeak for %s ===",
                    to_string(p2p_chain_db[item].chain_no));
        lowi_printf(lowi_test.summary_fp, "\n p2p68:0  p2p90:0  p2p99:0");
      }
    }
  }
  // This is for oem purpose so we need to dump max(p2p_chain_0, p2p_chain_1)
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    for (uint32 item = 0; item < p2p_chain_db.getNumOfElements(); item++)
    {
      if (p2p_chain_db[item].chain_no == CHAIN_0)
      {
        p2p_chain_0 = p2p_chain_db[item].p2p90;
      }
      if (p2p_chain_db[item].chain_no == CHAIN_1)
      {
        p2p_chain_1 = p2p_chain_db[item].p2p90;
      }
    }
    lowi_printf(lowi_test.summary_fp, "\n p2p90(%6.2f)",
                MAX(p2p_chain_0, p2p_chain_1));
  }
}

static void
lowi_print_cep_p2p_per_burst(struct p2p_per_chain &p2p_chain_db)
{
  // This is for internal purpose so we can dump all KPI info
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    if (p2p_chain_db.total_meas)
    {
      lowi_printf(lowi_test.summary_fp,
          "\n ===== P2P PeakToPeak from per burst RTT (%d measurements) ===",
           p2p_chain_db.total_meas);
      lowi_printf(lowi_test.summary_fp,
           "\n p2p68(%6.2f cm) p2p90(%6.2f cm) p2p99(%6.2f cm)",
           p2p_chain_db.p2p68,  p2p_chain_db.p2p90, p2p_chain_db.p2p99);
      }
      else
      {
        pr_kpi_fs_high ("\n%s: For %s there is no measurement hence skip it",
                      __func__, to_string(p2p_chain_db.chain_no));
        lowi_printf(lowi_test.summary_fp,
                  "\n === PeakToPeak is 0 as no meas from per burst data===");
        lowi_printf(lowi_test.summary_fp, "\n p2p68:0  p2p90:0  p2p99: 0");
      }
  }
  // This is for oem purpose so we need to dump max(p2p_chain_0, p2p_chain_1)
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
  {
    lowi_printf(lowi_test.summary_fp, "\n p2p90(%6.2f)", p2p_chain_db.p2p90);
  }
}

static void
lowi_cep_peek_to_peek(struct LOWIPostProcessNode* ap_node,
    vector <struct p2p_per_chain> &p2p_chain_db)
{
  pr_kpi_fs_high("\n***Process p2p stats from raw data for ap_node");

  vector <struct result_data> rtt_ps_vec;
  vector <int> flt_rtt_ps_vec; //filtered data
  float median = 0.0, curr_mean = 0.0, min_mean = 0.0;
  struct p2p_per_chain p2p_data;

  for (uint32 chain_mask = CHAIN_0; chain_mask < CHAIN_MAX; chain_mask++)
  {
    rtt_ps_vec.flush();
    flt_rtt_ps_vec.flush();
    lowi_split_rtt_per_chain_wise(ap_node,
       (e_chain_mask)chain_mask, rtt_ps_vec);
    pr_kpi_fs_high("\nTotal RTT Meas in %u in %s",
                  rtt_ps_vec.getNumOfElements(),
                  to_string((e_chain_mask)chain_mask));
    median = lowi_compute_float_median(rtt_ps_vec);
    lowi_filter_vector(rtt_ps_vec, flt_rtt_ps_vec,
       (e_chain_mask)chain_mask, median);
    curr_mean = lowi_compute_float_mean(flt_rtt_ps_vec);
    if ((!min_mean) && (curr_mean))
      min_mean = curr_mean;
    else if (min_mean && curr_mean)
       min_mean = MIN(curr_mean, min_mean);
    if (flt_rtt_ps_vec.getNumOfElements())
    {
      p2p_data = compute_cep_peek_to_peek(flt_rtt_ps_vec, curr_mean);
      p2p_data.chain_no = (e_chain_mask)chain_mask;
      p2p_chain_db.push_back(p2p_data);
    }
  }

  pr_kpi_fs_high ("\n%s:exit ", __func__);
}

static void lowi_print_rtt_stats(struct LOWIPostProcessNode* ap_node,
    struct s_rtt_stats &rtt_stats)
{
  float yieldResults = 0.0;

  if (lowi_test.seq_no && ap_node->frame_per_burst)
  {
    int total_cnt = 0;
    if (ap_node->skip_first)
      total_cnt = ap_node->rtt_cache.getNumOfElements();
    else
      total_cnt = ap_node->total_cnt;
    pr_kpi_fs_high("\ntotal_cnt %d frame_per_burst %d seq_no %d max_seq_no_in_csv %u",
                total_cnt, ap_node->frame_per_burst,
                lowi_test.seq_no,
                lowi_cmd->max_seq_no_in_csv);
    // lowi_test.seq_no - 1 needed as we are doing ++
    // after each iteration ap_node->frame_per_burst - 1
    //we always get one less resposne from negotiated frames
    if (!lowi_cmd->rtt_test_mode)
    {
      yieldResults = 100*float(total_cnt)/
         (float(ap_node->frame_per_burst - 1) * float(lowi_test.seq_no - 1));
    }
    else
    {
      // In rtt test mode seq number will not be updated in lowi test tool
      // so we have to parse the csv file and keep update of max seq no.
      yieldResults = 100*float(total_cnt)/
         (float(ap_node->frame_per_burst - 1) * float(lowi_cmd->max_seq_no_in_csv));
    }
  }

  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp,
              "\nRTT stats ...(ps) from total measurements (%d)",
              rtt_stats.total_no_meas);
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
    lowi_printf(lowi_test.summary_fp,
                "\n mean(%d) median(%d) stddev(%d) max(%d) min(%d)",
                rtt_stats.mean, rtt_stats.median, rtt_stats.std_dev,
                rtt_stats.max, rtt_stats.min);
  else if (CAN_DUMP_EXT_KPI_STATS(lowi_cmd->kpi_mask))
    lowi_printf(lowi_test.summary_fp, "\n median (%d)", rtt_stats.median);

  if ((lowi_cmd->kpi_mask) && (yieldResults))
    lowi_printf(lowi_test.summary_fp, " yield(%4.1f %c)", yieldResults, '%');
}

static void
lowi_print_final_rtt_stats(struct s_rtt_stats &rtt_stats)
{
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp,
              "\nRTT stats ...(ps) from total measurements (%d)",
              rtt_stats.total_no_meas);
  if (CAN_DUMP_INT_KPI_STATS(lowi_cmd->kpi_mask))
    lowi_printf(lowi_test.summary_fp,
                "\n mean(%d) median(%d) stddev(%d) max(%d) min(%d)",
                rtt_stats.mean, rtt_stats.median, rtt_stats.std_dev,
                rtt_stats.max, rtt_stats.min);
  else
    lowi_printf(lowi_test.summary_fp, "\n median (%d)", rtt_stats.median);
}

static struct s_rtt_stats
compute_rtt_stats( vector <int> &rtt_cache)
{
  uint32 size = rtt_cache.getNumOfElements();
  struct s_rtt_stats rtt_stats;
  if (rtt_cache.getNumOfElements() == 0)
  {
    pr_kpi_fs_high("\nUnable to compute rtt stats");
    return rtt_stats;
  }

  rtt_stats.min = *std::min_element(rtt_cache.begin(), rtt_cache.end());
  rtt_stats.max = *std::max_element(rtt_cache.begin(), rtt_cache.end());
  rtt_stats.sum = std::accumulate(rtt_cache.begin(), rtt_cache.end(), 0);
  rtt_stats.mean = rtt_stats.sum/(int)size;
  rtt_stats.median = compute_median_int(rtt_cache);
  rtt_stats.std_dev = compute_stddev_int(rtt_cache);
  rtt_stats.total_no_meas = rtt_cache.getNumOfElements();
  pr_kpi_fs_high("\nsum:%d size:%d mean:%d",
                rtt_stats.sum, size, rtt_stats.mean);

  if (rtt_stats.std_dev == (int)HUGE_STD_DEV)
  {
    pr_kpi_fs_high("\nhuge std dev");
  }
  return rtt_stats;
}

static struct s_rtt_stats
lowi_rtt_stats_of_ap_node(struct LOWIPostProcessNode* ap_node)
{
  pr_kpi_fs_high ("\n***Process rtt stats from raw data for ap_node");
  struct s_rtt_stats rtt_data;
  vector <struct s_rtt_stats> rtt_chain_db;
  vector <struct result_data> rtt_ps_vec;
  vector <int> flt_rtt_ps_vec; //filtered data
  float median = 0.0;

  for (uint32 chain_no = CHAIN_0; chain_no < CHAIN_MAX; chain_no++)
  {
    rtt_ps_vec.flush();
    flt_rtt_ps_vec.flush();
    lowi_split_rtt_per_chain_wise(ap_node, (e_chain_mask)chain_no, rtt_ps_vec);
    median = lowi_compute_float_median(rtt_ps_vec);
    lowi_filter_vector(rtt_ps_vec,
                       flt_rtt_ps_vec, (e_chain_mask)chain_no, median);
    pr_kpi_fs_low("\nNon filter RTT meas count %d filtered meas count %d",
       rtt_ps_vec.getNumOfElements(), flt_rtt_ps_vec.getNumOfElements());
    if (flt_rtt_ps_vec.getNumOfElements())
    {
      rtt_data = compute_rtt_stats(flt_rtt_ps_vec);
      rtt_data.chain_no = (e_chain_mask)chain_no;
      rtt_chain_db.push_back(rtt_data);
      pr_kpi_fs_high("\nrtt mean %d of chain %d", rtt_data.mean, chain_no);
    }
  }

  struct s_rtt_stats ret_stats;
  if (rtt_chain_db.getNumOfElements())
  {
    ret_stats = rtt_chain_db[0];
    for (uint32 cnt = 1; cnt <rtt_chain_db.getNumOfElements(); cnt++)
    {
      // what if first mean is zero
      if (ret_stats.mean == 0)
        ret_stats = rtt_chain_db[cnt];
      else if ((rtt_chain_db[cnt].mean > 0) &&
          (ret_stats.mean > rtt_chain_db[cnt].mean))
      {
        ret_stats = rtt_chain_db[cnt];
      }
    }
  }
  return ret_stats;
}

static void
lowi_mng_rtt_stats(struct LOWIPostProcessNode* ap_node)
{
  struct s_rtt_stats rtt_stats;
  rtt_stats = lowi_rtt_stats_of_ap_node(ap_node);
  lowi_print_rtt_stats(ap_node, rtt_stats);
}

static void
lowi_mng_per_burst_rtt_stats(vector <int> &per_burst_rtt)
{
  struct s_rtt_stats rtt_stats;
  rtt_stats = compute_rtt_stats(per_burst_rtt);
  lowi_print_final_rtt_stats(rtt_stats);
}

static void
lowi_mng_dist_stats(struct LOWIPostProcessNode* ap_node)
{
  struct s_dist_stats dist_stats;
  dist_stats = lowi_dist_stats_of_ap_node(ap_node);
  lowi_print_dist_stats(dist_stats, 0);
}

static void
lowi_mng_per_burst_dist_stats(vector <int> &per_burst_rtt)
{
  struct s_dist_stats dist_stats;
  dist_stats = compute_dist_stat(per_burst_rtt);
  lowi_print_dist_stats(dist_stats, 0);
}

//true distance will acroynm as td onwards
static void
lowi_mng_cep_td_stats(struct LOWIPostProcessNode* ap_node)
{
  vector <struct cep_per_chain> cep_chain_db;
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp, "\nCEP stats in cm");
  lowi_cep_true_distance(ap_node, cep_chain_db);
  lowi_print_cep_true_dist_of_all_meas(cep_chain_db);
}

static void
lowi_mng_per_burst_cep_td_stats(vector < int > &per_burst_rtt)
{
  struct cep_per_chain cep_data;
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp,"\nCEP stats in cm");
  cep_data = compute_cep_true_dist(lowi_cmd->trueDist, per_burst_rtt);
  lowi_print_cep_true_dist_of_per_burst(cep_data);
}

static void
lowi_mng_p2p_stats(struct LOWIPostProcessNode* ap_node)
{
  vector <struct p2p_per_chain> p2p_chain_db;
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp,"\nP2P stats in cm");
  lowi_cep_peek_to_peek(ap_node, p2p_chain_db);
  lowi_print_cep_p2p_of_all_meas(p2p_chain_db);
}

static void
lowi_mng_per_burst_p2p_stats(vector <int> &per_burst_rtt)
{
  struct p2p_per_chain p2p_data;
  lowi_printf(lowi_test.summary_fp, HYPEN_LINE);
  lowi_printf(lowi_test.summary_fp,"\nP2P stats in cm");
  p2p_data = compute_cep_peek_to_peek(per_burst_rtt,
                 lowi_compute_float_mean(per_burst_rtt));
  lowi_print_cep_p2p_per_burst(p2p_data);
}

void lowi_process_node(struct LOWIPostProcessNode* ap_node)
{
  uint32 size = ap_node->rtt_cache.getNumOfElements();

  lowi_printf(lowi_test.summary_fp,
      "\n\n==========Peer BSSID: " LOWI_MACADDR_FMT "==========",
              LOWI_MACADDR(ap_node->bssid));
  lowi_printf(lowi_test.summary_fp,
             "\nTotal number of measurements: %d, true distance: (%d in cm) "
             "requested TX-BW & RX-BW (%d , %d)",
             size, ap_node->true_dist, ap_node->req_tx_bw, ap_node->req_rx_bw);
  if (ap_node->skip_first)
  {
    lowi_printf(lowi_test.summary_fp,"\n After Skipping first measurements %d",
                (ap_node->total_cnt - size));
  }

  if (size)
  {
    lowi_mng_rtt_stats(ap_node);
    lowi_mng_dist_stats(ap_node);
    lowi_mng_cep_td_stats(ap_node);
    lowi_mng_p2p_stats(ap_node);
  }
  lowi_printf(lowi_test.summary_fp,
              "\n=================================================\n");
}

void lowi_process_raw_data(vector <LOWIPostProcessNode> &node_cache)
{
  struct LOWIPostProcessNode *ap_node = NULL;
  pr_kpi_fs_high ("\n*** Start Processing Raw Data, Total no of AP's are = %d",
                  node_cache.getNumOfElements());

  for (uint32 cnt = 0; cnt < node_cache.getNumOfElements(); cnt++)
  {
    struct LOWIPostProcessNode* ap_node = &node_cache[cnt];
    // Process nodes only when we have the valid rtt measurements
    pr_kpi_fs_high("\n*** AP:" LOWI_MACADDR_FMT "No of rtt measurement are %d",
                   LOWI_MACADDR(ap_node->bssid),
                   ap_node->rtt_cache.getNumOfElements());
    if (ap_node->rtt_cache.getNumOfElements())
      lowi_process_node(ap_node);
  }
}

int lowi_compute_burst_rtt_mean(
        struct LOWIPostProcessNode *ap_node, uint32 seq_no)
{
  pr_kpi_fs_high ("\n%s:enter ", __func__);
  struct s_rtt_stats rtt_data;
  vector <struct s_rtt_stats> rtt_chain_db;
  vector <struct result_data> rtt_ps_vec;
  vector <int> flt_rtt_ps_vec; //filtered data
  float median = 0.0;
  vector <int> rtt_mean_cache;

  for (uint32 chain_no = CHAIN_0; chain_no < CHAIN_MAX; chain_no++)
  {
    rtt_ps_vec.flush();
    flt_rtt_ps_vec.flush();
    lowi_split_rtt_per_chain_wise(ap_node, (e_chain_mask)chain_no, rtt_ps_vec);
    median = lowi_compute_float_median(rtt_ps_vec);
    lowi_filter_vector(rtt_ps_vec,
                       flt_rtt_ps_vec, (e_chain_mask)chain_no, median);
    pr_kpi_fs_low("\nNon filter RTT meas count %d filtered meas count %d",
       rtt_ps_vec.getNumOfElements(), flt_rtt_ps_vec.getNumOfElements());
    if (flt_rtt_ps_vec.getNumOfElements())
    {
      rtt_data = compute_rtt_stats(flt_rtt_ps_vec);
      rtt_chain_db.push_back(rtt_data);
      pr_kpi_fs_high("\nrtt mean %d of chain %d", rtt_data.mean, chain_no);
      rtt_mean_cache.push_back(rtt_data.mean);
    }
  }

  if (rtt_mean_cache.getNumOfElements())
  {
    pr_kpi_fs_high ("\n%s:exit seq_no %d min_mean %d", __func__, seq_no,
       *std::min_element(rtt_mean_cache.begin(), rtt_mean_cache.end()));
    return *std::min_element(rtt_mean_cache.begin(), rtt_mean_cache.end());
  }
  else
  {
    return 0;
  }
}

static int lowi_get_cached_burst_rtt(
   per_burst_map &burst_map, uint32 seq_no)
{
  auto it = burst_map.find(seq_no);
  if (it == burst_map.end())
  {
    pr_kpi_fs_high("\nNot able find the seq_no:%u in burst map", seq_no);
    return 0;
  }
  else
  {
    pr_kpi_fs_low("\nCache RTT %d for seq_no %d",
                  it->second.second.rtt_final, seq_no);
    return it->second.second.rtt_final;
  }
}

void lowi_per_burst_nodes(vector <int> &per_burst_rtt_cache)
{
  uint32 size = per_burst_rtt_cache.getNumOfElements();

  lowi_printf(lowi_test.summary_fp,
      "\n\n==========  RTT results (Per burst based) ==========");
  lowi_printf(lowi_test.summary_fp,
      "\nTotal number of measurements: %d, true distance: (%d in cm) "
      "requested TX-BW & RX-BW (%d , %d)",
      size, lowi_cmd->trueDist, lowi_cmd->req_tx_bw, lowi_cmd->req_rx_bw);

  if (size)
  {
    lowi_mng_per_burst_rtt_stats(per_burst_rtt_cache);
    lowi_mng_per_burst_dist_stats(per_burst_rtt_cache);
    lowi_mng_per_burst_cep_td_stats(per_burst_rtt_cache);
    lowi_mng_per_burst_p2p_stats(per_burst_rtt_cache);
  }
  lowi_printf(lowi_test.summary_fp,
              "\n=================================================\n");
}

void lowi_process_per_burst_map(per_burst_map &map)
{
  vector <int> per_burst_rtt_cache;
  pr_kpi_fs_high("\n***Process per burst data");
  struct LOWIPostProcessNode val_ap_node;
  for (auto it = map.begin(); it != map.end(); ++it)
  {
    uint32 seq_no = it->first;
    val_ap_node.resetNodeMetaData();
    val_ap_node.rtt_cache.flush();
    it->second.first.getNodeMetaData(val_ap_node);
    it->second.first.getRttCacheVec(val_ap_node);
    it->second.second.rtt_final =
        lowi_compute_burst_rtt_mean(&val_ap_node, seq_no);
    pr_kpi_fs_high("\nFINAL_RTT %d for seq no %d",
                it->second.second.rtt_final, seq_no);
    if (it->second.second.rtt_final)
      per_burst_rtt_cache.push_back(it->second.second.rtt_final);
  }
  lowi_per_burst_nodes(per_burst_rtt_cache);
}

/*=============================================================================
 * lowi_test_display_summary_stats
 *
 * Description:
 *    Display the summary stats
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_test_display_summary_stats( void )
{
  uint32 ap_cnt;
  LowiTestApInfo * p_ap_info = NULL;
  vector <LOWIMacAddress>& summaryList = lowi_cmd->summary_aps;


  lowi_printf( lowi_test.summary_fp, "Issued Request Type: %s\n",
               scan_type_str[lowi_cmd->cmd]);

  if (0 != summaryList.getNumOfElements())
  {
    QUIPC_DBG_HIGH ("%s: Number of items for summary = %d",
                    __FUNCTION__, summaryList.getNumOfElements());
  }
  // First print out discovery scan result
  if ((lowi_cmd->cmd == LOWI_DISCOVERY_SCAN)
      || (lowi_cmd->cmd == LOWI_ASYNC_DISCOVERY_SCAN))

  {
    lowi_printf( lowi_test.summary_fp, "Summary stats: Scan Type: %s\n",
                 "DISCOVERY");
    lowi_printf( lowi_test.summary_fp, "Avg Response Time");
    lowi_printf(lowi_test.summary_fp, ":Discovery: %d ms", lowi_test.avg_ps_rsp_ms);
    lowi_printf( lowi_test.summary_fp, "\n\n%10s %10s %16s %18s %12s %10s \n",
                 "MAC", "Chan", "Detection-rate", "RSSI(0.5 dBm)", "RTT_RSP", "SSID");
    lowi_printf( lowi_test.summary_fp, "%10s %10s %15s %4s %4s %7s %6s",
                  "", "", "", "Min", "Max", "Avg(dBm)", "Avg(W)\n");
    // Loop first to print discovery scan statistics
    for (ap_cnt = 0; ap_cnt < lowi_cmd->ap_info.getNumOfElements(); ++ap_cnt)
    {
      p_ap_info = &lowi_cmd->ap_info[ap_cnt];
      // Check if the user wants to only see the summary for specific AP's
      if ((0 != summaryList.getNumOfElements()) &&
          (!lowi_test_is_ap_in_list(p_ap_info->mac, summaryList)))
      {
        QUIPC_DBG_HIGH ("%s: " LOWI_MACADDR_FMT "not found in the summary list",
                        __FUNCTION__, LOWI_MACADDR(p_ap_info->mac));
        continue;
      }

      lowi_printf(lowi_test.summary_fp, LOWI_MACADDR_FMT " %3hu",
                  LOWI_MACADDR(p_ap_info->mac),
                  LOWIUtils::freqToChannel(p_ap_info->frequency));

      lowi_printf(lowi_test.summary_fp, " %5d/%-2d(%3d%%)",
                  scan_stats[ap_cnt].rssi.cnt, (lowi_test.seq_no-1),
                  scan_stats[ap_cnt].rssi.cnt*100/(lowi_test.seq_no-1));

      lowi_printf(lowi_test.summary_fp, "%5d %5d %5d %5d",
                  scan_stats[ap_cnt].rssi.low/2, scan_stats[ap_cnt].rssi.high/2,
                  (int) ((scan_stats[ap_cnt].rssi.cnt == 0) ?  0 :
                   (scan_stats[ap_cnt].rssi.total/(scan_stats[ap_cnt].rssi.cnt*2))),
                  (scan_stats[ap_cnt].rssi.cnt == 0 ?  0 :
                   (int32)(10*log10(scan_stats[ap_cnt].total_rssi_mw/scan_stats[ap_cnt].rssi.cnt))));
      if (p_ap_info->rtt_feat_of_ap)
       lowi_printf(lowi_test.summary_fp, "%8s", "T");
      else
       lowi_printf(lowi_test.summary_fp, "%8s", "-");

      lowi_printf(lowi_test.summary_fp, "%8s" "%.*s\n",
                  "", p_ap_info->ssid_length, p_ap_info->ssid);
    }
  }

  // Loop again to print out rtt statistics
  if ((lowi_cmd->cmd == LOWI_RTS_CTS_SCAN) ||
      (lowi_cmd->cmd == LOWI_BOTH_SCAN))
  {
    lowi_printf( lowi_test.summary_fp, "Summary stats: Scan Type: %s\n",
                 "RANGING");
    lowi_printf( lowi_test.summary_fp, "Avg Response Time");
    lowi_printf( lowi_test.summary_fp, ": Ranging: %d ms", lowi_test.avg_rs_rsp_ms);
    lowi_printf( lowi_test.summary_fp, "\n%10s %10s %16s %15s %25s %30s \n",
                 "AP", "Chan", "Detection rate", "RSSI(0.5 dBm)", "RTT(psec)", "RTT Meas Cnt");
    lowi_printf( lowi_test.summary_fp, "%10s %10s %15s %4s %4s %7s %6s %5s %7s %7s %6s %5s %5s %5s %5s %5s\n",
                 "", "", "", "Min", "Max", "Avg(dBm)", "Avg(W)", "Min", "Max", "Avg",
                 "#>5M", "#4M", "#3M",  "#2M",  "#1M", "#0M");

    // Loop first to print ranging scan statistics
    for (ap_cnt = 0; ap_cnt < lowi_cmd->ap_info.getNumOfElements(); ++ap_cnt)
    {
      p_ap_info = &lowi_cmd->ap_info[ap_cnt];
      if ((0 != summaryList.getNumOfElements()) &&
          (!lowi_test_is_ap_in_list(p_ap_info->mac, summaryList)))
      {
        QUIPC_DBG_HIGH ("%s: " LOWI_MACADDR_FMT "not found in the summary list",
                        __FUNCTION__, LOWI_MACADDR(p_ap_info->mac));
        continue;
      }

      lowi_printf(lowi_test.summary_fp, LOWI_MACADDR_FMT " %3hu",
                  LOWI_MACADDR(p_ap_info->mac),
                  LOWIUtils::freqToChannel(p_ap_info->frequency));

      lowi_printf(lowi_test.summary_fp, " %4d/%-4d(%3d%%)",
                  scan_stats[ap_cnt].rtt.total_meas_set_cnt,
                  (scan_stats[ap_cnt].rtt.total_attempt_cnt),
                  ((scan_stats[ap_cnt].rtt.total_meas_set_cnt == 0) || (scan_stats[ap_cnt].rtt.total_attempt_cnt == 0)) ? 0 :
                  (scan_stats[ap_cnt].rtt.total_meas_set_cnt*100/(scan_stats[ap_cnt].rtt.total_attempt_cnt)));

      lowi_printf(lowi_test.summary_fp, "%5d %5d %5d %5d",
                  scan_stats[ap_cnt].rtt.rssi_low/2, scan_stats[ap_cnt].rtt.rssi_high /2,
                  ((scan_stats[ap_cnt].rtt.total_meas_cnt == 0) ?  0 :
                   (int32) (scan_stats[ap_cnt].rtt.rssi_total / (2 * scan_stats[ap_cnt].rtt.total_meas_cnt))),
                  (scan_stats[ap_cnt].rtt.total_meas_cnt == 0 ?  0 :
                   (int32)(10*log10(scan_stats[ap_cnt].total_rtt_rssi_mw / scan_stats[ap_cnt].rtt.total_meas_cnt))));

      lowi_printf(lowi_test.summary_fp, " %8d %8d %8d",
                  scan_stats[ap_cnt].rtt.rtt_low, scan_stats[ap_cnt].rtt.rtt_high,
                  ((scan_stats[ap_cnt].rtt.total_meas_cnt == 0) ?  0 :
                   (int) (scan_stats[ap_cnt].rtt.rtt_total / scan_stats[ap_cnt].rtt.total_meas_cnt)));

      scan_stats[ap_cnt].rtt.meas_cnt[0] = scan_stats[ap_cnt].rtt.total_attempt_cnt -
                                           scan_stats[ap_cnt].rtt.total_meas_set_cnt;
      lowi_printf(lowi_test.summary_fp, "%5d %5d %5d %5d %5d %5d\n",
                  scan_stats[ap_cnt].rtt.meas_cnt[5], scan_stats[ap_cnt].rtt.meas_cnt[4],
                  scan_stats[ap_cnt].rtt.meas_cnt[3], scan_stats[ap_cnt].rtt.meas_cnt[2],
                  scan_stats[ap_cnt].rtt.meas_cnt[1], scan_stats[ap_cnt].rtt.meas_cnt[0]);
    }
  }

  if (lowi_cmd->cmd == LOWI_UART_TEST_REQ)
  {
    lowi_printf(lowi_test.summary_fp, "\nUART Test: %s\n",
                lowi_test.uart_test_success?"SUCCESS":"FAIL");
  }

  if (lowi_cmd->cmd == LOWI_CONFIG_REQ)
  {
    lowi_printf(lowi_test.summary_fp, "\nConfig Test: %s\n",
                lowi_test.config_test_success?"SUCCESS":"FAIL");
  }
}

/*=============================================================================
 * lowi_test_update_scan_stats
 *
 * Description:
 *   New scan results available. Update the stats.
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_test_update_scan_stats(LOWIResponse::eResponseType rspType,
                                        vector <LOWIScanMeasurement*> &scanMeas)
{
  LowiTestApInfo* p_ap_info;

  if (0 == scanMeas.getNumOfElements())
  {
    // No results to log or process
    QUIPC_DBG_HIGH("%s: Empty set of measurement results", __FUNCTION__);
    return;
  }

  if (0 == lowi_cmd->ap_info.getNumOfElements())
  {
    // No APs in measurement set. Create list from results
    for (uint32 ap_cnt = 0; ap_cnt < scanMeas.getNumOfElements(); ++ap_cnt)
    {
      LowiTestApInfo apInfo(scanMeas[ap_cnt]->bssid,
                            scanMeas[ap_cnt]->frequency,
                            scanMeas[ap_cnt]->ssid,
                            scanMeas[ap_cnt]->ranging_features_supported);
      lowi_cmd->ap_info.push_back(apInfo);
      if (lowi_cmd->ap_info.getNumOfElements() >= MAX_BSSIDS_STATS)
      {
        break;
      }
    }
  }
  else if ((LOWIResponse::DISCOVERY_SCAN == rspType) &&
           (lowi_cmd->ap_info.getNumOfElements() < MAX_BSSIDS_STATS))
  {
    // We might have received more AP's in this scan
    // Let's append the new found AP's in the list
    for (uint32 ap_cnt = 0; ap_cnt < scanMeas.getNumOfElements(); ++ap_cnt)
    {
      bool match_found = false;
      for (uint32 ap_index = 0; ap_index < lowi_cmd->ap_info.getNumOfElements();
           ++ap_index)
      {
        if (lowi_cmd->ap_info[ap_index].mac.compareTo(scanMeas[ap_cnt]->bssid) == 0 )
        {
          match_found = true;
          break;
        }
      }
      // We are here either because a match was found for the ap in the
      // list or because, this is a new AP, not in our list yet
      if (!match_found)
      {
        // Not in our list yet
        LowiTestApInfo apInfo(scanMeas[ap_cnt]->bssid,
                              scanMeas[ap_cnt]->frequency,
                              scanMeas[ap_cnt]->ssid,
                              scanMeas[ap_cnt]->ranging_features_supported);
        lowi_cmd->ap_info.push_back(apInfo);
        if (lowi_cmd->ap_info.getNumOfElements() >= MAX_BSSIDS_STATS)
        {
          break;
        }
      }
    } // for
  } // else if

  // Update total attempt cnt for ranging scan
  if (LOWIResponse::RANGING_SCAN == rspType)
  {
    for (uint32 ap_cnt = 0; ap_cnt < lowi_cmd->ap_info.getNumOfElements(); ++ap_cnt)
    {
      for (uint32 rtt_scan_ap_cnt = 0;
           rtt_scan_ap_cnt < rtt_scan_cmd.rttNodes.getNumOfElements();
           ++rtt_scan_ap_cnt)
      {
        LOWIMacAddress& bssid = lowi_cmd->ap_info[ap_cnt].mac;
        if (bssid.compareTo(rtt_scan_cmd.rttNodes[rtt_scan_ap_cnt].bssid) == 0 )
        {
           scan_stats[ap_cnt].rtt.total_attempt_cnt++;
           break;
        }
      }
    }
  }

  for (uint32 ap_cnt = 0; ap_cnt < lowi_cmd->ap_info.getNumOfElements(); ++ap_cnt)
  {
    p_ap_info = &lowi_cmd->ap_info[ap_cnt];
    for (uint32 ap_index = 0; ap_index < scanMeas.getNumOfElements(); ++ap_index)
    {
      LOWIMacAddress& bssid = p_ap_info->mac;
      if (bssid.compareTo(scanMeas[ap_index]->bssid) == 0)
      {
        // Match found. add to stats.
        if (0 == p_ap_info->frequency)
        {
          p_ap_info->frequency = scanMeas[ap_cnt]->frequency;
        }
        switch (rspType)
        {
          case LOWIResponse::DISCOVERY_SCAN:
            rssi_total_in_watt(LOWI_DISCOVERY_SCAN,
                               &scan_stats[ap_cnt],
                               scanMeas[ap_index]->measurementsInfo[0]->rssi);
            add_data_to_stat(LOWI_DISCOVERY_SCAN,
                             &scan_stats[ap_cnt],
                             scanMeas[ap_index]->measurementsInfo[0]->rssi,
                             0);
          break;
          case LOWIResponse::RANGING_SCAN:
          {
            vector<LOWIMeasurementInfo *>& measInfo = scanMeas[ap_index]->measurementsInfo;
            for (uint32 meas_cnt = 0; meas_cnt < measInfo.getNumOfElements(); ++meas_cnt)
            {
              rssi_total_in_watt(LOWI_RTS_CTS_SCAN,
                                 &scan_stats[ap_cnt],
                                 measInfo[meas_cnt]->rssi);
              add_data_to_stat(LOWI_RTS_CTS_SCAN,
                               &scan_stats[ap_cnt],
                               measInfo[meas_cnt]->rssi,
                               measInfo[meas_cnt]->rtt_ps);
            }
            // increase the cnt (with that number of measurement) for the AP
            if (measInfo.getNumOfElements() < MAX_NUM_RTT_MEASUREMENTS_PER_AP)
            {
              scan_stats[ap_cnt].rtt.meas_cnt[measInfo.getNumOfElements()]++;
            }
            else
            {
              scan_stats[ap_cnt].rtt.meas_cnt[MAX_NUM_RTT_MEASUREMENTS_PER_AP-1]++;
            }
            if (measInfo.getNumOfElements() > 0)
            {
              scan_stats[ap_cnt].rtt.total_meas_set_cnt++;
            }
          }
          break;
          default:
          break;
        } // switch()
        break;
      }
    }
  }
} // lowi_test_update_scan_stats

/*=============================================================================
 * lowi_test_log_meas_results
 *
 * Description:
 *   Log the measurement results
 *
 * Return value:
 *   void
 ============================================================================*/
void lowi_test_log_meas_results(LOWIResponse::eResponseType rspType,
                                vector <LOWIScanMeasurement*> &scanMeas)
{
  uint32 seq_no;
  uint32 rsp_time = 0;
  char string_buf[128];  // IPE_LOG_STRING_BUF_SZ
  double time_in_days;

  if (0 == scanMeas.getNumOfElements())
  {
    fprintf(stderr, "No results\n");
    return;
  }

  // Update most recent results
  lowi_test.recentMeas.flush();
  for (uint32 ap_cnt = 0; ap_cnt < scanMeas.getNumOfElements(); ++ap_cnt)
  {
    lowi_test.recentMeas.push_back(*scanMeas[ap_cnt]);
  }

  lowi_test.scan_end_ms = lowi_test_get_time_ms();
  rsp_time = (uint32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms);
  lowi_test_update_scan_stats(rspType, scanMeas);
  lowi_test.scan_success = false;
  switch (rspType)
  {
    case LOWIResponse::DISCOVERY_SCAN:
      seq_no = lowi_test.seq_no;
      lowi_test.avg_ps_rsp_ms = ((((uint64)lowi_test.avg_ps_rsp_ms) *
                                  (seq_no - 1)) +
                                 rsp_time)/seq_no;
      for (uint32 ap_cnt = 0; (lowi_test.out_fp != NULL) &&
            (ap_cnt < scanMeas.getNumOfElements()); ++ap_cnt)
      {
        char ssid_str[SSID_LEN+1] = "";
        lowi_test_log_time_ms_to_string(string_buf, 128, &time_in_days,
                                        scanMeas[ap_cnt]->measurementsInfo[0]->rssi_timestamp);

        fprintf(lowi_test.out_fp,
                "%s,%12.9f,%d," LOWI_MACADDR_FMT ",%u,%d,%d,%d,%d,%d,%s,%d,%d"
                ",,,,,,,,,,\n",
                string_buf, time_in_days, rspType,
                LOWI_MACADDR(scanMeas[ap_cnt]->bssid), lowi_test.seq_no,
                LOWIUtils::freqToChannel(scanMeas[ap_cnt]->frequency),
                scanMeas[ap_cnt]->measurementsInfo[0]->rssi,
                scanMeas[ap_cnt]->measurementsInfo[0]->rtt_ps, rsp_time,
                scanMeas[ap_cnt]->measurementsInfo[0]->meas_age,
                scanMeas[ap_cnt]->ssid.toString(ssid_str),
                scanMeas[ap_cnt]->rttType, scanMeas[ap_cnt]->phyMode);
        lowi_test.scan_success = true;
      }
      break;
    case  LOWIResponse::RANGING_SCAN:
      seq_no = lowi_test.seq_no;
      lowi_test.avg_rs_rsp_ms = ((((uint64)lowi_test.avg_rs_rsp_ms) *
                                  (seq_no - 1)) +
                                 rsp_time)/seq_no;

      for (uint32 ap_cnt = 0; (lowi_test.out_fp != NULL) &&
            (ap_cnt < scanMeas.getNumOfElements()); ++ap_cnt)
      {
        vector<LOWIMeasurementInfo*>& info = scanMeas[ap_cnt]->measurementsInfo;
        char ssid_str[SSID_LEN+1] = "";
        for (uint32 meas_cnt = 0; meas_cnt < info.getNumOfElements() ; ++meas_cnt)
        {
          lowi_test_log_time_ms_to_string(string_buf, 128, &time_in_days,
                                          info[meas_cnt]->rtt_timestamp);
          //DO NOT ADD KEY IN MIDDLE AS IT IS ONE TO ONE
          // MAPPED WITH CSV COLUMNS
          fprintf(lowi_test.out_fp,
                  "\n%s,%12.9f,%d," LOWI_MACADDR_FMT ",%d,%d,%d,%d,%d,%d,%s,%d,%d"
                  ",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
                  string_buf, time_in_days, rspType,
                  LOWI_MACADDR(scanMeas[ap_cnt]->bssid),lowi_test.seq_no,
                  LOWIUtils::freqToChannel(scanMeas[ap_cnt]->frequency),
                  info[meas_cnt]->rssi,
                  info[meas_cnt]->rtt_ps, rsp_time, info[meas_cnt]->meas_age,
                  scanMeas[ap_cnt]->ssid.toString(ssid_str),
                  scanMeas[ap_cnt]->rttType, scanMeas[ap_cnt]->phyMode,
                  info[meas_cnt]->tx_preamble, info[meas_cnt]->tx_nss,
                  info[meas_cnt]->tx_bw, info[meas_cnt]->tx_mcsIdx, info[meas_cnt]->tx_bitrate,
                  info[meas_cnt]->rx_preamble, info[meas_cnt]->rx_nss,
                  info[meas_cnt]->rx_bw, info[meas_cnt]->rx_mcsIdx, info[meas_cnt]->rx_bitrate,
                  info[meas_cnt]->tx_chain_no, info[meas_cnt]->rx_chain_no
                  );
                  if(lowi_test.out_cfr_fp != NULL &&
                     info[meas_cnt]->cfrcirInfo != NULL &&
                     info[meas_cnt]->cfrcirInfo->len)
                  {
                     fprintf(lowi_test.out_cfr_fp, LOWI_MACADDR_FMT " - Channel %d\n",
                             LOWI_MACADDR(scanMeas[ap_cnt]->bssid),
                             LOWIUtils::freqToChannel(scanMeas[ap_cnt]->frequency));

                     for(uint32 i=0; i < info[meas_cnt]->cfrcirInfo->len; i++)
                     {
                       fprintf(lowi_test.out_cfr_fp, "%x,",info[meas_cnt]->cfrcirInfo->data[i]);
                     }
                     fprintf(lowi_test.out_cfr_fp, "\n");
                  }
        }
      }
      break;
    default:
    break;
  }
} // lowi_test_log_meas_results

#if CONFIG_SUPPORT_LIBROXML
static void
parse_lci_info(node_t *a_node, t_lowi_test_cmd **const ppCmd)
{
  node_t *cur_node = NULL;
  LOWILciInformation *lci = NULL;
  char name[MAX_NAME_LEN];
  char payloadData[MAX_PAYLOAD_LEN];
  int size = 0;

  (*ppCmd)->lci_info = new LOWILciInformation ();
  lci = (*ppCmd)->lci_info;
  if (NULL == lci)
  {
    QUIPC_DBG_HIGH("parse_lci_info - out of memory\n");
    return;
  }

  //flags for mandatory fileds
  bool lat_available = false;
  bool lon_available = false;
  bool alt_available  = false;

  // defult values of optional fields
  lci->latitude_unc   = CHAR_MAX;
  lci->longitude_unc  = CHAR_MAX;
  lci->altitude_unc   = CHAR_MAX;
  lci->motion_pattern = LOWI_MOTION_UNKNOWN;
  lci->floor          = 80000000;
  lci->height_above_floor = 0;
  lci->height_unc     = INT_MAX;

  for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
  {
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
    if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
    {
      QUIPC_DBG_HIGH("parse_lci_info: Element, name: %s\n", name);
      if (strncmp(name, XML_NODE_LCI_LAT, strlen(XML_NODE_LCI_LAT) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%" PRId64, &(lci->latitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Latitude = %" PRId64 "\n", lci->latitude);
            break;
          }
          lat_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (strncmp(name, XML_NODE_LCI_LON, strlen(XML_NODE_LCI_LON) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%" PRId64, &(lci->longitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Longitude = %" PRId64 "\n", lci->longitude);
            break;
          }
          lon_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (strncmp(name, XML_NODE_LCI_ALT, strlen(XML_NODE_LCI_ALT) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%d", &(lci->altitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Altitude = %d\n", lci->altitude);
            break;
          }
          alt_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (strncmp(name, XML_NODE_LCI_LAT_UNC, strlen(XML_NODE_LCI_LAT_UNC) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->latitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Latitude Unc = %hhu\n", lci->latitude_unc);
          }
        }
      }
      else if (strncmp(name, XML_NODE_LCI_LON_UNC, strlen(XML_NODE_LCI_LON_UNC) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->longitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Longitude Unc = %hhu\n", lci->longitude_unc);
          }
        }
      }
      else if (strncmp(name, XML_NODE_LCI_ALT_UNC, strlen(XML_NODE_LCI_ALT_UNC) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->altitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Altitude Unc = %hhu\n", lci->altitude_unc);
          }
        }
      }
      else if (strncmp(name, XML_NODE_LCI_MOTION_PATTERN, strlen(XML_NODE_LCI_MOTION_PATTERN) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          // default value for unknown
          uint8 motion = 2;
          int status = sscanf(payloadData, "%hhu", &motion);
          if (status < 1 || motion > 2)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Motion Pattern = %hhu\n", motion);
            motion = 2;
          }
          lci->motion_pattern = (eLowiMotionPattern)motion;
        }
      }
      else if (strncmp(name, XML_NODE_LCI_FLOOR, strlen(XML_NODE_LCI_FLOOR) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%d", &(lci->floor));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Floor = %d\n", lci->floor);
          }
        }
      }
      else if (strncmp(name, XML_NODE_LCI_HEIGHT, strlen(XML_NODE_LCI_HEIGHT) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%d", &(lci->height_above_floor));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Height = %d\n", lci->height_above_floor);
          }
        }
      }
      else if (strncmp(name, XML_NODE_LCI_HEIGHT_UNC, strlen(XML_NODE_LCI_HEIGHT_UNC) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int status = sscanf(payloadData, "%d", &(lci->height_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Height Unc = %d\n", lci->height_unc);
          }
        }
      }
    }
  }
  if (!(lat_available && lon_available && alt_available))
  {
    delete (*ppCmd)->lci_info;
    (*ppCmd)->lci_info = NULL;
  }
}

static void
parse_lcr_info(node_t *a_node, t_lowi_test_cmd **const ppCmd)
{
  node_t *cur_node = NULL;
  LOWILcrInformation *lcr = NULL;
  char name[MAX_NAME_LEN];
  char payloadData[MAX_PAYLOAD_LEN];
  int size = 0;

  (*ppCmd)->lcr_info = new LOWILcrInformation ();
  lcr = (*ppCmd)->lcr_info;
  if (NULL == lcr)
  {
    QUIPC_DBG_HIGH("parse_lci_info - out of memory\n");
    return;
  }

  //flags for mandatory fileds
  bool cc_available = false;

  for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
  {
    memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
    {
      QUIPC_DBG_HIGH("parse_lcr_info: Element, name: %s\n", name);
      if (strncmp(name, XML_NODE_LCR_CC, strlen(XML_NODE_LCR_CC) + 1) == 0)
      {
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (strlen(payloadData) > 0)
        {
          int i = 0;
          for (; i < LOWI_COUNTRY_CODE_LEN; i++)
          {
            int status = sscanf(payloadData+i, "%c", &(lcr->country_code[i]));
            if (status < 1)
            {
              // No need to continue
              QUIPC_DBG_HIGH("parse_lcr_info: Element,"
                     " value is not formed correctly. Country Code[%d] = %c\n", i, lcr->country_code[i]);
              break;
            }
          }
          if (i != LOWI_COUNTRY_CODE_LEN)
          {
            break;
          }
          cc_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (strncmp(name, XML_NODE_LCR_CIVIC, strlen(XML_NODE_LCR_CIVIC) + 1) == 0)
      {
        char civicInfo[CIVIC_INFO_LEN];

        memset(&civicInfo[0], 0, sizeof(char)*CIVIC_INFO_LEN);
        roxml_get_content(cur_node, &civicInfo[0], CIVIC_INFO_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", civicInfo);
        if (strlen(civicInfo) > 0)
        {
          // Civic Info is in hex bytes format
          // 010203040506a1a2a3a4a5a6.....
          size_t i;
          for (i = 0; i < strlen(civicInfo)/2 && i < CIVIC_INFO_LEN; i++)
          {
            if (sscanf(civicInfo + 2*i, "%2hhx", &(lcr->civic_info[i])) <= 0)
            {
              break;
            }
          }
          lcr->length = i;
        }
        else
        {
          // No need to continue
          break;
        }
      }
    }
  }
  // Since Civic info is optional, cc_available only needs to be checked
  if (!cc_available)
  {
    delete(*ppCmd)->lcr_info;
    (*ppCmd)->lcr_info = NULL;
  }
}

static void
parse_ftmrr_info(node_t *a_node, t_lowi_test_cmd **const ppCmd)
{
  node_t *cur_node = NULL;
  node_t *cur_elm_node = NULL;

  bool bssid_available = false;
  bool bssid_info_available = false;
  bool op_class_available = false;
  bool ch_available = false;
  bool ch1_available = false;
  bool ch2_available = false;
  bool chw_available = false;
  bool phy_type_available = false;

  LOWIMacAddress bssid;
  uint32 bssidInfo;
  uint8 operatingClass;
  uint8 phyType;
  uint8 ch;
  uint8 center_Ch1;
  uint8 center_Ch2;
  eRangingBandwidth bandwidth;
  char name[MAX_NAME_LEN];
  char elm_name[MAX_NAME_LEN];
  char payloadData[MAX_PAYLOAD_LEN];
  int size = 0;

  for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
  {
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    if (roxml_get_type(cur_node) == ROXML_ELM_NODE &&
        strncmp(name, XML_NODE_FTMRR_ELM, strlen(XML_NODE_FTMRR_ELM) + 1) == 0)
    {
      if (bssid_available && bssid_info_available &&
          op_class_available && ch_available && phy_type_available)
      {
        if (ch1_available && ch2_available &&
            chw_available)
        {
          LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch,
                                 center_Ch1, center_Ch2, bandwidth);
          (*ppCmd)->ftmrr_info.push_back(node);
        }
        else
        {
          LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch);
          (*ppCmd)->ftmrr_info.push_back(node);
        }
      }

      QUIPC_DBG_HIGH("%s - element initializing ftmrr_node\n", __FUNCTION__);
      bssid_available = false;
      bssid_info_available = false;
      op_class_available = false;
      ch_available = false;
      ch1_available = false;
      ch2_available = false;
      chw_available = false;
      phy_type_available = false;
      for (cur_elm_node = roxml_get_chld(cur_node, NULL, 0); cur_elm_node;
           cur_elm_node = roxml_get_next_sibling(cur_elm_node))
      {
        memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
        roxml_get_name(cur_elm_node, &elm_name[0], MAX_NAME_LEN);
        if (roxml_get_type(cur_elm_node) == ROXML_ELM_NODE)
        {
          QUIPC_DBG_HIGH("parse_ftmrr_info: Element, name: %s\n", elm_name);
          if (strncmp(elm_name, XML_NODE_FTMRR_ELM_BSSID, strlen(XML_NODE_FTMRR_ELM_BSSID) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              unsigned char bssid_char[6];
              int status = sscanf(payloadData,
                                  "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                  &bssid_char[0],
                                  &bssid_char[1],
                                  &bssid_char[2],
                                  &bssid_char[3],
                                  &bssid_char[4],
                                  &bssid_char[5]);
              bssid.setMac(bssid_char);
              if (status < 6)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. bssid\n");
                break;
              }
              QUIPC_DBG_HIGH("%s - MAC Address from user: macAddr-parsed: " LOWI_MACADDR_FMT "\n",
                     __FUNCTION__,
                     LOWI_MACADDR(bssid));
              bssid_available = true;
            }
            else
            {
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_BSSID_INFO, strlen(XML_NODE_FTMRR_ELM_BSSID_INFO) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              uint8 bssid_Info[4] = {0};
              int status = sscanf(payloadData, "%02hhx%02hhx%02hhx%02hhx",
                                  &bssid_Info[0], &bssid_Info[1], &bssid_Info[2], &bssid_Info[3]);
              bssidInfo = *((uint32 *)bssid_Info);
              if (status < 4)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. bssidInfo\n");
                break;
              }
              bssid_info_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_CENTER_CH1, strlen(XML_NODE_FTMRR_ELM_CENTER_CH1) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &center_Ch1);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. center channel 1\n");
                break;
              }
              ch1_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_CENTER_CH2, strlen(XML_NODE_FTMRR_ELM_CENTER_CH2) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0],
                              MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &center_Ch2);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. center channel 2\n");
                break;
              }
              ch2_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_CH, strlen(XML_NODE_FTMRR_ELM_CH) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &ch);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. channel\n");
                break;
              }
              ch_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_CH_WIDTH, strlen(XML_NODE_FTMRR_ELM_CH_WIDTH) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int bwChoice = -1;
              int status = sscanf(payloadData, "%d", &bwChoice);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. channel width\n");
                break;
              }
              bandwidth = LOWIUtils::to_eRangingBandwidth(bwChoice);
              chw_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_OP_CLASS, strlen(XML_NODE_FTMRR_ELM_OP_CLASS) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &operatingClass);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. op class\n");
                break;
              }
              op_class_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (strncmp(elm_name, XML_NODE_FTMRR_ELM_PHY_TYPE, strlen(XML_NODE_FTMRR_ELM_PHY_TYPE) + 1) == 0)
          {
            roxml_get_content(cur_elm_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &phyType);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. phy type\n");
                break;
              }
              phy_type_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
        }
      }
    }
  }
  if (bssid_available && bssid_info_available &&
      op_class_available && ch_available && phy_type_available)
  {
    if (ch1_available && ch2_available &&
        chw_available)
    {
      LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch,
                             center_Ch1, center_Ch2, bandwidth);
      (*ppCmd)->ftmrr_info.push_back(node);
    }
    else
    {
      LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch);
      (*ppCmd)->ftmrr_info.push_back(node);
    }
  }
  else
  {
    QUIPC_DBG_HIGH("%s - bssid:%d, info:%d, op_class:%d, ch:%d ch1:%d ch2:%d chw:%d phy:%d",
           __FUNCTION__, bssid_available, bssid_info_available,
           op_class_available, ch_available, ch1_available, ch2_available,
           chw_available, phy_type_available);
  }
}

static int parse_int_element(node_t *pXmlNode, int& value,
                             const xmlChar * const xmlString)
{
  int retVal = -1;
  char payloadData[MAX_PAYLOAD_LEN];
  int size = 0;

  memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
  roxml_get_content(pXmlNode, &payloadData[0], MAX_PAYLOAD_LEN, &size);
  do
  {
    if (!strlen(payloadData))
    {
      QUIPC_DBG_HIGH("%s:%s No Payload\n", __FUNCTION__, xmlString);
      break;
    }
    QUIPC_DBG_HIGH("%s:%s Payload: %s\n", __FUNCTION__, xmlString, payloadData);
    int status = sscanf(payloadData, "%d", &value);
    if (status < 1)
    {
      QUIPC_DBG_ERROR("%s: Element %s not formed correctly. Value = %d\n",
                      __FUNCTION__, xmlString, value);
      break;
    }
    retVal = 0;
  }
  while (0);
  return retVal;
}

static int parse_string_element(node_t *pXmlNode, char* p_arr, int& len,
                                const xmlChar * const xmlString)
{
  int retVal = -1;
  char payloadData[MAX_PAYLOAD_LEN];
  int size = 0;

  memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
  roxml_get_content(pXmlNode, &payloadData[0], MAX_PAYLOAD_LEN, &size);
  do
  {
    if ( (NULL == p_arr) || (0 == len) )
    {
      QUIPC_DBG_HIGH("%s:%s Invalid input params\n", __FUNCTION__, xmlString);
      break;
    }
    if (!strlen(payloadData))
    {
      QUIPC_DBG_HIGH("%s:%s No Payload\n", __FUNCTION__, xmlString);
      break;
    }
    QUIPC_DBG_HIGH("%s:%s Payload: %s\n", __FUNCTION__, xmlString, payloadData);

    len = strlcpy (p_arr, payloadData, len);
    if (len < 1)
    {
      QUIPC_DBG_ERROR("%s: Element %s not formed correctly.\n",
                      __FUNCTION__, xmlString);
      break;
    }
    retVal = 0;
  }
  while (0);
  return retVal;
}
#else
static void
parse_lci_info(xmlNode *a_node, t_lowi_test_cmd **const ppCmd)
{
  xmlNode *cur_node = NULL;
  LOWILciInformation *lci = NULL;

  (*ppCmd)->lci_info = new LOWILciInformation ();
  lci = (*ppCmd)->lci_info;
  if (NULL == lci)
  {
    QUIPC_DBG_HIGH("parse_lci_info - out of memory\n");
    return;
  }

  //flags for mandatory fileds
  bool lat_available = false;
  bool lon_available = false;
  bool alt_available  = false;

  // defult values of optional fields
  lci->latitude_unc   = CHAR_MAX;
  lci->longitude_unc  = CHAR_MAX;
  lci->altitude_unc   = CHAR_MAX;
  lci->motion_pattern = LOWI_MOTION_UNKNOWN;
  lci->floor          = 80000000;
  lci->height_above_floor = 0;
  lci->height_unc     = INT_MAX;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next)
  {
    if (cur_node->type == XML_ELEMENT_NODE)
    {
      QUIPC_DBG_HIGH("parse_lci_info: Element, name: %s\n", cur_node->name);
      if (xmlStrncmp(cur_node->name, XML_NODE_LCI_LAT, xmlStrlen(XML_NODE_LCI_LAT)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%" PRId64, &(lci->latitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Latitude = %" PRId64 "\n", lci->latitude);
            break;
          }
          lat_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_LON, xmlStrlen(XML_NODE_LCI_LON)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%" PRId64, &(lci->longitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Longitude = %" PRId64 "\n", lci->longitude);
            break;
          }
          lon_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_ALT, xmlStrlen(XML_NODE_LCI_ALT)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%d", &(lci->altitude));
          if (status < 1)
          {
            // No need to continue
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Altitude = %d\n", lci->altitude);
            break;
          }
          alt_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_LAT_UNC, xmlStrlen(XML_NODE_LCI_LAT_UNC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->latitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Latitude Unc = %hhu\n", lci->latitude_unc);
          }
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_LON_UNC, xmlStrlen(XML_NODE_LCI_LON_UNC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->longitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Longitude Unc = %hhu\n", lci->longitude_unc);
          }
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_ALT_UNC, xmlStrlen(XML_NODE_LCI_ALT_UNC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%hhu", &(lci->altitude_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Altitude Unc = %hhu\n", lci->altitude_unc);
          }
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_MOTION_PATTERN, xmlStrlen(XML_NODE_LCI_MOTION_PATTERN)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          // default value for unknown
          uint8 motion = 2;
          int status = sscanf(payloadData, "%hhu", &motion);
          if (status < 1 || motion > 2)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Motion Pattern = %hhu\n", motion);
            motion = 2;
          }
          lci->motion_pattern = (eLowiMotionPattern)motion;
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_FLOOR, xmlStrlen(XML_NODE_LCI_FLOOR)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%d", &(lci->floor));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Floor = %d\n", lci->floor);
          }
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_HEIGHT, xmlStrlen(XML_NODE_LCI_HEIGHT)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%d", &(lci->height_above_floor));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Height = %d\n", lci->height_above_floor);
          }
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCI_HEIGHT_UNC, xmlStrlen(XML_NODE_LCI_HEIGHT_UNC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int status = sscanf(payloadData, "%d", &(lci->height_unc));
          if (status < 1)
          {
            // Can continue using default value
            QUIPC_DBG_HIGH("parse_lci_info: Element,"
                   " value is not formed correctly. Height Unc = %d\n", lci->height_unc);
          }
        }
      }
    }
  }
  if (!(lat_available && lon_available && alt_available))
  {
    delete (*ppCmd)->lci_info;
    (*ppCmd)->lci_info = NULL;
  }
}

static void
parse_lcr_info(xmlNode *a_node, t_lowi_test_cmd **const ppCmd)
{
  xmlNode *cur_node = NULL;
  LOWILcrInformation *lcr = NULL;

  (*ppCmd)->lcr_info = new LOWILcrInformation ();
  lcr = (*ppCmd)->lcr_info;
  if (NULL == lcr)
  {
    QUIPC_DBG_HIGH("parse_lci_info - out of memory\n");
    return;
  }

  //flags for mandatory fileds
  bool cc_available = false;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next)
  {
    if (cur_node->type == XML_ELEMENT_NODE)
    {
      QUIPC_DBG_HIGH("parse_lcr_info: Element, name: %s\n", cur_node->name);
      if (xmlStrncmp(cur_node->name, XML_NODE_LCR_CC, xmlStrlen(XML_NODE_LCR_CC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData)
        {
          int i = 0;
          for (; i < LOWI_COUNTRY_CODE_LEN; i++)
          {
            int status = sscanf(payloadData+i, "%c", &(lcr->country_code[i]));
            if (status < 1)
            {
              // No need to continue
              QUIPC_DBG_HIGH("parse_lcr_info: Element,"
                     " value is not formed correctly. Country Code[%d] = %c\n", i, lcr->country_code[i]);
              break;
            }
          }
          if (i != LOWI_COUNTRY_CODE_LEN)
          {
            break;
          }
          cc_available = true;
        }
        else
        {
          // No need to continue
          break;
        }
      }
      else if (xmlStrncmp(cur_node->name, XML_NODE_LCR_CIVIC, xmlStrlen(XML_NODE_LCR_CIVIC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n", payloadData);
        if (NULL != payloadData && strlen(payloadData) > 0)
        {
          // Civic Info is in hex bytes format
          // 010203040506a1a2a3a4a5a6.....
          size_t i;
          for (i = 0; i < strlen(payloadData)/2 && i < CIVIC_INFO_LEN; i++)
          {
            if (sscanf(payloadData + 2*i, "%2hhx", &(lcr->civic_info[i])) <= 0)
            {
              break;
            }
          }
          lcr->length = i;
        }
        else
        {
          // No need to continue
          break;
        }
      }
    }
  }
  // Since Civic info is optional, cc_available only needs to be checked
  if (!cc_available)
  {
    delete(*ppCmd)->lcr_info;
    (*ppCmd)->lcr_info = NULL;
  }
}

static void
parse_ftmrr_info(xmlNode *a_node, t_lowi_test_cmd **const ppCmd)
{
  xmlNode *cur_node = NULL;
  xmlNode *cur_elm_node = NULL;

  bool bssid_available = false;
  bool bssid_info_available = false;
  bool op_class_available = false;
  bool ch_available = false;
  bool ch1_available = false;
  bool ch2_available = false;
  bool chw_available = false;
  bool phy_type_available = false;

  LOWIMacAddress bssid;
  uint32 bssidInfo;
  uint8 operatingClass;
  uint8 phyType;
  uint8 ch;
  uint8 center_Ch1;
  uint8 center_Ch2;
  eRangingBandwidth bandwidth;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next)
  {
    if (cur_node->type == XML_ELEMENT_NODE && xmlStrncmp(cur_node->name, XML_NODE_FTMRR_ELM, xmlStrlen(XML_NODE_FTMRR_ELM)) == 0)
    {
      if (bssid_available && bssid_info_available &&
          op_class_available && ch_available && phy_type_available)
      {
        if (ch1_available && ch2_available &&
            chw_available)
        {
          LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch,
                                 center_Ch1, center_Ch2, bandwidth);
          (*ppCmd)->ftmrr_info.push_back(node);
        }
        else
        {
          LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch);
          (*ppCmd)->ftmrr_info.push_back(node);
        }
      }

      QUIPC_DBG_HIGH("%s - element initializing ftmrr_node\n", __FUNCTION__);
      bssid_available = false;
      bssid_info_available = false;
      op_class_available = false;
      ch_available = false;
      ch1_available = false;
      ch2_available = false;
      chw_available = false;
      phy_type_available = false;
      for (cur_elm_node = cur_node->children; cur_elm_node; cur_elm_node = cur_elm_node->next)
      {
        if (cur_elm_node->type == XML_ELEMENT_NODE)
        {
          QUIPC_DBG_HIGH("parse_ftmrr_info: Element, name: %s\n", cur_elm_node->name);
          if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_BSSID, xmlStrlen(XML_NODE_FTMRR_ELM_BSSID)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              unsigned char bssid_char[6];
              int status = sscanf(payloadData,
                                  "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                  &bssid_char[0],
                                  &bssid_char[1],
                                  &bssid_char[2],
                                  &bssid_char[3],
                                  &bssid_char[4],
                                  &bssid_char[5]);
              bssid.setMac(bssid_char);
              if (status < 6)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. bssid\n");
                break;
              }
              QUIPC_DBG_HIGH("%s - MAC Address from user: macAddr-parsed: " LOWI_MACADDR_FMT "\n",
                     __FUNCTION__,
                     LOWI_MACADDR(bssid));
              bssid_available = true;
            }
            else
            {
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_BSSID_INFO, xmlStrlen(XML_NODE_FTMRR_ELM_BSSID_INFO)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              uint8 bssid_Info[4] = {0};
              int status = sscanf(payloadData, "%02hhx%02hhx%02hhx%02hhx",
                                  &bssid_Info[0], &bssid_Info[1], &bssid_Info[2], &bssid_Info[3]);
              bssidInfo = *((uint32 *)bssid_Info);
              if (status < 4)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. bssidInfo\n");
                break;
              }
              bssid_info_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_CENTER_CH1, xmlStrlen(XML_NODE_FTMRR_ELM_CENTER_CH1)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &center_Ch1);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. center channel 1\n");
                break;
              }
              ch1_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_CENTER_CH2, xmlStrlen(XML_NODE_FTMRR_ELM_CENTER_CH2)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &center_Ch2);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. center channel 2\n");
                break;
              }
              ch2_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_CH, xmlStrlen(XML_NODE_FTMRR_ELM_CH)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &ch);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. channel\n");
                break;
              }
              ch_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_CH_WIDTH, xmlStrlen(XML_NODE_FTMRR_ELM_CH_WIDTH)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int bwChoice = -1;
              int status = sscanf(payloadData, "%d", &bwChoice);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. channel width\n");
                break;
              }
              bandwidth = LOWIUtils::to_eRangingBandwidth(bwChoice);
              chw_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_OP_CLASS, xmlStrlen(XML_NODE_FTMRR_ELM_OP_CLASS)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &operatingClass);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. op class\n");
                break;
              }
              op_class_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
          else if (xmlStrncmp(cur_elm_node->name, XML_NODE_FTMRR_ELM_PHY_TYPE, xmlStrlen(XML_NODE_FTMRR_ELM_PHY_TYPE)) == 0)
          {
            const char *payloadData = (const char *)xmlNodeGetContent(cur_elm_node);
            QUIPC_DBG_HIGH("parse_ftmrr_info: Element, value: %s\n", payloadData);
            if (NULL != payloadData && strlen(payloadData) > 0)
            {
              int status = sscanf(payloadData, "%hhu", &phyType);
              if (status < 1)
              {
                QUIPC_DBG_HIGH("parse_ftmrr_info: Element,"
                       " value is not formed correctly. phy type\n");
                break;
              }
              phy_type_available = true;
            }
            else
            {
              // No need to continue
              break;
            }
          }
        }
      }
    }
  }
  if (bssid_available && bssid_info_available &&
      op_class_available && ch_available && phy_type_available)
  {
    if (ch1_available && ch2_available &&
        chw_available)
    {
      LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch,
                             center_Ch1, center_Ch2, bandwidth);
      (*ppCmd)->ftmrr_info.push_back(node);
    }
    else
    {
      LOWIFTMRRNodeInfo node(bssid, bssidInfo, operatingClass, phyType, ch);
      (*ppCmd)->ftmrr_info.push_back(node);
    }
  }
  else
  {
    QUIPC_DBG_HIGH("%s - bssid:%d, info:%d, op_class:%d, ch:%d ch1:%d ch2:%d chw:%d phy:%d",
           __FUNCTION__, bssid_available, bssid_info_available,
           op_class_available, ch_available, ch1_available, ch2_available,
           chw_available, phy_type_available);
  }
}

static int parse_int_element(xmlNode *pXmlNode, int& value,
                             const xmlChar * const xmlString)
{
  int retVal = -1;
  const char *payloadData = (const char *)xmlNodeGetContent(pXmlNode);
  do
  {
    if (NULL == payloadData)
    {
      QUIPC_DBG_HIGH("%s:%s No Payload\n", __FUNCTION__, xmlString);
      break;
    }
    QUIPC_DBG_HIGH("%s:%s Payload: %s\n", __FUNCTION__, xmlString, payloadData);
    int status = sscanf(payloadData, "%d", &value);
    if (status < 1)
    {
      QUIPC_DBG_ERROR("%s: Element %s not formed correctly. Value = %d\n",
                      __FUNCTION__, xmlString, value);
      break;
    }
    retVal = 0;
  }
  while (0);
  return retVal;
}

static int parse_string_element(xmlNode *pXmlNode, char* p_arr, int& len,
                                const xmlChar * const xmlString)
{
  int retVal = -1;
  const char *payloadData = (const char *)xmlNodeGetContent(pXmlNode);
  do
  {
    if ( (NULL == p_arr) || (0 == len) )
    {
      QUIPC_DBG_HIGH("%s:%s Invalid input params\n", __FUNCTION__, xmlString);
      break;
    }
    if (NULL == payloadData)
    {
      QUIPC_DBG_HIGH("%s:%s No Payload\n", __FUNCTION__, xmlString);
      break;
    }
    QUIPC_DBG_HIGH("%s:%s Payload: %s\n", __FUNCTION__, xmlString, payloadData);

    len = strlcpy (p_arr, payloadData, len);
    if (len < 1)
    {
      QUIPC_DBG_ERROR("%s: Element %s not formed correctly.\n",
                      __FUNCTION__, xmlString);
      break;
    }
    retVal = 0;
  }
  while (0);
  return retVal;
}
#endif

void addElementstoLogInfo (const char* tag[], int size, uint8 loglevel,t_lowi_test_cmd **const ppCmd)
{
  for (int jj = 0; jj < size; ++jj)
  {
    if (tag != NULL)
    {
      LOWILogInfo loginfo(tag[jj], loglevel);
      (*ppCmd)->lowiconfigrequest->mLogInfo.push_back(loginfo);
    }
  }
}

static void mapModuleIdtoTag (vector<LOWIModuleInfo> vec, t_lowi_test_cmd **const ppCmd)
{
  for (uint32 ii = 0; ii < vec.getNumOfElements(); ++ii)
  {
    log_verbose (LOG_TAG,"module id %d log level %d \n", vec[ii].moduleid, vec[ii].log_level);
    switch (vec[ii].moduleid)
    {
      case LOWI_ENGINE:
        {
          addElementstoLogInfo(LOWI_ENGINE_TAGS, LOWI_ARR_SIZE(LOWI_ENGINE_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_COMMON_INFO:
        {
          addElementstoLogInfo(LOWI_COMMON_INFO_TAGS, LOWI_ARR_SIZE(LOWI_COMMON_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_CLIENT_INFO:
        {
          addElementstoLogInfo(LOWI_CLIENT_INFO_TAGS, LOWI_ARR_SIZE(LOWI_CLIENT_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_SCANS_INFO:
        {
          addElementstoLogInfo(LOWI_SCANS_INFO_TAGS, LOWI_ARR_SIZE(LOWI_SCANS_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_WIFI_INFO:
        {
          addElementstoLogInfo(LOWI_WIFI_INFO_TAGS, LOWI_ARR_SIZE(LOWI_WIFI_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_WIFIDRIVER_INFO:
        {
          addElementstoLogInfo(LOWI_WIFIDRIVER_INFO_TAGS, LOWI_ARR_SIZE(LOWI_WIFIDRIVER_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_WIFIHAL_INFO:
        {
          addElementstoLogInfo(LOWI_WIFIHAL_INFO_TAGS, LOWI_ARR_SIZE(LOWI_WIFIHAL_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_RANGING_INFO:
        {
          addElementstoLogInfo(LOWI_RANGING_INFO_TAGS, LOWI_ARR_SIZE(LOWI_RANGING_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_FSM_INFO:
        {
          addElementstoLogInfo(LOWI_FSM_INFO_TAGS, LOWI_ARR_SIZE(LOWI_FSM_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
      case LOWI_WIGIG_RANGING_INFO:
        {
          addElementstoLogInfo(LOWI_WIGIG_RANGING_INFO_TAGS, LOWI_ARR_SIZE(LOWI_WIGIG_RANGING_INFO_TAGS),
                               vec[ii].log_level, ppCmd);
          break;
        }
    }
  }
}

#if CONFIG_SUPPORT_LIBROXML
static void
parse_cfg_info(node_t *a_node, t_lowi_test_cmd **const ppCmd)
{
  node_t *cur_node = NULL;
  node_t *cur_elm_node = NULL;
  vector <LOWIModuleInfo> vec;
  LOWIModuleInfo lowimoduleinfo;
  char name[MAX_NAME_LEN];
  char chld_name[MAX_NAME_LEN];
  char sibl_name[MAX_NAME_LEN];

  (*ppCmd)->lowiconfigrequest = new LOWIConfigRequest(0, LOWIConfigRequest::LOG_CONFIG);
  if ((*ppCmd)->lowiconfigrequest == NULL)
  {
    QUIPC_DBG_HIGH("%s:Null Log Config request", __FUNCTION__);
    return;
  }

  for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
  {
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    if (roxml_get_type(cur_node) == ROXML_ELM_NODE &&
        strncmp(name, XML_NODE_CONFIG_GLOBAL_LOG_LEVEL, strlen(XML_NODE_CONFIG_GLOBAL_LOG_LEVEL) + 1) == 0)
    {
      int level = -1;
      int status = parse_int_element(cur_node, level, XML_NODE_CONFIG_GLOBAL_LOG_LEVEL);
      if (status != 0)
      {
        continue;
      }
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogLevel = level;
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogFlag = true;
    }

    if (roxml_get_type(cur_node) == ROXML_ELM_NODE &&
        strncmp(name, XML_NODE_CONFIG_LOG_INFO, strlen(XML_NODE_CONFIG_LOG_INFO) + 1) == 0)
    {
      for (cur_elm_node = roxml_get_chld(cur_node, NULL, 0); cur_elm_node; cur_elm_node = roxml_get_next_sibling(cur_elm_node))
      {
        roxml_get_name(cur_elm_node, &chld_name[0], MAX_NAME_LEN);
        if (roxml_get_type(cur_elm_node) == ROXML_ELM_NODE &&
            strncmp(chld_name, XML_NODE_CONFIG_LOG_MODULE_ID, strlen(XML_NODE_CONFIG_LOG_MODULE_ID) + 1) == 0 &&
            strncmp(roxml_get_name(roxml_get_next_sibling(cur_elm_node), &sibl_name[0], MAX_NAME_LEN),
                    XML_NODE_CONFIG_LOG_LEVEL,
                    strlen(XML_NODE_CONFIG_LOG_LEVEL) + 1) == 0)
        {
          int id = -1;
          int level = -1;
          int status = parse_int_element(cur_elm_node, id, XML_NODE_CONFIG_LOG_MODULE_ID);
          if (status != 0)
          {
            continue;
          }
          status = parse_int_element(roxml_get_next_sibling(cur_elm_node), level, XML_NODE_CONFIG_LOG_LEVEL);
          if (status != 0)
          {
            continue;
          }
          lowimoduleinfo.moduleid = (eModuleId)id;
          lowimoduleinfo.log_level = level;
          vec.push_back(lowimoduleinfo);
        }
      }
    }
  }
  mapModuleIdtoTag (vec, ppCmd);
}

static int parse_chan_element(node_t * a_node)
{
  int ch = 0; // 0 is an invalid channel
  char name[MAX_NAME_LEN];

  if (NULL == a_node)
  {
    QUIPC_DBG_HIGH("%s:Null input node: %p",
                   __FUNCTION__, a_node);
    return ch;
  }
  node_t *cur_node = roxml_get_chld(a_node, NULL, 0);
  LOWIDiscoveryScanRequest::eBand eband = LOWIDiscoveryScanRequest::BAND_ALL;
  for (; cur_node != NULL; cur_node = roxml_get_next_sibling(cur_node))
  {
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    if (strncmp(name, XML_NODE_CH, strlen(XML_NODE_CH) + 1) == 0)
    {
      parse_int_element(cur_node, ch, XML_NODE_CH);
    }
    if (strncmp(name, XML_NODE_BAND, strlen(XML_NODE_BAND) + 1) == 0)
    {
      // Only 2G / 5G allowed as a valid band.
      int band = -1;
      int status = parse_int_element(cur_node, band, XML_NODE_BAND);
      if (status != 0)
      {
        // No need to continue
        continue;
      }
      eband = LOWIUtils::to_eBand(band);
    }
  }
  return LOWIUtils::channelBandToFreq((uint32)ch, eband);
}

static void
parse_elements(node_t * a_node, t_lowi_test_cmd ** const ppCmd)
{
  node_t *cur_node = NULL;
  LOWIPeriodicNodeInfo node;
  node.paramControl = LOWI_NO_PARAMS_FROM_CACHE;

  struct LOWIPostProcessNode process_ap_node;
  char name[MAX_NAME_LEN];
  char parent_name[MAX_NAME_LEN];
  char ansc_name[MAX_NAME_LEN];

  for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
  {
    roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
    if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
    {
      vector<LOWIPeriodicNodeInfo>& rttVector = (*ppCmd)->rttNodes;
      LOWIPeriodicNodeInfo& rttNode = rttVector.getNumOfElements() ?
                                      rttVector[rttVector.getNumOfElements()-1] :
                                      node;

      vector <LOWIPostProcessNode >& node_cache_vector = (*ppCmd)->post_process_info.node_cache;
      struct LOWIPostProcessNode& node_cache = node_cache_vector.getNumOfElements() ?
                                     node_cache_vector[node_cache_vector.getNumOfElements() - 1] :
                                     process_ap_node;

      QUIPC_DBG_HIGH("parse_elements: Element, name: %s\n", name);
      if ((strncmp (name, XML_NODE_AP, strlen(XML_NODE_AP) + 1) == 0) &&
          (strncmp (roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                    XML_NODE_RANGING,
                    strlen(XML_NODE_RANGING) + 1) == 0))
      {
        rttVector.push_back(node);
        QUIPC_DBG_HIGH("Adding into lowi_cmd node cache");
        node_cache_vector.push_back(node_cache);
      }
      if (strncmp (name, XML_NODE_REPORTTYPE, strlen(XML_NODE_REPORTTYPE) + 1) == 0)
      {
        int reportType;
        int status = parse_int_element(cur_node, reportType, XML_NODE_REPORTTYPE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          (*ppCmd)->reportType = (uint32)reportType;
        }
        QUIPC_DBG_HIGH("parse_elements: Element, value: %d \n", reportType);
      }
      if (strncmp (name, XML_NODE_MAC, strlen(XML_NODE_MAC) + 1) == 0)
      {
        char payloadData[MAX_PAYLOAD_LEN];
        int size = 0;

        memset(&payloadData[0], 0, sizeof(char)*MAX_PAYLOAD_LEN);
        roxml_get_content(cur_node, &payloadData[0], MAX_PAYLOAD_LEN, &size);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n",
            payloadData);
        if (strlen(payloadData) > 0)
        {
          uint8 bssid[BSSID_LEN];
          memset(bssid, 0, sizeof(bssid));
          int status = sscanf(payloadData, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                              &bssid[0], &bssid[1], &bssid[2],
                              &bssid[3], &bssid[4], &bssid[5]);
          if (status < 6)
          {
            // Either the element does not contain the content or it is
            // not formatted correctly. Set all the entries to 0
            QUIPC_DBG_ERROR("parse_elements: Element,"
                " value is not formed correctly %d\n", status);
          }
          else if (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                            XML_NODE_RANGING,
                            strlen(XML_NODE_RANGING) + 1) == 0)
          {
            rttNode.bssid.setMac(bssid);
            node_cache.bssid.setMac(bssid);
            QUIPC_DBG_HIGH("%s: ftmParams: 0x%x, numFrames: %u\n", __FUNCTION__,
                           rttNode.ftmRangingParameters, rttNode.num_pkts_per_meas);
          }
          else if (strncmp (roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                            XML_NODE_SUMMARY,
                            strlen(XML_NODE_SUMMARY) + 1) == 0)
          {
            LOWIMacAddress mac (bssid);
            (*ppCmd)->summary_aps.push_back(mac);
          }//else if
          else if (strncmp (roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                            XML_NODE_DISCOVERY,
                            strlen(XML_NODE_DISCOVERY) + 1) == 0)
          {
            LOWIMacAddress mac (bssid);
            (*ppCmd)->discoveryBssids.push_back (mac);
          }//else if
        } //payloadData != NULL
      } //XML_NODE_MAC

      // Check SSID node
      if (strncmp (name, XML_NODE_SSID, strlen(XML_NODE_SSID) + 1) == 0)
      {
        char ss [SSID_LEN+1] = {0};
        int len = SSID_LEN+1;
        int status = parse_string_element(cur_node, ss, len, XML_NODE_SSID);
        if (status != 0)
        {
          // No need to continue
          continue;
        }
        if (0 != len)
        {
          LOWISsid ssid;
          ssid.setSSID((unsigned char*)ss, len);
          (*ppCmd)->discoverySsids.push_back (ssid);
        }
      }

      if ((strncmp (name, XML_NODE_CHAN, strlen(XML_NODE_CHAN) + 1) == 0) &&
          (strncmp(roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                   XML_NODE_DISCOVERY,
                   strlen(XML_NODE_DISCOVERY) + 1) == 0))
      {
        int freq = parse_chan_element(cur_node);
        LOWIChannelInfo chInfo(freq);
        (*ppCmd)->chList.push_back(chInfo);
        continue; // Don't parse the current node's children
      }
      if ((strncmp(name, XML_NODE_CH, strlen(XML_NODE_CH) + 1) == 0) &&
          (strncmp(roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                   XML_NODE_RANGING,
                   strlen(XML_NODE_RANGING) + 1) == 0) &&
          (rttNode.frequency == 0))
      {
        // CH element is only used if frequency is not set.
        int ch = -1;
        int status = parse_int_element(cur_node, ch, XML_NODE_CH);
        if (status != 0)
        {
          continue;
        }
        rttNode.frequency = LOWIUtils::channelBandToFreq(ch);
      }
      if (strncmp (name, XML_NODE_TRUE_DISTANCE, strlen(XML_NODE_TRUE_DISTANCE) + 1) == 0)
      {
        int trueDist = -1;
        int status = parse_int_element(cur_node, trueDist, XML_NODE_TRUE_DISTANCE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          node_cache.true_dist = trueDist;
        }
      }
      if (strncmp (name, XML_NODE_2P4_DELAY_PS, strlen(XML_NODE_2P4_DELAY_PS) + 1) == 0)
      {
        int delay_ps_2p4 = 0;
        int status = parse_int_element(cur_node, delay_ps_2p4, XML_NODE_2P4_DELAY_PS);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          node_cache.delay_ps_2p4 = delay_ps_2p4;
        }
      }
      if (strncmp (name, XML_NODE_5G_DELAY_PS, strlen(XML_NODE_5G_DELAY_PS) + 1) == 0)
      {
        int delay_ps_5g = 0;
        int status = parse_int_element(cur_node, delay_ps_5g, XML_NODE_5G_DELAY_PS);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          node_cache.delay_ps_5g = delay_ps_5g;
        }
      }
      if (strncmp (name, XML_NODE_SKIP_FIRT_MEAS, strlen(XML_NODE_SKIP_FIRT_MEAS) + 1) == 0)
      {
        int skipFirst = 0;
        int status = parse_int_element(cur_node, skipFirst, XML_NODE_SKIP_FIRT_MEAS);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          node_cache.skip_first = skipFirst;
          QUIPC_DBG_HIGH("%s: Skip first mesurements: %d \n", __FUNCTION__,
                          skipFirst);
        }
      }
      if (strncmp (name, XML_NODE_FREQUENCY, strlen(XML_NODE_FREQUENCY) + 1) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_FREQUENCY);
        if (status != 0)
        {
          continue;
        }
        if (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                     XML_NODE_RANGING,
                     strlen(XML_NODE_RANGING) + 1) == 0)
        {
          rttNode.frequency = freq;
        }
        else if (strncmp(roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                         XML_NODE_DISCOVERY,
                         strlen(XML_NODE_DISCOVERY) + 1) == 0)
        {
          if (LOWIUtils::freqToChannel(freq) != 0) // Frequency is valid
          {
            vector<LOWIChannelInfo>& chVector = (*ppCmd)->chList;
            LOWIChannelInfo chInfo(freq);
            chVector.push_back(chInfo);
          }
        }
      }
      if (strncmp (name, XML_NODE_BAND_CENTER_FREQ1, strlen(XML_NODE_BAND_CENTER_FREQ1) + 1) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_BAND_CENTER_FREQ1);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.band_center_freq1 = freq;
        }
      }

      if (strncmp (name, XML_NODE_BAND_CENTER_FREQ2, strlen(XML_NODE_BAND_CENTER_FREQ2) + 1) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_BAND_CENTER_FREQ2);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.band_center_freq2 = freq;
        }
      }

      if (strncmp (name, XML_NODE_RTT_TYPE, strlen(XML_NODE_RTT_TYPE) + 1) == 0)
      {
        int rttChoice = -1;
        int status = parse_int_element(cur_node, rttChoice, XML_NODE_RTT_TYPE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttChoice -= 1; // xml file value & lowi value don't match. make adjustment here.
          rttNode.rttType = LOWIUtils::to_eRttType(rttChoice);
        }
      }
      if (strncmp (name, XML_NODE_NUM_FRAMES_PER_BURST, strlen(XML_NODE_NUM_FRAMES_PER_BURST) + 1) == 0)
      {
        int numFramesPerBurst = -1;
        int status = parse_int_element(cur_node, numFramesPerBurst, XML_NODE_NUM_FRAMES_PER_BURST);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.num_pkts_per_meas = (uint32)numFramesPerBurst;
          node_cache.frame_per_burst = (uint32)numFramesPerBurst;
        }
      }
      if (strncmp (name, XML_NODE_RANGING_TX_BW, strlen(XML_NODE_RANGING_TX_BW) + 1) == 0)
      {
        int bwChoice = -1;
        int status = parse_int_element(cur_node, bwChoice, XML_NODE_RANGING_TX_BW);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.bandwidth = LOWIUtils::to_eRangingBandwidth(bwChoice);
          node_cache.req_tx_bw = LOWIUtils::to_eRangingBandwidth(bwChoice);
          node_cache.req_rx_bw = LOWIUtils::to_eRangingBandwidth(bwChoice);
        }
      }
      if (strncmp (name, XML_NODE_RANGING_RX_BW, strlen(XML_NODE_RANGING_RX_BW) + 1) == 0)
      {
        int rxbwChoice = -1;
        int status = parse_int_element(cur_node, rxbwChoice, XML_NODE_RANGING_RX_BW);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          node_cache.req_rx_bw = LOWIUtils::to_eRangingBandwidth(rxbwChoice);
        }
      }
      if (strncmp (name, XML_NODE_RANGING_PREAMBLE, strlen(XML_NODE_RANGING_PREAMBLE) + 1) == 0)
      {
        int preamble = -1;
        int status = parse_int_element(cur_node, preamble, XML_NODE_RANGING_PREAMBLE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.preamble = LOWIUtils::to_eRangingPreamble(preamble);
        }
      }

      if (strncmp (name, XML_NODE_PHYMODE, strlen(XML_NODE_PHYMODE) + 1) == 0)
      {
        int phymode = -1;
        int status = parse_int_element(cur_node, phymode, XML_NODE_PHYMODE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.phyMode = LOWIUtils::to_eLOWIPhyMode(phymode);
        }
      }

      if (strncmp (name, XML_NODE_PEER_TYPE, strlen(XML_NODE_PEER_TYPE) + 1) == 0)
      {
        int peerType = -1;
        int status = parse_int_element(cur_node, peerType, XML_NODE_PEER_TYPE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          rttNode.nodeType = LOWIUtils::to_eNodeType(peerType);
        }
      }

      if (strncmp (name, XML_NODE_INTERFACE, strlen(XML_NODE_INTERFACE) + 1) == 0)
      {
        int len = INTERFACE_MAX_LENGTH;
        char interface[INTERFACE_MAX_LENGTH];

        int status = parse_string_element(cur_node, interface, len, XML_NODE_INTERFACE);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          (*ppCmd)->interface = interface;
        }
      }

      if (strncmp (name, XML_NODE_FTM_RANGING_ASAP, strlen(XML_NODE_FTM_RANGING_ASAP) + 1) == 0)
      {
        int asapChoice = -1;
        int status = parse_int_element(cur_node, asapChoice, XML_NODE_FTM_RANGING_ASAP);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (asapChoice == 0)
          {
            FTM_CLEAR_ASAP(rttNode.ftmRangingParameters);
          }
          else if (asapChoice == 1)
          {
            FTM_SET_ASAP(rttNode.ftmRangingParameters);
          }
        }
      }

      if (strncmp (name, XML_NODE_FTM_RANGING_LCI, strlen(XML_NODE_FTM_RANGING_LCI) + 1) == 0)
      {
        int lciChoice = -1;
        int status = parse_int_element(cur_node, lciChoice, XML_NODE_FTM_RANGING_LCI);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (lciChoice == 0)
          {
            FTM_CLEAR_LCI_REQ(rttNode.ftmRangingParameters);
          }
          else if (lciChoice == 1)
          {
            FTM_SET_LCI_REQ(rttNode.ftmRangingParameters);
          }
        }
      }
      if (strncmp (name, XML_NODE_FTM_RANGING_LOC_CIVIC, strlen(XML_NODE_FTM_RANGING_LOC_CIVIC) + 1) == 0)
      {
        int civicChoice = -1;
        int status = parse_int_element(cur_node, civicChoice, XML_NODE_FTM_RANGING_LOC_CIVIC);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (civicChoice == 0)
          {
            FTM_CLEAR_LOC_CIVIC_REQ(rttNode.ftmRangingParameters);
          }
          else if (civicChoice == 1)
          {
            FTM_SET_LOC_CIVIC_REQ(rttNode.ftmRangingParameters);
          }
        }
      }
      if (strncmp (name, XLM_NODE_FTM_PTSF_TIMER_NO_PREF, strlen(XLM_NODE_FTM_PTSF_TIMER_NO_PREF) + 1) == 0)
      {
        int ptsfChoice = -1;
        int status = parse_int_element(cur_node, ptsfChoice, XLM_NODE_FTM_PTSF_TIMER_NO_PREF);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (ptsfChoice == 0)
          {
            FTM_CLEAR_PTSF_TIMER_NO_PREF(rttNode.ftmRangingParameters);
          }
          else if (ptsfChoice == 1)
          {
            FTM_SET_PTSF_TIMER_NO_PREF(rttNode.ftmRangingParameters);
          }
        }
      }
      if (strncmp (name, XML_NODE_FTM_RANGING_NUM_BURSTS_EXP, strlen(XML_NODE_FTM_RANGING_NUM_BURSTS_EXP) + 1) == 0)
      {
        int burstExpChoice = -1;
        int status = parse_int_element(cur_node, burstExpChoice, XML_NODE_FTM_RANGING_NUM_BURSTS_EXP);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          FTM_SET_BURSTS_EXP(rttNode.ftmRangingParameters, (uint32)burstExpChoice);
        }
      }
      if (strncmp (name, XML_NODE_FTM_RANGING_BURST_DURATION, strlen(XML_NODE_FTM_RANGING_BURST_DURATION) + 1) == 0)
      {
        int burstDurChoice = -1;
        int status = parse_int_element(cur_node, burstDurChoice, XML_NODE_FTM_RANGING_BURST_DURATION);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          FTM_SET_BURST_DUR(rttNode.ftmRangingParameters, (uint32)burstDurChoice);
        }
      }
      if (strncmp (name, XML_NODE_FTM_RANGING_BURST_PERIOD, strlen(XML_NODE_FTM_RANGING_BURST_PERIOD) + 1) == 0)
      {
        int burstPerChoice = -1;
        int status = parse_int_element(cur_node, burstPerChoice, XML_NODE_FTM_RANGING_BURST_PERIOD);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          FTM_SET_BURST_PERIOD(rttNode.ftmRangingParameters, (uint32)burstPerChoice);
        }
      }
      if (strncmp (name, XML_NODE_FTM_USE_LEG_ACK_ONLY, strlen(XML_NODE_FTM_USE_LEG_ACK_ONLY) + 1) == 0)
      {
        int forceLegAck = 0;
        int status = parse_int_element(cur_node, forceLegAck, XML_NODE_FTM_USE_LEG_ACK_ONLY);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (((*ppCmd)->forceLegAck == true) || forceLegAck != 0)
          {
            FTM_SET_LEG_ACK_ONLY(rttNode.ftmRangingParameters);
            node_cache.forceLegAck = true;
            /* req_tx_bw should always be zero when forceLegAck is enabled */
            node_cache.req_tx_bw = BW_20MHZ;
          }
          else
          {
            FTM_CLEAR_LEG_ACK_ONLY(rttNode.ftmRangingParameters);
            node_cache.forceLegAck = false;
          }
        }
      }
      if (strncmp (name, XML_NODE_FTM_FORCE_QCA_PEER, strlen(XML_NODE_FTM_FORCE_QCA_PEER) + 1) == 0)
      {
        int forceQcaPeer = 0;
        int status = parse_int_element(cur_node, forceQcaPeer, XML_NODE_FTM_FORCE_QCA_PEER);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (forceQcaPeer == 0)
          {
            FTM_CLEAR_QCA_PEER(rttNode.ftmRangingParameters);
          }
          else
          {
            FTM_SET_QCA_PEER(rttNode.ftmRangingParameters);
          }
        }
      }
      if (strncmp (name, XML_NODE_FTM_PARAM_CONTROL, strlen(XML_NODE_FTM_PARAM_CONTROL) + 1) == 0)
      {
        int paramControl = -1;
        int status = parse_int_element(cur_node, paramControl, XML_NODE_FTM_PARAM_CONTROL);
        if ((status == 0) &&
            (strncmp (roxml_get_name(roxml_get_parent(roxml_get_parent(cur_node)), &ansc_name[0], MAX_NAME_LEN),
                      XML_NODE_RANGING,
                      strlen(XML_NODE_RANGING) + 1) == 0))
        {
          if (paramControl == 0)
          {
            rttNode.paramControl = LOWI_USE_PARAMS_FROM_CACHE;
          }
          else
          {
            rttNode.paramControl = LOWI_NO_PARAMS_FROM_CACHE;
          }
        }
      }

    }
    parse_elements(roxml_get_chld(cur_node, NULL, 0), ppCmd);
  }

} // parse_elements

static void
parse_gen_input_elements(node_t *a_node, t_lowi_test_cmd **const ppCmd)
{

  node_t *cur_node = NULL;
  char name[MAX_NAME_LEN];
  char parent_name[MAX_NAME_LEN];

  switch ((*ppCmd)->cmd)
  {
  case LOWI_SET_LCI:
    for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
    {
      roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
      if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
      {
        if (strncmp(name, XML_NODE_LCI, strlen(XML_NODE_LCI) + 1) == 0)
        {
          parse_lci_info(roxml_get_chld(cur_node, NULL, 0), ppCmd);
          break;
        }
        if (strncmp (name, XML_NODE_INTERFACE,
                     strlen(XML_NODE_INTERFACE) + 1) == 0)
        {
          int len = INTERFACE_MAX_LENGTH;
          char interface[INTERFACE_MAX_LENGTH];

          int status = parse_string_element(cur_node, interface, len,
                                            XML_NODE_INTERFACE);
          if (status == 0)
          {
            (*ppCmd)->interface = interface;
          }
        }
      }
      parse_gen_input_elements(roxml_get_chld(cur_node, NULL, 0), ppCmd);
    }
    break;
  case LOWI_SET_LCR:
    for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
    {
      roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
      if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
      {
        if (strncmp(name, XML_NODE_LCR, strlen(XML_NODE_LCR) + 1) == 0)
        {
          parse_lcr_info(roxml_get_chld(cur_node, NULL, 0), ppCmd);
          break;
        }
        if (strncmp (name, XML_NODE_INTERFACE,
                     strlen(XML_NODE_INTERFACE) + 1) == 0)
        {
          int len = INTERFACE_MAX_LENGTH;
          char interface[INTERFACE_MAX_LENGTH];

          int status = parse_string_element(cur_node, interface, len,
                                            XML_NODE_INTERFACE);
          if (status == 0)
          {
            (*ppCmd)->interface = interface;
          }
        }
      }
      parse_gen_input_elements(roxml_get_chld(cur_node, NULL, 0), ppCmd);
    }
    break;
  case LOWI_FTMR_REQ:
    for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
    {
      roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
      if (roxml_get_type(cur_node) == ROXML_ELM_NODE)
      {
        if (strncmp(name, XML_NODE_FTMRR,
                    strlen(XML_NODE_FTMRR) + 1) == 0)
        {
          parse_ftmrr_info(roxml_get_chld(cur_node, NULL, 0), ppCmd);
          break;
        }
      }
      parse_gen_input_elements(roxml_get_chld(cur_node, NULL, 0), ppCmd);
    }
    break;
  case LOWI_CONFIG_REQ:
    for (cur_node = a_node; cur_node; cur_node = roxml_get_next_sibling(cur_node))
    {
      roxml_get_name(cur_node, &name[0], MAX_NAME_LEN);
      if (((roxml_get_type(cur_node) == ROXML_ELM_NODE)) &&
          ((strncmp (name, XML_NODE_CONFIG_LOG, strlen(XML_NODE_CONFIG_LOG) + 1) == 0) &&
           (strncmp (roxml_get_name(roxml_get_parent(cur_node), &parent_name[0], MAX_NAME_LEN),
                     XML_NODE_CONFIG, strlen(XML_NODE_CONFIG) + 1) == 0)))
      {
        parse_cfg_info(roxml_get_chld(cur_node, NULL, 0), ppCmd);
        break;
      }
      parse_gen_input_elements(roxml_get_chld(cur_node, NULL, 0), ppCmd);
    }
    break;
  default:
    QUIPC_DBG_HIGH("parse_gen_input_elements: unexpected command: %d\n", (*ppCmd)->cmd);
  }
}

static size_t getFilesize(const char* filename)
{
  struct stat st = {0};
  if (filename) {
      stat(filename, &st);
      return st.st_size;
  } else {
      return 0;
  }
}
#else
static void
parse_cfg_info(xmlNode *a_node, t_lowi_test_cmd **const ppCmd)
{
  xmlNode *cur_node = NULL;
  xmlNode *cur_elm_node = NULL;
  vector <LOWIModuleInfo> vec;
  LOWIModuleInfo lowimoduleinfo;
  (*ppCmd)->lowiconfigrequest = new LOWIConfigRequest(0, LOWIConfigRequest::LOG_CONFIG);
  if ((*ppCmd)->lowiconfigrequest == NULL)
  {
    QUIPC_DBG_HIGH("%s:Null Log Config request", __FUNCTION__);
    return;
  }

  for (cur_node = a_node; cur_node; cur_node = cur_node->next)
  {
    if (cur_node->type == XML_ELEMENT_NODE &&
        xmlStrncmp(cur_node->name, XML_NODE_CONFIG_GLOBAL_LOG_LEVEL,
                   xmlStrlen(XML_NODE_CONFIG_GLOBAL_LOG_LEVEL)) == 0)
    {
      int level = -1;
      int status = parse_int_element(cur_node, level, XML_NODE_CONFIG_GLOBAL_LOG_LEVEL);
      if (status != 0)
      {
        continue;
      }
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogLevel = level;
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogFlag = true;
    }

    if (cur_node->type == XML_ELEMENT_NODE &&
        xmlStrncmp(cur_node->name, XML_NODE_CONFIG_LOG_INFO,
                   xmlStrlen(XML_NODE_CONFIG_LOG_INFO)) == 0)
    {
      for (cur_elm_node = cur_node->children; cur_elm_node; cur_elm_node = cur_elm_node->next)
      {
        if (cur_elm_node->type == XML_ELEMENT_NODE &&
            xmlStrncmp(cur_elm_node->name, XML_NODE_CONFIG_LOG_MODULE_ID,
                       xmlStrlen(XML_NODE_CONFIG_LOG_MODULE_ID)) == 0 &&
            xmlStrncmp(cur_elm_node->next->next->name, XML_NODE_CONFIG_LOG_LEVEL,
                       xmlStrlen(XML_NODE_CONFIG_LOG_LEVEL)) == 0)
        {
          int id = -1;
          int level = -1;
          int status = parse_int_element(cur_elm_node, id, XML_NODE_CONFIG_LOG_MODULE_ID);
          if (status != 0)
          {
            continue;
          }
          status = parse_int_element(cur_elm_node->next->next, level, XML_NODE_CONFIG_LOG_LEVEL);
          if (status != 0)
          {
            continue;
          }
          lowimoduleinfo.moduleid = (eModuleId)id;
          lowimoduleinfo.log_level = level;
          vec.push_back(lowimoduleinfo);
        }
      }
    }
  }
  mapModuleIdtoTag (vec, ppCmd);
}

static int parse_chan_element(xmlNode * a_node)
{
  int ch = 0; // 0 is an invalid channel
  if (NULL == a_node)
  {
    QUIPC_DBG_HIGH("%s:Null input node: %p",
                   __FUNCTION__, a_node);
    return ch;
  }
  xmlNode *cur_node = a_node->children;
  LOWIDiscoveryScanRequest::eBand eband = LOWIDiscoveryScanRequest::BAND_ALL;
  for (; cur_node != NULL; cur_node = cur_node->next)
  {
    if (xmlStrcmp(cur_node->name, XML_NODE_CH) == 0)
    {
      parse_int_element(cur_node, ch, XML_NODE_CH);
    }
    if (xmlStrcmp(cur_node->name, XML_NODE_BAND) == 0)
    {
      // Only 2G / 5G allowed as a valid band.
      int band = -1;
      int status = parse_int_element(cur_node, band, XML_NODE_BAND);
      if (status != 0)
      {
        // No need to continue
        continue;
      }
      eband = LOWIUtils::to_eBand(band);
    }
  }
  return LOWIUtils::channelBandToFreq((uint32)ch, eband);
}

static void
parse_elements(xmlNode * a_node, t_lowi_test_cmd ** const ppCmd)
{
  xmlNode *cur_node = NULL;
  LOWIPeriodicNodeInfo node;
  node.paramControl = LOWI_NO_PARAMS_FROM_CACHE;

  struct LOWIPostProcessNode process_ap_node;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next)
  {
    if (cur_node->type == XML_ELEMENT_NODE)
    {
      vector<LOWIPeriodicNodeInfo>& rttVector = (*ppCmd)->rttNodes;
      LOWIPeriodicNodeInfo& rttNode = rttVector.getNumOfElements() ?
                                      rttVector[rttVector.getNumOfElements()-1] :
                                      node;

      vector <LOWIPostProcessNode >& node_cache_vector = (*ppCmd)->post_process_info.node_cache;
      struct LOWIPostProcessNode& node_cache = node_cache_vector.getNumOfElements() ?
                                     node_cache_vector[node_cache_vector.getNumOfElements() - 1] :
                                     process_ap_node;

      QUIPC_DBG_HIGH("parse_elements: Element, name: %s\n", cur_node->name);
      if ((xmlStrncmp (cur_node->name, XML_NODE_AP, xmlStrlen(XML_NODE_AP)) == 0) &&
          (xmlStrncmp (cur_node->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
      {
        rttVector.push_back(node);
        QUIPC_DBG_HIGH("Adding into lowi_cmd node cache");
        node_cache_vector.push_back(node_cache);
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_REPORTTYPE,
                      xmlStrlen(XML_NODE_REPORTTYPE)) == 0)
      {
        int reportType;
        int status = parse_int_element(cur_node, reportType, XML_NODE_REPORTTYPE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          (*ppCmd)->reportType = (uint32)reportType;
        }
        QUIPC_DBG_HIGH("parse_elements: Element, value: %d \n", reportType);
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_MAC, xmlStrlen(XML_NODE_MAC)) == 0)
      {
        const char *payloadData = (const char *)xmlNodeGetContent(cur_node);
        QUIPC_DBG_HIGH("parse_elements: Element, value: %s\n",
            payloadData);
        if (NULL != payloadData)
        {
          uint8 bssid[BSSID_LEN];
          memset(bssid, 0, sizeof(bssid));
          int status = sscanf(payloadData, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                              &bssid[0], &bssid[1], &bssid[2],
                              &bssid[3], &bssid[4], &bssid[5]);
          if (status < 6)
          {
            // Either the element does not contain the content or it is
            // not formatted correctly. Set all the entries to 0
            QUIPC_DBG_ERROR("parse_elements: Element,"
                " value is not formed correctly %d\n", status);
          }
          else if (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                          xmlStrlen(XML_NODE_RANGING)) == 0)
          {
            rttNode.bssid.setMac(bssid);
            node_cache.bssid.setMac(bssid);
            QUIPC_DBG_HIGH("%s: ftmParams: 0x%x, numFrames: %u\n", __FUNCTION__,
                           rttNode.ftmRangingParameters, rttNode.num_pkts_per_meas);
          }
          else if (xmlStrncmp (cur_node->parent->name, XML_NODE_SUMMARY,
                               xmlStrlen(XML_NODE_SUMMARY)) == 0)
          {
            LOWIMacAddress mac (bssid);
            (*ppCmd)->summary_aps.push_back(mac);
          }//else if
          else if (xmlStrncmp (cur_node->parent->name, XML_NODE_DISCOVERY,
                               xmlStrlen(XML_NODE_DISCOVERY)) == 0)
          {
            LOWIMacAddress mac (bssid);
            (*ppCmd)->discoveryBssids.push_back (mac);
          }//else if
        } //payloadData != NULL
      } //XML_NODE_MAC

      // Check SSID node
      if (xmlStrncmp (cur_node->name, XML_NODE_SSID,
                      xmlStrlen(XML_NODE_SSID)) == 0)
      {
        char ss [SSID_LEN+1] = {0};
        int len = SSID_LEN+1;
        int status = parse_string_element(cur_node, ss, len, XML_NODE_SSID);
        if (status != 0)
        {
          // No need to continue
          continue;
        }
        if (0 != len)
        {
          LOWISsid ssid;
          ssid.setSSID((unsigned char*)ss, len);
          (*ppCmd)->discoverySsids.push_back (ssid);
        }
      }

      if ((xmlStrcmp (cur_node->name, XML_NODE_CHAN) == 0) &&
          (xmlStrcmp(cur_node->parent->name, XML_NODE_DISCOVERY)) == 0)
      {
        int freq = parse_chan_element(cur_node);
        LOWIChannelInfo chInfo(freq);
        (*ppCmd)->chList.push_back(chInfo);
        continue; // Don't parse the current node's children
      }
      if ((xmlStrcmp(cur_node->name, XML_NODE_CH) == 0) &&
          (xmlStrcmp(cur_node->parent->parent->name, XML_NODE_RANGING) == 0) &&
          (rttNode.frequency == 0))
      {
        // CH element is only used if frequency is not set.
        int ch = -1;
        int status = parse_int_element(cur_node, ch, XML_NODE_CH);
        if (status != 0)
        {
          continue;
        }
        rttNode.frequency = LOWIUtils::channelBandToFreq(ch);
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_TRUE_DISTANCE,
                      xmlStrlen(XML_NODE_TRUE_DISTANCE)) == 0)
      {
        int trueDist = -1;
        int status = parse_int_element(cur_node, trueDist, XML_NODE_TRUE_DISTANCE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          node_cache.true_dist = trueDist;
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_2P4_DELAY_PS,
                      xmlStrlen(XML_NODE_2P4_DELAY_PS)) == 0)
      {
        int delay_ps_2p4 = 0;
        int status = parse_int_element(cur_node, delay_ps_2p4, XML_NODE_2P4_DELAY_PS);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          node_cache.delay_ps_2p4 = delay_ps_2p4;
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_5G_DELAY_PS,
                      xmlStrlen(XML_NODE_5G_DELAY_PS)) == 0)
      {
        int delay_ps_5g = 0;
        int status = parse_int_element(cur_node, delay_ps_5g, XML_NODE_5G_DELAY_PS);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          node_cache.delay_ps_5g = delay_ps_5g;
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_SKIP_FIRT_MEAS,
                      xmlStrlen(XML_NODE_SKIP_FIRT_MEAS)) == 0)
      {
        int skipFirst = 0;
        int status = parse_int_element(cur_node, skipFirst, XML_NODE_SKIP_FIRT_MEAS);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          node_cache.skip_first = skipFirst;
          QUIPC_DBG_HIGH("%s: Skip first mesurements: %d \n", __FUNCTION__,
                          skipFirst);
        }
      }
      if (xmlStrcmp (cur_node->name, XML_NODE_FREQUENCY) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_FREQUENCY);
        if (status != 0)
        {
          continue;
        }
        if (xmlStrncmp (cur_node->parent->parent->name,
                        XML_NODE_RANGING, xmlStrlen(XML_NODE_RANGING)) == 0)
        {
          rttNode.frequency = freq;
        }
        else if (xmlStrcmp(cur_node->parent->name, XML_NODE_DISCOVERY) == 0)
        {
          if (LOWIUtils::freqToChannel(freq) != 0) // Frequency is valid
          {
            vector<LOWIChannelInfo>& chVector = (*ppCmd)->chList;
            LOWIChannelInfo chInfo(freq);
            chVector.push_back(chInfo);
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_BAND_CENTER_FREQ1,
                      xmlStrlen(XML_NODE_BAND_CENTER_FREQ1)) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_BAND_CENTER_FREQ1);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.band_center_freq1 = freq;
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_BAND_CENTER_FREQ2,
                      xmlStrlen(XML_NODE_BAND_CENTER_FREQ2)) == 0)
      {
        int freq = -1;
        int status = parse_int_element(cur_node, freq, XML_NODE_BAND_CENTER_FREQ2);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.band_center_freq2 = freq;
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_RTT_TYPE,
                      xmlStrlen(XML_NODE_RTT_TYPE)) == 0)
      {
        int rttChoice = -1;
        int status = parse_int_element(cur_node, rttChoice, XML_NODE_RTT_TYPE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttChoice -= 1; // xml file value & lowi value don't match. make adjustment here.
          rttNode.rttType = LOWIUtils::to_eRttType(rttChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_NUM_FRAMES_PER_BURST,
                      xmlStrlen(XML_NODE_NUM_FRAMES_PER_BURST)) == 0)
      {
        int numFramesPerBurst = -1;
        int status = parse_int_element(cur_node, numFramesPerBurst, XML_NODE_NUM_FRAMES_PER_BURST);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.num_pkts_per_meas = (uint32)numFramesPerBurst;
          node_cache.frame_per_burst = (uint32)numFramesPerBurst;
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_RANGING_TX_BW,
                      xmlStrlen(XML_NODE_RANGING_TX_BW)) == 0)
      {
        int bwChoice = -1;
        int status = parse_int_element(cur_node, bwChoice, XML_NODE_RANGING_TX_BW);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.bandwidth = LOWIUtils::to_eRangingBandwidth(bwChoice);
          node_cache.req_tx_bw = LOWIUtils::to_eRangingBandwidth(bwChoice);
          node_cache.req_rx_bw = LOWIUtils::to_eRangingBandwidth(bwChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_RANGING_RX_BW,
                      xmlStrlen(XML_NODE_RANGING_RX_BW)) == 0)
      {
        int rxbwChoice = -1;
        int status = parse_int_element(cur_node, rxbwChoice, XML_NODE_RANGING_RX_BW);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          node_cache.req_rx_bw = LOWIUtils::to_eRangingBandwidth(rxbwChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_RANGING_PREAMBLE,
                      xmlStrlen(XML_NODE_RANGING_PREAMBLE)) == 0)
      {
        int preamble = -1;
        int status = parse_int_element(cur_node, preamble, XML_NODE_RANGING_PREAMBLE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.preamble = LOWIUtils::to_eRangingPreamble(preamble);
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_PHYMODE,
                      xmlStrlen(XML_NODE_PHYMODE)) == 0)
      {
        int phymode = -1;
        int status = parse_int_element(cur_node, phymode, XML_NODE_PHYMODE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.phyMode = LOWIUtils::to_eLOWIPhyMode(phymode);
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_PEER_TYPE,
                      xmlStrlen(XML_NODE_PEER_TYPE)) == 0)
      {
        int peerType = -1;
        int status = parse_int_element(cur_node, peerType, XML_NODE_PEER_TYPE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          rttNode.nodeType = LOWIUtils::to_eNodeType(peerType);
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_INTERFACE,
                      xmlStrlen(XML_NODE_INTERFACE)) == 0)
      {
        int len = INTERFACE_MAX_LENGTH;
        char interface[INTERFACE_MAX_LENGTH];

        int status = parse_string_element(cur_node, interface, len,
                                          XML_NODE_INTERFACE);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          (*ppCmd)->interface = interface;
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_ASAP,
                      xmlStrlen(XML_NODE_FTM_RANGING_ASAP)) == 0)
      {
        int asapChoice = -1;
        int status = parse_int_element(cur_node, asapChoice, XML_NODE_FTM_RANGING_ASAP);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (asapChoice == 0)
          {
            FTM_CLEAR_ASAP(rttNode.ftmRangingParameters);
          }
          else if (asapChoice == 1)
          {
            FTM_SET_ASAP(rttNode.ftmRangingParameters);
          }
        }
      }

      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_LCI,
                      xmlStrlen(XML_NODE_FTM_RANGING_LCI)) == 0)
      {
        int lciChoice = -1;
        int status = parse_int_element(cur_node, lciChoice, XML_NODE_FTM_RANGING_LCI);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (lciChoice == 0)
          {
            FTM_CLEAR_LCI_REQ(rttNode.ftmRangingParameters);
          }
          else if (lciChoice == 1)
          {
            FTM_SET_LCI_REQ(rttNode.ftmRangingParameters);
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_LOC_CIVIC,
                      xmlStrlen(XML_NODE_FTM_RANGING_LOC_CIVIC)) == 0)
      {
        int civicChoice = -1;
        int status = parse_int_element(cur_node, civicChoice, XML_NODE_FTM_RANGING_LOC_CIVIC);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (civicChoice == 0)
          {
            FTM_CLEAR_LOC_CIVIC_REQ(rttNode.ftmRangingParameters);
          }
          else if (civicChoice == 1)
          {
            FTM_SET_LOC_CIVIC_REQ(rttNode.ftmRangingParameters);
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XLM_NODE_FTM_PTSF_TIMER_NO_PREF,
                      xmlStrlen(XLM_NODE_FTM_PTSF_TIMER_NO_PREF)) == 0)
      {
        int ptsfChoice = -1;
        int status = parse_int_element(cur_node, ptsfChoice, XLM_NODE_FTM_PTSF_TIMER_NO_PREF);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (ptsfChoice == 0)
          {
            FTM_CLEAR_PTSF_TIMER_NO_PREF(rttNode.ftmRangingParameters);
          }
          else if (ptsfChoice == 1)
          {
            FTM_SET_PTSF_TIMER_NO_PREF(rttNode.ftmRangingParameters);
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_NUM_BURSTS_EXP,
                      xmlStrlen(XML_NODE_FTM_RANGING_NUM_BURSTS_EXP)) == 0)
      {
        int burstExpChoice = -1;
        int status = parse_int_element(cur_node, burstExpChoice,
                                       XML_NODE_FTM_RANGING_NUM_BURSTS_EXP);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          FTM_SET_BURSTS_EXP(rttNode.ftmRangingParameters, (uint32)burstExpChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_BURST_DURATION,
                      xmlStrlen(XML_NODE_FTM_RANGING_BURST_DURATION)) == 0)
      {
        int burstDurChoice = -1;
        int status = parse_int_element(cur_node, burstDurChoice,
                                       XML_NODE_FTM_RANGING_BURST_DURATION);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          FTM_SET_BURST_DUR(rttNode.ftmRangingParameters, (uint32)burstDurChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_RANGING_BURST_PERIOD,
                      xmlStrlen(XML_NODE_FTM_RANGING_BURST_PERIOD)) == 0)
      {
        int burstPerChoice = -1;
        int status = parse_int_element(cur_node, burstPerChoice,
                                       XML_NODE_FTM_RANGING_BURST_PERIOD);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          FTM_SET_BURST_PERIOD(rttNode.ftmRangingParameters, (uint32)burstPerChoice);
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_USE_LEG_ACK_ONLY,
                      xmlStrlen(XML_NODE_FTM_USE_LEG_ACK_ONLY)) == 0)
      {
        int forceLegAck = 0;
        int status = parse_int_element(cur_node, forceLegAck,
                                       XML_NODE_FTM_USE_LEG_ACK_ONLY);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (((*ppCmd)->forceLegAck == true) || forceLegAck != 0)
          {
            FTM_SET_LEG_ACK_ONLY(rttNode.ftmRangingParameters);
            node_cache.forceLegAck = true;
            /* req_tx_bw should always be zero when forceLegAck is enabled */
            node_cache.req_tx_bw = BW_20MHZ;
          }
          else
          {
            FTM_CLEAR_LEG_ACK_ONLY(rttNode.ftmRangingParameters);
            node_cache.forceLegAck = false;
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_FORCE_QCA_PEER,
                      xmlStrlen(XML_NODE_FTM_FORCE_QCA_PEER)) == 0)
      {
        int forceQcaPeer = 0;
        int status = parse_int_element(cur_node, forceQcaPeer,
                                       XML_NODE_FTM_FORCE_QCA_PEER);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (forceQcaPeer == 0)
          {
            FTM_CLEAR_QCA_PEER(rttNode.ftmRangingParameters);
          }
          else
          {
            FTM_SET_QCA_PEER(rttNode.ftmRangingParameters);
          }
        }
      }
      if (xmlStrncmp (cur_node->name, XML_NODE_FTM_PARAM_CONTROL,
                      xmlStrlen(XML_NODE_FTM_PARAM_CONTROL)) == 0)
      {
        int paramControl = -1;
        int status = parse_int_element(cur_node, paramControl,
                                       XML_NODE_FTM_PARAM_CONTROL);
        if ((status == 0) &&
            (xmlStrncmp (cur_node->parent->parent->name, XML_NODE_RANGING,
                        xmlStrlen(XML_NODE_RANGING)) == 0))
        {
          if (paramControl == 0)
          {
            rttNode.paramControl = LOWI_USE_PARAMS_FROM_CACHE;
          }
          else
          {
            rttNode.paramControl = LOWI_NO_PARAMS_FROM_CACHE;
          }
        }
      }

    }
    parse_elements(cur_node->children, ppCmd);
  }

} // parse_elements

static void
parse_gen_input_elements(xmlNode *a_node, t_lowi_test_cmd **const ppCmd)
{

  xmlNode *cur_node = NULL;
  switch ((*ppCmd)->cmd)
  {
  case LOWI_SET_LCI:
    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
      if (cur_node->type == XML_ELEMENT_NODE)
      {
        if (xmlStrncmp(cur_node->name, XML_NODE_LCI,
                       xmlStrlen(XML_NODE_LCI)) == 0)
        {
          parse_lci_info(cur_node->children, ppCmd);
          break;
        }
        if (xmlStrncmp (cur_node->name, XML_NODE_INTERFACE,
                        xmlStrlen(XML_NODE_INTERFACE)) == 0)
        {
          int len = INTERFACE_MAX_LENGTH;
          char interface[INTERFACE_MAX_LENGTH];

          int status = parse_string_element(cur_node, interface, len,
                                            XML_NODE_INTERFACE);
          if (status == 0)
          {
            (*ppCmd)->interface = interface;
          }
        }
      }
      parse_gen_input_elements(cur_node->children, ppCmd);
    }
    break;
  case LOWI_SET_LCR:
    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
      if (cur_node->type == XML_ELEMENT_NODE)
      {
        if (xmlStrncmp(cur_node->name, XML_NODE_LCR,
                       xmlStrlen(XML_NODE_LCR)) == 0)
        {
          parse_lcr_info(cur_node->children, ppCmd);
          break;
        }
        if (xmlStrncmp (cur_node->name, XML_NODE_INTERFACE,
                        xmlStrlen(XML_NODE_INTERFACE)) == 0)
        {
          int len = INTERFACE_MAX_LENGTH;
          char interface[INTERFACE_MAX_LENGTH];

          int status = parse_string_element(cur_node, interface, len,
                                            XML_NODE_INTERFACE);
          if (status == 0)
          {
            (*ppCmd)->interface = interface;
          }
        }
      }
      parse_gen_input_elements(cur_node->children, ppCmd);
    }
    break;
  case LOWI_FTMR_REQ:
    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
      if (cur_node->type == XML_ELEMENT_NODE)
      {
        if (xmlStrncmp(cur_node->name, XML_NODE_FTMRR,
                       xmlStrlen(XML_NODE_FTMRR)) == 0)
        {
          parse_ftmrr_info(cur_node->children, ppCmd);
          break;
        }
      }
      parse_gen_input_elements(cur_node->children, ppCmd);
    }
    break;
  case LOWI_CONFIG_REQ:
    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
      if (((cur_node->type == XML_ELEMENT_NODE)) &&
          ((xmlStrncmp (cur_node->name, XML_NODE_CONFIG_LOG, xmlStrlen(XML_NODE_CONFIG_LOG)) == 0) &&
           (xmlStrncmp (cur_node->parent->name, XML_NODE_CONFIG, xmlStrlen(XML_NODE_CONFIG)) == 0)))
      {
        parse_cfg_info(cur_node->children, ppCmd);
        break;
      }
      parse_gen_input_elements(cur_node->children, ppCmd);
    }
    break;
  default:
    QUIPC_DBG_HIGH("parse_gen_input_elements: unexpected command: %d\n", (*ppCmd)->cmd);
  }
}
#endif

#if CONFIG_SUPPORT_LIBROXML
/*=============================================================================
 * lowi_read_ap_list
 *
 * Description:
 *   Read the AP list for scan/stats parameters
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_read_ap_list(const char * const ap_list,  t_lowi_test_cmd ** const ppCmd)
{
  size_t filesize = 0;
  char *mmappedData = NULL;
  int fd = -1;
  node_t *doc_ptr, *root;

  if ((ppCmd == NULL) || ((*ppCmd) == NULL))
  {
    fprintf(stderr, "Null Pointer ppCmd = %p\n",
            (void *)ppCmd);
    return;
  }

  if ((ap_list == NULL) || (strlen(ap_list) == 0))
  {
    /* Empty AP List. Use discovery Scan to create list if needed. */
    return;
  }

  filesize = getFilesize(ap_list);
  if (!filesize)
      return;

  fd = open(ap_list, O_RDONLY, 0);

  // Get root node of xml doc
  mmappedData = (char *)mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
  doc_ptr = roxml_load_buf(mmappedData);

  if (!doc_ptr) {
      fprintf(stderr, "%s:%d: Invalid argument", __func__, __LINE__);
      return;
  }

  // We expect the  file format to be
  /*
    <ranging>
      <ap>
       <band>1</band>
       <ch>11</ch>
       <rttType>2</rttType>
       <bw>0</bw>
       <mac>a0:b2:c3:d4:e5:f6</ap>
      </ap>
      <ap>
       <band>2</band>
       <ch>165</ch>
       <rttType>3</rttType>
       <bw>2</bw>
       <mac>a1:b3:c4:d5:e6:f7</ap>
      </ap>
    </ranging>
    <discovery>
      <chan>
       <band>1</band>
       <ch>11</ch>
      </chan>
      <chan>
       <band>2</band>
       <ch>165</ch>
      </chan>
    </discovery>
    <summary>
      <mac>a1:b3:c4:d5:e6:f7</mac>
      <mac>a0:b2:c3:d4:e5:f6</mac>
    </summary>
    <lcr_info>
      <country_code>US</country_code>
      <civic_address>Carol Lane</civic_address>
    </lcr_info>
    <lci_info>
      <latitude>37.3740</latitude>
      <longitude>-121.9960</longitude>
      <altitude>7</altitude>
      <latitude_unc>61.8212</latitude_unc>
      <longitude_unc>61.9912</longitude_unc>
      <altitude_unc>59.9624</altitude_unc>
      <motion_pattern>0</motion_pattern>
      <floor>3</floor>
      <height_above_floor>2</height_above_floor>
      <height_unc>77</height_unc>
    </lci_info>
    <ftmrr>
      <element>
        <bssid></bssid>
        <info_bssid></info_bssid>
        <phy_type></phy_type>
        <op_class></op_class>
        <ch></ch>
        <center_ch1></center_ch1>
        <center_ch2></center_ch2>
        <width_ch></width_ch>
      </element>
    </ftmrr>
  */

  root = roxml_get_chld(doc_ptr, NULL, 0);

  if (((*ppCmd)->cmd == LOWI_SET_LCI   ) ||
      ((*ppCmd)->cmd == LOWI_SET_LCR   ) ||
      ((*ppCmd)->cmd == LOWI_FTMR_REQ  ) ||
      ((*ppCmd)->cmd == LOWI_CONFIG_REQ) )
  {
      parse_gen_input_elements (root, ppCmd);
  }
  else
  {
      parse_elements(root, ppCmd);
  }

  roxml_close(doc_ptr);
  munmap(mmappedData, filesize);
  close(fd);
  QUIPC_DBG_HIGH("Found %d APs in the input file\n", (*ppCmd)->rttNodes.getNumOfElements());
  return;
}
#else
/*=============================================================================
 * lowi_read_ap_list
 *
 * Description:
 *   Read the AP list for scan/stats parameters
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_read_ap_list(const char * const ap_list,  t_lowi_test_cmd ** const ppCmd)
{
  if ((ppCmd == NULL) || ((*ppCmd) == NULL))
  {
    fprintf(stderr, "Null Pointer ppCmd = %p\n",
            (void *)ppCmd);
    return;
  }

  if ((ap_list == NULL) || (strlen(ap_list) == 0))
  {
    /* Empty AP List. Use discovery Scan to create list if needed. */
    return;
  }

  // Open the xml file
  FILE *xmlFile = fopen(ap_list, "rb");
  if (xmlFile == NULL)
  {
    fprintf(stderr, "%s:%d: Error opening file %s: %s\n",
            __func__,__LINE__, ap_list, strerror(errno));
    xmlFile = fopen(DEFAULT_AP_LIST_FILE, "r");
    if (xmlFile == NULL)
    {
      fprintf(stderr, "%s:%d: Use Discovery Scan. Error opening file %s: %s\n",
              __func__,__LINE__, ap_list, strerror(errno));
    }
  }
  else
  {
    // File opened. Read it
    fseek(xmlFile, 0, SEEK_END);
    int xmlSize = (int)ftell(xmlFile);
    fseek(xmlFile, 0, SEEK_SET);

    char* buffer = new char[xmlSize];
    if (NULL == buffer)
    {
      fprintf(stderr, "Unable to allocate memory for provided xml size = %x\n",
              xmlSize);
      return;
    }
    fread(buffer, xmlSize, 1, xmlFile);
    fclose(xmlFile);

    // We expect the  file format to be
/*
  <ranging>
    <ap>
     <band>1</band>
     <ch>11</ch>
     <rttType>2</rttType>
     <bw>0</bw>
     <mac>a0:b2:c3:d4:e5:f6</ap>
    </ap>
    <ap>
     <band>2</band>
     <ch>165</ch>
     <rttType>3</rttType>
     <bw>2</bw>
     <mac>a1:b3:c4:d5:e6:f7</ap>
    </ap>
  </ranging>
  <discovery>
    <chan>
     <band>1</band>
     <ch>11</ch>
    </chan>
    <chan>
     <band>2</band>
     <ch>165</ch>
    </chan>
  </discovery>
  <summary>
    <mac>a1:b3:c4:d5:e6:f7</mac>
    <mac>a0:b2:c3:d4:e5:f6</mac>
  </summary>
  <lcr_info>
    <country_code>US</country_code>
    <civic_address>Carol Lane</civic_address>
  </lcr_info>
  <lci_info>
    <latitude>37.3740</latitude>
    <longitude>-121.9960</longitude>
    <altitude>7</altitude>
    <latitude_unc>61.8212</latitude_unc>
    <longitude_unc>61.9912</longitude_unc>
    <altitude_unc>59.9624</altitude_unc>
    <motion_pattern>0</motion_pattern>
    <floor>3</floor>
    <height_above_floor>2</height_above_floor>
    <height_unc>77</height_unc>
  </lci_info>
  <ftmrr>
    <element>
      <bssid></bssid>
      <info_bssid></info_bssid>
      <phy_type></phy_type>
      <op_class></op_class>
      <ch></ch>
      <center_ch1></center_ch1>
      <center_ch2></center_ch2>
      <width_ch></width_ch>
    </element>
  </ftmrr>
*/
    xmlDoc *doc = xmlParseMemory(buffer, xmlSize);
    xmlNode *root_element = xmlDocGetRootElement(doc);

    if (((*ppCmd)->cmd == LOWI_SET_LCI   ) ||
        ((*ppCmd)->cmd == LOWI_SET_LCR   ) ||
        ((*ppCmd)->cmd == LOWI_FTMR_REQ  ) ||
        ((*ppCmd)->cmd == LOWI_CONFIG_REQ) )
    {
      parse_gen_input_elements (root_element, ppCmd);
    }
    else
    {
      parse_elements(root_element, ppCmd);
    }

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    // Free the buffer
    delete [] buffer;
  }
  QUIPC_DBG_HIGH("Found %d APs in the input file\n", (*ppCmd)->rttNodes.getNumOfElements());
  return;
}
#endif

#if 0
/*=============================================================================
 * lowi_read_gen_input_file
 *
 * Description:
 *   Read the AP list for scan/stats parameters
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_read_gen_input_file(const char *const gen_input_file_name,
                                     t_lowi_test_cmd **const ppCmd)
{
  if ((ppCmd == NULL) || ((*ppCmd) == NULL))
  {
    fprintf(stderr, "Null Pointer ppCmd = %p\n",
            (void *)ppCmd);
    return;
  }

  if ((gen_input_file_name == NULL) || (strlen(gen_input_file_name) == 0))
  {
    /* Empty AP List. Use discovery Scan to create list if needed. */
    return;
  }

  // Open the xml file
  FILE *xmlFile = fopen(gen_input_file_name, "rb");
  if (xmlFile == NULL)
  {
    fprintf(stderr, "%s:%d: Error opening file %s: %s\n",
            __func__, __LINE__, gen_input_file_name, strerror(errno));
    xmlFile = fopen(DEFAULT_AP_LIST_FILE, "r");
    if (xmlFile == NULL)
    {
      fprintf(stderr, "%s:%d: Error opening file %s: %s\n",
              __func__, __LINE__, DEFAULT_AP_LIST_FILE, strerror(errno));
    }
  }
  else
  {
    // File opened. Read it
    fseek(xmlFile, 0, SEEK_END);
    int xmlSize = (int)ftell(xmlFile);
    fseek(xmlFile, 0, SEEK_SET);
    char* buffer = new char[xmlSize];
    if (NULL == buffer)
    {
      fprintf(stderr, "Unable to allocate memory for provided xml size = %x\n",
              xmlSize);
      return;
    }
    fread(buffer, xmlSize, 1, xmlFile);
    fclose(xmlFile);

    // We expect the  file format to be
    // refer to ap_list file for ranging and discovery requests
/*
  <lcr_info>
    <country_code>US</country_code>
    <civic_address>Carol Lane</civic_address>
  </lcr_info>
  <lci_info>
    <latitude>37.3740</latitude>
    <longitude>-121.9960</longitude>
    <altitude>7</altitude>
    <latitude_unc>61.8212</latitude_unc>
    <longitude_unc>61.9912</longitude_unc>
    <altitude_unc>59.9624</altitude_unc>
    <motion_pattern>0</motion_pattern>
    <floor>3</floor>
    <height_above_floor>2</height_above_floor>
    <height_unc>77</height_unc>
  </lci_info>
  <ftmrr>
    <element>
      <bssid></bssid>
      <info_bssid></info_bssid>
      <phy_type></phy_type>
      <op_class></op_class>
      <ch></ch>
      <center_ch1></center_ch1>
      <center_ch2></center_ch2>
      <width_ch></width_ch>
    </element>
  </ftmrr>
*/
    xmlDoc *doc = xmlParseMemory(buffer, xmlSize);
    xmlNode *root_element = xmlDocGetRootElement(doc);

    parse_gen_input_elements(root_element, ppCmd);
    QUIPC_DBG_HIGH("parse elements completed\n");

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    // Free the buffer
    delete [] buffer;
  }
  return;
}
#endif

/*=============================================================================
 * usage
 *
 * Description:
 *   Prints usage information for lowi_test
 *
 * Return value:
 *   void
 ============================================================================*/
static void usage(char * cmd)
{
  fprintf(stderr, "Usage: %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", cmd,
        "[-o output_file]",
        "[-s summary_file]",
        "[-n number of Scans]", "[-d delay between scans]",
        "[-p -r -f -pr -r3 -pr3 -a -ar -ar3 ap_list|ap_file]",
        "[-b band for discovery scan 0 - 2.4Ghz, 1 - 5Ghz, 2 - All]",
        "[-bw bandwidth for ranging scan 0 - 20Mhz, 1 - 40 Mhz, 2 - 80 Mhz, 3 - 160 Mhz]",
        "[-mf measurement age filter for discovery scan 0 sec - 180 sec]",
        "[-ft fallback tolerance for discovery scan 0 sec - 180 sec]",
        "[-c (C)onfig request for logging loginfo_file]",
        "[-l logLevel - set the global log level]",
        "[-t request timeout in seconds 0 - 86400]",
        "[-k send a kill request to lowi-server]");
}

/*=============================================================================
 * lowi_parse_args
 *
 * Description:
 *   Parse the arguments into LOWI test command
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_parse_args(const int argc, char * argv[],
                            t_lowi_test_cmd ** ppCmd)
{
  int i;
  char *ap_list = NULL;
  char *gen_input_file_name = NULL;

  *ppCmd = new t_lowi_test_cmd;
  if (NULL == *ppCmd)
  {
    return;
  }

  for (i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-o") == 0)
    {
      /* -o followed by file name */
      lowi_test.out_fp = fopen(argv[++i], "w");
      if (lowi_test.out_fp == NULL)
      {
        fprintf(stderr, "%s:%s:%d: Error opening file %s: %s\n",
              argv[0], __func__,__LINE__, argv[i], strerror(errno));
      }
    }
    else if (strcmp(argv[i], "-s") == 0)
    {
      /* -s followed by file name */
      lowi_test.summary_fp = fopen(argv[++i], "w");
      if (lowi_test.summary_fp == NULL)
      {
        fprintf(stderr, "%s:%s:%d: Error opening file %s: %s\n",
              argv[0], __func__,__LINE__, argv[i], strerror(errno));
      }
    }
    else if (strcmp(argv[i], "-cfr") == 0)
    {
      /* -cfr followed by file name */
      lowi_test.out_cfr_fp = fopen(argv[++i], "w");
      if (lowi_test.out_cfr_fp == NULL)
      {
        fprintf(stderr, "%s:%s:%d: Error opening file %s: %s\n",
              argv[0], __func__,__LINE__, argv[i], strerror(errno));
      }
    }
    else if ((strcmp(argv[i], "-start") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_START_RESP_MEAS;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-stop") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_STOP_RESP_MEAS;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-ba") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_BATCHING;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-f") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_ASYNC_DISCOVERY_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-p") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_DISCOVERY_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-a") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_DISCOVERY_SCAN;
      (*ppCmd)->scan_type = LOWIDiscoveryScanRequest::ACTIVE_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-r") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_RTS_CTS_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      (*ppCmd)->need_post_processing = TRUE;
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-r3") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_RTS_CTS_SCAN;
      (*ppCmd)->rttType = RTT3_RANGING;  // Set Ranging to RTT V3
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      (*ppCmd)->need_post_processing = TRUE;
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-pr") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_BOTH_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-pr3") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_BOTH_SCAN;
      (*ppCmd)->rttType = RTT3_RANGING;  // Set Ranging to RTT V3
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-ar") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_BOTH_SCAN;
      (*ppCmd)->scan_type = LOWIDiscoveryScanRequest::ACTIVE_SCAN;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-ar3") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_BOTH_SCAN;
      (*ppCmd)->scan_type = LOWIDiscoveryScanRequest::ACTIVE_SCAN;
      (*ppCmd)->rttType = RTT3_RANGING;  // Set Ranging to RTT V3
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-ut") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_UART_TEST_REQ;
      ap_list = ( ( i < argc - 1 && argv[i+1][0] != '-') ?
                  argv[++i] : NULL );
      lowi_read_ap_list(ap_list, ppCmd);
    }
    else if ((strcmp(argv[i], "-anqp") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_ANQP_REQ;
    }
    else if ((strcmp(argv[i], "-nrr") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_NR_REQ;
    }
    else if ((strcmp(argv[i], "-wsq") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_WSQ_REQ;
    }
    else if ((strcmp(argv[i], "-lci") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_SET_LCI;
      gen_input_file_name = ((i < argc - 1 && argv[i + 1][0] != '-') ?
                             argv[++i] : NULL);
      lowi_read_ap_list(gen_input_file_name, ppCmd);
    }
    else if ((strcmp(argv[i], "-lcr") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_SET_LCR;
      gen_input_file_name = ((i < argc - 1 && argv[i + 1][0] != '-') ?
                             argv[++i] : NULL);
      lowi_read_ap_list(gen_input_file_name, ppCmd);
    }
    else if ((strcmp(argv[i], "-c") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_CONFIG_REQ;
      gen_input_file_name = ((i < argc - 1 && argv[i + 1][0] != '-') ?
                             argv[++i] : NULL);
      lowi_read_ap_list(gen_input_file_name, ppCmd);
    }
    // sample usage for setting log level to debug(4)
    // "lowi_test -l 4"
    else if ((strcmp(argv[i], "-l") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {

      (*ppCmd)->lowiconfigrequest = new LOWIConfigRequest(0, LOWIConfigRequest::LOG_CONFIG);
      if ((*ppCmd)->lowiconfigrequest == NULL)
      {
        QUIPC_DBG_HIGH("%s:Null Log Config request", __FUNCTION__);
        return;
      }
      char* loglevel = (((i < argc - 1) && (argv[i + 1][0] != '-')) ?
                        argv[++i] : NULL);

      if (loglevel == NULL)
      {
        QUIPC_DBG_HIGH("%s:No argument passed, don't send the request", __FUNCTION__);
        return;
      }
      (*ppCmd)->cmd = LOWI_CONFIG_REQ;
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogLevel = atoi(loglevel);
      (*ppCmd)->lowiconfigrequest->mLowiGlobalLogFlag = true;
    }
    else if ((strcmp(argv[i], "-k") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {

      (*ppCmd)->lowiconfigrequest = new LOWIConfigRequest(0, LOWIConfigRequest::LOWI_EXIT);
      if ((*ppCmd)->lowiconfigrequest == NULL)
      {
        QUIPC_DBG_HIGH("%s:Null Log Config request", __FUNCTION__);
        return;
      }
      (*ppCmd)->cmd = LOWI_CONFIG_REQ;
    }
    else if ((strcmp(argv[i], "-w") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_WRU_REQ;
      int retVal = 0;
      i++;
      if (i < argc)
      {
        uint8  bssid[BSSID_LEN]; //BSSID of the AP to be measured
        retVal = sscanf(argv[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0],
                        &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
        QUIPC_DBG_HIGH("%s - MAC Address from user: %s, macAddr-parsed: " LOWI_MACADDR_FMT " status: %d",
                       __FUNCTION__, argv[i], LOWI_MACADDR(bssid), retVal);
        LowiTestApInfo apInfo(bssid, 0);
        (*ppCmd)->ap_info.push_back(apInfo);
      }
      else
      {
        QUIPC_DBG_HIGH("%s: -w flag provided with no mac address",
               __FUNCTION__);
      }
    }
    else if ((strcmp(argv[i], "-ftmrr") == 0) &&
             ((*ppCmd)->cmd == LOWI_MAX_SCAN))
    {
      (*ppCmd)->cmd = LOWI_FTMR_REQ;
      int retVal = 0;
      if ((i + 3) > argc)
      {
        QUIPC_DBG_HIGH("-ftmrr flag provided with wrong arguments list args-expected %d given %d\n",
               i+4, argc);
      }
      else
      {
        uint8  bssid[BSSID_LEN]; //BSSID of the AP to be measured
        retVal = sscanf(argv[++i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0],
                        &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
        QUIPC_DBG_HIGH("%s - MAC Address from user: %s, macAddr-parsed: " LOWI_MACADDR_FMT " status: %d",
                       __FUNCTION__, argv[i], LOWI_MACADDR(bssid), retVal);
        LowiTestApInfo apInfo(bssid, 0);
        (*ppCmd)->ap_info.push_back(apInfo);

        retVal = sscanf(argv[++i], "%hu", &(*ppCmd)->rand_inter);
        gen_input_file_name = ((i < argc - 1 && argv[i + 1][0] != '-') ?
                               argv[++i] : NULL);
        QUIPC_DBG_HIGH("%s - input file %s\n", __FUNCTION__, (NULL==gen_input_file_name)? "NULL" : gen_input_file_name);
        lowi_read_ap_list(gen_input_file_name, ppCmd);
      }
    }
    else if (strcmp(argv[i], "-mac") == 0)
    {
      int retVal = 0;
      i++;
      if (i < argc)
      {
        //check for Max APs supported
        if (((*ppCmd)->ap_info.getNumOfElements()) >= MAX_BSSIDS_STATS)
        {
          QUIPC_DBG_ERROR ("no of APs received as command %d"
                           "is higher than allowed value MAX_BSSIDS_STATS",
                           ((*ppCmd)->ap_info.getNumOfElements()));
          return;

        }
        uint8  bssid[BSSID_LEN]; //BSSID of the AP to be measured
        retVal = sscanf(argv[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0],
                        &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
        QUIPC_DBG_HIGH("%s - MAC Address from user: %s, macAddr-parsed: " LOWI_MACADDR_FMT " status: %d",
                       __FUNCTION__, argv[i], LOWI_MACADDR(bssid), retVal);
        LowiTestApInfo apInfo(bssid, 0);
        (*ppCmd)->ap_info.push_back(apInfo);
      }
      else
      {
        QUIPC_DBG_HIGH("%s: -mac flag provided with no mac address",
                       __FUNCTION__);
      }

    }
    else if (strcmp(argv[i], "-n") == 0)
    {
      int numrequested = atoi(argv[++i]);
      (*ppCmd)->num_requests = LOWI_APPLY_LIMITS(numrequested, 1, 30000);
    }
    else if (strcmp(argv[i], "-d") == 0)
    {
      int delay = atoi(argv[++i]);
      (*ppCmd)->delay = LOWI_APPLY_LIMITS(delay, 10, 30000);
    }
    else if (strcmp(argv[i], "-t") == 0)
    {
      // Timeout Seconds
      int timeout = atoi(argv[++i]);
      (*ppCmd)->timeout_offset = LOWI_APPLY_LIMITS(timeout, 0, 86400);
    }
    else if (strcmp(argv[i], "-b") == 0)
    {
      // Band
      int band = atoi(argv[++i]);
      (*ppCmd)->band = LOWIUtils::to_eBand(band);
    }
    else if (strcmp(argv[i], "-rprt") == 0)
    {
      // Report Type cmdline, This has highest preference
      int reportType = atoi(argv[++i]);
      (*ppCmd)->reportType_cmdline = reportType;
    }
    else if (strcmp(argv[i], "-bw") == 0)
    {
      // Bandwidth
      int bw = atoi(argv[++i]);
      (*ppCmd)->ranging_bandwidth = LOWIUtils::to_eRangingBandwidth(bw);
    }
    else if (strcmp(argv[i], "-mf") == 0)
    {
      // Measurement Age filter seconds - applicable to discovery scan only
      int meas_age = atoi(argv[++i]);
      (*ppCmd)->meas_age_filter_sec = LOWI_APPLY_LIMITS(meas_age, 0, 180);
    }
    else if (strcmp(argv[i], "-ft") == 0)
    {
      // Fallback tolerance seconds - applicable to discovery scan only
      int fb_tol = atoi(argv[++i]);
      (*ppCmd)->fallback_tolerance = LOWI_APPLY_LIMITS(fb_tol, 0, 180);
    }
    else if (strcmp(argv[i], "-sb") == 0)
    {
      int fb_tol = atoi(argv[++i]);
      (*ppCmd)->subscribe_batching = LOWI_APPLY_LIMITS(fb_tol, 0, 1);
    }
    else if (strcmp(argv[i], "-td") == 0)
    {
      int true_distance = atoi(argv[++i]);//in cm
      (*ppCmd)->trueDist = LOWI_APPLY_LIMITS(true_distance, 0, 30000);
      QUIPC_DBG_HIGH("*ppCmd)->trueDist %u", (*ppCmd)->trueDist);
    }
    else if (strcmp(argv[i], "-kdm") == 0)
    {
      int kpi_mask = atoi(argv[++i]);//KPI Mask value
      (*ppCmd)->kpi_mask = LOWI_APPLY_LIMITS(kpi_mask, 0, 60000);
      QUIPC_DBG_HIGH("*ppCmd)->kpi_mask %u", (*ppCmd)->kpi_mask);
    }
    else if (strcmp(argv[i], "-kfm") == 0)
    {
      int kpi_fs_mask = atoi(argv[++i]);//Log Mask value
      (*ppCmd)->kpi_fs_mask = LOWI_APPLY_LIMITS(kpi_fs_mask, 0, 255);
      QUIPC_DBG_HIGH("*ppCmd)->kpi_fs_mask %u", (*ppCmd)->kpi_fs_mask);
    }
    else if (strcmp(argv[i], "-2gdelay") == 0)
    {
      int delay_ps_2p4 = atoi(argv[++i]);//in picosec
      (*ppCmd)->delay_ps_2p4 = LOWI_APPLY_LIMITS(delay_ps_2p4, 0, 30000);
      QUIPC_DBG_HIGH("*ppCmd)->delay_ps_2p4 %u", (*ppCmd)->delay_ps_2p4);
    }
    else if (strcmp(argv[i], "-5gdelay") == 0)
    {
      int delay_ps_5g = atoi(argv[++i]);//in picosec
      (*ppCmd)->delay_ps_5g = LOWI_APPLY_LIMITS(delay_ps_5g, 0, 30000);
      QUIPC_DBG_HIGH("*ppCmd)->delay_ps_5g %u", (*ppCmd)->delay_ps_5g);
    }
    else if (strcmp(argv[i], "-legack") == 0)
    {
      int legack = atoi(argv[++i]);
      if(legack)
        (*ppCmd)->forceLegAck = true;
      QUIPC_DBG_HIGH("(*ppCmd)->forceLegAck %u", legack);
    }
    else if (strcmp(argv[i], "-gbw") == 0)
    {
      int req_bw = atoi(argv[++i]);
      (*ppCmd)->req_tx_bw = LOWI_APPLY_LIMITS(req_bw, 0, 5);
      QUIPC_DBG_HIGH("(*ppCmd)->req_tx_bw %u", (*ppCmd)->req_tx_bw);
    }
    else if (strcmp(argv[i], "-grxbw") == 0)
    {
      int req_bw = atoi(argv[++i]);
      (*ppCmd)->req_rx_bw = LOWI_APPLY_LIMITS(req_bw, 0, 5);
      QUIPC_DBG_HIGH("(*ppCmd)->req_rx_bw %u", (*ppCmd)->req_rx_bw);
    }
    else if (strcmp(argv[i], "-skipbw") == 0)
    {
      (*ppCmd)->skip_bw_check = true;
      QUIPC_DBG_HIGH("(*ppCmd)->skip_bw_check 1");
    }
    else if (strcmp(argv[i], "-rtm") == 0)
    {
      int rtt_test_mode = atoi(argv[++i]);// 1 for true in test mode
      (*ppCmd)->rtt_test_mode = LOWI_APPLY_LIMITS(rtt_test_mode, 0, 1);
      QUIPC_DBG_HIGH("(*ppCmd)->rtt_test_mode %u", (*ppCmd)->rtt_test_mode);
    }
    else if (strcmp(argv[i], "-tb") == 0)
    {
      int fb_tol = atoi(argv[++i]);
      (*ppCmd)->threshold_batching = LOWI_APPLY_LIMITS(fb_tol, 0, 100);
    }
    else if (strcmp(argv[i], "-fb") == 0)
    {
      int fb_tol = atoi(argv[++i]);
      (*ppCmd)->flush_buffer_batching = LOWI_APPLY_LIMITS(fb_tol, 0, 1);
    }
    else if (strcmp(argv[i], "-rb") == 0)
    {
      int fb_tol = atoi(argv[++i]);
      (*ppCmd)->max_results_batching = LOWI_APPLY_LIMITS(fb_tol, 0, 1000);
    }
    else if (strcmp(argv[i], "-fbr") == 0)
    {
      int fbr = atoi(argv[++i]);
      (*ppCmd)->fullBeaconResponse = LOWI_APPLY_LIMITS(fbr, 0, 1);
    }
    else if (strcmp(argv[i], "-dbg") == 0)
    {
      int dbgLvl = atoi(argv[++i]);
      log_set_global_level(LOWIUtils::to_logLevel(dbgLvl));
    }
    else
    {
      usage(argv[0]);
    }
  }
  // Avoid opening CSV file if tool is running into
  // Test mode else, file we reopen and all data will
  // of CSV file will be lost.
  if ((lowi_test.out_fp == NULL) && (!(*ppCmd)->rtt_test_mode))
  {
    /* Use default file */
    lowi_test.out_fp = fopen(LOWI_OUT_FILE_NAME, "w");
    if (lowi_test.out_fp == NULL)
    {
      fprintf(stderr, "%s:%s:%d: Error opening file %s. %s\n",
            argv[0], __func__,__LINE__, LOWI_OUT_FILE_NAME, strerror(errno));
    }
  }
  if (lowi_test.out_fp != NULL)
  {
    fprintf(lowi_test.out_fp,
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
            "Time", "Time(days)", "Scan Type",
            "Mac_Address", "Seq#", "Channel", "RSSI", "RTT", "RspTime", "MeasAge",
            "Ssid", "RttType", "PhyMode",
            "Tx_Preamble", "Tx_Nss", "Tx_Bw", "Tx_Mcs_Idx", "Tx_Bit_Rate",
            "Rx_Preamble", "Rx_Nss", "Rx_Bw", "Rx_Mcs_Idx", "Rx_Bit_Rate", "Tx_Chain", "Rx_Chain");

  }
  if (lowi_test.out_cfr_fp == NULL)
  {
    /* Use default file */
    lowi_test.out_cfr_fp = fopen(LOWI_OUT_CFR_FILE_NAME, "w");
    if (lowi_test.out_fp == NULL)
    {
      fprintf(stderr, "%s:%s:%d: Error opening file %s. %s\n",
            argv[0], __func__,__LINE__, LOWI_OUT_CFR_FILE_NAME, strerror(errno));
    }
  }
  if (lowi_test.out_cfr_fp != NULL)
  {
    fprintf(lowi_test.out_cfr_fp,
            "** CFR Data **\n");
  }
  if (lowi_test.kpi_log_fp == NULL)
  {
    /* Use default file */
    lowi_test.kpi_log_fp = fopen(LOWI_KPI_LOG_FILE, "w");
    if (lowi_test.kpi_log_fp == NULL)
    {
      fprintf(stderr, "%s:%s:%d: Error opening file %s. %s\n",
            argv[0], __func__, __LINE__, LOWI_KPI_LOG_FILE, strerror(errno));
    }
  }

  // Summary output file
  if (lowi_test.summary_fp == NULL)
  {
    /* Use default file */
    lowi_test.summary_fp = fopen(LOWI_SUMMARY_FILE_NAME, "w");
    if (lowi_test.summary_fp == NULL)
    {
      fprintf(stderr, "%s:%d: Error opening file %s. %s\n",
            __func__, __LINE__, LOWI_SUMMARY_FILE_NAME, strerror(errno));
    }
  }

  if ((*ppCmd)->cmd == LOWI_MAX_SCAN)
  {
    delete (*ppCmd);
    *ppCmd = NULL;
    usage(argv[0]);
  }
}

/*=============================================================================
 * lowi_get_cmd
 *
 * Description:
 *   Read the command line arguments
 *
 * Return value:
 *   LOWI test command or NULL if bad arguments
 ============================================================================*/
static t_lowi_test_cmd* lowi_get_cmd(const int argc, char *argv[])
{
  t_lowi_test_cmd *cmd_ptr = NULL;

  lowi_parse_args(argc, argv, &cmd_ptr);

  return cmd_ptr;
}

/*=============================================================================
 * lowi_wait_for_signal_or_timeout
 *
 * Description:
 *   Wait for a signal or timeout
 *
 * Return value:
 *   1 if signaled
 *   0 if timed out
 ============================================================================*/
static int lowi_wait_for_signal_or_timeout(uint32 timeout, pthread_cond_t& cond)
{
  struct timespec     present_time;
  int ret_val = -1;

  if (0 == clock_gettime(CLOCK_REALTIME, &present_time))
  {

    present_time.tv_sec += timeout / MSECS_PER_SEC;
    present_time.tv_nsec += ((timeout % MSECS_PER_SEC) * NSECS_PER_MSEC);
    if (present_time.tv_nsec > NSECS_PER_SEC)
    {
      present_time.tv_sec++;
      present_time.tv_nsec -= (NSECS_PER_SEC);
    }

    pthread_mutex_lock(&lowi_test.mutex);
    ret_val = pthread_cond_timedwait(&cond,
                                     &lowi_test.mutex,
                                     &present_time);
    pthread_mutex_unlock(&lowi_test.mutex);
  }
  return ret_val;
}

/*=============================================================================
 * lowi_wait_for_rts_scan_results
 *
 * Description:
 *   Wait for RTT Measurement results or timeout
 *
 * Return value:
 *   1 if results were received
 *   0 if timed out waiting for response
 ============================================================================*/
static int lowi_wait_for_rts_scan_results(uint32 timeout)
{
  int ret_val = lowi_wait_for_signal_or_timeout(timeout, lowi_test.rs_cond);
  return ret_val;
}

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
int lowi_wait_for_passive_scan_results(uint32 timeout)
{
  int ret_val = lowi_wait_for_signal_or_timeout(timeout, lowi_test.ps_cond);
  return ret_val;
}

/*=============================================================================
 * lowi_copy_ap_list
 *
 * Description:
 *   Copy AP list into cmd_ptr from recent results.
 *   This is used to figure out the set of APs that we
 *   will perform RTS/CTS on.
 *
 * NOTE: This function is not called if xml provides the
 * ranging data.
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_copy_ap_list(t_lowi_test_cmd *cmd_ptr)
{
  if ( (cmd_ptr == NULL) || (lowi_test.recentMeas.getNumOfElements() == 0) )
  {
    fprintf(stderr, "%s:%d: Null Pointer, %u meas\n",
            __FUNCTION__, __LINE__, lowi_test.recentMeas.getNumOfElements());
    return;
  }

  // Clear the vector
  cmd_ptr->rttNodes.flush ();

  if(cmd_ptr->reportType_cmdline != -1)
  {
    cmd_ptr->reportType = uint32(cmd_ptr->reportType_cmdline);
  }
  /* Copy the AP list from the results */
  for ( uint32 i = 0 ;
       (i < lowi_test.recentMeas.getNumOfElements()) &&
       (cmd_ptr->rttNodes.getNumOfElements() < MAX_BSSIDS_ALLOWED_FOR_RANGING_SCAN);
       i++)
  {
    // For RTS/CTS scan, we only scan the APs whose channel
    // number matches with the band requested in scan command
    bool scan_this_ap = false;

    // Check the band requested in scan command
    if ((lowi_cmd->band == LOWIDiscoveryScanRequest::BAND_ALL) ||
        (LOWIUtils::freqToBand(lowi_test.recentMeas[i].frequency) == lowi_cmd->band))
    {
      scan_this_ap = true;
    }

    if (scan_this_ap == true)
    {
      LOWIPeriodicNodeInfo rttNode;
      rttNode.bssid.setMac(lowi_test.recentMeas[i].bssid);
      rttNode.frequency = lowi_test.recentMeas[i].frequency;

      // Load global rttType and bandwidth because they are not
      // available in the scan results nor are they received from xml.
      rttNode.rttType = cmd_ptr->rttType;
      rttNode.reportType = cmd_ptr->reportType;
      rttNode.bandwidth = cmd_ptr->ranging_bandwidth;
      rttNode.num_pkts_per_meas = LOWI_TEST_DEFAULT_RTT_MEAS;
      rttNode.paramControl = LOWI_NO_PARAMS_FROM_CACHE;
      cmd_ptr->rttNodes.push_back(rttNode);
      QUIPC_DBG_HIGH("Adding Mac " LOWI_MACADDR_FMT " index %d",
                     LOWI_MACADDR(rttNode.bssid),
                     cmd_ptr->rttNodes.getNumOfElements());
    }
  }
}

/*=============================================================================
 * lowi_test_start_rtt_scan
 *
 * Description:
 *    Start the RTS/CTS Scan
 *
 * Return value:
 *   0: Success
 ============================================================================*/
static int lowi_test_start_rtt_scan(t_lowi_test_cmd * cmd_ptr)
{
  static uint32 tagCntr = 0;
  int retVal = -1;
  LOWIPeriodicRangingScanRequest * rttReq = NULL;
  tagCntr++;

  rttReq = new LOWIPeriodicRangingScanRequest(tagCntr, cmd_ptr->rttNodes, 0);
  if (NULL != rttReq)
  {
    QUIPC_DBG_HIGH("RTT Request created tag = %u", tagCntr);
    retVal =  lowi_queue_rtt_req(rttReq);
  }
  return retVal;
}

int lowi_test_do_rtt_scan(const uint32 seq_no)
{
  int ret_val;

  QUIPC_DBG_HIGH("*****STARTING RTT SCAN (%u)*****", seq_no);
  lowi_test.scan_start_ms = lowi_test_get_time_ms();
  ret_val = lowi_test_start_rtt_scan(&rtt_scan_cmd);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("RTT scan request (%u of %d)- FAILED, ret_val %d",
                   seq_no, lowi_cmd->num_requests, ret_val);
    return ret_val;
  }
  else
  {
    ret_val = lowi_wait_for_rts_scan_results(LOWI_SCAN_TIMEOUT_MS);
  }
  QUIPC_DBG_HIGH("RTT scan request (%u of %d)- %s, Rsp time %d",
                 seq_no, lowi_cmd->num_requests,
                 ret_val ? "Timeout" : "SUCCESS",
                 (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));
  return ret_val;
}

int lowi_test_set_lci(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("\n*****SET LCI INFORMATION (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }
  if (lowi_cmd->lci_info == NULL)
  {
    QUIPC_DBG_HIGH("SET LCI INFORMATION (%u)- FAILED(NOT AVAILABLE)\n", seq_no);
    return ret_val;
  }

  ret_val = lowi_queue_set_lci(lowi_cmd->lci_info, lowi_cmd->interface);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("SET LCI INFORMATION (%u)- FAILED\n", seq_no);
  }
  else
  {

    QUIPC_DBG_HIGH("SET LCI INFORMATION (%u)- SUCCESS\n", seq_no);
  }
  return ret_val;
}

int lowi_test_set_lcr(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("\n*****SET LCR INFORMATION (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }
  if (lowi_cmd->lcr_info == NULL)
  {
    QUIPC_DBG_HIGH("SET LCR INFORMATION (%u)- FAILED(NOT AVAILABLE)\n", seq_no);
    return ret_val;
  }

  ret_val = lowi_queue_set_lcr(lowi_cmd->lcr_info, lowi_cmd->interface);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("SET LCR INFORMATION (%u)- FAILED\n", seq_no);
  }
  else
  {

    QUIPC_DBG_HIGH("SET LCR INFORMATION (%u)- SUCCESS\n", seq_no);
  }
  return ret_val;
}

int lowi_test_where_are_you(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("\n*****WHERE ARE YOU REQUEST (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }
  if (lowi_cmd->ap_info.getNumOfElements() < 1)
  {
    QUIPC_DBG_HIGH("WHERE ARE YOU REQUEST (%u)- FAILED(TARGET STA NOT AVAILABLE)\n", seq_no);
    return ret_val;
  }

  lowi_test.scan_start_ms = lowi_test_get_time_ms();
  ret_val = lowi_queue_where_are_you(lowi_cmd->ap_info[0].mac);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("WHERE ARE YOU REQUEST (%u)- FAILED\n", seq_no);
  }

  QUIPC_DBG_HIGH("WHERE ARE YOU REQUEST (%u)- %s, Rsp time %d \n",
         seq_no, ret_val ? "Timeout" : "SUCCESS",
         (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));

  return ret_val;
}

int lowi_test_ftmrr(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("\n*****FTM RANGE REQUEST (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }
  if (lowi_cmd->ap_info.getNumOfElements() < 1)
  {
    QUIPC_DBG_HIGH("FTM RANGE REQUEST (%u)- FAILED(TARGET STA NOT AVAILABLE)\n", seq_no);
    return ret_val;
  }
  if (lowi_cmd->ftmrr_info.getNumOfElements() < 1)
  {
    QUIPC_DBG_HIGH("FTM RANGE REQUEST (%u)- FAILED(NODE INFO NOT AVAILABLE)\n", seq_no);
    return ret_val;
  }

  lowi_test.scan_start_ms = lowi_test_get_time_ms();
  ret_val = lowi_queue_ftmrr(lowi_cmd->ap_info[0].mac,
                             lowi_cmd->rand_inter, lowi_cmd->ftmrr_info);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("FTM RANGE REQUEST (%u)- FAILED\n", seq_no);
  }

  QUIPC_DBG_HIGH("FTM RANGE REQUEST (%u)- %s, Rsp time %d \n",
         seq_no, ret_val ? "Timeout" : "SUCCESS",
         (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));

  return ret_val;
}

int lowi_test_config_req(const uint32 seq_no)
{
  int ret_val = -1;

  lowi_test.config_test_success = false;
  QUIPC_DBG_HIGH("\n*****CONFIG REQUEST (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }
  if (lowi_cmd->lowiconfigrequest == NULL)
  {
    QUIPC_DBG_HIGH("Request pointer NULL \n");
    return ret_val;
  }

  ret_val = lowi_queue_config_req(lowi_cmd->lowiconfigrequest);
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("LOWI LOG CONFIG REQUEST (%u)- FAILED\n", seq_no);
  }
  lowi_test.config_test_success = true;
  return ret_val;
}
int lowi_test_start_responder_meas_req(const uint32 seq_no)
{
  int ret_val = -1;

  lowi_test.config_test_success = false;
  QUIPC_DBG_HIGH("\n*****RESPONDER MEASUREMENT START REQUEST (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }

  ret_val = lowi_queue_start_responder_meas_req(uint8(lowi_cmd->reportType & 0xFF));
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("LOWI RESPONDER MEASUREMENT START REQUEST (%u)- FAILED\n", seq_no);
  }
  lowi_test.config_test_success = true;
  return ret_val;
}

int lowi_test_stop_responder_meas_req(const uint32 seq_no)
{
  int ret_val = -1;

  lowi_test.config_test_success = false;
  QUIPC_DBG_HIGH("\n*****RESPONDER MEASUREMENT STOP REQUEST (%u)*****\n", seq_no);
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }

  ret_val = lowi_queue_stop_responder_meas_req();
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("LOWI RESPONDER MEASUREMENT STOP REQUEST (%u)- FAILED\n", seq_no);
  }
  lowi_test.config_test_success = true;
  return ret_val;
}
int lowi_test_do_neighbor_report_request(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("*****STARTING NEIGHBOR REPORT REQUEST (%u)*****", seq_no);
  lowi_test.scan_start_ms = lowi_test_get_time_ms();
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }

  ret_val = lowi_queue_nr_request();
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("STARTING NEIGHBOR REPORT REQUEST (%u of %d)- FAILED",
                   seq_no, lowi_cmd->num_requests);
  }
  else
  {

    QUIPC_DBG_HIGH("STARTING NEIGHBOR REPORT REQUEST (%u of %d)- SUCCESS, Rsp time %d",
                   seq_no, lowi_cmd->num_requests,
                   (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));
  }
  return ret_val;
}

int lowi_test_do_wlan_state_query_request(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("*****STARTING WLAN STATE QUERY REQUEST (%u)*****", seq_no);
  lowi_test.scan_start_ms = lowi_test_get_time_ms();
  if (lowi_cmd == NULL)
  {
    return ret_val;
  }

  ret_val = lowi_queue_wsq_request();
  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("STARTING WLAN STATE QUERY REQUEST (%u of %d)- FAILED",
                   seq_no, lowi_cmd->num_requests);
  }
  else
  {

    QUIPC_DBG_HIGH("STARTING WLAN STATE QUERY REQUEST (%u of %d)- SUCCESS, Rsp time %d",
                   seq_no, lowi_cmd->num_requests,
                   (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));
  }
  return ret_val;
}

int lowi_test_do_async_discovery_scan(const uint32 seq_no)
{
  int ret_val;
  QUIPC_DBG_HIGH("*****SENDING ASYNC DISCOVERY SCAN REQ (%u of %d)*****",
                 seq_no, lowi_cmd->num_requests); /* BAA */
  lowi_test.scan_start_ms = lowi_test_get_time_ms();

  ret_val = lowi_queue_async_discovery_scan_result_req (lowi_cmd->timeout_offset);

  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("Async Discovery scan request (%u of %d)- FAILED",
                   seq_no, lowi_cmd->num_requests);
  }
  else
  {
    ret_val = lowi_wait_for_passive_scan_results(LOWI_ASYNC_SCAN_TIMEOUT_MS);
  }
  QUIPC_DBG_HIGH("Async Discovery scan request (%u of %d)- %s, Rsp time %d",
                 seq_no, lowi_cmd->num_requests,
                 ret_val ? "Timeout" : "SUCCESS",
                 (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));
  return ret_val;
}


int lowi_test_do_passive_scan(const uint32 seq_no)
{
  int ret_val;
  QUIPC_DBG_HIGH("*****STARTING DISCOVERY SCAN (%u of %d)*****",
                 seq_no, lowi_cmd->num_requests);
  lowi_test.scan_start_ms = lowi_test_get_time_ms();

  int64 request_timeout = 0;
  if (0 != lowi_cmd->timeout_offset)
  {
    request_timeout = LOWIUtils::currentTimeMs () +
        (lowi_cmd->timeout_offset*1000);
  }

  // check if the discovery scan channels are specified
  if (0 != lowi_cmd->chList.getNumOfElements())
  {
    // Ignore the band specified through the -b option and use the channels
    ret_val = lowi_queue_discovery_scan_req_ch(lowi_cmd->chList,
        request_timeout, lowi_cmd->scan_type,
        lowi_cmd->meas_age_filter_sec, lowi_cmd->fullBeaconResponse,
        lowi_cmd->discoveryBssids, lowi_cmd->discoverySsids, lowi_cmd->fallback_tolerance);
  }
  else
  {
    ret_val = lowi_queue_discovery_scan_req_band(lowi_cmd->band, request_timeout,
        lowi_cmd->scan_type, lowi_cmd->meas_age_filter_sec,
        lowi_cmd->fullBeaconResponse, lowi_cmd->discoveryBssids,
        lowi_cmd->discoverySsids, lowi_cmd->fallback_tolerance);
  }

  if (ret_val != 0)
  {
    QUIPC_DBG_HIGH("Discovery scan request (%u of %d)- FAILED",
                   seq_no, lowi_cmd->num_requests);
  }
  else
  {
    ret_val = lowi_wait_for_passive_scan_results(LOWI_SCAN_TIMEOUT_MS);
  }
  QUIPC_DBG_HIGH("Discovery scan request (%u of %d)- %s, Rsp time %d",
                 seq_no, lowi_cmd->num_requests,
                 ret_val ? "Timeout" : "SUCCESS",
                 (int32)(lowi_test.scan_end_ms - lowi_test.scan_start_ms));
  return ret_val;
}

/*=============================================================================================
 * prepareRtsCtsParam
 *
 * Function description:
 *   Prepare the cmd_ptr for RTS/CTS scan.
 *   Make sure that the AP list is valid
 *
 * Return value: Number of APs for RTS/CTS Scan
 =============================================================================================*/
static int prepareRttParam(t_lowi_test_cmd *cmd_ptr,
                          const uint32 seq_no)
{
  int ret_val = cmd_ptr->rttNodes.getNumOfElements();

  if (ret_val == 0)
  {
    /* Request Discovery Scan */
    ret_val = lowi_test_do_passive_scan(seq_no);
    if (ret_val != 0)
    {
      QUIPC_DBG_HIGH("AP List incomplete. Discovery scan FAILED: %d", ret_val);
      ret_val = 0;
    }
    else
    {
      QUIPC_DBG_HIGH("AP List complete. Discovery scan request - SUCCESS.");
      /* Got Discovery scan results */
      lowi_copy_ap_list(cmd_ptr);
    }
  }
  return cmd_ptr->rttNodes.getNumOfElements();
}

int lowi_test_do_combo_scan(const uint32 seq_no)
{
  int ret_val = -1;

  QUIPC_DBG_HIGH("*****STARTING Combo SCAN (%u of %d)*****",
                 seq_no, lowi_cmd->num_requests);
  rtt_scan_cmd.rttNodes.flush(); // Flush current nodes to scan again
  if (prepareRttParam (&rtt_scan_cmd, seq_no) == 0)
  {
    fprintf(stderr, "Incorrect AP List. Num APs = %d",
            rtt_scan_cmd.rttNodes.getNumOfElements());
    QUIPC_DBG_HIGH("Prepare failed. Exit");
  }
  else
  {
    ret_val = lowi_test_do_rtt_scan(seq_no);
    if (ret_val != 0)
    {
      QUIPC_DBG_HIGH("Combo scan request (%u of %d)- Timeout",
                     seq_no, lowi_cmd->num_requests);
    }
  }
  return ret_val;
}

/*=============================================================================
 * lowi_test_init
 *
 * Description:
 *    Init the LOWI Test module
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_test_init( void )
{
  printf ("LOWI Test Version: %s\n", LOWI_TEST_VERSION);
  QUIPC_DBG_HIGH ("clock_id = %d", lowi_test.clock_id);
  if (-1 == lowi_test.timerFd)
  {
    printf("timerfd_create failed %d, %s", errno, strerror(errno));
    return;
  }
  log_set_global_level(lowi_test_debug_level);
  log_set_global_tag(LOG_TAG);

}

/*=============================================================================
 * lowi_test_exit
 *
 * Description:
 *   Cleanup the LOWI Test module
 *
 * Return value:
 *   void
 ============================================================================*/
static void lowi_test_exit( void )
{
  lowi_test_display_summary_stats();
  if ((lowi_cmd != NULL) &&
      (lowi_cmd->cmd == LOWI_RTS_CTS_SCAN))
  {
    if (lowi_test.out_fp!= NULL)
    {
      pr_kpi_fs_high("\n closing the out_fp ");
      fclose(lowi_test.out_fp);
      lowi_test.out_fp = NULL;
    }
    // Measure KPI data from CSV file
    lowi_calculate_kpi(LOWI_OUT_FILE_NAME);
  }

  if (lowi_test.summary_fp != NULL)
  {
    fclose(lowi_test.summary_fp);
    lowi_test.summary_fp = NULL;
  }

  /* Free memory */
  if (lowi_cmd != NULL)
  {
    delete lowi_cmd;
  }
}

/*=============================================================================
 * rts_cts_scan_meas_received
 *
 * Description:
 *   This is the callback function that  will be called to send RTS CTS scan
 *   results to the client.
 *   The memory pointed by p_wlan_meas is allocated by LOWI. However, the
 *   de-allocation is the responsibility of the client.
 *
 * Parameters:
 *   p_wlan_meas - Pointer to the measurement results.
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 ============================================================================*/
int rts_cts_scan_meas_received(vector <LOWIScanMeasurement*> &scanMeas)
{
  char string_buf[128];  // IPE_LOG_STRING_BUF_SZ

  QUIPC_DBG_HIGH("=== Ranging SCAN RESULTS (%d APs Found) ===\n",
                 scanMeas.getNumOfElements());

  for (uint32 ii = 0; ii < scanMeas.getNumOfElements(); ++ii)
  {
    vector<LOWIMeasurementInfo*>& measInfo = scanMeas[ii]->measurementsInfo;

    for (uint32 jj=0; jj < measInfo.getNumOfElements(); ++jj)
    {
      lowi_test_log_time_ms_to_string(string_buf, 128, NULL,
                                      (uint64)measInfo[jj]->rtt_timestamp);

      QUIPC_DBG_HIGH("[%u]itr " LOWI_MACADDR_FMT " %d %u %d %s\n",
                     lowi_test.seq_no, LOWI_MACADDR(scanMeas[ii]->bssid),
                     LOWIUtils::freqToChannel(scanMeas[ii]->frequency),
                     measInfo[jj]->rtt_ps, measInfo[jj]->rssi, string_buf);
    }
  }

  pthread_mutex_lock(&lowi_test.mutex);
  lowi_test_log_meas_results(LOWIResponse::RANGING_SCAN, scanMeas);
  pthread_cond_signal(&lowi_test.rs_cond);
  pthread_mutex_unlock(&lowi_test.mutex);
  return 0;
}

/*=============================================================================
 * passive_scan_meas_received
 *
 * Description:
 *   This is the callback function that  will be called to send PASSIVE scan
 *   results to the client.
 *   The memory pointed by p_wlan_meas is allocated by LOWI. However, the
 *   de-allocation is the responsibility of the client.
 *
 * Parameters:
 *   p_wlan_meas - Pointer to the measurement results.
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 ============================================================================*/
int passive_scan_meas_received(vector <LOWIScanMeasurement*> &scanMeas)
{
  char string_buf[128];  // IPE_LOG_STRING_BUF_SZ

  QUIPC_DBG_HIGH("=== DISCOVERY SCAN RESULTS (%d APs Found) [%u] ===\n",
              scanMeas.getNumOfElements(), lowi_test.seq_no);

  for (uint32 ii = 0; ii < scanMeas.getNumOfElements(); ++ii)
  {
      lowi_test_log_time_ms_to_string(string_buf, 128, NULL,
                                     (uint64)(scanMeas[ii]->measurementsInfo[0]->rssi_timestamp));
      QUIPC_DBG_HIGH("[%u]itp " LOWI_MACADDR_FMT " %d %d %s\n",
                     lowi_test.seq_no, LOWI_MACADDR(scanMeas[ii]->bssid),
                     LOWIUtils::freqToChannel(scanMeas[ii]->frequency),
                     scanMeas[ii]->measurementsInfo[0]->rssi, string_buf);
  }

  pthread_mutex_lock(&lowi_test.mutex);
  lowi_test_log_meas_results(LOWIResponse::DISCOVERY_SCAN, scanMeas);
  pthread_cond_signal(&lowi_test.ps_cond);
  pthread_mutex_unlock(&lowi_test.mutex);
  return 0;
}

/*=============================================================================
 * driver_capabilities_received
 *
 * Description:
 *   This is the callback function that is invoked to notify the capabilities
 *   of the driver.
 *
 * Parameters:
 *   LOWICapabilityResponse* - Pointer to Capability Response
 *
 * Return value:
 *   None
 ============================================================================*/
void driver_capabilities_received (LOWICapabilityResponse* cap)
{
  QUIPC_DBG_HIGH("\nDriver capabilities obtained!");
  if (NULL != cap)
  {
    QUIPC_DBG_HIGH("Driver capabilities discovery scan enabled = %d",
        cap->getCapabilities().discoveryScanSupported);
    QUIPC_DBG_HIGH("Driver capabilities ranging scan enabled   = %d",
        cap->getCapabilities().rangingScanSupported);
    QUIPC_DBG_HIGH("Driver capabilities active scan supported  = %d",
        cap->getCapabilities().activeScanSupported);
  }
}

int lowi_test_response_callback(LOWIResponse *response)
{
  if (NULL == response)
  {
    return -1;
  }
  switch (response->getResponseType())
  {
  case LOWIResponse::DISCOVERY_SCAN:
  case LOWIResponse::ASYNC_DISCOVERY_SCAN_RESULTS:
  {
    LOWIDiscoveryScanResponse *resp = (LOWIDiscoveryScanResponse *)response;
    vector<LOWIScanMeasurement *>& scanMeasurements = resp->scanMeasurements;

    log_debug(LOG_TAG, "Response for Discovery scan request");
    if (passive_scan_meas_received(scanMeasurements))
    {
      log_error(LOG_TAG, "sending msg to client failed");
    }
  }
  break;
  case LOWIResponse::RANGING_SCAN:
  {
    LOWIRangingScanResponse* resp = (LOWIRangingScanResponse*) response;
    vector <LOWIScanMeasurement*>& scanMeasurements = resp->scanMeasurements;

    if (rts_cts_scan_meas_received(scanMeasurements))
    {
      log_error(LOG_TAG, "sending msg to upper layer failed");
    }
  }
  break;
  case LOWIResponse::CAPABILITY:
  {
    log_debug (LOG_TAG, "Response for the capability request");
    LOWICapabilityResponse* cap_resp = (LOWICapabilityResponse*) response;

    driver_capabilities_received(cap_resp);
  }
  break;
  case LOWIResponse::LOWI_WLAN_STATE_QUERY_RESPONSE:
  {
    LOWIWlanStateQueryResponse* resp = (LOWIWlanStateQueryResponse*) response;
    log_debug (LOG_TAG, "LOWI_WLAN_STATE_QUERY_RESPONSE, status %d, connected %d,"
        " connected BSSID"
        LOWI_MACADDR_FMT
        " Connected RSSI %d", resp->status, resp->connected,
        LOWI_MACADDR(resp->connectedNodeBssid),
        resp->connectedNodeRssi);
  }
  break;
  default:
    lowi_test_extn_response_callback (response);
    break;
  }
  return 0;
}

void log_time ()
{
  QUIPC_DBG_HIGH ("Time from Android boot = %" PRId64, lowi_test_get_time_ms());
  QUIPC_DBG_HIGH ("Time current time of day = %" PRId64, LOWIUtils::currentTimeMs());
}

/*=============================================================================
 * signal_handler
 *
 * Function description:
 *   Handles a signal.
 *
 * Parameters: Signal ID.
 *
 * Return value: void
 ============================================================================*/
void signal_handler(int signal_id)
{
  QUIPC_DBG_HIGH("\nreceived signal [%d][%s], ignore",
      signal_id, strsignal(signal_id));
}

void lowi_read_csv_file(csv_row_db &all_meas_db, const char* path)
{

  std::ifstream ip(path);
  if (!ip.is_open())
  {
    pr_kpi_fs_high("\nNot able to open %s file", path);
    return;
  }

  std::string whole_line;
  std::string word;

  unsigned int row_count = 0;
  unsigned int col_count = 0;

  while (ip.good())
  {
    std::getline(ip, whole_line);
    const char *line = whole_line.c_str();
    pr_kpi_fs_low("\nwhole line %s", line);
    std::stringstream str_strm(whole_line);
    row_count++;
    if (row_count == 1)
      continue;
    col_count = 0;
    struct rtt_node_data node_data;
    while(std::getline(str_strm, word, ',') && col_count < KEY_MAX)
    {
      const char* s = word.c_str();
      switch (col_count)
      {
        case KEY_TIME:
          strlcpy(node_data.time, s, TIME_STR_LEN);
          pr_kpi_fs_low("\nnode time %s",  node_data.time);
          break;
        case KEY_TIME_DAYS:
          strlcpy(node_data.time_days, s, TIME_STR_LEN);
          pr_kpi_fs_low("\nnode time_days %s",  node_data.time_days);
          break;
        case KEY_SCAN_TYPE:
          node_data.scan_type = atoi(s);
          pr_kpi_fs_low("\nnode scan type %d",  node_data.scan_type);
          break;
        case KEY_MAC:
          strlcpy(node_data.mac_str, s, TIME_STR_LEN);
          pr_kpi_fs_low("\nnode mac_str %s",  node_data.mac_str);
          if (strlen(s) == 17)
          {
            int k = 0;
            while(s && k < 6)
            {
              unsigned char c;
              // 3bytes required because strlcpy will
              // add \n at the end of copying 2bytes
              char p[3];
              strlcpy (p, s, 3);
              node_data.mac[k] = std::strtoul(p, 0, 16);
              // mac address is in format AA:BB:CC:DD:EE:FF so
              // to read second address skip 3 char.
              s=s+3;
              k++;
            }
            pr_kpi_fs_low("\nnode *** mac address %x:%x:%x:%x:%x:%x",
              node_data.mac[0], node_data.mac[1], node_data.mac[2],
              node_data.mac[3], node_data.mac[4], node_data.mac[5]);
          }
          break;
        case KEY_SEQ_NO:
          node_data.seq_no = atoi(s);
          pr_kpi_fs_low("\nnode seq_no %d",  node_data.seq_no);
          if (lowi_cmd->max_seq_no_in_csv != node_data.seq_no)
            lowi_cmd->max_seq_no_in_csv = node_data.seq_no;
          break;
        case KEY_CHANNEL:
          node_data.channel = atoi(s);
          pr_kpi_fs_low("\nnode channel %d",  node_data.channel);
          break;
        case KEY_RSSI:
          node_data.rssi = atoi(s);
          pr_kpi_fs_low("\nnode rssi %d",  node_data.rssi);
          break;
        case KEY_RTT:
          node_data.rtt = atoi(s);
          pr_kpi_fs_low("\nnode rtt %d",  node_data.rtt);
          break;
        case KEY_RSP_TIME:
          node_data.rsp_time = atoi(s);
          pr_kpi_fs_low("\nnode rsp_time %d",  node_data.rsp_time);
          break;
        case KEY_MEAS_AGE:
          node_data.meas_age = atoi(s);
          pr_kpi_fs_low("\nnode meas_age %d",  node_data.meas_age);
          break;
        case KEY_SSID:
          strlcpy(node_data.ssid, s, 34);
          pr_kpi_fs_low("\nnode ssid %s",  node_data.ssid);
          break;
        case KEY_RTT_TYPE:
          node_data.rtt_type = atoi(s);
          pr_kpi_fs_low("\nnode rtt_type %d",  node_data.rtt_type);
          break;
        case KEY_PHY_MODE:
          node_data.phy_mode = atoi(s);
          pr_kpi_fs_low("\nnode phy_mode %d",  node_data.phy_mode);
          break;
        case KEY_TX_PREAM:
          node_data.tx_preamble = atoi(s);
          pr_kpi_fs_low("\nnode tx_preamble %d",  node_data.tx_preamble);
          break;
        case KEY_RX_PREAM:
          node_data.rx_preamble = atoi(s);
          pr_kpi_fs_low("\nnode rx_preamble %d",  node_data.rx_preamble);
          break;
        case KEY_TX_NSS:
          node_data.tx_nss = atoi(s);
          pr_kpi_fs_low("\nnode tx_nss %d",  node_data.tx_nss);
          break;
        case KEY_RX_NSS:
          node_data.rx_nss = atoi(s);
          pr_kpi_fs_low("\nnode rx_nss %d",  node_data.rx_nss);
          break;
        case KEY_TX_BW:
          node_data.tx_bw = atoi(s);
          pr_kpi_fs_low("\nnode tx_bw %d",  node_data.tx_bw);
          break;
        case KEY_RX_BW:
          node_data.rx_bw = atoi(s);
          pr_kpi_fs_low("\nnode rx_bw %d",  node_data.rx_bw);
          break;
        case KEY_TX_MCS:
          node_data.tx_mcs = atoi(s);
          pr_kpi_fs_low("\nnode tx_mcs %d",  node_data.tx_mcs);
          break;
        case KEY_RX_MCS:
          node_data.rx_mcs = atoi(s);
          pr_kpi_fs_low("\nnode rx_mcs %d",  node_data.rx_mcs);
          break;
        case KEY_TX_BIT_RATE:
          node_data.tx_bit_rate = atoi(s);
          pr_kpi_fs_low("\nnode tx_bit_rate %d",  node_data.tx_bit_rate);
          break;
        case KEY_RX_BIT_RATE:
          node_data.rx_bit_rate = atoi(s);
          pr_kpi_fs_low("\nnode rx_bit_rate %d",  node_data.rx_bit_rate);
          break;
        case KEY_TX_CHAIN:
          node_data.tx_chain = atoi(s);
          pr_kpi_fs_low("\nnode tx_chain %d",  node_data.tx_chain);
          break;
        case KEY_RX_CHAIN:
          node_data.rx_chain = atoi(s);
          pr_kpi_fs_low("\nnode rx_chain %d",  node_data.rx_chain);
          break;
      }
    col_count++;
    }
    all_meas_db.push_back(node_data);
  }
  pr_kpi_fs_high("\ntotal rows in csv :%u total meas in all_meas_db:%u ",
                row_count, all_meas_db.getNumOfElements());

  ip.close();

}

void lowi_update_node_cache_from_cmd_params(
        vector <LOWIPostProcessNode> &node_cache)
{
  for (uint32 i = 0; i < node_cache.getNumOfElements(); i++)
  {
    if (lowi_cmd->trueDist)
      node_cache[i].true_dist = lowi_cmd->trueDist;
    if (lowi_cmd->req_tx_bw != -1)
      node_cache[i].req_tx_bw =
      (enum eRangingBandwidth) lowi_cmd->req_tx_bw;
    if (lowi_cmd->req_rx_bw != -1)
      node_cache[i].req_rx_bw =
      (enum eRangingBandwidth) lowi_cmd->req_rx_bw;
    if (lowi_cmd->delay_ps_2p4)
      node_cache[i].delay_ps_2p4 = lowi_cmd->delay_ps_2p4;
    if (lowi_cmd->delay_ps_5g)
      node_cache[i].delay_ps_5g = lowi_cmd->delay_ps_5g;
    if (lowi_cmd->forceLegAck)
      node_cache[i].forceLegAck = true;
  }
}

void lowi_update_node_cache_from_csv_db(csv_row_db &all_meas_db,
        vector <LOWIPostProcessNode> &node_cache)
{

  pr_kpi_fs_high("\n***%s: enter", __func__);

  //Try to find the node in node_cache based on mac address
  //If not found then add a new entry in node cache
  struct LOWIPostProcessNode *ap_node = NULL;

  for (uint32 count = 0; count < all_meas_db.getNumOfElements(); count++)
  {
    ap_node = NULL;
    for (uint32 cnt = 0; cnt < node_cache.getNumOfElements(); cnt++)
    {
      if (node_cache[cnt].bssid.compareTo(all_meas_db[count].mac) == 0)
      {
        ap_node = &node_cache[cnt];
      }
    }

    struct LOWIPostProcessNode node;
    if (!ap_node)
    {
      pr_kpi_fs_high("\nCd not find xml node_cache mac: %s",
                      all_meas_db[count].mac_str);
      ap_node = &node;
      ap_node->bssid.setMac(all_meas_db[count].mac);
      ap_node->true_dist = lowi_cmd->trueDist;
      ap_node->delay_ps_2p4 = lowi_cmd->delay_ps_2p4;
      ap_node->delay_ps_5g = lowi_cmd->delay_ps_5g;
      ap_node->band = IS_2G_CHANNEL(all_meas_db[count].channel) ? 0 : 1;
      ap_node->req_tx_bw = (enum eRangingBandwidth)lowi_cmd->req_tx_bw;
      ap_node->req_rx_bw = (enum eRangingBandwidth)lowi_cmd->req_rx_bw;
      if(lowi_cmd->forceLegAck)
         ap_node->forceLegAck = true;
      lowi_cmd->post_process_info.node_cache.push_back(node);
    }
    else
    {
      ap_node->band = IS_2G_CHANNEL(all_meas_db[count].channel) ? 0 : 1;
    }

    struct result_data meas_data;
    // Band 2.4 GHz
    if(ap_node->band == 0)
    {
       meas_data.rtt = all_meas_db[count].rtt - ap_node->delay_ps_2p4;
    }
    // Band 5 GHz
    else if(ap_node->band == 1)
    {
       meas_data.rtt = all_meas_db[count].rtt - ap_node->delay_ps_5g;
    }
    meas_data.tx_bw = (enum eRangingBandwidth) all_meas_db[count].tx_bw;
    meas_data.rx_bw = (enum eRangingBandwidth) all_meas_db[count].rx_bw;
    meas_data.tx_chain_no = all_meas_db[count].tx_chain;
    meas_data.rx_chain_no = all_meas_db[count].rx_chain;
    meas_data.seq_no = all_meas_db[count].seq_no;

    //Increament total number of measurements
    ap_node->total_cnt++;

    ap_node->rtt_cache.push_back(meas_data);
  }

  pr_kpi_fs_high("\n%s: exit", __func__);
}

void lowi_update_node_cache(csv_row_db & all_meas_db,
        vector <LOWIPostProcessNode> &node_cache)
{
  lowi_update_node_cache_from_csv_db(all_meas_db, node_cache);
  lowi_update_node_cache_from_cmd_params(node_cache);
}

static bool lowi_get_node_info(unsigned char mac[6],
              struct LOWIPostProcessNode &ap_node)
{
  bool status = false;
  struct LOWIPostProcessNode *tmp_ap_node;
  for (uint32 cnt = 0; cnt < lowi_cmd->post_process_info.node_cache.getNumOfElements(); cnt++)
  {
    if (lowi_cmd->post_process_info.node_cache[cnt].bssid.compareTo(mac) == 0)
    {
       tmp_ap_node = &lowi_cmd->post_process_info.node_cache[cnt];
       status = true;
       break;
    }
  }

  if (status)
  {
    tmp_ap_node->getNodeMetaData(ap_node);
    pr_kpi_fs_low("\n\t\t%s:Got valid node band %d req bw rx %d tx %d"
                      " true_dist %d total_cnt %d frame_per_burst %d",
                      __func__, ap_node.band, ap_node.req_rx_bw,
                      ap_node.req_tx_bw, ap_node.true_dist,
                      ap_node.total_cnt, ap_node.frame_per_burst);
  }

  return status;
}

static void lowi_create_per_burst_map(csv_row_db &all_meas_db,
     per_burst_map &per_burst_dict)
{
  uint32 burst_seq_no = 0;
  vector <int> burst_rtt_vec;
  struct rtt_per_chain_info rtt_info;
  struct LOWIPostProcessNode ap_node;
  struct result_data result_info;
  bool is_ap_valid = false;
  uint32 total_meas = all_meas_db.getNumOfElements();

  pr_kpi_fs_high("\n***%s Total elem in all_meas_db %d", __func__, total_meas);
  if (!total_meas)
    return;

  burst_seq_no = all_meas_db[0].seq_no;
  for (uint32 count = 0; count < total_meas; count++)
  {
   /**
    * To keep it Simple, We are inserting the ap node into burst_map only
    * when all required data is available to us ( we need all rtt measurment
    * of same seq no and  meta data of that ap_node). For this purpose we are
    * pushing all RTT meas into the ap_node->rtt_cache vector till sequnce
    * no is same in all_meas_db ie row's in CSV file. once seq no is
    * different in CSV then we are getting meta data of ap_node and then
    * whole ap_node is getting pushed into burst_map.
    */
    if (burst_seq_no != all_meas_db[count].seq_no)
    {
      is_ap_valid = lowi_get_node_info(all_meas_db[burst_seq_no].mac, ap_node);
      if (is_ap_valid)
      {
        per_burst_dict[burst_seq_no] = std::make_pair(ap_node, rtt_info);
        pr_kpi_fs_med("\n\tPushing seq_no %d in map", burst_seq_no);
      }
      else
      {
        pr_kpi_fs_high("\n\t%s can't find node in node_cahce:" LOWI_MACADDR_FMT,
                      __func__, all_meas_db[burst_seq_no].mac);
      }
      ap_node.resetNodeMetaData();
      ap_node.rtt_cache.flush();
      result_info.reset_result_data();
      burst_seq_no = all_meas_db[count].seq_no;
    }
    result_info.rtt = all_meas_db[count].rtt;
    result_info.tx_bw = (enum eRangingBandwidth)all_meas_db[count].tx_bw;
    result_info.rx_bw = (enum eRangingBandwidth)all_meas_db[count].rx_bw;
    result_info.tx_chain_no = all_meas_db[count].tx_chain;
    result_info.rx_chain_no = all_meas_db[count].rx_chain;
    result_info.seq_no = all_meas_db[count].seq_no;
    pr_kpi_fs_low("\n\t\tburst_seq_no %d rx_chain_no %d count %d rtt %d",
                burst_seq_no, result_info.rx_chain_no, count, result_info.rtt);
    ap_node.rtt_cache.push_back(result_info);
  }

 /* Push last node ie above for loop will iterate till last row of csv.
  * hence we will not be able to push the last sequnce no as both the
  * burst_seq_no/all_meas_db[count].seq will point to same value.
  * will be same. Ideally we can push unconditonally but added saftey check.
  */
  if (burst_seq_no == all_meas_db[total_meas].seq_no)
  {
    is_ap_valid = lowi_get_node_info(all_meas_db[burst_seq_no].mac, ap_node);
    if (is_ap_valid)
    {
      per_burst_dict[burst_seq_no] = std::make_pair(ap_node, rtt_info);
      pr_kpi_fs_med("\nPushing last seq_no %d in map", burst_seq_no);
    }
    else
    {
      pr_kpi_fs_high("\n\t%s cannot find node node_cahce:" LOWI_MACADDR_FMT,
                    __func__, all_meas_db[burst_seq_no].mac);
    }
  }
  pr_kpi_fs_high("\n%s total no of keys in burst map(aka map_size): %d",
                __func__, per_burst_dict.size());
}

static void lowi_update_burst_rtt_in_all_meas_dict(
     csv_row_db &all_meas_db,
     per_burst_map &per_burst_dict)
{
  uint32 curr_seq_no = 0;
  int tmp_burst_rtt = 0;

  if (!all_meas_db.getNumOfElements())
    return;

  curr_seq_no = 0;
  for (uint32 count = 0; count < all_meas_db.getNumOfElements(); count++)
  {
    if (curr_seq_no != all_meas_db[count].seq_no)
    {
      tmp_burst_rtt = lowi_get_cached_burst_rtt(per_burst_dict,
                                  all_meas_db[count].seq_no);
    }
    all_meas_db[count].burst_rtt = tmp_burst_rtt;
    curr_seq_no = all_meas_db[count].seq_no;
  }
}

static void lowi_update_csv_file(const char* path,
    csv_row_db &all_meas_db)
{
  FILE * out_fp = NULL;
  if (path == NULL)
  {
    pr_kpi_fs_high("\nreturn due to path is null ");
    return;
  }

  out_fp = fopen(path, "w");
  if (out_fp == NULL)
  {
    pr_kpi_fs_high("\nfopen got failed ");
    fprintf(stderr, "%s:%d: Error opening file %s. %s\n",
             __func__, __LINE__, path, strerror(errno));
    return;
  }

  if (out_fp != NULL)
  {
    fprintf(out_fp,
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
            "Time", "Time(days)", "Scan Type",
            "Mac_Address", "Seq#", "Channel", "RSSI", "RTT", "RspTime", "MeasAge",
            "Ssid", "RttType", "PhyMode",
            "Tx_Preamble", "Tx_Nss", "Tx_Bw", "Tx_Mcs_Idx", "Tx_Bit_Rate",
            "Rx_Preamble", "Rx_Nss", "Rx_Bw", "Rx_Mcs_Idx", "Rx_Bit_Rate",
            "Tx_Chain", "Rx_Chain", "FINAL_RTT");
  }
  else
  {
    pr_kpi_fs_high("\n out_fp is null ");
    return;
  }

  for (auto it = all_meas_db.begin(); it != all_meas_db.end(); it++)
  {
    /* Ensure valid entry write into CSV file */
    if (it->seq_no)
    {
      fprintf(out_fp,
          "\n%s,%s,%d,%s,%d,%d,%d,%d,%d,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
          it->time, it->time_days, it->scan_type, it->mac_str,
          it->seq_no, it->channel, it->rssi, it->rtt,
          it->rsp_time, it->meas_age, it->ssid,
          it->rtt_type, it->phy_mode,
          it->tx_preamble, it->tx_nss, it->tx_bw, it->tx_mcs, it->tx_bit_rate,
          it->rx_preamble, it->rx_nss, it->rx_bw, it->rx_mcs, it->rx_bit_rate,
          it->tx_chain, it->rx_chain, it->burst_rtt);
    }
  }
  fclose(out_fp);
}

/**
 * Brief introduction of how KPI's are getting computed in LTT.
 *
 * We have implemented everything based on post processing
 * of data from DOT CSV file instead of live computation of
 * measurment data. It helps alot while debugging of KPI
 * mismatch issues with system team ie we can feed existing
 * DOT CSV file with input DOT XML to lowi test tool and
 * debug KPI mismatch issues to avoid Over The Air testing.
 * This mode of lowi test KPI computation is known as
 * RTT TEST MODE KPI computation. Sample command is as
 * lowi_test -rtm 1 -td 1000 -gbw 2 -kdm 255 -r /data/rtt.xml
 * where -rtm is abreviated of RTT TEST MODE.
 *
 * STEP-1 : Write all per frame data into DOT CSV file
 * STEP-2 : Create lowi_cmd->post_process_info.node_cache while
 *            parsing the initial input xml file onward referred
 *            as ap_node_cache throught description.
 * STEP-3 : Cache each column data lowi_ap_res.csv of into all_meas_db.
 * STEP-4 : Update fields of ap_node_cache from all_meas_db and from cmd params.
 * STEP-5 : Prepare per burst db (burst_map) from all_meas_db.
 * STEP-6 : Compute RTT/DISTANCE/CEP/P2P stats from ap_node_cache for all meas.
 * STEP-7 : Prepare ap_node_cache from per burst.map.
 * STEP-8 : Compute RTT/DISTANCE/CEP/P2P stats from ap_node_cache for per burst.
 * STEP-9 : Update the Per Burst RTT Final value to Same Sequence no
              based row's data in all_meas_db.
 * STEP-10: Repopen the DOT CSV file and rewrite the whole row data from
 *            all_meas_db. we need to do this step because initially we d'not
 *            have per burst/per seq no based RTT Final value which is only
 *            acheived in STEP-7.
 */
void lowi_calculate_kpi(const char* path)
{

  if (!lowi_cmd )
    return;
  if (lowi_cmd->cmd != LOWI_RTS_CTS_SCAN)
    return;
  if (!lowi_cmd->kpi_mask)
  {
    QUIPC_DBG_ERROR("\n Kpi stat is not enabled, pass -kdm 1 in cmd line");
    return;
  }

  csv_row_db all_meas_db;
  per_burst_map burst_map;

  vector <LOWIPostProcessNode> &node_cache =
       lowi_cmd->post_process_info.node_cache;
  /* read data from csv files and stored it into the all_meas_db */
  lowi_read_csv_file(all_meas_db, path);
  /* Update XML based ap_node_cahce from csv db aka all_meas_db
   * and from passed global command line parameters
   */
  lowi_update_node_cache(all_meas_db, node_cache);
  /* Create the per burst data from all meas dict to per burst map */
  lowi_create_per_burst_map(all_meas_db, burst_map);
  /* Process Raw data from node_cahce */
  lowi_process_raw_data(node_cache);
  /* Process per burst data from burst_map */
  lowi_process_per_burst_map(burst_map);
  /* Calculate per burst rtt mean and update it for all sequnce no
   * into all meas dict
   */
  lowi_update_burst_rtt_in_all_meas_dict(all_meas_db, burst_map);
  lowi_update_csv_file(path, all_meas_db);
}

/*=============================================================================
 * main
 *
 * Function description:
 *   The entry point to this LOWI test process.
 *
 * Parameters: Number of arguments (argc) and the arguments (argv[]).
 *
 * Return value: Process exit code
 ============================================================================*/
int main(int argc, char *argv[])
{
  //int (*scan_func)(const uint32) = NULL;
  lowi_test_func scan_func = NULL;

  // zero initialize the data structure
  memset (&scan_stats, 0, sizeof (scan_stats));

  log_time ();
  // Register signal handler
  signal(SIGHUP, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGILL, signal_handler);
  signal(SIGTRAP, signal_handler);
  signal(SIGABRT, signal_handler);
  signal(SIGIOT, signal_handler);
  signal(SIGBUS, signal_handler);
  signal(SIGFPE, signal_handler);
  signal(SIGPIPE, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGKILL, signal_handler);
  signal(SIGSTOP, signal_handler);
  signal(SIGTSTP, signal_handler);
  signal(SIGALRM, signal_handler);
  signal(NSIG, signal_handler);

  lowi_test_init();

  // Initialize lowi wrapper
  if (0 != lowi_wrapper_init (&lowi_test_response_callback) )
  {
    // Failed to init lowi wrapper, exit
    fprintf(stderr, "Failed to init lowi_wrapper\n");
    lowi_wrapper_destroy ();
    return 0;
  }


  // Retrieve the lowi_test command from the cmd line
  lowi_cmd = lowi_get_cmd(argc, argv);

  if (lowi_cmd != NULL)
  {
    /* This is to handle case where user hs only provided
      -gbw(ie tx bw) not the -grxbw(rx bw) */
    if ((lowi_cmd->req_tx_bw != -1) && (lowi_cmd->req_rx_bw == -1))
      lowi_cmd->req_rx_bw = lowi_cmd->req_tx_bw;

    if(lowi_cmd->reportType_cmdline != -1)
    {
      lowi_cmd->reportType = (uint32)lowi_cmd->reportType_cmdline;
    }

    for ( uint32 i = 0 ; i < lowi_cmd->rttNodes.getNumOfElements(); i++)
    {
      if (lowi_cmd->req_tx_bw != -1)
      {
        lowi_cmd->rttNodes[i].bandwidth = (enum eRangingBandwidth) lowi_cmd->req_tx_bw;
      }
      lowi_cmd->rttNodes[i].reportType = lowi_cmd->reportType;
      lowi_cmd->rttNodes[i].interface = lowi_cmd->interface;
    }

    /* This is for rtt test mode handling ie
     * just parse the csv file and then just
     * build data structure and compuet rtt
     * KPI and simply return after that.
     */
    if (lowi_cmd->rtt_test_mode)
    {
      goto out;
    }

    if ((lowi_cmd->cmd != LOWI_CONFIG_REQ) &&
        (lowi_cmd->cmd != LOWI_SET_LCI) &&
        (lowi_cmd->cmd != LOWI_SET_LCR))
    {
      // Request lowi wrapper for the driver capabilities. lowi_test does not use
      // the capabilities as of now but exercises the API
      lowi_queue_capabilities_req (lowi_cmd->interface);
    }

    switch (lowi_cmd->cmd)
    {
    case LOWI_BOTH_SCAN:
      /* --------------------------------------------------------------
      ** DISCOVERY SCAN FOLLOWED BY RTS/CTS SCAN SECTION
      ** ------------------------------------------------------------*/
      {
        rtt_scan_cmd = *lowi_cmd;
        break;
      }
    case LOWI_RTS_CTS_SCAN:
      /* --------------------------------------------------------------
      ** RANGING SCAN SECTION
      ** ------------------------------------------------------------*/
      rtt_scan_cmd = *lowi_cmd;
      if (prepareRttParam (&rtt_scan_cmd, lowi_test.seq_no) == 0)
      {
        fprintf(stderr, "Incorrect AP List. Num APs = %d",
                lowi_cmd->rttNodes.getNumOfElements());
        break;
      }
      break;
    default:
      break;
    }
    scan_func = lowi_test_function [lowi_cmd->cmd];
    LOWI_TEST_REQ_WAKE_LOCK;
    do
    {
      if (scan_func)
      {
        scan_func(lowi_test.seq_no);
      }
      lowi_test.seq_no++;
      if (lowi_test.seq_no > lowi_cmd->num_requests)
      {
        break;
      }
      lowi_test_start_timer(lowi_cmd->delay);
      lowi_test_wait(lowi_cmd->delay);
    } while (1);
    LOWI_TEST_REL_WAKE_LOCK;
  }

out:
  if (lowi_test.kpi_log_fp)
  {
    fclose(lowi_test.kpi_log_fp);
    lowi_test.kpi_log_fp = NULL;
  }

  if (lowi_cmd && !lowi_cmd->kpi_fs_mask)
  {
    remove(LOWI_KPI_LOG_FILE);
  }

  lowi_wrapper_destroy ();
  lowi_test_exit ();

  return 0;
}
