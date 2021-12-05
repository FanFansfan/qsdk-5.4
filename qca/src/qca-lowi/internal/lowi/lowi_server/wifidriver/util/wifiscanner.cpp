/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                  QuIPC Wireless Lan Scan Service Core
GENERAL DESCRIPTION
   This file contains functions which interface with WLAN drivers

Copyright (c) 2010-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
All Rights Reserved.
Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#define LOG_NDEBUG 0

#include <assert.h>
#include <base_util/time_routines.h>
// internal header files
#include <lowi_server/lowi_log.h>
#include "lowi_time.h"
#include "common/lowi_utils.h"
#include "lowi_measurement_result.h"
#include "lowi_internal_const.h"
#include "wifiscanner.h"
#include "lowi_diag_log.h"
#include "wifiscanner.h"

#undef LOG_TAG
#define LOG_TAG "LOWI-Scan"

using namespace qc_loc_fw;

/** General coding guidelines and conventions used */
/* Data types should be prepended by a letter which clearly indicates their data type */
/*
Enum                    e_
uint8   Unsigned char   u_
int8    Signed char     b_
uint16  Unsigned short  w_
int16   Signed short    x_
uint32  Unsigned long   q_
int32   Signed long     l_
uint64  Unsigned long long      t_
int64   Signed long long        r_
FLT     Float   f_
DBL     Double  d_
Structure       z_
Pointer p_  --> i.e. Pointer to int32 should be pl_xxxx. Pointer to f should be pf_ etc..
Boolean u_ or b_
*********************/

/* Cache of wireless interfaces */
//struct wireless_iface* interface_cache = NULL;
//struct rtnl_handle      rth_struct;

#define MAX_WPA_IE_LEN 40
#define VENDOR_SPECIFIC_IE 0xdd
#define MSAP_ADVT_IND_IE 0x18 /* MSAP advertisement indicator */
#define RSN_IE 0x30

// Defines and variables used by NL scan
extern int WipsScanUsingNL(char * results_buf_ptr,int cached, int timeout_val,
    int* pFreq, int num_of_freq, LOWIRequest* request);
extern int WipsSendFineTimeMeasurementReport(uint8* frameBody,
                                             uint32 frameLen,
                                             uint32 freq,
                                             uint8 sourceMac[BSSID_SIZE],
                                             uint8 selfMac[BSSID_SIZE]);
extern int WipsSendNeighborReportRequest(uint8* frameBody,
                                         uint32 frameLen,
                                         uint32 freq,
                                         uint8 sourceMac[BSSID_SIZE],
                                         uint8 selfMac[BSSID_SIZE]);
extern int WipsSendActionFrame(uint8* frameBody,
                               uint32 frameLen,
                               uint32 freq,
                               uint8 sourceMac[BSSID_SIZE],
                               uint8 selfMac[BSSID_SIZE]);

#define WLAN_CAPABILITY_PRIVACY        (1<<4)
#define ASSERT assert
LOWIMeasurementResult*  ptr_to_xchk = NULL;
uint32                  max_meas_age_sec_x=0;
uint64                  wipsiw_scan_req_time;

static pthread_mutex_t sWlanScanDoneEventMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  sWlanScanDoneEventCond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t sWlanScanInProgressMutex= PTHREAD_MUTEX_INITIALIZER;

/*=============================================================================================
 * Function description:
 *   Function to insert the next measurement record into the passive scan result data
 *   structure
 *
 * Parameters:
 *   void*: pointer to the scan results container class(LOWIMeasurementResult), passed in the request
 *   int32: Age - In units of 1 milli-second, -1 means info not available
 *   LOWIScanMeasurement*: Pointer to the AP data
 *
 * Return value:
 *    bool: true for success, false otherwise
 =============================================================================================*/
bool lowi_insert_record
(
  void* results_buf_ptr,
  int32  bss_age_msec,
  LOWIScanMeasurement* p_ap_scan_res
)
{
  bool retVal = false;

  if (NULL == p_ap_scan_res)
  {
    LOWI_LOG_DBG ("%s, NULL Scan data for AP", __FUNCTION__);
    return retVal;
  }
  int32 meas_time_delta = 0;
  //results_buf_ptr is the buffer allocated by iwss_proc_iwmm_req_passive_scan
  //until tested completely, the ptr to that buf is also stored in ptr_to_xchck
  //so do an assertion to ensure that callbacks are working correctly.

  LOWIMeasurementResult* p_wlan_meas =
                  (LOWIMeasurementResult*)results_buf_ptr;

  ASSERT(p_wlan_meas == ptr_to_xchk);


  if (max_meas_age_sec_x > 0)
  {
    /* Compare in msec unit. Convert each variable into msec */
    /* Make sure that the measurement is found after the scan request OR
    ** within reasonable age in the past from the scan request time */
    uint64 meas_time = lowi_get_time_from_boot() - bss_age_msec;

    /* Compute meas time delta with respect to scan request time */
    if (meas_time > wipsiw_scan_req_time)
    {
      meas_time_delta = meas_time - wipsiw_scan_req_time;
    }
    else
    {
      meas_time_delta = wipsiw_scan_req_time - meas_time;
      meas_time_delta *= -1;
    }

    if ((meas_time + (max_meas_age_sec_x*1000)) < wipsiw_scan_req_time)
    {
      LOWI_LOG_DBG ("Filtered out AP %d age %lu msec older than %d msecs (delta %d ms)\n",
                     p_wlan_meas->scanMeasurements.getNumOfElements(),(unsigned long)bss_age_msec, (max_meas_age_sec_x*1000),
                     meas_time_delta);
      return retVal;
    }
  }

  if (p_wlan_meas->scanMeasurements.getNumOfElements() == NUM_MAX_BSSIDS )
  {
     LOWI_LOG_VERB ("Exceeds maximum measurement of NUM_MAX_BSSIDS, discard\n");
     return retVal;
  }

  p_wlan_meas->scanMeasurements.push_back (p_ap_scan_res);
  return true;
}

/*=============================================================================================
 * Function description:
 *   Function to finalize packaging the passive scan result using NL driver.
 *
 * Parameters:
 *   results_buf_ptr: pointer to the passive scan result
 *
 * Return value:
 *    None
 =============================================================================================*/
void lowi_close_record(void * results_buf_ptr)
{
  LOWIMeasurementResult* p_wlan_meas = (LOWIMeasurementResult*)results_buf_ptr;

  //Handle the scenario, where the record has been closed already.
  if (NULL == ptr_to_xchk)
  {
    LOWI_LOG_ERROR("Closed record already");
    return ;
  }
  ASSERT(p_wlan_meas == ptr_to_xchk);

  p_wlan_meas->scanStatus = LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
  if (p_wlan_meas->scanMeasurements.getNumOfElements() > 0)
  {
    p_wlan_meas->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
  }

  // log the scan results through diag interface
  LOWIDiagLog::Log(p_wlan_meas);

  // Output wifi scan record as before
  LOWI_LOG_INFO ("%s:Scan done in % " PRIu64 ""
                 "ms, %u APs in scan results", __FUNCTION__,
                 (lowi_get_time_from_boot() - wipsiw_scan_req_time),
                 p_wlan_meas->scanMeasurements.getNumOfElements());
  unsigned int ap_index = 0;

  LOWIScanMeasurement* p_ap_meas = NULL;
  for (ap_index = 0; ap_index < p_wlan_meas->scanMeasurements.getNumOfElements(); ap_index++)
  {

    p_ap_meas = p_wlan_meas->scanMeasurements [ap_index];
    LOWI_LOG_VERB ("%s, BSSID[%d]: " LOWI_MACADDR_FMT ", RSSI = %d, AddInfo 0x%" PRIX64 " age = %d ms, Freq = %d",
                    __FUNCTION__, ap_index,
                    LOWI_MACADDR(p_ap_meas->bssid),
                    (int32) p_ap_meas->measurementsInfo[0]->rssi,
                    p_ap_meas->measAdditionalInfoMask,
                    p_ap_meas->measurementsInfo[0]->meas_age,
                    (uint32) p_ap_meas->frequency);
  }

  pthread_mutex_lock(&sWlanScanDoneEventMutex);
  pthread_cond_signal(&sWlanScanDoneEventCond);
  ptr_to_xchk = NULL; //Set this pointer to NULL - so that the caller
                      // knows that the function is done!!
  pthread_mutex_unlock(&sWlanScanDoneEventMutex);
}

void lowi_reset_records(void * results_buf_ptr)
{

  LOWIMeasurementResult* p_wlan_meas =
                  (LOWIMeasurementResult*)results_buf_ptr;

  //Handle the scenario, where the record has been closed already.
  if (NULL == ptr_to_xchk)
  {
    LOWI_LOG_ERROR("Closed record already");
    return ;
  }
  ASSERT(p_wlan_meas == ptr_to_xchk);
  p_wlan_meas->scanMeasurements.flush();
}

/*=============================================================================================
 * Function description:
 *   Function with processes IWMM passive scan request with fresh WIFI passive scan measurement
 *   with NL driver.
 *
 * Parameters:
 *   cached: indidates whether to request passive scan or fresh scan
 *   max_meas_age_sec: max age of the measurement for cached scan to be returned
 *   timeout_val: Time out value
 *   pRetVal: Pointer to the ret value
 *   pFreq: pointer to the frequency's that needs to be scanned.
 *   num_of_freq: Number of frequency's that needs to be scanned.
 *   LOWIRequest* Pointer to the LOWIRequest
 *
 * Return value:
 *    Non-NULL : pointer to parsed scan result. note the memory is allocated with QUIPC_MALLOC
 *    NULL : failure
 =============================================================================================*/
static const LOWIMeasurementResult* lowi_proc_iwmm_req_passive_scan_nl (
                                                const int cached,
                                                const uint32 max_meas_age_sec,
                                                int timeout_val,
                                                int* pRetVal,
                                                int* pFreq,
                                                int num_of_freq,
                                                LOWIRequest* request)
{
  int err_code;
  LOWIMeasurementResult* p_wlan_meas = NULL;


  // Note that this function is NOT reentracy safe.
  // If the same caller calls this function twice, then this will
  // run into multiple issues.
  // Waiting for a Mutex may seem too bad at this point - but in
  // reality, it comes at no performance penalty. When this Mutex
  // is unlocked, the WLAN scan would have been done and the resulting
  // results can be almost immediately obtained..(assuming that the
  // Caller is calling this function with "cached" parameter set to
  // true.
  // If the caller is calling this function with "Cached" set to FALSE,
  // anyway, this scan will wait in the queue of WLAN drivers. So waiting
  // here is no worse than waiting the queue of WLAN drivers.
  // We should however question a design, where one process is calling
  // two Scans to happen in Non-Cached mode.
  pthread_mutex_lock(&sWlanScanInProgressMutex);

  // Allocate the memory for LOWIMeasurementResult to hold the APs
  // seen in the dump callback of NL scan dump function. Also keep the
  // pointer to the LOWIMeasurementResult class as a reference to cross check
  // in every callback.

  max_meas_age_sec_x = max_meas_age_sec;

  p_wlan_meas = new (std::nothrow) LOWIMeasurementResult (false);
  if(p_wlan_meas == NULL)
  {
    LOWI_LOG_ERROR(
       "PASSIVE SCAN::: %s, error allocating memory at line %d\n",
       __func__, __LINE__);
    return NULL;
  }

  ptr_to_xchk = p_wlan_meas;

  err_code = WipsScanUsingNL((char *)p_wlan_meas,cached, timeout_val,
      pFreq, num_of_freq, request);
  *pRetVal = err_code;

  if (err_code >= 0)
  {
    // Not a enless loop. ptr_to_xchk is global variable,
    // updates in a callback.
    while (ptr_to_xchk != NULL)
    {
      pthread_mutex_lock(&sWlanScanDoneEventMutex);
      pthread_cond_wait(&sWlanScanDoneEventCond, &sWlanScanDoneEventMutex);
      pthread_mutex_unlock(&sWlanScanDoneEventMutex);
    }
  }
  pthread_mutex_unlock(&sWlanScanInProgressMutex);
  return p_wlan_meas;
}

LOWIMeasurementResult*
LOWIWifiScanner::lowi_proc_req_passive_scan_with_live_meas (const int cached,
                                                            const uint32 max_scan_age_sec,
                                                            const uint32 max_meas_age_sec,
                                                            int timeout,
                                                            int* pRetVal,
                                                            int* pFreq,
                                                            int num_of_freq,
                                                            int* frameArrived,
                                                            LOWIRequest* request)
{
  int result = 1;

  const uint64 max_scan_age_usec = (uint64)max_scan_age_sec * 1000000;
  LOWIMeasurementResult* ptr_measurement = NULL;

  /* Clear all Frame Storage before we begin */
  memset(&wlanFrameStore, 0, sizeof(wlanFrameStore));
  *frameArrived = 0;

  ptr_measurement = (LOWIMeasurementResult*)lowi_proc_iwmm_req_passive_scan_nl(
      cached, max_meas_age_sec, timeout, pRetVal, pFreq, num_of_freq, request);

  if(NULL == ptr_measurement)
  {
    result = 3;
  }
  else
  {
    result = 0;
  }

  do
  {
    unsigned int i;
    // system time is a dangerous concept to use, but I have to follow
    // what is defined in the wifiscanner interface, for now
    boolean lowest_age_valid = FALSE;
    uint64 lowest_age_usec = 0;
    boolean scan_again = FALSE;

    if (cached == 0)
    {
      /* NO Worry about caching */
      break;
    }
    if(NULL == ptr_measurement)
    {
      result = 2;
      break;
    }

    for(i = 0; i < ptr_measurement->scanMeasurements.getNumOfElements(); ++i)
    {
      LOWIScanMeasurement* ptr_ap = ptr_measurement->scanMeasurements [i];

      if (0 <= ptr_ap->measurementsInfo[0]->meas_age)
      {
        uint64 age_usec = ptr_ap->measurementsInfo[0]->meas_age * 1000;
        LOWI_LOG_VERB("Cached scan result, age (%lu)\n", age_usec);

        if(FALSE == lowest_age_valid)
        {
          lowest_age_valid = TRUE;
          lowest_age_usec = age_usec;
        }
        else if (age_usec < lowest_age_usec)
        {
          lowest_age_usec = age_usec;
          LOWI_LOG_VERB ("Cached scan result, reset lowest age (%lu)\n", age_usec);
        }
        else
        {
          // age is valid and larger than lowest_age_usec, skip
        }
      }
      else if(-1 == ptr_ap->measurementsInfo[0]->meas_age)
      {
        // skip the AP whose age is not present
      }
      else
      {
         LOWI_LOG_ERROR("Cached scan result, AP has invalid age (%d)\n", ptr_ap->measurementsInfo[0]->meas_age);
      }
    }

    if(TRUE == lowest_age_valid)
    {
      if(lowest_age_usec < max_scan_age_usec)
      {
        // the cached scan result is fresh enough, go
        scan_again = FALSE;
        LOWI_LOG_DBG("Cached scan result is still fresh (%lu)\n", lowest_age_usec);
      }
      else
      {
        // the cached scan result is stale, rescan
        scan_again = TRUE;
        LOWI_LOG_DBG("Cached scan result - stale (%lu)\n", lowest_age_usec);
      }
    }
    else
    {
      // age is not valid. trigger another scan
      scan_again = TRUE;
      LOWI_LOG_DBG("Cached scan, invalid timestamp, scan again\n");
    }

    if(TRUE == scan_again)
    {
      if ( (NULL == pFreq) && (0 == num_of_freq) )
      {
        // Fall back to a fresh scan is not required
        LOWI_LOG_INFO ("No input freq.Cannot do fresh scan,"
            " cached scan failed");
      }
      else
      {
        for (unsigned int ii = 0;
             ii < ptr_measurement->scanMeasurements.getNumOfElements();
             ++ii)
        {
          delete ptr_measurement->scanMeasurements[ii];
        }
        delete ptr_measurement;

        // scan without cached result
        LOWI_LOG_DBG("Scan again with timeout of %d\n", timeout);
        ptr_measurement =
            (LOWIMeasurementResult*) lowi_proc_iwmm_req_passive_scan_nl(
            0, max_meas_age_sec, timeout,
            pRetVal, pFreq, num_of_freq, request);

        if(NULL == ptr_measurement)
        {
          result = 3;
          break;
        }
      }
    }

    result = 0;
  } while(0);

  if(0 != result)
  {
     LOWI_LOG_ERROR("Scan failed: %d\n", result);
  }

  if (wlanFrameStore.numFrames)
  {
    LOWI_LOG_DBG("%s - WLAN Frames to be parsed\n", __FUNCTION__);
    *frameArrived = 1;
  }
  else
  {
    LOWI_LOG_DBG("%s - No WLAN Frames to be parsed\n", __FUNCTION__);
  }

  return ptr_measurement;
}

int lowi_send_action_frame(uint8* frameBody,
                           uint32 frameLen,
                           uint32 freq,
                           uint8 sourceMac[BSSID_SIZE],
                           uint8 selfMac[BSSID_SIZE])
{
  return WipsSendActionFrame(frameBody, frameLen, freq, sourceMac, selfMac);
}


