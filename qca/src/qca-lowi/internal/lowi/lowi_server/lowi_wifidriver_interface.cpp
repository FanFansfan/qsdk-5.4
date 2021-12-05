/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wifi Driver Interface

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Wifi Driver Interface

Copyright (c) 2012-2014, 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2014 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_wifidriver_interface.h>
#include "lowi_wifidriver_utils.h"
#include "wipsiw.h"
#include "lowi_wifi_hal.h"
#include "lowi_diag_log.h"
#include "lowi_internal_const.h"
#include "wifiscanner.h"
#include "lowi_utils_extn.h"
#include "lowi_strings.h"

#define BUF_LEN 25


#define LOWI_SELECT_TIMEOUT_NORMAL 10
#define LOWI_SELECT_TIMEOUT_NEVER -1
#define MAX_CACHED_SCAN_AGE_SEC 30

// Structure containing supported channels
static s_ch_info supportedChannels;

using namespace qc_loc_fw;


const char * const LOWIWifiDriverInterface::TAG = "LOWIWifiDriverInterface";
/** Strings used for debug purposes */
const char * LOWIWifiDriverInterface::modeStr[LOWIWifiDriverInterface::REQUEST_SCAN+1] =
  {
    "DISCOVERY_SCAN",
    "RANGING_SCAN",
    "BACKGROUND_SCAN",
    "REQUEST_SCAN"
  };

uint16 LOWIWifiDriverInterface::mCurrTargetHW = TARGET_TYPE_UNKNOWN;

LOWIWifiDriverInterface::LOWIWifiDriverInterface (ConfigFile* config)
: mConfig (config), mMsgQueue (NULL), mMutex (NULL)
{
  log_verbose (TAG, "LOWIWifiDriverInterface ()");
  if (NULL == mConfig)
  {
    log_error (TAG, "Handle to Config file is null");
  }

  mMutex = Mutex::createInstance("LOWIWifiDriverInterface",false);
  if(0 == mMutex)
  {
    log_error(TAG, "Cannot allocate mutex for LOWIWifiDriverInterface");
  }

  // Create the blocking Queue
  mMsgQueue = BlockingQueue::createInstance ("LOWIWifiDriverInterfaceQ");
  if (NULL == mMsgQueue)
  {
    log_error (TAG, "Unable to create Message Queue");
  }

  //set the default values as for external and fake wifi driver
  mCapabilities.supportedCapablities = LOWI_DISCOVERY_SCAN_SUPPORTED;

  supportedChannels.num_2g_ch = 0;
  supportedChannels.num_5g_ch = 0;
}

LOWIWifiDriverInterface::~LOWIWifiDriverInterface ()
{
  log_verbose (TAG, "~LOWIWifiDriverInterface ()");
  LOWIWifiDriverUtils::cleanupWifiCapability ();
  mMsgQueue->close();
  delete mMsgQueue;
  delete mMutex;
}

LOWIRTTInfo*
LOWIWifiDriverInterface::processRTT (vector <LOWIScanMeasurement*> & /* v */)
{
  // TODO - Implement the function later
  return NULL;
}

void LOWIWifiDriverInterface::configCapabilities ( LOWICapabilities& configCap )
{
  mCapabilities.rangingScanSupported = (mCapabilities.rangingScanSupported && configCap.rangingScanSupported);
  mCapabilities.discoveryScanSupported = (mCapabilities.discoveryScanSupported && configCap.discoveryScanSupported);
  mCapabilities.activeScanSupported = (mCapabilities.activeScanSupported && configCap.activeScanSupported);
}

void LOWIWifiDriverInterface::setNewRequest(const LOWIRequest* r, eListenMode /* mode */)
{
  AutoLock autolock(mMutex);
  mReq = r;
}

int LOWIWifiDriverInterface::unBlock (eListenMode mode)
{
  log_verbose (TAG, "unBlock Mode = %s", LOWI_TO_STRING( mode, modeStr ));
  AutoLock autolock(mMutex);
  if (mode == this->DISCOVERY_SCAN)
  {
    return Wips_nl_shutdown_communication();
  }
  else if (mode == BACKGROUND_SCAN)
  {
      return lowi_nl_unblock();
  }
  else
  {
    long event = 1;
    mMsgQueue->push ((void*) event);
    return 1; // Indicate that 1 byte is written (operation success)
  }
}

int LOWIWifiDriverInterface::terminate (eListenMode mode)
{
  return unBlock(mode);
}

int LOWIWifiDriverInterface::initFileDescriptor (eListenMode mode)
{
  log_verbose (TAG, "initFileDescriptor Mode = %s", LOWI_TO_STRING( mode, modeStr ));
  AutoLock autolock(mMutex);

  if (mode == DISCOVERY_SCAN)
  {
    lowi_gen_nl_drv_open();
    return Wips_nl_init_pipe();
  }
  if (mode == BACKGROUND_SCAN)
  {
    //Init WifiHal layer
    lowiWifiHalInit();
    return lowi_nl_init_pipe();
  }
  else
  {
    log_verbose (TAG, "initFileDescriptor not supported in RANGING mode");
    return 0;
  }
}

int LOWIWifiDriverInterface::closeFileDescriptor (eListenMode mode)
{
  log_verbose (TAG, "closeFileDescriptor Mode = %s", LOWI_TO_STRING( mode, modeStr ));
  AutoLock autolock(mMutex);

  if (mode == DISCOVERY_SCAN)
  {
    lowi_gen_nl_drv_close();
    return Wips_nl_close_pipe();
  }

  if (mode == BACKGROUND_SCAN)
  {
    // release resources in wifihal
    lowiWifiHalCleanup();
    return lowi_nl_close_pipe();
  }
  else
  {
    log_verbose (TAG, "closeFileDescriptor not supported in RANGING mode");
    return 0;
  }
}

void LOWIWifiDriverInterface::setLPExtendedBatching()
{
  mBGscanConfigFlags |= LOWI_LP_EXTENDED_BATCHING_MASK;
}

uint32 LOWIWifiDriverInterface::getLPExtendedBatching() const
{
  return mBGscanConfigFlags & LOWI_LP_EXTENDED_BATCHING_MASK;
}

uint32 LOWIWifiDriverInterface::getBGscanConfigFlags() const
{
  return mBGscanConfigFlags;
}

eWifiIntfState LOWIWifiDriverInterface::getInterfaceState(char const *intfName)
{
  return LOWIWifiDriverUtils::getInterfaceState(intfName);
}

void LOWIWifiDriverInterface::processWifiIntfStateMessage(LOWIWifiIntfStateMessage* req)
{
  do
  {
    if (NULL == req)
    {
      log_debug(TAG, "%s: Null request. Ignoring", __FUNCTION__);
      break;
    }
    eWifiIntfState wifiState = req->getIntfState();
    log_verbose(TAG, "%s: WiFi Interface Update %d", __FUNCTION__, wifiState);
    if (wifiState != INTF_RUNNING)
    {
      //Only processing INTF_RUNNING state
      log_debug(TAG, "%s: Ignoring state %d", __FUNCTION__, wifiState);
      break;
    }
    bool rangingSupported = (mCapabilities.mcVersion >= MC_DRAFT_VERSION_50);
    lowi_update_wifi_interface(rangingSupported);
  }
  while (0);
}

bool LOWIWifiDriverInterface::setDiscoveryScanType (LOWIDiscoveryScanRequest::eScanType type)
{
  bool ret = false;
  char buf[BUF_LEN];
  log_debug (TAG, "setDiscoveryScanType to %d", type);

  if (type == LOWIDiscoveryScanRequest::PASSIVE_SCAN)
  {
    strlcpy(buf, "SCAN-PASSIVE", BUF_LEN-1);
  }
  else if (type == LOWIDiscoveryScanRequest::ACTIVE_SCAN)
  {
    strlcpy(buf, "SCAN-ACTIVE", BUF_LEN-1);
  }
  else
  {
    log_debug (TAG, "Scan type other that active / passive. return");
    return ret;
  }
  return LOWIWifiDriverUtils::sendDriverCmd (buf);
}

LOWIMeasurementResult* LOWIWifiDriverInterface::getCacheMeasurements ()
{
  log_debug (TAG, "getCacheMeasurements");

  LOWIMeasurementResult* result = NULL;
  int retVal = -1;
  int frameArrived = 0;

  // Log the request through diag
  LOWIDiagLog::Log(1, MAX_CACHED_SCAN_AGE_SEC,
                   0, LOWI_SELECT_TIMEOUT_NORMAL,
                   NULL, 0);
  result =
      LOWIWifiScanner::lowi_proc_req_passive_scan_with_live_meas
      (1, MAX_CACHED_SCAN_AGE_SEC, 0, LOWI_SELECT_TIMEOUT_NORMAL,
          &retVal, NULL, 0, &frameArrived, NULL);

  if (NULL == result)
  {
    log_error (TAG, "Unable to create the cached measurement results");
  }
  else
  {
    result->request = NULL;
  }

  return result;
}

LOWIMeasurementResult* LOWIWifiDriverInterface::getMeasurements
(LOWIRequest* r, eListenMode mode)
{
  LOWIMeasurementResult* result = NULL;
  log_verbose (TAG, "getMeasurements");

  int retVal = -1001;
  int frameArrived = 0;

  if (NULL == r)
  {
    /////////////////////////////
    // Passive listening request
    /////////////////////////////
    if (LOWIWifiDriverInterface::DISCOVERY_SCAN == mode)
    {
      log_debug (TAG, "getMeasurements - Passive listening mode");

      // Log the request through diag
      LOWIDiagLog::Log(0, 0, 0, LOWI_SELECT_TIMEOUT_NEVER, NULL, 0);

      // Perform passive scan
      result =
          LOWIWifiScanner::lowi_proc_req_passive_scan_with_live_meas
          (0, 0, 0, LOWI_SELECT_TIMEOUT_NEVER, &retVal, NULL, 0, &frameArrived, r);
      if (ERR_SELECT_TERMINATED == retVal)
      {
        // No need to provide any results as the scan was terminated
          log_debug (TAG, "Scan terminated for passive listening request");
          delete result;
          result = NULL;
      }
    }
    else
    {
      log_debug (TAG, "getMeasurements RANGING mode");

      bool is_queue_closed = false;
      void * ptr = 0;
      mMsgQueue->pop (&ptr, TimeDiff(false), &is_queue_closed);

      // This means we were asked to stop listening.
      log_debug (TAG, "getMeasurements RANGING mode - unblocked");
      return NULL;
    }
  }
  else
  {
    // Check the type of request and issue the request to the
    // wifi driver accordingly
    if (LOWIRequest::DISCOVERY_SCAN == r->getRequestType ())
    {
      /////////////////////////////
      // Discovery scan request
      /////////////////////////////
      // Issue passive / active scan request to the wifi driver
      log_debug (TAG, "getMeasurements - Discovery scan request");

      if (false == mCapabilities.discoveryScanSupported)
      {
        log_error (TAG, "getMeasurements - Discovery scan request. Not supported");
        retVal = -ENOTSUP;
      }
      else
      {
        // Check the Channels on which the scan is to be performed
        LOWIDiscoveryScanRequest* req = (LOWIDiscoveryScanRequest*) r;

        bool scan_type_changed = false;

        // Check the scan type and request the driver
        if (LOWIDiscoveryScanRequest::PASSIVE_SCAN == req->getScanType())
        {
          log_debug (TAG, "True Passive scan requested."
                          " Send request to driver");
          scan_type_changed = setDiscoveryScanType(
                              LOWIDiscoveryScanRequest::PASSIVE_SCAN);
        }

        vector <LOWIChannelInfo> chanVector = req->getChannels();

        int * channelsToScan = NULL;
        unsigned char numChannels = 0;
        if (0 == chanVector.getNumOfElements())
        {
          // Request is to perform a scan on a band
          // Step 1 : Check if we have a supported channel list from kernel
          if (0 == supportedChannels.num_2g_ch &&
              0 == supportedChannels.num_5g_ch)
          {
            // We do not have the supported channel list yet.
            int err = WipsGetSupportedChannels (&supportedChannels);
            if (0 != err)
            {
              log_error (TAG, "getMeasurements - Unable to get the"
                  " supported channel list");
            }
          }

          // Step 2 : Get the final list of frequencies based on what's supported
          // by the kernel if it is available.
          // Use the default set of frequencies if the supported list is not
          // available
          channelsToScan =
              LOWIWifiDriverUtils::getSupportedFreqs (req->getBand(),
                  &supportedChannels, numChannels);
        }
        else
        {
          channelsToScan = LOWIUtils::getChannelsOrFreqs (chanVector,
              numChannels, true);
        }

        uint32 max_scan_age_sec = (uint32) req->getFallbackToleranceSec();
        uint32 max_meas_age_sec = (uint32) req->getMeasAgeFilterSec();
        int cached = 0;
        if (req->getRequestMode() == LOWIDiscoveryScanRequest::CACHE_FALLBACK)
        {
          // If it is a cache fallback mode, get the cached measurements
          // from the wifi driver
          cached = 1;
        }

        // Log the request through diag
        LOWIDiagLog::Log(cached, max_scan_age_sec, max_meas_age_sec,
            LOWI_SELECT_TIMEOUT_NORMAL, channelsToScan, numChannels);

        result =
            LOWIWifiScanner::lowi_proc_req_passive_scan_with_live_meas
            (cached, max_scan_age_sec, max_meas_age_sec,
                LOWI_SELECT_TIMEOUT_NORMAL, &retVal, channelsToScan, numChannels,
                &frameArrived, req);

        delete [] channelsToScan;

        // Check if the request was considered invalid
        if (-EINVAL == retVal)
        {
          log_error (TAG, "getMeasurements - Discovery scan request"
              " was invalid");
          if (0 == chanVector.getNumOfElements())
          {
            // It was a request to perform a scan on a band
            if (0 == supportedChannels.num_2g_ch &&
                0 == supportedChannels.num_5g_ch)
            {
              // The supported channel list was not available
              // We might have done the scan on default channels
              // The EINVAL is expected in this case.
              // We will continue to try to get the supported channel list
              // in subsequent requests.
              log_debug (TAG, "getMeasurements - Discovery scan request"
                  " the suppoorted channel list was never found");
            }
            else
            {
              // We had the supported channel list but still the request was
              // considered invalid. It's time to fetch the supported channel
              // list again. This might be because of the regulatory domain
              // change. The supported channel list will be fetched in subsequent
              // request for band scan. We will just make the list dirty now.
              supportedChannels.num_2g_ch = 0;
              supportedChannels.num_5g_ch = 0;
            }
          }
        }//if (-EINVAL == retVal)
        // Restore the scan type if it was changed
        if (true == scan_type_changed)
        {
          bool status = setDiscoveryScanType(
                                             LOWIDiscoveryScanRequest::ACTIVE_SCAN);
          log_debug (TAG, "Restored the scan type = %d", status);
          scan_type_changed = false;
        }
      }
    } // else if(DISCOVERY_SCAN == r->getRequestType())
    else if (LOWIRequest::LOWI_INTERNAL_MESSAGE == r->getRequestType())
    {
      LOWIInternalMessage *intreq = (LOWIInternalMessage*)r;
      result = new (std::nothrow) LOWIMeasurementResult;
      if (NULL == result)
      {
        log_error (TAG, "%s:Allocation failure for measurment results", __FUNCTION__);
        return NULL;
      }
      if (LOWIInternalMessage::LOWI_IMSG_WIFI_INTF_STATUS_MSG == intreq->getInternalMessageType())
      {
        log_verbose(TAG, "%s:Processing Wifi Interface Update",__FUNCTION__);
        LOWIWifiIntfStateMessage* req = (LOWIWifiIntfStateMessage*) r;
        processWifiIntfStateMessage(req);
        retVal = 0;
      }
      else
      {
        log_info (TAG, "%s: Internal message %d Not supported", __FUNCTION__,
                   intreq->getInternalMessageType());
        retVal = -ENOTSUP;
      }
    }
    else if (LOWIRequest::RANGING_SCAN == r->getRequestType ())
    {
      log_error (TAG, "%s:Ranging scan request. Not supported", __FUNCTION__);
      retVal = -ENOTSUP;
    }

  }
    /** Process any Action Frames that have arrived over the
     *  Generic Netlink socket */
    if (frameArrived)
    {
      log_verbose(TAG, "%s:Action Frames from Genl Socket",
                  __FUNCTION__);
      processWlanFrame();
    }
    else
    {
      log_verbose(TAG, "%s:No Action Frames from Genl Socket", __FUNCTION__);
    }

  log_verbose (TAG, "%s: Results are %s",
               __FUNCTION__, (result == NULL ? "NULL" : "not NULL"));
  if (NULL != result)
  {
    // As long as the scan was not terminated let's provide
    // the results even if we may have found NULL results
    // Parse the result and update the vector
    {
      result->request = r;
      {
        result->measurementTimestamp = LOWIUtils::currentTimeMs();

        setMeasScanStatus(result, retVal);
        result->scanType =
            LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
        if ((NULL != r) && (LOWIRequest::DISCOVERY_SCAN == r->getRequestType ()))
        {
          LOWIDiscoveryScanRequest* req = (LOWIDiscoveryScanRequest*) r;
          result->scanType = LOWIUtils::to_eScanTypeResponse (req->getScanType());
        }
      }
    }
  }
  return result;
}

void LOWIWifiDriverInterface::setMeasScanStatus (LOWIMeasurementResult* result, int retVal)
{

  result->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
  if (ERR_SELECT_TERMINATED == retVal)
  {
    // if it is a valid request and we got scan terminated from drivers
    // results needs to be send with proper error, other wise
    // LOWI-Controller will keep waiting for the measurements for that
    // request.
    log_debug (TAG, "%s: Select terminated for request " LOWI_REQINFO_FMT,
               __FUNCTION__, LOWI_REQINFO(result->request));
    result->scanStatus = LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
  }
  else if (-EINVAL == retVal)
  {
    log_debug (TAG, "%s:No measurements found"
               " - Request invalid", __FUNCTION__);
    result->scanStatus = LOWIResponse::SCAN_STATUS_INVALID_REQ;
  }
  else if (ERR_SELECT_TIMEOUT == retVal)
  {
    // Driver timed out
    log_debug (TAG, "%s:No measurements found"
               " Driver timed out", __FUNCTION__);
    result->scanStatus = LOWIResponse::SCAN_STATUS_DRIVER_TIMEOUT;
  }
  else if (-ENOTSUP == retVal)
  {
    log_debug (TAG, "%s:Request Not supported", __FUNCTION__);
    result->scanStatus = LOWIResponse::SCAN_STATUS_NOT_SUPPORTED;
  }
  else if (0 != retVal)
  {
    log_debug (TAG, "%s:No measurements found"
               " Err = %d", __FUNCTION__, retVal);
    result->scanStatus = LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
  }
}
