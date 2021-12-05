/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Scan Measurement

GENERAL DESCRIPTION
  This file contains the implementation of LOWIScanMeasurement

  Copyright (c) 2012,2016-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <base_util/log.h>

#include <inc/lowi_scan_measurement.h>

using namespace qc_loc_fw;
const char* const LOWIScanMeasurement::TAG = "LOWIScanMeasurement";

const char* const LOWIFullBeaconScanMeasurement::TAG = "LOWIFullBeaconScanMeasurement";

#define LOWI_LOC_IE_PRINT_LEN_MAX 100

LOWICFRCIRInfo::LOWICFRCIRInfo()
{
  len = 0;
  data = NULL;
}

LOWICFRCIRInfo::LOWICFRCIRInfo(const LOWICFRCIRInfo &rhs)
: len(rhs.len), data(NULL)
{
  if ( (0 != len) && (NULL != rhs.data) )
  {
    data =  new (std::nothrow) uint8 [len];
    if (NULL != data)
    {
      memcpy (data, rhs.data, len);
    }
  }
}

LOWICFRCIRInfo::~LOWICFRCIRInfo()
{
  if (NULL != data)
  {
    delete[] data;
    data = NULL;
  }
}
////////////////////////
/// LOWIMeasurementInfo
////////////////////////
LOWIMeasurementInfo::LOWIMeasurementInfo()
{
  meas_age = -1;
  rtt_ps   = 0;
  rtt      = 0;
  rssi     = 0;
  rtt_timestamp  = 0;
  rssi_timestamp = 0;

  tx_bitrate = 0;
  tx_preamble = 0;
  tx_nss = 0;
  tx_bw = 0;
  tx_mcsIdx = 0;

  rx_bitrate = 0;
  rx_preamble = 0;
  rx_nss = 0;
  rx_bw = 0;
  rx_mcsIdx = 0;
  tx_chain_no = -1;
  rx_chain_no = -1;
  cfrcirInfo = NULL;
}

////////////////////
// LOWIScanMeasurement
////////////////////
LOWIScanMeasurement::LOWIScanMeasurement ()
  : msapInfo(NULL), lciInfo(NULL), lcrInfo(NULL), aoaMeasurement(NULL),
    peerOEM (LOWI_PEER_OEM_UNKNOWN)
{
  // Default values
  frequency                  = 0;
  memset(&band_center_freq1, 0, sizeof(band_center_freq1));
  band_center_freq2          = 0;
  info                       = 0;
  tsfDelta                   = 0;
  ranging_features_supported = 0;
  rttMeasTimeStamp           = 0;
  associatedToAp             = false;
  isSecure                   = false;
  type                       = NODE_TYPE_UNKNOWN;
  rttType                    = RTT1_RANGING;
  cellPowerLimitdBm          = CELL_POWER_NOT_FOUND;
  indoor_outdoor             =  ' ';
  targetStatus               = LOWI_TARGET_STATUS_FAILURE;
  memset(country_code, 0, LOWI_COUNTRY_CODE_LEN);
  measurementNum                  = 0;
  beaconPeriod                    = 0;
  beaconCaps                      = 0;
  beaconStatus                    = 0;
  num_frames_attempted            = 0;
  actual_burst_duration           = 0;
  negotiated_num_frames_per_burst = 0;
  negotiated_burst_exp            = 0;
  retry_after_duration            = 0;
  location_features_supported     = 0;
  phyMode                         = LOWI_PHY_MODE_UNKNOWN;
  encryptionType                  = LOWI_ENCRYPTION_TYPE_UNKNOWN;
  maxTxRate                       = 0;
  targetTSF                       = 0;
  measAdditionalInfoMask          = 0;
}

LOWIScanMeasurement::~LOWIScanMeasurement ()
{
  for (unsigned int ii = 0; ii < measurementsInfo.getNumOfElements();
      ++ii)
  {
    if(measurementsInfo[ii]->cfrcirInfo)
    {
      delete  measurementsInfo[ii]->cfrcirInfo;
    }
    delete measurementsInfo[ii];
  }

  delete msapInfo;
  delete lciInfo;
  delete lcrInfo;
  delete aoaMeasurement;
}

LOWILocationIE::LOWILocationIE()
{
  id = 0;
  len = 0;
  locData = NULL;
}

LOWILocationIE::LOWILocationIE(const LOWILocationIE &rhs)
: id(rhs.id), len(rhs.len), locData(NULL)
{
  if ( (0 != len) && (NULL != rhs.locData) )
  {
    locData =  new (std::nothrow) uint8 [len];
    if (NULL != locData)
    {
      memcpy (locData, rhs.locData, len);
    }
  }
}

LOWILocationIE::~LOWILocationIE()
{
  if (NULL != locData)
  {
    delete[] locData;
    locData = NULL;
  }
}

void LOWILocationIE::printLocationIE ()
{
  char str [LOWI_LOC_IE_PRINT_LEN_MAX+1] = {0};
  uint8 print_len = len;

  // For IE_ID not 0, need to do String conversion
  // double the print length
  if (0 != id)
  {
    print_len *= 2;  // 2 char to print each byte
  }

  /* Just want to copy up to LOWI_LOC_IE_PRINT_LEN_MAX; cap it if it's more */
  if (print_len > LOWI_LOC_IE_PRINT_LEN_MAX)
  {
    print_len = LOWI_LOC_IE_PRINT_LEN_MAX;
  }

  /* Go through each character and if it's non-ASCII, convert it to Ascii */
  for (int ii = 0, jj = 0; ii < len && ii < print_len && jj < print_len; ++ii)
  {
    // For IE_ID 0 (SSID), no need of String conversion
    if (0 == id)
    {
      str [ii] = locData [ii];
      /* If it's not printable character */
      if (!isprint(str[ii]))
      {
        str[ii] = '_';
      }
    }
    else
    {
      snprintf (str+jj, print_len-jj+1, "%02x", locData [ii]);
      jj += 2;
    }
  }
  str [print_len] = '\0';

  log_verbose("LOWILocationIE", "%s: id = %d, len = %d, ie = %s\n",
                __FUNCTION__, id, len, str);
}

LOWIScanMeasurement::LOWIScanMeasurement(const LOWIScanMeasurement& rhs)
{
  this->msapInfo = NULL;
  this->lciInfo  = NULL;
  this->lcrInfo  = NULL;
  this->aoaMeasurement = NULL;
  /* Use the '=' Operator to initialize new object */
  *this = rhs;
}

LOWIScanMeasurement& LOWIScanMeasurement::operator=( const LOWIScanMeasurement& rhs )
{
  if (this != &rhs)
  {
    for (unsigned int ii = 0; ii < measurementsInfo.getNumOfElements();
        ++ii)
    {
      if(measurementsInfo[ii]->cfrcirInfo)
      {
        delete  measurementsInfo[ii]->cfrcirInfo;
      }
      delete measurementsInfo[ii];
    }

    this->measurementsInfo.flush();
    this->measurementNum = 0;
    bssid = rhs.bssid;
    frequency = rhs.frequency;
    memcpy(&band_center_freq1, &rhs.band_center_freq1, sizeof(band_center_freq1));
    band_center_freq2 = rhs.band_center_freq2;
    associatedToAp    = rhs.associatedToAp;
    rttMeasTimeStamp  = rhs.rttMeasTimeStamp;
    info = rhs.info;
    tsfDelta = rhs.tsfDelta;
    ranging_features_supported = rhs.ranging_features_supported;
    isSecure = rhs.isSecure;
    type = rhs.type;
    rttType = rhs.rttType;
    measAdditionalInfoMask = rhs.measAdditionalInfoMask;
    // Do a deep copy for the measurementsInfo
    unsigned int size = rhs.measurementsInfo.getNumOfElements();
    // The vector might be empty
    if (0 != size)
    {
      for (unsigned int ii = 0; ii < size; ++ii)
      {
        LOWIMeasurementInfo* info = new (std::nothrow) LOWIMeasurementInfo();
        if (NULL != info)
        {
          info->meas_age = rhs.measurementsInfo[ii]->meas_age;
          info->rssi = rhs.measurementsInfo[ii]->rssi;
          info->rssi_timestamp = rhs.measurementsInfo[ii]->rssi_timestamp;
          info->rtt_timestamp = rhs.measurementsInfo[ii]->rtt_timestamp;
          if(rhs.measurementsInfo[ii]->cfrcirInfo)
          {
            info->cfrcirInfo = new (std::nothrow) LOWICFRCIRInfo(*(rhs.measurementsInfo[ii]->cfrcirInfo));
          }
          measurementsInfo.push_back(info);
        }
        else
        {
          log_error(TAG, "Unexpected - Failed to copy LOWIMeasurementInfo");
        }
      }
    }

    ssid = rhs.ssid;
    delete msapInfo;
    msapInfo = NULL;
    if (NULL != rhs.msapInfo)
    {
      msapInfo = new (std::nothrow) LOWIMsapInfo;
      if (NULL != msapInfo)
      {
        msapInfo->protocolVersion = rhs.msapInfo->protocolVersion;
        msapInfo->serverIdx = rhs.msapInfo->serverIdx;
        msapInfo->venueHash = rhs.msapInfo->venueHash;
      }
    }
    cellPowerLimitdBm = rhs.cellPowerLimitdBm;
    measurementNum    = rhs.measurementNum;
    indoor_outdoor    = rhs.indoor_outdoor;
    targetStatus      = rhs.targetStatus;
    beaconPeriod      = rhs.beaconPeriod;
    beaconCaps        = rhs.beaconCaps;
    beaconStatus      = rhs.beaconStatus;
    ieData            = rhs.ieData;
    num_frames_attempted  = rhs.num_frames_attempted;
    actual_burst_duration = rhs.actual_burst_duration;
    negotiated_num_frames_per_burst = rhs.negotiated_num_frames_per_burst;
    retry_after_duration  = rhs.retry_after_duration;
    negotiated_burst_exp  = rhs.negotiated_burst_exp;
    memcpy(country_code, rhs.country_code, LOWI_COUNTRY_CODE_LEN);
    delete lciInfo;
    lciInfo = NULL;
    if (NULL != rhs.lciInfo)
    {
      lciInfo = new (std::nothrow) LOWILocationIE(*(rhs.lciInfo));
    }
    delete lcrInfo;
    lcrInfo = NULL;
    if (NULL != rhs.lcrInfo)
    {
      lcrInfo = new (std::nothrow) LOWILocationIE(*(rhs.lcrInfo));
    }
    location_features_supported = rhs.location_features_supported;
    phyMode                     = rhs.phyMode;
    encryptionType              = rhs.encryptionType;
    maxTxRate                   = rhs.maxTxRate;
    targetTSF                   = rhs.targetTSF;
    peerOEM                     = rhs.peerOEM;
    delete aoaMeasurement;
    aoaMeasurement = NULL;
    if (NULL != rhs.aoaMeasurement)
    {
      aoaMeasurement = new(std::nothrow) LOWIAoAResult(*(rhs.aoaMeasurement));
    }
  }
  return *this;
}

LOWIFullBeaconScanMeasurement::~LOWIFullBeaconScanMeasurement ()
{
  log_verbose (TAG, "~LOWIFullBeaconScanMeasurement");
  for (unsigned int ii = 0; ii < mLOWIIE.getNumOfElements();
      ++ii)
  {
    delete mLOWIIE[ii];
    mLOWIIE[ii] = NULL;
  }
}

