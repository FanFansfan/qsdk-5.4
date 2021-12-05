/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Utils

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Utils

  Copyright (c) 2012-2013,2016-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <base_util/log.h>

#include <base_util/postcard.h>
#include <inc/lowi_const.h>
#include <common/lowi_utils.h>
#include <inc/lowi_client.h>
#include <inc/lowi_client_receiver.h>
#include <inc/lowi_scan_measurement.h>
#include "lowi_utils_extn.h"

using namespace qc_loc_fw;


const int channelArr_2_4_ghz [] =
{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

const int freqArr_2_4_ghz [] =
{2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447,
    2452, 2457, 2462, 2467, 2472, 2484};

const int channelArr_5_ghz [] =
{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
    112, 116, 132, 136, 140, 149, 153, 157, 161, 165};

const int freqArr_5_ghz [] =
{5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540,
    5560, 5580, 5660, 5680, 5700, 5745, 5765, 5785, 5805, 5825};

const char * const LOWIUtils::TAG = "LOWIUtils";

// This macro checks if memory allocation for "r" failed.
// If so, log error and break out of for loop.
#define UTILS_BREAK_IF_NULL(r,b,s) if (NULL == r)\
      { \
        log_debug (TAG, "%s", s); \
        b = false; \
        break; \
      }

// Length of location IE data card name
#define LOCATION_IE_DATA_CARD_LEN 32

bool LOWIUtils::parseIEDataInfo
(InPostcard* const card, vector <int8> &measurements)
{
  bool retVal = true;
  log_verbose (TAG, "parseIEDataInfo");

  do
  {
    UTILS_BREAK_IF_NULL(card, retVal, "parseIEDataInfo - Argument NULL!")

    PostcardBase::UINT32 num_of_meas = 0;
    int err = card->getUInt32 ("NUM_OF_IE", num_of_meas);

    if (0 != err)
    {
      log_error(TAG, "parseIEDataInfo - Unable to extract NUM_OF_IE");
      retVal = false;
      break;
    }

    log_debug (TAG, "parseIEDataInfo - Total IE's = %u", num_of_meas);

    // For each information element, retrieve the corresponding InPostcard
    // and parse the information
    int8 ieData;
    for (uint32 ii = 0; ii < num_of_meas; ++ii)
    {
      InPostcard* inner = 0;
      if (0 == card->getCard ("IE_data_card", &inner, ii))
      {
        if (NULL == inner)
        {
          log_debug (TAG, "parseIEDataInfo - No IE_data_card found");
          break;
        }

        extractInt8(*inner, "parseIEDataInfo", "IE_DATA", ieData);
        log_debug (TAG, "parseIEDataInfo - IE_DATA(%d)", ieData);

        // Put the LOWIMeasurementInfo in the vector
        measurements.push_back (ieData);
        delete inner;
      }
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::parseLocationIEDataInfo
(InPostcard* const card, uint8 *info, uint8 len, char const *type)
{
  bool retVal = false;
  log_verbose (TAG, "parseLocationIEDataInfo");

  do
  {
    UTILS_BREAK_IF_NULL(card, retVal, "parseLocationIEDataInfo - Argument NULL!")

    // Create the appropriate card name, and parse the information
    char cardName[LOCATION_IE_DATA_CARD_LEN] = {0};
    snprintf(cardName, sizeof(cardName), "%s%s", "LOCATION_IE_DATA_CARD_", type);
    InPostcard* inner = 0;
    if (0 == card->getCard (cardName, &inner, 0))
    {
      if (NULL == inner)
      {
        log_debug (TAG, "parseLocationIEDataInfo - No LOCATION_IE_DATA_CARD found");
        break;
      }

      // extract the info field
      int length = (int)len;
      if (0 != inner->getArrayUInt8(cardName, &length, info))
      {
        log_debug(TAG, "parseLocationIEDataInfo - Unable to extract location info");
      }
      delete inner;
    }

    retVal = true;
  } while (0);
  return retVal;
}

bool LOWIUtils::parseRangingScanMeasurements
(InPostcard* const card, LOWIRangingScanMeasurement& ranging)
{
  bool retVal = true;
  log_verbose (TAG, "%s", __FUNCTION__);

  do
  {
    if (NULL == card)
    {
      log_error (TAG, "%s - Argument NULL!", __FUNCTION__);
      retVal = false;
      break;
    }

    extractUInt8 (*card, "parseRangingScanMeasurements", "MAX_BSS_IND",
                  ranging.maxBssidsIndicator);
    PostcardBase::UINT32 num = 0;
    extractUInt32 (*card, "parseRangingScanMeasurements", "NUM_COLOC_BSS",
                   num);
    uint8 temp = 0;
    extractUInt8 (*card, "parseRangingScanMeasurements", "PEER_OEM",
                  temp);
    ranging.peerOEM = LOWIUtils::to_ePeerOEM(temp);

    log_debug (TAG, "%s - MAX_BSS_IND = %u, NUM_COLOC_BSS = %u, Peer OEM = %d",
               __FUNCTION__, ranging.maxBssidsIndicator, num, temp);

    // For each BSS, retrieve the corresponding InPostcard
    // and parse the information
    for (uint32 ii = 0; ii < num; ++ii)
    {
      InPostcard* inner = 0;
      if (0 == card->getCard ("BSS_card", &inner, ii))
      {
        if (NULL == inner)
        {
          log_debug (TAG, "%s - No BSS_card found", __FUNCTION__);
          break;
        }
        LOWIMacAddress bss;
        extractBssid(*inner, bss);
        // Put the LOWIMacAddress in the vector
        ranging.colocatedBssids.push_back (bss);
        delete inner;
      }
    }
    retVal = true;
  } while (0);
  return retVal;
}

bool LOWIUtils::parseLocationIEs
(InPostcard* const card, vector <LOWILocationIE*>& lie)
{
  bool retVal = true;
  log_verbose (TAG, "%s", __FUNCTION__);

  do
  {
    if (NULL == card)
    {
      log_error (TAG, "%s - Argument NULL!", __FUNCTION__);
      retVal = false;
      break;
    }

    PostcardBase::UINT32 num_of_lie = 0;
    int err = card->getUInt32 ("NUM_OF_LIE", num_of_lie);
    if (0 != err)
    {
      log_debug (TAG, "%s - Unable to extract NUM_OF_LIE", __FUNCTION__);
      retVal = false;
      break;
    }
    log_debug (TAG, "%s - Total LIE = %u", __FUNCTION__, num_of_lie);

    // For each IE, retrieve the corresponding InPostcard
    // and parse the information
    for (uint32 ii = 0; ii < num_of_lie; ++ii)
    {
      InPostcard* inner = 0;
      if (0 == card->getCard ("LIE_card", &inner, ii))
      {
        if (NULL == inner)
        {
          log_debug (TAG, "%s - No Measurement_card found", __FUNCTION__);
          break;
        }
        LOWILocationIE * info = new (std::nothrow)LOWILocationIE;
        if (NULL == info)
        {
          log_error (TAG, "%s - Mem allocation failure!", __FUNCTION__);
          // Delete the card
          delete inner;
          retVal = false;
          break;
        }

        extractUInt8 (*inner, "parseLocationIEs", "LIE_ID", info->id);
        extractUInt8 (*inner, "parseLocationIEs", "LIE_LEN", info->len);

        // extract the info field only if len is non zero
        if (0 != info->len)
        {
          info->locData =  new (std::nothrow) uint8 [info->len];
          if (NULL != info->locData)
          {
            int length = (int)info->len;
            if (0 != inner->getArrayUInt8("LIE_ARR", &length, info->locData))
            {
              log_debug(TAG, "%s - Unable to extract location IE info", __FUNCTION__);
            }
            else
            {
              info->len = length;
            }
          }
        }
        log_debug(TAG, "%s - ID(%d) LEN(%d)", __FUNCTION__,
                  info->id, info->len);

        // Put the LOWIMeasurementInfo in the vector
        lie.push_back (info);
        delete inner;
      }
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::parseMeasurementInfo
(InPostcard* const card, vector <LOWIMeasurementInfo*>& measurements)
{
  bool retVal = true;
  log_verbose (TAG, "parseMeasurementInfo");

  do
  {
    if (NULL == card)
    {
      log_error (TAG, "parseMeasurementInfo - Argument NULL!");
      retVal = false;
      break;
    }

    PostcardBase::UINT32 num_of_meas = 0;
    int err = card->getUInt32 ("NUM_OF_MEAS", num_of_meas);
    if (0 != err)
    {
      log_error (TAG, "parseMeasurementInfo - Unable to extract NUM_OF_MEAS");
      retVal = false;
      break;
    }
    log_debug (TAG, "parseMeasurementInfo - Total measurements = %u", num_of_meas);

    // For each measurement, retrieve the corresponding InPostcard
    // and parse the information
    for (uint32 ii = 0; ii < num_of_meas; ++ii)
    {
      InPostcard* inner = 0;
      uint32 len = 0;
      if (0 == card->getCard ("Measurement_card", &inner, ii))
      {
        if (NULL == inner)
        {
          log_debug (TAG, "parseMeasurementInfo - No Measurement_card found");
          break;
        }
        LOWIMeasurementInfo * info = new (std::nothrow)LOWIMeasurementInfo;
        if (NULL == info)
        {
          log_error (TAG, "parseMeasurementInfo - Mem allocation failure!");
          // Delete the card
          delete inner;
          retVal = false;
          break;
        }

        extractInt64(*inner, "parseMeasurementInfo", "RSSI_TIMESTAMP", info->rssi_timestamp);
        extractInt16(*inner, "parseMeasurementInfo", "RSSI",           info->rssi);
        extractInt32(*inner, "parseMeasurementInfo", "MEAS_AGE",       info->meas_age);
        extractInt64(*inner, "parseMeasurementInfo", "RTT_TIMESTAMP",  info->rtt_timestamp);
        extractInt32(*inner, "parseMeasurementInfo", "RTT_PS",         info->rtt_ps);
        extractUInt8 (*inner, "parseMeasurementInfo", "TX_PREAMBLE", info->tx_preamble);
        extractUInt8 (*inner, "parseMeasurementInfo", "TX_NSS",      info->tx_nss);
        extractUInt8 (*inner, "parseMeasurementInfo", "TX_BW",       info->tx_bw);
        extractUInt8 (*inner, "parseMeasurementInfo", "TX_MCS_IDX",  info->tx_mcsIdx);
        extractUInt32(*inner, "parseMeasurementInfo", "TX_BIT_RATE", info->tx_bitrate);
        extractUInt8 (*inner, "parseMeasurementInfo", "RX_PREAMBLE", info->rx_preamble);
        extractUInt8 (*inner, "parseMeasurementInfo", "RX_NSS",      info->rx_nss);
        extractUInt8 (*inner, "parseMeasurementInfo", "RX_BW",       info->rx_bw);
        extractUInt8 (*inner, "parseMeasurementInfo", "RX_MCS_IDX",  info->rx_mcsIdx);
        extractUInt32(*inner, "parseMeasurementInfo", "RX_BIT_RATE", info->rx_bitrate);
        extractInt8(*inner, "parseMeasurementInfo", "TX_CHAIN_NO", info->tx_chain_no);
        extractInt8(*inner, "parseMeasurementInfo", "RX_CHAIN_NO", info->rx_chain_no);
        extractUInt32(*inner, "parseMeasurementInfo", "CFR_CIR_LENGTH", len);

        if(len)
        {
          info->cfrcirInfo = new(std::nothrow) LOWICFRCIRInfo;
          if (info->cfrcirInfo == NULL)
          {
            log_error (TAG, "parseMeasurementInfo - Mem allocation failure!");
            delete info;
            delete inner;
            retVal = false;
            break;
          }
          else
          {
            info->cfrcirInfo->len = len;
            info->cfrcirInfo->data = new uint8[len];
            if (NULL == info->cfrcirInfo->data)
            {
              log_error (TAG, "parseMeasurementInfo - Mem allocation failure!");
              delete info->cfrcirInfo;
              delete info;
              delete inner;
              retVal = false;
              break;
            }
            extractCFRCIR(*inner, info->cfrcirInfo->data);
          }
        }
        info->rtt = info->rtt_ps/1000;
        //Add Sanity check for TX BW
        if (info->tx_bw >= BW_MAX)
        {
           log_error(TAG, " %s: Invalid info Tx BW %d, capping to default", __func__, info->tx_bw);
           info->tx_bw = BW_20MHZ;
        }

        //Add Sanity check for RX BW
        if (info->rx_bw >= BW_MAX)
        {
           log_error(TAG, "%s: Invalid info Rx BW %d, capping to default", __func__, info->rx_bw);
           info->rx_bw = BW_20MHZ;
        }

        log_debug(TAG, "parseMeasurementInfo - RSSI_TIMESTAMP(%lld) RSSI(%d) MEAS_AGE(%d) RTT_TIMESTAMP(%" PRId64
                  ") RTT(%d) TX_PREAMBLE(%d) TX_NSS(%d) TX_BW(%d) TX_MCS_IDX(%d) TX_BIT_RATE(%d) RX_PREAMBLE(%d) RX_NSS(%d) RX_BW(%d) RX_MCS_IDX(%d) RX_BIT_RATE(%d) tx_chain_no(%d) rx_chain_no(%d)",
                  info->rssi_timestamp, info->rssi, info->meas_age,
                  info->rtt_timestamp, info->rtt, info->tx_preamble,
                  info->tx_nss, info->tx_bw, info->tx_mcsIdx,
                  info->tx_bitrate, info->rx_preamble, info->rx_nss,
                  info->rx_bw, info->rx_mcsIdx, info->rx_bitrate, info->tx_chain_no, info->rx_chain_no);

        // Put the LOWIMeasurementInfo in the vector
        measurements.push_back (info);
        delete inner;
      }
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::parseScanMeasurements
(InPostcard* const card, vector <LOWIScanMeasurement*> & measurements)
{
  log_verbose (TAG, "parseScanMeasurements");
  bool retVal = true;

  do
  {
    if (NULL == card)
    {
      log_error (TAG, "parseScanMeasurements - Argument NULL!");
      retVal = false;
      break;
    }

    PostcardBase::UINT32 num_of_scans = 0;
    int err = card->getUInt32 ("NUM_OF_SCANS", num_of_scans);
    if (0 != err)
    {
      log_error (TAG, "parseScanMeasurements - Unable to extract NUM_OF_SCANS");
      retVal = false;
      break;
    }
    log_debug (TAG, "parseScanMeasurements - Total Scan measurements = %u", num_of_scans);

    // For each scan measurement, retrieve the corresponding InPostcard
    // and parse the information
    for (uint32 ii = 0; ii < num_of_scans; ++ii)
    {
      InPostcard* inner = 0;
      if (0 == card->getCard ("SCAN_MEAS_CARD", &inner, ii))
      {
        if (NULL == inner)
        {
          log_debug (TAG, "parseScanMeasurements - No SCAN_MEAS_CARD found");
          break;
        }
        bool mem_failure = false;
        LOWIScanMeasurement * meas = NULL;
        do
        {
          uint8 type = 0;
          extractUInt8 (*inner, "parseScanMeasurements", "SCAN_M_TYPE", type);
          LOWIScanMeasurement::eScanMeasurementType scan_type = to_eScanMeasurementType (type);
          if (LOWIScanMeasurement::LOWI_FULL_BEACON_SCAN_MEASUREMENT == scan_type)
          {
            LOWIFullBeaconScanMeasurement* fm =
                new (std::nothrow) LOWIFullBeaconScanMeasurement ();
            if (NULL != fm)
            {
              // Parse the info from the LOWIFullBeaconScanMeasurement object
              parseLocationIEs (inner, fm->mLOWIIE);
            }
            meas = fm;
          }
          else if (LOWIScanMeasurement::LOWI_RANGING_SCAN_MEASUREMENT == scan_type)
          {
            LOWIRangingScanMeasurement* fm =
                new (std::nothrow) LOWIRangingScanMeasurement ();
            if (NULL != fm)
            {
              // Parse the info from the LOWIRangingScanMeasurement object
              parseRangingScanMeasurements (inner, *fm);
            }
            meas = fm;
          }
          else
          {
            meas = new (std::nothrow) LOWIScanMeasurement ();
          }

          if (NULL == meas)
          {
            log_error (TAG, "parseScanMeasurements - Mem allocation failure!");
            mem_failure = true;
            break;
          }

          LOWIUtils::extractBssid(*inner, meas->bssid);

          extractUInt32(*inner, "parseScanMeasurements", "FREQUENCY", meas->frequency);
          extractBool(*inner, "parseScanMeasurements", "IS_SECURE", meas->isSecure);
          extractBool(*inner, "parseScanMeasurements", "ASSOCIATED", meas->associatedToAp);
          uint8 temp;
          extractUInt8(*inner, "parseScanMeasurements", "NODE_TYPE", temp);
          meas->type = LOWIUtils::to_eNodeType (temp);
          extractUInt8(*inner, "parseScanMeasurements", "RTT_TYPE", temp);
          meas->rttType = LOWIUtils::to_eRttType(temp);

          extractUInt64(*inner, "parseScanMeasurements", "MEAS_ADDITION_INFO", meas->measAdditionalInfoMask);
          log_debug (TAG, "%s - FREQUENCY(%d) IS_SECURE(%d) NODE_TYPE(%d)"
                     "RTT_TYPE(%d) ADD_INFO 0x%" PRIX64,
                     __FUNCTION__, meas->frequency, (int)meas->isSecure, meas->type,
                     meas->rttType, meas->measAdditionalInfoMask);

          extractSsid (*inner, meas->ssid);

          // Check if the MSAP Info is present
          uint8 msap_info = 0;
          if (0 == inner->getUInt8 ("MSAP_PROT_VER", msap_info))
          {
            log_verbose (TAG, "parseScanMeasurements - MSAP Info present");
            meas->msapInfo = new (std::nothrow) LOWIMsapInfo;
            if (NULL == meas->msapInfo)
            {
              log_error (TAG, "parseScanMeasurements - Unable to allocate memory.");
              mem_failure = true;
              break;
            }

            extractUInt8(*inner, "parseScanMeasurements", "MSAP_PROT_VER", meas->msapInfo->protocolVersion);
            extractUInt32(*inner, "parseScanMeasurements", "MSAP_VENUE_HASH", meas->msapInfo->venueHash);
            extractUInt8(*inner, "parseScanMeasurements", "MSAP_SERVER_IDX", meas->msapInfo->serverIdx);
            log_debug (TAG, "parseScanMeasurements - MSAP_PROT_VER(%d) MSAP_VENUE_HASH(%d) MSAP_SERVER_IDX(%d)",
                       meas->msapInfo->protocolVersion, meas->msapInfo->venueHash, meas->msapInfo->serverIdx);
          }
          else
          {
            meas->msapInfo = NULL;
          }

          // Get the Cell power
          extractInt8(*inner, "parseScanMeasurements", "CELL_POWER", meas->cellPowerLimitdBm);

          // Get the country code
          int num_elements = LOWI_COUNTRY_CODE_LEN;
          memset(meas->country_code, 0, LOWI_COUNTRY_CODE_LEN);
          if (0 != inner->getArrayUInt8("COUNTRY_CODE", &num_elements, meas->country_code))
          {
            log_warning (TAG, "parseScanMeasurements - Unable to extract COUNTRY_CODE");
          }
          else
          {
            log_debug (TAG, "COUNTRY_CODE is %c%c", (char)meas->country_code [0], (char)meas->country_code [1]);
          }

          // Get Indoor / Outdoor
          extractUInt8(*inner, "parseScanMeasurements", "INDOOR_OUTDOOR", meas->indoor_outdoor);

          // get the measurement number
          extractUInt32(*inner, "parseScanMeasurements", "MEASUREMENT_NUM", meas->measurementNum);

          log_debug (TAG, "parseScanMeasurements - CELL_POWER(%d) INDOOR OUTDOOR(%c), MEASUREMENT_NUM(%u)",
                     meas->cellPowerLimitdBm,
                     (char)meas->indoor_outdoor,
                     meas->measurementNum);

          parseMeasurementInfo(inner, meas->measurementsInfo);

          //get the RTT target status code
          uint32 targetStatus = 0;
          extractUInt32(*inner, "parseScanMeasurements", "RTT_TARGET_STATUS", targetStatus);
          meas->targetStatus = (LOWIScanMeasurement::eTargetStatus)targetStatus;

          // get the beacon period
          extractUInt16(*inner, "parseScanMeasurements", "BEACON_PERIOD", meas->beaconPeriod);

          // get the beacon capabilities
          extractUInt16(*inner, "parseScanMeasurements", "BEACON_CAPS", meas->beaconCaps);

          // get the beacon status
          extractUInt32(*inner, "parseScanMeasurements", "BEACON_STATUS", meas->beaconStatus);

          // get the information element data
          parseIEDataInfo(inner, meas->ieData);

          log_debug (TAG, "parseScanMeasurements - RTT_TARGET_STATUS(%u) BEACON_PERIOD(%u), BEACON_CAPS(%u), IE_LENGTH(%u)",
                     meas->targetStatus,
                     meas->beaconPeriod,
                     meas->beaconCaps,
                     meas->ieData.getNumOfElements());

          // Get the Number of RTT frames attempted.
          extractUInt16(*inner, "parseScanMeasurements", "NUM_RTT_FRAMES_ATTEMPTED", meas->num_frames_attempted);
          // Get the actual time taken to complete rtt measurement.
          extractUInt16(*inner, "parseScanMeasurements", "ACTUAL_BURST_DURATION", meas->actual_burst_duration);
          // Get FTM frames per burst negotiated with target.
          extractUInt8(*inner, "parseScanMeasurements", "NEGOTIATED_NUM_FRAMES_PER_BURST", meas->negotiated_num_frames_per_burst);
          // Get the time after which FTM session can be retried.
          extractUInt8(*inner, "parseScanMeasurements", "RETRY_RTT_AFTER_DURATION", meas->retry_after_duration);
          // Get number of FTM bursts negotiated with the target.
          extractUInt8(*inner, "parseScanMeasurements", "NEGOTIATED_BURST_EXPONENT", meas->negotiated_burst_exp);

           // Check if the lciInfo is present
          uint8 lciInfoID = 0;
          if (0 == inner->getUInt8 ("LCI_INFO_ID", lciInfoID))
          {
            log_verbose (TAG, "parseScanMeasurements - LCI info present");
            meas->lciInfo = new (std::nothrow) LOWILocationIE();
            if (NULL == meas->lciInfo)
            {
              log_error (TAG, "parseScanMeasurements - Unable to allocate memory.");
              mem_failure = true;
              break;
            }

            meas->lciInfo->id = lciInfoID;
            uint8 len;
            extractUInt8(*inner, "parseScanMeasurements", "LCI_INFO_LEN", len);
            meas->lciInfo->len = len;
            log_debug (TAG, "parseScanMeasurements - LCI_INFO_ID(%d) LCI_INFO_LEN(%d)",
                       meas->lciInfo->id, meas->lciInfo->len);
            // get the location information element data
            if (0 != len)
            {
              meas->lciInfo->locData = new uint8[len];
              if (NULL != meas->lciInfo->locData)
              {
                memset(meas->lciInfo->locData, 0, len);
                parseLocationIEDataInfo(inner, meas->lciInfo->locData, len, "LCI");
              }
            }
          }
          else
          {
            meas->lciInfo = NULL;
          }

          // Check if the lcrInfo is present
          uint8 lcrInfoID = 0;
          if (0 == inner->getUInt8 ("LCR_INFO_ID", lcrInfoID))
          {
            log_verbose (TAG, "parseScanMeasurements - LCR info present");
            meas->lcrInfo = new (std::nothrow) LOWILocationIE();
            if (NULL == meas->lcrInfo)
            {
              log_error (TAG, "parseScanMeasurements - Unable to allocate memory.");
              mem_failure = true;
              break;
            }

            meas->lcrInfo->id = lcrInfoID;
            uint8 len;
            extractUInt8(*inner, "parseScanMeasurements", "LCR_INFO_LEN", len);
            meas->lcrInfo->len = len;
            log_debug (TAG, "parseScanMeasurements - LCR_INFO_ID(%d) LCR_INFO_LEN(%d)",
                       meas->lcrInfo->id, meas->lcrInfo->len);
            // get the location information element data
            if (0 != len)
            {
              meas->lcrInfo->locData = new uint8[len];
              if (NULL != meas->lcrInfo->locData)
              {
                memset(meas->lcrInfo->locData, 0, len);
                parseLocationIEDataInfo(inner, meas->lcrInfo->locData, len, "LCR");
              }
            }
          }
          else
          {
            meas->lcrInfo = NULL;
          }

          // get the beacon capabilities
          int8 phy_mode = 0;
          extractInt8(*inner, "parseScanMeasurements", "PHY_MODE", phy_mode);
          meas->phyMode = to_eLOWIPhyMode (phy_mode);
          extractUInt32(*inner, "parseScanMeasurements", "MAX_TX_RATE", meas->maxTxRate);
          uint8 enc = 0;
          extractUInt8(*inner, "parseScanMeasurements", "ENCRYPTION", enc);
          meas->encryptionType = to_eEncryptionType (enc);
          extractUInt64(*inner, "parseScanMeasurements", "TARGET_TSF", meas->targetTSF);

          // get the AoA result
          PostcardBase::DOUBLE azi = LOWI_AZIMUTH_DEFAULT;
          PostcardBase::DOUBLE ele = LOWI_ELEVATION_DEFAULT;
          int t1 = inner->getDouble("AZIMUTH", azi);
          int t2 = inner->getDouble("ELEVATION", ele);

          if ((0 != t1) && (0 != t2))
          {
            meas->aoaMeasurement = NULL;
          }
          else
          {
            meas->aoaMeasurement = new(std::nothrow) LOWIAoAResult();
            if (NULL == meas->aoaMeasurement)
            {
              log_error(TAG, "parseScanMeasurements - Unable to allocate memory.");
              mem_failure = true;
              break;
            }
            meas->aoaMeasurement->mAzimuth   = (double)azi;
            meas->aoaMeasurement->mElevation = (double)ele;
          }

          // Put the LOWIMeasurementInfo in the vector
          measurements.push_back (meas);
        } while (0);

        // Delete the card
        delete inner;
        // Delete the measurement pointer if we are here because
        // of mem allocation failure.
        if (true == mem_failure)
        {
          delete meas;
          // No need to continue. break out of the for loop.
          retVal = false;
          break;
        }
      } // if Card
    } // for
  } while (0);

  return retVal;
}

void LOWIUtils::rangeReqToCardCommonParams(LOWIRangingScanRequest* const req, OutPostcard * card, const char* reqType)
{
  if (card == NULL)
  {
    log_debug(TAG, "%s(): Received NULL for OutPostcard", __FUNCTION__);
    return;
  }
  if (req == NULL)
  {
    log_debug(TAG, "%s(): Received NULL for request", __FUNCTION__);
    return;
  }
  if (reqType == NULL)
  {
    log_debug(TAG, "%s(): Received NULL for reqType", __FUNCTION__);
    return;
  }

  card->addString("REQ", reqType);
  card->addUInt32("REQ_ID", req->getRequestId());
  // Add TX-ID of type int32 as a standard field in postcard
  card->addInt32("TX-ID", req->getRequestId());
  card->addUInt8("REQUEST_TYPE", req->getRequestType());
  card->addInt64("REQ_TIMEOUT", req->getTimeoutTimestamp());
  card->addUInt8("RANGING_SCAN_REPORT_TYPE", req->getReportType());

}

void LOWIUtils::rangeReqToCardNodeInfo(LOWINodeInfo &info, OutPostcard * node_card)
{
  if (node_card == NULL)
  {
    log_debug(TAG, "%s(): Received NULL for node_card", __FUNCTION__);
    return;
  }
  addBssidToCard (*node_card, info.bssid);

  node_card->addUInt32("FREQUENCY", info.frequency);

  node_card->addUInt32("BAND_CENTER_FREQ1", info.band_center_freq1);

  node_card->addUInt32("BAND_CENTER_FREQ2", info.band_center_freq2);

  node_card->addUInt8("NODE_TYPE", info.nodeType);

  unsigned int spoof_mac_id = info.spoofMacId.getLo24 ();
  node_card->addUInt32 ("SPOOF_MAC_ID_LO", spoof_mac_id);

  spoof_mac_id = info.spoofMacId.getHi24 ();
  node_card->addUInt32 ("SPOOF_MAC_ID_HI", spoof_mac_id);
  node_card->addUInt8("RTT_TYPE", info.rttType);
  node_card->addUInt8("RANGING_BW", info.bandwidth);
  node_card->addUInt8("RANGING_PREAMBLE", info.preamble);
  node_card->addInt8("RANGING_PHYMODE", info.phyMode);
  node_card->addUInt32("RANGING_REPORTTYPE", info.reportType);
  node_card->addUInt32("FTM_RANGING_PARAMS", info.ftmRangingParameters);
  node_card->addUInt8("NUM_PKTS_PER_MEAS", info.num_pkts_per_meas);
  node_card->addUInt8("NUM_RETRIES_PER_MEAS", info.num_retries_per_meas);
  node_card->addUInt32("RANGING_PARAM_CONTROL", info.paramControl);
  node_card->addString("INTERFACE", info.interface.c_str());
}

void LOWIUtils::rangeReqToCardPeriodicNodeInfo(LOWIPeriodicNodeInfo &info, OutPostcard * node_card)
{
  if (node_card == NULL)
  {
    log_debug(TAG, "%s(): Received NULL for node_card", __FUNCTION__);
    return;
  }
  node_card->addUInt8("PERIODIC", info.periodic);
  node_card->addUInt32 ("MEAS_PERIOD", info.meas_period);
  node_card->addUInt32 ("NUM_MEASUREMENTS", info.num_measurements);
}

OutPostcard* LOWIUtils::requestToOutPostcard (LOWIRequest* const request,
    const char* const originatorId)
{
  OutPostcard * card = NULL;
  bool success = false;
  log_verbose (TAG, "requestToOutPostcard");
  do
  {
    // Check the parameters
    if (NULL == request || NULL == originatorId)
    {
      log_error (TAG, "requestToOutPostcard - parameter can not be NULL");
      break;
    }

    // Create the OutPostcard
    card = OutPostcard::createInstance();
    if (NULL == card) break;
    card->init();
    card->addString("TO", SERVER_NAME);
    card->addString("FROM", originatorId);

    // Check the type of request and initialize postcard
    LOWIRequest::eRequestType type = request->getRequestType();
    log_verbose (TAG, "requestToOutPostcard - Request type = %s", LOWIUtils::to_string(type));
    switch (type)
    {
    case LOWIRequest::CAPABILITY:
    {
      LOWICapabilityRequest* req = (LOWICapabilityRequest*)request;
      card->addString("REQ", "LOWI_CAPABILITY");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      card->addString("INTERFACE", req->Interface.c_str());
      success = true;
    }
    break;
    case LOWIRequest::DISCOVERY_SCAN:
    {
      LOWIDiscoveryScanRequest* req = (LOWIDiscoveryScanRequest*)request;
      card->addString("REQ", "LOWI_DISCOVERY_SCAN");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      card->addUInt8("BAND", req->getBand());
      card->addBool("BUFFER_CACHE_BIT", req->getBufferCacheRequest());
      card->addUInt32("MEAS_AGE_FILTER", req->getMeasAgeFilterSec());
      card->addUInt32("FALLBACK_TOLERANCE", req->getFallbackToleranceSec());
      card->addUInt8("REQUEST_MODE", req->getRequestMode());
      card->addUInt8("REQUEST_TYPE", req->getRequestType());
      card->addUInt8("SCAN_TYPE",req->getScanType());
      card->addInt64("REQ_TIMEOUT", req->getTimeoutTimestamp());
      card->addBool("FULL_BEACON_BIT", req->getFullBeaconScanResponse());

      vector <LOWIChannelInfo> vec = req->getChannels();
      // Channels are optional. So continue if there are no channels
      // specified in the request.
      uint32 ii = 0;
      for (; ii < vec.getNumOfElements(); ++ii)
      {
        LOWIChannelInfo info = vec[ii];

        // For each Channel Info create a OutPostcard
        OutPostcard* ch_card = OutPostcard::createInstance ();
        if (NULL == ch_card)
        {
          // Unable to allocate memory for inner card
          // break out of for loop and log error.
          // The main card returned by the function will
          // contain less information.
          log_error (TAG, "requestToOutPostcard - Mem allocation failure!");
          break;
        }

        ch_card->init ();

        ch_card->addUInt32("FREQUENCY", info.getFrequency());

        ch_card->finalize ();
        card->addCard ("CHANNEL_CARD", ch_card);
        log_debug (TAG, "requestToOutPostcard - Added a channel card to the main card");
        delete ch_card;
      }
      card->addUInt32("NUM_OF_CHANNELS", ii);
      if (ii < vec.getNumOfElements())
      {
        // Not all channels could be allocated. Memory allocation error
        success = false;
        break;
      }

      // Add BSSIDs to Card
      addBssidsToCard (*card, req->scanBssids);

      // Add SSIDs to Card
      addSsidsToCard (*card, req->scanSsids);

      success = true;
    }
    break;
    case LOWIRequest::RANGING_SCAN:
    {
      uint32 ii = 0;
      LOWIRangingScanRequest* req = (LOWIRangingScanRequest*)request;
      rangeReqToCardCommonParams(req, card, "LOWI_RANGING_SCAN");

      vector <LOWINodeInfo> vec = req->getNodes();
      uint32 numElems = vec.getNumOfElements();
      if (0 == numElems)
      {
        log_warning(TAG, "Request has no nodes");
        break;
      }

      for (ii = 0; ii < numElems; ++ii)
      {
        LOWINodeInfo info = vec[ii];
        // For each Node Info create a OutPostcard
        OutPostcard* node_card = OutPostcard::createInstance ();
        if (NULL == node_card)
        {
          // Unable to allocate memory for inner card
          // break out of for loop and log error.
          // The main card returned by the function will
          // contain less information.
          log_error (TAG, "requestToOutPostcard - Mem allocation failure!");
          break;
        }

        node_card->init ();

        rangeReqToCardNodeInfo(info, node_card);

        node_card->finalize ();
        card->addCard ("WIFI_NODE_CARD", node_card);
        log_debug (TAG, "requestToOutPostcard - Added a node card to the main card");
        delete node_card;
      }
      card->addUInt32("NUM_OF_NODES", ii);

      if (ii < numElems)
      {
        // Not all nodes could be allocated. Memory allocation error
        success = false;
        break;
      }

      success = true;
    }
    break;
    case LOWIRequest::PERIODIC_RANGING_SCAN:
    {
      uint32 ii = 0;
      LOWIPeriodicRangingScanRequest* req = (LOWIPeriodicRangingScanRequest*)request;
      rangeReqToCardCommonParams(req, card, "LOWI_PERIODIC_RANGING_SCAN");

      vector <LOWIPeriodicNodeInfo> vec = req->getNodes();
      uint32 numElems = vec.getNumOfElements();
      if (0 == numElems)
      {
        log_warning(TAG, "Request has no nodes");
        break;
      }

      for (ii = 0; ii < numElems; ++ii)
      {
        LOWIPeriodicNodeInfo info = vec[ii];
        // For each Node Info create a OutPostcard
        OutPostcard* node_card = OutPostcard::createInstance ();
        if (NULL == node_card)
        {
          // Unable to allocate memory for inner card
          // break out of for loop and log error.
          // The main card returned by the function will
          // contain less information.
          log_error (TAG, "requestToOutPostcard - Mem allocation failure!");
          break;
        }

        node_card->init ();

        rangeReqToCardNodeInfo(info, node_card);

        rangeReqToCardPeriodicNodeInfo(info, node_card);

        node_card->finalize ();
        card->addCard ("WIFI_NODE_CARD", node_card);
        log_debug (TAG, "requestToOutPostcard - Added a node card to the main card");
        delete node_card;
      }
      card->addUInt32("NUM_OF_NODES", ii);

      if (ii < numElems)
      {
        // Not all nodes could be allocated. Memory allocation error
        success = false;
        break;
      }

      success = true;

    }
    break;
    case LOWIRequest::RESET_CACHE:
    {
      LOWICacheResetRequest* req = (LOWICacheResetRequest*)request;
      card->addString("REQ", "LOWI_RESET_CACHE");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      success = true;
    }
    break;
    case LOWIRequest::ASYNC_DISCOVERY_SCAN_RESULTS:
    {
      LOWIAsyncDiscoveryScanResultRequest* req =
          (LOWIAsyncDiscoveryScanResultRequest*)request;
      card->addString("REQ", "LOWI_ASYNC_DISCOVERY_SCAN_RESULTS");
      card->addUInt32("REQ_ID", req->getRequestId());
      card->addUInt8("REQUEST_TYPE", req->getRequestType());
      card->addUInt32("REQ_TIMEOUT", req->getRequestExpiryTime());

      success = true;
    }
    break;
    case LOWIRequest::CANCEL_RANGING_SCAN:
    {
      LOWICancelRangingScanRequest* req = (LOWICancelRangingScanRequest*)request;
      card->addString("REQ", "CANCEL_RANGING_SCAN");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      card->addUInt8("REQUEST_TYPE", req->getRequestType());

      vector <LOWIMacAddress> vec = req->getBssids();
      if (0 == vec.getNumOfElements()) break;

      uint32 ii = 0;
      for (; ii < vec.getNumOfElements(); ++ii)
      {
        LOWIMacAddress macAddr = vec[ii];

        // For each bssid create a OutPostcard
        OutPostcard* bssid_card = OutPostcard::createInstance ();
        if (NULL == bssid_card)
        {
          // Unable to allocate memory for inner card
          // break out of for loop and log error.
          // The main card returned by the function will
          // contain less information.
          log_error (TAG, "requestToOutPostcard - Mem allocation failure!");
          break;
        }

        bssid_card->init ();

        addBssidToCard (*bssid_card, macAddr);

        bssid_card->finalize ();
        card->addCard ("WIFI_BSSID_CARD", bssid_card);
        log_debug (TAG, "requestToOutPostcard - Added a node card to the main card");
        delete bssid_card;
      }
      card->addUInt32("NUM_OF_BSSIDS", ii);

      if (ii < vec.getNumOfElements())
      {
        // Not all nodes could be allocated. Memory allocation error
        success = false;
        break;
      }

      success = true;
    }
    break;
    case LOWIRequest::SET_LCI_INFORMATION:
    {
      LOWISetLCILocationInformation *req = (LOWISetLCILocationInformation*)request;
      card->addString("REQ", "SET_LCI_INFORMATION");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());

      LOWILciInformation params = req->getLciParams();
      card->addInt64("LATITUDE", params.latitude);
      card->addInt64("LONGITUDE", params.longitude);
      card->addInt32("ALTITUDE", params.altitude);
      card->addUInt8("LATITUDE_UNC", params.latitude_unc);
      card->addUInt8("LONGITUDE_UNC", params.longitude_unc);
      card->addUInt8("ALTITUDE_UNC", params.altitude_unc);
      card->addUInt8("MOTION_PATTERN", params.motion_pattern);
      card->addInt32("FLOOR", params.floor);
      card->addInt32("HEIGHT_ABOVE_FLOOR", params.height_above_floor);
      card->addInt32("HEIGHT_UNC", params.height_unc);
      card->addUInt32("USAGE_RULES", req->getUsageRules());
      card->addString("INTERFACE", req->get_interface().c_str());
      success = true;
    }
    break;
    case LOWIRequest::SET_LCR_INFORMATION:
    {
      LOWISetLCRLocationInformation *req = (LOWISetLCRLocationInformation*)request;
      card->addString("REQ", "SET_LCR_INFORMATION");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());

      LOWILcrInformation params = req->getLcrParams();
      card->addArrayUInt8("LCR_COUNTRY_CODE", LOWI_COUNTRY_CODE_LEN, params.country_code);
      card->addUInt32("LCR_LENGTH", params.length);
      card->addArrayInt8("LCR_CIVIC_INFO", CIVIC_INFO_LEN,
                         (PostcardBase::INT8 *)params.civic_info);
      card->addString("INTERFACE", req->get_interface().c_str());
      success = true;
    }
    break;
    case LOWIRequest::NEIGHBOR_REPORT:
    {
      LOWINeighborReportRequest* req = (LOWINeighborReportRequest*)request;
      card->addString("REQ", "NEIGHBOR_REPORT");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      success = true;
    }
    break;
    case LOWIRequest::LOWI_WLAN_STATE_QUERY_REQUEST:
    {
      LOWIWLANStateQueryRequest* req = (LOWIWLANStateQueryRequest*)request;
      card->addString("REQ", "LOWI_WLAN_STATE_QUERY_REQUEST");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      card->addUInt8("IFACE", req->getInterface());
      success = true;
    }
    break;
    case LOWIRequest::SEND_LCI_REQUEST:
    {
      LOWISendLCIRequest *req = (LOWISendLCIRequest *)request;
      card->addString("REQ", "SEND_LCI_REQUEST");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());

      addBssidToCard(*card, req->getBssid());
      success = true;
    }
    break;
    case LOWIRequest::FTM_RANGE_REQ:
    {
      LOWIFTMRangingRequest *req = (LOWIFTMRangingRequest *)request;
      card->addString("REQ", "FTM_RANGE_REQ");
      card->addUInt32("REQ_ID", req->getRequestId());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());

      addBssidToCard(*card, req->getBSSID());
      card->addUInt16("RAND_INTER", req->getRandInter());
      vector<LOWIFTMRRNodeInfo> nodes = req->getNodes();
      uint32 ii = 0;
      for (; ii < nodes.getNumOfElements(); ++ii)
      {
        if (!addFTMRRNodeToCard(*card, nodes[ii]))
        {
          break;
        }
      }
      if (ii < nodes.getNumOfElements())
      {
        success = false;
        log_error(TAG, "Failed to add nodes to FTMRR");
        break;
      }
      card->addUInt32("NUM_NODES", ii);
      success = true;
    }
    break;
    case LOWIRequest::LOWI_CONFIG_REQUEST:
    {
      LOWIConfigRequest* req = (LOWIConfigRequest*)request;
      card->addString("REQ", "LOWI_CONFIG_REQUEST");
      card->addUInt32("REQ_ID", req->getRequestId());
      card->addUInt8("LOWI_VARIANT", req->getLowiVariant());
      card->addUInt8("REQUEST_MODE", req->getConfigRequestMode());
      // Add TX-ID of type int32 as a standard field in postcard
      card->addInt32("TX-ID", req->getRequestId());
      card->addUInt8("GLOBAL_LOG_LEVEL", req->getGlobalLogLevel());
      card->addBool("GLOBAL_LOG_FLAG", req->getGlobalLogFlag());
      vector <LOWILogInfo>& vec = req->getLogInfo();
      uint32 ii = 0;
      for (; ii < vec.getNumOfElements(); ++ii)
      {
        LOWILogInfo info = vec[ii];

        OutPostcard* log_card = OutPostcard::createInstance ();
        if (NULL == log_card)
        {
          // Unable to allocate memory for inner card
          // break out of for loop and log error.
          // The main card returned by the function will
          // contain less information.
          log_error (TAG, "%s:Allocation failure for log_card", __FUNCTION__);
          break;
        }

        log_card->init ();

        log_card->addString("TAG", info.tag);
        log_card->addUInt8("LOG_LEVEL", info.log_level);

        log_card->finalize ();
        card->addCard ("LOGINFO_CARD", log_card);
        delete log_card;
      }
      if (ii < vec.getNumOfElements())
      {
        // Not all nodes could be allocated. Memory allocation error
        success = false;
        break;
      }
      card->addUInt32("NUM_OF_TAGS", ii);
      success = true;
      break;
    }
    default:
      log_debug (TAG, "%s - check if Extensions can handle this request", __FUNCTION__);
      success = LOWIUtilsExtn::requestToOutPostcard (request, *card);
      break;
    }

    if (true == success)
    {
      // Finalize post card
      card->finalize();
      log_verbose (TAG, "requestToOutPostcard - Card finalized");
    }
    else
    {
      log_warning (TAG, "requestToOutPostcard - Unable to create card");
      delete card;
      card = NULL;
    }
  } while (0);
  return card;
}

LOWIResponse* LOWIUtils::inPostcardToResponse (InPostcard* const card)
{
  log_verbose (TAG, "inPostcardToResponse");
  LOWIResponse* response = NULL;

  do
  {
    // Check the postcard
    if (NULL == card)
    {
      log_error (TAG, "inPostcardToResponse - Input Parameter can not be NULL!");
      break;
    }

    const char * print_from = NOT_AVAILABLE;
    const char * from = 0;
    if (0 != card->getString("FROM", &from))
    {
      log_debug (TAG, "inPostcardToResponse - Unable to extract FROM");
    }
    else
    {
      print_from = from;
    }

    const char * print_to = NOT_AVAILABLE;
    const char * to = 0;
    if (0 != card->getString("TO", &to))
    {
      log_debug (TAG, "inPostcardToResponse - Unable to extract TO");
    }
    else
    {
      print_to = to;
    }

    const char * print_resp_type = NOT_AVAILABLE;
    const char * resp_type = 0;
    if (0 != card->getString("RESP", &resp_type))
    {
      log_debug (TAG, "inPostcardToResponse - Unable to extract RESP");
    }
    else
    {
      print_resp_type = resp_type;
    }

    if (resp_type == NULL)
    {
      log_debug(TAG, "inPostcardToResponse - NULL resp, break");
      break;
    }
    log_info(TAG, "inPostcardToResponse - FROM: %s, TO:   %s, RESP:  %s",
        print_from, print_to, print_resp_type);

    // extract the Request ID which all responses have
    uint32 req_id = 0;
    extractUInt32(*card, "inPostcardToResponse", "REQ_ID", req_id);

    // Create the response
    if( (0 == strcmp(resp_type, "LOWI_DISCOVERY_SCAN")) ||
        (0 == strcmp(resp_type, "LOWI_ASYNC_DISCOVERY_SCAN_RESULTS")) )
    {
      // Scan Status
      uint8 scan_status = 0;
      extractUInt8(*card, "inPostcardToResponse", "SCAN_STATUS", scan_status);

      // Scan Type
      uint8 scan_type = 0;
      extractUInt8(*card, "inPostcardToResponse", "SCAN_TYPE", scan_type);

      // Packet Timestamp
      int64 packet_timestamp = 0;
      extractInt64(*card, "inPostcardToResponse", "PACKET_TIMESTAMP", packet_timestamp);

      log_debug (TAG, "inPostcardToResponse - Request id(%d) Scan Status(%d)"
                      " Scan Type(%d) Packet time stamp(%" PRId64 ")",
                 req_id, scan_status, scan_type, packet_timestamp);

      if (0 == strcmp(resp_type, "LOWI_DISCOVERY_SCAN"))
      {
        log_debug (TAG, "inPostcardToResponse - DiscoveryScanResponse");
        LOWIDiscoveryScanResponse* resp =
            new (std::nothrow) LOWIDiscoveryScanResponse (req_id);
        if (NULL == resp)
        {
          log_error (TAG, "inPostcardToResponse - Memory allocation failure!");
          break;
        }

        parseScanMeasurements (card, resp->scanMeasurements);

        resp->scanStatus = LOWIUtils::to_eScanStatus(scan_status);
        resp->scanTypeResponse = LOWIUtils::to_eScanTypeResponse(scan_type);
        resp->timestamp = packet_timestamp;
        extractBssid (*card, resp->self_mac);
        response = resp;
      }
      else
      {
        log_debug (TAG, "inPostcardToResponse -"
            " AsyncDiscoveryScanResultResponse");
        LOWIAsyncDiscoveryScanResultResponse* resp =
            new (std::nothrow) LOWIAsyncDiscoveryScanResultResponse (req_id);
        if (NULL == resp)
        {
          log_error (TAG, "inPostcardToResponse - Memory allocation failure!");
          break;
        }

        parseScanMeasurements (card, resp->scanMeasurements);

        resp->scanStatus = LOWIUtils::to_eScanStatus(scan_status);
        resp->scanTypeResponse = LOWIUtils::to_eScanTypeResponse(scan_type);
        resp->timestamp = packet_timestamp;
        response = resp;
      }

    }
    else if (0 == strcmp (resp_type, "LOWI_RANGING_SCAN"))
    {
      // Scan Status
      uint8 scan_status = 0;
      extractUInt8(*card, "inPostcardToResponse", "SCAN_STATUS", scan_status);

      log_debug (TAG, "inPostcardToResponse - Request id(%d) Scan Status(%d)",
                 req_id, scan_status);

      LOWIRangingScanResponse* resp =
          new (std::nothrow) LOWIRangingScanResponse (req_id);
      if (NULL == resp)
      {
        log_error (TAG, "inPostcardToResponse - Memory allocation failure!");
        break;
      }

      parseScanMeasurements (card, resp->scanMeasurements);

      resp->scanStatus = LOWIUtils::to_eScanStatus(scan_status);

      response = resp;
    }
    else if (0 == strcmp (resp_type, "LOWI_CAPABILITY"))
    {
      // Ranging Supported
      bool ranging_supported;
      extractBool(*card, "inPostcardToResponse", "RANGING_SCAN_SUPPORTED", ranging_supported);

      // Discovery Supported
      bool discovery_supported;
      extractBool(*card, "inPostcardToResponse", "DISCOVERY_SCAN_SUPPORTED", discovery_supported);

      // Active Scan Supported
      bool active_supported;
      extractBool(*card, "inPostcardToResponse", "ACTIVE_SCAN_SUPPORTED", active_supported);

      // scans Supported
      uint32 supported_capability;
      extractUInt32(*card, "inPostcardToResponse", "SUPPORTED_CAPABILITY", supported_capability);

      uint32 supported_caps_wigig;
      extractUInt32(*card, "inPostcardToResponse", "SUPPORTED_WIGIG_CAPABILITY", supported_caps_wigig);

      log_debug (TAG, "inPost cap Response - Request id(%d) Ranging scan(%d)"
                 "Discovery scan(%d) Active scan(%d) capability bitmask(0x%x) "
                 "capability_wigig_bitmask(0x%x)", req_id,
                 (int)ranging_supported, (int)discovery_supported, (int)active_supported,
                 supported_capability, supported_caps_wigig);

      // Single-sided ranging scan supported
      bool single_sided_supported;
      extractBool(*card, "inPostcardToResponse", "SINGLE_SIDED_RANGING_SCAN_SUPPORTED", single_sided_supported);

      // Dual-sided ranging scan supported (11v)
      bool dual_sided_supported_11v;
      extractBool(*card, "inPostcardToResponse", "DUAL_SIDED_RANGING_SCAN_SUPPORTED_11V", dual_sided_supported_11v);

      // Dual-sided ranging scan supported (11mc)
      bool dual_sided_supported_11mc;
      extractBool(*card, "inPostcardToResponse", "DUAL_SIDED_RANGING_SCAN_SUPPORTED_11MC", dual_sided_supported_11mc);

      // bgscan supported
      bool bgscan_supported;
      extractBool(*card, "inPostcardToResponse", "BGSCAN_SUPPORTED", bgscan_supported);

      log_debug (TAG, "inPostcardToResponse - Single-sided rang scan supported(%d)"
          " Ranging 11v(%d) Ranging 11mc(%d) bgscan supported(%d)",
          (int)single_sided_supported, (int)dual_sided_supported_11v,
          (int)dual_sided_supported_11mc, (int)bgscan_supported);

      // bw support level
      uint8 bw_support;
      extractUInt8(*card, "inPostcardToResponse", "BW_SUPPORT", bw_support);

      // preamble support mask
      uint8 preamble_support;
      extractUInt8(*card, "inPostcardToResponse", "PREAMBLE_SUPPORT", preamble_support);

      // MC version
      uint8 mc_version;
      extractUInt8(*card, "inPostcardToResponse", "MC_VERSION", mc_version);

      // Request status
      bool cap_status;
      extractBool(*card, "inPostcardToResponse", "CAPABILITY_STATUS", cap_status);

      log_debug (TAG, "inPostcardToResponse - Capability scan status = %d",
          (int)cap_status);

      LOWICapabilities cap;
      cap.discoveryScanSupported        = discovery_supported;
      cap.rangingScanSupported          = ranging_supported;
      cap.activeScanSupported           = active_supported;
      cap.oneSidedRangingSupported      = single_sided_supported;
      cap.dualSidedRangingSupported11v  = dual_sided_supported_11v;
      cap.dualSidedRangingSupported11mc = dual_sided_supported_11mc;
      cap.bgscanSupported               = bgscan_supported;
      cap.bwSupport                     = bw_support;
      cap.preambleSupport               = preamble_support;
      cap.mcVersion                     = mc_version;
      cap.supportedCapablities          = supported_capability;
      cap.supportedCapsWigig            = supported_caps_wigig;

      LOWICapabilityResponse* resp =
          new (std::nothrow) LOWICapabilityResponse (req_id, cap, cap_status);
      if (NULL == resp)
      {
        log_error (TAG, "inPostcardToResponse - Memory allocation failure!");
        break;
      }

      response = resp;
    }
    else if (0 == strcmp (resp_type, "LOWI_RESET_CACHE"))
    {
      // status
      bool status;
      extractBool(*card, "inPostcardToResponse", "CACHE_STATUS", status);
      log_debug (TAG, "inPostcardToResponse - Request id(%d) Cache status(%d)",
                 req_id, (int)status);

      LOWICacheResetResponse* resp =
          new (std::nothrow) LOWICacheResetResponse (req_id, status);
      if (NULL == resp)
      {
        log_error (TAG, "inPostcardToResponse - Memory allocation failure!");
        break;
      }

      response = resp;
    }
    else if (0 == strcmp (resp_type, "LOWI_STATUS"))
    {
      uint8 status;
      uint8 reqType;
      extractUInt8(*card, "inPostcardToResponse", "LOWI_STATUS", status);
      extractUInt8(*card, "inPostcardToResponse", "REQ_TYPE", reqType);
      log_debug (TAG, "inPostcardToResponse - Request id(%d) RspStatus(%u), ReqType(%u)",
                 req_id, status, reqType);

      LOWIStatusResponse* resp = new (std::nothrow) LOWIStatusResponse (req_id);
      LOWI_BREAK_ON_COND(!resp, debug, "Memory allocation failure!")

      resp->scanStatus = LOWIUtils::to_eLOWIDriverStatus(status);

      LOWIRequest::eRequestType r = (LOWIRequest::eRequestType)reqType;
      switch (r)
      {
        case LOWIRequest::BGSCAN_START:
          resp->mRequestType = LOWIRequest::BGSCAN_START;
        break;
        case LOWIRequest::BGSCAN_STOP:
          resp->mRequestType = LOWIRequest::BGSCAN_STOP;
        break;
        case LOWIRequest::HOTLIST_SET:
          resp->mRequestType = LOWIRequest::HOTLIST_SET;
        break;
        case LOWIRequest::HOTLIST_CLEAR:
          resp->mRequestType = LOWIRequest::HOTLIST_CLEAR;
        break;
        case LOWIRequest::SIGNIFINCANT_CHANGE_LIST_SET:
          resp->mRequestType = LOWIRequest::SIGNIFINCANT_CHANGE_LIST_SET;
        break;
        case LOWIRequest::SIGNIFINCANT_CHANGE_LIST_CLEAR:
          resp->mRequestType = LOWIRequest::SIGNIFINCANT_CHANGE_LIST_CLEAR;
        break;
        default:
        break;
      }

      response = resp;
    }
    else if( 0 == strcmp (resp_type, "LOWI_WLAN_STATE_QUERY_RESPONSE") )
    {
      uint8 status = 0;
      extractUInt8(*card, "inPostcardToResponse", "SCAN_STATUS", status);
      LOWIWlanStateQueryResponse* resp =
        new (std::nothrow) LOWIWlanStateQueryResponse (req_id,
                           LOWIUtils::to_eScanStatus(status));
      LOWI_BREAK_ON_COND(!resp, debug, "Memory allocation failure!")
      extractBool(*card, "inPostcardToResponse", "CONNECTED", resp->connected);
      extractBssid (*card, resp->connectedNodeBssid);
      extractUInt32(*card, "inPostcardToResponse", "FREQ", resp->connectedNodeFreq);
      extractInt16(*card, "inPostcardToResponse", "RSSI", resp->connectedNodeRssi);
      extractSsid (*card, resp->connectedNodeSsid);

      response = resp;
    }
    else
    {
      log_verbose (TAG, "%s - Check if Extension can handle the card", __FUNCTION__);
      LOWIUtilsExtn::inPostcardToResponse (*card, &response);
    }
  }
  while (0);

  return response;
}

void LOWIUtils::extractUInt8(InPostcard &inner, const char* n, const char* s, uint8 &num)
{
  num = 0;
  if( 0 != inner.getUInt8(s, num) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
}

void LOWIUtils::extractUInt16(InPostcard &card, const char* n, const char* s, uint16 &num)
{
  num = 0;
  if( 0 != card.getUInt16(s, num) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
}

void LOWIUtils::extractUInt32(InPostcard &card, const char* n, const char* s, uint32 &num)
{
  PostcardBase::UINT32 num32 = 0;
  if( 0 != card.getUInt32(s, num32) )
  {
    log_debug(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
  num = num32;
}

void LOWIUtils::extractInt8(InPostcard &inner, const char* n, const char* s, int8 &num)
{
  uint32 val = strncmp(s, "CELL_POWER", sizeof("CELL_POWER"));
  num = (0 == val) ? CELL_POWER_NOT_FOUND : 0;

  if( 0 != inner.getInt8(s, (PostcardBase::INT8&)num) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
}

void LOWIUtils::extractInt16(InPostcard &inner, const char* n, const char* s, int16 &num)
{
  num = 0;
  if( 0 != inner.getInt16(s, num) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
}

void LOWIUtils::extractInt32(InPostcard &inner, const char* n, const char* s, int32 &num)
{
  PostcardBase::INT32 num32 = 0;
  if( 0 != inner.getInt32(s, num32) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
  num = num32;
}

void LOWIUtils::extractInt64(InPostcard &inner, const char* n, const char* s, int64 &num)
{
  PostcardBase::INT64 num64 = 0;
  if( 0 != inner.getInt64(s, num64) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
  num = (int64)num64;
}

void LOWIUtils::extractUInt64(InPostcard &inner, const char* n, const char* s, uint64 &num)
{
  PostcardBase::UINT64 num64 = 0;
  if( 0 != inner.getUInt64(s, num64) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
  num = (uint64)num64;
}

void LOWIUtils::extractBool(InPostcard &inner, const char* n, const char* s, bool &num)
{
  num = false;
  if( 0 != inner.getBool(s, num) )
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
}

void LOWIUtils::extractDouble(InPostcard &inner, const char* n, const char* s, double &num)
{
  PostcardBase::DOUBLE doub = 0;
  if (0 != inner.getDouble(s, doub))
  {
    log_warning(TAG, "%s%s%s", n, " - Unable to extract ", s);
  }
  num = (double)doub;
}

LOWIRequest* LOWIUtils::inPostcardToRequest (InPostcard* const card)
{
  LOWIRequest* request = NULL;
  bool success = true;
  const char * from = 0;

  do
  {
    // Check the postcard
    if (NULL == card)
    {
      log_error (TAG, "inPostcardToRequest - Card can not be null!");
      break;
    }

    const char * print_from = NOT_AVAILABLE;
    if (0 != card->getString("FROM", &from))
    {
      log_warning (TAG, "inPostcardToRequest - Unable to extract FROM");
    }
    else
    {
      print_from = from;
    }

    const char * print_to = NOT_AVAILABLE;
    const char * to = 0;
    if (0 != card->getString("TO", &to))
    {
      log_warning (TAG, "inPostcardToRequest - Unable to extract TO");
    }
    else
    {
      print_to = to;
    }

    const char * print_req = NOT_AVAILABLE;
    const char * req = 0;
    if (0 != card->getString("REQ", &req))
    {
      log_warning (TAG, "inPostcardToRequest - Unable to extract REQ");
    }
    else
    {
      print_req = req;
    }

    log_info(TAG, "inPostcardToRequest - FROM: %s, TO:   %s, REQ:  %s",
        print_from, print_to, print_req);

    // Request ID
    uint32 req_id = 0;
    extractUInt32(*card, "inPostcardToRequest", "REQ_ID", req_id);

    // Create the request
    if(0 == strcmp(req, "LOWI_DISCOVERY_SCAN"))
    {
      // Create the Request
      LOWIDiscoveryScanRequest* disc = new (std::nothrow)LOWIDiscoveryScanRequest(req_id);
      UTILS_BREAK_IF_NULL(disc, success, "inPostcardToRequest - Memory allocation failure!")

      if(false == parseDiscScanParams(req_id, *card, disc))
      {
        success = false;
        delete disc;
        break;
      }
      request = disc;
    }
    else if (0 == strcmp(req, "LOWI_RANGING_SCAN") ||
             0 == strcmp(req, "LOWI_PERIODIC_RANGING_SCAN"))
    {
      success = parseRangScanParams(req_id,
                                    *card,
                                    request,
                                    (0 == strcmp (req, "LOWI_PERIODIC_RANGING_SCAN")));
    }
    else if (0 == strcmp (req, "LOWI_CAPABILITY"))
    {
      request = new (std::nothrow) LOWICapabilityRequest (req_id);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp (req, "LOWI_RESET_CACHE"))
    {
      request = new (std::nothrow) LOWICacheResetRequest (req_id);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp (req, "LOWI_ASYNC_DISCOVERY_SCAN_RESULTS"))
    {
      // Request timeout
      uint32 timeout = 0;
      extractUInt32(*card, "inPostcardToRequest", "REQ_TIMEOUT", timeout);

      log_debug (TAG, "inPostcardToRequest - Request id(%d) REQ_TIMEOUT(%d)",
          req_id, timeout);

      request = new (std::nothrow)LOWIAsyncDiscoveryScanResultRequest (req_id, timeout);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp (req, "CANCEL_RANGING_SCAN"))
    {
      // WiFi BSSIDs
      uint32 num_of_bssids = 0;
      extractUInt32(*card, "inPostcardToRequest", "NUM_OF_BSSIDS", num_of_bssids);

      log_debug (TAG, "inPostcardToRequest - Request id(%d) NUM_OF_BSSIDS(%u)",
                 req_id, num_of_bssids);

      vector <LOWIMacAddress> vec;
      for (uint32 ii = 0; ii < num_of_bssids; ++ii)
      {
        // For each Node extract the card
        InPostcard* inner = 0;
        int err = card->getCard ("WIFI_BSSID_CARD", &inner, ii);
        if (0 != err || NULL == inner)
        {
          // Unable to get card. break out of for loop.
          // vector will have less entries, which is probably fine
          log_error (TAG, "inPostcardToRequest - Unable to extract WIFI_BSSID_CARD");
          success = false;
          break;
        }

        LOWIMacAddress mac;
        LOWIUtils::extractBssid(*inner, mac);
        vec.push_back (mac);

        delete inner;
      }

      // Create the Ranging scan request
      LOWICancelRangingScanRequest* r = new (std::nothrow)
                   LOWICancelRangingScanRequest (req_id, vec);
      UTILS_BREAK_IF_NULL(r, success, "inPostcardToRequest - Memory allocation failure!")
      request = r;
    }
    else if(0 == strcmp (req, "SET_LCI_INFORMATION"))
    {
      LOWILciInformation params;
      extractLciInfo(card, params, req_id);
      uint32 usageRules;
      extractUInt32(*card, "inPostcardToRequest", "USAGE_RULES", usageRules);

      const char *iface = 0;
      std::string lci_iface;
      if((0 == card->getString("INTERFACE", &iface)))
          lci_iface = iface;

      LOWISetLCILocationInformation *r =
        new (std::nothrow) LOWISetLCILocationInformation(req_id, params, usageRules);
      UTILS_BREAK_IF_NULL(r, success, "inPostcardToRequest - Memory allocation failure!")
      request = r;
      request->set_interface(lci_iface);
    }
    else if(0 == strcmp (req, "SET_LCR_INFORMATION"))
    {
      LOWILcrInformation params;
      extractLcrInfo(card, params, req_id);

      const char *iface = 0;
      std::string lcr_iface;
      if((0 == card->getString("INTERFACE", &iface)))
          lcr_iface = iface;

      LOWISetLCRLocationInformation *r =
        new (std::nothrow) LOWISetLCRLocationInformation(req_id, params);
      UTILS_BREAK_IF_NULL(r, success, "inPostcardToRequest - Memory allocation failure!")
      request = r;
      request->set_interface(lcr_iface);
    }
    else if (0 == strcmp (req, "NEIGHBOR_REPORT"))
    {
      request = new (std::nothrow) LOWINeighborReportRequest (req_id);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp (req, "LOWI_WLAN_STATE_QUERY_REQUEST"))
    {
      uint8 iface = 0;
      extractUInt8(*card, "inPostcardToRequest", "IFACE", iface);
      request = new (std::nothrow) LOWIWLANStateQueryRequest (req_id, to_eLowiWlanInterface(iface));
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp(req, "SEND_LCI_REQUEST"))
    {
      LOWIMacAddress bssid;
      LOWIUtils::extractBssid(*card, bssid);
      request = new(std::nothrow) LOWISendLCIRequest(req_id, bssid);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp(req, "FTM_RANGE_REQ"))
    {
      LOWIMacAddress bssid;
      uint16 randInterval = 0;
      vector<LOWIFTMRRNodeInfo> vec;
      extractFTMRRInfo(card, vec, bssid, randInterval);
      if (0 == vec.getNumOfElements())
      {
        success = false;
        log_error(TAG, "inPostcardToRequest - failed to extract FTMRR Info");
        break;
      }
      request = new(std::nothrow) LOWIFTMRangingRequest(req_id, bssid, randInterval, vec);
      UTILS_BREAK_IF_NULL(request, success, "inPostcardToRequest - Memory allocation failure!")
    }
    else if (0 == strcmp (req, "LOWI_CONFIG_REQUEST"))
    {
      uint8 lowi_variant = (uint8)LOWI_AP;
      uint8 global_log_level = (uint8)EL_INFO;
      bool global_log_enabled = false;
      extractUInt8(*card, "inPostcardToRequest", "LOWI_VARIANT", lowi_variant);
      extractUInt8(*card, "inPostcardToRequest", "GLOBAL_LOG_LEVEL", global_log_level);
      extractBool(*card, "inPostcardToRequest", "GLOBAL_LOG_FLAG", global_log_enabled);
      // Request Mode
      uint8 req_mode = 0;
      extractUInt8(*card, "inPostcardToRequest", "REQUEST_MODE", req_mode);

      uint32 num_of_tags = 0;
      extractUInt32(*card, "inPostcardToRequest", "NUM_OF_TAGS", num_of_tags);

      log_debug (TAG, "inPostcardToRequest - Request id(%d) RequestMode (%u)"
                 "LOWI_VARIANT(%d) GLOBAL_LOG_LEVEL(%d) GLOBAL_LOG_FLAG(%u) NUM_OF_TAGS(%u)",
                 req_id, req_mode, lowi_variant, global_log_level, global_log_enabled, num_of_tags);

      vector <LOWILogInfo> vec;
      for (uint32 ii = 0; ii < num_of_tags; ++ii)
      {
        InPostcard* inner = 0;
        int err = card->getCard ("LOGINFO_CARD", &inner, ii);
        if (0 != err || NULL == inner)
        {
          // Unable to get card. break out of for loop.
          // vector will have less entries, which is probably fine
          log_error (TAG, "inPostcardToRequest - Unable to extract LOGINFO_CARD");
          success = false;
          break;
        }

        LOWILogInfo info;
        inner->getString("TAG", &info.tag);
        extractUInt8(*inner, __FUNCTION__, "LOG_LEVEL", info.log_level);
        vec.push_back (info);

        delete inner;
      }
      LOWIConfigRequest* configReq = new (std::nothrow) LOWIConfigRequest (req_id,
                                     LOWIUtils::to_eConfigRequestMode (req_mode));
      UTILS_BREAK_IF_NULL(configReq, success, "inPostcardToRequest - Memory allocation failure!")

      configReq->mLogInfo = vec;
      configReq->mLowiVariant = LOWIUtils::to_eLOWIVariant(lowi_variant);
      configReq->mLowiGlobalLogLevel = global_log_level;
      configReq->mLowiGlobalLogFlag = global_log_enabled;
      request = configReq;
    }
    else
    {
      success = LOWIUtilsExtn::inPostcardToRequest (*card, &request);
    }
  } while (0);

  if (false == success)
  {
    log_error (TAG, "inPostcardToRequest - Unable to create the Request from the Postcard");
    delete request;
    request = NULL;
  }
  else
  {
    // Set originator of the request
    if (NULL != request)
    {
      request->setRequestOriginator (from);
    }
  }
  return request;
}

bool LOWIUtils::parseDiscScanParams(uint32 &req_id,
                                    InPostcard &card,
                                    LOWIDiscoveryScanRequest *disc)
{
  // Scan Type
  uint8 scan_type = 0;
  extractUInt8(card, "parseDiscScanParams", "SCAN_TYPE", scan_type);

  // Request Mode
  uint8 req_mode = 0;
  extractUInt8(card, "parseDiscScanParams", "REQUEST_MODE", req_mode);

  uint8 band = 0;
  extractUInt8(card, "parseDiscScanParams", "BAND", band);

  bool buffer_cache_bit = false;
  extractBool(card, "parseDiscScanParams", "BUFFER_CACHE_BIT", buffer_cache_bit);

  uint32 measAgeFilter = 0;
  extractUInt32(card, "parseDiscScanParams", "MEAS_AGE_FILTER", measAgeFilter);

  log_info (TAG, "parseDiscScanParams - Request id = %d Scan Type(%d) REQUEST_MODE(%d) BAND(%d) BUFFER_CACHE_BIT(%d) MEAS_AGE_FILTER(%d)",
             req_id, scan_type, req_mode, band, buffer_cache_bit, measAgeFilter);

  uint32 num_of_channels = 0;
  extractUInt32(card, "parseDiscScanParams", "NUM_OF_CHANNELS", num_of_channels);

  vector <LOWIChannelInfo> vec;

  for (uint32 ii = 0; ii < num_of_channels; ++ii)
  {
    // For each Channel extract the card
    InPostcard* inner = 0;
    card.getCard ("CHANNEL_CARD", &inner, ii);
    if (NULL == inner)
    {
      // Unable to allocate memory. break out of for loop.
      // vector will have less entries, which is probably fine
      log_error (TAG, "parseDiscScanParams - Memory allocation failure");
      return false;
    }

    uint32 freq = 0;
    extractUInt32(*inner, "parseDiscScanParams", "FREQUENCY", freq);
    log_debug (TAG, "parseDiscScanParams - FREQUENCY = %d", freq);

    LOWIChannelInfo ch (freq);
    vec.push_back (ch);

    delete inner;
  } // for

  // Fallback tolerance
  uint32 fbTolerance = 0;
  extractUInt32(card, "parseDiscScanParams", "FALLBACK_TOLERANCE", fbTolerance);

  // Request type
  uint8 requestType = 0;
  extractUInt8(card, "parseDiscScanParams", "REQUEST_TYPE", requestType);

  // Time out timestamp
  int64 timeoutTimestamp = 0;
  extractInt64(card, "parseDiscScanParams", "REQ_TIMEOUT", timeoutTimestamp);

  extractBool(card, "parseDiscScanParams", "FULL_BEACON_BIT",
              disc->fullBeaconScanResponse);

  // Extract BSSIDs
  extractBssids (card, disc->scanBssids);

  // Extract SSIDs
  extractSsids (card, disc->scanSsids);

  log_debug(TAG, "parseDiscScanParams - FALLBACK_TOLERANCE(%d) REQUEST_TYPE(%d)"
            " REQ_TIMEOUT(%" PRId64 ") FULL_BEACON(%d)",
            fbTolerance, requestType, timeoutTimestamp,
            disc->fullBeaconScanResponse);

  // populate the request
  disc->band = LOWIUtils::to_eBand (band);
  disc->bufferCacheRequest = buffer_cache_bit;
  disc->measAgeFilterSec = measAgeFilter;
  disc->fallbackToleranceSec = fbTolerance;
  disc->scanType = LOWIUtils::to_eScanType (scan_type);
  disc->requestMode = LOWIUtils::to_eRequestMode (req_mode);
  disc->chanInfo = vec;
  disc->timeoutTimestamp = timeoutTimestamp;

  return true;
}

void LOWIUtils::parseRangReqInfo(uint32 &req_id,
                                 int64 &timeoutTimestamp,
                                 uint8 &rttReportType,
                                 uint32 &num_of_nodes,
                                 InPostcard &card)
{

  // Timeout timestamp
  extractInt64(card, __FUNCTION__, "REQ_TIMEOUT", timeoutTimestamp);
  // Ranging Scan Report Type
  extractUInt8(card, __FUNCTION__, "RANGING_SCAN_REPORT_TYPE", rttReportType);

  // Wifi Nodes
  extractUInt32(card, __FUNCTION__, "NUM_OF_NODES", num_of_nodes);

  log_debug(TAG, "%s - Request id(%d) REQ_TIMEOUT(%" PRId64
            ") RANGING_SCAN_REPORT_TYPE(%u), NUM_OF_NODES(%u)",
            __FUNCTION__, req_id, timeoutTimestamp, rttReportType, num_of_nodes);

}

void LOWIUtils::parseLOWINodeInfo(LOWINodeInfo &info,
                                  InPostcard *inner)
{
  if (inner == NULL)
  {
    log_debug(TAG, "%s - NULL pointer for inner", __FUNCTION__);
    return;
  }
  LOWIUtils::extractBssid(*inner, info.bssid);

  extractUInt32(*inner, __FUNCTION__, "FREQUENCY", info.frequency);

  extractUInt32(*inner, __FUNCTION__, "BAND_CENTER_FREQ1", info.band_center_freq1);

  extractUInt32(*inner, __FUNCTION__, "BAND_CENTER_FREQ2", info.band_center_freq2);

  unsigned char type = 0;
  extractUInt8(*inner, __FUNCTION__, "NODE_TYPE", type);
  info.nodeType = LOWIUtils::to_eNodeType (type);

  uint32 spoof_lo = 0;
  extractUInt32(*inner, __FUNCTION__, "SPOOF_MAC_ID_LO", spoof_lo);
  uint32 spoof_hi = 0;
  extractUInt32(*inner, __FUNCTION__, "SPOOF_MAC_ID_HI", spoof_hi);
  info.spoofMacId.setMac (spoof_hi, spoof_lo);

  uint8 rttType = 0;
  extractUInt8(*inner, __FUNCTION__, "RTT_TYPE", rttType);
  info.rttType = LOWIUtils::to_eRttType (rttType);

  uint8 ranging_bw = 0;
  extractUInt8(*inner, __FUNCTION__, "RANGING_BW", ranging_bw);
  info.bandwidth = LOWIUtils::to_eRangingBandwidth (ranging_bw);

  uint8 ranging_preamble = 0;
  extractUInt8(*inner, __FUNCTION__, "RANGING_PREAMBLE", ranging_preamble);
  info.preamble = LOWIUtils::to_eRangingPreamble (ranging_preamble);

  int8 ranging_phymode = 0;
  extractInt8(*inner, __FUNCTION__, "RANGING_PHYMODE", ranging_phymode);
  info.phyMode = to_eLOWIPhyMode(ranging_phymode);

  uint32 ranging_reporttype = 0;
  extractUInt32(*inner, __FUNCTION__, "RANGING_REPORTTYPE", ranging_reporttype);
  info.reportType = ranging_reporttype;
  extractUInt32(*inner, __FUNCTION__, "FTM_RANGING_PARAMS", info.ftmRangingParameters);

  extractUInt8(*inner, __FUNCTION__, "NUM_PKTS_PER_MEAS", info.num_pkts_per_meas);

  extractUInt8(*inner, __FUNCTION__, "NUM_RETRIES_PER_MEAS", info.num_retries_per_meas);

  extractUInt32(*inner, __FUNCTION__, "RANGING_PARAM_CONTROL", info.paramControl);

  const char *iface = 0;
  if((0 == inner->getString("INTERFACE", &iface)))
      info.interface = iface;
}

bool LOWIUtils::parseRangScanParams(uint32 &req_id,
                                    InPostcard &card,
                                    LOWIRequest* &request,
                                    bool periodic)
{
  int64 timeoutTimestamp = 0;
  uint8 rttReportType = 0;
  uint32 num_of_nodes = 0;
  vector<LOWINodeInfo> baseVec;
  vector<LOWIPeriodicNodeInfo> periodicVec;
  LOWIRangingScanRequest* rang = NULL;

  parseRangReqInfo(req_id, timeoutTimestamp, rttReportType, num_of_nodes, card);

  for (uint32 ii = 0; ii < num_of_nodes; ++ii)
  {
    LOWINodeInfo baseInfo, *info;
    LOWIPeriodicNodeInfo periodicInfo;
    info = (periodic)? &periodicInfo: &baseInfo;
    // For each Node extract the card
    InPostcard* inner = NULL;
    int err = card.getCard ("WIFI_NODE_CARD", &inner, ii);
    if (0 != err || NULL == inner)
    {
      // Unable to get card. break out of for loop.
      // vector will have less entries, which is probably fine
      log_error (TAG, "%s - Unable to extract WIFI_NODE_CARD", __FUNCTION__);
      return false;
    }

    parseLOWINodeInfo(*info, inner);

    log_debug (TAG, "%s - " LOWI_MACADDR_FMT " FREQ(%u - %u,%u) NODE_TYPE(%u) RTT Type(%u) BW(%u)"
               " PREAMBLE(%u) PKTS_PER_MEAS(%u) RETRIES_PER_MEAS(%u) PHYMODE(%d)",
               __FUNCTION__, LOWI_MACADDR(info->bssid), info->frequency, info->band_center_freq1,
               info->band_center_freq2, info->nodeType, info->rttType, info->bandwidth,
              info->preamble, info->num_pkts_per_meas, info->num_retries_per_meas, info->phyMode);

    if (periodic)
    {
      extractUInt8(*inner, "parseRangScanParams", "PERIODIC", periodicInfo.periodic);
      extractUInt32(*inner, "parseRangScanParams", "MEAS_PERIOD", periodicInfo.meas_period);
      extractUInt32(*inner, "parseRangScanParams", "NUM_MEASUREMENTS", periodicInfo.num_measurements);

      log_debug (TAG, "%s -  PERIODIC(%u) PERIOD(%u) COUNT(%u)",
                 __FUNCTION__, periodicInfo.periodic, periodicInfo.meas_period,
                 periodicInfo.num_measurements);

      periodicVec.push_back (periodicInfo);
    }
    else
    {
      baseVec.push_back (baseInfo);
    }

    delete inner;
  }

  if (periodic)
  {
    // Create the Periodic Ranging scan request
    rang = new (std::nothrow) LOWIPeriodicRangingScanRequest (req_id, periodicVec, timeoutTimestamp);
  }
  else
  {
    // Create the Ranging scan request
    rang = new (std::nothrow) LOWIRangingScanRequest (req_id, baseVec, timeoutTimestamp);
  }

  if(rang == NULL)
  {
    log_debug (TAG, "%s - Memory allocation failure!", __FUNCTION__);
    return false;
  }
  rang->setReportType(LOWIUtils::to_eRttReportType (rttReportType));
  request = rang;

  return true;
}

bool LOWIUtils::extractBssid(InPostcard &inner, LOWIMacAddress& bssid)
{
  bool retVal = false;
  unsigned int bssid_lo = 0;
  do
  {
    if (0 != inner.getUInt32("BSSID_LO", bssid_lo))
    {
      log_warning (TAG, "%s() - Unable to extract BSSID_LO", __FUNCTION__);
      break;
    }
    unsigned int bssid_hi = 0;
    if (0 != inner.getUInt32 ("BSSID_HI", bssid_hi))
    {
      log_warning (TAG, "%s() - Unable to extract BSSID_HIGH", __FUNCTION__);
      break;
    }

    bssid.setMac (bssid_hi, bssid_lo);
    retVal = true;
  }
  while (0);

  return retVal;
}

bool LOWIUtils::extractBssids(InPostcard &inner, vector<LOWIMacAddress>& bssids)
{
  bool retVal = false;

  uint32 length = 0;
  int ret = inner.getUInt32 ("NUM_OF_BSSIDS", length);
  if (0 == ret)
  {
    log_verbose (TAG, "%s - Num of BSSIDs found %d",
                 __FUNCTION__, length);
    for (uint32 ii = 0; ii < length; ++ii)
    {
      InPostcard* bssid_card = 0;
      int err = inner.getCard("BSSID_CARD", &bssid_card, ii);
      if( 0 != err || NULL == bssid_card )
      {
        // Unable to get card. break out of for loop.
        log_debug (TAG, "%s - Unable to extract BSSID_CARD", __FUNCTION__);
        break;
      }
      else
      {
        LOWIMacAddress bssid;
        if (true == extractBssid (*bssid_card, bssid) )
        {
          bssids.push_back (bssid);
        }
      }
    } // for
    retVal = true;
  }

  log_verbose (TAG, "%s: Total BSSIDs found = %d",
               __FUNCTION__, bssids.getNumOfElements ());
  return retVal;
}

bool LOWIUtils::extractCFRCIR(InPostcard &inner, uint8 *cfrcir)
{
  bool retVal = false;

  const void* blob = NULL;
  size_t length = 0;
  if (0 == inner.getBlob ("CFR_CIR", &blob, &length))
  {
    uint8* p_cfrcir = (uint8*) blob;
    memcpy(cfrcir, p_cfrcir, length);
    retVal = true;
  }
  else
  {
    log_verbose (TAG, "%s - Unable to extract"
        " CFR CIR. It is invalid", __FUNCTION__);
  }
  return retVal;
}

bool LOWIUtils::extractSsid(InPostcard &inner, LOWISsid& ssid)
{
  bool retVal = false;

  const void* blob = NULL;
  size_t length = 0;
  if (0 == inner.getBlob ("SSID", &blob, &length))
  {
    uint8* p_ssid = (uint8*) blob;
    ssid.setSSID(p_ssid, length);
    retVal = true;
  }
  else
  {
    log_verbose (TAG, "%s - Unable to extract"
        " SSID. It is invalid", __FUNCTION__);
  }
  return retVal;
}

bool LOWIUtils::extractSsids(InPostcard &inner, vector<LOWISsid>& ssids)
{
  bool retVal = false;

  uint32 length = 0;
  int ret = inner.getUInt32 ("NUM_OF_SSIDS", length);
  if (0 == ret)
  {
    log_verbose (TAG, "%s - Num of SSIDs found %d",
                 __FUNCTION__, length);
    for (uint32 ii = 0; ii < length; ++ii)
    {
      InPostcard* ssid_card = 0;
      int err = inner.getCard("SSID_CARD", &ssid_card, ii);
      if( 0 != err || NULL == ssid_card )
      {
        // Unable to get card. break out of for loop.
        log_debug (TAG, "%s - Unable to extract CARD", __FUNCTION__);
        break;
      }
      else
      {
        LOWISsid ssid;
        if (true == extractSsid (*ssid_card, ssid) )
        {
          ssids.push_back (ssid);
        }
      }
    } // for
    retVal = true;
  }

  log_verbose (TAG, "%s: Total SSIDs found = %d",
               __FUNCTION__, ssids.getNumOfElements ());
  return retVal;
}

void LOWIUtils::addBssidToCard(OutPostcard &card, const LOWIMacAddress &bssid)
{
  unsigned int mac = bssid.getLo24 ();
  card.addUInt32 ("BSSID_LO", mac);
  mac = bssid.getHi24 ();
  card.addUInt32 ("BSSID_HI", mac);
}

bool LOWIUtils::addBssidsToCard(OutPostcard &card,
                                const vector<LOWIMacAddress>& bssids)
{
  bool retVal = false;
  uint32 cards_added = 0;
  do
  {
    if (0 == bssids.getNumOfElements ())
    {
      // No Bssids to be added
      break;
    }
    for (uint32 ii = 0; ii < bssids.getNumOfElements(); ++ii)
    {
      OutPostcard* bss_card = NULL;
      bss_card = OutPostcard::createInstance();
      if (NULL == bss_card)
      {
        break;
      }

      bss_card->init();
      addBssidToCard (*bss_card, bssids[ii]);
      bss_card->finalize();

      if (0 == card.addCard ("BSSID_CARD", bss_card))
      {
        ++cards_added;
      }
      delete bss_card;
    }
    card.addUInt32 ("NUM_OF_BSSIDS", cards_added);
    retVal = true;
  } while (0);
  log_debug (TAG, "%s: BSSIDs added %d", __FUNCTION__, cards_added);
  return retVal;
}

bool LOWIUtils::addSsidsToCard(OutPostcard &card,
                               const vector<LOWISsid>& ssids)
{
  bool retVal = false;
  uint32 cards_added = 0;
  do
  {
    if (0 == ssids.getNumOfElements ())
    {
      // No Ssids to be added
      break;
    }
    for (uint32 ii = 0; ii < ssids.getNumOfElements(); ++ii)
    {
      OutPostcard* ssid_card = NULL;
      ssid_card = OutPostcard::createInstance();
      if (NULL == ssid_card)
      {
        break;
      }

      ssid_card->init();
      addSsidToCard (*ssid_card, ssids[ii]);
      ssid_card->finalize();

      if (0 == card.addCard ("SSID_CARD", ssid_card))
      {
        ++cards_added;
      }
      delete ssid_card;
    }
    card.addUInt32 ("NUM_OF_SSIDS", cards_added);
    retVal = true;
  } while (0);
  log_debug (TAG, "%s: SSIDs added %d", __FUNCTION__, cards_added);
  return retVal;
}

void LOWIUtils::addCFRCIRToCard(OutPostcard &card, uint8 *cfrcir, uint32 len)
{
  // Insert the CFR CIR as a blob

    uint8 *LocData = new (std::nothrow) uint8 [len];
    if(LocData != NULL)
    {
      memcpy(LocData, cfrcir, len);
      const void* blob = (const void*) (LocData);
      card.addBlob ("CFR_CIR", blob, (size_t)len);
      delete[] LocData;
    }
}
void LOWIUtils::addSsidToCard(OutPostcard &card, const LOWISsid &ssid)
{
  // Insert the SSID as a blob only if the SSID is valid
  if (ssid.isSSIDValid () == true)
  {
    unsigned char ssid_arr[SSID_LEN];
    int ssid_len = 0;
    ssid.getSSID (ssid_arr, &ssid_len);
    const void* blob = (const void*) (ssid_arr);
    // Insert only if SSID length > 0
    if (ssid_len > 0)
    {
      card.addBlob ("SSID", blob, (size_t)ssid_len);
    }
  }
}

bool LOWIUtils::addFTMRRNodeToCard(OutPostcard& card, const LOWIFTMRRNodeInfo& node)
{
  bool result = false;
  do
  {
    // For each bssid create a OutPostcard
    OutPostcard *ftm_node_card = OutPostcard::createInstance();
    if (NULL == ftm_node_card)
    {
      // Unable to allocate memory for inner card
      // break out of for loop
      log_error(TAG, "addFTMRRNodeToCard - Mem allocation failure!");
      break;
    }
    ftm_node_card->init();
    addBssidToCard(*ftm_node_card, node.bssid);

    ftm_node_card->addUInt32("BSSID_INFO", node.bssidInfo);
    ftm_node_card->addUInt8("OPERATING_CLASS", node.operatingClass);
    ftm_node_card->addUInt8("BANDWIDTH", node.bandwidth);
    ftm_node_card->addUInt8("CENTER_CHANEL1", node.center_Ch1);
    ftm_node_card->addUInt8("CENTER_CHANEL2", node.center_Ch2);
    ftm_node_card->addUInt8("CHANEL", node.ch);
    ftm_node_card->addUInt8("PHY_TYPE", node.phyType);

    ftm_node_card->finalize();
    card.addCard("FTMRR_NODE_CARD", ftm_node_card);
    log_debug(TAG, "addFTMRRNodeToCard - Added a node card to the main card");
    delete ftm_node_card;
    result = true;
  } while (0);
  return result;
}

OutPostcard* LOWIUtils::responseToOutPostcard (LOWIResponse* resp,
    const char* to)
{
  OutPostcard* card = NULL;
  const char * resp_type = 0;
  do
  {
    if (NULL == resp)
    {
      log_error (TAG, "responseToOutPostcard - Invalid argument!");
      break;
    }

    switch (resp->getResponseType())
    {
    case LOWIResponse::DISCOVERY_SCAN:
    {
      log_verbose (TAG, "responseToOutPostcard - DISCOVERY_SCAN");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_DISCOVERY_SCAN";
      LOWIDiscoveryScanResponse* response =
          (LOWIDiscoveryScanResponse*) resp;

      card->addUInt8("SCAN_STATUS", response->scanStatus);
      card->addUInt8("SCAN_TYPE", response->scanTypeResponse);
      card->addInt64("PACKET_TIMESTAMP", response->timestamp);
      addBssidToCard (*card, response->self_mac);
      log_verbose(TAG, "%s Fill Local STA MAC " LOWI_MACADDR_FMT ,
                  __FUNCTION__, LOWI_MACADDR(response->self_mac));
      // Scan measurements available
      injectScanMeasurements (*card, response->scanMeasurements);
    }
    break;
    case LOWIResponse::RANGING_SCAN:
    {
      log_verbose (TAG, "responseToOutPostcard - RANGING_SCAN");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_RANGING_SCAN";
      LOWIRangingScanResponse* response =
          (LOWIRangingScanResponse*) resp;

      card->addUInt8("SCAN_STATUS", response->scanStatus);

      // Scan measurements available
      injectScanMeasurements (*card, response->scanMeasurements);
    }
    break;
    case LOWIResponse::CAPABILITY:
    {
      log_verbose (TAG, "responseToOutPostcard - CAPABILITY");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_CAPABILITY";
      LOWICapabilityResponse* response = (LOWICapabilityResponse*) resp;
      LOWICapabilities cap = response->getCapabilities ();

      card->addBool("DISCOVERY_SCAN_SUPPORTED", cap.discoveryScanSupported);
      card->addBool("RANGING_SCAN_SUPPORTED", cap.rangingScanSupported);
      card->addBool("ACTIVE_SCAN_SUPPORTED", cap.activeScanSupported);
      card->addBool("SINGLE_SIDED_RANGING_SCAN_SUPPORTED", cap.oneSidedRangingSupported);
      card->addBool("DUAL_SIDED_RANGING_SCAN_SUPPORTED_11V", cap.dualSidedRangingSupported11v);
      card->addBool("DUAL_SIDED_RANGING_SCAN_SUPPORTED_11MC", cap.dualSidedRangingSupported11mc);
      card->addBool("BGSCAN_SUPPORTED", cap.bgscanSupported);
      card->addUInt8("BW_SUPPORT", cap.bwSupport);
      card->addUInt8("PREAMBLE_SUPPORT", cap.preambleSupport);
      card->addUInt8("MC_VERSION", cap.mcVersion);
      card->addBool("CAPABILITY_STATUS", response->getStatus());
      card->addUInt32("SUPPORTED_CAPABILITY", cap.supportedCapablities);
      card->addUInt32("SUPPORTED_WIGIG_CAPABILITY", cap.supportedCapsWigig);
    }
    break;
    case LOWIResponse::RESET_CACHE:
    {
      log_verbose (TAG, "responseToOutPostcard - RESET_CACHE");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_RESET_CACHE";
      LOWICacheResetResponse* response = (LOWICacheResetResponse*) resp;
      card->addBool("CACHE_STATUS", response->getStatus ());
    }
    break;
    case LOWIResponse::ASYNC_DISCOVERY_SCAN_RESULTS:
    {
      log_verbose (TAG, "responseToOutPostcard -"
          " ASYNC_DISCOVERY_SCAN_RESULTS");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_ASYNC_DISCOVERY_SCAN_RESULTS";
      LOWIAsyncDiscoveryScanResultResponse* response =
          (LOWIAsyncDiscoveryScanResultResponse*) resp;

      card->addUInt8("SCAN_STATUS", response->scanStatus);
      card->addUInt8("SCAN_TYPE", response->scanTypeResponse);
      card->addInt64("PACKET_TIMESTAMP", response->timestamp);
      // Scan measurements available
      injectScanMeasurements (*card, response->scanMeasurements);
    }
    break;
    case LOWIResponse::LOWI_STATUS:
    {
      log_verbose (TAG, "responseToOutPostcard -"
          " LOWI_STATUS");
      card = OutPostcard::createInstance();
      if (NULL == card) break;

      card->init();
      resp_type = "LOWI_STATUS";
      LOWIStatusResponse *response = (LOWIStatusResponse*)resp;

      card->addUInt8("LOWI_STATUS", response->scanStatus);
      card->addUInt8("REQ_TYPE", response->mRequestType);
    }
    break;
    case LOWIResponse::LOWI_WLAN_STATE_QUERY_RESPONSE:
    {
      log_verbose (TAG, "responseToOutPostcard - LOWI_WLAN_STATE_QUERY_RESPONSE");
      card = OutPostcard::createInstance();
      if( NULL == card )
      {
        break;
      }

      card->init();
      resp_type = "LOWI_WLAN_STATE_QUERY_RESPONSE";
      LOWIWlanStateQueryResponse* response = (LOWIWlanStateQueryResponse*) resp;
      card->addUInt8("SCAN_STATUS", response->status);
      card->addBool("CONNECTED", response->connected);
      addBssidToCard(*card, response->connectedNodeBssid);
      card->addUInt32("FREQ",response->connectedNodeFreq);
      card->addInt16("RSSI",response->connectedNodeRssi);
      addSsidToCard(*card, response->connectedNodeSsid);
    }
    break;
    default:
      card = LOWIUtilsExtn::responseToOutPostcard (resp);
      break;
    }
  } while (0);

  if (NULL == card)
  {
    log_error (TAG, "responseToOutPostcard - Unable to create the post card");
  }
  else
  {
    // Common to all type of requests
    card->addString("TO", to);
    card->addString("FROM", SERVER_NAME);
    card->addUInt32("REQ_ID", resp->getRequestId ());
    if (resp_type != NULL)
    {
      card->addString("RESP", resp_type);
      log_info(TAG, "responseToOutPostcard - TO: %s, FROM:   %s, RESP:  %s",
               to, SERVER_NAME, resp_type);
    }
    // Add TX-ID of type int32 as a standard field in postcard
    card->addInt32("TX-ID", resp->getRequestId ());
    card->finalize ();
  }

  return card;
}

bool LOWIUtils::injectScanMeasurements (OutPostcard & card,
    vector <LOWIScanMeasurement*> & meas)
{
  bool retVal = false;
  do
  {
    uint32 num_of_scans = meas.getNumOfElements();

    log_debug (TAG, "%s - num of APs = %d", __FUNCTION__,
               num_of_scans);
    card.addUInt32 ("NUM_OF_SCANS", num_of_scans);

    // For each scan measurement - insert a Post card
    for (uint32 ii = 0; ii < num_of_scans; ++ii)
    {
      OutPostcard* scan_card = OutPostcard::createInstance ();
      if (NULL == scan_card)
      {
        log_error (TAG, "injectScanMeasurements - Memory allocation failure!");
        break;
      }

      scan_card->init();

      if (NULL == meas[ii])
      {
        log_debug (TAG, "injectScanMeasurements - NULL(%u)", ii);
        delete scan_card;
        break;
      }

      meas[ii]->bssid.print();

      // Inject the Scan Measurement Type
      scan_card->addUInt8("SCAN_M_TYPE", meas[ii]->getScanMeasurementType());

      addBssidToCard (*scan_card, meas[ii]->bssid);

      unsigned int freq = meas[ii]->frequency;
      scan_card->addUInt32 ("FREQUENCY", freq);

      scan_card->addBool ("IS_SECURE", meas[ii]->isSecure);

      scan_card->addBool ("ASSOCIATED", meas[ii]->associatedToAp);

      unsigned char temp = meas[ii]->type;
      scan_card->addUInt8 ("NODE_TYPE", temp);

      unsigned char rttType = meas[ii]->rttType;
      scan_card->addUInt8 ("RTT_TYPE", rttType);

      scan_card->addUInt64 ("MEAS_ADDITION_INFO", meas[ii]->measAdditionalInfoMask);
      addSsidToCard (*scan_card, meas[ii]->ssid);

      if (NULL != meas[ii]->msapInfo)
      {
        scan_card->addUInt8 ("MSAP_PROT_VER",
            meas[ii]->msapInfo->protocolVersion);
        scan_card->addUInt32 ("MSAP_VENUE_HASH",
            meas[ii]->msapInfo->venueHash);
        scan_card->addUInt8 ("MSAP_SERVER_IDX",
            meas[ii]->msapInfo->serverIdx);
      }

      // Inject cell power
      scan_card->addInt8 ("CELL_POWER", meas[ii]->cellPowerLimitdBm);

      // Inject Country code
      scan_card->addArrayUInt8("COUNTRY_CODE", LOWI_COUNTRY_CODE_LEN, meas[ii]->country_code);

      // Inject Indoor / Outdoor
      scan_card->addUInt8("INDOOR_OUTDOOR", meas[ii]->indoor_outdoor);

      // Inject the measurement number
      scan_card->addUInt32("MEASUREMENT_NUM", meas[ii]->measurementNum);

      //inject the RTT target status code
      scan_card->addUInt32("RTT_TARGET_STATUS", (uint32)meas[ii]->targetStatus);

      // Inject the beacon period
      scan_card->addUInt16("BEACON_PERIOD", meas[ii]->beaconPeriod);

      // Inject the beacon capabilities
      scan_card->addUInt16("BEACON_CAPS", meas[ii]->beaconCaps);

      // Inject the beacon period
      scan_card->addUInt32("BEACON_STATUS", meas[ii]->beaconStatus);

      // Inject the ie data
      injectIeData(*scan_card, meas[ii]->ieData);

      // Inject the Number of RTT frames attempted.
      scan_card->addUInt16("NUM_RTT_FRAMES_ATTEMPTED", meas[ii]->num_frames_attempted);
      // Inject the actual time taken to complete rtt measurement.
      scan_card->addUInt16("ACTUAL_BURST_DURATION", meas[ii]->actual_burst_duration);
      // Inject FTM frames per burst negotiated with target.
      scan_card->addUInt8("NEGOTIATED_NUM_FRAMES_PER_BURST", meas[ii]->negotiated_num_frames_per_burst);
      // Inject the time after which FTM session can be retried.
      scan_card->addUInt8("RETRY_RTT_AFTER_DURATION", meas[ii]->retry_after_duration);
      // Inject number of FTM bursts negotiated with the target.
      scan_card->addUInt8("NEGOTIATED_BURST_EXPONENT", meas[ii]->negotiated_burst_exp);

      if (NULL != meas[ii]->lciInfo)
      {
        scan_card->addUInt8("LCI_INFO_ID", meas[ii]->lciInfo->id);
        scan_card->addUInt8("LCI_INFO_LEN", meas[ii]->lciInfo->len);
        injectLocationIeData(*scan_card, meas[ii]->lciInfo->locData,
                             meas[ii]->lciInfo->len, "LCI");
      }

      if (NULL != meas[ii]->lcrInfo)
      {
        scan_card->addUInt8("LCR_INFO_ID", meas[ii]->lcrInfo->id);
        scan_card->addUInt8("LCR_INFO_LEN", meas[ii]->lcrInfo->len);
        injectLocationIeData(*scan_card, meas[ii]->lcrInfo->locData,
                             meas[ii]->lcrInfo->len, "LCR");
      }

      scan_card->addInt8("PHY_MODE", meas[ii]->phyMode);
      scan_card->addUInt32("MAX_TX_RATE", meas[ii]->maxTxRate);
      scan_card->addUInt8("ENCRYPTION", meas[ii]->encryptionType);
      scan_card->addUInt64("TARGET_TSF", meas[ii]->targetTSF);

      if (NULL != meas[ii]->aoaMeasurement)
      {
        scan_card->addDouble("AZIMUTH", meas[ii]->aoaMeasurement->mAzimuth);
        scan_card->addDouble("ELEVATION", meas[ii]->aoaMeasurement->mElevation);
      }

      // Inject measurement info
      injectMeasurementInfo (*scan_card, meas[ii]->measurementsInfo);

      // Check the type of the ScanMeasurement class and see if additional
      // info is to be injected
      if (LOWIScanMeasurement::LOWI_FULL_BEACON_SCAN_MEASUREMENT ==
          meas[ii]->getScanMeasurementType ())
      {
        log_verbose (TAG, "injectScanMeasurements : Full Beacon Scan measurements");
        LOWIFullBeaconScanMeasurement* fm =
          (LOWIFullBeaconScanMeasurement*) meas[ii];
        if (NULL != fm)
        {
          injectLocationIEs (*scan_card, fm->mLOWIIE);
        }
      }
      else if (LOWIScanMeasurement::LOWI_RANGING_SCAN_MEASUREMENT ==
          meas[ii]->getScanMeasurementType ())
      {
        log_verbose (TAG, "injectScanMeasurements : Ranging Scan measurements");
        LOWIRangingScanMeasurement* fm =
          (LOWIRangingScanMeasurement*) meas[ii];
        if (NULL != fm)
        {
          injectRangingScanMeasurements (*scan_card, *fm);
        }
      }

      scan_card->finalize();

      card.addCard ("SCAN_MEAS_CARD", scan_card);
      delete scan_card;
      retVal = true;
    }
  } while (0);

  return retVal;
}

bool LOWIUtils::injectMeasurementInfo (OutPostcard & card,
    vector <LOWIMeasurementInfo*> & info)
{
  bool retVal = false;
  do
  {
    uint32 num_of_meas = info.getNumOfElements();

    card.addUInt32 ("NUM_OF_MEAS", num_of_meas);

    // For each measurement info - insert a Post card
    for (uint32 ii = 0; ii < num_of_meas; ++ii)
    {
      OutPostcard* meas_card = OutPostcard::createInstance ();
      if (NULL == meas_card)
      {
        log_error (TAG, "injectMeasurementInfo - Memory allocation failure!");
        break;
      }

      meas_card->init();

      meas_card->addInt64 ("RSSI_TIMESTAMP", info[ii]->rssi_timestamp);
      meas_card->addInt16 ("RSSI", info[ii]->rssi);
      meas_card->addInt32("MEAS_AGE", info[ii]->meas_age);
      meas_card->addInt64 ("RTT_TIMESTAMP", info[ii]->rtt_timestamp);
      meas_card->addInt32 ("RTT_PS", info[ii]->rtt_ps);
      meas_card->addUInt8("TX_PREAMBLE", info[ii]->tx_preamble);
      meas_card->addUInt8("TX_NSS", info[ii]->tx_nss);
      meas_card->addUInt8("TX_BW", info[ii]->tx_bw);
      meas_card->addUInt8("TX_MCS_IDX", info[ii]->tx_mcsIdx);
      meas_card->addUInt32("TX_BIT_RATE", info[ii]->tx_bitrate);
      meas_card->addUInt8("RX_PREAMBLE", info[ii]->rx_preamble);
      meas_card->addUInt8("RX_NSS", info[ii]->rx_nss);
      meas_card->addUInt8("RX_BW", info[ii]->rx_bw);
      meas_card->addUInt8("RX_MCS_IDX", info[ii]->rx_mcsIdx);
      meas_card->addUInt32("RX_BIT_RATE", info[ii]->rx_bitrate);
      meas_card->addInt8("TX_CHAIN_NO", info[ii]->tx_chain_no);
      meas_card->addInt8("RX_CHAIN_NO", info[ii]->rx_chain_no);

      if(info[ii]->cfrcirInfo) {
        meas_card->addUInt32("CFR_CIR_LENGTH", info[ii]->cfrcirInfo->len);
        addCFRCIRToCard(*meas_card, info[ii]->cfrcirInfo->data, info[ii]->cfrcirInfo->len);
      }

      meas_card->finalize();

      card.addCard ("Measurement_card", meas_card);
      delete meas_card;
      retVal = true;
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::injectRangingScanMeasurements (OutPostcard & card,
                                               LOWIRangingScanMeasurement& ranging)
{
  bool retVal = false;
  do
  {
    card.addUInt8 ("MAX_BSS_IND", ranging.maxBssidsIndicator);
    uint32 num = ranging.colocatedBssids.getNumOfElements();

    card.addUInt32 ("NUM_COLOC_BSS", num);
    log_debug (TAG, "%s - NUM_COLOC_BSS(%u), PEER_OEM(%s)",
               __FUNCTION__,
               num,
               to_string(ranging.peerOEM));

    // For each colocated BSS - insert a Post card
    for (uint32 ii = 0; ii < num; ++ii)
    {
      OutPostcard* bss_card = OutPostcard::createInstance ();
      if (NULL == bss_card)
      {
        log_error (TAG, "%s - Memory allocation failure!", __FUNCTION__);
        break;
      }

      log_debug(TAG, "%s - Adding the following co-located BSSID: "  LOWI_MACADDR_FMT,
                __FUNCTION__,
                LOWI_MACADDR(ranging.colocatedBssids[ii]));
      bss_card->init();
      addBssidToCard(*bss_card, ranging.colocatedBssids[ii]);
      bss_card->finalize();

      card.addCard ("BSS_card", bss_card);
      delete bss_card;
    }
    card.addUInt8 ("PEER_OEM", ranging.peerOEM);

    retVal = true;

  } while (0);
  return retVal;
}

bool LOWIUtils::injectLocationIEs (OutPostcard & card,
    vector <LOWILocationIE*> & info)
{
  bool retVal = false;
  do
  {
    uint32 num_of_lie = info.getNumOfElements();

    card.addUInt32 ("NUM_OF_LIE", num_of_lie);
    log_verbose (TAG, "%s - NUM_OF_LIE(%u)", __FUNCTION__, num_of_lie);

    // For each location IE - insert a Post card
    for (uint32 ii = 0; ii < num_of_lie; ++ii)
    {
      OutPostcard* lie_card = OutPostcard::createInstance ();
      if (NULL == lie_card)
      {
        log_error (TAG, "injectLocationIE - Memory allocation failure!");
        break;
      }

      lie_card->init();

      lie_card->addUInt8 ("LIE_ID", info[ii]->id);
      lie_card->addUInt8 ("LIE_LEN", info[ii]->len);
      if (info[ii]->len > 0)
      {
        lie_card->addArrayUInt8("LIE_ARR", info[ii]->len, info[ii]->locData);
      }
      log_verbose(TAG, "%s LIE id = %d, LIE len = %d", __FUNCTION__,
                  info[ii]->id, info[ii]->len);

      lie_card->finalize();

      card.addCard ("LIE_card", lie_card);
      delete lie_card;
      retVal = true;
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::injectIeData (OutPostcard &card,
                              vector <int8> &info)
{
  bool retVal = false;
  do
  {
    uint32 num_of_meas = info.getNumOfElements();

    card.addUInt32 ("NUM_OF_IE", num_of_meas);

    // For each Information Element - insert a Post card
    for (uint32 ii = 0; ii < num_of_meas; ++ii)
    {
      OutPostcard* ie_data_card = OutPostcard::createInstance ();
      if (NULL == ie_data_card)
      {
        log_error (TAG, "injectIeData - Memory allocation failure!");
        break;
      }

      ie_data_card->init();

      ie_data_card->addInt8("IE_DATA", info[ii]);

      ie_data_card->finalize();

      card.addCard ("IE_data_card", ie_data_card);
      delete ie_data_card;
      retVal = true;
    }
  } while (0);
  return retVal;
}

bool LOWIUtils::injectLocationIeData(OutPostcard &card, uint8 *info, uint8 len, char const *type)
{
  bool retVal = false;
  do
  {
    log_verbose (TAG, "injectLocationIeData");

    // Create a card name
    char cardName[LOCATION_IE_DATA_CARD_LEN] = {0};
    snprintf(cardName, sizeof(cardName), "%s%s", "LOCATION_IE_DATA_CARD_", type);

    OutPostcard* location_ie_data_card = OutPostcard::createInstance ();
    if (NULL == location_ie_data_card)
    {
      log_error (TAG, "injectLocationIeData - Memory allocation failure!");
      break;
    }

    location_ie_data_card->init();
    location_ie_data_card->addArrayUInt8(cardName, len, info);
    location_ie_data_card->finalize();

    card.addCard (cardName, location_ie_data_card);
    delete location_ie_data_card;
  } while (0);
  return retVal;
}

////////////////////////////////////////////////////////
// Other util functions
////////////////////////////////////////////////////////
LOWIResponse::eResponseType
LOWIUtils::to_eResponseType (int a)
{
  switch (a)
  {
  case 1:
    return LOWIResponse::DISCOVERY_SCAN;
  case 2:
    return LOWIResponse::RANGING_SCAN;
  case 3:
    return LOWIResponse::CAPABILITY;
  case 4:
    return LOWIResponse::RESET_CACHE;
  case 5:
    return LOWIResponse::ASYNC_DISCOVERY_SCAN_RESULTS;
  default:
    log_warning (TAG, "to_eResponseType - default case");
    return LOWIResponse::RESPONSE_TYPE_UNKNOWN;
  }
}

LOWIResponse::eScanStatus
LOWIUtils::to_eScanStatus (int a)
{
  switch (a)
  {
  case 1:  return LOWIResponse::SCAN_STATUS_SUCCESS;
  case 2:  return LOWIResponse::SCAN_STATUS_BUSY;
  case 3:  return LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
  case 4:  return LOWIResponse::SCAN_STATUS_DRIVER_TIMEOUT;
  case 5:  return LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;
  case 6:  return LOWIResponse::SCAN_STATUS_INVALID_REQ;
  case 7:  return LOWIResponse::SCAN_STATUS_NOT_SUPPORTED;
  case 8:  return LOWIResponse::SCAN_STATUS_NO_WIFI;
  case 9:  return LOWIResponse::SCAN_STATUS_TOO_MANY_REQUESTS;
  case 10: return LOWIResponse::SCAN_STATUS_OUT_OF_MEMORY;
  case 11: return LOWIResponse::SCAN_STATUS_NO_WIGIG;
  default:
    log_warning (TAG, "to_eScanStatus - default case");
    return LOWIResponse::SCAN_STATUS_UNKNOWN;
  }
}

LOWIDiscoveryScanResponse::eScanTypeResponse
LOWIUtils::to_eScanTypeResponse (int a)
{
  switch (a)
  {
  case 1:
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_PASSIVE;
  case 2:
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_ACTIVE;
  default:
    log_debug (TAG, "%s:default case - %d", __FUNCTION__, a);
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
  }
}

LOWIDiscoveryScanResponse::eScanTypeResponse
LOWIUtils::to_eScanTypeResponse (LOWIDiscoveryScanRequest::eScanType a)
{
  switch (a)
  {
  case LOWIDiscoveryScanRequest::PASSIVE_SCAN:
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_PASSIVE;
  case LOWIDiscoveryScanRequest::ACTIVE_SCAN:
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_ACTIVE;
  default:
    log_debug (TAG, "%s:default case - %d", __FUNCTION__, a);
    return LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
  }
}

eNodeType LOWIUtils::to_eNodeType (int a)
{
  switch (a)
  {
  case 1:
    return ACCESS_POINT;
  case 2:
    return PEER_DEVICE;
  case 3:
    return NAN_DEVICE;
  case 4:
    return STA_DEVICE;
  case 5:
    return SOFT_AP;
  default:
    log_verbose (TAG, "to_eNodeType - default case");
    return NODE_TYPE_UNKNOWN;
  }
}

eRttType LOWIUtils::to_eRttType (uint8 a)
{
  switch (a)
  {
  case 0:
    return RTT1_RANGING;
  case 1:
    return RTT2_RANGING;
  case 2:
    return RTT3_RANGING;
  default:
    log_verbose (TAG, "to_eRttType - default case - RTT2_RANGING");
    return RTT2_RANGING;
  }
}

eRttReportType LOWIUtils::to_eRttReportType (uint8 a)
{
  switch (a)
  {
  case 0:
    return RTT_REPORT_1_FRAME_CFR;
  case 1:
    return RTT_REPORT_1_FRAME_NO_CFR;
  case 2:
    return RTT_REPORT_AGGREGATE;
  default:
    log_verbose (TAG, "to_eRttReportType - default case - RTT_REPORT_AGGREGATE");
    return RTT_REPORT_AGGREGATE;
  }
}

eRangingBandwidth LOWIUtils::to_eRangingBandwidth (uint8 a)
{
  switch (a)
  {
  case 0:
    return BW_20MHZ;
  case 1:
    return BW_40MHZ;
  case 2:
    return BW_80MHZ;
  case 3:
    return BW_160MHZ;
  default:
    log_verbose (TAG, "to_eRangingBandwidth - default case");
    return BW_20MHZ;
  }
}

eRangingPreamble LOWIUtils::to_eRangingPreamble (uint8 a)
{
  switch (a)
  {
  case 0:
    return RTT_PREAMBLE_LEGACY;
  case 1:
    return RTT_PREAMBLE_HT;
  case 2:
    return RTT_PREAMBLE_VHT;
  default:
    log_verbose (TAG, "to_eRangingPreamble - default case");
    return RTT_PREAMBLE_LEGACY;
  }
}


LOWIDiscoveryScanRequest::eBand LOWIUtils::to_eBand (int a)
{
  switch (a)
  {
  case 0:
    return LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ;
  case 1:
    return LOWIDiscoveryScanRequest::FIVE_GHZ;
  default:
    return LOWIDiscoveryScanRequest::BAND_ALL;
  }
}

LOWIDiscoveryScanRequest::eScanType LOWIUtils::to_eScanType (int a)
{
  switch (a)
  {
  case 1:
    return LOWIDiscoveryScanRequest::ACTIVE_SCAN;
  default:
    return LOWIDiscoveryScanRequest::PASSIVE_SCAN;
  }
}

LOWIDiscoveryScanRequest::eRequestMode LOWIUtils::to_eRequestMode (int a)
{
  switch (a)
  {
  case 1:
    return LOWIDiscoveryScanRequest::NORMAL;
  case 2:
    return LOWIDiscoveryScanRequest::CACHE_ONLY;
  case 3:
    return LOWIDiscoveryScanRequest::CACHE_FALLBACK;
  default:
    return LOWIDiscoveryScanRequest::FORCED_FRESH;
  }
}
LOWIConfigRequest::eConfigRequestMode LOWIUtils::to_eConfigRequestMode (uint8 a)
{
  switch (a)
  {
  case 1:
    return LOWIConfigRequest::LOG_CONFIG;
  case 2:
    return LOWIConfigRequest::LOWI_EXIT;
  default:
    return LOWIConfigRequest::UNKNOWN_MODE;
  }
}

eLOWIVariant LOWIUtils::to_eLOWIVariant (uint8 a)
{
  switch (a)
  {
  case 0:
    return LOWI_AP;
  case 1:
    return LOWI_LP;
  case 2:
    return LOWI_AP_LP_BOTH;
  default:
    return LOWI_AP;
  }
}
qc_loc_fw::ERROR_LEVEL LOWIUtils::to_logLevel (int a)
{
  switch (a)
  {
  case 0:
    return EL_LOG_OFF;
  case 1:
    return EL_ERROR;
  case 2:
    return EL_WARNING;
  case 3:
    return EL_INFO;
  case 4:
    return EL_DEBUG;
  case 5:
    return EL_VERBOSE;
  case 100:
    // Fallback
  default:
    return EL_LOG_ALL;
  }
}

eLowiMotionPattern LOWIUtils::to_eLOWIMotionPattern (uint8 motion)
{
  switch( motion )
  {
    case 0:  return qc_loc_fw::LOWI_MOTION_NOT_EXPECTED;
    case 1:  return qc_loc_fw::LOWI_MOTION_EXPECTED;
    case 2:  return qc_loc_fw::LOWI_MOTION_UNKNOWN;
    default: return qc_loc_fw::LOWI_MOTION_UNKNOWN;
  }
}

int64 LOWIUtils::currentTimeMs ()
{
  struct timeval      present_time;
  int64              current_time_msec = 0;

  // present time: seconds, and nanoseconds
  if (0 == gettimeofday(&present_time, NULL))
  {
    // Calculate absolute expire time (to avoid data overflow)
    current_time_msec = present_time.tv_sec;
    current_time_msec *= 1000;  // convert to milli-seconds

    // covert the nano-seconds portion to milliseconds
    current_time_msec += (present_time.tv_usec + 500) / 1000;
  }
  return current_time_msec;
}

uint32 LOWIUtils::freqToChannel(uint32 freq)
{
  uint32 channel = 0;

  if (freq > BAND_60G_FREQ_BASE)
  {
    for (uint32 chIdx = BAND_60G_CHAN_BEGIN; chIdx <= BAND_60G_CHAN_END; chIdx++)
    {
      if (BAND_60G_FREQ_BASE + BAND_60G_CHAN_SPACING * chIdx == freq)
      {
        channel = chIdx;
        break;
      }
    }
  }
  else
  {
    uint32 freqBase = (freq < BAND_5G_FREQ_BASE) ? BAND_2G_FREQ_BASE : BAND_5G_FREQ_BASE;

    LOWIDiscoveryScanRequest::eBand band;

    band = (freq < BAND_5G_FREQ_BASE ?
            LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ :
            LOWIDiscoveryScanRequest::FIVE_GHZ);

    if (freq == BAND_2G_FREQ_LAST)
    {
      channel = BAND_2G_CHAN_END;
    }
    else if (((freq - freqBase) % WIFI_CHANNEL_SPACING) == 0)
    {
      channel = (freq - freqBase) / WIFI_CHANNEL_SPACING;
    }
    if (!isChannelValid(channel, band))
    {
      log_debug(TAG, "%s: Invalid frequency %u", __FUNCTION__, freq);
      channel = 0;
    }
  }

  return channel;
}

//See eLOWIPhyMode for phymode values
eRangingBandwidth LOWIUtils::phymodeToBw (uint32 a)
{
  switch (a)
  {
    case 14:
    case 15:
      return BW_160MHZ;
    case 10:
    case 13:
      return BW_80MHZ;
    case 6:
    case 7:
    case 9:
    case 12:
      return BW_40MHZ;
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 8:
    case 11:
      return BW_20MHZ;
    default:
      return BW_MAX;
  }
} // phymodeToBw

//See eLOWIPhyMode for phymode values
eRangingPreamble LOWIUtils::phymodeToPreamble (uint32 a)
{
  switch (a)
  {
    case 0:
    case 1:
    case 2:
    case 3:
      return RTT_PREAMBLE_LEGACY;
    case 4:
    case 5:
    case 6:
    case 7:
      return RTT_PREAMBLE_HT;
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    //consider the 160MHZ_SUPPORT too
    case 14:
    case 15:
      return RTT_PREAMBLE_VHT;
    default:
      return RTT_PREAMBLE_MAX;
  }
} // phymodeToPreamble

LOWIDiscoveryScanRequest::eBand LOWIUtils::freqToBand( uint32 freq )
{
  //freqToChannel checks if frequency is a valid frequenecy as well.
  //Returns non-zero only if channel is valid.
  uint32 channel = freqToChannel(freq);
  if (channel)
  {
    return (freq < BAND_5G_FREQ_BASE ?
            LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ :
            LOWIDiscoveryScanRequest::FIVE_GHZ);
  }
  return LOWIDiscoveryScanRequest::BAND_ALL;
}

uint32 LOWIUtils::channelBandToFreq (uint32 channel,
                                     LOWIDiscoveryScanRequest::eBand band)
{
  // If band is not set. Use default band based on channel #
  if ((band != LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ) &&
      (band != LOWIDiscoveryScanRequest::FIVE_GHZ))
  {
    band = (IS_2G_CHANNEL(channel) ?
            LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ :
            LOWIDiscoveryScanRequest::FIVE_GHZ);
  }

  //Check if channel is valid
  if (!isChannelValid(channel, band))
  {
    log_error(TAG, "%s: Invalid band,channel = %d,%u",
              __FUNCTION__, band, channel);
    return 0;
  }
  uint32 freqBase = (band == LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ ?
                     BAND_2G_FREQ_BASE : BAND_5G_FREQ_BASE);
  //special handling for channel 14;
  uint32 freq = (channel == BAND_2G_CHAN_END ? BAND_2G_FREQ_LAST :
                 freqBase + (channel * WIFI_CHANNEL_SPACING));
  log_verbose(TAG, "%s: Band,Channel = %d,%u, Freq = %u",
              __FUNCTION__, band, channel, freq);
  return freq;
}

uint32 LOWIUtils::channelToFreq60G(uint32 channel)
{
  if(channel >= BAND_60G_CHAN_BEGIN && channel <= BAND_60G_CHAN_END)
  {
    return BAND_60G_FREQ_BASE + BAND_60G_CHAN_SPACING * channel;
  }
  return 0;
}

int * LOWIUtils::getChannelsOrFreqs (LOWIDiscoveryScanRequest::eBand band,
    unsigned char & num_channels, bool freq)
{
  int * chan_freq = NULL;
  switch (band)
  {
  case LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ:
  {
    num_channels = sizeof(channelArr_2_4_ghz)/sizeof(channelArr_2_4_ghz[0]);
    chan_freq = new (std::nothrow) int [num_channels];
    if (NULL != chan_freq)
    {
      for (unsigned char ii = 0; ii < num_channels; ++ii)
      {
        if (true == freq)
        {
          chan_freq [ii] = freqArr_2_4_ghz [ii];
        }
        else
        {
          chan_freq [ii] = channelArr_2_4_ghz [ii];
        }
      }
    }
    break;
  }
  case LOWIDiscoveryScanRequest::FIVE_GHZ:
  {
    num_channels = sizeof(channelArr_5_ghz)/sizeof(channelArr_5_ghz[0]);
    chan_freq = new (std::nothrow) int [num_channels];
    if (NULL != chan_freq)
    {
      for (unsigned char ii = 0; ii < num_channels; ++ii)
      {
        if (true == freq)
        {
          chan_freq [ii] = freqArr_5_ghz [ii];
        }
        else
        {
          chan_freq [ii] = channelArr_5_ghz [ii];
        }
      }
    }
    break;
  }
  default:
    // All
    {
      num_channels = sizeof(channelArr_2_4_ghz)/sizeof(channelArr_2_4_ghz[0]);
      num_channels += sizeof(channelArr_5_ghz)/sizeof(channelArr_5_ghz[0]);
      chan_freq = new (std::nothrow) int [num_channels];
      if (NULL != chan_freq)
      {
        // First copy the 2.4 Ghz freq / channels
        unsigned int index = 0;
        for (;index < (sizeof(channelArr_2_4_ghz)/sizeof(channelArr_2_4_ghz[0]));
            ++index)
        {
          if (true == freq)
          {
            chan_freq [index] = freqArr_2_4_ghz [index];
          }
          else
          {
            chan_freq [index] = channelArr_2_4_ghz [index];
          }
        }
        // Copy the 5 Ghz freq / channels
        for (unsigned int ii = 0;
            ii < (sizeof(channelArr_5_ghz)/sizeof(channelArr_5_ghz[0])); ++ii)
        {
          if (true == freq)
          {
            chan_freq [index+ii] = freqArr_5_ghz [ii];
          }
          else
          {
            chan_freq [index+ii] = channelArr_5_ghz [ii];
          }
        }
      }
      break;
    }
  }
  return chan_freq;
}

int * LOWIUtils::getChannelsOrFreqs (vector<LOWIChannelInfo> & v,
    unsigned char & num_channels, bool freq)
{
  int * chan_freq = NULL;
  num_channels = v.getNumOfElements();
  chan_freq = new (std::nothrow) int [num_channels];
  if (NULL != chan_freq)
  {
    for (int ii = 0; ii < num_channels; ++ii)
    {
      if (true == freq)
      {
        chan_freq [ii] = v[ii].getFrequency();
      }
      else
      {
        chan_freq [ii] = v[ii].getChannel();
      }
    }
  }
  return chan_freq;
}

void LOWIUtils::extractLciInfo(InPostcard *const card,
                               LOWILciInformation &params,
                               uint32 &req_id)
{
  extractInt64(*card, "inPostcardToRequest", "LATITUDE", params.latitude);
  extractInt64(*card, "inPostcardToRequest", "LONGITUDE", params.longitude);
  extractInt32(*card, "inPostcardToRequest", "ALTITUDE", params.altitude);
  extractUInt8(*card, "inPostcardToRequest", "LATITUDE_UNC", params.latitude_unc);
  extractUInt8(*card, "inPostcardToRequest", "LONGITUDE_UNC", params.longitude_unc);
  extractUInt8(*card, "inPostcardToRequest", "ALTITUDE_UNC", params.altitude_unc);
  uint8 motion;
  extractUInt8(*card, "inPostcardToRequest", "MOTION_PATTERN", motion);
  params.motion_pattern = LOWIUtils::to_eLOWIMotionPattern(motion);
  extractInt32(*card, "inPostcardToRequest", "FLOOR", params.floor);
  extractInt32(*card, "inPostcardToRequest", "HEIGHT_ABOVE_FLOOR", params.height_above_floor);
  extractInt32(*card, "inPostcardToRequest", "HEIGHT_UNC", params.height_unc);
  log_debug(TAG, "inPostcardToRequest - Request id(%d) LATITUDE(%" PRId64 ") LONGITUDE(%" PRId64
            "), ALTITUDE(%d), LATITUDE_UNC(%u) LONGITUDE_UNC(%u), ALTITUDE_UNC(%u), MOTION(%u), FLOOR(%d), HEIGHT_ABOVE(%d), HEIGHT_UNC(%d)",
            req_id, params.latitude, params.longitude, params.altitude,
            params.latitude_unc, params.longitude_unc, params.altitude_unc,
            params.motion_pattern, params.floor, params.height_above_floor,
            params.height_unc);
}

void LOWIUtils::extractLcrInfo(InPostcard *const card,
                               LOWILcrInformation &params,
                               uint32 &req_id)
{
  // extract the country code
  int num_elements = LOWI_COUNTRY_CODE_LEN;
  memset(&params.country_code, 0, LOWI_COUNTRY_CODE_LEN);

  if (0 != card->getArrayUInt8("LCR_COUNTRY_CODE", &num_elements, params.country_code))
  {
    log_warning (TAG, "inPostcardToRequest - Unable to extract COUNTRY_CODE");
  }
  else
  {
    log_debug (TAG, "LCR_COUNTRY_CODE is %c%c", (char)params.country_code[0], (char)params.country_code[1]);
  }

  // extract the length of the info field
  extractUInt32(*card, "inPostcardToRequest", "LCR_LENGTH", params.length);
  log_debug (TAG, "inPostcardToRequest - Request id(%d) LCR_LENGTH(%u)",
             req_id, params.length);

  // extract the civic information
  num_elements = CIVIC_INFO_LEN;
  memset(&params.civic_info, 0, CIVIC_INFO_LEN);

  if (0 != card->getArrayInt8("LCR_CIVIC_INFO", &num_elements,
                              (PostcardBase::INT8 *)params.civic_info))
  {
    log_warning (TAG, "inPostcardToRequest - Unable to extract LCR_CIVIC_INFO");
  }
  else
  {
    for (uint32 ii = 0; ii < params.length; ++ii)
    {
      log_debug(TAG, "LCR_CIVIC_INFO[%u](%x)", ii, (char)params.civic_info[ii]);
    }
  }
}

LOWIScanMeasurement::eScanMeasurementType
LOWIUtils::to_eScanMeasurementType (uint8 a)
{
  switch (a)
  {
  case 0: return LOWIScanMeasurement::LOWI_SCAN_MEASUREMENT;
  case 1: return LOWIScanMeasurement::LOWI_FULL_BEACON_SCAN_MEASUREMENT;
  case 2: return LOWIScanMeasurement::LOWI_RANGING_SCAN_MEASUREMENT;
  default: return LOWIScanMeasurement::LOWI_SCAN_MEASUREMENT;
  };
}

eLOWIPhyMode
LOWIUtils::to_eLOWIPhyMode (int8 a)
{
  switch (a)
  {
  case -1: return LOWI_PHY_MODE_UNKNOWN;
  case 0: return LOWI_PHY_MODE_11A;
  case 1: return LOWI_PHY_MODE_11G;
  case 2: return LOWI_PHY_MODE_11B;
  case 3: return LOWI_PHY_MODE_11GONLY;
  case 4: return LOWI_PHY_MODE_11NA_HT20;
  case 5: return LOWI_PHY_MODE_11NG_HT20;
  case 6: return LOWI_PHY_MODE_11NA_HT40;
  case 7: return LOWI_PHY_MODE_11NG_HT40;
  case 8: return LOWI_PHY_MODE_11AC_VHT20;
  case 9: return LOWI_PHY_MODE_11AC_VHT40;
  case 10: return LOWI_PHY_MODE_11AC_VHT80;
  case 11: return LOWI_PHY_MODE_11AC_VHT20_2G;
  case 12: return LOWI_PHY_MODE_11AC_VHT40_2G;
  case 13: return LOWI_PHY_MODE_11AC_VHT80_2G;
  case 14: return LOWI_PHY_MODE_11AC_VHT80_80;
  case 15: return LOWI_PHY_MODE_11AC_VHT160;
  case 16: return LOWI_PHY_MODE_11AX_HE20;
  case 17: return LOWI_PHY_MODE_11AX_HE40;
  case 18: return LOWI_PHY_MODE_11AX_HE80;
  case 19: return LOWI_PHY_MODE_11AX_HE80_80;
  case 20: return LOWI_PHY_MODE_11AX_HE160;
  case 21: return LOWI_PHY_MODE_11AX_HE20_2G;
  case 22: return LOWI_PHY_MODE_11AX_HE40_2G;
  case 23: return LOWI_PHY_MODE_11AX_HE80_2G;
  default: return LOWI_PHY_MODE_UNKNOWN;
  };
}

LOWIScanMeasurement::eEncryptionType
LOWIUtils::to_eEncryptionType (uint8 a)
{
  switch (a)
  {
  case 0: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_UNKNOWN;
  case 1: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_OPEN;
  case 2: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WEP;
  case 3: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WPA_PSK;
  case 4: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WPA_EAP;
  default: return LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_UNKNOWN;
  };
}

LOWIScanMeasurement::ePeerOEM
LOWIUtils::to_ePeerOEM (uint8 a)
{
  switch (a)
  {
  case 0: return LOWIScanMeasurement::LOWI_PEER_OEM_UNKNOWN;
  case 1: return LOWIScanMeasurement::LOWI_PEER_OEM_QTI;
  default: return LOWIScanMeasurement::LOWI_PEER_OEM_UNKNOWN;
  };
}

eLowiWlanInterface
LOWIUtils::to_eLowiWlanInterface(uint8 a)
{
  switch (a)
  {
    case 0: return LOWI_DEV_STA;
    case 1: return LOWI_DEV_P2P_CLI;
    case 2: return LOWI_WLAN_DEV_ANY;
    default: return LOWI_WLAN_DEV_ANY;
  };
}

void LOWIUtils::extractFTMRRInfo(InPostcard *const card,
                                 vector<LOWIFTMRRNodeInfo>& params,
                                 LOWIMacAddress& bssid,
                                 uint16& interval)
{
  extractBssid(*card, bssid);
  uint32 num_elm = 0;
  extractUInt32(*card, "extractFTMRRInfo", "NUM_NODES",  num_elm);
  extractUInt16(*card, "extractFTMRRInfo", "RAND_INTER", interval);
  for (uint32 idx = 0; idx < num_elm; idx++)
  {
    // For each Node extract the card
    InPostcard *inner = 0;
    int err = card->getCard("FTMRR_NODE_CARD", &inner, idx);
    if (0 != err || NULL == inner)
    {
      // Unable to get card. break out of for loop.
      log_error(TAG, "extractFTMRRInfo - Unable to extract FTMRR_NODE_CARD");
      return;
    }

    LOWIFTMRRNodeInfo node;
    extractBssid(*inner, node.bssid);
    extractUInt32(*inner, "extractFTMRRInfo", "BSSID_INFO", node.bssidInfo);
    extractUInt8(*inner, "extractFTMRRInfo", "OPERATING_CLASS", node.operatingClass);
    uint8 bw = BW_20MHZ;
    extractUInt8(*inner, "extractFTMRRInfo", "BANDWIDTH", bw);
    node.bandwidth = to_eRangingBandwidth(bw);
    extractUInt8(*inner, "extractFTMRRInfo", "CENTER_CHANEL1", node.center_Ch1);
    extractUInt8(*inner, "extractFTMRRInfo", "CENTER_CHANEL2", node.center_Ch2);
    extractUInt8(*inner, "extractFTMRRInfo", "CHANEL", node.ch);
    extractUInt8(*inner, "extractFTMRRInfo", "PHY_TYPE", node.phyType);
    params.push_back(node);
    delete inner;
  }
}

LOWIResponse::eScanStatus LOWIUtils::to_eLOWIDriverStatus(uint8 err)
{
  switch( err )
  {
    case 0:  return LOWIResponse::SCAN_STATUS_UNKNOWN;
    case 1:  return LOWIResponse::SCAN_STATUS_SUCCESS;
    case 2:  return LOWIResponse::SCAN_STATUS_BUSY;
    case 3:  return LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
    case 4:  return LOWIResponse::SCAN_STATUS_DRIVER_TIMEOUT;
    case 5:  return LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;
    case 6:  return LOWIResponse::SCAN_STATUS_INVALID_REQ;
    case 7:  return LOWIResponse::SCAN_STATUS_NOT_SUPPORTED;
    case 8:  return LOWIResponse::SCAN_STATUS_NO_WIFI;
    case 12: return LOWIResponse::SCAN_STATUS_TOO_MANY_REQUESTS;
    case 13: return LOWIResponse::SCAN_STATUS_OUT_OF_MEMORY;
    default: return LOWIResponse::SCAN_STATUS_UNKNOWN;
  }
}

bool LOWIUtils::isBackgroundScan(LOWIRequest const *request)
{
  if(NULL == request)
  {
    return false;
  }

  LOWIRequest::eRequestType a = request->getRequestType();

  switch( a )
  {
    case LOWIRequest::BGSCAN_CAPABILITIES:            return true;
    case LOWIRequest::BGSCAN_CHANNELS_SUPPORTED:      return true;
    case LOWIRequest::BGSCAN_START:                   return true;
    case LOWIRequest::BGSCAN_STOP:                    return true;
    case LOWIRequest::BGSCAN_CACHED_RESULTS:          return true;
    case LOWIRequest::HOTLIST_SET:                    return true;
    case LOWIRequest::HOTLIST_CLEAR:                  return true;
    case LOWIRequest::SIGNIFINCANT_CHANGE_LIST_SET:   return true;
    case LOWIRequest::SIGNIFINCANT_CHANGE_LIST_CLEAR: return true;
    default:                                          return false;
  }
}

bool LOWIUtils::isBgScanReqAllowedThroughLP(LOWIRequest const *request)
{
  if(NULL == request)
  {
    return false;
  }

  LOWIRequest::eRequestType a = request->getRequestType();

  switch( a )
  {
    case LOWIRequest::BGSCAN_START:                   return true;
    case LOWIRequest::BGSCAN_STOP:                    return true;
    case LOWIRequest::BGSCAN_CACHED_RESULTS:          return true;
    default:                                          return false;
  }
}

void LOWIUtils::hexDump(char *msg, uint32 len)
{
  if (NULL != msg)
  {
    uint32 written = 0;
    int retVal = -1;
    uint32 const MAX_BODY_LEN = 2048;
    char buff[MAX_BODY_LEN];
    memset(buff, 0, MAX_BODY_LEN);
    for (uint32 ii = 0; ii < len && written < MAX_BODY_LEN; ii++)
    {
      retVal = snprintf(buff + written, MAX_BODY_LEN - written, "%02x ", msg[ii]);
      LOWI_BREAK_ON_COND((retVal < 0), debug, "Failed to print msg")
      written += retVal;
    }
    if (retVal >= 0)
    {
      log_debug(TAG, "%s: msg(%s)", __FUNCTION__, buff);
    }
  }
} // hexDump

uint32 LOWIUtils::getCenterFreq1(uint32 primaryFreqMhz)
{
  switch (primaryFreqMhz)
  {
    case 5180: /*  36 */
    case 5260: /*  52 */
    case 5500: /* 100 */
    case 5580: /* 116 */
    case 5660: /* 132 */
    case 5745: /* 149 */
      return primaryFreqMhz + CHANNEL_SPACING_30MHZ;
    case 5200: /*  40 */
    case 5280: /*  56 */
    case 5520: /* 104 */
    case 5600: /* 120 */
    case 5680: /* 136 */
    case 5765: /* 153 */
      return primaryFreqMhz + CHANNEL_SPACING_10MHZ;
    case 5220: /*  44 */
    case 5300: /*  60 */
    case 5540: /* 108 */
    case 5620: /* 124 */
    case 5700: /* 140 */
    case 5785: /* 157 */
      return primaryFreqMhz - CHANNEL_SPACING_10MHZ;
    case 5240: /*  48 */
    case 5320: /*  64 */
    case 5560: /* 112 */
    case 5640: /* 128 */
    case 5720: /* 144 */
    case 5805: /* 161 */
      return primaryFreqMhz - CHANNEL_SPACING_30MHZ;
    case 5825: /* 165 */
    default:
      log_debug(TAG, "%s: Not a valid 5G frequency for RTT(%u)", __FUNCTION__, primaryFreqMhz);
      return primaryFreqMhz;
  }
} // getCenterFreq1

