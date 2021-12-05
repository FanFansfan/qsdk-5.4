/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Cache Manager

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Cache Manager

Copyright (c) 2012-2013, 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <sys/param.h>
#include <lowi_server/lowi_cache_manager.h>
#include <base_util/log.h>
#include <common/lowi_utils.h>


using namespace qc_loc_fw;

const char * const LOWICacheManager::TAG = "LOWICacheManager";

namespace qc_loc_fw
{
int list_comparator(const LOWIScanMeasurement lhs, const LOWIScanMeasurement rhs)
{
  if (lhs.measurementsInfo[0]->rssi_timestamp > rhs.measurementsInfo[0]->rssi_timestamp)
  {
    return -1;
  }
  else if (lhs.measurementsInfo[0]->rssi_timestamp < rhs.measurementsInfo[0]->rssi_timestamp)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}
}

LOWICacheManager::LOWICacheManager(uint32 limit)
{
  log_verbose (TAG, "LOWICacheManager");
  mLimit = limit;
  mLowestAgeMs = -1;
  mLastMeasurementTs = -1;
  associatedToAp = false;
  localStaMacValid = false;
}

LOWICacheManager::~LOWICacheManager()
{
  log_verbose (TAG, "~LOWICacheManager");
}

bool LOWICacheManager::resetCache()
{
  bool retVal = true;
  log_verbose (TAG, "resetCache");
  return retVal;
}

void LOWICacheManager::storeStaMacInCache (LOWIMacAddress staMac)
{
  /** Store flag indicating if local STA's MAC is valid */
  localStaMacValid = true;
  /** Store Local STA Mac address */
  localStaMac = staMac;
  log_verbose(TAG, "%s - Store Local STA MAC address: " LOWI_MACADDR_FMT ,
              __FUNCTION__, LOWI_MACADDR(localStaMac));
}

bool LOWICacheManager::getStaMacInCache (LOWIMacAddress &staMac)
{
  staMac = localStaMac;
  log_verbose(TAG, "%s - Stored Local STA MAC address: " LOWI_MACADDR_FMT ,
              __FUNCTION__, LOWI_MACADDR(localStaMac));
  return localStaMacValid;
}

bool LOWICacheManager::putInCache (vector<LOWIScanMeasurement*> & measurements,
    bool result_from_lowilp, bool isRangingScan)
{
  bool retVal = true;
  if (measurements.getNumOfElements() != 0)
  {
    List<LOWIScanMeasurement> newMeasurements;
    log_debug(TAG, "%s:Num of Meas to add: %u", __FUNCTION__, measurements.getNumOfElements());
    for (unsigned int i = 0; i< measurements.getNumOfElements(); ++i)
    {
      newMeasurements.add(*(measurements[i]));
    }
    if (mMeasurementCache.getSize() != 0)
    {
      /** Update BSSIDs in the cache with new measurements if
       *  new measurements have arrived for them.
       */
      updateCachedMeas(newMeasurements, result_from_lowilp, isRangingScan);
    }

    /** Add new BSSIDs to the Cache only for discovery / snoop scans */
    if (false == isRangingScan)
    {
      addToCache(newMeasurements, result_from_lowilp);
    }
  }
  else
  {
    log_debug(TAG, "%s:No measurements to put in cache", __FUNCTION__);
  }
  return retVal;
}

bool LOWICacheManager::getAssociatedAP (LOWIScanMeasurement &outBssidMeas)
{
  if (associatedToAp)
  {
    outBssidMeas = associatedApMeas;
    log_verbose(TAG, "%s - STA is Associated to: " LOWI_MACADDR_FMT,
                __FUNCTION__,LOWI_MACADDR(outBssidMeas.bssid));
  }
  else
  {
    log_verbose(TAG, "%s - STA is NOT Associated", __FUNCTION__);
  }

  return associatedToAp;
}

void LOWICacheManager::updateScanMeasInfo(LOWIScanMeasurement &scanMeas,
                                          LOWIScanMeasurement &newScanMeas,
                                          bool isRangingScan)
{

  if (newScanMeas.measurementsInfo.getNumOfElements() == 0)
  {
    /* No Measurements, No need to update cache */
    log_verbose(TAG, "%s: No Measurements, not updating " LOWI_MACADDR_FMT,
                __FUNCTION__, LOWI_MACADDR(newScanMeas.bssid));
    return;
  }

  if (isRangingScan)
  {
    /* Update only the peer information from the ranging scan results */
    /* This is done only for 2-sided RTT */
    if (newScanMeas.rttType == RTT3_RANGING)
    {
      scanMeas.peerOEM = newScanMeas.peerOEM;
    }
  }
  else
  {
    newScanMeas.peerOEM = scanMeas.peerOEM;
    scanMeas = newScanMeas;
  }
}

bool LOWICacheManager::updateCachedMeas (List<LOWIScanMeasurement> &newMeasurements,
                                         bool result_from_lowilp,
                                         bool isRangingScan)
{
  bool retVal = true;
  log_verbose (TAG, "updateCachedMeas");

  for (List<LOWIScanMeasurement>::Iterator cacheItr = mMeasurementCache.begin();
       cacheItr != mMeasurementCache.end();
       ++cacheItr)
  {
    LOWIScanMeasurement scanMeas = *cacheItr;
    for (List<LOWIScanMeasurement>::Iterator newMeasItr = newMeasurements.begin(); newMeasItr != newMeasurements.end(); ++newMeasItr)
    {
      LOWIScanMeasurement newScanMeas = *newMeasItr;
      if (scanMeas.bssid.compareTo(newScanMeas.bssid) == 0)
      {
        /** Found BSSID in Cache, update it and move on
         *  Note: Add further checks here if needed before updating the
         *  Cached BSSID */
        LOWIScanMeasurement *scanMeasPtr = cacheItr.ptr();
        if (scanMeasPtr != NULL)
        {
          updateScanMeasInfo(*scanMeasPtr, newScanMeas, isRangingScan);
          if (!isRangingScan) /* Update only for Discovery Scan */
          {
            // Update associated field in cache
            // only if results are not from LOWI LP
            if ((false == result_from_lowilp) && scanMeasPtr->associatedToAp)
            {
              /* Device is associated with this AP. Update associated Status */
              {
                associatedToAp = true;
                associatedApMeas = *(scanMeasPtr);
                log_verbose(TAG, "%s - Associated to AP: " LOWI_MACADDR_FMT,
                          __FUNCTION__,LOWI_MACADDR(associatedApMeas.bssid));
              }
            }
          }
        }
        /* Remove the BSSID from the new scan measurement list */
        newMeasurements.erase(newMeasItr);
        break;
      }
    }
  }
  return retVal;
}

bool LOWICacheManager::addToCache (List<LOWIScanMeasurement> &newMeasurements,
                                   bool result_from_lowilp)
{
  bool retVal = true;


  if (newMeasurements.getSize() > (mLimit - mMeasurementCache.getSize()))
  {

    unsigned int excessMeas = newMeasurements.getSize() - (mLimit - mMeasurementCache.getSize());

    /* Purge 1/2 of the cache */
    unsigned int purgeCount = mLimit/2;

    /** If the purgint 1/2 the cache is not enought make it
     *  equal to the amount of space needed
     */
    purgeCount = MAX(purgeCount, excessMeas);

    /** If the space needed exceeds the cache size, make it equal
     *  to the cache Size.
     */
    purgeCount = MIN(purgeCount, mLimit);

    unsigned int cacheElemetsToKeep = mLimit - purgeCount;

    log_debug(TAG, "%s: Cache Full, Cache Limit: %u, Purging: %u", __FUNCTION__, mLimit, purgeCount);

    mMeasurementCache.sort();

    List<LOWIScanMeasurement>::Iterator it = mMeasurementCache.begin();

    while (it != mMeasurementCache.end())
    {
      if (cacheElemetsToKeep)
      {
        cacheElemetsToKeep--;
        ++it;
      }
      else
      {
        it = mMeasurementCache.erase(it);
      }
    }

    log_verbose(TAG, "%s:Purging Done", __FUNCTION__);
  }
  else
  {
    log_verbose(TAG,"%s:Cache Not Full", __FUNCTION__);
  }

  for (List<LOWIScanMeasurement>::Iterator pIt = newMeasurements.begin(); pIt != newMeasurements.end(); ++pIt)
  {
    if (mLimit > mMeasurementCache.getSize())
    {
      LOWIScanMeasurement newScanMeas = *pIt;
      mMeasurementCache.add(newScanMeas);
      // Check if the results are from LOWI-LP and update associated field in cache
      // only if they are not
      if (false == result_from_lowilp)
      {
        /* Check to see if we are now associated with this AP and update associated Status*/
        if (newScanMeas.associatedToAp)
        {
          associatedToAp = true;
          associatedApMeas = newScanMeas;
          log_verbose(TAG, "%s - Associated to AP: " LOWI_MACADDR_FMT,
                      __FUNCTION__,LOWI_MACADDR(associatedApMeas.bssid));
        }
      }
      log_verbose(TAG, "%s - Cache Size: %u, Added Element Size: %u, New Cache size: %u",
                  __FUNCTION__,
                  sizeof(mMeasurementCache),
                  sizeof(newScanMeas),
                  mMeasurementCache.getSize());
    }
    else
    {
      log_warning(TAG, "%s - Cache Full! - this should never happen", __FUNCTION__);
      retVal = false;
      break;
    }
  }

  return retVal;
}

int32 LOWICacheManager::getFromCache (int64 /* timestamp */,
    vector<LOWIScanMeasurement*> & /* v */)
{
  int32 retVal = -1;
  log_verbose (TAG, "getFromCache");
  return retVal;
}

int32 LOWICacheManager::getFromCache (int64 /* cache_timestamp  */,
    int64 /* fallback_timestamp */,
    LOWIDiscoveryScanRequest::eBand /* band */,
    vector<LOWIScanMeasurement*> & /* v */,
    int64& /* latest_cached_timestamp */)
{
  int32 retVal = -1;
  log_verbose (TAG, "getFromCache");
  return retVal;
}

int32 LOWICacheManager::getFromCache (int64 /* cache_timestamp */,
    int64 /* fallback_timestamp */,
    vector <LOWIChannelInfo> & /* chanInfo */,
    vector<LOWIScanMeasurement*> & /* v */,
    int64& /* latest_cached_timestamp */)
{
  int32 retVal = -1;
  log_verbose (TAG, "getFromCache");
  return retVal;
}

boolean LOWICacheManager::getFromCache (LOWIMacAddress bssid,
                                        LOWIScanMeasurement &scanMeasurement)
{
  boolean retVal = false;
  log_verbose(TAG, "%s - BSSID: " LOWI_MACADDR_FMT, __FUNCTION__,LOWI_MACADDR(bssid));
  for (List<LOWIScanMeasurement>::Iterator it = mMeasurementCache.begin(); it != mMeasurementCache.end(); ++it)
  {
    LOWIScanMeasurement scanMeas = *it;
    // if the BSSID matches and the primary 20MHz channel was populated
    // from a scan (and not rtt request), return the scan measurement
    // from cache
    if ((scanMeas.bssid.compareTo(bssid) == 0) &&
        (0 != scanMeas.band_center_freq1[BW_20MHZ]))
    {
      log_verbose(TAG, "%s: Found BSSID" LOWI_MACADDR_FMT " in Cache - Freq: %u, "
                  "centerFreq1[20:40:80:160] = [%u:%u:%u:%u], centerFreq2 = %u info: %u tsfDelta: %u",
                  __FUNCTION__,
                  LOWI_MACADDR(scanMeas.bssid),
                  scanMeas.frequency,
                  scanMeas.band_center_freq1[BW_20MHZ],
                  scanMeas.band_center_freq1[BW_40MHZ],
                  scanMeas.band_center_freq1[BW_80MHZ],
                  scanMeas.band_center_freq1[BW_160MHZ],
                  scanMeas.band_center_freq2,
                  scanMeas.info,
                  scanMeas.tsfDelta);
      scanMeasurement = scanMeas;
      retVal = true;
      break;
    }
  }
  return retVal;
}

int32 LOWICacheManager::checkMeasurementValidity (int64 /* timestamp */,
    LOWIChannelInfo* /* p_channel */)
{
  int32 retVal = -1;
  log_verbose (TAG, "checkMeasurementValidity");
  return retVal;
}

bool LOWICacheManager::getFreqFromCache(LOWIMacAddress mac, uint32 &freq)
{
  bool retVal = false;
  LOWIScanMeasurement scanMeasurement;
  if (true == getFromCache(mac, scanMeasurement))
  {
    freq = scanMeasurement.frequency;
    retVal = true;
    log_verbose(TAG, "%s: Found BSSID in cache, frequency(%u)", __FUNCTION__, freq);
  }
  else
  {
    log_debug(TAG, "%s: No target BSSID in cache", __FUNCTION__);
  }
  return retVal;
}

bool LOWICacheManager::updateResultRecdFrmLP (LOWIMeasurementResult& res)
{
  bool retVal = false;
  if (true == res.isResultFromLOWILP())
  {
    // find the associated AP in the results received from LOWI-LP
    // and mark it associated
    for (unsigned int ii = 0; ii < res.scanMeasurements.getNumOfElements (); ++ii)
    {
      LOWIScanMeasurement * resMeas = res.scanMeasurements[ii];
      if ((true == associatedToAp) &&
          (0 == associatedApMeas.bssid.compareTo(resMeas->bssid)) )
      {
        log_debug (TAG, "%s: Associated AP found" LOWI_MACADDR_FMT,
                   __FUNCTION__, LOWI_MACADDR(resMeas->bssid));
        resMeas->associatedToAp = true;
      }

      // Check for the encryption type and update from Cache
      for (List<LOWIScanMeasurement>::Iterator it =
           mMeasurementCache.begin(); it != mMeasurementCache.end(); ++it)
      {
        LOWIScanMeasurement scanMeas = *it;
        // If the BSSID and operating channel match, update the
        // encryption type from the cache
        if (0 == scanMeas.bssid.compareTo(resMeas->bssid))
        {
          // Copy fields not available in LP results from cached data.
          // If these fields become available in LP results, this list
          // needs to be updated.
          resMeas->encryptionType = scanMeas.encryptionType;
          resMeas->beaconCaps     = scanMeas.beaconCaps;
          resMeas->beaconPeriod   = scanMeas.beaconPeriod;
          resMeas->indoor_outdoor = scanMeas.indoor_outdoor;
          resMeas->maxTxRate      = scanMeas.maxTxRate;
          resMeas->location_features_supported = scanMeas.location_features_supported;
          memcpy(resMeas->country_code, scanMeas.country_code,
                 LOWI_COUNTRY_CODE_LEN);
          log_debug (TAG, "%s: Updated " LOWI_MACADDR_FMT "Enc: %d, CC: %c%c, LOC features: %d",
                     __FUNCTION__, LOWI_MACADDR(resMeas->bssid),
                     resMeas->encryptionType,
                     resMeas->country_code[0], resMeas->country_code[1],
                     resMeas->location_features_supported);
        }
      } // for - inner
    } // for
    retVal = true;
  }
  else
  {
    log_verbose (TAG, "%s: Not from LOWI-LP", __FUNCTION__);
  }
  return retVal;
}
