#ifndef __LOWI_WIFI_DRIVER_INTERFACE_H__
#define __LOWI_WIFI_DRIVER_INTERFACE_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wifi Driver Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Wifi Driver Interface

  Copyright (c) 2012, 2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <inc/lowi_request.h>
#include <lowi_server/lowi_rtt_range_processing.h>
#include <inc/lowi_scan_measurement.h>
#include "lowi_measurement_result.h"
#include <lowi_server/lowi_scan_result_listener.h>
#include <lowi_server/lowi_internal_message_listener.h>
#include <lowi_server/lowi_cache_manager.h>
#include <inc/lowi_response.h>
#include <base_util/config_file.h>
#include <common/lowi_utils.h>
#include <base_util/sync.h>

// V4.0 of the 11mc standard
#define MC_DRAFT_VERSION_40 40
// V5.0 of the 11mc standard
#define MC_DRAFT_VERSION_50 50

namespace qc_loc_fw
{

/**
 * This class is an interface to the WifiDriver
 * and provides abstraction from the underlying
 * driver implementation.
 * Used to issue requests to the underlying wifi driver
 * response are received in a separate thread
 */
class LOWIWifiDriverInterface
{
private:
  static const char* const   TAG;

  /**
   * Sets the HW target type appropriately
   * @param uint32: target type coming from driver
   */
  static void setTargetType(uint32 targetType);

protected:

  ConfigFile             *mConfig;

  LOWICapabilities        mCapabilities;

  BlockingQueue          *mMsgQueue;

  Mutex                  *mMutex;

  const LOWIRequest      *mReq;

  /** Parameter used to pass different configuration flags to FW
   *  Bits 0: 1 -> LP extended batching is supported
   *          0 -> LP extended batching is not supported
   *  Bits 1-31: reserved, set to zero for now
   */
  #define LOWI_LP_EXTENDED_BATCHING_MASK 0x00000001;
  uint32                     mBGscanConfigFlags;

  /**
   * Constructor
   * Starts the WifiDriver
   * @param ConfigFile*    Handle to the config file to read the configuration
   *                       parameters, during the lifetime of this object
   */
  LOWIWifiDriverInterface (ConfigFile* config);

  /**
   * Configure capabilities of the driver from external configuration.
   * The effective capabilities will depend on the actual supported
   * capabilities of the driver.
   *    effectiveCap = configCap && driverCap
   * If want do configure to disable: set configCap.cap to 0
   * If want to configure to enable or do-not-care: set configCap.cap to 1
   * @param [in] configCap   Capabilities that need to be configured.
   */
  virtual void configCapabilities ( LOWICapabilities& configCap );

public:
  /**
   * Mode of listening in Wifi driver.
   * Driver can be asked to listen to events in these modes.
   */
  enum eListenMode
  {
    /** Discovery scan mode */
    DISCOVERY_SCAN,
    /** Ranging scan mode */
    RANGING_SCAN,
    /** Background scan mode */
    BACKGROUND_SCAN,
    /** Request scan mode */
    REQUEST_SCAN
  };

  /** Strings used for debug purposes */
  static const char * modeStr[REQUEST_SCAN+1];

  /** target HW type */
  static uint16           mCurrTargetHW;

  /**
   * Gets the cached measurements from the Wifi driver which
   * are cached by the wifi driver
   *
   * @return Measurements
   */
  virtual LOWIMeasurementResult* getCacheMeasurements ();

  /* Sets the scan type (Active / Passive) for the discovery scan.
  * @param eScanType Scan Type (Active / Passive)
  * @return bool true is success, false otherwise
  */
 virtual bool setDiscoveryScanType (LOWIDiscoveryScanRequest::eScanType type);

  /**
   * Returns the Capabilities of the driver
   * @return Capabilities of the driver
   */
  virtual LOWICapabilities getCapabilities () = 0;
  virtual bool sendCapabilitiesReq (std::string interface) = 0;

  /**
   * Performs the RTT processing and generates the RTTInfo
   * @param vector<LOWIScanMeasurement*> Vector containing scan measurements
   * @return RTTInfo generated
   */
  virtual LOWIRTTInfo* processRTT (vector <LOWIScanMeasurement*> & v);

  /**
   * Blocking call to listen for the scan measurements from the
   * wifi driver. It can also listen to additional file descriptor, if
   * initialized through initFileDescriptor
   * @param LOWIRequest*   Request
   * @param eListenMode Mode of listening, used only if the request is NULL
   * @return Measurement results
   */
  virtual LOWIMeasurementResult* getMeasurements (LOWIRequest* request,
      eListenMode mode) = 0;

  /**
   * Set the Measurment result scan status based on scan return value from
   * wifidriver
   * @param LOWIMeasurementResult* Result
   * @param int retval from the wifidriver once the scan is over.
   */
  void setMeasScanStatus (LOWIMeasurementResult* result, int retVal);
  /**
   * Blocking call to listen for the scan measurements from the
   * wifi driver. It can also listen to additional file descriptor, if
   * initialized through initFileDescriptor
   *
   * NOTE: Currently just handles the BACKGROUND_SCAN mode and forwards
   * all other modes to getMeasurements () call
   *
   * @param LOWIRequest*   Request
   * @param eListenMode Mode of listening, used only if the request is NULL
   * @return Measurement results
   */
  virtual LOWIMeasurementResult* block (LOWIRequest* request,
      eListenMode mode);

  /**
   * Stops listening to the events from the Wifi Driver and unblocks the
   * getMeasurements call. This call unblocks the thread by
   * writing to the initialized file descriptor.
   * Note: This function is called in context of a different thread
   * Note: This function will only work, if initFileDescriptor was called
   *       before calling getMeasurements ()
   * @param eListenMode Mode of listening on which listening is to stop
   * @return 0 - success, other values otherwise
   */
  virtual int unBlock (eListenMode mode);

  /**
   * Terminates the getMeasurements call.
   * This call unblocks the thread by writing to the initialized
   * file descriptor. Note: This function is called in context of
   * a different thread.
   *
   * NOTE: This function will only work, if initFileDescriptor was
   *       called before calling getMeasurements ()
   * @param eListenMode Mode of listening on which listening is to stop
   * @return 0 - success, other values otherwise
   */
  virtual int terminate (eListenMode mode);

  /**
   * Initialize the file descriptor to which the thread will additionally
   * listen to during getMeasurements() in specified mode.
   * @param eListenMode Mode of listening
   * @return 0 - success, other values otherwise
   */
  virtual int initFileDescriptor (eListenMode mode);

  /**
   * Closes the file descriptor.
   * @param eListenMode Mode of listening
   * @return 0 - success, other values otherwise
   */
  virtual int closeFileDescriptor (eListenMode mode);

  /**
   * Sets the LOWI Request - this is called by LOWI controller to
   * pass in the new Request to the LOWI Wifi Driver. The purpose
   * of this call is so that the WiFi Driver can pick up the new
   * request without having to return from the "getMeasurements"
   * call.
   * @param [in] LOWIRequest*: The Current valid Request.
   * @param [in] eListenMode: The Thread Listen Mode -
   *             Ranging/Disc
   */
  virtual void setNewRequest(const LOWIRequest* r, eListenMode mode);

  /**
   * Sets the extended batching flag when LP is present and extended batching is
   * supported.
   */
  virtual void setLPExtendedBatching();

  /**
   * Gets the extended batching flag
   * @return uint32: 1 if extended batching is supported; else 0
   */
  virtual uint32 getLPExtendedBatching() const;

  /**
   * Gets the bgscan configuration flags parameter
   * @return uint32: bgscan config flags
   */
  virtual uint32 getBGscanConfigFlags() const;

  /**
   * Parse and take action on the newly arrived WLAN frame
   * @return NONE
   */
  virtual void processWlanFrame() {}

  /**
   * Get the current interface state of Wi-Fi
   * @return eWifiIntfState: WiFi Interface state
   */
  static eWifiIntfState getInterfaceState(char const *intfName);

  /**
   * This function processes the WiFi interface status update
   * message.
   *
   * @param req: The Wifi Interface Status update Message.
   *
   * @return NONE.
   */
  virtual void processWifiIntfStateMessage(LOWIWifiIntfStateMessage* req);

  /**
   * Destructor
   * Stops the WifiDriver
   */
  virtual ~LOWIWifiDriverInterface () = 0;

  /**
   * Creates appropriate underlying driver based on the available hardware
   * @param ConfigFile*    Handle to the config file to read the configuration
   *                       parameters, during the lifetime of this object
   *
   * @param LOWIScanResultReceiverListener* Handle to the Listener
   *                                        Object to send back
   *                                        Scan results.
   * @param LOWIInternalMessageReceiverListener* Handle to
   *                                             internal Message
   *                                             Listener Object
   *                                             to send back
   *                                             internal
   *                                             Messages.
   * @param LOWICacheManager* Handle to the Cache Manager object.
   *                          This will be used by lower layers to
   *                          access the cache.
   *
   * @return LOWIWifiDriverInterface*: handle to wifi driver if
   *         success, else NULL.
   */
  static LOWIWifiDriverInterface* createInstance (ConfigFile* config,
                                                  LOWIScanResultReceiverListener* scanResultListener,
                                                  LOWIInternalMessageReceiverListener* internalMessageListener,
                                                  LOWICacheManager* cacheManager);

  /**
   * Creates underlying lowi wigig driver based on the available hardware
   *
   * @param ConfigFile*: Handle to the config file to read the configuration
   *                  parameters during the lifetime of this object
   * @param LOWIScanResultReceiverListener*: handle to object listening for scan
   *                                      results
   * @param LOWIInternalMessageReceiverListener*: Handle to object listening for
   *                                           internal messages
   * @param LOWICacheManager*: Handle to the cache manager object. This will be
   *                        used by the lower layers to access teh cache.
   *
   * @return LOWIWifiDriverInterface*: handle to wigig driver if success, else
   *         NULL.
   */
  static LOWIWifiDriverInterface* createWiGigInstance(ConfigFile *config,
                                                      LOWIScanResultReceiverListener *scanResultListener,
                                                      LOWIInternalMessageReceiverListener* internalMessageListener,
                                                      LOWICacheManager* cacheManager);
};
} // namespace
#endif //#ifndef __LOWI_WIFI_DRIVER_INTERFACE_H__
