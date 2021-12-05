#ifndef __LOWI_ROME_WIFI_DRIVER_H__
#define __LOWI_ROME_WIFI_DRIVER_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI ROME Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI ROME Wifi Driver

Copyright (c) 2012-2013, 2017-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <lowi_server/lowi_wifidriver_interface.h>
#include <lowi_server/lowi_cache_manager.h>
#include <base_util/sync.h>
#include "wlan_capabilities.h"
#include "lowi_ranging_fsm.h"
#include "lowi_ranging.h"
#include "lowi_nl80211.h"

namespace qc_loc_fw
{
/**
 * This class implements the WifiDriverInterface
 * and provides implementation for ROME Atheros wifi driver
 */
class LOWIROMEWifiDriver : public LOWIWifiDriverInterface
{
protected:
  static const char* const TAG;
  bool                  mConnectedToDriver;
  uint32                mInternalMsgId;
  unsigned int*         mChList;
  LOWIRangingFSM*       mLowiRangingFsm;
  LOWIRanging*          mLowiRanging;
  LOWIInternalMessageReceiverListener* mInternalMessageListener;
  LOWIRangingFSM::eLowiRangingInterface mLowiRangingInterface;
  /** The Cache Manager object through which the FSM can access
   *  the BSSID cache.
   */
  LOWICacheManager*                        mCacheManager;

  // private copy constructor and assignment operator so that the
  // the instance can not be copied.
  LOWIROMEWifiDriver( const LOWIROMEWifiDriver& rhs );
  LOWIROMEWifiDriver& operator=( const LOWIROMEWifiDriver& rhs );

  /**
   * This function passes in the newly arrived PIPE event to the
   * underlying Rome driver.
   *
   * @param mode: The listenning mode of the Driver thread
   *              - Discovery/Ranging.
   * @param newEvent: The newly arrived PIPE event from LOWI
   *                 controller.
   *
   * @return int: Error code - 0 for success, other values
   *              indicate failures.
   */
  int processPipeEvent(eListenMode mode, RangingPipeEvents newEvent);

  /**
   * This function Sends out a Neighbor Report Request to the WLAn
   * driver to be sent out to the target Access Point.
   *
   * @param NONE.
   *
   * @return NONE.
   */
  void sendNeighborRprtReq();

  /**
   * This function Sends out a Fine Timing Measurement Report
   * Action Frame to the driver to be sent out to the target
   * Access Point.
   *
   * @param req: The Fine Timing Measurements to be sent out.
   *
   * @return NONE.
   */
  void SendFTMRRep(LOWIFTMRangeRprtMessage* req);

  /**
   * Construct the Radio Measurement Report Frame header and the Measurement
   * Report Element header. This is common for the following requests:
   * -- FTMRR
   * -- LCI Report
   * -- Civic Report
   *
   * @param req: LOWI internal request
   * @param frameBody: buffer to be populated with the frame contents
   * @param frameBodyLen: tracks the length of the buffer already populated
   * @param measRptLen: report length so far
   *
   * @return uint8*: NULL if failure, else pointer to the report element
   *         length
   */
  uint8* initMeasRspFrame(LOWIInternalMessage *req, uint8 *frameBody,
                          uint32 &frameBodyLen, uint32 &measRptLen);

  /**
   * Retrieve the frequency information from the Neighbor Report element that
   * came in the Radio Measurement request. This will be used to send back the
   * report.
   *
   * @param node: peer information
   * @param nbrElem: neighbor report element
   */
  void retrieveFreqInfo(LOWIPeriodicNodeInfo &node, NeighborRprtElem &nbrElem);

  /**
   * Process the FTM range report request that came in the Radio
   * Measurement Request.
   *
   * @param dialogTok: The dialog token of the current Radio Measurement Request
   * @param elemLen: Measurement element length
   * @param measReqElement: Measurement request element parameters
   * @param measReqElemBody: Measurement request element body
   * @param sourceMac: The Source MAC address of the frame
   * @param staMac: The local STA MAC address of the frame
   * @param freq: The channel frequency on which the frame arrived
   *
   * @return int8: < 0 if failure, else success
   */
   int8 processFtmRangeReq(uint8 dialogTok, uint8 &elemLen,
                           MeasReqElem &measReqElement,
                           uint8 *measReqElemBody,
                           uint8 sourceMac[BSSID_SIZE],
                           uint8 staMac[BSSID_SIZE], uint32 freq);

  /**
   * Process the LCI Report request that came in the Radio Measurement Request.
   * @param dialogTok: The dialog token of the current Radio Measurement Request
   * @param measReqElement: Measurement request element parameters
   * @param measReqElemBody: Measurement request element body
   * @param sourceMac: The Source MAC address of the frame
   * @param staMac: The local STA MAC address of the frame
   * @param freq: The channel frequency on which the frame arrived
   *
   * @return int8: < 0 if failure, else success
   */
   int8 processLciReq(uint8 dialogTok,
                      MeasReqElem &measReqElement,
                      uint8 *measReqElemBody,
                      uint8 sourceMac[BSSID_SIZE],
                      uint8 staMac[BSSID_SIZE],
                      uint32 freq);

  /**
   * Puts together the LCI report using three subelements:
   * -- LCI subelement
   * -- Z subelement
   * -- Usage Rules/Policy subelement
   *
   * @param req: report message containing all the information used to fill out
   *           the LCI report.
   */
  void SendLCIReport(LOWILCIRprtMessage* req);

  /**
   * Appends the LCI subelement to the frame body
   *
   * @param req: report message containing all the information used to fill out
   *           the LCI subelement
   * @param frameBody: buffer to be populated with the frame contents
   * @param frameBodyLen: tracks the length of the buffer already populated
   * @param measRptLen: report length so far
   */
  void appendLciSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                        uint32 &frameBodyLen, uint32 &measRptLen);

  /**
   * Appends the Z subelement to the frame body
   *
   * @param req: report message containing all the information used to fill out
   *           the Z subelement
   * @param frameBody: buffer to be populated with the frame contents
   * @param frameBodyLen: tracks the length of the buffer already populated
   * @param measRptLen: report length so far
   */
  void appendZSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                      uint32 &frameBodyLen, uint32 &measRptLen);

  /**
  * Appends the Usage rules/policy subelement to the frame body
  *
  * @param req: report message containing all the information used to fill out
  *           the Usage rules/policy subelement
  * @param frameBody: buffer to be populated with the frame contents
  * @param frameBodyLen: tracks the length of the buffer already populated
  * @param measRptLen: report length so far
   */
  void appendUsageRulesSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                               uint32 &frameBodyLen, uint32 &measRptLen);

  /**
   * Packs the LCI field per the IEEE std specification
   *
   * @param lciField: packed lci field struct
   * @param lciInfo : lci info used to fill out the lci field
   */
  void packLciField(LOWILCIField &lciField, LOWILCIInfo &lciInfo);

  /**
   * Prints the frame body of the report
   *
   * @param frameBody: frame body to print
   * @param frameBodyLen: how much of the frame body to print
   */
  void printFrame(uint8 *frameBody, uint32 frameBodyLen);

  /* The listener through which Rome Driverwill send Internal Requests */
  LOWIScanResultReceiverListener *mListener;

  /**
   * Constructor
   * Starts the WifiDriver
   * @param [in] config: Provides the configuration parameters
   *        provided by the user which allows the driver to behave
   *        according to user's needs, for example to run in CFR
   *        capture mode.
   * @param [in] scanResultListener: This is a pointer to the
   *        Listener object. The Driver uses this object to send
   *        the results from scans to the client.
   * @param [in] internalMessageListener: This is the pointer to
   *        the internal Message listerner Object. The Driver uses
   *        this object to send internal messages to the Client.
   * @param [in] cacheManager: This is a pointer to the Cache
   *        Manager Object. The Driver uses this to access the
   *        Cache to retrieve BSSID related information.
   * @param [in] eLowiRangingInterface: This enum represents the interface
   *        which will be used when doing the ranging scans as Pronto currenly
   *        inherits from Rome driver.
   */
  LOWIROMEWifiDriver (ConfigFile* config,
                      LOWIScanResultReceiverListener* scanResultListener,
                      LOWIInternalMessageReceiverListener* internalMessageListener,
                      LOWICacheManager* cacheManager,
                      LOWIRangingFSM::eLowiRangingInterface);

public:

  /**
   * Returns the Capabilities of the driver
   * @return Capabilities of the driver
   */
  virtual LOWICapabilities getCapabilities ();
  virtual bool sendCapabilitiesReq (std::string interface);

  /**
   * Blocking call to listen for the scan measurements from the
   * wifi driver. It can also listen to additional file descriptor, if
   * initialized through initFileDescriptor
   * @param LOWIRequest*   Request
   * @param eListenMode Mode of listening, used only if the request is NULL
   * @return Measurement results
   */
  virtual LOWIMeasurementResult* getMeasurements (LOWIRequest* request,
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
   * a different thread Note: This function will only work, if
   * initFileDescriptor was called
   *       before calling getMeasurements ()
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
   * @param [in] eListenMode :Mode of Listening
   */
  virtual void setNewRequest(const LOWIRequest* r, eListenMode mode);

  /**
   * Parse and take action on the newly arrived WLAN frame
   * @return NONE
   */
  virtual void processWlanFrame();

  /**
   * Parse Neighbor Report Element
   *
   * @param [in] elemLen: The length of FTM Range Request
   *                      Element
   * @param [in] frameBody: The frame Body byte stream
   * @param [out] rangeReq: The location where the parsed neighbor
   *                        report will be stored
   *
   * @return uint8*: return pointer to the frame body after
   *                 parsing current element
   */
  uint8* parseNeighborReport(uint8  &elemLen,
                             uint8* frameBody,
                             FineTimingMeasRangeReq &rangeReq);

  /**
   * Generate BW and Preamble based on bssif Info field
   *
   * @param [in] bssidInfo: bssidInfo field from Neighbor report
   *                        Element
   * @param [in] channelWidth: Channel Width of used by Target
   * @param [out] preamble: destination for computed preamble
   * @param [out] bandwidth: destination for computed bandwidth
   * @return None
   */
  void bssidInfoToPreambleAndBw(uint32 bssidInfo,
                                uint8 channelWidth,
                                eRangingPreamble &preamble,
                                eRangingBandwidth &bandwidth);
  /**
   * Parse Measurement Request Element
   *
   * @param [in] currentFrameLen: The length of the measurement request elements
   *        field
   * @param [in] frameBody: Measurement request elements part of the Radio
   *        Measurement Request frame Action field
   * @param [in] dialogTok: The dialog Token of the current Radio
   *                        Measurement Frame
   * @param [in] sourceMac: The Source MAC address of the frame
   * @param [in] sourceMac: The local STA MAC address of the
   *                         frame
   * @param [in] freq: The channel frequency on which the frame
   *                   arrived
   *
   * @return uint8*: return pointer to the frame body after
   *                 parsing current element.
   *                 NULL if no more elements are available for parsing.
   *                 NULL if an error occurred.
   */
  uint8* parseMeasReqElem(uint32 &currentFrameLen,
                          uint8* frameBody,
                          uint8 dialogTok,
                          uint8 sourceMac[BSSID_SIZE],
                          uint8 staMac[BSSID_SIZE],
                          uint32 freq);

  /**
   * Constructor
   * Starts the WifiDriver
   * @param [in] config: Provides the configuration parameters
   *        provided by the user which allows the driver to behave
   *        according to user's needs, for example to run in CFR
   *        capture mode.
   * @param [in] scanResultListener: This is a pointer to the
   *        Listener object. The Driver uses this object to send
   *        the results from scans to the client.
   * @param [in] internalMessageListener: This is the pointer to
   *        the internal Message listerner Object. The Driver uses
   *        this object to send internal messages to the Client.
   * @param [in] cacheManager: This is a pointer to the Cache
   *        Manager Object. The Driver uses this to access the
   *        Cache to retrieve BSSID related information.
   */
  LOWIROMEWifiDriver (ConfigFile* config,
                      LOWIScanResultReceiverListener* scanResultListener,
                      LOWIInternalMessageReceiverListener* internalMessageListener,
                      LOWICacheManager* cacheManager);

  /**
   * Destructor
   * Stops the WifiDriver
   */
  virtual ~LOWIROMEWifiDriver ();
};
} // namespace
#endif //#ifndef __LOWI_ROME_WIFI_DRIVER_H__
