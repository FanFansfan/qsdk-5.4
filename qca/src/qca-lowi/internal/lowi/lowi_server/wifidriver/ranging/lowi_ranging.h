#ifndef __LOWI_RANGING_H__
#define __LOWI_RANGING_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        WIPS module - Wifi Interface for Positioning System for ranging

GENERAL DESCRIPTION
  This file contains the declaration and some global constants for WIPS
  module.

Copyright (c) 2013-2019  Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <stdint.h>
#include <common/lowi_utils.h>
#include <base_util/sync.h>
#include <lowi_server/lowi_internal_message_listener.h>
#include "innavService.h"                           //  structure definitions and such
#include "wlan_capabilities.h"
#include "rttm.h"
#include "lowi_wigig_caps.h"
#include <inc/lowi_scan_measurement.h>
#include <inc/lowi_request.h>
#include "lowi_request_extn.h"
#include "lowi_response_extn.h"
#include <netlink/attr.h>
#include <string>

extern int net_admin_capable;
#define MAX_BSSIDS_TO_SCAN  10

#define MAX_NLMSG_LEN 5120   /* 5K Buffer for Netlink Message */
#define MAX_ELEMENTS_2G_ARR 14
#define MAX_ELEMENTS_5G_ARR 56


#define RTT_MEAS_FRAME_NULL 0
#define RTT_MEAS_FRAME_QOSNULL 1
#define RTT_MEAS_FRAME_TMR 2

#define WMI_RTT_BW_20 0
#define WMI_RTT_BW_40 1
#define WMI_RTT_BW_80 2
#define WMI_RTT_BW_160 3

#define WMI_RTT_PREAM_LEGACY 0
#define WMI_RTT_PREAM_HT 2
#define WMI_RTT_PREAM_VHT 3

#define SELECT_TIMEOUT_NORMAL 5
#define SELECT_TIMEOUT_NON_ASAP_TARGET 70
#define SELECT_TIMEOUT_NEVER -1

/* This is the mask used to acces/clear the Phy Mode field from
 * Channel Structure's "info" field.
 */
#define PHY_MODE_MASK 0xFFFFFFC0

/* RTT timeout per BSSID target in milliseconds - set to 50 ms */
#define RTT_TIMEOUT_PER_TARGET 50

/* channel info will have the 10th bit set if it is DFS channel */
#define WMI_CHAN_FLAG_DFS (1 << 10)

/* this mask is used to determine if the peer info is for STA or p2p Peer.
 * if bit 0 of reserved0 0th is set, the peer info is for the AP to which
 * STA is connected,other wise; it is for P2P peer */
#define WMI_PEER_STA_MODE 0x01
//Below is the current wmi_channel.info field expansion
//Please refer WMIUNIFIED.h for latest declarations
#if 0
/** channel info consists of 6 bits of channel/phy mode */

#define WMI_SET_CHANNEL_MODE(pwmi_channel,val) do { \
     (pwmi_channel)->info &= 0xffffffc0;            \
     (pwmi_channel)->info |= (val);                 \
     } while (0)

#define WMI_GET_CHANNEL_MODE(pwmi_channel) ((pwmi_channel)->info & 0x0000003f)

#define WMI_CHAN_FLAG_HT40_PLUS   6
#define WMI_CHAN_FLAG_PASSIVE     7
#define WMI_CHAN_ADHOC_ALLOWED    8
#define WMI_CHAN_AP_DISABLED      9
#define WMI_CHAN_FLAG_DFS         10
#define WMI_CHAN_FLAG_ALLOW_HT    11  /* HT is allowed on this channel */
#define WMI_CHAN_FLAG_ALLOW_VHT   12  /* VHT is allowed on this channel */
#define WMI_CHANNEL_CHANGE_CAUSE_CSA 13 /*Indicate reason for channel switch */
#define WMI_CHAN_FLAG_HALF_RATE     14  /* Indicates half rate channel */
#define WMI_CHAN_FLAG_QUARTER_RATE  15  /* Indicates quarter rate channel */
#define WMI_CHAN_FLAG_DFS_CFREQ2  16 /* Enable radar event reporting for sec80 */
#endif

#define INTERFACE_PREFIX "wifi"
#define INTERFACE_IDX_LEN 3
/* peer connection status */
typedef enum peer_status_s
{
  PEER_STATUS_CONNECTED = 1,
  PEER_STATUS_DISCONNECTED = 2,
  PEER_STATUS_UNDEF = 3
} peer_status_t;

/*==================================================================
 * Structure Description:
 * cld80211_ctx is cld80211 context structure which will be returned
 * during the init call of CLD80211 lib.
 *
 * nl_sock         : NL Socket information
 * netlink_familyid: Netlink Family id number.
 * exit_sockets[2] : socket pair used to exit from blocking poll.
 * sock_buf_size   : socket buffer size.
 ==================================================================*/
typedef struct
{
  struct nl_sock *sock;
  int netlink_familyid;
  int exit_sockets[2];
  int sock_buf_size;
  int nlctrl_familyid;
} cld80211_ctx;

/* CLD80211 netlink message attribute enum values */
enum cld80211_attr
{
  CLD80211_ATTR_VENDOR_DATA = 1,
  CLD80211_ATTR_DATA,
  CLD80211_ATTR_MAX
};


/*==================================================================
 * Structure Description:
 * Structure used to convet Target/Destination device information
 * to RTT measurement function.
 *
 * mac         : The MAC address of the Target/Destination device
 * rttFrameType: The frame type to be used for RTT indicating
 *               RTTV2 or RTTV3
 ==================================================================*/
typedef struct
{
  tANI_U8 mac[BSSID_LEN];
  tANI_U8 rttFrameType;
  tANI_U8 bandwidth;
  tANI_U8 preamble;
  tANI_U8 numFrames;
  tANI_U8 numFrameRetries;
  tANI_U8 vDevType;

  /*** FTMR related fields */
  tANI_U32 ftmParams;
  tANI_U32 tsfDelta;
  bool tsfValid;
  bool isQtiPeer;
  tANI_U32 reportType;
} DestInfo;

typedef enum
{
  /* ROME CLD Messages */
  ROME_REG_RSP_MSG,
  ROME_CHANNEL_INFO_MSG,
  ROME_P2P_PEER_EVENT_MSG,
  ROME_CLD_ERROR_MSG,
  ROME_WIPHY_INFO_MSG,
  /* ROME FW Messages*/
  ROME_RANGING_CAP_MSG,
  ROME_RANGING_MEAS_MSG,
  ROME_RANGING_ERROR_MSG,
  ROME_RTT_CHANNEL_INFO_MSG,
  ROME_RESPONDER_INFO_MSG,
  ROME_CFG_RESPONDER_MEAS_RSP_MSG,
  ROME_RESPONDER_MEAS_INFO_MSG,
  ROME_FTM_SESSION_DONE_MSG,
  /* NL/Kernel Messages */
  ROME_NL_ERROR_MSG,
  ROME_MSG_MAX
} RomeNlMsgType;

typedef PACK(struct)
{
  tANI_U32 chId;
  wmi_channel wmiChannelInfo;
} ChannelInfo;

/** This structure contains information for a target that failed ranging
 *  mac      : the target's mac address
 *  errorCode: the error code for the failure returned by FW */
typedef PACK(struct)
{
  tANI_U8 mac[ETH_ALEN_PLUS_2];
  WMI_RTT_STATUS_INDICATOR errorCode;
} FailedTarget;

namespace qc_loc_fw
{

#define TIMEOUT_CLD80211_RECV_MS 5000 /* Timeout in milliseconds for during recv call*/

/**
 * Create socket of type NETLINK_GENERIC.
 *
 * Returns valid cld context only if socket creation is succeful and cld80211
 * family is present, returns NULL otherwise
 */
typedef cld80211_ctx* (*cld80211Init_t)();
/**
 * Free the socket created in cld80211_init()
 */
typedef void (*cld80211Deinit_t)(cld80211_ctx *ctx);
/**
 * Allocate nl_msg and populate family and genl header details.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 * int           : command for which allocation is required.
 * struct nlattr : data.
 * int           : pid of the client.
 *
 * Returns valid nl_msg pointer, returns NULL otherwise.
 */
typedef struct nl_msg* (*cld80211MsgAlloc_t)(cld80211_ctx *ctx, int cmd, struct nlattr **nla_data, int pid);
/**
 * Add membership for multicast group "mcgroup" to receive the messages.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 * const char*   : name of the group in string.
 *
 * Returns postive for success, negative for failure.
 */
typedef int (*cld80211AddMcastGroup_t)(cld80211_ctx *ctx, const char* mcgroup);
/**
 * Remove membership for multicast group "mcgroup" to receive the messages.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 * const char*   : name of the group in string.
 *
 * Returns postive for success, negative for failure.
 */
typedef int (*cld80211RemoveMcastGroup_t)(cld80211_ctx *ctx, const char* mcgroup);
/**
 * Send nlmsg to driver and return; It doesn't wait for response.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 * struct nl_msg : nl message.
 *
 * Zero for success, Returns corresponding error no when a
 * failure happens while receiving nl msg
 */
typedef int (*cld80211SendMsg_t)(cld80211_ctx *ctx, struct nl_msg *nlmsg);
/**
 * Receive messages from driver on cld80211 family from the
 * multicast groups subscribed.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 * int           : timeout in milliseconds.
 * bool          : recv multiple messages.
 * int           : callback to receive the messages.
 * void          : context which will be NULL for our case.
 *
 * Zero for success, Returns corresponding error no when a
 * failure happens while receiving nl msg
 */
typedef int (*cld80211Recv_t) (cld80211_ctx *ctx, int timeout,  bool recv_multi_msg,
                               int (*valid_handler)(struct nl_msg *, void *), void *context);
/**
 * Exit the recv call.
 *
 * Parameters:
 * cld80211_ctx* : cld80211 context and socket details.
 */
typedef void (*cld80211ExitRecv_t) (cld80211_ctx *ctx);

/*==================================================================
 * Class Description:
 * Class LOWICLD80211Intf instance will only be created if generic
 * netlink library libcld80211.so is present and successfully dynamically
 * loaded.
 * once the Library is found, the corresponding symbols will be loaded
 * in this class member variables.
 *
 ==================================================================*/
class LOWICLD80211Intf
{
  public:
    static LOWICLD80211Intf* mInstance;
    void *mLibcld80211_handle;                            /* handle to load the libcld80211 library */
    static char mRecvdata[MAX_NLMSG_LEN];                 /* Buffer used to store in coming messages */
    static unsigned int mRecvdataLen;
    cld80211Init_t mCld80211Init;                         /* Init the cld80211 lib and return the cld80211_ctx*/
    cld80211Deinit_t mCld80211DeInit;                     /* de-init the library. */
    cld80211MsgAlloc_t mCld80211MsgAlloc;                 /* used for allocation the message memory
                                                            before sending and recieving */
    cld80211AddMcastGroup_t mCld80211AddMcastGroup;       /* Subscribe to the group for which module wants to
                                                             send and receive the messages,
                                                             for LOWI it is "oem_msgs"*/
    cld80211RemoveMcastGroup_t mCld80211RemoveMcastGroup; /* used to remove the subscription for sending
                                                             and receiving messages */
    cld80211SendMsg_t mCld80211SendMsg;                   /* used for sending message over 80211 netlink socket */
    cld80211Recv_t mCld80211Recv;                         /* used for receiving the message and it will
                                                             also register for callback, on which LOWI will
                                                             receive the messages */
    cld80211ExitRecv_t mCld80211ExitRecv;                 /* used for exit the recieve message, LOWI is not
                                                             required to use it */
    cld80211_ctx *mCldctx;                                /* cld80211 context */

  public:
    /*=============================================================================================
     * Function description:
     *   Create an LOWICLD80211Intf Instance
     *
     * Return value:
     *   LOWICLD80211Intf*: pointer to LOWICLD80211Intf object.
     *
     =============================================================================================*/
    static LOWICLD80211Intf* createInstance();
    /*=============================================================================================
     * Function description:
     *   Load all the symbols of CLD80211 dynamically, this will also init the CLD80211 lib
     *   and register LOWI to recieve messages for "oem_msgs" multicast group.
     *
     * Return value:
     *   Zero if success, -1 for failure.
     *
     =============================================================================================*/
    int cld80211LoadSymbols();
    /*=============================================================================================
     * Function description:
     *   this will init the CLD80211 lib and register LOWI to recieve messages for
     *   "oem_msgs" multicast group.
     *
     * Return value:
     *   Zero if success, -1 for failure.
     *
     =============================================================================================*/
    int cld80211InitAndRegister();
    /*=============================================================================================
     * Function description:
     *   Inline Wrapper function to receive the message over 80211 generic netlink socket.
     *
     * Return value:
     *   Zero if success, -1 for failure.
     *
     =============================================================================================*/
    inline int recv_nlmsg ()
    {
      int retVal = -1;
      if (mCld80211Recv && mCldctx)
      {
        retVal = mCld80211Recv(mCldctx, TIMEOUT_CLD80211_RECV_MS, false,
                                              &LOWICLD80211Intf::event_handler, NULL);
      }
      return retVal;
    }
    /*=============================================================================================
     * Function description:
     *   Pack the data and sends the message over the CLD80211 Socket.
     *
     * Parameters:
     *   int          : command value.
     *   void*        : the command message body
     *   int          : Length of the message
     *   int          : process id.
     *
     * Return value:
     *   Zero if success, -1 for failure.
     *
     =============================================================================================*/
    int send_cld80211_nlmsg(int cmd, void *data, int len, int pid);
    /*=============================================================================================
     * Function description:
     *   This Function will be registered as a callback for the Recv call.
     *
     * Parameters:
     *   struct nl_msg* : the Data received over NL socket.
     *   void*          : Arguments received over NL socket.
     *
     * Return value:
     *   Zero if success, -1 for failure.
     *
     =============================================================================================*/
    static int event_handler(struct nl_msg *msg, void *arg);
    LOWICLD80211Intf(void* libcld80211_handle);
    virtual ~LOWICLD80211Intf();
};
class LOWIRanging
{
private:

protected:
  static int  pipe_ranging_fd[2];          /* Pipe used to terminate select in Ranging thread */
  static int  nl_sock_fd;
  uint32 req_id;
  uint8  rxChainsUsed;

  static char rxBuff[MAX_NLMSG_LEN];       /* Buffer used to store in coming messages */
  vector <FailedTarget> failedTargets;
  /* This variable represents the status information about the AP to which STA
   * is connected, this variable will only be updated if it is a STA mode*/
  ani_peer_status_info mPeerInfo;
  LOWICLD80211Intf* mLowiCLD80211Intf;

public:
  /** Holds the capabilities returned by the sparrow driver */
  LOWIWigigLocCaps          mFtmCaps;

  /*===========================================================================
   * Function description:
   *   This function parses the ranging measurements that arrive from FW
   *
   * Parameters:
   *   measRes: The ranging measurements from FW.
   *   scanMEasurements: The destination where parsed scan measurements
   *                     will be stored.
   *   lastMeas: indicates when last measurement has arrived
   *
   * Return value:
   *   error Code: 0 - Success, -1 - Failure
   ===========================================================================*/
  virtual int RomeParseRangingMeas(char* measRes,
                                   vector <LOWIScanMeasurement*> *scanMeasurements);
  virtual int RomeParseRangingMeas(char* measRes,
                                   vector <LOWIScanMeasurement*> *scanMeasurements,
                                   bool& /* lastMeas */, unsigned int /*reportType*/)
  {
    return RomeParseRangingMeas(measRes, scanMeasurements);
  }

  /*===========================================================================
   * Parses the responder channel info measurement from FW
   *
   * @param measResp: pointer to message
   * @param channelresponse: where parsed measurements will be stored
   * @return int: 0 if success, else failure
   ===========================================================================*/
  virtual int ParseResponderChannelMeas(char* /* measRes */,
                                        LOWIRMChannelResponse* /* channelresponse */)
  {
    return -1;
  }

  /*===========================================================================
   * Function description:
   *   This function constructs the LCI configuration message and
   *   sends it to FW.
   *
   * Parameters:
   *   reqId: The request Id for this request.
   *   request: The LCI configuration request and parameters.
   *
   * Return value:
   *   error Code: 0 - Success, -1 - Failure
   ===========================================================================*/
   virtual int RomeSendLCIConfiguration(tANI_U16 reqId, LOWISetLCILocationInformation* request);

  /*===========================================================================
   * Function description:
   *   This function constructs the LCR configuration message and
   *   sends it to FW.
   *
   * Parameters:
   *   reqId: The request Id for this request.
   *   request: The LCR configuration request and parameters.
   *
   * Return value:
   *   error Code: 0 - Success, -1 - Failure
   ===========================================================================*/
   virtual int RomeSendLCRConfiguration(tANI_U16 reqId, LOWISetLCRLocationInformation* request);

   /*===========================================================================
    * Function description:
    *   This function constructs the LCI request message and
    *   sends it to host.
    *
    * Parameters:
    *   reqId: The request Id for this request.
    *   request: The Where are you request and parameters.
    *
    * Return value:
    *   error Code: 0 - Success, -1 - Failure
    ===========================================================================*/
   virtual int RomeSendLCIRequest(tANI_U16 reqId, LOWISendLCIRequest *request);

   /*===========================================================================
    * Function description:
    *   This function constructs the FTM ranging request message and
    *   sends it to host.
    *
    * Parameters:
    *   reqId: The request Id for this request.
    *   request: The Where are you request and parameters.
    *
    * Return value:
    *   error Code: 0 - Success, -1 - Failure
    ===========================================================================*/
   virtual int RomeSendFTMRR(tANI_U16 reqId, LOWIFTMRangingRequest *request);

  /*=============================================================================================
   * Function description:
   * Open Rome RTT Interface Module
   *
   * Parameters:
   *    None
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
  virtual int RomeWipsOpen();

  /*=============================================================================================
   * Function description:
   * Close Rome RTT Interface Module
   *
   * Parameters:
   *    None
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
  virtual int RomeWipsClose();

  /*=============================================================================================
   * Function description:
   * Send Channel Info request to Rome CLD
   *
   * Parameters:
   *    iwOemDataCap: The WLAn capabilites information
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeSendChannelInfoReq(IwOemDataCap iwOemDataCap);

  /*=============================================================================================
   * Function description:
   * Extract information from Channein info message.
   *
   * Parameters:
   *    data   : The message body
   *    pChannelInfoArray: Pointer to Channel info Array
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeExtractChannelInfo(void* data, ChannelInfo *pChannelInfoArray);

   /*=============================================================================================
   * Function description:
   * Send Registration request to Rome CLD
   *
   * Parameters:
   *    None
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeSendRegReq();

  /*=============================================================================================
   * Function description:
   * This function receives the FW message, extracts the OEM subtype so that the
   * FSM can process it.
   *
   * Parameters:
   *    msgType: The Type of Message received
   *    data   : The message body
   *    maxDataLen: length of message (bytes)
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
  virtual int RomeNLRecvMessage(RomeNlMsgType* msgType, void* data, tANI_U32 maxDataLen);

  /*=============================================================================================
   * Function description:
   * Extract information from registration message
   *
   * Parameters:
   *    data   : The message body
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeExtractRegRsp(void* data);

  /*=============================================================================================
   * Function description:
   * Create Ranging Capabilities request and send to FW.
   *
   * Parameters:
   *    None
   *
   * Return value:
   *    FAILURE: < 0, else SUCCESS
   =============================================================================================*/
   virtual int RomeSendRangingCapReq(std::string interface);

  /*=============================================================================================
   * Function description:
   * Extract information from Ranging Capability message
   *
   * Parameters:
   *    data   : The message body
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
  virtual int RomeExtractRangingCap(void* data, RomeRttCapabilities* pRomeRttCapabilities);

  /*=============================================================================================
   * Function description:
   * Extract Error Code from Ranging Error Message
   *
   * Parameters:
   *    data   : The message body
   *    errorCode: Thelocation to store the extracted error code
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeExtractRangingError(void* data, tANI_U32* errorCode, tANI_U8* bssid);

  /*=============================================================================================
   * Function description:
   * Based on the Error Code if the bssid Will be skipped, then the bssid will be added
   * to the "Skipped Targets" List. This will allow the driver to send back appropriate
   * error Codes to the Client.
   *
   * Parameters:
   *    errorCode   : The Error code recieved from FW
   *    bssid       : the bssid associated with the error code
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeAddSkippedTargetToList(tANI_U32 errorCode, tANI_U8 mac[BSSID_LEN + 2]);

  /*=============================================================================================
   * Function description:
   * Extract information from P2P Peer info message
   *
   * Parameters:
   *    data   : The message body
   *
   * Return value:
   *    SUCCESS/FAILURE
   =============================================================================================*/
   virtual int RomeExtractP2PInfo(void* data);

  /*=============================================================================================
   * Function description:
   * Enquire the mpeerInfo to check if device is in associated mode
   * and the peer info is for the AP to which STA is connected.
   * reserved0 will have 0th bit set if STA is connected.
   *
   * Parameters:
   *    none
   *
   * Return value:
   *    true if connected,otherwise;false
   =============================================================================================*/
   bool isSTAConnected() const
   {
     return ((PEER_STATUS_CONNECTED == mPeerInfo.peer_conn_status &&
              (mPeerInfo.reserved0 & WMI_PEER_STA_MODE)));
   }

  /*=============================================================================================
   * Function description:
   *   Called by external entity to create the pipe to Ranging thread
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    0 Success, other values otherwise
   =============================================================================================*/
  virtual int RomeInitRangingPipe();

  /*=============================================================================================
   * Function description:
   *   Called by external entity to create the pipe to Raning Thread
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    0 Success, other values otherwise
   =============================================================================================*/
  virtual int RomeCloseRangingPipe();

  /*=============================================================================================
   * Function description:
   *   Called by external entity to terminate the blocking of the Ranging thread on select call
   *   by means of writing to a pipe. Thread is blocked on socket and a pipe in select call
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    num of bytes written, -1 for error, 0 for no bytes written
   =============================================================================================*/
  virtual int RomeUnblockRangingThread();

  /*===========================================================================
   * Function description:
   *   Waits on a private Netlink socket for one of the following events
   *       1) Data becomes available on socket
   *       2) Activity on unBlock Pipe
   *       3) A timeout happens.
   *
   * Parameters:
   *   int timeout_val is the timout value specified by caller
   *
   * Return value:
   *   TRUE, if some data is available on socket. FALSE, if timed out or error
   ===========================================================================*/
  virtual int RomeWaitOnActivityOnSocketOrPipe(int timeout_val);

  /*=====================================================================================
   * Function description:
   *   This function sends the Ranging Request to the FW
   *
   * Parameters:
   *   ChannelInfo: The object containing the channel on which ranging will be performed.
   *   unsigned int numBSSIDs: Number of BSSIDs in the request.
   *   DestInfo bssidsToScan: BSSIDs to Range with.
   *   DestInfo spoofBssids: Spoof Addresses of the BSSIDs to range with.
   *   unsigned int reportType: Report Type for Masurements from FW
   *
   * Return value:
   *   error Code: 0 - Success, -1 - Failure
   ======================================================================================*/
  virtual int RomeSendRttReq(uint16 reqId,
                            ChannelInfo chanInfo,
                            unsigned int numBSSIDs,
                            DestInfo bssidsToScan[MAX_BSSIDS_TO_SCAN],
                            DestInfo spoofBssids[MAX_BSSIDS_TO_SCAN],
                            unsigned int reportType,
                            std::string interface);
  /*=====================================================================================
   * Function description:
   *   This function checks for the input MAC address where they are part of
   *   failed target list or not.
   *
   * Parameters:
   *   char dest_mac[ETH_ALEN + 2]: destination mac to check in the list of failed target.
   *   WMI_RTT_STATUS_INDICATOR &errorCode: fills the errorcode if given Mac is found in the list.
   *
   * Return value:
   *   error Code: 0 - if target mac is not in the failed list, 1 - if it is a part of failed list.
   ======================================================================================*/
  virtual int failedTargetCheck(tANI_U8  dest_mac[ETH_ALEN + 2], WMI_RTT_STATUS_INDICATOR &errorCode);
  /*=====================================================================================
   * Function description:
   *   This function sets the default FTM parameters.
   *
   * Parameters:
   *   unsigned long *ftmParams: pointer to ftmParams for which values need to be set.
   ======================================================================================*/
  virtual void setDefaultFtmParams(tANI_U32 *ftmParams);
  /*=====================================================================================
   * Function description:
   *   This function prints the current FTM parameters.
   *
   * Parameters:
   *   char *bssid: bssid for which FTM paramters needs to be printed.
   *   unsigned long ftmParams: ftmParams from which we need to extract the FTM info.
   *   unsigned long tsfDelta: tsfDelta to be printed.
   ======================================================================================*/
  virtual void printFTMParams(tANI_U8* bssid, tANI_U32 ftmParams, tANI_U32 tsfDelta);
  /*=====================================================================================
   * Function description:
   *   This function prints the tx rx info from the measurement info
   *
   * Parameters:
   *   LOWIMeasurementInfo* measInfo: pointer of measurement info from tx rx info
   *   needs to be extracted and printed.
   ======================================================================================*/
  virtual void print_tx_rx_params(LOWIMeasurementInfo* measInfo);
  /*=====================================================================================
   * Function description:
   *   Takes care of setting up the Netlink Socket and binds its the required address
   *
   * Parameters:
   *   NONE
   *
   * Return value:
   *   Valid Socket File Descriptor or a negative Error code.
   ======================================================================================*/
  virtual int create_nl_sock();
  /*=====================================================================================
   * Function description:
   *   Sends a netlink message via socket to the kernel. Logs the request to diag log
   *
   * Parameters:
   *   fd:  socket file descriptor
   *   data:  pointer to data to be sent
   *   hdrLen: msg header length
   *   msgLen: msg body length
   *   metaLen: Meta data length
   *
   * Return value:
   *   error code: 0 = Success, -1 = Failure
   ======================================================================================*/
  int send_nl_msg(int fd,char *data, unsigned int hdrLen, unsigned int msgLen, unsigned int metaLen, unsigned int InterfaceLen);
  /*=====================================================================================
   * Function description:
   *   Recvs a netlink message to via socket from  the kernel
   *
   * Parameters:
   *   fd:  socket file descriptor
   *   data:  pointer to data to be sent
   *   len:   length of data to be sent
   *
   * Return value:
   *   error code: 0 = Success, -1 = Failure
   ======================================================================================*/
  int recv_nl_msg(int fd,char *data,unsigned int len);
  /**
   * This function will send the rtt available channel request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
  virtual int SendRTTAvailableChannelReq()
  {
    return -1;
  }
  /**
   * This function will send the enable responder request to FW.
   *
   * @param int8   : channel width
   *        uint32 : duration in seconds for which responder should be enabled
   *        int32  : primary freq
   *        int32  : center freq 0
   *        int32  : center freq 1
   *        uint32 : reg info 1
   *        uint32 : reg info 2
   *        uint32 : Phy mode
   * @return int: 0 if success, else failure
   */
  virtual int SendEnableResponderReq(int8, uint32, int32, int32, int32, uint32, uint32, uint32)
  {
    return -1;
  }

  /**
   * This function will send the disable responder request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
  virtual int SendDisableResponderReq()
  {
    return -1;
  }
   virtual int SendResponderMeasurementConfigReq(uint8 ,uint8)
  {
    return -1;
  }


  /**
   * This function will send the start measurments from responder request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
   virtual int SendResponderMeasurementStartReq(uint8)
   {
     return -1;
   }

  /**
   * This function will send the stop measurments from responder request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
   virtual int SendResponderMeasurementStopReq()
   {
     return -1;
   }

  /**
   * This function requests basic location capabilities from the driver via
   * the NL80211_CMD_GET_WIPHY cmd
   *
   * @param none
   * @return int: 0 if success, else failure
   */
  virtual int sendWiPhyInfoReq()
  {
    return -1;
  }

  /**
   * Extract WIPHY information delivered from wigig driver
   *
   * @param data: WiPhy information
   * @param caps: location capabilities container
   *
   * @return int: 0 - Success, -1 - Failure
   */
  virtual int extractWiPhyInfo(void * /* data */, LOWIWigigLocCaps & /* caps */)
  {
    return -1;
  }

  /**
   * Creates and initializes the LOWIRanging object
   * @param LOWIInternalMessageReceiverListener: internal msg listener
   * @return int: 0 if successfully initialized, else non-zero
   */
  virtual int init(LOWIInternalMessageReceiverListener * /* internalMessageListener */)
  {
    return -1;
  }

  LOWIRanging();
  virtual ~LOWIRanging();
};
}
#endif // __LOWI_RANGING_H__

