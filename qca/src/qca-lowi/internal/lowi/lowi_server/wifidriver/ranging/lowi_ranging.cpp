/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

   NL80211 Interface for ranging scan

   GENERAL DESCRIPTION
   This component performs ranging scan with NL80211 Interface.

   Driver interaction with Linux nl80211/cfg80211
   Copyright (c) 2002-2015, Jouni Malinen <j@w1.fi>
   Copyright (c) 2003-2004, Instant802 Networks, Inc.
   Copyright (c) 2005-2006, Devicescape Software, Inc.
   Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
   Copyright (c) 2009-2010, Atheros Communications

   This software may be distributed under the terms of the BSD license.
   See README for more details.
   Copyright (c) 2013, 2018-2019 Qualcomm Technologies, Inc.

   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.

   2013 Qualcomm Atheros, Inc.
   All Rights Reserved.
   Qualcomm Atheros Confidential and Proprietary.

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
=============================================================================*/

#define LOG_NDEBUG 0
#include <common/lowi_utils.h>
#include "lowi_diag_log.h"
#include <lowi_server/lowi_log.h>
#include <sys/param.h>
#include "rttm.h"
#include "wlan_location_defs.h"
#include "lowi_ranging.h"
#include "wifiscanner.h"
#include "wipsiw.h"
#include "wlan_capabilities.h"
#include "lowi_p2p_ranging.h"
#include "lowi_internal_const.h"
#include <lowi_strings.h>
#include "lowi_ranging_defines.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>

// This needs to be further evaluated and logged under different log levels.
#ifdef LOG_TAG
  #undef LOG_TAG
#endif
#define LOG_TAG "LOWI-ROME-RTT"

#define OFFSET_30MHZ 30

#define DO_EXTRA_PRINTS 0

using namespace qc_loc_fw;

const char* const TAG = LOG_TAG;

int  LOWIRanging::pipe_ranging_fd[2] = {0};          /* Pipe used to terminate select in Ranging thread */
char LOWIRanging::rxBuff[MAX_NLMSG_LEN] = "";       /* Buffer used to store in coming messages */
ChannelInfo channelInfoArray[MAX_CHANNEL_ID];
int LOWIRanging::nl_sock_fd = 0;
VDevInfo vDevInfo;
tANI_U8 vDevId;
bool romeWipsReady = FALSE;
tANI_U8 rxChainsUsed = 0;

/* WLAN frame parameters */
static uint8 gDialogTok = 1;
static uint8 gMeasTok = 1;

vector <FailedTarget> failedTargets;
LOWIRanging::LOWIRanging()
{
  LOWI_LOG_VERB("LOWIRanging\n");
  mPeerInfo.peer_conn_status = PEER_STATUS_DISCONNECTED;
  mPeerInfo.vdev_id = 0;
  mPeerInfo.peer_rtt_cap = 0;
  mPeerInfo.reserved0 |= 0x01; // by default consider it to be STA peer.
  memset(&mPeerInfo.peer_chan_info, 0, sizeof(Ani_channel_info));
  req_id = 0;
}

LOWIRanging::~LOWIRanging()
{
}

/*=============================================================================================
 * Function description:
 *   Takes care of setting up the Netlink Socket and binds its the required address
 *
 * Parameters:
 *   NONE
 *
 * Return value:
 *    Valid Socket File Descriptor or a negative Error code.
 *
 =============================================================================================*/
int LOWIRanging::create_nl_sock()
{
  int nl_sock_fd;
  int on = 1;
  int return_status;
  struct sockaddr_nl src_addr;
  nl_sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_LOWI);
  if( nl_sock_fd < 0 )
  {
    LOWI_LOG_ERROR("%s: Failed to create Socket\n", __FUNCTION__);
    return nl_sock_fd;
  }
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = PF_NETLINK;
  src_addr.nl_pid = getpid();  /* self pid */
  /* interested in group 1<<0 */
  src_addr.nl_groups = 0;

  return_status = setsockopt(nl_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if( return_status < 0 )
  {
    LOWI_LOG_ERROR("%s: nl socket option failed\n", __FUNCTION__);
    close(nl_sock_fd);
    return return_status;
  }
  else
  {
    LOWI_LOG_VERB("%s: NL socket created and options set\n", __FUNCTION__);
  }
  return_status = bind(nl_sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
  if( return_status < 0 )
  {
    LOWI_LOG_VERB("%s: BIND errno=%d - %s\n", __FUNCTION__, errno, strerror(errno));
    close(nl_sock_fd);
    return return_status;
  }
  else
  {
    LOWI_LOG_VERB("%s: Binding success\n", __FUNCTION__);
  }

  return nl_sock_fd;
}

/*=============================================================================================
 * Function description:
 *   Sends a netlink message via socket to the kernel
 *
 * Parameters:
 *   fd:  socket file descriptor
 *   data:  pointer to data to be sent
 *   len:   length of data to be sent
 *
 * Return value:
 *    error code: 0 = Success, -1 = Failure
 *
 =============================================================================================*/
int LOWIRanging::send_nl_msg(int fd, char *data, unsigned int hdrLen, unsigned int msgLen, unsigned int metaLen, unsigned int interfaceLen)
{
  struct sockaddr_nl d_nladdr;
  struct msghdr msg ;
  struct iovec iov;
  struct nlmsghdr *nlh=NULL;

  // calculate the total message length
  unsigned int len = hdrLen + msgLen + metaLen + interfaceLen;

  nlh = (struct nlmsghdr *)calloc(NLMSG_SPACE(len),1);
  if(!nlh) /* Memory allocation failed */
  {
    return -1;
  }

  /* destination address */
  memset(&d_nladdr, 0 ,sizeof(d_nladdr));
  d_nladdr.nl_family= AF_NETLINK ;
  d_nladdr.nl_pad=0;
  d_nladdr.nl_pid = 0; /* destined to kernel */

  /* Fill the netlink message header */
  memset(nlh , 0 , len);

  nlh->nlmsg_len =NLMSG_LENGTH(len);
  nlh->nlmsg_type = WLAN_NL_MSG_OEM;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_pid = getpid();

  /*iov structure */
  iov.iov_base = (void *)nlh;
  iov.iov_len = nlh->nlmsg_len;
  /* msg */
  memset(&msg,0,sizeof(msg));
  msg.msg_name = (void *) &d_nladdr ;
  msg.msg_namelen=sizeof(d_nladdr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  memcpy(NLMSG_DATA(nlh), data,len );
  int retVal = -1;
  if (mLowiCLD80211Intf && mLowiCLD80211Intf->mCldctx)
  {
    retVal = mLowiCLD80211Intf->send_cld80211_nlmsg(WLAN_NL_MSG_OEM, NLMSG_DATA(nlh), len, nlh->nlmsg_pid);
  }
  else
  {
    retVal = sendmsg(fd, &msg, 0);
  }
  if (retVal < 0)
  {
    LOWI_LOG_WARN("%s: Failed, errno:%d - %s\n", __FUNCTION__, errno, strerror(errno));
  }
  else
  {
    // Log Ranging request to Diag Log
    char *aniMsgBody = (char *)(data + (char)hdrLen);
    LOWIDiagLog::Log((uint16)msgLen, (uint8_t*)aniMsgBody, LOWI_ROME_RANGING_REQ);
    LOWI_LOG_VERB("%s: SUCCESS \n", __FUNCTION__);
  }
  free(nlh);

  return retVal;
} // send_nl_msg

/*=============================================================================================
 * Function description:
 *   Recvs a netlink message to via socket from  the kernel
 *
 * Parameters:
 *   fd:  socket file descriptor
 *   data:  pointer to data to be sent
 *   len:   length of data to be sent
 *
 * Return value:
 *    error code: positive length = Success, -1 = Failure
 *
 =============================================================================================*/
int LOWIRanging::recv_nl_msg(int fd,char *data,unsigned int len)
{
  int retVal = 0;

  LOWI_LOG_VERB("%s:Wait for NL msg\n", __FUNCTION__);
  if (mLowiCLD80211Intf  && mLowiCLD80211Intf->mCldctx)
  {
    memset(mLowiCLD80211Intf->mRecvdata, 0, MAX_NLMSG_LEN);
    mLowiCLD80211Intf->mRecvdataLen = 0;
    retVal = mLowiCLD80211Intf->recv_nlmsg();
    if (retVal < 0)
    {
      LOWI_LOG_DBG("%s:No message\n", __FUNCTION__);
      return retVal;
    }
    else
    {
      LOWI_LOG_VERB("%s: Message received - Length %d\n", __FUNCTION__, mLowiCLD80211Intf->mRecvdataLen);
      memcpy(data,mLowiCLD80211Intf->mRecvdata,mLowiCLD80211Intf->mRecvdataLen);
      retVal = mLowiCLD80211Intf->mRecvdataLen;
    }
  }
  else
  {
    struct nlmsghdr *nlh=NULL;

    nlh = (struct nlmsghdr *)calloc(NLMSG_SPACE(MAX_NLMSG_LEN),1);
    if(!nlh) /* Memory Allocation Failed */
    {
      LOWI_LOG_DBG("%s: Memory allocation failed\n", __FUNCTION__);
      return -1;
    }

    memset(nlh , 0 , MAX_NLMSG_LEN);

    nlh->nlmsg_len =NLMSG_SPACE(MAX_NLMSG_LEN);
    nlh->nlmsg_type = WLAN_NL_MSG_OEM;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_pid = getpid();

    /* Source address */
    struct sockaddr_nl d_nladdr;
    memset(&d_nladdr, 0 ,sizeof(d_nladdr));
    d_nladdr.nl_family= AF_NETLINK ;
    d_nladdr.nl_pad=0;
    d_nladdr.nl_pid = 0; /* Source from kernel */

    /*iov structure */
    struct iovec iov;
    iov.iov_base = (void *)nlh;
    iov.iov_len = MAX_NLMSG_LEN;

    /* msg */
    struct msghdr msg ;
    memset(&msg,0,sizeof(msg));
    msg.msg_name = (void *) &d_nladdr;
    msg.msg_namelen=sizeof(d_nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    retVal = recvmsg(fd, &msg, 0);

    if( retVal < 0)
    {
      LOWI_LOG_DBG("%s: - failed\n", __FUNCTION__);
    }
    else if(retVal == 0)
    {
      LOWI_LOG_DBG("%s: No pending message or peer is gone \n", __FUNCTION__);
    }
    else
    {
      LOWI_LOG_VERB("%s: SUCCESS - retVal - %d & Msg Len - %d\n",
                    __FUNCTION__, retVal, nlh->nlmsg_len );
      char* recvdata = (char *)NLMSG_DATA(nlh);

      /* Actual length of data in NL Message */
      retVal = nlh->nlmsg_len - NLMSG_HDRLEN;
      if(retVal > ((int) len))
      {
        LOWI_LOG_DBG("%s: Too much data!, expected: %u, got %u", __FUNCTION__, len, retVal);
        memcpy(data,recvdata,len);
      }
      else
      {
        memcpy(data,recvdata,retVal);
      }
    }
    free(nlh);
  }

  // Log message from CLD/FW to diag log
  if(retVal > 0)
  {
    tAniMsgHdr *aniMsgHdr = (tAniMsgHdr *)data;
    LOWIDiagLog::Log((uint16)aniMsgHdr->length, (tANI_U8*)data, LOWI_ROME_RANGING_RESP);
  }
  return retVal;
} // recv_nl_msg

/*=============================================================================================
 * Function description:
 *   Initializes Rome RTT Module
 *
 * Parameters:
 *    cfrCaptureModeState: indicates whether LOWI is running in CFR capture mode
 * Return value:
 *    error code: 0 = Success, -1 = Failure
 *
 =============================================================================================*/
int LOWIRanging::RomeWipsOpen()
{
  romeWipsReady = FALSE;
  nl_sock_fd = 0;
  memset(rxBuff, 0, MAX_NLMSG_LEN);
  mLowiCLD80211Intf = LOWICLD80211Intf::createInstance();
  if (mLowiCLD80211Intf != NULL)
  {
    LOWI_LOG_INFO("%s: libCld80211 found, load the symbols..\n", __FUNCTION__);
    if (mLowiCLD80211Intf->cld80211LoadSymbols() == 0)
    {
      if (mLowiCLD80211Intf->cld80211InitAndRegister() < 0)
      {
        LOWI_LOG_INFO("%s: Init and Registration failed\n", __FUNCTION__);
        delete mLowiCLD80211Intf;
        mLowiCLD80211Intf = NULL;
      }
    }
    else
    {
      LOWI_LOG_WARN("%s: unable to load symbols\n", __FUNCTION__);
      delete mLowiCLD80211Intf;
      mLowiCLD80211Intf = NULL;
    }
  }
  //if unable to load the cld80211 library and init failed go back to legacy method.
  if ((mLowiCLD80211Intf) && (mLowiCLD80211Intf->mCldctx))
  {
    nl_sock_fd = nl_socket_get_fd(mLowiCLD80211Intf->mCldctx->sock);
    LOWI_LOG_VERB("%s: Created  80211 library Netlink Socket...: %d\n", __FUNCTION__, nl_sock_fd);
  }
  else
  {
    nl_sock_fd = create_nl_sock();
    LOWI_LOG_VERB("%s: Created Netlink Socket...: %d\n", __FUNCTION__, nl_sock_fd);
  }
  if (nl_sock_fd < 0)
  {
    return -1;
  }
  memset(pipe_ranging_fd, 0, sizeof(int));
  romeWipsReady = TRUE;
  failedTargets.flush();
  return 0;
}

/*=============================================================================================
 * Function description:
 *   Closes the Rome RTT Module
 *
 * Parameters:
 *   NONE
 * Return value:
 *    error code: Succes = 0, -1 = Failure
 *
 =============================================================================================*/
int LOWIRanging::RomeWipsClose()
{
  if(nl_sock_fd > 0)
  {
    close(nl_sock_fd);
    nl_sock_fd = 0;
  }
  return 0;
}

/** Message Senders - These functions send construct and send messages to Rome CLD/FW */

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
int LOWIRanging::RomeSendRegReq()
{
  std::string interface = "wifi0";

  if (!romeWipsReady)
  {
    /** Rome Wips Not Ready */
    LOWI_LOG_VERB("%s: Driver Not Ready", __FUNCTION__);
    return -1;
  }

  const char appRegSignature[] = APP_REG_SIGNATURE;
  /* Alocate Space for ANI Message (Header + Body) */

  uint32 aniInterfaceLen = sizeof(tAniInterface);

  char* aniMessage = (char *)calloc((sizeof(tAniMsgHdr) + APP_REG_SIGNATURE_LENGTH + aniInterfaceLen), 1);
  if(!aniMessage) /* Memory Allocation Failed */
  {
    LOWI_LOG_ERROR("%s: Failed to Allocate %lu bytes of Memory...\n",
                   __FUNCTION__, (sizeof(tAniMsgHdr) + APP_REG_SIGNATURE_LENGTH));
    return -1;
  }

  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_APP_REG_REQ;
  aniMsgHeader->length = APP_REG_SIGNATURE_LENGTH;

  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + sizeof(tAniMsgHdr));
  memcpy(aniMsgBody, appRegSignature, APP_REG_SIGNATURE_LENGTH);

  if (interface.length() > MAX_INTERFACE_LEN) {
      LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
      free(aniMessage);
      return -1;
  }

  struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + sizeof(tAniMsgHdr) + APP_REG_SIGNATURE_LENGTH);
  aniInterface->length = interface.length();
  strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), APP_REG_SIGNATURE_LENGTH, 0, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: APP reg NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);

  return 0;
}

/*=============================================================================================
 * Function description:
 * Send Channel Info request to Rome CLD
 *
 * Parameters:
 *    iwOemDataCap: The WLAN capabilites information
 *
 * Return value:
 *    SUCCESS/FAILURE
 =============================================================================================*/
int LOWIRanging::RomeSendChannelInfoReq(IwOemDataCap iwOemDataCap)
{
  unsigned int i;
  unsigned int aniMsgLen;
  char* aniChIds;
  std::string interface = "wifi0";

  if (iwOemDataCap.num_channels > WNI_CFG_VALID_CHANNEL_LIST_LEN)
  {
    aniMsgLen = WNI_CFG_VALID_CHANNEL_LIST_LEN;
  }
  else
  {
   aniMsgLen = iwOemDataCap.num_channels;
  }

  uint32 aniInterfaceLen = sizeof(tAniInterface);

  /* Allocate Space for ANI Message (Header + Body) */
  char* aniMessage = (char *)calloc((sizeof(tAniMsgHdr) + aniMsgLen + aniInterfaceLen), 1);
  if(!aniMessage) /* Memory Allocation Failed */
  {
    return -1;
  }

  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_CHANNEL_INFO_REQ;
  aniMsgHeader->length = aniMsgLen;

  /* Fill in the ANI Message Body */
  aniChIds = (char*) (aniMessage + sizeof(tAniMsgHdr));
  for(i = 0; i < aniMsgLen; i++)
  {
    aniChIds[i] = ((unsigned char)iwOemDataCap.channel_list[i]);
  }

  if (interface.length() > MAX_INTERFACE_LEN) {
      LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
      free(aniMessage);
      return -1;
  }

  struct tAniInterface *aniInterface = (struct tAniInterface *)(aniMessage + sizeof(tAniMsgHdr) + aniMsgLen);
  aniInterface->length = interface.length();
  strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* Send ANI Message over Netlink Socket */
  if(send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, 0, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  LOWI_LOG_VERB("%s: to CLD - SUCCESS", __FUNCTION__);
  free(aniMessage);
  return 0;
}

/*=============================================================================================
 * Function description:
 * Send Ranging Capabilities request to Rome FW
 *
 * Parameters:
 *    None
 *
 * Return value:
 *    SUCCESS/FAILURE
 =============================================================================================*/
int LOWIRanging::RomeSendRangingCapReq(std::string interface)
{
  /* Calculate Message Length */
  unsigned int aniMsgLen = sizeof(OemMsgSubType) +
                           sizeof(RomeRttReqHeaderIE);

  /** Request RTT Capability information from Rome FW */
  /* Allocate Space for ANI Message (Header + Body) */
  char* aniMessage = (char *) calloc((sizeof(tAniMsgHdr) + aniMsgLen), 1);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    LOWI_LOG_ERROR("%s: Failed to allocate memory for ANI message", __FUNCTION__);
    return -1;
  }
  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);
  OemMsgSubType*       oemMsgSubType        = (OemMsgSubType*) aniMsgBody;
  RomeRttReqHeaderIE*  romeRttReqHeaderIE   = (RomeRttReqHeaderIE*)  (aniMsgBody + sizeof(OemMsgSubType));

  /* Load the OEM Message Subtype */
  *oemMsgSubType = TARGET_OEM_CAPABILITY_REQ;
  /* Load in the RTT Header IE */
  WMI_RTT_REQ_ID_SET ((romeRttReqHeaderIE->requestID), 0);
  LOWI_LOG_VERB("%s: subtype: 0x%x , requestID: 0x%x\n", __FUNCTION__, *oemMsgSubType, romeRttReqHeaderIE->requestID);

  /* Send ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, 0, 0) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  LOWI_LOG_VERB("%s: SUCCESS", __FUNCTION__);
  free(aniMessage);
  return 0;
}

void LOWIRanging::setDefaultFtmParams(tANI_U32 *ftmParams)
{
  #define BURST_DURATION_32_MS 9
  FTM_SET_ASAP(*ftmParams);
  FTM_CLEAR_LCI_REQ(*ftmParams);
  FTM_CLEAR_LOC_CIVIC_REQ(*ftmParams);
  FTM_SET_BURSTS_EXP(*ftmParams, 0);
  FTM_SET_BURST_DUR(*ftmParams, BURST_DURATION_32_MS);
  FTM_SET_BURST_PERIOD(*ftmParams, 0);
}

void LOWIRanging::printFTMParams(tANI_U8* bssid, tANI_U32 ftmParams, tANI_U32 tsfDelta)
{
  LOWI_LOG_DBG("%s: BSSID: " LOWI_MACADDR_FMT " ftmParams: 0x%x ASAP: 0x%x, LCI Req: 0x%x, Civic: 0x%x, TSF Valid: 0x%x, Bursts Exp: %u, Burst Duration: %u, Burst Period: %u, tsfDelta: %u",
               __FUNCTION__,
               LOWI_MACADDR(bssid),
               ftmParams,
               FTM_GET_ASAP(ftmParams),
               FTM_GET_LCI_REQ(ftmParams),
               FTM_GET_LOC_CIVIC_REQ(ftmParams),
               FTM_GET_TSF_VALID_BIT(ftmParams),
               FTM_GET_BURSTS_EXP(ftmParams),
               FTM_GET_BURST_DUR(ftmParams),
               FTM_GET_BURST_PERIOD(ftmParams),
               tsfDelta);
}

/*=============================================================================================
 * Function description:
 *   Sends RTT request to Rome Converged Linux driver
 *
 * Parameters:
 *   chNum       : Channel Id of Target devices
 *   numBSSIDs   : unsigned int Number of BSSIDs in this request
 *   BSSIDs      : DestInfo Array of BSSIDs and RTT Type
 *   spoofBSSIDs : DestInfo Array of Spoof BSSIDs and RTT Type
 *   reportType  : unsigned int Type of Report from FW (Type: 0/1/2)
 *
 * Return value:
 *    error code : 0 for success and -1 for failure.
 *
 =============================================================================================*/
int LOWIRanging::RomeSendRttReq(uint16 reqId,
                   ChannelInfo  chanInfo,
                   unsigned int numBSSIDs,
                   DestInfo bssidsToScan[MAX_BSSIDS_TO_SCAN],
                   DestInfo spoofBssids[MAX_BSSIDS_TO_SCAN],
                   unsigned int reportType,
                   std::string interface)
{

  /* flush the list of failed Targets */
  failedTargets.flush();
  wmi_channel channelInfo = chanInfo.wmiChannelInfo;
  /* Initialize the local VdevID to STA Vdev ID */
  tANI_U8 locVDevId = vDevId;
  unsigned int i = 0;
  unsigned int aniMsgLen;
  tANI_U32 phyMode;
  aniMsgLen = sizeof(OemMsgSubType) +
              sizeof(RomeRttReqHeaderIE) +
              (numBSSIDs * sizeof(RomeRTTReqCommandIE));
  tANI_U32 flag = 0;

  /** Retrieve Channel information from Channel Info Array for the specific channel ID */
  LOWI_LOG_VERB("%s: Retrieve channel info for ch#: %u \n",
                __FUNCTION__, LOWIUtils::freqToChannel(channelInfo.mhz));

  /* Check to see if the Target is a P2P Peer.
   * IF target is a P2P Peer, load the channel info from p2p event storage table
   */
  p2pBssidDetected((tANI_U32)numBSSIDs, bssidsToScan, &channelInfo, &locVDevId);

  LOWI_LOG_VERB("%s: Channel info - chNum(%u): Freq %u(%u, %u), info= 0x%x, reg_info = (0x%x, 0x%x)\n",
                __FUNCTION__,
                LOWIUtils::freqToChannel(channelInfo.mhz),
                channelInfo.mhz,
                channelInfo.band_center_freq1,
                channelInfo.band_center_freq2,
                channelInfo.info,
                channelInfo.reg_info_1,
                channelInfo.reg_info_2);

  /* Allocate Space for ANI Message (Header + Body) */
  char* aniMessage = (char *) calloc((sizeof(tAniMsgHdr) + aniMsgLen), 1);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return -1;
  }
  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);
  OemMsgSubType*       oemMsgSubType        = (OemMsgSubType*) aniMsgBody;
  RomeRttReqHeaderIE*  romeRttReqHeaderIE   = (RomeRttReqHeaderIE*)  (aniMsgBody + sizeof(OemMsgSubType));

  void* rttCommandIE                              = (aniMsgBody + sizeof(OemMsgSubType) + sizeof(RomeRttReqHeaderIE));
  RomeRTTReqCommandIE* romeRTTReqCommandIEs       = (RomeRTTReqCommandIE*) (rttCommandIE);

  /* Load the OEM Message Subtype */
  *oemMsgSubType = TARGET_OEM_MEASUREMENT_REQ;
  /* Load in the RTT Header IE */
  WMI_RTT_REQ_ID_SET ((romeRttReqHeaderIE->requestID), reqId);
  WMI_RTT_NUM_STA_SET((romeRttReqHeaderIE->numSTA), numBSSIDs);
  LOWI_LOG_VERB("%s: subtype: 0x%x, requestID: 0x%x, numSTA: 0x%x\n",
                __FUNCTION__,
                *oemMsgSubType,
                romeRttReqHeaderIE->requestID,
                romeRttReqHeaderIE->numSTA);

  if (channelInfo.band_center_freq1 == 0)
  {
    LOWI_LOG_VERB("%s: Setting band_center_freq1 = primary Frequency\n",
                  __FUNCTION__);
    channelInfo.band_center_freq1 = channelInfo.mhz;
  }
  memcpy(&(romeRttReqHeaderIE->channelInfo), &channelInfo, sizeof(channelInfo));

  /* Load in the RTT Command IEs for all the APs */
  for (i = 0; i < numBSSIDs; i++)
  {
    phyMode  = channelInfo.info & ~(PHY_MODE_MASK);

    /* set the RTT type, tx/rx chain, QCA peer and BW */
    WMI_RTT_FRAME_TYPE_SET(romeRTTReqCommandIEs->controlFlag, bssidsToScan[i].rttFrameType);
    WMI_RTT_TX_CHAIN_SET  (romeRTTReqCommandIEs->controlFlag, TX_CHAIN_1);
    WMI_RTT_RX_CHAIN_SET  (romeRTTReqCommandIEs->controlFlag, RX_CHAIN_1);
    WMI_RTT_QCA_PEER_SET  (romeRTTReqCommandIEs->controlFlag, NON_QTI_PEER);
    WMI_RTT_BW_SET        (romeRTTReqCommandIEs->controlFlag, bssidsToScan[i].bandwidth);
    LOWI_LOG_DBG("%s: TX_BW: %s, RTT_PKT_TYPE: %s\n",
                 __FUNCTION__,
                 LOWIUtils::to_string(LOWIUtils::to_eRangingBandwidth(bssidsToScan[i].bandwidth)),
                 LOWIStrings::rtt_pkt_type_to_string(bssidsToScan[i].rttFrameType));

    /* Pick Preamble */
    switch (bssidsToScan[i].preamble)
    {
      case RTT_PREAMBLE_LEGACY:
      {
        WMI_RTT_PREAMBLE_SET  (romeRTTReqCommandIEs->controlFlag, ROME_PREAMBLE_LEGACY);
        break;
      }
      case RTT_PREAMBLE_HT:
      {
        WMI_RTT_PREAMBLE_SET  (romeRTTReqCommandIEs->controlFlag, ROME_PREAMBLE_HT);
        break;
      }
      case RTT_PREAMBLE_VHT:
      {
        WMI_RTT_PREAMBLE_SET  (romeRTTReqCommandIEs->controlFlag, ROME_PREAMBLE_VHT);
        break;
      }
      default:
      {
        WMI_RTT_PREAMBLE_SET  (romeRTTReqCommandIEs->controlFlag, ROME_PREAMBLE_LEGACY);
        break;
      }
    }

    flag = WMI_RTT_PREAMBLE_GET(romeRTTReqCommandIEs->controlFlag);

    /* Pick the data rate */
    if (flag == ROME_PREAMBLE_LEGACY)
    {
      /* for Legacy Frame types, we will always use a data rate of 6MBps.
         This is indicated to FW by setting the MCS field to 3 */
      WMI_RTT_MCS_SET       (romeRTTReqCommandIEs->controlFlag, 3);
    }
    else
    {
      /* for HT and VHT Frame types, we will always use adata rate of 6.5MBps.
         This is indicated to FW by setting the MCS field to 0 */
      WMI_RTT_MCS_SET       (romeRTTReqCommandIEs->controlFlag, 0x00);
    }

    /** Set the number of HW retries for RTT frames:
     *  For RTT2 it is the QosNull Frame retries
     *  For RTT3 it is the FTMR Frame retries. */
    WMI_RTT_RETRIES_SET   (romeRTTReqCommandIEs->controlFlag, bssidsToScan[i].numFrameRetries);

    /* Load the measurementInfo */
    WMI_RTT_VDEV_ID_SET   (romeRTTReqCommandIEs->measurementInfo, locVDevId);
    LOWI_LOG_DBG("%s: PHY Mode : %s, PREAMBLE: %s, controlFlag[%u]: 0x%x, vDevID: %u\n",
                 __FUNCTION__,
                 LOWIUtils::to_string(LOWIUtils::to_eLOWIPhyMode(phyMode)),
                 LOWIStrings::rtt_preamble_type_to_string((uint8)flag),
                 i,
                 romeRTTReqCommandIEs->controlFlag,
                 locVDevId);

    WMI_RTT_MEAS_NUM_SET  (romeRTTReqCommandIEs->measurementInfo, bssidsToScan[i].numFrames);
    WMI_RTT_TIMEOUT_SET   (romeRTTReqCommandIEs->measurementInfo, RTT_TIMEOUT_PER_TARGET);
    WMI_RTT_REPORT_TYPE_SET(romeRTTReqCommandIEs->measurementInfo, reportType);
    LOWI_LOG_VERB("%s: measurementInfo[%u]: 0x%x, numFrames[%u]: %u\n",
                  __FUNCTION__,
                  i,
                  romeRTTReqCommandIEs->measurementInfo,
                  i,
                  WMI_RTT_MEAS_NUM_GET(romeRTTReqCommandIEs->measurementInfo));

    memcpy(romeRTTReqCommandIEs->destMac,&bssidsToScan[i].mac[0] ,ETH_ALEN);
    memcpy(romeRTTReqCommandIEs->spoofBSSID,&spoofBssids[i].mac[0] ,ETH_ALEN);

    romeRTTReqCommandIEs->ftmParams = bssidsToScan[i].ftmParams;

    if (bssidsToScan[i].tsfValid)
    {
      FTM_SET_TSF_VALID(romeRTTReqCommandIEs->ftmParams);
      romeRTTReqCommandIEs->tsfDelta = bssidsToScan[i].tsfDelta;
      LOWI_LOG_VERB("%s: Valid TSF\n", __FUNCTION__);
    }
    else
    {
      FTM_CLEAR_TSF_VALID(romeRTTReqCommandIEs->ftmParams);
      romeRTTReqCommandIEs->tsfDelta = 0;
      LOWI_LOG_VERB("%s: InValid TSF\n", __FUNCTION__);
    }

    printFTMParams(romeRTTReqCommandIEs->destMac,
                   romeRTTReqCommandIEs->ftmParams,
                   romeRTTReqCommandIEs->tsfDelta);

    romeRTTReqCommandIEs++;
  }

  LOWI_LOG_VERB("%s: send Ranging Req message over NL at TS: %" PRId64 " ms\n", __FUNCTION__,
                LOWIUtils::currentTimeMs());

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, 0, 0) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);
  return 0;
}

int LOWIRanging::RomeSendLCIConfiguration(tANI_U16 reqId, LOWISetLCILocationInformation* request)
{
  int retVal = 0;

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return -1;
  }

  LOWILciInformation lciInfo = request->getLciParams();
  tANI_U32        usageRules = request->getUsageRules();


  LOWI_LOG_VERB("%s - LCIParam - latitude: %" PRId64 " latitude_unc: %d \n",
                __FUNCTION__,
                lciInfo.latitude,
                lciInfo.latitude_unc);
  LOWI_LOG_VERB("%s - LCIParam - longitude: %" PRId64 " longitude_unc: %d\n",
                __FUNCTION__,
                lciInfo.longitude,
                lciInfo.longitude_unc);
  LOWI_LOG_VERB("%s - LCIParam - altitude: %d altitude_unc: %d",
                __FUNCTION__,
                lciInfo.altitude,
                lciInfo.altitude_unc);
  LOWI_LOG_VERB("%s - LCIParam - motion_pattern: %d, floor: %d & usageRules: %u",
                __FUNCTION__,
                lciInfo.motion_pattern,
                lciInfo.floor,
                usageRules);
  LOWI_LOG_VERB("%s - LCIParam - height_above_floor: %d height_unc: %d",
                __FUNCTION__,
                lciInfo.height_above_floor,
                lciInfo.height_unc);

  unsigned int aniMsgLen;
  aniMsgLen = sizeof(OemMsgSubType) +
              sizeof(wmi_rtt_lci_cfg_head);

  /* Allocate Space for ANI Message (Header + Body) */
  char* aniMessage = (char *) calloc((sizeof(tAniMsgHdr) + aniMsgLen), 1);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return -1;
  }

  LOWI_LOG_VERB("%s: Fill in LCI Config ANI Message Header\n", __FUNCTION__);
  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  LOWI_LOG_VERB("%s: Fill in LCI Config Message Body\n", __FUNCTION__);
  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);
  OemMsgSubType*       oemMsgSubType        = (OemMsgSubType*) aniMsgBody;
  wmi_rtt_lci_cfg_head*    lciConfig        = (wmi_rtt_lci_cfg_head*)  (aniMsgBody + sizeof(OemMsgSubType));

  /* Load the OEM Message Subtype */
  *oemMsgSubType = TARGET_OEM_CONFIGURE_LCI;
  /* Load in the LCI IE */
  WMI_RTT_REQ_ID_SET ((lciConfig->req_id), reqId);
  LOWI_LOG_VERB("%s: subtype: 0x%x, requestID: 0x%x\n",
                __FUNCTION__,
                *oemMsgSubType,
                lciConfig->req_id);

  lciConfig->latitude  = (tANI_U64)lciInfo.latitude;
  lciConfig->longitude = (tANI_U64)lciInfo.longitude;
  lciConfig->altitude  = (tANI_U64)lciInfo.altitude;
  WMI_RTT_LCI_LAT_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.latitude_unc);
  WMI_RTT_LCI_LON_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.longitude_unc);
  WMI_RTT_LCI_ALT_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.altitude_unc);
  WMI_RTT_LCI_Z_MOTION_PAT_SET(lciConfig->lci_cfg_param_info, lciInfo.motion_pattern);
  lciConfig->floor     = (tANI_U32)lciInfo.floor;
  WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_SET(lciConfig->floor_param_info, (tANI_U32)lciInfo.height_above_floor);
  WMI_RTT_LCI_Z_HEIGHT_UNC_SET(lciConfig->floor_param_info, (tANI_U32)lciInfo.height_unc);
  lciConfig->usage_rules = usageRules;

  LOWI_LOG_VERB("%s: Sending LCI Configuration Req message over NL at TS: %" PRId64 " ms\n", __FUNCTION__,
                LOWIUtils::currentTimeMs());

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, 0, 0) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);

  return retVal;
}

int LOWIRanging::RomeSendLCRConfiguration(tANI_U16 reqId, LOWISetLCRLocationInformation* request)
{
  int retVal = 0;

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return -1;
  }

  LOWILcrInformation lcrInfo = request->getLcrParams();

  unsigned int aniMsgLen;
  aniMsgLen = sizeof(OemMsgSubType) +
              sizeof(wmi_rtt_lcr_cfg_head);

  /* Allocate Space for ANI Message (Header + Body) */
  char* aniMessage = (char *) calloc((sizeof(tAniMsgHdr) + aniMsgLen), 1);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return -1;
  }

  LOWI_LOG_VERB("%s: Fill in LCI Config ANI Message Header\n", __FUNCTION__);
  /* Fill the ANI Header */
  tAniMsgHdr* aniMsgHeader = (tAniMsgHdr*)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  LOWI_LOG_VERB("%s: Fill in LCI Config Message Body\n", __FUNCTION__);
  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);
  OemMsgSubType*       oemMsgSubType = (OemMsgSubType*) aniMsgBody;
  wmi_rtt_lcr_cfg_head*    lcrConfig = (wmi_rtt_lcr_cfg_head*)  (aniMsgBody + sizeof(OemMsgSubType));

  /* Load the OEM Message Subtype */
  *oemMsgSubType = TARGET_OEM_CONFIGURE_LCR;
  /* Load in the LCI IE */
  WMI_RTT_REQ_ID_SET ((lcrConfig->req_id), reqId);

  /* The following subtraction and addition of the value 2 to length is being done because
   * Country code which is 2 bytes comes separately from the actual Civic Info String
   */
  tANI_U8 len = (lcrInfo.length > (MAX_CIVIC_INFO_LEN - 2)) ? (MAX_CIVIC_INFO_LEN - 2) : lcrInfo.length;

  WMI_RTT_LOC_CIVIC_LENGTH_SET(lcrConfig->loc_civic_params, (len + 2));

  tANI_U8* civicInfo = (tANI_U8*) lcrConfig->civic_info;

  LOWI_LOG_VERB("%s - subtype: 0x%x, requestID: 0x%x, LCRParam: country[0]: %u & country[1]: %u",
                __FUNCTION__,
                *oemMsgSubType,
                lcrConfig->req_id,
                lcrInfo.country_code[0],
                lcrInfo.country_code[1]);

  civicInfo[0] = lcrInfo.country_code[0];
  civicInfo[1] = lcrInfo.country_code[1];
  memcpy(&civicInfo[2], lcrInfo.civic_info, (tANI_U8)lcrInfo.length);


  char civic_info_string[MAX_CIVIC_INFO_LEN];
  if((snprintf(civic_info_string, len, "%c", lcrInfo.civic_info[3])) >= 0)
  {
    LOWI_LOG_VERB("%s - LCRParam: len: %u: civic_info: %s",
                  __FUNCTION__,
                  len,
                  civic_info_string);
  }

  LOWI_LOG_VERB("%s: Sending LCR Configuration Req message over NL at TS: %" PRId64 " ms\n", __FUNCTION__,
                LOWIUtils::currentTimeMs());

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, 0, 0) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);

  return retVal;
}

int LOWIRanging::RomeSendLCIRequest(tANI_U16 /*reqId*/, LOWISendLCIRequest *request)
{
  int retVal = 0;

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return -1;
  }

  unsigned int aniMsgLen;
  aniMsgLen = sizeof(OemMsgSubType) +
              sizeof(meas_req_lci_request);

  uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);
  /* Allocate Space for ANI Message (Header + Body) */
  char *aniMessage = (char *)calloc((sizeof(tAniMsgHdr) + aniMsgLen + aniMetaLen), 1);
  if (aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return -1;
  }

  LOWI_LOG_VERB("%s: Fill in Where are you request ANI Message Header\n", __FUNCTION__);
  /* Fill the ANI Header */
  tAniMsgHdr *aniMsgHeader = (tAniMsgHdr *)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  LOWI_LOG_VERB("%s: Fill in Where are you Message Body\n", __FUNCTION__);
  /* Fill in the ANI Message Body */
  char *aniMsgBody = (char *)(aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);

  /* Load the OEM Message Subtype */
  OemMsgSubType *oemMsgSubType = (OemMsgSubType *)aniMsgBody;
  *oemMsgSubType = TARGET_OEM_LCI_REQ;

  meas_req_lci_request *wru = (meas_req_lci_request *)(aniMsgBody + sizeof(OemMsgSubType));
  memset(wru, 0, sizeof(meas_req_lci_request));
  wru->req_id = request->getRequestId();
  LOWIMacAddress sta_mac(request->getBssid());
  for (int i = 0; i < BSSID_SIZE; i++)
  {
    wru->sta_mac[i] = sta_mac[i];
  }
  wru->dialogtoken = gDialogTok++;
  if (gDialogTok == 0)
  {
    /* Dialog Token shall always be a non zero number so increment again*/
    gDialogTok++;
  }
  wru->element_id     = RM_MEAS_REQ_ELEM_ID;
  wru->length         = sizeof(wru->meas_token) + sizeof(wru->meas_req_mode) +
                        sizeof(wru->meas_type) + sizeof(wru->loc_subject);
  wru->meas_token = gMeasTok++;
  if (gMeasTok == 0)
  {
    /* Mesurement Token shall always be a non zero number so increment again*/
    gMeasTok++;
  }
  wru->meas_type      = LOWI_WLAN_LCI_REQ_TYPE;
  wru->loc_subject    = LOWI_LOC_SUBJECT_REMOTE;

  LOWI_LOG_VERB("%s: Sending Where are you Req message over NL at TS: %" PRId64 " ms\n", __FUNCTION__,
              LOWIUtils::currentTimeMs());

  /* Fill Meta data */
  uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
  *count = 1;
  struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
  sMetaData->id = WMIRTT_FIELD_ID_oem_data_sub_type;
  sMetaData->offset = 0;
  sMetaData->length = sizeof(uint32_t);

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, aniMetaLen, 0) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);

  return retVal;
}

int LOWIRanging::RomeSendFTMRR(tANI_U16 /*reqId*/, LOWIFTMRangingRequest *request)
{
  int retVal = 0;
  std::string interface = "wifi0";

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return -1;
  }

  unsigned int aniMsgLen;
  aniMsgLen = sizeof(OemMsgSubType) +
              sizeof(neighbor_report_arr);

  uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);
  uint32 aniInterfaceLen = sizeof(tAniInterface) + sizeof(uint32_t);

  /* Allocate Space for ANI Message (Header + Body) */
  char *aniMessage = (char *)calloc((sizeof(tAniMsgHdr) + aniMsgLen + aniMetaLen + aniInterfaceLen), 1);
  if (aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return -1;
  }

  LOWI_LOG_VERB("%s: Fill in FTMRR ANI Message Header\n", __FUNCTION__);
  /* Fill the ANI Header */
  tAniMsgHdr *aniMsgHeader = (tAniMsgHdr *)aniMessage;
  aniMsgHeader->type = ANI_MSG_OEM_DATA_REQ;
  aniMsgHeader->length = aniMsgLen;

  LOWI_LOG_VERB("%s: Fill in FTMRR Message Body\n", __FUNCTION__);
  /* Fill in the ANI Message Body */
  char *aniMsgBody = (char *)(aniMessage + sizeof(tAniMsgHdr));
  memset(aniMsgBody, 0, aniMsgLen);

  /* Load the OEM Message Subtype */
  OemMsgSubType *oemMsgSubType = (OemMsgSubType *)aniMsgBody;
  *oemMsgSubType = TARGET_OEM_FTMR_REQ;

  neighbor_report_arr *ftmrr = (neighbor_report_arr *)(aniMsgBody + sizeof(OemMsgSubType));
  memset(ftmrr, 0, sizeof(neighbor_report_arr));
  ftmrr->req_id = request->getRequestId();
  LOWIMacAddress sta_mac(request->getBSSID());
  for (int i = 0; i < BSSID_SIZE; i++)
  {
    ftmrr->sta_mac[i] = sta_mac[i];
  }
  ftmrr->dialogtoken = gDialogTok++;
  if (gDialogTok == 0)
  {
    /* Dialog Token shall always be a non zero number so increment again*/
    gDialogTok++;
  }
  const vector<LOWIFTMRRNodeInfo>& nodes = request->getNodes();
  ftmrr->element_id   = RM_MEAS_REQ_ELEM_ID;
  ftmrr->min_ap_count = nodes.getNumOfElements();
  ftmrr->len          = sizeof(ftmrr->meas_token) + sizeof(ftmrr->meas_req_mode) +
                        sizeof(ftmrr->meas_type) + sizeof(ftmrr->rand_inter) +
                        sizeof(ftmrr->min_ap_count) +
                        ftmrr->min_ap_count*sizeof(ftmrr->elem[0]);
  ftmrr->meas_token   = gMeasTok++;
  if (gMeasTok == 0)
  {
    /* Mesurement Token shall always be a non zero number so increment again*/
    gMeasTok++;
  }
  ftmrr->meas_type      = LOWI_WLAN_FTM_RANGE_REQ_TYPE;
  ftmrr->rand_inter     = request->getRandInter();

  for (unsigned int ii = 0; ii < nodes.getNumOfElements(); ++ii)
  {
    ftmrr->elem[ii].sub_element_id = RM_NEIGHBOR_RPT_ELEM_ID;
    ftmrr->elem[ii].sub_element_len = sizeof(neighbor_report_element_arr) -
                                      sizeof(ftmrr->elem[ii].sub_element_id) -
                                      sizeof(ftmrr->elem[ii].sub_element_len);
    for (int bssid_idx = 0; bssid_idx < BSSID_SIZE; bssid_idx++)
    {
      ftmrr->elem[ii].bssid[bssid_idx] = nodes[ii].bssid[bssid_idx];
    }
    ftmrr->elem[ii].bssid_info = nodes[ii].bssidInfo;
    ftmrr->elem[ii].operating_class = nodes[ii].operatingClass;
    ftmrr->elem[ii].channel_num = nodes[ii].ch;
    ftmrr->elem[ii].phy_type = nodes[ii].phyType;
    ftmrr->elem[ii].wbc_element_id = RM_WIDE_BW_CHANNEL_ELEM_ID;
    ftmrr->elem[ii].wbc_len = sizeof(ftmrr->elem[ii].wbc_ch_width) +
                              sizeof(ftmrr->elem[ii].wbc_center_ch0) +
                              sizeof(ftmrr->elem[ii].wbc_center_ch0);
    ftmrr->elem[ii].wbc_ch_width = (uint8)nodes[ii].bandwidth;
    ftmrr->elem[ii].wbc_center_ch0 = nodes[ii].center_Ch1;
    ftmrr->elem[ii].wbc_center_ch1 = nodes[ii].center_Ch2;

    unsigned char *charPtr = (unsigned char *)&(ftmrr->elem[ii]);
    for (size_t idx = 0; idx < sizeof(neighbor_report_element_arr); ++idx)
    {
      LOWI_LOG_VERB("%s - nbr(%d), %02x ", __FUNCTION__, ii, charPtr[idx]);
    }
  }
  LOWI_LOG_VERB("%s: Sending FTMRR message over NL at TS: %" PRId64 " ms\n", __FUNCTION__,
              LOWIUtils::currentTimeMs());

  /* Fill Meta data */
  uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
  *count = 1;
  struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
  sMetaData->id = WMIRTT_FIELD_ID_oem_data_sub_type;
  sMetaData->offset = 0;
  sMetaData->length = sizeof(uint32_t);


  struct tAniInterface *aniInterface = (struct tAniInterface *)(aniMsgBody + aniMsgLen + aniMetaLen);
  aniInterface->length = interface.length();
  strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, sizeof(tAniMsgHdr), aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return -1;
  }

  free(aniMessage);

  return retVal;
}


/***** END - Message Senders *******/

/***** Event related Functions *******/
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
int LOWIRanging::RomeUnblockRangingThread(void)
{
  int retVal = -1;
  char string [] = "Close";
  LOWI_LOG_DBG ("%s", __FUNCTION__);
  if (0 != pipe_ranging_fd [1])
  {
    retVal = write(pipe_ranging_fd[1], string, (strlen(string)+1));
  }

  return retVal;
}

/*=============================================================================================
 * Function description:
 *   Called by external entity to create the pipe to Ranging Thread
 *
 * Parameters:
 *   None
 *
 * Return value:
 *    0 Success, other values otherwise
 =============================================================================================*/
int LOWIRanging::RomeInitRangingPipe(void)
{
  if (pipe_ranging_fd[0] == 0 &&
      pipe_ranging_fd[1] == 0)
  {
    LOWI_LOG_DBG( "Creating pipe to Ranging Thread\n");
    return pipe(pipe_ranging_fd);
  }
  else
  {
    LOWI_LOG_DBG( "The pipe to Ranging Thread is already valid\n");
    return -1;
  }
}

/*=============================================================================================
 * Function description:
 *   Called by external entity to close the pipe to Ranging thread
 *
 * Parameters:
 *   None
 *
 * Return value:
 *    0 Success, other values otherwise
 =============================================================================================*/
int LOWIRanging::RomeCloseRangingPipe(void)
{
  LOWI_LOG_DBG( "Closing the Ranging pipe\n");
  if (pipe_ranging_fd[0] > 0)
  {
    close (pipe_ranging_fd[0]);
    pipe_ranging_fd [0] = 0;
  }

  if (pipe_ranging_fd[1] > 0)
  {
    close (pipe_ranging_fd[1]);
    pipe_ranging_fd [1] = 0;
  }
  return 0;
}

/*===========================================================================
 * Function description:
 *   Waits on a private Netlink socket for one of the following events
 *       1) Data becomes available on socket
 *       2) Activity on unBlock Pipe
 *       3) A timeout happens.
 *
 * Parameters:
 *   nl_sock_fd is the file descriptor of the Private Netlink Socket
 *   int timeout_val is the timout value specified by caller
 *
 * Return value:
 *   TRUE, if some data is available on socket. FALSE, if timed out or error
 ===========================================================================*/
int LOWIRanging::RomeWaitOnActivityOnSocketOrPipe(int timeout_val)
{
  struct timeval tv;
  fd_set read_fd_set;
  int max_fd;
  int retval;

  max_fd = MAX(nl_sock_fd, pipe_ranging_fd[0]);
  if (max_fd <= 0)
  {
    LOWI_LOG_ERROR("%s: Both socket and pipe not initialized %d, %d",
                   __FUNCTION__, nl_sock_fd, pipe_ranging_fd[0]);
    return ERR_NOT_READY;
  }
  // At least one socket is valid
  tv.tv_sec = timeout_val;
  tv.tv_usec = 0;
  FD_ZERO(&read_fd_set);
  if (nl_sock_fd > 0)
  {
    FD_SET(nl_sock_fd, &read_fd_set);
  }
  else
  {
    LOWI_LOG_WARN("%s: Bad netlink socket %d", __FUNCTION__,
                  nl_sock_fd);
  }
  if (pipe_ranging_fd[0] > 0)
  {
    FD_SET(pipe_ranging_fd[0], &read_fd_set);
  }
  else
  {
    LOWI_LOG_WARN("%s: Bad pipe %d", __FUNCTION__, pipe_ranging_fd[0]);
  }

  if (timeout_val >= 0)
  {
    LOWI_LOG_DBG("%s: issue timed select: TO: %i \n", __FUNCTION__, timeout_val);
    retval = select(max_fd+1, &read_fd_set, NULL,NULL,&tv);
    LOWI_LOG_DBG("%s: timed select over: TO: %i retVal: %d\n",
                 __FUNCTION__, timeout_val, retval);
  }
  else
  {
    LOWI_LOG_DBG("%s: issue blocking select \n", __FUNCTION__);
    retval = select(max_fd+1, &read_fd_set, NULL,NULL,NULL);
  }

  if (retval == 0) //This means the select timed out
  {
    LOWI_LOG_DBG("%s: No Messages Received!! Timeout \n", __FUNCTION__);
    retval = ERR_SELECT_TIMEOUT;
    return retval;
  }

  if (retval < 0) //This means the select failed with some error
  {
    LOWI_LOG_ERROR("%s: No scan Results!! Error %s(%d)\n",
                   __FUNCTION__, strerror(errno), errno);
  }

  if ( FD_ISSET( pipe_ranging_fd[0], &read_fd_set ) )
  {
    char readbuffer [50];
    read(pipe_ranging_fd[0], readbuffer, sizeof(readbuffer));

    LOWI_LOG_DBG("%s: Ranging thread Received string: %s, request socket shutdown \n",
                 __FUNCTION__, readbuffer);
    retval = ERR_SELECT_TERMINATED;
  }

  return retval;
}
/***** END - Event related Functions *******/

/******* Message Handlers **************/

/*=============================================================================================
 * Function description:
 * Close Rome RTT Interface Module
 *
 * Parameters:
 *    msgType: The Type of Message received
 *    data   : The message body
 *
 * Return value:
 *    SUCCESS/FAILURE
 =============================================================================================*/
int LOWIRanging::RomeNLRecvMessage(RomeNlMsgType* msgType, void* data, tANI_U32 maxDataLen)
{
  int retVal = 0;
  OemMsgSubType* oemMsgSubType = NULL;
  tAniMsgHdr* aniMsgHdr = NULL;
  bool validMsgType = TRUE;
  char* localp = (char*)data;

  LOWI_LOG_VERB("%s", __FUNCTION__);
  if (msgType == NULL || localp == NULL)
  {
    LOWI_LOG_ERROR("%s, Received NULL pointer for msgType or data", __FUNCTION__);
    return -1;
  }

  tANI_U32 maxCopyLen = (maxDataLen > MAX_NLMSG_LEN) ? MAX_NLMSG_LEN : maxDataLen;
  memset(rxBuff, 0, MAX_NLMSG_LEN);
  memset(localp, 0, maxDataLen);
  *msgType = ROME_MSG_MAX;

  if(recv_nl_msg(nl_sock_fd, rxBuff, MAX_NLMSG_LEN) > 0)
  {
    aniMsgHdr = (tAniMsgHdr*)rxBuff;

    switch(aniMsgHdr->type)
    {
      case ANI_MSG_APP_REG_RSP:
      {
        *msgType = ROME_REG_RSP_MSG;
        break;
      }
      case ANI_MSG_OEM_DATA_RSP:
      {
        oemMsgSubType = (OemMsgSubType *) (rxBuff + sizeof(tAniMsgHdr));
        LOWI_LOG_DBG("%s:  received message of subtype: %u", __FUNCTION__, *oemMsgSubType);
        switch (*oemMsgSubType)
        {
          case TARGET_OEM_CAPABILITY_RSP:
          {
            *msgType = ROME_RANGING_CAP_MSG;
            break;
          }
          case TARGET_OEM_MEASUREMENT_RSP:
          {
            LOWI_LOG_VERB("%s: Received Ranging Response message at TS: %" PRId64 " ms\n",
                          __FUNCTION__, LOWIUtils::currentTimeMs());

            *msgType = ROME_RANGING_MEAS_MSG;
            break;
          }
          case TARGET_OEM_ERROR_REPORT_RSP:
          {
            *msgType = ROME_RANGING_ERROR_MSG;
            break;
          }
          default:
          {
            LOWI_LOG_INFO("%s: Received OEM Data message with bad subtype: %u",
                           __FUNCTION__, *oemMsgSubType);
            *msgType = ROME_NL_ERROR_MSG;
            validMsgType = FALSE;
            retVal = -1;
            break;
          }
        }
        break;
      }
      case ANI_MSG_CHANNEL_INFO_RSP:
      {
        *msgType = ROME_CHANNEL_INFO_MSG;
        break;
      }
      case ANI_MSG_OEM_ERROR:
      {
        *msgType = ROME_CLD_ERROR_MSG;
        break;
      }
      case ANI_MSG_PEER_STATUS_IND:
      {
        *msgType = ROME_P2P_PEER_EVENT_MSG;
        break;
      }
      default:
      {
        *msgType = ROME_NL_ERROR_MSG;
        validMsgType = FALSE;
        break;
      }
    }
  }
  else
  {
    if (errno < 0)
    {
      LOWI_LOG_WARN("%s: NL Recv Failed, with errno(%d): %s", __FUNCTION__, errno, strerror(errno));
    }
    *msgType = ROME_NL_ERROR_MSG;
    retVal = -1;
  }

  if (validMsgType)
  {
    LOWI_LOG_DBG("Loading Message to Data");
    memcpy(localp, rxBuff, maxCopyLen);
  }

  if (aniMsgHdr)
  {
    if (oemMsgSubType)
    {
      LOWI_LOG_DBG("%s: Received ANI Msg Type: %u, OEM Type: %u, RomeMsgType: %u",
                    __FUNCTION__, aniMsgHdr->type, *oemMsgSubType, *msgType);
    }
    else
    {
      LOWI_LOG_DBG("%s: Received ANI Msg Type: %u, Type: %u",
                    __FUNCTION__, aniMsgHdr->type, *msgType);
    }
  }
  return retVal;
}

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
int LOWIRanging::RomeExtractRegRsp(void* data)
{
  char* datap = (char*) data;
  LOWI_RETURN_ON_COND(datap == NULL, -1, debug, "NULL pointer");
  tANI_U8  numVDevs = 0;
  VDevMap* aniVdevInfo;
  unsigned int ii;
  /* Extract Data from ANI Message Body */
  memset(&vDevInfo, 0, sizeof(VDevInfo));
  uint8 *aniNumVDevs = (uint8 *)(datap + sizeof(tAniMsgHdr));
  aniVdevInfo = (VDevMap*) (aniNumVDevs + 1);
  vDevInfo.numInterface = (*aniNumVDevs);
  for(ii = 0; (ii < WLAN_HDD_MAX_DEV_MODE) && (ii < (*aniNumVDevs)); ii++)
  {
    vDevInfo.vDevMap[ii].iFaceId = (aniVdevInfo + ii)->iFaceId;
    vDevInfo.vDevMap[ii].vDevId  = (aniVdevInfo + ii)->vDevId;
    if(vDevInfo.vDevMap[ii].iFaceId == WLAN_HDD_INFRA_STATION)
    {
      vDevId = vDevInfo.vDevMap[ii].vDevId;
    }
  }
  LOWI_LOG_DBG("%s: Registered with CLD, %u vDevs. Using %d for STA",
               __FUNCTION__, (*aniNumVDevs), vDevId);

  numVDevs = ii;

  LOWI_RETURN_ON_COND(numVDevs <= 0, -1, debug,
                      "CLD Registration Failed %d", numVDevs);
  return 0;
}

/*=============================================================================================
 * Function description:
 * Extract information from Channel Info message
 *
 * Parameters:
 *    data   : The message body
 *
 * Return value:
 *    SUCCESS/FAILURE
 =============================================================================================*/
int LOWIRanging::RomeExtractChannelInfo(void* data, ChannelInfo *pChannelInfoArray)
{
  char* datap = (char*) data;
  LOWI_RETURN_ON_COND(datap == NULL, -1, debug, "NULL pointer");
  /* Extract Data from ANI Message Body */
  uint8 *aniNumChan = (uint8 *)(datap + sizeof(tAniMsgHdr));
  Ani_channel_info *aniChannelInfo = (Ani_channel_info*) (aniNumChan+1);
  LOWI_LOG_VERB("%s: aniNumChan: %u \n", __FUNCTION__, (*aniNumChan));
  for( uint32 ii = 0; ii < (*aniNumChan); ii++ )
  {
    LOWI_LOG_VERB ("%s: Chan ID = %d", __FUNCTION__, aniChannelInfo[ii].chan_id);
    /* Copy Channel info for valid positive channel IDs only */
    if (aniChannelInfo[ii].chan_id > 0 && aniChannelInfo[ii].chan_id <= MAX_CHANNEL_ID)
    {
      ChannelInfo* channelInfo = &(channelInfoArray[(aniChannelInfo[ii].chan_id) - 1]);
      channelInfo->chId = (tANI_U8)aniChannelInfo[ii].chan_id;
      memcpy(&(channelInfo->wmiChannelInfo), &(aniChannelInfo[ii].channel_info), sizeof(wmi_channel));
      uint32 phyMode = channelInfo->wmiChannelInfo.info & ~PHY_MODE_MASK;
      if ((phyMode == 0) || (phyMode >= LOWI_PHY_MODE_MAX))
      {
        /* Set default values for phy mode */
        channelInfo->wmiChannelInfo.info &= PHY_MODE_MASK;
        if (LOWIUtils::freqToBand(channelInfo->wmiChannelInfo.mhz) == LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ)
        {
          channelInfo->wmiChannelInfo.info |= LOWI_PHY_MODE_11G;
        }
        else
        {
          channelInfo->wmiChannelInfo.info |= LOWI_PHY_MODE_11A;
        }
      }
      /* Copy over to Caller's Memory */
      if (pChannelInfoArray != NULL)
      {
        pChannelInfoArray[(channelInfo->chId - 1)].chId = channelInfo->chId;
        memcpy(&(pChannelInfoArray[channelInfo->chId - 1].wmiChannelInfo),
               &(channelInfo->wmiChannelInfo), sizeof(wmi_channel));
      }
    }
  }
#if 0  /* Enable this section to verify the channel info sent by the host driver */
  LOWI_LOG_VERB("%s: Here is the channel info From the Host Driver", __FUNCTION__);

  for(i = 0; i < MAX_CHANNEL_ID; i++)
  {
    if(channelInfoArray[i].chId != 0)
    {
      LOWI_LOG_VERB("%s: Ch ID: %u\n", __FUNCTION__, channelInfoArray[i].chId);
      LOWI_LOG_VERB("%s: MHz#: %u\n", __FUNCTION__, channelInfoArray[i].wmiChannelInfo.mhz);
      LOWI_LOG_VERB("%s: band_center_freq1: %u, band_center_freq2: %u\n", __FUNCTION__,
                    channelInfoArray[i].wmiChannelInfo.band_center_freq1,
                    channelInfoArray[i].wmiChannelInfo.band_center_freq2);
      LOWI_LOG_VERB("%s: info: 0x%x, reg_info_1: 0x%x, reg_info_2: 0x%x\n", __FUNCTION__,
                    channelInfoArray[i].wmiChannelInfo.info,
                    channelInfoArray[i].wmiChannelInfo.reg_info_1,
                    channelInfoArray[i].wmiChannelInfo.reg_info_2);
    }
    else
    {
      LOWI_LOG_VERB("%s: Skipping index %u which is for Ch ID: %u\n", __FUNCTION__, i, i + 1);
    }

  }
#endif
  return 0;
}

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
int LOWIRanging::RomeExtractRangingCap(void* data, RomeRttCapabilities*   pRomeRttCapabilities)
{
  if (data == NULL || pRomeRttCapabilities == NULL)
  {
    LOWI_LOG_ERROR("%s, NULL pointer - message body(%p) or capabilties(%p)",
                   __FUNCTION__, data, pRomeRttCapabilities);
    return -1;
  }
  LOWI_LOG_VERB("%s", __FUNCTION__);
  /** Get pointer to the start of the RTT capability data
   *  Moving pointer by the size of:
   *  The ANI message header +
   *  OEM Data message subtype +
   *  Request ID element */
  char *rttCap = ((char *)(data)) + sizeof(tAniMsgHdr) + sizeof(OemMsgSubType) + sizeof(tANI_U32);

  memcpy(pRomeRttCapabilities, rttCap, sizeof(RomeRttCapabilities));

  /* Extract number of RX chains being used and store in Ranging Driver*/
  rxChainsUsed = 0;
  tANI_U8 rxChainBitMask = pRomeRttCapabilities->maxRfChains;

  /* This for loop counts the bits that are set in the chain mask and stores them*/
  for (rxChainsUsed = 0; rxChainBitMask; rxChainsUsed++)
  {
    rxChainBitMask &= rxChainBitMask - 1;
  }

  return 0;

}

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
int LOWIRanging::RomeExtractRangingError(void* data, tANI_U32* errorCode, tANI_U8* bssid)
{
  int retVal = 0;
  if ( (data == NULL) || (errorCode == NULL) || (bssid == NULL) )
  {
    LOWI_LOG_DBG("%s, NULL pointer - data: %p, errorCode: %p, bssid: %p",
                   __FUNCTION__, data, errorCode, bssid);
    return -1;
  }
  RomeRTTReportHeaderIE* romeRTTReportHeaderIE = (RomeRTTReportHeaderIE*)(((char*) data) + sizeof(tAniMsgHdr) + sizeof(OemMsgSubType));
  memcpy(bssid, romeRTTReportHeaderIE->dest_mac, ETH_ALEN_PLUS_2);
  tANI_U32* pErrorCode = (tANI_U32*) (((char*) romeRTTReportHeaderIE) + sizeof(RomeRTTReportHeaderIE));
  *errorCode = *pErrorCode;
  return retVal;
}

/*=============================================================================================
 * Function description:
 * Based on the error code if the bssid will be skipped, then the bssid will be added
 * to the "Skipped Targets" List. This will allow the driver to send back appropriate
 * error codes to the client.
 *
 * Parameters:
 *    errorCode   : The Error code recieved from FW
 *    bssid       : the bssid associated with the error code
 *
 * Return value:
 *    SUCCESS/FAILURE
 =============================================================================================*/
int LOWIRanging::RomeAddSkippedTargetToList(tANI_U32 errorCode, tANI_U8 mac[ETH_ALEN_PLUS_2])
{
  switch (errorCode)
  {
    case RTT_TRANSIMISSION_ERROR:
    case RTT_TMR_TRANS_ERROR:
    case RTT_TM_TIMER_EXPIRE:
    case WMI_RTT_REJECT_MAX:
    case RTT_DFS_CHANNEL_QUIET:
    case RTT_NAN_REQUEST_FAILURE:
    case RTT_NAN_NEGOTIATION_FAILURE:
    case RTT_NAN_DATA_PATH_ACTIVE:
    {
      /* First check if Target already has an associated error code */
      for (unsigned int i = 0; i <failedTargets.getNumOfElements(); ++i)
      {
        if (!memcmp(failedTargets[i].mac, mac, BSSID_LEN))
        {
          /* Already in the List */
          failedTargets[i].errorCode = (WMI_RTT_STATUS_INDICATOR) errorCode;
          LOWI_LOG_VERB("%s: Found Target(" LOWI_MACADDR_FMT ") in Failed List. "
                        "Update errCode(%s)",
                         __FUNCTION__,
                        LOWI_MACADDR(mac),
                        LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
          return 0;
        }
      }

      FailedTarget failedTarget;
      failedTarget.errorCode = (WMI_RTT_STATUS_INDICATOR) errorCode;
      memcpy (failedTarget.mac, mac, ETH_ALEN_PLUS_2);
      failedTargets.push_back(failedTarget);
      LOWI_LOG_VERB("%s: Added Target(" LOWI_MACADDR_FMT ") to Failed List - errCode(%s)",
                     __FUNCTION__, LOWI_MACADDR(mac), LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
      break;
    }
    default:
    {
      /* Do Nothing */
      LOWI_LOG_VERB("%s: Do Nothing", __FUNCTION__);
      break;
    }
  }

#if DO_EXTRA_PRINTS
  LOWI_LOG_VERB("%s: Current failed target list:", __FUNCTION__);
  for (unsigned int i = 0; i <failedTargets.getNumOfElements(); ++i)
  {
    LOWI_LOG_VERB("%s: BSSID: " LOWI_MACADDR_FMT " ErrorCode: %s",
                   __FUNCTION__,
                   LOWI_MACADDR(failedTargets[i].mac),
                   LOWIStrings::to_string(failedTargets[i].errorCode));

  }
#endif
  return 0;
}

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
int LOWIRanging::RomeExtractP2PInfo(void* data)
{
  LOWI_LOG_DBG(" %s - P2P EVENT Received!", __FUNCTION__);

  if(NULL == data)
  {
    LOWI_LOG_ERROR("%s: NULL ptr...\n", __FUNCTION__);
    return -1;
  }

  // save peerInfo in table to be used later in ranging requests
  if( p2pStoreStatusInfo((char*) data, &mPeerInfo))
  {
    LOWI_LOG_ERROR("%s:Store peer info - failed\n", __FUNCTION__);
    return -1;
  }
  return 0;
}


void LOWIRanging::print_tx_rx_params(LOWIMeasurementInfo* measInfo)
{
  LOWI_LOG_VERB("%s: TX Params from FW: tx_preamble: %u, tx_nss: %u, tx_bw: %u, "
                "tx_mcs: %u, tx_bitrate: %u\n",
                __FUNCTION__,
               measInfo->tx_preamble,
               measInfo->tx_nss,
               measInfo->tx_bw,
               measInfo->tx_mcsIdx,
               measInfo->tx_bitrate);

  LOWI_LOG_VERB("%s: RX Params from FW: rx_preamble: %u, rx_nss: %u, rx_bw: %u, "
                "rx_mcs: %u, rx_bitrate: %u\n",
                __FUNCTION__,
                measInfo->rx_preamble,
                measInfo->rx_nss,
                measInfo->rx_bw,
                measInfo->rx_mcsIdx,
                measInfo->rx_bitrate);
}

int LOWIRanging::failedTargetCheck(tANI_U8  dest_mac[ETH_ALEN_PLUS_2],
                                   WMI_RTT_STATUS_INDICATOR &errorCode)
{
  for (unsigned int i = 0; i < failedTargets.getNumOfElements(); ++i)
  {
    if(!memcmp(dest_mac, failedTargets[i].mac, ETH_ALEN_PLUS_2))
    {
      errorCode = failedTargets[i].errorCode;
      LOWI_LOG_VERB("%s: Found Target in Failed List.", __FUNCTION__);
      return 1;
    }
  }
  return 0;
}

/*=============================================================================================
 * Function description:
 *   Processes the received RTT response from Rome FW
 *
 * Parameters:
 *   measResp: The ranging measurements from FW.
 *   scanMeasurements: The destination where parsed scan measurements
 *                     will be stored.
 *
 * Return value:
 *   error Code: 0 - Success, -1 - Failure
 *
 =============================================================================================*/
int LOWIRanging::RomeParseRangingMeas(char* measResp, vector <LOWIScanMeasurement*> *scanMeasurements)
{
  tANI_U8 rttFrameType = FRAME_TYPE_NULL;
  char* tempPtr = NULL;
  OemMsgSubType *oemMsgSubType;
  uint64 rttMeasTimestamp = 0;

  if (scanMeasurements == NULL)
  {
    return -1;
  }

  oemMsgSubType = (OemMsgSubType *) (measResp + sizeof(tAniMsgHdr));

  /* Extract RTT Report */
  RomeRTTReportHeaderIE*    rttReportHdr      = (RomeRTTReportHeaderIE *)  ((char*)oemMsgSubType     + sizeof(OemMsgSubType));
  RomeRttPerPeerReportHdr*  rttPerAPReportHdr = (RomeRttPerPeerReportHdr*) ((char*)rttReportHdr      + sizeof(RomeRTTReportHeaderIE));
  uint8*                    romeRttIes        = ((unsigned char*)rttPerAPReportHdr                   + sizeof(RomeRttPerPeerReportHdr));
  RomeRttPerFrame_IE_RTTV2* rttPerFrameRtt2IE = (RomeRttPerFrame_IE_RTTV2*)((char*)rttPerAPReportHdr + sizeof(RomeRttPerPeerReportHdr));
  RomeRttPerFrame_IE_RTTV3* rttPerFrameRtt3IE = (RomeRttPerFrame_IE_RTTV3*)((char*)rttPerAPReportHdr + sizeof(RomeRttPerPeerReportHdr));

  /* RTT was successfull -  Report has valid Data */
  /* Start extracting Measurements */

  uint8 numBSSIDs  = WMI_RTT_REPORT_NUM_AP_GET(rttReportHdr->req_id);
  uint8 reportType = WMI_RTT_REPORT_REPORT_TYPE_GET(rttReportHdr->req_id);

  /* Enable following section to debug the Data coming from FW */
#if 0
  uint32* dPtr = (uint32*) (rttReportHdr);
  #define RTT_SIZE_OF_STRING 5
  for (unsigned int kk = 0; kk < ((MAX_WMI_MESSAGE_SIZE / 4) / 5) ; kk++)
  {
    unsigned int idx = kk * 5;
    LOWI_LOG_VERB("%s: Data from FW: 0x%x 0x%x 0x%x 0x%x 0x%x ", __FUNCTION__, dPtr[idx], dPtr[idx + 1], dPtr[idx + 2], dPtr[idx + 3], dPtr[idx + 4]);
  }
#endif

  if (reportType != REPORT_AGGREGATE_MULTIFRAME)
  {
    LOWI_LOG_WARN("%s: Received RTT report type: %u, not expected",
                  __FUNCTION__, reportType);
    return -1;
  }
  uint32* freq = (uint32*)rttReportHdr->dest_mac;
  *freq = WMI_RTT_REPORT_CHAN_INFO_GET(*freq);
  LOWI_LOG_VERB("%s: Received RTT response from FW: numBSSIDs: %u, ReqID: 0x%x, channel: %u\n",
                __FUNCTION__,
                numBSSIDs,
                (rttReportHdr->req_id),
                *freq);

  for(unsigned int i = 0; i < numBSSIDs; i++)
  {
    LOWIScanMeasurement* rangingMeasurement = new (std::nothrow) LOWIScanMeasurement;
    bool invalidTimeStamp = false;
    if (rangingMeasurement == NULL)
    {
      LOWI_LOG_WARN("%s:rangingMeasurement memory allocation failure", __FUNCTION__);
      return -1;
    }
    rangingMeasurement->bssid.setMac(rttPerAPReportHdr->dest_mac);
    rangingMeasurement->frequency = *freq;
    rangingMeasurement->isSecure = false;
    rangingMeasurement->msapInfo = NULL;
    rangingMeasurement->cellPowerLimitdBm = 0;

    /* by default the measurement is a success */
    rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_SUCCESS;

    if (p2pIsStored(rttPerAPReportHdr->dest_mac, NULL))
    {
      rangingMeasurement->type = PEER_DEVICE;
    }
    else
    {
      rangingMeasurement->type = ACCESS_POINT;
    }

    rttFrameType = WMI_RTT_REPORT_TYPE2_MEAS_TYPE_GET(rttPerAPReportHdr->control);
    if (rttFrameType == RTT_MEAS_FRAME_TMR)
    {
      rangingMeasurement->rttType = qc_loc_fw::RTT3_RANGING;
    }
    else
    {
      rangingMeasurement->rttType = qc_loc_fw::RTT2_RANGING;
    }

    uint32 numSuccessfulMeasurements = WMI_RTT_REPORT_TYPE2_NUM_MEAS_GET(rttPerAPReportHdr->control);

    rangingMeasurement->num_frames_attempted = WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_GET(rttPerAPReportHdr->result_info1);
    rangingMeasurement->actual_burst_duration = WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_GET(rttPerAPReportHdr->result_info1);
    rangingMeasurement->negotiated_num_frames_per_burst = WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_GET(rttPerAPReportHdr->result_info2);
    rangingMeasurement->retry_after_duration = WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_GET(rttPerAPReportHdr->result_info2);
    rangingMeasurement->negotiated_burst_exp = WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_GET(rttPerAPReportHdr->result_info2);
    uint32 numIes = WMI_RTT_REPORT_TYPE2_NUM_IES_GET(rttPerAPReportHdr->result_info2);

    LOWI_LOG_DBG("%s: BSSID: " LOWI_MACADDR_FMT ", controlField: 0x%x, numMeas: %u, rttFrameType: %u, num_frames_attempted: %u, actual_burst_duration: %u, negotiated_num_frames_per_burst: %u, retry_after_duration: %u, negotiated_burst_exp: %u, numIEs: %u\n",
                 __FUNCTION__,
                 LOWI_MACADDR(rttPerAPReportHdr->dest_mac),
                 rttPerAPReportHdr->control,
                 numSuccessfulMeasurements,
                 rttFrameType,
                 rangingMeasurement->num_frames_attempted,
                 rangingMeasurement->actual_burst_duration,
                 rangingMeasurement->negotiated_num_frames_per_burst,
                 rangingMeasurement->retry_after_duration,
                 rangingMeasurement->negotiated_burst_exp,
                 numIes);

    rangingMeasurement->lciInfo = NULL;
    rangingMeasurement->lcrInfo = NULL;

    if (numIes)
    {
      uint8* rttIes;
      LOWILocationIE* locIe = NULL;

      for (unsigned int i = 0; i < numIes; i++)
      {
        rttIes = romeRttIes;
        // The first byte is the ID - access like an array
        uint8 id = rttIes[0];
        // The second byte is the Length - access like an array
        uint8 len = rttIes[1];
        // Move pointer by 2 bytes to point to the data section;
        romeRttIes += 2 * sizeof(uint8);
        LOWI_LOG_VERB("%s:received IE: %u, and Len: %u", __FUNCTION__, id, len);
        if (i > 1) // LOWI should receive only 2 IEs
        {
          LOWI_LOG_WARN("%s:received more than 2 IES from FW", __FUNCTION__);
        }
        else
        {
          if (romeRttIes[2] == RTT_LCI_ELE_ID ||
              romeRttIes[2] == RTT_LOC_CIVIC_ELE_ID)
          {
            locIe = new LOWILocationIE();
            if (locIe == NULL)
            {
              LOWI_LOG_WARN("%s - Failed to allocate memory!", __FUNCTION__);
              break;
            }
            locIe->id = id;
            locIe->len = len;
            locIe->locData = new uint8[len];
            if (NULL == locIe->locData)
            {
              LOWI_LOG_WARN("%s - Failed to allocate memory!", __FUNCTION__);
              delete locIe;
              break;
            }

            memcpy(locIe->locData, &romeRttIes[0], len);
          }
          switch(romeRttIes[2])
          {
            case RTT_LCI_ELE_ID:
            {
              if(rangingMeasurement->lciInfo == NULL && locIe != NULL)
              {
                LOWI_LOG_VERB("%s:received LCI IE %u - len: %u", __FUNCTION__, romeRttIes[2], locIe->len);
                rangingMeasurement->lciInfo = locIe;
              }
              else
              {
                LOWI_LOG_WARN("%s:Discarding this LCI IE - already received", __FUNCTION__);
                delete locIe;
              }
              break;
            }
            case RTT_LOC_CIVIC_ELE_ID:
            {
              if (rangingMeasurement->lcrInfo == NULL && locIe != NULL)
              {
                LOWI_LOG_VERB("%s: received LCR IE %u - len: %u", __FUNCTION__, romeRttIes[2], locIe->len);
                rangingMeasurement->lcrInfo = locIe;
              }
              else
              {
                LOWI_LOG_WARN("%s: Discarding this LCR IE - already received", __FUNCTION__);
                delete locIe;
              }

              break;
            }
            default:
            {
              LOWI_LOG_WARN("%s: received unrecognized IE %u", __FUNCTION__, romeRttIes[2]);
              delete locIe;
              break;
            }
          }
          locIe = NULL;
        }

        /* Move to next IE */
        romeRttIes += len;
        if ((len + 2) % 4) // check if length is 4 byte aligned
        {
          romeRttIes += (4 - ((len + 2)% 4));
        }
      }

      /* If there are measurements following, They will be after the IEs
         So setting Meas pointers accordingly */
      rttPerFrameRtt2IE = (RomeRttPerFrame_IE_RTTV2*)(romeRttIes);
      rttPerFrameRtt3IE = (RomeRttPerFrame_IE_RTTV3*)(romeRttIes);
    }
    else
    {
      LOWI_LOG_VERB("%s: No IEs received", __FUNCTION__);
    }

    if(numSuccessfulMeasurements)
    {
      for(unsigned int j = 0; j < numSuccessfulMeasurements; j++)
      {
        tANI_U64 rttTod = 0, rttToa = 0;
        int64    rtt64 = 0;

        LOWIMeasurementInfo* measurementInfo = new (std::nothrow) LOWIMeasurementInfo;
        if (measurementInfo == NULL)
        {
          LOWI_LOG_WARN("%s: measurementInfo memory allocation faliure", __FUNCTION__);
          return -1;
        }

        if(rttFrameType == FRAME_TYPE_NULL ||
           rttFrameType == FRAME_TYPE_QOS_NULL)
        {
          /* Get RSSI and convert it to 0.5 dBm units */
          measurementInfo->rssi = lowi_get_primary_channel_rssi(rttPerFrameRtt2IE->rssi);

          LOWI_LOG_VERB("%s: TOD.time32: 0x%x, TOD.time0: 0x%x, TOA.time32: 0x%x, TOA.time0: 0x%x \n", __FUNCTION__,
                        rttPerFrameRtt2IE->tod.time32,
                        rttPerFrameRtt2IE->tod.time0,
                        rttPerFrameRtt2IE->toa.time32,
                        rttPerFrameRtt2IE->toa.time0);

          rttTod = (tANI_U64)rttPerFrameRtt2IE->tod.time32;
          rttTod = ((rttTod << 32) | rttPerFrameRtt2IE->tod.time0);
          rttToa = (tANI_U64)rttPerFrameRtt2IE->toa.time32;
          rttToa = ((rttToa << 32) | rttPerFrameRtt2IE->toa.time0);
          rtt64 = rttToa - rttTod;
          /** Note: For now we are subtracting a offset value which will be removed
           *  After the FW team figures out the HW calibration factor
           */
          measurementInfo->rtt_ps = (rtt64 - RTT2_OFFSET)*100;
          measurementInfo->rtt    = measurementInfo->rtt_ps/1000;

          LOWI_LOG_DBG("%s: RTT: %u (ps), RSSI: %d \n",
                       __FUNCTION__,
                       measurementInfo->rtt_ps,
                       measurementInfo->rssi);

          /* Get TX Parameters */
          measurementInfo->tx_preamble = WMI_RTT_RSP_X_PREAMBLE_GET(rttPerFrameRtt2IE->tx_rate_info_1);
          measurementInfo->tx_nss = TX_CHAIN_1;
          measurementInfo->tx_bw = WMI_RTT_RSP_X_BW_USED_GET(rttPerFrameRtt2IE->tx_rate_info_1);
          measurementInfo->tx_mcsIdx = WMI_RTT_RSP_X_MCS_GET(rttPerFrameRtt2IE->tx_rate_info_1);
          measurementInfo->tx_bitrate = rttPerFrameRtt2IE->tx_rate_info_2;
          /* Get RX Parameters */
          measurementInfo->rx_preamble = WMI_RTT_RSP_X_PREAMBLE_GET(rttPerFrameRtt2IE->rx_rate_info_1);
          measurementInfo->rx_nss = rxChainsUsed;
          measurementInfo->rx_bw = WMI_RTT_RSP_X_BW_USED_GET(rttPerFrameRtt2IE->rx_rate_info_1);
          measurementInfo->rx_mcsIdx = WMI_RTT_RSP_X_MCS_GET(rttPerFrameRtt2IE->rx_rate_info_1);
          measurementInfo->rx_bitrate = rttPerFrameRtt2IE->rx_rate_info_2;
          // Add Sanity check for TX BW
          if (measurementInfo->tx_bw >= BW_MAX)
          {
            LOWI_LOG_ERROR("Invalid measurementInfo Tx BW from fw %d, capping to default", measurementInfo->tx_bw);
            measurementInfo->tx_bw = BW_20MHZ;
          }
          // Add Sanity check for RX BW
          if (measurementInfo->rx_bw >= BW_MAX)
          {
            LOWI_LOG_ERROR("Invalid measurementInfo Rx BW from fw %d, capping to default", measurementInfo->rx_bw);
            measurementInfo->rx_bw = BW_20MHZ;
          }

          /* Increment pointers - Per frame Pointers*/
          rttPerFrameRtt2IE++;
        }
        else if(rttFrameType == FRAME_TYPE_TMR)
        {
          LOWI_LOG_VERB("%s: T1.time32: 0x%x, T1.time0: 0x%x, T2.time32: 0x%x, T2.time0: 0x%x, T3_del: 0x%x, T4_del: 0x%x \n",
                        __FUNCTION__,
                        rttPerFrameRtt3IE->t1.time32,
                        rttPerFrameRtt3IE->t1.time0,
                        rttPerFrameRtt3IE->t2.time32,
                        rttPerFrameRtt3IE->t2.time0,
                        rttPerFrameRtt3IE->t3_del,
                        rttPerFrameRtt3IE->t4_del);

          /* collect Time stamp from first measurement */
          if (j == 0)
          {
            rttMeasTimestamp = (uint64) (rttPerFrameRtt3IE->t2.time32);
            rttMeasTimestamp = (uint64) ((rttMeasTimestamp << 32) | rttPerFrameRtt3IE->t2.time0);
            LOWI_LOG_VERB("%s: rttMeasTimestamp = 0x%" PRIx64, __FUNCTION__, rttMeasTimestamp);
          }
          WMI_RTT_STATUS_INDICATOR errCode;
          if(failedTargetCheck(rttPerAPReportHdr->dest_mac, errCode))
          {
            /** This AP has a failure code associated with it, which
             *  means we shall discard its measurements and use only the
             *  timestamp from the first measurement */
            LOWI_LOG_VERB("%s: Failed to range with this target - Not parsing Measurement",
                          __FUNCTION__);
            delete measurementInfo;
            measurementInfo = NULL;
            break;
          }
          else if (numSuccessfulMeasurements == 1 &&
                   (!rttPerFrameRtt3IE->t3_del &&
                    !rttPerFrameRtt3IE->t4_del))
          {
            /* This implies that there are no valid successful measurements */
            invalidTimeStamp = true;
            delete measurementInfo;
            measurementInfo = NULL;
            break; /* Skip this measurement */
          }
          /* Get RSSI and convert it to 0.5 dBm units */
          measurementInfo->rssi = lowi_get_primary_channel_rssi(rttPerFrameRtt3IE->rssi);

          /** According to FW team t3_del & t4_del are defined as follows
           *  t3_del = T3 - T2
           *  t4_Del = T4 - T1
           *
           * In RTTV3 protocol:   RTT =  (T4 - T1) - (T3 - T2)
           * which translates to: RTT =    t4_del  -  t3_del
           * T1 and T2 are not needed for calculating RTT
           * Since t4_del and t3_del are uint32, cast to int32 and then
           * to int64 to keep sign.
           */
          rtt64 = (int64)((int32)(rttPerFrameRtt3IE->t4_del - rttPerFrameRtt3IE->t3_del));
          measurementInfo->rtt_ps = ((int32)(rtt64))*100;

          measurementInfo->rtt    = measurementInfo->rtt_ps/1000;
          LOWI_LOG_DBG("%s: RTT: %d (ps), RSSI: %d \n", __FUNCTION__,
                       measurementInfo->rtt_ps,
                       measurementInfo->rssi);

          /* Get TX Parameters */
          measurementInfo->tx_preamble = WMI_RTT_RSP_X_PREAMBLE_GET(rttPerFrameRtt3IE->tx_rate_info_1);
          measurementInfo->tx_nss = TX_CHAIN_1;
          measurementInfo->tx_bw = WMI_RTT_RSP_X_BW_USED_GET(rttPerFrameRtt3IE->tx_rate_info_1);
          measurementInfo->tx_mcsIdx = WMI_RTT_RSP_X_MCS_GET(rttPerFrameRtt3IE->tx_rate_info_1);
          measurementInfo->tx_bitrate = rttPerFrameRtt3IE->tx_rate_info_2;
          /* Get RX Parameters */
          measurementInfo->rx_preamble = WMI_RTT_RSP_X_PREAMBLE_GET(rttPerFrameRtt3IE->rx_rate_info_1);
          measurementInfo->rx_nss = rxChainsUsed;
          measurementInfo->rx_bw = WMI_RTT_RSP_X_BW_USED_GET(rttPerFrameRtt3IE->rx_rate_info_1);
          measurementInfo->rx_mcsIdx = WMI_RTT_RSP_X_MCS_GET(rttPerFrameRtt3IE->rx_rate_info_1);
          measurementInfo->rx_bitrate = rttPerFrameRtt3IE->rx_rate_info_2;

          LOWI_LOG_VERB("%s: RTT V3 Performed - Preamble: %s, RX BW: %s, MCS Index: %u, BitRate: %u (100Kbps) Raw RSSI: 0x%x \n",
                        __FUNCTION__,
                        LOWIStrings::rtt_preamble_type_to_string(measurementInfo->rx_preamble),
                        LOWIUtils::to_string(LOWIUtils::to_eRangingBandwidth(measurementInfo->rx_bw)),
                        measurementInfo->rx_mcsIdx,
                        measurementInfo->rx_bitrate,
                        measurementInfo->rssi);

          /* Increment pointers - Per frame Pointers*/
          rttPerFrameRtt3IE++;
        }

        //print_tx_rx_params(measurementInfo);
        /* Set the timestamp for this measurement */
        measurementInfo->rssi_timestamp = measurementInfo->rtt_timestamp = LOWIUtils::currentTimeMs();
        rangingMeasurement->measurementsInfo.push_back(measurementInfo);
      } /* loop end */
    }

    /** Section of code that assigns the error codes */
    {

      WMI_RTT_STATUS_INDICATOR errorCode;
      if (failedTargetCheck(rttPerAPReportHdr->dest_mac, errorCode))
      {
        /* Target failed so it was skipped by FW */
        if (errorCode == RTT_TRANSIMISSION_ERROR ||
            errorCode == RTT_TMR_TRANS_ERROR ||
            errorCode == RTT_DFS_CHANNEL_QUIET)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_NO_RSP;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_FAIL_NO_RSP\n",
                        __FUNCTION__);
        }
        else if (errorCode == RTT_NAN_REQUEST_FAILURE)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_FAILURE;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_FAILURE\n",
                        __FUNCTION__);
          goto exit;
        }
        else if (errorCode == RTT_NAN_NEGOTIATION_FAILURE)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_NAN_RANGING_PROTOCOL_FAILURE;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_NAN_RANGING_PROTOCOL_FAILURE\n",
                        __FUNCTION__);
          goto exit;
        }
        else if (errorCode == RTT_NAN_DATA_PATH_ACTIVE)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_NAN_RANGING_CONCURRENCY_NOT_SUPPORTED;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_NAN_RANGING_CONCURRENCY_NOT_SUPPORTED\n",
                        __FUNCTION__);
          goto exit;
        }
        else if (errorCode == WMI_RTT_REJECT_MAX)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_REJECTED;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_FAIL_REJECTED\n",
                        __FUNCTION__);
        }
        else if (errorCode == RTT_TM_TIMER_EXPIRE)
        {
          rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_FTM_TIMEOUT;
          LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_FAIL_FTM_TIMEOUT\n",
                        __FUNCTION__);
        }
      }
      else if (rangingMeasurement->retry_after_duration)
      {
        rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_BUSY_TRY_LATER;
        LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_FAIL_TARGET_BUSY_TRY_LATER\n",
                      __FUNCTION__);
      }
    }

    /* Target has no valid measurements because all the Time stamps were invalid */
    if (invalidTimeStamp &&
        rangingMeasurement->measurementsInfo.getNumOfElements() == 0)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_INVALID_TS;
      LOWI_LOG_VERB("%s: Target Setting Status to LOWI_TARGET_STATUS_RTT_FAIL_INVALID_TS\n",
                    __FUNCTION__);
    }

exit:
    /* Store RTT time stamp for when the measurement was started in FW */
    rangingMeasurement->rttMeasTimeStamp = rttMeasTimestamp;
    LOWI_LOG_VERB("%s: The RTT timestamp for this target: 0x%" PRIx64"\n",
                  __FUNCTION__, rangingMeasurement->rttMeasTimeStamp);

    /* Increment and reset pointers - Per AP pointers*/
    tempPtr = (char*)rttPerAPReportHdr;
    if(rttFrameType == FRAME_TYPE_TMR)
    {
      tempPtr = tempPtr + (sizeof(RomeRttPerPeerReportHdr) + (sizeof(RomeRttPerFrame_IE_RTTV3) * numSuccessfulMeasurements));
    }
    else
    {
      tempPtr = tempPtr + (sizeof(RomeRttPerPeerReportHdr) + (sizeof(RomeRttPerFrame_IE_RTTV2) * numSuccessfulMeasurements));
    }
    rttPerAPReportHdr = (RomeRttPerPeerReportHdr*)tempPtr;
    rttPerFrameRtt2IE = (RomeRttPerFrame_IE_RTTV2*)(tempPtr + sizeof(RomeRttPerPeerReportHdr));
    rttPerFrameRtt3IE = (RomeRttPerFrame_IE_RTTV3*)(tempPtr + sizeof(RomeRttPerPeerReportHdr));

    LOWI_LOG_VERB("%s: The Target Status set to: %u\n", __FUNCTION__, rangingMeasurement->targetStatus);
    scanMeasurements->push_back(rangingMeasurement);
    invalidTimeStamp = false;
  }

  failedTargets.flush();
  return 0;
}



/************ END - Message Handlers ****************/
LOWICLD80211Intf* LOWICLD80211Intf::mInstance = NULL;
char LOWICLD80211Intf::mRecvdata[MAX_NLMSG_LEN] = "";       /* Buffer used to store in coming messages */
unsigned int LOWICLD80211Intf::mRecvdataLen = 0;

LOWICLD80211Intf::LOWICLD80211Intf(void* libcld80211_handle)
{
  mLibcld80211_handle = libcld80211_handle;
  mCldctx = NULL;
  mCld80211Init = NULL;
  mCld80211DeInit = NULL;
  mCld80211MsgAlloc = NULL;
  mCld80211AddMcastGroup = NULL;
  mCld80211RemoveMcastGroup = NULL;
  mCld80211SendMsg = NULL;
  mCld80211Recv = NULL;
  mCld80211ExitRecv = NULL;
};

LOWICLD80211Intf:: ~LOWICLD80211Intf()
{
  if (mInstance != NULL)
  {
    if(mCldctx != NULL)
    {
      mCld80211RemoveMcastGroup(mCldctx, "oem_msgs");
      mCld80211ExitRecv(mCldctx);
      mCld80211DeInit(mCldctx);
    }
    mInstance = NULL;
  }
  if (mLibcld80211_handle != NULL)
  {
    dlclose(mLibcld80211_handle);
  }
}

LOWICLD80211Intf* LOWICLD80211Intf::createInstance()
{
  void* libcld80211_handle = NULL;

  if (mInstance != NULL)
  {
    return mInstance;
  }
#if __WORDSIZE == 64
  else if (((libcld80211_handle = dlopen("/system/lib64/libcld80211.so", RTLD_NOW)) != NULL) ||
           ((libcld80211_handle = dlopen("/system/vendor/lib64/libcld80211.so", RTLD_NOW)) != NULL))
#else
  else if (((libcld80211_handle = dlopen("/system/lib/libcld80211.so" , RTLD_NOW)) != NULL) ||
           ((libcld80211_handle = dlopen("/system/vendor/lib/libcld80211.so", RTLD_NOW)) != NULL))
#endif
  {
    mInstance = new LOWICLD80211Intf(libcld80211_handle);
  }
  else
  {
    LOWI_LOG_DBG("%s: libCld80211 not found\n", __FUNCTION__);
  }
  return mInstance;
}

int LOWICLD80211Intf::cld80211InitAndRegister()
{
  int retVal = -1;
  mCldctx = mCld80211Init();
  if (mCldctx == NULL)
  {
    LOWI_LOG_DBG("%s: cld80211 Init failed\n", __FUNCTION__);
    return retVal;
  }
  if (mCld80211AddMcastGroup(mCldctx, "oem_msgs") < 0)
  {
    LOWI_LOG_DBG("%s: failed to register for OEM MSGS\n", __FUNCTION__);
    return retVal;
  }
  LOWI_LOG_DBG("%s: Init and Registration done\n", __FUNCTION__);
  return 0;
}

int LOWICLD80211Intf::cld80211LoadSymbols()
{
  int retVal = -1;
  do
  {
    //break if handle is null
    LOWI_BREAK_ON_COND((NULL == mLibcld80211_handle), debug, "invalid libCld80211 handle")
    //load the cld80211_init function
    mCld80211Init = (cld80211Init_t)dlsym(mLibcld80211_handle, "cld80211_init");
    LOWI_BREAK_ON_COND((NULL == mCld80211Init), debug, "failed to load cld80211_init symbol")

    //load cld80211_add_mcast_group function and register for oem_msgs
    mCld80211AddMcastGroup  = (cld80211AddMcastGroup_t)dlsym(mLibcld80211_handle, "cld80211_add_mcast_group");
    LOWI_BREAK_ON_COND((NULL == mCld80211AddMcastGroup), debug,
                       "failed to load cld80211_add_mcast_group symbol")

    //load the cld80211_remove_mcast_group function
    mCld80211RemoveMcastGroup  = (cld80211RemoveMcastGroup_t)dlsym(mLibcld80211_handle, "cld80211_remove_mcast_group");
    LOWI_BREAK_ON_COND((NULL == mCld80211RemoveMcastGroup), debug,
                       "failed to load cld80211_remove_mcast_group symbol")

    //load the cld80211_send_msg function
    mCld80211SendMsg  = (cld80211SendMsg_t)dlsym(mLibcld80211_handle, "cld80211_send_msg");
    LOWI_BREAK_ON_COND((NULL == mCld80211SendMsg), debug, "failed to load cld80211_send_msg")

    //load the cld80211_recv function
    mCld80211Recv  = (cld80211Recv_t)dlsym(mLibcld80211_handle, "cld80211_recv");
    LOWI_BREAK_ON_COND((NULL == mCld80211Recv), debug, "failed to load cld80211_recv function")

    //load the exit_cld80211_recv function
    mCld80211ExitRecv  = (cld80211ExitRecv_t)dlsym(mLibcld80211_handle, "exit_cld80211_recv");
    LOWI_BREAK_ON_COND((NULL == mCld80211ExitRecv), debug, "failed to load exit_cld80211_recv function")

    //load the cld80211_msg_alloc function
    mCld80211MsgAlloc  = (cld80211MsgAlloc_t)dlsym(mLibcld80211_handle, "cld80211_msg_alloc");
    LOWI_BREAK_ON_COND((NULL == mCld80211MsgAlloc), debug, "failed to load cld80211_msg_alloc function")

    retVal = 0;
  }while(0);
  return retVal;
}

int LOWICLD80211Intf::send_cld80211_nlmsg(int cmd, void *data, int len, int pid)
{
  int ret = -1;
  struct nlattr *nla_data = NULL;
  struct nl_msg *nlmsg;

  nlmsg = (struct nl_msg *)mCld80211MsgAlloc(mCldctx, cmd, &nla_data, pid);
  if (!nlmsg)
  {
    return ret;
  }
  ret = nla_put(nlmsg, CLD80211_ATTR_DATA, len, data);
  if (ret != 0)
  {
    nlmsg_free(nlmsg);
    return ret;
  }
  nla_nest_end(nlmsg, nla_data);
  ret = mCld80211SendMsg(mCldctx, nlmsg);
  if (ret != 0)
  {
    LOWI_LOG_INFO("%s: send cld80211 message - failed\n", __FUNCTION__);
    nlmsg_free(nlmsg);
    return ret;
  }
  LOWI_LOG_DBG("%s: sent cld80211 message for pid %d\n", __FUNCTION__, pid);
  nlmsg_free(nlmsg);
  return ret;
}

int LOWICLD80211Intf::event_handler(struct nl_msg *msg, void * /*arg*/)
{
  memset(mRecvdata, 0, MAX_NLMSG_LEN);
  mRecvdataLen = 0;
  struct nlattr *attrs[CLD80211_ATTR_MAX +1];
  struct genlmsghdr *header;
  struct nlattr *tb_vendor [CLD80211_ATTR_MAX +1];
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  header = (struct genlmsghdr *)nlmsg_data(nlh);

  int result = nla_parse(attrs, CLD80211_ATTR_MAX, genlmsg_attrdata(header, 0),
                         genlmsg_attrlen(header, 0), NULL);

  if (!result && attrs[CLD80211_ATTR_VENDOR_DATA])
  {
    nla_parse(tb_vendor, CLD80211_ATTR_MAX,
             (struct nlattr *)nla_data(attrs[CLD80211_ATTR_VENDOR_DATA]),
              nla_len(attrs[CLD80211_ATTR_VENDOR_DATA]), NULL);

    if(tb_vendor[CLD80211_ATTR_DATA])
    {
      tAniMsgHdr *clh = (tAniMsgHdr *)nla_data(tb_vendor[CLD80211_ATTR_DATA]);
      if (clh == NULL)
      {
        LOWI_LOG_DBG("%s: NULL data received\n", __FUNCTION__);
        return -1;
      }
      mRecvdataLen = nla_len(tb_vendor[CLD80211_ATTR_DATA]);
      memcpy(mRecvdata, clh, mRecvdataLen);
      LOWI_LOG_DBG("%s: Valid data with length %d\n", __FUNCTION__, mRecvdataLen);
    }
    else
    {
      LOWI_LOG_INFO("%s: invalid data\n", __FUNCTION__);
      return -1;
    }
  }
  else
  {
    LOWI_LOG_INFO("%s: no CLD80211_ATTR_DATA data\n", __FUNCTION__);
    return -1;
  }
  return 0;
}
