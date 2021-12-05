/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
LOWI Internal Message

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Internal Message

Copyright (c) 2015-2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <base_util/log.h>
#include <common/lowi_utils.h>
#include <lowi_server/lowi_internal_message.h>
#include <lowi_server/lowi_controller.h>
#include <lowi_server/lowi_rome_wifidriver.h>

using namespace qc_loc_fw;

const char* const LOWIInternalMessage::TAG = "LOWIInternalMessage";

LOWIRangeEntry::LOWIRangeEntry()
{
  measStartTime = 0;
  range         = 0;
  maxErrRange   = 0;
}

LOWIErrEntry::LOWIErrEntry()
{
  measStartTime = 0;
  errCode       = TX_FAIL;
}

//////////////////////
// LOWIInternalMessage
//////////////////////
LOWIInternalMessage::LOWIInternalMessage(uint32 msgId, const char* const orig)
: LOWIRequest(msgId)
{
  log_verbose (TAG, "LOWIInternalMessage");
  setRequestOriginator(orig);
}

LOWIInternalMessage::~LOWIInternalMessage()
{
  log_verbose (TAG, "~LOWIInternalMessage");
}

InPostcard* LOWIInternalMessage::createPostcard (LOWIInternalMessage* req)
{
  InPostcard* card = NULL;
  do
  {
    if (NULL == req)
    {
        break;
    }

    OutPostcard* out = OutPostcard::createInstance ();
    if (NULL == out)
    {
      break;
    }

    out->init ();

    const void* blob = (const void*) &req;
    size_t length = sizeof (req);
    out->addString("IMSG", "INTERNAL_MESSAGE");
    out->addBlob ("IMESSAGE", blob, length);
    out->finalize ();

    // Create InPostcard from the OutPostcard
    card = InPostcard::createInstance (out);
    delete out;
  } while (0);
  return card;
}

LOWIInternalMessage* LOWIInternalMessage::parseInternalMessage (InPostcard* card)
{
  LOWIInternalMessage * req = NULL;

  do
  {
    if (NULL == card)
    {
      break;
    }

    const void* blob = NULL;
    size_t length = 0;
    card->getBlob ("IMESSAGE", &blob, &length);
    req =  *(LOWIInternalMessage **) blob;
  } while (0);
  return req;
}

LOWIRequest::eRequestType LOWIInternalMessage::getRequestType () const
{
  return LOWI_INTERNAL_MESSAGE;
}

/////////////////////////////
// LOWIFTMRangeReqMessage
/////////////////////////////
LOWIFTMRangeReqMessage::LOWIFTMRangeReqMessage (uint32 msgId,
                                                vector<LOWIPeriodicNodeInfo> &v,
                                                RadioMeasReqParams & params, const char* const orig)
: LOWIInternalMessage (msgId, orig)
{
  log_verbose (TAG, "LOWIFTMRangeReqMessage");
  mNodeInfo       = v;
  mRangeReqParams = params;
}

LOWIFTMRangeReqMessage::~LOWIFTMRangeReqMessage ()
{
  log_verbose (TAG, "~LOWIFTMRangeReqMessage");
}


const RadioMeasReqParams & LOWIFTMRangeReqMessage::getRadioMeasReqParams() const
{
  return mRangeReqParams;
}

vector <LOWIPeriodicNodeInfo> & LOWIFTMRangeReqMessage::getNodes(){
  return mNodeInfo;
}

LOWIInternalMessage::eLowiInternalMessage
LOWIFTMRangeReqMessage::getInternalMessageType () const
{
  return LOWI_IMSG_FTM_RANGE_REQ;
}

//////////////////////////////////
// LOWIFTMRangeRprtMessage
//////////////////////////////////
LOWIFTMRangeRprtMessage::LOWIFTMRangeRprtMessage(uint32 msgId,
                                                 RadioMeasReqParams & params,
                                                 vector<LOWIRangeEntry> & vR,
                                                 vector<LOWIErrEntry> & vE, const char* const orig)
: LOWIInternalMessage (msgId, orig)
{
  log_verbose (TAG, "LOWIFTMRangeRprtMessage");
  mRangeReqParams = params;
  measInfoSuccess = vR;
  measInfoErr     = vE;
}

/** Destructor*/
LOWIFTMRangeRprtMessage::~LOWIFTMRangeRprtMessage()
{
  log_verbose (TAG, "~LOWIFTMRangeRprtMessage");
}

const RadioMeasReqParams & LOWIFTMRangeRprtMessage::getRadioMeasReqParams() const
{
  return mRangeReqParams;
}

vector<LOWIRangeEntry> & LOWIFTMRangeRprtMessage::getSuccessNodes()
{
  return measInfoSuccess;
}

vector<LOWIErrEntry> & LOWIFTMRangeRprtMessage::getErrNodes()
{
  return measInfoErr;
}

LOWIInternalMessage::eLowiInternalMessage
LOWIFTMRangeRprtMessage::getInternalMessageType () const
{
  return LOWI_IMSG_FTM_RANGE_RPRT;
}

//////////////////////////////////
// LOWIWifiIntfStateMessage
//////////////////////////////////
LOWIWifiIntfStateMessage::LOWIWifiIntfStateMessage(uint32 msgId,
                                                   eWifiIntfState wifiState, const char* const orig)
: LOWIInternalMessage (msgId, orig)
{
  log_verbose (TAG, "LOWIWifiIntfStateMessage %d", wifiState);
  mWifiState = wifiState;
}

/** Destructor*/
LOWIWifiIntfStateMessage::~LOWIWifiIntfStateMessage()
{
  log_verbose (TAG, "~LOWIWifiIntfStateMessage");
}

eWifiIntfState LOWIWifiIntfStateMessage::getIntfState() const
{
  return mWifiState;
}

LOWIInternalMessage::eLowiInternalMessage
LOWIWifiIntfStateMessage::getInternalMessageType () const
{
  return LOWI_IMSG_WIFI_INTF_STATUS_MSG;
}
