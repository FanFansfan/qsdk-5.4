/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Scan Result Receiver

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Scan Result Receiver

  Copyright (c) 2012-2013, 2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <unistd.h>
#include "lowi_server/lowi_scan_result_receiver.h"
#include "lowi_server/lowi_wifidriver_interface.h"
#include "lowi_server/lowi_strings.h"

using namespace qc_loc_fw;

const char * const LOWIScanResultReceiver::TAG = "LOWIScanResultReceiver";

LOWIScanResultReceiver::LOWIScanResultReceiver
(
    LOWIScanResultReceiverListener* listener,
    LOWIWifiDriverInterface* interface
)
: mListener (listener), mWifiDriver (interface), mRequest (NULL),
  mReceiverThread (NULL), mMutex (NULL)
{
  log_verbose (TAG, "LOWIScanResultReceiver");
  mMutex = Mutex::createInstance("LOWIScanResultReceiver",false);
  if(0 == mMutex)
  {
    log_error(TAG, "Could not create mutex!");
  }
  mThreadAboutToBlock = false;
  mThreadTerminateRequested = false;
  mNewRequestArrived = false;
}

LOWIScanResultReceiver::~LOWIScanResultReceiver ()
{
  log_verbose (TAG, "~LOWIScanResultReceiver");
  if (mReceiverThread != NULL)
  {
    terminate ();
  }
  delete mMutex;
  delete mReceiverThread;
}

bool LOWIScanResultReceiver::init ()
{
  bool retVal = true;
  // If the thread is not already running start it.
  if (NULL == mReceiverThread)
  {
    // Re-start the Receiver thread. No need to delete the runnable
    // at destruction.
    mReceiverThread = Thread::createInstance(TAG, this, false);
    if (mReceiverThread == NULL)
    {
      log_warning (TAG, "%s: Unable to create receiver"
          " thread instance", __FUNCTION__);
      retVal = false;
    }
    else
    {
      int ret = mReceiverThread->launch ();
      log_verbose (TAG, "%s: Launch thread returned = %d", __FUNCTION__, ret);
      if (0 != ret)
      {
        retVal = false;
      }
    }
  }
  return retVal;
}

bool LOWIScanResultReceiver::execute (LOWIRequest* request)
{
  bool retVal = true;
  log_verbose(TAG, "%s request " LOWI_REQINFO_FMT, __FUNCTION__,
              LOWI_REQINFO(request));
  {
    AutoLock autolock(mMutex);
    mRequest = request;
    mWifiDriver->setNewRequest(request, mListenMode);
    mNewRequestArrived = true;
  }

  // unblock the thread
  if (mReceiverThread != NULL)
  {
    retVal = unblockThread ();
  }
  return retVal;
}

bool LOWIScanResultReceiver::unblockThread ()
{
  bool retVal = true;
  log_verbose (TAG, "%s", __FUNCTION__);
  bool thread_running = false;

  {
    AutoLock autolock(mMutex);
    thread_running = mThreadAboutToBlock;
  }

  if (true == thread_running)
  {
    if (mWifiDriver->unBlock (mListenMode) <= 0)
    {
      log_error (TAG, "%s: shutdown failed", __FUNCTION__);
      retVal = false;
    }
    else
    {
      log_verbose (TAG, "%s: success", __FUNCTION__);
    }
  }

  return retVal;
}

bool LOWIScanResultReceiver::terminate ()
{
  bool retVal = false;
  log_verbose (TAG, "%s", __FUNCTION__);
  bool thread_running = false;

  {
    AutoLock autolock(mMutex);
    thread_running = mThreadAboutToBlock;
    // Thread is not running
    mThreadTerminateRequested = true;
    if (false == thread_running)
    {
      retVal = true;
    }
  }

  if (true == thread_running)
  {
    if (mWifiDriver && mWifiDriver->terminate (mListenMode) <= 0)
    {
      log_error (TAG, "%s: shutdown failed", __FUNCTION__);
    }
    else
    {
      log_verbose (TAG, "%s: success", __FUNCTION__);
      retVal = true;
    }
  }

  log_verbose (TAG, "%s: About to join, thread %s", __FUNCTION__,
               thread_running ? "RUNNING" : "STOPPED");
  mReceiverThread->join ();
  log_debug (TAG, "After join complete");

  {
    AutoLock autolock(mMutex);
    mThreadTerminateRequested = false;
  }
  return retVal;
}

void LOWIScanResultReceiver::run ()
{
  log_verbose (TAG, "%s", __FUNCTION__);
  LOWIRequest* req = NULL;

  // Initialize the file descriptor.
  // This is required to initialize the communication
  // pipe between this thread and the main thread so that the
  // main thread could unblock this thread at any point
  // by writing to the file descriptor after this thread
  // is blocked listening to the events from wifi driver and
  // the file descriptor.
  mWifiDriver->initFileDescriptor (mListenMode);
  do
  {
    {
      AutoLock autolock(mMutex);
      if (true == mThreadTerminateRequested)
      {
        log_info (TAG, "Thread terminate was requested");
        break;
      }
      mThreadAboutToBlock = true;

      // Check if a new request has arrived
      if (true == mNewRequestArrived)
      {
        req = mRequest;
        log_debug (TAG, "%s:Execute new request " LOWI_REQINFO_FMT,
                   __FUNCTION__, LOWI_REQINFO(req));
        mNewRequestArrived = false;
      }
      else
      {
        req = NULL;
        log_debug (TAG, "Enter passive listening mode");
      }
    }
    // This is a blocking call and waits on measurements.
    LOWIMeasurementResult* result = mWifiDriver->block(req, mListenMode);

    {
      AutoLock autolock(mMutex);
      mThreadAboutToBlock = false;
    }

    if (NULL != result)
    {
      // No need to send call back to the listener when no measurements.
      // This might be the case that the passive
      // scanning mode was terminated by LOWIController or there was
      // mem allocation failure.
      // Report the results to the Listener only when results are there.
      if (NULL != mListener)
      {
        log_debug (TAG, "Send scan meas to listener");
        mListener->scanResultsReceived (result);
      }
      else
      {
        log_warning (TAG, "No listener. Unexpected!");
      }
    }
  } while (1);
  // Close the communication pipe created by this thread.
  mWifiDriver->closeFileDescriptor(mListenMode);
}
