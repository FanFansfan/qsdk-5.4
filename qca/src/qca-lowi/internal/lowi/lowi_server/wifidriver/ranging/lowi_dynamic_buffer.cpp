/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Dynamic Buffer class implementation

GENERAL DESCRIPTION
  This file contains the implementation for the LOWIDynBuffer class

  Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc
=============================================================================*/
#include <base_util/log.h>
#include <string.h>
#include "lowi_dynamic_buffer.h"

using namespace qc_loc_fw;

#define LOWI_DYNBUFF_BREAK_IF_NULL(p,s) if (NULL == p) \
  {                                                    \
    log_warning(TAG, "%s: %s", __FUNCTION__, s);       \
    break;                                             \
  }

const char * const LOWIDynBuffer::TAG = "LOWIDynBuffer";
uint32 const DEFAULT_CAPACITY = 1024;
uint32 const MULTIPLE_RESIZE_INCREMENT = 2;

// log prints needed for debugging buffer functionality
#undef ADDITIONAL_LOWIDYNBUFFER_DBG
#ifdef ADDITIONAL_LOWIDYNBUFFER_DBG
#define EXISTING_BUFFER_DBG() log_verbose(TAG, "%s: Existing buffer: mCapacity(%u) mDataLen(%u)\n", \
                                          __FUNCTION__, mCapacity, mDataLen);
#define ADDED_DATA_DBG() log_verbose(TAG, "%s: added %u bytes to existing buffer\n", \
                                     __FUNCTION__, len);
#define GROWING_BUFFER_DBG() log_verbose(TAG, "%s: Growing buffer: new mCapacity(%u)\n", \
                                         __FUNCTION__, mCapacity);
#else
#define EXISTING_BUFFER_DBG()
#define ADDED_DATA_DBG()
#define GROWING_BUFFER_DBG()
#endif

LOWIDynBuffer * LOWIDynBuffer::createInstance(uint8 *data, uint32 len, uint32 capacity)
{
  LOWIDynBuffer *dynBuff = NULL;
  uint32 initialCap = 0;
  do
  {
    dynBuff = new(std::nothrow) LOWIDynBuffer();
    LOWI_DYNBUFF_BREAK_IF_NULL(dynBuff, "mem alloc failure");

    // The initial capacity of the buffer will depend on the capacity and len passed
    // in by the user. All combinations of capacity and len are addressed below.
    if (0 == capacity && 0 != len)
    {
      initialCap = len * MULTIPLE_RESIZE_INCREMENT;
    }
    else if (0 == capacity && 0 == len)
    {
      initialCap = DEFAULT_CAPACITY;
    }
    else if (0 != capacity && 0 == len)
    {
      initialCap = capacity;
    }
    else if(0 != capacity && 0 != len)
    {
      initialCap = (capacity > len) ? capacity : len * MULTIPLE_RESIZE_INCREMENT;
    }

    dynBuff->mData = new(std::nothrow) uint8[initialCap];
    LOWI_DYNBUFF_BREAK_IF_NULL(dynBuff->mData, "mem alloc failure");

    dynBuff->mCapacity = initialCap;
    dynBuff->mDataLen  = len;
    // copy data over
    if (NULL != data)
    {
      memcpy(dynBuff->mData, data, len);
    }
    log_verbose(TAG, "%s: created buffer: mCapacity(%u) mDataLen(%u)\n", __FUNCTION__,
                dynBuff->mCapacity, dynBuff->mDataLen);
  } while (0);

  return dynBuff;
}

LOWIDynBuffer::LOWIDynBuffer()
{
  log_verbose (TAG, "LOWIDynBuffer()");
}

LOWIDynBuffer::LOWIDynBuffer(const LOWIDynBuffer &rhs)
{
    (void) operator=(rhs);
}

LOWIDynBuffer& LOWIDynBuffer::operator=(LOWIDynBuffer const &rhs)
{
  do
  {
    if (this != &rhs)
    {
      uint8 *temp = new(std::nothrow) uint8[rhs.mCapacity];
      LOWI_DYNBUFF_BREAK_IF_NULL(temp, "mem alloc failure");

      mCapacity = rhs.mCapacity;
      mDataLen  = rhs.mDataLen;

      delete[] mData;
      mData = temp;
      memcpy(mData, rhs.mData, rhs.mDataLen);
    }
  } while (0);

  return *this;
}

LOWIDynBuffer::~LOWIDynBuffer()
{
  if (NULL != mData)
  {
    delete[] mData;
    mData = NULL;
  }
}

uint32 LOWIDynBuffer::getCapacity()
{
  return mCapacity;
}

uint32 LOWIDynBuffer::getNumElems()
{
  return mDataLen;
}

uint8* LOWIDynBuffer::getData()
{
  return mData;
}

uint32 LOWIDynBuffer::addData(uint8 *data, uint32 len)
{
  uint32 retVal = -1;
  do
  {
    LOWI_DYNBUFF_BREAK_IF_NULL(data, "data to be added was null");
    EXISTING_BUFFER_DBG()

    if (0 == len)
    {
      log_debug(TAG, "%s: input param...zero length\n", __FUNCTION__);
      break;
    }

    // check current buffer capacity
    if (mCapacity >= mDataLen + len)
    {
      // can add the data without growing the buffer
      memcpy(&mData[mDataLen], data, len);
      ADDED_DATA_DBG()
    }
    else
    {
      // grow the buffer to add the data
      mCapacity = (mDataLen + len) * MULTIPLE_RESIZE_INCREMENT;
      uint8 *tmp = new(std::nothrow) uint8[mCapacity];
      LOWI_DYNBUFF_BREAK_IF_NULL(tmp, "mem alloc failure");
      GROWING_BUFFER_DBG()

      // copy the data from the old buffer first
      memcpy(tmp, mData, mDataLen);
      // then add the new data
      memcpy(&tmp[mDataLen], data, len);

      // release the old buffer and point to the new buffer
      delete[] mData;
      mData = tmp;
    }
    mDataLen += len;
    log_verbose(TAG, "%s: Resulting buffer: mCapacity(%u) mDataLen(%u)\n", __FUNCTION__,
                mCapacity, mDataLen);

    retVal = 0;
  } while (0);

  return retVal;
}



