/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI DYNAMIC BUFFER class header file

GENERAL DESCRIPTION
  This file contains the interface for a LOWIDynBuffer. A LOWIDynBuffer is a
  dynamically growing byte array.

  Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_DYN_BUFFER_H__
#define __LOWI_DYN_BUFFER_H__

#include <inc/lowi_const.h>

namespace qc_loc_fw
{

/** LOWIDynBuffer Class
 *  This is basically a more flexible growing byte array where multiple
 *  elements can be added at a time. This is particularly useful when dealing
 *  with large stream of bytes.
 */
class LOWIDynBuffer
{
private:
  /** Current capacity of the buffer */
  uint32 mCapacity;
  /** Data length in bytes. Everytime data is added to the buffer
   *  this variable changes to indicate the position in the buffer
   *  where data can be added next. It also doubles as the current
   *  number of elements in the array */
  uint32 mDataLen;
  /** Holds the data */
  uint8 *mData;

  /** Constructor */
  LOWIDynBuffer();

public:
  static char const *const TAG;

  /** Copy Constructor */
  LOWIDynBuffer(const LOWIDynBuffer &rhs);

  /** Assignment operator */
  LOWIDynBuffer& operator=(const LOWIDynBuffer &rhs);

  /** Destructor */
  virtual ~LOWIDynBuffer();

  /**
   * Creates an instance of the LOWIDynBuffer and initializes it.
   * @param data: pointer to data to be stored
   * @param len : length of data to be stored (in bytes)
   * @param capacity: initial capacity of the buffer
   * @return LOWIDynBuffer*: LOWIDynBuffer if success, else NULL
   */
  static LOWIDynBuffer * createInstance(uint8 *data, uint32 len, uint32 capacity);

  /** return the current capacity */
  uint32 getCapacity();

  /** return the current number of elements in the buffer */
  uint32 getNumElems();

  /** returns a ptr to the beginning of the buffer */
  uint8* getData();

  /** Adds data to the dynamic buffer */
  uint32 addData(uint8 *data, uint32 len);
};

} // namespace qc_loc_fw
#endif // __LOWI_DYN_BUFFER_H__
