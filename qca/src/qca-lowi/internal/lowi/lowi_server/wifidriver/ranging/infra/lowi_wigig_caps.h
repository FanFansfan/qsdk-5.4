/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        Wigig location capabilities

GENERAL DESCRIPTION
  This file contains definitions and classes implemented to deal with the location
  capabilities of the wigig driver. This file exists purely for the purposes of compiling
  in infra.

  Copyright (c) 2017-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_WIGIG_CAPS_H__
#define __LOWI_WIGIG_CAPS_H__

namespace qc_loc_fw
{

/** Location capabilities from wigig driver. This structure is used in the
 *  handlers to collect the location capabilities from the driver wigig
 *  driver. */
class LOWIWigigLocCaps
{
public:
  /** whether location caps are available */
  bool locCapsAvailable;
  /** location capabilities bitmask */
  uint8 flags;
  /** Maximum number of measurement sessions that can run concurrently */
  uint16 maxSessions;
  /** Maximum destinations allowed in measurement session */
  uint16 maxDest;
  /** Maximum measurements per Burst supported by FW */
  uint8 maxMeasPerBurst;
  /** Maximum burst exponent as specified in 802.11mc */
  uint8  maxBurstExp;
  /** Supported types of AOA measurements */
  uint32 aoaTypesSupported;

  /** Constructor */
  LOWIWigigLocCaps()
  {
    locCapsAvailable  = false;
    flags             = 0;
    maxSessions       = 0;
    maxDest           = 0;
    maxMeasPerBurst   = 0;
    maxBurstExp       = 0;
    aoaTypesSupported = 0;
  }

  /** Destructor */
  ~LOWIWigigLocCaps()
  {
  }

  /** Parses the "flags" bitmask and return whether driver can be FTM
   *  initiator
   * @return bool: false. stub
   */
  bool isInitiator()
  {
    return false;
  }

  /** Parses the "flags" bitmask and return whether driver can be FTM
   *  responder
   * @return bool: false. stub
   */
  bool isResponder()
  {
    return false;
  }

  /**
   * Parses the ASAP capability from bitmask
   * @return bool: false. stub
   */
  bool isAsapCapable()
  {
    return false;
  }

  /**
   * Parses the AoA stand-alone capability from bitmask
   * @return bool: false. stub
   */
  bool isAoACapable()
  {
    return false;
  }

  /**
   * Parses the AoA in FTM session capability from bitmask
   * @return bool: false. stub
   */
  bool isFTMAoACapable()
  {
    return false;
  }

  /**
   * Returns whether the wigig driver supports AoA measurements
   * @return bool: false. stub
   */
  bool isAoASupported()
  {
    return false;
  }

  bool isAoAMeasTopCirPh()
  {
    return false;
  }

  bool isAoAMeasTopCirPhAmp()
  {
    return false;
  }

  /**
   * Prints the class fields
   * @param TAG: log tag of caller
   */
  void PrintLocationCaps(const char *const /* TAG */)
  {
  }
};

} // namespace qc_loc_fw
#endif // __LOWI_WIGIG_CAPS_H__
