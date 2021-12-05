/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        Wifi Driver Utilities

GENERAL DESCRIPTION
  This file contains the implementation of utilities for Wifi Driver

Copyright (c) 2012-2013, 2015-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include "lowi_utils_defines.h"
#include <base_util/string_routines.h>
#include <common/lowi_utils.h>
#include "innavService.h"
#include "lowi_wifidriver_utils.h"
#include "wifiscanner.h"

#define RX_BUFF_SIZE  1024
#define MAX_CAPABILITY_REQ_RETRY_COUNT 3
#define CAPABILITY_RETRY_WAIT_TIME_IN_SEC 1

using namespace qc_loc_fw;

// initialization of static variables
const char * const LOWIWifiDriverUtils::TAG                = "LOWIWifiDriverUtils";
char LOWIWifiDriverUtils::wlan_ifname[PROPERTY_VALUE_MAX]  = "";
char LOWIWifiDriverUtils::wigig_ifname[PROPERTY_VALUE_MAX] = "";
int LOWIWifiDriverUtils::ioctlSock = 0;

int* LOWIWifiDriverUtils::getSupportedFreqs (
    LOWIDiscoveryScanRequest::eBand band,
    s_ch_info* p_ch_info,
    unsigned char & num_channels)
{
  if (0 == p_ch_info->num_2g_ch && 0 == p_ch_info->num_5g_ch)
  {
    log_debug (TAG, "getSupportedFreqs - supported channel list not found"
        " using the default");
    return LOWIUtils::getChannelsOrFreqs (band,
                    num_channels, true);
  }
  int * freqs = NULL;
  switch (band)
  {
  case LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ:
  {
    num_channels = p_ch_info->num_2g_ch;
    freqs = new (std::nothrow) int [num_channels];
    if (NULL != freqs)
    {
      for (unsigned char ii = 0; ii < num_channels; ++ii)
      {
        freqs [ii] = p_ch_info->arr_2g_ch [ii];
      }
    }
    break;
  }
  case LOWIDiscoveryScanRequest::FIVE_GHZ:
  {
    num_channels = p_ch_info->num_5g_ch;
    freqs = new (std::nothrow) int [num_channels];
    if (NULL != freqs)
    {
      for (unsigned char ii = 0; ii < num_channels; ++ii)
      {
        freqs [ii] = p_ch_info->arr_5g_ch [ii];
      }
    }
    break;
  }
  default:
    // All
    {
      num_channels = p_ch_info->num_2g_ch + p_ch_info->num_5g_ch;
      freqs = new (std::nothrow) int [num_channels];
      if (NULL != freqs)
      {
        // First copy the 2.4 Ghz freq / channels
        int index = 0;
        for (;index < p_ch_info->num_2g_ch; ++index)
        {
          freqs [index] = p_ch_info->arr_2g_ch [index];
        }
        // Copy the 5 Ghz freq / channels
        for (int ii = 0; ii < p_ch_info->num_5g_ch; ++ii)
        {
          freqs [index+ii] = p_ch_info->arr_5g_ch [ii];
        }
      }
      break;
    }
  }
  return freqs;
}

char * LOWIWifiDriverUtils::get_interface_name()
{
  if (0 == wlan_ifname[0])
  {
#ifdef __ANDROID__
    if (property_get("wifi.interface", wlan_ifname, DEFAULT_WLAN_INTERFACE) != 0)
    {
      log_debug("LOWIWpaInterface", "Using interface '%s'\n", wlan_ifname);
      return wlan_ifname;
    }
#else
    strlcpy(wlan_ifname, DEFAULT_WLAN_INTERFACE, sizeof(wlan_ifname));
#endif
  }
  return wlan_ifname;
}

char* LOWIWifiDriverUtils::get_wigig_interface_name()
{
  if (0 == wigig_ifname[0])
  {
    strlcpy(wigig_ifname, DEFAULT_WIGIG_INTERFACE, sizeof(wigig_ifname));
  }
  return wigig_ifname;
}

eWifiIntfState LOWIWifiDriverUtils::getInterfaceState(char const *intfName)
{
  eWifiIntfState state = INTF_UNKNOWN;

#ifdef LOWI_ON_ACCESS_POINT
  const char* ifr_num[] = { "0", "1", "2" };
#else
  const char* ifr_num[] = { "" };
#endif
  uint32 ifr_count = 0;
  do
  {
    LOWI_BREAK_ON_COND((NULL==intfName), debug, "NULL pointer received")

    if (ioctlSock <= 0) /* Open IOCTL socket if socket not already open or failed to open the last time */
    {
      ioctlSock = socket(AF_INET, SOCK_DGRAM, 0);
      if (ioctlSock < 0)
      {
        log_error(TAG, "%s - Failed to open IOCTL socket", __FUNCTION__);
        break;
      }
    }
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strlcpy(req.ifr_name, intfName, IFNAMSIZ);
    strlcat(req.ifr_name, ifr_num[ifr_count], IFNAMSIZ);
    errno = 0;
    int ret = ioctl(ioctlSock, SIOCGIFFLAGS, &req);
    if (ret < 0)
    {
      log_debug(TAG, "%s - ioctl(GET_IFFLAGS) returned: %d, Errno: %s(%d)",
                __FUNCTION__, ret, strerror(errno), errno);
    }
    else
    {
    log_debug(TAG, "%s: ifname %s, flags 0x%x (%s%s)", __FUNCTION__,
              req.ifr_name, req.ifr_flags,
              (req.ifr_flags & IFF_UP) ? "[UP]" : "",
              (req.ifr_flags & IFF_RUNNING) ? "[RUNNING]" : "" );
    state = (req.ifr_flags & IFF_RUNNING ? INTF_RUNNING :
             (req.ifr_flags & IFF_UP     ? INTF_UP      : INTF_DOWN));
     if ((state == INTF_UP) || (state == INTF_RUNNING))
     {
       break;
     }
    }
  }
  while ((++ifr_count) < LOWI_ARR_SIZE(ifr_num));
  return state;
}
