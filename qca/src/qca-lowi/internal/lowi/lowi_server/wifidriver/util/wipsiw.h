#ifndef __WIPS_IW_H__
#define __WIPS_IW_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        WIPS module - Wifi Scanner Interface for Positioning System

GENERAL DESCRIPTION
  This file contains the declaration and some global constants for WIPS
  module.

  Copyright (c) 2012-2013, 2017-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <stdint.h>

#define MAX_ELEMENTS_2G_ARR 14
#define MAX_ELEMENTS_5G_ARR 56

// Structure to keep the channels supported for discovery scan
// by the kernel.
typedef struct s_ch_info {
  // Num of 2g channels supported
  uint8_t num_2g_ch;
  // array of center frequencies for supported 2g channels
  int arr_2g_ch[MAX_ELEMENTS_2G_ARR];
  // Num of 5g channels supported
  uint8_t num_5g_ch;
  // array of center frequencies for supported 5g channels
  int arr_5g_ch[MAX_ELEMENTS_5G_ARR];
}s_ch_info;

int Wips_nl_shutdown_communication();
int Wips_nl_init_pipe();
int Wips_nl_close_pipe();
int WipsGetSupportedChannels(s_ch_info* p_ch_info);
/*=============================================================================================
 * Function description:
 *   External interface function to initilaizes NL interface for passive scan request.
 *
 * Parameters:
 *   none
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int lowi_gen_nl_drv_open();

/*=============================================================================================
 * Function description:
 *   external interface function to clean up when NL80211 Interface is being closed.
 *
 * Parameters:
 *   none
 *
 * Return value:
 *    none
 =============================================================================================*/
void lowi_gen_nl_drv_close();

/*=============================================================================================
 * Function description:
 *   Check if the Wifi Interface is STA or not and update as necessary
 *   Register with Wi-fi Host driver for events when Fine Timing Measurement Request
 *   frames are received from an AP.
 *
 * Parameters:
 *   bool rangingSupported - Whether ranging is supported or not.
 *
 * Return value:
 *    None
 =============================================================================================*/
void lowi_update_wifi_interface(bool rangingSupported);

#ifdef __cplusplus
extern "C" {
#endif

struct handler_args {
  const char *group;
  int id;
};

/*=============================================================================================
 * Function description:
 *   Callback function with family and group info of the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wips_family_handler(struct nl_msg *msg, void *arg);

/*=============================================================================================
 * Function description:
 *   Callback function with wiphy info of the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wiphy_info_handler(struct nl_msg *msg, void *arg);


/*=============================================================================================
 * Function description:
 *   Parse nested NL attribute to BSS fields
 *
 * Parameters:
 *   nla: Nested NL attributes
 *   bss: Parsed bss fields
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wips_parse_bss(struct nlattr *bss[], struct nlattr *nla);
#ifdef __cplusplus
}
#endif
#endif // __WIPS_IW_H__
