/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

   WiFi Scanner with NL80211 Interface

   GENERAL DESCRIPTION
   This component performs passive scan with NL80211 Interface.

   Copyright (c) 2012-2013, 2016-2019 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.

   (c) 2012-2013 Qualcomm Atheros, Inc.
   All Rights Reserved.
   Qualcomm Atheros Confidential and Proprietary.

   Copyright (c) 2007, 2008        Johannes Berg
   Copyright (c) 2007              Andy Lutomirski
   Copyright (c) 2007              Mike Kershaw
   Copyright (c) 2008-2009         Luis R. Rodriguez

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

* Driver interaction with Linux nl80211/cfg80211
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
=============================================================================*/

#define LOG_NDEBUG 0

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <net/if.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include "inc/lowi_const.h"
#include <base_util/time_routines.h>
#include <lowi_server/lowi_log.h>
#include "innavService.h"                           //  structure definitions and such
#include "wlan_location_defs.h"

#include "lowi_time.h"
#include "wipsiw.h"
#include "common/lowi_utils.h"
#include "lowi_wifidriver_utils.h"
#include "lowi_internal_const.h"
#include "lowi_ranging.h"
#include "qca-vendor.h"


using namespace qc_loc_fw;
int net_admin_capable = 0;

#undef LOG_TAG
#define LOG_TAG "LOWI-Scan"

#define WLAN_FC_TYPE_MGMT 0
#define WLAN_FC_STYPE_ACTION 13
#define LOWI_FRAME_MATCH_LEN 2

#define IEEE80211_FRAME_CTRL(type, stype) ((type << 2) | (stype << 4))

// In number of milli-seconds. If AP age exceeds this limit,
// it will not be adjusted for NL 3 seconds buffering
#define AP_AGE_ADJUST_UPPER_LIMIT 10000

// Time to wait when NL init fails before returning back
#define WIPS_WAIT_NL_FAIL  5

#undef WIPSIW_ENABLE_ENTER_EXIT
#ifdef WIPSIW_ENABLE_ENTER_EXIT
#define WIPSIW_ENTER LOWI_LOG_VERB( "WIPSIW_ENTER: %s\n",__FUNCTION__);
#define WIPSIW_EXIT  LOWI_LOG_VERB( "WIPSIW_EXIT : %s\n",__FUNCTION__);
#else
#define WIPSIW_ENTER
#define WIPSIW_EXIT
#endif

/* QCA OUI in vendor commands */
#define LOWI_OUI_QCA 0x001374

/* Vendor scan commands */
#define LOWI_QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN 106
#define LOWI_QCA_NL80211_VENDOR_SUBCMD_SCAN_DONE    107
#define NSEC_PER_MSEC 1000000
/* This enumeration lists the varios preamble + BW combos */
struct LOWIPreBwCombo
{
  uint32 lowi_HT20     :1;
  uint32 lowi_HT40     :1;
  uint32 lowi_VHT20    :1;
  uint32 lowi_VHT40    :1;
  uint32 lowi_VHT80    :1;
  uint32 lowi_VHT160   :1;
  uint32 lowi_VHT80P80 :1;

  LOWIPreBwCombo()
  {
    lowi_HT20 = 0;
    lowi_HT40 = 0;
    lowi_VHT20 = 0;
    lowi_VHT40 = 0;
    lowi_VHT80 = 0;
    lowi_VHT160 = 0;
    lowi_VHT80P80 = 0;
  }
};

WlanFrameStore wlanFrameStore;

struct nl80211_state {
        struct nl_sock *nl_sock;
        struct genl_family * nl80211_family_ptr;
        struct nl_cache * nl_cache;
        unsigned int nl80211_id;
        uint32 idx;
        struct nl_cb *s_cb;
        bool nlInitialized;
        bool ftmrr_registered;
        enum nl80211_iftype iftype;
        nl80211_state()
        {
          nl_sock            = NULL;
          nl80211_family_ptr = NULL;
          nl_cache           = NULL;
          nl80211_id         = 0;
          idx                = 0;
          s_cb               = NULL;
          nlInitialized      = false;
          ftmrr_registered   = false;
          iftype             = NL80211_IFTYPE_UNSPECIFIED;
        }
};

struct s_wait_event {
        int n_cmds;
        const __u32 *cmds;
        __u32 cmd;
        void *pargs;
};
static struct nl80211_state nlstate; //Used throughout the code..

static int      pipe_fd[2] = {0,0};                  // Pipe used to terminate select in Discovery thread
extern bool lowi_insert_record(void * results_buf_ptr,
                               int32  bss_age_msec,
                               LOWIScanMeasurement* p_ap_scan_res);
extern void lowi_close_record(void * results_buf_ptr);
extern void lowi_reset_records(void * results_buf_ptr);

extern uint64 wipsiw_scan_req_time;

#define AP_AGE_UNSPECIFIED_IN_MSECS -1

static int num_acks_for_dump = 0;
static int num_finishes_for_dump = 0;
static int genl_integrity_check_fail = FALSE;

static bool parseFullBeacon = false;

// This data structure is used to filter out those APs
// that are not seen by RIVA driver layer, but is buffered by
// NL layer. NL layer will report them up to 3 seconds
// without properly populating the age info
typedef struct
{
  unsigned char bssid[ETH_ALEN];
  uint64        bss_tsf_usec;
  uint32        bss_age_msec;
  uint64        bss_meas_recv_msec;
} wips_nl_ap_info;

// Allocate AP three times as much as the maximum used in upper layer.
// As the upper layer will filter out APs based on age
// which will reduce the number of APs outputted from
// this module
//
// It uses two list of APs:
// The current list saves the APs from the previous discovery scan
// The new list saves the APs from the on-going discovery scan.
// And right before a fresh passive scan is issued, the data
// in the new list is saved into current list, and the new list
// will be used to save the APs coming from the on-going discovery scan.
typedef struct
{
  wips_nl_ap_info current_list[3*NUM_MAX_BSSIDS];
  wips_nl_ap_info new_list[3*NUM_MAX_BSSIDS];
  uint32          num_ap_current;
  uint32          num_ap_new;
} wips_nl_ap_list;

// Memory is zero initialized
static wips_nl_ap_list wips_nl_ap_store;

static enum nl80211_iftype get_intf_mode(struct nl80211_state *pstate);
static int lowi_add_nl80211_membership(struct nl_sock *sock, const char *group);

static struct nl_msg * Wips_nl_msg_alloc(struct nl80211_state * pstate,
                                         enum nl80211_commands cmd, int flags)
{
  struct nl_msg *msg = NULL;

  if ((cmd > NL80211_CMD_MAX) || (NULL == pstate))
  {
    LOWI_LOG_INFO("%s: Bad params state %p, cmd %d", __FUNCTION__,
                  pstate, cmd);
    return NULL;
  }
  msg = nlmsg_alloc();
  if (NULL == msg)
  {
    return NULL;
  }
  genlmsg_put(msg, 0, 0, pstate->nl80211_id, 0, flags, cmd, 0);
  pstate->idx = if_nametoindex(LOWIWifiDriverUtils::get_interface_name());
  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, pstate->idx);

  return msg;

nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return msg;
}

/*=============================================================================================
 * Function description:
 *   Called by external entity to terminate the blocking of this thread on select call
 *   by means of writing to a pipe. Thread is blocked on socket and a pipe in select call
 *
 * Parameters:
 *   None
 *
 * Return value:
 *    num of bytes written, -1 for error, 0 for no bytes written
 =============================================================================================*/
int Wips_nl_shutdown_communication(void)
{
  int retVal = -1;
  char string [] = "Close";
  if (0 != pipe_fd [1])
  {
    retVal = write(pipe_fd[1], string, (strlen(string)+1));
  }

  return retVal;
}

/*=============================================================================================
 * Function description:
 *   Called by external entity to create the pipe
 *
 * Parameters:
 *   None
 *
 * Return value:
 *    0 Success, other values otherwise
 =============================================================================================*/
int Wips_nl_init_pipe(void)
{
  LOWI_LOG_DBG( "Creating the pipe\n");
  return pipe(pipe_fd);
}

/*=============================================================================================
 * Function description:
 *   Called by external entity to close the pipe
 *
 * Parameters:
 *   None
 *
 * Return value:
 *    0 Success, other values otherwise
 =============================================================================================*/
int Wips_nl_close_pipe(void)
{
  LOWI_LOG_DBG( "Closing the pipe\n");
  if (pipe_fd[0] > 0)
  {
    close (pipe_fd[0]);
    pipe_fd [0] = 0;
  }

  if (pipe_fd[1] > 0)
  {
    close (pipe_fd[1]);
    pipe_fd [1] = 0;
  }
  return 0;
}

/*=============================================================================================
 * Function description:
 *   The cleanup function when passive scan has been performed with NL80211 Interface.
 *
 * Parameters:
 *   state: pointer to the data structure for NL80211 state
 *
 * Return value:
 *    error code: NL_OK
 =============================================================================================*/
static void nl80211_cleanup(struct nl80211_state *state)
{
  nl_socket_free(state->nl_sock);
  nl_cb_put (state->s_cb);
  if (state->nl_cache)
  {
    nl_cache_free(state->nl_cache);
  }
  if (state->nl80211_id)
  {
    genl_family_put(state->nl80211_family_ptr);
  }
  state->nlInitialized = false;
}

/*=============================================================================================
 * Function description:
 *   Callback function with Interface mode of the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int get_intf_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  enum nl80211_iftype *iftype = (enum nl80211_iftype *)arg;

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (tb[NL80211_ATTR_IFTYPE])
  {
    *iftype = (enum nl80211_iftype)nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
  }

  return NL_SKIP;
}
/*=============================================================================================
 * Function description:
 *   Initilaize NL interface for passive scan request.
 *
 * Parameters:
 *   pstate: pointer to the data structure for NL80211 state
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int nl80211_init(struct nl80211_state *state)
{
  int err;

  if (state->nlInitialized)
  {
    return 0;
  }

  memset(state, 0, sizeof(struct nl80211_state));
  state->iftype = NL80211_IFTYPE_STATION; // Default interface type is STA

  state->nlInitialized = false;
  state->s_cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!state->s_cb)
  {
    LOWI_LOG_ERROR ("%s: Failed to allocate memory\n", __FUNCTION__);
    err = -ENOMEM;
    goto out_handle_destroy;
  }

  state->nl_sock = nl_socket_alloc_cb(state->s_cb);
  if (!state->nl_sock)
  {
    LOWI_LOG_ERROR ( "%s: Failed to allocate netlink socket.\n", __FUNCTION__);
    err = -ENOMEM;
    goto out_handle_destroy;
  }

  if (genl_connect(state->nl_sock))
  {
    LOWI_LOG_ERROR ( "%s: connect generic netlink - Failed\n", __FUNCTION__);
    err = -ENOLINK;
    goto out_handle_destroy;
  }

  if (genl_ctrl_alloc_cache(state->nl_sock, &(state->nl_cache)))
  {
    LOWI_LOG_ERROR ("%s: Error in Allocating Cache\n", __FUNCTION__);
    err = -ENOMEM;
    goto out_handle_destroy;
  }
  state->nl80211_family_ptr = genl_ctrl_search_by_name(state->nl_cache,"nl80211");

  if(!state->nl80211_family_ptr)
  {
      LOWI_LOG_ERROR ( "%s:get n180211 family - Failed\n", __FUNCTION__);
      err = -ENOMEM;
      goto out_handle_destroy;
  }

  state->nl80211_id = genl_family_get_id(state->nl80211_family_ptr);

  if (state->nl80211_id == 0)
  {
    LOWI_LOG_ERROR ( "%s: nl80211 id not found.\n", __FUNCTION__);
    err = -ENOENT;
    goto out_handle_destroy;
  }

  if ((lowi_add_nl80211_membership(state->nl_sock, "scan") != 0) ||
      (lowi_add_nl80211_membership(state->nl_sock, "vendor") != 0))
  {
    LOWI_LOG_ERROR ( "%s: nl80211 add membership failed\n", __FUNCTION__);
    err = -EBADF;
    goto out_handle_destroy;
  }
  state->nlInitialized = true;
  LOWI_LOG_DBG ("%s:SUCCESS\n", __FUNCTION__);
  return 0;

out_handle_destroy:
  nl80211_cleanup(state);
  return err;
}

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
int lowi_gen_nl_drv_open()
{
  return nl80211_init(&nlstate);
}

/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_CUSTOM with operations on NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int dump_error_handler(struct sockaddr_nl* /*nla*/, struct nlmsgerr *err,
                         void *arg)
{
  //Something wrong with socket??
  int *ret = (int *)arg;
  *ret = err->error;
  LOWI_LOG_DBG("%s:called with error %d . SKIP!!", __FUNCTION__, *ret);
  return NL_SKIP;
}

/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_FINISH with operations on the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int dump_finish_handler(struct nl_msg *msg, void *arg)
{
  int *ret = (int *)arg;
  struct nlmsghdr *nlh;

  *ret = 1;
  nlh = (struct nlmsghdr *)nlmsg_hdr(msg);
  LOWI_LOG_VERB("%s:Length %d Type %d Flags %d Seq %d Sender pid %d", __FUNCTION__,
  (int)(nlh->nlmsg_len), (int)(nlh->nlmsg_type), (int)(nlh->nlmsg_flags),
  (int)(nlh->nlmsg_seq), (int)(nlh->nlmsg_pid));

  num_finishes_for_dump++;

  if (nlh->nlmsg_type == 3)
  {
    *ret = 0;
    return NL_STOP;
  }

  return NL_SKIP;
}


/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_CUSTOM with operations on the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int dump_ack_handler(struct nl_msg *msg, void *arg)
{
  int *ret = (int *)arg;
  struct nlmsghdr *nlh;
  nlh = (struct nlmsghdr *)nlmsg_hdr(msg);
  *ret = 0;
  LOWI_LOG_DBG("%s:Length %d Type %d Flags %d Seq %d Sender %d", __FUNCTION__,
  nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags,
  nlh->nlmsg_seq, nlh->nlmsg_pid);

  num_acks_for_dump++;
  return NL_STOP;
}
/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_CUSTOM with operations on NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int error_handler(struct sockaddr_nl */* nla */, struct nlmsgerr *err,
                         void *arg)
{
  //Something wrong with socket??
  int *ret = (int *)arg;
  *ret = err->error;
  return NL_STOP;
}

/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_FINISH with operations on the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int finish_handler(struct nl_msg */* msg */, void *arg)
{
  int *ret = (int *)arg;
  *ret = 0;
  return NL_SKIP;
}


/*=============================================================================================
 * Function description:
 *   Callback function for NL_CB_CUSTOM with operations on the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
static int ack_handler(struct nl_msg */* msg */, void *arg)
{
  LOWI_LOG_VERB("%s", __FUNCTION__);
  int *ret = (int *)arg;
  *ret = 0;
  return NL_STOP;
}

/*=============================================================================================
 * Function description:
 *   This function gets the Interface mode of the NL80211 Interface.
 *
 * Parameters:
 *   pstate: pointer to the data structure for NL80211 state
 *
 * Return value:
 *    nl80211_iftype: NL80211_IFTYPE_UNSPECIFIED if error, else the
 *                    interface type returned by the driver
 =============================================================================================*/
static enum nl80211_iftype get_intf_mode(struct nl80211_state *pstate)
{
  struct nl_cb * cb;
  enum nl80211_iftype iftype = NL80211_IFTYPE_UNSPECIFIED;
  struct nl_msg * msg = Wips_nl_msg_alloc(pstate, NL80211_CMD_GET_INTERFACE, 0);
  int err;

  if (!msg)
  {
    LOWI_LOG_INFO("%s: Failed to allocate netlink message", __FUNCTION__);
    return iftype;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb)
  {
    LOWI_LOG_INFO("%s: Failed to allocate netlink callbacks", __FUNCTION__);
    goto out_free_msg;
  }
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_intf_handler, &iftype);
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  err = nl_send_auto_complete(nlstate.nl_sock, msg);
  if (err < 0)
  {
    LOWI_LOG_INFO("%s: Failed to send GET_INTERFACE request", __FUNCTION__);
    goto nla_put_failure;
  }

  err = 1;
  while (err > 0)
  {
    nl_recvmsgs(nlstate.nl_sock, cb);
  }

  LOWI_LOG_INFO("%s: WLAN interface type %d, err %d", __FUNCTION__, iftype, err);
  if ((iftype > NL80211_IFTYPE_UNSPECIFIED) &&
      (iftype < NUM_NL80211_IFTYPES))
  {
    nlstate.iftype = iftype;
  }
nla_put_failure:
  nl_cb_put(cb); //Free the CB.
out_free_msg:
  nlmsg_free(msg); //Free the allocated Message

  return iftype;
}

/*=============================================================================================
 * Function description:
 *   This function gets the multicase ID with NL80211 Interface.
 *
 * Parameters:
 *   sock: pointer to the NL socket
 *   family: pointer to the family information
 *   group: pointer to the group information
 *
 * Return value:
 *    error code: NL_OK
 =============================================================================================*/
int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group)
{
  struct nl_msg *msg;
  struct nl_cb *cb;
  int ret, ctrlid;
  struct handler_args grp;

  grp.group = group;
  grp.id = -ENOENT,

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    ret = -ENOMEM;
    goto out_fail_cb;
  }

  ctrlid = genl_ctrl_resolve(sock, "nlctrl");

  genlmsg_put(msg, 0, 0, ctrlid, 0,
              0, CTRL_CMD_GETFAMILY, 0);

  ret = -ENOBUFS;
  NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

  ret = nl_send_auto_complete(sock, msg);
  if (ret < 0)
    goto out;

  ret = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wips_family_handler, &grp);

  // Not an infinite loop
  while (ret > 0)
    nl_recvmsgs(sock, cb);

  if (ret == 0)
    ret = grp.id;

nla_put_failure:
out:
  nl_cb_put(cb);
out_fail_cb:
  nlmsg_free(msg);
  return ret;
}

/*=============================================================================================
 * Function description:
 *   This function gets the wiphy info with NL80211 Interface.
 *
 * Parameters:
 *   sock: pointer to the NL socket
 *
 * Return value:
 *    error code: NL_OK
 =============================================================================================*/
int nl_get_wiphy_info(struct nl_sock *sock, s_ch_info* ch_info)
{
  struct nl_msg *msg;
  struct nl_cb *cb;
  int ret = 0;

  if (NULL == ch_info || NULL == sock)
  {
    LOWI_LOG_ERROR ( "nl_get_wiphy_info, invalid argument, NULL pointer");
    return -1;
  }

  msg = Wips_nl_msg_alloc(&nlstate, NL80211_CMD_GET_WIPHY, NLM_F_DUMP);
  if (!msg)
    return -ENOMEM;

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    ret = -ENOMEM;
    goto out_fail_cb;
  }

  ret = -ENOBUFS;

  ret = nl_send_auto_complete(sock, msg);
  if (ret < 0)
    goto out;

  ret = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wiphy_info_handler, ch_info);

  // Not an infinite loop
  while (ret > 0)
  {
    nl_recvmsgs(sock, cb);
  }
  LOWI_LOG_DBG ( "nl_get_wiphy_info, done err = %d", ret);
out:
  nl_cb_put(cb);
out_fail_cb:
  nlmsg_free(msg);
  return ret;
}

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
void lowi_gen_nl_drv_close()
{
  nl80211_cleanup(&nlstate);
}

/*=============================================================================================
 * Function description:
 *   The callback function for NL_CB_SEQ_CHECK option using NL80211 Interface.
 *
 * Parameters:
 *   nl_msg: pointer to the result message from NL80211 message
 *   arg: the passed argument via nc_cb_set
 *
 * Return value:
 *    error code: NL_OK
 =============================================================================================*/
static int no_seq_check(struct nl_msg* /*msg*/, void* /*arg*/)
{
  return NL_OK;
}

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
void lowi_update_wifi_interface(bool rangingSupported)
{
  struct nl_msg * msg = NULL;
  struct nl_cb * cb = NULL;
  do
  {
    if (FALSE == nlstate.nlInitialized)
    {
      LOWI_LOG_DBG("%s: NL not initialized %d",
                   __FUNCTION__, nlstate.nlInitialized);
      break;
    }
    if (TRUE  == nlstate.ftmrr_registered)
    {
      LOWI_LOG_DBG("%s: FTMRR Already registered", __FUNCTION__);
      break;
    }
    if (get_intf_mode(&nlstate) != NL80211_IFTYPE_STATION)
    {
      LOWI_LOG_DBG ("%s: Skip FTMRR - not STA interface", __FUNCTION__);
      break;
    }
    if (!rangingSupported)
    {
      LOWI_LOG_DBG ("%s: Skip FTMRR - Ranging not supported", __FUNCTION__);
      break;
    }
    LOWI_LOG_VERB("%s: Register for FTMRR", __FUNCTION__);
    int err = 0;

    msg = Wips_nl_msg_alloc(&nlstate, NL80211_CMD_REGISTER_ACTION, 0);
    if (!msg)
    {
      LOWI_LOG_INFO("%s: Failed to allocate netlink message", __FUNCTION__);
      break;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
    {
      LOWI_LOG_INFO("%s: Failed to allocate netlink callbacks", __FUNCTION__);
      break;
    }

    uint16 type = (WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_ACTION << 4);
    const uint8 lowi_ftmrr_frame_match[LOWI_FRAME_MATCH_LEN] = {5,0};
    NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
    NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, LOWI_FRAME_MATCH_LEN, lowi_ftmrr_frame_match);

    err = nl_send_auto_complete(nlstate.nl_sock, msg);
    if (err < 0)
    {
      break;
    }

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    // NOTE: Not an infinite loop
    while (err > 0)
      nl_recvmsgs(nlstate.nl_sock, cb);

    LOWI_LOG_DBG ("%s: the err is: %d\n", __FUNCTION__, err);
    nlstate.ftmrr_registered = (err == 0);
  }
  while (0);

nla_put_failure:
  if (cb)
  {
    nl_cb_put(cb);
  }
  if (msg)
  {
    nlmsg_free(msg);
  }
  return;
}

/*=============================================================================================
 * Function description:
 *   Function to add membership for NL80211 socket
 *
 * Parameters:
 *   sock: pointer to the NL socket
 *   group: pointer to the group information
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
static int lowi_add_nl80211_membership(struct nl_sock *sock, const char *group)
{
  int mcid;
  int ret = -1;
  WIPSIW_ENTER
  /* Scan multicast group */
  mcid = nl_get_multicast_id(sock, "nl80211", group);
  if (mcid >= 0)
  {
    ret = nl_socket_add_membership(sock, mcid);
  }
  WIPSIW_EXIT
  return ret;
}

/*=============================================================================================
 * Function description:
 *   Callback function to nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wait_event, &wait_ev)
 *
 * Parameters:
 *   nl_msg: pointer to the result message from NL80211 message
 *   arg: the passed argument via nc_cb_set
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
static int parse_action_frame(struct nl_msg *msg, void * /* arg */)
{
  struct genlmsghdr *genlHdr = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *attrs[NL80211_ATTR_MAX + 1];
  tANI_U32 freq = 0;

  LOWI_LOG_DBG("%s - wlanFrameStore.numFrames: %u", __FUNCTION__, wlanFrameStore.numFrames);
  nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(genlHdr, 0),
            genlmsg_attrlen(genlHdr, 0), NULL);

  if (!attrs[NL80211_ATTR_WIPHY_FREQ])
  {
    LOWI_LOG_DBG("%s: No Source MAC address", __FUNCTION__);
  }
  else
  {
    freq = nla_get_u32(attrs[NL80211_ATTR_WIPHY_FREQ]);
  }
  if (!attrs[NL80211_ATTR_FRAME])
  {
    LOWI_LOG_DBG("%s: No Frame body", __FUNCTION__);
    return -1;
  }

  WlanFrame *wlanFrame = &wlanFrameStore.wlanFrames[wlanFrameStore.numFrames];
  wlanFrame->frameLen = nla_len(attrs[NL80211_ATTR_FRAME]);
  memcpy(wlanFrame->frameBody, nla_data(attrs[NL80211_ATTR_FRAME]), wlanFrame->frameLen);
  wlanFrame->freq = freq;
  wlanFrameStore.numFrames++;

  LOWI_LOG_DBG("%s: Frame received - frame length %u, Total Frames received: %u",
               __FUNCTION__,
               wlanFrame->frameLen,
               wlanFrameStore.numFrames);
  return 0;
}

#ifndef IZAT_OFFLINE
/*=============================================================================================
 * Function description:
 *   Check if the vendor cmd is relevant to LOWI. And convert to equivalent NL command
 *
 * Parameters:
 *   nl_msg: pointer to the result message from NL80211 message
 *   cmd: the NL equivalent command
 *
 * Return value:
 *    None
 =============================================================================================*/
static void lowi_vendor_cmd_to_nl_cmd(struct nl_msg *msg, __u32& nl_cmd)
{
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb[NL80211_ATTR_MAX + 1];

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);
  do
  {
    uint32 vendorId = (tb[NL80211_ATTR_VENDOR_ID]?
                       nla_get_u32(tb[NL80211_ATTR_VENDOR_ID]): 0);
    uint32 subCmd = (tb[NL80211_ATTR_VENDOR_SUBCMD] ?
                     nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]): 0);
    if ((vendorId != LOWI_OUI_QCA) || !subCmd)
    {
      LOWI_LOG_VERB("%s: vendor id(%u)/subcmd(%u) Ignored",
                    __FUNCTION__, vendorId, subCmd);
      break;
    }
    if (nlstate.idx && tb[NL80211_ATTR_IFINDEX])
    {
      uint32 idx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
      if (idx != nlstate.idx)
      {
        LOWI_LOG_DBG("%s: Mismatched IF Index %d, global %d", __FUNCTION__,
                      idx, nlstate.idx);
        break;
      }
    }
    if ((subCmd == LOWI_QCA_NL80211_VENDOR_SUBCMD_SCAN_DONE) &&
        (tb[NL80211_ATTR_VENDOR_DATA]))
    {
      uint8* pData = (uint8 *)nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
      size_t dataLen = nla_len(tb[NL80211_ATTR_VENDOR_DATA]);
      struct nlattr *sb[QCA_WLAN_VENDOR_ATTR_SCAN_MAX + 1];
      nla_parse(sb, QCA_WLAN_VENDOR_ATTR_SCAN_MAX,
                (struct nlattr *) pData, dataLen, NULL);
      if (!sb[QCA_WLAN_VENDOR_ATTR_SCAN_STATUS] ||
          !sb[QCA_WLAN_VENDOR_ATTR_SCAN_COOKIE])
      {
        LOWI_LOG_DBG("%s: Invalid buffer for subCmd %u", __FUNCTION__, subCmd);
        break;
      }
      uint8 scanStatus = nla_get_u8(sb[QCA_WLAN_VENDOR_ATTR_SCAN_STATUS]);
      LOWI_LOG_DBG("%s: Rcvd Vendor Scan Done status %d", __FUNCTION__, scanStatus);
      switch (scanStatus)
      {
        case 0:
          nl_cmd = NL80211_CMD_NEW_SCAN_RESULTS;
          break;
        case 1:
          nl_cmd = NL80211_CMD_SCAN_ABORTED;
          break;
        default:
          break;
      }
    }
    else
    {
      LOWI_LOG_VERB("%s: vendor id(%u)/subcmd(%u) Ignored",
                    __FUNCTION__, vendorId, subCmd);
    }
  }
  while (0);
}
#endif

/*=============================================================================================
 * Function description:
 *   Callback function to nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wait_event, &wait_ev)
 *
 * Parameters:
 *   nl_msg: pointer to the result message from NL80211 message
 *   arg: the passed argument via nc_cb_set
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
static int wait_event(struct nl_msg *msg, void *arg)
{
  struct s_wait_event *wait = (struct s_wait_event *)arg;
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  int i;

  LOWI_LOG_DBG ( "%s:Wait done with Cmd %u", __FUNCTION__, gnlh->cmd);

  for (i = 0; i < wait->n_cmds; i++)
  {
    if (gnlh->cmd == wait->cmds[i])
    {
      wait->cmd = gnlh->cmd;
    }
  }

  if (gnlh->cmd == NL80211_CMD_FRAME)
  {
    parse_action_frame(msg, arg);
  }
  #ifndef IZAT_OFFLINE
  else if (gnlh->cmd == NL80211_CMD_VENDOR)
  {
    wait->cmd = 0; // By default vendor commands are not useful
    lowi_vendor_cmd_to_nl_cmd(msg, wait->cmd);
  }
  #endif
  return NL_SKIP;
}
/*===========================================================================
 * Function description:
 *   Waits on a socket till some data to read becomes available, or a
 *   timeout of 10 seconds happens.
 *
 * Parameters:
 *   nl_sock which has been returned by nl_socket_alloc_cb
 *
 * Return value:
 *   TRUE, if some data is available on socket. FALSE, if timed out or error
 ===========================================================================*/
static int wips_wait_on_nl_socket(struct nl_sock * sock, int timeout_val)
{
  struct timeval tv;
  fd_set read_fd_set;
  int max_fd = -1;
  int retval;

  tv.tv_sec = timeout_val;
  tv.tv_usec = 0;
  FD_ZERO(&read_fd_set);

  // add the read end of the pipe. this will allow a "external entity" to kick the
  // pipe; hence, unblocking the thread is waiting on the socket and a request comes in.
  FD_SET(pipe_fd[0], &read_fd_set);
  if (sock != NULL)
  {
    // get the socket descriptor so the socket can be monitored
    max_fd = nl_socket_get_fd(sock);

    // add the socket descriptor to monitor incoming info on the socket
    FD_SET(max_fd, &read_fd_set);
  }

  if (pipe_fd[0] > max_fd)
  {
    max_fd = pipe_fd[0];
  }

  // monitor until the result comes or the timeout occurs
  if (timeout_val >= 0)
  {
    LOWI_LOG_VERB("%s:issue timed select \n", __FUNCTION__);
    retval = select(max_fd+1, &read_fd_set, NULL,NULL,&tv);
  }
  else
  { // monitor forever...
    LOWI_LOG_VERB("%s:issue blocking select \n", __FUNCTION__);
    retval = select(max_fd+1, &read_fd_set, NULL,NULL,NULL);
  }

  if (retval == 0) //This means the select timed out
  {
    LOWI_LOG_DBG("%s:Timeout. No scan results!!", __FUNCTION__);
    retval = ERR_SELECT_TIMEOUT;
    return retval;
  }

  if (retval < 0) //This means the select failed with some error
  {
    LOWI_LOG_ERROR("%s:Error %d No scan results",__FUNCTION__, errno);
  }

  if ( FD_ISSET( pipe_fd[0], &read_fd_set ) )
  {
    char readbuffer [50] = "";
    int nbytes = read(pipe_fd[0], readbuffer, sizeof(readbuffer));

    LOWI_LOG_DBG("%s: read returned %d, Received string: %s \n",
                 __FUNCTION__, nbytes, readbuffer);
    retval = ERR_SELECT_TERMINATED;
  }

  return retval;
}

/*=============================================================================================
 * Function description:
 *   Function to prepare to listen for passive scan results with NL80211 Interface.
 *
 * Parameters:
 *   pstate: pointer to the data structure for NL80211 state
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
int do_listen_events(struct nl80211_state *state, int timeout_val)
{
  struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
  struct s_wait_event wait_ev;
  int err_code = 0, select_retval;
  static const __u32 cmds[] = {
      NL80211_CMD_UNSPEC,
      NL80211_CMD_NEW_SCAN_RESULTS,
      NL80211_CMD_SCAN_ABORTED,
      NL80211_CMD_FRAME,
#ifndef IZAT_OFFLINE
      NL80211_CMD_VENDOR
#endif
  };
  WIPSIW_ENTER
  if (!cb)
  {
    LOWI_LOG_ERROR ( "failed to allocate netlink callbacks\n");
    return -ENOMEM;
  }

  /* no sequence checking for multicast messages */
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

  wait_ev.cmds = cmds;
  wait_ev.n_cmds = LOWI_ARR_SIZE(cmds);
  wait_ev.pargs = NULL;
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wait_event, &wait_ev);

  wait_ev.cmd = 0;

  while (!wait_ev.cmd)
  {
    select_retval = wips_wait_on_nl_socket(state->nl_sock, timeout_val );

    // for case a)valid result msg on socket b)scan request issued by someone
    if (select_retval > 0)
    {
      err_code = nl_recvmsgs(state->nl_sock, cb);
      LOWI_LOG_DBG("%s: Rcvd valid Netlink Cmd %d Err %d\n",
                    __FUNCTION__, wait_ev.cmd, err_code);
    }

    // If the scan got aborted, we do not have to listen anymore.
    if(wait_ev.cmd == NL80211_CMD_SCAN_ABORTED)
    {
      LOWI_LOG_DBG("%s:got scan abort message, return", __FUNCTION__);
      wait_ev.cmd = -1;
      break;
    }

    if (wait_ev.cmd == NL80211_CMD_FRAME)
    {
      if (timeout_val != -1)
      {
        /* Continue waiting because we are NOT in passiver listening meaning...
           we are waiting for some other events to complete */
        LOWI_LOG_DBG("%s - Continue to wait on Netlink socket", __FUNCTION__);
        wait_ev.cmd = 0;
        //continue waiting;
      }
      else
      {
        LOWI_LOG_DBG("%s - NL80211_CMD_FRAME received.Stop waiting on Netlink socket - cmd: %u",
                     __FUNCTION__,
                     wait_ev.cmd);
      }
    }

    if (select_retval <= 0)
    {
      LOWI_LOG_DBG("%s: Select Error return - %d", __FUNCTION__ , select_retval);
      wait_ev.cmd = select_retval;
      break;
    }

    //timeout_val >= 0 &&  err_code < 0 , means that a trigger request was issued, and that when NL socket was read, nothing was returned
    else if (  timeout_val >= 0 &&  err_code < 0 )
    {
      // EAGAIN is acceptable error code and we can go ahead and retrieve
      // the scan dump. EAGAIN error is trying to tell us to get the command
      // again which we already have. No need to get the command again and
      // so we log it at a lower level.
      if (err_code == -EAGAIN)
      {
        LOWI_LOG_VERB("%s: No valid messages on Netlink. Err %d",__FUNCTION__, err_code);
      }
      else
      {
        LOWI_LOG_INFO("%s:No valid messages on Netlink. Err %d",__FUNCTION__, err_code);
      }
      wait_ev.cmd = select_retval;
      break;
    }

  }

  if (wait_ev.cmd == NL80211_CMD_NEW_SCAN_RESULTS)
  {
    // no error if we were able to receive the scan results
    wait_ev.cmd = 0;
  }
  WIPSIW_EXIT
  nl_cb_put(cb);
  return wait_ev.cmd;
}

/*=============================================================================================
 * Function description:
 *   Untility function to print out IE (information elements) from the passive scan report
 *   using NL80211 Interface. Only SSID will be printed out.
 *
 * Parameters:
 *   ie: pointer to the IE
 *   ielen: length of the IE
 *
 * Return value:
 *    None
 =============================================================================================*/
/** The following are the list of Information elements that LOWI
  * is looking for in the Discovery Scan results
  */
#define COUNTRY_CODE_IE 0x7
#define BSSID_IE 0x00
#define VENDOR_SPECIFIC_IE 0xdd
#define CELL_POWER_INFO_IE 0x96
#define SUPPORTED_RATES_IE 1
#define EXT_SUPPORTED_RATES_IE 50
#define SUPPORTED_RATE_MASK 0x7F
#define BASIC_RATE_MASK    0x80

#define HT_CAP_IE          45
#define HT_CAP_40MHZ_SUPPORTED_BIT 1
#define HT_CAP_PROHIBIT_40MHZ_BIT 14

#define HT_OPERATION_IE    61
#define HT_OP_SEC_CH_NOT_PRESENT 0      /* No Seconday Channel present */
#define HT_OP_SEC_CH_ABOVE_PRIMARY_CH 1 /* Seconday Channel is above the Primary Channel */
#define HT_OP_SEC_CH_BELOW_PRIMARY_CH 3 /* Seconday Channel is below the Primary Channel */
#define VHT_CAP_IE         191
#define VHT_OPERATION_IE   192
#define VHT_OPER_IE_MIN_LEN  5
#define EXTENDED_CAP_IE    127
#define EXTENDED_CAP_11MC_SUPPORTED_BIT 70
#define EXTENDED_CAP_LOC_CIVIC_SUPPORTED_BIT 14
#define EXTENDED_CAP_LCI_SUPPORTED_BIT 15
#define EXTENDED_CAP_INTW_ANQP_SUPPORTED_BIT 31

#define NUM_11G_RATES 8
static const uint8 elevenGRates[NUM_11G_RATES] = { 6, 9, 12, 18, 24, 36, 48, 54 };

static const unsigned char u_CiscoOUI[3] = { 0x00, 0x40, 0x96 };
#define MSAP_ADVT_IND_IE 0x18 /* MSAP advertisement indicator */
#define RSN_IE 0x30
static const unsigned char u_QcomOUI[3] = { 0x00, 0xA0, 0xC6 };
#define QCOM_BSS_AGE_IE_IND 0x100 /* QCOM BSS Age IE indicator */

static const unsigned char u_CiscoOUI_Ext[4] = { 0x00, 0x40, 0x96, 0x00 };

/**
 * Description:
 *  This function us used to generate the byte number and bit
 *  number within that byte for a given IE sub field.
 *
 * @param[in] elemBitNum: the Bit number of the IE subfield in
 *                    the IE
 * @param[out] elemByteNum: The byte within the IE where the sub
 *                     field resides.
 * @param[out] elemBitNumInByte: The bit within the above byte
 *                        where the sub field resides.
 */
void getByteAndBitForField(uint32 elemBitNum, uint8* elemByteNum, uint8 *elemBitNumInByte)
{
  *elemByteNum = elemBitNum / 8;
  *elemBitNumInByte = elemBitNum % 8;
}

/**
 * Description:
 *  This function checks the corresponding bit in the Extended
 *  Cap IE and returns TRUE if bit set or FALSE if it is not.
 *
 * @param[in] elemBitNum: the Bit number of the IE subfield in
 *                    the IE
 * @param[in] extendedCaps: Extended Capability IEs.
 *
 * @return[out] true or false
 */
boolean isExtCapSupported(uint32 elemBitNum, uint8* ie)
{
  uint8 elemByteNum = elemBitNum / 8;
  uint8 elemBitNumInByte = elemBitNum % 8;
  boolean retVal = false;

  if (ie && ie[1] > elemByteNum)
  {
    uint8* extendedCaps = (uint8*) &ie[2];
    if (extendedCaps[elemByteNum] & (1 << elemBitNumInByte))
    {
      retVal = true;
    }
  }
  return retVal;
}

/*=============================================================================
 * is_msap_ie
 *
 * Description:
 *   This function checks the given IE string for an MSAP indication. If the
 *   MSAP indication is found, then MSAP related values are copied into the
 *   given structure.
 *
 * Parameters:
 *   ie - Pointer to the IE buffer
 *   LOWIScanMeasurement& Reference to the Scan Measurement class
 *
 * Return value:
 *   TRUE - if MSAP flag is found. Memory referenced by scan is updated.
 *   FALSE - if MSAP flag not found. Memory referenced by scan is
 *     UNTOUCHED!
 ============================================================================*/
unsigned int is_msap_ie(unsigned char * ie,
                        LOWIScanMeasurement& scan)
{
  int len;

  //If an IE already has been found, detecting this AP as MSAP enabled, Skip.

  len = ie[1];

  /* Check for CISCO OUI */
  if ((len >= 5) &&
      (memcmp(&ie[2], u_CiscoOUI, sizeof(u_CiscoOUI)) == 0) &&
               (ie[5] == MSAP_ADVT_IND_IE)
     )
  {
    scan.msapInfo = new (std::nothrow) LOWIMsapInfo();
    if (NULL == scan.msapInfo)
    {
      LOWI_LOG_DBG ("%s, Memory allocation failure", __func__);
      return FALSE;
    }
    scan.msapInfo->protocolVersion = ie[6];
    scan.msapInfo->serverIdx = ie[11];
    memcpy(&(scan.msapInfo->venueHash), &ie[7], 4);

    return TRUE;
  }
  return FALSE;
}

/*=============================================================================
 * is_qcom_ie
 *
 * Description:
 *   This function checks to see if the given IE matches the QCOM IE
 *   string, if it does it will return TRUE and save the decoded age & Delta TSF
 *   in the output parameter. Otherwise, FALSE will be returned.
 *
 * Parameters:
 *   ie - Pointer the given IE.
 *   p_bss_age - Pointer to variable to store decoded QCOM age info.
 *   p_bss_deltaTsf - Pointer to variable to store decoded delta in TSF
 *
 * Return value:
 *   TRUE - If the given IE is indeed QCOM age IE.
 *   FALSE - If the given IE is not a QCOM age IE.
 ============================================================================*/
unsigned int is_qcom_ie(unsigned char* ie, int* p_bss_age, uint32* p_bss_deltaTsf)
{
  int len, retval = FALSE;
  len = ie[1];
  unsigned int age_ie_ind;
  int bss_age;

  /* Check for QCOM OUI */
  if (memcmp(&ie[2], u_QcomOUI, sizeof(u_QcomOUI)) == 0)
  {
    /* Then check age indicator */
    memcpy(&age_ie_ind, &ie[5], 4);
    memcpy(&bss_age, &ie[9], 4);
    if (age_ie_ind == QCOM_BSS_AGE_IE_IND)
    {
      *p_bss_age = bss_age;
      retval = TRUE;
      if ((len > 11) && (p_bss_deltaTsf != NULL))
      {
        memcpy(p_bss_deltaTsf, &ie[13], 4);
      }
    }
  }
  return retval;
}

/*=============================================================================
 * decode_rsn_wpa_ie
 *
 * Description:
 *   This function decodes information within the RSN / WPA IE and store
 *   desired info within the given buffer. If nothing is found, then the
 *   given structure is UNTOUCHED.
 *
 *  Decoding logic for the Encryption Type
 *  LOWI_ENCRYPTION_TYPE_OPEN -
 *   RSN IE not found
 *  LOWI_ENCRYPTION_TYPE_WEP -
 *   RSN IE found, Cipher Suite OUI 00-0F-AC, Suite type 1 / 5
 *  LOWI_ENCRYPTION_TYPE_EAP -
 *   RSN IE found, Cipher Suite OUI 00-0F-AC, Suite type 2 (TKIP)
 *   AND
 *   Auth Key Mgmt Suite OUI 00-0F-AC, AUTH TYPE 1 / 3 / 5
 *   OR
 *   WPA_IE (Vendor IE 221)
 *  LOWI_ENCRYPTION_TYPE_WPA_PSK -
 *   RSN IE found, Cipher Suite OUI 00-0F-AC, Suite type 2 (TKIP)
 *   AND
 *   Auth Key Mgmt Suite OUI 00-0F-AC, Suite type 2 / 4 / 6
 *   OR
 *
 * Parameters:
 *   unsigned char*       Pointer to the RSN / WPA IE buffer.
 *   LOWIScanMeasurement& Reference to Scan Measurement class
 *   uint8                oui_0 (OUI of 80211 / MS index 0)
 *   uint8                oui_1 (OUI of 80211 / MS index 1)
 *   uint8                oui_2 (OUI of 80211 / MS index 2)
 *   uint8                Group cypher suite index
 *   uint32               length of the IE
 *
 * Return value: NONE
 ============================================================================*/
#define OUI_80211_0 0x0
#define OUI_80211_1 0x0F
#define OUI_80211_2 0xAC
#define GCS_SUITE_TYPE_WEP_40 1
#define GCS_SUITE_TYPE_TKIP 2
#define GCS_SUITE_TYPE_CCMP 4
#define GCS_SUITE_TYPE_WEP_104 5
#define AKM_SUITE_TYPE_8021X 1
#define AKM_SUITE_TYPE_PSK 2
#define AKM_SUITE_TYPE_FT_8021X 3
#define AKM_SUITE_TYPE_FT_PSK 4
#define AKM_SUITE_TYPE_256KEY_8021X 5
#define AKM_SUITE_TYPE_256KEY_PSK 6

#define OUI_MS_0 0x0
#define OUI_MS_1 0x0F
#define OUI_MS_2 0xAC

// Group Cipher Suite Index for RSN and WPA IE
#define GCS_INDEX_RSN_IE 4
#define GCS_INDEX_WPA_IE 8

inline uint16 lowi_get_little_endian_16 (const uint8 *le)
{
 return (le[1] << 8) | le[0];
}

void decode_rsn_wpa_ie (unsigned char* ie, LOWIScanMeasurement& scan, uint8 oui_0,
                        uint8 oui_1, uint8 oui_2, uint8 gcsIdx, uint32 len)
{
  uint8 akmIdx = 0; // Authentication key Management index
  if (len < gcsIdx)
  {
    LOWI_LOG_DBG ("%s: No Group Cypher suite", __FUNCTION__);
    return;
  }
  // Group Cipher Suite OUI
  if ( (oui_0 == ie [gcsIdx]) &&
       (oui_1 == ie [gcsIdx+1]) &&
       (oui_2 == ie [gcsIdx+2]) )
  {
    // Check for WEP
    if ( (ie [gcsIdx+3] == GCS_SUITE_TYPE_WEP_40) ||
         (ie [gcsIdx+3] == GCS_SUITE_TYPE_WEP_104) )
    {
      scan.encryptionType = LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WEP;
      return;
    }
    else if ( (ie [gcsIdx+3] == GCS_SUITE_TYPE_TKIP) ||
        (ie [gcsIdx+3] == GCS_SUITE_TYPE_CCMP) )
    {
      uint16 pairwise_count = lowi_get_little_endian_16 (&ie [gcsIdx+4]);
      akmIdx = gcsIdx + 6 + pairwise_count*4;
      if (len > akmIdx)
      {
        akmIdx += 2;
        // Let's parse the first AKM suite only
        // AKM Cipher Suite OUI
        if ( (oui_0 == ie [akmIdx]) &&
             (oui_1 == ie [akmIdx+1]) &&
             (oui_2 == ie [akmIdx+2]) )
        {
          // Check for WPA / WPA_PSK
          if ( (ie [akmIdx+3] == AKM_SUITE_TYPE_8021X) ||
               (ie [akmIdx+3] == AKM_SUITE_TYPE_FT_8021X) ||
               (ie [akmIdx+3] == AKM_SUITE_TYPE_256KEY_8021X) )
          {
            scan.encryptionType = LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WPA_EAP;
            return;
          }
          else if ( (ie [akmIdx+3] == AKM_SUITE_TYPE_PSK) ||
              (ie [akmIdx+3] == AKM_SUITE_TYPE_FT_PSK) ||
              (ie [akmIdx+3] == AKM_SUITE_TYPE_256KEY_PSK) )
          {
            scan.encryptionType = LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_WPA_PSK;
            return;
          }
        }
      }
    }
  }
}

void decode_wpa_ie (unsigned char* ie, LOWIScanMeasurement& scan)
{
  if(ie != NULL)
  {
    decode_rsn_wpa_ie (ie, scan, OUI_MS_0, OUI_MS_1, OUI_MS_2, GCS_INDEX_WPA_IE, ie[1]);
  }
}

void decode_rsn_ie (unsigned char* ie, LOWIScanMeasurement& scan)
{
  if(ie != NULL)
  {
    decode_rsn_wpa_ie (ie, scan, OUI_80211_0, OUI_80211_1, OUI_80211_2, GCS_INDEX_RSN_IE, ie[1]);
  }
}
/*=============================================================================
 * decode_cell_power_ie
 *
 * Description:
 *   This function decodes information within the cell power IE and store
 *   desired info within the given buffer. If nothing is found, then the
 *   given structure is UNTOUCHED.
 *
 * Parameters:
 *   ie - Pointer to the cell power IE buffer.
 *   LOWIScanMeasurement& Reference to Scan Measurement class
 *
 * Return value: NONE
 ============================================================================*/
void decode_cell_power_ie
(
  unsigned char* ie,
  LOWIScanMeasurement& scan
)
{
  int len;

  len = ie[1];

  scan.cellPowerLimitdBm = WPOS_CPL_UNAVAILABLE;
  /* Check for client transmit power IE */
  if ((len >= 6) &&
      (memcmp(&ie[2], u_CiscoOUI_Ext, sizeof(u_CiscoOUI_Ext)) == 0))
  {
    scan.cellPowerLimitdBm = (int8)ie[6];
  }
}

/*=============================================================================
 * Function description:
 *   Utility function to determine if the data rate is a 11g datarate.
 *
 * Parameters:
 *   rate: data rate
 *
 * Return value:
 *    TRUE or FALSE
 ============================================================================*/
boolean RateIs11g(uint8 rate)
{
  unsigned int i = 0;
  for(i = 0; i < NUM_11G_RATES; i++)
  {
    if (rate == elevenGRates[i])
    {
      return true;
    }
  }

  return false;
}

/*=============================================================================
 * Function description:
 *   Utility function to determine if 11g phy mode should be used.
 *
 * Parameters:
 *   ie: pointer to the IE
 *   phyMode: The PHY Mode result
 *   [out] uint32&: max supported rate
 *
 * Return value:
 *    None
 ============================================================================*/
void checkFor11gPhyModeAndRate(unsigned char *ie, int8 *phyMode,
                               uint32& /* maxTxRate */)
{
  if((ie != NULL) && (phyMode != NULL))
  {
    uint8 numSupRates = ie[1];
    uint8 rateIdx = 2;
    while (numSupRates)
    {
      uint8 rate = ie[rateIdx] & SUPPORTED_RATE_MASK;
      if (RateIs11g(rate))
      {
        *phyMode = LOWI_PHY_MODE_11G;
        if (ie[rateIdx] & BASIC_RATE_MASK)
        {
          *phyMode = LOWI_PHY_MODE_11GONLY;
          break;
        }
      }
      rateIdx++;
      numSupRates--;
    }
  }
}

/*=============================================================================
 * Function description:
 *   Utility function to determine if HT20 and Ht40 are supported.
 *
 * Parameters:
 *   unsigned char*: pointer to the IE
 *   uint16 frequency
 *   LOWIPreBwCombo&: Bit mask of the supported Preamble & BW combinations.
 *
 * Return value:
 *    None
 ============================================================================*/
void checkIfHT20AndHT40Supported(unsigned char* ie, uint16 frequency,
                                 LOWIPreBwCombo &supportedPreBwCombos)
{
  if (ie !=NULL)
  {
    supportedPreBwCombos.lowi_HT20 = TRUE;
    if (ie[1] > 2)
    {
      uint16 htCapInfo = ((ie[3] << 8) | ie[2]);
      if (htCapInfo & (1 << HT_CAP_40MHZ_SUPPORTED_BIT))
      {
        if (frequency > BAND_2G_FREQ_LAST) /* For 5G always true */
        {
          supportedPreBwCombos.lowi_HT40 = TRUE;
        }
        else
        { /* for 2.4G check intolerant bit (should NOT be set) */
          if(!(htCapInfo & (1 << HT_CAP_PROHIBIT_40MHZ_BIT)))
          {
            supportedPreBwCombos.lowi_HT40 = TRUE;
          }
        }
      }
    }
  }
}

/*=============================================================================
 * Function description:
 *   Utility function to determine the channel info for HT40 targets.
 *
 * Parameters:
 *   unsigned char*: pointer to the IE
 *   uint32*: Secondary Channel Freq
 *   LOWIPreBwCombo&: Bit mask of the supported Preamble & BW combinations.
 *
 * Return value:
 *    None
 ============================================================================*/
void setChannelInfoForHT40(unsigned char* ie,
                           uint32 *u_Band_center_freq1,
                           LOWIPreBwCombo &supportedPreBwCombos)
{
  uint8 primaryChan = ie[2];
  uint8 htOpInfo1 = (ie[3] & 0x3);

  *u_Band_center_freq1 = (uint16)LOWIUtils::channelBandToFreq((uint32)primaryChan);
  switch (htOpInfo1)
  {
    case HT_OP_SEC_CH_NOT_PRESENT: /* No Seconday Channel present */
    {
      supportedPreBwCombos.lowi_HT40 = false;
      LOWI_LOG_DBG(" No Secondary channel present");
      break;
    }
    case HT_OP_SEC_CH_ABOVE_PRIMARY_CH: /* Seconday Channel is above the Primary Channel */
    {
      *u_Band_center_freq1 += 10;
      break;
    }
    case HT_OP_SEC_CH_BELOW_PRIMARY_CH: /* Seconday Channel is below the Primary Channel */
    {
      *u_Band_center_freq1 -= 10;
      break;
    }
    default:
    {
      LOWI_LOG_WARN("%s: - This should have never hapenned: %u", __FUNCTION__, htOpInfo1);
      break;
    }
  }
  LOWI_LOG_VERB("HT40 - Secondary Channel: %u", *u_Band_center_freq1);
}

/*=============================================================================
 * Function description:
 *   Utility function to determine the channel info for 160MHz & 80+80MHZ targets.
 *
 * Parameters:
 *   unsigned char*: pointer to the IE
 *   uint32: primary frequency
 *   uint32*: Secondary Channel Freq1
 *   uint32*: Secondary Channel Freq2
 *   LOWIPreBwCombo&: Bit mask of the supported Preamble & BW combinations.
 *
 * Return value:
 *    None
 ============================================================================*/
static void setChannelInfoForVHT160(unsigned char* ie,
                                    uint32 primary,
                                    uint32 *u_Band_center_freq1,
                                    uint32 &u_Band_center_freq2,
                                    LOWIPreBwCombo &supportedPreBwCombos)
{

  uint16 bandCenter1 = (uint16)(ie[3] == 0 ? 0 :
                                LOWIUtils::channelBandToFreq((uint32)ie[3]));
  uint16 bandCenter2 = (uint16)(ie[4] == 0 ? 0 :
                                LOWIUtils::channelBandToFreq((uint32)ie[4]));
  u_Band_center_freq2 = 0;
  supportedPreBwCombos.lowi_VHT80 = false;
  supportedPreBwCombos.lowi_VHT160 = false;
  supportedPreBwCombos.lowi_VHT80P80 = false;

  if (ie[2] == 1) /* 80 OR 160 OR (80 + 80) MHz BW supported */
  {
    if (IS_VALID_80MHZ_CHAN_SPACING(primary, bandCenter1))
    {
      supportedPreBwCombos.lowi_VHT80 = true;
      u_Band_center_freq1[BW_80MHZ] = bandCenter1;
    }
    // Check if 160 MHz supported
    if (bandCenter2 != 0)
    {
      // Check if AP is operating in 80 + 80 Mode
      if (IS_VALID_80P80MHZ_CHAN_SPACING(primary, bandCenter1, bandCenter2))
      {
        supportedPreBwCombos.lowi_VHT80P80 = true;
      }
      else if (IS_VALID_160MHZ_CHAN_SPACING(primary, bandCenter1, bandCenter2))
      {
        // AP is operating in 160MHZ mode
        supportedPreBwCombos.lowi_VHT160 = true;
      }

      if (supportedPreBwCombos.lowi_VHT160 || supportedPreBwCombos.lowi_VHT80P80)
      {
        u_Band_center_freq1[BW_160MHZ] = bandCenter1;
        u_Band_center_freq2 = bandCenter2;
      }
    }
  }
}

/*=============================================================================
 * Function description:
 *   This function will parse the extended capabilty field.
 *
 * Parameters:
 *   ie: pointer to the IE
 *   u_Ranging_features_supported: Flag indicating support for 802.11mc Ranging
 *   u_location_features_supported: Bitfield containing Flags
 *                                  Support for LCI, LCR and
 *                                  Support for Interworking/ANQP support
 *
 * Return value:
 *    None
 ============================================================================*/
void parseExtendedCapIe(unsigned char* ie,
                        uint32 *u_Ranging_features_supported,
                        uint32 *u_location_features_supported)
{

  *u_Ranging_features_supported   = (isExtCapSupported(EXTENDED_CAP_11MC_SUPPORTED_BIT, ie)) ?
                                    TRUE : FALSE;
  *u_location_features_supported |= (isExtCapSupported(EXTENDED_CAP_LOC_CIVIC_SUPPORTED_BIT, ie)) ?
                                    LOC_CIVIC_SUPPORTED_MASK : 0;
  *u_location_features_supported |= (isExtCapSupported(EXTENDED_CAP_LCI_SUPPORTED_BIT, ie)) ?
                                    LCI_SUPPORTED_MASK : 0;
  *u_location_features_supported |= (isExtCapSupported(EXTENDED_CAP_INTW_ANQP_SUPPORTED_BIT, ie)) ?
                                    ANQP_SUPPORTED_MASK : 0;
}

/*=============================================================================
 * Function description:
 *   Utility function to determine the operating PHY mode for Target.
 *
 * Parameters:
 *   LOWIPreBwCombo&: Bit mask of the supported Preamble & BW combinations.
 *   uint32: Primary Operating channel frequency
 *   int8&: The resultant PHY mode
 *
 * Return value:
 *    None
 ============================================================================*/
void setPhyMode(LOWIPreBwCombo &supportedPreBwCombos, uint32 freq, int8 &phyMode)
{
  LOWI_LOG_VERB("%s: Supported: ht20: %s, ht40: %s, vht20: %s, vht40: %s, vht80: %s, vht160: %s, vht80p80: %s, Freq: %u",
                __FUNCTION__,
                (supportedPreBwCombos.lowi_HT20     ? "True" : "False"),
                (supportedPreBwCombos.lowi_HT40     ? "True" : "False"),
                (supportedPreBwCombos.lowi_VHT20    ? "True" : "False"),
                (supportedPreBwCombos.lowi_VHT40    ? "True" : "False"),
                (supportedPreBwCombos.lowi_VHT80    ? "True" : "False"),
                (supportedPreBwCombos.lowi_VHT160   ? "True" : "False"),
                (supportedPreBwCombos.lowi_VHT80P80 ? "True" : "False"),
                freq);

  if (supportedPreBwCombos.lowi_VHT160)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_UNKNOWN : LOWI_PHY_MODE_11AC_VHT160;
  }
  else if (supportedPreBwCombos.lowi_VHT80P80)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_UNKNOWN : LOWI_PHY_MODE_11AC_VHT80_80;
  }
  else if (supportedPreBwCombos.lowi_VHT80)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11AC_VHT80_2G : LOWI_PHY_MODE_11AC_VHT80;
  }
  else if (supportedPreBwCombos.lowi_VHT40)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11AC_VHT40_2G : LOWI_PHY_MODE_11AC_VHT40;
  }
  else if (supportedPreBwCombos.lowi_VHT20)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11AC_VHT20_2G : LOWI_PHY_MODE_11AC_VHT20;
  }
  else if (supportedPreBwCombos.lowi_HT40)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11NG_HT40 : LOWI_PHY_MODE_11NA_HT40;
  }
  else if (supportedPreBwCombos.lowi_HT20)
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11NG_HT20 : LOWI_PHY_MODE_11NA_HT20;
  }
  else
  {
    phyMode = IS_2G_FREQ(freq) ? LOWI_PHY_MODE_11G : LOWI_PHY_MODE_11A;
  }
}
/*=============================================================================
 * print_and_scan_ies
 *
 * Function description:
 *   This function decodes the some information elements (IEs) that WLAN
 *   positioning module is interested in and store them in the given structure.
 *
 * Parameters:
 *   ie: pointer to the IE
 *   ielen: length of the IE
 *   LOWIScanMeasurement* : Pointer to LOWIScanMeasurement class
 *   int*: Pointer to the BSS age
 *
 * Return value:
 *    None
 ============================================================================*/

void print_and_scan_ies(unsigned char *ie, int ielen,
                        LOWIScanMeasurement* scan,
                        int * p_bss_age)
{
  LOWIPreBwCombo supportedPreBwCombos;
  int8 phyMode;
  LOWIFullBeaconScanMeasurement* beacon = NULL;
  memset(&supportedPreBwCombos, 0, sizeof(supportedPreBwCombos));

  if (NULL == scan)
  {
    LOWI_LOG_DBG("Not valid pointer - scan\n");
    return;
  }

  phyMode = IS_2G_FREQ(scan->frequency) ? LOWI_PHY_MODE_11B : LOWI_PHY_MODE_11A;

  // By default assume the encryption type as OPEN if we are here
  // Idea is that if the RSN_IE is not found the encryption type is OPEN
  scan->encryptionType = LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_OPEN;
  // By default assume AP supports RTT2 Ranging
  scan->rttType = RTT2_RANGING;

  if (LOWIScanMeasurement::LOWI_FULL_BEACON_SCAN_MEASUREMENT ==
      scan->getScanMeasurementType ())
  {
    beacon = (LOWIFullBeaconScanMeasurement*) scan;
  }

  while (ielen >= 2 && ielen >= ie[1])
  {
    // Parse full beacon only when requested
    if (NULL != beacon)
    {
      LOWILocationIE* lowi_ie = new LOWILocationIE ();
      lowi_ie->id = ie[0];
      lowi_ie->len = ie[1];
      if (0 != lowi_ie->len)
      {
        lowi_ie->locData =  new (std::nothrow) uint8 [lowi_ie->len];
        if (NULL != lowi_ie->locData)
        {
          memcpy (lowi_ie->locData, &ie [2], lowi_ie->len);
          lowi_ie->printLocationIE ();
        }
        else
        {
          LOWI_LOG_DBG ("%s: memory allocation failure!\n", __FUNCTION__);
        }
      }
      beacon->mLOWIIE.push_back (lowi_ie);
    }

    switch (ie[0])
    {
      case BSSID_IE:
      {
        // already printed out
        break;
      }
      case VENDOR_SPECIFIC_IE:
      {
        uint32 bss_deltaTsf;
        if (is_qcom_ie(ie, p_bss_age, &bss_deltaTsf))
        {
          /* QC Age value is in 10ms unit, multiply by 10 to get ms */
          *p_bss_age *= 10;
          scan->tsfDelta = bss_deltaTsf;
        }
        else if (is_msap_ie(ie, *scan))
        {
          LOWI_LOG_DBG("Found MSAP ENABLED AP");
        }
        else if ((ie[1] >= 4) &&
                 (OUI_MS_0 == ie[2] && OUI_MS_1 == ie[3] && OUI_MS_2 == ie[4]) )
        {
          LOWI_LOG_VERB ("WPA_IE: 0x%x", ie[5]);
          if (0x01 == ie[5])
          {
            if (scan->encryptionType == LOWIScanMeasurement::LOWI_ENCRYPTION_TYPE_OPEN)
            {
              LOWI_LOG_VERB ("RSN_IE not found yet. Decode WPA_IE");
              decode_wpa_ie (ie, *scan);
              scan->isSecure = true;
            }
          }
        }
        break;
      }

      case RSN_IE:
      {
        decode_rsn_ie (ie, *scan);
        scan->isSecure = true;
        break;
      }
      case CELL_POWER_INFO_IE:
      {
        decode_cell_power_ie(ie, *scan);
        break;
      }
      case COUNTRY_CODE_IE:
      {
        // Confirm the length first
        if (ie[1] < 4)
        {
          // As per 802.11d, minimum length should be 8 but we are only interested in
          // country code
          LOWI_LOG_DBG ("Error - COUNTRY CODE IE LEN Invalid = %d", ie[1]);
        }
        else
        {
          scan->country_code[0] = ie[2];
          scan->country_code[1] = ie[3];
          scan->indoor_outdoor = ie[4];
        }
        break;
      }
      case SUPPORTED_RATES_IE:
      case EXT_SUPPORTED_RATES_IE:
      {
        checkFor11gPhyModeAndRate(ie, &phyMode, scan->maxTxRate);
        break;
      }
      case HT_CAP_IE:
      {
        checkIfHT20AndHT40Supported(ie, scan->frequency, supportedPreBwCombos);
        break;
      }
      case HT_OPERATION_IE:
      {
        if (supportedPreBwCombos.lowi_HT40 && ie[1] > 2)
        {
          setChannelInfoForHT40(ie, &scan->band_center_freq1[BW_40MHZ],
                                supportedPreBwCombos);
        }
        break;
      }
      case VHT_CAP_IE:
      {
        supportedPreBwCombos.lowi_VHT20 = true;
        supportedPreBwCombos.lowi_VHT40 = supportedPreBwCombos.lowi_HT40;
        break;
      }
      case VHT_OPERATION_IE:
      {
        if ((scan->frequency > BAND_2G_FREQ_LAST) &&
            (ie[1] >= VHT_OPER_IE_MIN_LEN))
        {
          setChannelInfoForVHT160(ie, scan->frequency, scan->band_center_freq1,
                                  scan->band_center_freq2, supportedPreBwCombos);
        }
        break;
      }
      case EXTENDED_CAP_IE:
      {
        scan->ranging_features_supported = 0;
        scan->location_features_supported = 0;
        parseExtendedCapIe(ie,
                           &scan->ranging_features_supported,
                           &scan->location_features_supported);
        if (TRUE == scan->ranging_features_supported)
        {
          // Set the rttType supported by AP to RTT3 based on the
          // info from the beacon
          scan->rttType = RTT3_RANGING;
        }
        break;
      }
      default:
      {
        /* Do nothing*/
        break;
      }
    }

    ielen -= ie[1] + 2; //Subtract the remaining IE Length
                        // (by 2+Length of this IE)
    ie += ie[1] + 2;    //move the pointer to the next IE.
  }

  setPhyMode(supportedPreBwCombos, scan->frequency, phyMode);
  scan->info = phyMode;
  scan->phyMode = LOWIUtils::to_eLOWIPhyMode(phyMode);
}

/*=============================================================================================
 * Function description:
 *   This function prepares the nl ap store before the next scan starts.
 *
 * Return value:
 *  None
 =============================================================================================*/
static void init_wips_nl_ap_store_for_next_scan (void)
{
  // Copy new list to current list, so that
  // the new list can be used to save next scan result
  if (wips_nl_ap_store.num_ap_new > 0)
  {
     memset (wips_nl_ap_store.current_list,
             0,
             sizeof (wips_nl_ap_store.current_list));

     memcpy (wips_nl_ap_store.current_list,
             wips_nl_ap_store.new_list,
             sizeof (wips_nl_ap_store.current_list));

     wips_nl_ap_store.num_ap_current = wips_nl_ap_store.num_ap_new;

     memset (wips_nl_ap_store.new_list, 0, sizeof (wips_nl_ap_store.new_list));
     wips_nl_ap_store.num_ap_new = 0;
  }
}

/*=============================================================================================
 * Function description:
 *   This function adjusts the age for the AP.
 *   The reason to adjust the age is that we may or may not get the Age from the driver
 *   based on what driver is used and also in case of age from driver the NL layer does
 *   caching.
 *
 *   NL caching has the following limitation:
 *   If one AP is found in current scan, NL will cache a copy. If subsequent scan does
 *   not find this AP, it will return this cached copy with the same tsf and age for up
 *   to three seconds.
 *
 *   This function will adjust the age of the AP in this case to properly reflect the
 *   cache due to NL layer buffering. For example, say NL fist receives an AP with age of 500ms,
 *   if the next scan result was received 1 second later by NL layer and wlan driver
 *   does not find this AP, NL layer will report this AP with age unchanged of 500 ms
 *   to this module. This function will then adjust the age of the AP to (500ms + 1000ms).
 *
 *   This function will also approximately compute the age of the AP in case there is
 *   no age available from the driver.
 *
 * Parameters:
 *  mac_id_ptr:
 *  tsf: from NL socket
 *  age: from the IE
 *
 * Return value:
 *  the age after adjustment
 =============================================================================================*/
static int32 adjust_age (char* mac_addr_ptr, uint64 tsf, int32 age)
{
  // This function is called to adjust age of each ap and insert it in the new list.
  // num_ap_new contains the number of ap's inserted in the new list so far and incremented
  // only after a new ap is inserted in the new list. So essentially this is an index to the
  // new list where a new ap could potentially be inserted.
  uint32 index = wips_nl_ap_store.num_ap_new;

  do
  {
    // exceeds maximum size. So we do not want to store this AP
    if (index >= (sizeof (wips_nl_ap_store.new_list)/ sizeof (wips_nl_ap_info)))
    {
      LOWI_LOG_DBG("Age %d - No more space left to store the AP", age);
      break;
    }

    // If AP is more than AP_AGE_ADJUST_UPPER_LIMIT (10) seconds old, we will not save
    // this AP for subsequent adjustment. As the NL buffering is 3 seconds, and when
    // age is old enough, the adjustment is not going to have significant impact.
    // And this will allow more entries for APs with smaller age that adjustment
    // will be more significant.
    if (age > AP_AGE_ADJUST_UPPER_LIMIT)
    {
      LOWI_LOG_DBG("%s:AP AGE upper limit reached. Dont store", __FUNCTION__);
      break;
    }

    // Set the defaults
    memcpy (wips_nl_ap_store.new_list[index].bssid,
            mac_addr_ptr,
            sizeof (wips_nl_ap_store.new_list[index].bssid));
    wips_nl_ap_store.new_list[index].bss_tsf_usec = tsf;
    wips_nl_ap_store.new_list[index].bss_meas_recv_msec = lowi_get_time_from_boot();

    // check whether this AP is found in the previous scan. If it was, adjust
    // the age accordingly.
    uint32 i;
    for (i = 0; i < wips_nl_ap_store.num_ap_current; i++)
    {
      // Check if this AP is already found in previous scans
      if ((memcmp (mac_addr_ptr,
                   wips_nl_ap_store.current_list[i].bssid,
                   sizeof (wips_nl_ap_store.current_list[i].bssid)) == 0))
      {
        break;
      }
    }

    // Check if the AP was found in the last snapshot or not
    if (i < wips_nl_ap_store.num_ap_current)
    {
      // The AP was seen earlier
      // Check if the tsf is still the same as last time. If that's the case,
      // this is a cached result.
      // In this case, we need to adjust the AP age by time elapsed in between.
      if ( (0 != tsf) && (tsf == wips_nl_ap_store.current_list[i].bss_tsf_usec) )
      {
        LOWI_LOG_VERB("Age - Found AP, tsf has not changed");
        // Check if the time has moved backwards. We have observed
        // this on a few occurrences and ended up calculating age
        // in negative.
        if (wips_nl_ap_store.new_list[index].bss_meas_recv_msec <
            wips_nl_ap_store.current_list[i].bss_meas_recv_msec)
        {
          LOWI_LOG_DBG("Age - Time has moved backwards. Set age to 0");
          age = 0;
        }
        else
        {
          // calculate the time difference between now and when
          // this AP with the same tsf was first seen
          age =
            (int32) (wips_nl_ap_store.new_list[index].bss_meas_recv_msec -
                     wips_nl_ap_store.current_list[i].bss_meas_recv_msec);
        }

        // store age
        wips_nl_ap_store.new_list[index].bss_age_msec = age;

        // save the first recv time in bss_meas_recv_msec for
        // subsequent adjustment
        wips_nl_ap_store.new_list[index].bss_meas_recv_msec =
            wips_nl_ap_store.current_list[i].bss_meas_recv_msec;

        // increase the number of aps in new list
        wips_nl_ap_store.num_ap_new++;

        break;
      }
      else
      {
        LOWI_LOG_VERB("Age - Found AP, tsf has changed or is 0");
      }
    }
    else
    {
      LOWI_LOG_VERB("Age - AP not found in the store");
    }

    // We are here because
    // AP was not found in last scan snapshot
    // OR Found but tsf has changed
    // OR Found but tsf is not available
    // Check if the age information is avialble from the driver
    if (age == AP_AGE_UNSPECIFIED_IN_MSECS)
    {
      // Age not available from driver
      // Store the age as 0 and measurement time as current time
      age = 0;
      wips_nl_ap_store.new_list[index].bss_age_msec = age;

      // Meas recv time already set as current time. No need to set again
    }
    else
    {
      // Age available from driver
      // Store the age that's received from driver
      wips_nl_ap_store.new_list[index].bss_age_msec = age;

      // Store the meas recv time as "cur time - age"
      wips_nl_ap_store.new_list[index].bss_meas_recv_msec -= age;
    }

    // increase the number of aps in new list
    wips_nl_ap_store.num_ap_new++;
  } while (0);

  return age;
}

/*=============================================================================================
 * Function description:
 *   The callback function to process passive scan result using NL80211 Interface.
 *
 * Parameters:
 *   nl_msg: pointer to the result message from NL80211 message
 *   results_buf_ptr: if this is NULL, the result will only be printed on the screen.
 *                    This function assumes that caller has allocated sufficient amount
 *                    of memory to store max APs in the results buf ptr. If that doesn't
 *                    happen - this function WILL CRASH!!
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
#define WLAN_CAPABILITY_ESS             (1<<0)
#define WLAN_CAPABILITY_IBSS            (1<<1)
#define WLAN_CAPABILITY_CF_POLLABLE     (1<<2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST (1<<3)
#define WLAN_CAPABILITY_PRIVACY         (1<<4)
#define WLAN_CAPABILITY_SHORT_PREAMBLE  (1<<5)
#define WLAN_CAPABILITY_PBCC            (1<<6)
#define WLAN_CAPABILITY_CHANNEL_AGILITY (1<<7)
#define WLAN_CAPABILITY_SPECTRUM_MGMT   (1<<8)
#define WLAN_CAPABILITY_QOS             (1<<9)
#define WLAN_CAPABILITY_SHORT_SLOT_TIME (1<<10)
#define WLAN_CAPABILITY_APSD            (1<<11)
#define WLAN_CAPABILITY_DSSS_OFDM       (1<<13)
#define MAC_STR_LEN 20
static int print_bss_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  char dev[IF_NAMESIZE] = "";
  char * mac_addr_n;
  __u32 bss_freq = 0, bss_ssid_len = 0;

  int bss_rssi = 0;
  char * bss_ssid_ptr = NULL;
  int age = AP_AGE_UNSPECIFIED_IN_MSECS;
  uint64_t tsf = 0;
  uint64_t probeTsf = 0;
  uint64_t beaconTsf = 0;
  int16 bss_rssi_0p5dBm;
  bool bss_associated = false;
  char * results_buf_ptr = (char *)arg;
  char ssid_str[SSID_LEN+1] = "";
  LOWIScanMeasurement* scan = NULL;
  LOWIMeasurementInfo* info = NULL;
  bool scan_added = false;

  WIPSIW_ENTER

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_BSS])
  {
    LOWI_LOG_DBG("bss info missing! Msg Size %d",((nlmsg_hdr(msg))->nlmsg_len - NLMSG_HDRLEN));
    genl_integrity_check_fail = TRUE;
    return NL_STOP;
  }

  if (wips_parse_bss(bss, tb[NL80211_ATTR_BSS]))
  {
    LOWI_LOG_ERROR ( "failed to parse nested attributes!\n");
    return NL_SKIP;
  }

  if (!bss[NL80211_BSS_BSSID])
    return NL_SKIP;

  if (true == parseFullBeacon)
  {
    scan = new (std::nothrow) LOWIFullBeaconScanMeasurement ();
  }
  else
  {
    scan = new (std::nothrow) LOWIScanMeasurement ();
  }
  if (NULL == scan)
  {
    LOWI_LOG_ERROR ("Memory allocation failed for scan results");
    return NL_STOP;
  }
  info = new (std::nothrow) LOWIMeasurementInfo ();
  if (NULL == info)
  {
    LOWI_LOG_ERROR ("Unable to allocate memory for LOWIMeasurementInfo");
    delete scan;
    return NL_STOP;
  }
  mac_addr_n = (char *)nla_data(bss[NL80211_BSS_BSSID]);
  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

  if (bss[NL80211_BSS_STATUS])
  {
    scan->beaconStatus = nla_get_u32(bss[NL80211_BSS_STATUS]);
    switch (scan->beaconStatus)
    {
      case NL80211_BSS_STATUS_AUTHENTICATED:
        LOWI_LOG_DBG(" -- authenticated");
        break;
      case NL80211_BSS_STATUS_ASSOCIATED:
        LOWI_LOG_DBG(" -- associated");
        /* Setting flag to Associated*/
        bss_associated = true;
        scan->associatedToAp = true;
        break;
      case NL80211_BSS_STATUS_IBSS_JOINED:
        LOWI_LOG_DBG(" -- joined");
        break;
      default:
        LOWI_LOG_DBG(" -- unknown status: %d",
        nla_get_u32(bss[NL80211_BSS_STATUS]));
        break;
    }
  }
  LOWI_LOG_DBG("\n");

  if (bss[NL80211_BSS_TSF])
  {
    probeTsf = (uint64_t)nla_get_u64(bss[NL80211_BSS_TSF]);
  }
  /**
   * IMPORTANT NOTE: THE FOLLOWING CODE IS IN
   * PLACE TO OVERCOME A MISMATCH IN THE KERNEL BETWEEN PL
   * BRANCHES.
   *
   * TODO: After kernel changes are merged, replace
   * "LOWI_NL80211_BSS_BEACON_TSF" with "NL80211_BSS_BEACON_TSF".
   *
   * Reference Kernel Enumeration
   * enum nl80211_bss
   * {
   *   __NL80211_BSS_INVALID,  // 0
   *   NL80211_BSS_BSSID,      // 1
   *   NL80211_BSS_FREQUENCY,  // 2
   *   NL80211_BSS_TSF,        // 3
   *   NL80211_BSS_BEACON_INTERVAL,      // 4
   *   NL80211_BSS_CAPABILITY,           // 5
   *   NL80211_BSS_INFORMATION_ELEMENTS, // 6
   *   NL80211_BSS_SIGNAL_MBM,           // 7
   *   NL80211_BSS_SIGNAL_UNSPEC,        // 8
   *   NL80211_BSS_STATUS,     // 9
   *   NL80211_BSS_SEEN_MS_AGO,// 10
   *   NL80211_BSS_BEACON_IES, // 11
   *   NL80211_BSS_CHAN_WIDTH, // 12
   *   NL80211_BSS_BEACON_TSF, // 13 <=LOWI_NL80211_BSS_BEACON_TSF
   *   NL80211_BSS_PRESP_DATA, // 14
   *   NL80211_BSS_LAST_SEEN_BOOTTIME, //15
   *
   *   // keep last
   *   __NL80211_BSS_AFTER_LAST,
   *   NL80211_BSS_MAX = __NL80211_BSS_AFTER_LAST - 1  // 15
   * };
   *
   */
  if (bss[NL80211_BSS_BEACON_IES])
  {
    #define LOWI_NL80211_BSS_BEACON_TSF 13
    if ((LOWI_NL80211_BSS_BEACON_TSF <= NL80211_BSS_MAX)  &&
        (bss[LOWI_NL80211_BSS_BEACON_TSF]))
    {
      beaconTsf = (uint64_t)nla_get_u64(bss[LOWI_NL80211_BSS_BEACON_TSF]);
    }
  }

  // whichever has the highest TSF (probe or beacon) report that TSF.
  if (beaconTsf >= probeTsf)
  {
    tsf = beaconTsf;
    LOWI_LOG_DBG("%s: Report beacon TSF %" PRIu64 " as it greater than probe TSF %" PRIu64,
                 __FUNCTION__, beaconTsf, probeTsf);
    scan->measAdditionalInfoMask |= LOWI_BEACON_IE_MASK;
  }
  else
  {
    tsf = probeTsf;
    LOWI_LOG_DBG("%s: Report Probe TSF %" PRIu64 " as it greater than Beacon TSF %" PRIu64,
                 __FUNCTION__, probeTsf, beaconTsf);
  }

  if (bss[NL80211_BSS_FREQUENCY])
  {
    bss_freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);

    scan->frequency = bss_freq;
    memset(&scan->band_center_freq1, 0, sizeof(scan->band_center_freq1));
    scan->band_center_freq1[BW_20MHZ] = bss_freq;

  }

  if (bss[NL80211_BSS_BEACON_INTERVAL])
  {
    scan->beaconPeriod = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
  }

  if (bss[NL80211_BSS_CAPABILITY])
  {
    __u16 capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
    scan->beaconCaps = capa;
  }
  if (bss[NL80211_BSS_SIGNAL_MBM])
  {
    int s = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
    bss_rssi = s;
  }
  if (bss[NL80211_BSS_SIGNAL_UNSPEC])
  {
    unsigned char s = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
    bss_rssi = s;
  }

  // The AGE info from the block below may not be available on
  // external drivers
  if (bss[NL80211_BSS_INFORMATION_ELEMENTS] )
  {
    char * ie_data_ptr;
    int  ie_len;
    ie_data_ptr = (char *)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    if (ie_data_ptr[0] == 0)
    {
      bss_ssid_ptr = ie_data_ptr+2;
      bss_ssid_len = ie_data_ptr[1];
    }
    print_and_scan_ies((unsigned char *)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
                       ie_len, scan, &age);
    LOWI_LOG_VERB("%s: QCOM IE Age: %d \n", __FUNCTION__, age);
  }

  // override the age if available from NL80211_BSS_SEEN_MS_AGO or NL80211_BSS_LAST_SEEN_BOOTTIME
  // @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
  if (bss[NL80211_BSS_SEEN_MS_AGO])
  {
    age = (uint32_t)nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
    LOWI_LOG_VERB("%s: NL80211_BSS_SEEN_MS_AGO IE Age: %d\n", __FUNCTION__, age);
  }

  /** @NL80211_BSS_LAST_SEEN_BOOTTIME: CLOCK_BOOTTIME timestamp when this entry
    * was last updated by a received frame. The value is expected to be
    * accurate to about 10ms.else (u64, nanoseconds) */
  // defining the local macro as it is not available on LE platforms, to make it compilable.
#define LOWI_NL80211_BSS_LAST_SEEN_BOOTTIME 15
  else if ((LOWI_NL80211_BSS_LAST_SEEN_BOOTTIME <= NL80211_BSS_MAX) &&
           (bss[LOWI_NL80211_BSS_LAST_SEEN_BOOTTIME]))
  {
    uint64_t bss_last_seen_bootime_ns = (uint64_t)nla_get_u64(bss[LOWI_NL80211_BSS_LAST_SEEN_BOOTTIME]);
    uint64_t currentime = lowi_get_time_from_boot();
    // to calculate Age subtract BSS bss_last_seen_bootime from current time(ms).
    // bss_last_seen_bootime is reported in nanoseconds, convert it to milliseconds.
    age = currentime - (bss_last_seen_bootime_ns/NSEC_PER_MSEC);
    LOWI_LOG_VERB("%s: NL80211_BSS_LAST_SEEN_BOOTTIME IE Age: %d \n",__FUNCTION__, age);
  }
  // There seems to be some issue with bitwidth of bss_rssi, because
  // of which it wraps around..
  //
  // So the issue is further complicated because in AR6K driver, there is a factor of 96dB,
  // so -96dBm is represented as 0 coming out of the AR6K driver.
  //
  // Here is the table that will explain the bug:
  // ==================================================
  // Actual RSSI : Driver RSSI : NL-truncated RSSI : NL-reported RSSI
  // ==================================================
  // -224dBm -128 128   3200
  //  ..      ..  ..    ..
  // -128dBm -32  224  12800
  //  ..      ..  ..    ..
  // -98 dBm  -2  254  15800
  // -97 dBm  -1  255  15900
  // -96 dBm   0    0  -9600
  // -95 dBm   1    1  -9500
  //  ..      ..   ..   ..
  //   0 dBm  96   96   0
  //  ..      ..   ..   ..
  // 31  dBm 127  127  3100
  //
  // So the bug started to show up when the actual RSSI dips below -96 dBm,
  // all of a sudden the rssi becomes a large number, i.e. ~15900. To mitigate this,
  // any large number above 12800, can be considered a negative number. This is
  // safe to assume because RSSI is assumed that it cannot be larger than 128 dBm,
  // and cannot be smaller than -128 dBm. Note that this workaround does not harm RIVA
  // or any driver that does *not* have a bug; because we assume that RSSI cannot be
  // larger than 128dBm, so it won't even kick in for any other driver without a bug!
  if (bss_rssi > 12800)
  {
    bss_rssi -= 25600;
  }

  bss_rssi_0p5dBm = (int16)(((float)bss_rssi/100.0) * 2 - 0.5);
  if (FALSE == scan->isSecure)
  {
    scan->isSecure = ((0 == (scan->beaconCaps & WLAN_CAPABILITY_PRIVACY))?TRUE:FALSE);
  }

  // Limit the SSID size to be capped at a max, as that is the size of buffer allocated
  // to retain the SSID.
  uint8 ssid_len = (bss_ssid_len > SSID_LEN)?SSID_LEN:bss_ssid_len;

//  if (bss_freq < MAX_FREQ_BANDS24)
  {
    // There seems to be some bug in age for Associated AP
    // set it to AP_AGE_UNSPECIFIED_IN_MSECS.
    //
    // Please note that setting it to 0 or small values will cause issue for
    // cached passive scan. In this usage scenario, when any measurement
    // returned has a smaller age than the specified, the cached scan will be
    // deemed fresh and it will be returned to the caller without triggering
    // fresh passive scan.
    if (bss_associated == true)
    {
      age = AP_AGE_UNSPECIFIED_IN_MSECS;
    }

    // Copy the other fields to the struct
    if (NULL != mac_addr_n)
    {
      // Adjust the current age, which could be -1 (third party wifi or associated)
      // or some age (provided by wifi driver) in case of QC wifi.
      age = adjust_age (mac_addr_n, tsf, age);
      scan->bssid = LOWIMacAddress ((const unsigned char* const)mac_addr_n);
    }
    if (NULL != bss_ssid_ptr)
    {
      scan->ssid.setSSID ((const unsigned char * const)bss_ssid_ptr, ssid_len);
    }
    // Copy the tsf
    scan->targetTSF = tsf;

    info->meas_age = age;
    info->rssi = bss_rssi_0p5dBm;
    info->rssi_timestamp = get_time_rtc_ms() - age;
    scan->measurementsInfo.push_back(info);
    if (NULL != results_buf_ptr)
    {
      scan_added = lowi_insert_record(results_buf_ptr,
                                      age,
                                      scan);
    }
    else
    {
      LOWI_LOG_ERROR("%s]%d results_buf_ptr is NULL\n", __func__, __LINE__);
    }
  }

  LOWI_LOG_DBG("BSS " LOWI_MACADDR_FMT " %s(%u), Beacon Interval: %d, "
               "%s 11mcRanging: %s, ANQP: %s, LCI: %s, Civic: %s, "
               "capability(0x%.4x):%s%s%s%s%s%s%s%s%s%s%s",
               LOWI_MACADDR(scan->bssid), LOWIUtils::to_string(scan->phyMode), scan->phyMode,
               scan->beaconPeriod, LOWIUtils::to_string(scan->encryptionType),
               (scan->ranging_features_supported ? "Yes" : "No"),
               (scan->location_features_supported & ANQP_SUPPORTED_MASK) ? "Yes" : "No",
               (scan->location_features_supported & LCI_SUPPORTED_MASK) ? "Yes" : "No",
               (scan->location_features_supported & LOC_CIVIC_SUPPORTED_MASK) ? "Yes" : "No",
               scan->beaconCaps,
               (scan->beaconCaps & WLAN_CAPABILITY_ESS ? " ESS" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_IBSS ? " IBSS" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_PRIVACY ? " Privacy" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_SHORT_PREAMBLE ? " ShortPreamble" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_PBCC ? " PBCC" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_CHANNEL_AGILITY ? " ChannelAgility" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_SPECTRUM_MGMT ? " SpectrumMgmt" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_QOS ? " QoS" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_SHORT_SLOT_TIME ? " ShortSlotTime" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_APSD ? " APSD" : ""),
               (scan->beaconCaps & WLAN_CAPABILITY_DSSS_OFDM ? " DSSS-OFDM" : ""));
  LOWI_LOG_DBG("BSS " LOWI_MACADDR_FMT " FREQ: %u, cFreq1[40:80] = [%u:%u] cFreq2 = %u"
               " Country Code = %c%c%c",
               LOWI_MACADDR(scan->bssid),
               scan->frequency,
               scan->band_center_freq1[BW_40MHZ],
               scan->band_center_freq1[BW_80MHZ],
               scan->band_center_freq2,
               ((scan->country_code[0] == 0) ? ' ' : scan->country_code[0]),
               ((scan->country_code[1] == 0) ? ' ' : scan->country_code[1]),
               ((scan->indoor_outdoor == 0) ? ' ' : scan->indoor_outdoor));

  LOWI_LOG_DBG("BSS " LOWI_MACADDR_FMT " (%s) ASSO: %s AddInfo: 0x%" PRIX64","
               " TSF %" PRIu64", %.2" PRIu64":%.2" PRIu64":%.2" PRIu64".%.3" PRIu64","
               " RSSI: %d, CPL: %d, AGE: %d,  SSID %s, TSFDelta: 0x%x, TXRate: %u",
               LOWI_MACADDR(scan->bssid), dev,
               (scan->associatedToAp) ? "YES" : "NO",
               scan->measAdditionalInfoMask,
               tsf/1000/1000/60/60/24, (tsf/1000/1000/60/60) % 24,
               (tsf/1000/1000/60) % 60, (tsf/1000/1000) % 60,
               (tsf/1000) % 1000, scan->measurementsInfo[0]->rssi,
               scan->cellPowerLimitdBm, scan->measurementsInfo[0]->meas_age,
               LOWISsid::toString((const uint8*)bss_ssid_ptr, ssid_len, ssid_str),
               scan->tsfDelta, scan->maxTxRate);
  if (false == scan_added)
  {
    // Scan was not added to the results. Delete the scan
    delete scan;
  }

  WIPSIW_EXIT
  return NL_SKIP;
}


/*=============================================================================================
 * Function description:
 *   Set up various callbacks to process the passive scan results using NL80211 Interface.
 *   If the scan is succesful, the result will be processed by print_bss_handler.
 *
 * Parameters:
 *   pstate: pointer to the data structure for NL80211 state
 *   results_buf_tpr: ptr to store the scan results
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
static int do_scan_dump(struct nl80211_state *p_nlstate,
                        char * results_buf_ptr)
{
  struct nl_msg * msg;
  struct nl_cb * cb;
  int err = 0;
  WIPSIW_ENTER

  num_acks_for_dump = 1; //Just to satisfy the while condition
  num_finishes_for_dump = 0;
  while ((num_finishes_for_dump == 0)&&(num_acks_for_dump > 0))
  {
    num_acks_for_dump = 0;
    num_finishes_for_dump = 0;
    genl_integrity_check_fail = FALSE;
    lowi_reset_records(results_buf_ptr);
    msg = Wips_nl_msg_alloc(p_nlstate, NL80211_CMD_GET_SCAN,
                            NLM_F_ROOT|NLM_F_MATCH);
    if (!msg)
    {
      LOWI_LOG_ERROR ( "failed to allocate netlink message\n");
      return 2;
    }
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
    {
      LOWI_LOG_ERROR ( "failed to allocate netlink callbacks\n");
      err = 2;
      goto out_free_msg;
    }

    //Here, do whatever the handle_scan_dump function does...
    //Should set a pointer to the buffer where the scan results
    //will arrive and also a callback function which will be called
    //with this buffer pointer as a parameter.
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_bss_handler,results_buf_ptr);
    err = nl_send_auto_complete(p_nlstate->nl_sock, msg);
    if (err < 0)
    {
      LOWI_LOG_WARN ( "Failed to send the request for scan results to nl. Retry\n");
      num_acks_for_dump = 1; //Just to satisfy the while condition
      num_finishes_for_dump = 0;
      goto nla_put_failure;
    }

    err = 1; // Set err to 1, so that we can wait for err to become 0
    // after sending the command. err is set to 0 by finish_handler or
    // ack handler.
    nl_cb_err(cb, NL_CB_CUSTOM, dump_error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, dump_finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, dump_ack_handler, &err);

    // DO NOTE THAT IF FOR WHATEVER REASON ERROR HANDLER IS CALLED -
    // WE SPIN FOREVER HERE !!
    // NOTE: Not an infinite loop
    while ((err > 0) && (FALSE == genl_integrity_check_fail) )
      nl_recvmsgs(p_nlstate->nl_sock, cb);

    if ((genl_integrity_check_fail == TRUE) && (num_finishes_for_dump == 0))
    {
      num_acks_for_dump = 1;
      genl_integrity_check_fail = FALSE;
      LOWI_LOG_ERROR ( "GENL Msg Integrity Check Failed");
    }

nla_put_failure:
  nl_cb_put(cb); //Free the CB.
out_free_msg:
  nlmsg_free(msg); //Free the allocated Message
    if ((num_finishes_for_dump == 0) && (num_acks_for_dump > 0))
    {
      LOWI_LOG_ERROR ( "RETRY: Finish NL Msg err code %d Num Finish %d Num Ack %d",
                  err,num_finishes_for_dump,num_acks_for_dump);
     nl80211_cleanup(p_nlstate);
     nl80211_init(p_nlstate);
    }
  }
  lowi_close_record(results_buf_ptr);
  WIPSIW_EXIT
  return err;
}

/*=============================================================================================
 * Function description:
 *   Trigger the passive scan results from NL80211 Interface.
 *
 * Parameters:
 *   pstate: pointer to the data structure for NL80211 state
 *   pFreq: pointer to the frequency's that needs to be scanned.
 *   num_of_freq: Number of frequency's that needs to be scanned.
 *   LOWIRequest* Pointer to the LOWIRequest
 *
 * Return value:
 *    error code: 0, no error
 *                non-0, error
 =============================================================================================*/
static int do_trigger_scan(struct nl80211_state * pstate,
                           int* pFreq, int num_of_freq, LOWIRequest* request)
{
  struct nl_msg * msg;
  struct nl_msg *ssids = NULL, *freqs = NULL;
  struct nl_cb * cb;
  int err, i;
  struct timeval tv;
  LOWIDiscoveryScanRequest* disc = NULL;
  bool ssids_added = false;
  unsigned char ssid [SSID_LEN+1] = {0};

  WIPSIW_ENTER
  if ( (NULL == pFreq) || (0 == num_of_freq) )
  {
    LOWI_LOG_ERROR ("No frequency specified to be scanned");
    return -1;
  }
  if (pstate->iftype != NL80211_IFTYPE_STATION)
  {
    LOWI_LOG_INFO("%s: Cannot request scan on Interface %d",
                  __FUNCTION__, pstate->iftype);
    return -ENODEV;
  }
  msg = Wips_nl_msg_alloc(pstate, NL80211_CMD_TRIGGER_SCAN, 0);
  if (!msg)
  {
    LOWI_LOG_ERROR ( "failed to allocate netlink message\n");
    err = 2;
    goto out_free_msg;
  }

  ssids = nlmsg_alloc();
  if (!ssids) {
    LOWI_LOG_ERROR ( "failed to allocate ssid space\n");
    err = -ENOMEM;
    goto out_free_msg;
  }

  freqs = nlmsg_alloc();
  if (!freqs)
  {
    fprintf(stderr, "failed to allocate freq space\n");
    err = -ENOMEM;
    goto out_free_msg;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb)
  {
    LOWI_LOG_ERROR ( "failed to allocate netlink callbacks\n");
    err = 2;
    goto out_free_msg;
  }

  for ( i=0;i < num_of_freq; i++)
  {
    LOWI_LOG_DBG ("Freq added = %d\n", pFreq[i]);
    NLA_PUT_U32(freqs, i+1, pFreq[i]);
  }

  // Check the request type
  if (NULL != request &&
      LOWIRequest::DISCOVERY_SCAN == request->getRequestType())
  {
    disc = (LOWIDiscoveryScanRequest*) request;
  }

  if (NULL != disc)
  {
    for (uint32 ii = 0; ii < disc->getScanSsids().getNumOfElements(); ++ii)
    {
      memset (&ssid, 0, SSID_LEN+1);
      int length = 0;

      disc->getScanSsids()[ii].getSSID(ssid, &length);
      if (length > SSID_LEN)
      {
        length = SSID_LEN;
      }
      NLA_PUT(ssids, ii+1, length, &ssid);
      ssids_added = true;
    }
  }

  // If No SSID was added, add a wild card SSID for broadcast probe request
  if (false == ssids_added)
  {
    // note: Appending SSID ATTRIB structure to the message.
    // With zero payload. Doing this to circumvent RIVA issue.
    NLA_PUT(ssids, 1, 0, "");
  }

  //Here, add whatever other options for scan..like filling in ssid, freqs etc..

  // adding the required frequencies
  nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);

  // adding ssids
  nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

  // adding bssid
  // Note: Host limitation to only do BSSID scan with one BSSID per request
  if (disc->getScanMacAddress().getNumOfElements() > 0)
  {
    LOWIMacAddress mac = disc->getScanMacAddress()[0];
    uint8 bss [ETH_ALEN] = {0};
    for (int32 uu = 0; uu < ETH_ALEN; ++uu)
    {
      bss [uu] = mac [uu];
    }
    LOWI_LOG_DBG ( "Sending NL message Trigger Scan@ bss " LOWI_MACADDR_FMT "\n",
                    LOWI_MACADDR(bss));
    nla_put (msg, NL80211_ATTR_MAC, ETH_ALEN, bss);
  }

  if (0 == gettimeofday(&tv,NULL) )
  {
    LOWI_LOG_INFO ( "Sending NL message Trigger Scan@ %d(s).%d(us)\n",(int)tv.tv_sec,(int)tv.tv_usec);
  }
  wipsiw_scan_req_time = lowi_get_time_from_boot();
  err = nl_send_auto_complete(pstate->nl_sock, msg);
  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  // NOTE: Not an infinite loop
  while (err > 0)
    nl_recvmsgs(pstate->nl_sock, cb);

  if (err < 0)
  {
    LOWI_LOG_INFO ("Trigger Scan: the value err is: %d\n", err);
  }
  else
  {
    LOWI_LOG_DBG ("Trigger Scan: the value err is: %d\n", err);
  }
  WIPSIW_EXIT

nla_put_failure:
    err = 2;
out:
  nl_cb_put(cb);
out_free_msg:
  if (msg)
  {
    nlmsg_free(msg);
  }
  if (ssids)
  {
    nlmsg_free(ssids);
  }
  if (freqs)
  {
    nlmsg_free(freqs);
  }
  return err;
}

/*=============================================================================================
 * Function description:
 *   Performs Passive Scan using NL80211 Interface.
 *
 * Parameters:
 *   results_buf_ptr: if this is NULL, the result will only be printed on the screen.
 *                    This function assumes that caller has allocated sufficient amount
 *                    of memory to store max APs in the results buf ptr. If that doesn't
 *                    happen - this function WILL CRASH!!
 *
 *   cached: whether cached result can be used or no. Currently it is assumed the function
 *           is called with cached set to FALSE.
 *   pFreq: pointer to the frequency's that needs to be scanned.
 *   num_of_freq: Number of frequency's that needs to be scanned.
 *   LOWIRequest* Pointer to the LOWIRequest
 *
 * Return value:
 *    error code
 =============================================================================================*/
int WipsScanUsingNL(char * results_buf_ptr,int cached, int timeout_val,
    int* pFreq, int num_of_freq, LOWIRequest* request)
{
  int err;
  uint64 req_time;
  WIPSIW_ENTER

  // Save the request in global variable
  parseFullBeacon = false;
  if ( (NULL != request) && (LOWIRequest::DISCOVERY_SCAN == request->getRequestType ()) )
  {
    LOWIDiscoveryScanRequest* disc = (LOWIDiscoveryScanRequest*) request;
    parseFullBeacon = disc->getFullBeaconScanResponse();
  }

  // Initialize the nl AP store
  init_wips_nl_ap_store_for_next_scan();

  req_time = lowi_get_time_from_boot();

  err = nl80211_init(&nlstate);
  if (0 == err)
  {
    do
    {
      // Only continue if the init is successful.
      if (FALSE == cached)
      {
        if ( timeout_val >= 0)
        {
          err = do_trigger_scan(&nlstate, pFreq, num_of_freq, request);

          if (-EINVAL == err || -ENODEV == err)
          {
            LOWI_LOG_ERROR ("%s:Trigger scan failed, err: %d\n", __FUNCTION__, err);
            break;
          }
          // For all other unknown error cases we could potentially leverage the scans
          // triggered by wpa_supplicant so we should continue.
        }

        // Now that a scan has been issued, listen to incoming events on Scan multicast socket
        LOWI_LOG_DBG ( "%s:wait %d sec for netlink message\n", __FUNCTION__, timeout_val);
        err = do_listen_events(&nlstate, timeout_val);
      }
      else
      {
        // In case of a cached scan request also, initialize the request time
        wipsiw_scan_req_time = lowi_get_time_from_boot ();
      }

      if (err >= 0)
      {
        do_scan_dump(&nlstate,results_buf_ptr);
      }
      else
      {
        LOWI_LOG_DBG ( "No dump done. Error %d",err);
      }
    }
    while (0);

    LOWI_LOG_DBG ("%s: passive scan cached %d, took %d ms, err %d", __FUNCTION__,
        cached, (uint32) (lowi_get_time_from_boot() - req_time), err);
  }
  else
  {
    //Error in NL socket creation
    //If doing Passive scan, just wait for next command from Controller
    // for 5 seconds
    if (timeout_val < 0)
    {
      err = wips_wait_on_nl_socket(NULL, WIPS_WAIT_NL_FAIL);
    }
  }
  WIPSIW_EXIT
  return err;
}

/*=============================================================================================
 * Function description:
 *   Looks up Wiphy info using NL80211 Interface and parses the supported channels.
 *
 * Parameters:
 *   s_ch_info: Contains the 2G and 5G supported channels
 *
 * Return value:
 *    error code - 0 = SUCCESS
 =============================================================================================*/
int WipsGetSupportedChannels(s_ch_info* p_ch_info)
{
  int err;
  LOWI_LOG_VERB ( "%s\n", __FUNCTION__);
  if (NULL == p_ch_info)
  {
    LOWI_LOG_ERROR ( "%s:invalid argument\n", __FUNCTION__);
    return -1;
  }

  err = nl80211_init(&nlstate);
  if (0 == err)
  {
    p_ch_info->num_2g_ch = 0;
    p_ch_info->num_5g_ch = 0;
    err = nl_get_wiphy_info (nlstate.nl_sock, p_ch_info);
  }
  LOWI_LOG_DBG ( "%s: nl_get_wiphy_info err = %d\n", err, __FUNCTION__);
  return err;
}

int WipsSendActionFrame(uint8* frameBody,
                        uint32 frameLen,
                        uint32 freq,
                        uint8 destMac[BSSID_SIZE],
                        uint8 selfMac[BSSID_SIZE])
{
  WIPSIW_ENTER
  struct nl_msg * msg;
  struct nl_cb * cb;
  int err = 0, l=0;
  struct nl80211_state* pstate = &nlstate;
  uint8 frameBuff[2000];
  char frameChar[2000];
  uint32 i;
  tANI_U32 dur = 20;

  LOWI_LOG_DBG(">>> ENTER: %s  frameLen(%u) freq(%u) srcMac(" LOWI_MACADDR_FMT
               ") selfMac(" LOWI_MACADDR_FMT ")\n", __FUNCTION__, frameLen,
               freq, LOWI_MACADDR(destMac), LOWI_MACADDR(selfMac));

  Wlan80211FrameHeader frameHeader;
  memset(&frameHeader, 0, sizeof(Wlan80211FrameHeader));

  frameHeader.frameControl = IEEE80211_FRAME_CTRL(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
  memcpy(frameHeader.addr1, destMac, BSSID_SIZE);
  memcpy(frameHeader.addr2, selfMac, BSSID_SIZE);
  memcpy(frameHeader.addr3, destMac, BSSID_SIZE);

  LOWI_LOG_DBG("%s - AP Mac " LOWI_MACADDR_FMT " Self Mac " LOWI_MACADDR_FMT " BSSID Mac " LOWI_MACADDR_FMT,
               __FUNCTION__,
               LOWI_MACADDR(frameHeader.addr1),
               LOWI_MACADDR(frameHeader.addr2),
               LOWI_MACADDR(frameHeader.addr3));

  memset(frameBuff, 0, sizeof(frameBuff));
  memcpy(frameBuff, &frameHeader, sizeof(frameHeader));

  memcpy((frameBuff + sizeof(frameHeader)), frameBody, frameLen);

  msg = Wips_nl_msg_alloc(pstate, NL80211_CMD_FRAME, 0);
  if (!msg)
  {
    LOWI_LOG_DBG ( "failed to allocate netlink message\n");
    return 2;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb)
  {
    LOWI_LOG_DBG ( "failed to allocate netlink callbacks\n");
    err = 2;
    goto out_free_msg;
  }

  /* Add Channel Here */
  NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
  /* Add Wait Duration Here */
  NLA_PUT_U32(msg, NL80211_ATTR_DURATION, dur);
  NLA_PUT_FLAG(msg, NL80211_ATTR_TX_NO_CCK_RATE);
  /* Add ACK or No ACK flag Here */
  NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
  /* Add Frame here */
  NLA_PUT(msg, NL80211_ATTR_FRAME, (frameLen + sizeof(frameHeader)), frameBuff);

  for (i = 0; i < (frameLen + sizeof(frameHeader)); i++)
  {
    l+=snprintf(frameChar+l, 10, "0x%02x ", frameBuff[i]);
  }

  LOWI_LOG_VERB("%s - The Final Frame: %s", __FUNCTION__, frameChar);

  err = nl_send_auto_complete(pstate->nl_sock, msg);
  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  // NOTE: Not an infinite loop
  while (err > 0)
    nl_recvmsgs(pstate->nl_sock, cb);

  LOWI_LOG_DBG ("%s: the value err is: %d\n", __FUNCTION__, err);

nla_put_failure:
out:
  nl_cb_put(cb);
out_free_msg:
  nlmsg_free(msg);
  WIPSIW_EXIT
  return err;
}
