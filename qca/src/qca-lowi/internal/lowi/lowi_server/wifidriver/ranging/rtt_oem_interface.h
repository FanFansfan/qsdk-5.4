/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        TLV definitions and macros

GENERAL DESCRIPTION
  This file contains the TLV definitions shared by FW and LOWI

Copyright (c) 2015, 2018-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/

#ifndef _RTT_OEM_INTF_H_
#define _RTT_OEM_INTF_H_

// These are added to be able to use the new definitions
// introduced when using TLVs (11/2015)
// Having these definitions here, before #include "rttm.h"
// is critical. DO NOT CHANGE ORDER
#define USE_ALL_OTHER_NEW_DEFS
#define USE_NEW_CAPABILITY_TLV_DEFS
#define USE_NEW_MEAS_REQ_TLV_DEFS
#define USE_NEW_MEAS_RSP_TLV_DEFS
#define USE_NEW_ERROR_RSP_TLV_DEFS
#define USE_NEW_CONFIGURE_LCI_TLV_DEFS
#define USE_NEW_CONFIGURE_LCR_TLV_DEFS
#define USE_NEW_NAN_TLV_DEFS

#include "innavService.h" /* LOWI specific include */
#include "rttm.h" /* original FW defs file used by LOWI */

// used for definitions that came with this file
typedef uint8_t      A_UINT8;
typedef int8_t       A_INT8;
typedef uint16_t     A_UINT16;
typedef int16_t      A_INT16;
typedef uint32_t     A_UINT32;
typedef int32_t      A_INT32;
typedef uint64_t     A_UINT64;
typedef int64_t      A_INT64;
typedef A_UINT8      wmi_mac_addr[8]; // for byte alignment
typedef tANI_TIME64  A_TIME64;


/** values for vdev_type */
typedef enum {
  RTT_WMI_VDEV_TYPE_AP        = 0x1,
  RTT_WMI_VDEV_TYPE_STA       = 0x2,
  RTT_WMI_VDEV_TYPE_NAN       = 0x3,
  RTT_WMI_VDEV_TYPE_P2P_GO    = 0x4,
  RTT_WMI_VDEV_TYPE_P2P_CLI   = 0x5,
} wmi_rtt_vdev_type;

typedef enum {
  RTT_RESP_MODE_ENABLE = 0x0, //responder mode enable
  RTT_RESP_MODE_DISABLE = 0x1, // responder mode disable
} wmi_rtt_set_responder_mode;

/** status of TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_REQ*/
typedef enum {
  RTT_CANCEL_MEAS_REQ_SUCCESS,
  RTT_CANCEL_MEAS_REQ_ID_NOT_FOUND,
  RTT_CANCEL_MEAS_REQ_CMD_FAILED,
} WMI_RTT_CANCEL_MEAS_REQ_STATUS;
#define WMI_F_MS(_v, _f)                                            \
            ( ((_v) & (_f)) >> (_f##_S) )

/*
 * This breaks the "good macro practice" of only referencing each
 * macro field once (to avoid things like field++ from causing issues.)
 */
#define WMI_F_RMW(_var, _v, _f)                                     \
            do {                                                    \
                (_var) &= ~(_f);                                    \
                (_var) |= ( ((_v) << (_f##_S)) & (_f));             \
            } while (0)


typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header; // TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head
    A_UINT32 sub_type; // WMIRTT_OEM_MSG_SUBTYPE
    A_UINT32 req_id; //unique request ID for this RTT oem req
    /******************************************************************************
     *bit 15:0       Request ID
     *bit 16:        sps enable  0- unenable  1--enable
     *bit 31:17      reserved
     ******************************************************************************/
    A_UINT32 pdev_id;
} wmi_rtt_oem_req_head;

typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header; // TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head
    A_UINT32 sub_type; // WMIRTT_OEM_MSG_SUBTYPE
    A_UINT32 req_id; // request ID for which this RTT oem rsp corresponds
    /**result is a bit mask
     *bit 15:0 req_id from measurement request command
     *bit 23:16 status from WMI_RTT_STATUS_INDICATOR
     *bit 24    request fully serviced
     *bit 31:25 reserved
     */
    A_UINT32 fragment_info;
    /*
      * bit 0 more fragments (associate with token_id)
      * bit 5:1 fragment index (associate with token_id; maximum 32 fragments)
      * bit 17:6 fragment length that follows this structure (associate with token_id; maximum length 4096; current limitation 1500; valid only if more fragments of fragment index is non-zero)
      * bit 22:18 token id
      * bit 31-23 reserved
      */
        A_UINT32 pdev_id;
    /**
     *      * pdev_id for identifying the MAC.  See macros starting with WMI_PDEV_ID_ for values.
     *           * In non-DBDC case host should set it to 0
     *                */
    A_UINT32 time_left;
        /**
 *      * Time remaining (units = micro seconds) to finish on-going Ranging request.
 *           */

} wmi_rtt_oem_rsp_head;

typedef struct {
A_UINT32 tlv_header;  // TLV tag and len; tag equals WMIRTT_TLV_TAG_ARRAY_UINT8
A_UINT8   bytes[1];      // placeholder for first byte, other bytes follow; Should be 32 bit aligned
} wmi_rtt_oem_generic_byte_array;


#define WMI_RTT_SUB_TYPE_S 0
#define WMI_RTT_SUB_TYPE (0xffffffff << WMI_RTT_SUB_TYPE_S)
#define WMI_RTT_SUB_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_SUB_TYPE)
#define WMI_RTT_SUB_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SUB_TYPE)

#define WMI_RTT_REQ_ID_S 0
#define WMI_RTT_REQ_ID (0xffff << WMI_RTT_REQ_ID_S)
#define WMI_RTT_REQ_ID_GET(x) WMI_F_MS(x,WMI_RTT_REQ_ID)
#define WMI_RTT_REQ_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REQ_ID)

//SPS here is synchronized power save
#define WMI_RTT_REQ_SPS_S 16
#define WMI_RTT_REQ_SPS (0x1 << WMI_RTT_REQ_SPS_S)
#define WMI_RTT_REQ_SPS_GET(x) WMI_F_MS(x,WMI_RTT_REQ_SPS)
#define WMI_RTT_REQ_SPS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REQ_SPS)

#define WMI_RTT_RSP_STATUS_S 16
#define WMI_RTT_RSP_STATUS (0xff << WMI_RTT_RSP_STATUS_S)
#define WMI_RTT_RSP_STATUS_GET(x) WMI_F_MS(x,WMI_RTT_RSP_STATUS)
#define WMI_RTT_RSP_STATUS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_STATUS)

#define WMI_RTT_RSP_DONE_S 24
#define WMI_RTT_RSP_DONE (0x1 << WMI_RTT_RSP_DONE_S)
#define WMI_RTT_RSP_DONE_GET(x) WMI_F_MS(x,WMI_RTT_RSP_DONE)
#define WMI_RTT_RSP_DONE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_DONE)

#define WMI_RTT_RSP_MORE_FRAG_S 0
#define WMI_RTT_RSP_MORE_FRAG (0x1 << WMI_RTT_RSP_MORE_FRAG_S)
#define WMI_RTT_RSP_MORE_FRAG_GET(x) WMI_F_MS(x,WMI_RTT_RSP_MORE_FRAG)
#define WMI_RTT_RSP_MORE_FRAG_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_MORE_FRAG)

#define WMI_RTT_RSP_FRAG_IDX_S 1
#define WMI_RTT_RSP_FRAG_IDX (0x1f << WMI_RTT_RSP_FRAG_IDX_S)
#define WMI_RTT_RSP_FRAG_IDX_GET(x) WMI_F_MS(x,WMI_RTT_RSP_FRAG_IDX)
#define WMI_RTT_RSP_FRAG_IDX_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_FRAG_IDX)

#define WMI_RTT_RSP_FRAG_LEN_S 6
#define WMI_RTT_RSP_FRAG_LEN (0xfff << WMI_RTT_RSP_FRAG_LEN_S)
#define WMI_RTT_RSP_FRAG_LEN_GET(x) WMI_F_MS(x,WMI_RTT_RSP_FRAG_LEN)
#define WMI_RTT_RSP_FRAG_LEN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_FRAG_LEN)

#define WMI_RTT_RSP_TOKEN_ID_S 18
#define WMI_RTT_RSP_TOKEN_ID (0x1f << WMI_RTT_RSP_TOKEN_ID_S)
#define WMI_RTT_RSP_TOKEN_ID_GET(x) WMI_F_MS(x,WMI_RTT_RSP_TOKEN_ID)
#define WMI_RTT_RSP_TOKEN_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RSP_TOKEN_ID)

#ifdef USE_NEW_CAPABILITY_TLV_DEFS
/************************  TARGET_MSG_SUBTYPE_CAPABILITY_REQ/RSP Start ***************************/

/** Major version number is incremented when there are significant changes to RTT Interface that break compatibility. */
#define RTT_VERSION_MAJOR    1
/** Minor version number is incremented when there are changes
 *  (however minor) to RTT Interface that break
 *  compatibility. */
#define RTT_VERSION_MINOR    0
/** RTT revision number has to be incremented when there is a
 *  change that may or may not break compatibility. */
#define RTT_REVISION 1

/* Format of the version number. */
#define RTT_VER_MAJOR_BIT_OFFSET        24
#define RTT_VER_MINOR_BIT_OFFSET        0

#define RTT_VER_MAJOR_BIT_MASK          0xFF000000
#define RTT_VER_MINOR_BIT_MASK          0x00FFFFFF

/* Macros to extract the sw_version components.
 */
#define RTT_VER_GET_MAJOR(x) (((x) & RTT_VER_MAJOR_BIT_MASK)>>RTT_VER_MAJOR_BIT_OFFSET)
#define RTT_VER_GET_MINOR(x) (((x) & RTT_VER_MINOR_BIT_MASK)>>RTT_VER_MINOR_BIT_OFFSET)

#define RTT_VER_SET_VERSION(major, minor) ( (( major << RTT_VER_MAJOR_BIT_OFFSET ) & RTT_VER_MAJOR_BIT_MASK) + (( minor << RTT_VER_MINOR_BIT_OFFSET ) & RTT_VER_MINOR_BIT_MASK) )


/* RTT service bit mask */
#define RTT_SERVICE_BITMASK_SZ  4

/* Message format for WMI_OEM_REQ_CMDID => TARGET_MSG_SUBTYPE_GET_CHANNEL_INFO_REQ
 * This CMD trigger to provide RTT responder channel information
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_get_channel_info_req_head
 *
 * */
typedef struct { //notice on 32 bit alignment if need do any further change
  A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_req_head
  A_UINT32 version;
  /******************************************************************************
   * bit 23:0       RTT interface minor version number
   * bit 31:24       RTT interface major version number
   *                ******************************************************************************/
  A_UINT32 revision; // RTT_REVISION
} wmi_rtt_oem_get_channel_info_req_head;

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info
    /** primary 20 MHz channel frequency in mhz */
    A_UINT32 mhz;
    /** Center frequency 1 in MHz*/
    A_UINT32 band_center_freq1;
    /** Center frequency 2 in MHz - valid only for 11acvht 80plus80 mode*/
    A_UINT32 band_center_freq2;
    /** channel info described below */
    A_UINT32 info;
    /** contains min power, max power, reg power and reg class id.  */
    A_UINT32 reg_info_1;
    /** contains antennamax */
    A_UINT32 reg_info_2;
} wmi_rtt_oem_channel_info;

/*********************  TARGET_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP  Start *******************************/

/* Message format for WMI_OEM_RESP_EVENTID => TARGET_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP
 * This EVENT provide report from FW
 * Need be careful about 32 bit alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_get_channel_info_rsp_head
 *     wmi_rtt_oem_channel_info
 */

 typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_rsp_head
    A_UINT32 version;
    /******************************************************************************
     *bit 23:0       RTT interface minor version number
     *bit 31:24       RTT interface major version number
     ******************************************************************************/
    A_UINT32 revision; // RTT_REVISION
} wmi_rtt_oem_get_channel_info_rsp_head;

/*********************  TARGET_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP End **********************************/

/* Message format for  WMI_OEM_REQ_CMDID => TARGET_OEM_MSG_SUBTYPE_CFG_RESPONDER_MODE_REQ
 * This CMD trigger to provide RTT Capability information
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_set_responder_mode_req_head
 *
 */
 typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_req_head
    A_UINT32 version;
    /******************************************************************************
     *bit 23:0       RTT interface minor version number
     *bit 31:24       RTT interface major version number
     ******************************************************************************/
    A_UINT32 revision; // RTT_REVISION
    A_UINT8  mode; // RTT responder enable/disable
    A_UINT32 duration; // duration for which responder mode needs to be enabled
    wmi_rtt_oem_channel_info channel_info; // channel hint to be passed from framework to FW
} wmi_rtt_oem_set_responder_mode_req_head;


/*********************  TARGET_MSG_SUBTYPE_SUBTYPE_CFG_RESPONDER_MODE_RSP Start *******************************/

/* Message format for WMI_OEM_RESP_EVENTID => TARGET_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP
 * This EVENT provide report from FW
 * Need be careful about 32 bit alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_set_responder_mode_rsp_head
 *     wmi_rtt_oem_channel_info
 */

 typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_rsp_head
    A_UINT32 version;
    /******************************************************************************
     *bit 23:0       RTT interface minor version number
     *bit 31:24       RTT interface major version number
     ******************************************************************************/
    A_UINT32 revision; // RTT_REVISION
} wmi_rtt_oem_set_responder_mode_rsp_head;

/*********************  TARGET_MSG_SUBTYPE_SUBTYPE_CFG_RESPONDER_MODE_RSP End **********************************/

/*********************  TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_REQ Start *******************************/

/* Message format for  WMI_OEM_REQ_CMDID => TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_REQ
 * This CMD trigger to cancel measurement request previously Queued/Running.
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_cancel_measurement_req_info
 *
 */
typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_req_head
    A_UINT32 req_id; //unique request ID (Queued/Running) which needs to be cancelled.
} wmi_rtt_oem_cancel_measurement_req_info;

/*********************  TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_REQ End *******************************/

/*********************  TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_RSP Start  *******************************/

/* Message format for WMI_OEM_RESP_EVENTID => TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_RSP
 * This EVENT provide cancel measurement request response status
 * Need be careful about 32 bit alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_cancel_measurement_rsp_info
 */
typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_rsp_head
    A_UINT32 req_id; //unique request ID (Queued/Running) which is cancelled.
    A_UINT32 status; //status of cancel ranging request.
} wmi_rtt_oem_cancel_measurement_rsp_info;

/*********************  TARGET_OEM_MSG_SUBTYPE_CANCEL_MEASUREMENT_RSP End **********************************/

/*********************  RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ Start ***********************************/

/* Message format for WMI_OEM_REQ_CMDID => RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ
 * This CMD enables or disables responder measurement
 *
 * Message Format:
 *      wmi_rtt_oem_req_head
 *      wmi_rtt_oem_cfg_resp_meas_req_head
 */

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cfg_resp_meas_req_head
    A_UINT32 config;
    /******************************************************************************
     *bit 0:3       report type
     *bit 4         responder measurement enable / disable
     ******************************************************************************/
} wmi_rtt_oem_cfg_resp_meas_req_head;

#define WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE_S 0
#define WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE (0xf << WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE_S)
#define WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE)
#define WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE_SET(x,y)  WMI_F_RMW(x,y,WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE)



#define WMI_RTT_CFG_RESP_MEAS_REQ_ENABLE_S 4
#define WMI_RTT_CFG_RESP_MEAS_REQ_ENABLE (0x1 << WMI_RTT_CFG_RESP_MEAS_REQ_ENABLE_S)

typedef enum {
    RTT_RESP_REPORT_PER_FRAME,
    RTT_RESP_REPORT_PER_FRAME_WITH_CFR,
    RTT_RESP_REPORT_PER_FRAME_WITH_CFR_CIR,
} wmi_rtt_resp_report_type;

/*********************  RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ End ***********************************/

/*********************  RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_RSP Start ***********************************/

/* Message format for WMI_OEM_RESPONSE_EVENTID => RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP
 * This EVENT reports the status of a RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ
 *
 * Message Format:
 *      wmi_rtt_oem_rsp_head
 */

/*********************  RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_RSP End ***********************************/

/*********************  RTT_MSG_SUBTYPE_RESPONDER_MEASUREMENT_RSP Start ***********************************/

/* Message format for WMI_OEM_REQ_CMDID => RTT_MSG_SUBTYPE_RESPONDER_MEASUREMENT_RSP
 * This CMD provides responder measurement results
 *
 * Message Format:
 *      wmi_rtt_oem_rsp_head
 *      wmi_rtt_oem_responder_measrsp_head
 *      loop_start
 *          wmi_rtt_oem_per_frame_info
 *          byte array TLV including raw rx_location_info data
 *          if report type is RTT_RESP_REPORT_PER_FRAME_WITH_CFR or RTT_RESP_REPORT_PER_FRAME_WITH_CFR_CIR
 *              byte array TLV including raw CFR/CIR capture data
 *          end if
 *      loop end
 */

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_responder_measrsp_head
    wmi_mac_addr dest_mac;
    A_UINT32 info;
    /******************************************************************************
     *bit 0:3       report type
     *bit 4         last TM frame of a TM sequence
     *bit 5         first TM frame of a TM sequence
     ******************************************************************************/
    A_UINT32 channel_info;  // channel frequency in MHz
} wmi_rtt_oem_responder_measrsp_head;

#define WMI_RTT_RESP_MEAS_RSP_REPORT_TYPE_S 0
#define WMI_RTT_RESP_MEAS_RSP_REPORT_TYPE (0xf << WMI_RTT_RESP_MEAS_RSP_REPORT_TYPE_S)

#define WMI_RTT_RESP_MEAS_RSP_TM_FINISH_S 4
#define WMI_RTT_RESP_MEAS_RSP_TM_FINISH (1 << WMI_RTT_RESP_MEAS_RSP_TM_FINISH_S)

#define WMI_RTT_RESP_MEAS_RSP_TM_START_S 5
#define WMI_RTT_RESP_MEAS_RSP_TM_START (1 << WMI_RTT_RESP_MEAS_RSP_TM_START_S)

/*********************  RTT_MSG_SUBTYPE_RESPONDER_MEASUREMENT_RSP End ***********************************/

/* Message format for WMI_OEM_REQ_CMDID => TARGET_MSG_SUBTYPE_CAPABILITY_REQ
 * This CMD trigger to provide RTT Capability information
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_cap_req_head
 *
 */
 typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_req_head
    A_UINT32 version;
    /******************************************************************************
     *bit 23:0       RTT interface minor version number
     *bit 31:24       RTT interface major version number
     ******************************************************************************/
    A_UINT32 revision; // RTT_REVISION
} wmi_rtt_oem_cap_req_head;

/* Message format for WMI_OEM_RESP_EVENTID => TARGET_OEM_MSG_SUBTYPE_CAPABILITY_RSP
 * This EVENT provides RTT Capabiity information
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_cap_rsp_head
 *     wmi_rtt_oem_cap_rsp_event
 */

 typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_head
    A_UINT32 version;
    /******************************************************************************
     *bit 23:0       RTT interface minor version number
     *bit 31:24       RTT interface major version number
     ******************************************************************************/
    A_UINT32 revision; // RTT_REVISION
    A_UINT32 service_bitmask[RTT_SERVICE_BITMASK_SZ];
} wmi_rtt_oem_cap_rsp_head;

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_event
    A_UINT32 support;
    /**************************************************************************
     * Bit 8 - 0 Version support
     *    bit 0 -- One Sided RTT
     *    Bit 1 -- Two sided RTT (802.11mc)
     *    Bit 7 - 2 Reserved
     * Bit 15 - 8 Supported Frame types
     *    Bit 8   NULL Frame
     *    Bit 9   QoS_NULL Frame
     *    Bit 10  TMR/TM frame
     *    Bit 11  F-TMR/TM
     *    Bit 12  CTS/RTS
     *    Bit 13-15 : Reserved
     * Bit 23 - 16: Max Dests Allowed (how many destinations supported over multiple meas cmd)
     * Bit 31 - 24: Max Measurements per dest
     **************************************************************************/
    A_UINT32 cap;
    /**************************************************************************
     *Bit 7 - 0 Max Channels allowed  (how many channels supported over multiple meas cmd)
     *Bit 15 - 8 Max BW allowed
     *    0 - 20MHz, 1-40MHz, 2-80MHz, 3 -160MHz
     *Bit 23 - 16 Preamble Support
     *    Bit 16 -- Legacy
     *    Bit 17 -- HT
     *    Bit 18-- VHT
     *    Bit 19-23: Reserved
     *Bit 24 - 31 Report types support
     *    Bit 24  Report per frame with CFR
     *    Bit 25  Report Per frame without CFR
     *    Bit 26  Aggregate Report without CFR
     *    Bit 27 Report per burst without CFR
     **************************************************************************/
    A_UINT32 cap_2;
    /**************************************************************************
     *Bit 7 - 0  Maximum chain mask, eg. Peregrine 0x07
     *Bit 15 - 8 FAC support, 0-No FAC, 1- SW IFFT 2 -HW-IFFT
     *Bit 24 - 16 # of radios
     *Bit 25 - Multiburst support
     *Bit 29-26 - Maximum supported multiburst sessions (currently 2)
     *Bit 31 - 30  Reserved
     *************************************************************************/
} wmi_rtt_oem_cap_rsp_event;

#define WMI_RTT_CAP_ONESIDED_RTT               (0x01)
#define WMI_RTT_CAP_TWOSIDED_RTT               (0x02)
#define WMI_RTT_CAP_NULL                       (0x01)
#define WMI_RTT_CAP_QOS_NULL                   (0x02)
#define WMI_RTT_CAP_TMR                        (0x04)
#define WMI_RTT_CAP_FTMR                       (0x08)
#define WMI_RTT_CAP_RTS                        (0x10)
#define WMI_RTT_CAP_20M                        (0x0)
#define WMI_RTT_CAP_40M                        (0x01)
#define WMI_RTT_CAP_80M                        (0x02)
#define WMI_RTT_CAP_160M                       (0x03)
#define WMI_RTT_CAP_LEGACY                     (0x01)
#define WMI_RTT_CAP_HT                         (0x02)
#define WMI_RTT_CAP_VHT                        (0x04)
#define WMI_RTT_CAP_REPORT_PER_FRAME_CFR       (0x01)
#define WMI_RTT_CAP_REPORT_PER_FRAME_NO_CFR    (0x02)
#define WMI_RTT_CAP_REPORT_AGGREGATE_NO_CFR    (0x04)
#define WMI_RTT_CAP_REPORT_PER_BURST_NO_CFR    (0x08)
#define WMI_RTT_CAP_NO_FAC                     (0x0)
#define WMI_RTT_CAP_SW_FAC                     (0x01)
#define WMI_RTT_CAP_HW_FAC                     (0x02)

#define WMI_RTT_CAP_VER_S 0
#define WMI_RTT_CAP_VER (0xff <<  WMI_RTT_CAP_VER_S)
#define WMI_RTT_CAP_VER_GET(x) WMI_F_MS(x, WMI_RTT_CAP_VER)
#define WMI_RTT_CAP_VER_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_VER)

#define WMI_RTT_CAP_FRAME_S 8
#define WMI_RTT_CAP_FRAME (0xff <<  WMI_RTT_CAP_FRAME_S)
#define WMI_RTT_CAP_FRAME_GET(x) WMI_F_MS(x, WMI_RTT_CAP_FRAME)
#define WMI_RTT_CAP_FRAME_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_FRAME)

#define WMI_RTT_CAP_MAX_DES_NUM_S 16
#define WMI_RTT_CAP_MAX_DES_NUM (0xff <<  WMI_RTT_CAP_MAX_DES_NUM_S)
#define WMI_RTT_CAP_MAX_DES_NUM_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_DES_NUM)
#define WMI_RTT_CAP_MAX_DES_NUM_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_DES_NUM)

#define WMI_RTT_CAP_MAX_MEAS_NUM_S 24
#define WMI_RTT_CAP_MAX_MEAS_NUM (0xff <<  WMI_RTT_CAP_MAX_MEAS_NUM_S)
#define WMI_RTT_CAP_MAX_MEAS_NUM_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_MEAS_NUM)
#define WMI_RTT_CAP_MAX_MEAS_NUM_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_MEAS_NUM)

#define WMI_RTT_CAP_MAX_CHAN_NUM_S 0
#define WMI_RTT_CAP_MAX_CHAN_NUM (0xff <<  WMI_RTT_CAP_MAX_CHAN_NUM_S)
#define WMI_RTT_CAP_MAX_CHAN_NUM_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_CHAN_NUM)
#define WMI_RTT_CAP_MAX_CHAN_NUM_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_CHAN_NUM)

#define WMI_RTT_CAP_MAX_BW_S 8
#define WMI_RTT_CAP_MAX_BW (0xff <<  WMI_RTT_CAP_MAX_BW_S)
#define WMI_RTT_CAP_MAX_BW_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_BW)
#define WMI_RTT_CAP_MAX_BW_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_BW)

#define WMI_RTT_CAP_PREAMBLE_S 16
#define WMI_RTT_CAP_PREAMBLE (0xff <<  WMI_RTT_CAP_PREAMBLE_S)
#define WMI_RTT_CAP_PREAMBLE_GET(x) WMI_F_MS(x, WMI_RTT_CAP_PREAMBLE)
#define WMI_RTT_CAP_PREAMBLE_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_PREAMBLE)

#define WMI_RTT_CAP_REPORT_TYPE_S 24
#define WMI_RTT_CAP_REPORT_TYPE (0xff <<  WMI_RTT_CAP_REPORT_TYPE_S)
#define WMI_RTT_CAP_REPORT_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_CAP_REPORT_TYPE)
#define WMI_RTT_CAP_REPORT_TYPE_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_REPORT_TYPE)

#define WMI_RTT_CAP_MAX_CHAIN_MASK_S 0
#define WMI_RTT_CAP_MAX_CHAIN_MASK (0xff <<  WMI_RTT_CAP_MAX_CHAIN_MASK_S)
#define WMI_RTT_CAP_MAX_CHAIN_MASK_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_CHAIN_MASK)
#define WMI_RTT_CAP_MAX_CHAIN_MASK_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_CHAIN_MASK)

#define WMI_RTT_CAP_FAC_S 8
#define WMI_RTT_CAP_FAC (0xff <<  WMI_RTT_CAP_FAC_S)
#define WMI_RTT_CAP_FAC_GET(x) WMI_F_MS(x, WMI_RTT_CAP_FAC)
#define WMI_RTT_CAP_FAC_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_FAC)

#define WMI_RTT_CAP_RADIO_NUM_S 16
#define WMI_RTT_CAP_RADIO_NUM (0xff <<  WMI_RTT_CAP_RADIO_NUM_S)
#define WMI_RTT_CAP_RADIO_NUM_GET(x) WMI_F_MS(x, WMI_RTT_CAP_RADIO_NUM)
#define WMI_RTT_CAP_RADIO_NUM_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_RADIO_NUM)

#define WMI_RTT_CAP_MULTIBURST_SUPPORT_S 25
#define WMI_RTT_CAP_MULTIBURST_SUPPORT (0x1 <<  WMI_RTT_CAP_MULTIBURST_SUPPORT_S)
#define WMI_RTT_CAP_MULTIBURST_SUPPORT_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MULTIBURST_SUPPORT)
#define WMI_RTT_CAP_MULTIBURST_SUPPORT_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MULTIBURST_SUPPORT)

#define WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS_S 26
#define WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS (0xf <<  WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS_S)
#define WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS_GET(x) WMI_F_MS(x, WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS)
#define WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS_SET(x,y)  WMI_F_RMW(x,y, WMI_RTT_CAP_MAX_MULTIBURST_SESSIONS)


/************************  TARGET_MSG_SUBTYPE_CAPABILITY_REQ/RSP End *****************************/
#endif

#ifdef USE_NEW_MEAS_REQ_TLV_DEFS
/*********************  TARGET_MSG_SUBTYPE_MEASUREMENT_REQ/RSP Start *****************************/

/* Message format for WMI_OEM_REQ_CMDID => TARGET_MSG_SUBTYPE_MEASUREMENT_REQ
 * This CMD trigger FW to start measurement with given peers and specified channels
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_measreq_head
 *     loop controlled by channel_cnt in wmi_rtt_oem_measreq_head
 *         wmi_rtt_oem_channel_info
 *         wmi_rtt_oem_measreq_per_channel_info
 *         loop controlled by sta_num in wmi_rtt_oem_measreq_per_channel_info
 *                 wmi_rtt_oem_measreq_peer_info
 *         loop end
 *    loop end
 */

typedef struct { //notice on 32 bit alignment if need do any further change
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_head
    A_UINT32 channel_cnt; // how many number of channels in this RTT requirement
    /******************************************************************************
     *bit 7:0        # of measurement channels
     *bit 31:8       reserved
     ******************************************************************************/
} wmi_rtt_oem_measreq_head;


typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_per_channel_info
    /* how many number of STA for this channel in this RTT requirement */
    A_UINT32 sta_num;
    /******************************************************************************
     *bit 7:0        # of measurement peers
     *bit 23:8       if  sps, time delay for SPS (ms)
     *bit 31:24      reserved
     ******************************************************************************/
}wmi_rtt_oem_measreq_per_channel_info;

typedef struct { //any new change need take care of 32 alignment
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_peer_info
    A_UINT32 control_flag; // some control information here
    /*********************************************************************************
     *Bits 2:0:   802.11 Frame Type to measure RTT
     *            000: NULL, 001: Qos NULL, 010: TMR-TM
     *Bits 6:3:   Tx chain mask used for transmission 0000 - 1111
     *Bits 10:7:  Receive chainmask to use for reception 0000 - 1111
     *Bits 11:11  peer is qca chip or not
     *Bits 14:12: BW 0- 20MHz 1- 40MHz 2- 80MHz 3 - 160 MHz
     *Bits 16:15: Preamble 0- Legacy 2- HT 3-VHT
     *Bits 20:17: Retry times
     *Bits 28:21: MCS
     *Bit  29:    ack type in FTM transactions
     *            0 - default, use high speed acks with QTI peers
     *            1 - use only legacy acks regardless of peer
     *Bits 31:30  Reserved
     *********************************************************************************/
    A_UINT32 measure_info;
    /*******************************************************************************
     *Bit 3:0:   vdev_type vdev used for RTT
     *Bit 11:4:  num_meas #of measurements of each peer
     *Bit 19:12: timeout for this rtt mesurement for one burst (ms)
     *Bit 23:20: report_type
     *Bit 31:24: Reserved
     *******************************************************************************/
    wmi_mac_addr dest_mac; //destination mac address for measurement
    wmi_mac_addr spoof_bssid; //spoof BSSID for measurement with unassociated STA
    A_UINT32 measure_params_1;
    /*******************************************************************************
     *Bit 0:       ASAP = 0/1
     *Bit 1:       LCI Req = True/False
     *Bit 2:       Location Civic Req = True/False
     *Bit 3:       PTSF timer no preference. Used in iFTMR to indicate validity of PTSF timer field in the frame
     *Bits 7:4:    Number of Bursts Exponent
     *Bits 11:8:   Burst Duration (Maximum 128ms)
     *Bits 27:12:  Burst Period (time between Burst starts)
     *Bits 31:28:  Reserved
     *******************************************************************************/
    A_UINT32 measure_params_2;
    /*******************************************************************************
     *Bits 31:0:   Reserved
     *******************************************************************************/
} wmi_rtt_oem_measreq_peer_info;


//Bit map macro define for RTT measurement command
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

#define WMI_RTT_NUM_CHAN_S 0
#define WMI_RTT_NUM_CHAN (0xff << WMI_RTT_NUM_CHAN_S)
#define WMI_RTT_NUM_CHAN_GET(x) WMI_F_MS(x,WMI_RTT_NUM_CHAN)
#define WMI_RTT_NUM_CHAN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_NUM_CHAN)

#define WMI_RTT_NUM_STA_S 0
#define WMI_RTT_NUM_STA (0xff << WMI_RTT_NUM_STA_S)
#define WMI_RTT_NUM_STA_GET(x) WMI_F_MS(x,WMI_RTT_NUM_STA)
#define WMI_RTT_NUM_STA_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_NUM_STA)

#define WMI_RTT_SPS_DELAY_S 8
#define WMI_RTT_SPS_DELAY (0xffff << WMI_RTT_SPS_DELAY_S)
#define WMI_RTT_SPS_DELAY_GET(x) WMI_F_MS(x,WMI_RTT_SPS_DELAY)
#define WMI_RTT_SPS_DELAY_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SPS_DELAY)

#define WMI_RTT_FRAME_TYPE_S 0
#define WMI_RTT_FRAME_TYPE (7 << WMI_RTT_FRAME_TYPE_S)
#define WMI_RTT_FRAME_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_FRAME_TYPE)
#define WMI_RTT_FRAME_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_FRAME_TYPE)

#define WMI_RTT_TX_CHAIN_S 3
#define WMI_RTT_TX_CHAIN (0xf << WMI_RTT_TX_CHAIN_S)
#define WMI_RTT_TX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_TX_CHAIN)
#define WMI_RTT_TX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TX_CHAIN)

#define WMI_RTT_RX_CHAIN_S 7
#define WMI_RTT_RX_CHAIN (0xf << WMI_RTT_RX_CHAIN_S)
#define WMI_RTT_RX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_RX_CHAIN)
#define WMI_RTT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RX_CHAIN)

#define WMI_RTT_QCA_PEER_S 11
#define WMI_RTT_QCA_PEER (0x1 << WMI_RTT_QCA_PEER_S)
#define WMI_RTT_QCA_PEER_GET(x) WMI_F_MS(x,WMI_RTT_QCA_PEER)
#define WMI_RTT_QCA_PEER_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_QCA_PEER)

#define WMI_RTT_BW_S 12
#define WMI_RTT_BW (0x7 <<WMI_RTT_BW_S)
#define WMI_RTT_BW_GET(x) WMI_F_MS(x,WMI_RTT_BW)
#define WMI_RTT_BW_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_BW)

#define WMI_RTT_PREAMBLE_S 15
#define WMI_RTT_PREAMBLE (0x3 <<WMI_RTT_PREAMBLE_S)
#define WMI_RTT_PREAMBLE_GET(x) WMI_F_MS(x,WMI_RTT_PREAMBLE)
#define WMI_RTT_PREAMBLE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_PREAMBLE)

#define WMI_RTT_RETRIES_S 17
#define WMI_RTT_RETRIES (0xf << WMI_RTT_RETRIES_S)
#define WMI_RTT_RETRIES_GET(x) WMI_F_MS(x,WMI_RTT_RETRIES)
#define WMI_RTT_RETRIES_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RETRIES)

#define WMI_RTT_MCS_S 21
#define WMI_RTT_MCS (0xff << WMI_RTT_MCS_S)
#define WMI_RTT_MCS_GET(x) WMI_F_MS(x,WMI_RTT_MCS)
#define WMI_RTT_MCS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MCS)

#define WMI_RTT_FORCE_LEGACY_ACK_S 29
#define WMI_RTT_FORCE_LEGACY_ACK (0x1 << WMI_RTT_FORCE_LEGACY_ACK_S)
#define WMI_RTT_FORCE_LEGACY_ACK_GET(x) WMI_F_MS(x,WMI_RTT_FORCE_LEGACY_ACK)
#define WMI_RTT_FORCE_LEGACY_ACK_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_FORCE_LEGACY_ACK)

#define WMI_RTT_VDEV_TYPE_S 0
#define WMI_RTT_VDEV_TYPE (0xf << WMI_RTT_VDEV_TYPE_S)
#define WMI_RTT_VDEV_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_VDEV_TYPE)
#define WMI_RTT_VDEV_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_VDEV_TYPE)

#define WMI_RTT_MEAS_NUM_S 4
#define WMI_RTT_MEAS_NUM (0xff << WMI_RTT_MEAS_NUM_S)
#define WMI_RTT_MEAS_NUM_GET(x) WMI_F_MS(x,WMI_RTT_MEAS_NUM)
#define WMI_RTT_MEAS_NUM_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MEAS_NUM)

#define WMI_RTT_TIMEOUT_S 12
#define WMI_RTT_TIMEOUT (0xff << WMI_RTT_TIMEOUT_S)
#define WMI_RTT_TIMEOUT_GET(x) WMI_F_MS(x,WMI_RTT_TIMEOUT)
#define WMI_RTT_TIMEOUT_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TIMEOUT)

#define WMI_RTT_REPORT_TYPE_S 20
#define WMI_RTT_REPORT_TYPE (0xf <<WMI_RTT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_TYPE)
#define WMI_RTT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_TYPE)

#define WMI_RTT_ASAP_MODE_S 0
#define WMI_RTT_ASAP_MODE (0x1 <<WMI_RTT_ASAP_MODE_S)
#define WMI_RTT_ASAP_MODE_GET(x) WMI_F_MS(x,WMI_RTT_ASAP_MODE)
#define WMI_RTT_ASAP_MODE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_ASAP_MODE)

#define WMI_RTT_LCI_REQ_S 1
#define WMI_RTT_LCI_REQ (0x1 <<WMI_RTT_LCI_REQ_S)
#define WMI_RTT_LCI_REQ_GET(x) WMI_F_MS(x,WMI_RTT_LCI_REQ)
#define WMI_RTT_LCI_REQ_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_REQ)

#define WMI_RTT_LOC_CIV_REQ_S 2
#define WMI_RTT_LOC_CIV_REQ (0x1 <<WMI_RTT_LOC_CIV_REQ_S)
#define WMI_RTT_LOC_CIV_REQ_GET(x) WMI_F_MS(x,WMI_RTT_LOC_CIV_REQ)
#define WMI_RTT_LOC_CIV_REQ_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LOC_CIV_REQ)

#define WMI_RTT_NUM_BURST_EXP_S 4
#define WMI_RTT_NUM_BURST_EXP (0xf <<WMI_RTT_NUM_BURST_EXP_S)
#define WMI_RTT_NUM_BURST_EXP_GET(x) WMI_F_MS(x,WMI_RTT_NUM_BURST_EXP)
#define WMI_RTT_NUM_BURST_EXP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_NUM_BURST_EXP)

#define WMI_RTT_BURST_DUR_S 8
#define WMI_RTT_BURST_DUR (0xf <<WMI_RTT_BURST_DUR_S)
#define WMI_RTT_BURST_DUR_GET(x) WMI_F_MS(x,WMI_RTT_BURST_DUR)
#define WMI_RTT_BURST_DUR_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_BURST_DUR)

#define WMI_RTT_PTSF_TIMER_S 3
#define WMI_RTT_PTSF_TIMER (0x1 <<WMI_RTT_PTSF_TIMER_S)
#define WMI_RTT_PTSF_TIMER_GET(x) WMI_F_MS(x,WMI_RTT_PTSF_TIMER)
#define WMI_RTT_PTSF_TIMER_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_PTSF_TIMER)

#define WMI_RTT_BURST_PERIOD_S 12
#define WMI_RTT_BURST_PERIOD (0xffff <<WMI_RTT_BURST_PERIOD_S)
#define WMI_RTT_BURST_PERIOD_GET(x) WMI_F_MS(x,WMI_RTT_BURST_PERIOD)
#define WMI_RTT_BURST_PERIOD_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_BURST_PERIOD)

#define WMI_RTT_TSF_DELTA_S 0
#define WMI_RTT_TSF_DELTA (0xffffffff <<WMI_RTT_TSF_DELTA_S)
#define WMI_RTT_TSF_DELTA_GET(x) WMI_F_MS(x,WMI_RTT_TSF_DELTA)
#define WMI_RTT_TSF_DELTA_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TSF_DELTA)
#endif

#ifdef USE_NEW_MEAS_RSP_TLV_DEFS
/* Message format for WMI_OEM_RESP_EVENTID => TARGET_OEM_MSG_SUBTYPE_MEASUREMENT_RSP
 * This EVENT provide measurement response from FW
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_measrsp_head
 *     if report_type is 0 or 1 in info field of wmi_rtt_oem_measrsp_head
 *         wmi_rtt_oem_per_frame_info
 *         Byte array TLV including rssi + CFR dump for each chain
 *     else if report_type is 2 or 3 in info field of wmi_rtt_oem_measrsp_head
 *         loop based on num of AP in info field of wmi_rtt_oem_measrsp_head (For report type 3, num of APs would always be 1)
 *             wmi_rtt_oem_per_peer_event_hdr
 *             Byte array TLV including all IEs of format wmi_rtt_oem_ie (LCI, LCR etc)
 *             loop based on num of meas reports in control field of wmi_rtt_oem_per_peer_event_hdr
 *                     wmi_rtt_oem_per_frame_info
 *                 end elseif
 *             loop end
 *         loop end
 *     end elseif
 *
 */

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head
    A_UINT32 info;
    /*
     * bit 8:0: Report type (0,1,2,3)
     * bit 9: Reserved
     * bit 14:10 RTT measurement Type 000 - NULL 001-QoS_NULL 002 -TMR (one sided rtt ignore) (report type 2,3 ignore)
     * bit 17:15 Two sided report status (one sided rtt ignore) (report type 2,3 ignore)
     *    00-Good 01 - Bad CFR 10 -- bad token
     * bit 18:   Two sided RTT accomplishment (one sided rtt ignore) (report type 2,3 ignore)
     *    0 - sending side is not finishing
     *    1 - sending side finish
     * bit 19: Two sided RTT start of a TM sequence (one sided rtt ignore) (report type 2,3 ignore)
     *    0 - not a start frame  1 -- start frame
     * bit 23:20: #of AP inside this report (valid for report type 2,3; 0,1 ignore)
     * bit 31:24: reserved
     */
    wmi_mac_addr dest_mac; // valid for report type 0 and 1, MAC of the AP; valid also for error_report subtype irrespective of report_type
    A_UINT32 channel_info; // valid for report type 2 and 3, channel info; not valid for error_report subtype
} wmi_rtt_oem_measrsp_head;

typedef struct {
    A_UINT32 info;
   /** bits 15:0     IE Element ID
    *  bits 31:16    Length */
    A_UINT32 bytes;
}wmi_rtt_oem_ie;

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr
    wmi_mac_addr dest_mac;
    A_UINT32 control;
   /** bits 7:0 #of measurement reports in this AP
     * bits 10:8 RTT measurement type
     * bits 11 Peer chip is qca or not, if known.(1=yes, 0=no/unknown)
     * bits 31:12 reserved */
    A_UINT32 result_info1;
    /** bits 15:0: num_frames_attempted
     *  bits 31:16: actual_burst_duration */
    A_UINT32 result_info2;
    /** bits 7:0:   actual_num_frames_per_burst
     *  bits 15:8: retry_after_duration
     *  bits 23:16 actual_burst_exp
     *  bits 24:31 num_ie_in_hdr */
    A_UINT32 result_info3;
    /**
     * bit 15:0: burst index (valid for report type 3; 0,1,2 ignore) */
    A_UINT32 meas_start_tsf;
    /**
     * lower 4 bytes of TSF: provides measurement time in usecs */
} wmi_rtt_oem_per_peer_event_hdr;

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info
    A_UINT32 rssi;
    A_TIME64 t1; //tod; resolution picoseconds
    A_TIME64 t2; // resolution picoseconds; valid for two-sided RTT only
    A_UINT32 t3_del; // t3-t2 for two-sided RTT; resolution picoseconds; valid for two-sided RTT only
    A_UINT32 t4_del; // toa-tod for one-sided RTT; t4-t1 for two-sided RTT: resolution picoseconds;
    A_UINT32 tx_rate_info_1;
    /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
     *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
     *  bits 7:    reserved
     *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
     *                           ieee std in the units of 0.5mbps
     *                         - HT/VHT it would be mcs index
     *  bits 19:16: tx chain mask for RTT frame
     *  31:20: reserved  */
    A_UINT32 tx_rate_info_2;
    /** bits 31:0: TX bit rate in 100kbps */
    A_UINT32 rx_rate_info_1;
    /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
     *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
     *  bits 7:    reserved
     *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
     *                           ieee std in the units of 0.5mbps
     *                         - HT/VHT it would be mcs index
     *  bits 19:16: HW rx chain mask
     *  bits 23:20: rx chain mask for RTT frame
     *  31:24: reserved  */
    A_UINT32 rx_rate_info_2;
    /** bits 31:0: TX bit rate in 100kbps */
    A_UINT32 max_tod_toa_error;
    /*******************************************************************************
     *Bits 15:0:   Max TOD Error
     *Bits 31:16: Max TOA Error
     *******************************************************************************/

} wmi_rtt_oem_per_frame_info;

#define RTT_V3_GOOD 0x0
#define RTT_V3_BAD_CFR 0x1
#define RTT_V3_BAD_TOKEN 0x2

//define RTT report macro
#define WMI_RTT_REPORT_REQ_ID_S 0
#define WMI_RTT_REPORT_REQ_ID (0xffff << WMI_RTT_REPORT_REQ_ID_S)
#define WMI_RTT_REPORT_REQ_ID_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REQ_ID)
#define WMI_RTT_REPORT_REQ_ID_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REQ_ID)

#define WMI_RTT_REPORT_CHAN_INFO_S 0
#define WMI_RTT_REPORT_CHAN_INFO (0xffffffff << WMI_RTT_REPORT_CHAN_INFO_S)
#define WMI_RTT_REPORT_CHAN_INFO_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_CHAN_INFO)
#define WMI_RTT_REPORT_CHAN_INFO_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_CHAN_INFO)

#define WMI_RTT_REPORT_REPORT_TYPE_S 0
#define WMI_RTT_REPORT_REPORT_TYPE (0xff << WMI_RTT_REPORT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_REPORT_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REPORT_TYPE)
#define WMI_RTT_REPORT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REPORT_TYPE)

#define WMI_RTT_REPORT_MEAS_TYPE_S 10
#define WMI_RTT_REPORT_MEAS_TYPE (0x1f << WMI_RTT_REPORT_MEAS_TYPE_S)
#define WMI_RTT_REPORT_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_MEAS_TYPE)
#define WMI_RTT_REPORT_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_MEAS_TYPE)

#define WMI_RTT_REPORT_V3_STATUS_S 15
#define WMI_RTT_REPORT_V3_STATUS (0x7 << WMI_RTT_REPORT_V3_STATUS_S)
#define WMI_RTT_REPORT_V3_STATUS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_STATUS)
#define WMI_RTT_REPORT_V3_STATUS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_STATUS)

#define WMI_RTT_REPORT_V3_FINISH_S 18
#define WMI_RTT_REPORT_V3_FINISH (0x1 << WMI_RTT_REPORT_V3_FINISH_S)
#define WMI_RTT_REPORT_V3_FINISH_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_FINISH)
#define WMI_RTT_REPORT_V3_FINISH_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_FINISH)

#define WMI_RTT_REPORT_V3_TM_START_S 19
#define WMI_RTT_REPORT_V3_TM_START (0x1 << WMI_RTT_REPORT_V3_TM_START_S)
#define WMI_RTT_REPORT_V3_TM_START_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_TM_START)
#define WMI_RTT_REPORT_V3_TM_START_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_TM_START)

#define WMI_RTT_REPORT_NUM_AP_S 20     //used for only Report Type 2, 3
#define WMI_RTT_REPORT_NUM_AP (0xf << WMI_RTT_REPORT_NUM_AP_S)
#define WMI_RTT_REPORT_NUM_AP_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_NUM_AP)
#define WMI_RTT_REPORT_NUM_AP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_NUM_AP)

//body start here
#define WMI_RTT_REPORT_RX_CHAIN_S 0
#define WMI_RTT_REPORT_RX_CHAIN (0xf << WMI_RTT_REPORT_RX_CHAIN_S)
#define WMI_RTT_REPORT_RX_CHAIN_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_CHAIN)
#define WMI_RTT_REPORT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_CHAIN)

#define WMI_RTT_REPORT_RX_BW_S 4
#define WMI_RTT_REPORT_RX_BW (0x3 << WMI_RTT_REPORT_RX_BW_S)
#define WMI_RTT_REPORT_RX_BW_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_BW)
#define WMI_RTT_REPORT_RX_BW_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_BW)

#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_S 0
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS (0xff << WMI_RTT_REPORT_TYPE2_NUM_MEAS_S)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NUM_MEAS)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NUM_MEAS)

#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S 8
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE (0x7 << WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)

#define WMI_RTT_REPORT_TYPE2_QTI_PEER_S 11
#define WMI_RTT_REPORT_TYPE2_QTI_PEER (0x1 << WMI_RTT_REPORT_TYPE2_QTI_PEER_S)
#define WMI_RTT_REPORT_TYPE2_QTI_PEER_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_QTI_PEER)
#define WMI_RTT_REPORT_TYPE2_QTI_PEER_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_QTI_PEER)

#define WMI_RTT_REPORT_BUR_IDX_S 0
#define WMI_RTT_REPORT_BUR_IDX (0xffff << WMI_RTT_REPORT_BUR_IDX_S)
#define WMI_RTT_REPORT_BUR_IDX_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_BUR_IDX)
#define WMI_RTT_REPORT_BUR_IDX_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_BUR_IDX)

#define WMI_RTT_REPORT_TSF_S 0
#define WMI_RTT_REPORT_TSF (0xffffffff << WMI_RTT_REPORT_TSF_S)
#define WMI_RTT_REPORT_TSF_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TSF)
#define WMI_RTT_REPORT_TSF_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TSF)

#define WMI_RTT_CHAIN_MASK_S 16
#define WMI_RTT_CHAIN_MASK (0xf << WMI_RTT_CHAIN_MASK_S)
#define WMI_RTT_CHAIN_MASK_GET(x) WMI_F_MS(x, WMI_RTT_CHAIN_MASK)
#define WMI_RTT_CHAIN_MASK_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_CHAIN_MASK)
/*
 * For e.g if chain 0 is used then bit 16 will be set
 * For chain 1 bit 17 will be set
 */
#define WMI_RTT_USED_TX_CHAIN_NUM_MASK_S 16
#define WMI_RTT_USED_TX_CHAIN_NUM_MASK (0xf << WMI_RTT_USED_TX_CHAIN_NUM_MASK_S)
#define WMI_RTT_USED_TX_CHAIN_NUM_MASK_GET(x) WMI_F_MS(x, WMI_RTT_USED_TX_CHAIN_NUM_MASK)
#define WMI_RTT_USED_TX_CHAIN_NUM_MASK_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_USED_TX_CHAIN_NUM_MASK)

/*
 * For e.g if chain 0 is used then bit 20 will be set
 * For chain 1 bit 21 will be set
 */
#define WMI_RTT_USED_RX_CHAIN_NUM_MASK_S 20
#define WMI_RTT_USED_RX_CHAIN_NUM_MASK (0xf << WMI_RTT_USED_RX_CHAIN_NUM_MASK_S)
#define WMI_RTT_USED_RX_CHAIN_NUM_MASK_GET(x) WMI_F_MS(x, WMI_RTT_USED_RX_CHAIN_NUM_MASK)
#define WMI_RTT_USED_RX_CHAIN_NUM_MASK_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_USED_RX_CHAIN_NUM_MASK)

#define WMI_RTT_TOD_ERR_S 0
#define WMI_RTT_TOD_ERR (0xffff << WMI_RTT_TOD_ERR_S)
#define WMI_RTT_TOD_ERR_GET(x) WMI_F_MS(x, WMI_RTT_TOD_ERR)
#define WMI_RTT_TOD_ERR_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_TOD_ERR)

#define WMI_RTT_TOA_ERR_S 16
#define WMI_RTT_TOA_ERR (0xffff << WMI_RTT_TOA_ERR_S)
#define WMI_RTT_TOA_ERR_GET(x) WMI_F_MS(x, WMI_RTT_TOA_ERR)
#define WMI_RTT_TOA_ERR_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_TOA_ERR)

#endif

/*********************  TARGET_MSG_SUBTYPE_MEASUREMENT_REQ/RSP End *******************************/

/*********************  TARGET_MSG_SUBTYPE_ERROR_REPORT_RSP  Start *******************************/

/* Message format for WMI_OEM_RESP_EVENTID => TARGET_OEM_MSG_SUBTYPE_ERROR_REPORT_RSP
 * This EVENT provide error report from FW
 * Need be careful about 32 bit alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_rsp_head
 *     wmi_rtt_oem_measrsp_head
 *
 */

/*********************  TARGET_MSG_SUBTYPE_ERROR_REPORT_RSP End **********************************/

#ifdef USE_NEW_CONFIGURE_LCR_TLV_DEFS
/************************  TARGET_MSG_SUBTYPE_CONFIGURE_LCR Start ********************************/

/* For backward compatibility reason, CIVIC_INFO_MAX_LENGTH shouldn't be changed from value 64 */
#define CIVIC_INFO_MAX_LENGTH   64

/* Message format for WMI_OEM_REQ_CMDID => TARGET_MSG_SUBTYPE_CONFIGURE_LCR
 * This CMD configures the LCR information to FW
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_lcr_cfg_head
 */

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lcr_cfg_head
    A_UINT32 loc_civic_params; // length
    /******************************************************************************
     *bit 7:0        len in bytes. civic_info to be used in reference to this.
     *bit 31:8       reserved
     ******************************************************************************/
    A_UINT32 civic_info[CIVIC_INFO_MAX_LENGTH];      // Civic info including country_code to be copied in FTM frame.
                                  // 256 bytes max. Based on len, FW will copy byte-wise into
                                  // local buffers and transfer OTA. This is packed as a 4 bytes
                                  // aligned buffer at this interface for transfer to FW though.
} wmi_rtt_oem_lcr_cfg_head;

#define WMI_RTT_LOC_CIVIC_LENGTH_S 0
#define WMI_RTT_LOC_CIVIC_LENGTH (0xff << WMI_RTT_LOC_CIVIC_LENGTH_S)
#define WMI_RTT_LOC_CIVIC_LENGTH_GET(x) WMI_F_MS(x,WMI_RTT_LOC_CIVIC_LENGTH)
#define WMI_RTT_LOC_CIVIC_LENGTH_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LOC_CIVIC_LENGTH)


/************************  TARGET_MSG_SUBTYPE_CONFIGURE_LCR End ****************************/
#endif

#ifdef USE_NEW_CONFIGURE_LCI_TLV_DEFS
/************************  TARGET_MSG_SUBTYPE_CONFIGURE_LCI Start ***************************/

/* Message format for WMI_OEM_REQ_CMDID => TARGET_MSG_SUBTYPE_CONFIGURE_LCI
 * This CMD configures the LCI information to FW
 * Need be careful about 32 alignment if any change made in future
 *
 * Message Format:
 *     wmi_rtt_oem_req_head
 *     wmi_rtt_oem_lci_cfg_head
 */

typedef struct {
    A_UINT32 tlv_header;// TLV tag and len; tag equals WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lci_cfg_head
    A_UINT64 latitude;             // LS 34 bits - latitude in degrees * 2^25 , 2's complement; Lower 32 bits comes first followed by higher 32 bytes
    A_UINT64 longitude;            // LS 34 bits - latitude in degrees * 2^25 , 2's complement; Lower 32 bits comes first followed by higher 32 bytes
    A_UINT32 altitude;             // LS 30bits - Altitude in units of 1/256 m
    A_UINT32 lci_cfg_param_info;   // Uncertainities & motion pattern cfg
    /******************************************************************************
     *bits 7:0       Latitude_uncertainity as defined in Section 2.3.2 of IETF RFC 6225
     *bits 15:8      Longitude_uncertainity as defined in Section 2.3.2 of IETF RFC 6225
     *bits 23:16     Altitude_uncertainity as defined in Section 2.4.5 of IETF RFC 6225
     *bits 31:24     motion_pattern for use with z subelement cfg as per
                     wmi_rtt_z_subelem_motion_pattern
      ******************************************************************************/
     //Following elements for configuring the Z subelement
    A_UINT32  floor;               // in units 1/16th of floor # if known.
                                   // value is 80000000 if unknown.
    A_UINT32  floor_param_info;    // height_above_floor & uncertainity
    /******************************************************************************
     *bits 15:0      Height above floor in units of 1/64 m
     *bits 23:16     Height uncertainity as defined in 802.11REVmc D4.0 Z subelem format
                     value 0 means unknown, values 1-18 are valid and 19 and above are reserved
     *bits 31:24     reserved
      ******************************************************************************/
    A_UINT32  usage_rules;
    /******************************************************************************
     *bit  0         usage_rules: retransmittion allowed: 0-No 1-Yes
     *bit  1         usage_rules: retention expires relative present: 0-No 1-Yes
     *bit  2         usage_rules: STA Location policy for Additional neighbor info: 0-No 1-Yes
     *bits 7:3       usage_rules: reserved
     *bits 23:8      usage_rules: retention expires relative, if present, as per IETF RFC 4119
     *bits 31:24     reserved
      ******************************************************************************/
} wmi_rtt_oem_lci_cfg_head;

#define WMI_RTT_LCI_LAT_UNC_S 0
#define WMI_RTT_LCI_LAT_UNC (0xff << WMI_RTT_LCI_LAT_UNC_S)
#define WMI_RTT_LCI_LAT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_LAT_UNC)
#define WMI_RTT_LCI_LAT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_LAT_UNC)

#define WMI_RTT_LCI_LON_UNC_S 8
#define WMI_RTT_LCI_LON_UNC (0xff << WMI_RTT_LCI_LON_UNC_S)
#define WMI_RTT_LCI_LON_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_LON_UNC)
#define WMI_RTT_LCI_LON_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_LON_UNC)

#define WMI_RTT_LCI_ALT_UNC_S 16
#define WMI_RTT_LCI_ALT_UNC (0xff << WMI_RTT_LCI_ALT_UNC_S)
#define WMI_RTT_LCI_ALT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_ALT_UNC)
#define WMI_RTT_LCI_ALT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_ALT_UNC)

#define WMI_RTT_LCI_Z_MOTION_PAT_S 24
#define WMI_RTT_LCI_Z_MOTION_PAT (0xff << WMI_RTT_LCI_Z_MOTION_PAT_S)
#define WMI_RTT_LCI_Z_MOTION_PAT_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_MOTION_PAT)
#define WMI_RTT_LCI_Z_MOTION_PAT_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_MOTION_PAT)

#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_S 0
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR (0xffff << WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_S)
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_HEIGHT_ABV_FLR)
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_HEIGHT_ABV_FLR)

#define WMI_RTT_LCI_Z_HEIGHT_UNC_S 16
#define WMI_RTT_LCI_Z_HEIGHT_UNC (0xff << WMI_RTT_LCI_Z_HEIGHT_UNC_S)
#define WMI_RTT_LCI_Z_HEIGHT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_HEIGHT_UNC)
#define WMI_RTT_LCI_Z_HEIGHT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_HEIGHT_UNC)

#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_S 0
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED (0x1 << WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_S)
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED)
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED)

#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_S 1
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP (0x1 << WMI_RTT_LCI_USG_RUL_RETENTION_EXP_S)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETENTION_EXP)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETENTION_EXP)

#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_S 2
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY (0x1 << WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_S)
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY)
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY)

#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_S 8
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE (0xff << WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_S)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE)

/************************  TARGET_MSG_SUBTYPE_CONFIGURE_LCI End ****************************/
#endif


/************************ TLV Helper definitions Start ***********************************************/

/* Size of the TLV Header which is the Tag and Length fields */
#define RTT_TLV_HDR_SIZE   (1 * sizeof(A_UINT32))

/** TLV Helper macro to set the TLV Header given the pointer
 *  to the TLV buffer. */
#define WMIRTT_TLV_SET_HDR(tlv_buf, tag, len) (((A_UINT32 *)(tlv_buf))[0]) = ((tag << 16) | (len & 0x0000FFFF))

/** TLV Helper macro to get the TLV Tag given the TLV header. */
#define WMIRTT_TLV_GET_TLVTAG(tlv_header)  ((A_UINT32)((tlv_header)>>16))

/** TLV Helper macro to get the TLV Buffer Length (minus TLV
 *  header size) given the TLV header. */
#define WMIRTT_TLV_GET_TLVLEN(tlv_header)  ((A_UINT32)((tlv_header) & 0x0000FFFF))

/** Enum list of TLV Tags for each parameter structure type. */
typedef enum {
    WMIRTT_TLV_TAG_UNKNOWN= 0,
    /* 0 to 15 is reserved */
    WMIRTT_TLV_TAG_LAST_RESERVED = 15,
    WMIRTT_TLV_TAG_STRUC_loop_start,
    WMIRTT_TLV_TAG_STRUC_loop_end,
    WMIRTT_TLV_TAG_FIRST_ARRAY_ENUM, /* First entry of ARRAY type tags */
    WMIRTT_TLV_TAG_ARRAY_UINT8 = WMIRTT_TLV_TAG_FIRST_ARRAY_ENUM,
    WMIRTT_TLV_TAG_LAST_ARRAY_ENUM = 31,   /* Last entry of ARRAY type tags */
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_req_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_event,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_per_channel_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_peer_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_nan_ranging_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_nan_req_cmd,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lcr_cfg_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lci_cfg_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_req_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_rsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_req_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_rsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cancel_measurement_req_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cancel_measurement_rsp_info,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cfg_resp_meas_req_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cfg_resp_meas_rsp_head,
    WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_responder_measrsp_head,
} WMIRTT_TLV_TAG_ID;

/************************ TLV Helper definitions End ***********************************************/

#endif /* _RTT_OEM_INTF_H_ */

