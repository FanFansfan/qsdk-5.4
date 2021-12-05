/* Copyright (c) 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc. */

/* Diag related header files */
#include "event.h"
#include "msg.h"
#include "diag_lsm.h"
#include "diagpkt.h"
#include "diagcmd.h"
#include "diag.h"
#include <semaphore.h>

/* Maple Specific IOCTL for powering up/down the Bluetooth controller */

#define MAPLE_IOCTL_IPC_BOOT_REQUEST_CODE 0xBE
#define MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_UP 0x01
#define MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_DOWN 0x00
#define BT_DEVNODE "/dev/ttyBT0"
#define NVM_BIN_FILE "/lib/firmware/IPQ5018/mpnv10.bin"
#define NVM_SEGMENT_SIZE 243
#define TLV_REQ_OPCODE 0xFC00
#define TLV_COMMAND_REQUEST 0x1E
#define DATA_REMAINING_LENGTH 2
#define TLV_RESPONSE_PACKET_SIZE 8
#define TLV_RESPONSE_STATUS_INDEX 6

#define PACKED_STRUCT __attribute__((__packed__))

#define ASSIGN_HOST_WORD_TO_LITTLE_ENDIAN_UNALIGNED_WORD(x, y)  \
{                                                               \
    ((byte *)(x))[0] = ((byte)(((word)(y)) & 0xFF));            \
    ((byte *)(x))[1] = ((byte)((((word)(y)) >> 8) & 0xFF));     \
}

#ifdef IPQ_IPQ50XX_SUPPORT
typedef enum
{
    ptHCICommandPacket = 0x01,           /* Simple HCI Command Packet    */
    ptHCIACLDataPacket = 0x02,           /* HCI ACL Data Packet Type.    */
    ptHCISCODataPacket = 0x03,           /* HCI SCO Data Packet Type.    */
    ptHCIeSCODataPacket= 0x03,           /* HCI eSCO Data Packet Type.   */
    ptHCIEventPacket   = 0x04,           /* HCI Event Packet Type.       */
    ptHCIAdditional    = 0x05            /* Starting Point for Additional*/
} HCI_PacketType_t;

typedef struct _tlv_download_req
{
    uint16 opcode;
    uint8 parameter_total_length;
    uint8 command_request;
    uint8 tlv_segment_length;
    byte tlv_segment_data[0];

} PACKED_STRUCT tlv_download_req;

typedef struct _tagHCI_Packet_t
{
    uint8 HCIPacketType;
    tlv_download_req HCIPayload;
} PACKED_STRUCT HCI_Packet_t;


typedef struct
{
    uint16 cmd_id;        /* command id (required) */
    uint16 cmd_data_len;  /* request pkt data length, excluding the diag and ftm headers (optional, set to 0 if not used)*/
    uint16 cmd_rsp_pkt_size; /* rsp pkt size, size of response pkt if different then req pkt (optional, set to 0 if not used)*/
} PACKED_STRUCT ftm_bt_cmd_header_type;

typedef struct
{
    diagpkt_subsys_header_type diag_hdr;   /* Diag Header */
    ftm_bt_cmd_header_type ftm_hdr;        /* FTM Header */
    byte data[1];                          /* payload sent to Maple BTSS */
} PACKED_STRUCT ftm_bt_pkt_type;

int initialize_nvm_ipq50xx();
int read_btss_ipq50xx(int handle, void** buffer);
int write_btss_ipq50xx(int handle, void* buffer);
int ipq50xx_btss_init ();
void ipq50xx_btss_deinit();
#endif /* IPQ_IPQ50XX_SUPPORT */

int btss_init ();
void btss_deinit ();
int bt_daemon_send(int handle, void* buffer);
int bt_daemon_receive(int handle, void** buffer);
