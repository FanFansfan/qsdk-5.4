/* Copyright (c) 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "btdaemon.h"
#include "btdaemon_dbg.h"

#define MAX_BUF_SIZE 2048
#define BTSS_PKT_HEADER_SIZE 3
#define BTSS_PKT_PAYLOAD_SIZE_INDEX 2
#define MEMSET_RESET_VALUE 0
#define WAIT_TIME_MS 50

int handle = -1;
void print_array(uint8_t *addr, int len)
{
    int i;
    int line = 1;
    for (i = 0; i < len; i++) {
        if (i == (line * 80)) {
            DPRINTF(BTD_DBG_TRACE, "\n");
            line++;
        }
       DPRINTF(BTD_DBG_TRACE, "%02X ", addr[i]);
    }
    DPRINTF(BTD_DBG_TRACE, "\n");
}

#ifdef IPQ_IPQ50XX_SUPPORT
int initialize_nvm_ipq50xx()
{
    unsigned char *buffer;
    FILE *fptr = NULL;
    void *rsp = NULL;
    int bytes_read = 0, bytes_write = 0, bytes_read_rsp = 0;
    HCI_Packet_t *hci_packet = NULL;

    buffer = (unsigned char*)malloc(NVM_SEGMENT_SIZE);
    if(!buffer)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Cannot allocate memory to NVM Buffer \n");
        return -ENOMEM;
    }

    memset(buffer, MEMSET_RESET_VALUE, NVM_SEGMENT_SIZE);

    fptr = fopen(NVM_BIN_FILE,"rb");
    if(!fptr)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Unable to open mpnv10.bin file to initialize NVM \n");
        free(buffer);
        return -EBADF;
    }

    while(((bytes_read = fread(buffer, sizeof(byte), NVM_SEGMENT_SIZE, fptr)) > 0) || (!feof(fptr)))
    {
        if(bytes_read == 0 && ferror(fptr))
        {
            DPRINTF(BTD_DBG_ERROR, "\n Error occured while reading NVM File \n");
            free(buffer);
            fclose(fptr);
            return -EBADF;
        }

        /* Constructing a HCI Packet to write NVM Segments to BTSS */
        hci_packet = (HCI_Packet_t*)malloc(sizeof(HCI_Packet_t) + NVM_SEGMENT_SIZE);

        if(!hci_packet)
        {
            DPRINTF(BTD_DBG_ERROR, "\n Cannot allocate memory to HCI Packet \n");
            free(buffer);
            fclose(fptr);
            return -ENOMEM;
        }

        /* Initializing HCI Packet Header */
        hci_packet->HCIPacketType = ptHCICommandPacket;

        /* Populating TLV Request Packet in HCI */
        ASSIGN_HOST_WORD_TO_LITTLE_ENDIAN_UNALIGNED_WORD(&(hci_packet->HCIPayload.opcode), TLV_REQ_OPCODE);
        ASSIGN_HOST_WORD_TO_LITTLE_ENDIAN_UNALIGNED_WORD(&(hci_packet->HCIPayload.parameter_total_length), (bytes_read + DATA_REMAINING_LENGTH));
        hci_packet->HCIPayload.command_request = TLV_COMMAND_REQUEST;
        hci_packet->HCIPayload.tlv_segment_length = bytes_read;
        memcpy(hci_packet->HCIPayload.tlv_segment_data, buffer, bytes_read);

        /* Flushing the BT DevNode before writing */
        if (tcflush(handle, TCIOFLUSH) != 0)
        {
            DPRINTF(BTD_DBG_ERROR, "\n tcflush error \n");
            free(buffer);
            free(hci_packet);
            fclose(fptr);
            return -EIO;
        }

        /* Writing to TLV Request Packet to BT DEVNODE */
        bytes_write = write(handle, hci_packet, sizeof(HCI_Packet_t) + bytes_read);
        if(bytes_write < 0)
        {
            DPRINTF(BTD_DBG_ERROR, "\n Unable to write it to the BT DEVNODE \n");
            free(buffer);
            free(hci_packet);
            fclose(fptr);
            return -EBADF;
        }

        free(hci_packet);
        bytes_read = 0;
        bytes_read_rsp = 0;
        memset(buffer, MEMSET_RESET_VALUE, NVM_SEGMENT_SIZE);
    } /* end of while */

    /* Reading Last TLV Response from BTSS System */
    sleep(2);
    rsp = malloc(TLV_RESPONSE_PACKET_SIZE);
    memset(rsp, MEMSET_RESET_VALUE, TLV_RESPONSE_PACKET_SIZE);

    bytes_read_rsp = read(handle, rsp, TLV_RESPONSE_PACKET_SIZE);
    if((bytes_read_rsp < 0) || (*((uint8 *)rsp + TLV_RESPONSE_STATUS_INDEX) != 0))
    {
        DPRINTF(BTD_DBG_ERROR, "\n NVM download failed\n");
        free(buffer);
        free(rsp);
        fclose(fptr);
        return -1;
    }

    DPRINTF(BTD_DBG_TRACE, "\n NVM download successful \n");
    fclose(fptr);
    free(buffer);
    return 1;
}

int read_btss_ipq50xx(int handle, void** buffer)
{
    void *rsp_pkt = NULL;
    int bytes_read = 0, bytes = 0;
    int payload_bytes = 0;

    if(handle < 0) {
        DPRINTF(BTD_DBG_ERROR, "\n Invalid BTDEV Node Handle Received\n");
        return -EBADF;
    }

    if(buffer == NULL || *buffer == NULL)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Buffer received from FTM is not allocated\n");
        return -ENOMEM;
    }

    rsp_pkt = malloc(MAX_BUF_SIZE);
    if(!rsp_pkt)
    {
        DPRINTF(BTD_DBG_ERROR, "Cannot allocate memory to response packet\n");
        return -ENOMEM;
    }

    memset(rsp_pkt, MEMSET_RESET_VALUE, MAX_BUF_SIZE);

    /* Adding 100 milliseconds usleep */
    if (usleep(WAIT_TIME_MS) < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n usleep() failed\n");
    }

    /* Reading the First 3 Bytes from BTSS Dev Node */
    while(bytes_read < BTSS_PKT_HEADER_SIZE)
    {
        bytes = read(handle, (rsp_pkt + bytes_read), BTSS_PKT_HEADER_SIZE);

        if(bytes <= 0)
        {
            free(rsp_pkt);
            return bytes;
        }

        bytes_read += bytes;
    }

    /* The numbers of bytes available as payload for HCI Packet */
    payload_bytes = *(((uint8*)rsp_pkt) + BTSS_PKT_HEADER_SIZE - 1);
    while(bytes_read < (BTSS_PKT_HEADER_SIZE + payload_bytes))
    {
        bytes = read(handle, (rsp_pkt + bytes_read), payload_bytes);
        if(bytes < 0)
        {
            DPRINTF(BTD_DBG_ERROR, "\n Read Failure to read the Payload from BTSS\n");
            free(rsp_pkt);
            return -EBADF;
        }

        bytes_read += bytes;
    }

    /* Discarding the first byte of the HCI payload from the reponse read from BTSS
     * Hence subtracting 1 Byte from bytes_read */
    bytes_read--;
    (byte*)rsp_pkt++;
    memcpy((*buffer), ((byte*)rsp_pkt), bytes_read);

    free(rsp_pkt);
    return bytes_read;
}

int write_btss_ipq50xx(int handle, void* buffer)
{
    int bytes_write=0;

    ftm_bt_pkt_type *new_ftm_pkt = NULL;
    new_ftm_pkt = (ftm_bt_pkt_type*)buffer;

    if(handle < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Invalid BTDEV Node Handle Received\n");
        return -EBADF;
    }

    if(buffer == NULL)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Buffer received is invalid");
        return -ENOMEM;
    }

    /* Adding 100 milliseconds usleep */
    if (usleep(WAIT_TIME_MS) < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n usleep() failed\n");
    }

    /* Flushing the BT DevNode before writing to DEVNODE */
    if (tcflush(handle, TCIOFLUSH) != 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n tcflush error \n");
        return -EIO;
    }

    bytes_write = write(handle, new_ftm_pkt->data, new_ftm_pkt->ftm_hdr.cmd_data_len);

    if(bytes_write < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Write Failure on BTSS\n");
        return -EBADF;
    }

    return bytes_write;
}

int ipq50xx_btss_init ()
{
    int nvm_status = -1;

    /* Open a descriptor to BT_DEVNODE */
    handle = open (BT_DEVNODE, O_RDWR | O_NOCTTY | O_NONBLOCK);

    /* In case of a invalid handle received */
    if (handle < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n Unable to open the BT DEVNODE File Handle \n");
        return -EBADF;
    }

    /* Power up BTSS*/
    DPRINTF(BTD_DBG_INFO, "\n MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_UP ioctl fired! \n");
    ioctl(handle, MAPLE_IOCTL_IPC_BOOT_REQUEST_CODE,
                           MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_UP);

    sleep(1);

    /* Initializing NVM Download */
    nvm_status = initialize_nvm_ipq50xx();
    if(nvm_status < 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n NVM Download and Initialization Failed \n");
    }

    /* Flushing the BT DevNode before starting the async threads */
    if (tcflush(handle, TCIOFLUSH) != 0)
    {
        DPRINTF(BTD_DBG_ERROR, "\n tcflush error \n");
        return -EIO;
    }

    /* Returning the handle to BT DevNode. */
    return handle;
}

void ipq50xx_btss_deinit()
{
    /*Power down BTSS*/
    DPRINTF(BTD_DBG_INFO, "\n MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_DOWN ioctl fired! \n\n");
    ioctl(handle, MAPLE_IOCTL_IPC_BOOT_REQUEST_CODE,
                           MAPLE_IOCTL_IPC_BOOT_REQUEST_ARG_POWER_DOWN);
    close(handle);
}
#endif /* IPQ_IPQ50XX_SUPPORT */

int btss_init ()
{
#ifdef IPQ_IPQ50XX_SUPPORT
    int handle = -1;
    handle = ipq50xx_btss_init();
    return handle;
#endif
}

void btss_deinit ()
{
#ifdef IPQ_IPQ50XX_SUPPORT
    ipq50xx_btss_deinit();
#endif
}


int bt_daemon_send(int handle, void* buffer)
{
#ifdef IPQ_IPQ50XX_SUPPORT
    int bytes_write = write_btss_ipq50xx(handle, buffer);
    return bytes_write;
#endif
}

int bt_daemon_receive(int handle, void** buffer)
{
#ifdef IPQ_IPQ50XX_SUPPORT
    int bytes_read = read_btss_ipq50xx(handle, buffer);
    return bytes_read;
#endif
}
