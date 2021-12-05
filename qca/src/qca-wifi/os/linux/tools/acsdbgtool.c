/*
 * Copyright (c) 2018, 2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Description:
 * Sends user-defined beacon and channel events from an acsreport-like
 * file and sends it to the driver to the ACS debug framework which injects
 * these parameters into the algorithm to give you the ability to analyze
 * in-depth
 *
 * Usage:
 * acsdbgtool athX --file|-f <filename>
 * acsdbgtool athX --help|-h
 */

#include <qcatools_lib.h>
#include <ieee80211_external.h>

/* Error Codes */
#define ACSDBG_SUCCESS            0
#define ACSDBG_ERROR             -1

/* Limits and Keywords */
#define MAX_INTERFACE_LEN        20
#define MAX_FILENAME_LEN         255
#define MAX_BEACON_COUNT         100
#define MAX_SSID_LEN             32
#define MAX_REPORT_LINE_LEN      200
#define MAC_ADDR_SIZE            6
#define BCN_PARAM_NUM            16
#define CHAN_EVENT_PARAM_NUM      5
#define SECTION_CAPTURE_START     "BAND"

/* Netlink Macros */
#define ACS_DBG_NL80211_CMD_SOCK_ID   DEFAULT_NL80211_CMD_SOCK_ID
#define ACS_DBG_NL80211_EVENT_SOCK_ID DEFAULT_NL80211_EVENT_SOCK_ID

/* Utility Macros */
#define strchk(a,b)              (strncasecmp(a,b,sizeof(b)-1) == 0)
#define acsdbg_log(str, args...) fprintf(stdout, "%s: " str, __func__, ## args)

/* Structures */
struct raw_bcn_event {
    uint32_t channel_number;
    int32_t  rssi;
    uint8_t  bssid[MAC_ADDR_SIZE];
    uint8_t  ssid[MAX_SSID_LEN];
    uint32_t phymode;
    uint8_t  sec_chan_seg1;
    uint8_t  sec_chan_seg2;
    uint8_t  srpen;
    uint8_t  srp_allowed;
    uint8_t  client_srp_allowed;
    uint8_t  client_obsspd_allowed;
};

struct raw_bcn_event_container {
    int8_t band;
    int8_t nbss;
    int8_t is_first_bcn_block;
    struct raw_bcn_event *event;
};

struct raw_chan_event {
    uint8_t  channel_number;
    uint8_t  channel_load;
    int16_t  noise_floor;
    uint32_t txpower;
    uint32_t channel_rf_characterization;
};

struct raw_chan_event_container {
    int8_t band;
    int8_t nchan;
    int8_t is_first_chan_event_block;
    struct raw_chan_event *event;
};

struct socket_context sock_ctx = {0};

/* Enums and Arrays */
static const uint32_t max_channel_count[] = {
    [WLAN_BAND_2GHZ]      = 14,
    [WLAN_BAND_5GHZ]      = 27,
    [WLAN_BAND_6GHZ]      = 60,
};

enum data_block_type {
    BLOCK_TYPE_INVALID = 0,
    BLOCK_TYPE_BCN     = 1,
    BLOCK_TYPE_CHAN    = 2,
};

/* Prototypes */
static int  validate_command(int argc, char **argv, char *ifname);
static void print_usage(void);
static int  validate_file(char *file);
static int  parse_report(FILE *fp, char *ifname);
static enum data_block_type find_next_data_block(FILE *fp, char *line,
                                                 int8_t *data_count, int8_t *band);
static int record_data_block(enum data_block_type block_type, void *buf,
                             int8_t band, int8_t data_count, char *line,
                             FILE *fp);
static void * create_buf(enum data_block_type block_type, int8_t data_count);
static void cleanup_buf(void *buf);

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    char ifname[MAX_INTERFACE_LEN]  = {0};
    int8_t ret = ACSDBG_SUCCESS;
    uint8_t is_sock_init = 0;

    sock_ctx.cfg80211 = get_config_mode_type();

    if (validate_command(argc, argv, ifname))
        ret = ACSDBG_ERROR;

    if (!ret && (strchk(argv[2], "--help") || strchk(argv[2], "-h"))) {
        /* Help Command */
        print_usage();
        ret = ACSDBG_SUCCESS;

    } else if (!ret && (strchk(argv[2], "--file") || strchk(argv[2], "-f"))) {
        /* Actionable Parsing Command */
        if (validate_file(argv[3])) {
            acsdbg_log("File information is invalid\n");
            ret = ACSDBG_ERROR;
        }

        if (!ret)
            fp = fopen(argv[3], "r");

        if (!ret && !fp) {
            acsdbg_log("File cannot be opened\n");
            ret = ACSDBG_ERROR;
        }

        if (!ret && init_socket_context(&sock_ctx, DEFAULT_NL80211_CMD_SOCK_ID,
                DEFAULT_NL80211_EVENT_SOCK_ID) && (is_sock_init = 1)) {
            acsdbg_log("Socket could not be initialized\n");
            ret = ACSDBG_ERROR;
        }

        /* Parsing the report */
        if (!ret && parse_report(fp, ifname)) {
            acsdbg_log("Report cannot be parsed\n");
            ret =  ACSDBG_ERROR;
        }

        /*
         * Post-Application Clean-Up:
         */
        if (is_sock_init) {
            destroy_socket_context(&sock_ctx);
        }

        if (fp) {
            fclose(fp);
        }

    } else {
        acsdbg_log("Invalid command entered\n");
        print_usage();
        ret = ACSDBG_ERROR;
    }

    return ret;
}

/*
 * validate_command:
 * Checks if the command is valid to continue further into the application
 * In addition to the above, it puts the interface name in the "ifname".
 *
 * Parameters:
 * argc: The number of arguments in the command (including the application name)
 * argv: Character double pointer pointing to each argument as a string array
 *
 * Return:
 *  0 - Success
 * -1 - Failure
 */
static int validate_command(int argc, char **argv, char *ifname)
{
    int ret = ACSDBG_SUCCESS;

    if (argc < 3) {
        ret = ACSDBG_ERROR;
    }

    if (!ret && strlcpy(ifname, argv[1], strlen(argv[1]) + 1) >= MAX_INTERFACE_LEN) {
        acsdbg_log("Interface name is too long\n");
        ret = ACSDBG_ERROR;
    }

    return ret;
}

/*
 * print_usage:
 * Prints the general usage of the application. This function gets called if
 * the user sends in a help command or if the user has incorrectly sent in a
 * command
 *
 * Parameters:
 * None
 *
 * Return:
 * None
 */
static void print_usage(void)
{
    acsdbg_log("Usage: \n"
               "acsdbgtool athX --file|-f <filename>\n"
               "acsdbgtool athX --help|-h\n");
}

/*
 * validate_file:
 * Checks if the file path is valid and if its valid, checks to see if its
 * length is within limits set by the application.
 *
 * Parameters:
 * file: Pointer to the filepath
 *
 * Return:
 *  0 - Success
 * -1 - Failure
 */
static int validate_file(char *file)
{
    int ret = ACSDBG_SUCCESS;

    if (!file) {
        /* File information is invalid or not present */
        ret = ACSDBG_ERROR;
    }

    if (!ret && (strlen(file) > MAX_FILENAME_LEN)) {
        /* File path is too long */
        ret = ACSDBG_ERROR;
    }

    return ret;
}

/*
 * parse_report:
 * Parses the report CSV file from the userspace and places it in a buffer
 * to be sent into the driver.
 *
 * Parameters:
 * fp    : Pointer to the CSV report file
 * ifname: Name of the interface sent when the user calls the application from
 *         the command line
 *
 * Returns:
 *  0 - Success
 * -1 - Failure
 */
static int parse_report(FILE *fp, char *ifname)
{
    char line[MAX_REPORT_LINE_LEN];
    int8_t ret = ACSDBG_SUCCESS, band = WLAN_BAND_UNSPECIFIED, data_count = -1;
    enum data_block_type block_type = BLOCK_TYPE_INVALID;
    void *buf_data = NULL;
    int8_t is_first_bcn_block = 1, is_first_chan_event_block = 1;
    uint32_t bcn_block_cnt = 0, chan_event_block_cnt = 0;

    do {
        /*
         * If not in a block, find the next data block along with
         * it's meta information
         */
        if (block_type == BLOCK_TYPE_INVALID) {
            block_type = find_next_data_block(fp, line, &data_count, &band);

            if ((block_type == BLOCK_TYPE_INVALID) ||
                (data_count == -1) ||
                (band == WLAN_BAND_UNSPECIFIED)) {
                /* Found an invalid block header or no block header */
                continue;
            }
        }

        /* If capture information is invalid, then skip the block */
        if ((data_count == -1) || (band == WLAN_BAND_UNSPECIFIED)) {
            acsdbg_log("Invalid block meta information. Skipping block\n");
            block_type = BLOCK_TYPE_INVALID;
            continue;
        }

        /* Create buffer based on type and block count*/
        buf_data = create_buf(block_type, data_count);
        if (!buf_data) {
            acsdbg_log("Could not create buffer for block data. Abandoning process.\n");
            block_type = BLOCK_TYPE_INVALID;
            ret = ACSDBG_ERROR;
        }

        /* Record the block information based on the data */
        if ((block_type != BLOCK_TYPE_INVALID) &&
            record_data_block(block_type, buf_data, band, data_count, line, fp)) {
            acsdbg_log("Error recording data block. Skipping block\n");
            block_type = BLOCK_TYPE_INVALID;
        }

#if ATH_ACS_DEBUG_SUPPORT
        /* Send data to driver if the block data is valid. */
        switch(block_type) {
            case BLOCK_TYPE_BCN:
                if (is_first_bcn_block) {
                    ((struct raw_bcn_event_container *)buf_data)->is_first_bcn_block = 1;
                    is_first_bcn_block = 0;
                }

                acsdbg_log("Sending beacon data block\n");
                bcn_block_cnt++;
                send_command(&sock_ctx, ifname, buf_data,
                             sizeof(struct raw_bcn_event_container) +
                             (data_count * sizeof(struct raw_bcn_event)), NULL,
                             QCA_NL80211_VENDOR_SUBCMD_ACSDBGTOOL_ADD_BCN, 0);
            break;

            case BLOCK_TYPE_CHAN:
                if (is_first_chan_event_block) {
                    ((struct raw_chan_event_container *)buf_data)->is_first_chan_event_block = 1;
                    is_first_chan_event_block = 0;
                }

                acsdbg_log("Sending channel events data block\n");
                chan_event_block_cnt++;
                send_command(&sock_ctx, ifname, buf_data,
                             sizeof(struct raw_chan_event_container) +
                             (data_count * sizeof(struct raw_chan_event)), NULL,
                             QCA_NL80211_VENDOR_SUBCMD_ACSDBGTOOL_ADD_CHAN, 0);
            break;

            default:
                /* Do nothing */
            break;
        }

        /* Reset block type to invalid since next block is to be read */
        block_type = BLOCK_TYPE_INVALID;
#else
        acsdbg_log("Debug framework is disabled. Abandoning process\n");
        block_type = BLOCK_TYPE_INVALID;
        ret = ACSDBG_ERROR;
#endif
        cleanup_buf(buf_data);
    } while (!ret && fgets(line, MAX_REPORT_LINE_LEN, fp));

    /*
     * If we are sending only one of the two events, notify the driver so it can delete
     * previous entries.
     */
    if (!ret && !chan_event_block_cnt) {
        send_command(&sock_ctx, ifname, NULL, 0, NULL,
                     QCA_NL80211_VENDOR_SUBCMD_ACSDBGTOOL_ADD_CHAN, 0);
    }

    if (!ret && !bcn_block_cnt) {
        send_command(&sock_ctx, ifname, NULL, 0, NULL,
                     QCA_NL80211_VENDOR_SUBCMD_ACSDBGTOOL_ADD_BCN, 0);
    }

    return ret;
}

/*
 * find_next_data_block:
 * Find the next block in the report along with the block's meta data which
 * include the type, count and band
 *
 * Parameters:
 * fp        : Pointer to the file.
 * line      : Current line of the file.
 * data_count: Number of elements in the block.
 * band      : The operating band for which the elements are valid.
 *
 * Return:
 * Block Type (enum data_block_type)
 */
static enum data_block_type find_next_data_block(FILE *fp, char *line,
                                                 int8_t *data_count, int8_t *band)
{
    enum data_block_type ret = BLOCK_TYPE_INVALID;

    while ((ret == BLOCK_TYPE_INVALID) && fgets(line, MAX_REPORT_LINE_LEN, fp)) {
        if (strchk(line, SECTION_CAPTURE_START)) {
            if (sscanf(line, "BAND = %hhd\n", band)) {
                continue;
            } else {
                break;
            }
        }

        if (strchk(line, "BEACONS") &&
            sscanf(line, "BEACONS = %hhd\n", data_count)) {
            ret = BLOCK_TYPE_BCN;
            break;
        } else if (strchk(line, "CHANNELS") &&
                   sscanf(line, "CHANNELS = %hhd\n", data_count)) {
            ret = BLOCK_TYPE_CHAN;
            break;
        } else {
            break;
        }
    }

    if ((*band < WLAN_BAND_2GHZ) || (*band >= WLAN_BAND_MAX) ||
        (*data_count <= 0) ||
        ((ret == BLOCK_TYPE_CHAN) && (*data_count > max_channel_count[*band])) ||
        ((ret == BLOCK_TYPE_BCN) && (*data_count > MAX_BEACON_COUNT))) {
        ret = BLOCK_TYPE_INVALID;
    }

    return ret;
}


/*
 * create_buf:
 * Creates the buffer that gets sent to the driver to the ACS debug framework
 * for injection into the ACS algorithm based on the block type.
 *
 * NOTE: Allocating another int32_t size to account for some padding used by
 *       the cfg80211 APIs. The buffers are considered corrupted otherwise.
 *
 * Parameters:
 * block_type: The block type (i.e., beacon, channel events, etc.)
 * data_count: Value for the items in the block to send into the driver.
 *
 * Return:
 *  Pointer to allocated memory
 */
static void * create_buf(enum data_block_type block_type, int8_t data_count)
{
    void *ptr = NULL;

    if (data_count > 0) {
        switch(block_type) {
            case BLOCK_TYPE_BCN:
                ptr = malloc(sizeof(struct raw_bcn_event_container) +
                             (data_count * sizeof(struct raw_bcn_event) + sizeof(int32_t)));
                if (ptr) {
                    memset(ptr, 0, sizeof(struct raw_bcn_event_container) +
                           (data_count * sizeof(struct raw_bcn_event) + sizeof(int32_t)));
                }
            break;

            case BLOCK_TYPE_CHAN:
                ptr = malloc(sizeof(struct raw_chan_event_container) +
                             (data_count * sizeof(struct raw_chan_event) + sizeof(int32_t)));
                if (ptr) {
                    memset(ptr, 0, sizeof(struct raw_chan_event_container) +
                           (data_count * sizeof(struct raw_chan_event) + sizeof(int32_t)));
                }
            break;

            default:
                acsdbg_log("Cannot create buffer, invalid block_type\n");
            break;
        }
    }

    return ptr;
}

/*
 * cleanup_buf:
 * Cleans up all the allocated memory which was used for the data block.
 *
 * Parameters:
 * buf: Pointer to the buffer location containing all the beacon events
 *
 * Return:
 *  None
 */
static void cleanup_buf(void *buf)
{
    if (buf) {
        free(buf);
        buf = NULL;
    }

}

/*
 * record_data_block:
 * Records each line in the CSV which corresponds to a unique element
 * in the data block.
 *
 * Beacons: The information includes - BSSID, channel number, phymode,
 * rssi, secondary_channel segments and SRP
 * Channel Events:  The information includes - Channel number, noise_floor value
 * for that channel, max Tx power value and channel load.
 *
 * Parameters:
 * block_type: Type of data block
 * buf       : Pointer to the buffer for beacon events
 * band      : Value for the band ID of the beacon set
 * buf       : Value for the number of beacons to send into the driver
 * line      : Pointer to the line that contains the unique beacon information
 * fp        : Pointer to the CSV report file
 *
 * Return:
 *  0 - Success
 * -1 - Failure
 */
static int record_data_block(enum data_block_type block_type, void *buf,
                             int8_t band, int8_t data_count, char *line,
                             FILE *fp)
{
    uint8_t ix;
    uint8_t ret = ACSDBG_SUCCESS;
    struct raw_bcn_event_container  *bcn  = NULL;
    struct raw_chan_event_container *chan = NULL;

    switch(block_type) {
        case BLOCK_TYPE_BCN:
            bcn = (struct raw_bcn_event_container *)buf;
            bcn->event = (struct raw_bcn_event *)((void *)bcn + sizeof(*bcn));

            for (ix = 0; ix < data_count && fgets(line, MAX_REPORT_LINE_LEN, fp); ix++) {
               if (sscanf(line,
                          "%2x:%2x:%2x:%2x:%2x:%2x ,%u ,%u ,%d ,%u ,%u ,%u ,%u, %u ,%u ,%s",
                          (unsigned int *) &bcn->event[ix].bssid[0],
                          (unsigned int *) &bcn->event[ix].bssid[1],
                          (unsigned int *) &bcn->event[ix].bssid[2],
                          (unsigned int *) &bcn->event[ix].bssid[3],
                          (unsigned int *) &bcn->event[ix].bssid[4],
                          (unsigned int *) &bcn->event[ix].bssid[5],
                          &bcn->event[ix].channel_number,
                          &bcn->event[ix].phymode,
                          &bcn->event[ix].rssi,
                          (unsigned int *) &bcn->event[ix].sec_chan_seg1,
                          (unsigned int *) &bcn->event[ix].sec_chan_seg2,
                          (unsigned int *) &bcn->event[ix].srpen,
                          (unsigned int *) &bcn->event[ix].srp_allowed,
                          (unsigned int *) &bcn->event[ix].client_srp_allowed,
                          (unsigned int *) &bcn->event[ix].client_obsspd_allowed,
                          bcn->event[ix].ssid) != BCN_PARAM_NUM) {
                   ret = ACSDBG_ERROR;
                   break;
               }

               if (!ret && (strlen((char *) bcn->event[ix].ssid) >= MAX_SSID_LEN)) {
                       acsdbg_log("SSID length is too long (max %d chars)\n", MAX_SSID_LEN);
                       ret = ACSDBG_ERROR;
                       break;
               }
            }

            if (!ret) {
                bcn->band = band;
                bcn->nbss = data_count;
            }
        break;

        case BLOCK_TYPE_CHAN:
            chan = (struct raw_chan_event_container *)buf;
            chan->event = (struct raw_chan_event *)((void *)chan + sizeof(*chan));

            for (ix = 0; ix < data_count && fgets(line, MAX_REPORT_LINE_LEN, fp); ix++) {
              if (sscanf(line,
                          "%hhu ,%hd ,%u ,%hhu ,%u",
                          &chan->event[ix].channel_number,
                          &chan->event[ix].noise_floor,
                          &chan->event[ix].txpower,
                          &chan->event[ix].channel_load,
                          &chan->event[ix].channel_rf_characterization) != CHAN_EVENT_PARAM_NUM) {
                  ret = ACSDBG_ERROR;
                  break;
              }
            }

            if (!ret) {
                chan->band  = band;
                chan->nchan = data_count;
            }
        break;

        default:
           acsdbg_log("Invalid block type");
           ret = ACSDBG_ERROR;
    }

    return ret;
}
