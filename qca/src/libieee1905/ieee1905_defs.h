/*
 * @File: ieee1905_defs.h
 *
 * @Abstract: IEEE 1905.1 definition header file.
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2014-2015, 2018 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef ieee1905_defs__h /*once only*/
#define ieee1905_defs__h

#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <ieee1905_vendor_consts.h>

#undef IEEE1905_USE_BCAST

/*
 * Packet header macros
 */
#define IEEE1905_ETHER_TYPE         (0x893A) /* IEEE 1905.1 Ethertype */
#ifdef IEEE1905_USE_BCAST
#define IEEE1905_MULTICAST_ADDR     "\xFF\xFF\xFF\xFF\xFF\xFF" /* DEBUG ONLY! */
#else
#define IEEE1905_MULTICAST_ADDR     "\x01\x80\xC2\x00\x00\x13" /* IEEE 1905.1 Multicast address */
#endif

#define IEEE1905_OUI_LENGTH     3

#define IEEE1905_ETH_HEAD_LEN       (sizeof(struct ether_header))
#define IEEE1905_HEAD_LEN           (sizeof(struct ieee1905Header_t))
#define IEEE1905_TLV_MIN_LEN        (sizeof(u_int8_t) + sizeof(u_int16_t))
#define IEEE1905_TLV_LEN( _len )    (sizeof(u_int8_t) + sizeof(u_int16_t) + _len)
#define IEEE1905_FRAME_MIN_LEN      (IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN + IEEE1905_TLV_MIN_LEN)
#define IEEE1905_CONTENT_MAXLEN     (ETH_FRAME_LEN - IEEE1905_HEAD_LEN - IEEE1905_ETH_HEAD_LEN)
#define IEEE1905_LARGE_BUFFER_SIZE (ETH_FRAME_LEN * 8)

/*
 * Supported IEEE 1905.1 protocol version
 */
#define IEEE1905_PROTOCOL_VERSION  0x00

/*
 * IEEE 1905.1 header flags
 */
#define IEEE1905_HEADER_FLAG_LAST_FRAGMENT      ( 1 << 7 )  /* Last fragment */
#define IEEE1905_HEADER_FLAG_RELAY              ( 1 << 6 )  /* Relay message */

#define ieee1905IsMessageFragmented( _flags ) (!( _flags & IEEE1905_HEADER_FLAG_LAST_FRAGMENT ))

#define MAP_SERVICE_STEERING_POLICY_MAX_STAS 128

#define MAP_SERVICE_STEERING_POLICY_MAX_RADIOS 4

#define MAP_SERVICE_STA_LINK_METRIC_MAX_STAS   32
/*
 * IEEE 1905.1 Topology Discovery message timeout
 */
#define IEEE1905_TOPOLOGY_DISCOVERY_TIMEOUT     ( 60 ) /* Seconds */

/*
 * Basic enumerations
 */
typedef enum
{
    IEEE1905_OK = 0,
    IEEE1905_NOK = -1,

} IEEE1905_STATUS;

typedef enum
{
    IEEE1905_FALSE = 0,
    IEEE1905_TRUE = !IEEE1905_FALSE

} IEEE1905_BOOL;

/*
 * IEEE 1905.1 message types
 */
typedef enum ieee1905MessageType_e {
    IEEE1905_MSG_TYPE_TOPOLOGY_DISCOVERY = 0,
    IEEE1905_MSG_TYPE_TOPOLOGY_NOTIFICATION,
    IEEE1905_MSG_TYPE_TOPOLOGY_QUERY,
    IEEE1905_MSG_TYPE_TOPOLOGY_RESPONSE,
    IEEE1905_MSG_TYPE_VENDOR_SPECIFIC,
    IEEE1905_MSG_TYPE_LINK_METRIC_QUERY,
    IEEE1905_MSG_TYPE_LINK_METRIC_RESPONSE,
    IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH,
    IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
    IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS,
    IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RENEW,
    IEEE1905_MSG_TYPE_PB_EVENT_NOTIFICATION,
    IEEE1905_MSG_TYPE_PB_JOIN_NOTIFICATION,
    /// MAP(Easy Mesh) R3
    /// These messages are for sending Q capability response and query
    /// The reason for choosing 0x7FFE and 0x7FFF is that new messages
    /// added in future will not be assigned these values and will continue
    /// from 0x8000 onwards.
    IEEE1905_MSG_TYPE_Q_CAP_QUERY = 0x7FFE,
    IEEE1905_MSG_TYPE_Q_CAP_REPORT = 0x7FFF,
    /// MAP(Easy Mesh) R1
    IEEE1905_MSG_TYPE_ACK = 0x8000,
    IEEE1905_MSG_TYPE_AP_CAP_QUERY = 0x8001,
    IEEE1905_MSG_TYPE_AP_CAP_REPORT = 0x8002,
    IEEE1905_MSG_TYPE_MAP_POLICY_CONFIG = 0x8003,
    IEEE1905_MSG_TYPE_CHANNEL_PREFERENCE_QUERY = 0x8004,
    IEEE1905_MSG_TYPE_CHANNEL_PREFERENCE_REPORT = 0x8005,
    IEEE1905_MSG_TYPE_CHANNEL_SELECTION_REQUEST = 0x8006,
    IEEE1905_MSG_TYPE_CHANNEL_SELECTION_RESPONSE = 0x8007,
    IEEE1905_MSG_TYPE_OPERATING_CHANNEL_REPORT = 0x8008,
    IEEE1905_MSG_TYPE_CLIENT_CAPABILITY_QUERY = 0x8009,
    IEEE1905_MSG_TYPE_CLIENT_CAPABILITY_REPORT = 0x800a,
    IEEE1905_MSG_TYPE_AP_METRICS_QUERY = 0x800b,
    IEEE1905_MSG_TYPE_AP_METRICS_RESPONSE = 0x800c,
    IEEE1905_MSG_TYPE_ASSOC_STA_LINK_METRIC_QUERY = 0x800d,
    IEEE1905_MSG_TYPE_ASSOC_STA_LINK_METRIC_RESPONSE = 0x800e,
    IEEE1905_MSG_TYPE_UNASSOC_STA_METRIC_REQUEST = 0x800f,
    IEEE1905_MSG_TYPE_UNASSOC_STA_METRIC_RESPONSE = 0x8010,
    IEEE1905_MSG_TYPE_BEACON_METRICS_QUERY = 0x8011,
    IEEE1905_MSG_TYPE_BEACON_METRICS_RESPONSE = 0x8012,
    IEEE1905_MSG_TYPE_COMBINED_INFRASTRUCTURE_METRICS = 0x8013,
    IEEE1905_MSG_TYPE_CLIENT_STEERING_REQUEST = 0x8014,
    IEEE1905_MSG_TYPE_CLIENT_STEERING_BTM_REPORT = 0x8015,
    IEEE1905_MSG_TYPE_CLIENT_ASSOC_CONTROL_REQUEST = 0x8016,
    IEEE1905_MSG_TYPE_CLIENT_STEERING_COMPLETED = 0x8017,
    IEEE1905_MSG_TYPE_HIGHER_LAYER_PAYLOAD = 0x8018,
    IEEE1905_MSG_TYPE_BACKHAUL_STEERING_REQUEST = 0x8019,
    IEEE1905_MSG_TYPE_BACKHAUL_STEERING_RESPONSE = 0x801A,
    IEEE1905_MSG_TYPE_CHANNEL_SCAN_REQUEST = 0x801B,
    IEEE1905_MSG_TYPE_CHANNEL_SCAN_REPORT = 0x801C,
    IEEE1905_MSG_TYPE_DPP_CCE_INDICATION = 0x801D,
    IEEE1905_MSG_TYPE_REKEY_REQUEST = 0x801E,
    IEEE1905_MSG_TYPE_DECRYPTION_FAILURE = 0x801F,
    IEEE1905_MSG_TYPE_CAC_REQUEST = 0x8020,
    IEEE1905_MSG_TYPE_CAC_TERMINATION = 0x8021,
    IEEE1905_MSG_TYPE_CLIENT_DISASSOC_STATS = 0x8022,
    IEEE1905_MSG_TYPE_SP = 0x8023,
    IEEE1905_MSG_TYPE_TRAFFIC_SEPRATION_ERROR = 0x8024,
    IEEE1905_MSG_TYPE_ASSOC_STATUS_NOTIFICATION = 0x8025,
    IEEE1905_MSG_TYPE_TUNNELED_MESSAGE = 0x8026,
    IEEE1905_MSG_TYPE_BACKHAUL_STA_CAP_QUERY_MESSAGE = 0x8027,
    IEEE1905_MSG_TYPE_BACKHAUL_STA_CAP_REPORT_MESSAGE = 0x8028,
    IEEE1905_MSG_TYPE_DPP_PROXIED_ENCAP = 0x8029,
    IEEE1905_MSG_TYPE_DPP_DIRECT_ENCAP = 0x802A,
    IEEE1905_MSG_TYPE_DPP_RECONFIG_TRIGGER = 0x802B,
    IEEE1905_MSG_TYPE_DPP_BSS_CONFIG_REQUEST = 0x802C,
    IEEE1905_MSG_TYPE_DPP_BSS_CONFIG_RESPONSE = 0x802D,
    IEEE1905_MSG_TYPE_DPP_BSS_CONFIG_RESULT = 0x802E,
    IEEE1905_MSG_TYPE_DPP_CHIRP = 0x802F,
    IEEE1905_MSG_TYPE_ENCAP_EAPOL = 0x8030,
    IEEE1905_MSG_TYPE_DPP_BS_URI_NOTIFICATION = 0x8031,
    IEEE1905_MSG_TYPE_DPP_BS_URI_QUERY = 0x8032,
    IEEE1905_MSG_TYPE_FAILED_CONNECTION_MESSAGE = 0x8033,
    IEEE1905_MSG_TYPE_AGENT_LIST = 0x8035,

    IEEE1905_MSG_TYPE_RESERVED /* Must be the last */
} ieee1905MessageType_e;

/*
 * IEEE 1905.1 control frame header
 */
typedef struct ieee1905Header_t
{
    u_int8_t    version;    /* Version of IEEE 1905.1 protocol used in frame */
    u_int8_t    reserved;   /* Reserved */
    u_int16_t   type;       /* Message type */
    u_int16_t   mid;        /* Message identifier */
    u_int8_t    fid;        /* Fragment identifier */
    u_int8_t    flags;      /* Flags */

} ieee1905Header_t;

/*
 * IEEE 1905.1 TLV
 */
typedef enum ieee1905TlvType_e {
    IEEE1905_TLV_TYPE_END_OF_MESSAGE = 0,
    IEEE1905_TLV_TYPE_AL_ID = 1,
    IEEE1905_TLV_TYPE_MAC_ID = 2,
    IEEE1905_TLV_TYPE_DEVICE_INFORMATION = 3,
    IEEE1905_TLV_TYPE_DEVICE_BRIDGING_CAPABILITY = 4,
    IEEE1905_TLV_TYPE_MEDIA_TYPE = 5,
    IEEE1905_TLV_TYPE_LEGACY_NEIGHBOR = 6,
    IEEE1905_TLV_TYPE_NEIGHBOR_DEVICE = 7,
    IEEE1905_TLV_TYPE_LINK_METRIC_QUERY = 8,
    IEEE1905_TLV_TYPE_TRANSMITTER_LINK_METRIC_RESPONSE = 9,
    IEEE1905_TLV_TYPE_RECEIVER_LINK_METRIC_RESPONSE = 10,
    IEEE1905_TLV_TYPE_VENDOR_SPECIFIC = 11,
    IEEE1905_TLV_TYPE_RESULT_CODE = 12,
    IEEE1905_TLV_TYPE_SEARCHED_ROLE = 13,
    IEEE1905_TLV_TYPE_FREQ_BAND = 14,
    IEEE1905_TLV_TYPE_SUPPORTED_ROLE = 15,
    IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND = 16,
    IEEE1905_TLV_TYPE_WPS = 17,
    IEEE1905_TLV_TYPE_PUSH_BUTTON_EVENT = 18,
    IEEE1905_TLV_TYPE_PUSH_BUTTON_JOIN = 19,
    IEEE1905_TLV_TYPE_SUPPORTED_SERVICE = 0x80,
    IEEE1905_TLV_TYPE_SEARCHED_SERVICE = 0x81,
    IEEE1905_TLV_TYPE_RADIO_IDENTIFIER = 0x82,
    IEEE1905_TLV_TYPE_OPERATIONAL_BSS = 0x83,
    IEEE1905_TLV_TYPE_ASSOCIATED_CLIENTS = 0x84,
    IEEE1905_TLV_TYPE_AP_RADIO_BASIC_CAP = 0x85,
    IEEE1905_TLV_TYPE_AP_HT_CAP = 0x86,
    IEEE1905_TLV_TYPE_AP_VHT_CAP = 0x87,
    IEEE1905_TLV_TYPE_AP_HE_CAP = 0x88,
    IEEE1905_TLV_TYPE_STEERING_POLICY = 0x89,
    IEEE1905_TLV_TYPE_METRIC_REPORT_POLICY = 0x8A,
    IEEE1905_TLV_TYPE_CHANNEL_PREFERENCE = 0x8B,
    IEEE1905_TLV_TYPE_RADIO_OPERATION_RESTRICTION = 0x8C,
    IEEE1905_TLV_TYPE_TRANSMIT_POWER_LIMIT = 0x8D,
    IEEE1905_TLV_TYPE_CHANNEL_SELECTION_RESPONSE = 0x8E,
    IEEE1905_TLV_TYPE_OPERATING_CHANNEL_REPORT = 0x8F,
    IEEE1905_TLV_TYPE_CLIENT_INFO = 0x90,
    IEEE1905_TLV_TYPE_CLIENT_CAP_REPORT = 0x91,
    IEEE1905_TLV_TYPE_CLIENT_ASSOC_EVENT = 0x92,
    IEEE1905_TLV_TYPE_AP_METRIC_QUERY = 0x93,
    IEEE1905_TLV_TYPE_AP_METRICS = 0x94,
    IEEE1905_TLV_TYPE_STA_MAC = 0x95,
    IEEE1905_TLV_TYPE_ASSOC_STA_LINK_METRICS = 0x96,
    IEEE1905_TLV_TYPE_UNASSOC_STA_LINK_METRICS_QUERY = 0x97,
    IEEE1905_TLV_TYPE_UNASSOC_STA_LINK_METRICS_RESPONSE = 0x98,
    IEEE1905_TLV_TYPE_BEACON_METRICS_QUERY = 0x99,
    IEEE1905_TLV_TYPE_BEACON_METRICS_RESPONSE = 0x9A,
    IEEE1905_TLV_TYPE_STEERING_REQUEST = 0x9B,
    IEEE1905_TLV_TYPE_STEERING_BTM_REPORT = 0x9C,
    IEEE1905_TLV_TYPE_CLIENT_ASSOICATION_CONTROL = 0x9D,
    IEEE1905_TLV_TYPE_BACKHAUL_STEERING_REQUEST = 0x9E,
    IEEE1905_TLV_TYPE_BACKHAUL_STEERING_RESPONSE = 0x9F,
    IEEE1905_TLV_TYPE_HIGHER_LAYER_PAYLOAD = 0xA0,
    IEEE1905_TLV_TYPE_AP_CAP = 0xA1,
    IEEE1905_TLV_TYPE_ASSOC_STA_TRAFFIC_STATS = 0xA2,
    IEEE1905_TLV_TYPE_ERROR = 0xA3,
    IEEE1905_TLV_TYPE_CHANNEL_SCAN_REPORT_POLICY = 0xA4,
    IEEE1905_TLV_TYPE_CHANNEL_SCAN_CAP = 0xA5,
    IEEE1905_TLV_TYPE_CHANNEL_SCAN_REQUEST = 0xA6,
    IEEE1905_TLV_TYPE_CHANNEL_SCAN_RESULT = 0xA7,
    IEEE1905_TLV_TYPE_TIMESTAMP = 0xA8,
    IEEE1905_TLV_TYPE_SECURITY_CAP = 0xA9,
    IEEE1905_TLV_TYPE_AP_WIFI6_CAP = 0xAA,
    IEEE1905_TLV_TYPE_MIC = 0xAB,
    IEEE1905_TLV_TYPE_ENCRYPTED = 0xAC,
    IEEE1905_TLV_TYPE_CAC_REQUEST = 0xAD,
    IEEE1905_TLV_TYPE_CAC_TERMINATION = 0xAE,
    IEEE1905_TLV_TYPE_CAC_COMPLETE = 0xAF,
    IEEE1905_TLV_TYPE_WIFI6_STA_STATS = 0xB0,
    IEEE1905_TLV_TYPE_CAC_STATUS_REPORT = 0xB1,
    IEEE1905_TLV_TYPE_CAC_CAP = 0xB2,
    IEEE1905_TLV_TYPE_MAP_VERSION = 0xB3,
    IEEE1905_TLV_TYPE_R2_APCAP = 0xB4,
    IEEE1905_TLV_TYPE_8021Q_RULES = 0xB5,
    IEEE1905_TLV_TRAFFIC_SEPARATON_POLICY = 0xB6,
    IEEE1905_TLV_TYPE_BSS_CONFIG_REPORT = 0xB7,
    IEEE1905_TLV_TYPE_BSSID = 0xB8,
    IEEE1905_TLV_TYPE_SP_RULE = 0xB9,
    IEEE1905_TLV_TYPE_DSCP_MAPPING = 0xBA,
    IEEE1905_TLV_TYPE_BSS_CONFIG_REQUEST = 0xBB,
    IEEE1905_TLV_TYPE_R2_ERROR_CODE = 0xBC,
    IEEE1905_TLV_TYPE_BSS_CONFIG_RESPONSE = 0xBD,
    IEEE1905_TLV_TYPE_AP_RADIO_ADVANCED_CAP = 0xBE,
    IEEE1905_TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION = 0xBF,
    IEEE1905_TLV_TYPE_SOURCE_INFO = 0xC0,
    IEEE1905_TLV_TYPE_TUNNELED_MSG_TYPE = 0xC1,
    IEEE1905_TLV_TYPE_TUNNELED_PAYLOAD = 0xC2,
    IEEE1905_TLV_TYPE_R2_STEERING_REQUEST = 0xC3,
    IEEE1905_TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY = 0xC4,
    IEEE1905_TLV_TYPE_METRIC_COLLECTION_INTERVAL = 0xC5,
    IEEE1905_TLV_TYPE_RADIO_METRIC = 0xC6,
    IEEE1905_TLV_TYPE_AP_EXTENDED_METRICS = 0xC7,
    IEEE1905_TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS = 0xC8,
    IEEE1905_TLV_TYPE_STATUS_CODE = 0xC9,
    IEEE1905_TLV_TYPE_DISASSOC_REASON_CODE = 0xCA,
    IEEE1905_TLV_TYPE_BSTA_RADIO_CAP = 0xCB,
    IEEE1905_TLV_TYPE_AKM_SUITE_CAP = 0xCC,
    IEEE1905_TLV_TYPE_ENCAP_DPP = 0xCD,
    IEEE1905_TLV_TYPE_ENCAP_EAPOL = 0xCE,
    IEEE1905_TLV_TYPE_DPP_BS_URI_NOTIFICATION = 0xCF,
    IEEE1905_TLV_TYPE_BACKHAUL_BSS_CONFIG = 0xD0,
    IEEE1905_TLV_TYPE_DPP_MESSAGE = 0xD1,
    IEEE1905_TLV_TYPE_DPP_CCE_INDICATION = 0xD2,
    IEEE1905_TLV_TYPE_DPP_CHIRP_VALUE = 0xD3,
    IEEE1905_TLV_TYPE_DEVICE_INVENTORY = 0xD4,
    IEEE1905_TLV_TYPE_AGENTS_LIST = 0xD5,

    IEEE1905_TLV_TYPE_RESERVED /* Must be the last */
} ieee1905TlvType_e;

typedef enum ieee1905ErrorCode_t
{
    IEEE1905_TLV_ERROR_CODE_RESERVED,
    IEEE1905_TLV_ERROR_CODE_STA_ASSOCIATED,
    IEEE1905_TLV_ERROR_CODE_STA_NOT_ASSOCIATED,
    IEEE1905_TLV_ERROR_CODE_UNSPECIFIED_FAILURE,
    IEEE1905_TLV_ERROR_CODE_BACKHAUL_CANNOT_OPERATE,
    IEEE1905_TLV_ERROR_CODE_TARGET_SIGNAL_TOO_WEAK,
    IEEE1905_TLV_ERROR_CODE_TARGET_BSS_AUTH_REJECTED
} ieee1905ErrorCode_e;

/*
 * IEEE1905.1 Media types
 */

typedef enum
{
    IEEE1905_MEDIA_TYPE_IEEE802_3,
    IEEE1905_MEDIA_TYPE_IEEE802_11,
    IEEE1905_MEDIA_TYPE_IEEE1901,
    IEEE1905_MEDIA_TYPE_MOCA,

    IEEE1905_MEDIA_TYPE_RESERVED,
    IEEE1905_MEDIA_TYPE_UNKNOWN = 255

} ieee1905MediaType_e;

enum
{
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_3U_FAST_ETHERNET,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_3AB_GIGABIT_ETHERNET,
};

enum
{
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11B_2_4G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11G_2_4G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11A_5G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_2_4G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_5G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AC_5G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AD_60G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AF,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AXG_2_4G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AXA_5G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AXA_6G,
    IEEE1905_MEDIA_DESCRIPTION_IEEE802_RESERVED

};

enum
{
    IEEE1905_MEDIA_DESCRIPTION_IEEE1901_WAVELET,
    IEEE1905_MEDIA_DESCRIPTION_IEEE1901_OFDM,
};

enum
{
    IEEE1905_MEDIA_DESCRIPTION_MOCA_V1_1,
};

#define IEEE1905_SPECIFIC_INFO_IEEE80211( _info ) ( _info << 6 )
#define IEEE1905_SPECIFIC_INFO_IEEE80211_EXTRACT_ROLE( _info ) ( _info >> 6 )

enum
{
    IEEE1905_SPECIFIC_INFO_IEEE80211_AP,
    IEEE1905_SPECIFIC_INFO_IEEE80211_STATION,
    IEEE1905_SPECIFIC_INFO_IEEE80211_P2P,

    IEEE1905_SPECIFIC_INFO_IEEE80211_RESERVED
};

typedef struct ieee1905MediaType_t {
    u_int8_t medtypeClass;
    u_int8_t medtypePhy;
    u_int8_t val_length;
    u_int8_t val[ 0 ];
} ieee1905MediaType_t;

typedef struct ieee1905MediaSpecificHPAV_t
{
    u_int8_t avln[7];
} ieee1905MediaSpecificHPAV_t;

typedef struct ieee1905MediaSpecificWiFi_t
{
    u_int8_t bssid[ETH_ALEN];
    u_int8_t role;
    u_int8_t reserved[3];
} ieee1905MediaSpecificWiFi_t;

/*
 * Legacy bridges
 */
enum
{
    IEEE1905_LEGACY_BRIDGES_NONE,
    IEEE1905_LEGACY_BRIDGES_EXIST,
};


/*
 * IEEE 1905.1 control frame content(one or more TLV).
 *          -----------
 *         |    TLV    |
 *          -----------
 *         |    TLV    |
 *          -----------
 *         |    ...    |
 *          -----------
 *         | EndOfMsg  |
 *          -----------
 */
typedef struct ieee1905TLV_t
{
    u_int8_t type;      /* Type of TLV */
    u_int16_t length;   /* Length of contents */
    u_int8_t val[ 0 ];  /* Contents data */

} __attribute__((packed)) ieee1905TLV_t;

/*
 * Complete Ethernet IEEE 1905.1 control frame message
 */
typedef struct ieee1905Message_t
{
    struct ether_header etherHeader;
    struct ieee1905Header_t ieee1905Header;

    u_int8_t content[ IEEE1905_CONTENT_MAXLEN ];

} ieee1905Message_t;

/*
 * Generic TLV structures used in multiple message types
 */

typedef struct ieee1905NeighbourDevice_t
{
    struct ether_addr addr;
    u_int8_t legacyBridge;

} __attribute__((packed)) ieee1905NeighbourDevice_t;


typedef struct ieee1905SingleAddressTLV_t
{
    ieee1905TLV_t tlvHeader;
    struct ether_addr mac;
} ieee1905SingleAddressTLV_t;

typedef struct ieee1905VendorSpecificHeaderTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t oui[ IEEE1905_OUI_LENGTH ];
    u_int8_t val[ 0 ];
} ieee1905VendorSpecificHeaderTLV_t;

/*
 * Link metrics structures and enumerations
 */

enum /* used in queryScope field */
{
    IEEE1905_LINK_METRIC_SCOPE_ALL_NEIGHBORS = 0,
    IEEE1905_LINK_METRIC_SCOPE_SPECIFIC_NEIGHBOR,

    IEEE1905_LINK_METRIC_SCOPE_RESERVED
};

enum /* used in requestedMetrics field */
{
    IEEE1905_LINK_METRIC_REQ_TX = 0,
    IEEE1905_LINK_METRIC_REQ_RX,
    IEEE1905_LINK_METRIC_REQ_TX_RX,

    IEEE1905_LINK_METRIC_REQ_RESERVED
};

enum
{
    IEEE1905_LINK_METRIC_RESPONSE_INVALID_NEIGHBOR = 0
};

typedef struct ieee1905LinkMetricQuery1TLV_t /* used with queryScope == IEEE1905_LINK_METRIC_SCOPE_SPECIFIC_NEIGHBOR */
{
    ieee1905TLV_t tlvHeader;
    u_int8_t queryScope;
    struct ether_addr neighborAlId;
    u_int8_t requestedMetrics;
} __attribute__((packed)) ieee1905LinkMetricQuery1TLV_t;

/**
 * @brief Tx link metrics specified in Table 6-18 of IEEE 1905 Standard-2013
 */
typedef struct ieee1905TransmitterLinkMetric_t {
    /// Interface type as defined in Table 6-12 of IEEE 1905 Standard-2013
    u_int16_t intfType;

    /// Whether the 1905.1 link includes 802.1 bridges
    u_int8_t bridgeFlag;

    /// Number of lost packets on the Tx side of the link
    u_int32_t pktErrors;

    /// Total number of packets transmitted
    u_int32_t pktSent;

    /// Max MAC throughput of the egress link in Mbps
    u_int16_t macTpCapacity;

    /// Average percentage of time the link is available for data transmission
    u_int16_t linkAvailability;

    /// PHY rate at the transmitter in Mbps
    u_int16_t phyRate;
} __attribute__((packed)) ieee1905TransmitterLinkMetric_t;

/**
 * @brief Tx link data for a link between the receiving device (i.e. device
 *        being queried) and its connected neighboring device
 */
typedef struct ieee1905TransmitterLinkData_t {
    /// Interface address of the receiving device that connects to a neighboring
    /// interface
    struct ether_addr devIntfMAC;

    /// Interface address of the neighboring device that connects to the receiving
    /// device
    struct ether_addr neighborIntfMAC;

    /// Tx link metrics
    ieee1905TransmitterLinkMetric_t metrics;
} __attribute__((packed)) ieee1905TransmitterLinkData_t;

/**
 * @brief Tx link metrics TLV specified in Table 6-17 of IEEE 1905 Standard-2013
 */
typedef struct ieee1905TransmitterLinkMetricTLV_t {
    /// Type and length of the TLV
    ieee1905TLV_t tlvHeader;

    /// Address of the device being queried
    struct ether_addr devAlMAC;

    /// Address of the neighboring device
    struct ether_addr neighborAlMAC;

    /// Tx link metrics
    ieee1905TransmitterLinkData_t data[];
} __attribute__((packed)) ieee1905TransmitterLinkMetricTLV_t;

// Constants used to calculate TLV length in Table 6.19 of IEEE 1905 Standard
#define IEEE1905_TX_LINK_METRIC_COMMON_DATA_SIZE 12
#define IEEE1905_TX_LINK_METRIC_PER_LINK_DATA_SIZE 29

/**
 * @brief Rx link metrics specified in Table 6-20 of IEEE 1905 Standard-2013
 */
typedef struct ieee1905ReceiverLinkMetric_t {
    /// Interface type as defined in Table 6-12 of IEEE 1905 Standard-2013
    u_int16_t intfType;

    /// Number of lost packets
    u_int32_t pktErrors;

    /// Total number of packets received at the interface
    u_int32_t pktRcvd;

    /// For 802.11: RSSI (in dB) of ingress frame. For other interfaces, 0xFF
    u_int8_t rssi;
} __attribute__((packed)) ieee1905ReceiverLinkMetric_t;

/**
 * @brief Rx link data for a link between the receiving device (i.e. device
 *        being queried) and its connected neighboring device
 */
typedef struct ieee1905ReceiverLinkData_t {
    /// Interface address of the receiving device that connects to a neighboring
    /// interface
    struct ether_addr devIntfMAC;

    /// Interface address of the neighboring device that connects to the receiving
    /// device
    struct ether_addr neighborIntfMAC;

    /// Rx link metrics
    ieee1905ReceiverLinkMetric_t metrics;
} __attribute__((packed)) ieee1905ReceiverLinkData_t;

/**
 * @brief Rx link metric TLV  specified in Table 6-17 of IEEE 1905 Standard-2013
 */
typedef struct ieee1905ReceiverLinkMetricTLV_t {
    /// Type and length of the TLV
    ieee1905TLV_t tlvHeader;

    /// Address of the device being queried
    struct ether_addr devAlMAC;

    /// Address of the neighboring device
    struct ether_addr neighborAlMAC;

    /// Rx link metrics
    ieee1905ReceiverLinkData_t data[];
} __attribute__((packed)) ieee1905ReceiverLinkMetricTLV_t;

// Constants used to calculate TLV length in Table 6.19 of IEEE 1905 Standard
#define IEEE1905_RX_LINK_METRIC_COMMON_DATA_SIZE 12
#define IEEE1905_RX_LINK_METRIC_PER_LINK_DATA_SIZE 23

typedef struct ieee1905LinkMetricQuery2TLV_t /* used with queryScope == IEEE1905_LINK_METRIC_SCOPE_ALL_NEIGHBORS */
{
    ieee1905TLV_t tlvHeader;
    u_int8_t queryScope;
    u_int8_t requestedMetrics;
} __attribute__((packed)) ieee1905LinkMetricQuery2TLV_t;

typedef enum {
    IEEE1905_MAP_SUPPORTED_SERVICE_CONTROLLER = 0,
    IEEE1905_MAP_SUPPORTED_SERVICE_AGENT = 1
} ieee1905SupportedServiceType_e;

#define IEEE1905_CLIENT_ASSOC_EVENT_CONNECTED    (1 << 7)
#define IEEE1905_CLIENT_ASSOC_EVENT_DISCONNECTED 0

typedef struct ieee1905ClientAssocEventTLV_t
{
    u_int8_t stamac[ ETH_ALEN ];
    u_int8_t bssid[ ETH_ALEN ];
    u_int8_t status; // 1<<7 for assoc 0 for disconnection
} __attribute__((packed)) ieee1905ClientAssocEventTLV_t;

typedef enum {
    IEEE1905_DEVICE_PROVISIONING_PROTOCOL = 0,
    IEEE1905_DEVICE_PROVISIONING_RESERVED /* Must Be Last */
} ieee1905OnboardingProtocolsSupported_e;

typedef enum {
    IEEE1905_MSG_INTEGRITY_HMAC_SHA256 = 0,
    IEEE1905_MSG_INTEGRITY_RESERVED /* Must Be Last */
} ieee1905MsgIntegrityAlgoSupported_e;

typedef enum {
    IEEE1905_MSG_ENCRYPTION_AES_SIV = 0,
    IEEE1905_MSG_ENCRYPTION_RESERVED /* Must Be Last */
} ieee1905MsgEncryptionAlgoSupported_e;

typedef struct ieee1905SecurityCap_t {
    /// 0x00: 1905 Device Provisioning Protocol.
    /// 0x01 - 0xFF: Reserved.
    u_int8_t protocolSupport;

    /// 0x00: HMAC-SHA256.
    /// 0x01 - 0xFF: Reserved.
    u_int8_t msgIntegritySupport;

    /// 0x00: AES-SIV.
    /// 0x01 - 0xFF: Reserved.
    u_int8_t msgEncryptionSupport;
} __attribute__((packed)) ieee1905SecurityCap_t;

// Age value that means the client has been associated for this amount of
// time or longer.
#define IEEE1905_ASSOC_CLIENTS_AGE_SECS_MAX 0xFFFFu

/*
 * AP Auto-Configuration structures and enumerations
 */

enum /* used in searchedRole and supportedRole fields */
{
    IEEE1905_AP_AUTOCONFIG_ROLE_REGISTRAR = 0,
    IEEE1905_AP_AUTOCONFIG_ROLE_AP_ENROLLEE
};

enum /* used in freqBand and supportedFreqBand fields */
{
    IEEE1905_AP_AUTOCONFIG_FREQ_BAND_2P4G = 0,
    IEEE1905_AP_AUTOCONFIG_FREQ_BAND_5G,
    IEEE1905_AP_AUTOCONFIG_FREQ_BAND_60G
};

typedef struct ieee1905APAutoConfigSearchedRoleTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t searchedRole;
} ieee1905APAutoConfigSearchedRoleTLV_t;

typedef struct ieee1905APAutoConfigFreqBandTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t freqBand;
} ieee1905APAutoConfigFreqBandTLV_t;

typedef struct ieee1905APAutoConfigSupportedRoleTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t supportedRole;
} ieee1905APAutoConfigSupportedRoleTLV_t;

typedef struct ieee1905APAutoConfigSupportedFreqBandTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t supportedFreqBand;
} ieee1905APAutoConfigSupportedFreqBandTLV_t;

typedef struct ieee1905APAutoConfigWPSTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t wps[0];
} ieee1905APAutoConfigWPSTLV_t;

/*
 * Push Button structures
 */

typedef struct ieee1905PushButtonEventTLV_t
{
    ieee1905TLV_t tlvHeader;
    u_int8_t numEntries;
    u_int8_t val[ 0 ];
} ieee1905PushButtonEventTLV_t;

typedef struct ieee1905PushButtonJoinTLV_t
{
    ieee1905TLV_t tlvHeader;
    struct ether_addr alID;
    u_int16_t midPBEvent;
    struct ether_addr txIfMac;
    struct ether_addr newIfMac;
} __attribute__((packed)) ieee1905PushButtonJoinTLV_t;

#define IEEE1905_DISPATCH_FIXED_FIELDS_SIZE 12

typedef struct ieee1905DispatchFrame_t
{
    u_int16_t msgType;
    u_int16_t mid;
    struct ether_addr alId;
    u_int16_t tlvType;
    char content[0];
} ieee1905DispatchFrame_t;

// ====================================================================
// Types and Structs used for LBD
// ====================================================================

#define IEEE1905_MAX_OPERATING_CLASSES 25
#define IEEE1905_MAX_CHANNELS_PER_OP_CLASS 17
#define IEEE1905_MAX_SSID_LEN 32

/**
 * @brief Representation of the beacon metrics query
 */
typedef struct ieee1905BcnMetricsQuery_t {
    /// The MAC address of the STA for which beacon report is requested
    struct ether_addr staAddr;

    /// Operating class to be specified in the Beacon request
    u_int8_t opClass;

    /// Channel number to be specified in the Beacon request
    u_int8_t chanNum;

    /// BSSID to be specified in the Beacon request
    struct ether_addr bssid;

    /// Reporting Detail value to be specified in the Beacon Request
    /// One of wlanif_bcnMetricQueryRptDetail_e
    u_int8_t reportDetail;

    /// SSID length
    u_int8_t ssidLen;

    /// SSID
    char ssid[IEEE1905_MAX_SSID_LEN];

    /// Number of AP Channel Reports
    u_int8_t numChanReport;

    struct {
        /// Length of an AP Channel Report
        u_int8_t lenChanReport;

        /// Operating Class in an AP Channel Report
        u_int8_t chanReportOpClass;

        /// Channel List in an AP Channel Report
        u_int8_t chanList[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];
    } chanReport[IEEE1905_MAX_OPERATING_CLASSES];

    /// Number of element IDs
    u_int8_t numElementID;

    /// Element List
    u_int8_t elementList[];
} ieee1905BcnMetricsQuery_t;

typedef struct ieee1905StaTrafficStats_t {
    /// Raw counter of the number of bytes sent to the STA
    u_int32_t txBytes;

    /// Raw counter of the number of bytes received from the STA
    u_int32_t rxBytes;

    /// Raw counter of the number of packets successfully sent to the STA
    u_int32_t pktsSent;

    /// Raw counter of the number of packets received from the STA
    u_int32_t pktsRcvd;

    /// Raw counter of the number of packets not transmitted to the STA
    /// due to errors
    u_int32_t txPktErr;

    /// Raw counter of the number of packets received in error from the STA
    u_int32_t rxPktErr;

    /// Raw counter of the number of packets sent to the STA
    /// with retry flag set
    u_int32_t cntRetx;
} ieee1905StaTrafficStats_t;

// ====================================================================
// Types and constants used for ieee1905 TX and RX messages
// ====================================================================

typedef struct ieee1905APCapabilities_t {
    /// Support Unassociated STA Link Metrics reporting on the channels its
    /// BSSs are currently operating on.
    IEEE1905_BOOL unassocStaLinkMetricsOnCurrChan : 1;

    /// Support Unassociated STA Link Metrics reporting on the channels its
    /// BSSs are not currently operating on.
    IEEE1905_BOOL unassocStaLinkMetricsOnNonCurrChan : 1;

    /// Support Agent-initiated RSSI-based steering
    IEEE1905_BOOL agentInitiatedRssiBasedSteering : 1;

    u_int8_t reserved : 5;
} ieee1905APCapabilities_t;

typedef struct ieee1905QCapabilities_t {
    /// Enhanced SP enabled flag
    IEEE1905_BOOL enhancedSPEnabled : 1;
    /// QSP enabled flag
    IEEE1905_BOOL qspEnabled : 1;

    u_int32_t reserved : 30;
} ieee1905QCapabilities_t;

/// each rule has CPU and memory penality so restricting with MAX value
#define IEEE1905_MAP_MAX_SP_RULES 10
typedef struct ieee1905SPRule_t {
    /// Service Prioritization Rule Identifier.
    u_int32_t spRuleID;
    /// Add-Remove Filter Rule bit.
    /// 1 means add 0 means delete
    IEEE1905_BOOL addDeleteRule : 1;
    /// Rule Precedence – higher number means higher priority.
    u_int8_t rulePrecedence;
    /// Rule Output The value of or method  used to select the 802.1Q C-TAG
    /// PCP value with which  to mark the matched packet.
    u_int8_t ruleOutput;
    /// Rule Match Always True
    /// S(skip field matching) flag
    IEEE1905_BOOL ruleMatchAlwaysTrue : 1;
    /// Match UP in 802.11 QoS Control flag
    IEEE1905_BOOL matchUP : 1;
    /// UP in 802.11 QoS Control Match Sense flag
    IEEE1905_BOOL matchUPSense : 1;
    /// Match Source MAC Address flag
    IEEE1905_BOOL matchSourceMAC : 1;
    /// Match Source MAC Address sense
    IEEE1905_BOOL matchSourceMACSense : 1;
    /// Match Destination MAC Address flags
    IEEE1905_BOOL matchDstMAC : 1;
    /// Destination MAC Address Match Sense Flag
    IEEE1905_BOOL matchDstMACSense : 1;
    /// UP in 802.11 QoS Control
    u_int8_t userPriority;
    /// Source MAC Address
    /// If “Match Source MAC Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    struct ether_addr srcAddr;
    /// Destination MAC Address
    /// If “Match Destination MAC Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    struct ether_addr dstAddr;

    /// internal field to keep track if rule is valid or not
    IEEE1905_BOOL valid;

} ieee1905SPRule_t;

typedef struct ieee1905QSPRule_t {
    /// Service Prioritization Rule Identifier.
    u_int32_t spRuleID;
    /// Match Source IPv4 Address flag
    IEEE1905_BOOL matchSourceIPv4 : 1;
    /// Match Source IPv4 Address sense
    IEEE1905_BOOL matchSourceIPv4Sense : 1;
    /// Match Destination IPv4 Address flags
    IEEE1905_BOOL matchDstIPv4 : 1;
    /// Destination IPv4 Address Match Sense Flag
    IEEE1905_BOOL matchDstIPv4Sense : 1;

    /// Match Source IPv6 Address flag
    IEEE1905_BOOL matchSourceIPv6 : 1;
    /// Match Source IPv6 Address sense
    IEEE1905_BOOL matchSourceIPv6Sense : 1;
    /// Match Destination IPv6 Address flags
    IEEE1905_BOOL matchDstIPv6 : 1;
    /// Destination IPv6 Address Match Sense Flag
    IEEE1905_BOOL matchDstIPv6Sense : 1;

    /// Match Source port flag
    IEEE1905_BOOL matchSourcePort : 1;
    /// Match Source port sense
    IEEE1905_BOOL matchSourcePortSense : 1;
    /// Match Destination port flags
    IEEE1905_BOOL matchDstPort : 1;
    /// Destination port Match Sense Flag
    IEEE1905_BOOL matchDstPortSense : 1;

    /// Match protocol number or next header flag
    IEEE1905_BOOL matchProtocolNumber : 1;
    /// Match protocol number or next header Match sense flag
    IEEE1905_BOOL matchProtocolNumberSense : 1;
    /// Match VLAN ID flags
    IEEE1905_BOOL matchVLANID : 1;
    /// Match VLAN ID Match sense flags
    IEEE1905_BOOL matchVLANIDSense : 1;

    /// Match dscp flags
    IEEE1905_BOOL matchDscp : 1;
    /// Match dscp sense flags
    IEEE1905_BOOL matchDscpSense : 1;

    /// Source IPv4 Address
    /// If “Match Source IPv4 Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    u_int32_t srcIPv4Addr;
    /// Source IPv6 Address
    /// If “Match Source IPv6 Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    u_int32_t srcIPv6Addr[4];
    /// Destination IPv4 Address
    /// If “Match Destination IPv4 Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    u_int32_t dstIPv4Addr;
    /// Destination IPv6 Address
    /// If “Match Destination IPv6 Address” flag bit is set to one,
    /// this field shall be included, otherwise this field shall be omitted.
    u_int32_t dstIPv6Addr[4];
    /// Source Port
    u_int16_t srcPort;
    /// Destination Port
    u_int16_t dstPort;
    /// Protocol Number or Next Header
    u_int8_t protocolNumber;
    /// VLAN ID
    u_int16_t vlanID;

    /// DSCP value
    u_int8_t dscp;

    /// Service interval downlink
    u_int8_t serviceIntervalDl;
    /// Service interval uplink
	u_int8_t serviceIntervalUl;
	/// Burst size downlink
	uint32_t burstSizeDl;
	/// Burst size uplink
	uint32_t burstSizeUl;

} ieee1905QSPRule_t;

#define MAP_SERVICE_INVENTORY_STRING_LENGTH 64
typedef struct ieee1905DeviceInventoryInfo_t {
    u_int8_t serialNumberLen;
    u_int8_t serialNumber[MAP_SERVICE_INVENTORY_STRING_LENGTH];

    u_int8_t softwareVersionNumberLen;
    u_int8_t softwareVersionNumber[MAP_SERVICE_INVENTORY_STRING_LENGTH];

    u_int8_t executionEnvLen;
    u_int8_t executionEnv[MAP_SERVICE_INVENTORY_STRING_LENGTH];

    u_int8_t radioNum;

    struct {
        struct ether_addr radioAddr;
        u_int8_t chipSetVendorLen;
        u_int8_t chipSetVendor[MAP_SERVICE_INVENTORY_STRING_LENGTH];
    } radios[MAP_SERVICE_STEERING_POLICY_MAX_RADIOS];
} deviceInventoryInfo_t;

// Accounts for worst case where a 5G radio operates on both 5GL and 5GH.
#define IEEE1905_MAX_OP_CLASS_CHAN_PAIRS 120

/**
 * @brief The basic capabilities for a specific radio on an AP
 *
 * @warning Same structure is used in driver api any change here should be done
 * in driver as well.
 */
typedef struct ieee1905APRadioBasicCapabilities_t {
    /// Maximum number of BSSes supported by this radio
    u_int8_t maxSupportedBSS;

    /// Number of operating classes supported for this radio
    u_int8_t numSupportedOpClasses;

    /// Info for each supported operating class
    struct {
        /// Operating class that this radio is capable of operating on
        /// as defined in Table E-4.
        u_int8_t opClass;

        /// Maximum transmit power EIRP the radio is capable of transmitting
        /// in the current regulatory domain for the operating class.
        /// The field is coded as 2's complement signed dBm.
        int8_t maxTxPwrDbm;

        /// Number of statically non-operable channels in the operating class
        /// Other channels from this operating class which are not listed here
        /// are supported by this radio.
        u_int8_t numNonOperChan;

        /// Channel number which is statically non-operable in the operating class
        /// (i.e. the radio is never able to operate on this channel)
        u_int8_t nonOperChanNum[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];
    } opClasses[IEEE1905_MAX_OPERATING_CLASSES];
} ieee1905APRadioBasicCapabilities_t;

/**
 * @brief The HT capabilities for a specific radio on an AP.
 *
 * @warning Same structure is used in driver api, any change here should be done
 * in driver as well.
 */
typedef struct ieee1905APHtCapabilities_t {
    /// Maximum number of supported Tx spatial streams
    u_int8_t maxTxNSS;

    /// Maximum number of supported Rx spatial streams
    u_int8_t maxRxNSS;

    /// Short GI support for 20 MHz
    IEEE1905_BOOL shortGiSupport20Mhz : 1;

    /// Short GI support for 40 MHz
    IEEE1905_BOOL shortGiSupport40Mhz : 1;

    // HT support for 40 MHz
    IEEE1905_BOOL htSupport40Mhz : 1;

    u_int8_t reserved : 5;
} ieee1905APHtCapabilities_t;

/**
 * @brief The VHT capabilities for a specific radio on an AP
 *
 * @warning Same structure is used in driver api, any change
 * here should be done in driver as well.
 */
typedef struct ieee1905APVhtCapabilities_t {
    /// Supported VHT Tx MCS
    /// Supported set to VHT MCSs that can be received.
    /// Set to Tx VHT MCS Map field per Figure 9-562.
    u_int16_t supportedTxMCS;

    /// Supported VHT Rx MCS
    /// Supported set to VHT MCSs that can be transmitted.
    /// Set to Rx VHT MCS Map field per Figure 9-562.
    u_int16_t supportedRxMCS;

    /// Maximum number of supported Tx spatial streams
    u_int8_t maxTxNSS;

    /// Maximum number of supported Rx spatial streams
    u_int8_t maxRxNSS;

    /// Short GI support for 80 MHz
    IEEE1905_BOOL shortGiSupport80Mhz : 1;

    /// Short GI support for 160 and 80+80 MHz
    IEEE1905_BOOL shortGiSupport160Mhz80p80Mhz : 1;

    /// VHT support for 80+80 MHz
    IEEE1905_BOOL support80p80Mhz : 1;

    /// VHT support for 160 MHz
    IEEE1905_BOOL support160Mhz : 1;

    /// SU beamformer capable
    IEEE1905_BOOL suBeamformerCapable : 1;

    /// MU beamformer capable
    IEEE1905_BOOL muBeamformerCapable : 1;

    u_int8_t reserved : 2;
} ieee1905APVhtCapabilities_t;

#define IEEE1905_MAX_HE_MCS 6
/**
 * @brief The HE capabilities for a specific radio on an AP
 */
typedef struct ieee1905APHeCapabilities_t {
    /// Number of supported HE MCS entries
    u_int8_t numMCSEntries;

    /// Supported HE MCS indicating set of supported HE Tx and Rx MCS
    u_int16_t supportedHeMCS[IEEE1905_MAX_HE_MCS];

    /// Maximum number of supported Tx spatial streams
    u_int8_t maxTxNSS;

    /// Maximum number of supported Rx spatial streams
    u_int8_t maxRxNSS;

    /// HE support for 80+80 MHz
    IEEE1905_BOOL support80p80Mhz : 1;

    /// HE support for 160 MHz
    IEEE1905_BOOL support160Mhz : 1;

    /// SU beamformer capable
    IEEE1905_BOOL suBeamformerCapable : 1;

    /// MU beamformer capable
    IEEE1905_BOOL muBeamformerCapable : 1;

    /// UL MU-MIMO capable
    IEEE1905_BOOL ulMuMimoCapable : 1;

    /// UL MU-MIMO + OFDMA capable
    IEEE1905_BOOL ulMuMimoOfdmaCapable : 1;

    /// DL MU-MIMO + OFDMA capable
    IEEE1905_BOOL dlMuMimoOfdmaCapable : 1;

    /// UL OFDMA capable
    IEEE1905_BOOL ulOfdmaCapable : 1;

    /// DL OFDMA capable
    IEEE1905_BOOL dlOfdmaCapable : 1;

    u_int8_t reserved : 7;
} ieee1905APHeCapabilities_t;

/**
 * @brief Representation of a channel on which a radio is operating.
 *
 * Since the 802.11 spec uses different operating classes for different
 * bandwidths, it is possible for a radio to be operating on multiple
 * channels with this representation. The operating class with 20 MHz
 * bandwidth is considered the primary channel.
 */
typedef struct ieee1905RadioOperatingChannel_t {
    u_int16_t freq;

    /// The operating class from Table E-4 from 802.11-2016.
    u_int8_t opClass;

    /// The channel within the operating class that the radio is using.
    u_int8_t channel;

} ieee1905RadioOperatingChannel_t;

/**
 * @brief Representation of channel preference of a radio
 */
typedef struct ieee1905RadioChannelPreference_t {
    /// Whether the store channel preference is valid
    IEEE1905_BOOL isValid;

    /// The number of <op class, channel> pairs
    u_int8_t numPairs;

    struct {
        /// The global operating class as defined in Table E-4
        u_int8_t opClass;

        /// The channel number
        /// When channel number is 0, the preference applies to all
        /// channels in the op class
        u_int8_t channel;

        /// The preference value as defined in the spec.
        u_int8_t preference : 4;

        /// The reason for the preference not being the max.
        u_int8_t reason : 4;
    } operatingClasses[IEEE1905_MAX_OP_CLASS_CHAN_PAIRS];
} ieee1905RadioChannelPreference_t;

/* Max Access Category - Must be consistent with pcServiceAC_Max */
#define IEEE1905_ACCESS_CATEGORY_MAX 5

/**
 * @brief Representation of the AP metrics
 */
typedef struct ieee1905APMetricData_t
{
    /// Channel utilization measured by the radio operating the BSS
    u_int8_t channelUtil;

    /// Total number of STAs currently associated
    u_int16_t numAssocSTA;

    struct {
        /// Whether the ESP Info for this AC is included
        IEEE1905_BOOL includeESPInfo : 1;

        /// Access Category
        u_int8_t ac : 2;

        /// Data format
        u_int8_t dataFormat : 2;

        /// BA window size
        u_int8_t baWindowSize;

        /// Estimated air time fraction (as a percentage from 0 - 100)
        u_int8_t estAirTimeFraction;

        /// Data PPDU duration target (in microseconds)
        u_int16_t dataPPDUDurTarget;
    } espInfo[IEEE1905_ACCESS_CATEGORY_MAX];
} ieee1905APMetricData_t;

/// Associated Wi-Fi 6 STA Status Report TLV format
#define MAP_SERVICE_MAX_TID 0x04
typedef struct ieee1905STAWIFI6Capabilities_t {
    /// MAC address of the associated STA.
    struct ether_addr macAddr;
    u_int8_t n;

    struct {
        u_int8_t tid;
        u_int8_t queueSize;
    } tidInfo[MAP_SERVICE_MAX_TID];
} ieee1905STAWIFI6Capabilities_t;

// Station or AP
#define IEEE1905_MAX_ROLES 2
typedef struct ieee1905APWIFI6Capabilities_t {
    u_int8_t radioId[ETH_ALEN];
    u_int8_t numOfRoles;

  struct {
        /// 0: Wi-Fi 6 support info for the AP role
        /// 1: Wi-Fi 6 support info for the non-AP STA role
        /// 2-3: Reserved
        u_int8_t role : 2;
        /// Support for HE 160 MHz
        /// 0: Not supported
        /// 1: Supported
        IEEE1905_BOOL he160 : 1;
        /// Support for HE 80+80 MHz
        /// 0: Not supported
        /// 1: Supported
        IEEE1905_BOOL he80Plus80 : 1;
        /// Supported HE MCS indicating set of supported HE Tx and Rx MCS
        u_int16_t supportedHeMCS[IEEE1905_MAX_HE_MCS];
        /// Support for SU Beamformer.
        IEEE1905_BOOL suBeamFormer : 1;
        /// Support for SU Beamformee
        IEEE1905_BOOL suBeamFormee : 1;
        /// Support for MU beamformer Status
        IEEE1905_BOOL muBeamFormerStatus : 1;
        /// Support for Beamformee STS ≤ 80 MHz
        IEEE1905_BOOL beamFormeeSTSlessThan80Supported : 1;
        /// Support for Beamformee STS > 80 MHz
        IEEE1905_BOOL beamFormeeSTSMoreThan80Supported : 1;
        /// Support for UL MU-MIMO
        IEEE1905_BOOL ulMuMIMOSupported : 1;
        /// Support for UL OFDMA.
        IEEE1905_BOOL ulOFDMASupported : 1;
        /// Support for DL OFDMA
        IEEE1905_BOOL dlOFDMASupported : 1;
        /// Max number of users supported per
        /// DL MU-MIMO TX in an AP role
        uint8_t maxUserPerDLMuMIMOTxAP : 4;
        /// Max number of users supported per
        /// DL MU-MIMO RX in an AP role
        uint8_t maxUserPerDLMuMIMORxAP : 4;
        /// Max number of users supported per DL OFDMA TX in an AP role
        uint8_t maxUserDLOFDMATxAP;
        /// Max number of users supported per UL OFDMA RX in an AP role
        uint8_t maxUserDLOFDMARxAP;
        /// Support for RTS
        IEEE1905_BOOL rtsSupported : 1;
        /// Support for MU RTS
        IEEE1905_BOOL muRTSSupported : 1;
        /// Support for Multi-BSSID
        IEEE1905_BOOL multiBSSIDSupported : 1;
        /// Support for MU EDCA
        IEEE1905_BOOL muEDCASupported : 1;
        /// Support for TWT Requester
        IEEE1905_BOOL TWTRequesterSupprted : 1;
        /// Support for TWT Responder
        IEEE1905_BOOL TWTResponderSupported : 1;
  } roleCap[IEEE1905_MAX_ROLES];
} ieee1905APWIFI6Capabilities_t;

// ====================================================================
// Types and constants used for MAPr1 TX and RX messages
// ====================================================================

typedef ieee1905APCapabilities_t mapServiceAPCapabilities_t;

typedef ieee1905QCapabilities_t mapServiceQCapabilities_t;

typedef ieee1905APRadioBasicCapabilities_t mapServiceAPRadioBasicCapabilities_t;

typedef ieee1905APHtCapabilities_t mapServiceAPHtCapabilities_t;

typedef ieee1905APVhtCapabilities_t mapServiceAPVhtCapabilities_t;

typedef ieee1905APHeCapabilities_t mapServiceAPHeCapabilities_t;

typedef ieee1905STAWIFI6Capabilities_t mapServiceSTAWIFI6Capabilities_t;

typedef ieee1905APWIFI6Capabilities_t mapServiceAPWIFI6Capabilites_t;


/**
 * @brief The basic HW capabilities and radio address for a
 *        specific radio on device
 */
typedef struct mesh1905APRadioBasicCapabilities_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Structure to store basic hw capabilities, defined above
    mapServiceAPRadioBasicCapabilities_t hwCap;
} mesh1905APRadioBasicCapabilities_t;

/**
 * @brief The HT capabilities and radio address for a
 *        specific radio on device
 */
typedef struct mesh1905APHtCapabilities_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Structure to store HT capabilities, defined above
    mapServiceAPHtCapabilities_t htCap;
} mesh1905APHtCapabilities_t;

/**
 * @brief The VHT Capabilities and radio addresss for a
 *        specific radio on device
 */
typedef struct mesh1905APVhtCapabilities_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Structure to store AP VHT capabilities, defined above
    mapServiceAPVhtCapabilities_t vhtCap;
} mesh1905APVhtCapabilities_t;

/**
 * @brief The HE capabilities and radio addresss for a
 *        specific radio on device
 */
typedef struct mesh1905APHeCapabilities_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Structure to store HE capabilities, defined above
    mapServiceAPHeCapabilities_t heCap;
} mesh1905APHeCapabilities_t;

/**
 * @brief The policy that defines under which conditions an agent is
 *        allowed/mandated to steer a STA on its own.
 */
typedef enum mapServiceSteeringPolicyMode_e {
    /// Agent cannot steer the STA unless requested by controller
    mapServiceSteeringPolicyMode_AgentDisallowed,

    /// Agent must steer the STA when RSSI conditions are met
    mapServiceSteeringPolicyMode_AgentRSSIMandated,

    /// Agent may steer the STA when RSSI conditions are met
    mapServiceSteeringPolicyMode_AgentRSSIAllowed,

    /// All values from this point onwards are reserved
    mapServiceSteeringPolicyMode_Max
} mapServiceSteeringPolicyMode_e;

/**
 * @brief Policy provided by the controller with regard to which STAs
 *        may be steered by an agent and under what conditions.
 */
typedef struct mapServiceSteeringPolicy_t {
    /// How many STAs can never be steered under any circumstances
    u_int8_t numDisallowedSTAs;

    /// The MAC addresses of the STAs that cannot be steered under any
    /// circumstances
    struct ether_addr disallowedSTAs[MAP_SERVICE_STEERING_POLICY_MAX_STAS];

    /// How many STAs cannot be steered using BSS Transition Management Request
    u_int8_t numBTMDisallowedSTAs;

    /// The MAC addresses of the STAs that cannot be steered using BSS
    /// Transition Management Request
    struct ether_addr btmDisallowedSTAs[MAP_SERVICE_STEERING_POLICY_MAX_STAS];

    /// The number of radios for which a policy is provided
    u_int8_t numRadios;

    /// The policies for each radio
    struct {
        /// The MAC address of the radio (aka. radio unique ID)
        struct ether_addr radioAddr;

        /// What forms of steering are allowed/mandated
        mapServiceSteeringPolicyMode_e mode;

        /// The threshold for channel utilization to use for steering
        u_int8_t channelUtilThreshold;

        /// The RSSI (in dBm) below which AP steering should be performed
        int8_t rssiThreshold;
    } radioPolicies[MAP_SERVICE_STEERING_POLICY_MAX_RADIOS];
} mapServiceSteeringPolicy_t;

/**
 * @brief Representation of the metrics reporting policy for a single agent.
 */
typedef struct mapServiceMetricsReportingPolicy_t {
    /// How often to report the metrics.
    u_int8_t reportingIntervalSecs;

    /// How many radios reporting policies are provided for
    u_int8_t numRadios;

    struct {
        /// The MAC address of the radio (aka. radio unique ID)
        struct ether_addr radioAddr;

        /// The RSSI (in dBm) that is used as the trigger point for crossing-
        /// based reporting
        int8_t rssiThreshold;

        /// 0: Use agent's implementation specific default hysteresis value
        /// non-zero: Use this value
        u_int8_t rssiHysteresis;

        /// Utilization value to use for crossing-based reporting.
        u_int8_t channelUtilThreshold;

        /// Whether to include the STA traffic stats when reporting metrics
        IEEE1905_BOOL includeSTATrafficStats : 1;

        /// Whether to include the STA link metrics when reporting. Without
        /// this, only AP link metrics will be reported.
        IEEE1905_BOOL includeSTALinkMetrics : 1;
        /// MAP R3 /// Associated Wi-Fi6 STA Status Inclusion Policy.
        IEEE1905_BOOL includeWIFI6STAStats : 1;
    } radioPolicies[MAP_SERVICE_STEERING_POLICY_MAX_RADIOS];
} mapServiceMetricsReportingPolicy_t;

#define MAP_SERVICE_MAX_OPERATING_CLASSES 20

#define MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS 16

#define MAP_SERVICE_MAX_OP_CLASS_CHAN_PAIRS IEEE1905_MAX_OP_CLASS_CHAN_PAIRS

/**
 * @brief Representation of the channel preferences for an agent on a
 *        radio.
 */
typedef struct mapServiceChannelPreference_t {
    /// The MAC address of the radio (aka. radio unique ID).
    struct ether_addr radioAddr;

    /// The channel preference
    ieee1905RadioChannelPreference_t chanPref;
} mapServiceChannelPreference_t;

/**
 * @brief Representation of the radio operation restrictions for an agent
 *        on a radio.
 */
typedef struct mapServiceRadioRestriction_t {
    /// The MAC address of the radio (aka. radio unique ID).
    struct ether_addr radioAddr;

    /// The number of operating classes included.
    u_int8_t numOpClass;

    struct {
        /// The global operating class as defined in Table E-4.
        u_int8_t opClass;

        /// The number of channels within the operating class for which
        /// a restriction is provided.
        u_int8_t numChannels;

        struct {
            /// The channel number.
            u_int8_t channel;

            /// The minimum frequency separation (in multiples of 10 MHz)
            /// to another radio (with respect to center frequencies) when
            /// operating on this channel.
            u_int8_t minFreqSep;
        } channels[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];
    } operatingClasses[MAP_SERVICE_MAX_OPERATING_CLASSES];
} mapServiceRadioRestriction_t;

/**
 * @brief Representation of the maximum transmit power for an agent on a
 *        radio.
 */
typedef struct mapServiceTransmitPowerLimit_t {
    /// The MAC address of the radio (aka. radio unique ID).
    struct ether_addr radioAddr;

    /// The Transmit Power Limit EIRP per 20 MHz bandwidth.
    int8_t txPowerLimit;
} mapServiceTransmitPowerLimit_t;

/**
 * @brief Enum that indicates whether the channel selection request
 *        was activated or not.
 */
typedef enum mapServiceChannelSelectionStatus_e {
    /// Accept channel selection request
    mapServiceChannelSelectionStatus_Accept,

    /// Decline because request violates current pref
    mapServiceChannelSelectionStatus_DeclineViolateCurrent,

    /// Decline because request violates last reported pref
    mapServiceChannelSelectionStatus_DeclineViolateReported,

    /// Decline because request would prevent backhaul link operation
    mapServiceChannelSelectionStatus_DeclineBackhaul,

    /// All values from this point onwards are reserved
    mapServiceChannelSelectionStatus_Max
} mapServiceChannelSelectionStatus_e;

/**
 * @brief Representation of Channel Selection Response
 */
typedef struct mesh1905ChannelSelectionRsp_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Status, represented by above enum
    u_int8_t status;
} mesh1905ChannelSelectionRsp_t;

/**
 * @brief Representation of the operating channel of a radio.
 */
typedef struct mapServiceOperatingChannelReport_t {
    /// The MAC address of the radio (aka. radio unique ID)
    struct ether_addr radioAddr;

    /// The number of operating classes that follow
    u_int8_t numOpClass;

    ieee1905RadioOperatingChannel_t operatingChannels[MAP_SERVICE_MAX_OPERATING_CLASSES];

    /// The current nominal transmit power.
    int8_t txPower;
} mapServiceOperatingChannelReport_t;

/**
 * @brief representation of a client
 */
typedef struct mapServiceClientInfo_t {
    /// The BSSID of a BSS
    struct ether_addr bssid;

    /// The MAC address of the client
    struct ether_addr clientAddr;
} mapServiceClientInfo_t;

/**
 * @brief Enum that indicates whether the client capability query succeeded
 *        or not.
 */
typedef enum mapServiceClientCapStatus_e {
    /// (Re)Association Request frame is included
    mapServiceClientCapStatus_Success,

    /// (Re)Association Request frame is not included due to a failure
    mapServiceClientCapStatus_Failure,

    /// All values from this point onwards are reserved
    mapServiceClientCapStatus_Max
} mapServiceClientCapStatus_e;

#define MAP_SERVICE_MAX_ASSOC_FRAME_SZ 1024

typedef struct mapServiceClientCapability_t {
    /// Size of the (Re)Assoc frame in bytes
    u_int16_t frameSize;

    /// The frame body of the most recently received
    /// (Re)Association Request frame
    u_int8_t assocReqFrame[MAP_SERVICE_MAX_ASSOC_FRAME_SZ];
} mapServiceClientCapability_t;

typedef struct mesh1905ClientCapability_t {
    /// Result Code flag of client capability report
    u_int8_t resultCode;

    /// Client capability structure, defined above
    mapServiceClientCapability_t cap;
} mesh1905ClientCapability_t;

#define MAP_SERVICE_STEER_REQ_MAX_STAS 32

/**
 * @brief Representation of a request to steer one or more STAs.
 */
typedef struct mapServiceSteeringRequest_t {
    /// MAC address of the serving BSS from which clients should be
    /// steered
    struct ether_addr bssid;

    /// Whether steering is mandated or the receiving node just has an
    /// opportunity
    IEEE1905_BOOL isMandate : 1;

    /// If BTM is used, whether to set the disassociation imminent bit
    IEEE1905_BOOL disassocImminent : 1;

    /// If BTM is used, whether to set the abridged bit
    IEEE1905_BOOL abridged : 1;

    u_int8_t reserved : 5;

    /// Number of seconds during which steering is allowed. This is ignored
    /// if isMandate is true.
    u_int16_t opWindow;

    /// If BTM is used, the value for the disassoication timer field (in TUs).
    u_int16_t disassocTimer;

    /// The number of STAs for which steering is being requested. If 0, then
    /// the request applies to all STAs on the BSS.
    u_int8_t numSTAs;

    /// The MAC addresses of the STAs.
    struct ether_addr staAddr[MAP_SERVICE_STEER_REQ_MAX_STAS];

    /// The number of BSSes specified as steering targets. If this is 1, all
    /// STAs indicated should be steered to that BSS. Otherwise, it can either
    /// be set to 0 (for a steering opportunity) or to the same value as
    /// numSTAs.
    u_int8_t targetBSSCount;

    struct {
        /// The MAC address of the target BSS.
        struct ether_addr bssid;

        /// The current operating class for the BSS (to be included in the
        /// BTM).
        u_int8_t opClass;

        /// The channel within the operating class on which the BSS is
        /// operating.
        u_int8_t channel;
    } targetBSSes[MAP_SERVICE_STEER_REQ_MAX_STAS];
} mapServiceSteeringRequest_t;

/**
 * @brief Representation of a single report of a BTM Response.
 */
typedef struct mapServiceSteeringBTMReport_t {
    /// The MAC address of the BSS that received the BTM Response.
    struct ether_addr bssid;

    /// The MAC address of the STA that sent the response.
    struct ether_addr staAddr;

    /// The BTM Status Code from the STa (per Table 9-357).
    u_int8_t status;

    /// If non-zero, the TargetBSSID field in the BTM Response.
    struct ether_addr targetBSSID;
} mapServiceSteeringBTMReport_t;

/**
 * @brief Enum that indicates what association policy should be applied.
 */
typedef enum mapServiceMsgClientAssocControlPolicy_e {
    /// Do not allow the STA to associate
    mapServiceMsgClientAssocControlPolicy_Block,

    /// Allow the STA to associate
    mapServiceMsgClientAssocControlPolicy_Unblock,

    /// All values from this point onwards are reserved
    mapServiceMsgClientAssocControlPolicy_Max
} mapServiceMsgClientAssocControlPolicy_e;

#define MAP_SERVICE_MAX_ASSOC_CTRL_STA 1

/**
 * @brief Representation of a request to change the blacklist status for a
 *        STA on a BSS.
 */
typedef struct mapServiceClientAssocControlRequest_t {
    /// The MAC address of the BSS on which to apply the new policy
    struct ether_addr bssid;

    /// The desired state
    mapServiceMsgClientAssocControlPolicy_e policy;

    /// How long this policy stays in place (only valid for block policy)
    u_int16_t validitySecs;

    /// The number of STA MAC addresses that follow
    u_int8_t numSTAs;

    /// The STA MAC addresses
    struct ether_addr staAddrs[MAP_SERVICE_MAX_ASSOC_CTRL_STA];
} mapServiceClientAssocControlRequest_t;

/**
 * @brief Representation of higher layer data for Mesh Application
 */
typedef struct mesh1905HigherLayerData_t {
    /// The protocol ID (as defined in Appendix A.1)
    u_int8_t protocol;

    /// The number of bytes
    u_int16_t length;

    /// The raw data bytes
    u_int8_t data[];
} mesh1905HigherLayerData_t;

/**
 * @brief Representation of higher layer data bytes sent/received between
 *        devices.
 */
typedef struct mapServiceHigherLayerData_t {
    /// The protocol ID (as defined in Appendix A.1)
    u_int8_t protocol;

    /// The number of bytes
    u_int16_t length;

    /// The raw data bytes
    const u_int8_t *data;
} mapServiceHigherLayerData_t;

typedef struct mapServiceBackhaulSteeringReq_t {
    /// The MAC address of the associated backhaul station operated by the
    /// Multi-AP Agent.
    struct ether_addr staAddr;

    /// The BSSID of the target BSS
    struct ether_addr targetBSSID;

    /// Operating class per Table E-4
    u_int8_t opClass;

    /// Channel number on which Beacon frames are being transmitted by the
    /// target BSS
    u_int8_t channel;
} mapServiceBackhaulSteeringReq_t;

typedef enum mapServiceBackhaulSteeringStatus_e {
    /// Backhaul steering was successful
    mapServiceBackhaulSteeringStatus_Success,

    /// Rejected because the backhaul station cannot operate on
    /// the channel specified.
    mapServiceBackhaulSteeringStatus_RejectedInvalidChannel,

    /// Rejected becuase the target BSS signal is too weak or
    /// not found.
    mapServiceBackhaulSteeringStatus_RejectedLowSignal,

    /// Authentication or association rejected by the target BSS.
    mapServiceBackhaulSteeringStatus_RejectedByTargetBSS
} mapServiceBackhaulSteeringStatus_e;

typedef struct mapServiceBackhaulSteeringRsp_t {
    /// The MAC address of the associated backhaul station operated by the
    /// Multi-AP Agent.
    struct ether_addr staAddr;

    /// The BSSID of the target BSS
    struct ether_addr targetBSSID;

    /// The status code to indicate in the response. Note that the failure
    /// codes actually need to be placed in the Error Code TLV, but this is
    /// handled by the implementation.
    mapServiceBackhaulSteeringStatus_e statusCode;
} mapServiceBackhaulSteeringRsp_t;

#define MAP_SERVICE_UNASSOC_QUERY_MAX_STAS 16

/**
 * @brief Representation of an Unassociated STA Link Metrics Query.
 */
typedef struct mapServiceUnassociatedSTALinkMetricsQuery_t {
    /// The operating class being requested
    u_int8_t opClass;

    /// The number of channels within the operating class for which
    /// unassociated STA link metrics are being requested
    u_int8_t numChannels;

    struct {
        /// The channel ID within the operating class
        u_int8_t channel;

        /// The number of STAs for which metrics are requested on this
        /// channel
        u_int8_t numSTAs;

        /// The STA MAC adddresses
        struct ether_addr staAddrs[MAP_SERVICE_UNASSOC_QUERY_MAX_STAS];
    } channels[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];
} mapServiceUnassociatedSTALinkMetricsQuery_t;

#define MAP_SERVICE_MAX_NUM_ASSOC_BSS 2

/**
 * @brief Representation of the associated STA link metrics
 */
typedef struct mapServiceAssocSTALinkMetrics_t {
    /// The MAC address of the associated STA
    struct ether_addr staAddr;

    /// The number of BSS link metrics reported for this STA
    u_int8_t numBSS;

    struct {
        /// BSSID of the BSS for which the STA is associated
        struct ether_addr bssid;

        /// The time delta (in ms) between the earliest measurement and
        /// the time at which this report was set.
        u_int32_t timeDeltaMSec;

        /// Estimated downlink MAC data rate (in Mbps)
        u_int32_t downlinkDataRate;

        /// Estimated uplink MAC data rate (in Mbps)
        u_int32_t uplinkDataRate;

        /// Uplink RSSI (in dBm)
        int8_t uplinkRSSI;

    } bssLinkMetric[MAP_SERVICE_MAX_NUM_ASSOC_BSS];
} mapServiceAssocSTALinkMetrics_t;

/**
 * @brief Representation of the Block ACK window size in
 *        actual MPDU counts in native format.
 */
typedef enum mapServiceBAWindowSize_e {
    mapBAWindowNotUsed = 0,
    mapBAWindowSize_2 = 2,
    mapBAWindowSize_4 = 4,
    mapBAWindowSize_6 = 6,
    mapBAWindowSize_8 = 8,
    mapBAWindowSize_16 = 16,
    mapBAWindowSize_32 = 32,
    mapBAWindowSize_64 = 64,
} mapServiceBAWindowSize_e;

/**
 * @brief Representation of the Block ACK window size
 *        value in OTA format.
 */
typedef enum mapServiceBAWindowValue_e {
    mapBAWindowValue_0,
    mapBAWindowValue_1,
    mapBAWindowValue_2,
    mapBAWindowValue_3,
    mapBAWindowValue_4,
    mapBAWindowValue_5,
    mapBAWindowValue_6,
    mapBAWindowValue_7,
} mapServiceBAWindowValue_e;

typedef enum mapServiceAccessCategory_e {
    mapServiceAC_BE,
    mapServiceAC_BK,
    mapServiceAC_VO,
    mapServiceAC_VI,
    mapServiceAC_Max,  // always last
} mapServiceAccessCategory_e;

#define MAP_SERVICE_MAX_NUM_BSSID 16
/**
 * @brief Representation of the AP metric Query
 */
typedef struct mesh1905APMetricQuery_t {
    /// number of BSSIDs
    size_t numBSSID;

    /// BSSIDs
    struct ether_addr bssids[MAP_SERVICE_MAX_NUM_BSSID];
} mesh1905APMetricQuery_t;

/**
 * @brief Representation of the AP metrics
 */
typedef struct mapServiceAPMetrics_t {
    /// BSSID of the BSS
    struct ether_addr bssid;

    /// AP metrics
    ieee1905APMetricData_t apMetrics;
} mapServiceAPMetrics_t;

/**
 * @brief Representation of the associated STA traffic stats
 */
typedef struct mapServiceAssocSTATrafficStats_t {
    /// The MAC address of the associated STA
    struct ether_addr staAddr;

    /// Associated STA traffic stats
    ieee1905StaTrafficStats_t staStats;
} mapServiceAssocSTATrafficStats_t;

#define MAP_PUBLIC_MAX_UNASSOC_STAS 1
/**
 * @brief Representation of the unassociated STA link metrics
 */
typedef struct mapServiceUnassocSTALinkMetrics_t {
    /// The MAC address of the STA
    struct ether_addr staAddr;

    /// Operating class defined in table E-4 of IEEE Std 802.11-2016
    u_int8_t opClass;

    /// Channel number
    u_int8_t chanNum;

    /// The time delta (in ms) between the earliest measurement and
    /// the time at which this report was set.
    u_int32_t timeDelta;

    /// Uplink RSSI (in dBm)
    int8_t uplinkRSSI;

} mapServiceUnassocSTALinkMetrics_t;

/**
 * @brief Representation of Unassoc STA Link Metrics TLV
 */
typedef struct mesh1905UnassocSTALinkMetrics_t {
    /// Num of STAs
    u_int8_t numStas;

    /// Operating class
    u_int8_t opClass;

    /// Unassoc STA Link metrics defined above
    mapServiceUnassocSTALinkMetrics_t metric[MAP_PUBLIC_MAX_UNASSOC_STAS];
} mesh1905UnassocSTALinkMetrics_t;

typedef ieee1905BcnMetricsQuery_t mapServiceBcnMetricsQuery_t ;

/**
 * @brief Representation of the beacon metrics response for Mesh Application
 */
typedef struct mesh1905BcnMetrics_t {
    /// The MAC address of the STA for which beacon report is requested
    struct ether_addr staAddr;

    /// Number of measurement report elements
    u_int8_t numReportElements;

    /// Total length of Measurement Report elements
    size_t lenReport;

    /// Measurement reports as in IEEE 802.11 -2016 Fig.9-199.
    u_int8_t report[];
} mesh1905BcnMetrics_t;

/**
 * @brief Representation of the beacon metrics response
 */
typedef struct mapServiceBcnMetrics_t {
    /// The MAC address of the STA for which beacon report is requested
    struct ether_addr staAddr;

    /// Number of measurement report elements
    u_int8_t numReportElements;

    /// Total length of Measurement Report elements
    size_t lenReport;

    /// Measurement reports as in IEEE 802.11 -2016 Fig.9-199.
    const u_int8_t *report;
} mapServiceBcnMetrics_t;

/**
 * @brief Representation of an Error Code TLV
 */
typedef struct mapServiceErrorCode_t {
    /// The reason code provided in the Error Code TLV
    ieee1905ErrorCode_e reasonCode;

    /// The MAC address of the STA referred to by the reason code
    /// This value is only valid if reason code is set to 0x1 or 0x2
    struct ether_addr staAddr;
} mapServiceErrorCode_t;


/**
 * @brief Representation of Tx Link Metrics
 */
typedef struct mesh1905TransmitterLinkMetrics_t {
    /// Address of the device being queried
    struct ether_addr devAlMAC;

    /// Address of the neighboring device
    struct ether_addr neighborAlMAC;

    /// Tx link metrics
    ieee1905TransmitterLinkData_t data[];
} mesh1905TransmitterLinkMetrics_t;

/**
 * @brief Representation of Rx Link Metrics
 */
typedef struct mesh1905ReceiverLinkMetrics_t {
    /// Address of the device being queried
    struct ether_addr devAlMAC;

    /// Address of the neighboring device
    struct ether_addr neighborAlMAC;

    /// Rx link metrics
    ieee1905ReceiverLinkData_t data[];
} mesh1905ReceiverLinkMetrics_t;

// ====================================================================
// MAP R2 related definitions
// ====================================================================

/**
 * @brief Representation of R2 MAP Ap CAP
 */
typedef struct ieee1905R2APCapabilities_t {
    /// Max Total Number Service Prioritization Rules
    u_int8_t maxSPRules;
    u_int8_t reserved;  // reserved as per R3

    /// Byte Counter Units
    u_int8_t byteCounterUnits : 2;
    IEEE1905_BOOL basicSPEnabled : 1;
    /// Max Total Number of VIDs
    u_int8_t maxTotalNumVIDs;
} ieee1905R2APCapabilities_t;

/**
 * @brief Representation of Metric Collection Interval
 */
typedef struct ieee1905R2MetricCollectionInterval_t {
    /// Collection Interval
    u_int32_t collectionInterval;
} ieee1905R2MetricCollectionInterval_t;

#define IEEE1905_MAX_RADIOS 4
#define IEEE1905_MAX_CAC_MODES 4
#define IEEE1905_CAC_TIME_SECS_SIZE 3
/**
 * @brief The CAC capabilities for a specific radio on an AP
 */
typedef struct ieee1905CACCap_t {

    /// Numer of types of CAC the radio can perform
    u_int8_t numOfCACType;

    /// cac type defined by cac mode + time to complete cac
    struct {
        /// 0: Continuous CAC
        /// 1: Continuous with dedicated radio
        /// 2: MIMO dimension reduced
        /// 3: Time sliced CAC
        /// >3: Reserved
        u_int8_t cacMode;

        /// time to complete cac in seconds
        u_int8_t secRequiredForCAC[IEEE1905_CAC_TIME_SECS_SIZE];

        /// Numer of classes supported
        u_int8_t numOpClass;

        /// Info for each supported operating class
        struct {
            /// Operating class for which capability is being described
            u_int8_t opClass;

            /// Number of channels supported in the operating class
            u_int8_t numOfChannels;

            /// Single channel number for which capability is being described
            u_int8_t channelNum[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];
        } opClass[IEEE1905_MAX_OPERATING_CLASSES];

    } cacType[IEEE1905_MAX_CAC_MODES];

} ieee1905CACCap_t;

typedef struct mesh1905CACCap_t {
    /// Country Code
    u_int16_t countryCode;

    /// Number of Radios
    u_int8_t numRadio;

    struct {
        /// Radio Address
        struct ether_addr radioAddr;

        /// CAC capabilities for radio
        ieee1905CACCap_t cacCap;
    } radioCACCap[IEEE1905_MAX_RADIOS];
} mesh1905CACCap_t;

/**
 * @brief Enumeration for Multi-AP Version
 **/
typedef enum ieee1905MultiApVersion_e {
    /* Multi-AP Version 1 */
    ieee1905MultiApVersion_1 = 1,
    /* Multi-AP Version 2 */
    ieee1905MultiApVersion_2,
    /* Multi-AP Version 3 */
    ieee1905MultiApVersion_3,
    ieee1905Version_invalid = 0x0f,
} ieee1905MultiApVersion_e;

// For now, 4 operating channels should account for different bandwidths
#define IEEE1905_MAX_OP_CHANNELS 4

/**
 * @brief Representation of Channel Scan Capabilities
 */
typedef struct ieee1905APChannelScanCap_t {
    /// 1: True (Agent can only perform scan on boot)
    /// 0: False (Agent can perform scan on request)
    IEEE1905_BOOL onBootScan : 1;

    /// 0x00: No impact
    /// 0x01: Reduced number of spatial streams
    /// 0x02: Time slicing impairment
    /// 0x03: Radio unavailable for >= 2 seconds)
    u_int8_t scanImpact;

    /// minimum time interval between two consecutive scan
    u_int32_t minScanInterval;

    /// number of operating class
    u_int8_t numOpClass;

    struct {
        /// operating class
        u_int8_t opClass;

        /// Number of channels
        u_int8_t numChannels;

        /// Channels
        u_int8_t channels[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];
    } scanCapOpClass[IEEE1905_MAX_OPERATING_CLASSES];
} ieee1905APChannelScanCap_t;

typedef struct mesh1905APChannelScanCap_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Channel Scan Capabilities
    ieee1905APChannelScanCap_t chanScanCap;
} mesh1905APChannelScanCap_t;

/// The number of channels in 20Mhz BW that scan results can be obtained on
#define IEEE1905_MAX_SCAN_CHANNELS_PER_RADIO 25
#define IEEE1905_MAX_NEIGHBORS 48
#define IEEE1905_ISO_STR_SIZE sizeof("YYYY-MM-DDThh:mm:ss.ssssss±hh:mmm")
#define IEEE1905_NWID_LEN 32

/**
 * @brief Representation of timestamp
 */
typedef struct ieee1905ISOTimeStamp_t {
    u_int8_t length;
    char timeStamp[IEEE1905_ISO_STR_SIZE];
} ieee1905ISOTimeStamp_t;

/**
 * @brief Representation of Channel Scan Results
 */
typedef struct ieee1905APChannelScanResult_t {
    /// OpClass
    u_int8_t opClass;

    /// Channel
    u_int8_t channel;

    /// 0x00: Success
    /// 0x01: Scan not supported on this operating class/channel on this radio
    /// 0x02: Request too soon after last scan
    /// 0x03: Radio too busy to perform scan
    /// 0x04: Scan not completed
    /// 0x05: Scan aborted
    /// 0x06: Fresh scan not supported. Radio only supports on boot scans.
    /// 0x07 – 0xFF: Reserved.
    u_int8_t scanStatus;

    /// timeStamp Length
    u_int8_t timeStampLength;

    /// The start time of the scan of the channel
    char timeStamp[IEEE1905_ISO_STR_SIZE];

    /// The current channel utilization measured by the radio on the scanned 20
    /// MHz channel - as defined in section 9.4.2.28 of [1]
    u_int8_t chUtil;

    /// An indicator of the average radio noise plus interference power measured
    /// on the 20 MHz channel during a channel scan. Encoding as defined as for
    /// ANPI in section 11.11.9.4 of [1]
    int8_t noise;

    /// The number of neighbor BSS discovered on this channel.
    u_int16_t numNeighbors;
    struct {
        /// The BSSID indicated by the neighboring BSS.
        struct ether_addr bssid;

        /// SSID Length
        u_int8_t ssidLen;

        /// The SSID indicated by the neighboring BSS.
        char ssid[IEEE1905_NWID_LEN + 1];

        /// An indicator of radio signal strength (RSSI) of the Beacon or Probe
        /// Response frames of the neighboring BSS as received by the radio
        /// measured in dBm. (RSSI is encoded per Table 9-154 of [[1]). Reserved:
        /// 221 - 255.
        u_int8_t signalStrength;

        /// Channel BW of the neighbor
        u_int8_t channelBw;

        /// BSS Load Element Present
        IEEE1905_BOOL bssLoadPresent;

        /// The value of the "Channel Utilization" field as reported by the
        /// neighboring BSS in the BSS Load element.
        u_int8_t chUtil;

        /// The value of the "Station Count" field reported by the neighboring BSS in the BSS
        /// Load element.
        u_int16_t staCnt;
    } scanResults[IEEE1905_MAX_NEIGHBORS];

    u_int32_t aggregateScanDuration;

    /// Active or Passive
    IEEE1905_BOOL scanType;
} ieee1905APChannelScanResult_t;

typedef struct mesh1905APChannelScanResult_t {
    /// Radio Address
    struct ether_addr radioAddr;

    /// Channel Scan Result
    ieee1905APChannelScanResult_t chanScanResult;
} mesh1905APChannelScanResult_t;

#define IEEE1905_SIMULTANEOUS_CAC_RADIOS 1
/**
 * @brief Representation of CAC Completion
 */
typedef struct ieee1905CACCompletionReport_t {
    u_int8_t numRadios;

    struct {
        struct ether_addr radioAddr;
        u_int8_t opClass;
        u_int8_t channelNum;

        /// 0: Successful
        /// 1: Radar detected
        /// 2: CAC not supported as requested (capability mismatch)
        /// 3: Radio too busy to perform CAC
        /// 4: Request was considered to be non-conformant to regulations in
        /// the country in which the MAP Agent is operating
        /// 5: Other error
        /// >5: Reserved
        IEEE1905_BOOL cacStatus;
        u_int8_t numChannelOpClassPair;

        struct {
            u_int8_t opClass;
            u_int8_t channelNum;
        } radarAffectedPair[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];

    } cacRadioCap[IEEE1905_SIMULTANEOUS_CAC_RADIOS];
} ieee1905CACCompletionReport_t;

/**
 * @brief Representation of Channel Scan report Policy
 */
typedef struct ieee1905ChannelScanReportPolicy_t {
    /// Report Independent Channel Scans
    IEEE1905_BOOL rptIndScan : 1;

    IEEE1905_BOOL reserved : 7;
} ieee1905ChannelScanReportPolicy_t;

/**
 * @brief Representation of timestamp
 */
typedef struct ieee1905Timestamp_t {
    u_int8_t length;
    u_int8_t timestamp[IEEE1905_ISO_STR_SIZE];
} ieee1905Timestamp_t;

/**
 * @brief Representation of Channel Scan Capabilities
 */
typedef struct ieee1905ChannelScanCap_t {
    /// number of radio must be less than MAP_SERVICE_STEERING_POLICY_MAX_RADIOS
    u_int8_t numRadios;

    struct {
        /// Mac address of Radio
        struct ether_addr radioAddr;
        /// 1: True (Agent can only perform scan on boot)
        /// 0: False (Agent can performRequested scans)
        IEEE1905_BOOL onBootScan : 1;

        /// 0x00: No impact
        /// 0x01: Reduced number of spatial streams
        /// 0x02: Time slicing impairment
        /// 0x03: Radio unavailable for >= 2 seconds)
        IEEE1905_BOOL scanImpact : 2;

        IEEE1905_BOOL reserved : 5;
        /// minimum time interval between two consective scan
        u_int32_t minScanInterval;
        /// number of operating class
        u_int8_t numOpClass;
        struct {
            /// operating class
            u_int8_t opClass;
            /// Number of channels
            u_int8_t numChannels;

            u_int8_t channels[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];

        } scanCapOpClass[MAP_SERVICE_MAX_OPERATING_CLASSES];

    } ScanCapRadio[IEEE1905_MAX_RADIOS];
} ieee1905ChannelScanCap_t;

/**
 * @brief Representation of Channel Scan Request
 */
typedef struct ieee1905ChannelScanRequest_t {
    /// 1 perform fresh scan
    /// 0 Return stored table
    IEEE1905_BOOL performFreshScan;

    /// number of radios
    u_int8_t numRadios;

    struct {
        /// Radio Address
        struct ether_addr radioAddr;

        /// number of operating classes
        u_int8_t numOpClass;
        struct {
            /// operating class
            u_int8_t opClass;

            /// Number of channels
            u_int8_t numChannels;

            /// Channels
            u_int8_t channels[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];
        } scanReqOpClass[MAP_SERVICE_MAX_OPERATING_CLASSES];
    } scanReqRadio[IEEE1905_MAX_RADIOS];
} ieee1905ChannelScanRequest_t;

/**
 * @brief Representation of Unsuccessful Association Policy
 */
typedef struct ieee1905UnSuccessfulAssocPolicy_t {
    /// Report Unsuccessful Associations
    IEEE1905_BOOL reportUnSuccessfulAssoc;

    /// Maximum Reporting Rate
    u_int32_t maxReportingRate;
} ieee1905UnSuccessfulAssocPolicy_t;

/**
 * @brief Representation of Backhaul BSS Configuration
 */
typedef struct ieee1905BackhaulBSSConfig_t {
    /// BSSID
    struct ether_addr bssid;

    /// Profile-1 Backhaul STA association disallowedSTAs
    IEEE1905_BOOL map1bStaAssocDisAllowed : 1;

    /// Profile-2 Backhaul STA association disallowedSTAs
    IEEE1905_BOOL map2bStaAssocDisAllowed : 1;
} ieee1905BackhaulBSSConfig_t;

/**
 * @brief Representation of AP Radio Identifier TLV
 */
typedef struct ieee1905APRadioIdentifier_t {
    /// radioAddr
    struct ether_addr radioAddr;
} ieee1905APRadioIdentifier_t;

/**
 * @brief Representation of AP Radio Metrics TLV
 */
typedef struct ieee1905APRadioMetrics_t {
    /// RUID
    struct ether_addr radioAddr;

    /// Noise
    u_int8_t noise;

    /// Transmit
    u_int8_t transmit;

    /// ReceiveSelf
    u_int8_t receiveSelf;

    /// ReceiveOther
    u_int8_t receiveOther;
} ieee1905APRadioMetrics_t;

/**
 * @brief Representation of AP Extended Metrics TLV
 */
typedef struct ieee1905APExtendedMetricTLV_t {
    /// BSSID of the BSS
    struct ether_addr bssid;

    /// unicastBytesSent
    u_int32_t unicastBytesSent;

    /// unicastBytesReceived
    u_int32_t unicastBytesReceived;

    /// multicastBytesSent
    u_int32_t multicastBytesSent;

    /// multicastBytesReceived
    u_int32_t multicastBytesReceived;

    /// broadcastBytesSent
    u_int32_t broadcastBytesSent;

    /// broadcastBytesReceived
    u_int32_t broadcastBytesReceived;
} ieee1905APExtendedMetricTLV_t;

#define IEEE1905_STA_EXTENDED_LINK_METRIC_STA_BSS_CONNECTION 0x01
/**
 * @brief Representation of STA Extended Metrics TLV
 */
typedef struct ieee1905StaExtendedLinkMetricTlv_t {
    /// MAC address of the associated STA
    struct ether_addr staAddr;

    /// Number of BSSIDs reported for this STA.
    u_int8_t numBSSID;

    struct staLinkMetic_t {
        /// BSSID of the BSS to which the STA is associated.
        struct ether_addr bssid;

        /// LastDataDownlinkRate
        u_int32_t lastDataDownlinkRate;

        /// LastDataUplinkRate
        u_int32_t lastDataUplinkRate;

        /// UtilizationReceive
        u_int32_t utilizationReceive;

        /// UtilizationTransmit
        u_int32_t utilizationTransmit;
    } staLinkMetric[IEEE1905_STA_EXTENDED_LINK_METRIC_STA_BSS_CONNECTION];
} ieee1905StaExtendedLinkMetricTlv_t;

typedef struct ieee1905CACRadioReq_t {
    struct ether_addr radioAddr;
    u_int8_t opClass;

    u_int8_t channelNum;

    /// 0: Continuous CAC
    /// 1: Continuous with dedicated radio
    /// 2: MIMO dimension reduced
    /// 3: Time sliced CAC
    /// >3: Reserved
    IEEE1905_BOOL cacMode : 3;

    /// 0: Remain on channel and continue to monitor for radar
    /// 1: Return to previous state
    /// >1 Reserved
    IEEE1905_BOOL successfullCACCompleteAction : 3;

    IEEE1905_BOOL reserved : 2;

} ieee1905CACRadioReq_t;

/**
 * @brief Representation of CAC request
 */
typedef struct ieee1905CACRequest_t {
    u_int8_t numRadios;

    ieee1905CACRadioReq_t cacRadioCap[IEEE1905_SIMULTANEOUS_CAC_RADIOS];
} ieee1905CACRequest_t;

/**
 * @brief Representation of CAC Terminate
 */
typedef struct ieee1905CACTerminate_t {
    u_int8_t numRadios;

    struct {
        struct ether_addr radioAddr;
        u_int8_t opClass;

        u_int8_t channelNum;

    } cacRadioCap[IEEE1905_SIMULTANEOUS_CAC_RADIOS];
} ieee1905CACTerminate_t;;

/**
 * @brief Representation of CAC Status report
 */
typedef struct ieee1905CACStatusReport_t {
    u_int8_t numCACDoneChannelOpclassPairs;

    struct {
        u_int8_t opClass;
        u_int8_t channelNum;
        u_int16_t minSinceLastCACComplete;
    } cacDone[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];

    u_int8_t numNOLChannelOpclassPairs;

    struct {
        u_int8_t opClass;
        u_int8_t channelNum;
        u_int8_t secRemainingInNOLList;
    } nolList[MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS];

    u_int8_t numCACOngoingChannelOpclassPairs;

    struct {
        u_int8_t opClass;
        u_int8_t channelNum;
        u_int16_t secRemainingToCACComplete;
    } cacOngoing[MAP_SERVICE_MAX_OPERATING_CLASSES];

} ieee1905CACStatusReport_t;

/**
 * @brief Representation of Multi AP Version
 */
typedef struct ieee1905MultiAPVersion_t {
    /// 0x00: Reserved
    /// 0x01: Multi-AP Version 1
    /// 0x02: Multi-AP Version 2
    /// 0x03 ~0xFF Reserved
    u_int8_t version;
} ieee1905MultiAPVersion_t;

/**
 * @brief Representation of Defualt 802.1Q settings
 */
typedef struct ieee19058021QSettings_t {
    u_int16_t vlanID;
    u_int8_t pcp;
} ieee19058021QSettings_t;

/**
 * @brief Representation of Traffic Seperation policy
 */
typedef struct ieee1905TrafficSepPolicy_t {
    /// Number of SSIDs
    u_int8_t numOfSSIDs;

    struct {
        /// Length of SSID name
        u_int8_t ssidLen;

        /// SSID name
        char ssid[IEEE1905_MAX_SSID_LEN];

        /// 0x0000 – 0x0002: Reserved
        /// 0x0003 – 0x0FFE
        /// 0xFFF – 0xFFFF: Reserved
        u_int16_t vlanID;
    } interfaceConf[IEEE1905_QCA_VENDOR_MAX_INTERFACE];
} ieee1905TrafficSepPolicy_t;

#define IEEE1905_MAX_PERMITTED_DSTMAC 32
/**
 * @brief Representation of Traffic Seperation policy
 */
typedef struct ieee1905PacketFiltering_t {
    u_int8_t numOfBssids;
    struct {
        struct ether_addr bssid;

        u_int8_t numOfPermittedMACAddress;
        struct {
            struct ether_addr dstMAC;
        } permittedMAC[IEEE1905_MAX_PERMITTED_DSTMAC];
    } bssid[IEEE1905_QCA_VENDOR_MAX_INTERFACE];

} ieee1905PacketFiltering_t;

/**
 * @brief Representation of R2 Error Code
 */
typedef struct ieee1905R2ErrorCode_t {
    /// 0x00: Reserved
    /// 0x01: Service Prioritization Rule not found
    /// 0x02: Number of Service Prioritization Rules reached the maximum supported
    /// 0x03: Default PCP or VLAN ID not provided
    /// 0x04: Advanced field not supported
    /// 0x05 – 0xFF: Reserved.
    u_int8_t errorCode;

    /// Service Prioritization Rule ID field
    u_int32_t ruleID;
} ieee1905R2ErrorCode_t;

/**
 * @brief Representation of AP Radio advance cap
 */
typedef struct ieee1905APRadioAdvanceCap_t {
    /// Radio Unique Identifier of the radio for which capabilities are reported
    struct ether_addr radioAddr;

    /// Combined Front Back
    IEEE1905_BOOL combinedFrontBack : 1;

    /// Combined Profile-1 and Profile-2
    IEEE1905_BOOL combinedProfiles : 1;

    u_int8_t reserved : 6;
} ieee1905APRadioAdvanceCap_t;

/**
 * @brief Representation of Source info
 */
typedef struct ieee1905SrcInfo_t {
    struct ether_addr srcAddr;
} ieee1905SrcInfo_t;

/**
 * @brief Representation of channel preference of a radio in array format
 */
typedef struct ieee1905RadioChannelPreferenceArray_t {
    /// Whether the store channel preference is valid
    IEEE1905_BOOL isValid;

    /// The number of <op class, channel> pairs
    u_int8_t numPairs;

    struct {
        /// The global operating class as defined in Table E-4
        u_int8_t opClass;

        /// The numer of channels withint the operating class
        u_int8_t numChannels;

        /// The channel number
        /// When channel number is 0, the preference applies to all
        /// channels in the op class
        u_int8_t channels[IEEE1905_MAX_CHANNELS_PER_OP_CLASS];

        /// The preference value as defined in the spec.
        u_int8_t preference : 4;

        /// The reason for the preference not being the max.
        u_int8_t reason : 4;
    } operatingClasses[IEEE1905_MAX_OP_CLASS_CHAN_PAIRS];
} ieee1905RadioChannelPreferenceArray_t;

/**
 * @brief Representation of Association Status Notification message type
 */
typedef struct ieee1905AssocStatusNotify_t {
    u_int8_t numBSSInNotification;

    struct {
        struct ether_addr bssid;
        u_int8_t assocAllowanceStatus;
    } bss[IEEE1905_QCA_VENDOR_MAX_INTERFACE];
} ieee1905AssocStatusNotify_t;

/**
 * @brief Representation of AP Association Status
 */
typedef struct ieee1905APAssocStatus_t {
    u_int8_t numOfRadios;

    struct {
        struct ether_addr radioAddr;
        /// Backhaul BSS Traffic Separation R1/R2 mix NOT supported.
        IEEE1905_BOOL apAdvanceCapMask : 1;
        IEEE1905_BOOL reserved : 7;
    } radios[IEEE1905_MAX_RADIOS];
} ieee1905APAssocStatus_t;

/**
 * @brief Representation of a request to steer one or more STAs.
 */
typedef struct ieee1905R2SteeringRequest_t {
    /// MAC address of the serving BSS from which clients should be
    /// steered
    struct ether_addr bssid;

    /// Whether steering is mandated or the receiving node just has an
    /// opportunity
    IEEE1905_BOOL isMandate : 1;

    /// If BTM is used, whether to set the disassociation imminent bit
    IEEE1905_BOOL disassocImminent : 1;

    /// If BTM is used, whether to set the abridged bit
    IEEE1905_BOOL abridged : 1;

    u_int8_t reserved : 5;

    /// Number of seconds during which steering is allowed. This is ignored
    /// if isMandate is true.
    u_int16_t opWindow;

    /// If BTM is used, the value for the disassociation timer field (in TUs).
    u_int16_t disassocTimer;

    /// The number of STAs for which steering is being requested. If 0, then
    /// the request applies to all STAs on the BSS.
    u_int8_t numSTAs;

    /// The MAC addresses of the STAs.
    struct ether_addr staAddr[MAP_SERVICE_STEER_REQ_MAX_STAS];

    /// The number of BSSes specified as steering targets. If this is 1, all
    /// STAs indicated should be steered to that BSS. Otherwise, it can either
    /// be set to 0 (for a steering opportunity) or to the same value as
    /// numSTAs.
    u_int8_t targetBSSCount;

    struct {
        /// The MAC address of the target BSS.
        struct ether_addr bssid;

        /// The current operating class for the BSS (to be included in the
        /// BTM).
        u_int8_t opClass;

        /// The channel within the operating class on which the BSS is
        /// operating.
        u_int8_t channel;

        /// Reason code
        u_int8_t reason;
    } targetBSSes[MAP_SERVICE_STEER_REQ_MAX_STAS];
} ieee1905R2SteeringRequest_t;

/**
 * @brief Backhaul STA radio capability
 */
typedef struct ieee1905BSTARadioCap_t {
    /// Radio Unique Identifier
    struct ether_addr ruid;

    /// MAC address included flag
    IEEE1905_BOOL macIncluded : 1;

    IEEE1905_BOOL reserved : 7;

    /// MAC address of the backhaul STA
    struct ether_addr macAddr;
} ieee1905BSTARadioCap_t;

// ====================================================================
// MAP R3 related definitions
// ====================================================================

#define IEEE1905_MAX_GIK_LEN 128
#define IEEE1905_MAX_PCP_LEN 64

/**
 * @brief Representation of Group Integrity Key
 */
typedef struct ieee1905GikId_t {
    /// group identity key Id
    u_int8_t gikId;

    u_int8_t gikLen;
    /// we are assuming 1024 bits as max length of Gik Key length for now
    /// Group integrity key
    u_int8_t gik[IEEE1905_MAX_GIK_LEN];  // 1024/8 = 128

    /// 00: HMAC SHA 256
    /// 0x01- 0xff : reserved
    u_int8_t integrityAlgoUsed;
} ieee1905GikId_t;

#define IEEE1905_ENCRYPTED_OUTPUT_LEN_MAX IEEE1905_LARGE_BUFFER_SIZE
#define IEEE1905_MIC_LENGTH_MAX 32
/**
 * @brief Representation of Encrypted TLV
 */
typedef struct ieee1905Encrypt_t {
    /// Encryption Transmission Counter.
    u_int64_t encryptTxCounter;

    /// Source LA MAC ID of this TLV.
    struct ether_addr srcMAC;

    /// Source LA MAC ID of this TLV.
    struct ether_addr destMAC;

    /// Length of the AES-SIV Encryption Output field.
    u_int16_t aesLen;

    /// AES-SIV Encryption Output field (i.e., SIV concatenated with all the
    /// encrypted TLVs)
    u_int8_t output[IEEE1905_ENCRYPTED_OUTPUT_LEN_MAX];
} __attribute__((packed)) ieee1905Encrypt_t;

/**
 * @brief Representation of MIC
 */
typedef struct ieee1905MIC_t {
    /// 1905 GTK Key Id
    u_int8_t gtkId : 2;

    /// MIC version
    u_int8_t micVersion : 2;

    u_int8_t reserved : 4;

    /// Integrity Tx Counter
    u_int64_t integrityTxCounter;

    /// Source 1905 AL MAC Address
    struct ether_addr srcAddr;

    /// Length of MIC
    u_int16_t micLength;

    u_int8_t mic[IEEE1905_MIC_LENGTH_MAX];
} ieee1905MIC_t;

/**
 * @brief Representation of DSCP Mapping
 */
typedef struct ieee1905DSCP_t {
    /// List of 64 PCP values (one octet per value) corresponding to
    /// the DSCP markings 0x00 to 0x3F,
    /// ordered by increasing DSCP value.
    u_int8_t dscpToPCP[IEEE1905_MAX_PCP_LEN];
} ieee1905DSCP_t;

#define IEEE1905_MAX_SUPPORTED_SERVICES 2
/**
 * @brief Supported Service Representation
 */
typedef struct ieee1905SupportedServices_t {
    /// Number of Supported Services
    u_int8_t numServices;

    /// List of supported services
    u_int8_t supportedService[IEEE1905_MAX_SUPPORTED_SERVICES];
} ieee1905SupportedServices_t;

/**
 * @brief Searched Service Representation
 */
typedef struct ieee1905SearchedServices_t {
    /// Number of Searched Services
    u_int8_t numServices;

    /// List of searched services
    u_int8_t searchedService[IEEE1905_MAX_SUPPORTED_SERVICES];
} ieee1905SearchedServices_t;

typedef enum ieee1905DPPFrameType_e {
    ieee1905DPPAction_authReq = 0,
    ieee1905DPPAction_authResp = 1,
    ieee1905DPPAction_authConfirm = 2,
    ieee1905DPPAction_peerDiscoveryReq = 5,
    ieee1905DPPAction_peerDiscoveryResp = 6,
    ieee1905DPPAction_pkexExReq = 7,
    ieee1905DPPAction_pkexExResp = 8,
    ieee1905DPPAction_pkexCommitReq = 9,
    ieee1905DPPAction_pkexCommitResp = 10,
    ieee1905DPPAction_ConfigResult = 11,
    ieee1905DPPAction_ConnStatusResult = 12,
} ieee1905DPPFrameType_e;

#define IEEE1905_MAX_NUM_AKM_SUITES 12
#define IEEE1905_SIZE_OF_OUI 3

/**
 * @brief AKM Suite
 */
typedef struct ieee1905AKMSuite_t {
    /// AKM OUI
    u_int8_t oui[IEEE1905_SIZE_OF_OUI];

    /// Suite type
    u_int8_t type;
} ieee1905AKMSuite_t;

/**
 * @brief AKM Suite Capabilities
 */
typedef struct ieee1905AKMSuiteCapabilities_t {
    /// Num BH AKM Suite Selectors
    u_int8_t numBhAKM;

    /// BH AKM Suite
    ieee1905AKMSuite_t bhAKMSuite[IEEE1905_MAX_NUM_AKM_SUITES];

    /// Num FH AKM Suite Selectors
    u_int8_t numFhAKM;

    /// FH AKM Suite
    ieee1905AKMSuite_t fhAKMSuite[IEEE1905_MAX_NUM_AKM_SUITES];
} ieee1905AKMSuiteCapabilities_t;

/**
 * @brief Encap DPP TLV
 */
typedef struct ieee1905DPPEncap_t {
    /// URI information
    IEEE1905_BOOL enrolleeMacPresent : 1;
    IEEE1905_BOOL reserved1 : 1;
    u_int8_t dppFrameIndicator : 1;
    u_int8_t reserved2 : 5;

    /// STA MAC Address
    struct ether_addr staAddr;

    /// DPP Frame Type
    ieee1905DPPFrameType_e dppFrameType;

    /// Length of encapsulated frame
    u_int16_t length;

    /// DPP or GAS frame
    u_int8_t dppFrame[ETH_FRAME_LEN * 2];
} ieee1905DPPEncap_t;

/**
 * @brief DPP Encap EAPOL TLV representation
 */
typedef struct ieee1905DPPEncapEapol_t {
    /// Length of eapol frame payload (Not part of TLV)
    u_int16_t length;

    /// EAPOL frame payload
    u_int8_t eapolPayload[ETH_FRAME_LEN];
} ieee1905DPPEncapEapol_t;

#define IEEE1905_BOOTSTRAP_URI_LENGTH 512
/**
 * @brief DPP Bootstrapping URI Notification
 */
typedef struct ieee1905DPPBootstrappingURI_t {
    /// RUI of a radio
    struct ether_addr ruiAddr;

    /// MAC Address of Local Interface (equal to BSSID) operating on the radio,
    /// on which the URI was received during PBC onboarding
    struct ether_addr bSSID;

    /// MAC Address of bSTA from which the URI was received during PBC onboarding
    struct ether_addr bstaAddr;

    /// Length of URI (Not part of TLV)
    u_int16_t uriLength;

    /// DPP Bootstrapping URI received during PBC onboarding
    u_int8_t uri[IEEE1905_BOOTSTRAP_URI_LENGTH];
} ieee1905DPPBootstrappingURI_t;

#define IEEE1905_HASH_VALUE_MAX_SIZE 256
/**
 * @brief DPP CCE Indication TLV
 */
typedef struct ieee1905DPPChirpValue_t {
    /// Enrollee MAC Address Present This field is only set to 1 for reconfiguration purposes
    IEEE1905_BOOL enrolleeMacPresent : 1;
    IEEE1905_BOOL hashValidity : 1;
    u_int8_t reserved : 6;

    /// Destination STA MAC Address
    struct ether_addr staAddr;

    /// Hash Length
    u_int8_t hashLength;

    /// Hash Value
    u_int8_t hashValue[IEEE1905_HASH_VALUE_MAX_SIZE];
} ieee1905DPPChirpValue_t;

typedef enum mapServiceVersion_e {
    /* Multi-AP Version 1 */
    mapServiceVersion_1 = 1,
    /* Multi-AP Version 2 */
    mapServiceVersion_2 = 2,
    /* Multi-AP Version 3 */
    mapServiceVersion_3 = 3,

    ///should be last
    mapServiceVersion_invalid = 0x0f,
} mapServiceVersion_e;

/*-------------------------------------------------------------------*/
/*---------------------------IEEE1905 API----------------------------*/
/*-------------------------------------------------------------------*/

/*
 * TLV Handling API
 */
#define ieee1905TLVTypeGet( _TLV ) \
    ( (_TLV)->type )

#define ieee1905TLVTypeSet( _TLV, _type ) \
    do{ (_TLV)->type = _type; (_TLV)->length = 0;} while(0)

#define ieee1905TLVLenGet( _TLV ) \
    ( htons( (_TLV)->length ) )

#define ieee1905TLVLenSet( _TLV, _length, _total ) \
    do{ (_TLV)->length = htons( _length ); ( _total ) += ( _length ) + IEEE1905_TLV_MIN_LEN; } while(0)

#define ieee1905TLVValGet( _TLV ) \
    ( (_TLV)->val )

#define ieee1905EndOfTLVSet( _TLV ) \
    do{ (_TLV)->type = IEEE1905_TLV_TYPE_END_OF_MESSAGE; (_TLV)->length = 0; } while(0)

#define ieee1905TLVGetNext( _TLV ) \
    ((ieee1905TLV_t *)((u_int8_t *)(_TLV) + htons( (_TLV)->length ) + IEEE1905_TLV_MIN_LEN))

#define ieee1905TLVValSet( _TLV, _val, _len ) \
    do{ (_TLV)->length = htons(_len) ; memcpy((_TLV)->val, (_val), (_len) ); } while(0)

#define ieee1905TLVSet( _TLV, _type, _len, _val, _total ) \
    do{ (_TLV)->type = _type; (_TLV)->length = htons(_len); memcpy((_TLV)->val, (_val), (_len) ); ( _total ) += ( _len ) + IEEE1905_TLV_MIN_LEN; } while(0)

#define ieee1905GetTotalEncryptionLength(frameLen) \
    (frameLen - IEEE1905_ETH_HEAD_LEN - IEEE1905_HEAD_LEN - IEEE1905_TLV_MIN_LEN)

#define ieee1905GetFirstTLV(frame) (frame + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN)

#endif /* ieee1905_defs__h */
