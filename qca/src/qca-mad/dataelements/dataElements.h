/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef deInit__h
#define deInit__h

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <jansson.h>
#include <errno.h>
#include <time.h>
#include <evloop.h>
#include <dbg.h>
#include <sys/time.h>
#include <ieee1905_defs.h>
#include <string.h>
#include <bufrd.h>

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Config Parameters
// ====================================================================

#define DE_SERVICE_ENABLE "EnableDataElements"
#define DE_JSON_REPORTING_INTERVAL "DEReportingInteval"
#define DE_NEIGHBOUR_SCAN_INTERVAL "DENeighbourScanInterval"
#define DE_JSON_FILE_PATH "DEJsonFilePath"
#define DE_RADIO_JSON_ENABLE "DERadioJsonEnable"
#define DE_RADIO_CAPS_JSON_ENABLE "DERadioCapsJsonEnable"
#define DE_RADIO_BSS_LIST_JSON_ENABLE "DERadioBssListJsonEnable"
#define DE_RADIO_BACKHAUL_STA_JSON_ENABLE "DERadioBkStaJsonEnable"
#define DE_RADIO_SCAN_RESULT_JSON_ENABLE "DERadioScanResultJsonEnable"
#define DE_RADIO_UNASSOC_STA_JSON_ENABLE "DERadioUnAssocStaJsonEnable"
#define DE_RADIO_CUR_OP_CLASS_JSON_ENABLE "DERadioCurOpClassJsonEnable"
#define DE_BSS_STA_LIST_JSON_ENABLE "DEBssSTAListJsonEnable"
#define DE_STA_ASSOC_EVENT_JSON_ENABLE "DEStaAssocEventJsonEnable"
#define DE_STA_DISASSOC_EVENT_JSON_ENABLE "DEStaDisAssocEventJsonEnable"
#define DE_IS_SINGLE_AP "DESingleAPMode"
#define DE_IS_MAP "DEMAPMode"
#define DE_IS_SON "DESONMode"
#define DE_ENABLE_BASE64_ENCODING "DEEnableBase64Encoding"
#define DE_ENABLE_NB_EVENTS "NBEventEnable"
#define DE_ENABLE_CERT "DEEnableCertCompliance"
#define DE_CONFIG_SECTION "DATAELEMENTS"
#define WLAN_CONFIG_SECTION "WLANIF"

// ====================================================================
// Data Structures for DataElements
// ====================================================================

/*ToDo: Sync all the #defines to the original source */
#define WLANIF_MAX_OPERATING_CLASSES 25
#define WLANIF_MAX_CHANNELS_PER_OP_CLASS IEEE1905_MAX_CHANNELS_PER_OP_CLASS
#define WLAN_MANAGER_MAX_NUM_NEIGHBORS 128
#define WLAN_MANAGER_MAX_NUM_CHANS 32
/* Data Elements MACROS */
#define DATA_ELEMENTS_MAX_SCAN_RESULTS 256
#define DATA_ELEMENTS_IPV4_STRING_LEN 15
#define DATA_ELEMENTS_IPV6_STRING_LEN 39
#define DATA_ELEMENTS_NUMBER_OF_DEVICES 30
#define DATA_ELEMENT_IEEE80211_ADDR_LEN 6
#define DATA_ELEMENT_IEEE80211_NWID_LEN 32
#define DATA_ELEMENTS_STRING_LEN 32
#define DATA_ELEMENTS_MAX_OPERATING_CLASSES WLANIF_MAX_OPERATING_CLASSES
#define DATA_ELEMENTS_MAX_CHANNELS_PER_OP_CLASS WLANIF_MAX_CHANNELS_PER_OP_CLASS
#define DATA_ELEMENTS_MAX_NEIGHBOURS DATA_ELEMENTS_MAX_SCAN_RESULTS
#define DATA_ELEMENTS_HASH_TABLE_SIZE DATA_ELEMENTS_MAX_SCAN_RESULTS
#define DATA_ELEMENTS_IEEE80211_MAX_NEIGHBOURS DATA_ELEMENT_IEEE80211_NWID_LEN
#define DATA_ELEMENTS_STA_ASSOC_SUCCESS 0

#define DATA_ELEMENTS_FILE_NAME_LENGTH 50
#define MAP_SERVICE_MAX_OPERATING_CLASSES 20

#define IEEE1905_QCA_VENDOR_MAX_BSS ( 15 )

#define HD_ETH_ADDR_LEN             ETH_ALEN

#define __deMidx(_arg, _i) (((u_int8_t *)_arg)[_i])

#define deMACAddHash(_arg) (__deMidx(_arg, 0) ^ __deMidx(_arg, 1) ^ __deMidx(_arg, 2) \
                ^ __deMidx(_arg, 3) ^ __deMidx(_arg, 4) ^ __deMidx(_arg, 5)) /* convert to use the ETH_ALEN constant */

#define deCopyMACAddr(src, dst) memcpy( dst, src, HD_ETH_ADDR_LEN )

#define deAreEqualMACAddrs(arg1, arg2) (!memcmp(arg1, arg2, HD_ETH_ADDR_LEN))

#define deMACAddFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"

#define deMACAddData(_arg) __hyMidx(_arg, 0), __hyMidx(_arg, 1), __hyMidx(_arg, 2), __hyMidx(_arg, 3), __hyMidx(_arg, 4), __hyMidx(_arg, 5)

#define __hyMidx(_arg, _i) (((u_int8_t *)_arg)[_i])

#define DATA_LEN_MAX 1024
#define LOCAL_PORT 8090
#define CLI_PORT 8091

#include <sys/types.h>          /* Primitive types: u_int32_t, u_int8_t... */
#include <net/ethernet.h>       /* Ethernet structures */

#define dataElementDebug(level, ...) dbgf(dataElementState.dbgModule, (level), __VA_ARGS__)

#define DE_NB_FRAME_LEN_MAX 2048
#define SERVICE_TYPE_DE 2

/*
* DE_STATUS - Hybrid daemon API return values:
*
* DE_OK: Function succeeded
* DE_NOK: Function failed
*
*/
typedef enum
{
    DE_OK = 0,
    DE_NOK = -1

} DE_STATUS;

/*
* DE_BOOL - Hybrid daemon boolean return values: FALSE & TRUE
*/
typedef enum
{
    DE_FALSE = 0,
    DE_TRUE = !DE_FALSE

} DE_BOOL;

typedef struct dataElementJsonObjectDB_t {
    /// Key
    u_int8_t key;

    /// Init Time
    struct timeval initTime;

    /// MAC
    struct ether_addr macAddress;

    /// MAC Key address
    struct ether_addr macKey;

    /// Flag
    u_int8_t acsReady;

    //SingleAPmode: previous utilization Receive
    u_int32_t utilizationReceive;

    //SingleAPmode: previous utilization Transmit
    u_int32_t utilizationTransmit;

    //SingleAPmode: previous rxbyte
    u_int32_t prevrxByte;

    //SingleAPmode: previous txbyte
    u_int32_t prevtxByte;

    /// JSON Object
    json_t *jObject;
} dataElementJsonObjectDB_t;

typedef enum DETlvType_e {
    DE_TLV_TYPE_GET_NETWORK = 1,
    DE_TLV_TYPE_GET_DEVICE = 2,
    DE_TLV_TYPE_GET_RADIO = 3,
    DE_TLV_TYPE_GET_CUR_OP_CLASS = 4,
    DE_TLV_TYPE_GET_BSS = 5,
    DE_TLV_TYPE_GET_CAPABILITIES = 6,
    DE_TLV_TYPE_GET_STA = 7,
    DE_TLV_TYPE_GET_CAP_OP_CLASS_PROF = 8,
    DE_TLV_TYPE_GET_BACKHAUL = 9,
    DE_TLV_TYPE_GET_SCAN_RESULT = 10,
    DE_TLV_TYPE_GET_OP_CLASS_SCAN = 11,
    DE_TLV_TYPE_GET_CHAN_SCAN = 12,
    DE_TLV_TYPE_GET_NEIGH_BSS = 13,
    DE_TLV_TYPE_GET_UNASSOC_STA = 14,
    DE_TLV_TYPE_GET_NUM_RADIOS = 15,
    DE_TLV_TYPE_GET_RADIO_ADDR = 16,
    DE_TLV_TYPE_GET_RADIO_CAP = 17,
    DE_TLV_TYPE_ASSOC_EVENT = 18,
    DE_TLV_TYPE_DISASSOC_EVENT = 19,
    DE_TLV_TYPE_ENABLE_NBEVENT = 20,
    DE_TLV_TYPE_INTERFACE_UP_EVENT = 21,
    DE_TLV_TYPE_INTERFACE_DOWN_EVENT = 22,
    DE_TLV_TYPE_RE_JOIN_EVENT = 23,
    DE_TLV_TYPE_RE_LEAVE_EVENT = 24,
    DE_TLV_TYPE_CONTROLLER_UP_EVENT = 25,
    DE_TLV_TYPE_CONTROLLER_DOWN_EVENT = 26,
    DE_TLV_TYPE_ENABLE_EVENT = 27,
    DE_TLV_TYPE_ERROR = 255
} DETlvType_e;

struct profileElement {
    const char *Element;
    const char *Default;
};

/**
 * @brief Internal state for Data Elements.
 */
typedef struct {
    /// Handle to use when logging
    struct dbgModule *dbgModule;

    struct ether_addr devAddr;

    int isNBSocket_init;

    int NBSocket;

    /// Configuration parameters
    struct {
        /// Init the Module
        DE_BOOL enableDE;

        /// Radio JSON Object Enabled
        DE_BOOL enableRadioObject;

        /// Radio CAPS JSON Object Enabled
        DE_BOOL enableRadioCapsObject;

        /// Radio BSS List JSON Object Enabled
        DE_BOOL enableRadioBssListObject;

        /// Radio BackhaulSta Object Enabled
        DE_BOOL enableRadioBkStaObject;

        /// Radio Scan Result Object Enabled
        DE_BOOL enableRadioScanResultObject;

        /// Radio UnAssociated STA Object Enabled
        DE_BOOL enableRadioUnAssocStaObject;

        /// Radio Current Op Class Object Enabled
        DE_BOOL enableRadioCurOpClassObject;

        /// BSS Sta List Object Enabled
        DE_BOOL enableBssStaListObject;

        /// Sta Assoc Event Object Enabled
        DE_BOOL enableStaAssocEventObject;

        /// Sta DisAssoc Event Object Enabled
        DE_BOOL enableStaDisAssocEventObject;

        ///Single AP mode
        DE_BOOL isSingleAP;

        ///MultiAP map mode
        DE_BOOL isMAP;

        ///MultiAP son mode
        DE_BOOL isSON;

        ///Enabled base64 Encoding
        DE_BOOL enableb64Enc;

        //WFA certificate compliance
        DE_BOOL enableCertCompliance;

        //BT event request
        DE_BOOL NBEventEnable;

        /// JSON Reporting Interval
        u_int32_t reportingIntervalSecs;

        /// Neighbour Scan Interval
        u_int32_t neighbourScanIntervalSecs;

        /// Json File creation path
        char jsonFileName[DATA_ELEMENTS_FILE_NAME_LENGTH];
    } config;

    struct bufrd ReadBuf;

    /// Network Type
    DE_BOOL isMultiAP;

    ///stats collection state
    DE_BOOL isRunning;

    ///number of devices in the network
    u_int32_t numOfdevice;

    ///Number of Radios in the device
    u_int32_t numOfRadios;

    /// JSON Init Time
    struct timeval initTime;

    /// Timer used for periodically creating JSON Object
    struct evloopTimeout jsonReportTimer;

    /// Timer used for Neighbor Scan Interval Time
    struct evloopTimeout neighbourScanTimer;

    /// Stats without scan result
    DE_BOOL isStatsOnly;
} dataElementState_t;

extern dataElementState_t dataElementState;

typedef struct dataElementsStaApCapabilities_t {
    DE_BOOL isHTValid;
    DE_BOOL isVHTValid;
    DE_BOOL isHEValid;

    /// Describes the HT capabilities of the radio as defined by the HT
    /// Capabilities TLV  Section 17.2.8 in [3]
    ieee1905APHtCapabilities_t apHtCap;

    /// Describes the VHT capabilities of the radio as defined by the VHT
    /// Capabilities TLV  Section 17.2.9 in [3]
    ieee1905APVhtCapabilities_t apVhtCap;

    /// Describes the HE capabilities of the radio as defined by the HE
    /// Capabilities TLV  Section 17.2.10 in [3]
    ieee1905APHeCapabilities_t apHeCap;
} dataElementsStaApCapabilities_t;

typedef struct dataElementsNeighbourBSS_t {

    u_int8_t channel;
    /// The BSSID used for the neighboring Wi-Fi SSID.
    struct ether_addr BSSID;

    /// The SSID in use by the neighbor
    char ssid[DATA_ELEMENT_IEEE80211_NWID_LEN + 1];

    /// An indicator of radio signal strength (RSSI) of the neighboring Wi-Fi
    /// radio measured in dBm. (RSSI threshold is encoded per Table 9-154 of [1]).
    /// 221 - 255: Reserved.
    u_int8_t signalStrength;

    /// Indicates the bandwidth at which the neighbor BSS is operating. e.g. 20,
    /// 40, 80, 160 MHz
    u_int8_t channelBandwidth;

    /// The channel utilization reported by the neighbor Beacon BSS load element
    /// if present, as defined by Section 9.4.2.28 in [1]
    u_int8_t channelUtilization;

    /// The number of associated stations reported by this neighbor in the
    /// Beacon BSS load element as defined by Section 9.4.2.28 in [1]
    u_int16_t stationCount;
} dataElementsNeighbourBSS_t;

typedef struct dataElementsChannelScan_t {
    /// The channel number scanned by the Wi-Fi radio.
    u_int8_t channel;

    struct timeval Time;

    /// The current channel utilization, which is scanned by the Wi-Fi radio, as
    /// defined by Section 9.4.2.28 in [1]
    u_int8_t utilization;

    /// An indicator of the average radio noise plus interference power measured
    /// on the channel during a channel scan. Encoding as defined as for ANPI in
    /// Section 11.11.9.4 in [1]
    /// Reserved: 221-224
    u_int8_t noise;

    /// Number of Neighbours
    u_int8_t numberOfNeighbours;


} dataElementsChannelScan_t;

typedef struct dataElementsOpClassScan_t {
    /// The number of channels scanned in the last scan.
    u_int8_t operatingClass;

    /// The number of channels scanned in the last scan.
    u_int8_t numberOfChannelScans;

    /// The list of ChannelScan results
    dataElementsChannelScan_t ScanChanList[WLAN_MANAGER_MAX_NUM_CHANS];

    /// Neighbour data
    dataElementsNeighbourBSS_t neighData[WLAN_MANAGER_MAX_NUM_NEIGHBORS];

} dataElementsOpClassScan_t;

typedef struct dataElementsScanResult_t {
    /// The number of OpClass scanned in the last scan.
    u_int8_t numberOfOpClassScans;

    dataElementsOpClassScan_t opClassScanList[DATA_ELEMENTS_MAX_OPERATING_CLASSES];
} dataElementsScanResult_t;

typedef struct dataElementsAssociationEventData_t {
    /// The MAC Address of the logical BSS (BSSID) which is reporting the
    /// Association Event
    struct ether_addr BSSID;

    /// The MAC address of an associated device.
    struct ether_addr macAddress;

    /// The status code sent to the station in the latest association response
    /// as defined by Table 9-46 in [1]
    u_int8_t statusCode;

    dataElementsStaApCapabilities_t caps;

} dataElementsAssociationEventData_t;

typedef struct dataElementsDisassociationEventData_t {
    /// The MAC Address of the logical BSS (BSSID) which is reporting the
    /// disassociation event
    struct ether_addr BSSID;

    /// The MAC address of an associated device.
    struct ether_addr macAddress;

    /// The latest reason code received by the AP from the STA in the most
    /// recent  Disassociation message or sent by the AP to the Station in the
    /// most recent Deauthenticaiton message as defined in Table 9-45 in [1]
    u_int8_t reasonCode;

    //STA Stats
    ieee1905StaTrafficStats_t stats;

} dataElementsDisassociationEventData_t;

typedef struct dataElementsDisassociationEvent_t {
    /// The data provided in the event when a disassociation event is generated
    dataElementsDisassociationEventData_t disassocData;
} dataElementsDisassociationEvent_t;

typedef struct dataElementsAssociationEvent_t {
    /// The data provided in the event when a disassociation event is generated
    dataElementsAssociationEventData_t assocData;
} dataElementsAssociationEvent_t;

typedef struct dataElementsUnassociatedSTA_t {
    /// Number of unassociated STA
    u_int8_t numberOfUnassocSta;

    /// The MAC address of the logical STA sharing the Radio for Wi-Fi backhaul
    struct ether_addr macAddress;

    /// An indicator of radio signal strength of the uplink from the
    /// unassociated station, measured in dBm. (RSSI threshold is encoded per
    /// Table 9-154 of [1]).
    /// 221 - 255: Reserved.
    u_int8_t signalStrength;
} dataElementsUnassociatedSTA_t;

typedef struct dataElementsBackHaulSTA_t {
    /// The MAC address of the logical STA sharing the Radio for Wi-Fi backhaul
    struct ether_addr macAddress;
} dataElementsBackHaulSTA_t;

typedef struct dataElementsSTAList_t {
    /// The MAC address of an associated device.
    struct ether_addr macAddress;

    /// The data transmit rate in kbps that was most recently used for
    /// transmission of data PPDUs from the access point to the associated device.
    u_int32_t lastDataDownlinkRate;

    /// The data transmit rate in kbps that was most recently used for
    /// transmission of data PPDUs from the associated device to the access point.
    u_int32_t lastDataUplinkRate;

    /// The amount of time the radio has spent on the channel receiving data
    /// from this STA in milliseconds
    u_int32_t utilizationReceive;

    /// The amount of time the radio has spent on the channel transmitting data
    /// to this STA in milliseconds
    u_int32_t utilizationTransmit;

    /// Estimate of the MAC layer throughput in Mbps achievable in the downlink
    /// if 100% of channel airtime and BSS operating bandwidth were to be
    /// available, as defined in Section 10.3.1 of [3]
    u_int32_t estMACDataRateDownlink;

    /// Estimate of the MAC layer throughput in Mbps achievable in the uplink if
    /// 100% of channel airtime and BSS operating bandwidth were to be available,
    /// as defined in Section 10.3.1 of [3]
    u_int32_t estMACDataRateUplink;

    /// An indicator of radio signal strength of the uplink from the associated
    /// device to the access point, measured in dBm. RSSI threshold (encoded per
    /// Table 9-154 of [1]).
    /// 221 - 255: Reserved.
    u_int8_t signalStrength;

    /// The time when the station associated.
    /// Note Multi-AP reports seconds since association not time
    u_int32_t lastConnectTime;

    /// Number of Measurement Report
    u_int8_t numberOfMeasureReports;

    /// Array of Measurement Report element(s)that was received from the STA in
    /// the latest beacon measurement report frame  as defined per Figure 9-199
    ///(Beacon report) in [1]
    u_int32_t measurementReport;

    /// IPV4 Address assigned to the client
    char ipV4Address[DATA_ELEMENTS_IPV4_STRING_LEN];

    /// IPV6 Address assigned to the client
    char ipV6Address[DATA_ELEMENTS_IPV6_STRING_LEN];

    /// Should client ID or hostname obtained via non Wi-Fi means e.g. from DHCP
    /// be part of WFA spec
    char hostname[DATA_ELEMENTS_STRING_LEN];

    /// STA Capabilities
    dataElementsStaApCapabilities_t caps;

    /// STA Traffic Stats
    ieee1905StaTrafficStats_t stats;

} dataElementsSTAList_t;

typedef struct dataElementsBSS_t {
    /// The MAC Address of the logical BSS (BSSID)
    struct ether_addr BSSID;

    /// The SSID in use for this BSS
    char ssid[DATA_ELEMENT_IEEE80211_NWID_LEN + 1];

    /// Whether the BSSID is currently enabled and beaconing
    DE_BOOL enabled;

    /// UTC time in secs of the last change to the Enabled value
    u_int32_t lastChange;

    /// BSS wide statistics for total unicast bytes transmitted
    u_int32_t unicastBytesSent;

    /// BSS wide statistics for total unicast bytes received
    u_int32_t unicastBytesReceived;

    /// BSS wide statistics for total multicast bytes transmitted
    u_int32_t multicastBytesSent;

    /// BSS wide statistics for total multicast bytes received
    u_int32_t multicastBytesReceived;

    /// BSS wide statistics for total broadcast bytes transmitted
    u_int32_t broadcastBytesSent;

    /// BSS wide statistics for total broadcast bytes received
    u_int32_t broadcastBytesReceived;

    u_int32_t NumberOfSTA;

    ieee1905APMetricData_t apMetrics;

} dataElementsBSS_t;

typedef struct dataElementsCapableOpClassProfile_t {
    /// Operating class per Table E-4 in [1] that this radio is capable of
    /// operating on
    u_int8_t opClass;

    /// Maximum transmit power EIRP that this radio is capable of transmitting
    /// in the current regulatory domain for the operating class; represented as
    /// 2's complement signed integer in units of decibels relative to 1 mW (dBm).
    int8_t maxTxPower;

    /// Number of Non Operable Channels
    u_int8_t numberOfNonOperChan;

    /// List of channel numbers which are statically non-operable in the
    /// operating class (i.e. the radio is never able to operate on these channels
    ///- Other channels from this operating class which are not listed here are
    /// supported for the radio.).
    u_int8_t nonOperable[DATA_ELEMENTS_MAX_CHANNELS_PER_OP_CLASS];
} dataElementsCapableOpClassProfile_t;

typedef struct dataElementsCapabilities_t {
    /// Number of Operating Classes
    u_int8_t numberOfOpClass;

    dataElementsStaApCapabilities_t caps;

} dataElementsCapabilities_t;

typedef struct dataElementsCurrentOpClassProfile_t {

    struct timeval Time;

    DE_BOOL valid;
    /// Operating class per Table E-4 in [1] that this radio is currently
    /// operating on
    u_int8_t opClass;

    /// The channel number of the operating class in the previous field
    u_int8_t channel;

    u_int8_t numberOfCurrOpClass;
    /// Nominal transmit power EIRP that this radio is currently using for the
    /// operating class; represented as 2's complement signed integer in units of
    /// decibels relative to 1 mW (dBm).
    int8_t txPower;
} dataElementsCurrentOpClassProfile_t;

typedef struct dataElementsRadio_t {
    /// radio Object
    json_t *radioObject;

    /// Unique ID for this radio
    struct ether_addr id;

    /// Indicates whether this radio is enabled
    DE_BOOL enabled;

    /// An indicator of the average radio noise plus interference power measured
    // for the primary operating channel. Encoding as defined for ANPI in Section
    // 11.11.9.4 of [1]
    u_int8_t noise;

    /// The current total channel utilization as defined by Section 9.4.2.28
    u_int8_t utilization;

    /// The percentage of time, linearly scaled with 255 representing 100%, the
    /// radio has spent on individually or group addressed transmissions by the
    /// AP. When more than one channel is in use by BSS operating on the radio,
    /// the Transmit value is calculated only for the primary channel.
    u_int8_t transmit;

    /// The percentage of time, linearly scaled with 255 representing 100%, the
    /// radio has spent on receiving individually or group addressed transmissions
    /// from any STA associated with any BSS operating on this radio. When more
    /// than one channel is in use by BSS operating on the radio, the ReceiveSelf
    /// value is calculated only for the primary channel.
    u_int8_t receiveSelf;

    /// The percentage of time, linearly scaled with 255 representing 100%, the
    /// radio has spent on receiving valid IEEE 802.11 PPDUs that are not
    /// associated with any BSS operating on this radio. When more than one
    /// channel is in use by BSS operating on the radio, the ReceiveOther value is
    /// calculated only for the primary channel.
    u_int8_t receiveOther;

    /// The number of logical BSS configured on this radio
    u_int8_t numberOfBSS;

    /// The number of current operating class
    u_int8_t numberOfCurrOpClass;

    /// The number of UnAssocSta
    u_int8_t numberOfUnassocSta;
} dataElementsRadio_t;

typedef struct dataElementsDevice_t {
    /// A unique identifier for this particular device within the Wi-Fi network
    struct ether_addr id;

    /// The Multi-AP capabilities supported by this device as defined by the AP
    // Capability TLV in [3]
    u_int8_t multiAPCapabilities;

    /// The number of radios in this Access Point
    u_int8_t numberOfRadios;

    /// The Collection Interval in ms
    u_int32_t collectionInterval;
} dataElementsDevice_t;

typedef struct dataElementsNetwork_t {
    /// A unique identifier for this particular Wi-Fi network
    char id[DATA_ELEMENTS_STRING_LEN];

    struct timeval Time;

    /// A unique identifier for a controller only device
    struct ether_addr ctrlId;

    /// The number of Access Points [Multi-AP Agents] devices in this particular
    // Wi-Fi Network
    u_int8_t numberOfDevices;
} dataElementsNetwork_t;

struct dataElementJsonObjectDB_t *dEFindorCreateJsonEntry(const struct ether_addr *macAddress, const struct ether_addr *macKey);

DE_STATUS dEGetTimeElapsed(dataElementJsonObjectDB_t *jsonEntry, u_int32_t *timeElapsed);

void dataElementsCreateJsonObjects();

/**
 * @brief Initialize the Data Element JSON library.
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
int dataElementsInit(void);

/**
 * @brief Creates north bound Server socket
 *
 * @return DE_OK on success. Otherwise return DE_NOK
 */
DE_STATUS create_server_socket();

/**
 * @brief Registers the CallBack function
 *
 */
void dataElementEventRdbufRegister(void);

/**
 * @brief Fetch and process the data sent by north bound client
 *
 */
void dataElementCB(void *Cookie);

/**
 * @brief Handles request sent from the client
 *
 * @param [in] request   query sent from the client
 */
void request_handler(char *request);


/**
 * @brief Extract the query from the HTTP request sent from client
 *
 * @param [in] query   HTTP query sent from the client
 * @param [inout] buffer   The actual request extracted from the query
 */
void extract_request(char *query, char *buffer);


/**
 * @brief Get the request number associated with the client request
 *
 * @param [in] request   query sent from the client
 * @param [inout] num   request number associated to the request
 */
void getRequestNumber(char *request, int *num);

void sendNBRequest(void);

int dENBMsgDispatch(int msgType, int count,  char *data, int dataLen);

enum dataQuery
{
    GET_STATS = 1,
    GET_STATS_ONLY = 2,
};

#if defined(__cplusplus)
}
#endif

#endif /* deInit__h */
