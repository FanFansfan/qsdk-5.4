/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef deServiceMsg_h
#define deServiceMsg_h

#include "dataElements.h"

#if defined(__cplusplus)
extern "C" {
#endif


// ====================================================================
// Data Elements Key Names
// ====================================================================
/// Common Parameters
#define DE_COMMON_TIMESTAMP "TimeStamp"
#define DE_COMMON_EVENT_TIMESTAMP "eventTime"
#define DE_COMMON_ID "ID"
#define DE_COMMON_OP_CLASS "Class"
#define DE_COMMON_ENABLED "Enabled"
#define DE_COMMON_MAC_ADDR "MACAddress"
#define DE_COMMON_BSSID "BSSID"
#define DE_COMMON_SSID "SSID"
#define DE_COMMON_SIGNAL_STRENGTH "SignalStrength"
#define DE_COMMON_CHANNEL "Channel"
#define DE_COMMON_UTILIZATION "Utilization"
#define DE_COMMON_NOISE "Noise"

/// Config Parameters
#define DE_CONFIG_VERSION "version"
#define DE_CONFIG_NAME "name"
#define DE_CONFIG_DESCRIPTION "description"
#define DE_CONFIG_DATE "date"

/// Network Parameters
#define DE_NETWORK_ID DE_COMMON_ID
#define DE_NETWORK_NUM_OF_DEVICES "NumberOfDevices"
#define DE_NETWORK_CONTROLLER_ID "ControllerID"

/// Device Parameters
#define DE_DEVICE_ID DE_COMMON_ID
#define DE_DEVICE_NUM_OF_RADIOS "NumberOfRadios"
#define DE_DEVICE_COLLECTION_INTERVAL "CollectionInterval"
#define DE_DEVICE_MULTI_AP_CAP "MultiAPCapabilities"

/// Radio Parameters
#define DE_RADIO_ID DE_COMMON_ID
#define DE_RADIO_ENABLED DE_COMMON_ENABLED
#define DE_RADIO_NOISE DE_COMMON_NOISE
#define DE_RADIO_NUM_CUR_OP_CLASS "NumberOfCurrOpClass"
#define DE_RADIO_NUM_OF_UNASSOC_STA "NumberOfUnassocSta"
#define DE_RADIO_NUM_OF_BSS "NumberOfBSS"
#define DE_RADIO_UTILIZATION DE_COMMON_UTILIZATION
#define DE_RADIO_TRANSMIT "Transmit"
#define DE_RADIO_RECEIVE_SELF "ReceiveSelf"
#define DE_RADIO_RECEIVE_OTHER "ReceiveOther"

/// Current OpClass Parameters
#define DE_CUR_OP_CLASS DE_COMMON_OP_CLASS
#define DE_CUR_OP_TX_POWER "TxPower"
#define DE_CUR_OP_CHANNEL DE_COMMON_CHANNEL

/// Current Capabilities Parameters
#define DE_CAPABILITIES_NUM_OP_CLASS "NumberOfOpClass"
#define DE_CAPABILITIES_OP_CLASS DE_COMMON_OP_CLASS
#define DE_CAPABILITIES_MAX_TX_POWER "MaxTxPower"
#define DE_CAPABILITIES_NUM_NON_OP_CHAN "NumberOfNonOperChan"
#define DE_CAPABILITIES_NON_OPERABLE_CHAN "NonOperable"
#define DE_CAPABILITIES_ESP_BE "EstServiceParametersBE"
#define DE_CAPABILITIES_ESP_BK "EstServiceParametersBK"
#define DE_CAPABILITIES_ESP_VI "EstServiceParametersVI"
#define DE_CAPABILITIES_ESP_VO "EstServiceParametersVO"
#define DE_CAPABILITIES_HT "HTCapabilities"
#define DE_CAPABILITIES_VHT "VHTCapabilities"
#define DE_CAPABILITIES_HE "HECapabilities"

/// BSS Parameters
#define DE_BSS_BSSID DE_COMMON_BSSID
#define DE_BSS_SSID DE_COMMON_SSID
#define DE_BSS_ENABLED DE_COMMON_ENABLED
#define DE_BSS_LAST_CHANGE "LastChange"
#define DE_BSS_NUM_OF_STA "NumberOfSTA"
#define DE_BSS_UNICAST_BYTES_SENT "UnicastBytesSent"
#define DE_BSS_UNICAST_BYTES_RECEIVED "UnicastBytesReceived"
#define DE_BSS_MULTICAST_BYTES_SENT "MulticastBytesSent"
#define DE_BSS_MULTICAST_BYTES_RECEIVED "MulticastBytesReceived"
#define DE_BSS_BROADCAST_BYTES_SENT "BroadcastBytesSent"
#define DE_BSS_BROADCASR_BYTES_RECEIVED "BroadcastBytesReceived"

/// STA Parameters
#define DE_STA_MAC_ADDR DE_COMMON_MAC_ADDR
#define DE_BACKHAUL_STA_MAC_ADDR DE_COMMON_MAC_ADDR
#define DE_UNASSOC_STA_MAC_ADDR DE_COMMON_MAC_ADDR
#define DE_STA_SIGNAL_STRENGTH DE_COMMON_SIGNAL_STRENGTH
#define DE_STA_BSSID DE_COMMON_BSSID
#define DE_STA_LAST_DATA_DOWNLINK_RATE "LastDataDownlinkRate"
#define DE_STA_LAST_DATA_UPLINK_RATE "LastDataUplinkRate"
#define DE_STA_EST_MAC_DATA_DOWNLINK_RATE "EstMACDataRateDownlink"
#define DE_STA_EST_MAC_DATA_UPLINK_RATE "EstMACDataRateUplink"
#define DE_STA_UTIL_RX "UtilizationReceive"
#define DE_STA_UTIL_TX "UtilizationTransmit"
#define DE_STA_LAST_CONNECT_TIME "LastConnectTime"
#define DE_STA_NUM_MEASUREMENT_REPORTS "NumberOfMeasureReports"
#define DE_STA_MEASUREMENT_REPORT "Measurementreport"
#define DE_STA_IPV4_ADDRESS "IPV4Address"
#define DE_STA_IPV6_ADDRESS "IPV6Address"
#define DE_STA_HOSTNAME "Hostname"
#define DE_STA_STATUS_CODE "StatusCode"
#define DE_STA_REASON_CODE "ReasonCode"
#define DE_STA_BYTES_SENT "BytesSent"
#define DE_STA_BYTES_RECEIVED "BytesReceived"
#define DE_STA_PACKETS_SENT "PacketsSent"
#define DE_STA_PACKETS_RECEIVED "PacketsReceived"
#define DE_STA_ERRORS_SENT "ErrorsSent"
#define DE_STA_ERRORS_RECEIVED "ErrorsReceived"
#define DE_STA_RETRANS_COUNT "RetransCount"
#define DE_CAP_HTSHGI_20MHZ "HtShortGi20Mhz"
#define DE_CAP_HTSHGI_40MHZ "HtShortGi40Mhz"
#define DE_CAP_HT40MHZ "Ht40MHz"
#define DE_CAP_VHTSHGI_80MHZ "VhtShortGi80Mhz"
#define DE_CAP_VHTSHGI_160_80P_80 "VhtShortGi160Mhz80p80Mhz"
#define DE_CAP_VHTSHGI_80P80MHZ "VhtShortGi80p80Mhz"
#define DE_CAP_VHT160MHZ "Vht160Mhz"
#define DE_CAP_TX_MCS "TxMcs"
#define DE_CAP_RX_MCS "RxMcs"
#define DE_CAP_MAX_TX_NSS "MaxTxNss"
#define DE_CAP_MAX_RX_NSS "MaxRxNss"
#define DE_CAP_HT_VALID "HTValid"
#define DE_CAP_VHT_VALID "VHTValid"
#define DE_CAP_HE_VALID "HEValid"
#define DE_CAP_HE_MCS_ENTRY "numMCSEntries"
#define DE_SUP_HE_MCS "supportedHeMCS"
#define DE_CAP_SU_BEAM_FORMER "suBeamformerCapable"
#define DE_CAP_MU_BEAM_FORMER "muBeamformerCapable"
#define DE_CAP_ULMU_MIMO  "ulMuMimoCapable"
#define DE_CAP_ULMU_MIMO_OFDMA "ulMuMimoOfdmaCapable"
#define DE_CAP_DLMU_MIMO_OFDMA "dlMuMimoOfdmaCapable"
#define DE_CAP_UL_OFDMA "ulOfdmaCapable"
#define DE_CAP_DL_OFDMA "dlOfdmaCapable"
#define DE_CAP_HE_80MHZ "support80p80Mhz"
#define DE_CAP_HE_160MHZ "support160Mhz"


/// Neighbour Scan Parameters
#define DE_NEIGHBOUR_NUM_OP_CLASS_SCAN "NumberOfOpClassScans"
#define DE_NEIGHBOUR_OP_CLASS "OperatingClass"
#define DE_NEIGHBOUR_NUM_CHAN_SCAN "NumberOfChannelScans"
#define DE_NEIGHBOUR_CHANNEL DE_COMMON_CHANNEL
#define DE_NEIGHBOUR_UTILIZATION DE_COMMON_UTILIZATION
#define DE_NEIGHBOUR_NOISE DE_COMMON_NOISE
#define DE_NEIGHBOUR_NUM_NEIGHBOURS "NumberOfNeighbors"
#define DE_NEIGHBOUR_BSSID DE_COMMON_BSSID
#define DE_NEIGHBOUR_SSID DE_COMMON_SSID
#define DE_NEIGHBOUR_SIGNAL_STRENGTH DE_COMMON_SIGNAL_STRENGTH
#define DE_NEIGHBOUR_CHANNEL_BW "ChannelBandwidth"
#define DE_NEIGHBOUR_CHANNEL_UTIL "ChannelUtilization"
#define DE_NEIGHBOUR_STATION_COUNT "StationCount"

/**
 * @brief Base-64 Conversion Table
 */
static const char dEBase64ConversionTable[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

/**
 * @brief Type of Operation to modify JSON Object
 */
typedef enum dataElementModifyJsonValue_e {
    /// Replace the JSON Value
    dataElementObjectValue_replace,

    /// Add to existing JSON Value
    dataElementObjectValue_add,

    /// Subtract from existing JSON Value
    dataElementObjectValue_subtract,
} dataElementModifyJsonValue_e;

// ----------------------------------------------------------------
// Operations used when constructing a Json Message
// ----------------------------------------------------------------

/**
 * @brief Callback to be invoked to populate config data
 *        elements object
 *
 * @param [in] isMultiAP  flag to notify if network is MAP or SAP
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateConfigJsonObject(DE_BOOL isMultiAP, json_t *config);

/**
 * @brief Callback to be invoked to populate network data
 *        elements object
 *
 * @param [in] networkData  structure containing the network parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateNetworkJsonObject(dataElementsNetwork_t networkData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate device data
 *        elements object
 *
 * @param [in] deviceData  structure containing the device parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateDeviceJsonObject(dataElementsDevice_t deviceData, json_t *jObject);


/**
 * @brief Callback to be invoked to populate radio data
 *        elements object
 *
 * @param [in] radioData  structure containing the radio parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateRadioJsonObject(dataElementsRadio_t radioData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate current operating class
 *        elements object
 *
 * @param [in] curOpClassData  structure containing the current OpClass parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateCurrentOpClassesObject(dataElementsCurrentOpClassProfile_t curOpClassData,
        json_t *jObject);

/**
 * @brief Callback to be invoked to populate Capabilities data
 *        elements object
 *
 * @param [in] capsData  structure containing the Capabilities parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateCapabilitiesJsonObject(dataElementsCapabilities_t capsData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate Capable OpClass
 *        elements object
 *
 * @param [in] capOpClassData  structure containing the capable OpClass parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateCapableOpClassesObject(dataElementsCapableOpClassProfile_t capOpClassData,
        json_t *jObject);

/**
 * @brief Callback to be invoked to populate BSS data
 *        elements object
 *
 * @param [in] bssData  structure containing the BSS parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateBssListJsonObject(dataElementsBSS_t bssData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate STA List
 *        elements object
 *
 * @param [in] staData  structure containing the STA parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateStaListObject(dataElementsSTAList_t *staData, json_t *staObject);

/**
 * @brief Callback to be invoked to populate backhaul STA
 *        elements object
 *
 * @param [in] bkhaulStaData  structure containing the backhaul STA parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateBackHaulSTAJsonObject(dataElementsBackHaulSTA_t *bkhaulStaData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate UnAssoc STA data
 *        elements object
 *
 * @param [in] unAssocStaData  structure containing the UnAssoc STA parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateUnAssocSTAObject(dataElementsUnassociatedSTA_t *unAssocStaData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate Scan Result data
 *        elements object
 *
 * @param [in] scanData  structure containing the Scan list parameters
 * @param [in/out] jObject  json object used to build elements
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateScanResultJsonObject(dataElementsScanResult_t scanData, json_t *jObject);

/**
 * @brief Callback to be invoked to populate STA Disassociation data
 *        elements object
 *
 * @param [in] disAssocData  structure containing the disAssoc parameters
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateDisAssocObject(dataElementsDisassociationEventData_t *disAssocData);

/**
 * @brief Callback to be invoked to populate STA Assoc data
 *        elements object
 *
 * @param [in] assocData  structure containing the association parameters
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dECreateAssocObject(dataElementsAssociationEventData_t *assocData);

/*************************************************************************
 * APIs for creating JSON
 *************************************************************************/
/**
 * @brief Function to get JSON key Value
 *
 * @param [in] jObject  Json Object
 * @param [in] name  The Key name
 * @param [out] retVal  json object to return the value
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dEGetJsonObjectValueforKey(json_t *jObject, const char *name, json_t **retVal);

/**
 * @brief Function to get Integer value from JSON Object
 *
 * @return integer value of the Json Object
 */
int dEGetIntegerFromJson(json_t *jObject);

/**
 * @brief Function to get String value from JSON
 *
 * @return string value of the Json Object
 */
const char *dEGetStringFromJson(json_t *jObject);

/**
 * @brief Function to change object value for JSON
 *
 * @param [in] jObject  Json Object for which value needs to be updated
 * @param [in] name  The Key name
 * @param [in] newValue  new value to update in json_t object
 * @param [in] opType  the type of operation
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dEUpdateJsonKeyValue(json_t *jObject, const char *name, json_t *newValue,
                                dataElementModifyJsonValue_e opType);

/**
 * @brief Dump the JSON object onto a file
 *
 * @param [in] fileName  fileName to dump the Json Object into
 * @param [in] root  json object
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
void dEDumpJsonObject(const char *fileName, json_t *root);

#if defined(__cplusplus)
}
#endif

#endif /* deServiceMsg_h */
