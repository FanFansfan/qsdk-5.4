/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <string.h>
#include "dataElements.h"
#include "dataElementsJson.h"

#define MAC_STR_SIZE 18
#define ISO_STR_SIZE sizeof "2011-10-08T07:07:09.000000-08:000000000"

#define CONVERT_TO_MILLI 1000
//////////////////////////////////////////////////////////////////////////////////////////////////
/// JSON Function Handlers
//////////////////////////////////////////////////////////////////////////////////////////////////
/// Dump JSON Object
void dEDumpJsonObject(const char *fileName, json_t *root) {
    if (json_dump_file(root, fileName, JSON_INDENT(4)) != 0) {
        perror("Error: ");
        dataElementDebug(DBGERR, "%s: writing to file failed \n",__func__);
    } else {
        sendNBRequest();
        dataElementDebug(DBGINFO, "%s: json write successful \n",__func__);
    }
}

/// Set new UNSIGNED INT Value for Object
void dESetObjectKeyUIntValue(json_t *root, const char *key, u_int32_t value) {
    json_object_set_new(root, key, json_integer(value));
}

/// Set new INT Value for Object
void dESetObjectKeyIntValue(json_t *root, const char *key, int value) {
    json_object_set_new(root, key, json_integer(value));
}

/// Set new STRING Value for Object
static void dESetObjectKeyStringValue(json_t *root, const char *key, const char *value) {
    json_object_set_new(root, key, json_string(value));
}

/// Get Integer from JSON
int dEGetIntegerFromJson(json_t *jObj) {
    int ret = 0;

    if (jObj != NULL && json_is_integer(jObj)) {
        ret = json_integer_value(jObj);
    } else if (jObj != NULL && json_is_real(jObj))
        ret = (int)json_real_value(jObj);

    return ret;
}

/// Get String from JSON
const char *dEGetStringFromJson(json_t *jObj) {

    if (jObj != NULL && json_is_string(jObj)) {
        return json_string_value(jObj);
    } else
        dataElementDebug(DBGERR, "%s: Could not get parameter\n",__func__);

    return NULL;
}

/// Get the Object Value for JSON
DE_STATUS dEGetJsonObjectValueforKey(json_t *jRoot, const char *keyName, json_t **retVal) {
    const char *key;
    json_t *value;
    void *iter = json_object_iter(jRoot);

    while (iter) {
        key = json_object_iter_key(iter);
        value = json_object_iter_value(iter);

        if (strcmp(key, keyName) == 0) {
            *retVal = value;
            return DE_OK;
        } else if (json_is_array(value)) {
            int arrSize = json_array_size(value), i;
            for (i = 0; i < arrSize; i++) {
                json_t *arrayData = json_array_get(value, i);
                dEGetJsonObjectValueforKey(arrayData, keyName, retVal);
            }

        } else if (json_is_object(value)) {
            dEGetJsonObjectValueforKey(value, keyName, retVal);
        }

        /* use key and value ... */
        iter = json_object_iter_next(jRoot, iter);
    }

    return DE_NOK;
}

/// Update value of JSON Object
DE_STATUS dEUpdateJsonKeyValue(json_t *jObject, const char *name, json_t *newValue,
                                dataElementModifyJsonValue_e opType) {

    json_t *jsonValue;
    if (dEGetJsonObjectValueforKey(jObject, name, &jsonValue) == DE_OK) {
        switch (opType) {
            case dataElementObjectValue_replace:
                if (json_is_string(jsonValue)) {
                    json_string_set(jsonValue, json_string_value(newValue));
                } else if (json_is_integer(jsonValue)) {
                    json_integer_set(jsonValue, json_integer_value(newValue));
                }
                return DE_OK;
            case dataElementObjectValue_add:
                json_integer_set(jsonValue,
                                 json_integer_value(jsonValue) + json_integer_value(newValue));
                return DE_OK;
            case dataElementObjectValue_subtract:
                json_integer_set(jsonValue,
                                 json_integer_value(jsonValue) - json_integer_value(newValue));
                return DE_OK;
            default:
                dataElementDebug(DBGERR, " %s: Invalid Operation %d", __func__, opType);
                break;
        }
    }
    return DE_NOK;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
/// Conversions
//////////////////////////////////////////////////////////////////////////////////////////////////
/// b64 Conversion
static void dataElemenetb64Convert(unsigned char *dEEncodeBuf, unsigned char *dETempBuf) {
    dEEncodeBuf[0] = (dETempBuf[0] & 0xfc) >> 2;
    dEEncodeBuf[1] = ((dETempBuf[0] & 0x03) << 4) + ((dETempBuf[1] & 0xf0) >> 4);
    dEEncodeBuf[2] = ((dETempBuf[1] & 0x0f) << 2) + ((dETempBuf[2] & 0xc0) >> 6);
    dEEncodeBuf[3] = dETempBuf[2] & 0x3f;
}

char *dataElementb64Encode(const unsigned char *src, size_t len) {
    int i = 0, j = 0;
    size_t size = 0;
    unsigned char dEEncodeBuf[4], dETempBuf[3];
    char *dEb64Data = NULL;

    dEb64Data = (char *)malloc(1);
    if (NULL == dEb64Data) {
        return NULL;
    }

    while (len--) {
        /// read up to 3 bytes at a time into `dETempBuf'
        dETempBuf[i++] = *(src++);

        /// if 3 bytes read then do conversion
        if (3 == i) {
            dataElemenetb64Convert(dEEncodeBuf, dETempBuf);

            /// allocate 4 new byts and use table for conversion
            dEb64Data = (char *)realloc(dEb64Data, size + 4);
            if (!dEb64Data){
                dataElementDebug(DBGERR, "%s:%d Memmory allocation failed",
                        __func__,__LINE__);
                return NULL;
            }
            for (i = 0; i < 4; ++i) {
                dEb64Data[size++] = dEBase64ConversionTable[dEEncodeBuf[i]];
            }
            i = 0;
        }
    }

    /// Check remainder
    if (i > 0) {
        /// fill `dETempBuf' with `\0' at most 3 times
        for (j = i; j < 3; ++j) {
            dETempBuf[j] = '\0';
        }
        dataElemenetb64Convert(dEEncodeBuf, dETempBuf);

        /// perform same write to `dEb64Data` with new allocation
        for (j = 0; (j < i + 1); ++j) {
            dEb64Data = (char *)realloc(dEb64Data, size + 1);
            if (!dEb64Data){
                dataElementDebug(DBGERR, "%s:%d Memmory allocation failed",
                        __func__,__LINE__);
                return NULL;
            }
            dEb64Data[size++] = dEBase64ConversionTable[dEEncodeBuf[j]];
        }

        /// while there is still a remainder append `=' to `dEb64Data'
        while ((i++ < 3)) {
            dEb64Data = (char *)realloc(dEb64Data, size + 1);
            if (!dEb64Data){
                dataElementDebug(DBGERR, "%s:%d Memmory allocation failed",
                        __func__,__LINE__);
                return NULL;
            }
            dEb64Data[size++] = '=';
        }
    }

    dEb64Data = (char *)realloc(dEb64Data, size + 1);
    if (!dEb64Data){
        dataElementDebug(DBGERR, "%s:%d Memmory allocation failed",
                __func__,__LINE__);
        return NULL;
    }
    dEb64Data[size] = '\0';

    return dEb64Data;
}

/// Convert MAC Address to String
static void dataElementMacToString(const struct ether_addr *mac, char *macStr) {
    if (mac != NULL) {
        snprintf(macStr, MAC_STR_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned char)mac->ether_addr_octet[0], (unsigned char)mac->ether_addr_octet[1],
                 (unsigned char)mac->ether_addr_octet[2], (unsigned char)mac->ether_addr_octet[3],
                 (unsigned char)mac->ether_addr_octet[4], (unsigned char)mac->ether_addr_octet[5]);
    }
    macStr[17]='\0';
}


/// Get timestamp in ISO format
// =================================================================================================
DE_STATUS dEGetTimeStamp(char *timeISO) {
    struct timeval tmnow;
    struct tm *tm;
    char usecBuf[14];

    gettimeofday(&tmnow, NULL);
    tm = localtime(&tmnow.tv_sec);
    if (tm == NULL) {
        return DE_NOK;
    }
    strftime(timeISO, 30, "%Y-%m-%dT%H:%M:%S", tm);
    strlcat(timeISO, ".", ISO_STR_SIZE);
    snprintf(usecBuf, sizeof(usecBuf), "%d-08:00", (int)tmnow.tv_usec);
    strlcat(timeISO, usecBuf, ISO_STR_SIZE);

    return DE_OK;
}

/// Get timestamp in ISO format for JSON Objects
// =================================================================================================
DE_STATUS dESetIsoTimeStamp(json_t *timeObject) {
    char timeISO[ISO_STR_SIZE];
    if (dEGetTimeStamp(timeISO) == DE_OK) {
        dESetObjectKeyStringValue(timeObject, DE_COMMON_TIMESTAMP, timeISO);
    }
    return DE_OK;
}

/// Get timestamp in ISO format for Event Objects
// =================================================================================================
DE_STATUS dESetIsoTimeStampEvent(json_t *timeObject) {
    char timeISO[ISO_STR_SIZE];
    if (dEGetTimeStamp(timeISO) == DE_OK) {
        dESetObjectKeyStringValue(timeObject, DE_COMMON_EVENT_TIMESTAMP, timeISO);
    }
    return DE_OK;
}

/// HT to String Conversion
static void dataElementHtCapToString(ieee1905APHtCapabilities_t apHtCap, json_t *capabilities) {
    u_int8_t htCap = ((apHtCap.maxTxNSS - 1) & 0x3) << 6 | ((apHtCap.maxRxNSS - 1) & 0x03) << 4 |
        apHtCap.shortGiSupport20Mhz << 3 | apHtCap.shortGiSupport40Mhz << 2 |
        apHtCap.htSupport40Mhz << 1;
    char *htCapHex = NULL;
    if (dataElementState.config.enableb64Enc) {
        htCapHex = dataElementb64Encode(&htCap, 1);
        if(!htCapHex) {
            dataElementDebug(DBGERR,"%s: base64 returned NULL",__func__);
            return;
        }
    } else {
        htCapHex = (char *)malloc(5);
        if(!htCapHex) {
            dataElementDebug(DBGERR,"%s: Memory allocation failed",__func__);
            return;
        } else {
            snprintf(htCapHex, 5, "0x%x", htCap);
        }
    }
    dataElementDebug(DBGDEBUG,"%s: htcap is %s \n",__func__,htCapHex);
    dESetObjectKeyStringValue(capabilities, DE_CAPABILITIES_HT, htCapHex);
    free(htCapHex);
}

/// VHT to String Conversion
static void dataElementVhtCapToString(ieee1905APVhtCapabilities_t apVhtCap, json_t *capabilities) {
    u_int8_t vhtCap[6];
    vhtCap[0] = (apVhtCap.supportedTxMCS >> 8);
    vhtCap[1] = (apVhtCap.supportedTxMCS & 0xff);
    vhtCap[2] = apVhtCap.supportedRxMCS >> 8;
    vhtCap[3] = apVhtCap.supportedRxMCS & 0xff;
    vhtCap[4] = ((apVhtCap.maxTxNSS - 1) & 0x07) << 5 | ((apVhtCap.maxRxNSS - 1) & 0x07) << 2 |
        apVhtCap.shortGiSupport80Mhz << 1 | apVhtCap.shortGiSupport160Mhz80p80Mhz;
    vhtCap[5] = apVhtCap.support80p80Mhz << 7 | apVhtCap.support160Mhz << 6 |
        apVhtCap.suBeamformerCapable << 5 | apVhtCap.muBeamformerCapable << 4;
    char *vhtCapHex = NULL;
    if (dataElementState.config.enableb64Enc) {
        vhtCapHex = dataElementb64Encode(vhtCap, 6);
        if (!vhtCapHex) {
            dataElementDebug(DBGERR,"%s: base64 returned NULL",__func__);
            return;
        }
    } else {
        vhtCapHex = (char *)malloc(15);
        if (!vhtCapHex) {
            dataElementDebug(DBGERR,"%s: Memory Allocation failed",__func__);
            return;
        } else {
            snprintf(vhtCapHex, 15, "0x%x%x%x%x%x%x", vhtCap[0], vhtCap[1], vhtCap[2], vhtCap[3],
                    vhtCap[4], vhtCap[5]);
        }
    }
    dataElementDebug(DBGDEBUG,"%s: vhtCapHex %s \n",__func__, vhtCapHex);
    dESetObjectKeyStringValue(capabilities, DE_CAPABILITIES_VHT, vhtCapHex);
    free(vhtCapHex);
}


/// HE to String Conversion
static void dataElementHeCapToString(ieee1905APHeCapabilities_t apHeCap, json_t *capabilities) {
    u_int8_t heCap[14];
    int i;

    if (apHeCap.numMCSEntries > IEEE1905_MAX_HE_MCS) {
        dataElementDebug(DBGERR,"MAPUNEXPECTED:%s apHeCap.numMCSEntries:%d \n",__func__, apHeCap.numMCSEntries);
        return;
    }
    for(i=0; i < apHeCap.numMCSEntries; i++) {
        heCap[2*i] = (apHeCap.supportedHeMCS[i] >> 8);
        heCap[2*i+1] = (apHeCap.supportedHeMCS[i] & 0xff);
    }
    heCap[12] = (apHeCap.maxTxNSS & 0x07) << 5 | (apHeCap.maxRxNSS & 0x07) << 2 |
                (apHeCap.support80p80Mhz & 0x01) << 1 | (apHeCap.support160Mhz & 0x01);
    heCap[13] = (apHeCap.suBeamformerCapable & 0x01) << 7 | (apHeCap.muBeamformerCapable & 0x01) << 6|
                (apHeCap.ulMuMimoCapable & 0x01) << 5 | (apHeCap.ulMuMimoOfdmaCapable & 0x01) << 4 |
                (apHeCap.dlMuMimoOfdmaCapable & 0x01) << 3 | (apHeCap.dlMuMimoOfdmaCapable & 0x01) << 2 |
                (apHeCap.dlOfdmaCapable & 0x01) << 1;
    char *heCapHex = NULL;
    if (dataElementState.config.enableb64Enc) {
        heCapHex = dataElementb64Encode(heCap, sizeof(heCap));
        if (!heCapHex) {
            dataElementDebug(DBGERR,"%s: base64 returned NULL",__func__);
            return;
        }
    } else {
        heCapHex = (char *)malloc(40);
        if (!heCapHex) {
            dataElementDebug(DBGERR,"%s: Memory Allocation failed",__func__);
            return;
        } else {
            char strByte[10] = {0};
            int ret;
            snprintf(heCapHex, 4, "0x");
            for(i=0; i <  sizeof(heCap); i++) {
                ret = snprintf(strByte, 4, "%x", heCap[i]);
                strlcat(heCapHex, strByte, ret);
            }
        }
    }

    dataElementDebug(DBGDEBUG,"%s: heCapHex %s \n",__func__, heCapHex);
    dESetObjectKeyStringValue(capabilities, DE_CAPABILITIES_HE, heCapHex);
    free(heCapHex);
}


/// Fill Capabilities Object
DE_STATUS dEFillCapabilitiesMsgObject(json_t *capabilities,
        dataElementsStaApCapabilities_t capData) {
    if (capData.isHTValid) {
        dataElementHtCapToString(capData.apHtCap, capabilities);
    }

    if (capData.isVHTValid) {
        dataElementVhtCapToString(capData.apVhtCap, capabilities);
    }

    if (capData.isHEValid) {
        dataElementHeCapToString(capData.apHeCap, capabilities);
    }

    if (!capabilities) {
        dataElementDebug(DBGERR, "%s: Error Could not Create capabilities list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}



/// Create STA Traffic STATs
// =================================================================================================
DE_STATUS dECreateStaTrafficStatsObject(ieee1905StaTrafficStats_t stats,
                                            json_t *staObject) {
    dESetObjectKeyUIntValue(staObject, DE_STA_BYTES_SENT, stats.txBytes);
    dESetObjectKeyUIntValue(staObject, DE_STA_BYTES_RECEIVED, stats.rxBytes);
    dESetObjectKeyUIntValue(staObject, DE_STA_PACKETS_SENT, stats.pktsSent);
    dESetObjectKeyUIntValue(staObject, DE_STA_PACKETS_RECEIVED, stats.pktsRcvd);
    dESetObjectKeyUIntValue(staObject, DE_STA_ERRORS_SENT, stats.txPktErr);
    dESetObjectKeyUIntValue(staObject, DE_STA_ERRORS_RECEIVED, stats.rxPktErr);
    dESetObjectKeyUIntValue(staObject, DE_STA_RETRANS_COUNT, stats.cntRetx);
    if (!staObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create STA Traffic Stats ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Assoc Event Data
// =================================================================================================
DE_STATUS dECreateAssocObject(dataElementsAssociationEventData_t *assocData) {
    json_t *jRootAssoc = json_object();

    /// Clear Object before Building
    json_object_clear(jRootAssoc);

    /// Add JSON Notification Object
    json_t *notifyObject = json_object();
    json_object_set_new(jRootAssoc, "notification", notifyObject);
    dESetIsoTimeStampEvent(notifyObject);

    /// Add JSON Event Object
    json_t *eventObject = json_object();
    json_object_set_new(notifyObject, "wfa-dataelements:AssociationEvent", eventObject);

    /// Add JSON Assoc Object
    json_t *assocObject = json_object();
    json_object_set_new(eventObject, "AssocData", assocObject);

    char bssidStr[MAC_STR_SIZE];
    char staStr[MAC_STR_SIZE];
    dataElementMacToString(&assocData->BSSID, bssidStr);
    dataElementMacToString(&assocData->macAddress, staStr);
    dESetObjectKeyStringValue(assocObject, DE_STA_BSSID, bssidStr);
    dESetObjectKeyStringValue(assocObject, DE_STA_MAC_ADDR, staStr);
    dESetObjectKeyIntValue(assocObject, DE_STA_STATUS_CODE, 0);
    dEFillCapabilitiesMsgObject(assocObject, assocData->caps);
    //dECreateCapsListJsonObject(&assocData->caps, assocObject);

    if (!assocObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create STA Assoc Data ",__func__);
        return DE_NOK;
    }

    dEDumpJsonObject("/www/dataAssoc", jRootAssoc);
    json_decref(jRootAssoc);

    return DE_OK;
}

/// Create DisAssoc Event Data
// =================================================================================================
DE_STATUS dECreateDisAssocObject(dataElementsDisassociationEventData_t *disAssocData) {
    json_t *jRootDisAssoc = json_object();

    /// Clear Object before Building
    json_object_clear(jRootDisAssoc);

    /// Add JSON Notification Object
    json_t *notifyObject = json_object();
    json_object_set_new(jRootDisAssoc, "notification", notifyObject);
    dESetIsoTimeStampEvent(notifyObject);

    /// Add JSON Event Object
    json_t *eventObject = json_object();
    json_object_set_new(notifyObject, "wfa-dataelements:DisassociationEvent", eventObject);

    /// Add DisAssoc Object
    json_t *disAssocObject = json_object();
    json_object_set_new(eventObject, "DisassocData", disAssocObject);

    char bssidStr[MAC_STR_SIZE];
    char staStr[MAC_STR_SIZE];
    dataElementMacToString(&disAssocData->BSSID, bssidStr);
    dataElementMacToString(&disAssocData->macAddress, staStr);
    dESetObjectKeyStringValue(disAssocObject, DE_STA_BSSID, bssidStr);
    dESetObjectKeyStringValue(disAssocObject, DE_STA_MAC_ADDR, staStr);
    dESetObjectKeyIntValue(disAssocObject, DE_STA_REASON_CODE, disAssocData->reasonCode);
    dECreateStaTrafficStatsObject(disAssocData->stats, disAssocObject);

    if (!disAssocObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create DisAssoc Object ",__func__);
        return DE_NOK;
    }

    dEDumpJsonObject("/www/dataAssoc", jRootDisAssoc);
    json_decref(jRootDisAssoc);

    return DE_OK;
}


/// Create Estimated Service Parameters Object
// =================================================================================================
static void dECreateEstServiceParameters(json_t *bssListObject, ieee1905APMetricData_t apMetrics) {
    u_int8_t k = 0;

    for (k = 0; k < mapServiceAC_Max; k++) {
        u_int8_t espByteOne = 0;
        u_int8_t esp[3] = {0};
        if (apMetrics.espInfo[k].includeESPInfo) {
            espByteOne = apMetrics.espInfo[k].ac;
            // bit 2 is reserved
            espByteOne = espByteOne | apMetrics.espInfo[k].dataFormat << 3;
            espByteOne = espByteOne | apMetrics.espInfo[k].baWindowSize << 5;
            esp[0] = espByteOne;
            esp[1] = apMetrics.espInfo[k].estAirTimeFraction;
            esp[2] = apMetrics.espInfo[k].dataPPDUDurTarget;
        }

        char *estParHex = NULL;
        if (dataElementState.config.enableb64Enc) {
            estParHex = dataElementb64Encode(esp, 3);
            if (!estParHex) {
                dataElementDebug(DBGERR,"%s: base64 returned NULL",__func__);
                return;
            }
        } else {
            estParHex = (char *)malloc(9);
            if (!estParHex) {
                dataElementDebug(DBGERR,"%s: Memory Allocation failed",__func__);
                return;
            } else {
                snprintf(estParHex, 9, "0x%x%x%x", esp[0], esp[1], esp[2]);
            }
        }

        switch (k) {
            case mapServiceAC_BE:
                dESetObjectKeyStringValue(bssListObject, DE_CAPABILITIES_ESP_BE, estParHex);
                break;
            case mapServiceAC_BK:
                dESetObjectKeyStringValue(bssListObject, DE_CAPABILITIES_ESP_BK, estParHex);
                break;
            case mapServiceAC_VI:
                dESetObjectKeyStringValue(bssListObject, DE_CAPABILITIES_ESP_VI, estParHex);
                break;
            case mapServiceAC_VO:
                dESetObjectKeyStringValue(bssListObject, DE_CAPABILITIES_ESP_VO, estParHex);
                break;
            default:
                dataElementDebug(DBGERR, "%s: Invalid EstServiceParameters ",__func__);
        }
        free(estParHex);
    }
}

/// Create NeighbourList Object
// =================================================================================================
DE_STATUS deCreateNeighListObject(dataElementsNeighbourBSS_t neighData,
                                      json_t *neighbourObject) {

    char bssidStr[MAC_STR_SIZE];
    struct ether_addr bssid = {0};
    deCopyMACAddr(neighData.BSSID.ether_addr_octet, bssid.ether_addr_octet);
    dataElementMacToString(&bssid, bssidStr);
    dESetObjectKeyStringValue(neighbourObject, DE_NEIGHBOUR_BSSID, bssidStr);
    dESetObjectKeyStringValue(neighbourObject, DE_NEIGHBOUR_SSID, (const char *)neighData.ssid);
    dESetObjectKeyIntValue(neighbourObject, DE_NEIGHBOUR_SIGNAL_STRENGTH, neighData.signalStrength);
    dESetObjectKeyIntValue(neighbourObject, DE_NEIGHBOUR_CHANNEL_BW, neighData.channelBandwidth);
    dESetObjectKeyIntValue(neighbourObject, DE_NEIGHBOUR_CHANNEL_UTIL,
                           neighData.channelUtilization);
    dESetObjectKeyIntValue(neighbourObject, DE_NEIGHBOUR_STATION_COUNT, neighData.stationCount);

    if (!neighbourObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create Neighbor Object list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Scan Result Object
// =================================================================================================
DE_STATUS dECreateScanResultJsonObject(dataElementsScanResult_t scanData,
                                       json_t *scanResultObject) {

    dESetIsoTimeStamp(scanResultObject);
    dESetObjectKeyIntValue(scanResultObject, DE_NEIGHBOUR_NUM_OP_CLASS_SCAN,
                           scanData.numberOfOpClassScans);

    /// Create Op Class Scan Array
    json_t *opClassScanArray = json_array();
    json_object_set_new(scanResultObject, "OpClassScanList", opClassScanArray);

    u_int8_t numOpClass;
    for (numOpClass = 0; numOpClass < scanData.numberOfOpClassScans; numOpClass++) {
        json_t *opClassScanObject = json_object();
        dESetObjectKeyIntValue(opClassScanObject, DE_NEIGHBOUR_OP_CLASS,
                               scanData.opClassScanList[numOpClass].operatingClass);
        dESetObjectKeyIntValue(opClassScanObject, DE_NEIGHBOUR_NUM_CHAN_SCAN,
                               scanData.opClassScanList[numOpClass].numberOfChannelScans);
        json_array_append_new(opClassScanArray, opClassScanObject);

        /// Create Channel Scan Array
        json_t *channelListArray = json_array();
        json_object_set_new(opClassScanObject, "ChannelScanList", channelListArray);

        u_int8_t chanIdx;
        u_int8_t neighIndex=0;
        for (chanIdx = 0; chanIdx < scanData.opClassScanList[numOpClass].numberOfChannelScans;
             chanIdx++) {
            /// Create Channel Scan Object
            json_t *channelScanObject = json_object();
            json_array_append_new(channelListArray, channelScanObject);

            dESetIsoTimeStamp(channelScanObject);
            dESetObjectKeyIntValue(
                channelScanObject, DE_NEIGHBOUR_CHANNEL,
                scanData.opClassScanList[numOpClass].ScanChanList[chanIdx].channel);
            dESetObjectKeyIntValue(
                channelScanObject, DE_NEIGHBOUR_UTILIZATION,
                scanData.opClassScanList[numOpClass].ScanChanList[chanIdx].utilization);
            dESetObjectKeyIntValue(
                channelScanObject, DE_NEIGHBOUR_NOISE,
                scanData.opClassScanList[numOpClass].ScanChanList[chanIdx].noise);
            dESetObjectKeyIntValue(
                channelScanObject, DE_NEIGHBOUR_NUM_NEIGHBOURS,
                scanData.opClassScanList[numOpClass].ScanChanList[chanIdx].numberOfNeighbours);

            /// Create NeighbourList Array
            json_t *neighbourListArray = json_array();
            json_object_set_new(channelScanObject, "NeighborList", neighbourListArray);

            u_int8_t neighIdx;
            for (neighIdx=neighIndex; neighIdx < (scanData.opClassScanList[numOpClass].ScanChanList[chanIdx].numberOfNeighbours + neighIndex);
                 neighIdx++) {
                /// Create Neighbor Object
                json_t *neighbourObject = json_object();
                json_array_append_new(neighbourListArray, neighbourObject);
                deCreateNeighListObject(scanData.opClassScanList[numOpClass].neighData[neighIdx], neighbourObject);
            }
            neighIndex=neighIdx;
        }
    }

    if (!scanResultObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create Scan Result Object list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create BackHaul STA Object
// =================================================================================================
DE_STATUS dECreateBackHaulSTAJsonObject(dataElementsBackHaulSTA_t *bkhaulStaData,
        json_t *backHaulSTAObject) {
    char bstaStr[MAC_STR_SIZE];
    dataElementMacToString(&bkhaulStaData->macAddress, bstaStr);
    dESetObjectKeyStringValue(backHaulSTAObject, DE_BACKHAUL_STA_MAC_ADDR, bstaStr);
    if (!backHaulSTAObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create STA Object ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create UnAssoc STA Object
// =================================================================================================
DE_STATUS dECreateUnAssocSTAObject(dataElementsUnassociatedSTA_t *unAssocStaData,
                                       json_t *unAssocSTAObject) {
    char staStr[MAC_STR_SIZE];
    dataElementMacToString(&unAssocStaData->macAddress, staStr);

    dESetObjectKeyStringValue(unAssocSTAObject, DE_UNASSOC_STA_MAC_ADDR, staStr);

    dESetObjectKeyIntValue(unAssocSTAObject, DE_STA_SIGNAL_STRENGTH, unAssocStaData->signalStrength);
    if (!unAssocSTAObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create UnAssociated STA Object list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create STA List Data
// =================================================================================================
DE_STATUS dECreateStaListObject(dataElementsSTAList_t *staData, json_t *staObject) {
    char staStr[MAC_STR_SIZE];
    dataElementMacToString(&staData->macAddress, staStr);
    dESetObjectKeyStringValue(staObject, DE_STA_MAC_ADDR, staStr);
    dESetIsoTimeStamp(staObject);
    dEFillCapabilitiesMsgObject(staObject, staData->caps);
    dESetObjectKeyIntValue(staObject, DE_STA_SIGNAL_STRENGTH, staData->signalStrength);
    dESetObjectKeyIntValue(staObject, DE_STA_LAST_DATA_DOWNLINK_RATE, staData->lastDataDownlinkRate);
    dESetObjectKeyIntValue(staObject, DE_STA_LAST_DATA_UPLINK_RATE, staData->lastDataUplinkRate);
    dESetObjectKeyIntValue(staObject, DE_STA_EST_MAC_DATA_DOWNLINK_RATE,
                           staData->estMACDataRateDownlink);
    dESetObjectKeyIntValue(staObject, DE_STA_EST_MAC_DATA_UPLINK_RATE,
                           staData->estMACDataRateUplink);
    if(dataElementState.isMultiAP) {
        dESetObjectKeyUIntValue(staObject, DE_STA_UTIL_RX, staData->utilizationReceive * CONVERT_TO_MILLI);
        dESetObjectKeyUIntValue(staObject, DE_STA_UTIL_TX, staData->utilizationTransmit * CONVERT_TO_MILLI);
    }
    else {
        dESetObjectKeyUIntValue(staObject, DE_STA_UTIL_RX, staData->utilizationReceive);
        dESetObjectKeyUIntValue(staObject, DE_STA_UTIL_TX, staData->utilizationTransmit);
    }
    dESetObjectKeyIntValue(staObject, DE_STA_LAST_CONNECT_TIME, staData->lastConnectTime);
    if (!dataElementState.isMultiAP) {
        dESetObjectKeyIntValue(staObject, DE_STA_NUM_MEASUREMENT_REPORTS,
                               staData->numberOfMeasureReports);
        //dESetObjectKeyStringValue(staObject, DE_STA_IPV4_ADDRESS, staData->ipV4Address);
        //dESetObjectKeyStringValue(staObject, DE_STA_IPV6_ADDRESS, staData->ipV6Address);
        //dESetObjectKeyStringValue(staObject, DE_STA_HOSTNAME, staData->hostname);

        /// Add Measurement Report
        ///TO DO: Enable when measurement report is supported
        //json_t *measurementReportArray = json_array();
        //json_object_set_new(staObject, DE_STA_MEASUREMENT_REPORT, measurementReportArray);
        //json_array_append_new(measurementReportArray, json_integer(0));
    }

    dECreateStaTrafficStatsObject(staData->stats, staObject);

    if (!staObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create STA Object ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create BSS List Data
// =================================================================================================
DE_STATUS dECreateBssListJsonObject(dataElementsBSS_t bssData, json_t *bssList) {
    char bssidStr[MAC_STR_SIZE];
    dataElementMacToString(&bssData.BSSID, bssidStr);
    dESetObjectKeyStringValue(bssList, DE_BSS_BSSID, bssidStr);
    dESetObjectKeyStringValue(bssList, DE_BSS_SSID, (const char *)bssData.ssid);
    dESetObjectKeyStringValue(bssList, DE_BSS_ENABLED, "False");
    if (bssData.enabled) {
        dESetObjectKeyStringValue(bssList, DE_BSS_ENABLED, "True");
    }
    dESetObjectKeyIntValue(bssList, DE_BSS_LAST_CHANGE, bssData.lastChange);
    dESetIsoTimeStamp(bssList);
    dESetObjectKeyUIntValue(bssList, DE_BSS_UNICAST_BYTES_SENT, bssData.unicastBytesSent);
    dESetObjectKeyUIntValue(bssList, DE_BSS_UNICAST_BYTES_RECEIVED, bssData.unicastBytesReceived);
    dESetObjectKeyIntValue(bssList, DE_BSS_NUM_OF_STA, bssData.apMetrics.numAssocSTA);
    dECreateEstServiceParameters(bssList, bssData.apMetrics);
    if (!dataElementState.isMultiAP) {
        dESetObjectKeyUIntValue(bssList, DE_BSS_MULTICAST_BYTES_SENT, bssData.multicastBytesSent);
        dESetObjectKeyUIntValue(bssList, DE_BSS_MULTICAST_BYTES_RECEIVED,
                               bssData.multicastBytesReceived);
        dESetObjectKeyUIntValue(bssList, DE_BSS_BROADCAST_BYTES_SENT, bssData.broadcastBytesSent);
        dESetObjectKeyUIntValue(bssList, DE_BSS_BROADCASR_BYTES_RECEIVED,
                               bssData.broadcastBytesReceived);
        dESetObjectKeyIntValue(bssList, DE_BSS_NUM_OF_STA, bssData.NumberOfSTA);
    }

    if (!bssList) {
        dataElementDebug(DBGERR, "%s: Error Could not Create BSS list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Capable Operating Class Object
// =================================================================================================
DE_STATUS dECreateCapableOpClassesObject(dataElementsCapableOpClassProfile_t capOpClassData,
                                             json_t *capableOpClassObject) {
    dESetObjectKeyIntValue(capableOpClassObject, DE_CAPABILITIES_OP_CLASS, capOpClassData.opClass);
    dESetObjectKeyIntValue(capableOpClassObject, DE_CAPABILITIES_MAX_TX_POWER,
                           capOpClassData.maxTxPower);
    dESetObjectKeyIntValue(capableOpClassObject, DE_CAPABILITIES_NUM_NON_OP_CHAN,
                           capOpClassData.numberOfNonOperChan);

    // Add Non Operable Channel Array
    json_t *nonOperableArray = json_array();
    json_object_set_new(capableOpClassObject, DE_CAPABILITIES_NON_OPERABLE_CHAN, nonOperableArray);

    u_int8_t j;
    for (j = 0; j < capOpClassData.numberOfNonOperChan; j++) {
        json_array_append_new(nonOperableArray, json_integer(capOpClassData.nonOperable[j]));
    }

    if (!capableOpClassObject) {
        dataElementDebug(DBGERR, "%s: Error Could not Create capable Op Class list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Capabilities Object
// =================================================================================================
DE_STATUS dECreateCapabilitiesJsonObject(dataElementsCapabilities_t capData, json_t *capabilities) {
    dESetObjectKeyIntValue(capabilities, DE_CAPABILITIES_NUM_OP_CLASS, capData.numberOfOpClass);
    dEFillCapabilitiesMsgObject(capabilities, capData.caps);

    if (!capabilities) {
        dataElementDebug(DBGERR, "%s: Error Could not Create capabilities list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Current Op Class List
// =================================================================================================
DE_STATUS dECreateCurrentOpClassesObject(dataElementsCurrentOpClassProfile_t copData,
                                             json_t *cOpClass) {
    dESetIsoTimeStamp(cOpClass);
    dESetObjectKeyIntValue(cOpClass, DE_CUR_OP_CLASS, copData.opClass);
    dESetObjectKeyIntValue(cOpClass, DE_CUR_OP_TX_POWER, copData.txPower);
    dESetObjectKeyIntValue(cOpClass, DE_CUR_OP_CHANNEL, copData.channel);
    if (!cOpClass) {
        dataElementDebug(DBGERR, "%s: Error Could not Create OpClass list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create RadioList Object
// =================================================================================================
DE_STATUS dECreateRadioJsonObject(dataElementsRadio_t radioData, json_t *radio) {

    char radioStr[MAC_STR_SIZE];
    dataElementMacToString(&radioData.id, radioStr);
    dESetObjectKeyStringValue(radio, DE_RADIO_ID, radioStr);
    if (radioData.enabled) {
        dESetObjectKeyStringValue(radio, DE_RADIO_ENABLED, "True");
    } else {
        dESetObjectKeyStringValue(radio, DE_RADIO_ENABLED, "False");
    }
    dESetObjectKeyIntValue(radio, DE_RADIO_NOISE, radioData.noise);
    dESetObjectKeyIntValue(radio, DE_RADIO_NUM_CUR_OP_CLASS, radioData.numberOfCurrOpClass);
    if(dataElementState.isMultiAP) {
        dESetObjectKeyIntValue(radio, DE_RADIO_NUM_OF_UNASSOC_STA, radioData.numberOfUnassocSta);
    }
    dESetObjectKeyIntValue(radio, DE_RADIO_NUM_OF_BSS, radioData.numberOfBSS);
    dESetObjectKeyIntValue(radio, DE_RADIO_UTILIZATION, radioData.utilization);
    if (!dataElementState.isMultiAP) {
        dESetObjectKeyIntValue(radio, DE_RADIO_TRANSMIT, radioData.transmit);
        dESetObjectKeyIntValue(radio, DE_RADIO_RECEIVE_SELF, radioData.receiveSelf);
        dESetObjectKeyIntValue(radio, DE_RADIO_RECEIVE_OTHER, radioData.receiveOther);
    }

    if (!radio) {
        dataElementDebug(DBGERR, "%s: Error Could not Create radio list %p \n", __func__, radio);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Device Object
// =================================================================================================
DE_STATUS dECreateDeviceJsonObject(dataElementsDevice_t deviceData, json_t *device) {
    char devMac[MAC_STR_SIZE];
    dataElementMacToString(&deviceData.id, devMac);

    dESetObjectKeyStringValue(device, DE_DEVICE_ID, devMac);
    dESetObjectKeyIntValue(device, DE_DEVICE_NUM_OF_RADIOS, deviceData.numberOfRadios);
    dESetObjectKeyIntValue(device, DE_DEVICE_COLLECTION_INTERVAL,
            (dataElementState.config.reportingIntervalSecs *CONVERT_TO_MILLI));
    if (dataElementState.isMultiAP) {
        char *mapHex = NULL;
        if (dataElementState.config.enableb64Enc) {
            mapHex = dataElementb64Encode(&deviceData.multiAPCapabilities, 1);
            if (!mapHex) {
                dataElementDebug(DBGERR,"%s: base64 returned NULL",__func__);
                return DE_NOK;
            }
        } else {
            mapHex = (char *)malloc(5);
            if (!mapHex) {
                dataElementDebug(DBGERR,"%s: Memory allocation failed",__func__);
                return DE_NOK;
            } else {
                snprintf(mapHex, 5, "0x%x", deviceData.multiAPCapabilities);
            }
        }
        dESetObjectKeyStringValue(device, DE_DEVICE_MULTI_AP_CAP, mapHex);
        free(mapHex);
    }

    if (!device) {
        dataElementDebug(DBGERR, "%s: Error Could not Create device list ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Network Object
// =================================================================================================
DE_STATUS dECreateNetworkJsonObject(dataElementsNetwork_t networkData, json_t *network) {
    char devMac[MAC_STR_SIZE];
    dataElementMacToString(&networkData.ctrlId, devMac);
    dESetObjectKeyStringValue(network, DE_NETWORK_ID, "NETWORK-ID");
    dESetObjectKeyIntValue(network, DE_NETWORK_NUM_OF_DEVICES, networkData.numberOfDevices);
    dESetIsoTimeStamp(network);
    if (dataElementState.isMultiAP) {
        dESetObjectKeyStringValue(network, DE_NETWORK_CONTROLLER_ID, devMac);
    }

    if (!network) {
        dataElementDebug(DBGERR, "%s: Error Could not Create Network ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}

/// Create Configuration Object
// =================================================================================================
DE_STATUS dECreateConfigJsonObject(DE_BOOL isMultiAP, json_t *config) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];

    if (!tm) {
        dataElementDebug(DBGERR, "%s: Error Could not Create tm structure", __func__);
        return DE_NOK;
    }
    strftime(s, sizeof(s), "%c", tm);
    dESetObjectKeyStringValue(config, DE_CONFIG_VERSION, "1.0");
    dESetObjectKeyStringValue(config, DE_CONFIG_NAME, "wifi");
    dESetObjectKeyStringValue(config, DE_CONFIG_DESCRIPTION, "Wireless 802.11 plugin");
    dESetObjectKeyStringValue(config, DE_CONFIG_DATE, s);
    dESetIsoTimeStamp(config);
    if (!config) {
        dataElementDebug(DBGERR, "%s: Error Could not Create Object ",__func__);
        return DE_NOK;
    }
    return DE_OK;
}
