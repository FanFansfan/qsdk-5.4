/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "dataElements.h"
#include "dataElementsHyd.h"
#include "dataElementsJson.h"
#include "../meshevent/meshEvent.h"

/**
 * @brief Internal state for Data Elements Msg.
 */
typedef struct {
    /// Handle to use when logging
    //struct dbgModule *dbgModule;

    /// Init the Module
    DE_BOOL isInit;

    ///json handle
    json_t *jRoot;

    ///json handle
    json_t *network;

    ///json handle
    json_t *deviceArray;

    ///json handle
    json_t *radioArray;

    ///json handle
    json_t *radio;

    ///json handle
    json_t *capabilities;

    ///json handle
    json_t *capableOpClassArray;

    ///json handle
    json_t *bssListArray;

    ///json handle
    json_t *bssObject[IEEE1905_QCA_VENDOR_MAX_BSS];

    ///json handle
    json_t *staListArray[IEEE1905_QCA_VENDOR_MAX_BSS];

    ///json handle
    json_t *unAssocSTAListArray;

    ///json handle
    json_t *backhaulSTAListArray;

    ///json handle
    json_t *scanResultListArray;

    int numDevices;

    int curDevIndex;

    int numRadios;

    int curRadioIndex;

    int curBssSta;

    int curBssUnicastByteSent;

    int curBssUnicastByteReceived;

    int curStaCount;

    char *scanData;

    char *tmpScanData;
    /// Network Type
    DE_BOOL isMultiAP;
} dataElementHydState_t;

static dataElementHydState_t dataElementHydState;

dataElementsRadio_t radioData = {0};

#define     IFNAMSIZ    16

extern void dESetObjectKeyUIntValue(json_t *root, const char *key, u_int32_t value);
extern void dESetObjectKeyIntValue(json_t *root, const char *key, int value);

/**
 * @brief Dispatch socket messages to HYD
 *
 * @param [in] msgType TLV type to send
 * @param [in] count repurposed as needed by each tlv
 * @param [in] data payload
 * @param [in] dataLen length of payload
 *
 * @return
 */
DE_STATUS dataElementsMsgDispatch(int msgType, int count, char *data, int dataLen)
{
    int status = DE_NOK;
    ieee1905DispatchFrame_t *frame=NULL;
    int nBytes = dataLen+ IEEE1905_DISPATCH_FIXED_FIELDS_SIZE + 1;
    char *buf = malloc(nBytes*sizeof(char));
    if (!buf) {
        dataElementDebug(DBGERR, "%s: frame memory allocation failed \n",__func__);
        return DE_NOK;
    }

    char *tmpBuf = buf;

    memset(buf, 0, nBytes);

    *tmpBuf = SERVICE_TYPE_DE;
    tmpBuf++;
    frame = (ieee1905DispatchFrame_t *)tmpBuf;
    frame->tlvType = msgType;
    frame->msgType = count;

    if ((dataLen > 0) && data) {
        memcpy(frame->content, data, dataLen);
    }

    status = meshEventSend(buf, nBytes);

    free(buf);

    return status;

}

/// Send request to hyd for Scan List Data
// =================================================================================================
DE_STATUS dERequestHydScanListData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_SCAN_RESULT;

    if(dataElementState.config.enableRadioScanResultObject && (!dataElementState.isStatsOnly)) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dERequestHydRadioData(dataElementHydState.curRadioIndex);
    }

    return DE_OK;
}

/// Send request to hyd to Enable Events
// =================================================================================================
DE_STATUS dERequestEventsEnable() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_ENABLE_EVENT;

    status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
    return status;
}

/// Send request to hyd to Enable Northbound Event Data
// =================================================================================================
DE_STATUS dERequestNbEventsEnableData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_ENABLE_NBEVENT;

    status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
    return status;
}

/// Send request to hyd for BackHaul sta Data
// =================================================================================================
DE_STATUS dERequestHydBackHaulStaData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_BACKHAUL;

    if(dataElementState.config.enableRadioBkStaObject && dataElementState.config.isMAP) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dERequestHydScanListData();
    }

    return DE_OK;

}

/// Send request to hyd for UnAssoc STA Data
// =================================================================================================
DE_STATUS dERequestHydUnAssocStaData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_UNASSOC_STA;

    if(dataElementState.config.enableRadioUnAssocStaObject) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dERequestHydBackHaulStaData();
    }

    return DE_OK;
}

///Send request to hyd for BSS Sta Data
// =================================================================================================
DE_STATUS dERequestHydStaData(struct ether_addr *bssid) {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_STA;

    if(dataElementState.config.enableBssStaListObject) {
        status = dataElementsMsgDispatch(msgtype, 0, (char *)bssid, sizeof(struct ether_addr ));
        return status;
    } else {
        dERequestHydUnAssocStaData();
    }
    return DE_OK;
}

///Send request to hyd for BSS Data
// =================================================================================================
DE_STATUS dERequestHydBssData(u_int8_t radioIndex) {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_BSS;

    if(dataElementState.config.enableRadioBssListObject) {
        status = dataElementsMsgDispatch(msgtype, radioIndex, NULL, 0);
        return status;
    } else {
        dERequestHydUnAssocStaData();
    }

    return DE_OK;
}


/// Send request to hyd for Radio Capable Operating Class
// =================================================================================================
DE_STATUS dERequestHydRadioCapableOpClassData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_CAP_OP_CLASS_PROF;

    if(dataElementState.config.enableRadioCapsObject && dataElementState.config.isMAP) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dERequestHydBssData(dataElementHydState.curRadioIndex-1);
    }
    return DE_OK;
}

///Send request to hyd for Radio Capabilities Data
// =================================================================================================
DE_STATUS dEGetRadioCapsData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_CAPABILITIES;

    if(dataElementState.config.enableRadioCapsObject && dataElementState.config.isMAP) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dERequestHydBssData(dataElementHydState.curRadioIndex-1);
    }

    return DE_OK;
}

/// Send request to hyd for Current Op Class Data
// =================================================================================================
DE_STATUS dERequestHydCurOpClassData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_CUR_OP_CLASS;

    if (dataElementState.config.enableRadioCurOpClassObject) {
        status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);
        return status;
    } else {
        dEGetRadioCapsData();
    }

    return DE_OK;
}

/// Send request to hyd for Device Data
// =================================================================================================
DE_STATUS dERequestHydDeviceData(int deviceIndex) {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_DEVICE;

    if(dataElementHydState.isMultiAP) {
        if (dataElementHydState.curDevIndex <= dataElementHydState.numDevices) {
            status = dataElementsMsgDispatch(msgtype, deviceIndex, NULL, 0);
            dataElementHydState.curDevIndex++;
            return status;
        }
    } else {
        if (dataElementHydState.curDevIndex < dataElementHydState.numDevices) {
            status = dataElementsMsgDispatch(msgtype, deviceIndex, NULL, 0);
            dataElementHydState.curDevIndex++;
            return status;
        }
    }
    dEDumpJsonObject(dataElementState.config.jsonFileName, dataElementHydState.jRoot);
    json_decref(dataElementHydState.jRoot);
    dataElementState.isStatsOnly = 0;
    return DE_OK;
}

/// Send request to hyd for Network Data
// =================================================================================================
DE_STATUS dERequestHydNetworkData() {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_NETWORK;

    status = dataElementsMsgDispatch(msgtype, 0, NULL, 0);

    return status;
}

/// Send request to hyd for Radio Data
// =================================================================================================
DE_STATUS dERequestHydRadioData(int radioIndex) {
    DE_STATUS status = DE_NOK;
    int msgtype = DE_TLV_TYPE_GET_RADIO;

    if (dataElementState.config.enableRadioObject) {
        if (dataElementHydState.curRadioIndex < dataElementHydState.numRadios) {
            status = dataElementsMsgDispatch(msgtype, radioIndex, NULL, 0);
            dataElementHydState.curRadioIndex++;
            return status;
        } else {
            dERequestHydDeviceData(dataElementHydState.curDevIndex);
        }
    } else {
        dERequestHydDeviceData(dataElementHydState.curDevIndex);
    }
    return DE_OK;
}

/// Parse network data from payload and update it in Json
// =================================================================================================
DE_STATUS dENetworkParser(char *payload) {
    dataElementHydState.jRoot = json_object();
    json_object_clear(dataElementHydState.jRoot);

    /// Add JSON Config
    dECreateConfigJsonObject(dataElementState.isMultiAP, dataElementHydState.jRoot);

    /// Add JSON Data Array and Object
    json_t *dataArray = json_array();
    json_t *dataObject = json_object();
    json_object_set_new(dataElementHydState.jRoot, "data", dataArray);
    json_array_append_new(dataArray, dataObject);

    dataElementHydState.network = json_object();
    dataElementsNetwork_t networkData = {0};
    memcpy(&networkData, (dataElementsNetwork_t *)payload, sizeof(dataElementsNetwork_t));
    dataElementHydState.curDevIndex = 0;
    if (networkData.numberOfDevices == 0) {
        networkData.numberOfDevices = 1;
        dataElementHydState.isMultiAP = 0;
    } else {
        dataElementHydState.isMultiAP = 1;
        if (dataElementState.config.enableCertCompliance) {
            dataElementHydState.curDevIndex = 1;
        }
    }
    /* Revisit if interswitching of modes is required */
#if 0
    if(!dataElementHydState.isMultiAP) {
        dataElementDebug(DBGINFO, "%s: number of devices is %d, switching to singleAP mode \n",__func__,networkData.numberOfDevices);
        dataElementsCreateJsonObjects();
    }
#endif
    dataElementHydState.numDevices = networkData.numberOfDevices;
    dECreateNetworkJsonObject(networkData, dataElementHydState.network);
    json_object_set_new(dataObject, "wfa-dataelements:Network", dataElementHydState.network);
    dataElementHydState.deviceArray = json_array();
    json_object_set_new(dataElementHydState.network, "DeviceList", dataElementHydState.deviceArray);

    dERequestHydDeviceData(dataElementHydState.curDevIndex);
    return DE_OK;
}

/// Parse device data from payload and update it in Json
// =================================================================================================
DE_STATUS dEDeviceParser(char *payload, int valid) {
    if (valid) {
        dataElementsDevice_t deviceData = {0};
        memcpy(&deviceData, (dataElementsDevice_t *)payload, sizeof(dataElementsDevice_t));
        dataElementState.numOfRadios = deviceData.numberOfRadios;
        dataElementHydState.numRadios = deviceData.numberOfRadios;
        dataElementHydState.curRadioIndex = 0;
        json_t *device = json_object();
        dECreateDeviceJsonObject(deviceData, device);
        json_array_append_new(dataElementHydState.deviceArray, device);

        /// Add JSON Radio Array
        dataElementHydState.radioArray = json_array();
        json_object_set_new(device, "RadioList", dataElementHydState.radioArray);

        dERequestHydRadioData(dataElementHydState.curRadioIndex);
    } else {
        dERequestHydDeviceData(dataElementHydState.curDevIndex);
    }
    return DE_OK;
}

/// Parse radio data from payload and update it in Json
// =================================================================================================
DE_STATUS dERadioParser(char *payload) {
    memset(&radioData, 0, sizeof(dataElementsRadio_t));
    memcpy(&radioData, (dataElementsRadio_t *)payload, sizeof(dataElementsRadio_t));
    dataElementHydState.radio = json_object();
    dECreateRadioJsonObject(radioData, dataElementHydState.radio);
    json_array_append_new(dataElementHydState.radioArray, dataElementHydState.radio);

    if (dataElementState.config.enableRadioBssListObject) {
        /// Add BSS List Array
        dataElementHydState.bssListArray = json_array();
        json_object_set_new(dataElementHydState.radio, "BSSList", dataElementHydState.bssListArray);
    }

    if (dataElementState.config.enableRadioUnAssocStaObject) {
        /// Create UnAssociated STA List Array
        dataElementHydState.unAssocSTAListArray = json_array();
        json_object_set_new(dataElementHydState.radio, "UnassociatedStaList", dataElementHydState.unAssocSTAListArray);
    }

    if (dataElementState.config.enableRadioBkStaObject && dataElementState.config.isMAP) {
        /// Create Bachaul STA List Array
        dataElementHydState.backhaulSTAListArray = json_array();
        json_object_set_new(dataElementHydState.radio, "BackhaulStaList", dataElementHydState.backhaulSTAListArray);
    }

    if (dataElementState.config.enableRadioScanResultObject) {
        /// Create scan List Array
        dataElementHydState.scanResultListArray = json_array();
        json_object_set_new(dataElementHydState.radio, "ScanResultList", dataElementHydState.scanResultListArray);
    }

    dERequestHydCurOpClassData();
    return DE_OK;
}

/// Parse current opclass data from payload and update it in Json
// =================================================================================================
DE_STATUS dECurOpClassParser(char *payload) {
    dataElementsCurrentOpClassProfile_t cOpClassData = {0};
    memcpy(&cOpClassData, (dataElementsCurrentOpClassProfile_t *)payload, sizeof(dataElementsCurrentOpClassProfile_t));
    radioData.numberOfCurrOpClass = cOpClassData.numberOfCurrOpClass;
    if(cOpClassData.valid == 1) {

        /// Add Current Operating Classes Array
        json_t *cOpArray = json_array();
        json_object_set_new(dataElementHydState.radio, "CurrentOperatingClasses", cOpArray);
        json_t *cOpClassObj = json_object();
        dECreateCurrentOpClassesObject(cOpClassData, cOpClassObj);
        json_array_append_new(cOpArray, cOpClassObj);
    } else {
        dataElementDebug(DBGERR,"%s: getCurOpclass failed \n",__func__);
    }
    dEGetRadioCapsData();
    return DE_OK;
}

/// Parse radio capability data from payload and update it in Json
// =================================================================================================
DE_STATUS dERadioCapParser(char *payload, int valid) {
    if (valid) {
        dataElementsCapabilities_t capData = {0};
        memcpy(&capData, (dataElementsCapabilities_t *)payload, sizeof(dataElementsCapabilities_t));
        /// Add Capabilities Object
        dataElementHydState.capabilities = json_object();
        json_object_set_new(dataElementHydState.radio, "Capabilities", dataElementHydState.capabilities);

        dECreateCapabilitiesJsonObject(capData, dataElementHydState.capabilities);

        dataElementHydState.capableOpClassArray = json_array();
        json_object_set_new(dataElementHydState.capabilities, "OperatingClasses", dataElementHydState.capableOpClassArray);
    }

    dERequestHydRadioCapableOpClassData();

    return DE_OK;
}

/// Parse capable opclass data from payload and update it in Json
// =================================================================================================
DE_STATUS dECapableOpClassParser(char *payload, int numOpClass) {
    if (numOpClass) {
        dataElementsCapableOpClassProfile_t capOpClassData[MAP_SERVICE_MAX_OPERATING_CLASSES] = {0};
        memcpy(&capOpClassData, (dataElementsCapableOpClassProfile_t *)payload, sizeof(dataElementsCapableOpClassProfile_t)*numOpClass);
        u_int8_t i;
        for (i = 0; i < numOpClass; i++) {
            json_t *capableOpClassObject = json_object();
            json_array_append_new(dataElementHydState.capableOpClassArray, capableOpClassObject);
            dECreateCapableOpClassesObject(capOpClassData[i],
                    capableOpClassObject);
        }
    }

    dERequestHydBssData(dataElementHydState.curRadioIndex-1);

    return DE_OK;
}

/// Parse Bss data from payload and update it in Json
// =================================================================================================
DE_STATUS dEBssParser(char *payload, int numBss) {
    radioData.numberOfBSS = numBss;
    dataElementHydState.curStaCount=0;
    dataElementHydState.curBssSta=0;
    dataElementHydState.curBssUnicastByteSent=0;
    dataElementHydState.curBssUnicastByteReceived=0;
    dataElementsBSS_t bssData[IEEE1905_QCA_VENDOR_MAX_BSS] = {0};
    memcpy(&bssData, (dataElementsBSS_t *)payload, sizeof(dataElementsBSS_t)*radioData.numberOfBSS);
    u_int8_t bssCount;
    for (bssCount = 0; bssCount < radioData.numberOfBSS; bssCount++) {
        dataElementDebug(DBGINFO,
                " BSS  " deMACAddFmt(":"),
                deMACAddData(bssData[bssCount].BSSID.ether_addr_octet));

        /// Add JSON BSS Object
        dataElementJsonObjectDB_t *bssEntry = NULL;
        bssEntry = dEFindorCreateJsonEntry(&bssData[bssCount].BSSID, &radioData.id);
        if (!bssEntry) {
            dataElementDebug(DBGERR,
                    "%s: Failed to find or create bss Entry  " deMACAddFmt(":"),
                    __func__, deMACAddData(&bssData[bssCount].BSSID.ether_addr_octet));
            return DE_NOK;
        }
        bssEntry->jObject = json_object();
        dataElementHydState.bssObject[bssCount] = bssEntry->jObject;
        json_array_append_new(dataElementHydState.bssListArray, dataElementHydState.bssObject[bssCount]);
        dEGetTimeElapsed(bssEntry, &bssData[bssCount].lastChange);

        dECreateBssListJsonObject(bssData[bssCount], dataElementHydState.bssObject[bssCount]);

        if (dataElementState.config.enableBssStaListObject) {
            /// Add STA List Array
            dataElementHydState.staListArray[bssCount] = json_array();
            json_object_set_new(dataElementHydState.bssObject[bssCount],
                    "STAList", dataElementHydState.staListArray[bssCount]);
        }

        dECreateRadioJsonObject(radioData, dataElementHydState.radio);
        dERequestHydStaData(&bssData[bssCount].BSSID);
    }
    if(numBss == 0) {
        dERequestHydUnAssocStaData();
    }

    return DE_OK;
}

/// Parse station data from payload and update it in Json
// =================================================================================================
DE_STATUS dEStaParser(char *payload, int staReqInProgress) {
    dataElementsSTAList_t staData = {0};
    memcpy(&staData, (dataElementsSTAList_t *)payload, sizeof(dataElementsSTAList_t));

    if(staReqInProgress) {
        json_t *staObject = json_object();
        dECreateStaListObject(&staData, staObject);
        json_array_append_new(dataElementHydState.staListArray[dataElementHydState.curBssSta], staObject);
        dataElementHydState.curStaCount+=1;
        dataElementHydState.curBssUnicastByteSent += staData.stats.txBytes;
        dataElementHydState.curBssUnicastByteReceived += staData.stats.rxBytes;
    } else {
        dESetObjectKeyUIntValue(dataElementHydState.bssObject[dataElementHydState.curBssSta],
                DE_BSS_UNICAST_BYTES_SENT, dataElementHydState.curBssUnicastByteSent);
        dESetObjectKeyUIntValue(dataElementHydState.bssObject[dataElementHydState.curBssSta],
                DE_BSS_UNICAST_BYTES_RECEIVED, dataElementHydState.curBssUnicastByteReceived);
        dataElementDebug(DBGDUMP, "%s: numberofSta %d \n",__func__, dataElementHydState.curStaCount);
        dESetObjectKeyIntValue(dataElementHydState.bssObject[dataElementHydState.curBssSta],
                DE_BSS_NUM_OF_STA, dataElementHydState.curStaCount);
        dataElementHydState.curStaCount=0;
        dataElementHydState.curBssSta++;
        dataElementHydState.curBssUnicastByteSent=0;
        dataElementHydState.curBssUnicastByteReceived=0;

        if (dataElementHydState.curBssSta == radioData.numberOfBSS) {
            dataElementDebug(DBGINFO, "%s: Station data collection for all bss completed \n",__func__);
            dERequestHydUnAssocStaData();
        }
    }

    return DE_OK;
}

/// Parse unassoc sta data from payload and update it in Json
// =================================================================================================
DE_STATUS dEUnassocStaParser(char *payload, int unAssocStaReqInProgress) {
    dataElementsUnassociatedSTA_t unAssocStaData = {0};
    memcpy(&unAssocStaData, (dataElementsUnassociatedSTA_t *)payload, sizeof(dataElementsUnassociatedSTA_t));

    if(unAssocStaReqInProgress) {
        json_t *unAssocstaObject = json_object();
        dECreateUnAssocSTAObject(&unAssocStaData, unAssocstaObject);
        json_array_append_new(dataElementHydState.unAssocSTAListArray, unAssocstaObject);
    } else {
        dataElementDebug(DBGINFO,"%s: UnAssocciated STA collection completed \n",__func__);
        radioData.numberOfUnassocSta = json_array_size(dataElementHydState.unAssocSTAListArray);
        dECreateRadioJsonObject(radioData, dataElementHydState.radio);
        dERequestHydBackHaulStaData();
    }

    return DE_OK;
}

/// Parse scanresult data from payload and update it in Json
// =================================================================================================
DE_STATUS dEScanDataParser(char *payload, int payloadSize, int status) {
    if (status == SCAN_DATA_START) {
        dataElementHydState.scanData = (char *)malloc(sizeof(dataElementsScanResult_t));
        dataElementHydState.tmpScanData = dataElementHydState.scanData;
        if(dataElementHydState.scanData == NULL) {
            dataElementDebug(DBGERR, "ScanData Insufficient Memory \n");
        }
    }
    dataElementDebug(DBGDUMP, "%s:%d> payload:%d status:%d scandata:%p tempscandata:%p\n", __func__, __LINE__,
            payloadSize, status, dataElementHydState.scanData, dataElementHydState.tmpScanData );
    if (dataElementHydState.scanData) {
        memcpy(dataElementHydState.tmpScanData, (char *)payload, payloadSize);
        dataElementHydState.tmpScanData = dataElementHydState.tmpScanData+payloadSize;
    }
    if (status == SCAN_DATA_STOP){
        if (dataElementHydState.scanData) {
            json_t *scanListObject = json_object();
            json_array_append_new(dataElementHydState.scanResultListArray, scanListObject);
            dECreateScanResultJsonObject((dataElementsScanResult_t)*((dataElementsScanResult_t *)(dataElementHydState.scanData)), scanListObject);

            free (dataElementHydState.scanData);
            dataElementHydState.scanData = NULL;
            dataElementHydState.tmpScanData = NULL;
            dERequestHydRadioData(dataElementHydState.curRadioIndex);
        }
    }
    if (payloadSize == 0) {
        dataElementDebug(DBGINFO, "%s: ScanResult data is not captured \n",__func__);
        dERequestHydRadioData(dataElementHydState.curRadioIndex);
    }
    return DE_OK;
}

/// Parse backhaul sta data from payload and update it in Json
// =================================================================================================
DE_STATUS dEBackhaulStaParser(char *payload, int IsBstaValid) {
    dataElementsBackHaulSTA_t bstaData = {0};
    memcpy(&bstaData, (dataElementsBackHaulSTA_t *)payload, sizeof(dataElementsBackHaulSTA_t));

    if (IsBstaValid) {
        json_t *bkstaObject = json_object();
        dECreateBackHaulSTAJsonObject(&bstaData, bkstaObject);
        json_array_append_new(dataElementHydState.backhaulSTAListArray, bkstaObject);
    }

    dERequestHydScanListData();

    return DE_OK;
}

/// Parse assoc event data from payload and update it in Json
// =================================================================================================
DE_STATUS dEAssocEvent(char *payload) {
    dataElementsAssociationEvent_t Assoc = {0};
    memcpy(&Assoc, (dataElementsAssociationEvent_t *)payload, sizeof(dataElementsAssociationEvent_t));
    if (dataElementState.config.NBEventEnable) {
    dataElementDebug(DBGINFO, "dENBEventParser: NB: Assoc Event: macaddress " deMACAddFmt(":") " BSSID "
            deMACAddFmt(":") "\n", deMACAddData(Assoc.assocData.macAddress.ether_addr_octet),
            deMACAddData(Assoc.assocData.BSSID.ether_addr_octet));
    }
    dECreateAssocObject(&Assoc.assocData);
    dENBMsgDispatch(DE_TLV_TYPE_ASSOC_EVENT, 0,  (char *)&Assoc.assocData, sizeof(dataElementsAssociationEventData_t));

    return DE_OK;
}

/// Parse disassoc event data from payload and update it in Json
// =================================================================================================
DE_STATUS dEDisassocEvent(char *payload) {
    dataElementsDisassociationEvent_t disAssoc = {0};
    memcpy(&disAssoc, (dataElementsDisassociationEvent_t *)payload, sizeof(dataElementsDisassociationEvent_t));
    if (dataElementState.config.NBEventEnable) {
    dataElementDebug(DBGINFO, "dENBEventParser: NB: Disassoc Event: macaddress " deMACAddFmt(":") " BSSID "
            deMACAddFmt(":") "\n", deMACAddData(disAssoc.disassocData.macAddress.ether_addr_octet),
            deMACAddData(disAssoc.disassocData.BSSID.ether_addr_octet));
    }
    dECreateDisAssocObject(&disAssoc.disassocData);
    dENBMsgDispatch(DE_TLV_TYPE_DISASSOC_EVENT, 0,  (char *)&disAssoc.disassocData, sizeof(dataElementsDisassociationEventData_t));

    return DE_OK;
}

void dENBEventParser(int event, char *payload, int value) {
    char name[IFNAMSIZ];
    struct ether_addr addr = {0};
    if (event == DE_TLV_TYPE_INTERFACE_DOWN_EVENT ||
            event == DE_TLV_TYPE_INTERFACE_UP_EVENT) {
        memcpy((char *) &name, (char *)payload, IFNAMSIZ);
    } else {
        deCopyMACAddr(payload, addr.ether_addr_octet);
    }
    switch(event) {
        case DE_TLV_TYPE_INTERFACE_DOWN_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: Interface down event: iface %s \n", __func__,name);
            dENBMsgDispatch(DE_TLV_TYPE_INTERFACE_DOWN_EVENT, 0, (char *)&name, IFNAMSIZ);
            break;
        case DE_TLV_TYPE_INTERFACE_UP_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: Interface up event: iface %s \n", __func__,name);
            dENBMsgDispatch(DE_TLV_TYPE_INTERFACE_UP_EVENT, 0, (char *)&name, IFNAMSIZ);
            break;
        case DE_TLV_TYPE_RE_JOIN_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: RE join event: macaddress " deMACAddFmt(":") " isDistantNeighbor:%d \n",
                    __func__, deMACAddData(addr.ether_addr_octet), value);
            dENBMsgDispatch(DE_TLV_TYPE_RE_JOIN_EVENT, value, (char *)&addr, sizeof(struct ether_addr));
            break;
        case DE_TLV_TYPE_RE_LEAVE_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: RE leave event: macaddress " deMACAddFmt(":") " isDistantNeighbor:%d \n",
                    __func__, deMACAddData(addr.ether_addr_octet), value);
            dENBMsgDispatch(DE_TLV_TYPE_RE_LEAVE_EVENT, value, (char *)&addr, sizeof(struct ether_addr));
            break;
        case DE_TLV_TYPE_CONTROLLER_UP_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: Controller up event: macaddress " deMACAddFmt(":") "\n",
                    __func__, deMACAddData(addr.ether_addr_octet));
            dENBMsgDispatch(DE_TLV_TYPE_CONTROLLER_UP_EVENT, 0, (char *)&addr, sizeof(struct ether_addr));
            break;
        case DE_TLV_TYPE_CONTROLLER_DOWN_EVENT:
            dataElementDebug(DBGINFO, "%s: NB: Controller down event: macaddress " deMACAddFmt(":") "\n",
                    __func__, deMACAddData(addr.ether_addr_octet));
            dENBMsgDispatch(DE_TLV_TYPE_CONTROLLER_DOWN_EVENT, 0, (char *)&addr, sizeof(struct ether_addr));
            break;
    }
}

/**
 * Parse IEEE1905 message
 */
int meshDEParseFrame(char *frame)
{
    ieee1905DispatchFrame_t *meshFrame = NULL;

    if (!frame)
        return MESH_EVENT_NO_DATA;

    frame++; //skip buffer type
    meshFrame = (ieee1905DispatchFrame_t *) frame;

    dbgf(dataElementState.dbgModule, DBGDUMP, "Buffer received in frame parse = ");
    for (size_t k=0; k<16; k++)
    {
        dbgf(dataElementState.dbgModule, DBGDUMP, "\t%x", frame[k]);
    }

    dataElementDebug(DBGDEBUG,
            "msgType=%u \t tlvType=%u",
            meshFrame->msgType, meshFrame->tlvType);

    switch (meshFrame->tlvType) {
        case DE_TLV_TYPE_GET_NETWORK:
            if (dENetworkParser(meshFrame->content) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Network Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_DEVICE:
            if (dEDeviceParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Device Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_RADIO:
            if (dERadioParser(meshFrame->content) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Radio Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_CUR_OP_CLASS:
            if (dECurOpClassParser(meshFrame->content) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Current opclass Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_CAPABILITIES:
            if (dERadioCapParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Radio Capability Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_CAP_OP_CLASS_PROF:
            if (dECapableOpClassParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Capable Opclass Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_BSS:
            if (dEBssParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: BSS Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_GET_STA:
            if (dEStaParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
            }
            break;
        case DE_TLV_TYPE_GET_UNASSOC_STA:
            if (dEUnassocStaParser (meshFrame->content, meshFrame->msgType) == DE_OK) {
            }
            break;
        case DE_TLV_TYPE_GET_SCAN_RESULT:
            if (dEScanDataParser(meshFrame->content, meshFrame->msgType, meshFrame->mid) == DE_OK) {
            }
            break;
        case DE_TLV_TYPE_GET_BACKHAUL:
            if (dEBackhaulStaParser(meshFrame->content, meshFrame->msgType) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Backhaul Sta Data Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_ASSOC_EVENT:
            if (dEAssocEvent(meshFrame->content) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Assoc Event Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_DISASSOC_EVENT:
            if (dEDisassocEvent(meshFrame->content) == DE_OK) {
                dataElementDebug(DBGDUMP, "%s: Assoc Event Parsed \n",__func__);
            }
            break;
        case DE_TLV_TYPE_CONTROLLER_UP_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
        case DE_TLV_TYPE_CONTROLLER_DOWN_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
        case DE_TLV_TYPE_RE_JOIN_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
        case DE_TLV_TYPE_RE_LEAVE_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
        case DE_TLV_TYPE_INTERFACE_UP_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
        case DE_TLV_TYPE_INTERFACE_DOWN_EVENT:
            dENBEventParser(meshFrame->tlvType, meshFrame->content, meshFrame->msgType);
            break;
    }
    return DE_OK;
}


DE_STATUS dataElementHydInit(void) {
    dataElementHydState.isInit = DE_TRUE;
    return DE_OK;
}

DE_STATUS dataElementHydFini(void) {
    dataElementHydState.isInit = DE_FALSE;
    return DE_OK;
}
