/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <dbg.h>
#include <eloop.h>

#include "dataElements.h"
#include "dataElementsUtil.h"
#include "dataElementsJson.h"
#include "dataElementsHyd.h"
#include "dataElementsWlan.h"


extern DE_STATUS dataElementsBSEventWlanInit(void);

extern DE_STATUS dataElementsBSEventWlanInit(void);

dataElementJsonObjectDB_t *dataElementJsonObjectArray[DATA_ELEMENTS_HASH_TABLE_SIZE];

dataElementState_t dataElementState;

void dEJSONReportingTimeoutHandler(void *);
/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement dataElementDefaultTable[] = {
    { DE_JSON_REPORTING_INTERVAL,                   "600" },
    { DE_RADIO_JSON_ENABLE,                         "1" },
    { DE_RADIO_CAPS_JSON_ENABLE,                    "1" },
    { DE_RADIO_BSS_LIST_JSON_ENABLE,                "1" },
    { DE_RADIO_BACKHAUL_STA_JSON_ENABLE,            "1" },
    { DE_RADIO_SCAN_RESULT_JSON_ENABLE,             "1" },
    { DE_RADIO_UNASSOC_STA_JSON_ENABLE,             "1" },
    { DE_RADIO_CUR_OP_CLASS_JSON_ENABLE,            "1" },
    { DE_BSS_STA_LIST_JSON_ENABLE,                  "1" },
    { DE_STA_ASSOC_EVENT_JSON_ENABLE,               "1" },
    { DE_STA_DISASSOC_EVENT_JSON_ENABLE,            "1" },
    { DE_IS_SINGLE_AP,                              "1" },
    { DE_IS_MAP,                                    "0" },
    { DE_IS_SON,                                    "0" },
    { DE_ENABLE_BASE64_ENCODING,                    "0" },
    { DE_ENABLE_CERT,                               "0" },
    { DE_ENABLE_NB_EVENTS,                          "0" },
    { DE_JSON_FILE_PATH,                            "www/dataElement" },
    { NULL, NULL }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
/// JSON DB Operations
//////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @brief  Hash Table operations use 2 macAddress as input. macAddress is the
 *         MAC for which Json Object needs to be created. macKey is used for
 *         additional checks. We are using 2 MAC addresses to maintain the JSON
 *         hash table because we have cases where the Radio MAC is same as the
 *         BSSID of the first VAP.
 *
 *         The macAddress is the MAC for which you want to get the object
 *         structure. macKey is the parent device for that macAddress.
 *         example:
 *         for device object : macAddress = dev alId , macKey = dev alId
 *         for radio object : macAddress = radio MAC , macKey = dev alId
 *         for bss object : macAddress =  BSSID , macKey = radio MAC
 *         for sta object : macAddress =  sta MAC , macKey = BSSID
 *
 */

/**
 * @brief function to generate hash code.
 *
 * @param [in] macAddress  MAC address in network byte order
 * @param [in] macKey  MAC address in network byte order
 *
 * @return hash key generated
 */
int hashCodeDB(const struct ether_addr *macAddress, const struct ether_addr *macKey) {
    return (deMACAddHash(macAddress->ether_addr_octet) | deMACAddHash(macKey->ether_addr_octet));
}

/**
 * @brief function to insert new entry for macAddress and macKey into
 *         database and create Json Object for this entry.
 *
 * @param [in] macAddress  MAC address in network byte order
 * @param [in] macKey  MAC address in network byte order
 *
 * @return the new entry that is created.
 */
struct dataElementJsonObjectDB_t *dEJsonInsert(const struct ether_addr *macAddress,
                                               const struct ether_addr *macKey) {
    /// get the hash
    int hashIndex = hashCodeDB(macAddress, macKey);

    /// move in array until an empty or deleted cell
    while (dataElementJsonObjectArray[hashIndex] != NULL &&
           dataElementJsonObjectArray[hashIndex]->key != -1) {
        /// wrap around and get new hashIndex
        ++hashIndex;
        hashIndex %= hashCodeDB(macAddress, macKey);

        if (hashIndex >= DATA_ELEMENTS_HASH_TABLE_SIZE) {
            dataElementDebug(DBGERR, " HASH index %d grater than 255 ", hashIndex);
            return NULL;
        }
    }

    struct dataElementJsonObjectDB_t *newEntry =
        (struct dataElementJsonObjectDB_t *)malloc(sizeof(struct dataElementJsonObjectDB_t));
    if (!newEntry) {
        dataElementDebug(DBGERR, " %s: Memory allocation failed",__func__);
        return NULL;
    }
    newEntry->key = hashIndex;
    newEntry->acsReady = DE_FALSE;
    deCopyMACAddr(macAddress->ether_addr_octet, newEntry->macAddress.ether_addr_octet);
    deCopyMACAddr(macKey->ether_addr_octet, newEntry->macKey.ether_addr_octet);
    /*json object creation is to handle by the calling function */
    //newEntry->jObject = json_object();
    newEntry->utilizationReceive = 0;
    newEntry->utilizationTransmit = 0;
    newEntry->prevrxByte = 0;
    newEntry->prevtxByte = 0;
    gettimeofday(&newEntry->initTime, NULL);
    dataElementJsonObjectArray[hashIndex] = newEntry;

    return dataElementJsonObjectArray[hashIndex];
}

/**
 * @brief function to find if Json Entry for macAddress and macKey
 *         exists in DataBase.
 *
 * @param [in] macAddress  MAC address in network byte order
 * @param [in] macKey  MAC address in network byte order
 *
 * @return entry if found , else NULL
 */
struct dataElementJsonObjectDB_t *dEFindJsonEntry(const struct ether_addr *macAddress,
                                                  const struct ether_addr *macKey) {
    /// get the hash
    int hashIndex = hashCodeDB(macAddress, macKey);

    while (dataElementJsonObjectArray[hashIndex] != NULL) {
        if ((deAreEqualMACAddrs(macAddress->ether_addr_octet,
                        dataElementJsonObjectArray[hashIndex]->macAddress.ether_addr_octet)) &&
            (deAreEqualMACAddrs(macKey->ether_addr_octet,
                                dataElementJsonObjectArray[hashIndex]->macKey.ether_addr_octet))) {
            return dataElementJsonObjectArray[hashIndex];
        }

        /// wrap around and get new hashIndex
        ++hashIndex;
        hashIndex %= hashCodeDB(macAddress, macKey);

        if (hashIndex >= DATA_ELEMENTS_HASH_TABLE_SIZE) {
            dataElementDebug(DBGERR, " HASH index %d grater than 255 ", hashIndex);
            return NULL;
        }
    }

    return NULL;
}

/**
 * @brief function to find or create Json Entry for macAddress and macKey
 *         in DataBase.
 *
 * @param [in] macAddress  MAC address in network byte order
 * @param [in] macKey  MAC address in network byte order
 *
 * @return entry created in database.
 */
struct dataElementJsonObjectDB_t *dEFindorCreateJsonEntry(const struct ether_addr *macAddress,
                                                          const struct ether_addr *macKey) {
    dataElementJsonObjectDB_t *macEntry = NULL;
    macEntry = dEFindJsonEntry(macAddress, macKey);
    if (!macEntry) {
        return dEJsonInsert(macAddress, macKey);
    }

    return macEntry;
}

/**
 * @brief function to delete Json Entry for macAddress and macKey
 *         in DataBase.
 *
 * @param [in] macAddress  MAC address in network byte order
 * @param [in] macKey  MAC address in network byte order
 *
 * @return DE_OK on success; otherwise DE_NOK
 */
DE_STATUS dEDeleteJsonObjectEntry(const struct ether_addr *macAddress,
                                   const struct ether_addr *macKey) {
    dataElementJsonObjectDB_t *dummyItem;
    dummyItem =
        (struct dataElementJsonObjectDB_t *)malloc(sizeof(struct dataElementJsonObjectDB_t));
    if (!dummyItem) {
        dataElementDebug(DBGERR, " %s: Memory allocation failed",__func__);
        return DE_NOK;
    }
    dummyItem->key = -1;

    /// get the hash
    int hashIndex = hashCodeDB(macAddress, macKey);

    /// move in array until an empty
    while (dataElementJsonObjectArray[hashIndex] != NULL) {

        if (deAreEqualMACAddrs(macAddress->ether_addr_octet,
                    dataElementJsonObjectArray[hashIndex]->macAddress.ether_addr_octet)) {
            // assign a dummy item at deleted position
            dataElementJsonObjectArray[hashIndex] = dummyItem;
            return DE_OK;
        }

        /// wrap around and get new hashIndex
        ++hashIndex;
        hashIndex %= hashCodeDB(macAddress, macKey);
    }

    return DE_NOK;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//// North Bound Socket
//////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Creates north bound Server socket
 *
 * @return DE_OK on success. Otherwise return DE_NOK
 */


DE_STATUS create_server_socket(void)
{
    struct sockaddr_in address;
    // Creating socket file descriptor
    if ( (dataElementState.NBSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        return DE_NOK;
    }

    // Filling server information
    address.sin_family    = AF_INET; // IPv4
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(LOCAL_PORT);

    // Bind the socket with the server address
    if ( bind(dataElementState.NBSocket, (const struct sockaddr *)&address,
            sizeof(address)) < 0 )
    {
        perror("bind failed");
        return DE_NOK;
    }

    dataElementEventRdbufRegister();
    return DE_OK;
}

/**
 * @brief Registers the CallBack function
 *
 */
void dataElementEventRdbufRegister()
{
    bufrdCreate(&dataElementState.ReadBuf, "dataElement-server",
            dataElementState.NBSocket,
            DATA_LEN_MAX, /* Read buf size */
            dataElementCB,   /* callback */
            NULL);

}

/**
 * @brief Fetch and process the data sent by north bound client
 *
 */
void dataElementCB(void *data)
{
    struct bufrd *readBuf = &dataElementState.ReadBuf;
    u_int32_t buff_len = bufrdNBytesGet(readBuf);
    char *query = bufrdBufGet(readBuf);
    char buffer[DATA_LEN_MAX] = {0};

    if (bufrdErrorGet(readBuf)) {
        return;
    }

    if(!buff_len) {
        return;
    }
    dataElementDebug(DBGDEBUG,"%s:%d> frame:%s len:%d\n", __func__, __LINE__, query, buff_len );
    // extract the query from the HTTP request sent from client.
    extract_request(query, buffer);

    request_handler(buffer);

    bufrdConsume(readBuf, buff_len);

}

/**
 * @brief Extract the query from the HTTP request sent from client
 *
 * @param [in] query   HTTP query sent from the client
 * @param [inout] buffer   The actual request extracted from the query
 */
void extract_request(char *query, char *buffer)
{
    char *pos = NULL;
    char request[100];
    int i=1,j=0;
    pos = strstr(query, "/");
    if (!pos) {
        dataElementDebug(DBGERR,"%s: string exract failed",__func__);
        return;
    }
    while(pos[i]!=' ' && pos[i]!='?')
    {
        request[j] = pos[i];
        j++;
        i++;
    }
    request[j] = '\0';
    strlcpy(buffer, request, DATA_LEN_MAX);
}

/**
 * @brief Get the request number associated with the client request
 *
 * @param [in] request   query sent from the client
 * @param [inout] num   request number associated to the request
 */
void getRequestNumber(char *request, int *num)
{
    if(!strcmp(request, "getStats"))
        *num = 1;
    else if (!strcmp(request, "getStatsOnly"))
        *num = 2;
}

/**
 * @brief Handles request sent from the client
 *
 * @param [in] request   query sent from the client
 */
void request_handler(char *request)
{
    char *response = "HTTP/1.1 200 OK\n\nServer says Hi!\nPrint the JSON here";
    char *default_response = "HTTP/1.1 400 Bad Request\n\n";
    int req;

    struct sockaddr_in cliaddr;
    memset(&cliaddr, 0, sizeof(cliaddr));
    int len = sizeof(cliaddr);

    cliaddr.sin_family = AF_INET;
    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_port = htons(CLI_PORT);


    getRequestNumber(request, &req);

    switch(req)
    {
        case GET_STATS:
            dEJSONReportingTimeoutHandler(NULL);
            sendto(dataElementState.NBSocket, (const char *)response, strlen(response), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
            break;
        case GET_STATS_ONLY:
            dataElementState.isStatsOnly = 1;
            dEJSONReportingTimeoutHandler(NULL);
            sendto(dataElementState.NBSocket, (const char *)response, strlen(response), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
        default:
            sendto(dataElementState.NBSocket, (const char *)default_response, strlen(default_response), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
    }
}

void sendNBRequest() {
    char *response = "Json created";

    struct sockaddr_in cliaddr;
    memset(&cliaddr, 0, sizeof(cliaddr));
    int len = sizeof(cliaddr);

    cliaddr.sin_family = AF_INET;
    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_port = htons(CLI_PORT);

    if((sendto(dataElementState.NBSocket,(const char *)response, strlen(response), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len)) < 0 ) {
        dataElementDebug(DBGERR, "%s: sendto failed\n",__func__);
    }

}

int dENBMsgWrite(const char *buf, int NBytes) {
    int NBSock_len;
    struct sockaddr_in cliaddr;

    if (!buf) {
        dataElementDebug(DBGERR, "%s: Invalid buffer to send \n",__func__);
        return DE_NOK;
    }

    if (NBytes > DE_NB_FRAME_LEN_MAX) {
        dataElementDebug(DBGERR, "%s: Size greater than max size allowed", __func__);
        return DE_NOK;
    }

    memset(&cliaddr, 0, sizeof(cliaddr));
    NBSock_len = sizeof(cliaddr);
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_port = htons(CLI_PORT);

    if (sendto(dataElementState.NBSocket, buf, NBytes, MSG_CONFIRM,
                (const struct sockaddr *)&cliaddr, NBSock_len) < 0) {
        dataElementDebug(DBGERR, "%s send to NB Socket failed %s", __func__,
                strerror (errno));
        return DE_NOK;
    }
    return DE_OK;
}

int dENBMsgDispatch(int msgType, int count,  char *data, int dataLen) {
    int status = DE_NOK;
    ieee1905DispatchFrame_t *frame=NULL;
    int nBytes = dataLen+ IEEE1905_DISPATCH_FIXED_FIELDS_SIZE + 1;
    char *buf = malloc(nBytes*sizeof(char));
    if (!buf) {
        dataElementDebug(DBGERR, "%s: frame memory allocation failed \n",__func__);
        return status;
    }

    char *tmpBuf = buf;

    memset(buf, 0, nBytes);

    *tmpBuf = SERVICE_TYPE_DE;
    tmpBuf++;
    frame = (ieee1905DispatchFrame_t *)tmpBuf;
    frame->tlvType = msgType;
    frame->msgType = count;
    if  ((dataLen > 0) && data) {
        memcpy(frame->content, data, dataLen);
    }
    status = dENBMsgWrite(buf, nBytes);
    free(buf);

    return status;
}

///////////////////////////////////////////////////////////////////////////////////////////

/// Get Time Elapsed
DE_STATUS dEGetTimeElapsed(dataElementJsonObjectDB_t *jsonEntry, u_int32_t *timeElapsed) {
    if (jsonEntry) {
        struct timeval curTime;
        gettimeofday(&curTime, NULL);
        *timeElapsed = curTime.tv_sec - jsonEntry->initTime.tv_sec;
        return DE_OK;
    }

    return DE_NOK;
}

/// Create STA List Object
// =================================================================================================
/**
 * @brief send the sta details to json updation
 *
 * @param [in] bssCount Index of the bss
 * @param [in] radioData Radio data
 *
 */
static void dECreateSTAObject(u_int32_t bssCount, dataElementsRadio_t *radioData,
        struct ether_addr bssid, u_int32_t no_of_sta, json_t *staListArray) {
    dataElementsSTAList_t *staData = NULL;
    int i=0;

    staData = (dataElementsSTAList_t *)malloc( no_of_sta * sizeof(dataElementsSTAList_t));
    if ( staData == NULL ){
        return;
    }
    if (dEGetWlanStaData(bssCount, no_of_sta, staData) == DE_OK) {
        dataElementDebug(DBGDUMP, "Collected all the sta data\n");
    }
    else {
        dataElementDebug(DBGERR, "%s: Failed to collect sta data\n", __func__);
        free(staData);
        return;
    }
    while ( i < no_of_sta ) {
        dataElementJsonObjectDB_t *station = NULL;
        station = dEFindorCreateJsonEntry(&bssid, &staData[i].macAddress);
        if(!station) {
            dataElementDebug(DBGERR,
                       "%s: Failed to find or create sta Entry  " deMACAddFmt(":"),
                        __func__, deMACAddData(&staData[i].macAddress.ether_addr_octet));
            i++;
            continue;
        }
        json_t *staListObject = json_object();
        station->jObject = staListObject;
        dataElementsSTAList_t *stadata = &staData[i];
#define Kbps_to_Bps 125
#define CONVERT_TO_MILLI 1000
        /* utilizationTransmit is assigned to avoid garbage value */
        stadata->utilizationReceive = station->utilizationReceive;
        if(stadata->stats.rxBytes > 0 && (stadata->stats.rxBytes > station->prevrxByte)) {
        stadata->utilizationReceive = station->utilizationReceive +
            (((stadata->stats.rxBytes - station->prevrxByte) * CONVERT_TO_MILLI) /
             (stadata->lastDataDownlinkRate * Kbps_to_Bps));
        station->utilizationReceive = stadata->utilizationReceive;
        }

        stadata->utilizationTransmit = station->utilizationTransmit;
        if(stadata->stats.txBytes > 0 && (stadata->stats.txBytes > station->prevtxByte)) {
        stadata->utilizationTransmit = station->utilizationTransmit +
            (((stadata->stats.txBytes - station->prevtxByte) * CONVERT_TO_MILLI) /
             (stadata->lastDataUplinkRate * Kbps_to_Bps));
        station->utilizationTransmit = stadata->utilizationTransmit;
        }
        station->prevrxByte = stadata->stats.rxBytes;
        station->prevtxByte = stadata->stats.txBytes;
        json_array_append_new(staListArray, staListObject);
        dECreateStaListObject(&staData[i], staListObject );
        i++;
    }
    free(staData);
}

/// Create BSSList Object
// =================================================================================================
/**
 * @brief Get bss info and update in json
 *
 * @param [in] radioIndex Index of the radio
 * @param [in] radioData
 *
 * @return DE_OK on success
 */
DE_STATUS dECreateBssList(u_int8_t radioIndex,
                            dataElementsRadio_t *radioData) {
    /// Add BSS List Array
    json_t *bssListArray = json_array();
    json_object_set_new(radioData->radioObject, "BSSList", bssListArray);

        dataElementsBSS_t bssData[IEEE1905_QCA_VENDOR_MAX_BSS] = {0};
        if (dEGetWlanBssData(radioIndex, radioData, bssData) == DE_OK) {
            u_int8_t bssCount;
            for (bssCount = 0; bssCount < radioData->numberOfBSS; bssCount++) {
                dataElementDebug(DBGINFO, " BSS  " deMACAddFmt(":"),
                                 deMACAddData(bssData[bssCount].BSSID.ether_addr_octet));

                /// Add JSON BSS Object
                dataElementJsonObjectDB_t *bssEntry = NULL;
                bssEntry = dEFindorCreateJsonEntry(&bssData[bssCount].BSSID, &radioData->id);
                if (!bssEntry) {
                    dataElementDebug(DBGERR,
                       "%s: Failed to find or create bss Entry  " deMACAddFmt(":"),
                        __func__, deMACAddData(&bssData[bssCount].BSSID.ether_addr_octet));
                    return DE_NOK;
                }
                json_t *bssListObject = json_object();
                bssEntry->jObject = bssListObject;
                json_array_append_new(bssListArray, bssListObject);
                dEGetTimeElapsed(bssEntry, &bssData[bssCount].lastChange);

                dECreateBssListJsonObject(bssData[bssCount], bssListObject);

                if (dataElementState.config.enableBssStaListObject && bssData[bssCount].NumberOfSTA) {
                    /// Add STA List Array
                    json_t *staListArray = json_array();
                    json_object_set_new(bssListObject, "STAList", staListArray);

                    /// Add STA Object
                    dECreateSTAObject(bssCount, radioData, bssData[bssCount].BSSID, bssData[bssCount].NumberOfSTA, staListArray);
                }
            }
        }

    return DE_OK;
}

/// Create Capabilities JSON File
// =================================================================================================
/**
 * @brief Get radio capabilities and update in json
 *
 * @param [in] radioData
 *
 */
static void dECreateCapabilities(dataElementsRadio_t *radioData) {
    dataElementsCapabilities_t capData = {0};

    /// Add Capabilities Object
    json_t *capabilities = json_object();
    json_object_set_new(radioData->radioObject, "Capabilities", capabilities);
        if (dEGetWlanRadioCapsData(radioData, &capData) == DE_OK) {
                dECreateCapabilitiesJsonObject(capData, capabilities);
        }

    /// Add Capable Opearting Class Array
    json_t *capableOpClassArray = json_array();
    json_object_set_new(capabilities, "OperatingClasses", capableOpClassArray);

    // Add Capable Operating Class Object
    dataElementsCapableOpClassProfile_t capOpClassData[MAP_SERVICE_MAX_OPERATING_CLASSES] = {0};
        if (dEGetWlanRadioCapableOpClassData(capOpClassData) == DE_OK) {
            u_int8_t i;
            for (i = 0; i < capData.numberOfOpClass; i++) {
                json_t *capableOpClassObject = json_object();
                json_array_append_new(capableOpClassArray, capableOpClassObject);
                    dECreateCapableOpClassesObject(capOpClassData[i],
                            capableOpClassObject);
            }
        }
}

/// Create Current Op Class List
// =================================================================================================
/**
 * @brief Get current opclass and update in json
 *
 * @param [in] radioData
 *
 */
static void dECreateCurrentOpClassesArray(dataElementsRadio_t *radioData) {
    dataElementsCurrentOpClassProfile_t cOpClassData = {0};
    if (dEGetWlanCurOpClassData(radioData, &cOpClassData) == DE_OK) {
        /// Add Current Operating Classes Array
        json_t *cOpArray = json_array();
        json_object_set_new(radioData->radioObject, "CurrentOperatingClasses", cOpArray);

        radioData->numberOfCurrOpClass = cOpClassData.numberOfCurrOpClass;
        dataElementDebug(DBGDUMP, "%s: numberOfCurrOp is %d \n",__func__, cOpClassData.numberOfCurrOpClass);
        json_t *cOpClassObj = json_object();
        dECreateCurrentOpClassesObject(cOpClassData,
                cOpClassObj);
        json_array_append_new(cOpArray, cOpClassObj);
    }
}

/// Create RadioList Object
// =================================================================================================
/**
 * @brief get Radio details and update in json
 *
 * @param [in] radioData
 * @param [in] radioIndex index of the radio
 *
 * @return DE_OK on success
 */
DE_STATUS dECreateRadioObject(dataElementsRadio_t radioData, int radioIndex) {
    json_t* radioObject = radioData.radioObject;
    if (dEGetWlanRadioData(&radioData, radioIndex) == DE_OK) {
        radioData.radioObject = radioObject;
        dECreateRadioJsonObject(radioData, radioData.radioObject);
    }

    return DE_OK;
}

/// Create Device Object
// =================================================================================================
/**
 * @brief Get device data and update in json
 *
 * @param [in] json_t object
 *
 * @return DE_OK on success
 */
DE_STATUS dECreateDeviceObject(json_t *device) {
    dataElementsDevice_t deviceData = {0};

    if (dEGetWlanDeviceData(&deviceData) == DE_OK) {
        dataElementState.numOfRadios = deviceData.numberOfRadios;
        dECreateDeviceJsonObject(deviceData, device);
    }

    return DE_OK;
}

/// Create Network Object
// =================================================================================================
/**
 * @brief Get network data and update in json
 *
 * @return json_t object
 */
json_t* dECreateNetworkObject() {
    json_t *network = json_object();
    dataElementsNetwork_t networkData = {0};

    if (dEGetWlanNetworkData(&networkData) == DE_OK) {
           dataElementState.numOfdevice=networkData.numberOfDevices;
           deCopyMACAddr(networkData.ctrlId.ether_addr_octet, dataElementState.devAddr.ether_addr_octet);
           dECreateNetworkJsonObject(networkData, network);
    } else {
        dataElementDebug(DBGERR, "%s: Get Network data failed \n",__func__);
    }
    return network;
}

/// Create Scan Object
// =================================================================================================
/**
 * @brief Get scan result and update in json
 *
 * @param [in] radioData
 *
 */
static void dECreateScanObject(dataElementsRadio_t *radioData) {
    /// Create Scan Result List Object
    dataElementsScanResult_t scanData = {0};
    json_t *scanListObject = json_object();
    if (dEGetWlanScanListData(&scanData) == DE_OK) {
        dECreateScanResultJsonObject(scanData, scanListObject);
    }
    json_object_set_new(radioData->radioObject, "ScanResultList", scanListObject);
}

/**
 * @brief Function to create SingleAP DataElement Objects
 *        Starting point of stats collection for SingleAP mode
 */
void dataElementsCreateJsonObjects() {
    u_int16_t numberOfDevices;

    dataElementState.isRunning = 1;

    /// Clear Object before Building
    json_t *jRoot = json_object();
    json_object_clear(jRoot);

    /// Add JSON Config
    dECreateConfigJsonObject(dataElementState.isMultiAP, jRoot);

    /// Add JSON Data Array and Object
    json_t *dataArray = json_array();
    json_t *dataObject = json_object();
    json_object_set_new(jRoot, "data", dataArray);
    json_array_append_new(dataArray, dataObject);

    /// Add JSON Network Object
    json_t *networkObject = dECreateNetworkObject();
    json_object_set_new(dataObject, "wfa-dataelements:Network", networkObject);

    numberOfDevices=dataElementState.numOfdevice;
    dataElementDebug(DBGDUMP,"%s: numberOfDevices %d \n",__func__,numberOfDevices);

    /// Add JSON Device Array
    json_t *deviceArray = json_array();
    json_object_set_new(networkObject, "DeviceList", deviceArray);

    do {
        /// Add JSON Device Object
        dataElementDebug(DBGINFO, "AlId :" deMACAddFmt(":"), deMACAddData(dataElementState.devAddr.ether_addr_octet));
        json_t *deviceObject = json_object();
        dECreateDeviceObject(deviceObject);
        json_array_append_new(deviceArray, deviceObject);

        if (!dataElementState.config.enableRadioObject) {
            dataElementDebug(DBGINFO, "%s: Radio Object Creation Disabled", __func__);
            dataElementState.isRunning = 0;
            dEDumpJsonObject("/www/dataElement", jRoot);
            json_decref(jRoot);
            dataElementState.isStatsOnly = 0;
            return;
        }

        /// Add JSON Radio Array
        json_t *radioArray = json_array();
        json_object_set_new(deviceObject, "RadioList", radioArray);

        u_int8_t radioIndex;
        for (radioIndex = 0; radioIndex < dataElementState.numOfRadios; radioIndex++) {
            dataElementsRadio_t radioData = {0};
            /// Add JSON Radio Object
            dEGetWlanRadioData(&radioData, radioIndex);
            dataElementDebug(DBGINFO, "%s: RadioAddr " deMACAddFmt(":") "\n", __func__,deMACAddData(radioData.id.ether_addr_octet));
            radioData.radioObject = json_object();
            //dECreateRadioJsonObject(radioData, radioData.radioObject);
            //json_array_append_new(radioArray, radioData.radioObject);

            if (dataElementState.config.enableRadioCapsObject) {
                /// Create Data Elements Radio Capabilities
                dECreateCapabilities(&radioData);
            }

            if (dataElementState.config.enableRadioCurOpClassObject) {
                /// Create the Current Op Class Array
                dECreateCurrentOpClassesArray(&radioData);
            }

            if (dataElementState.config.enableRadioBssListObject) {
                /// Create BSS list Object
                dECreateBssList(radioIndex, &radioData);
            }

            /// Create scan Object
            if (dataElementState.config.enableRadioScanResultObject && !dataElementState.isStatsOnly ) {
                dECreateScanObject(&radioData);
            }

            dECreateRadioJsonObject(radioData, radioData.radioObject);
            json_array_append_new(radioArray, radioData.radioObject);
        }

        numberOfDevices--;
    } while (numberOfDevices);

    dataElementState.isRunning = 0;
    dEDumpJsonObject("/www/dataElement", jRoot);
    json_decref(jRoot);
    dataElementState.isStatsOnly = 0;
}

/**
 * @brief Callback function invoked to report JSON data file
 *
 * @param [in] cookie  value provided during registration (currently unused)
 */
void dEJSONReportingTimeoutHandler(void *cookie) {
    if (!dataElementState.isRunning) {
        if (dataElementState.isMultiAP) {
            dERequestHydNetworkData();
        } else {
            dataElementsCreateJsonObjects();
        }
    } else {
        dataElementDebug(DBGINFO, "Stats collection is in progress wait for completion \n");
    }

    /* Schedule the next periodic query */
    evloopTimeoutRegister(&dataElementState.jsonReportTimer,
                          dataElementState.config.reportingIntervalSecs, 0);
}

/**
 * @brief Callback function invoked to trigger Neighbor scan
 *
 * @param [in] cookie  value provided during registration (currently unused)
 */
static void dENeighbourScanTimeoutHandler(void *cookie) {
    dESendScanRequest();

    /* Schedule the next periodic query */
    evloopTimeoutRegister(&dataElementState.neighbourScanTimer,
            dataElementState.config.reportingIntervalSecs, 0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions
//////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Read String configuration parameters from the config framework.
 *
 * @param [in] configElement  the config element to read from config framework
 * @param [out] configFileName  returns config file name read for configElement
 *
 * @return DE_OK if all parameter read correctly; DE_NOK if it fails
 */
DE_STATUS dataElementsParseStringConfig(const char *configElement, char *configFileName) {
    const char *fileName =
        profileGetOpts(DE_CONFIG_SECTION, configElement, dataElementDefaultTable);

    if (!fileName) {
        dataElementDebug(DBGERR, "%s: failed to get Json File Path config parameter", __func__);
        return DE_NOK;
    }

    if (strlen(fileName) > DATA_ELEMENTS_FILE_NAME_LENGTH) {
        dataElementDebug(DBGERR, "%s: Enter a file name with length less than %d", __func__,
                         DATA_ELEMENTS_FILE_NAME_LENGTH);
        return DE_NOK;
    }

    memcpy(configFileName, fileName, strlen(fileName));
    free((void *)fileName);

    return DE_OK;
}

/**
 * @brief Read all configuration parameters from the config framework.
 *
 * @return DE_OK if all parameters are valid; DE_NOK if there is some
 *         problem in the configuration (after logging it)
 */
static DE_STATUS dataElementReadConfig(void) {
    dataElementState.config.reportingIntervalSecs = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_JSON_REPORTING_INTERVAL,
        dataElementDefaultTable);

    dataElementState.config.enableRadioObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioCapsObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_CAPS_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioBssListObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_BSS_LIST_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioBkStaObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_BACKHAUL_STA_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioScanResultObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_SCAN_RESULT_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioUnAssocStaObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_UNASSOC_STA_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableRadioCurOpClassObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_RADIO_CUR_OP_CLASS_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableBssStaListObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_BSS_STA_LIST_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableStaAssocEventObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_STA_ASSOC_EVENT_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.enableStaDisAssocEventObject = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_STA_DISASSOC_EVENT_JSON_ENABLE,
        dataElementDefaultTable);

    dataElementState.config.isSingleAP = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_IS_SINGLE_AP, dataElementDefaultTable);

    dataElementState.config.isMAP = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_IS_MAP, dataElementDefaultTable);

    dataElementState.config.isSON = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_IS_SON, dataElementDefaultTable);

    dataElementState.config.enableb64Enc = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_ENABLE_BASE64_ENCODING, dataElementDefaultTable);

    dataElementState.config.enableCertCompliance = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_ENABLE_CERT, dataElementDefaultTable);

    dataElementState.config.NBEventEnable = profileGetOptsInt(
        DE_CONFIG_SECTION, DE_ENABLE_NB_EVENTS, dataElementDefaultTable);

    if (dataElementsParseStringConfig(DE_JSON_FILE_PATH, dataElementState.config.jsonFileName) ==
        DE_NOK) {
        dataElementDebug(DBGERR, "%s: Failed to parse json file name \n",__func__);
        return DE_NOK;
    }

    if (dataElementState.config.isMAP || dataElementState.config.isSON) {
        dataElementState.isMultiAP=1;
    }

    return DE_OK;
}

DE_STATUS dataElementFini(int sock) {
//    evloopTimeoutUnregister(&dataElementState.jsonReportTimer);
    if ( sock != -1){
        close(sock);
    }
    return DE_OK;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Lifecycle functions
//////////////////////////////////////////////////////////////////////////////////////////////////

int dataElementsInit(void) {
    int sock=-1;

    dataElementState.dbgModule = dbgModuleFind("dataElement");
    dataElementState.dbgModule->Level = DBGINFO;

    /// First Read the Config parameters
    if (dataElementReadConfig() != DE_OK) {
        dataElementDebug(DBGERR, "%s: Config file Failed \n",__func__);
        return DE_NOK;
    }

    gettimeofday(&dataElementState.initTime, NULL);
    dataElementState.isRunning = 0;
    dataElementState.isStatsOnly = 0;

    if ((sock = create_server_socket()) == -1) {
        dataElementDebug(DBGERR, "%s: North Bound Socket creation failed \n",__func__);
        dataElementFini(sock);
        return DE_NOK;
    }

    if (dataElementState.config.isSingleAP) {
        if (dataElementWlanInit() != DE_OK) {
            dataElementDebug(DBGERR, "%s: WLAN init failed aborting \n",__func__);
            return DE_NOK;
        }
        dataElementDebug(DBGINFO, "%s: dataElementWlan init successful",__func__);
    } else if (dataElementState.config.isMAP || dataElementState.config.isSON){
        if (dataElementHydInit() != DE_OK) {
            dataElementDebug(DBGERR,  "%s: HYD init failed aborting \n",__func__);
            return DE_NOK;
        }
        if(dERequestEventsEnable() != DE_OK) {
            dataElementDebug(DBGERR,  "%s: DE Events Enable failed \n",__func__);
        }
        if (dataElementState.config.NBEventEnable) {
           if(dERequestNbEventsEnableData() != DE_OK) {
               dataElementDebug(DBGERR,  "%s: North Bound Events Enable failed \n",__func__);
           }
        }
        dataElementDebug(DBGINFO, "%s: dataElementHyd init successful",__func__);
    } else {
        dataElementFini(sock);
        dataElementDebug(DBGERR, "%s: DataElement invalid mode init fail \n",__func__);
        return DE_NOK;
    }

    /// Neighbour scan Timer
    evloopTimeoutCreate(&dataElementState.neighbourScanTimer, "dENeighbourScanTimer",
            dENeighbourScanTimeoutHandler, NULL);
    evloopTimeoutRegister(&dataElementState.neighbourScanTimer,
            (dataElementState.config.reportingIntervalSecs - 15), 0);
    /// Register JSON Timer
    evloopTimeoutCreate(&dataElementState.jsonReportTimer, "dEJsonReportingTimer",
            dEJSONReportingTimeoutHandler, NULL);
    evloopTimeoutRegister(&dataElementState.jsonReportTimer,
            dataElementState.config.reportingIntervalSecs, 0);

    return DE_OK;
}

