/* @File: apac_hyfi20_wps.c
 * @Notes:
 *
 * Copyright (c) 2011-2012, 2018-2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011-2012 Qualcomm Atheros, Inc.
 *
 * Qualcomm Atheros Confidential and Proprietary.
 * All rights reserved.
 *
 */

/**************************************************************************

Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
   * Neither the name of Sony Corporation nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <netinet/ether.h>
#include "common.h"
#include "defs.h"
#include "wps_parser.h"
#include "wsplcd.h"
#include "wps_config.h"

#include "apac_priv.h"
#include "apac_hyfi20_mib.h"
#include "storage.h"
#include "wlanif_cmn.h"
#if MAP_ENABLED
#include "apac_map.h"
#endif

#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#undef QCA_MOD_INPUT
#define QCA_MOD_INPUT QCA_MOD_WSPLCD
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */

extern struct wlanif_config *wlanIfWd;
#if HYFI10_COMPATIBLE
const struct apac_mib_param_set apac_clone_sets[] =
{
    { "RADIO",   APCLONE_TYPE_RADIO,         WPS_VALTYPE_PTR},
    { "BSS", APCLONE_TYPE_BSS,           WPS_VALTYPE_PTR},
    { NULL, 0, 0},
};

const struct apac_mib_param_set apac_radio_sets[] =
{
    { "Channel",                        RADIO_TYPE_CHANNEL,             WPS_VALTYPE_U32},
    { "RadioEnabled",                   RADIO_TYPE_RADIOENABLED,        WPS_VALTYPE_BOOL},
    { "X_ATH-COM_Powerlevel",           RADIO_TYPE_POWERLEVEL,          WPS_VALTYPE_ENUM},
    { "X_ATH-COM_Rxchainmask",          RADIO_TYPE_RXCHAINMASK,         WPS_VALTYPE_U32},
    { "X_ATH-COM_Txchainmask",          RADIO_TYPE_TXCHAINMASK,         WPS_VALTYPE_U32},
    { "X_ATH-COM_TBRLimit",             RADIO_TYPE_TBRLIMIT,            WPS_VALTYPE_U32},
    { "X_ATH-COM_AMPDUEnabled",         RADIO_TYPE_AMPDUENABLED,        WPS_VALTYPE_BOOL},
    { "X_ATH-COM_AMPDULimit",           RADIO_TYPE_AMPDULIMIT,          WPS_VALTYPE_U32},
    { "X_ATH-COM_AMPDUFrames",          RADIO_TYPE_AMPDUFRAMES,         WPS_VALTYPE_U32},
    { "macaddr",                        RADIO_TYPE_MACADDRESS,          WPS_VALTYPE_PTR},
    { NULL, 0, 0},
};
#endif

const struct apac_mib_param_set apac_bss_sets[] =
{
    { "Enable",                         BSS_TYPE_ENABLE,                WPS_VALTYPE_BOOL},
    { "X_ATH-COM_RadioIndex",           BSS_TYPE_RADIOINDEX,            WPS_VALTYPE_U32},
    { "SSID",                           BSS_TYPE_SSID,                  WPS_VALTYPE_PTR},
    { "BeaconType",                     BSS_TYPE_BEACONTYPE,            WPS_VALTYPE_ENUM},
    { "Standard",                       BSS_TYPE_STANDARD,              WPS_VALTYPE_ENUM},
    { "WEPKeyIndex",                    BSS_TYPE_WEPKEYINDEX,           WPS_VALTYPE_U32},
    { "KeyPassphrase",                  BSS_TYPE_KEYPASSPHRASE,         WPS_VALTYPE_PTR},
    { "BasicEncryptionModes",           BSS_TYPE_BASIC_ENCRYPTIONMODE,  WPS_VALTYPE_ENUM},
    { "BasicAuthenticationMode",        BSS_TYPE_BASIC_AUTHMODE,        WPS_VALTYPE_ENUM},
    { "WPAEncryptionModes",             BSS_TYPE_WPA_ENCRYPTIONMODE,    WPS_VALTYPE_ENUM},
    { "WPAAuthenticationMode",          BSS_TYPE_WPA_AUTHMODE,          WPS_VALTYPE_ENUM},
    { "IEEE11iEncryptionModes",         BSS_TYPE_11I_ENCRYPTIONMODE,    WPS_VALTYPE_ENUM},
    { "IEEE11iAuthenticationMode",      BSS_TYPE_11I_AUTHMODE,          WPS_VALTYPE_ENUM},
#if GATEWAY_WLAN_WAPI
    { "WAPIAuthenticationMode",         BSS_TYPE_WAPI_AUTHMODE,         WPS_VALTYPE_ENUM},
    { "WAPIPSKType",                    BSS_TYPE_WAPI_PSKTYPE,          WPS_VALTYPE_ENUM},
    { "WAPIPreAuth",                    BSS_TYPE_WAPI_PREAUTH,          WPS_VALTYPE_BOOL},
    { "WAPIPSK",                        BSS_TYPE_WAPI_PSK,              WPS_VALTYPE_PTR},
    { "WAPICertContent",                BSS_TYPE_WAPI_CERTCONTENT,      WPS_VALTYPE_PTR},
    { "WAPICertIndex",                  BSS_TYPE_WAPI_CERTINDEX,        WPS_VALTYPE_ENUM},
    { "WAPICertStatus",                 BSS_TYPE_WAPI_CERTSTATUS,       WPS_VALTYPE_ENUM},
    { "WAPICertMode",                   BSS_TYPE_WAPI_CERTMODE,         WPS_VALTYPE_ENUM},
    { "WAPIASUAddress",                 BSS_TYPE_WAPI_ASUADDRESS,       WPS_VALTYPE_PTR},
    { "WAPIASUPort",                    BSS_TYPE_WAPI_ASUPORT,          WPS_VALTYPE_U32},
    { "WAPIUcastRekeyTime",             BSS_TYPE_WAPI_UCASTREKEYTIME,   WPS_VALTYPE_U32},
    { "WAPIUcastRekeyPacket",           BSS_TYPE_WAPI_UCASTREKEYPACKET, WPS_VALTYPE_U32},
    { "WAPIMcastRekeyTime",             BSS_TYPE_WAPI_MCASTREKEYTIME,   WPS_VALTYPE_U32},
    { "WAPIMcastRekeyPacket",           BSS_TYPE_WAPI_MCASTREKEYPACKET, WPS_VALTYPE_U32},
#endif
    { "BasicDataTransmitRates",         BSS_TYPE_BASIC_DATA_TXRATES,    WPS_VALTYPE_PTR},
    { "RTS",                            BSS_TYPE_RTS,                   WPS_VALTYPE_PTR},
    { "Fragmentation",                  BSS_TYPE_FRAGMENTATION,         WPS_VALTYPE_PTR},
    { "AuthenticationServiceMode",      BSS_TYPE_AUTH_SERVICE_MODE,     WPS_VALTYPE_ENUM},
    { "X_ATH-COM_EAPReauthPeriod",      BSS_TYPE_EAP_REAUTH_PERIOD,     WPS_VALTYPE_ENUM},
    { "X_ATH-COM_WEPRekeyPeriod",       BSS_TYPE_WEP_REKEY_PERIOD,      WPS_VALTYPE_U32},
    { "X_ATH-COM_AuthServerAddr",       BSS_TYPE_AUTH_SERVER_ADDR,      WPS_VALTYPE_PTR},
    { "X_ATH-COM_AuthServerPort",       BSS_TYPE_AUTH_SERVER_PORT,      WPS_VALTYPE_U32},
    { "X_ATH-COM_AuthServerSecret",     BSS_TYPE_AUTH_SERVER_SECRET,    WPS_VALTYPE_PTR},
    { "X_ATH-COM_RSNPreAuth",           BSS_TYPE_RSN_PREAUTH,           WPS_VALTYPE_BOOL},
    { "X_ATH-COM_SSIDHide",             BSS_TYPE_SSID_HIDE,             WPS_VALTYPE_BOOL},
    { "X_ATH-COM_APModuleEnable",       BSS_TYPE_APMODULE_ENABLE,       WPS_VALTYPE_BOOL},
    { "X_ATH-COM_WPSPin",               BSS_TYPE_WPS_PIN,               WPS_VALTYPE_PTR},
    { "X_ATH-COM_WPSConfigured",        BSS_TYPE_WPS_CONFIGURED,        WPS_VALTYPE_ENUM},
    { "X_ATH-COM_ShortGI",              BSS_TYPE_SHORT_GI,              WPS_VALTYPE_BOOL},
    { "X_ATH-COM_CWMEnable",            BSS_TYPE_CWM_ENABLE,            WPS_VALTYPE_BOOL},
    { "X_ATH-COM_WMM",                  BSS_TYPE_WMM,                   WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HT40Coexist",          BSS_TYPE_HT40COEXIST,           WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HBREnable",            BSS_TYPE_HBRENABLE,             WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HBRPERLow",            BSS_TYPE_HBRPERLOW,             WPS_VALTYPE_U32},
    { "X_ATH-COM_HBRPERHigh",           BSS_TYPE_HBRPERHIGH,            WPS_VALTYPE_U32},
    { "X_ATH-COM_MEMode",               BSS_TYPE_MEMODE,                WPS_VALTYPE_ENUM},
    { "X_ATH-COM_MELength",             BSS_TYPE_MELENGTH,              WPS_VALTYPE_U32},
    { "X_ATH-COM_METimer",              BSS_TYPE_METIMER,               WPS_VALTYPE_U32},
    { "X_ATH-COM_METimeout",            BSS_TYPE_METIMEOUT,             WPS_VALTYPE_U32},
    { "X_ATH-COM_MEDropMcast",          BSS_TYPE_MEDROPMCAST,           WPS_VALTYPE_BOOL},
    { "WEPKey.1.WEPKey",                BSS_TYPE_WEPKEY_1,              WPS_VALTYPE_PTR},
    { "WEPKey.2.WEPKey",                BSS_TYPE_WEPKEY_2,              WPS_VALTYPE_PTR},
    { "WEPKey.3.WEPKey",                BSS_TYPE_WEPKEY_3,              WPS_VALTYPE_PTR},
    { "WEPKey.4.WEPKey",                BSS_TYPE_WEPKEY_4,              WPS_VALTYPE_PTR},
    { "DeviceOperationMode",            BSS_TYPE_DEV_OPMODE,            WPS_VALTYPE_PTR},
    { "X_ATH-COM_GroupRekeyPeriod",     BSS_TYPE_GROUP_REKEY_PERIOD,    WPS_VALTYPE_PTR},
    { "PreSharedKey.1.PreSharedKey",    BSS_TYPE_PRESHARED_KEY,         WPS_VALTYPE_PTR},
    { "WsplcdUnmanaged",                BSS_TYPE_WSPLCD_UNMANAGED,      WPS_VALTYPE_BOOL},
    { "Network",                        BSS_TYPE_NETWORK,               WPS_VALTYPE_PTR},
    { "backhaul_ap",                    BSS_TYPE_BACKHAUL_AP,           WPS_VALTYPE_U32},
    { "SteeringDisabled",               BSS_TYPE_DISABLE_STEER,         WPS_VALTYPE_U32},
    { "SAEPWE",                         BSS_TYPE_SAE_PWE,               WPS_VALTYPE_U8},
    { "SAEEn6GSecComp",                 BSS_TYPE_SAE_EN_6G_SEC_COMP,    WPS_VALTYPE_U8},
    { NULL, 0, 0},
};

#if SON_ENABLED
const struct apac_mib_param_set apac_wpa3_param_sets[] =
{
    { "EnableSAE",                      BSS_TYPE_WPA3_SAE,              WPS_VALTYPE_U8},
    { "SAEPassword",                    BSS_TYPE_WPA3_SAE_PASSWORD,     WPS_VALTYPE_PTR},
    { "SAEAntiCloggingThreshold",       BSS_TYPE_WPA3_SAE_ANTI_CLOG_THRES,   WPS_VALTYPE_U32},
    { "SAESync",                        BSS_TYPE_WPA3_SAE_SYNC,         WPS_VALTYPE_U32},
    { "SAEGroups",                      BSS_TYPE_WPA3_SAE_GROUPS,       WPS_VALTYPE_PTR},
    { "SAERequireMFP",                  BSS_TYPE_WPA3_SAE_REQUIRE_MFP,  WPS_VALTYPE_U8},
    { "EnableOWE",                      BSS_TYPE_WPA3_OWE,              WPS_VALTYPE_U8},
    { "OWEGroups",                      BSS_TYPE_WPA3_OWE_GROUPS,       WPS_VALTYPE_PTR},
    { "OWETransIfname",                 BSS_TYPE_WPA3_OWE_TRANS_IF,     WPS_VALTYPE_PTR},
    { "OWETransSSID",                   BSS_TYPE_WPA3_OWE_TRANS_SSID,   WPS_VALTYPE_PTR},
    { "OWETransBSSID",                  BSS_TYPE_WPA3_OWE_TRANS_BSSID,  WPS_VALTYPE_PTR},
    { "SuiteB",                         BSS_TYPE_WPA3_SUITE_B,          WPS_VALTYPE_U8},
    { "IEEE80211w",                     BSS_TYPE_IEEE80211W,            WPS_VALTYPE_U8},
    { "X_ATH-COM_AuthServerAddr",       BSS_TYPE_AUTH_SERVER_ADDR,      WPS_VALTYPE_PTR},
    { "X_ATH-COM_AuthServerPort",       BSS_TYPE_AUTH_SERVER_PORT,      WPS_VALTYPE_U32},
    { "X_ATH-COM_AuthServerSecret",     BSS_TYPE_AUTH_SERVER_SECRET,    WPS_VALTYPE_PTR},
    { "X_ATH-COM_SSIDHide",             BSS_TYPE_SSID_HIDE,             WPS_VALTYPE_BOOL},
    { "X_ATH-COM_NASID",                BSS_TYPE_NASID,                 WPS_VALTYPE_PTR},
    { "SAEPWE",                         BSS_TYPE_SAE_PWE,               WPS_VALTYPE_U8},
    { "SAEEn6GSecComp",                 BSS_TYPE_SAE_EN_6G_SEC_COMP,    WPS_VALTYPE_U8},
    { NULL, 0, 0},
};
#endif

#if MAP_ENABLED
const struct apac_mib_param_set apac_wpa3_param_map_sets[] =
{
    { "EnableSAE",                      BSS_TYPE_WPA3_SAE,              WPS_VALTYPE_U8},
    { "SAEPassword",                    BSS_TYPE_WPA3_SAE_PASSWORD,     WPS_VALTYPE_PTR},
    { "SAEAntiCloggingThreshold",       BSS_TYPE_WPA3_SAE_ANTI_CLOG_THRES,   WPS_VALTYPE_U32},
    { "SAESync",                        BSS_TYPE_WPA3_SAE_SYNC,         WPS_VALTYPE_U32},
    { "SAEGroups",                      BSS_TYPE_WPA3_SAE_GROUPS,       WPS_VALTYPE_PTR},
    { "SAERequireMFP",                  BSS_TYPE_WPA3_SAE_REQUIRE_MFP,  WPS_VALTYPE_U8},
    { NULL, 0, 0},
};

const struct apac_mib_param_set apac_qca_param_map_sets[] =
{
    { "SteeringDisabled",               BSS_TYPE_DISABLE_STEER,         WPS_VALTYPE_U32},
    { NULL, 0, 0},
};
#endif

#if SON_ENABLED
const struct apac_mib_param_set apac_wpa3_param_sae_password_set[] =
{
    { "SAEPassword",                    BSS_TYPE_WPA3_SAE_PASSWORD,     WPS_VALTYPE_PTR},
    { NULL, 0, 0},
};

const struct apac_mib_param_set apac_wpa3_param_sae_groups_set[] =
{
    { "SAEGroups",                    BSS_TYPE_WPA3_SAE_GROUPS,     WPS_VALTYPE_PTR},
    { NULL, 0, 0},
};

const struct apac_mib_param_set apac_wpa3_param_owe_groups_set[] =
{
    { "OWEGroups",                    BSS_TYPE_WPA3_OWE_GROUPS,     WPS_VALTYPE_PTR},
    { NULL, 0, 0},
};

const struct apac_mib_param_set apac_dpcloning_sets[] =
{
    { "Standard",                       BSS_TYPE_STANDARD,              WPS_VALTYPE_ENUM},
    { "Channel",                        BSS_TYPE_CHANNEL,               WPS_VALTYPE_U32},
    { "BSSID",                          BSS_TYPE_BSSID  ,               WPS_VALTYPE_PTR},
    { "BasicDataTransmitRates",         BSS_TYPE_BASIC_DATA_TXRATES,    WPS_VALTYPE_PTR},
    { "RTS",                            BSS_TYPE_RTS,                   WPS_VALTYPE_PTR},
    { "Fragmentation",                  BSS_TYPE_FRAGMENTATION,         WPS_VALTYPE_PTR},
    { "X_ATH-COM_ShortGI",              BSS_TYPE_SHORT_GI,              WPS_VALTYPE_BOOL},
    { "X_ATH-COM_CWMEnable",            BSS_TYPE_CWM_ENABLE,            WPS_VALTYPE_BOOL},
    { "X_ATH-COM_WMM",                  BSS_TYPE_WMM,                   WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HT40Coexist",          BSS_TYPE_HT40COEXIST,           WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HBREnable",            BSS_TYPE_HBRENABLE,             WPS_VALTYPE_BOOL},
    { "X_ATH-COM_HBRPERLow",            BSS_TYPE_HBRPERLOW,             WPS_VALTYPE_U32},
    { "X_ATH-COM_HBRPERHigh",           BSS_TYPE_HBRPERHIGH,            WPS_VALTYPE_U32},
    { "X_ATH-COM_MEMode",               BSS_TYPE_MEMODE,                WPS_VALTYPE_ENUM},
    { "X_ATH-COM_MELength",             BSS_TYPE_MELENGTH,              WPS_VALTYPE_U32},
    { "X_ATH-COM_METimer",              BSS_TYPE_METIMER,               WPS_VALTYPE_U32},
    { "X_ATH-COM_METimeout",            BSS_TYPE_METIMEOUT,             WPS_VALTYPE_U32},
    { "X_ATH-COM_MEDropMcast",          BSS_TYPE_MEDROPMCAST,           WPS_VALTYPE_BOOL},
    { "backhaul_ap",                    BSS_TYPE_BACKHAUL_AP,           WPS_VALTYPE_U32},
    { "Network",                        BSS_TYPE_NETWORK,               WPS_VALTYPE_PTR},
    { "SteeringDisabled",               BSS_TYPE_DISABLE_STEER,         WPS_VALTYPE_U32},
    { NULL, 0, 0},
};
#endif


int apac_mib_get_tlv(const struct apac_mib_param_set *mibset, const char *value,  struct wps_tlv **tlv)
{
    u16 type;
    size_t length;
    Boolean b_value = FALSE;
    u8 u8_value = 0;
    u16 u16_value = 0;
    u32 u32_value = 0;
    u8 *ptr_value = 0;

    if (! mibset || !value  || !tlv)
        return -1;

    *tlv = 0;
    type = mibset->type;

    switch (mibset->value_type) {
        case WPS_VALTYPE_BOOL:
            length = 1;
            b_value = atoi(value);
            break;
        case WPS_VALTYPE_U8:
            length = 1;
            u8_value = atoi(value);
            break;
        case WPS_VALTYPE_U16:
            length = 2;
            u16_value = atoi(value);
            break;
        case WPS_VALTYPE_U32:
            length = 4;
            u32_value = atoi(value);
            break;
        case WPS_VALTYPE_PTR:
            length = strlen(value);
            ptr_value = (u8 *)malloc(length);
            if (!ptr_value)
                return -1; /* Memory allocation error */
            memcpy(ptr_value, value, length);
            break;
        default:
            return -1;
    }

    *tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
    if (0 == *tlv) {
        if (ptr_value)
            free(ptr_value);
        return -1; /* Memory allocation error */
    }

    (*tlv)->type = type;
    (*tlv)->length = length;
    (*tlv)->value_type = mibset->value_type;
    switch ((*tlv)->value_type) {
        case WPS_VALTYPE_BOOL:
            (*tlv)->value.bool_ = (u8)b_value;
            break;
        case WPS_VALTYPE_U8:
            (*tlv)->value.u8_ = u8_value;
            break;
        case WPS_VALTYPE_U16:
            (*tlv)->value.u16_ = u16_value;
            break;
        case WPS_VALTYPE_U32:
            (*tlv)->value.u32_ = u32_value;
            break;
        case WPS_VALTYPE_PTR:
            (*tlv)->value.ptr_ = ptr_value;
            break;
        default:
            return -1;
    }

    return 0;
}


static int apac_add_tlv(struct wps_data *data, struct wps_tlv *tlv)
{

    data->tlvs = (struct wps_tlv **)realloc(data->tlvs,
            sizeof(struct wps_tlv *) * (data->count + 1));

    if (!data->tlvs)
        return -1;  /* Memory allocation error */
    data->tlvs[data->count++] = tlv;

    return 0;
}


int apac_mib_parse_value(const struct apac_mib_param_set *mibset, const char *buf, size_t length, char *value, size_t size)
{
    Boolean b_value = FALSE;
    u8 u8_value = 0;
    u16 u16_value = 0;
    u32 u32_value = 0;

    if (! mibset || !buf )
        return -1;

    switch (mibset->value_type) {
        case WPS_VALTYPE_BOOL:
            b_value = *(Boolean*)buf;
            length = snprintf(value, size, "%u", b_value);
            break;
        case WPS_VALTYPE_U8:
            u8_value = *(u8*)buf;
            length = snprintf(value, size, "%u", u8_value);
            break;
        case WPS_VALTYPE_U16:
            u16_value = *(u16*)buf;
            length = snprintf(value, size, "%u", u16_value);
            break;
        case WPS_VALTYPE_U32:
            u32_value = *(u32*)buf;
            length = snprintf(value, size, "%u", u32_value);
            break;
        case WPS_VALTYPE_PTR:
            memcpy(value, buf, length);
            value[length] = '\0';
            break;
        default:
            return -1;
    }

    return 0;
}


/*
 * open configuration file to read wlan setting parameters
*/
int apac_mib_get_object(char * path, struct wps_data *data, const struct apac_mib_param_set * mibsets)
{
    char *fname = g_cfg_file;
    const struct apac_mib_param_set * mibset;
    FILE *f;
    char mibpath[256];
    char buf[256];
    char *tag;
    char *value;
    int  param_num = 0;

    /*Open config file*/
    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR, "%s, couldn't open configuration file: '%s'. \n", __func__, fname);
        return -1;
    }

    /*get the line from config file by path and name,
      and copy value string*/
    while (fgets(buf, sizeof(buf), f) != NULL) {
        tag = apac_config_line_lex(buf, &value);

        if (tag == NULL || *tag == 0) {
            continue;
        }

        mibset = mibsets;

        while(mibset && mibset->name) {
            struct wps_tlv *tlv;

            snprintf(mibpath, sizeof(mibpath), "%s.%s", path, mibset->name);

            if (strcmp(mibpath, tag) == 0) {

                if(apac_mib_get_tlv(mibset, value ,& tlv) < 0)
                {
                    dprintf(MSG_ERROR, "Fails: Path [%s], value [%s]\n", path, value);
                    break;
                }

                apac_add_tlv(data,  tlv);
                param_num ++;
                break;
            }
            mibset ++;
        }
    }

    /*Close config file*/
    fclose(f);

    if (param_num > 0)
        return 0;
    else
        return -1;
}

#if HYFI10_COMPATIBLE
int apac_mib_set_object(char * path, struct wps_data *data, const struct apac_mib_param_set * mibsets)
{
    void *mibHandle = NULL;
    int fail = 0;
    char  mibpath[256];
    char buf[4096];
    size_t len;
    char *value;

    apacHyfi20TRACE();

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    while(mibsets && mibsets->name)
    {
        len = sizeof(buf);
        if (wps_get_value(data, mibsets->type, buf, &len)==0) {
            value = (char *)malloc(len + 32);
            if( value == NULL || apac_mib_parse_value(mibsets, buf, len, value, len + 32) != 0) {
                dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
                mibsets++;
                continue;
            }
            snprintf(mibpath, sizeof(mibpath), "%s.%s", path, mibsets->name);
            storage_setParam(mibHandle,mibpath,value);

            free (value);
            value = 0;

        }
        else
            dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);

        mibsets ++;
    }

    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail) {
        dprintf(MSG_ERROR, "failed when set:%s, restarting wsplcd daemon!\n",path);
        shutdown_fatal();
    }

    return fail;

}

int apac_mib_update_credential(struct wps_credential* cred)
{
    void *mibHandle = NULL;
    int fail = 0;
    char path[128];
    char value[128];
    int i;
    char *root = CONFIG_WLAN"1.";

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    if (!cred || strlen((char *)cred->ssid) ==0)
        return -1;

    /*set SSID*/
    snprintf(path, sizeof(path), "%s%s", root, "SSID");
    storage_setParam(mibHandle,path,(char*)cred->ssid);

    if (cred->auth_type & WPS_AUTHTYPE_WPA2PSK) {
        /*WPA2PSK or WPA2PSK/WPAPSK*/
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
        if (cred->auth_type & WPS_AUTHTYPE_WPAPSK) {
            snprintf(value, sizeof(value), "%s", "WPAand11i");
        } else {
            snprintf(value, sizeof(value), "%s", "11i");
        }
        storage_setParam(mibHandle,path,value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iAuthenticationMode");
        snprintf(value, sizeof(value),  "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
        if (cred->encr_type & WPS_ENCRTYPE_AES) {
            if (cred->encr_type & WPS_ENCRTYPE_TKIP) {
                snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
            } else {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
        } else {
            snprintf(value, sizeof(value), "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value);

        /*set PSK or passphrase*/
        snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
        if (cred->key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)cred->key);
        }
        else
        {
            storage_setParam(mibHandle,path,"");
            snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
            storage_setParam(mibHandle,path,(char*)cred->key);
        }

    }
    else if (cred->auth_type & WPS_AUTHTYPE_WPAPSK) {
        /*WPAPSK*/
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
        snprintf(value, sizeof(value), "%s", "WPA");
        storage_setParam(mibHandle,path,value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%s", root, "WPAAuthenticationMode");
        snprintf(value, sizeof(value), "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "WPAEncryptionModes");
        if (cred->encr_type & WPS_ENCRTYPE_AES) {
            if (cred->encr_type & WPS_ENCRTYPE_TKIP) {
                snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
            } else {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
        } else {
            snprintf(value, sizeof(value), "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value);

        /*set PSK or passphrase*/
        snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
        if (cred->key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)cred->key);
        }
        else
        {
            storage_setParam(mibHandle,path,"");
            snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
            storage_setParam(mibHandle,path,(char*)cred->key);
        }

    }
    else if ((cred->auth_type & WPS_AUTHTYPE_OPEN)
            || (cred->auth_type & WPS_AUTHTYPE_SHARED)) {
        /*WEP or OPEN*/
        if (cred->encr_type & WPS_ENCRTYPE_WEP) {
            /*WEP*/
            /*set beacon type*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "Basic");
            storage_setParam(mibHandle,path,value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "BasicEncryptionModes");
            snprintf(value, sizeof(value), "%s", "WEPEncryption");
            storage_setParam(mibHandle,path,value);

            /*set auth type*/
            snprintf(path, sizeof(path), "%s%s", root, "BasicAuthenticationMode");
            if (cred->auth_type & WPS_AUTHTYPE_SHARED) {
                snprintf(value, sizeof(value), "%s", "SharedAuthentication");
            } else {
                snprintf(value, sizeof(value), "%s", "None");
            }
            storage_setParam(mibHandle,path,value);

            /*set wep key idx*/
            snprintf(path, sizeof(path), "%s%s", root, "WEPKeyIndex");
            snprintf(value, sizeof(value), "%d", cred->key_idx);
            storage_setParam(mibHandle,path,value);

            for (i = 1; i <= 4; i ++) {
                /*set wep keys*/
                snprintf(path, sizeof(path), "%sWEPKey.%d.WEPKey", root, i);
                if (i == cred->key_idx)
                    storage_setParam(mibHandle,path,(char*)cred->key);
                else
                    storage_setParam(mibHandle,path,"");
            }
        }
        else {
            /*OPEN*/
            /*set beacon type*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "None");
            storage_setParam(mibHandle,path,value);
        }
    }

    /*set authentication server mode to none*/
    snprintf(path, sizeof(path), "%s%s", root, "AuthenticationServiceMode");
    snprintf(value, sizeof(value), "%s", "None");
    storage_setParam(mibHandle,path,value);

    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail)
    {
        dprintf(MSG_ERROR, "failed when set:%s, restarting wsplcd daemon!\n", root);
        shutdown_fatal();
    }

    return fail;
}
#endif

static const struct apac_mib_param_set *apac_match_tlv(
        const u16 type, const size_t length, const struct apac_mib_param_set *parse_table)
{
    const struct apac_mib_param_set *set = parse_table;

    while (set->type) {
        if ((set->type & APCLONE_TYPE_MASK) &&
                (set->type == (type & APCLONE_TYPE_MASK)))
            break;

        if (type == set->type)
            break;

        set++;
    }

    if (!set->type)
        return 0;   /* Invalidate tlv */

    return set;
}


static int apac_parse_tlv(const u8 *buf, size_t len,
        struct wps_tlv **tlv, const struct apac_mib_param_set *parse_table)
{
    const u8 *pos = buf;
    const struct apac_mib_param_set *set;
    u16 type;
    size_t length;
    Boolean b_value = FALSE;
    u8 u8_value = 0;
    u16 u16_value = 0;
    u32 u32_value = 0;
    u8 *ptr_value = 0;

    if (!buf || 4 > len || !tlv)
        return -1;

    *tlv = 0;

    type = WPA_GET_BE16(pos);
    length = WPA_GET_BE16(pos+2);

    set = apac_match_tlv(type, length, parse_table);
    if (!set)
        return -1;  /* Invalidate tlv */

    if (length + 4 > len)
        return -1;  /* Buffer too short */

    switch (set->value_type) {
        case WPS_VALTYPE_BOOL:
            if (length != 1)
                return -1;
            b_value = (Boolean)*(pos+4);
            break;
        case WPS_VALTYPE_U8:
            if (length != 1)
                return -1;
            u8_value = *(pos+4);
            break;
        case WPS_VALTYPE_U16:
            if (length != 2)
                return -1;
            u16_value = WPA_GET_BE16(pos+4);
            break;
        case WPS_VALTYPE_U32:
            if (length != 4)
                return -1;
            u32_value = WPA_GET_BE32(pos+4);
            break;
        case WPS_VALTYPE_PTR:
            ptr_value = (u8 *)os_malloc(length);
            if (!ptr_value)
                return -1; /* Memory allocation error */
            os_memcpy(ptr_value, pos+4, length);
            break;
        default:
            return -1;
    }

    *tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
    if (0 == *tlv) {
        if (ptr_value) {
            os_free(ptr_value);
            ptr_value = NULL;
        }
        return -1; /* Memory allocation error */
    }

    (*tlv)->type = type;
    (*tlv)->length = length;
    (*tlv)->value_type = set->value_type;
    switch ((*tlv)->value_type) {
        case WPS_VALTYPE_BOOL:
            (*tlv)->value.bool_ = (u8)b_value;
            break;
        case WPS_VALTYPE_U8:
            (*tlv)->value.u8_ = u8_value;
            break;
        case WPS_VALTYPE_U16:
            (*tlv)->value.u16_ = u16_value;
            break;
        case WPS_VALTYPE_U32:
            (*tlv)->value.u32_ = u32_value;
            break;
        case WPS_VALTYPE_PTR:
            (*tlv)->value.ptr_ = ptr_value;
            break;
        default:
            return -1;
    }

    return 0;
}


#if HYFI10_COMPATIBLE
static int apac_add_wps_data(struct wps_data *data, u16 type, u8 *buf, size_t length)
{

    struct wps_tlv *tlv;
    tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
    if (0 == tlv) {
        free (buf);
        return -1;
    }

    tlv->type = type;
    tlv->length = length;
    tlv->value_type = WPS_VALTYPE_PTR;
    tlv->value.ptr_ = (u8*)buf;
    apac_add_tlv(data,  tlv);

    return 0;
}
#endif


int apac_parse_wps_data(const u8 *buf, size_t len,
        struct wps_data *data, const struct apac_mib_param_set *parse_table)
{
    const u8 *pos = buf;
    const u8 *end = buf + len;
    struct wps_tlv *tlv;

    if (!buf || 4 > len || !data) {
        dprintf(MSG_ERROR, "!buf || 4 > len || !data\n");
        return -1;
    }

    data->count = 0;
    while (pos + 4 <= end) {
        if (0 != apac_parse_tlv(pos, end - pos, &tlv, parse_table))
        {
            dprintf(MSG_ERROR, "Unknown mib type %d, length %d\n",  WPA_GET_BE16(pos), WPA_GET_BE16(pos+2));
            pos += 4 + WPA_GET_BE16(pos+2);
            continue;
        }
        apac_add_tlv(data, tlv);

        pos += 4 + tlv->length;
    }

    return 0;
}


int apac_get_mib_data_in_wpsdata(char * path, const struct apac_mib_param_set * mibsets,
        struct wps_data *data, size_t *length)
{
    if(apac_mib_get_object(path, data, mibsets) != 0)
    {
        dprintf(MSG_ERROR, "%s - failed to get mib_object[%s]\n", __func__, path);
        return -1;
    }

    return 0;

}


int apac_get_mib_data(char * path, const struct apac_mib_param_set * mibsets, u8 **buf, size_t *length)
{
    struct wps_data *data;
    int ret;

    if(wps_create_wps_data(&data) < 0)
        return -1;

    if(apac_mib_get_object(path, data, mibsets) != 0)
    {
        dprintf(MSG_ERROR, "%s, error in apac_mib_get_object! path: %s\n", __func__, path);
        wps_destroy_wps_data(&data);
        return -1;
    }

    ret = wps_write_wps_data(data, buf, length);

    wps_destroy_wps_data(&data);

    return ret;

}

#if HYFI10_COMPATIBLE
static int apac_set_mib_data(char * path, const struct apac_mib_param_set * mibsets,
        struct wps_data *data, u16 type, int dyn_obj)
{

    struct wps_data *wlan_data = 0;
    int local_configed = 0;
    int remote_configed = 0;
    size_t local_dlen, remote_dlen;
    u8 *local_buf = NULL;
    u8 *remote_buf = NULL;
    int ret = -1;
    char  mibpath[256];

    remote_buf= calloc(1, 4096);
    remote_dlen= 4096;
    if (!remote_buf)
    {
        dprintf(MSG_ERROR, "Malloc error\n");
        goto failure;
    }

    if(strlcpy(mibpath, path, sizeof(mibpath)) >= sizeof(mibpath)) {
        dprintf(MSG_ERROR, "%s local buffer mibpath overflow", __func__);
        goto failure;
    }

    if (apac_get_mib_data(mibpath, mibsets, &local_buf, &local_dlen) == 0)
        local_configed = 1;

    if (wps_get_value(data, type, remote_buf, &remote_dlen) ==0)
        remote_configed =1;

    if ( !local_configed && !remote_configed){
        goto success;
    } else if ( local_configed &&  !remote_configed ) {
        dprintf(MSG_INFO, "Remote doesn't have mib: %s\n",mibpath);
        if (!dyn_obj)
            goto failure;
        storage_delVAP(atoi(mibpath + strlen(CONFIG_WLAN)));
        goto success;

    } else if ( !local_configed &&  remote_configed ) {
        int obj_index;
        char* path_end;
        dprintf(MSG_INFO, "Local doesn't have mib: %s\n",mibpath);
        if (!dyn_obj)
            goto failure;

        //strip last '.' and num for path
        path_end = strrchr(mibpath,'.');
        if (path_end)
            *path_end = '\0';
        //its just a place holder , not expected to execute .
        obj_index = storage_addVAP();

        if (obj_index <=0)
        {
            dprintf(MSG_WARNING, "Can't add object %s\n",mibpath);
            goto failure;
        }
        snprintf(mibpath, sizeof(mibpath), "%s.%d", mibpath, obj_index);
        dprintf(MSG_INFO, "bss path :%s\n", mibpath);

    } else if (local_dlen == remote_dlen &&
            memcmp(local_buf, remote_buf, local_dlen) == 0) {
        dprintf(MSG_INFO, "Mib %s unchanged!\n", path);
        goto success;
    }


    if(wps_create_wps_data(&wlan_data))
        goto failure;

    if (apac_parse_wps_data((u8*)remote_buf, remote_dlen, wlan_data, mibsets))
    {
        dprintf(MSG_ERROR, "Mib %s parse error\n", mibpath);
        (void)wps_destroy_wps_data(&wlan_data);
        goto failure;
    }

    apac_mib_set_object(mibpath, wlan_data, mibsets);

    (void)wps_destroy_wps_data(&wlan_data);

success:
    ret = 0;

failure:
    if (local_buf)
        free (local_buf);
    if(remote_buf)
        free (remote_buf);
    return ret;

}


int apac_get_wlan_data(struct wps_data *data)
{
    int i;
    char  mibpath[256];
    const struct apac_mib_param_set * mibsets;
    u8 *buf;
    size_t length;


    mibsets = apac_radio_sets;
    for (i=0; i < MAX_RADIO_CONFIGURATION; i++)
    {
        snprintf(mibpath, sizeof(mibpath), CONFIG_RADIO"%d", i+1);
        if ( apac_get_mib_data(mibpath, mibsets, &buf, &length) == 0)
        {
            apac_add_wps_data(data, APCLONE_TYPE_RADIO|(u8)i, buf, length);
        }

    }

    mibsets = apac_bss_sets;

    for (i = 0; i < MAX_WLAN_CONFIGURATION; i++)
    {
        snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN"%d", i+1);
        if ( apac_get_mib_data(mibpath, mibsets, &buf, &length) == 0) {
            apac_add_wps_data(data, APCLONE_TYPE_BSS|(u8)i, buf, length);
        }
    }

    return 0;
}


int apac_set_wlan_data(struct wps_data *data)
{
    int i;

    char  mibpath[256];
    const struct apac_mib_param_set * mibsets;

    mibsets = apac_radio_sets;
    for (i=0; i < MAX_RADIO_CONFIGURATION; i++)
    {

        snprintf(mibpath, sizeof(mibpath), CONFIG_RADIO"%d", i+1);
        apac_set_mib_data(mibpath,  mibsets, data, APCLONE_TYPE_RADIO|(u8)i, 0);

    }

    mibsets = apac_bss_sets;
    for (i=0; i < MAX_WLAN_CONFIGURATION; i++)
    {
        snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN"%d", i+1);
        apac_set_mib_data(mibpath,  mibsets, data, APCLONE_TYPE_BSS|(u8)i, 1);
    }

    return 0;

}


int apac_set_clone_data(const u8 *buf, size_t len)
{

    struct wps_data *data = 0;
    int ret = -1;

    do {

        if(wps_create_wps_data(&data))
            break;

        if (apac_parse_wps_data(buf, len, data, apac_clone_sets)) {
            dprintf(MSG_ERROR, "Parse error\n");
            break;
        }

        if(apac_set_wlan_data(data))
            break;

        /*other non-wlan paramters can be handled here*/

        ret = 0;

    }while (0);

    (void)wps_destroy_wps_data(&data);

    return ret;
}

int apac_get_clone_data(char **buf, size_t* len)
{
    struct wps_data *data = 0;
    int ret = -1;

    do {
        if(wps_create_wps_data(&data))
            break;

        if (apac_get_wlan_data(data))
            break;

        /*other non-wlan paramters can be added here*/

        if (wps_write_wps_data(data, (u8**)buf, len))
            break;

        ret = 0;

    } while (0);

    (void)wps_destroy_wps_data(&data);

    return ret;

}
#endif

#if SON_ENABLED
int apac_mib_get_qca_ext(apacHyfi20AP_t* apinfo, int vap_index, int channel, u8 use_bh_standard)
{
    char path[256];
    u8 *buf;
    size_t length = 0, offset = 0;
    u8 *pos, *end;
    int hasStandard = 0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (!apinfo->qca_ext)
    {
        apinfo->qca_ext = os_malloc(1024);
        if (!apinfo->qca_ext)
        {
            dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
            return -1;
        }
        apinfo->qca_ext_len = 0;
    }

    snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

    if ( apac_get_mib_data(path, apac_dpcloning_sets, &buf, &length) != 0)
    {
        dprintf(MSG_ERROR, "QCA vendor extension - Deep cloning mib getting failed\n");
        return -1;
    }

    if (length  > 1024 - sizeof(atheros_smi_oui))
    {
        free(buf);
        dprintf(MSG_ERROR, "QCA vendor extension is over the limits MAX length [%d]\n",(s32)length);
        return -1;
    }

    os_memcpy(apinfo->qca_ext, atheros_smi_oui, sizeof(atheros_smi_oui));
    offset = sizeof(atheros_smi_oui);

    /* overwrite channel and standard */
    pos = buf;
    end = buf + length;
    while (pos + WPS_TLV_MIN_LEN <= end) {
        if (WPA_GET_BE16(pos) == BSS_TYPE_CHANNEL)
        {
            dprintf(MSG_DEBUG, "found channel %d\n", WPA_GET_BE32(pos + WPS_TLV_MIN_LEN));
            WPA_PUT_BE32(pos + WPS_TLV_MIN_LEN, channel);
        } else if (WPA_GET_BE16(pos) == BSS_TYPE_STANDARD) {
            u16 std_len = WPA_GET_BE16(pos + 2);
            // Standard needs to be updated, so it is deleted from buf
            // temporarily as buf size is fixed to fit original Standard
            // string. Overwriting directly may cause heap corruption.
            // The Standard TLV will be added to qca_ext directly later.
            memmove(pos, pos + WPS_TLV_MIN_LEN + std_len,
                    length - (pos - buf) - (WPS_TLV_MIN_LEN + std_len));
            length = length - std_len - WPS_TLV_MIN_LEN;
            end = buf + length;
            hasStandard = 1;
            // No need to move the pointer to visit next TLV
            continue;
        }
        pos += WPS_TLV_MIN_LEN + WPA_GET_BE16(pos+2);
    }

    if (hasStandard) {
        char standard_buf[APAC_STD_MAX_LEN + WPS_TLV_MIN_LEN];
        WPA_PUT_BE16(standard_buf, BSS_TYPE_STANDARD);
        if(use_bh_standard) {
            WPA_PUT_BE16(standard_buf + 2, apinfo->bh_standard_len);
            os_memcpy(standard_buf + WPS_TLV_MIN_LEN, apinfo->bh_standard,
                    apinfo->bh_standard_len);
            os_memcpy(apinfo->qca_ext + offset, standard_buf,
                    apinfo->bh_standard_len + WPS_TLV_MIN_LEN);
            offset += WPS_TLV_MIN_LEN + apinfo->bh_standard_len;
        } else {
            WPA_PUT_BE16(standard_buf + 2, apinfo->standard_len);
            os_memcpy(standard_buf + WPS_TLV_MIN_LEN, apinfo->standard,
                    apinfo->standard_len);
            os_memcpy(apinfo->qca_ext + offset, standard_buf,
                    apinfo->standard_len + WPS_TLV_MIN_LEN);
            offset += WPS_TLV_MIN_LEN + apinfo->standard_len;
        }
    }

    os_memcpy(apinfo->qca_ext + offset, buf, length);
    apinfo->qca_ext_len = offset + length;

    free(buf);
    return 0;
}

int apac_mib_get_qca_ext_channel(apacHyfi20AP_t* apinfo, int vap_index)
{
    char path[256];
    u8 *buf;
    size_t length = 0, offset = 0;
    u8 *pos, *end;
    int channel = 0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (!apinfo->qca_ext)
    {
        apinfo->qca_ext = os_malloc(1024);
        if (!apinfo->qca_ext)
        {
            dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
            return -1;
        }
        apinfo->qca_ext_len = 0;
    }

    snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

    if ( apac_get_mib_data(path, apac_dpcloning_sets, &buf, &length) != 0)
    {
        dprintf(MSG_ERROR, "QCA vendor extension - Deep cloning mib getting failed\n");
        return -1;
    }

    if (length  > 1024 - sizeof(atheros_smi_oui))
    {
        free(buf);
        dprintf(MSG_ERROR, "QCA vendor extension is over the limits MAX length [%d]\n",(s32)length);
        return -1;
    }

    os_memcpy(apinfo->qca_ext, atheros_smi_oui, sizeof(atheros_smi_oui));
    offset = sizeof(atheros_smi_oui);

    /* overwrite channel and standard */
    pos = buf;
    end = buf + length;
    while (pos + WPS_TLV_MIN_LEN <= end) {
        if (WPA_GET_BE16(pos) == BSS_TYPE_CHANNEL)
        {
            dprintf(MSG_DEBUG, "found channel %d\n", WPA_GET_BE32(pos + WPS_TLV_MIN_LEN));
            channel = WPA_GET_BE32(pos + WPS_TLV_MIN_LEN);
        }
        pos += WPS_TLV_MIN_LEN + WPA_GET_BE16(pos+2);
    }

    os_memcpy(apinfo->qca_ext + offset, buf, length);
    apinfo->qca_ext_len = offset + length;

    free(buf);
    return channel;
}

int apac_mib_get_qca_ext_wpa3(apacHyfi20AP_t* apinfo, int vap_index)
{
    char path[256];
    u8 *buf;
    size_t length = 0, dclength = 0, offset = 0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (!apinfo->qca_ext)
    {
        apinfo->qca_ext = os_malloc(1024);
        if (!apinfo->qca_ext)
        {
            dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
            return -1;
        }
        apinfo->qca_ext_len = 0;
        os_memcpy(apinfo->qca_ext, atheros_smi_oui, sizeof(atheros_smi_oui));
        offset = sizeof(atheros_smi_oui);
    }

    // data already copied as part of deep cloning is taken here
    dclength = apinfo->qca_ext_len;

    snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

    if ( apac_get_mib_data(path, apac_wpa3_param_sets, &buf, &length) != 0)
    {
        dprintf(MSG_ERROR, "QCA vendor extension - WPA3 mib getting failed\n");
        return -1;
    }

    if (length + dclength  > 1024 - sizeof(atheros_smi_oui))
    {
        free(buf);
        dprintf(MSG_ERROR, "WPA3 QCA vendor extension is over the limits MAX length [%d]\n",(s32)length);
        return -1;
    }

    os_memcpy(apinfo->qca_ext + offset + dclength , buf, length);
    apinfo->qca_ext_len = offset + dclength + length;

    free(buf);
    return 0;
}
#endif
#if MAP_ENABLED
/*
 * apac_map_parse_sae_vendor_ext - function to parse the SAE parameters
 * from Vendor extension TLV
 */
int apac_map_parse_sae_vendor_ext(apacMapAP_t* map, u8* vendor_ext, size_t len )
{
    const struct apac_mib_param_set *mibsets = apac_wpa3_param_map_sets;
    struct wps_data *wps = 0;
    char buf[1024];
    char *value = NULL;
    size_t buflen, data_len;

    if(wps_create_wps_data(&wps))
        return -1;

    if (apac_parse_wps_data(vendor_ext + 3,
                len - 3 , wps, mibsets))
    {
        dprintf(MSG_ERROR, "QCA vendor extension wpa3 parse error\n");
        (void)wps_destroy_wps_data(&wps);
        return -1;
    }

    map->sae = 0xff;
    map->sae_password_len = 0;
    map->sae_anticloggingthreshold = 0xff;
    map->sae_sync = 0xff;
    memset(map->sae_groups, 0, sizeof(map->sae_groups));
    map->sae_requireMFP = 0xff;

    while(mibsets && mibsets->name)
    {
        buflen = sizeof(buf);
        if (wps_get_value(wps, mibsets->type, buf, &buflen)!=0)
        {
            dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
            mibsets++;
            continue;

        }

        value = (char *)malloc(buflen + 32);
        if(value == NULL ||  apac_mib_parse_value(mibsets, buf, buflen, value, buflen + 32) != 0)
        {
            dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
            if(value)
            {
                free(value);
                value=NULL;
            }
            mibsets++;
            continue;
        }

        switch (mibsets->type){
            case BSS_TYPE_WPA3_SAE:
                map->sae = *buf;
                dprintf(MSG_INFO, "Receive cred EnableSAE: 0x%04x\n", map->sae);
                break;

            case BSS_TYPE_WPA3_SAE_PASSWORD:
                map->sae_password_len = MAX_PASSPHRASE_LEN ;
                strlcpy(map->sae_password, value,map->sae_password_len);
                map->sae_password[map->sae_password_len] = '\0';
                dprintf(MSG_INFO, "Receive cred SAEPassword: '%s',length: %d\n", map->sae_password, map->sae_password_len);
                break;

            case BSS_TYPE_WPA3_SAE_ANTI_CLOG_THRES:
                map->sae_anticloggingthreshold = *buf;
                dprintf(MSG_INFO, "Receive cred SAEAntiCloggingThreshold : 0x%04x\n", map->sae_anticloggingthreshold);
                break;

            case BSS_TYPE_WPA3_SAE_SYNC:
                map->sae_sync = *buf;
                dprintf(MSG_INFO, "Receive cred SAESync  : 0x%04x\n", map->sae_sync);
                break;

            case BSS_TYPE_WPA3_SAE_GROUPS:
                data_len = MAX_SEC_GROUPS_LEN ;
                strlcpy(map->sae_groups, value, data_len);
                map->sae_groups[data_len] = '\0';
                dprintf(MSG_INFO, "Receive cred SAEGroups: '%s',length: %d\n", map->sae_groups,(s32)data_len);
                break;

            case BSS_TYPE_WPA3_SAE_REQUIRE_MFP:
                map->sae_requireMFP = *buf;
                dprintf(MSG_INFO, "Receive cred SAE Require MFP: 0x%04x\n", map->sae_requireMFP);
                break;
        }
        free(value);
        value = 0;
        mibsets++;
    }

    (void)wps_destroy_wps_data(&wps);
    return 0;
}

/*
 * apac_map_parse_qca_vendor_ext - function to parse the qca vendor extension TLV
 */
int apac_map_parse_qca_vendor_ext(apacMapAP_t* map, u8* vendor_ext, size_t len )
{
    const struct apac_mib_param_set *mibsets = apac_qca_param_map_sets;
    struct wps_data *wps = 0;
    char buf[1024];
    char *value = NULL;
    size_t buflen;

    if(wps_create_wps_data(&wps))
        return -1;

    if (apac_parse_wps_data(vendor_ext + 3,
                len - 3 , wps, mibsets))
    {
        dprintf(MSG_ERROR, "QCA vendor extension parse error\n");
        (void)wps_destroy_wps_data(&wps);
        return -1;
    }

    map->vap_disable_steering = 0;
    while(mibsets && mibsets->name)
    {
        buflen = sizeof(buf);
        if (wps_get_value(wps, mibsets->type, buf, &buflen)!=0)
        {
            dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
            mibsets++;
            continue;

        }

        value = (char *)malloc(buflen + 32);
        if(value == NULL ||  apac_mib_parse_value(mibsets, buf, buflen, value, buflen + 32) != 0)
        {
            dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
            if(value)
            {
                free(value);
                value=NULL;
            }
            mibsets++;
            continue;
        }

        switch (mibsets->type){
            case BSS_TYPE_DISABLE_STEER:
                map->vap_disable_steering = *buf;
                dprintf(MSG_INFO, "Receive vap_disable_steering :%d\n", map->vap_disable_steering);
                break;

            default:
                dprintf(MSG_INFO, "Receive unhandled qca vendor ext param 0x%x\n",mibsets->type);
                break;
        }
        free(value);
        value = 0;
        mibsets++;
    }

    (void)wps_destroy_wps_data(&wps);
    return 0;
}

/*
 * apac_mib_get_map_qca_ext_wpa3 - function to get the WPA3 parameters from
 * mib data
 */
int apac_mib_get_map_qca_ext_wpa3(apacHyfi20AP_t* apinfo, int vap_index)
{
    char path[256];
    u8 *buf;
    size_t length = 0, offset = 0, qca_ext_length=0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    apacHyfi20TRACE();

    if (!apinfo->qca_ext)
    {
        apinfo->qca_ext = os_malloc(1024);
        if (!apinfo->qca_ext)
        {
            dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
            return -1;
        }
        apinfo->qca_ext_len = 0;
        os_memcpy(apinfo->qca_ext, atheros_smi_oui, sizeof(atheros_smi_oui));
        offset = sizeof(atheros_smi_oui);
    }

    qca_ext_length = apinfo->qca_ext_len;

    snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

    if ( apac_get_mib_data(path, apac_wpa3_param_map_sets, &buf, &length) != 0)
    {
        dprintf(MSG_ERROR, "QCA vendor extension - WPA3 mib getting failed\n");
        return -1;
    }

    if (length + qca_ext_length > (1024 - sizeof(atheros_smi_oui)))
    {
        free(buf);
        dprintf(MSG_ERROR, "WPA3 QCA vendor extension is over the limits MAX length [%d]\n",(s32)length);
        return -1;
    }

    os_memcpy(apinfo->qca_ext + offset + qca_ext_length, buf, length);
    apinfo->qca_ext_len = offset + length + qca_ext_length;

    free(buf);
    return 0;
}

/*
 * apac_mib_get_map_qca_ext - function to get the MAP qca parameters from
 * mib data
 */
int apac_mib_get_map_qca_ext(apacHyfi20AP_t* apinfo, int vap_index)
{
    char path[256];
    u8 *buf;
    size_t length = 0, offset = 0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    apacHyfi20TRACE();

    if (!apinfo->qca_ext)
    {
        apinfo->qca_ext = os_malloc(1024);
        if (!apinfo->qca_ext)
        {
            dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
            return -1;
        }
        apinfo->qca_ext_len = 0;
        os_memcpy(apinfo->qca_ext, atheros_smi_oui, sizeof(atheros_smi_oui));
        offset = sizeof(atheros_smi_oui);
    }

    snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

    if ( apac_get_mib_data(path, apac_qca_param_map_sets, &buf, &length) != 0)
    {
        dprintf(MSG_ERROR, "QCA vendor extension mib getting failed\n");
        return -1;
    }

    if (length > (1024 - sizeof(atheros_smi_oui)))
    {
        free(buf);
        dprintf(MSG_ERROR, "QCA vendor extension is over the limits MAX length [%d]\n",(s32)length);
        return -1;
    }

    os_memcpy(apinfo->qca_ext + offset , buf, length);
    apinfo->qca_ext_len = offset + length;

    free(buf);
    return 0;
}
#endif

#if SON_ENABLED
int apac_get_qca_ext_from_tlv(apacHyfi20AP_t* apinfo)
{
    const struct apac_mib_param_set *mibsets = apac_dpcloning_sets;
    char buffer[1024];
    size_t length;
    char *value = 0;
    struct wps_data *wps = 0;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (apinfo->qca_ext && apinfo->qca_ext_len) {

        if (os_memcmp(apinfo->qca_ext, atheros_smi_oui, 3) != 0)
        {
            dprintf(MSG_ERROR, "Unknown Vendor Extension %02x %02x %02x\n",
                    apinfo->qca_ext[0], apinfo->qca_ext[1], apinfo->qca_ext[2]);
            return -1;
        }

        if(wps_create_wps_data(&wps)) {
            dprintf(MSG_ERROR, "%s: WPS create data failed\n",__func__);
            return -1;
        }

        if (apac_parse_wps_data((u8*)apinfo->qca_ext + 3,
                    apinfo->qca_ext_len - 3 , wps, mibsets))
        {
            dprintf(MSG_ERROR, "QCA vendor extension parse error\n");
            wps_destroy_wps_data(&wps);
            return -1;
        }

        while(mibsets && mibsets->name)
        {
            length = sizeof(buffer);
            if (wps_get_value(wps, mibsets->type, buffer, &length)!=0)
            {
                dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
                mibsets++;
                continue;
            }

            value = (char *)malloc(length + 32);
            if(value == NULL ||  apac_mib_parse_value(mibsets, buffer, length, value, length + 32) != 0)
            {
                dprintf(MSG_ERROR, "%s: Value parse error %s\n", __func__, mibsets->name);
                mibsets++;
                continue;
            }

            switch (mibsets->type){
                case BSS_TYPE_BACKHAUL_AP:
                    apinfo->backhaul_ap = *buffer;
                    break;

                default:
                    dprintf(MSG_INFO, "%s: default\n",__func__);
            }

            free (value);
            value = 0;
            mibsets ++;
        }
    }
    wps_destroy_wps_data(&wps);
    return 0;
}

int apac_mib_set_qca_ext(void *mibHandle, apacHyfi20AP_t* apinfo, int vap_type, int vap_index,
        apacBool_e manageVAPInd, apacBool_e deepCloneNoBSSID)
{
    const struct apac_mib_param_set *mibsets = apac_dpcloning_sets;
    struct wps_data *wps = 0;
    char buf[1024];
    size_t len;
    char mibpath[256];
    char mibroot[128];
    char *value = 0;
    char bssid[20];
    int radio_index;
    char *regStd = NULL;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (os_memcmp(apinfo->qca_ext, atheros_smi_oui, 3) != 0)
    {
        dprintf(MSG_ERROR, "Unknown Vendor Extension %02x %02x %02x\n",
                apinfo->qca_ext[0], apinfo->qca_ext[1], apinfo->qca_ext[2]);
        return -1;
    }

    if(wps_create_wps_data(&wps))
        return -1;

    if (apac_parse_wps_data((u8*)apinfo->qca_ext + 3,
                apinfo->qca_ext_len - 3 , wps, mibsets))
    {
        dprintf(MSG_ERROR, "QCA vendor extension parse error\n");
        (void)wps_destroy_wps_data(&wps);
        return -1;
    }

    snprintf(mibroot, sizeof(mibroot), "%s%d.", CONFIG_WLAN, vap_index);
    memset(bssid, 0, sizeof(bssid));

    radio_index = apinfo->radio_index;
    if (radio_index < 0 )
    {
        dprintf(MSG_ERROR, "Can't get Radio Index for vap[%d]\n", vap_index);
        return -1;
    }

    while(mibsets && mibsets->name)
    {
        len = sizeof(buf);
        if (wps_get_value(wps, mibsets->type, buf, &len)!=0)
        {
            dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
            mibsets++;
            continue;

        }

        value = (char *)malloc(len + 32);
        if(value == NULL ||  apac_mib_parse_value(mibsets, buf, len, value, len + 32) != 0)
        {
            dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
            mibsets++;
            continue;
        }

        switch (mibsets->type){
            /* BSSID */
            case BSS_TYPE_BSSID:
                strlcpy(bssid, value, sizeof(bssid));
                bssid[sizeof(bssid) - 1] = '\0';

                dprintf(MSG_INFO, "Receive QCA BSSID: %s\n", bssid);
                break;

                /* Channel */
            case BSS_TYPE_CHANNEL:
                /* channel should not be modified by Guest wsplcd */
                if (!g_wsplcd_instance) {
                    apinfo->channel = *buf;
                    dprintf(MSG_INFO, "Receive QCA Channel : %s\n", value);
                    snprintf(mibpath, sizeof(mibpath), CONFIG_RADIO"%d.ClonedChannel", radio_index);
                    storage_setParam(mibHandle,mibpath,value);
                }
                break;

            case BSS_TYPE_STANDARD:
                dprintf(MSG_INFO, "Receive QCA Standard: %s\n", value);
                /* Mode should not be modified by Guest wsplcd */
                if (!g_wsplcd_instance) {
                    /* todo: if regStd is not NULL, should free it first here. */
                    regStd = strdup(value);
                    /* from passing KW check, this seems not needed */
                    if( regStd != NULL )
                        regStd[strlen(value)] = 0;
                }
                break;

            case BSS_TYPE_BACKHAUL_AP:
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, mibsets->name);
                if(vap_type == APAC_WLAN_AP) {
                    apinfo->backhaul_ap = *buf;
                    storage_setParam(mibHandle,mibpath,value);
                }
                break;

            case BSS_TYPE_NETWORK:
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "network");
                storage_setParam(mibHandle,mibpath,value);
                dprintf(MSG_INFO, "Network is: %s\n", value);
                break;

            case BSS_TYPE_DISABLE_STEER:
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SteeringDisabled");
                storage_setParam(mibHandle,mibpath,value);
                break;
                /* Others */
            default:
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, mibsets->name);
                storage_setParam(mibHandle,mibpath,value);

        }

        free (value);
        value = 0;
        mibsets ++;
    }

    (void)wps_destroy_wps_data(&wps);

    if (regStd != NULL)
    {
        char *bestStd = NULL;
        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "Standard");
        if (apacHyfi20GetWlanBestStandard(radio_index, apinfo->channel, regStd, &bestStd)
                >= 0)
        {
            dprintf(MSG_INFO, "Set best standard: %s\n", bestStd);
            storage_setParam(mibHandle,mibpath,bestStd);
            free(bestStd);
        }
        else
        {
            /*try to set registrar's standard*/
            dprintf(MSG_INFO, "Try to set standard: %s\n", regStd);
            storage_setParam(mibHandle,mibpath,regStd);
        }
        free(regStd);
    }

    if (manageVAPInd)
    {
        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "VAPIndependent");
        if (apinfo->channel != 0)
            storage_setParam(mibHandle,mibpath,"1");
        else
            storage_setParam(mibHandle,mibpath,"0");
    }

    if (vap_type == APAC_WLAN_STA && !deepCloneNoBSSID)
    {
        /* Peer BSSID */
        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "PeerBSSID");
        storage_setParam(mibHandle,mibpath,bssid);
    }

    return 0;
}

/*
 *  apac_mib_parse_sae_password - function to parse the single SAE Password
 *  and identify password key, and other optional parameters password identifier, mac address, vlanid
 */
int apac_mib_parse_sae_password(char *data, char **dest, char *key)
{
    char value[MAX_SAE_PASSWORD_LEN+1];
    char *data_ptr = data;
    int i = 0, ret = 0;

    if ( data == NULL || dest == NULL)
        return -1;

    if ( (key == NULL)
            || ((key != NULL) && (data_ptr = strstr(data, key)) != NULL ))
    {
        if (key != NULL)
            data_ptr += strlen(key);
        while (*data_ptr != '|' && *data_ptr != '\0') {
            value[i] = *data_ptr;
            data_ptr++;
            i++;
        }
    }

    if (i > 0) {
        value[i] = '\0';
        *dest = strdup(value);
        if (*dest == NULL)
            ret = -1;
        dprintf(MSG_MSGDUMP, "Parsed Key [%s] Value [%s] \n", key, *dest);
        ret = 0;
    }

    return ret;
}

/*
 *  apac_mib_decode_sae_password- function to decode the single SAE Password
 */
int apac_mib_decode_sae_password(char *sae_password, apacHyfi20SAEPassword_t *ptr_sae_password)
{
    char *vlanid = NULL, *peer_mac = NULL;
    const struct ether_addr *peerAddr = NULL;

    if (sae_password == NULL || ptr_sae_password == NULL)
        return -1;

    memset(ptr_sae_password->peer_addr, 0xff, ETH_ALEN);

    // Parse password string, mac address, password identifier
    if (apac_mib_parse_sae_password(sae_password, &ptr_sae_password->password, NULL) < 0 )
        goto fail;
    if (apac_mib_parse_sae_password(sae_password, &ptr_sae_password->identifier, "|id=") < 0 )
        goto fail;
    if (apac_mib_parse_sae_password(sae_password, &peer_mac, "|mac=")  == 0 )
    {
        if (peer_mac) {
            peerAddr = ether_aton(peer_mac);
            if (peerAddr) {
                memcpy(ptr_sae_password->peer_addr, peerAddr->ether_addr_octet, ETH_ALEN);
            }
            free (peer_mac);
        }
    } else {
        goto fail;
    }

    if (apac_mib_parse_sae_password(sae_password, &vlanid, "|vlanid=") == 0) {
        if (vlanid) {
            ptr_sae_password->vlan_id = atoi(vlanid);
            free (vlanid);
        }
    } else {
        goto fail;
    }

    ptr_sae_password->pwd = strdup(sae_password);
    if (!ptr_sae_password->pwd) {
        goto fail;
    }

    dprintf(MSG_DEBUG, "WPA3 Credential:[%s] Password Identifier:[%s] vlanID:[%d]",
            ptr_sae_password->password, ptr_sae_password->identifier, ptr_sae_password->vlan_id);

    if (peerAddr != NULL) {
        dprintf(MSG_DEBUG, "Peer MAC:[%02x:%02x:%02x:%02x:%02x:%02x]\n",
                peerAddr->ether_addr_octet[0], peerAddr->ether_addr_octet[1], peerAddr->ether_addr_octet[2],
                peerAddr->ether_addr_octet[3], peerAddr->ether_addr_octet[4], peerAddr->ether_addr_octet[5]);
    }
    return 0;

fail:
    if (ptr_sae_password->password) {
        free(ptr_sae_password->password);
        ptr_sae_password->password = NULL;
    }
    if (ptr_sae_password->identifier) {
        free(ptr_sae_password->identifier);
        ptr_sae_password->identifier = NULL;
    }
    if (peer_mac) {
        free(peer_mac);
    }
    if (vlanid) {
        free(vlanid);
    }
    return -1;
}

/*
 *  apac_mib_free_sae_password_list - function to free the SAE Password list parameters
 */
void apac_mib_free_sae_password_list(struct sae_password_entry *pass_list)
{
    struct sae_password_entry *fnode = NULL;
    while (pass_list) {
        if (pass_list->password) {
            free(pass_list->password);
            pass_list->password = NULL;
        }
        if (pass_list->identifier) {
            free(pass_list->identifier);
            pass_list->identifier = NULL;
        }
        if (pass_list->pwd) {
            free(pass_list->pwd);
            pass_list->pwd = NULL;
        }
        memset(pass_list->peer_addr, 0, ETH_ALEN);
        fnode = pass_list;
        pass_list = pass_list->next;
        free(fnode);
    }
}

/*
 *  apac_mib_get_list_parameter - function to decode the SAE list parameters
 *  from Vendor extension TLV
 */
int apac_mib_get_list_parameter(apacHyfi20IF_t *vapInterface, struct wps_data *wps, void **list, int bss_msg_type)
{
    int ret = -1, itlv;
    char data[256];
    size_t data_len;
    struct sae_password_entry *new_pw = NULL;
    struct string_list_entry *new_group = NULL;

    for (itlv = 0; itlv < wps->count; itlv++) {
        struct wps_tlv *tlv = wps->tlvs[itlv];
        if (tlv == NULL)
            break;

        if (bss_msg_type != tlv->type)
            continue;

        switch (tlv->type) {

            case BSS_TYPE_WPA3_SAE_PASSWORD:
                data_len = MAX_SAE_PASSWORD_LEN;
                if (wps_tlv_get_value(tlv, data, &data_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid SAE Password length\n");
                    return -1;
                }
                data[data_len] = '\0';

                dprintf(MSG_INFO, "%s: Receive cred SAEPassword: '%s',length: %zu\n", __func__, data, data_len);

                new_pw = (apacHyfi20SAEPassword_t *) calloc (1, sizeof (apacHyfi20SAEPassword_t));
                if (new_pw == NULL) {
                    dprintf(MSG_ERROR, "%s: SAEPassword malloc failed !\n", __func__);
                    return -1;
                }

                // Initially mark all passwords as new password
                // Post processing, flags are set accordingly
                new_pw->changed = APAC_PASSWORD_ADD;

                // Decode sae_password : <password/credential>[|mac=<peer mac>][|vlanid=<VLAN ID>][|id=<identifier>]
                if ((ret = apac_mib_decode_sae_password(data, new_pw)) != 0) {
                    free(new_pw);
                    break;
                }
                new_pw->next = *((apacHyfi20SAEPassword_t **)list);
                *((apacHyfi20SAEPassword_t **)list)  = new_pw;
                break;

            case BSS_TYPE_WPA3_SAE_GROUPS:
            case BSS_TYPE_WPA3_OWE_GROUPS:
                data_len = MAX_SEC_GROUPS_LEN;
                if (wps_tlv_get_value(tlv, data, &data_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid Groups length\n");
                    return -1;
                }
                data[data_len] = '\0';
                dprintf(MSG_INFO, "%s: Receive cred Groups: '%s',length: %zu\n", __func__, data, data_len);

                new_group = (apacHyfi20StringList_t *) calloc (1, sizeof (apacHyfi20StringList_t));

                if (new_group == NULL) {
                    dprintf(MSG_ERROR, "%s: SAEGroups malloc failed !\n", __func__);
                    return -1;
                }
                new_group->data = strdup(data);
                if (!new_group->data) {
                    free(new_group);
                    break;
                }
                new_group->next = *((apacHyfi20StringList_t **)list);
                *((apacHyfi20StringList_t **)list)  = new_group;
                break;
        }
    }
    return 0;
}

/*
 * apac_mib_read_list_parameter - Function to parse list parameter from wps data
 */
int apac_mib_read_list_parameter(apacHyfi20IF_t *vapInterface, int vap_index, void** list, int bss_msg_type)
{
    u8 *buf;
    size_t length;
    struct wps_data *data = 0;
    char  mibpath[256];
    int ret = -1;
    const struct apac_mib_param_set *mibsets = NULL;

    if (bss_msg_type == BSS_TYPE_WPA3_SAE_PASSWORD)
        mibsets = apac_wpa3_param_sae_password_set;
    else if (bss_msg_type == BSS_TYPE_WPA3_SAE_GROUPS)
        mibsets = apac_wpa3_param_sae_groups_set;
    else if (bss_msg_type == BSS_TYPE_WPA3_OWE_GROUPS)
        mibsets = apac_wpa3_param_owe_groups_set;
    else
        mibsets = NULL;

    snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN"%d", vap_index);

    if ( (ret = apac_get_mib_data(mibpath, mibsets, &buf, &length)) != 0)
    {
        dprintf(MSG_MSGDUMP, "%s: wpa3 parameter[%d] not present in config \n", __func__, bss_msg_type);
    }

    if (ret == 0) {

        if( wps_create_wps_data(&data)) {
            free (buf);
            return -1;
        }
        if (apac_parse_wps_data(buf, length, data, mibsets)) {
            dprintf(MSG_ERROR, "%s: Parse error\n", __func__);
            (void)wps_destroy_wps_data(&data);
            free (buf);
            return -1;
        }
        if (apac_mib_get_list_parameter(vapInterface, data, (void**)list, bss_msg_type) ) {
            dprintf(MSG_ERROR, "%s: Config Read error\n", __func__);
            free (buf);
            return -1;
        }
        free (buf);
    }
    return 0;
}

/*
 *  apac_mib_process_sae_password- function to process the SAE Password
 *
 *  1. ADD    : Mark the new passwords that need to be notified to libstorage
 *  2. DELETE : Mark the removed passwords that does not exist in new password list,
 *     so that it will be deleted in libstorage
 *  3. MATCH  : Ignore the matched passwords
 */

apacHyfi20SAEPassword_t *apac_mib_process_sae_password(apacHyfi20AP_t* apinfo, apacHyfi20SAEPassword_t *new_pass, apacHyfi20SAEPassword_t *old_pass)
{
    int match_found = 0;
    apacHyfi20SAEPassword_t *new_pass_list = NULL, *old_pass_list = NULL, *del_pw = NULL;

    new_pass_list = new_pass;
    old_pass_list = old_pass;
    if (old_pass_list && new_pass_list) {

        while (old_pass_list) {
            match_found = 0;
            new_pass_list = new_pass;
            while (new_pass_list) {
                if(strcmp(old_pass_list->pwd, new_pass_list->pwd) == 0 )
                {
                    old_pass_list->changed = new_pass_list->changed = APAC_PASSWORD_MATCH;
                    match_found = 1;
                }
                new_pass_list = new_pass_list->next;
            }
            // old password is deleted in config, so mark for deletion
            if (!match_found) {
                old_pass_list->changed = APAC_PASSWORD_DEL;
            }
            old_pass_list = old_pass_list->next;
        }
    } else if (old_pass_list == NULL && new_pass_list != NULL) {
        // Add all passwords
    } else if (old_pass_list != NULL && new_pass_list == NULL) {
        // mark all password to delete
        while (old_pass_list) {
            old_pass_list->changed = APAC_PASSWORD_DEL;
            old_pass_list = old_pass_list->next;
        }
    }
    // Copy password to be deleted
    old_pass_list = old_pass;
    while (old_pass_list) {

        if (old_pass_list->changed == APAC_PASSWORD_DEL) {
            // copy the password to be deleted from old list to new list
            del_pw = (apacHyfi20SAEPassword_t *) calloc (1, sizeof (apacHyfi20SAEPassword_t));
            if (del_pw) {
                memcpy(del_pw, old_pass_list, sizeof(apacHyfi20SAEPassword_t));
                old_pass_list->password = NULL;
                old_pass_list->identifier = NULL;
                old_pass_list->pwd = NULL;
                old_pass_list->vlan_id = 0;
                memset(old_pass_list->peer_addr, 0, ETH_ALEN);
                del_pw->next = new_pass;
               new_pass = del_pw;
            }
        }
        old_pass_list = old_pass_list->next;
    }
    return new_pass;
}

/*
 * apac_mib_identify_sae_password_list - Function to identify sae_password list parameter from wps data and process it
 */
int apac_mib_identify_sae_password_list(apacHyfi20AP_t* apinfo, struct wps_data *wps, apacHyfi20IF_t* vapInterface, apacHyfi20SAEPassword_t **pw_list)
{
    int ret = -1;
    // Read password list from M2 Message (new password list)
    if ((ret = apac_mib_get_list_parameter(vapInterface, wps, (void**)pw_list, BSS_TYPE_WPA3_SAE_PASSWORD)) == 0) {

        // Read password list from Config file (old password list)
        if (vapInterface && vapInterface->sae_password_list == NULL)
            ret = apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->sae_password_list, BSS_TYPE_WPA3_SAE_PASSWORD);

        // Compare both old and new password list, identify new updates to be notified to libstorage and ignore matching entries
        if (!ret && vapInterface && vapInterface->wlanDeviceMode == APAC_WLAN_AP) {
            if ((*pw_list = apac_mib_process_sae_password(apinfo, *pw_list, vapInterface->sae_password_list)) != NULL) {
                // Remove Old password List
                apac_mib_free_sae_password_list(vapInterface->sae_password_list);
                vapInterface->sae_password_list = NULL;
                ret = 0;
            }
        }
    }
    return ret;
}

/*
 * apac_mib_identify_groups_list - Function to identify sae_groups, owe_groups list parameter from wps data
 */

int apac_mib_identify_groups_list(apacHyfi20AP_t* apinfo, struct wps_data *wps, apacHyfi20IF_t* vapInterface,
        apacHyfi20StringList_t **groups_list, int bss_msg_type)
{
    int ret = -1;
    // Read password list from M2 Message (new groups list)
    if ( (ret = apac_mib_get_list_parameter(vapInterface, wps, (void**)groups_list, bss_msg_type)) == 0) {
        if (bss_msg_type == BSS_TYPE_WPA3_SAE_GROUPS) {
            // Read password list from Config file (old groups list)
            if (vapInterface && vapInterface->sae_groups_list == NULL) {
                ret = apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->sae_groups_list, bss_msg_type);
            }
        }
        else if (bss_msg_type == BSS_TYPE_WPA3_OWE_GROUPS) {
            // Read password list from Config file (old groups list)
            if (vapInterface && vapInterface->owe_groups_list == NULL) {
                ret = apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->owe_groups_list, bss_msg_type);
            }
        }
    }
    return ret;
}

/*
 * apac_mib_set_list_parameter - Function to send list parameter updates to storage
 */
void apac_mib_set_list_parameter(void *mibHandle, char *mibroot, struct string_list_entry **oldlist, struct string_list_entry *newlist, char *addData, char *delData)
{
    char mibpath[256];
    char mibvalue[128];
    struct string_list_entry *olist = *oldlist, *nlist = newlist, *prev = NULL;
    if (olist != NULL) {
        // Send first sae_groups data, TBD: send all data
        if (strcmp(newlist->data, olist->data) != 0) {
            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, delData);
            snprintf(mibvalue, sizeof(mibvalue), "%s", olist->data);
            storage_setParam(mibHandle, mibpath, mibvalue);
            dprintf(MSG_DEBUG, "Send Update to Storage: pwd[%s] changed[Delete]\n", olist->data);

            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, addData);
            snprintf(mibvalue, sizeof(mibvalue), "%s", newlist->data);
            storage_setParam(mibHandle, mibpath, mibvalue);
            dprintf(MSG_DEBUG, "Send Update to Storage: pwd[%s] changed[ADD]\n", newlist->data);

            // free old data and store new one
            free(olist->data);
            free(olist);
            *oldlist = nlist;
            olist = *oldlist;
            nlist = nlist->next;
            olist->next = NULL;
        }
    } else {
            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, addData);
            snprintf(mibvalue, sizeof(mibvalue), "%s", newlist->data);
            storage_setParam(mibHandle, mibpath, mibvalue);
            dprintf(MSG_DEBUG, "Send Update to Storage: pwd[%s] changed[ADD]\n", newlist->data);

            *oldlist = nlist;
            olist = *oldlist;
            nlist = nlist->next;
            olist->next = NULL;

    }
    newlist = nlist;
    while (newlist) {
        if (newlist->data != NULL)
            free(newlist->data);
        prev = newlist;
        newlist = newlist->next;
        if ( prev == *oldlist ) {
            *oldlist = NULL;
        }
        free(prev);
    }
}

/*
 * apac_mib_sae_password_cleanup - Function to send update to storage to clear all sae_password entries
 */
void apac_mib_sae_password_cleanup(void *mibHandle, char *mibpath, struct sae_password_entry *pw_list)
{
    char mibvalue[128];

    dprintf(MSG_DEBUG, "Cleanup sae_password parameter\n");
    while (pw_list != NULL) {
       if (pw_list->pwd != NULL) {
            snprintf(mibvalue, sizeof(mibvalue), "%s", pw_list->pwd);
            storage_addListParam(mibHandle, mibpath, mibvalue);
       }
       pw_list = pw_list->next;
    }
    apac_mib_free_sae_password_list(pw_list);
}

/*
 * apac_mib_list_parameter_cleanup - Function to send update to storage to clear all list parameter entries (sae_groups, owe_groups)
 */
void apac_mib_list_parameter_cleanup(void *mibHandle, char *mibpath,  apacHyfi20StringList_t *list_data)
{
    char mibvalue[128];
    apacHyfi20StringList_t *list = list_data, *fnode = NULL;

    dprintf(MSG_DEBUG, "Cleanup list parameter\n");
    while (list != NULL) {
       if (list->data != NULL) {
            snprintf(mibvalue, sizeof(mibvalue), "%s", list->data);
            storage_addListParam(mibHandle, mibpath, mibvalue);
       }
       list = list->next;
    }

    list = list_data;
    while (list != NULL) {
        fnode = list;
        if (list->data)
            free(list->data);
        list = list->next;
        free(fnode);
    }
}

/*
 * apac_mib_sae_password_storage_update - Function to send update to storage
 */
int apac_mib_sae_password_storage_update(apacHyfi20IF_t *vapInterface, void *mibHandle, char *mibroot, struct sae_password_entry *pw_list )
{
    char mibpath[256];
    char mibvalue[128];
    struct sae_password_entry *new_pass_list = NULL, *prev = NULL, *free_node, *chosen_password = NULL;
    u8 default_mac[ETH_ALEN];

    if ((vapInterface != NULL) && (vapInterface->wlanDeviceMode == APAC_WLAN_AP) && (pw_list != NULL)) {

        new_pass_list = pw_list;

        dprintf( MSG_MSGDUMP, "AP VAP MAC [%x:%x:%x:%x:%x:%x]\n", vapInterface->mac_addr[0], vapInterface->mac_addr[1],vapInterface->mac_addr[2],vapInterface->mac_addr[3],vapInterface->mac_addr[4],vapInterface->mac_addr[5]);

        while (new_pass_list != NULL) {

            if (new_pass_list->changed != APAC_PASSWORD_MATCH) {

                if (new_pass_list->changed == APAC_PASSWORD_ADD) {
                    dprintf(MSG_INFO, "Send Update to Storage: pwd[%s] changed[%d]\n", new_pass_list->pwd, new_pass_list->changed);
                    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAEPassword");
                } else if (new_pass_list->changed == APAC_PASSWORD_DEL) {
                    dprintf(MSG_INFO, "Send Update to Storage: pwd[%s] changed[%d]\n", new_pass_list->pwd, new_pass_list->changed);
                    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "DeleteSAEPassword");
                }
                snprintf(mibvalue, sizeof(mibvalue), "%s", new_pass_list->pwd);
                storage_addListParam(mibHandle, mibpath, mibvalue);
            }
            new_pass_list = new_pass_list->next;
        }
        // Cleanup nodes marked as delete, after update is sent to libstorage
        new_pass_list = pw_list;
        prev = NULL; free_node = NULL;
        while (new_pass_list != NULL) {
            if (new_pass_list->changed == APAC_PASSWORD_DEL) {
                free_node = new_pass_list;
                if (prev != NULL)
                    prev->next = new_pass_list->next;
                else
                    pw_list = new_pass_list->next;
                new_pass_list = new_pass_list->next;
            } else {
                prev = new_pass_list;
                new_pass_list = new_pass_list->next;
            }

            if (free_node) {
                if (free_node->password) {
                    free(free_node->password);
                    free_node->password = NULL;
                }
                if (free_node->identifier) {
                    free(free_node->identifier);
                    free_node->identifier = NULL;
                }
                if (free_node->pwd) {
                    free(free_node->pwd);
                    free_node->pwd = NULL;
                }
                memset(free_node->peer_addr, 0, ETH_ALEN);
                free(free_node);
                free_node = NULL;
            }
        }
        vapInterface->sae_password_list = pw_list;

    } else if ((vapInterface != NULL) && (vapInterface->wlanDeviceMode == APAC_WLAN_STA) && (pw_list != NULL)) {

        struct sae_password_entry *mac_match_pass = NULL, *def_pass = NULL, *id_pass = NULL;

        memset(default_mac, 0xff, ETH_ALEN);
        new_pass_list = pw_list;

        dprintf( MSG_INFO, "STA VAP MAC [%x:%x:%x:%x:%x:%x]\n", vapInterface->mac_addr[0], vapInterface->mac_addr[1],vapInterface->mac_addr[2],vapInterface->mac_addr[3],vapInterface->mac_addr[4],vapInterface->mac_addr[5]);

        // Choosing password from list for password for STA VAP
        // 1) Find Matching password based on STA MAC Address, If found, use that Password
        // 2) If matching MAC not found, then search for password without MAC and identifier and vlan id
        // 3) If password without MAC and identifier and vlan id is not found , then use the password with identifier and without vlan
        while (new_pass_list) {
            if (new_pass_list->peer_addr) {
                if (memcmp(new_pass_list->peer_addr, vapInterface->mac_addr, ETH_ALEN) == 0) {
                    dprintf(MSG_MSGDUMP, "MAC Match found !!!\n");
                    mac_match_pass = new_pass_list;
                }
                if (memcmp(new_pass_list->peer_addr, default_mac, ETH_ALEN) == 0) {
                    dprintf(MSG_MSGDUMP, "Default MAC Match found [ff:ff:ff:ff:ff:ff]!!!\n");
                    def_pass = new_pass_list;
                }
            }
            new_pass_list = new_pass_list->next;
        }
        if (mac_match_pass != NULL) {
            chosen_password = mac_match_pass;
        } else if (def_pass != NULL) {
            chosen_password = def_pass;
        } else if (id_pass != NULL) {
            chosen_password = id_pass;
        } else {
            dprintf(MSG_MSGDUMP, "Password not found for STA VAP[%s]\n", vapInterface->ifName);
            return -1;
        }

        dprintf(MSG_MSGDUMP, "Chosen Password for STA VAP[%s] : %s", vapInterface->ifName, chosen_password->password);
        if (chosen_password != NULL ) {

            if (vapInterface->sae_password_list == NULL) {
                // Send update to write chosen password to config file
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAEPassword");
                snprintf(mibvalue, sizeof(mibvalue), "%s", chosen_password->password);
                storage_setParam(mibHandle, mibpath, mibvalue);

            }
            else {
                if (vapInterface->sae_password_list->pwd) {
                    if (strcmp(chosen_password->password, vapInterface->sae_password_list->pwd) != 0 ) {
                        // Password changed, Delete Old password and Add New password
                        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "DeleteSAEPassword");
                        snprintf(mibvalue, sizeof(mibvalue), "%s", vapInterface->sae_password_list->pwd);
                        storage_setParam(mibHandle, mibpath, mibvalue);

                        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAEPassword");
                        snprintf(mibvalue, sizeof(mibvalue), "%s", chosen_password->password);
                        storage_setParam(mibHandle, mibpath, mibvalue);

                        // Update vap info, free old data and update new data
                        free(vapInterface->sae_password_list->pwd);
                        free(vapInterface->sae_password_list->password);
                        free(vapInterface->sae_password_list->identifier);
                        free(vapInterface->sae_password_list);
                    }
                }
            }
            // save it in vap interface info
            vapInterface->sae_password_list = (apacHyfi20SAEPassword_t *) calloc (1, sizeof (apacHyfi20SAEPassword_t));
            if (vapInterface->sae_password_list == NULL) {
                return -1;
            }
            vapInterface->sae_password_list->pwd = strdup(chosen_password->pwd);
            if (!vapInterface->sae_password_list->pwd)
                return -1;
            vapInterface->sae_password_list->password = strdup(chosen_password->password);
            if (!vapInterface->sae_password_list->password)
                return -1;
            //identifier is optional config so NULL is expected
            if(chosen_password->identifier) {
                vapInterface->sae_password_list->identifier = strdup(chosen_password->identifier);
            }
            if (!vapInterface->sae_password_list->identifier)
                return -1;
            vapInterface->sae_password_list->vlan_id = chosen_password->vlan_id;
            memcpy(vapInterface->sae_password_list->peer_addr, chosen_password->peer_addr, ETH_ALEN);
        }
        apac_mib_free_sae_password_list(pw_list);
    }
    return 0;
}

/*
 * apac_mib_find_vap_interface - Function to find the vap interface information
 */
apacHyfi20IF_t *apac_mib_find_vap_interface(apacHyfi20Data_t *pApacData, int vap_index)
{
    int iter = 0;
    apacHyfi20IF_t *hyif = pApacData->hyif;
    // Find VAP interface
    while( iter < APAC_MAXNUM_HYIF) {
        hyif = &pApacData->hyif[iter];
        if (hyif->valid && hyif->mediaType == APAC_MEDIATYPE_WIFI) {
            if (hyif->vapIndex == vap_index) {
                dprintf(MSG_INFO, "vapInterface %s \n", hyif->ifName);
                return hyif;
            }
        }
        iter++;
    }
    return NULL;
}

int apac_mib_set_qca_ext_wpa3(apacHyfi20Data_t *pApacData, apacHyfi20AP_t* apinfo, int vap_type, int vap_index)
{
    const struct apac_mib_param_set *mibsets = apac_wpa3_param_sets;
    struct wps_data *wps = 0;
    char buf[1024];
    size_t len;
    char mibpath[256];
    char mibroot[128];
    char mibvalue[129];
    char *value = NULL;
    size_t data_len;
    void *mibHandle = pApacData->wifiConfigHandle;
    apacHyfi20IF_t *vapInterface = NULL;
    struct sae_password_entry *pw_list = NULL;
    struct string_list_entry *sae_groups_list = NULL, *owe_groups_list = NULL, *listIter = NULL;

    static const u8 atheros_smi_oui[3] = {
        0x00, 0x24, 0xe2
    };

    if (os_memcmp(apinfo->qca_ext, atheros_smi_oui, 3) != 0)
    {
        dprintf(MSG_ERROR, "Unknown Vendor Extension %02x %02x %02x\n",
                apinfo->qca_ext[0], apinfo->qca_ext[1], apinfo->qca_ext[2]);
        return -1;
    }

    if(wps_create_wps_data(&wps))
        return -1;

    if (apac_parse_wps_data((u8*)apinfo->qca_ext + 3,
                apinfo->qca_ext_len - 3 , wps, mibsets))
    {
        dprintf(MSG_ERROR, "QCA vendor extension wpa3 parse error\n");
        (void)wps_destroy_wps_data(&wps);
        return -1;
    }

    vapInterface = apac_mib_find_vap_interface(pApacData, vap_index);
    snprintf(mibroot, sizeof(mibroot), "%s%d.", CONFIG_WLAN, vap_index);

    while(mibsets && mibsets->name)
    {
        len = sizeof(buf);
        if (wps_get_value(wps, mibsets->type, buf, &len)!=0)
        {
            dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
            mibsets++;
            continue;

        }

        value = (char *)malloc(len + 32);
        if(value == NULL ||  apac_mib_parse_value(mibsets, buf, len, value, len + 32) != 0)
        {
            dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
            mibsets++;
            continue;
        }

        switch (mibsets->type){
            case BSS_TYPE_WPA3_SAE:
                apinfo->sae = *buf;
                apinfo->is_sae_enabled = APAC_TRUE;
                dprintf(MSG_INFO, "Receive cred EnableSAE: 0x%04x\n", apinfo->sae);
                break;

            case BSS_TYPE_WPA3_SAE_PASSWORD:
                if (len > MAX_SAE_PASSWORD_LEN) {
                    dprintf(MSG_ERROR, "Invalid SAEPassword Length: %u\n", (u32)len);
                    break;
                }
                strlcpy(apinfo->sae_password, value, len + 1);
                apinfo->sae_password_len = len;

                if (apac_mib_identify_sae_password_list(apinfo, wps, vapInterface, &pw_list) == 0) {
                    apinfo->is_sae_password_set = APAC_TRUE;
                }
                dprintf(MSG_INFO, "Receive cred SAEPassword: '%s',length: %u\n", apinfo->sae_password, (u32)len);
                break;

            case BSS_TYPE_WPA3_SAE_ANTI_CLOG_THRES:
                apinfo->sae_anticloggingthreshold = *buf;
                apinfo->is_sae_anticlogthres_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive cred SAEAntiCloggingThreshold : 0x%04x\n", apinfo->sae_anticloggingthreshold);
                break;

            case BSS_TYPE_WPA3_SAE_SYNC:
                apinfo->sae_sync = *buf;
                apinfo->is_sae_sync_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive cred SAESync  : 0x%04x\n", apinfo->sae_sync);
                break;

            case BSS_TYPE_WPA3_SAE_GROUPS:
                if (len > MAX_SEC_GROUPS_LEN) {
                    dprintf(MSG_ERROR, "Invalid SAEGroups Length: %u\n", (u32)len);
                    break;
                }
                strlcpy(apinfo->sae_groups, value, len + 1);
                if (apac_mib_identify_groups_list(apinfo, wps, vapInterface, &sae_groups_list, BSS_TYPE_WPA3_SAE_GROUPS) == 0) {
                    apinfo->is_sae_groups_set = APAC_TRUE;
                    listIter = sae_groups_list;
                    while (listIter) {
                        dprintf(MSG_INFO, "SAEGroups data : %s\n", listIter->data);
                        listIter = listIter->next;
                    }
                }
                dprintf(MSG_INFO, "Receive cred SAEGroups: '%s',length: %d\n", apinfo->sae_groups, (s32)len);
                break;

            case BSS_TYPE_WPA3_SAE_REQUIRE_MFP:
                apinfo->sae_requireMFP = *buf;
                apinfo->is_sae_reqmfp_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive cred SAE Require MFP: 0x%04x\n", apinfo->sae_requireMFP);
                break;

            case BSS_TYPE_WPA3_OWE:
                apinfo->owe = *buf;
                apinfo->is_owe_enabled = APAC_TRUE;
                dprintf(MSG_INFO, "Receive cred OWE: 0x%04x\n", apinfo->owe);
                break;

            case BSS_TYPE_WPA3_OWE_GROUPS:
                data_len = MAX_SEC_GROUPS_LEN ;
                strlcpy(apinfo->owe_groups, value, data_len);
                apinfo->owe_groups[data_len] = '\0';
                if (apac_mib_identify_groups_list(apinfo, wps, vapInterface, &owe_groups_list, BSS_TYPE_WPA3_OWE_GROUPS) == 0) {
                    apinfo->is_owe_groups_set = APAC_TRUE;
                    listIter = owe_groups_list;
                    while (listIter) {
                        dprintf(MSG_INFO, "OWEGroups data : %s\n", listIter->data);
                        listIter = listIter->next;
                    }
                }
                dprintf(MSG_INFO, "Receive cred OWEGroups : '%s',length: %d\n", apinfo->owe_groups, (s32)data_len);
                break;

            case BSS_TYPE_WPA3_OWE_TRANS_IF:
                data_len = IFNAMSIZ;
                strlcpy(apinfo->owe_transition_ifname, value, data_len);
                apinfo->owe_transition_ifname[data_len] = '\0';
                apinfo->is_owe_trans_if_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive owe_transition_ifname: '%s',length: %d\n", apinfo->owe_transition_ifname, (s32)data_len);
                break;

            case BSS_TYPE_WPA3_OWE_TRANS_SSID:
                data_len = MAX_SSID_LEN;
                strlcpy(apinfo->owe_transition_ssid, value, data_len);
                apinfo->owe_transition_ssid[data_len] = '\0';
                apinfo->is_owe_trans_ssid_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive owe_transition_ssid: '%s',length: %d\n", apinfo->owe_transition_ssid, (s32)data_len);
                break;

            case BSS_TYPE_WPA3_OWE_TRANS_BSSID:
                data_len = MAX_SSID_LEN;
                strlcpy(apinfo->owe_transition_bssid, value, data_len);
                apinfo->owe_transition_bssid[data_len] = '\0';
                apinfo->is_owe_trans_bssid_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive owe_transition_bssid: '%s',length: %d\n", apinfo->owe_transition_bssid, (s32)data_len);
                break;

            case BSS_TYPE_WPA3_SUITE_B:
                apinfo->suite_b = *buf;
                apinfo->is_suite_b_enabled = APAC_TRUE;
                dprintf(MSG_INFO, "Receive Suite_B settings: 0x%04x\n", apinfo->suite_b);
                break;

            case BSS_TYPE_AUTH_SERVER_ADDR:
                data_len = MAX_AUTH_SERVER_IP_LEN ;
                strlcpy(apinfo->auth_server, value, data_len);
                apinfo->auth_server[data_len] = '\0';
                apinfo->is_auth_server_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive Auth Server IP : '%s',length: %d\n", apinfo->auth_server, (s32)data_len);
                break;

            case BSS_TYPE_AUTH_SERVER_SECRET:
                data_len = MAX_AUTH_SECRET_LEN ;
                strlcpy(apinfo->auth_secret, value, data_len);
                apinfo->auth_secret[data_len] = '\0';
                apinfo->is_auth_secret_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive Auth Server IP : '%s',length: %d\n", apinfo->auth_secret, (s32)data_len);
                break;

            case BSS_TYPE_AUTH_SERVER_PORT:
                apinfo->auth_port = *buf;
                apinfo->is_auth_port_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive Auth Port settings: 0x%04x\n", apinfo->auth_port);
                break;

            case BSS_TYPE_NASID:
                data_len = MAX_NASID_LEN;
                strlcpy(apinfo->nasid, value, data_len);
                apinfo->nasid[data_len] = '\0';
                apinfo->is_nasid_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive NASID : '%s',length: %d\n", apinfo->nasid, (s32)data_len);
                break;

            case BSS_TYPE_IEEE80211W:
                apinfo->ieee80211w = *buf;
                apinfo->is_ieee80211w_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive IEEE80211w settings: 0x%04x\n", apinfo->ieee80211w);
                break;

            case BSS_TYPE_SSID_HIDE:
                apinfo->hidden_ssid = *buf;
                apinfo->is_hidden_ssid_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive Hidden SSID settings: 0x%04x\n", apinfo->hidden_ssid);
                break;

            case BSS_TYPE_SAE_PWE:
                apinfo->sae_pwe = *buf;
                apinfo->is_sae_pwe_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive SAE PWE settings: 0x%04x\n", apinfo->sae_pwe);
                break;

            case BSS_TYPE_SAE_EN_6G_SEC_COMP:
                apinfo->en_6g_sec_comp = *buf;
                apinfo->is_en_6g_sec_comp_set = APAC_TRUE;
                dprintf(MSG_INFO, "Receive SAE En_6G_SEC_COMP settings: 0x%04x\n", apinfo->en_6g_sec_comp);
                break;

            default:
                snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, mibsets->name);
                storage_setParam(mibHandle,mibpath,value);
        }

        free (value);
        value = 0;
        mibsets ++;
    }

    (void)wps_destroy_wps_data(&wps);

    /* SAE */
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "EnableSAE");
    if( (apinfo->is_sae_enabled == APAC_TRUE) && (apinfo->sae == 0 || apinfo->sae == 1) )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->sae);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");


    /*Overwrite the 6G specific Mandatory SAE parameters*/
    if( apinfo->is_en_6g_sec_comp_set == APAC_TRUE ) {
        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "en_6g_sec_comp");
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->en_6g_sec_comp);
        storage_setParam(mibHandle, mibpath, mibvalue);
    } else if ( apinfo->freq == APAC_WIFI_FREQ_6 ) {
        /* en_6g_sec_comp is not set when Inter-Op CAP-2R and 6G enabled RE .
            So, enable en_6g_sec_comp based pwe and SAE values*/
        snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "en_6g_sec_comp");
        if((apinfo->is_sae_enabled == APAC_TRUE) && apinfo->sae == 1 &&
            (apinfo->is_sae_pwe_set == APAC_TRUE) && apinfo->sae_pwe == 1) {
                storage_setParam(mibHandle, mibpath, "1");
        } else {
                storage_setParam(mibHandle, mibpath, "0");
        }
    }

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "sae_pwe");
    if( apinfo->is_sae_pwe_set == APAC_TRUE ) {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->sae_pwe);
        storage_setParam(mibHandle, mibpath, mibvalue);
    } else {
        storage_setParam(mibHandle, mibpath, "");
    }

    if ((apinfo->is_sae_password_set == APAC_TRUE) && (pw_list != NULL)) {
        apac_mib_sae_password_storage_update(vapInterface, mibHandle, mibroot, pw_list);
        pw_list = NULL;
    } else if (apinfo->is_sae_password_set == APAC_FALSE) {
        // Read password list from Config file (old password list)
        if (vapInterface && vapInterface->sae_password_list == NULL) {
            if (apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->sae_password_list, BSS_TYPE_WPA3_SAE_PASSWORD) == -1) {
                dprintf(MSG_DEBUG, "Unable to read sae_password list parameter\n");
            }
        }

        if (vapInterface && vapInterface->sae_password_list != NULL) {
            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "DeleteSAEPassword");
            apac_mib_sae_password_cleanup(mibHandle, mibpath, vapInterface->sae_password_list);
            vapInterface->sae_password_list = NULL;
        }
    }

    // Store VAP type to identify AP or STA vap and process sae_password into String or List
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "VAPType");
    snprintf(mibvalue, sizeof(mibvalue), "%d", vap_type);
    storage_setParam(mibHandle, mibpath, mibvalue);


    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAEAntiCloggingThreshold");
    if( apinfo->is_sae_anticlogthres_set == APAC_TRUE )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->sae_anticloggingthreshold);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAESync");
    if( apinfo->is_sae_sync_set == APAC_TRUE )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->sae_sync);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    if ( (apinfo->is_sae_groups_set == APAC_TRUE) && (vapInterface != NULL) && (sae_groups_list != NULL))
    {
        apac_mib_set_list_parameter(mibHandle, mibroot, &vapInterface->sae_groups_list, sae_groups_list, "SAEGroups", "DeleteSAEGroups");
    }
    else if (apinfo->is_sae_groups_set == APAC_FALSE) {
        // Read password list from Config file (old groups list)
        if (vapInterface && vapInterface->sae_groups_list == NULL) {
            if (apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->sae_groups_list, BSS_TYPE_WPA3_SAE_GROUPS) == -1) {
                dprintf(MSG_DEBUG, "Unable to read sae_groups list parameter\n");
            }
        }
        if (vapInterface && vapInterface->sae_groups_list != NULL) {
            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "DeleteSAEGroups");
            apac_mib_list_parameter_cleanup(mibHandle, mibpath, vapInterface->sae_groups_list);
            vapInterface->sae_groups_list = NULL;
        }
    }

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SAERequireMFP");
    if( apinfo->is_sae_reqmfp_set == APAC_TRUE )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->sae_requireMFP);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    /* OWE */
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "EnableOWE");
    if( (apinfo->is_owe_enabled == APAC_TRUE) && (apinfo->owe == 0 || apinfo->owe == 1) )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->owe);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    if ( (apinfo->is_owe_groups_set == APAC_TRUE) && (vapInterface != NULL) && (owe_groups_list != NULL))
    {
        apac_mib_set_list_parameter(mibHandle, mibroot, &vapInterface->owe_groups_list, owe_groups_list, "OWEGroups", "DeleteOWEGroups");
    }
    else if (apinfo->is_owe_groups_set == APAC_FALSE) {
        // Read password list from Config file (old groups list)
        if (vapInterface && vapInterface->owe_groups_list == NULL) {
            if (apac_mib_read_list_parameter(vapInterface, vapInterface->vapIndex, (void**)&vapInterface->owe_groups_list, BSS_TYPE_WPA3_OWE_GROUPS) == -1) {
                dprintf(MSG_DEBUG, "Unable to read owe_groups list parameter\n");
            }
        }
        if (vapInterface && vapInterface->owe_groups_list != NULL) {
            snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "DeleteOWEGroups");
            apac_mib_list_parameter_cleanup(mibHandle, mibpath, vapInterface->owe_groups_list);
            vapInterface->owe_groups_list = NULL;
        }
    }

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "OWETransIfname");
    if( apinfo->is_owe_trans_if_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->owe_transition_ifname);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "OWETransSSID");
    if( apinfo->is_owe_trans_ssid_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->owe_transition_ssid);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "OWETransBSSID");
    if( apinfo->is_owe_trans_bssid_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->owe_transition_bssid);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    /* SUITE B */
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "SuiteB");
    if( apinfo->is_suite_b_enabled == APAC_TRUE && vap_type == APAC_WLAN_AP)
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->suite_b);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle,mibpath,"");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "X_ATH-COM_AuthServerAddr");
    if( apinfo->is_auth_server_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->auth_server);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "X_ATH-COM_AuthServerPort");
    if( apinfo->is_auth_port_set == APAC_TRUE && vap_type == APAC_WLAN_AP)
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->auth_port);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "X_ATH-COM_AuthServerSecret");
    if( apinfo->is_auth_secret_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->auth_secret);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "X_ATH-COM_NASID");
    if( apinfo->is_nasid_set == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%s", apinfo->nasid);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    /* MFP */
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "IEEE80211w");
    if( apinfo->is_ieee80211w_set == APAC_TRUE )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->ieee80211w);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    /*set SSID Hidden */
    snprintf(mibpath, sizeof(mibpath), "%s%s", mibroot, "X_ATH-COM_SSIDHide");
    if( apinfo->is_hidden_ssid_set == APAC_TRUE && apinfo->is_owe_enabled == APAC_TRUE && vap_type == APAC_WLAN_AP )
    {
        snprintf(mibvalue, sizeof(mibvalue), "%d", apinfo->hidden_ssid);
        storage_setParam(mibHandle, mibpath, mibvalue);
    }
    else
        storage_setParam(mibHandle, mibpath, "");

    return 0;
}

int apac_mib_get_wifi_configuration(apacHyfi20AP_t* apinfo, int vap_index)
{
    char path[256];
    char buf[1024];
    size_t len;

    int ret = -1;
    struct wps_data *wps = 0;

    if(wps_create_wps_data(&wps))
        return ret;

    dprintf(MSG_DEBUG, "%s for VAP_index:%d\n",__func__,vap_index);
    do{
        snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

        if ( apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0)
        {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        apinfo->ssid_len = MAX_SSID_LEN;
        if (wps_get_value(wps, BSS_TYPE_SSID, apinfo->ssid, (size_t *)&apinfo->ssid_len))
        {
            dprintf(MSG_ERROR, "Get ssid error from mib data %s\n", path);
            break;
        }

        /*auth type*/
        len = sizeof(buf);
        if (wps_get_value(wps, BSS_TYPE_BEACONTYPE, buf, &len))
        {
            dprintf(MSG_ERROR, "Get beacon type error from mib data \n");
            break;
        }
        if (strncmp(buf, "Basic", len) == 0)
        {
            /*auth type could be open or shared*/
            apinfo->encr = WPS_ENCRTYPE_WEP;
        }
        else if (strncmp(buf, "WPA", len) == 0)
        {
            apinfo->auth = WPS_AUTHTYPE_WPAPSK;
        }
        else if (strncmp(buf, "11i", len) == 0)
        {
            len = sizeof(buf);
            if (wps_get_value(wps, BSS_TYPE_11I_AUTHMODE, buf, &len))
            {
                dprintf(MSG_ERROR, "Get 11I Auth Mode type error from mib data \n");
                break;
            }
            if(strncmp(buf, "WPA3Authentication", len) == 0)
                apinfo->auth = WPS_AUTHTYPE_WPA3;
            else
                apinfo->auth = WPS_AUTHTYPE_WPA2PSK;
        }
        else if (strncmp(buf, "WPAand11i", len) == 0)
        {
            apinfo->auth = WPS_AUTHTYPE_WPAPSK|WPS_AUTHTYPE_WPA2PSK;
        }
        else if (strncmp(buf, "None", len) == 0)
        {
            apinfo->auth = WPS_AUTHTYPE_OPEN;
            apinfo->encr = WPS_ENCRTYPE_NONE;
        }
        else
        {
            apinfo->auth = WPS_AUTHTYPE_OPEN;
            apinfo->encr = WPS_ENCRTYPE_NONE;
        }

        /*wpa/11i*/
        if (apinfo->auth & (WPS_AUTHTYPE_WPAPSK|WPS_AUTHTYPE_WPA2PSK|WPS_AUTHTYPE_WPA3))
        {
            u16 encrmode;
            if (apinfo->auth & (WPS_AUTHTYPE_WPA2PSK|WPS_AUTHTYPE_WPA3))
            {
                encrmode = BSS_TYPE_11I_ENCRYPTIONMODE;
            }
            else
            {
                encrmode = BSS_TYPE_WPA_ENCRYPTIONMODE;
            }
            len = sizeof(buf);
            if (wps_get_value(wps, encrmode, buf, &len))
            {
                dprintf(MSG_ERROR, "Get wpa encrypt mode error from mib data \n");
                break;
            }

            if (strncmp(buf,"TKIPEncryption", len) == 0)
                apinfo->encr = WPS_ENCRTYPE_TKIP;
            else if (strncmp(buf,"AESEncryption", len) == 0)
                apinfo->encr = WPS_ENCRTYPE_AES;
            else if  (strncmp(buf,"TKIPandAESEncryption", len) == 0)
                apinfo->encr = WPS_ENCRTYPE_AES|WPS_ENCRTYPE_TKIP;

            apinfo->nw_key_len = MAX_PASSPHRASE_LEN;
            if (wps_get_value(wps, BSS_TYPE_KEYPASSPHRASE, apinfo->nw_key, (size_t *)&apinfo->nw_key_len))
            {
                dprintf(MSG_ERROR, "Get passphrase error from mib data, try with PresharedKey then\n");
                apinfo->nw_key_len = MAX_NW_KEY_LEN;
                if (wps_get_value(wps, BSS_TYPE_PRESHARED_KEY, apinfo->nw_key, (size_t *)&apinfo->nw_key_len))
                {
                    dprintf(MSG_ERROR, "Get key error from mib data \n");
                    apinfo->nw_key_len = 0;
                }
            }

            if (apinfo->nw_key_len == 0)
            {
                struct wps_data *wps_wpa3 = 0;
                if (wps_create_wps_data(&wps_wpa3))
                    break;

                if ( apac_get_mib_data_in_wpsdata(path, apac_wpa3_param_sets, wps_wpa3, NULL) == 0)
                {
                    apinfo->sae_password_len = MAX_SAE_PASSWORD_LEN;
                    apinfo->is_sae_password_set = !wps_get_value(wps_wpa3, BSS_TYPE_WPA3_SAE_PASSWORD,
                            apinfo->sae_password, (size_t *)&apinfo->sae_password_len);

                    len = MAX_SEC_GROUPS_LEN;
                    apinfo->is_owe_enabled = !wps_get_value(wps_wpa3, BSS_TYPE_WPA3_OWE, &apinfo->owe, &len);

                    len = MAX_SEC_GROUPS_LEN;
                    apinfo->is_suite_b_enabled = !wps_get_value(wps_wpa3, BSS_TYPE_WPA3_SUITE_B, &apinfo->suite_b, &len);
                    dprintf(MSG_ERROR, "key not present !!! sae_pass[%d] owe[%d] suite_b[%d]\n", apinfo->is_sae_password_set,
                            apinfo->is_owe_enabled, apinfo->is_suite_b_enabled);

                    if(apinfo->is_sae_password_set != APAC_TRUE && apinfo->is_owe_enabled != APAC_TRUE
                            && apinfo->is_suite_b_enabled != APAC_TRUE )
                    {
                        dprintf(MSG_ERROR, "Security credential is not configured \n");
                        wps_destroy_wps_data(&wps_wpa3);
                        break;
                    }
                }
                else {
                    dprintf(MSG_DEBUG, "wpa3 mib data not present: %s\n", path);
                    break;
                }
                wps_destroy_wps_data(&wps_wpa3);
            }
            apinfo->nw_key_index = 0;
        }
        /*wep*/
        if (apinfo->encr & WPS_ENCRTYPE_WEP)
        {
            len = sizeof(buf);
            if (wps_get_value(wps, BSS_TYPE_BASIC_AUTHMODE, buf, &len))
            {
                dprintf(MSG_ERROR, "Get wep auth mode error from mib data \n");
                break;
            }

            if (strncmp(buf,"Both", len) == 0)
                apinfo->auth = WPS_AUTHTYPE_OPEN|WPS_AUTHTYPE_SHARED;
            else if (strncmp(buf,"SharedAuthentication", len) == 0)
                apinfo->auth = WPS_AUTHTYPE_SHARED;
            else if  (strncmp(buf,"None", len) == 0)
                apinfo->auth = WPS_AUTHTYPE_OPEN;

            if (wps_get_value(wps, BSS_TYPE_WEPKEYINDEX, buf, &len))
            {
                dprintf(MSG_ERROR, "Get keyindex error from mib data \n");
                break;
            }

            apinfo->nw_key_index = *buf;
            if (apinfo->nw_key_index < 1 || apinfo->nw_key_index >4 )
            {
                dprintf(MSG_ERROR, "Get wep key  index error: %d\n", apinfo->nw_key_index);
                break;

            }
            apinfo->nw_key_len = MAX_NW_KEY_LEN;
            if (wps_get_value(wps, BSS_TYPE_WEPKEY_1 - 1 + apinfo->nw_key_index, apinfo->nw_key, (size_t *)&apinfo->nw_key_len))
            {
                dprintf(MSG_ERROR, "Get wep key error from mib data \n");
                break;
            }

        }

        ret = 0;
    }while(0);


    wps_destroy_wps_data(&wps);
    return ret;
}
#endif

void * apac_mib_get_wifi_config_handle(void)
{
    return storage_getHandle();
}

void * apac_mib_apply_wifi_configuration(void *mibHandle, apacBool_e createNew)
{
    int fail = 0;

#if SON_ENABLED
    /* Indicate repacd that config is cloned */
    /*int fd = -1;
#define APAC_REPACD_PIPE_PATH       "/var/run/repacd.pipe"
    if(g_wsplcd_instance == APAC_WSPLCD_INSTANCE_PRIMARY) {
        fd = open(APAC_REPACD_PIPE_PATH, O_RDWR);
        if( fd > 0 ) {
            if(write(fd, "cloning_done", strlen("cloning_done")))
                dprintf(MSG_ERROR, "%s: repacd pipe write error\n",__func__);
        } else {
            dprintf(MSG_ERROR, "%s: repacd pipe int failed\n",__func__);
        }
        close(fd);
    }
#undef APAC_REPACD_PIPE_PATH */
    if(g_wsplcd_instance == APAC_WSPLCD_INSTANCE_PRIMARY) {
        system("echo cloning_done > /var/run/repacd.pipe &");
    }
#endif

    fail = storage_apply(mibHandle);

    if(fail)
    {
        dprintf(MSG_ERROR, "%s: failed when apply wifi config, restarting wsplcd daemon!\n", __func__);
        shutdown_fatal();
    }

    void *newHandle = NULL;
    if (createNew) {
        newHandle = storage_getHandle();
    }

    return newHandle;
}

#if MAP_ENABLED
apacBool_e apac_mib_set_interface_state(
        const char* intfName,
        const int intfState) /* 1=bring up, 0=take down*/
{
    apacHyfi20TRACE();

    if(!intfName || 0 == strlen(intfName)) return -1;

    int s = -1;
    struct ifreq ifr = {};

    if (0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        dprintf(MSG_ERROR,"%s Socket Binding fails \n", __func__);
        close(s);
        return APAC_FALSE;
    }

    dprintf(MSG_INFO, "Bringing %s %s \n", intfName, intfState ? "UP" : "Down");

    strlcpy(ifr.ifr_name, intfName, sizeof(ifr.ifr_name));
    int param[2] = {MESH_MAP_VAP_BEACONING, intfState};

    if(setMapVapBeacon_cfg80211(wlanIfWd->ctx, intfName,
                (void*)&param[0], (sizeof(int) * 2)) < 0) {
        dprintf(MSG_INFO, "%s: VAP BEACON IOCTL should already be set to %d \n", __func__,
                intfState);
    }

    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) {
        dprintf(MSG_ERROR,"%s Get Ioctl fail For intfName %s \n",__func__, intfName);
        close(s);
        return APAC_FALSE;
    }

    if (ifr.ifr_flags == (ifr.ifr_flags & ~IFF_UP)) {
        if (intfState == 0) {
            dprintf(MSG_ERROR, "%s intfName %s is already down\n", __func__, intfName);
            return APAC_TRUE;
        }
    } else {
        if (intfState == 1) {
            dprintf(MSG_ERROR, "%s intfName %s is already up\n", __func__, intfName);
            return APAC_TRUE;
        }
    }

    if (intfState) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
        dprintf(MSG_ERROR,"%s Set Ioctl fail For intfName %s \n",__func__, intfName);
        close(s);
        return APAC_FALSE;
    }

    close(s);
    return APAC_TRUE;
}

apacBool_e apac_map_set_radio_state(apacHyfi20Data_t *pData, u8 rIndex, u8 action) {
    char buf[IFNAMSIZ] = {0};
    u8 i = 0, j = 0;
    apacHyfi20IF_t *hyif = pData->hyif;

    apacHyfi20TRACE();
    snprintf(buf, sizeof(buf), "ath%d", rIndex);
    if (apac_mib_set_interface_state(buf, action) == APAC_FALSE) {
        return APAC_FALSE;
    }

    for (j = 1; j < MAX_WLAN_CONFIGURATION; j++) {
        memset(buf, 0x00, sizeof(buf));
        snprintf(buf, sizeof(buf), "ath%d%d", rIndex, j);
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
            hyif = &pData->hyif[i];

            if (hyif->valid && hyif->mediaType == APAC_MEDIATYPE_WIFI &&
                hyif->wlanDeviceMode == APAC_WLAN_AP) {
                if (!strncasecmp(hyif->ifName, buf, strlen(buf))) {
                    if (apac_mib_set_interface_state(buf, action) == APAC_FALSE) {
                        return APAC_FALSE;
                    }
                }
            }
        }
    }

    return APAC_TRUE;
}

static void apac_mib_map_vlanID_to_network(apacMapData_t *mapData, apacMapAP_t *map,
                                           int8_t vlanIdx) {
    char network[IFNAMSIZ] = {0};
    u8 nw_name_len = 0, lanIdx = 0;

    /* Set Fronthaul to network name read at init */
    if ((map->mapBssType & MAP_BSS_TYPE_FRONTHAUL) == MAP_BSS_TYPE_FRONTHAUL) {
        memset(network, '\0', IFNAMSIZ);
        if (vlanIdx >= 0) {
            memcpy(network, mapData->br_names[vlanIdx], IFNAMSIZ);
            nw_name_len = strlen(mapData->br_names[vlanIdx]);
        }
    }

    /* Set Backhaul to network name read at init */
    if (mapData->numVlanSupported != 0) {
        if (map->mapBssType & MAP_BSS_TYPE_BACKHAUL) {
            /* Set network as backhaul for r2 Device connection */
            memset(network, '\0', IFNAMSIZ);
            memcpy(network, mapData->br_backhaul, IFNAMSIZ);
            nw_name_len = strlen(mapData->br_backhaul);
            /* Set network as lan for r1 Device connection */
            if (map->mapBssType & MAP2_R2_ABOVE_BSTA_ASSOC_DISALLOW) {
                memcpy(network, mapData->br_names[lanIdx], IFNAMSIZ);
                nw_name_len = strlen(mapData->br_names[lanIdx]);
            }
        }
    }

    /* set network type to lan if vlan Removal */
    if (vlanIdx == -1) {
        memset(network, '\0', IFNAMSIZ);
        memcpy(network, mapData->br_names[lanIdx], IFNAMSIZ);
        nw_name_len = strlen(mapData->br_names[lanIdx]);
    }

    memset(map->nw_name, '\0', IFNAMSIZ);
    memcpy(map->nw_name, network, nw_name_len);
    map->nw_name[nw_name_len + 1] = '\0';
}

apacBool_e apac_mib_set_network_for_vlan(apacHyfi20Data_t *pData, apacBool_e *applyVLAN,
                                         u16 *map8021qvlan) {
    apacMapData_t *mapData = HYFI20ToMAP(pData);
    apacMapAP_t *map = NULL;
    apacBool_e vlanFound = APAC_FALSE;
    u8 i, k, total = 0, numVLANs = 0, priVlanIdx = 0, secVlanIdx = 1;
    int8_t vlanRemoveIdx = -1;
    u16 vlanID[MAP2_SERVICE_MAX_VLAN_SUPPORTED] = {0};

    total = mapData->mapEncrCnt;
    for (i = 0; i < total; i++) {
        map = &mapData->mapEncr[i];

        *map8021qvlan = map->vlan8021Q;
        if (map->vlanID == 0) {
            /* Set Network Type to Lan By Default */
            if (map->vlan8021Q != 0) {
                apac_mib_map_vlanID_to_network(mapData, map, priVlanIdx);
            } else {
                apac_mib_map_vlanID_to_network(mapData, map, vlanRemoveIdx);
            }
            continue;
        }

        for (k = 0; k < numVLANs; k++) {
            if (map->vlanID > 0) {
                if (vlanID[k] == map->vlanID) {
                    apac_mib_map_vlanID_to_network(mapData, map, k);
                    vlanFound = APAC_TRUE;
                }
            }
        }

        if (!vlanFound && map->vlanID > 0) {
            if (numVLANs > MAP2_SERVICE_MAX_VLAN_SUPPORTED) {
                dprintf(MSG_ERROR, "%s: Agent supports MAX of %d VLANs", __func__,
                        MAP2_SERVICE_MAX_VLAN_SUPPORTED);
                return APAC_FALSE;
            }

            if (map->vlanID == map->vlan8021Q) {
                vlanID[priVlanIdx] = map->vlanID;
                apac_mib_map_vlanID_to_network(mapData, map, priVlanIdx);
            } else {
                vlanID[secVlanIdx] = map->vlanID;
                apac_mib_map_vlanID_to_network(mapData, map, secVlanIdx);
                secVlanIdx++;
            }
            numVLANs++;
        }
    }

    dprintf(MSG_INFO, "%s: Number of VLANs Received %d \n", __func__, numVLANs);
    dprintf(MSG_INFO, "%s: Number of VLANs Supported %d \n", __func__, mapData->numVlanSupported);
    if (mapData->numVlanSupported != 0 && numVLANs != 0 && numVLANs <= mapData->numVlanSupported) {
        *applyVLAN = APAC_TRUE;
    }
    dprintf(MSG_INFO, "%s: Apply VLAN %s \n", __func__, *applyVLAN == APAC_TRUE ? "TRUE" : "FALSE");

    return APAC_TRUE;
}

int apac_mib_set_map_data(void *mibHandle, apacHyfi20Data_t *pData, u8 radioIdx,
                          apacHyfi20WifiFreq_e freq, const u8 *managedVapIdxList,
                          const u8 *unmanagedVapIdxList, const u8 *bstaIdxList) {
    char root[128];
    char path[256];
    char value[128];
    char networkType[128];
    apacMapAP_t *map = NULL;
    u8 index = 0, ret = 0, curVapIdx = 0, numFH = 0;
    u8 total = 0, i = 0, tearDownNo = 0, numbSTA = 0, unmanagedVAPCnt = 0;
    u16 map8021qvlan = 0;
    apacMapData_t *mapData = HYFI20ToMAP(pData);
    apacBool_e fullRadioTearDown = APAC_FALSE, applyVLAN = APAC_FALSE;

    apacHyfi20TRACE();
    // trimming it to max
    if (mapData->mapEncrCnt > MAX_WLAN_CONFIGURATION) mapData->mapEncrCnt = MAX_WLAN_CONFIGURATION;

    if (NULL == mibHandle) return -1;

    /* Get VLAN Network Settings */
    if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) >= APAC_MAP_VERSION_2) {
        if (apacHyfiMapIsTrafficSeparationEnabled(mapData) == APAC_TRUE) {
            if (apac_mib_set_network_for_vlan(pData, &applyVLAN, &map8021qvlan) == APAC_FALSE) {
                dprintf(MSG_ERROR, "%s: Invalid VLAN Config. Discard Config Apply ", __func__);
                return 0;
            }
        }
    }

    if (apacHyfiMapPfComplianceEnabled(mapData)) {
        if (mapData->map2TSSetFromHYD) {
            dprintf(MSG_ERROR, "%s: Traffic Sepration Set for PF . Dont Reapply \n ", __func__);
            return 0;
        }
    }

    total = mapData->mapEncrCnt;
    for (i = 0; i < total; i++) {
        map = &mapData->mapEncr[i];

        if (map->mapBssType & MAP_BSS_TYPE_TEARDOWN) {
            tearDownNo++;
        }

        if (map->mapBssType & MAP_BSS_TYPE_FRONTHAUL) {
            numFH++;
        }
    }

    total = mapData->mapEncrCnt;
    while (managedVapIdxList[index]) {
        dprintf(MSG_MSGDUMP, "Existing Managed VapIdxList[%d] \n", managedVapIdxList[index]);
        index++;
    }

    while (unmanagedVapIdxList[unmanagedVAPCnt]) {
        dprintf(MSG_MSGDUMP, "Existing UnManaged VapIdxList[%d] \n",
                unmanagedVapIdxList[unmanagedVAPCnt]);
        unmanagedVAPCnt++;
    }

    while (index > total - tearDownNo) {
        index--;
        dprintf(MSG_INFO, " Will Delete VAP %d during Apply \n", managedVapIdxList[index]);
        if (index == 0) {
            fullRadioTearDown = APAC_TRUE;
            /*set VAP teardown for Radio*/
            if (!mapData->isZeroBssEnabled && !apac_map_set_radio_state(pData, radioIdx - 1, 0)) {
                dprintf(MSG_ERROR, " Tear down for radioIdx %d failed", radioIdx - 1);
            }
        }
    }

    if (index != 0 && apacHyfiMapPfComplianceEnabled(mapData)) {
        /* Mark All VAPs that are up as beaconing */
        if (!apac_map_set_radio_state(pData, radioIdx - 1, 1)) {
            dprintf(MSG_ERROR, " VAP beacon set for radioIdx %d failed", radioIdx - 1);
        }
    }

    while (bstaIdxList[numbSTA]) {
        dprintf(MSG_MSGDUMP, "Existing bSTA IndexList[%d] \n", bstaIdxList[numbSTA]);
        if (bstaIdxList[numbSTA]) {
            snprintf(root, sizeof(root), "%s%d.", CONFIG_WLAN, bstaIdxList[numbSTA]);

            if (apacHyfiMapPfComplianceEnabled(mapData)) {
                /*set PBC to 0 on STA*/
                snprintf(path, sizeof(path), "%s%s", root, "wps_pbc");
                snprintf(value, sizeof(value), "%d", 0);
                storage_setParam(mibHandle, path, value);

                /*set PBC skip to 1 on STA*/
                snprintf(path, sizeof(path), "%s%s", root, "wps_pbc_skip");
                snprintf(value, sizeof(value), "%d", 1);
                storage_setParam(mibHandle, path, value);

                if (applyVLAN && map8021qvlan > 0) {
                    snprintf(path, sizeof(path), "%s%s", root, "network");
                    snprintf(value, sizeof(value), "%s", mapData->br_backhaul);
                    storage_setParam(mibHandle, path, value);

                    snprintf(path, sizeof(path), "%s%s", root, "vlan_bridge");
                    snprintf(value, sizeof(value), "%s", "br-lan");
                    storage_setParam(mibHandle, path, value);

                } else {
                    snprintf(path, sizeof(path), "%s%s", root, "network");
                    snprintf(value, sizeof(value), "%s", "lan");
                    storage_setParam(mibHandle, path, value);
                }

                /* Disable amsdu */
                snprintf(path, sizeof(path), "%s%s", root, "amsdu");
                snprintf(value, sizeof(value), "%d", 1);
                storage_setParam(mibHandle, path, value);
            }
        }
        numbSTA++;
    }

    index = 0;
    dprintf(MSG_INFO, "%s: Total Vap to be Reconfigured %d \n", __func__, total);
    for (i = 0; i < total; i++) {
        map = &mapData->mapEncr[i];

        if (fullRadioTearDown && !index) {
            if (!mapData->isZeroBssEnabled) {
                index++;
                continue;
            }
        }

        if (!managedVapIdxList[index]) {
            if ((map->mapBssType & MAP_BSS_TYPE_TEARDOWN)) {
                continue;
            }

            snprintf(path, sizeof(path), CONFIG_RADIO "%d.Add", radioIdx);
            snprintf(value, sizeof(value), "%d", radioIdx);
            ret = storage_AddVap(mibHandle, path, value);
            dprintf(MSG_INFO, "%s: New vap[ath%d] added \n", __func__, ret);
            snprintf(root, sizeof(root), "%s%d.", CONFIG_WLAN, ret);
            if (mapData->isZeroBssEnabled) {
                index++;
            }
        } else {
            snprintf(root, sizeof(root), "%s%d.", CONFIG_WLAN, (int)managedVapIdxList[index]);
            curVapIdx = (u8)managedVapIdxList[index];
            index++;
        }
        /* VAP set to Bss Type TearDown will be deleted during APPLY */
        dprintf(MSG_INFO, "%s: Configure %s with MapBSSType=%d, vlanID=%d, network=%s \n", __func__,
                root, map->mapBssType, map->vlanID, map->nw_name);
        dprintf(MSG_INFO, "%s: Reset Traffic Separation Settings %d \n", __func__,
                map->validTSPolicy);

        /*set SSID*/
        snprintf(path, sizeof(path), "%s%s", root, "SSID");
        storage_setParam(mibHandle, path, map->ssid);

        snprintf(path, sizeof(path), "%s%s", root, "Enable");
        snprintf(value, sizeof(value), "%d", 1);
        if ((map->mapBssType & MAP_BSS_TYPE_TEARDOWN)) {
            snprintf(value, sizeof(value), "%d", 0);
        }
        storage_setParam(mibHandle, path, value);

        snprintf(path, sizeof(path), "%s%s", root, "X_ATH-COM_RadioIndex");
        snprintf(value, sizeof(value), "%d", radioIdx);
        storage_setParam(mibHandle, path, value);

        snprintf(path, sizeof(path), "%s%s", root, "network");
        if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) == APAC_MAP_VERSION_1) {
            snprintf(value, sizeof(value), "%s", "lan");
        } else if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) >= APAC_MAP_VERSION_2) {
            memset(networkType, '\0', 128);
            apac_mib_get_wlan_network_by_vapindex(curVapIdx, networkType);
            snprintf(value, sizeof(value), "%s", "lan");
            if (applyVLAN) {
                snprintf(value, sizeof(value), "%s", map->nw_name);
            }
            /* if traffic separation policy is not received in WSC message leave config unchanged as
             * Traffic separation will be applied through HYD policy */
            if (map->validTSPolicy == 0) {
                dprintf(MSG_INFO, " Network Type %s\n ", networkType);
                if (strlen(networkType)) {
                    snprintf(value, sizeof(value), "%s", networkType);
                }
            }
        }
        storage_setParam(mibHandle, path, value);

        if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) >= APAC_MAP_VERSION_2 &&
            (map->mapBssType == (MAP_BSS_TYPE_BACKHAUL| MAP2_R1_BSTA_ASSOC_DISALLOW)) &&
            applyVLAN
            ) {
            snprintf(path, sizeof(path), "%s%s", root, "vlan_bridge");
            snprintf(value, sizeof(value), "%s", "br-lan");
            storage_setParam(mibHandle, path, value);
        }

        snprintf(path, sizeof(path), "%s%s", root, "mode");
        snprintf(value, sizeof(value), "%s", "ap");
        storage_setParam(mibHandle, path, value);

        if (map->auth & WPS_AUTHTYPE_WPA3) {
            /*WPA3 */
            /*set BeaconType*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "11i");
            storage_setParam(mibHandle, path, value);

            /*set auth type*/
            snprintf(path, sizeof(path), "%s%s", root, "IEEE11iAuthenticationMode");
            snprintf(value, sizeof(value), "%s", "WPA3Authentication");
            storage_setParam(mibHandle, path, value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
            if (map->encr & WPS_ENCRTYPE_AES) {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
            storage_setParam(mibHandle, path, value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
            if (map->encr & WPS_ENCRTYPE_AES) {
                if (map->encr & WPS_ENCRTYPE_TKIP) {
                    snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
                } else {
                    snprintf(value, sizeof(value), "%s", "AESEncryption");
                }
            } else {
                snprintf(value, sizeof(value), "%s", "TKIPEncryption");
            }
            storage_setParam(mibHandle, path, value);

            /*set PSK or passphrase*/
            // NOTE: SAE uses sae_password and does not require KeyPassphrase
            // But due to a bug in Host module , using sae_password does not authenticate in
            // hostapd/supplicant application
            // The workaround is to use "key" parameter instead of "sae_password"

            snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
            if (map->nw_key_len == 64) {
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            } else {
                storage_setParam(mibHandle, path, "");

                snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            }
            snprintf(path, sizeof(path), "%s%s", root, "EnableSAE");
            memset(value, 0, sizeof(value));
            snprintf(value, sizeof(value), "%d", 1);
            storage_setParam(mibHandle, path, value);
        }
        if (map->auth & WPS_AUTHTYPE_WPA2PSK) {
            /*WPA2PSK or WPA2PSK/WPAPSK*/
            /*set BeaconType*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");

            if (map->auth & WPS_AUTHTYPE_WPAPSK) {
                snprintf(value, sizeof(value), "%s", "WPAand11i");
            } else {
                snprintf(value, sizeof(value), "%s", "11i");
            }
            storage_setParam(mibHandle, path, value);

            /*set auth type*/
            snprintf(path, sizeof(path), "%s%s", root, "IEEE11iAuthenticationMode");
            snprintf(value, sizeof(value), "%s", "PSKAuthentication");
            storage_setParam(mibHandle, path, value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");

            if (map->encr & WPS_ENCRTYPE_AES) {
                if (map->encr & WPS_ENCRTYPE_TKIP) {
                    snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
                } else {
                    snprintf(value, sizeof(value), "%s", "AESEncryption");
                }
            } else {
                snprintf(value, sizeof(value), "%s", "TKIPEncryption");
            }
            storage_setParam(mibHandle, path, value);

            /*set PSK or passphrase*/
            snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
            if (map->nw_key_len == 64) {
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            } else {
                storage_setParam(mibHandle, path, "");
                snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            }

        } else if (map->auth & WPS_AUTHTYPE_WPAPSK) {
            /*WPAPSK*/
            /*set BeaconType*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "WPA");
            storage_setParam(mibHandle, path, value);

            /*set auth type*/
            snprintf(path, sizeof(path), "%s%s", root, "WPAAuthenticationMode");
            snprintf(value, sizeof(value), "%s", "PSKAuthentication");
            storage_setParam(mibHandle, path, value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "WPAEncryptionModes");
            if (map->encr & WPS_ENCRTYPE_AES) {
                if (map->encr & WPS_ENCRTYPE_TKIP) {
                    snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
                } else {
                    snprintf(value, sizeof(value), "%s", "AESEncryption");
                }
            } else {
                snprintf(value, sizeof(value), "%s", "TKIPEncryption");
            }
            storage_setParam(mibHandle, path, value);
            /*set PSK or passphrase*/
            snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
            if (map->nw_key_len == 64) {
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            } else {
                storage_setParam(mibHandle, path, "");
                snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
                storage_setParam(mibHandle, path, (char *)map->nw_key);
            }

        } else if ((map->auth & WPS_AUTHTYPE_OPEN) || (map->auth & WPS_AUTHTYPE_SHARED)) {
            /*WEP or OPEN*/
            if (map->encr & WPS_ENCRTYPE_WEP) {
                /*WEP*/
                /*set beacon type*/
                snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
                snprintf(value, sizeof(value), "%s", "Basic");
                storage_setParam(mibHandle, path, value);

                /*set encr type*/
                snprintf(path, sizeof(path), "%s%s", root, "BasicEncryptionModes");
                snprintf(value, sizeof(value), "%s", "WEPEncryption");
                storage_setParam(mibHandle, path, value);

                /*set auth type*/
                snprintf(path, sizeof(path), "%s%s", root, "BasicAuthenticationMode");
                if (map->auth & WPS_AUTHTYPE_SHARED) {
                    snprintf(value, sizeof(value), "%s", "SharedAuthentication");
                } else {
                    snprintf(value, sizeof(value), "%s", "None");
                }
                storage_setParam(mibHandle, path, value);
                /*set wep key idx*/
                snprintf(path, sizeof(path), "%s%s", root, "WEPKeyIndex");
                snprintf(value, sizeof(value), "%d", map->nw_key_index);
                storage_setParam(mibHandle, path, value);
                for (i = 1; i <= 4; i++) {
                    /*set wep keys*/
                    snprintf(path, sizeof(path), "%sWEPKey.%d.WEPKey", root, i);
                    if (i == map->nw_key_index)
                        storage_setParam(mibHandle, path, (char *)map->nw_key);
                    else
                        storage_setParam(mibHandle, path, "");
                }
            } else {
                /*OPEN*/
                /*set beacon type*/
                snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
                snprintf(value, sizeof(value), "%s", "None");
                storage_setParam(mibHandle, path, value);
            }
        }

        /*set authentication server mode to none*/
        snprintf(path, sizeof(path), "%s%s", root, "AuthenticationServiceMode");
        snprintf(value, sizeof(value), "%s", "None");
        storage_setParam(mibHandle, path, value);

        /* set Map */
        snprintf(path, sizeof(path), "%s%s", root, "map");
        snprintf(value, sizeof(value), "%d", apacHyfiMapIsEnabled(HYFI20ToMAP(pData)));
        storage_setParam(mibHandle, path, value);

        /* set MapBSSType */
        snprintf(path, sizeof(path), "%s%s", root, "MapBSSType");
        snprintf(value, sizeof(value), "%d", map->mapBssType);
        storage_setParam(mibHandle, path, value);

        if (map->mapBssType & MAP_BSS_TYPE_BACKHAUL) {
            /*set PBC to 0*/
            snprintf(path, sizeof(path), "%s%s", root, "wps_pbc");
            snprintf(value, sizeof(value), "%d", 0);
            storage_setParam(mibHandle, path, value);
        }

        /* Always set FH PBC after BH as we might have single VAP both as FH and
         * BH */
        if (map->mapBssType & MAP_BSS_TYPE_FRONTHAUL) {
            /*set PBC to 1 only on one FH as it causes overlap connections when
             * set on multiple at once */
            snprintf(path, sizeof(path), "%s%s", root, "wps_pbc");
            if (numFH == 1) {
                snprintf(value, sizeof(value), "%d", 1);
            } else {
                snprintf(value, sizeof(value), "%d", 0);
            }
            storage_setParam(mibHandle, path, value);
            numFH -= 1;
        }

        /*set PBC Enable*/
        snprintf(path, sizeof(path), "%s%s", root, "wps_pbc_enable");
        snprintf(value, sizeof(value), "%d", 0);
        storage_setParam(mibHandle, path, value);

        /*set PBC Start Time*/
        snprintf(path, sizeof(path), "%s%s", root, "wps_pbc_start_time");
        snprintf(value, sizeof(value), "%d", 0);
        storage_setParam(mibHandle, path, value);

        /*set PBC Duration*/
        snprintf(path, sizeof(path), "%s%s", root, "wps_pbc_duration");
        snprintf(value, sizeof(value), "%d", 120);
        storage_setParam(mibHandle, path, value);

        /*WDS*/
        snprintf(path, sizeof(path), "%s%s", root, "wds");
        snprintf(value, sizeof(value), "%d", 1);
        storage_setParam(mibHandle, path, value);

        /*RRM*/
        snprintf(path, sizeof(path), "%s%s", root, "rrm");
        snprintf(value, sizeof(value), "%d", 1);
        storage_setParam(mibHandle, path, value);

        if ((apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) > APAC_MAP_VERSION_2) &&
            apacHyfiMapPfComplianceEnabled(HYFI20ToMAP(pData))) {
            /* Set TX STBC to 0 */
            snprintf(path, sizeof(path), "%s%s", root, "tx_stbc");
            snprintf(value, sizeof(value), "%d", 0);
            storage_setParam(mibHandle, path, value);

            /* Set RX STBC to 0 */
            snprintf(path, sizeof(path), "%s%s", root, "rx_stbc");
            snprintf(value, sizeof(value), "%d", 0);
            storage_setParam(mibHandle, path, value);
        }

        if (apacHyfiMapPfComplianceEnabled(HYFI20ToMAP(pData))) {
            /* Disable amsdu */
            snprintf(path, sizeof(path), "%s%s", root, "amsdu");
            snprintf(value, sizeof(value), "%d", 1);
            storage_setParam(mibHandle, path, value);
        }

        snprintf(path, sizeof(path), "%s%s", root, "SteeringDisabled");
        if(map->vap_disable_steering == 1) {
            snprintf(value, sizeof(value), "%d", map->vap_disable_steering);
            storage_setParam(mibHandle, path, value);
        }

        if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) >= APAC_MAP_VERSION_2) {
            if (mapData->r2EnableMboOcePmf) {
                /* Enable MBO */
                snprintf(path, sizeof(path), "%s%s", root, "mbo");
                snprintf(value, sizeof(value), "%d", 1);
                storage_setParam(mibHandle, path, value);

                /* Enable OCE */
                snprintf(path, sizeof(path), "%s%s", root, "oce");
                snprintf(value, sizeof(value), "%d", 1);
                storage_setParam(mibHandle, path, value);

                /* Enable PMF */
                snprintf(path, sizeof(path), "%s%s", root, "IEEE80211w");
                snprintf(value, sizeof(value), "%d", 1);
                storage_setParam(mibHandle, path, value);
            }

            /* if traffic separation policy is not received in WSC message leave config unchanged as
             * Traffic separation will be applied through HYD policy */
            if (map->validTSPolicy == 1) {
                /* Set VLAN ID */
                snprintf(path, sizeof(path), "%s%s", root, "mapVlanID");
                snprintf(value, sizeof(value), "%d", map->vlanID);
                storage_setParam(mibHandle, path, value);

                /* Set 8021Q VLAN */
                snprintf(path, sizeof(path), "%s%s", root, "map8021qvlan");
                snprintf(value, sizeof(value), "%d", map->vlan8021Q);
                storage_setParam(mibHandle, path, value);
            }

            snprintf(path, sizeof(path), "%s%s", root, "SAEPassword");
            if (map->sae_password_len) {
                snprintf(value, sizeof(value), "%s", map->sae_password);
                storage_setParam(mibHandle, path, value);
            } else
                storage_setParam(mibHandle, path, "");

            snprintf(path, sizeof(path), "%s%s", root, "SAEAntiCloggingThreshold");
            if (map->sae_anticloggingthreshold != 0xff) {
                snprintf(value, sizeof(value), "%d", map->sae_anticloggingthreshold);
                storage_setParam(mibHandle, path, value);
            } else
                storage_setParam(mibHandle, path, "");

            snprintf(path, sizeof(path), "%s%s", root, "SAESync");
            if (map->sae_sync != 0xff) {
                snprintf(value, sizeof(value), "%d", map->sae_sync);
                storage_setParam(mibHandle, path, value);
            } else
                storage_setParam(mibHandle, path, "");

            snprintf(path, sizeof(path), "%s%s", root, "SAEGroups");
            if (strlen(map->sae_groups) != APAC_FALSE) {
                snprintf(value, sizeof(value), "%s", map->sae_groups);
                storage_setParam(mibHandle, path, value);
            } else
                storage_setParam(mibHandle, path, "");

            snprintf(path, sizeof(path), "%s%s", root, "SAERequireMFP");
            if (map->sae_requireMFP != 0xff) {
                snprintf(value, sizeof(value), "%d", map->sae_requireMFP);
                storage_setParam(mibHandle, path, value);
            } else
                storage_setParam(mibHandle, path, "");
        }
    }

    // Reinit to zero for next attempt
    mapData->mapEncrCnt = 0;

    return 0;
}
#endif

#if SON_ENABLED
int apac_mib_set_wifi_configuration(apacHyfi20Data_t* pApacData, apacHyfi20AP_t* apinfo, int vap_type,
        int vap_index, const char* ssid_suffix, apacBool_e changeBand,
        apacBool_e manageVAPInd, apacBool_e deepCloneNoBSSID)
{
    int fail = 0;
    char path[256];
    char value[128];
    int i;
    char root[128];
    char final_ssid[256];
    void *mibHandle;
    apacHyfi20IF_t *vapInterface = NULL;

    mibHandle = pApacData->wifiConfigHandle;
    if(NULL == mibHandle)
    {
        return -1;
    }

    if (!apinfo || strlen(apinfo->ssid) ==0)
        return -1;

    snprintf(root, sizeof(root), "%s%d.", CONFIG_WLAN, vap_index);

    /*set SSID*/
    snprintf(path, sizeof(path), "%s%s", root, "SSID");
    snprintf(final_ssid, sizeof(final_ssid), "%s%s", apinfo->ssid, ssid_suffix);
    storage_setParam(mibHandle, path, final_ssid);

    /*set Standard
     * Warning: For DBSR device, the PHY mode may be lower than what the radio
     *          is capable of. Deep cloning can be used to set the Registrar's
     *          PHY mode. It should be revisited when there is such DBSR platform to test.
     */
    if (changeBand) {
        const char STANDARD2G[] = "ng20";
        const char STANDARD5G[] = "na40plus";

        snprintf(path, sizeof(path), "%s%s", root, "Standard");
        if (apinfo->freq == APAC_WIFI_FREQ_2) {
            snprintf(value, sizeof(value), "%s", STANDARD2G);
        }
        else if (apinfo->freq == APAC_WIFI_FREQ_5) {
            snprintf(value, sizeof(value), "%s", STANDARD5G);
        }
        else {
            dprintf(MSG_ERROR, "%s, not able to find MIB value for freq %u\n", __func__, apinfo->freq);
            return -1;
        }
        storage_setParam(mibHandle,path,value);

        /* Set Channel, it may be overwrite by QCA deep cloning */
        snprintf(path, sizeof(path), "%s%s", root, "Channel");
        snprintf(value, sizeof(value), "%d", 0);    /* always set channel to 0 */
        storage_setParam(mibHandle,path,value);
    }

    if (apinfo->auth & WPS_AUTHTYPE_WPA3) {
        /*WPA3 */
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
        snprintf(value, sizeof(value), "%s", "11i");
        storage_setParam(mibHandle, path, value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iAuthenticationMode");
        snprintf(value, sizeof(value), "%s", "WPA3Authentication");
        storage_setParam(mibHandle, path, value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
        if (apinfo->encr & WPS_ENCRTYPE_AES) {
            snprintf(value, sizeof(value), "%s", "AESEncryption");
        }
        storage_setParam(mibHandle, path, value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
        if (apinfo->encr & WPS_ENCRTYPE_AES) {
            if (apinfo->encr & WPS_ENCRTYPE_TKIP) {
                snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
            } else {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
        } else {
            snprintf(value, sizeof(value), "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle, path, value);

        /*set PSK or passphrase*/
        // NOTE: SAE uses sae_password and does not require KeyPassphrase
        // But due to a bug in Host module , using sae_password does not authenticate in hostapd/supplicant application
        // The workaround is to use "key" parameter instead of "sae_password"

        if( apinfo->is_key_set == APAC_TRUE )
        {
            snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
            if (apinfo->nw_key_len == 64)
            {
                storage_setParam(mibHandle, path, (char*)apinfo->nw_key);
            }
            else
            {
                storage_setParam(mibHandle,path,"");

                snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
                storage_setParam(mibHandle, path, (char*)apinfo->nw_key);
            }
        }
        else
        {
            snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
            storage_setParam(mibHandle, path, "");
            snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
            storage_setParam(mibHandle, path, "");
        }
    }
    if (apinfo->auth & WPS_AUTHTYPE_WPA2PSK) {
        /*WPA2PSK or WPA2PSK/WPAPSK*/
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
        if (apinfo->auth & WPS_AUTHTYPE_WPAPSK) {
            snprintf(value, sizeof(value), "%s", "WPAand11i");
        } else {
            snprintf(value, sizeof(value), "%s", "11i");
        }
        storage_setParam(mibHandle,path,value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iAuthenticationMode");
        snprintf(value, sizeof(value), "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "IEEE11iEncryptionModes");
        if (apinfo->encr & WPS_ENCRTYPE_AES) {
            if (apinfo->encr & WPS_ENCRTYPE_TKIP) {
                snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
            } else {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
        } else {
            snprintf(value, sizeof(value), "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value);

        /*set PSK or passphrase*/
        snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
        if (apinfo->nw_key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)apinfo->nw_key);
        }
        else
        {
            storage_setParam(mibHandle,path,"");

            snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
            storage_setParam(mibHandle,path,(char*)apinfo->nw_key);
        }

    }
    else if (apinfo->auth & WPS_AUTHTYPE_WPAPSK) {
        /*WPAPSK*/
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
        snprintf(value, sizeof(value), "%s", "WPA");
        storage_setParam(mibHandle,path,value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%s", root, "WPAAuthenticationMode");
        snprintf(value, sizeof(value), "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%s", root, "WPAEncryptionModes");
        if (apinfo->encr & WPS_ENCRTYPE_AES) {
            if (apinfo->encr & WPS_ENCRTYPE_TKIP) {
                snprintf(value, sizeof(value), "%s", "TKIPandAESEncryption");
            } else {
                snprintf(value, sizeof(value), "%s", "AESEncryption");
            }
        } else {
            snprintf(value, sizeof(value), "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value);

        /*set PSK or passphrase*/
        snprintf(path, sizeof(path), "%s%s", root, "PreSharedKey.1.PreSharedKey");
        if (apinfo->nw_key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)apinfo->nw_key);
        }
        else
        {
            storage_setParam(mibHandle,path,"");
            snprintf(path, sizeof(path), "%s%s", root, "KeyPassphrase");
            storage_setParam(mibHandle,path,(char*)apinfo->nw_key);
        }

    } else if ((apinfo->auth & WPS_AUTHTYPE_OPEN)
            || (apinfo->auth & WPS_AUTHTYPE_SHARED)) {
        /*WEP or OPEN*/
        if (apinfo->encr & WPS_ENCRTYPE_WEP) {
            /*WEP*/
            /*set beacon type*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "Basic");
            storage_setParam(mibHandle,path,value);

            /*set encr type*/
            snprintf(path, sizeof(path), "%s%s", root, "BasicEncryptionModes");
            snprintf(value, sizeof(value), "%s", "WEPEncryption");
            storage_setParam(mibHandle,path,value);

            /*set auth type*/
            snprintf(path, sizeof(path), "%s%s", root, "BasicAuthenticationMode");
            if (apinfo->auth & WPS_AUTHTYPE_SHARED) {
                snprintf(value, sizeof(value), "%s", "SharedAuthentication");
            } else {
                snprintf(value, sizeof(value), "%s", "None");
            }
            storage_setParam(mibHandle,path,value);

            /*set wep key idx*/
            snprintf(path, sizeof(path), "%s%s", root, "WEPKeyIndex");
            snprintf(value, sizeof(value), "%d", apinfo->nw_key_index);
            storage_setParam(mibHandle,path,value);

            for (i = 1; i <= 4; i ++) {
                /*set wep keys*/
                snprintf(path, sizeof(path), "%sWEPKey.%d.WEPKey", root, i);
                if (i == apinfo->nw_key_index)
                    storage_setParam(mibHandle,path,(char*)apinfo->nw_key);
                else
                    storage_setParam(mibHandle,path,"");
            }
        }
        else {
            /*OPEN*/
            /*set beacon type*/
            snprintf(path, sizeof(path), "%s%s", root, "BeaconType");
            snprintf(value, sizeof(value), "%s", "None");
            storage_setParam(mibHandle,path,value);
        }
    }

    /*set authentication server mode to none*/
    snprintf(path, sizeof(path), "%s%s", root, "AuthenticationServiceMode");
    snprintf(value, sizeof(value), "%s", "None");
    storage_setParam(mibHandle,path,value);

    /*Deep cloning, QCA Vendor Extension*/
    if (apinfo->qca_ext && apinfo->qca_ext_len)
    {
        if (apac_mib_set_qca_ext(mibHandle, apinfo, vap_type, vap_index,
                    manageVAPInd, deepCloneNoBSSID) != 0)
            dprintf(MSG_ERROR, "failed to set Deepcloning QCA extension!\n");
        if (apac_mib_set_qca_ext_wpa3(pApacData, apinfo, vap_type, vap_index) != 0 )
            dprintf(MSG_ERROR, "failed to set WPA3 QCA extension!\n");
    }
    else
    {
        /* Cleanup WPA3 parameter in libstorage */
        const struct apac_mib_param_set * mibset = apac_wpa3_param_sets;
        vapInterface = apac_mib_find_vap_interface(pApacData, vap_index);

        while(mibset && mibset->name) {
            snprintf(path, sizeof(path), "%s%s", root, mibset->name);
            storage_setParam(mibHandle,path,"");
            mibset ++;
        }
        if (vapInterface != NULL) {
            if (vapInterface->sae_password_list != NULL) {
                snprintf(path, sizeof(path), "%s%s", root, "DeleteSAEPassword");
                apac_mib_sae_password_cleanup(mibHandle, path, vapInterface->sae_password_list);
                vapInterface->sae_password_list = NULL;
            }
            if (vapInterface->sae_groups_list != NULL) {
                snprintf(path, sizeof(path), "%s%s", root, "DeleteSAEGroups");
                apac_mib_list_parameter_cleanup(mibHandle,path, vapInterface->sae_groups_list);
                vapInterface->sae_groups_list = NULL;
            }
            if (vapInterface->owe_groups_list != NULL) {
                snprintf(path, sizeof(path), "%s%s", root, "DeleteOWEGroups");
                apac_mib_list_parameter_cleanup(mibHandle, path, vapInterface->owe_groups_list);
                vapInterface->owe_groups_list = NULL;
            }
        }
    }

    dprintf(MSG_WARNING, "[WSPLCD] set cloned configuration to vap %d\n", vap_index);

    return fail;
}
#endif

int apac_mib_get_opmode(char *mibpath, struct wps_data *wps) {
    char opMode[128];
    size_t modeLength = sizeof(opMode);
    const struct apac_mib_param_set apac_op_mode_type[] = {
        {"DeviceOperationMode", BSS_TYPE_DEV_OPMODE, WPS_VALTYPE_PTR}, {NULL, 0, 0}, };

    if (apac_get_mib_data_in_wpsdata(mibpath, apac_op_mode_type, wps, 0) == 0) {
        memset(opMode, 0, sizeof(opMode));
        if (wps_get_value(wps, BSS_TYPE_DEV_OPMODE, opMode, (size_t *)&modeLength)) {
            dprintf(MSG_ERROR, "Get Op Mode error from mib data %s\n", mibpath);
        }
        if (strncmp(opMode, "WDSStation", modeLength) == 0) {
            return APAC_WLAN_STA;
        } else {
            return APAC_WLAN_AP;
        }
    }
    return 0;
}

u8 apacMibGetVapIdxByRadioId(int radioId, u8 *managedVAPList, u8 *unmanagedVAPList, u8 *bstaList) {
    u8 i, j = 0, bstaTotal = 0, unmanagedVAPCnt = 0, wlanVapIdx = 0;
    int ret = -1;
    char mibpath[256] = {0};
    char value[128] = {0};
    size_t length;
    struct wps_data *wps;
    int val = 0;
    const struct apac_mib_param_set apac_bss_name[] = {
        {"X_ATH-COM_RadioIndex", BSS_TYPE_RADIOINDEX, WPS_VALTYPE_PTR}, {NULL, 0, 0}, };

    for (i = 0; i < MAX_WLAN_CONFIGURATION; i++) {
        wps = 0;
        if (wps_create_wps_data(&wps)) {
            break;
        }

        wlanVapIdx = i + 1;
        snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN "%d", wlanVapIdx);

        if (apac_get_mib_data_in_wpsdata(mibpath, apac_bss_name, wps, 0) == 0) {
            length = sizeof(value);

            if (wps_get_value(wps, BSS_TYPE_RADIOINDEX, value, (size_t *)&length) == 0) {
                val = atoi(value);

                if (val == radioId) {
                    if (apac_mib_get_opmode(mibpath, wps) == APAC_WLAN_STA) {
                        bstaList[bstaTotal] = wlanVapIdx;
                        bstaTotal++;
                        wps_destroy_wps_data(&wps);
                        continue;
                    }
                    if (apac_mib_get_wsplcdUnmanaged_by_vapindex(wlanVapIdx) > 0) {
                        unmanagedVAPList[unmanagedVAPCnt] = wlanVapIdx;
                        unmanagedVAPCnt++;
                        wps_destroy_wps_data(&wps);
                        continue;
                    }
                    managedVAPList[j] = wlanVapIdx;
                    ret = 0;
                    j++;
                }
            }
        }

        wps_destroy_wps_data(&wps);
    }

    return ret;
}

#if MAP_ENABLED
int apac_mib_get_ssid(char *mibpath, struct wps_data *wps, char *ssid)
{
    size_t ssidLength = MAX_SSID_LEN;
    const struct apac_mib_param_set apac_ssid_type[] = {
        { "SSID", BSS_TYPE_SSID, WPS_VALTYPE_PTR}, {NULL, 0, 0}, };

    if (apac_get_mib_data_in_wpsdata(mibpath, apac_ssid_type, wps, 0) == 0) {
        memset(ssid, 0, MAX_SSID_LEN);
        if (wps_get_value(wps, BSS_TYPE_SSID, ssid, (size_t *)&ssidLength)) {
            dprintf(MSG_ERROR, "Get SSID error from mib data %s\n", mibpath);
        }
    }
    return 0;
}

int apacMibGetVapIdxbySSID(int RadioIdx, const char* ssidMatcher)
{
    u8 i=0;
    int ret=-1,wlanVapIdx=0;
    char mibpath[256] = {0};
    char value[128] = {0};
    size_t length;
    struct wps_data *wps;
    int val = 0;
    char ssid[MAX_SSID_LEN] = {0};
    int ssidLen=strlen(ssidMatcher);
    const struct apac_mib_param_set apac_bss_name[] = {
        {"X_ATH-COM_RadioIndex", BSS_TYPE_RADIOINDEX, WPS_VALTYPE_PTR}, {NULL, 0, 0}, };

    for (i = 0; i < MAX_WLAN_CONFIGURATION; i++) {
        wps = 0;
        if (wps_create_wps_data(&wps)) {
            break;
        }

        wlanVapIdx = i + 1;
        snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN "%d", wlanVapIdx);

        if (apac_get_mib_data_in_wpsdata(mibpath, apac_bss_name, wps, 0) == 0) {
            length = sizeof(value);
            if (wps_get_value(wps, BSS_TYPE_RADIOINDEX, value, (size_t *)&length) == 0) {
                val = atoi(value);

                if (val == RadioIdx) {
                    apac_mib_get_ssid(mibpath, wps, ssid);
                    if (strncmp(ssidMatcher, ssid, ssidLen) == 0) {
                        ret=wlanVapIdx;
                    }
                }
            }
        }

        wps_destroy_wps_data(&wps);

        if (ret != -1)
            break;
    }

    return ret;
}

int apacMibGetRadioIdxByMacAddr(u8 *mac)
{
    int i;
    int ret = 0;
    char  mibpath[256] = {0};
    char  value[128] = {0};
    size_t   length;
    struct wps_data *wps;
    const struct apac_mib_param_set radio_mac_address[] = {
        { "macaddr",    RADIO_TYPE_MACADDRESS, WPS_VALTYPE_PTR},
        { NULL, 0, 0},
    };

    if (!mac)
        return 0;

    for (i=0; i < MAX_RADIO_CONFIGURATION; i++) {
        wps = 0;

        if(wps_create_wps_data(&wps)) {
            break;
        }

        snprintf(mibpath, sizeof(mibpath), CONFIG_RADIO"%d", i+1);

        if ( apac_get_mib_data_in_wpsdata(mibpath, radio_mac_address, wps, 0) == 0) {
            length = sizeof(value);

            if (wps_get_value(wps, RADIO_TYPE_MACADDRESS, value, (size_t *)&length) == 0) {
                dprintf(MSG_DEBUG," Searching Mib Mac address  %s \n",value);
                const struct ether_addr *staAddr = ether_aton(value);

                if(staAddr)
                    if (!os_memcmp(staAddr->ether_addr_octet, mac, IEEE80211_ADDR_LEN)) {
                        wps_destroy_wps_data(&wps);
                        return i+1;//index
                    }
            } else {
                wps_destroy_wps_data(&wps);
                break;
            }
        }
        wps_destroy_wps_data(&wps);
        memset(value, 0x00, 128);
        memset(mibpath, 0x00, 256);
    }

    return ret;
}
#endif

int apac_mib_get_vapindex(const char *ifname)
{
    int i;
    int ret = -1;
    char  mibpath[256];
    char  value[128];
    size_t   length;
    struct wps_data *wps;
    const struct apac_mib_param_set apac_bss_name[] = {
        { "X_ATH-COM_VapIfname", BSS_TYPE_IFNAME, WPS_VALTYPE_PTR},
        { NULL, 0, 0},
    };

    for (i=0; i < MAX_WLAN_CONFIGURATION; i++)
    {
        wps = 0;
        if(wps_create_wps_data(&wps)) {
            break;
        }

        snprintf(mibpath, sizeof(mibpath), CONFIG_WLAN"%d", i+1);
        if ( apac_get_mib_data_in_wpsdata(mibpath, apac_bss_name, wps, 0) == 0)
        {
            length = sizeof(value);
            if (wps_get_value(wps, BSS_TYPE_IFNAME, value, (size_t *)&length) == 0
                    && length == strlen(ifname)
                    && memcmp(ifname, value, length) == 0 )
            {
                wps_destroy_wps_data(&wps);
                ret = i + 1;
                break;
            }
        }

        wps_destroy_wps_data(&wps);

    }

    return ret;
}

int apac_mib_get_wsplcdUnmanaged_by_vapindex(int vap_index)
{
    char path[256];
    size_t len;

    int wsplcdUnmanaged = -1;
    struct wps_data *wps = 0;

    if(wps_create_wps_data(&wps)) {
        return wsplcdUnmanaged;
    }

    do{
        snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

        if ( apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0)
        {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        len = sizeof(wsplcdUnmanaged);
        if (wps_get_value(wps, BSS_TYPE_WSPLCD_UNMANAGED, &wsplcdUnmanaged, &len))
        {
            dprintf(MSG_ERROR, "Get Wsplcd Unmanaged error from mib data \n");
            break;
        }

    }while(0);

    wps_destroy_wps_data(&wps);
    return wsplcdUnmanaged;
}

int apac_mib_get_wlan_standard_by_vapindex(int vap_index, char *standard)
{
    char path[256] = {0};
    char buf[1024] = {0};
    size_t len = 0;

    int ret = -1;
    int i = 1;
    struct wps_data *wps = 0;


    if(wps_create_wps_data(&wps))
        return ret;

    do{
        snprintf(path, sizeof(path),CONFIG_WLAN"%d", vap_index);

        if ( apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0)
        {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        len = sizeof(buf);
        /* Get standard takes time in case of auto channel with 160Mhz
        Instead if asserting trying to get the standard for 5 iterations*/
        while (i <= 5)
        {
            if (wps_get_value(wps, BSS_TYPE_STANDARD, buf, &len))
            {
                dprintf(MSG_ERROR, "Get standard error from mib data \n");
                sleep (1);
                ++i;
            }
            else {
                break;
            }
        }
        ret = 0;
    }while(0);

    os_memcpy(standard, buf, len);
    standard[len] = '\0';

    wps_destroy_wps_data(&wps);
    return ret;
}


int apac_mib_get_radio_by_vapindex(int vap_index)
{
    char path[256];
    size_t len;

    int radioIndex = -1;
    struct wps_data *wps = 0;


    if(wps_create_wps_data(&wps))
        return radioIndex;

    do{
        snprintf(path, sizeof(path),CONFIG_WLAN"%d", vap_index);

        if ( apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0)
        {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        len = sizeof(radioIndex);
        if (wps_get_value(wps, BSS_TYPE_RADIOINDEX, &radioIndex, &len))
        {
            dprintf(MSG_ERROR, "Get RADIO error from mib data \n");
            break;
        }

    }while(0);



    wps_destroy_wps_data(&wps);
    return radioIndex;
}

int apac_mib_get_bsstype_by_vapindex(int vap_index, uint32_t *bss_type) {
    char path[256] = {0};
    size_t len = 0;

    int ret = -1;
    struct wps_data *wps = 0;

    if (wps_create_wps_data(&wps)) {
        return ret;
    }

    do {
        snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

        if (apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0) {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        len = sizeof(uint32_t);
        if (wps_get_value(wps, BSS_TYPE_BACKHAUL_AP, bss_type, &len)) {
            dprintf(MSG_ERROR, "Get standard error from mib data \n");
            break;
        }
        ret = 0;
    } while (0);

    wps_destroy_wps_data(&wps);
    return ret;
}


int apac_mib_get_wlan_network_by_vapindex(int vap_index, char *network) {
    char path[256] = {0};
    char buf[1024] = {0};
    size_t len = 0;

    int ret = -1;
    struct wps_data *wps = 0;

    if (wps_create_wps_data(&wps)) {
        return ret;
    }

    do {
        snprintf(path, sizeof(path), CONFIG_WLAN"%d", vap_index);

        if (apac_get_mib_data_in_wpsdata(path, apac_bss_sets, wps, NULL) != 0) {
            dprintf(MSG_ERROR, "Get mib data error: %s\n", path);
            break;
        }

        len = sizeof(buf);
        if (wps_get_value(wps, BSS_TYPE_NETWORK, buf, &len)) {
            dprintf(MSG_ERROR, "Get standard error from mib data \n");
            break;
        }
        ret = 0;
    } while (0);

    os_memcpy(network, buf, len);
    network[len] = '\0';

    wps_destroy_wps_data(&wps);
    return ret;
}

int apac_mib_set_ucpk(apacHyfi20Data_t *pData, const char *wpapsk, const char *plcnmk) {
    void *mibHandle = NULL;
    int fail = 0;
    char path[128];
    char  value[128];
    int i;
    char *beacontype, *authtype, *encrtype;
    apacHyfi20IF_t *pIF = pData->hyif;

    beacontype = "11i";
    authtype = "PSKAuthentication";
    encrtype = "AESEncryption";

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    /*Set WPA PSK*/
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!(pIF[i].valid) || pIF[i].mediaType != APAC_MEDIATYPE_WIFI) {
            continue;
        }
        /*set BeaconType*/
        snprintf(path, sizeof(path), "%s%d.BeaconType",CONFIG_WLAN, pIF[i].vapIndex);
        snprintf(value, sizeof(value), "%s", beacontype);
        storage_setParam(mibHandle,path,value);

        /*set auth type*/
        snprintf(path, sizeof(path), "%s%d.IEEE11iAuthenticationMode", CONFIG_WLAN, pIF[i].vapIndex);
        snprintf(value, sizeof(value), "%s", authtype);
        storage_setParam(mibHandle,path,value);

        /*set encr type*/
        snprintf(path, sizeof(path), "%s%d.IEEE11iEncryptionModes", CONFIG_WLAN, pIF[i].vapIndex);
        snprintf(value, sizeof(value), "%s", encrtype);
        storage_setParam(mibHandle,path,value);

        /*set passphrase*/
        snprintf(path, sizeof(path), "%s%d.KeyPassphrase", CONFIG_WLAN, pIF[i].vapIndex);
        storage_setParam(mibHandle,path,wpapsk);

    }

    /*Set PLC NMK*/
    snprintf(path, sizeof(path), "%sNMK", CONFIG_PLC);
    storage_setParam(mibHandle,path,plcnmk);

    /*Clear PLC Password*/
    snprintf(path, sizeof(path), "%sNetworkPwd", CONFIG_PLC);
    storage_setParam(mibHandle,path,"");

    dprintf(MSG_WARNING, "[WSPLCD] set UCPK\n");
    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail)
    {
        dprintf(MSG_ERROR, "failed when set ucpk, restart wsplcd daemon!\n");
        shutdown_fatal();
    }

    return fail;
}

#if 0
int apac_mib_set_vap_status(int vap_index, int status)
{
    void *mibHandle = NULL;
    int fail = 0;
    char path[128];
    char value[128];

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    snprintf(path, sizeof(path), "%s%d.Enable", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%d", status);
    storage_setParam(mibHandle,path,value);

    dprintf(MSG_WARNING, "[WSPLCD] set vap %d status to %d\n", vap_index, status);
    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail)
    {
        dprintf(MSG_ERROR, "failed when set:%s, restarting wsplcd daemon!\n", path);
        shutdown_fatal();
    }

    return fail;
}
#endif


int apac_mib_set_vapind(apacHyfi20Data_t *pData, int enable)
{
    void *mibHandle = NULL;
    int fail = 0;
    char path[128];
    char  value[128];
    int i;

    apacHyfi20IF_t *pIF = pData->hyif;

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!(pIF[i].valid) || pIF[i].mediaType != APAC_MEDIATYPE_WIFI) {
            continue;
        }

        snprintf(path, sizeof(path), "%s%d.VAPIndependent",CONFIG_WLAN, pIF[i].vapIndex);
        snprintf(value, sizeof(value), "%d", enable);
        storage_setParam(mibHandle,path,value);

    }

    dprintf(MSG_WARNING, "[WSPLCD] set vap_ind to %d\n",enable);
    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail)
    {
        dprintf(MSG_ERROR, "failed when set vapind, restarting wsplcd daemon!\n");
        shutdown_fatal();
    }

    return fail;
}

#if MAP_ENABLED
int apac_mib_map_set_bsta_bssid(int vap_index, struct ether_addr targetBSSID)
{
    void *mibHandle = NULL;
    int fail = 0;
    char path[128];
    char value[128];

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
        return -1;
    }

    snprintf(path, sizeof(path), "%s%d.mapTargetBSSID", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%02x:%02x:%02x:%02x:%02x:%02x", targetBSSID.ether_addr_octet[0],
             targetBSSID.ether_addr_octet[1], targetBSSID.ether_addr_octet[2],
             targetBSSID.ether_addr_octet[3], targetBSSID.ether_addr_octet[4],
             targetBSSID.ether_addr_octet[5]);
    storage_setParam(mibHandle,path,value);

    dprintf(MSG_DEBUG, "%s calling storage apply\n", __func__);
    fail = storage_apply(mibHandle);
    if(fail)
    {
        dprintf(MSG_ERROR, "failed when set:%s, restarting wsplcd daemon!\n", path);
        shutdown_fatal();
    }

    return fail;
}

int apac_mib_backhaul_sta_callback(apacHyfi20Data_t *pData, char *backhaulData) {
    const char deLimiter[2] = ",";
    char *token, *tag, *value, *bhsString;
    struct ether_addr *parseMac = NULL;
    struct ether_addr backhaulStaMac = {0}, targetBSSID = {0};
    int bstaIdx, foundBsta = APAC_FALSE;
    void *mibHandle = pData->wifiConfigHandle;

    if (NULL == mibHandle) {
        return -1;
    }

    token = strtok_r(backhaulData, deLimiter, &bhsString);

    /* walk through other tokens */
    while (token != NULL) {
        tag = apac_config_line_lex(token, &value);

        if (tag == NULL || *tag == 0) {
            continue;
        }

        dprintf(MSG_MSGDUMP, " %s, tag: %s, value: %s\n", __func__, tag, value);
        if (strncmp(tag, BACKHAUL_STA_MAC, strlen(BACKHAUL_STA_MAC)) == 0) {
            parseMac = ether_aton(value);
            if (!parseMac) {
                dprintf(MSG_MSGDUMP, " %s, Failed to get STA MAC \n", __func__);
                return -1;
            }
            memcpy(&backhaulStaMac.ether_addr_octet, parseMac->ether_addr_octet, ETH_ALEN);
        } else if (strncmp(tag, TARGET_BSSID, strlen(TARGET_BSSID)) == 0) {
            parseMac = ether_aton(value);
            if (!parseMac) {
                dprintf(MSG_MSGDUMP, " %s, Failed to get Target BSSID \n", __func__);
                return -1;
            }
            memcpy(&targetBSSID.ether_addr_octet, parseMac->ether_addr_octet, ETH_ALEN);
        }

        token = strtok_r(NULL, deLimiter, &bhsString);
    }

    /* check if bSTA exists */
    apacHyfi20IF_t *pIF = pData->hyif;
    for (bstaIdx = 0; bstaIdx < APAC_MAXNUM_HYIF; bstaIdx++) {
        if (!pIF[bstaIdx].valid) {
            continue;
        }

        if (pIF[bstaIdx].mediaType == APAC_MEDIATYPE_WIFI &&
            pIF[bstaIdx].wlanDeviceMode == APAC_WLAN_STA) {
            if (os_memcmp(pIF[bstaIdx].mac_addr, backhaulStaMac.ether_addr_octet, ETH_ALEN) == 0) {
                foundBsta = APAC_TRUE;
                break;
            }
        }
    }

    /* if bSTA found set the target BSSID through wpa_cli command */
    if (foundBsta) {
        apac_mib_map_set_bsta_bssid(pIF[bstaIdx].vapIndex, targetBSSID);
    }

    return 0;
}

int apac_mib_map_set_network_type(void *mibHandle, int vap_index, const char *networkType) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.network", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%s", networkType);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_set_vlan_bridge_network(void *mibHandle, int vap_index, const char *vlanBridge) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.vlan_bridge", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "br-%s", vlanBridge);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_set_vlanID(void *mibHandle, int vap_index, int vlanID) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.mapVlanID", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%d", vlanID);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_set_8021qVLAN(void *mibHandle, int vap_index, int vlanID) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.map8021qvlan", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%d", vlanID);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_set_mapBSSType(void *mibHandle, int vap_index, int mapBSSType) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.MapBSSType", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%d", mapBSSType);
    storage_setParam(mibHandle, path, value);

    return 0;
}

int apac_mib_map_set_map_version(void *mibHandle, int vap_index, int mapVersion) {
    char path[128];
    char value[128];

    snprintf(path, sizeof(path), "%s%d.map", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%d", mapVersion);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_reset_wifi_restart(apacHyfi20Data_t *pData){
    char path[256], value[128];
    void *mibHandle = pData->wifiConfigHandle;
    apacHyfi20AP_t *pAP = pData->ap;
    int i = 0;

    if (NULL == mibHandle ) return -1;

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (!pAP[i].valid) {
            continue;
        }
        snprintf(value, sizeof(value), "%d", i);
        snprintf(path, sizeof(path), "%s%d.wifi_reset", CONFIG_RADIO,  pAP[i].radio_index);
        storage_setParam(mibHandle, path, value);
    }

    return 0;
}

int apac_mib_map_set_upstream_device_version(apacHyfi20Data_t *pData, uint8_t upstream_version) {
    char path[256], value[128];
    void *mibHandle = pData->wifiConfigHandle;
    apacHyfi20AP_t *pAP = pData->ap;
    int i = 0;

    if (NULL == mibHandle || !upstream_version) return -1;

    snprintf(value, sizeof(value), "%d", upstream_version);
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (!pAP[i].valid) {
            continue;
        }
        snprintf(path, sizeof(path), "%s%d.upstream_version", CONFIG_RADIO, pAP[i].radio_index);
        dprintf(MSG_MSGDUMP, " %s radio index %d Freq %d\n", path,pAP[i].radio_index,pAP[i].freq);
        storage_setParam(mibHandle, path, value);
    }

    return 0;
}

int apac_mib_map_set_channel(void *mibHandle, int radio_index, char *channel) {
    char path[128] = {0};
    char value[128] = {0};

    snprintf(path, sizeof(path), "%s%d.Channel", CONFIG_RADIO, radio_index);
    snprintf(value, sizeof(value), "%s", channel);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_map_set_mode(void *mibHandle, int vap_index, char *mode) {
    char path[128] = {0};
    char value[128] = {0};

    snprintf(path, sizeof(path), "%s%d.Standard", CONFIG_WLAN, vap_index);
    snprintf(value, sizeof(value), "%s", mode);
    storage_setParam(mibHandle, path, value);
    return 0;
}

int apac_mib_channel_mode_update_cb(apacHyfi20Data_t *pData, char *channelModeData) {
    void *newHandle = NULL;
    void *mibHandle = pData->wifiConfigHandle;
    apacHyfi20AP_t *pAP = pData->ap;

    const char deLimiter[2] = ",";
    const char tokendeLimiter[2] = "=";
    char *dup, *token, *iface, *value, *temp;
    u8 radioIdx = -1;
    int vapIdx = -1, fail = 0, i = 0;
    char newMode[20] = {0};

    if (NULL == mibHandle) {
        return -1;
    }

    dup = strdup(channelModeData);
    if (!dup) {
        return -1;
    }
    temp = dup;
    token = strtok_r(dup, deLimiter, &dup);
    if (!token) {
        return -1;
    }
    value = strstr(token, tokendeLimiter);
    if (!value) {
        return -1;
    }
    value = value + 1;
    iface = strstr(dup, tokendeLimiter);
    if (!iface) {
        return -1;
    }
    iface = iface + 1;

    if(strncmp(channelModeData, CONFIG_CHANNEL, strlen(CONFIG_CHANNEL)) == 0) {
        for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
            if (!pAP[i].valid) {
                continue;
            }
            if(!strcmp(pAP[i].radioName, iface)) {
                radioIdx = pAP[i].radio_index;
            }
        }
        if (radioIdx == -1) {
            return -1;
        }
        apac_mib_map_set_channel(mibHandle, radioIdx, value);
    }
    else if(strncmp(channelModeData, CONFIG_MODE, strlen(CONFIG_MODE)) == 0) {
        for (i = 0; phy_to_std_mappings[i].phy_mode; ++i) {
            if (!strcmp(phy_to_std_mappings[i].phy_mode, value)) {
                strlcpy(newMode, phy_to_std_mappings[i].apac_std, APAC_STD_MAX_LEN);
                break;
            }
        }
        vapIdx = apac_mib_get_vapindex(iface);
        if (vapIdx == -1) {
            return -1;
        }
        apac_mib_map_set_mode(mibHandle, vapIdx, newMode);
    }

    // To avoid possible wifi restart while channel or mode change
    // the following optimization is applied
    apac_mib_map_reset_wifi_restart(pData);

    fail = storage_apply(mibHandle);
    if (fail) {
        shutdown_fatal();
    }

    newHandle = storage_getHandle();
    if (newHandle) {
        pData->wifiConfigHandle = newHandle;
    }

    if(temp) {
        free(temp);
    }
    return fail;
}

int apac_mib_traffic_separation_cb(apacHyfi20Data_t *pData, char *trafficSepData) {
    void *newHandle = NULL;
    void *mibHandle = pData->wifiConfigHandle;
    apacHyfi20Config_t *pConfig = &pData->config;
    const char deLimiter[2] = ",";
    const char tokendeLimiter[2] = " ";
    char *token, *tag, *value, *trafficSepString;
    char *subtoken, *ifnameString;
    char primaryVlanIfname[MAP_SERVICE_AGENT_MAX_BRIDGE_IFNAME_LENGTH],
        secondaryVlanIfname[MAP_SERVICE_AGENT_MAX_BRIDGE_IFNAME_LENGTH];
    char ifNamebSTA[IFNAMSIZ], ifNamebhBSS[MAP_SERVICE_MAX_RADIOS][IFNAMSIZ];
    apacMapData_t *mapData = HYFI20ToMAP(pData);
    int vapIdx, fail = 0, primaryVlanID = 0, secondaryVlanID = 0, numBhBss = 0, TSEnabled = 0;
    u_int8_t priIdx = 0, secIdx = 1, numVlanRx = 0;
    apacBool_e skipVlanApply = APAC_FALSE;

    if (NULL == mibHandle) {
        return -1;
    }

    if (pConfig && !apacHyfiMapPfComplianceEnabled(mapData)) {
        if (pConfig->state != APAC_E_IDLE) {
            dprintf(MSG_MSGDUMP,
                    " %s, Config State Not Idle %d . Do not set Traffic Separation Policy \n",
                    __func__, pConfig->state);
            return -1;
        }
    }

    token = strtok_r(trafficSepData, deLimiter, &trafficSepString);

    /* walk through other tokens */
    while (token != NULL) {
        tag = apac_config_line_lex(token, &value);

        if (tag == NULL || *tag == 0) {
            continue;
        }

        if (numVlanRx > mapData->numVlanSupported) {
            dprintf(MSG_MSGDUMP,
                    " %s: Number of VLAN Supported by Agent:%d , Set Skip Vlan Apply \n ", __func__,
                    numVlanRx);
            skipVlanApply = APAC_TRUE;
        }

        dprintf(MSG_MSGDUMP, " %s, tag: %s, value: %s \n", __func__, tag, value);
        ifnameString = value;
        if (strncmp(tag, CONFIG_NETWORK_TS_ENABLED, strlen(CONFIG_NETWORK_TS_ENABLED)) == 0) {
            TSEnabled = atoi(value);
        } else if (strncmp(tag, CONFIG_NETWORK_PRIMARY_VLAN_ID,
                           strlen(CONFIG_NETWORK_PRIMARY_VLAN_ID)) == 0) {
            primaryVlanID = atoi(value);
            numVlanRx++;
        } else if (strncmp(tag, CONFIG_NETWORK_SECONDARY_VLAN_ID,
                           strlen(CONFIG_NETWORK_SECONDARY_VLAN_ID)) == 0) {
            secondaryVlanID = atoi(value);
            if (secondaryVlanID > 0) {
                numVlanRx++;
            }
        } else if (strncmp(tag, CONFIG_NETWORK_PRIMARY_VLAN, strlen(CONFIG_NETWORK_PRIMARY_VLAN)) ==
                   0) {
            memcpy(primaryVlanIfname, value, strlen(value));
            primaryVlanIfname[strlen(value)] = '\0';
            dprintf(MSG_MSGDUMP, " %s, Set Primary Network %s \n", __func__,
                    mapData->br_names[priIdx]);
            while ((subtoken = strtok_r(ifnameString, tokendeLimiter, &ifnameString))) {
                vapIdx = apac_mib_get_vapindex(subtoken);
                dprintf(MSG_MSGDUMP, " %s, ifname: %s vapIdx: %d \n", __func__, subtoken, vapIdx);
                if (vapIdx >= 0) {
                    apac_mib_map_set_network_type(mibHandle, vapIdx, mapData->br_names[priIdx]);
                    if (TSEnabled) {
                        apac_mib_map_set_vlanID(mibHandle, vapIdx, primaryVlanID);
                        apac_mib_map_set_8021qVLAN(mibHandle, vapIdx, primaryVlanID);
                    } else {
                        apac_mib_map_set_vlanID(mibHandle, vapIdx, 0);
                    }
                }
            }
        } else if (strncmp(tag, CONFIG_NETWORK_SECONDARY_VLAN,
                           strlen(CONFIG_NETWORK_SECONDARY_VLAN)) == 0) {
            // If Secondary Vlan ID is 0. Use Primary Bridge name
            if (secondaryVlanID == 0) {
                secIdx = priIdx;
            }

            if (skipVlanApply == APAC_FALSE) {
                memcpy(secondaryVlanIfname, value, strlen(value));
                secondaryVlanIfname[strlen(value)] = '\0';
                dprintf(MSG_MSGDUMP, " %s, Set Secondary Network %s \n", __func__,
                        mapData->br_names[secIdx]);
                while ((subtoken = strtok_r(ifnameString, tokendeLimiter, &ifnameString))) {
                    vapIdx = apac_mib_get_vapindex(subtoken);
                    dprintf(MSG_MSGDUMP, " %s, ifname: %s vapIdx: %d \n", __func__, subtoken,
                            vapIdx);
                    if (vapIdx >= 0 && TSEnabled) {
                        apac_mib_map_set_network_type(mibHandle, vapIdx, mapData->br_names[secIdx]);
                        apac_mib_map_set_vlanID(mibHandle, vapIdx, secondaryVlanID);
                        apac_mib_map_set_8021qVLAN(mibHandle, vapIdx, primaryVlanID);
                    }
                }
                secIdx++;
            }
        } else if (strncmp(tag, CONFIG_NETWORK_BSTA_IFACE, strlen(CONFIG_NETWORK_BSTA_IFACE)) ==
                   0) {
            /// Network will be set in repacd for STA
            vapIdx = apac_mib_get_vapindex(value);
            memcpy(ifNamebSTA, value, strlen(value));
            ifNamebSTA[strlen(value)] = '\0';
            dprintf(MSG_MSGDUMP, " %s, ifname: %s vapIdx: %d \n", __func__, value, vapIdx);
        } else if (strncmp(tag, CONFIG_NETWORK_BHBSS_IFACE, strlen(CONFIG_NETWORK_BHBSS_IFACE)) ==
                   0) {
            dprintf(MSG_MSGDUMP, " %s, Set Backhaul Network R2 :%s \n", __func__,
                    mapData->br_backhaul);
            while ((subtoken = strtok_r(ifnameString, tokendeLimiter, &ifnameString))) {
                char *dot;
                dot = strchr(subtoken, '.');
                if (dot) {
                    *dot = '\0';
                }
                vapIdx = apac_mib_get_vapindex(subtoken);
                memcpy(ifNamebhBSS[numBhBss], subtoken, strlen(subtoken));
                ifNamebhBSS[numBhBss][strlen(subtoken)] = '\0';
                numBhBss++;
                dprintf(MSG_MSGDUMP, " %s, ifname: %s vapIdx: %d \n", __func__, subtoken, vapIdx);
                if (vapIdx >= 0 && TSEnabled) {
                    apac_mib_map_set_network_type(mibHandle, vapIdx, mapData->br_backhaul);
                    apac_mib_map_set_vlan_bridge_network(mibHandle, vapIdx, mapData->br_names[priIdx]);
                    apac_mib_map_set_vlanID(mibHandle, vapIdx, 0);
                    apac_mib_map_set_8021qVLAN(mibHandle, vapIdx, primaryVlanID);
                    apac_mib_map_set_mapBSSType(
                        mibHandle, vapIdx, MAP_BSS_TYPE_BACKHAUL | MAP2_R1_BSTA_ASSOC_DISALLOW);
                }
            }
        } else if (strncmp(tag, CONFIG_NETWORK_BHBSS_IFACE_R1_ONLY,
                           strlen(CONFIG_NETWORK_BHBSS_IFACE_R1_ONLY)) == 0) {
            numBhBss = 0;
            dprintf(MSG_MSGDUMP, " %s, Set Backhaul Network %s \n", __func__,
                    mapData->br_names[priIdx]);
            while ((subtoken = strtok_r(ifnameString, tokendeLimiter, &ifnameString))) {
                char *dot;
                dot = strchr(subtoken, '.');
                if (dot) {
                    *dot = '\0';
                }
                vapIdx = apac_mib_get_vapindex(subtoken);
                memcpy(ifNamebhBSS[numBhBss], subtoken, strlen(subtoken));
                ifNamebhBSS[numBhBss][strlen(subtoken)] = '\0';
                numBhBss++;
                dprintf(MSG_MSGDUMP, " %s, ifname: %s vapIdx: %d \n", __func__, subtoken, vapIdx);
                if (vapIdx >= 0 && TSEnabled) {
                    apac_mib_map_set_network_type(mibHandle, vapIdx, mapData->br_names[priIdx]);
                    apac_mib_map_set_vlanID(mibHandle, vapIdx, 0);
                    apac_mib_map_set_map_version(mibHandle, vapIdx, 1);
                    apac_mib_map_set_mapBSSType(
                        mibHandle, vapIdx,
                        MAP_BSS_TYPE_BACKHAUL | MAP2_R2_ABOVE_BSTA_ASSOC_DISALLOW);
                }
            }
        } else if (strncmp(tag, CONFIG_NETWORK_UPSTREAM_DEVICE_VERSION,
                           strlen(CONFIG_NETWORK_UPSTREAM_DEVICE_VERSION)) == 0) {
            uint8_t version;
            version = atoi(value);
            if (apac_mib_map_set_upstream_device_version(pData, version) == -1)
                dprintf(MSG_ERROR, " %s, upstream version failed \n", __func__);
        }

        token = strtok_r(NULL, deLimiter, &trafficSepString);
    }
    /// for PF compliance we want to avoid network restart
    /// too many restart are causing sniffer to miss packets
    /// following optimization is valid only for Compliance event
    if (apacHyfiMapPfComplianceEnabled(HYFI20ToMAP(pData)) &&
        apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) > APAC_MAP_VERSION_2) {
        apac_mib_map_reset_wifi_restart(pData);
    }

    fail = storage_apply(mibHandle);
    if (fail) {
        shutdown_fatal();
    }

    newHandle = storage_getHandle();
    if (newHandle) {
        pData->wifiConfigHandle = newHandle;
    }

    return fail;
}
#endif

void apac_mib_restart_wireless(void) {
    storage_restartWireless();
}
