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

#include "ieee1905_defs.h"
#include "meshIeee1905.h"
#include "../src/mesh_app.h"
#include "../meshevent/meshEvent.h"

#include "dbg.h"

static struct dbgModule *dbgModule;

/**
 * Parse IEEE1905 message
 */
int meshIeee1905ParseFrame(char *frame, u_int32_t frameLen)
{
    ieee1905DispatchFrame_t *meshFrame = NULL;

    if (!frame)
        return MESH_EVENT_NO_DATA;

    frame++; //skip buffer type
    meshFrame = (ieee1905DispatchFrame_t *) frame;

    dbgf(dbgModule, DBGDUMP, "Buffer received in frame = ");
    for (size_t k=0; k<frameLen-1; k++) {
        dbgf(dbgModule, DBGDUMP, "\t%x", frame[k]);
    }

    dbgf(dbgModule, DBGDEBUG,
         "msgType=0x%04X \t mid=%u \t tlvType=0x%02X",
         meshFrame->msgType, meshFrame->mid, meshFrame->tlvType);

    if (!meshFrame->content && (meshFrame->tlvType != IEEE1905_TLV_TYPE_END_OF_MESSAGE)) {
        dbgf(dbgModule, DBGDEBUG,
            "%s content is NULL", __func__);
        return MESH_EVENT_NO_DATA;
    }

    switch (meshFrame->tlvType) {
        case IEEE1905_TLV_TYPE_END_OF_MESSAGE:
        {
            // Messages that do not contain any TLVs
            if (meshFrame->msgType == IEEE1905_MSG_TYPE_AP_CAP_QUERY) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: AP Capability Query sent to alId = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_CHANNEL_PREFERENCE_QUERY) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Channel Preference Query sent to alId = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_CLIENT_STEERING_COMPLETED) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Steering Complete received from alId = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_BACKHAUL_STA_CAP_QUERY_MESSAGE) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: bsta capability query sent to alId = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG, "%s End of Message TLV", __func__);
            break;
        }
        case IEEE1905_TLV_TYPE_SUPPORTED_SERVICE:
        {
            ieee1905SupportedServices_t *services =
                (ieee1905SupportedServices_t*) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Supported service for alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numServices = %u;", services->numServices);
            for (size_t k=0; k<services->numServices; k++) {
                if (k >= IEEE1905_MAX_SUPPORTED_SERVICES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "supportedService = %u", services->supportedService[k]);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_SEARCHED_SERVICE:
        {
            ieee1905SearchedServices_t *services =
                (ieee1905SearchedServices_t*) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Searched service received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numServices = %u;", services->numServices);
            for (size_t k=0; k<services->numServices; k++) {
                if (k >= IEEE1905_MAX_SUPPORTED_SERVICES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "searchedService = %u", services->searchedService[k]);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_RADIO_IDENTIFIER:
        {
            ieee1905APRadioIdentifier_t *radio =
                (ieee1905APRadioIdentifier_t*) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Radio Identifier sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "radioAddr = " meshMACAddFmt(":"),
                 meshMACAddData(radio->radioAddr.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_OPERATIONAL_BSS:
        {
            dbgf(dbgModule, DBGDEBUG,
                 "%s: Operational BSS received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_ASSOCIATED_CLIENTS:
        {
            dbgf(dbgModule, DBGDEBUG,
                 "%s: Associated clients received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_AP_CAP:
        {
            mapServiceAPCapabilities_t *apCap =
                (mapServiceAPCapabilities_t*) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP Capability Received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG, "unassocStaLinkMetricsOnCurrChan=%d; "
                    "unassocStaLinkMetricsOnNonCurrChan=%d; "
                    "agentInitiatedRssiBasedSteering=%d",
                 apCap->unassocStaLinkMetricsOnCurrChan,
                 apCap->unassocStaLinkMetricsOnNonCurrChan,
                 apCap->agentInitiatedRssiBasedSteering);

            break;
        }
        case IEEE1905_TLV_TYPE_AP_RADIO_BASIC_CAP:
        {
            mesh1905APRadioBasicCapabilities_t *radioHwCap =
                (mesh1905APRadioBasicCapabilities_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP HW Capability Received from alId = " meshMACAddFmt(":")
                    " and Radio addr = " meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(radioHwCap->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG, "maxSupportedBSS=%u; numSupportedOpClasses=%u",
                 radioHwCap->hwCap.maxSupportedBSS, radioHwCap->hwCap.numSupportedOpClasses);
            for (size_t k = 0; k < radioHwCap->hwCap.numSupportedOpClasses; k++) {
                if (k >= IEEE1905_MAX_OPERATING_CLASSES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opclass=%u; maxTxPwrDbm=%u; numNonOperChan=%u",
                     radioHwCap->hwCap.opClasses[k].opClass,
                     radioHwCap->hwCap.opClasses[k].maxTxPwrDbm,
                     radioHwCap->hwCap.opClasses[k].numNonOperChan);
                for (size_t m = 0; m < radioHwCap->hwCap.opClasses[k].numNonOperChan; m++) {
                    if (m >= IEEE1905_MAX_CHANNELS_PER_OP_CLASS) {
                        break;
                    }
                    dbgf(dbgModule, DBGDEBUG,
                         "nonOperChanNum=%u", radioHwCap->hwCap.opClasses[k].nonOperChanNum[m]);
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_AP_HT_CAP:
        {
            mesh1905APHtCapabilities_t *radioHtCap =
                (mesh1905APHtCapabilities_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP HT Capability Received from alId = " meshMACAddFmt(":") " and Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet), meshMACAddData(radioHtCap->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG, "maxTxNSS=%u; maxRxNSS=%u; "
                    "shortGiSupport20Mhz=%d; shortGiSupport40Mhz=%d; "
                    "htSupport40Mhz=%d",
                 radioHtCap->htCap.maxTxNSS, radioHtCap->htCap.maxRxNSS,
                 radioHtCap->htCap.shortGiSupport20Mhz,
                 radioHtCap->htCap.shortGiSupport40Mhz,
                 radioHtCap->htCap.htSupport40Mhz);

            break;
        }
        case IEEE1905_TLV_TYPE_AP_VHT_CAP:
        {
            mesh1905APVhtCapabilities_t *radioVhtCap =
                (mesh1905APVhtCapabilities_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP VHT Capability Received from alId = " meshMACAddFmt(":") " and Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet), meshMACAddData(radioVhtCap->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG, "supportedTxMCS=%u; supportedRxMCS=%u; "
                    "maxTxNSS=%u; maxRxNSS=%u; shortGiSupport80Mhz=%d; "
                    "shortGiSupport160Mhz80p80Mhz=%d; support80p80Mhz=%d; "
                    "support160Mhz=%d; suBeamformerCapable=%d; muBeamformerCapable=%d",
                 radioVhtCap->vhtCap.supportedTxMCS, radioVhtCap->vhtCap.supportedRxMCS,
                 radioVhtCap->vhtCap.maxTxNSS, radioVhtCap->vhtCap.maxRxNSS,
                 radioVhtCap->vhtCap.shortGiSupport80Mhz,
                 radioVhtCap->vhtCap.shortGiSupport160Mhz80p80Mhz,
                 radioVhtCap->vhtCap.support80p80Mhz,
                 radioVhtCap->vhtCap.support160Mhz,
                 radioVhtCap->vhtCap.suBeamformerCapable,
                 radioVhtCap->vhtCap.muBeamformerCapable);

            break;
        }
        case IEEE1905_TLV_TYPE_AP_HE_CAP:
        {
            mesh1905APHeCapabilities_t *radioHeCap =
                (mesh1905APHeCapabilities_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP HE Capability Received from alId = " meshMACAddFmt(":") " and Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet), meshMACAddData(radioHeCap->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 " maxTxNSS=%u; maxRxNSS=%u; support80p80Mhz=%d; support160Mhz=%d;"
                    "suBeamformerCapable=%d; muBeamformerCapable=%d; ulMuMimoCapable=%d;"
                    "ulMuMimoOfdmaCapable=%d; dlMuMimoOfdmaCapable=%d; ulOfdmaCapable=%d;"
                    "dlOfdmaCapable=%d",
                 radioHeCap->heCap.maxTxNSS, radioHeCap->heCap.maxRxNSS,
                 radioHeCap->heCap.support80p80Mhz, radioHeCap->heCap.support160Mhz,
                 radioHeCap->heCap.suBeamformerCapable, radioHeCap->heCap.muBeamformerCapable,
                 radioHeCap->heCap.ulMuMimoCapable, radioHeCap->heCap.ulMuMimoOfdmaCapable,
                 radioHeCap->heCap.dlMuMimoOfdmaCapable, radioHeCap->heCap.ulOfdmaCapable,
                 radioHeCap->heCap.dlOfdmaCapable);

            break;
        }
        case IEEE1905_TLV_TYPE_STEERING_POLICY:
        {
            mapServiceSteeringPolicy_t *steeringPolicy =
                (mapServiceSteeringPolicy_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Steering Policy sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            for (size_t k=0; k<steeringPolicy->numDisallowedSTAs; k++) {
                if (k >= MAP_SERVICE_STEERING_POLICY_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "disallowedSTA=" meshMACAddFmt(":"),
                     meshMACAddData(steeringPolicy->disallowedSTAs[k].ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numBTMDisallowedSTAs=%u", steeringPolicy->numBTMDisallowedSTAs);
            for (size_t k=0; k<steeringPolicy->numBTMDisallowedSTAs; k++) {
                if (k >= MAP_SERVICE_STEERING_POLICY_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "btmDisallowedSTA=" meshMACAddFmt(":"),
                     meshMACAddData(steeringPolicy->btmDisallowedSTAs[k].ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numRadios=%u", steeringPolicy->numRadios);
            for (size_t k=0; k<steeringPolicy->numRadios; k++) {
                if (k >= MAP_SERVICE_STEERING_POLICY_MAX_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr=" meshMACAddFmt(":") "; mode=%d; "
                        "channelUtilThreshold=%u; rssiThreshold=%d",
                     meshMACAddData(steeringPolicy->radioPolicies[k].radioAddr.ether_addr_octet),
                     steeringPolicy->radioPolicies[k].mode,
                     steeringPolicy->radioPolicies[k].channelUtilThreshold,
                     steeringPolicy->radioPolicies[k].rssiThreshold);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_METRIC_REPORT_POLICY:
        {
            mapServiceMetricsReportingPolicy_t *metricsPolicy =
                (mapServiceMetricsReportingPolicy_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Metric Reporting Policy sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "reportingIntervalSecs=%u; numRadios=%u",
                 metricsPolicy->reportingIntervalSecs, metricsPolicy->numRadios);
            for (size_t k=0; k<metricsPolicy->numRadios; k++) {
                if (k >= MAP_SERVICE_STEERING_POLICY_MAX_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr=" meshMACAddFmt(":") "; rssiThreshold=%d; "
                        "rssiHysteresis=%u; channelUtilThreshold=%u;"
                        "includeSTATrafficStats=%d; includeSTALinkMetrics=%d",
                     meshMACAddData(metricsPolicy->radioPolicies[k].radioAddr.ether_addr_octet),
                     metricsPolicy->radioPolicies[k].rssiThreshold,
                     metricsPolicy->radioPolicies[k].rssiHysteresis,
                     metricsPolicy->radioPolicies[k].channelUtilThreshold,
                     metricsPolicy->radioPolicies[k].includeSTATrafficStats,
                     metricsPolicy->radioPolicies[k].includeSTALinkMetrics);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_PREFERENCE:
        {
            mapServiceChannelPreference_t *chanPref =
                (mapServiceChannelPreference_t *) meshFrame->content;

            // TLV used by multiple message types, checking type here
            if (meshFrame->msgType == IEEE1905_MSG_TYPE_CHANNEL_SELECTION_REQUEST) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Channel Selection Request sent to alId = " meshMACAddFmt(":")
                         ", for Radio addr = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                     meshMACAddData(chanPref->radioAddr.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_CHANNEL_PREFERENCE_REPORT) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Channel Preference Report Received for alId = " meshMACAddFmt(":")
                         " and Radio addr = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                     meshMACAddData(chanPref->radioAddr.ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numPairs=%u",
                 chanPref->chanPref.numPairs);
            for (int k = 0; k < chanPref->chanPref.numPairs; k++) {
                if (k >= IEEE1905_MAX_OP_CLASS_CHAN_PAIRS)
                    break;
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; channel=%u; preference=%u; reason=%u",
                     chanPref->chanPref.operatingClasses[k].opClass,
                     chanPref->chanPref.operatingClasses[k].channel,
                     chanPref->chanPref.operatingClasses[k].preference,
                     chanPref->chanPref.operatingClasses[k].reason);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_RADIO_OPERATION_RESTRICTION:
        {
            mapServiceRadioRestriction_t *radioRestriction =
                (mapServiceRadioRestriction_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Radio Operation Restriction Received from alId = "
                     meshMACAddFmt(":") ", for Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(radioRestriction->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numOpClass=%u", radioRestriction->numOpClass);
            for (size_t k = 0; k < radioRestriction->numOpClass; k++) {
                if (k >= MAP_SERVICE_MAX_OPERATING_CLASSES)
                    break;
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; numChannels=%u",
                     radioRestriction->operatingClasses[k].opClass,
                     radioRestriction->operatingClasses[k].numChannels);
                for (size_t m = 0; m < radioRestriction->operatingClasses[k].numChannels; m++) {
                    if (m >= MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS)
                        break;
                dbgf(dbgModule, DBGDEBUG,
                     "channel=%u; minFreqSep=%u",
                     radioRestriction->operatingClasses[k].channels[m].channel,
                     radioRestriction->operatingClasses[k].channels[m].minFreqSep);
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_TRANSMIT_POWER_LIMIT:
        {
            mapServiceTransmitPowerLimit_t *txPower =
                (mapServiceTransmitPowerLimit_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Transmit Power Limit sent to alId = " meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "radioAddr=" meshMACAddFmt(":") "; txPowerLimit=%d",
                 meshMACAddData(txPower->radioAddr.ether_addr_octet), txPower->txPowerLimit);

            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_SELECTION_RESPONSE:
        {
            mesh1905ChannelSelectionRsp_t *chanSelRsp =
                (mesh1905ChannelSelectionRsp_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Channel Selection Response Received from alId = "
                    meshMACAddFmt(":") ", for Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(chanSelRsp->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "status = %u", chanSelRsp->status);

            break;
        }
        case IEEE1905_TLV_TYPE_OPERATING_CHANNEL_REPORT:
        {
            mapServiceOperatingChannelReport_t *opChan =
                (mapServiceOperatingChannelReport_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Radio Operating Channel Report Received from alId = "
                    meshMACAddFmt(":") ", for Radio addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(opChan->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numOpClass=%u; txPower=%u",
                 opChan->numOpClass, opChan->txPower);
            for (size_t k = 0; k < opChan->numOpClass; k++) {
                if (k >= MAP_SERVICE_MAX_OPERATING_CLASSES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; channel=%u",
                     opChan->operatingChannels[k].opClass,
                     opChan->operatingChannels[k].channel);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CLIENT_INFO:
        {
            mapServiceClientInfo_t *clientInfo =
                (mapServiceClientInfo_t *) meshFrame->content;

            // This TLV is used in multiple messages, checking msg type here
            if (meshFrame->msgType == IEEE1905_MSG_TYPE_CLIENT_CAPABILITY_QUERY) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Client Capability Query sent to alId = "
                        meshMACAddFmt(":") ", for BSS = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                     meshMACAddData(clientInfo->bssid.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_CLIENT_CAPABILITY_REPORT) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Client Info in Capability Report received from alId = "
                        meshMACAddFmt(":") ", for BSS = " meshMACAddFmt(":"),
                     __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                     meshMACAddData(clientInfo->bssid.ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "clientAddr =" meshMACAddFmt(":"),
                 meshMACAddData(clientInfo->clientAddr.ether_addr_octet));

            break;
        }
        case IEEE1905_TLV_TYPE_CLIENT_CAP_REPORT:
        {
            mesh1905ClientCapability_t *clientCap =
                (mesh1905ClientCapability_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Client Capability Report received from alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "resultCode = %d", clientCap->resultCode);
            if (clientCap->resultCode == mapServiceClientCapStatus_Success) {
                dbgf(dbgModule, DBGDEBUG,
                     "frameSize = %u", clientCap->cap.frameSize);
                for (size_t k=0; k<clientCap->cap.frameSize; k++) {
                    dbgf(dbgModule, DBGDUMP,
                         " assocFrame byte#%zu = 0x%02X",
                         k, clientCap->cap.assocReqFrame[k]);
                }
            }

            break;
        }
        case IEEE1905_TLV_TYPE_CLIENT_ASSOC_EVENT:
        {
            dbgf(dbgModule, DBGDEBUG,
                 "%s: Client Assoc received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));

            break;
        }
        case IEEE1905_TLV_TYPE_AP_METRIC_QUERY:
        {
            mesh1905APMetricQuery_t *query =
                (mesh1905APMetricQuery_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP Metric Query sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numBSSID=%zu", query->numBSSID);
            for (size_t k=0; k<query->numBSSID; k++) {
                if (k >= MAP_SERVICE_MAX_NUM_BSSID) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssids=" meshMACAddFmt(":"),
                     meshMACAddData(query->bssids[k].ether_addr_octet));
            }
            break;
        }
        case IEEE1905_TLV_TYPE_AP_METRICS:
        {
            mapServiceAPMetrics_t *metric =
                (mapServiceAPMetrics_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP Metrics Received from alId = "
                     meshMACAddFmt(":") ", for BSSID = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(metric->bssid.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "channelUtil=%u; numAssocSTA=%u",
                 metric->apMetrics.channelUtil, metric->apMetrics.numAssocSTA);
            for (size_t k = 0; k < mapServiceAC_Max; k++) {
                if (metric->apMetrics.espInfo[k].includeESPInfo) {
                    dbgf(dbgModule, DBGDEBUG,
                         "dataFormat=%u; baWindowSize=%u;"
                            "estAirTimeFraction=%u dataPPDUDurTarget=%u",
                         metric->apMetrics.espInfo[k].dataFormat,
                         metric->apMetrics.espInfo[k].baWindowSize,
                         metric->apMetrics.espInfo[k].estAirTimeFraction,
                         metric->apMetrics.espInfo[k].dataPPDUDurTarget);
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_STA_MAC:
        {
            struct ether_addr *staAddr =
                (struct ether_addr *) meshFrame->content;

            // This TLV is used in multiple messages, checking msg type here
            if (meshFrame->msgType == IEEE1905_MSG_TYPE_ASSOC_STA_LINK_METRIC_QUERY) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Assoc STA Link Metric Query sent to alId = "
                        meshMACAddFmt(":"), __func__,
                     meshMACAddData(meshFrame->alId.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_CLIENT_DISASSOC_STATS) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Client Disassoc Stats received from alId = "
                        meshMACAddFmt(":"), __func__,
                     meshMACAddData(meshFrame->alId.ether_addr_octet));
            } else if (meshFrame->msgType == IEEE1905_MSG_TYPE_FAILED_CONNECTION_MESSAGE) {
                dbgf(dbgModule, DBGDEBUG,
                     "%s: Failed Connection Message received from alId = "
                        meshMACAddFmt(":"), __func__,
                     meshMACAddData(meshFrame->alId.ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "staAddr=" meshMACAddFmt(":"),
                 meshMACAddData(staAddr->ether_addr_octet));

            break;
        }
        case IEEE1905_TLV_TYPE_ASSOC_STA_LINK_METRICS:
        {
            mapServiceAssocSTALinkMetrics_t *metric =
                (mapServiceAssocSTALinkMetrics_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Assoc STA link metrics Received from alId = "
                    meshMACAddFmt(":") ", for STA addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(metric->staAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numBSS=%u", metric->numBSS);
            for (size_t k = 0; k < metric->numBSS; k++) {
                if (k >= MAP_SERVICE_MAX_NUM_ASSOC_BSS)
                    break;
                dbgf(dbgModule, DBGDEBUG,
                     "bssid=" meshMACAddFmt(":")
                         "timeDeltaMSec=%u; downlinkDataRate=%u;"
                         "uplinkDataRate=%u; uplinkRSSI=%d",
                     meshMACAddData(metric->bssLinkMetric[k].bssid.ether_addr_octet),
                     metric->bssLinkMetric[k].timeDeltaMSec,
                     metric->bssLinkMetric[k].downlinkDataRate,
                     metric->bssLinkMetric[k].uplinkDataRate,
                     metric->bssLinkMetric[k].uplinkRSSI);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_UNASSOC_STA_LINK_METRICS_QUERY:
        {
            mapServiceUnassociatedSTALinkMetricsQuery_t *query =
                (mapServiceUnassociatedSTALinkMetricsQuery_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Unassoc STA Link Metric Query sent to alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "opClass=%u; numChannels=%u",
                 query->opClass, query->numChannels);
            for (size_t k=0; k<query->numChannels; k++) {
                if (k >= MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "channel=%u; numSTAs=%u",
                     query->channels[k].channel, query->channels[k].numSTAs);
                for (size_t m=0; m<query->channels[k].numSTAs; m++) {
                    if (m >= MAP_SERVICE_UNASSOC_QUERY_MAX_STAS) {
                        break;
                    }
                    dbgf(dbgModule, DBGDEBUG,
                         "staAddrs=" meshMACAddFmt(":"),
                         meshMACAddData(query->channels[k].staAddrs[m].ether_addr_octet));
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_UNASSOC_STA_LINK_METRICS_RESPONSE:
        {
            mesh1905UnassocSTALinkMetrics_t *unassocSTAs =
                (mesh1905UnassocSTALinkMetrics_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Unassoc STA Link Metrics Received from alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numStas=%u; opClass=%u",
                 unassocSTAs->numStas, unassocSTAs->opClass);
            for (size_t k=0; k<unassocSTAs->numStas; k++) {
                if (k >= MAP_PUBLIC_MAX_UNASSOC_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "staAddr=" meshMACAddFmt(":")
                         "chanNum=%u; timeDelta=%u; uplinkRSSI=%d",
                     meshMACAddData(unassocSTAs->metric[k].staAddr.ether_addr_octet),
                     unassocSTAs->metric[k].chanNum, unassocSTAs->metric[k].timeDelta,
                     unassocSTAs->metric[k].uplinkRSSI);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_BEACON_METRICS_QUERY:
        {
            mapServiceBcnMetricsQuery_t *query =
                (mapServiceBcnMetricsQuery_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s Beacon Metric Query sent to alId = " meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "staAddr=" meshMACAddFmt(":") "; opClass=%u; chanNum=%u; "
                     "bssid=" meshMACAddFmt(":") "; reportDetail=%u; ssidLen=%u; ssid=%s; numChanReport=%u",
                 meshMACAddData(query->staAddr.ether_addr_octet), query->opClass,
                 query->chanNum, meshMACAddData(query->bssid.ether_addr_octet),
                 query->reportDetail, query->ssidLen, query->ssid, query->numChanReport);
            for (size_t k=0; k<query->numChanReport; k++) {
                if (k >= IEEE1905_MAX_OPERATING_CLASSES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "lenChanReport=%u; chanReportOpClass=%u",
                     query->chanReport[k].lenChanReport, query->chanReport[k].chanReportOpClass);
                for (size_t m=0; m<query->chanReport[k].lenChanReport; m++) {
                if (m >= IEEE1905_MAX_CHANNELS_PER_OP_CLASS) {
                    break;
                }
                    dbgf(dbgModule, DBGDEBUG,
                         "channel=%u", query->chanReport[k].chanList[m]);
                }
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numElementID=%u", query->numElementID);
            for (size_t k=0; k<query->numElementID; k++) {
                dbgf(dbgModule, DBGDEBUG,
                     "element=%u", query->elementList[k]);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_BEACON_METRICS_RESPONSE:
        {
            mesh1905BcnMetrics_t *metric =
                (mesh1905BcnMetrics_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Beacon Metrics Received from alId = "
                     meshMACAddFmt(":") ", for STA addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(metric->staAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numReportElements=%u; lenReport=%zu",
                 metric->numReportElements, metric->lenReport);
            for (size_t k=0; k<metric->lenReport; k++) {
                dbgf(dbgModule, DBGDUMP,
                     "report byte #%zu = 0x%02X", k, metric->report[k]);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_STEERING_REQUEST:
        {
            mapServiceSteeringRequest_t *steerReq =
                (mapServiceSteeringRequest_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Steering Request sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "bssid=" meshMACAddFmt(":") "; isMandate=%d; "
                    "disassocImminent=%d; abridged=%d; opWindow=%u; disassocTimer=%u; "
                    "numSTAs=%u", meshMACAddData(steerReq->bssid.ether_addr_octet),
                 steerReq->isMandate, steerReq->disassocImminent, steerReq->abridged,
                 steerReq->opWindow, steerReq->disassocTimer, steerReq->numSTAs);
            for (size_t k=0; k<steerReq->numSTAs; k++) {
                if (k >= MAP_SERVICE_STEER_REQ_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "staAddr=" meshMACAddFmt(":"),
                     meshMACAddData(steerReq->staAddr[k].ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "targetBSSCount=%u", steerReq->targetBSSCount);
            for (size_t k=0; k<steerReq->targetBSSCount; k++) {
                if (k >= MAP_SERVICE_STEER_REQ_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssid=" meshMACAddFmt(":") "; opClass=%u; channel=%u",
                     meshMACAddData(steerReq->targetBSSes[k].bssid.ether_addr_octet),
                     steerReq->targetBSSes[k].opClass, steerReq->targetBSSes[k].channel);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_STEERING_BTM_REPORT:
        {
            mapServiceSteeringBTMReport_t *btmReport =
                (mapServiceSteeringBTMReport_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Steering BTM Report Received from alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "bssid = " meshMACAddFmt(":") "; staAddr = " meshMACAddFmt(":")
                     "; status=%u; targetBSSID = " meshMACAddFmt(":"),
                 meshMACAddData(btmReport->bssid.ether_addr_octet),
                 meshMACAddData(btmReport->staAddr.ether_addr_octet),
                 btmReport->status,
                 meshMACAddData(btmReport->targetBSSID.ether_addr_octet));

            break;
        }
        case IEEE1905_TLV_TYPE_CLIENT_ASSOICATION_CONTROL:
        {
            mapServiceClientAssocControlRequest_t *assocReqList =
                (mapServiceClientAssocControlRequest_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Client Association Control Request sent to alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "bssid=" meshMACAddFmt(":") "; policy=%d; validitySecs=%u; "
                    "numSTAs=%u", meshMACAddData(assocReqList->bssid.ether_addr_octet),
                 assocReqList->policy, assocReqList->validitySecs, assocReqList->numSTAs);
            for (size_t k=0; k<assocReqList->numSTAs; k++) {
                if (k >= MAP_SERVICE_MAX_ASSOC_CTRL_STA) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "staAddr=" meshMACAddFmt(":"),
                     meshMACAddData(assocReqList->staAddrs[k].ether_addr_octet));
            }
            break;
        }
        case IEEE1905_TLV_TYPE_BACKHAUL_STEERING_REQUEST:
        {
            mapServiceBackhaulSteeringReq_t *steerReq =
                (mapServiceBackhaulSteeringReq_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Backhaul Steering Request sent to alId = "
                    meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "staAddr=" meshMACAddFmt(":") "; targetBSSID="
                     meshMACAddFmt(":") " opClass=%u; channel=%u",
                 meshMACAddData(steerReq->staAddr.ether_addr_octet),
                 meshMACAddData(steerReq->targetBSSID.ether_addr_octet),
                 steerReq->opClass, steerReq->channel);

            break;
        }
        case IEEE1905_TLV_TYPE_BACKHAUL_STEERING_RESPONSE:
        {
            mapServiceBackhaulSteeringRsp_t *steerRsp =
                (mapServiceBackhaulSteeringRsp_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Backhaul Steering Response Received from alId = "
                     meshMACAddFmt(":") ", for STA addr = " meshMACAddFmt(":")
                     ", being steered to target BSS = "meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(steerRsp->staAddr.ether_addr_octet),
                 meshMACAddData(steerRsp->targetBSSID.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "statusCode = %d ", steerRsp->statusCode);

            break;
        }
        case IEEE1905_TLV_TYPE_HIGHER_LAYER_PAYLOAD:
        {
            mesh1905HigherLayerData_t *higherLayerData =
                (mesh1905HigherLayerData_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Higher Payload Data sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "protocol=%u; length=%u;",
                 higherLayerData->protocol, higherLayerData->length);
            for (size_t k=0; k<higherLayerData->length; k++) {
                dbgf(dbgModule, DBGDUMP,
                     "payload data dump byte#%zu = 0x%02X",
                     k, higherLayerData->data[k]);
            }

            break;
        }
        case IEEE1905_TLV_TYPE_ASSOC_STA_TRAFFIC_STATS:
        {
            mapServiceAssocSTATrafficStats_t *stats =
                (mapServiceAssocSTATrafficStats_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Assoc STA Traffic Stats Received from alId = "
                     meshMACAddFmt(":") ", for STA addr = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(stats->staAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 " txBytes=%u; rxBytes=%u; pktsSent=%u; "
                     "pktsRcvd=%u; txPktErr=%u; rxPktErr=%u; cntRetx=%u",
                 stats->staStats.txBytes, stats->staStats.rxBytes,
                 stats->staStats.pktsSent, stats->staStats.pktsRcvd,
                 stats->staStats.txPktErr, stats->staStats.rxPktErr,
                 stats->staStats.cntRetx);

            break;
        }
        case IEEE1905_TLV_TYPE_ERROR:
        {
            mapServiceErrorCode_t *errorCode =
                (mapServiceErrorCode_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Error Code received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 " reasonCode=%u; staAddr=" meshMACAddFmt(":"),
                 errorCode->reasonCode, meshMACAddData(errorCode->staAddr.ether_addr_octet));

            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_SCAN_REPORT_POLICY:
        {
            ieee1905ChannelScanReportPolicy_t *policy =
                (ieee1905ChannelScanReportPolicy_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Channel Scan Report Policy sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "rptIndScan=%d", policy->rptIndScan);

            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_SCAN_CAP:
        {
            mesh1905APChannelScanCap_t *radioChanScanCap =
                (mesh1905APChannelScanCap_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Channel Scan Capability received from alId = " meshMACAddFmt(":")
                    " and Radio addr = " meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(radioChanScanCap->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "onBootScan=%d; scanImpact=%u; minScanInterval=%u; numOpClass=%u",
                 radioChanScanCap->chanScanCap.onBootScan,
                 radioChanScanCap->chanScanCap.scanImpact,
                 radioChanScanCap->chanScanCap.minScanInterval,
                 radioChanScanCap->chanScanCap.numOpClass);
            for (size_t k=0; k<radioChanScanCap->chanScanCap.numOpClass; k++) {
                if (k >= IEEE1905_MAX_OPERATING_CLASSES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; numChannels=%u",
                     radioChanScanCap->chanScanCap.scanCapOpClass[k].opClass,
                     radioChanScanCap->chanScanCap.scanCapOpClass[k].numChannels);
                for (size_t j=0; j<radioChanScanCap->chanScanCap.scanCapOpClass[k].numChannels; j++) {
                    if (j >= IEEE1905_MAX_CHANNELS_PER_OP_CLASS) {
                        break;
                    }
                    dbgf(dbgModule, DBGDEBUG,
                         "channels=%u",
                         radioChanScanCap->chanScanCap.scanCapOpClass[k].channels[j]);
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_SCAN_REQUEST:
        {
            ieee1905ChannelScanRequest_t *scanReq =
                (ieee1905ChannelScanRequest_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Channel Scan Request sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "performFreshScan=%d; numRadios=%u",
                 scanReq->performFreshScan, scanReq->numRadios);
            for (size_t k=0; k<scanReq->numRadios; k++) {
                if (k >= IEEE1905_MAX_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr = " meshMACAddFmt(":") " numOpClass=%u",
                     meshMACAddData(scanReq->scanReqRadio[k].radioAddr.ether_addr_octet),
                     scanReq->scanReqRadio[k].numOpClass);
                for (size_t j=0; j<scanReq->scanReqRadio[k].numOpClass; j++) {
                    if (j >= MAP_SERVICE_MAX_OPERATING_CLASSES) {
                        break;
                    }
                    dbgf(dbgModule, DBGDEBUG,
                         "opClass=%u; numChannels=%u",
                         scanReq->scanReqRadio[k].scanReqOpClass[j].opClass,
                         scanReq->scanReqRadio[k].scanReqOpClass[j].numChannels);
                    for (size_t i=0; i<scanReq->scanReqRadio[k].scanReqOpClass[j].numChannels; i++) {
                        if (i >= MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS) {
                            break;
                        }
                        dbgf(dbgModule, DBGDEBUG,
                             "channels=%u",
                             scanReq->scanReqRadio[k].scanReqOpClass[j].channels[i]);
                    }
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CHANNEL_SCAN_RESULT:
        {
            mesh1905APChannelScanResult_t *result =
                (mesh1905APChannelScanResult_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Channel scan result received from alId = " meshMACAddFmt(":")
                    " and Radio addr = " meshMACAddFmt(":"), __func__,
                 meshMACAddData(meshFrame->alId.ether_addr_octet),
                 meshMACAddData(result->radioAddr.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "opClass=%u; channel=%u; scanStatus=%u; timeStampLength=%u; timeStamp=%s;"
                    " chUtil=%u; noise=%u; numNeighbors=%u;",
                 result->chanScanResult.opClass, result->chanScanResult.channel,
                 result->chanScanResult.scanStatus, result->chanScanResult.timeStampLength,
                 result->chanScanResult.timeStamp, result->chanScanResult.chUtil,
                 result->chanScanResult.noise, result->chanScanResult.numNeighbors);
            for (size_t k=0; k<result->chanScanResult.numNeighbors; k++) {
                if (k >= IEEE1905_MAX_NEIGHBORS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssid = " meshMACAddFmt(":") "ssidLen=%u; ssid=%s",
                     meshMACAddData(result->chanScanResult.scanResults[k].bssid.ether_addr_octet),
                     result->chanScanResult.scanResults[k].ssidLen,
                     result->chanScanResult.scanResults[k].ssid);
                dbgf(dbgModule, DBGDEBUG,
                     "signalStrength=%u; channelBw=%u; bssLoadPresent=%d; chUtil=%u staCnt=%u;",
                     result->chanScanResult.scanResults[k].signalStrength,
                     result->chanScanResult.scanResults[k].channelBw,
                     result->chanScanResult.scanResults[k].bssLoadPresent,
                     result->chanScanResult.scanResults[k].chUtil,
                     result->chanScanResult.scanResults[k].staCnt);
            }
            dbgf(dbgModule, DBGDEBUG,
                 "aggregateScanDuration=%u; scanType=%d;",
                 result->chanScanResult.aggregateScanDuration, result->chanScanResult.scanType);
            break;
        }
        case IEEE1905_TLV_TYPE_TIMESTAMP:
        {
            ieee1905ISOTimeStamp_t *isoTimeStamp =
                (ieee1905ISOTimeStamp_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: ISO Timestamp received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "length=%u; timeStamp=%s",
                 isoTimeStamp->length, isoTimeStamp->timeStamp);

            break;
        }
        case IEEE1905_TLV_TYPE_CAC_REQUEST:
        {
            ieee1905CACRequest_t *request =
                (ieee1905CACRequest_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: CAC request sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numRadios=%u",
                 request->numRadios);
            for (size_t k=0; k<request->numRadios; k++) {
                if (k >= IEEE1905_SIMULTANEOUS_CAC_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr = " meshMACAddFmt(":") " opClass=%u; channelNum=%u;"
                        " cacMode=%d; successfullCACCompleteAction=%d",
                     meshMACAddData(request->cacRadioCap[k].radioAddr.ether_addr_octet),
                     request->cacRadioCap[k].opClass, request->cacRadioCap[k].channelNum,
                     request->cacRadioCap[k].cacMode,
                     request->cacRadioCap[k].successfullCACCompleteAction);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CAC_TERMINATION:
        {
            ieee1905CACTerminate_t *termination =
                (ieee1905CACTerminate_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: CAC termination sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numRadios=%u",
                 termination->numRadios);
            for (size_t k=0; k<termination->numRadios; k++) {
                if (k >= IEEE1905_SIMULTANEOUS_CAC_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr = " meshMACAddFmt(":") " opClass=%u; channelNum=%u;",
                     meshMACAddData(termination->cacRadioCap[k].radioAddr.ether_addr_octet),
                     termination->cacRadioCap[k].opClass, termination->cacRadioCap[k].channelNum);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CAC_COMPLETE:
        {
            ieee1905CACCompletionReport_t *report =
                (ieee1905CACCompletionReport_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: CAC completion report received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numRadios=%u",
                 report->numRadios);
            for (size_t k=0; k<report->numRadios; k++) {
                if (k >= IEEE1905_SIMULTANEOUS_CAC_RADIOS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "radioAddr = " meshMACAddFmt(":") " opClass=%u; channelNum=%u;"
                        " cacStatus=%d; numChannelOpClassPair=%d",
                     meshMACAddData(report->cacRadioCap[k].radioAddr.ether_addr_octet),
                     report->cacRadioCap[k].opClass, report->cacRadioCap[k].channelNum,
                     report->cacRadioCap[k].cacStatus,
                     report->cacRadioCap[k].numChannelOpClassPair);
                for (size_t j=0; j<report->cacRadioCap[k].numChannelOpClassPair; j++) {
                    if (j >= IEEE1905_MAX_CHANNELS_PER_OP_CLASS) {
                        break;
                    }
                    dbgf(dbgModule, DBGDEBUG,
                         "opClass=%u; channelNum=%u",
                         report->cacRadioCap[k].radarAffectedPair[j].opClass,
                         report->cacRadioCap[k].radarAffectedPair[j].channelNum);
                }
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CAC_STATUS_REPORT:
        {
            ieee1905CACStatusReport_t *report =
                (ieee1905CACStatusReport_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: CAC status report received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numCACDoneChannelOpclassPairs=%u",
                 report->numCACDoneChannelOpclassPairs);
            for (size_t k=0; k<report->numCACDoneChannelOpclassPairs; k++) {
                if (k >= MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; channelNum=%u; minSinceLastCACComplete=%u",
                     report->cacDone[k].opClass, report->cacDone[k].channelNum,
                     report->cacDone[k].minSinceLastCACComplete);
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numNOLChannelOpclassPairs=%u",
                 report->numNOLChannelOpclassPairs);
            for (size_t k=0; k<report->numNOLChannelOpclassPairs; k++) {
                if (k >= MAP_SERVICE_MAX_CHANNELS_PER_OP_CLASS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; channelNum=%u; secRemainingInNOLList=%u",
                     report->nolList[k].opClass, report->nolList[k].channelNum,
                     report->nolList[k].secRemainingInNOLList);
            }
            dbgf(dbgModule, DBGDEBUG,
                 "numCACOngoingChannelOpclassPairs=%u",
                 report->numCACOngoingChannelOpclassPairs);
            for (size_t k=0; k<report->numCACOngoingChannelOpclassPairs; k++) {
                if (k >= MAP_SERVICE_MAX_OPERATING_CLASSES) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "opClass=%u; channelNum=%u; secRemainingToCACComplete=%u",
                     report->cacOngoing[k].opClass, report->cacOngoing[k].channelNum,
                     report->cacOngoing[k].secRemainingToCACComplete);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_CAC_CAP:
        {
            mesh1905CACCap_t *cacCap =
                (mesh1905CACCap_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: CAC Capability received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "countryCode=%u; numRadio=%u", cacCap->countryCode, cacCap->numRadio);
            break;
        }
        case IEEE1905_TLV_TYPE_MAP_VERSION:
        {
            ieee1905MultiAPVersion_t *mapVersion =
                (ieee1905MultiAPVersion_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: MultiAP version received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "version=%u", mapVersion->version);
            break;
        }
        case IEEE1905_TLV_TYPE_R2_APCAP:
        {
            ieee1905R2APCapabilities_t *cap =
                (ieee1905R2APCapabilities_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: R2 AP Capability received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "maxSPRules=%u; byteCounterUnits=%u; maxTotalNumVIDs=%u",
                 cap->maxSPRules, cap->byteCounterUnits, cap->maxTotalNumVIDs);
            break;
        }
        case IEEE1905_TLV_TYPE_8021Q_RULES:
        {
            ieee19058021QSettings_t *policy =
                (ieee19058021QSettings_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: 802.1Q rules sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "vlanID=%u; pcp=%u", policy->vlanID, policy->pcp);
            break;
        }
        case IEEE1905_TLV_TRAFFIC_SEPARATON_POLICY:
        {
            ieee1905TrafficSepPolicy_t *policy =
                (ieee1905TrafficSepPolicy_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Traffic separation policy sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numOfSSIDs=%u",
                 policy->numOfSSIDs);
            for (size_t k=0; k<policy->numOfSSIDs; k++) {
                if (k >= IEEE1905_QCA_VENDOR_MAX_INTERFACE) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "ssidLen=%u; ssid=%s; vlanID=%u;",
                     policy->interfaceConf[k].ssidLen, policy->interfaceConf[k].ssid,
                     policy->interfaceConf[k].vlanID);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_R2_ERROR_CODE:
        {
            ieee1905R2ErrorCode_t *errorCode =
                (ieee1905R2ErrorCode_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: R2 Error code received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "errorCode=%u; ruleID=%u", errorCode->errorCode, errorCode->ruleID);
            break;
        }
        case IEEE1905_TLV_TYPE_AP_RADIO_ADVANCED_CAP:
        {
            ieee1905APRadioAdvanceCap_t *cap =
                (ieee1905APRadioAdvanceCap_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP Radio Advanced Capability received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "radioAddr = " meshMACAddFmt(":") "combinedFrontBack=%d; combinedProfiles=%d;",
                 meshMACAddData(cap->radioAddr.ether_addr_octet),
                 cap->combinedFrontBack, cap->combinedProfiles);
            break;
        }
        case IEEE1905_TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION:
        {
            ieee1905AssocStatusNotify_t *status =
                (ieee1905AssocStatusNotify_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Assoc status notification for alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "numBSSInNotification=%u",
                 status->numBSSInNotification);
            for (size_t k=0; k<status->numBSSInNotification; k++) {
                if (k >= IEEE1905_QCA_VENDOR_MAX_INTERFACE) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssid = " meshMACAddFmt(":") " assocAllowanceStatus=%u;",
                     meshMACAddData(status->bss[k].bssid.ether_addr_octet),
                     status->bss[k].assocAllowanceStatus);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_SOURCE_INFO:
        {
            ieee1905SrcInfo_t *srcInfo = (ieee1905SrcInfo_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Source info received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "srcAddr = " meshMACAddFmt(":"),
                 meshMACAddData(srcInfo->srcAddr.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_TUNNELED_MSG_TYPE:
        {
            int *type = (int *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Tunneled message type %d received from alId = " meshMACAddFmt(":"),
                 __func__, *type, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_TUNNELED_PAYLOAD:
        {
            char *payload = meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Tunneled payload = %s , received from alId = " meshMACAddFmt(":"),
                 __func__, payload, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_R2_STEERING_REQUEST:
        {
            ieee1905R2SteeringRequest_t *steerReq =
                (ieee1905R2SteeringRequest_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: R2 steering request sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "bssid = " meshMACAddFmt(":") " isMandate=%d; disassocImminent=%d; abridged=%d",
                 meshMACAddData(steerReq->bssid.ether_addr_octet),
                 steerReq->isMandate, steerReq->disassocImminent, steerReq->abridged);
            dbgf(dbgModule, DBGDEBUG,
                 "opWindow=%u; disassocTimer=%u; numSTAs=%u",
                 steerReq->opWindow, steerReq->disassocTimer, steerReq->numSTAs);
            for (size_t k=0; k<steerReq->targetBSSCount; k++) {
                if (k >= MAP_SERVICE_STEER_REQ_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "staAddr = " meshMACAddFmt(":"),
                     meshMACAddData(steerReq->staAddr[k].ether_addr_octet));
            }
            dbgf(dbgModule, DBGDEBUG,
                 "targetBSSCount=%u",
                 steerReq->targetBSSCount);
            for (size_t k=0; k<steerReq->targetBSSCount; k++) {
                if (k >= MAP_SERVICE_STEER_REQ_MAX_STAS) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssid = " meshMACAddFmt(":") " opClass=%u; channel=%u; reason=%u",
                     meshMACAddData(steerReq->targetBSSes[k].bssid.ether_addr_octet),
                     steerReq->targetBSSes[k].opClass, steerReq->targetBSSes[k].channel,
                     steerReq->targetBSSes[k].reason);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY:
        {
            ieee1905UnSuccessfulAssocPolicy_t *policy =
                (ieee1905UnSuccessfulAssocPolicy_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Unsuccessful assoc policy sent to alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "reportUnSuccessfulAssoc=%d; maxReportingRate=%u",
                 policy->reportUnSuccessfulAssoc, policy->maxReportingRate);
            break;
        }
        case IEEE1905_TLV_TYPE_METRIC_COLLECTION_INTERVAL:
        {
            ieee1905R2MetricCollectionInterval_t *metric =
                (ieee1905R2MetricCollectionInterval_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Metric collection interval received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "collectionInterval=%u", metric->collectionInterval);

            break;
        }
        case IEEE1905_TLV_TYPE_RADIO_METRIC:
        {
            ieee1905APRadioMetrics_t *metric =
                (ieee1905APRadioMetrics_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Radio Metrics received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "radioAddr = " meshMACAddFmt(":") " noise=%u; transmit=%u;"
                 " receiveSelf=%u; receiveOther=%u",
                 meshMACAddData(metric->radioAddr.ether_addr_octet),
                 metric->noise, metric->transmit,
                 metric->receiveSelf, metric->receiveOther);
            break;
        }
        case IEEE1905_TLV_TYPE_AP_EXTENDED_METRICS:
        {
            ieee1905APExtendedMetricTLV_t *metric =
                (ieee1905APExtendedMetricTLV_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: AP Extentded Metrics received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "bssid = " meshMACAddFmt(":") " unicastBytesSent=%u; unicastBytesReceived=%u;"
                    " multicastBytesSent=%u; multicastBytesReceived=%u"
                    " broadcastBytesSent=%u; broadcastBytesReceived=%u",
                 meshMACAddData(metric->bssid.ether_addr_octet),
                 metric->unicastBytesSent, metric->unicastBytesReceived,
                 metric->multicastBytesSent, metric->multicastBytesReceived,
                 metric->broadcastBytesSent, metric->broadcastBytesReceived);
            break;
        }
        case IEEE1905_TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS:
        {
            ieee1905StaExtendedLinkMetricTlv_t *metric =
                (ieee1905StaExtendedLinkMetricTlv_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Assoc sta extended link metrics received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "staAddr = " meshMACAddFmt(":") " numBSSID=%u",
                 meshMACAddData(metric->staAddr.ether_addr_octet), metric->numBSSID);
            for (size_t k=0; k<metric->numBSSID; k++) {
                if (k >= IEEE1905_STA_EXTENDED_LINK_METRIC_STA_BSS_CONNECTION) {
                    break;
                }
                dbgf(dbgModule, DBGDEBUG,
                     "bssid = " meshMACAddFmt(":") " lastDataDownlinkRate=%u;"
                        " lastDataUplinkRate=%u; utilizationReceive=%u; utilizationTransmit=%u",
                     meshMACAddData(metric->staLinkMetric[k].bssid.ether_addr_octet),
                     metric->staLinkMetric[k].lastDataDownlinkRate,
                     metric->staLinkMetric[k].lastDataUplinkRate,
                     metric->staLinkMetric[k].utilizationReceive,
                     metric->staLinkMetric[k].utilizationTransmit);
            }
            break;
        }
        case IEEE1905_TLV_TYPE_STATUS_CODE:
        {
            u_int16_t *statusCode = (u_int16_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Status code %u received from alId = " meshMACAddFmt(":"),
                 __func__, *statusCode, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_DISASSOC_REASON_CODE:
        {
            u_int16_t *reasonCode = (u_int16_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: Disassoc reason code %u received from alId = " meshMACAddFmt(":"),
                 __func__, *reasonCode, meshMACAddData(meshFrame->alId.ether_addr_octet));
            break;
        }
        case IEEE1905_TLV_TYPE_BSTA_RADIO_CAP:
        {
            ieee1905BSTARadioCap_t *bstaCap =
                (ieee1905BSTARadioCap_t *) meshFrame->content;

            dbgf(dbgModule, DBGDEBUG,
                 "%s: bsta radio capability received from alId = " meshMACAddFmt(":"),
                 __func__, meshMACAddData(meshFrame->alId.ether_addr_octet));
            dbgf(dbgModule, DBGDEBUG,
                 "ruid = " meshMACAddFmt(":") " macIncluded=%d; macAddr = " meshMACAddFmt(":"),
                 meshMACAddData(bstaCap->ruid.ether_addr_octet), bstaCap->macIncluded,
                 meshMACAddData(bstaCap->macAddr.ether_addr_octet));
            break;
        }
        default:
            dbgf(dbgModule, DBGDEBUG, "%s TLV not found = %u", __func__, meshFrame->tlvType);
            break;
    }
    return MESH_OK;
}

/**
 * Mesh Ieee1905 Init
 */
int meshIeee1905Init(void)
{
    dbgModule = dbgModuleFind("ieee1905");
    dbgModule->Level = DBGINFO;

    return MESH_OK;
}
