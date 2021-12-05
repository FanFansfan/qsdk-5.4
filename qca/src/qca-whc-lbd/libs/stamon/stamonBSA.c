// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stamonBSA.c
 *
 * @Abstract: Implementation of single AP station monitor
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015, 2017-2018 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include "lb_assert.h"
#include "stadb.h"
#include "bandmon.h"

#include "stamonCmn.h"

// ====================================================================
// Private functions
// ====================================================================

// ====================================================================
// Package level functions
// ====================================================================
void stamonMakeSteerDecisionIdle(stadbEntry_handle_t entry) {
    if (bandmon_areAllChannelsOverloaded()) {
        // No steering is performed if there are no non-overloaded channels.
        // We just let the client decide, as there is not really anything we
        // can do to make the situation better.
        return;
    }

    if (LBD_NOK == stamonCmnGetUplinkRSSI(entry, NULL)) {
        // RSSI information not ready
        return;
    }

    steeralg_steerIdleClient(entry);
}

// For active clients in single AP setup, will attempt to upgrade
// from 2.4GHz to 5GHz if both the rate and RSSI are sufficiently high,
// or to downgrade from 5GHz to 2.4GHz if the rate or RSSI is sufficiently low.
void stamonMakeSteerDecisionActive(stadbEntry_handle_t entry,
                                   const struct ether_addr *staAddr, wlanif_band_e band,
                                   const wlanif_staStatsSnapshot_t *staStats,
                                   steeralg_rateSteerEligibility_e rateEligibility) {
    lbd_rssi_t rssi = LBD_INVALID_RSSI;
    steerexec_reason_e trigger = steerexec_reason_invalid;

    if (rateEligibility == steeralg_rateSteer_downgrade) {
        dbgf(stamonState.dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " eligible for downgrade at rate %u",
             __func__, lbMACAddData(staAddr->ether_addr_octet), staStats->lastTxRate);
        trigger = steerexec_reason_activeDowngradeRate;
    } else if ((rateEligibility == steeralg_rateSteer_none) && (band == wlanif_band_24g)) {
        // For upgrade, both rate and rssi need to exceed their respective thresholds
        // Rate is neither sufficient for upgrade or downgrade.
        trigger = steerexec_reason_invalid;
    } else {
        // For downgrade, either rate or rssi needs to exeed their respective thresholds.
        // The rate is not sufficient for downgrade, but check RSSI as well.
        // For upgrade, the rate was sufficient for upgrade, but still need to check RSSI.
        if (stamonCmnGetUplinkRSSI(entry, &rssi) == LBD_NOK) {
            trigger = steerexec_reason_invalid;
        } else if ((rssi < stamonState.config.lowRateRSSIXingThreshold) &&
                    stadbEntry_isBandSupported(entry, wlanif_band_6g) ){
            if (band == wlanif_band_5g || band == wlanif_band_24g) {
                if (stamonCmnIsEligibleForActiveUpgrade(entry, staAddr, band,
                                                        staStats->lastTxRate, rssi)) {
                    trigger = steerexec_reason_activeUpgrade;
                }
            } else {
                trigger = steerexec_reason_activeDowngradeRSSI;
            }
        } else if ( (rssi < stamonState.config.lowRateRSSIXingThreshold) &&
                    (band == wlanif_band_5g)) {
                dbgf(stamonState.dbgModule, DBGINFO,
                    "%s: Device " lbMACAddFmt(":")
                    " eligible for downgrade at rate %u, rssi %u",
                    __func__, lbMACAddData(staAddr->ether_addr_octet),
                    staStats->lastTxRate, rssi);
                trigger = steerexec_reason_activeDowngradeRSSI;
        }
        else if ((band == wlanif_band_24g) &&
                  stamonCmnIsEligibleForActiveUpgrade(entry, staAddr, band,
                                                       staStats->lastTxRate, rssi)) {
           trigger = steerexec_reason_activeUpgrade;
        }
    }
    if (trigger != steerexec_reason_invalid) {
        stamonCmnTriggerActiveSteering(entry, staAddr, trigger);
    }
}

// For idle or active legacy clients in multi AP setup, attempt AP steering
// on the same band.
void stamonMakeLegacyAPSteerDecision(stadbEntry_handle_t entry) {
    // Do Nothing for single AP setup.
}

LBD_BOOL stamonIsBSSAllowedToInitSteering(const lbd_bssInfo_t *bss) {
    // Only allow steering for local STA
    return lbIsBSSLocal(bss);
}

void stamonSubInit(){
    // Do Noting in BSA case for now
}
