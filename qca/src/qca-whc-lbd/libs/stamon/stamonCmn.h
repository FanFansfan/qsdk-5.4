// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stamonCmn.h
 *
 * @Abstract: Functions shared by stamonBSA and stamonMBSA
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015, 2017-2019 Qualcomm Technologies, Inc.
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
 */

#ifndef stamonCmn__h
#define stamonCmn__h

#include <dbg.h>

#include "steeralg.h"
#include "stadbEntry.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define BSTEERING_MAX_CLIENT_CLASS_GROUP 2

// ====================================================================
// Protected members (for use within the common functions and any
// "derived" functions that may be using this component).
// ====================================================================

struct stamonPriv_t {
    struct dbgModule *dbgModule;

    /// Configuration data obtained at init time
    struct {
        /// The number of inst RSSI measurements per-band
        u_int8_t instRSSINumSamples[wlanif_band_invalid];

        /// Number of seconds allowed for a measurement to
        /// be considered as recent
        u_int8_t freshnessLimit;

        /// Number of seconds allowed for a measurement to
        /// be considered recent for a legacy client
        u_int8_t legacyClientFreshnessLimit;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;

        /// The lower-bound Tx rate value (Mbps) below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        lbd_linkCapacity_t lowTxRateCrossingThreshold;

        /// The upper-bound Tx rate value (Mbps) above which a client on 2.4GHz
        /// is eligible for upgrade to 5GHz.
        lbd_linkCapacity_t highTxRateCrossingThreshold[BSTEERING_MAX_CLIENT_CLASS_GROUP];

        /// The lower-bound RSSI value below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        u_int8_t lowRateRSSIXingThreshold;

        /// When evaluating a STA for upgrade from 2.4GHz to 5GHz, the RSSI must
        /// also exceed this value.
        u_int8_t highRateRSSIXingThreshold[BSTEERING_MAX_CLIENT_CLASS_GROUP];

        /// The RSSI threshold for downgrading an idle client
        u_int8_t inactRSSIXingThreshold_DG[BSTEERING_MAX_CLIENT_CLASS_GROUP];

        /// The lower-bound RSSI value below which a client is eligible for being
        /// steered to another AP
        u_int8_t apSteerLowRSSIXingThresholds[wlanif_band_invalid][BSTEERING_MAX_CLIENT_CLASS_GROUP];

        // Enable or Disable Steering of InActive legacy clients.
        LBD_BOOL disableSteeringInactiveLegacyClients;

        // Enable or Disable Steering of Active legacy clients.
        LBD_BOOL disableSteeringActiveLegacyClients;

        // Enable or Disable Steering of consecutive 11k failed clients for max count.
        LBD_BOOL disableSteering11kUnfriendlyClients;
    } config;
};

extern struct stamonPriv_t stamonState;
#define stamonDebug(level, ...) \
            dbgf(stamonState.dbgModule,(level),__VA_ARGS__)

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Make a steering decision for an idle client
 *
 * @pre entry is dual band, associated and idle
 *
 * @param [in] entry  the STA that needs to be checked
 */
void stamonMakeSteerDecisionIdle(stadbEntry_handle_t entry);

/**
 * @brief Determine if a STA can be steered while active based on
 *        its rate and RSSI
 *
 * @pre STA is associated and eligible for active steering
 *
 * @param [in] entry  STA to evaluate for steering by rate
 * @param [in] staAddr  the MAC address of the station
 * @param [in] band  the band STA is associated on
 * @param [in] staStats  stats sample containing last Tx rate
 * @param [in] rateEligibility  whether the rate meets steering threshold
 */
void stamonMakeSteerDecisionActive(stadbEntry_handle_t entry,
                                   const struct ether_addr *staAddr, wlanif_band_e band,
                                   const wlanif_staStatsSnapshot_t *staStats,
                                   steeralg_rateSteerEligibility_e rateEligibility);

/**
 * @brief Make a monitoring decision for an legacy client in multi AP setup
 * on the same band.
 *
 * @pre entry is legacy and associated
 *
 * @param [in] entry  the STA that needs to be checked
 */
void stamonMakeLegacyAPSteerDecision(stadbEntry_handle_t entry);

/**
 * @brief Hook function that determines whether this BSS is allowed to
 *        initiate steering.
 *
 * @param [in] bss  the BSS from which a STA may be steered; this will
 *                  always be a local BSS
 *
 * @return LBD_TRUE if steering is allowed; otherwise LBD_FALSE
 */
LBD_BOOL stamonIsBSSAllowedToInitSteering(const lbd_bssInfo_t *bss);

/**
 * @brief Function to initialize MBSA specific init
 */
void stamonSubInit(void);

// ====================================================================
// Functions internally shared by BSA and MBSA
// ====================================================================

/**
 * @brief Get the latest uplink RSSI measurement on serving BSS and make estimation
 *        on non-serving BSSes
 *
 * @pre entry is valid and associated
 *
 * @param [in] entry  the entry to check RSSI
 * @param [out] rssiOut  if non-NULL, just return the RSSI in
 *                       this parameter and don't estimate on the
 *                       non-serving BSSes
 *
 * @return LBD_OK if all RSSI info are up-to-date; otherwise return LBD_NOK
 */
LBD_STATUS stamonCmnGetUplinkRSSI(stadbEntry_handle_t entry, lbd_rssi_t *rssiOut);

/**
 * @brief Check if the STA can be active upgraded
 *
 * @pre The Tx rate has met active upgrade threshold.
 *
 * It includes checking RSSI, checking if there is at least one target to be directed to
 * and checking if it is in steering blackout window.
 *
 * @param [in] entry  the STA to check eligibility for
 * @param [in] staAddr  MAC address of the STA
 * @param [in] band  band the STA is associated on
 * @param [in] tx_rate  last rate this STA transmitted at (for logging purpose)
 * @param [in] tx_rate  last rate this STA transmitted at
 *
 * @return LBD_TRUE if the STA is eligible and allowed to active upgrade,
 *         otherwise return LBD_FALSE
 */
LBD_BOOL stamonCmnIsEligibleForActiveUpgrade(stadbEntry_handle_t entry,
                                             const struct ether_addr *staAddr,
                                             wlanif_band_e band, u_int32_t tx_rate,
                                             lbd_rssi_t rssi);

/**
 * @brief Trigger active steering
 *
 * @pre STA has been determined to be eligible for active steering
 *
 * @param [in] handle  the handle to the STA
 * @param [in] staAddr MAC address of the STA
 * @param [in] trigger  the trigger of this steering (upgrade/downgrade/AP steer)
 */
void stamonCmnTriggerActiveSteering(stadbEntry_handle_t handle,
                                    const struct ether_addr *staAddr,
                                    steerexec_reason_e trigger);

#if defined(__cplusplus)
}
#endif

#endif // stamonCmn__h
