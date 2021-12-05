// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRateTable.c
 *
 * @Abstract: The actual SNR to PHY rate table.
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include "lb_assert.h"

#include "estimatorSNRToPhyRateTable.h"

const estimatorSNRToPhyRateEntry_t
    estimatorSNRToPhyRateTable[wlanif_phymode_invalid]
                              [wlanif_chwidth_invalid]
                              [ESTIMATOR_MAX_NSS]
                              [ESTIMATOR_MAX_RATES] =
{
    // Data is extracted from SNR_table_WHC_v01.xlsx, using the SNR and Rates
    // worksheets. When dealing with fractional values, the ceiling is used
    // for the SNR and the floor is used for the rate (to be conservative).

    // 802.11g/a mode - derived from 11n with 51% efficiency (due to
    //                  no AMPDU)
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7  /* snr */,    3  /* rate */ },
                { 10 /* snr */,    6  /* rate */ },
                { 13 /* snr */,    9  /* rate */ },
                { 14 /* snr */,    13 /* rate */ },
                { 18 /* snr */,    19 /* rate */ },
                { 22 /* snr */,    26 /* rate */ },
                { 23 /* snr */,    29 /* rate */ },
                { 25 /* snr */,    33 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 40 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 80 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 160 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
    },

    // 802.11n mode - note that MCS8 and 9 are always invalid
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7 /* snr */,     6  /* rate */ },
                { 10 /* snr */,    13 /* rate */ },
                { 13 /* snr */,    19 /* rate */ },
                { 14 /* snr */,    26 /* rate */ },
                { 18 /* snr */,    39 /* rate */ },
                { 22 /* snr */,    52 /* rate */ },
                { 23 /* snr */,    58 /* rate */ },
                { 25 /* snr */,    65 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 40 MHz
        {
            // 1 spatial stream
            {
                { 6 /* snr */,     13  /* rate */ },
                { 9 /* snr */,     27  /* rate */ },
                { 12 /* snr */,    40  /* rate */ },
                { 13 /* snr */,    54  /* rate */ },
                { 17 /* snr */,    81  /* rate */ },
                { 21 /* snr */,    108 /* rate */ },
                { 22 /* snr */,    121 /* rate */ },
                { 24 /* snr */,    135 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 80 MHz - not valid for 802.11n
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 160 MHz - not valid for 802.11n
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
    },

    // 802.11ac mode - identical to 802.11n but with MCS8 and 9 populated
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7 /* snr */,     6  /* rate */ },
                { 10 /* snr */,    13 /* rate */ },
                { 13 /* snr */,    19 /* rate */ },
                { 14 /* snr */,    26 /* rate */ },
                { 18 /* snr */,    39 /* rate */ },
                { 22 /* snr */,    52 /* rate */ },
                { 23 /* snr */,    58 /* rate */ },
                { 25 /* snr */,    65 /* rate */ },
                { 31 /* snr */,    78 /* rate */ },
                { 32 /* snr */,    78 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { 35 /* snr */,    156 /* rate */ },
                { 37 /* snr */,    156 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { 8 /* snr */,     19  /* rate */ },
                { 13 /* snr */,    39  /* rate */ },
                { 16 /* snr */,    58  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 25 /* snr */,    117  /* rate */ },
                { 29 /* snr */,    156 /* rate */ },
                { 31 /* snr */,    175 /* rate */ },
                { 33 /* snr */,    195 /* rate */ },
                { 37 /* snr */,    234 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { 7 /* snr */,     26  /* rate */ },
                { 12 /* snr */,    52  /* rate */ },
                { 14 /* snr */,    78  /* rate */ },
                { 20 /* snr */,    104  /* rate */ },
                { 23 /* snr */,    156  /* rate */ },
                { 28 /* snr */,    208 /* rate */ },
                { 30 /* snr */,    234 /* rate */ },
                { 31 /* snr */,    260 /* rate */ },
                { 35 /* snr */,    312 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     26  /* rate */ },
                { 12 /* snr */,    52  /* rate */ },
                { 14 /* snr */,    78  /* rate */ },
                { 20 /* snr */,    104  /* rate */ },
                { 23 /* snr */,    156  /* rate */ },
                { 28 /* snr */,    208 /* rate */ },
                { 30 /* snr */,    234 /* rate */ },
                { 31 /* snr */,    260 /* rate */ },
                { 35 /* snr */,    312 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     26  /* rate */ },
                { 12 /* snr */,    52  /* rate */ },
                { 14 /* snr */,    78  /* rate */ },
                { 20 /* snr */,    104  /* rate */ },
                { 23 /* snr */,    156  /* rate */ },
                { 28 /* snr */,    208 /* rate */ },
                { 30 /* snr */,    234 /* rate */ },
                { 31 /* snr */,    260 /* rate */ },
                { 35 /* snr */,    312 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     26  /* rate */ },
                { 12 /* snr */,    52  /* rate */ },
                { 14 /* snr */,    78  /* rate */ },
                { 20 /* snr */,    104  /* rate */ },
                { 23 /* snr */,    156  /* rate */ },
                { 28 /* snr */,    208 /* rate */ },
                { 30 /* snr */,    234 /* rate */ },
                { 31 /* snr */,    260 /* rate */ },
                { 35 /* snr */,    312 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     26  /* rate */ },
                { 12 /* snr */,    52  /* rate */ },
                { 14 /* snr */,    78  /* rate */ },
                { 20 /* snr */,    104  /* rate */ },
                { 23 /* snr */,    156  /* rate */ },
                { 28 /* snr */,    208 /* rate */ },
                { 30 /* snr */,    234 /* rate */ },
                { 31 /* snr */,    260 /* rate */ },
                { 35 /* snr */,    312 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 40 MHz
        {
            // 1 spatial stream
            {
                { 6 /* snr */,     13  /* rate */ },
                { 9 /* snr */,     27  /* rate */ },
                { 12 /* snr */,    40  /* rate */ },
                { 13 /* snr */,    54  /* rate */ },
                { 17 /* snr */,    81  /* rate */ },
                { 21 /* snr */,    108 /* rate */ },
                { 22 /* snr */,    121 /* rate */ },
                { 24 /* snr */,    135 /* rate */ },
                { 30 /* snr */,    162 /* rate */ },
                { 31 /* snr */,    180 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { 34 /* snr */,    324 /* rate */ },
                { 36 /* snr */,    360 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - derived from 20 MHz by subtracting 1 dB
            {
                { 7 /* snr */,     40  /* rate */ },
                { 12 /* snr */,    81  /* rate */ },
                { 15 /* snr */,    121 /* rate */ },
                { 20 /* snr */,    162 /* rate */ },
                { 24 /* snr */,    243 /* rate */ },
                { 28 /* snr */,    324 /* rate */ },
                { 30 /* snr */,    364 /* rate */ },
                { 32 /* snr */,    405 /* rate */ },
                { 36 /* snr */,    486 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { 6 /* snr */,     54  /* rate */ },
                { 11 /* snr */,    108 /* rate */ },
                { 13 /* snr */,    162 /* rate */ },
                { 19 /* snr */,    216 /* rate */ },
                { 22 /* snr */,    324 /* rate */ },
                { 27 /* snr */,    432 /* rate */ },
                { 29 /* snr */,    486 /* rate */ },
                { 30 /* snr */,    540 /* rate */ },
                { 34 /* snr */,    648 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     54  /* rate */ },
                { 11 /* snr */,    108 /* rate */ },
                { 13 /* snr */,    162 /* rate */ },
                { 19 /* snr */,    216 /* rate */ },
                { 22 /* snr */,    324 /* rate */ },
                { 27 /* snr */,    432 /* rate */ },
                { 29 /* snr */,    486 /* rate */ },
                { 30 /* snr */,    540 /* rate */ },
                { 34 /* snr */,    648 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     54  /* rate */ },
                { 11 /* snr */,    108 /* rate */ },
                { 13 /* snr */,    162 /* rate */ },
                { 19 /* snr */,    216 /* rate */ },
                { 22 /* snr */,    324 /* rate */ },
                { 27 /* snr */,    432 /* rate */ },
                { 29 /* snr */,    486 /* rate */ },
                { 30 /* snr */,    540 /* rate */ },
                { 34 /* snr */,    648 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     54  /* rate */ },
                { 11 /* snr */,    108 /* rate */ },
                { 13 /* snr */,    162 /* rate */ },
                { 19 /* snr */,    216 /* rate */ },
                { 22 /* snr */,    324 /* rate */ },
                { 27 /* snr */,    432 /* rate */ },
                { 29 /* snr */,    486 /* rate */ },
                { 30 /* snr */,    540 /* rate */ },
                { 34 /* snr */,    648 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     54  /* rate */ },
                { 11 /* snr */,    108 /* rate */ },
                { 13 /* snr */,    162 /* rate */ },
                { 19 /* snr */,    216 /* rate */ },
                { 22 /* snr */,    324 /* rate */ },
                { 27 /* snr */,    432 /* rate */ },
                { 29 /* snr */,    486 /* rate */ },
                { 30 /* snr */,    540 /* rate */ },
                { 34 /* snr */,    648 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 80 MHz
        {
            // 1 spatial stream
            {
                { 5 /* snr */,     29  /* rate */ },
                { 8 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 12 /* snr */,    117 /* rate */ },
                { 16 /* snr */,    175 /* rate */ },
                { 20 /* snr */,    234 /* rate */ },
                { 21 /* snr */,    263 /* rate */ },
                { 23 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 5 /* snr */,     58  /* rate */ },
                { 9 /* snr */,     117 /* rate */ },
                { 12 /* snr */,    175 /* rate */ },
                { 16 /* snr */,    234 /* rate */ },
                { 20 /* snr */,    351 /* rate */ },
                { 24 /* snr */,    468 /* rate */ },
                { 26 /* snr */,    526 /* rate */ },
                { 29 /* snr */,    585 /* rate */ },
                { 33 /* snr */,    702 /* rate */ },
                { 35 /* snr */,    780 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - derived from 20 MHz by subtracting 2 dB
            {
                { 6 /* snr */,     87  /* rate */ },
                { 11 /* snr */,    175 /* rate */ },
                { 14 /* snr */,    263 /* rate */ },
                { 19 /* snr */,    351 /* rate */ },
                { 23 /* snr */,    526 /* rate */ },
                { 27 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    702 /* rate */ },
                { 31 /* snr */,    877 /* rate */ },
                { 35 /* snr */,    1053 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { 5 /* snr */,     117  /* rate */ },
                { 10 /* snr */,    234  /* rate */ },
                { 12 /* snr */,    351  /* rate */ },
                { 18 /* snr */,    468  /* rate */ },
                { 21 /* snr */,    702  /* rate */ },
                { 26 /* snr */,    936  /* rate */ },
                { 28 /* snr */,    1053 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     117  /* rate */ },
                { 10 /* snr */,    234  /* rate */ },
                { 12 /* snr */,    351  /* rate */ },
                { 18 /* snr */,    468  /* rate */ },
                { 21 /* snr */,    702  /* rate */ },
                { 26 /* snr */,    936  /* rate */ },
                { 28 /* snr */,    1053 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     117  /* rate */ },
                { 10 /* snr */,    234  /* rate */ },
                { 12 /* snr */,    351  /* rate */ },
                { 18 /* snr */,    468  /* rate */ },
                { 21 /* snr */,    702  /* rate */ },
                { 26 /* snr */,    936  /* rate */ },
                { 28 /* snr */,    1053 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     117  /* rate */ },
                { 10 /* snr */,    234  /* rate */ },
                { 12 /* snr */,    351  /* rate */ },
                { 18 /* snr */,    468  /* rate */ },
                { 21 /* snr */,    702  /* rate */ },
                { 26 /* snr */,    936  /* rate */ },
                { 28 /* snr */,    1053 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     117  /* rate */ },
                { 10 /* snr */,    234  /* rate */ },
                { 12 /* snr */,    351  /* rate */ },
                { 18 /* snr */,    468  /* rate */ },
                { 21 /* snr */,    702  /* rate */ },
                { 26 /* snr */,    936  /* rate */ },
                { 28 /* snr */,    1053 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 160 MHz - derived from 80 MHz by reducing SNR requirement by 1 dB
        {
            // 1 spatial stream
            {
                { 4 /* snr */,     58  /* rate */ },
                { 7 /* snr */,     116 /* rate */ },
                { 10 /* snr */,    174 /* rate */ },
                { 11 /* snr */,    234 /* rate */ },
                { 15 /* snr */,    350 /* rate */ },
                { 19 /* snr */,    468 /* rate */ },
                { 20 /* snr */,    526 /* rate */ },
                { 22 /* snr */,    584 /* rate */ },
                { 28 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    780 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 4 /* snr */,     116  /* rate */ },
                { 8 /* snr */,     234  /* rate */ },
                { 11 /* snr */,    350  /* rate */ },
                { 15 /* snr */,    468  /* rate */ },
                { 19 /* snr */,    702  /* rate */ },
                { 23 /* snr */,    936  /* rate */ },
                { 25 /* snr */,    1052 /* rate */ },
                { 28 /* snr */,    1170 /* rate */ },
                { 32 /* snr */,    1404 /* rate */ },
                { 34 /* snr */,    1560 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { 5 /* snr */,     175  /* rate */ },
                { 10 /* snr */,    351  /* rate */ },
                { 13 /* snr */,    526  /* rate */ },
                { 18 /* snr */,    702  /* rate */ },
                { 22 /* snr */,    1053 /* rate */ },
                { 26 /* snr */,    1404 /* rate */ },
                { 28 /* snr */,    1579 /* rate */ },
                { 30 /* snr */,    1755 /* rate */ },
                { 34 /* snr */,    2106 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { 4 /* snr */,     234  /* rate */ },
                { 9 /* snr */,    468  /* rate */ },
                { 11 /* snr */,    702  /* rate */ },
                { 17 /* snr */,    936  /* rate */ },
                { 20 /* snr */,    1404  /* rate */ },
                { 25 /* snr */,    1872  /* rate */ },
                { 27 /* snr */,    2106 /* rate */ },
                { 28 /* snr */,    2340 /* rate */ },
                { 32 /* snr */,    2808 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     234  /* rate */ },
                { 9 /* snr */,    468  /* rate */ },
                { 11 /* snr */,    702  /* rate */ },
                { 17 /* snr */,    936  /* rate */ },
                { 20 /* snr */,    1404  /* rate */ },
                { 25 /* snr */,    1872  /* rate */ },
                { 27 /* snr */,    2106 /* rate */ },
                { 28 /* snr */,    2340 /* rate */ },
                { 32 /* snr */,    2808 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     234  /* rate */ },
                { 9 /* snr */,    468  /* rate */ },
                { 11 /* snr */,    702  /* rate */ },
                { 17 /* snr */,    936  /* rate */ },
                { 20 /* snr */,    1404  /* rate */ },
                { 25 /* snr */,    1872  /* rate */ },
                { 27 /* snr */,    2106 /* rate */ },
                { 28 /* snr */,    2340 /* rate */ },
                { 32 /* snr */,    2808 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     234  /* rate */ },
                { 9 /* snr */,    468  /* rate */ },
                { 11 /* snr */,    702  /* rate */ },
                { 17 /* snr */,    936  /* rate */ },
                { 20 /* snr */,    1404  /* rate */ },
                { 25 /* snr */,    1872  /* rate */ },
                { 27 /* snr */,    2106 /* rate */ },
                { 28 /* snr */,    2340 /* rate */ },
                { 32 /* snr */,    2808 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 8 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     234  /* rate */ },
                { 9 /* snr */,    468  /* rate */ },
                { 11 /* snr */,    702  /* rate */ },
                { 17 /* snr */,    936  /* rate */ },
                { 20 /* snr */,    1404  /* rate */ },
                { 25 /* snr */,    1872  /* rate */ },
                { 27 /* snr */,    2106 /* rate */ },
                { 28 /* snr */,    2340 /* rate */ },
                { 32 /* snr */,    2808 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
    },

    // 802.11ax mode
    // =============
    {
        // 20 MHz - derived from 40 MHz by requiring 1 dB more SNR
        {
            // 1 spatial stream - derived from 4 NSS by subtracting 6 dB and
            // applying a ceiling to 1
            {
                { 3 /* snr */,     7   /* rate */ },
                { 4 /* snr */,     14  /* rate */ },
                { 5 /* snr */,     21  /* rate */ },
                { 8 /* snr */,     29  /* rate */ },
                { 11 /* snr */,    43  /* rate */ },
                { 16 /* snr */,    58  /* rate */ },
                { 17 /* snr */,    65  /* rate */ },
                { 18 /* snr */,    73  /* rate */ },
                { 23 /* snr */,    87  /* rate */ },
                { 24 /* snr */,    97  /* rate */ },
                { 28 /* snr */,    109 /* rate */ },
                { 30 /* snr */,    121 /* rate */ },
            },

            // 2 spatial streams - derived from 4 NSS by subtracting 3 dB
            {
                { 3 /* snr */,     14  /* rate */ },
                { 6 /* snr */,     29  /* rate */ },
                { 8 /* snr */,     43  /* rate */ },
                { 11 /* snr */,    58  /* rate */ },
                { 14 /* snr */,    87  /* rate */ },
                { 19 /* snr */,    117 /* rate */ },
                { 20 /* snr */,    131 /* rate */ },
                { 21 /* snr */,    146 /* rate */ },
                { 26 /* snr */,    175 /* rate */ },
                { 27 /* snr */,    195 /* rate */ },
                { 31 /* snr */,    219 /* rate */ },
                { 33 /* snr */,    243 /* rate */ },
            },

            // 3 spatial streams - derived from 4 NSS by subtracting 1 dB
            {
                { 5 /* snr */,     21  /* rate */ },
                { 8 /* snr */,     43  /* rate */ },
                { 10 /* snr */,    65  /* rate */ },
                { 13 /* snr */,    87  /* rate */ },
                { 16 /* snr */,    131 /* rate */ },
                { 21 /* snr */,    175 /* rate */ },
                { 22 /* snr */,    197 /* rate */ },
                { 23 /* snr */,    219 /* rate */ },
                { 28 /* snr */,    263 /* rate */ },
                { 29 /* snr */,    292 /* rate */ },
                { 33 /* snr */,    329 /* rate */ },
                { 35 /* snr */,    365 /* rate */ },
            },

            // 4 spatial streams
            {
                { 6 /* snr */,     29  /* rate */ },
                { 9 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 14 /* snr */,    117 /* rate */ },
                { 17 /* snr */,    175 /* rate */ },
                { 22 /* snr */,    234 /* rate */ },
                { 23 /* snr */,    263 /* rate */ },
                { 24 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
                { 34 /* snr */,    438 /* rate */ },
                { 36 /* snr */,    487 /* rate */ },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     29  /* rate */ },
                { 9 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 14 /* snr */,    117 /* rate */ },
                { 17 /* snr */,    175 /* rate */ },
                { 22 /* snr */,    234 /* rate */ },
                { 23 /* snr */,    263 /* rate */ },
                { 24 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
                { 34 /* snr */,    438 /* rate */ },
                { 36 /* snr */,    487 /* rate */ },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     29  /* rate */ },
                { 9 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 14 /* snr */,    117 /* rate */ },
                { 17 /* snr */,    175 /* rate */ },
                { 22 /* snr */,    234 /* rate */ },
                { 23 /* snr */,    263 /* rate */ },
                { 24 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
                { 34 /* snr */,    438 /* rate */ },
                { 36 /* snr */,    487 /* rate */ },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     29  /* rate */ },
                { 9 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 14 /* snr */,    117 /* rate */ },
                { 17 /* snr */,    175 /* rate */ },
                { 22 /* snr */,    234 /* rate */ },
                { 23 /* snr */,    263 /* rate */ },
                { 24 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
                { 34 /* snr */,    438 /* rate */ },
                { 36 /* snr */,    487 /* rate */ },
            },

            // 8 spatial streams
            {
                { 13 /* snr */,    58  /* rate */ },
                { 17 /* snr */,    117 /* rate */ },
                { 19 /* snr */,    175 /* rate */ },
                { 24 /* snr */,    234 /* rate */ },
                { 27 /* snr */,    351 /* rate */ },
                { 33 /* snr */,    468 /* rate */ },
                { 34 /* snr */,    526 /* rate */ },
                { 36 /* snr */,    585 /* rate */ },
                { 40 /* snr */,    702 /* rate */ },
                { 42 /* snr */,    780 /* rate */ },
                { 46 /* snr */,    877 /* rate */ },
                { 48 /* snr */,    975 /* rate */ },
            },
        },

        // 40 MHz - derived from 80 MHz by requiring 1 dB more SNR
        {
            // 1 spatial stream - derived from 4 NSS by subtracting 6 dB and
            // applying a ceiling to 1
            {
                { 2 /* snr */,     14  /* rate */ },
                { 3 /* snr */,     29  /* rate */ },
                { 4 /* snr */,     43  /* rate */ },
                { 7 /* snr */,     58  /* rate */ },
                { 10 /* snr */,    87  /* rate */ },
                { 15 /* snr */,    117 /* rate */ },
                { 16 /* snr */,    131 /* rate */ },
                { 17 /* snr */,    146 /* rate */ },
                { 22 /* snr */,    175 /* rate */ },
                { 23 /* snr */,    195 /* rate */ },
                { 27 /* snr */,    219 /* rate */ },
                { 29 /* snr */,    243 /* rate */ },
            },

            // 2 spatial streams - derived from 4 NSS by subtracting 3 dB
            {
                { 2 /* snr */,     29  /* rate */ },
                { 5 /* snr */,     58  /* rate */ },
                { 7 /* snr */,     87  /* rate */ },
                { 10 /* snr */,    117 /* rate */ },
                { 13 /* snr */,    175 /* rate */ },
                { 18 /* snr */,    234 /* rate */ },
                { 19 /* snr */,    263 /* rate */ },
                { 20 /* snr */,    292 /* rate */ },
                { 25 /* snr */,    351 /* rate */ },
                { 26 /* snr */,    390 /* rate */ },
                { 30 /* snr */,    438 /* rate */ },
                { 32 /* snr */,    487 /* rate */ },
            },

            // 3 spatial streams - derived from 4 NSS by subtracting 1 dB
            {
                { 4 /* snr */,     43  /* rate */ },
                { 7 /* snr */,     87  /* rate */ },
                { 9 /* snr */,     131 /* rate */ },
                { 12 /* snr */,    175 /* rate */ },
                { 15 /* snr */,    263 /* rate */ },
                { 20 /* snr */,    351 /* rate */ },
                { 21 /* snr */,    394 /* rate */ },
                { 22 /* snr */,    438 /* rate */ },
                { 27 /* snr */,    526 /* rate */ },
                { 28 /* snr */,    585 /* rate */ },
                { 32 /* snr */,    658 /* rate */ },
                { 34 /* snr */,    731 /* rate */ },
            },

            // 4 spatial streams
            {
                { 5 /* snr */,     58  /* rate */ },
                { 8 /* snr */,     117 /* rate */ },
                { 10 /* snr */,    175 /* rate */ },
                { 13 /* snr */,    234 /* rate */ },
                { 16 /* snr */,    351 /* rate */ },
                { 21 /* snr */,    468 /* rate */ },
                { 22 /* snr */,    526 /* rate */ },
                { 23 /* snr */,    585 /* rate */ },
                { 28 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    780 /* rate */ },
                { 33 /* snr */,    877 /* rate */ },
                { 35 /* snr */,    975 /* rate */ },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     58  /* rate */ },
                { 8 /* snr */,     117 /* rate */ },
                { 10 /* snr */,    175 /* rate */ },
                { 13 /* snr */,    234 /* rate */ },
                { 16 /* snr */,    351 /* rate */ },
                { 21 /* snr */,    468 /* rate */ },
                { 22 /* snr */,    526 /* rate */ },
                { 23 /* snr */,    585 /* rate */ },
                { 28 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    780 /* rate */ },
                { 33 /* snr */,    877 /* rate */ },
                { 35 /* snr */,    975 /* rate */ },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     58  /* rate */ },
                { 8 /* snr */,     117 /* rate */ },
                { 10 /* snr */,    175 /* rate */ },
                { 13 /* snr */,    234 /* rate */ },
                { 16 /* snr */,    351 /* rate */ },
                { 21 /* snr */,    468 /* rate */ },
                { 22 /* snr */,    526 /* rate */ },
                { 23 /* snr */,    585 /* rate */ },
                { 28 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    780 /* rate */ },
                { 33 /* snr */,    877 /* rate */ },
                { 35 /* snr */,    975 /* rate */ },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     58  /* rate */ },
                { 8 /* snr */,     117 /* rate */ },
                { 10 /* snr */,    175 /* rate */ },
                { 13 /* snr */,    234 /* rate */ },
                { 16 /* snr */,    351 /* rate */ },
                { 21 /* snr */,    468 /* rate */ },
                { 22 /* snr */,    526 /* rate */ },
                { 23 /* snr */,    585 /* rate */ },
                { 28 /* snr */,    702 /* rate */ },
                { 29 /* snr */,    780 /* rate */ },
                { 33 /* snr */,    877 /* rate */ },
                { 35 /* snr */,    975 /* rate */ },
            },

            // 8 spatial streams
            {
                { 12 /* snr */,    117  /* rate */ },
                { 16 /* snr */,    234  /* rate */ },
                { 18 /* snr */,    351  /* rate */ },
                { 23 /* snr */,    468  /* rate */ },
                { 26 /* snr */,    702  /* rate */ },
                { 32 /* snr */,    936  /* rate */ },
                { 33 /* snr */,    1053 /* rate */ },
                { 35 /* snr */,    1170 /* rate */ },
                { 39 /* snr */,    1404 /* rate */ },
                { 41 /* snr */,    1560 /* rate */ },
                { 45 /* snr */,    1755 /* rate */ },
                { 47 /* snr */,    1950 /* rate */ },
            },
        },

        // 80 MHz
        {
            // 1 spatial stream - derived from 4 NSS by subtracting 6 dB and
            // applying a ceiling to 1
            {
                { 1 /* snr */,     30  /* rate */ },
                { 2 /* snr */,     61  /* rate */ },
                { 3 /* snr */,     91  /* rate */ },
                { 6 /* snr */,     122 /* rate */ },
                { 9 /* snr */,     183 /* rate */ },
                { 14 /* snr */,    245 /* rate */ },
                { 15 /* snr */,    275 /* rate */ },
                { 16 /* snr */,    306 /* rate */ },
                { 21 /* snr */,    367 /* rate */ },
                { 22 /* snr */,    408 /* rate */ },
                { 26 /* snr */,    459 /* rate */ },
                { 28 /* snr */,    510 /* rate */ },
            },

            // 2 spatial streams - derived from 4 NSS by subtracting 3 dB
            {
                { 1 /* snr */,     61   /* rate */ },
                { 4 /* snr */,     122  /* rate */ },
                { 6 /* snr */,     183  /* rate */ },
                { 9 /* snr */,     245  /* rate */ },
                { 12 /* snr */,    367  /* rate */ },
                { 17 /* snr */,    490  /* rate */ },
                { 18 /* snr */,    551  /* rate */ },
                { 19 /* snr */,    612  /* rate */ },
                { 24 /* snr */,    735  /* rate */ },
                { 25 /* snr */,    816  /* rate */ },
                { 29 /* snr */,    918  /* rate */ },
                { 31 /* snr */,    1020 /* rate */ },
            },

            // 3 spatial streams - derived from 4 NSS by subtracting 1 dB
            {
                { 3 /* snr */,     91   /* rate */ },
                { 6 /* snr */,     183  /* rate */ },
                { 8 /* snr */,     275  /* rate */ },
                { 11 /* snr */,    367  /* rate */ },
                { 14 /* snr */,    551  /* rate */ },
                { 19 /* snr */,    735  /* rate */ },
                { 20 /* snr */,    826  /* rate */ },
                { 21 /* snr */,    918  /* rate */ },
                { 26 /* snr */,    1102 /* rate */ },
                { 27 /* snr */,    1225 /* rate */ },
                { 31 /* snr */,    1378 /* rate */ },
                { 33 /* snr */,    1531 /* rate */ },
            },

            // 4 spatial streams
            {
                { 4 /* snr */,     122  /* rate */ },
                { 7 /* snr */,     245  /* rate */ },
                { 9 /* snr */,     367  /* rate */ },
                { 12 /* snr */,    490  /* rate */ },
                { 15 /* snr */,    735  /* rate */ },
                { 20 /* snr */,    980  /* rate */ },
                { 21 /* snr */,    1102 /* rate */ },
                { 22 /* snr */,    1225 /* rate */ },
                { 27 /* snr */,    1470 /* rate */ },
                { 28 /* snr */,    1633 /* rate */ },
                { 32 /* snr */,    1837 /* rate */ },
                { 34 /* snr */,    2041 /* rate */ },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     122  /* rate */ },
                { 7 /* snr */,     245  /* rate */ },
                { 9 /* snr */,     367  /* rate */ },
                { 12 /* snr */,    490  /* rate */ },
                { 15 /* snr */,    735  /* rate */ },
                { 20 /* snr */,    980  /* rate */ },
                { 21 /* snr */,    1102 /* rate */ },
                { 22 /* snr */,    1225 /* rate */ },
                { 27 /* snr */,    1470 /* rate */ },
                { 28 /* snr */,    1633 /* rate */ },
                { 32 /* snr */,    1837 /* rate */ },
                { 34 /* snr */,    2041 /* rate */ },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     122  /* rate */ },
                { 7 /* snr */,     245  /* rate */ },
                { 9 /* snr */,     367  /* rate */ },
                { 12 /* snr */,    490  /* rate */ },
                { 15 /* snr */,    735  /* rate */ },
                { 20 /* snr */,    980  /* rate */ },
                { 21 /* snr */,    1102 /* rate */ },
                { 22 /* snr */,    1225 /* rate */ },
                { 27 /* snr */,    1470 /* rate */ },
                { 28 /* snr */,    1633 /* rate */ },
                { 32 /* snr */,    1837 /* rate */ },
                { 34 /* snr */,    2041 /* rate */ },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 4 /* snr */,     122  /* rate */ },
                { 7 /* snr */,     245  /* rate */ },
                { 9 /* snr */,     367  /* rate */ },
                { 12 /* snr */,    490  /* rate */ },
                { 15 /* snr */,    735  /* rate */ },
                { 20 /* snr */,    980  /* rate */ },
                { 21 /* snr */,    1102 /* rate */ },
                { 22 /* snr */,    1225 /* rate */ },
                { 27 /* snr */,    1470 /* rate */ },
                { 28 /* snr */,    1633 /* rate */ },
                { 32 /* snr */,    1837 /* rate */ },
                { 34 /* snr */,    2041 /* rate */ },
            },

            // 8 spatial streams
            {
                { 11 /* snr */,    245  /* rate */ },
                { 15 /* snr */,    490  /* rate */ },
                { 17 /* snr */,    735  /* rate */ },
                { 22 /* snr */,    980  /* rate */ },
                { 25 /* snr */,    1470 /* rate */ },
                { 31 /* snr */,    1960 /* rate */ },
                { 32 /* snr */,    2205 /* rate */ },
                { 34 /* snr */,    2450 /* rate */ },
                { 38 /* snr */,    2940 /* rate */ },
                { 40 /* snr */,    3266 /* rate */ },
                { 44 /* snr */,    3675 /* rate */ },
                { 46 /* snr */,    4083 /* rate */ },
            },
        },

        // 160 MHz - assumed to require one less dB of SNR than 80 MHz
        {
            // 1 spatial stream - derived from 4 NSS by subtracting 6 dB and
            // applying a ceiling to 1
            {
                { 1 /* snr */,     61   /* rate */ },
                { 2 /* snr */,     122  /* rate */ },
                { 3 /* snr */,     183  /* rate */ },
                { 5 /* snr */,     245  /* rate */ },
                { 8 /* snr */,     367  /* rate */ },
                { 13 /* snr */,    490  /* rate */ },
                { 14 /* snr */,    551  /* rate */ },
                { 15 /* snr */,    612  /* rate */ },
                { 20 /* snr */,    735  /* rate */ },
                { 21 /* snr */,    816  /* rate */ },
                { 25 /* snr */,    918  /* rate */ },
                { 27 /* snr */,    1020 /* rate */ },
            },

            // 2 spatial streams - derived from 4 NSS by subtracting 3 dB and
            // applying a ceiling to 1
            {
                { 1 /* snr */,     122  /* rate */ },
                { 3 /* snr */,     245  /* rate */ },
                { 5 /* snr */,     367  /* rate */ },
                { 10 /* snr */,    490  /* rate */ },
                { 11 /* snr */,    735  /* rate */ },
                { 16 /* snr */,    980  /* rate */ },
                { 17 /* snr */,    1102 /* rate */ },
                { 18 /* snr */,    1225 /* rate */ },
                { 23 /* snr */,    1470 /* rate */ },
                { 24 /* snr */,    1633 /* rate */ },
                { 28 /* snr */,    1837 /* rate */ },
                { 30 /* snr */,    2041 /* rate */ },
            },

            // 3 spatial streams - derived from 4 NSS by subtracting 1 dB
            {
                { 2 /* snr */,     183  /* rate */ },
                { 5 /* snr */,     367  /* rate */ },
                { 7 /* snr */,     551  /* rate */ },
                { 10 /* snr */,    735  /* rate */ },
                { 13 /* snr */,    1102 /* rate */ },
                { 18 /* snr */,    1470 /* rate */ },
                { 19 /* snr */,    1653 /* rate */ },
                { 20 /* snr */,    1837 /* rate */ },
                { 25 /* snr */,    2205 /* rate */ },
                { 26 /* snr */,    2450 /* rate */ },
                { 30 /* snr */,    2756 /* rate */ },
                { 32 /* snr */,    3402 /* rate */ },
            },

            // 4 spatial streams
            {
                { 3 /* snr */,     245  /* rate */ },
                { 6 /* snr */,     490  /* rate */ },
                { 8 /* snr */,     735  /* rate */ },
                { 11 /* snr */,    980  /* rate */ },
                { 14 /* snr */,    1470 /* rate */ },
                { 19 /* snr */,    1960 /* rate */ },
                { 20 /* snr */,    2205 /* rate */ },
                { 21 /* snr */,    2450 /* rate */ },
                { 26 /* snr */,    2940 /* rate */ },
                { 27 /* snr */,    3266 /* rate */ },
                { 31 /* snr */,    3675 /* rate */ },
                { 33 /* snr */,    4083 /* rate */ },
            },

            // 5 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 3 /* snr */,     245  /* rate */ },
                { 6 /* snr */,     490  /* rate */ },
                { 8 /* snr */,     735  /* rate */ },
                { 11 /* snr */,    980  /* rate */ },
                { 14 /* snr */,    1470 /* rate */ },
                { 19 /* snr */,    1960 /* rate */ },
                { 20 /* snr */,    2205 /* rate */ },
                { 21 /* snr */,    2450 /* rate */ },
                { 26 /* snr */,    2940 /* rate */ },
                { 27 /* snr */,    3266 /* rate */ },
                { 31 /* snr */,    3675 /* rate */ },
                { 33 /* snr */,    4083 /* rate */ },
            },

            // 6 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 3 /* snr */,     245  /* rate */ },
                { 6 /* snr */,     490  /* rate */ },
                { 8 /* snr */,     735  /* rate */ },
                { 11 /* snr */,    980  /* rate */ },
                { 14 /* snr */,    1470 /* rate */ },
                { 19 /* snr */,    1960 /* rate */ },
                { 20 /* snr */,    2205 /* rate */ },
                { 21 /* snr */,    2450 /* rate */ },
                { 26 /* snr */,    2940 /* rate */ },
                { 27 /* snr */,    3266 /* rate */ },
                { 31 /* snr */,    3675 /* rate */ },
                { 33 /* snr */,    4083 /* rate */ },
            },

            // 7 spatial streams - assumed to be the same as 4 NSS due to no
            // data available at this time
            {
                { 3 /* snr */,     245  /* rate */ },
                { 6 /* snr */,     490  /* rate */ },
                { 8 /* snr */,     735  /* rate */ },
                { 11 /* snr */,    980  /* rate */ },
                { 14 /* snr */,    1470 /* rate */ },
                { 19 /* snr */,    1960 /* rate */ },
                { 20 /* snr */,    2205 /* rate */ },
                { 21 /* snr */,    2450 /* rate */ },
                { 26 /* snr */,    2940 /* rate */ },
                { 27 /* snr */,    3266 /* rate */ },
                { 31 /* snr */,    3675 /* rate */ },
                { 33 /* snr */,    4083 /* rate */ },
            },

            // 8 spatial streams
            {
                { 11 /* snr */,    490  /* rate */ },
                { 15 /* snr */,    980  /* rate */ },
                { 17 /* snr */,    1470 /* rate */ },
                { 22 /* snr */,    1960 /* rate */ },
                { 25 /* snr */,    2940 /* rate */ },
                { 31 /* snr */,    3920 /* rate */ },
                { 32 /* snr */,    4410 /* rate */ },
                { 34 /* snr */,    4900 /* rate */ },
                { 38 /* snr */,    5880 /* rate */ },
                { 40 /* snr */,    6533 /* rate */ },
                { 44 /* snr */,    7350 /* rate */ },
                { 46 /* snr */,    8166 /* rate */ },
            },
        },
    }
};

lbd_linkCapacity_t estimatorSNRToPhyRateTablePerformLookup(
        struct dbgModule *dbgModule,
        wlanif_phymode_e phyMode, wlanif_chwidth_e chwidth,
        u_int8_t numSpatialStreams, u_int8_t maxMCSIndex, lbd_snr_t snr) {
    // These are preconditions that should have already been ensured
    // by the rest of lbd.
    lbDbgAssertExit(dbgModule, phyMode < wlanif_phymode_invalid);
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    lbDbgAssertExit(dbgModule, numSpatialStreams <= ESTIMATOR_MAX_NSS);
    lbDbgAssertExit(dbgModule, numSpatialStreams >= ESTIMATOR_MIN_NSS);

    const estimatorSNRToPhyRateEntry_t *entries =
        estimatorSNRToPhyRateTable[phyMode][chwidth][numSpatialStreams - 1];

    // Although this could be done with a binary search, for the small
    // size of this array, it is not likely worth the complexity. Thus,
    // we search through the array until we find an entry whose SNR is
    // larger than the client one. The entry right before this is the
    // one to use.
    size_t i;
    for (i = 0; i < ESTIMATOR_MAX_RATES && i <= maxMCSIndex; ++i) {
        if (snr < entries[i].snr) {
            break;
        }
    }

    if (0 == i) {
        return entries[i].phyRate;
    } else {
        return entries[i - 1].phyRate;
    }
}

lbd_snr_t estimatorSNRToPhyRateTablePerformReverseLookup(
        struct dbgModule *dbgModule, wlanif_phymode_e phyMode,
        wlanif_chwidth_e chwidth, u_int8_t numSpatialStreams,
        u_int8_t maxMCSIndex, lbd_linkCapacity_t phyRate) {
    // These are preconditions that should have already been ensured
    // by the rest of lbd.
    lbDbgAssertExit(dbgModule, phyMode < wlanif_phymode_invalid);
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    lbDbgAssertExit(dbgModule, numSpatialStreams <= ESTIMATOR_MAX_NSS);

    const estimatorSNRToPhyRateEntry_t *entries =
        estimatorSNRToPhyRateTable[phyMode][chwidth][numSpatialStreams - 1];

    size_t i;
    for (i = 0; i < ESTIMATOR_MAX_RATES && i <= maxMCSIndex; ++i) {
        if (entries[i].phyRate == LBD_INVALID_LINK_CAP ||
            phyRate < entries[i].phyRate) {
            break;
        }
    }

    if (0 == i) {
        return entries[i].phyRate == LBD_INVALID_LINK_CAP ? LBD_INVALID_SNR : entries[i].snr;
    } else {
        return entries[i - 1].snr;
    }
}
