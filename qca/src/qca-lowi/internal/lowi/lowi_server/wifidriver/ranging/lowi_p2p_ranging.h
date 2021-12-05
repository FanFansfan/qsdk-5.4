#ifndef __LOWI_P2P_RANGING_H
#define __LOWI_P2P_RANGING_H
/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
GENERAL DESCRIPTION
   This file contains functions that are used to exercise rtt ranging in p2p mode

   Copyright (c) 2014-2016,2018 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include "rttm.h"
#include "lowi_ranging.h"

/* RTT capability types */
typedef enum p2p_peer_cap_s {
   P2P_PEER_CAP_RTT2 = 0,
   P2P_PEER_CAP_RTT3 = 1,
   P2P_PEER_CAP_UNDEF = 2
} p2p_peer_cap_t;

/*=============================================================================================
 * p2pGetNumPeersConnected
 *
 * Description:
 *   Returns the number of currently connected p2p peers
 *
 * Parameters:
 *   none
 * Return value:
 *   number of currently connected p2p peers
 =============================================================================================*/
tANI_U16 p2pGetNumPeersConnected();

/*=============================================================================================
 * p2pStoreStatusInfo
 *
 * Description:
 *   Stores p2p peer status information when p2p status event occurs
 *   and store the mPeerInfo only when it is STA peer mode.
 *
 * Parameters:
 *   rxBuff   - ptr to msg containing peer info
 *   peerInfo - ptr to msg for STA peer info, it will be copied
 *              to mPeerInfo in lowiRanging
 *
 * Return value:
 *   -1: error, 0: ok
 =============================================================================================*/
tANI_S8 p2pStoreStatusInfo(char* rxBuff, ani_peer_status_info* peerInfo);

/*=============================================================================================
 * p2pBssidDetected
 *
 * Description:
 *   checks whether mac address of peer is already stored
 *
 * Parameters:
 *   numBssids - number of BSSIDs to check
 *   bssidsToScan - array of BSSIDs to check
 *   channelInfoPtr - ptr to channel information used for RTT request
 *   vDev - ptr to vdev ID to be used in the RTT request
 * Return value:
 *   FALSE: peer not stored, TRUE: peer is stored in table
 =============================================================================================*/
boolean p2pBssidDetected(tANI_U32 numBssids, DestInfo* bssidsToScan, wmi_channel* channelInfoPtr, tANI_U8* vDev);

/*=============================================================================================
 * p2pIsStored
 *
 * Description:
 *   checks whether mac address of peer is already stored.
 *
 * Parameters:
 *   addr1 - Mac address #1
 *   k - placeholder for index where peer is stored to be passed to caller
 * Return value:
 *   FALSE: peer not stored, TRUE: peer is stored in table array
 =============================================================================================*/
boolean p2pIsStored(tANI_U8* addr1, tANI_U16* k);
#endif /* __LOWI_P2P_RANGING_H */

