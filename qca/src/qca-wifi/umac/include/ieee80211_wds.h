/*
 * Copyright (c) 2011,2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 */

#ifndef IEEE80211_WDS_H
#define IEEE80211_WDS_H

#include <if_upperproto.h>
#include <ieee80211_var.h>
#include <ieee80211_node.h>

#if (MESH_MODE_SUPPORT||ATH_SUPPORT_NAC)

#define MESH_CAPS_VER1 0x8000
#define MESH_CAPS_BW_OFFSET 0
#define MESH_CAPS_NSS_OFFSET 4
#define MESH_CAPS_MODE_OFFSET 8
#define MESH_CAPS_NIBBLE_MASK 0xF
#define MESH_CAPS_MAX_NSS 8
#define MESH_CAPS_SHORT_SLOT 0x1000
#define MESH_CAPS_SHORT_PREAMBLE 0x2000
typedef enum {
    MESH_PREAMBLE_OFDM,
    MESH_PREAMBLE_CCK,
    MESH_PREAMBLE_HT ,
    MESH_PREAMBLE_VHT,
    MESH_PREAMBLE_HE,
    MESH_PREAMBLE_MAX,
} localpeer_preamble_type_t;

typedef enum {
    MESH_BW_20,
    MESH_BW_40,
    MESH_BW_80,
    MESH_BW_80_80,
    MESH_BW_160,
    MESH_BW_MAX,
} localpeer_bw_type_t;

#endif

void
ieee80211_wds_attach(struct ieee80211_node_table *nt);
void
ieee80211_wds_detach(struct ieee80211_node_table *nt);

/* Add wds address to the node table */
int
ieee80211_add_wds_addr(wlan_if_t vaphandle,
                       struct ieee80211_node_table *nt,
		       struct ieee80211_node *ni, const u_int8_t *macaddr,
		       u_int32_t flags);

/* remove wds address from the wds hash table */
void
ieee80211_remove_wds_addr(wlan_if_t vaphandle,
                          struct ieee80211_node_table *nt,
			  const u_int8_t *macaddr,u_int32_t flags);
/* Remove node references from wds table */
void
ieee80211_del_wds_node(struct ieee80211_node_table *nt,
                      struct ieee80211_node *ni);

/* Remove all the wds entries associated with the AP when the AP to
 * which STA is associated goes down
 */
int ieee80211_node_removeall_wds (struct ieee80211_node_table *nt,struct ieee80211_node *ni);

struct ieee80211_node *
ieee80211_find_wds_node(struct ieee80211_node_table *nt, const u_int8_t *macaddr, wlan_objmgr_ref_dbgid id);
void wds_clear_wds_table(struct ieee80211_node * ni, struct ieee80211_node_table *nt, wbuf_t wbuf );

/* Function to check if the packet has to be sent as 4 addr packet
 * Takes as input ni, wbuf and returns 1 if 4 address is required
 * returns 0 if 4 address is not required
 */

static INLINE int
wds_is4addr(struct ieee80211vap * vap, struct ether_header eh , struct ieee80211_node *ni)
{
    /*
     * Removing the below check, to force all frames to WDS STA as 4-addr
     *     !(IEEE80211_ADDR_EQ(eh.ether_dhost, macaddr)))
     * This is done to WAR a HW issue, where encryption fails if 4-addr and 3-addr
     * frames are mixed in an AMPDU
     */
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
        (ni->ni_flags & IEEE80211_NODE_WDS))
        {
            return 1;
        }
    else
        {
            return 0;
        }
}

#if UMAC_SUPPORT_NAWDS
void ieee80211_nawds_attach(struct ieee80211vap *vap);
int ieee80211_nawds_send_wbuf(struct ieee80211vap *vap, wbuf_t wbuf);
int ieee80211_nawds_disable_beacon(struct ieee80211vap *vap);
int ieee80211_nawds_enable_learning(struct ieee80211vap *vap);
void ieee80211_nawds_learn(struct ieee80211vap *vap, u_int8_t *mac);
#ifndef ATH_HTC_MII_RXIN_TASKLET
#define IEEE80211_NAWDS_LEARN(_vap, _mac) ieee80211_nawds_learn(_vap, _mac)
#else
void ieee80211_nawds_learn_defer(struct ieee80211vap *vap, u_int8_t *mac);
#define IEEE80211_NAWDS_LEARN(_vap, _mac) ieee80211_nawds_learn_defer(_vap, _mac)
#endif

#else
static INLINE void ieee80211_nawds_attach(struct ieee80211vap *vap) 
{
    /* do nothing */
};
static INLINE int ieee80211_nawds_send_wbuf(struct ieee80211vap *vap, wbuf_t wbuf)
{
    /* do nothing */
    return 0;
}

static INLINE int ieee80211_nawds_disable_beacon(struct ieee80211vap *vap)
{
    /* do nothing */
    return 0;
}

static INLINE int ieee80211_nawds_enable_learning(struct ieee80211vap *vap)
{
    /* do nothing */
    return 0;
}

static INLINE void ieee80211_nawds_learn(struct ieee80211vap *vap, u_int8_t *mac)
{
    /* do nothing */
}

#endif

#endif //IEEE80211_WDS_H
