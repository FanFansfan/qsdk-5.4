/*
 *
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2009 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file contains the main implementation of the multicast
 * enhancement functionality.
 *
 * The main purpose of this module is to convert (by translating or
 * tunneling) the multicast stream into duplicated unicast streams for
 * performance enhancement of home wireless applications. For more
 * details, please refer to the design documentation.
 *
 */
#include <qdf_nbuf.h>
#include <qdf_module.h>
#include <cdp_txrx_cmn_struct.h>
#include <htt_common.h>
#if ATH_SUPPORT_IQUE
#include "osdep.h"
#include "wbuf.h"
#include "dp_me.h"
#include "dp_txrx.h"
#include "cdp_txrx_me.h"
#include "cdp_txrx_host_stats.h"

static int dp_me_igmp_mld_inspect(struct cdp_soc_t *soc, uint8_t pdev_id,
				  qdf_nbuf_t wbuf, u_int8_t *type,
				  void *group, u_int8_t *hmmc_found, u_int8_t *deny_list);

void dp_pdev_me_setup(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	dp_txrx_pdev_handle_t *dp_hdl;
	dp_pdev_me_t *pdev_me_hdl;

	dp_hdl = cdp_pdev_get_dp_txrx_handle(soc, pdev_id);

	if (!dp_hdl)
		return;

	pdev_me_hdl = &dp_hdl->pdev_me_hdl;

	pdev_me_hdl->pdev_deny_list_cnt= 3;
	pdev_me_hdl->pdev_denylist[0].ip = be32toh(0xeffffffa); /* 239.255.255.250 */
	pdev_me_hdl->pdev_denylist[0].mask = 0xffffffff;
	pdev_me_hdl->pdev_denylist[1].ip = be32toh(0xe00000fb); /* 224.0.0.251 */
	pdev_me_hdl->pdev_denylist[1].mask = 0xffffffff;
	pdev_me_hdl->pdev_denylist[2].ip = be32toh(0xe00000fc); /* 224.0.0.252 */
	pdev_me_hdl->pdev_denylist[2].mask = 0xffffffff;

	pdev_me_hdl->pdev_hmmc_cnt = 0;
}
qdf_export_symbol(dp_pdev_me_setup);

/*
 * dp_me_find_next_hop_mac:
 * Find the receiver's address (RA) for a multicast group member given
 * it's destination address (DA) from the MCS snoop table.
 *
 * Parameters:
 * @soc: soc txrx handle
 * @vdev_me: vdev ME handle
 * @pdev_id: pdev id
 *
 * Returns:
 * Nothing
 */
void dp_me_find_next_hop_mac(struct cdp_soc_t *soc, dp_vdev_me_t *vdev_me,
			     uint8_t pdev_id )
{
	struct cdp_ast_entry_info ast_entry_info;
	uint32_t group_ix, group_cnt;
	uint32_t node_ix, node_ix2, node_cnt;

	/* Resolving the RA, if there is any failure, the destination
	 * MAC address will be used. This is done for each node of each
	 * group address */
	group_cnt = vdev_me->me_mcast_table.entry_cnt;
	for (group_ix = 0; group_ix < group_cnt; group_ix++) {
		node_cnt = vdev_me->me_mcast_table.entry[group_ix].node_cnt;
		for (node_ix = 0; node_ix < node_cnt; node_ix++) {
			vdev_me->me_ra[group_ix][node_ix].dup = 0;
			if (cdp_peer_get_ast_info_by_pdev(soc, vdev_me->me_mcast_table.entry[group_ix].nodes[node_ix].mac,
							  pdev_id, &ast_entry_info)) {
				WLAN_ADDR_COPY(vdev_me->me_ra[group_ix][node_ix].mac,
					       ast_entry_info.peer_mac_addr);
			} else {
				/* If AST entry is not found, then the destination address is
				 * copied to the receiver's address table */
				WLAN_ADDR_COPY(vdev_me->me_ra[group_ix][node_ix].mac,
					       vdev_me->me_mcast_table.entry[group_ix].nodes[node_ix].mac);
			}

			/* If there are members with the same next-hop, subsequent members
			 * are ignored */
			for (node_ix2 = 0; node_ix2 < node_ix; node_ix2++) {
				if((WLAN_ADDR_EQ(vdev_me->me_ra[group_ix][node_ix].mac,
						 vdev_me->me_ra[group_ix][node_ix2].mac) == 0)) {
					vdev_me->me_ra[group_ix][node_ix].dup = 1;
					break;
				}
			}
		}
	}
}

void
dp_me_update_mcast_table(ol_txrx_soc_handle soc, uint8_t vdev_id,
			 uint8_t pdev_id, void *data, uint32_t msglen,
			 uint16_t hdrlen)
{
	dp_vdev_me_t *vdev_me;
	dp_pdev_me_t *pdev_me_hdl;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return;

	vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

	if (!vdev_me)
		return;

	if (msglen <= hdrlen) {
		vdev_me->me_mcast_table.entry_cnt = 0;
	} else {
		unsigned int mcast_table_size = sizeof(vdev_me->me_mcast_table);

		if (msglen - hdrlen < mcast_table_size)
			mcast_table_size = msglen - hdrlen;

		qdf_mem_copy(&vdev_me->me_mcast_table, data,
			     mcast_table_size);

		/* Populating the RA table for each group*/
		dp_me_find_next_hop_mac(soc, vdev_me, pdev_id);
	}

}

#ifdef QCA_OL_DMS_WAR

static int dp_get_tid_from_iptos(qdf_nbuf_t msdu)
{
#define TID_MASK 0x7
	struct ether_header *eh;
	uint16_t ether_type;
	uint8_t tos = 0, dscp_tid_override = 0, tid = CDP_INVALID_TID;

	eh = (struct ether_header *) qdf_nbuf_data(msdu);
	ether_type = eh->ether_type;

	/*
	 * Multicast enhancement can only be done for IPv4, IPv6 frames.
	 * Not adding cases for ARP, EAPOL because of this reason.
	 * Vlan check is not required either.
	 */
	if (ether_type == __constant_htons(ETHERTYPE_IP))
	{
		struct iphdr *ip = (struct iphdr *)((uint8_t *)eh +
				    sizeof(qdf_ether_header_t));
		/*
		 * Save ip tos/tid/dscp
		 */
		tos = ip->tos;
		dscp_tid_override = 1;
	} else if ((ether_type == htons(ETHERTYPE_IPV6))) {
		/*
		 * use flowlabel
		 */
		unsigned long ver_pri_flowlabel;
		unsigned long pri;
		ver_pri_flowlabel = *(unsigned long *)(eh + 1);
		pri = (ntohl(ver_pri_flowlabel) & IPV6_PRIORITY_MASK) >> IPV6_PRIORITY_SHIFT;
		tos = pri;
		dscp_tid_override = 1;
	}

	if (dscp_tid_override) {
		tos = (tos & (~0x3)) >> IP_PRI_SHIFT;
		tid = (tos & TID_MASK);
	}

	return tid;
}

static int
transcap_8023_to_nwifi(struct cdp_soc_t *soc, qdf_nbuf_t msdu,
		       uint8_t *peer_addr, uint8_t *macaddr)
{
	struct ieee80211_frame *wh;
	struct ether_header eth_hdr, *eh;
	uint16_t typeorlen, length;
	struct llc *llcHdr;

	qdf_assert(msdu != NULL);

	if (qdf_nbuf_headroom(msdu) < sizeof(*wh) + sizeof(*llcHdr))
	{
		dp_me_info("%pK: DMS encap: Don't have enough headroom", soc);
		return 1;
	}

	eh = (struct ether_header *) qdf_nbuf_data(msdu);
	/*
	 * Save addresses to be inserted later
	 */
	WLAN_ADDR_COPY(eth_hdr.ether_dhost, eh->ether_dhost);
	WLAN_ADDR_COPY(eth_hdr.ether_shost, eh->ether_shost);
	typeorlen = eh->ether_type;

	length = qdf_nbuf_len(msdu);

	/*
	 * Make room for nwifi header for DMS
	 */
	if (qdf_nbuf_push_head(msdu, sizeof(*wh) + sizeof(*llcHdr)) == NULL) {
		dp_me_info("%pK: Encap: Failed to push nwifi and LLC header for DMS"
			   , soc);
		return 1;
	}

	/* Set ftype to DMS - Will be used to perform DP operations later */
	qdf_nbuf_set_tx_fctx_type(msdu, (void *) 0, CB_FTYPE_DMS);
	wh = (struct ieee80211_frame *) qdf_nbuf_data(msdu);
	WLAN_ADDR_COPY(wh->i_addr1, peer_addr);
	WLAN_ADDR_COPY(wh->i_addr2, macaddr);
	WLAN_ADDR_COPY(wh->i_addr3, eth_hdr.ether_shost);
	wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
	wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
	wh->i_fc[0] |= (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA);

	eh = (struct ether_header *)((uint8_t *)wh + sizeof(*wh));
	WLAN_ADDR_COPY(eh->ether_dhost, eth_hdr.ether_dhost);
	WLAN_ADDR_COPY(eh->ether_shost, eth_hdr.ether_shost);
	eh->ether_type = htons(length - sizeof(eth_hdr) + sizeof(*llcHdr));

	llcHdr = (struct llc *)((uint8_t *)eh + sizeof(eth_hdr));
	llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
	llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
	llcHdr->llc_un.type_snap.control     = LLC_UI;
	llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
	llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
	llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
	llcHdr->llc_un.type_snap.ether_type  = typeorlen;

	return 0;
}

int
dp_dms_amsdu_war(struct cdp_soc_t *soc, struct sk_buff **skb,
		 uint8_t *peer_addr,
		 struct cdp_tx_exception_metadata *tx_exc_param,
		 uint8_t *macaddr, uint8_t desired_tid)
{
	uint8_t tid;
	tid = dp_get_tid_from_iptos(*skb);
	if (transcap_8023_to_nwifi(soc, *skb, peer_addr, macaddr)) {
		return 1;
	}

	tx_exc_param->tid = desired_tid == HTT_INVALID_TID ? tid : desired_tid;
	tx_exc_param->peer_id = CDP_INVALID_PEER;
	tx_exc_param->tx_encap_type = htt_cmn_pkt_type_native_wifi;
	tx_exc_param->sec_type = cdp_sec_type_none;

	return 0;
}
qdf_export_symbol(dp_dms_amsdu_war);

/*
 * dp_me_convert_amsdu_ucast:
 * Encapsulates an 802.11 header on the 802.3 frame and sends the resulting
 * buffer to the firmware to enable the AMSDU aggregation.
 *
 * Parameters:
 * @soc: soc txrx handle
 * @vdev_id: Handle to vap pointer
 * @wbuf: Frame buffer containing the 802.3 frame
 * @mcast_grp_mac: List of MAC address of the members of the multicast group
 * @mcast_grp_mac_cnt: Total number of members in the multicast group
 * @macaddr: vdev MAC adderss
 * @tid: desired tid
 * @is_igmp: falg to indicate if the packet is igmp packet
 *
 * Return:
 * Total Number of successful unicast conversions
 */

uint16_t dp_me_convert_amsdu_ucast(struct cdp_soc_t *soc,
				   uint8_t vdev_id,
				   qdf_nbuf_t wbuf,
				   uint8_t mcast_grp_mac[][QDF_MAC_ADDR_SIZE],
				   uint8_t mcast_grp_mac_cnt,
				   uint8_t *macaddr, uint8_t tid, bool is_igmp)
{
	uint8_t total_mcast_grp_mac = mcast_grp_mac_cnt;
	struct cdp_tx_exception_metadata tx_exc_param = {0};
	struct cdp_tx_ingress_stats stats = {0};
	qdf_nbuf_t wbuf_copy = NULL;

	while(mcast_grp_mac_cnt > 0 && mcast_grp_mac_cnt--) {
		if (mcast_grp_mac_cnt > 0) {
			wbuf_copy = qdf_nbuf_copy(wbuf);
			if (wbuf_copy == NULL) {
				qdf_nbuf_free(wbuf);
				stats.mcast_en.fail_seg_alloc++;
				return (total_mcast_grp_mac - (mcast_grp_mac_cnt+1));
			}
		} else {
			wbuf_copy = wbuf;
		}
		wbuf_copy->next = NULL;

		if (dp_dms_amsdu_war(soc, &wbuf_copy,
				     mcast_grp_mac[mcast_grp_mac_cnt],
				     &tx_exc_param, macaddr, tid)) {
			dp_me_err("%pK: Unable to convert to native wifi packet",
				  soc);
			qdf_nbuf_free(wbuf_copy);
			stats.mcast_en.dropped_map_error++;
			return (total_mcast_grp_mac - (mcast_grp_mac_cnt+1));
		}

		/* Successful conversion to ucast */
		if (is_igmp)
			stats.igmp_mcast_en.igmp_ucast_converted++;
		else
			stats.mcast_en.ucast++;

		wbuf_copy = cdp_tx_send_exc(soc, vdev_id, wbuf_copy, &tx_exc_param);

		if (wbuf_copy != NULL) {
			qdf_nbuf_free(wbuf_copy);
			stats.mcast_en.dropped_send_fail++;
		}
	}

	/* Updating stats */
	cdp_update_vdev_host_stats(soc, vdev_id, &stats, DP_VDEV_STATS_TX_ME);
	return (total_mcast_grp_mac - mcast_grp_mac_cnt);
}
#endif

static inline bool igmp_query_check (uint8_t igmp_pkt)
{

	switch (igmp_pkt){
		case IGMP_QUERY :
		case MLD_QUERY :
		case IGMPv1_REPORT:
		case IGMPv2_REPORT:
		case IGMP_LEAVE :
		case IGMPv3_REPORT :
		case MLD_REPORT :
		case MLD_LEAVE:
		case MLDv2_REPORT :
			return true ;
		default:
			return false;
	}

}

uint16_t
dp_me_convert_ucast(struct cdp_soc_t *soc, uint8_t vdev_id,
		    qdf_nbuf_t wbuf, u_int8_t newmac[][QDF_MAC_ADDR_SIZE],
		    uint8_t new_mac_cnt, uint8_t me_mode, u_int8_t *macaddr,
		    uint8_t tid, bool is_igmp)
{
#ifdef QCA_OL_DMS_WAR
	if (me_mode == MC_AMSDU_ENABLE)
		return dp_me_convert_amsdu_ucast(soc, vdev_id, wbuf, newmac,
						 new_mac_cnt, macaddr, tid,
						 is_igmp);
	else
#endif
	{
		return cdp_tx_me_convert_ucast(soc,
					       vdev_id, wbuf,
					       newmac, new_mac_cnt, tid,
					       is_igmp);
	}
}

static struct dp_me_mcast_entry *dp_me_mcast_find_entry(
		struct dp_me_mcast_group *group,
		int *group_ix,
		struct dp_me_mcast_table *table)
{
	int cnt;

	if (!group || !table)
		return NULL;

	for (cnt = 0; cnt < table->entry_cnt; cnt++) {
		if (!qdf_mem_cmp(&table->entry[cnt].group, group, sizeof(*group)))
			break;
	}
	if (cnt == table->entry_cnt)
		return NULL;

	*group_ix = cnt;
	return &table->entry[cnt];
}

int dp_me_mcast_filter(struct dp_me_mcast_node *node, const void *ip_header,
		u_int16_t protocol)
{
	int i;

	if (!node->filter_mode ||
	    (node->filter_mode == DP_ME_MCAST_EXCLUDE && !node->nsrcs))
		return 0;

	if (node->filter_mode == DP_ME_MCAST_INCLUDE && !node->nsrcs)
		return 1;

	if (protocol == htobe16(ETHERTYPE_IP)) {
		u_int32_t ip4 = ((struct ip_header *)ip_header)->saddr;
		const u_int32_t *srcs = (u_int32_t *)node->srcs;
		for (i = 0; i < node->nsrcs; i++) {
			if (srcs[i] == ip4)
				break;
		}
	} else if (protocol == htobe16(ETHERTYPE_IPV6)) {
		qdf_net_ipv6_addr_t *ip6 = &((qdf_net_ipv6hdr_t *)ip_header)->ipv6_saddr;
		qdf_net_ipv6_addr_t *srcs = (qdf_net_ipv6_addr_t *)node->srcs;
		for (i = 0; i < node->nsrcs; i++) {
			if (!qdf_mem_cmp(&srcs[i], ip6, sizeof(*srcs)))
				break;
		}
	} else {
		return 0;
	}

	return ((node->filter_mode == DP_ME_MCAST_INCLUDE && i == node->nsrcs) ||
		(node->filter_mode == DP_ME_MCAST_EXCLUDE && i != node->nsrcs));
}


static int dp_me_mcast_hmmc_convert(ol_txrx_soc_handle soc,
				    uint8_t vdev_id,
				    dp_vdev_me_t *vdev_me,
				    qdf_nbuf_t wbuf,
				    uint8_t tid, bool is_igmp)
{
	u_int8_t newmac[MAX_SNOOP_ENTRIES][QDF_MAC_ADDR_SIZE];
	int new_mac_cnt = 0;                        /* count of entries in newmac */

	/* Convert the packet to unicast to all STAs of vdev */
	new_mac_cnt = cdp_vdev_get_peer_mac_list(soc,vdev_id,newmac,
						 MAX_SNOOP_ENTRIES, false);
	return dp_me_convert_ucast(soc, vdev_id, wbuf, newmac, new_mac_cnt,
				   vdev_me->me_mcast_mode, vdev_me->macaddr, tid,
				   is_igmp);
}

/*
 * dp_igmp_me_mcast_convert: Convert igmp mcast packets to unicast
 *
 * Parameters:
 * @soc: soc txrx handle
 * @vdev_id: id of handle to vap pointer
 * @pdev_id: id of handle to pdev pointer
 * @wbuf: Frame buffer containing the 802.3 frame
 * @tid: desired tid
 *
 * Return:
 * n  : Total Number of successful unicast conversions
 * < 0 : Packets not converted
 */

int dp_igmp_me_mcast_convert(struct cdp_soc_t *soc, uint8_t vdev_id,
			     uint8_t pdev_id, qdf_nbuf_t wbuf)
{
	dp_vdev_igmp_me_t *vdev_igmp_me;
	dp_vdev_me_t *vdev_me;
	int new_mac_cnt;
	uint8_t igmp_pkt = 0;
	u_int8_t newmac[MAX_SNOOP_ENTRIES][QDF_MAC_ADDR_SIZE];

	vdev_me = dp_get_vdev_me_handle(soc, vdev_id);
	if (!vdev_me)
		return -1;

	vdev_igmp_me = dp_get_vdev_igmp_me_handle(soc, vdev_id);

	if (!vdev_igmp_me || !vdev_igmp_me->igmp_me_enabled) {
		return -1;
	}

	if (dp_me_igmp_mld_inspect(soc, pdev_id, wbuf, &igmp_pkt, NULL, NULL, NULL)) {
		if (!igmp_query_check(igmp_pkt)){
			/* Not an IGMP/MLD packet */
			return -1;
		}
	}

	new_mac_cnt = cdp_vdev_get_peer_mac_list(soc, vdev_id, newmac,
						 MAX_SNOOP_ENTRIES, true);

	if (!new_mac_cnt) {
		return -1;
	}

	return dp_me_convert_ucast(soc, vdev_id, wbuf, newmac, new_mac_cnt,
				   vdev_me->me_mcast_mode,
				   vdev_igmp_me->macaddr,
				   DP_VO_TID, true);
}
qdf_export_symbol(dp_igmp_me_mcast_convert);

int dp_me_mcast_convert(struct cdp_soc_t *soc,
			uint8_t vdev_id,
			uint8_t pdev_id,
			qdf_nbuf_t wbuf)
{
	int n;
	u_int8_t hmmc_found = 0;
	u_int8_t deny_list = 0;
	rwlock_state_t lock_state;
	struct ether_header *eh = NULL;
	u_int8_t zero_mac[QDF_MAC_ADDR_SIZE];
	struct dp_me_mcast_group group;
	struct dp_me_mcast_entry *entry = NULL;
	struct dp_me_mcast_table *table;
	u_int8_t newmac[MAX_SNOOP_ENTRIES][QDF_MAC_ADDR_SIZE];
	int new_mac_cnt = 0;
	uint8_t igmp_pkt = 0;
	uint8_t *is_igmp = NULL;
	int group_ix = 0; /* Multicast group index */
	dp_vdev_me_t *vdev_me;
	uint32_t grp_cnt;

	vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

	if (!vdev_me)
		return -1;

	grp_cnt = vdev_me->me_mcast_table.entry_cnt;

	if (!vdev_me->me_mcast_mode)
		return -1;

	if (vdev_me->me_igmp_allow)
		is_igmp = &igmp_pkt;

	if (dp_me_igmp_mld_inspect(soc, pdev_id, wbuf, is_igmp, &group,
				   &hmmc_found, &deny_list)) {
		if (igmp_query_check(igmp_pkt)) {
			struct cdp_tx_ingress_stats stats = {0};
			stats.igmp_mcast_en.igmp_rcvd++;
			cdp_update_vdev_host_stats(soc, vdev_id, &stats,
						   DP_VDEV_STATS_TX_ME);
			if (!vdev_me->me_igmp_allow)
				return -1;
		} else
			return -1;
	}

	if (deny_list)
		return -1;

	if (hmmc_found) {
		return dp_me_mcast_hmmc_convert(soc, vdev_id, vdev_me, wbuf,
						igmp_pkt ? DP_VO_TID : HTT_INVALID_TID,
						igmp_query_check(igmp_pkt));
	}

	OS_RWLOCK_READ_LOCK(&vdev_me->me_mcast_lock, &lock_state);
	table = &vdev_me->me_mcast_table;
	if (!table->entry_cnt ||
	    !(entry = dp_me_mcast_find_entry(&group, &group_ix, table)) ||
	    !entry->node_cnt ) {
		OS_RWLOCK_READ_UNLOCK(&vdev_me->me_mcast_lock, &lock_state);
		if (vdev_me->me_igmp_allow && igmp_query_check(igmp_pkt)) {
			return -1;
		}

		/*If there are no one in group. drop the frame*/
		wbuf_complete(wbuf);
		return 1;
	}

	eh = (struct ether_header *) wbuf_header(wbuf);
	switch (ntohs(eh->ether_type)) {
	case ETHERTYPE_IP:
	{
		struct ip_header *iph = (struct ip_header *)(eh + 1);

		if (!vdev_me->me_igmp_allow && (iph->protocol == IPPROTO_IGMP))
			return -1;

		OS_MEMSET(&group, 0, sizeof group);
			  group.u.ip4 = ntohl(iph->daddr);
			  group.protocol = ETHERTYPE_IP;
	}
		break;
	case ETHERTYPE_IPV6:
	{
		qdf_net_ipv6hdr_t *ip6h = (qdf_net_ipv6hdr_t *)(eh + 1);
		u_int8_t *nexthdr = (u_int8_t *)(ip6h + 1);

		if (!vdev_me->me_igmp_allow &&
		    (ip6h->ipv6_nexthdr == IPPROTO_ICMPV6 ||
		    (ip6h->ipv6_nexthdr == IPPROTO_HOPOPTS &&
		     *nexthdr == IPPROTO_ICMPV6)))
			return -1;

		OS_MEMSET(&group, 0, sizeof group);
		OS_MEMCPY(group.u.ip6,
			  ip6h->ipv6_daddr.s6_addr,
			  sizeof(qdf_net_ipv6_addr_t));
		group.protocol = ETHERTYPE_IPV6;
	}
		break;
	default:
		return -1;
	}


	OS_MEMSET(zero_mac, 0, QDF_MAC_ADDR_SIZE);
	for (n = 0; n < entry->node_cnt; n++) {
		if ((WLAN_ADDR_EQ(eh->ether_shost, entry->nodes[n].mac) == 0) ||
		    (WLAN_ADDR_EQ(zero_mac, entry->nodes[n].mac) == 0 ) ||
		    dp_me_mcast_filter(&entry->nodes[n], eh + 1,
		    ntohs(eh->ether_type))) {
			continue;
		}

		if(new_mac_cnt < MAX_SNOOP_ENTRIES) {
			if (vdev_me->me_mcast_mode == MC_HYFI_ENABLE)
				WLAN_ADDR_COPY(newmac[new_mac_cnt], entry->nodes[n].mac);
			else
			{
				if (!vdev_me->me_ra[group_ix][n].dup) {
					WLAN_ADDR_COPY(newmac[new_mac_cnt],
							vdev_me->me_ra[group_ix][n].mac);
				} else {
					/* Peer is dropped since frame is being sent to a
					 * common next-hop node */
					continue;
				}
			}
			new_mac_cnt++;
		} else {
			qdf_nofl_info("WARNING: too many nodes in %s:%d",
					__func__, __LINE__);
			break;
		}
	}
	OS_RWLOCK_READ_UNLOCK(&vdev_me->me_mcast_lock, &lock_state);

	if(new_mac_cnt) {
		return dp_me_convert_ucast(soc, vdev_id, wbuf, newmac, new_mac_cnt,
					   vdev_me->me_mcast_mode, vdev_me->macaddr,
					   igmp_pkt ? DP_VO_TID : HTT_INVALID_TID,
					   igmp_query_check(igmp_pkt));
	} else if(new_mac_cnt == 0){
		if ( dp_me_igmp_mld_inspect(soc, pdev_id, wbuf,
					&igmp_pkt, NULL, NULL, NULL))
			if(igmp_query_check(igmp_pkt)){
				return -1;
			}
		/*If there are no one in group. drop the frame*/
		wbuf_complete(wbuf);
		return 1;
	}
	return -1;
}
qdf_export_symbol(dp_me_mcast_convert);

static inline int _dp_me_deny_list_find(struct cdp_soc_t *soc, uint8_t pdev_id,
				   u_int32_t dip)
{
	int i;
	dp_pdev_me_t *pdev_me_hdl;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return 0;

	for (i = 0; i < pdev_me_hdl->pdev_deny_list_cnt; i++) {
		if (pdev_me_hdl->pdev_denylist[i].ip ==
		    (dip & pdev_me_hdl->pdev_denylist[i].mask))
			return 1;
	}
	return 0;
}

static inline int _dp_me_hmmc_find(struct cdp_soc_t *soc, uint8_t pdev_id,
				   u_int32_t dip)
{
	int i;
	dp_pdev_me_t *pdev_me_hdl;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return 0;

	for (i = 0; i < pdev_me_hdl->pdev_hmmc_cnt; i++) {
		if (pdev_me_hdl->pdev_hmmcs[i].ip ==
		    (dip & pdev_me_hdl->pdev_hmmcs[i].mask))
			return 1;
	}
	return 0;
}

static int dp_me_igmp_mld_inspect(struct cdp_soc_t *soc, uint8_t pdev_id,
				  qdf_nbuf_t wbuf, u_int8_t *type,
				  void *group, u_int8_t *hmmc_found, u_int8_t *deny_list)
{
	u_int16_t protocol;
	u_int32_t ip4 = 0;
	u_int8_t *ip6 = NULL;
	struct ether_header *eh = (struct ether_header *) wbuf_header(wbuf);
	int is_multicast = IEEE80211_IS_MULTICAST(eh->ether_dhost) &&
		!IEEE80211_IS_BROADCAST(eh->ether_dhost);
	int ret = 0;

	switch (eh->ether_type) {
	case htobe16(ETHERTYPE_IP):
	{
		struct ip_header *iph = (struct ip_header *)(eh + 1);
		int ip_headerlen;
		const struct igmp_header *igmp;

		ip4 = iph->saddr;
		protocol = ETHERTYPE_IP;

		if (iph->protocol == IPPROTO_IGMP) {
			if (!type) return 1;

			ip_headerlen = iph->version_ihl & 0x0F;

			igmp = (struct igmp_header *)(wbuf_header(wbuf) +
						sizeof (struct ether_header) + (4 * ip_headerlen));
			*type = igmp->type;
			ret = 1;
			break;
		}
		if (is_multicast && group) {
			struct dp_me_mcast_group *grp = (struct dp_me_mcast_group *)group;
			OS_MEMSET(grp, 0, sizeof(*grp));
			grp->u.ip4 = iph->daddr;
			grp->protocol = htobe16(ETHERTYPE_IP);
			if (deny_list) {
				*deny_list = _dp_me_deny_list_find(soc, pdev_id, iph->daddr);
				if (*deny_list)
					break;
			}
			if (hmmc_found)
				*hmmc_found = _dp_me_hmmc_find(soc, pdev_id, iph->daddr);
		}
	}
		break;
	case htobe16(ETHERTYPE_IPV6):
	{
			qdf_net_ipv6hdr_t *ip6h = (qdf_net_ipv6hdr_t *)(eh + 1);
			u_int8_t *nexthdr = (u_int8_t *)(ip6h + 1);
			qdf_net_icmpv6hdr_t *mld;

			ip6 = ip6h->ipv6_saddr.s6_addr;
			protocol = ETHERTYPE_IPV6;

			if (ip6h->ipv6_nexthdr == IPPROTO_ICMPV6 ||
			    (ip6h->ipv6_nexthdr == IPPROTO_HOPOPTS &&
			    *nexthdr == IPPROTO_ICMPV6)) {
				if (!type) return 1;

				if (ip6h->ipv6_nexthdr == IPPROTO_ICMPV6)
					mld = (qdf_net_icmpv6hdr_t *)nexthdr;
				else
					mld = (qdf_net_icmpv6hdr_t *)(nexthdr + 8);
				*type = mld->icmp6_type;
				ret = 1;
				break;
			}
			if (is_multicast && group) {
				struct dp_me_mcast_group *grp = (struct dp_me_mcast_group *)group;
				OS_MEMSET(grp, 0, sizeof(*grp));
				OS_MEMCPY(grp->u.ip6,
						ip6h->ipv6_daddr.s6_addr,
						sizeof(qdf_net_ipv6_addr_t));
				grp->protocol = htobe16(ETHERTYPE_IPV6);
			}
	}
		break;
	default:
		/*
		 * This case returns 1 although the packet is not IGMP.
		 * This is being used by L2 layer multicast packets
		 * such as IEEE-1905.1-control packets
		 */
		return 1;
	}
	return ret;
}

QDF_STATUS dp_me_attach(ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *macaddr)
{
	struct dp_vdev_me *vdev_me;

	vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

	if (!vdev_me)
		return QDF_STATUS_E_FAILURE;;

	vdev_me->me_mcast_mode = 0;
	qdf_mem_copy(vdev_me->macaddr, macaddr, QDF_MAC_ADDR_SIZE);
        vdev_me->me_igmp_allow = 0;
	OS_RWLOCK_INIT(&vdev_me->me_mcast_lock);
	return QDF_STATUS_SUCCESS;
}

int dp_add_hmmc(ol_txrx_soc_handle soc, uint8_t pdev_id,
		u_int32_t ip, u_int32_t mask)
{
	int i;
	dp_pdev_me_t *pdev_me_hdl;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return -1;

	if (!ip || !mask || DP_ADD_HMMC_CHECK_IP(ip))
		return -EINVAL;

	for (i = 0; i < pdev_me_hdl->pdev_hmmc_cnt; i++) {
		if (pdev_me_hdl->pdev_hmmcs[i].ip == ip)
			break;
	}
	if (i != pdev_me_hdl->pdev_hmmc_cnt) {
		pdev_me_hdl->pdev_hmmcs[i].ip = ip;
		pdev_me_hdl->pdev_hmmcs[i].mask = mask;
		return 0;
	}
	if (pdev_me_hdl->pdev_hmmc_cnt < DP_ME_HMMC_CNT_MAX) {
		pdev_me_hdl->pdev_hmmcs[pdev_me_hdl->pdev_hmmc_cnt].ip = ip;
		pdev_me_hdl->pdev_hmmcs[pdev_me_hdl->pdev_hmmc_cnt].mask = mask;

		pdev_me_hdl->pdev_hmmc_cnt++;
		return 0;
	}
	return -1;
}

int dp_del_hmmc(ol_txrx_soc_handle soc, uint8_t pdev_id,
		u_int32_t ip, u_int32_t mask)
{
	dp_pdev_me_t *pdev_me_hdl;
	int i, hmmc_size;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return -EINVAL;

	hmmc_size = sizeof(pdev_me_hdl->pdev_hmmcs) / DP_ME_HMMC_CNT_MAX;

	if (!ip || !mask)
		return -EINVAL;

	if (!pdev_me_hdl->pdev_hmmc_cnt)
		return 0;

	for (i = 0; i < pdev_me_hdl->pdev_hmmc_cnt; i++) {
		if (pdev_me_hdl->pdev_hmmcs[i].ip == ip &&
		    pdev_me_hdl->pdev_hmmcs[i].mask == mask)
			break;
	}

	if (i == pdev_me_hdl->pdev_hmmc_cnt)
		return -EINVAL;

	OS_MEMCPY(&pdev_me_hdl->pdev_hmmcs[i], &pdev_me_hdl->pdev_hmmcs[i+1],
		  (pdev_me_hdl->pdev_hmmc_cnt - i - 1) * hmmc_size );
	pdev_me_hdl->pdev_hmmc_cnt--;

	return 0;
}

int dp_hmmc_dump(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	dp_pdev_me_t *pdev_me_hdl;
	int i;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return 0;

	dp_me_info("\nMULTICAST RANGE:");
	for (i = 0; i < pdev_me_hdl->pdev_hmmc_cnt; i++)
		qdf_info("\t%d of %d: %08x/%08x",
			 i+1,
			 pdev_me_hdl->pdev_hmmc_cnt,
			 pdev_me_hdl->pdev_hmmcs[i].ip,
			 pdev_me_hdl->pdev_hmmcs[i].mask);
	return 0;
}

int dp_add_deny_list(ol_txrx_soc_handle soc, uint8_t pdev_id,
		     u_int32_t ip, u_int32_t mask)
{
	int i;
	dp_pdev_me_t *pdev_me_hdl;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return -1;

	if (!ip || !mask || DP_ADD_HMMC_CHECK_IP(ip))
		return -EINVAL;

	for (i = 0; i < pdev_me_hdl->pdev_deny_list_cnt; i++) {
		if (pdev_me_hdl->pdev_denylist[i].ip == ip)
			break;
	}

	/* IP found in list, updating entry as mask value may be different */
	if (i != pdev_me_hdl->pdev_deny_list_cnt) {
		pdev_me_hdl->pdev_denylist[i].ip = ip;
		pdev_me_hdl->pdev_denylist[i].mask = mask;
		return 0;
	}

	/* IP not found in existing list, so add entry in the list */
	if (pdev_me_hdl->pdev_deny_list_cnt < DP_ME_HMMC_CNT_MAX) {
		pdev_me_hdl->pdev_denylist[pdev_me_hdl->pdev_deny_list_cnt].ip = ip;
		pdev_me_hdl->pdev_denylist[pdev_me_hdl->pdev_deny_list_cnt].mask = mask;

		pdev_me_hdl->pdev_deny_list_cnt++;
		return 0;
	}
	return -1;
}

int dp_del_deny_list(ol_txrx_soc_handle soc, uint8_t pdev_id,
		     u_int32_t ip, u_int32_t mask)
{
	dp_pdev_me_t *pdev_me_hdl;
	int i, hmmc_size;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return -EINVAL;

	hmmc_size = sizeof(pdev_me_hdl->pdev_denylist) / DP_ME_HMMC_CNT_MAX;

	if (!ip || !mask)
		return -EINVAL;

	if (!pdev_me_hdl->pdev_deny_list_cnt)
		return 0;

	for (i = 0; i < pdev_me_hdl->pdev_deny_list_cnt; i++) {
		if (pdev_me_hdl->pdev_denylist[i].ip == ip &&
		    pdev_me_hdl->pdev_denylist[i].mask == mask)
			break;
	}

	if (i == pdev_me_hdl->pdev_deny_list_cnt)
		return -EINVAL;

	OS_MEMCPY(&pdev_me_hdl->pdev_denylist[i], &pdev_me_hdl->pdev_denylist[i+1],
		  (pdev_me_hdl->pdev_deny_list_cnt - i - 1) * hmmc_size );
	pdev_me_hdl->pdev_deny_list_cnt--;

	return 0;
}

int dp_deny_list_dump(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	dp_pdev_me_t *pdev_me_hdl;
	int i;

	pdev_me_hdl = dp_get_pdev_me_handle(soc, pdev_id);

	if (!pdev_me_hdl)
		return 0;

	dp_me_info("\nMULTICAST RANGE:");
	for (i = 0; i < pdev_me_hdl->pdev_deny_list_cnt; i++)
		qdf_info("\t%d of %d: %08x/%08x",
			 i+1,
			 pdev_me_hdl->pdev_deny_list_cnt,
			 pdev_me_hdl->pdev_denylist[i].ip,
			 pdev_me_hdl->pdev_denylist[i].mask);
	return 0;
}


/**
 * Function to dump the RA table used for the Multicast Enhancement mode 6
 * feature.
 * @vdev - Handle to vdev structure
 */
void dp_show_me_ra_table(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	uint32_t grp_cnt, node_cnt;
	uint32_t grp_ix, node_ix;
	dp_vdev_me_t *vdev_me;

	vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

	if (!vdev_me)
		return;

	grp_cnt = vdev_me->me_mcast_table.entry_cnt;

	if (!grp_cnt) {
		return;
	}

	dp_me_info("-------------------------------------------------------------------");
	dp_me_info("|  Group Address  | Destination Address | Receiver Address  | Dup |");
	dp_me_info("-------------------------------------------------------------------");

	for (grp_ix = 0; grp_ix < grp_cnt; grp_ix++) {
		node_cnt = vdev_me->me_mcast_table.entry[grp_ix].node_cnt;
		for (node_ix = 0; node_ix < node_cnt; node_ix++) {
			dp_me_info("| %pi4 |  %pM  | %pM |  %u  |",
				   &(vdev_me->me_mcast_table.entry[grp_ix].group.u.ip4),
				   &(vdev_me->me_mcast_table.entry[grp_ix].nodes[node_ix].mac),
				   &(vdev_me->me_ra[grp_ix][node_ix].mac),
				   vdev_me->me_ra[grp_ix][node_ix].dup);
		}
	}
	dp_me_info("-------------------------------------------------------------------");
}

#endif /* ATH_SUPPORT_IQUE */

