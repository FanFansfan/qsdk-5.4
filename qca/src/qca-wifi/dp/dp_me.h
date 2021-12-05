/*
 * Copyright (c) 2013, 2018-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

/*
 * Copyright (c) 2010, Atheros Communications Inc.
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
 * 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#if ATH_SUPPORT_IQUE

#ifndef DP_ME_PRIV_H
#define DP_ME_PRIV_H

#include <qdf_nbuf.h>
#include <ieee80211.h>

#ifndef MAX_SNOOP_ENTRIES
#define MAX_SNOOP_ENTRIES    64    /* max number*/
#endif

#define MC_ME_DISABLE          (0)
#define MC_HYFI_ENABLE         (5)
#define MC_AMSDU_ENABLE        (6)

#define DP_REPORT_FROM_STA 1
#define DP_QUERY_FROM_STA  2
#define DP_ME_MCAST_SRCS_MAX 4
#define DP_ME_MCAST_NODE_MAX 8
#define DP_ME_MCAST_GROUP_MAX 16
#define DP_ME_MCAST_INCLUDE 1
#define DP_ME_MCAST_EXCLUDE 2
#define DP_ME_HMMC_CNT_MAX 8

#define IGMP_QUERY      0x11
#define IGMPv1_REPORT   0x12
#define IGMPv2_REPORT   0x16
#define IGMP_LEAVE      0x17
#define IGMPv3_REPORT   0x22
#define MLD_QUERY       0x82
#define MLD_REPORT      0x83
#define MLD_LEAVE       0x84
#define MLDv2_REPORT    0x8f

#define DP_ADD_HMMC_CHECK_IP(ip) \
		(((ip) & htobe32(0xf0000000)) != htobe32(0xe0000000))

#define dp_me_alert(params...) QDF_TRACE_FATAL(QDF_MODULE_ID_ME, params)
#define dp_me_err(params...) QDF_TRACE_FATAL(QDF_MODULE_ID_ME, params)
#define dp_me_warn(params...) QDF_TRACE_WARN(QDF_MODULE_ID_ME, params)
#define dp_me_info(params...) QDF_TRACE_INFO(QDF_MODULE_ID_ME, params)
#define dp_me_debug(params...) QDF_TRACE_DEBUG(QDF_MODULE_ID_ME, params)

#define DP_VO_TID 6
/*
 * Data structures for mcast enhancement
 */

typedef rwlock_t dp_me_snoop_lock_t;

struct dp_me_mcast_group {
	u_int32_t                       protocol;
	union {
		u_int32_t                   ip4;
		u_int8_t                    ip6[QDF_IPV6_ADDR_SIZE];
	} u;
};
struct dp_me_mcast_node {
	u_int8_t mac[QDF_MAC_ADDR_SIZE];
	u_int8_t filter_mode;
	u_int8_t nsrcs;
	u_int8_t srcs[DP_ME_MCAST_SRCS_MAX * QDF_IPV6_ADDR_SIZE];
};
struct dp_me_mcast_entry {
	struct dp_me_mcast_group  group;
	u_int32_t                 node_cnt;
	struct dp_me_mcast_node   nodes[DP_ME_MCAST_NODE_MAX];
};
struct dp_me_mcast_table {
	u_int32_t                 entry_cnt;
	struct dp_me_mcast_entry  entry[DP_ME_MCAST_GROUP_MAX];
};
struct dp_me_ra_entry {
	uint8_t mac[QDF_MAC_ADDR_SIZE];
	/* Duplicate bit is set if the peer's next hop is the same as
	   an existing entry */
	bool   dup;
};

typedef struct dp_pdev_me {
	u_int32_t pdev_hmmc_cnt;
	struct {
		u_int32_t ip;
		u_int32_t mask;
	} pdev_hmmcs[DP_ME_HMMC_CNT_MAX];
	u_int32_t pdev_deny_list_cnt;
	struct {
		u_int32_t ip;
		u_int32_t mask;
	} pdev_denylist[DP_ME_HMMC_CNT_MAX];

}dp_pdev_me_t;

typedef struct dp_vdev_me {
	uint8_t                    me_mcast_mode;
	uint8_t                    me_igmp_allow;
	dp_me_snoop_lock_t         me_mcast_lock;
	struct dp_me_mcast_table   me_mcast_table;
	struct dp_me_ra_entry      me_ra[DP_ME_MCAST_GROUP_MAX][DP_ME_MCAST_NODE_MAX];
	uint8_t                    macaddr[QDF_MAC_ADDR_SIZE];
}dp_vdev_me_t;

typedef struct dp_vdev_igmp_me {
	uint8_t                    igmp_me_enabled;
	uint8_t                    macaddr[QDF_MAC_ADDR_SIZE];
}dp_vdev_igmp_me_t;


int dp_add_hmmc(ol_txrx_soc_handle soc, uint8_t pdev_id,
		u_int32_t ip, u_int32_t mask);

int dp_del_hmmc(ol_txrx_soc_handle soc, uint8_t pdev_id,
		u_int32_t ip, u_int32_t mask);

int dp_hmmc_dump(ol_txrx_soc_handle soc, uint8_t pdev_id);

int dp_add_deny_list(ol_txrx_soc_handle soc, uint8_t pdev_id,
		     u_int32_t ip, u_int32_t mask);

int dp_del_deny_list(ol_txrx_soc_handle soc, uint8_t pdev_id,
		     u_int32_t ip, u_int32_t mask);

int dp_deny_list_dump(ol_txrx_soc_handle soc, uint8_t pdev_id);


/**
 * Show RA table used for Multicast Enhancement Mode 6
 *
 * @soc: soc txrx handle
 * @vdev_id : vdev_id
 *
 * Return: void
 */
void dp_show_me_ra_table(ol_txrx_soc_handle soc, uint8_t vdev_id);

/**
 * dp_pdev_me_setup() - Setup pdev me handle
 *
 * @soc: soc txrx handle
 * @pdev_id : pdev_id
 *
 * Return: void
 */
void dp_pdev_me_setup(ol_txrx_soc_handle soc, uint8_t pdev_id);

QDF_STATUS dp_me_attach(ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *macaddr);

void
dp_me_update_mcast_table(ol_txrx_soc_handle soc, uint8_t vdev_id,
			 uint8_t pdev_id, void *data, uint32_t msglen,
			 uint16_t hdrlen);

int dp_me_mcast_convert(struct cdp_soc_t *soc,
			uint8_t vdev_id,
			uint8_t pdev_id,
			qdf_nbuf_t wbuf);

int dp_igmp_me_mcast_convert(struct cdp_soc_t *soc,
			     uint8_t vdev_id,
			     uint8_t pdev_id,
			     qdf_nbuf_t wbuf);
#endif
#endif /* ATH_SUPPORT_IQUE */
