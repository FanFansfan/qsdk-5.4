/*
 **************************************************************************
 * Copyright (c) 2014-2021 The Linux Foundation.  All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/kthread.h>
#include <linux/debugfs.h>
#include <linux/pkt_sched.h>
#include <linux/string.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/addrconf.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ppp_defs.h>
#include <linux/mroute.h>

#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <net/arp.h>
#ifdef ECM_INTERFACE_VXLAN_ENABLE
#include <net/vxlan.h>
#endif
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <linux/netfilter/nf_conntrack_zones_common.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#ifdef ECM_INTERFACE_VLAN_ENABLE
#include <linux/../../net/8021q/vlan.h>
#include <linux/if_vlan.h>
#endif

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_NSS_IPV4_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_state.h"
#include "ecm_tracker.h"
#include "ecm_front_end_types.h"
#include "ecm_classifier.h"
#include "ecm_tracker_datagram.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#ifdef ECM_CLASSIFIER_NL_ENABLE
#include "ecm_classifier_nl.h"
#endif
#include "ecm_interface.h"
#include "ecm_nss_ported_ipv4.h"
#ifdef ECM_MULTICAST_ENABLE
#include "ecm_nss_multicast_ipv4.h"
#endif
#ifdef ECM_NON_PORTED_SUPPORT_ENABLE
#include "ecm_nss_non_ported_ipv4.h"
#endif
#include "ecm_nss_common.h"
#include "ecm_front_end_common.h"
#include "ecm_front_end_ipv4.h"
#ifdef ECM_INTERFACE_OVS_BRIDGE_ENABLE
#include <ovsmgr.h>
#endif

#define ECM_NSS_IPV4_STATS_SYNC_PERIOD msecs_to_jiffies(1000)
#define ECM_NSS_IPV4_STATS_SYNC_UDELAY 4000	/* Delay for 4 ms */

int ecm_nss_ipv4_no_action_limit_default = 250;		/* Default no-action limit. */
int ecm_nss_ipv4_driver_fail_limit_default = 250;		/* Default driver fail limit. */
int ecm_nss_ipv4_nack_limit_default = 250;			/* Default nack limit. */
int ecm_nss_ipv4_accelerated_count = 0;			/* Total offloads */
int ecm_nss_ipv4_pending_accel_count = 0;			/* Total pending offloads issued to the NSS / awaiting completion */
int ecm_nss_ipv4_pending_decel_count = 0;			/* Total pending deceleration requests issued to the NSS / awaiting completion */
int ecm_nss_ipv4_vlan_passthrough_enable = 0;		/* VLAN passthrough feature enable or disable flag */

/*
 * Limiting the acceleration of connections.
 *
 * By default there is no acceleration limiting.
 * This means that when ECM has more connections (that can be accelerated) than the acceleration
 * engine will allow the ECM will continue to try to accelerate.
 * In this scenario the acceleration engine will begin removal of existing rules to make way for new ones.
 * When the accel_limit_mode is set to FIXED ECM will not permit more rules to be issued than the engine will allow.
 */
uint32_t ecm_nss_ipv4_accel_limit_mode = ECM_FRONT_END_ACCEL_LIMIT_MODE_UNLIMITED;

/*
 * Locking of the classifier - concurrency control for file global parameters.
 * NOTE: It is safe to take this lock WHILE HOLDING a feci->lock.  The reverse is NOT SAFE.
 */
DEFINE_SPINLOCK(ecm_nss_ipv4_lock);			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * Management thread control
 */
bool ecm_nss_ipv4_terminate_pending = false;		/* True when the user has signalled we should quit */

/*
 * NSS driver linkage
 */
struct nss_ctx_instance *ecm_nss_ipv4_nss_ipv4_mgr = NULL;

static unsigned long ecm_nss_ipv4_accel_cmd_time_avg_samples = 0;	/* Sum of time taken for the set of accel command samples, used to compute average time for an accel command to complete */
static unsigned long ecm_nss_ipv4_accel_cmd_time_avg_set = 1;	/* How many samples in the set */
static unsigned long ecm_nss_ipv4_decel_cmd_time_avg_samples = 0;	/* Sum of time taken for the set of accel command samples, used to compute average time for an accel command to complete */
static unsigned long ecm_nss_ipv4_decel_cmd_time_avg_set = 1;	/* How many samples in the set */

/*
 * Debugfs dentry object.
 */
static struct dentry *ecm_nss_ipv4_dentry;

/*
 * Workqueue for the connection sync
 */
struct workqueue_struct *ecm_nss_ipv4_workqueue;
struct delayed_work ecm_nss_ipv4_work;
struct nss_ipv4_msg *ecm_nss_ipv4_sync_req_msg;
static unsigned long int ecm_nss_ipv4_next_req_time;
static unsigned long int ecm_nss_ipv4_roll_check_jiffies;
static unsigned long int ecm_nss_ipv4_stats_request_success = 0;	/* Number of success stats request */
static unsigned long int ecm_nss_ipv4_stats_request_fail = 0;		/* Number of failed stats request */
static unsigned long int ecm_nss_ipv4_stats_request_nack = 0;		/* Number of NACK'd stats request */

/*
 * ecm_nss_ipv4_node_establish_and_ref()
 *	Returns a reference to a node, possibly creating one if necessary.
 *
 * The given_node_addr will be used if provided.
 *
 * Returns NULL on failure.
 */
struct ecm_db_node_instance *ecm_nss_ipv4_node_establish_and_ref(struct ecm_front_end_connection_instance *feci,
							struct net_device *dev, ip_addr_t addr,
							struct ecm_db_iface_instance *interface_list[], int32_t interface_list_first,
							uint8_t *given_node_addr, struct sk_buff *skb)
{
	struct ecm_db_node_instance *ni;
	struct ecm_db_node_instance *nni;
	struct ecm_db_iface_instance *ii;
	int i;
	bool done;
	uint8_t node_addr[ETH_ALEN];
#if defined(ECM_INTERFACE_L2TPV2_ENABLE) || defined(ECM_INTERFACE_PPTP_ENABLE)
	ip_addr_t local_ip, remote_ip;
#endif

#if defined(ECM_INTERFACE_VXLAN_ENABLE) || defined(ECM_INTERFACE_L2TPV2_ENABLE) || defined(ECM_INTERFACE_PPTP_ENABLE)
	struct net_device *local_dev;
#endif

#if defined(ECM_INTERFACE_MAP_T_ENABLE) || defined(ECM_INTERFACE_GRE_TUN_ENABLE) || defined(ECM_XFRM_ENABLE)
	struct net_device *in;
#endif

#ifdef ECM_INTERFACE_GRE_TUN_ENABLE
	struct ip_tunnel *gre4_tunnel;
	struct ip6_tnl *gre6_tunnel;
	ip_addr_t local_gre_tun_ip;
#endif

	DEBUG_INFO("%px: Establish node for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));

	/*
	 * The node is the datalink address, typically a MAC address.
	 * However the node address to use is not always obvious and depends on the interfaces involved.
	 * For example if the interface is PPPoE then we use the MAC of the PPPoE server as we cannot use normal ARP resolution.
	 * Not all hosts have a node address, where there is none, a suitable alternative should be located and is typically based on 'addr'
	 * or some other datalink session information.
	 * It should be, at a minimum, something that ties the host with the interface.
	 *
	 * Iterate from 'inner' to 'outer' interfaces - discover what the node is.
	 */
	memset(node_addr, 0, ETH_ALEN);
	done = false;
	if (given_node_addr) {
		memcpy(node_addr, given_node_addr, ETH_ALEN);
		done = true;
		DEBUG_TRACE("%px: Using given node address: %pM\n", feci, node_addr);
	}

	for (i = ECM_DB_IFACE_HEIRARCHY_MAX - 1; (!done) && (i >= interface_list_first); i--) {
		ecm_db_iface_type_t type;
#ifdef ECM_INTERFACE_PPPOE_ENABLE
		struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_L2TPV2_ENABLE
		struct ecm_db_interface_info_pppol2tpv2 pppol2tpv2_info;
#endif
#ifdef ECM_INTERFACE_PPTP_ENABLE
		struct ecm_db_interface_info_pptp pptp_info;
#endif
		type = ecm_db_iface_type_get(interface_list[i]);
		DEBUG_INFO("%px: Lookup node address, interface @ %d is type: %d\n", feci, i, type);

		switch (type) {

		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPPOE_ENABLE
			/*
			 * Node address is the address of the remote PPPoE server
			 */
			ecm_db_iface_pppoe_session_info_get(interface_list[i], &pppoe_info);
			memcpy(node_addr, pppoe_info.remote_mac, ETH_ALEN);
			done = true;
			break;
#else
			DEBUG_TRACE("%px:PPPoE interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_SIT:
		case ECM_DB_IFACE_TYPE_TUNIPIP6:
			done = true;
			break;

		case ECM_DB_IFACE_TYPE_PPPOL2TPV2:
#ifdef ECM_INTERFACE_L2TPV2_ENABLE
			ecm_db_iface_pppol2tpv2_session_info_get(interface_list[i], &pppol2tpv2_info);
			ECM_HIN4_ADDR_TO_IP_ADDR(local_ip, pppol2tpv2_info.ip.saddr);
			ECM_HIN4_ADDR_TO_IP_ADDR(remote_ip, pppol2tpv2_info.ip.daddr);
			DEBUG_TRACE("%px: local=" ECM_IP_ADDR_DOT_FMT " remote=" ECM_IP_ADDR_DOT_FMT " addr=" ECM_IP_ADDR_DOT_FMT "\n", feci,
			       ECM_IP_ADDR_TO_DOT(local_ip), ECM_IP_ADDR_TO_DOT(remote_ip), ECM_IP_ADDR_TO_DOT(addr));

			local_dev = ecm_interface_dev_find_by_local_addr(local_ip);
			if (!local_dev) {
				DEBUG_WARN("%px: Failed to find local netdevice of l2tp tunnel for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(local_ip));
				return NULL;
			}

			DEBUG_TRACE("%px: local_dev found is %s\n", feci, local_dev->name);

			if (local_dev->type == ARPHRD_PPP) {
				struct ppp_channel *ppp_chan[1];
				struct pppoe_opt addressing;
				int px_proto;
#ifndef ECM_INTERFACE_PPPOE_ENABLE
				DEBUG_TRACE("%px: l2tp over netdevice %s unsupported\n", feci, local_dev->name);
				dev_put(local_dev);
				return NULL;
#else
				if (ppp_hold_channels(local_dev, ppp_chan, 1) != 1) {
					DEBUG_WARN("%px: l2tpv2 over netdevice %s unsupported; could not hold ppp channels\n", feci, local_dev->name);
					dev_put(local_dev);
					return NULL;
				}

				px_proto = ppp_channel_get_protocol(ppp_chan[0]);
				if (px_proto != PX_PROTO_OE) {
					DEBUG_WARN("%px: l2tpv2 over PPP protocol %d unsupported\n", feci, px_proto);
					ppp_release_channels(ppp_chan, 1);
					dev_put(local_dev);
					return NULL;
				}

				if (pppoe_channel_addressing_get(ppp_chan[0], &addressing)) {
					DEBUG_WARN("%px: failed to get PPPoE addressing info\n", feci);
					ppp_release_channels(ppp_chan, 1);
					dev_put(local_dev);
					return NULL;
				}

				DEBUG_TRACE("%px: Obtained mac address for %s remote address " ECM_IP_ADDR_OCTAL_FMT "\n", feci, addressing.dev->name, ECM_IP_ADDR_TO_OCTAL(addr));
				memcpy(node_addr, addressing.dev->dev_addr, ETH_ALEN);
				dev_put(addressing.dev);
				ppp_release_channels(ppp_chan, 1);
				dev_put(local_dev);
				done = true;
				break;
#endif
			}

			if (ECM_IP_ADDR_MATCH(local_ip, addr)) {
				if (unlikely(!ecm_interface_mac_addr_get_no_route(local_dev, local_ip, node_addr))) {
					DEBUG_WARN("%px: failed to obtain node address for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(local_ip));
					dev_put(local_dev);
					return NULL;
				}

			} else {
				if (unlikely(!ecm_interface_mac_addr_get_no_route(local_dev, remote_ip, node_addr))) {
					DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(remote_ip));
					dev_put(local_dev);
					return NULL;
				}
			}

			dev_put(local_dev);
			done = true;
			break;
#else
			DEBUG_TRACE("%px: PPPoL2TPV2 interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_PPTP:
#ifdef ECM_INTERFACE_PPTP_ENABLE
			ecm_db_iface_pptp_session_info_get(interface_list[i], &pptp_info);
			ECM_HIN4_ADDR_TO_IP_ADDR(local_ip, pptp_info.src_ip);
			ECM_HIN4_ADDR_TO_IP_ADDR(remote_ip, pptp_info.dst_ip);
			DEBUG_TRACE("%px: local=" ECM_IP_ADDR_DOT_FMT " remote=" ECM_IP_ADDR_DOT_FMT " addr=" ECM_IP_ADDR_DOT_FMT "\n", feci,
			       ECM_IP_ADDR_TO_DOT(local_ip), ECM_IP_ADDR_TO_DOT(remote_ip), ECM_IP_ADDR_TO_DOT(addr));

			local_dev = ecm_interface_dev_find_by_local_addr(local_ip);

			if (!local_dev) {
				DEBUG_WARN("%px: Failed to find local netdevice of pptp tunnel for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(local_ip));
				return NULL;
			}

			DEBUG_TRACE("%px: local_dev found is %s\n", feci, local_dev->name);

			if (ECM_IP_ADDR_MATCH(local_ip, addr)) {
				if (unlikely(!ecm_interface_mac_addr_get_no_route(local_dev, local_ip, node_addr))) {
					DEBUG_WARN("%px: failed to obtain node address for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(local_ip));
					dev_put(local_dev);
					return NULL;
				}

			} else {
				if (unlikely(!ecm_interface_mac_addr_get_no_route(local_dev, remote_ip, node_addr))) {
					ip_addr_t gw_addr = ECM_IP_ADDR_NULL;

					if (!ecm_interface_find_gateway(remote_ip, gw_addr)) {
						DEBUG_WARN("%px: failed to obtain Gateway address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(remote_ip));
						dev_put(local_dev);
						return NULL;
					}

					if (ECM_IP_ADDR_MATCH(gw_addr, remote_ip)) {
						DEBUG_WARN("%px: host ip address match with gw address " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(remote_ip));
						dev_put(local_dev);
						return NULL;
					}

					if (!ecm_interface_mac_addr_get_no_route(local_dev, gw_addr, node_addr)) {
						DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(gw_addr));
						dev_put(local_dev);
						return NULL;
					}
				}
			}

			dev_put(local_dev);
			done = true;
			break;
#else
			DEBUG_TRACE("%px: PPTP interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_MAP_T:
#ifdef ECM_INTERFACE_MAP_T_ENABLE
			in = dev_get_by_index(&init_net, skb->skb_iif);
			if (!in) {
				DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));
				return NULL;
			}
			memcpy(node_addr, in->dev_addr, ETH_ALEN);
			dev_put(in);
			done = true;
			break;
#else
			DEBUG_TRACE("%px: MAP-T interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_GRE_TUN:
#ifdef ECM_INTERFACE_GRE_TUN_ENABLE
			in = dev_get_by_index(&init_net, skb->skb_iif);
			if (!in) {
				DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));
				return NULL;
			}

			switch(in->type) {
			case ARPHRD_IPGRE:
				gre4_tunnel = netdev_priv(in);
				if (!gre4_tunnel) {
					dev_put(in);
					DEBUG_WARN("%px: failed to obtain node address for host. GREv4 tunnel not initialized\n", feci);
					return NULL;
				}
				ECM_NIN4_ADDR_TO_IP_ADDR(local_gre_tun_ip, gre4_tunnel->parms.iph.saddr);
				dev_put(in);
				in = ecm_interface_dev_find_by_local_addr(local_gre_tun_ip);
				if (!in) {
					DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(local_gre_tun_ip));
					return NULL;
				}
				break;

			case ARPHRD_IP6GRE:
				gre6_tunnel = netdev_priv(in);
				if (!gre6_tunnel) {
					dev_put(in);
					DEBUG_WARN("%px: failed to obtain node address for host. GREv6 tunnel not initialized\n", feci);
					return NULL;
				}
				ECM_NIN6_ADDR_TO_IP_ADDR(local_gre_tun_ip, gre6_tunnel->parms.laddr);
				dev_put(in);
				in = ecm_interface_dev_find_by_local_addr(local_gre_tun_ip);
				if (!in) {
					DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_OCTAL_FMT "\n", feci, ECM_IP_ADDR_TO_OCTAL(local_gre_tun_ip));
					return NULL;
				}
				break;

			default:
				DEBUG_TRACE("%px: establish node with physical netdev: %s\n", feci, in->name);
			}
			memcpy(node_addr, in->dev_addr, ETH_ALEN);
			dev_put(in);
			done = true;
			break;
#else
			DEBUG_TRACE("%px: GRE Tunnel interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			/*
			 * VLAN handled same along with ethernet, lag, bridge etc.
			 */
#else
			DEBUG_TRACE("%px: VLAN interface unsupported\n", feci);
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
#ifdef ECM_XFRM_ENABLE
			if (dst_xfrm(skb_dst(skb))) {
				ether_addr_copy(node_addr, dev->dev_addr);
				done = true;
				break;
			}

			if (secpath_exists(skb)) {
				in = dev_get_by_index(&init_net, skb->skb_iif);
				if (!in) {
					DEBUG_WARN("%px: failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));
					return NULL;
				}

				ether_addr_copy(node_addr, in->dev_addr);
				dev_put(in);
				done = true;
				break;
			}
#if __has_attribute(__fallthrough__)
			__attribute__((__fallthrough__));
#endif
#endif
		case ECM_DB_IFACE_TYPE_ETHERNET:
		case ECM_DB_IFACE_TYPE_LAG:
		case ECM_DB_IFACE_TYPE_BRIDGE:
#ifdef ECM_INTERFACE_OVS_BRIDGE_ENABLE
		case ECM_DB_IFACE_TYPE_OVS_BRIDGE:
#endif
			if (!ecm_interface_mac_addr_get_no_route(dev, addr, node_addr)) {
				ip_addr_t gw_addr = ECM_IP_ADDR_NULL;

				/*
				 * Try one more time with gateway ip address if it exists.
				 */
				if (!ecm_interface_find_gateway(addr, gw_addr)) {
					DEBUG_WARN("%px: Node establish failed, there is no gateway address for 2nd mac lookup try\n", feci);
					return NULL;
				}

				DEBUG_TRACE("%px: Have a gw address " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(gw_addr));

				if (ecm_interface_mac_addr_get_no_route(dev, gw_addr, node_addr)) {
					DEBUG_TRACE("%px: Found the mac address for gateway\n", feci);
					goto done;
				}

				ecm_interface_send_arp_request(dev, addr, false, gw_addr);

				DEBUG_WARN("%px: failed to obtain any node address for host " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));

				/*
				 * Unable to get node address at this time.
				 */
				return NULL;
			}
done:
			if (is_multicast_ether_addr(node_addr)) {
				DEBUG_TRACE("%px: multicast node address for host " ECM_IP_ADDR_DOT_FMT ", node_addr: %pM\n", feci, ECM_IP_ADDR_TO_DOT(addr), node_addr);
				return NULL;
			}

			/*
			 * Because we are iterating from inner to outer interface, this interface is the
			 * innermost one that has a node address - take this one.
			 */
			done = true;
			break;
		case ECM_DB_IFACE_TYPE_RAWIP:
#ifdef ECM_INTERFACE_RAWIP_ENABLE
			done = true;
			break;
#else
			DEBUG_TRACE("%px: RAWIP interface unsupported\n", feci);
			return NULL;
#endif
		case ECM_DB_IFACE_TYPE_OVPN:
#ifdef ECM_INTERFACE_OVPN_ENABLE
			done = true;
			break;
#else
			DEBUG_TRACE("%px: OVPN interface unsupported\n", feci);
			return NULL;
#endif
		case ECM_DB_IFACE_TYPE_VXLAN:
#ifdef ECM_INTERFACE_VXLAN_ENABLE
			local_dev = ecm_interface_dev_find_by_local_addr(addr);
			if (!local_dev) {
				DEBUG_WARN("%px: Failed to find local netdevice of VxLAN tunnel for " ECM_IP_ADDR_DOT_FMT "\n",
						feci, ECM_IP_ADDR_TO_DOT(addr));
				return NULL;
			}

			if (!ecm_interface_mac_addr_get_no_route(local_dev, addr, node_addr)) {
				DEBUG_WARN("%px: Couldn't find mac address for local dev\n", feci);
				dev_put(local_dev);
				return NULL;
			}
			DEBUG_TRACE("%px: Found the mac address for local dev\n", feci);
			dev_put(local_dev);
			done = true;
			break;
#else
			DEBUG_TRACE("%px: VXLAN interface unsupported\n", feci);
			return NULL;
#endif
		default:
			/*
			 * Don't know how to handle these.
			 * Just copy some part of the address for now, but keep iterating the interface list
			 * in the hope something recognisable will be seen!
			 * GGG TODO We really need to roll out support for all interface types we can deal with ASAP :-(
			 */
			memcpy(node_addr, (uint8_t *)addr, ETH_ALEN);
		}
	}
	if (!done) {
		DEBUG_WARN("%px: Failed to establish node for " ECM_IP_ADDR_DOT_FMT "\n", feci, ECM_IP_ADDR_TO_DOT(addr));
		return NULL;
	}

	/*
	 *  Establish iface
	 */
	ii = ecm_interface_establish_and_ref(feci, dev, skb);
	if (!ii) {
		DEBUG_WARN("%px: Failed to establish iface\n", feci);
		return NULL;
	}

	/*
	 * Locate the node
	 */
	ni = ecm_db_node_find_and_ref(node_addr, ii);
	if (ni) {
		DEBUG_TRACE("%px: node established: %px\n", feci, ni);
		ecm_db_iface_deref(ii);
		return ni;
	}

	/*
	 * No node - create one
	 */
	nni = ecm_db_node_alloc();
	if (!nni) {
		DEBUG_WARN("%px: Failed to establish node\n", feci);
		ecm_db_iface_deref(ii);
		return NULL;
	}

	/*
	 * Add node into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	ni = ecm_db_node_find_and_ref(node_addr, ii);
	if (ni) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		ecm_db_node_deref(nni);
		ecm_db_iface_deref(ii);
		return ni;
	}

	ecm_db_node_add(nni, ii, node_addr, NULL, nni);
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Don't need iface instance now
	 */
	ecm_db_iface_deref(ii);

	DEBUG_TRACE("%px: node (%px) established, node address: %pM\n", feci, nni, node_addr);
	return nni;
}

/*
 * ecm_nss_ipv4_host_establish_and_ref()
 *	Returns a reference to a host, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
struct ecm_db_host_instance *ecm_nss_ipv4_host_establish_and_ref(ip_addr_t addr)
{
	struct ecm_db_host_instance *hi;
	struct ecm_db_host_instance *nhi;

	DEBUG_INFO("Establish host for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));

	/*
	 * Locate the host
	 */
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		DEBUG_TRACE("%px: host established\n", hi);
		return hi;
	}

	/*
	 * No host - create one
	 */
	nhi = ecm_db_host_alloc();
	if (!nhi) {
		DEBUG_WARN("Failed to establish host\n");
		return NULL;
	}

	/*
	 * Add host into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		ecm_db_host_deref(nhi);
		return hi;
	}

	ecm_db_host_add(nhi, addr, true, NULL, nhi);

	spin_unlock_bh(&ecm_nss_ipv4_lock);

	DEBUG_TRACE("%px: host established\n", nhi);
	return nhi;
}

/*
 * ecm_nss_ipv4_mapping_establish_and_ref()
 *	Returns a reference to a mapping, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
struct ecm_db_mapping_instance *ecm_nss_ipv4_mapping_establish_and_ref(ip_addr_t addr, int port)
{
	struct ecm_db_mapping_instance *mi;
	struct ecm_db_mapping_instance *nmi;
	struct ecm_db_host_instance *hi;

	DEBUG_INFO("Establish mapping for " ECM_IP_ADDR_DOT_FMT ":%d\n", ECM_IP_ADDR_TO_DOT(addr), port);

	/*
	 * Locate the mapping
	 */
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		DEBUG_TRACE("%px: mapping established\n", mi);
		return mi;
	}

	/*
	 * No mapping - establish host existence
	 */
	hi = ecm_nss_ipv4_host_establish_and_ref(addr);
	if (!hi) {
		DEBUG_WARN("Failed to establish host\n");
		return NULL;
	}

	/*
	 * Create mapping instance
	 */
	nmi = ecm_db_mapping_alloc();
	if (!nmi) {
		ecm_db_host_deref(hi);
		DEBUG_WARN("Failed to establish mapping\n");
		return NULL;
	}

	/*
	 * Add mapping into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		ecm_db_mapping_deref(nmi);
		ecm_db_host_deref(hi);
		return mi;
	}

	ecm_db_mapping_add(nmi, hi, port, NULL, nmi);

	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Don't need the host instance now - the mapping maintains a reference to it now.
	 */
	ecm_db_host_deref(hi);

	/*
	 * Return the mapping instance
	 */
	DEBUG_INFO("%px: mapping established\n", nmi);
	return nmi;
}

/*
 * ecm_nss_ipv4_accel_done_time_update()
 *	Record how long the command took to complete, updating average samples
 */
void ecm_nss_ipv4_accel_done_time_update(struct ecm_front_end_connection_instance *feci)
{
	unsigned long delta;

	/*
	 * How long did it take the command to complete?
	 */
	spin_lock_bh(&feci->lock);
	feci->stats.cmd_time_completed = jiffies;
	delta = feci->stats.cmd_time_completed - feci->stats.cmd_time_begun;
	spin_unlock_bh(&feci->lock);

	spin_lock_bh(&ecm_nss_ipv4_lock);
	ecm_nss_ipv4_accel_cmd_time_avg_samples += delta;
	ecm_nss_ipv4_accel_cmd_time_avg_set++;
	spin_unlock_bh(&ecm_nss_ipv4_lock);
}

/*
 * ecm_nss_ipv4_deccel_done_time_update()
 *	Record how long the command took to complete, updating average samples
 */
void ecm_nss_ipv4_decel_done_time_update(struct ecm_front_end_connection_instance *feci)
{
	unsigned long delta;

	/*
	 * How long did it take the command to complete?
	 */
	spin_lock_bh(&feci->lock);
	feci->stats.cmd_time_completed = jiffies;
	delta = feci->stats.cmd_time_completed - feci->stats.cmd_time_begun;
	spin_unlock_bh(&feci->lock);

	spin_lock_bh(&ecm_nss_ipv4_lock);
	ecm_nss_ipv4_decel_cmd_time_avg_samples += delta;
	ecm_nss_ipv4_decel_cmd_time_avg_set++;
	spin_unlock_bh(&ecm_nss_ipv4_lock);
}

/*
 * ecm_nss_ipv4_connection_regenerate()
 *	Re-generate a connection.
 *
 * Re-generating a connection involves re-evaluating the interface lists in case interface heirarchies have changed.
 * It also involves the possible triggering of classifier re-evaluation but only if all currently assigned
 * classifiers permit this operation.
 */
void ecm_nss_ipv4_connection_regenerate(struct ecm_db_connection_instance *ci, ecm_tracker_sender_type_t sender,
							struct net_device *out_dev, struct net_device *out_dev_nat,
							struct net_device *in_dev, struct net_device *in_dev_nat,
							__be16 *layer4hdr, struct sk_buff *skb)
{
	int i;
	bool reclassify_allowed;
	int32_t to_list_first;
	struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t to_nat_list_first;
	struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t from_list_first;
	struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t from_nat_list_first;
	struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	ip_addr_t ip_src_addr;
	ip_addr_t ip_dest_addr;
	ip_addr_t ip_src_addr_nat;
	ip_addr_t ip_dest_addr_nat;
	int protocol;
	bool is_routed;
	uint8_t src_node_addr[ETH_ALEN];
	uint8_t dest_node_addr[ETH_ALEN];
	uint8_t src_node_addr_nat[ETH_ALEN];
	uint8_t dest_node_addr_nat[ETH_ALEN];
	int assignment_count;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_interface_construct_instance efeici;
	 ecm_db_direction_t ecm_dir;
	struct ecm_front_end_ovs_params *from_ovs_params = NULL;
	struct ecm_front_end_ovs_params *to_ovs_params = NULL;
	struct ecm_front_end_ovs_params *from_nat_ovs_params = NULL;
	struct ecm_front_end_ovs_params *to_nat_ovs_params = NULL;

	DEBUG_INFO("%px: re-gen needed\n", ci);

	/*
	 * We may need to swap the devices around depending on who the sender of the packet that triggered the re-gen is
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_DEST) {
		struct net_device *tmp_dev;

		/*
		 * This is a packet sent by the destination of the connection, i.e. it is a packet issued by the 'from' side of the connection.
		 */
		DEBUG_TRACE("%px: Re-gen swap devs\n", ci);
		tmp_dev = out_dev;
		out_dev = in_dev;
		in_dev = tmp_dev;

		tmp_dev = out_dev_nat;
		out_dev_nat = in_dev_nat;
		in_dev_nat = tmp_dev;
	}

	/*
	 * Update the interface lists - these may have changed, e.g. LAG path change etc.
	 * NOTE: We never have to change the usual mapping->host->node_iface arrangements for each side of the connection (to/from sides)
	 * This is because if these interfaces change then the connection is dead anyway.
	 * But a LAG slave might change the heirarchy the connection is using but the LAG master is still sane.
	 * If any of the new interface heirarchies cannot be created then simply set empty-lists as this will deny
	 * acceleration and ensure that a bad rule cannot be created.
	 * IMPORTANT: The 'sender' defines who has sent the packet that triggered this re-generation
	 */
	protocol = ecm_db_connection_protocol_get(ci);

	is_routed = ecm_db_connection_is_routed_get(ci);
	ecm_dir = ecm_db_connection_direction_get(ci);

	ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, ip_src_addr);
	ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM_NAT, ip_src_addr_nat);

	ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, ip_dest_addr);
	ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO_NAT, ip_dest_addr_nat);

	ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, src_node_addr);
	ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM_NAT, src_node_addr_nat);

	ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, dest_node_addr);
	ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO_NAT, dest_node_addr_nat);

	feci = ecm_db_connection_front_end_get_and_ref(ci);

	if (!ecm_front_end_ipv4_interface_construct_set_and_hold(skb, sender, ecm_dir, is_routed,
							in_dev, out_dev,
							ip_src_addr, ip_src_addr_nat,
							ip_dest_addr, ip_dest_addr_nat,
							&efeici)) {

		DEBUG_WARN("ECM front end ipv4 interface construct set failed for regeneration\n");
		goto ecm_ipv4_retry_regen;
	}

	if ((protocol == IPPROTO_TCP) || (protocol == IPPROTO_UDP)) {
		int src_port, src_port_nat, dest_port, dest_port_nat;
		struct ecm_front_end_ovs_params ovs_params[ECM_DB_OBJ_DIR_MAX];

		src_port = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_FROM);
		src_port_nat = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_FROM_NAT);
		dest_port = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_TO);
		dest_port_nat = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_TO_NAT);

		ecm_front_end_fill_ovs_params(ovs_params,
				      ip_src_addr, ip_src_addr_nat,
				      ip_dest_addr, ip_dest_addr_nat,
				      src_port, src_port_nat,
				      dest_port, dest_port_nat, ecm_dir);

		from_ovs_params = &ovs_params[ECM_DB_OBJ_DIR_FROM];
		to_ovs_params = &ovs_params[ECM_DB_OBJ_DIR_TO];
		from_nat_ovs_params = &ovs_params[ECM_DB_OBJ_DIR_FROM_NAT];
		to_nat_ovs_params = &ovs_params[ECM_DB_OBJ_DIR_TO_NAT];
	}

	DEBUG_TRACE("%px: Update the 'from' interface heirarchy list\n", ci);
	from_list_first = ecm_interface_heirarchy_construct(feci, from_list, efeici.from_dev, efeici.from_other_dev, ip_dest_addr, efeici.from_mac_lookup_ip_addr, ip_src_addr, 4, protocol, in_dev, is_routed, in_dev, src_node_addr, dest_node_addr, layer4hdr, skb, from_ovs_params);
	if (from_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		ecm_front_end_ipv4_interface_construct_netdev_put(&efeici);
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_interfaces_reset(ci, from_list, from_list_first, ECM_DB_OBJ_DIR_FROM);
	ecm_db_connection_interfaces_deref(from_list, from_list_first);

	DEBUG_TRACE("%px: Update the 'from NAT' interface heirarchy list\n", ci);
	if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
		from_nat_list_first = ecm_interface_heirarchy_construct(feci, from_nat_list, efeici.from_nat_dev, efeici.from_nat_other_dev, ip_dest_addr, efeici.from_nat_mac_lookup_ip_addr, ip_src_addr_nat, 4, protocol, in_dev, is_routed, in_dev, src_node_addr_nat, dest_node_addr_nat, layer4hdr, skb, from_nat_ovs_params);
	} else {
		from_nat_list_first = ecm_interface_heirarchy_construct(feci, from_nat_list, efeici.from_nat_dev, efeici.from_nat_other_dev, ip_dest_addr, efeici.from_nat_mac_lookup_ip_addr, ip_src_addr_nat, 4, protocol, in_dev_nat, is_routed, in_dev_nat, src_node_addr_nat, dest_node_addr_nat, layer4hdr, skb, from_nat_ovs_params);
	}

	if (from_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		ecm_front_end_ipv4_interface_construct_netdev_put(&efeici);
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_interfaces_reset(ci, from_nat_list, from_nat_list_first, ECM_DB_OBJ_DIR_FROM_NAT);
	ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

	DEBUG_TRACE("%px: Update the 'to' interface heirarchy list\n", ci);
	to_list_first = ecm_interface_heirarchy_construct(feci, to_list, efeici.to_dev, efeici.to_other_dev, ip_src_addr, efeici.to_mac_lookup_ip_addr, ip_dest_addr, 4, protocol, out_dev, is_routed, in_dev, dest_node_addr, src_node_addr, layer4hdr, skb, to_ovs_params);
	if (to_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		ecm_front_end_ipv4_interface_construct_netdev_put(&efeici);
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_interfaces_reset(ci, to_list, to_list_first, ECM_DB_OBJ_DIR_TO);
	ecm_db_connection_interfaces_deref(to_list, to_list_first);

	DEBUG_TRACE("%px: Update the 'to NAT' interface heirarchy list\n", ci);
	to_nat_list_first = ecm_interface_heirarchy_construct(feci, to_nat_list, efeici.to_nat_dev, efeici.to_nat_other_dev, ip_src_addr, efeici.to_nat_mac_lookup_ip_addr, ip_dest_addr_nat, 4, protocol, out_dev_nat, is_routed, in_dev, dest_node_addr_nat, src_node_addr_nat, layer4hdr, skb, to_nat_ovs_params);
	if (to_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		ecm_front_end_ipv4_interface_construct_netdev_put(&efeici);
		goto ecm_ipv4_retry_regen;
	}

	ecm_front_end_ipv4_interface_construct_netdev_put(&efeici);

	feci->deref(feci);
	ecm_db_connection_interfaces_reset(ci, to_nat_list, to_nat_list_first, ECM_DB_OBJ_DIR_TO_NAT);
	ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

	/*
	 * Get list of assigned classifiers to reclassify.
	 * Remember: This also includes our default classifier too.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);

	/*
	 * All of the assigned classifiers must permit reclassification.
	 */
	reclassify_allowed = true;
	for (i = 0; i < assignment_count; ++i) {
		DEBUG_TRACE("%px: Calling to reclassify: %px, type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
		if (!assignments[i]->reclassify_allowed(assignments[i])) {
			DEBUG_TRACE("%px: reclassify denied: %px, by type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
			reclassify_allowed = false;
			break;
		}
	}

	/*
	 * Now we action any classifier re-classify
	 */
	if (!reclassify_allowed) {
		/*
		 * Regeneration came to a successful conclusion even though reclassification was denied
		 */
		DEBUG_WARN("%px: re-classify denied\n", ci);
		goto ecm_ipv4_regen_done;
	}

	/*
	 * Reclassify
	 */
	DEBUG_INFO("%px: reclassify\n", ci);
	if (!ecm_classifier_reclassify(ci, assignment_count, assignments)) {
		/*
		 * We could not set up the classifiers to reclassify, it is safer to fail out and try again next time
		 */
		DEBUG_WARN("%px: Regeneration: reclassify failed\n", ci);
		goto ecm_ipv4_regen_done;
	}
	DEBUG_INFO("%px: reclassify success\n", ci);

ecm_ipv4_regen_done:

	/*
	 * Release the assignments
	 */
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Re-generation of state is successful.
	 */
	ecm_db_connection_regeneration_completed(ci);

	return;

ecm_ipv4_retry_regen:
	feci->deref(feci);
	ecm_db_connection_regeneration_failed(ci);
	return;
}

/*
 * ecm_nss_ipv4_ip_process()
 *	Process IP datagram skb
 */
static unsigned int ecm_nss_ipv4_ip_process(struct net_device *out_dev, struct net_device *in_dev,
							uint8_t *src_node_addr, uint8_t *dest_node_addr,
							bool can_accel, bool is_routed, bool is_l2_encap, struct sk_buff *skb, uint16_t l2_encap_proto)
{
	struct ecm_tracker_ip_header ip_hdr;
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	ecm_db_direction_t ecm_dir;
	ecm_tracker_sender_type_t sender;
	ip_addr_t ip_src_addr;
	ip_addr_t ip_dest_addr;
	ip_addr_t ip_src_addr_nat;
	ip_addr_t ip_dest_addr_nat;
	struct net_device *out_dev_nat;
	struct net_device *in_dev_nat;
	uint8_t *src_node_addr_nat;
	uint8_t *dest_node_addr_nat;
	uint8_t protonum;

	/*
	 * Obtain the IP header from the skb
	 */
	if (!ecm_tracker_ip_check_header_and_read(&ip_hdr, skb)) {
		DEBUG_WARN("Invalid ip header in skb %px\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Process only IPv4 packets
	 */
	if (!ip_hdr.is_v4) {
		DEBUG_TRACE("Not an IPv4 packet, skb %px\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * If the DSCP value of the packet maps to the NOT accel action type,
	 * do not accelerate the packet and let it go through the
	 * slow path.
	 */
	if (ip_hdr.protocol == IPPROTO_UDP) {
		uint8_t action = nss_ipv4_dscp_action_get(ip_hdr.dscp);
		if (action == NSS_IPV4_DSCP_MAP_ACTION_DONT_ACCEL) {
			DEBUG_TRACE("dscp: %d maps to action not accel type, skip acceleration\n", ip_hdr.dscp);
			return NF_ACCEPT;
		}
	}

	if (ip_hdr.fragmented) {
		DEBUG_TRACE("skb %px is fragmented\n", skb);
		return NF_ACCEPT;
	}

	if (ecm_nss_common_is_xfrm_flow(skb, &ip_hdr)) {
#ifdef ECM_XFRM_ENABLE
		struct net_device *ipsec_dev;
		int32_t interface_type;

		/* Check if the transformation for this flow
		 * is done by NSS. If yes, then only try to accelerate.
		 */
		ipsec_dev = ecm_interface_get_and_hold_ipsec_tun_netdev(NULL, skb, &interface_type);
		if (!ipsec_dev) {
			DEBUG_TRACE("%px xfrm flow not managed by NSS; skip it\n", skb);
			return NF_ACCEPT;
		}
		dev_put(ipsec_dev);
#else
		DEBUG_TRACE("%px xfrm flow, but accel is disabled; skip it\n", skb);
		return NF_ACCEPT;
#endif
	}

	/*
	 * Extract information, if we have conntrack then use that info as far as we can.
	 */
        ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("%px: no ct\n", skb);
		ECM_IP_ADDR_TO_NIN4_ADDR(orig_tuple.src.u3.ip, ip_hdr.src_addr);
		ECM_IP_ADDR_TO_NIN4_ADDR(orig_tuple.dst.u3.ip, ip_hdr.dest_addr);
		orig_tuple.dst.protonum = ip_hdr.protocol;
		reply_tuple.src.u3.ip = orig_tuple.dst.u3.ip;
		reply_tuple.dst.u3.ip = orig_tuple.src.u3.ip;
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		/*
		 * Fake untracked conntrack objects were removed on 4.12 kernel version
		 * and onwards.
		 * So, for the newer kernels, instead of comparing the ct with the percpu
		 * fake conntrack, we can check the ct status.
		 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0))
		if (unlikely(ct == nf_ct_untracked_get())) {
#else
		if (unlikely(ctinfo == IP_CT_UNTRACKED)) {
#endif
#ifdef ECM_INTERFACE_VXLAN_ENABLE
			/*
			 * If the conntrack connection is set as untracked,
			 * ECM will accept and process only VxLAN outer flows,
			 * otherwise such flows will not be processed by ECM.
			 *
			 * E.g. In the following network arramgement,
			 * Eth1 ---> Bridge ---> VxLAN0(Bridge Port) ---> Eth0(WAN)
			 * The packets from VxLAN0 to Eth0 will be routed.
			 *
			 * netif_is_vxlan API is used to identify the VxLAN device &
			 * is_routed flag is used to identify the outer flow.
			 */
			if (is_routed && netif_is_vxlan(in_dev)) {
				DEBUG_TRACE("%px: Untracked CT for VxLAN\n", skb);
				ECM_IP_ADDR_TO_NIN4_ADDR(orig_tuple.src.u3.ip, ip_hdr.src_addr);
				ECM_IP_ADDR_TO_NIN4_ADDR(orig_tuple.dst.u3.ip, ip_hdr.dest_addr);
				orig_tuple.dst.protonum = ip_hdr.protocol;
				reply_tuple.src.u3.ip = orig_tuple.dst.u3.ip;
				reply_tuple.dst.u3.ip = orig_tuple.src.u3.ip;
				sender = ECM_TRACKER_SENDER_TYPE_SRC;
				ct = NULL;
				goto vxlan_done;
			}
#endif
			DEBUG_TRACE("%px: ct: untracked\n", skb);
			return NF_ACCEPT;
		}

		/*
		 * If the conntrack connection is using a helper (i.e. Application Layer Gateway)
		 * then acceleration is denied (connection needs assistance from HLOS to function)
		 */
		if (nfct_help(ct)) {
			DEBUG_TRACE("%px: Connection has helper\n", ct);
			can_accel = false;
		}

		/*
		 * Extract conntrack connection information
		 */
		DEBUG_TRACE("%px: ct: %px, ctinfo: %x\n", skb, ct, ctinfo);
		orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		if (IP_CT_DIR_ORIGINAL == CTINFO2DIR(ctinfo)) {
			sender = ECM_TRACKER_SENDER_TYPE_SRC;
		} else {
			sender = ECM_TRACKER_SENDER_TYPE_DEST;
		}

		/*
		 * Is this a related connection?
		 */
		if ((ctinfo == IP_CT_RELATED) || (ctinfo == IP_CT_RELATED_REPLY)) {
			/*
			 * ct is related to the packet at hand.
			 * We can use the IP src/dest information and the direction information.
			 * We cannot use the protocol information from the ct (typically the packet at hand is ICMP error that is related to the ct we have here).
			 */
			orig_tuple.dst.protonum = ip_hdr.protocol;
			DEBUG_TRACE("%px: related ct, actual protocol: %u\n", skb, orig_tuple.dst.protonum);
		}
#ifdef ECM_INTERFACE_VXLAN_ENABLE
vxlan_done:
		;
#endif
	}

	/*
	 * Check if we can accelerate the GRE protocol.
	 */
	if (ip_hdr.protocol == IPPROTO_GRE) {
		if (!ecm_front_end_gre_proto_is_accel_allowed(in_dev, out_dev, skb, &orig_tuple, 4)) {
			DEBUG_WARN("%px: GRE protocol is not allowed\n", skb);
			return NF_ACCEPT;
		}
	}

	/*
	 * Check for a multicast Destination address here.
	 */
	ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
	if (ecm_ip_addr_is_multicast(ip_dest_addr)) {
#ifdef ECM_MULTICAST_ENABLE

		if (unlikely(ecm_front_end_ipv4_mc_stopped)) {
			DEBUG_TRACE("%px: Multicast disabled by ecm_front_end_ipv4_mc_stopped = %d\n", skb, ecm_front_end_ipv4_mc_stopped);
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%px: Multicast, Processing\n", skb);
		return ecm_nss_multicast_ipv4_connection_process(out_dev, in_dev, src_node_addr, dest_node_addr,
									can_accel, is_routed, skb, &ip_hdr, ct, sender,
									&orig_tuple, &reply_tuple);
#else
		return NF_ACCEPT;
#endif
	}

	/*
	 * Work out if this packet involves NAT or not.
	 * If it does involve NAT then work out if this is an ingressing or egressing packet.
	 */
	if (orig_tuple.src.u3.ip != reply_tuple.dst.u3.ip) {
		/*
		 * Egressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_EGRESS_NAT;
	} else if (orig_tuple.dst.u3.ip != reply_tuple.src.u3.ip) {
		/*
		 * Ingressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_INGRESS_NAT;
	} else if (is_routed) {
		/*
		 * Non-NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_NON_NAT;
	} else {
		/*
		 * Bridged
		 */
		ecm_dir = ECM_DB_DIRECTION_BRIDGED;
	}

	/*
	 * Is ecm_dir consistent with is_routed flag?
	 * In SNAT and hairpin NAT scenario, while accessing the LAN side server with its private
	 * IP address from another client in the same LAN, the packets come through the bridge post routing hook
	 * have the WAN interface IP address as the SNAT address. Then in the above ecm_dir calculation,
	 * it is calculated as ECM_DB_DIRECTION_EGRESS_NAT. So, we shouldn't accelerate the flow this time
	 * and wait for the packet to pass through the post routing hook.
	 *
	 */
	if (!is_routed && (ecm_dir != ECM_DB_DIRECTION_BRIDGED)) {
		DEBUG_TRACE("Packet comes from bridge post routing hook but ecm_dir is not bridge\n");
		return NF_ACCEPT;
	}

	/*
	 * If PPPoE bridged flows are to be handled with 3-tuple rule, set protocol to IPPROTO_RAW.
	 */
	protonum = orig_tuple.dst.protonum;

	if (unlikely(!is_routed && (l2_encap_proto == ETH_P_PPP_SES))) {
		/*
		 * Check if PPPoE bridge acceleration is 3-tuple based.
		 */
		if (nss_pppoe_get_br_accel_mode() == NSS_PPPOE_BR_ACCEL_MODE_EN_3T) {
			DEBUG_TRACE("3-tuple acceleration is enabled for PPPoE bridged flows\n");
			protonum = IPPROTO_RAW;
		}
	}

	DEBUG_TRACE("IP Packet ORIGINAL src: %pI4 ORIGINAL dst: %pI4 protocol: %u, sender: %d ecm_dir: %d\n",
			&orig_tuple.src.u3.ip, &orig_tuple.dst.u3.ip, protonum, sender, ecm_dir);

	/*
	 * Get IP addressing information.  This same logic is applied when extracting port information too.
	 * This is tricky to do as what we are after is src and destination addressing that is non-nat but we also need the nat information too.
	 * INGRESS connections have their conntrack information reversed!
	 * We have to keep in mind the connection direction AND the packet direction in order to be able to work out what is what.
	 *
	 * ip_src_addr and ip_dest_addr MUST always be the NON-NAT endpoint addresses and reflect PACKET direction and not connection direction 'dir'.
	 *
	 * Examples 1 through 4 cater for NAT and NON-NAT in the INGRESS or EGRESS cases.
	 *
	 * Example 1:
	 * An 'original' direction packet to an egress connection from br-lan:192.168.0.133:12345 to eth0:80.132.221.34:80 via NAT'ing router mapping eth0:10.10.10.30:33333 looks like:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_dest_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_dest_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_src_addr_nat
	 *
	 *	in_dev would be br-lan - i.e. the device of ip_src_addr
	 *	out_dev would be eth0 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. out_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC======BR-LAN___ETH0====X====WAN_PC
	 *
	 *	src_node_addr refers to node address of of ip_src_addr_nat
	 *	src_node_addr_nat is set to src_node_addr
	 *	src_node_addr is then set to NULL as there is no node address available here for ip_src_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is the node of ip_dest_addr_nat which is the same as dest_node_addr
	 *
	 * Example 2:
	 * However an 'original' direction packet to an ingress connection from eth0:80.132.221.34:3321 to a LAN host (e.g. via DMZ) br-lan@192.168.0.133:12345 via NAT'ing router mapping eth0:10.10.10.30:12345 looks like:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_src_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_dest_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_src_addr_nat
	 *
	 *	in_dev would be eth0 - i.e. the device of ip_src_addr
	 *	out_dev would be br-lan - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. in_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC===X===BR-LAN___ETH0========WAN_PC
	 *
	 *	src_node_addr refers to node address of br-lan which is not useful
	 *	src_node_addr_nat AND src_node_addr become NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to NULL
	 *
	 * When dealing with reply packets this confuses things even more.  Reply packets to the above two examples are as follows:
	 *
	 * Example 3:
	 * A 'reply' direction packet to the egress connection above:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_src_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_src_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be eth0 - i.e. the device of ip_src_addr
	 *	out_dev would be br-lan - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. in_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC===X===BR-LAN___ETH0========WAN_PC
	 *
	 *	src_node_addr refers to node address of br-lan which is not useful
	 *	src_node_addr_nat AND src_node_addr become NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to NULL
	 *
	 * Example 4:
	 * A 'reply' direction packet to the ingress connection above:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_dest_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_src_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be br-lan - i.e. the device of ip_src_addr
	 *	out_dev would be eth0 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. out_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC======BR-LAN___ETH0====X====WAN_PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr_nat
	 *	src_node_addr_nat is set to src_node_addr
	 *	src_node_addr becomes NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr also.
	 *
	 * The following examples are for BRIDGED cases:
	 *
	 * Example 5:
	 * An 'original' direction packet to an bridged connection from eth1:192.168.0.133:12345 to eth2:192.168.0.244:80 looks like:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	orig_tuple->dst == 192.168.0.244:80		This becomes ip_dest_addr
	 *	reply_tuple->src == 192.168.0.244:80		This becomes ip_dest_addr_nat
	 *	reply_tuple->dest == 192.168.0.133:12345	This becomes ip_src_addr_nat
	 *
	 *	in_dev would be eth1 - i.e. the device of ip_src_addr
	 *	out_dev would be eth2 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth1 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth2 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN PC======ETH1___ETH2====X====LAN PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr
	 *	src_node_addr_nat is set to src_node_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr
	 *
	 * Example 6:
	 * An 'reply' direction packet to the bridged connection above:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	orig_tuple->dst == 192.168.0.244:80		This becomes ip_src_addr
	 *	reply_tuple->src == 192.168.0.244:80		This becomes ip_src_addr_nat
	 *	reply_tuple->dest == 192.168.0.133:12345	This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be eth2 - i.e. the device of ip_src_addr
	 *	out_dev would be eth1 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth2 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth1 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN PC===X===ETH1___ETH2========LAN PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr
	 *	src_node_addr_nat is set to src_node_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			/*
			 * Example 1
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = out_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;
			src_node_addr = NULL;

			dest_node_addr_nat = dest_node_addr;
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			/*
			 * Example 2
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = in_dev;
			out_dev_nat = in_dev;

			src_node_addr = NULL;
			src_node_addr_nat = NULL;

			dest_node_addr_nat = NULL;
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			/*
			 * Example 5
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = in_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;

			dest_node_addr_nat = dest_node_addr;
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	} else {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			/*
			 * Example 3
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat  = in_dev;
			out_dev_nat = in_dev;

			src_node_addr = NULL;
			src_node_addr_nat = NULL;

			dest_node_addr_nat = NULL;
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			/*
			 * Example 4
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = out_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;
			src_node_addr = NULL;

			dest_node_addr_nat = dest_node_addr;
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			/*
			 * Example 6
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat  = in_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;

			dest_node_addr_nat = dest_node_addr;
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	}

	/*
	 * Non-unicast source or destination packets are ignored
	 * NOTE: Only need to check the non-nat src/dest addresses here.
	 */
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_dest_addr))) {
		DEBUG_TRACE("skb %px non-unicast daddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_dest_addr));
		return NF_ACCEPT;
	}
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_src_addr))) {
		DEBUG_TRACE("skb %px non-unicast saddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_src_addr));
		return NF_ACCEPT;
	}

	/*
	 * Process IP specific protocol
	 * TCP and UDP are the most likliest protocols.
	 */
	if (likely(protonum == IPPROTO_TCP) || likely(protonum == IPPROTO_UDP)) {
		return ecm_nss_ported_ipv4_process(out_dev, out_dev_nat,
				in_dev, in_dev_nat,
				src_node_addr, src_node_addr_nat,
				dest_node_addr, dest_node_addr_nat,
				can_accel, is_routed, is_l2_encap, skb,
				&ip_hdr,
				ct, sender, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat, l2_encap_proto);
	}
#ifdef ECM_NON_PORTED_SUPPORT_ENABLE
	return ecm_nss_non_ported_ipv4_process(out_dev, out_dev_nat,
				in_dev, in_dev_nat,
				src_node_addr, src_node_addr_nat,
				dest_node_addr, dest_node_addr_nat,
				can_accel, is_routed, is_l2_encap, skb,
				&ip_hdr,
				ct, sender, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat, l2_encap_proto);
#else
	return NF_ACCEPT;
#endif
}

/*
 * ecm_nss_ipv4_post_routing_hook()
 *	Called for IP packets that are going out to interfaces after IP routing stage.
 */
static unsigned int ecm_nss_ipv4_post_routing_hook(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *nhs)
{
	struct net_device *out = nhs->out;
	struct net_device *in;
	bool can_accel = true;
	unsigned int result;

	DEBUG_TRACE("%px: Routing: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		DEBUG_TRACE("Broadcast, ignoring: %px\n", skb);
		return NF_ACCEPT;
	}

#ifndef ECM_INTERFACE_PPTP_ENABLE
	/*
	 * skip pptp because we don't accelerate them
	 */
	if (ecm_interface_is_pptp(skb, out)) {
		return NF_ACCEPT;
	}
#endif

#ifndef ECM_INTERFACE_L2TPV2_ENABLE
	/*
	 * skip l2tpv2 because we don't accelerate them
	 */
	if (ecm_interface_is_l2tp_packet_by_version(skb, out, 2)) {
		return NF_ACCEPT;
	}
#endif

	/*
	 * skip l2tpv3 because we don't accelerate them
	 */
	if (ecm_interface_is_l2tp_packet_by_version(skb, out, 3)) {
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		/*
		 * Locally sourced packets are not processed in ECM.
		 */
		return NF_ACCEPT;
	}

#ifndef ECM_INTERFACE_OVS_BRIDGE_ENABLE
	/*
	 * skip OpenVSwitch flows because we don't accelerate them
	 */
	if (netif_is_ovs_master(out) || netif_is_ovs_master(in)) {
		dev_put(in);
		return NF_ACCEPT;
	}
#endif

	DEBUG_TRACE("Post routing process skb %px, out: %px (%s), in: %px (%s)\n", skb, out, out->name, in, in->name);
	result = ecm_nss_ipv4_ip_process((struct net_device *)out, in, NULL, NULL,
							can_accel, true, false, skb, 0);
	dev_put(in);
	return result;
}

/*
 * ecm_front_end_ipv4_pppoe_bridge_process()
 *	Called for PPPoE session packets that are going
 *	out to one of the bridge physical interfaces.
 */
static unsigned int ecm_front_end_ipv4_pppoe_bridge_process(struct net_device *out,
						     struct net_device *in,
						     struct ethhdr *skb_eth_hdr,
						     bool can_accel,
						     struct sk_buff *skb)
{
	struct ecm_tracker_ip_header ip_hdr;
	unsigned int result = NF_ACCEPT;
	struct pppoe_hdr *ph = pppoe_hdr(skb);
	uint16_t ppp_proto = *(uint16_t *)ph->tag;
	uint32_t encap_header_len = 0;

	ppp_proto = ntohs(ppp_proto);
	if (ppp_proto != PPP_IP) {
		return NF_ACCEPT;
	}

	encap_header_len = ecm_front_end_l2_encap_header_len(ntohs(skb->protocol));
	ecm_front_end_pull_l2_encap_header(skb, encap_header_len);
	skb->protocol = htons(ETH_P_IP);

	if (!ecm_tracker_ip_check_header_and_read(&ip_hdr, skb)) {
		DEBUG_WARN("Invalid ip header in skb %px\n", skb);
		goto skip_ipv4_process;
	}

	/*
	 * Return if destination IP address is multicast address.
	 */
	if (ecm_ip_addr_is_multicast(ip_hdr.dest_addr)) {
		DEBUG_WARN("Multicast acceleration is not support in PPPoE bridge %px\n", skb);
		goto skip_ipv4_process;
	}

	result = ecm_nss_ipv4_ip_process(out, in, skb_eth_hdr->h_source,
					 skb_eth_hdr->h_dest, can_accel,
					 false, true, skb, ETH_P_PPP_SES);
skip_ipv4_process:
	ecm_front_end_push_l2_encap_header(skb, encap_header_len);
	skb->protocol = htons(ETH_P_PPP_SES);

	return result;
}

/*
 * ecm_nss_ipv4_bridge_post_routing_hook()
 *	Called for packets that are going out to one of the bridge physical interfaces.
 *
 * These may have come from another bridged interface or from a non-bridged interface.
 * Conntrack information may be available or not if this skb is bridged.
 */
static unsigned int ecm_nss_ipv4_bridge_post_routing_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *nhs)
{
	struct net_device *out = nhs->out;
	struct ethhdr *skb_eth_hdr;
	uint16_t eth_type;
	struct net_device *bridge;
	struct net_device *in;
	bool can_accel = true;
	unsigned int result = NF_ACCEPT;

	DEBUG_TRACE("%px: Bridge: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		DEBUG_TRACE("Broadcast, ignoring: %px\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * skip l2tp/pptp because we don't accelerate them
	 */
	if (ecm_interface_is_l2tp_pptp(skb, out)) {
		return NF_ACCEPT;
	}

	/*
	 * Check packet is an IP Ethernet packet
	 */
	skb_eth_hdr = eth_hdr(skb);
	if (!skb_eth_hdr) {
		DEBUG_TRACE("%px: Not Eth\n", skb);
		return NF_ACCEPT;
	}
	eth_type = ntohs(skb_eth_hdr->h_proto);
	if (unlikely((eth_type != 0x0800) && (eth_type != ETH_P_PPP_SES))) {
		DEBUG_TRACE("%px: Not IP/PPPoE session: %d\n", skb, eth_type);
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came.
	 * There are three scenarios to consider here:
	 * 1. Packet came from a local source.
	 *	Ignore - local is not handled.
	 * 2. Packet came from a routed path.
	 *	Ignore - it was handled in INET post routing.
	 * 3. Packet is bridged from another port.
	 *	Process.
	 *
	 * Begin by identifying case 1.
	 * NOTE: We are given 'out' (which we implicitly know is a bridge port) so out interface's master is the 'bridge'.
	 */
	bridge = ecm_interface_get_and_hold_dev_master((struct net_device *)out);
	DEBUG_ASSERT(bridge, "Expected bridge\n");
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if  (!in) {
		/*
		 * Case 1.
		 */
		DEBUG_TRACE("Local traffic: %px, ignoring traffic to bridge: %px (%s) \n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}
	dev_put(in);

	/*
	 * Case 2:
	 *	For routed packets the skb will have the src mac matching the bridge mac.
	 * Case 3:
	 *	If the packet was not local (case 1) or routed (case 2) then
	 *	we process. There is an exception to case 2: when hairpin mode
	 *	is enabled, we process.
	 */

	/*
	 * Pass in NULL (for skb) and 0 for cookie since doing FDB lookup only
	 */
	in = br_port_dev_get(bridge, skb_eth_hdr->h_source, NULL, 0);
	if (!in) {
		DEBUG_TRACE("skb: %px, no in device for bridge: %px (%s)\n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}

	/*
	 * This flag needs to be checked in slave port(eth0/ath0)
	 * and not on master interface(br-lan). Hairpin flag can be
	 * enabled/disabled for ports individually.
	 */
	if (in == out) {
		if (!br_is_hairpin_enabled(in)) {
			DEBUG_TRACE("skb: %px, bridge: %px (%s), ignoring"
					"the packet, hairpin not enabled"
					"on port %px (%s)\n", skb, bridge,
					bridge->name, out, out->name);
			goto skip_ipv4_bridge_flow;
		}
		DEBUG_TRACE("skb: %px, bridge: %px (%s), hairpin enabled on port"
				"%px (%s)\n", skb, bridge, bridge->name, out, out->name);
	}

	/*
	 * Case 2: Routed trafffic would be handled by the INET post routing.
	 */
	if (!ecm_mac_addr_equal(skb_eth_hdr->h_source, bridge->dev_addr)) {
		DEBUG_TRACE("skb: %px, Ignoring routed packet to bridge: %px (%s)\n", skb, bridge, bridge->name);
		goto skip_ipv4_bridge_flow;
	}

	if (!is_multicast_ether_addr(skb_eth_hdr->h_dest)) {
		/*
		 * Process the packet, if we have this mac address in the fdb table.
		 * TODO: For the kernel versions later than 3.6.x, the API needs vlan id.
		 * 	 For now, we are passing 0, but this needs to be handled later.
		 */
		if (!br_fdb_has_entry((struct net_device *)out, skb_eth_hdr->h_dest, 0)) {
			DEBUG_WARN("skb: %px, No fdb entry for this mac address %pM in the bridge: %px (%s)\n",
					skb, skb_eth_hdr->h_dest, bridge, bridge->name);
			goto skip_ipv4_bridge_flow;
		}
	}
	DEBUG_TRACE("Bridge process skb: %px, bridge: %px (%s), In: %px (%s), Out: %px (%s)\n",
			skb, bridge, bridge->name, in, in->name, out, out->name);

	if (unlikely(eth_type != 0x0800)) {
		/*
		 * Check if PPPoE bridge acceleration is disabled.
		 */
		if (nss_pppoe_get_br_accel_mode() == NSS_PPPOE_BR_ACCEL_MODE_DIS) {
			DEBUG_TRACE("skb: %px, PPPoE bridge flow acceleration is disabled\n", skb);
			goto skip_ipv4_bridge_flow;
		}

		result = ecm_front_end_ipv4_pppoe_bridge_process((struct net_device *)out, in, skb_eth_hdr, can_accel, skb);
		goto skip_ipv4_bridge_flow;
	}

	result = ecm_nss_ipv4_ip_process((struct net_device *)out, in,
				skb_eth_hdr->h_source, skb_eth_hdr->h_dest, can_accel, false, false, skb, 0);
skip_ipv4_bridge_flow:
	dev_put(in);
	dev_put(bridge);
	return result;
}

#ifdef ECM_INTERFACE_OVS_BRIDGE_ENABLE
/*
 * ecm_nss_ipv4_ovs_dp_process()
 *      Process OVS IPv4 bridged packets.
 */
unsigned int ecm_nss_ipv4_ovs_dp_process(struct sk_buff *skb, struct net_device *out)
{
	struct ethhdr *skb_eth_hdr;
	bool can_accel = true;
	struct net_device *in;

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return 1;
	}
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Don't process broadcast.
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		DEBUG_TRACE("Broadcast, ignoring: %px\n", skb);
		return 1;
	}

	if (skb->protocol != ntohs(ETH_P_IP)) {
		DEBUG_WARN("%px: Wrong skb protocol: %d", skb, skb->protocol);
		return 1;
	}

        skb_eth_hdr = eth_hdr(skb);
        if (!skb_eth_hdr) {
                DEBUG_WARN("%px: Not Eth\n", skb);
                return 1;
        }

        in = dev_get_by_index(&init_net, skb->skb_iif);
        if (!in) {
                DEBUG_WARN("%px: No in device\n", skb);
                return 1;
        }

        DEBUG_TRACE("%px: in: %s out: %s skb->protocol: %x\n", skb, in->name, out->name, skb->protocol);

	if (netif_is_ovs_master(in)) {
		if (!ecm_mac_addr_equal(skb_eth_hdr->h_dest, in->dev_addr)) {
			DEBUG_TRACE("%px: in is bridge and mac address equals to packet dest, flow is routed, ignore \n", skb);
			dev_put(in);
			return 1;
		}
	}

	if (netif_is_ovs_master(out)) {
		if (!ecm_mac_addr_equal(skb_eth_hdr->h_source, out->dev_addr)) {
			DEBUG_TRACE("%px: out is bridge and mac address equals to packet source, flow is routed, ignore \n", skb);
			dev_put(in);
			return 1;
		}
	}

        ecm_nss_ipv4_ip_process((struct net_device *)out, in,
                                skb_eth_hdr->h_source, skb_eth_hdr->h_dest, can_accel, false, false, skb, ETH_P_IP);

        dev_put(in);

        return 0;
}

static struct ovsmgr_dp_hook_ops ecm_nss_ipv4_dp_hooks = {
	.protocol = 4,
	.hook_num = OVSMGR_DP_HOOK_POST_FLOW_PROC,
	.hook = ecm_nss_ipv4_ovs_dp_process,
};
#endif

/*
 * ecm_nss_ipv4_process_one_conn_sync_msg()
 *	Process one connection sync message.
 */
static inline void ecm_nss_ipv4_process_one_conn_sync_msg(struct nss_ipv4_conn_sync *sync)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	struct nf_conn_counter *acct;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct neighbour *neigh;
	ip_addr_t flow_ip;
	ip_addr_t return_ip_xlate;
	ip_addr_t return_ip;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	int flow_ident;
	int return_ident_xlate;
	struct ecm_classifier_rule_sync class_sync;
	int flow_dir;
	int return_dir;
	unsigned long int delta_jiffies;
	int elapsed;

	/*
	 * Look up ecm connection with a view to synchronising the connection, classifier and data tracker.
	 * Note that we use _xlate versions for destination - for egressing connections this would be the wan IP address,
	 * but for ingressing this would be the LAN side (non-nat'ed) address and is what we need for lookup of our connection.
	 */
	DEBUG_INFO("%px: NSS Sync, lookup connection using\n"
			"Protocol: %d\n" \
			"src_addr: %pI4h:%d\n" \
			"dest_addr: %pI4h:%d\n",
			sync,
			(int)sync->protocol,
			&sync->flow_ip, (int)sync->flow_ident,
			&sync->return_ip_xlate, (int)sync->return_ident_xlate);

	ECM_HIN4_ADDR_TO_IP_ADDR(flow_ip, sync->flow_ip);
	ECM_HIN4_ADDR_TO_IP_ADDR(return_ip_xlate, sync->return_ip_xlate);
	ECM_HIN4_ADDR_TO_IP_ADDR(return_ip, sync->return_ip);
	flow_ident = (int)sync->flow_ident;
	return_ident_xlate = (int)sync->return_ident_xlate;

	/*
	 * GRE connections such as PPTP-GRE are stored into the db using a 3 tuple based hash.
	 * So we ignore the port information here when trying to lookup the connection
	 */
	if (sync->protocol == IPPROTO_GRE) {
		flow_ident = 0;
		return_ident_xlate = 0;
	}
#ifdef ECM_MULTICAST_ENABLE
	/*
	 * Check for multicast flow
	 */
	if (ecm_ip_addr_is_multicast(return_ip)) {
		ci = ecm_db_connection_find_and_ref(flow_ip, return_ip, sync->protocol, flow_ident, (int)sync->return_ident);
	} else {
		ci = ecm_db_connection_find_and_ref(flow_ip, return_ip_xlate, sync->protocol, flow_ident, return_ident_xlate);
	}
#else
	ci = ecm_db_connection_find_and_ref(flow_ip, return_ip_xlate, sync->protocol, flow_ident, return_ident_xlate);
#endif
	if (!ci) {
		DEBUG_TRACE("%px: NSS Sync: no connection\n", sync);
		return;
	}

	DEBUG_TRACE("%px: Sync conn %px\n", sync, ci);

	/*
	 * Copy the sync data to the classifier sync structure to
	 * update the classifiers' stats.
	 */
	class_sync.tx_packet_count[ECM_CONN_DIR_FLOW] = sync->flow_tx_packet_count;
	class_sync.tx_byte_count[ECM_CONN_DIR_FLOW] = sync->flow_tx_byte_count;
	class_sync.rx_packet_count[ECM_CONN_DIR_FLOW] = sync->flow_rx_packet_count;
	class_sync.rx_byte_count[ECM_CONN_DIR_FLOW] = sync->flow_rx_byte_count;
	class_sync.tx_packet_count[ECM_CONN_DIR_RETURN] = sync->return_tx_packet_count;
	class_sync.tx_byte_count[ECM_CONN_DIR_RETURN] = sync->return_tx_byte_count;
	class_sync.rx_packet_count[ECM_CONN_DIR_RETURN] = sync->return_rx_packet_count;
	class_sync.rx_byte_count[ECM_CONN_DIR_RETURN] = sync->return_rx_byte_count;
	class_sync.reason = sync->reason;

	/*
	 * Sync assigned classifiers
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;
		aci = assignments[aci_index];
		DEBUG_TRACE("%px: sync to: %px, type: %d\n", ci, aci, aci->type_get(aci));
		aci->sync_to_v4(aci, &class_sync);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Get the elapsed time since the last sync and add this elapsed time
	 * to the conntrack's timeout while updating it. If the return value is
	 * a negative value which means the timer is not in a valid state, just
	 * return here and do not update the defunct timer and the conntrack.
	 */
	elapsed = ecm_db_connection_elapsed_defunct_timer(ci);
	if (elapsed < 0) {
		ecm_db_connection_deref(ci);
		return;
	}
	DEBUG_TRACE("%px: elapsed: %d\n", ci, elapsed);
	delta_jiffies = elapsed * HZ;

	/*
	 * Keep connection alive and updated
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		goto sync_conntrack;
	}

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);

	if (sync->flow_tx_packet_count || sync->return_tx_packet_count) {
		DEBUG_TRACE("%px: flow_rx_packet_count: %u, flow_rx_byte_count: %u, return_rx_packet_count: %u, return_rx_byte_count: %u\n",
				ci, sync->flow_rx_packet_count, sync->flow_rx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);
		DEBUG_TRACE("%px: flow_tx_packet_count: %u, flow_tx_byte_count: %u, return_tx_packet_count: %u, return_tx_byte_count: %u\n",
				ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->return_tx_packet_count, sync->return_tx_byte_count);
#ifdef ECM_MULTICAST_ENABLE
		if (ecm_ip_addr_is_multicast(return_ip)) {
			/*
			 * The amount of data *sent* by the ECM multicast connection 'from' side is the amount the NSS has *received* in the 'flow' direction.
			 */
			ecm_db_multicast_connection_data_totals_update(ci, true, sync->flow_rx_byte_count, sync->flow_rx_packet_count);
			ecm_db_multicast_connection_data_totals_update(ci, false, sync->return_rx_byte_count, sync->return_rx_packet_count);
			ecm_db_multicast_connection_interface_heirarchy_stats_update(ci, sync->flow_rx_byte_count, sync->flow_rx_packet_count);

			/*
			 * As packets have been accelerated we have seen some action.
			 */
			feci->action_seen(feci);

			/*
			 * Update interface statistics
			 */
			ecm_interface_multicast_stats_update(ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->flow_rx_packet_count, sync->flow_rx_byte_count,
										sync->return_tx_packet_count, sync->return_tx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);
			/*
			 * Update IP multicast routing cache stats
			 */
			ipmr_mfc_stats_update(&init_net, htonl(flow_ip[0]), htonl(return_ip[0]), sync->flow_rx_packet_count,
										 sync->flow_rx_byte_count, sync->flow_rx_packet_count, sync->flow_rx_byte_count);
		} else {
			/*
			 * The amount of data *sent* by the ECM connection 'from' side is the amount the NSS has *received* in the 'flow' direction.
			 */
			ecm_db_connection_data_totals_update(ci, true, sync->flow_rx_byte_count, sync->flow_rx_packet_count);

			/*
			 * The amount of data *sent* by the ECM connection 'to' side is the amount the NSS has *received* in the 'return' direction.
			 */
			ecm_db_connection_data_totals_update(ci, false, sync->return_rx_byte_count, sync->return_rx_packet_count);

			/*
			 * As packets have been accelerated we have seen some action.
			 */
			feci->action_seen(feci);

			/*
			 * Update interface statistics
			 */
			ecm_interface_stats_update(ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->flow_rx_packet_count, sync->flow_rx_byte_count,
							sync->return_tx_packet_count, sync->return_tx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);
		}

#else
		/*
		 * The amount of data *sent* by the ECM connection 'from' side is the amount the NSS has *received* in the 'flow' direction.
		 */
		ecm_db_connection_data_totals_update(ci, true, sync->flow_rx_byte_count, sync->flow_rx_packet_count);

		/*
		 * The amount of data *sent* by the ECM connection 'to' side is the amount the NSS has *received* in the 'return' direction.
		 */
		ecm_db_connection_data_totals_update(ci, false, sync->return_rx_byte_count, sync->return_rx_packet_count);

		/*
		 * As packets have been accelerated we have seen some action.
		 */
		feci->action_seen(feci);

		/*
		 * Update interface statistics
		 */
		ecm_interface_stats_update(ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->flow_rx_packet_count, sync->flow_rx_byte_count,
						sync->return_tx_packet_count, sync->return_tx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);
#endif
	}

	switch(sync->reason) {
	case NSS_IPV4_RULE_SYNC_REASON_DESTROY:
		/*
		 * This is the final sync from the NSS for a connection whose acceleration was
		 * terminated by the ecm.
		 * NOTE: We take no action here since that is performed by the destroy message ack.
		 */
		DEBUG_INFO("%px: ECM initiated final sync seen: %d\n", ci, sync->reason);
		break;
	case NSS_IPV4_RULE_SYNC_REASON_FLUSH:
	case NSS_IPV4_RULE_SYNC_REASON_EVICT:
		/*
		 * NSS has ended acceleration without instruction from the ECM.
		 */
		DEBUG_INFO("%px: NSS Initiated final sync seen: %d cause:%d\n", ci, sync->reason, sync->cause);

		/*
		 * NSS Decelerated the connection
		 */
		feci->accel_ceased(feci);
		break;
	default:
		if (ecm_db_connection_is_routed_get(ci)) {
			/*
			 * Update the neighbour entry for source IP address
			 */
			neigh = ecm_interface_ipv4_neigh_get(flow_ip);
			if (!neigh) {
				DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->flow_ip);
			} else {
				if (sync->flow_tx_packet_count) {
					DEBUG_TRACE("Neighbour entry event send for %pI4h: %px\n", &sync->flow_ip, neigh);
					neigh_event_send(neigh, NULL);
				}

				neigh_release(neigh);
			}

#ifdef ECM_MULTICAST_ENABLE
			/*
			 * Update the neighbour entry for destination IP address
			 */
			if (!ecm_ip_addr_is_multicast(return_ip)) {
				neigh = ecm_interface_ipv4_neigh_get(return_ip);
				if (!neigh) {
					DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->return_ip);
				} else {
					if (sync->return_tx_packet_count) {
						DEBUG_TRACE("Neighbour entry event send for %pI4h: %px\n", &sync->return_ip, neigh);
						neigh_event_send(neigh, NULL);
					}

					neigh_release(neigh);
				}
			}
#else
			/*
			 * Update the neighbour entry for destination IP address
			 */
			neigh = ecm_interface_ipv4_neigh_get(return_ip);
			if (!neigh) {
				DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->return_ip);
			} else {
				if (sync->return_tx_packet_count) {
					DEBUG_TRACE("Neighbour entry event send for %pI4h: %px\n", &sync->return_ip, neigh);
					neigh_event_send(neigh, NULL);
				}

				neigh_release(neigh);
			}
#endif
		}
	}

	/*
	 * If connection should be re-generated then we need to force a deceleration
	 */
	if (unlikely(ecm_db_connection_regeneration_required_peek(ci))) {
		DEBUG_TRACE("%px: Connection generation changing, terminating acceleration", ci);
		feci->decelerate(feci);
	}

	feci->deref(feci);
	ecm_db_connection_deref(ci);

sync_conntrack:
	;

	/*
	 * Create a tuple so as to be able to look up a conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(sync->flow_ip);
	tuple.src.u.all = (__be16)htons(sync->flow_ident);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(sync->return_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)sync->protocol;
	tuple.dst.u.all = (__be16)htons(sync->return_ident);

	DEBUG_TRACE("Conntrack sync, lookup conntrack connection using\n"
			"Protocol: %d\n"
			"src_addr: %pI4:%d\n"
			"dest_addr: %pI4:%d\n",
			(int)tuple.dst.protonum,
			&tuple.src.u3.ip, (int)(ntohs(tuple.src.u.all)),
			&tuple.dst.u3.ip, (int)(ntohs(tuple.dst.u.all)));

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
	if (!h) {
		DEBUG_WARN("%px: NSS Sync: no conntrack connection\n", sync);
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
#endif
	DEBUG_TRACE("%px: NSS Sync: conntrack connection\n", ct);

	ecm_front_end_flow_and_return_directions_get(ct, flow_ip, 4, &flow_dir, &return_dir);

	/*
	 * Only update if this is not a fixed timeout
	 * delta_jiffies is the elapsed time since the last sync of this connection.
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		spin_lock_bh(&ct->lock);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
		ct->timeout.expires += delta_jiffies;
#else
		ct->timeout += delta_jiffies;
#endif
		spin_unlock_bh(&ct->lock);
	}

	acct = nf_conn_acct_find(ct)->counter;
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_add(sync->flow_rx_packet_count, &acct[flow_dir].packets);
		atomic64_add(sync->flow_rx_byte_count, &acct[flow_dir].bytes);

		atomic64_add(sync->return_rx_packet_count, &acct[return_dir].packets);
		atomic64_add(sync->return_rx_byte_count, &acct[return_dir].bytes);
		spin_unlock_bh(&ct->lock);
	}

	switch (sync->protocol) {
	case IPPROTO_TCP:
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.seen[flow_dir].td_maxwin < sync->flow_max_window) {
			ct->proto.tcp.seen[flow_dir].td_maxwin = sync->flow_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[flow_dir].td_end - sync->flow_end) < 0) {
			ct->proto.tcp.seen[flow_dir].td_end = sync->flow_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[flow_dir].td_maxend - sync->flow_max_end) < 0) {
			ct->proto.tcp.seen[flow_dir].td_maxend = sync->flow_max_end;
		}
		if (ct->proto.tcp.seen[return_dir].td_maxwin < sync->return_max_window) {
			ct->proto.tcp.seen[return_dir].td_maxwin = sync->return_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[return_dir].td_end - sync->return_end) < 0) {
			ct->proto.tcp.seen[return_dir].td_end = sync->return_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[return_dir].td_maxend - sync->return_max_end) < 0) {
			ct->proto.tcp.seen[return_dir].td_maxend = sync->return_max_end;
		}
		spin_unlock_bh(&ct->lock);
		break;
	case IPPROTO_UDP:
		/*
		 * In Linux connection track, UDP flow has two timeout values:
		 * /proc/sys/net/netfilter/nf_conntrack_udp_timeout:
		 * 	this is for uni-direction UDP flow, normally its value is 60 seconds
		 * /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream:
		 * 	this is for bi-direction UDP flow, normally its value is 180 seconds
		 *
		 * Linux will update timer of UDP flow to stream timeout once it seen packets
		 * in reply direction. But if flow is accelerated by NSS or SFE, Linux won't
		 * see any packets. So we have to do the same thing in our stats sync message.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status) && acct) {
			u_int64_t reply_pkts = atomic64_read(&acct[IP_CT_DIR_REPLY].packets);

			if (reply_pkts != 0) {
				struct nf_conntrack_l4proto *l4proto __maybe_unused;
				unsigned int *timeouts;

				set_bit(IPS_SEEN_REPLY_BIT, &ct->status);
				set_bit(IPS_ASSURED_BIT, &ct->status);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
				l4proto = __nf_ct_l4proto_find(AF_INET, IPPROTO_UDP);
				timeouts = nf_ct_timeout_lookup(&init_net, ct, l4proto);

				spin_lock_bh(&ct->lock);
				ct->timeout.expires = jiffies + timeouts[UDP_CT_REPLIED];
				spin_unlock_bh(&ct->lock);
#else
				timeouts = nf_ct_timeout_lookup(ct);
				if (!timeouts) {
					timeouts = udp_get_timeouts(nf_ct_net(ct));
				}

				spin_lock_bh(&ct->lock);
				ct->timeout = jiffies + timeouts[UDP_CT_REPLIED];
				spin_unlock_bh(&ct->lock);
#endif
			}
		}
		break;
	}

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * ecm_nss_ipv4_net_dev_callback()
 *	Callback handler from the NSS.
 */
static void ecm_nss_ipv4_net_dev_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_conn_sync *sync;

	/*
	 * Only respond to sync messages
	 */
	if (nim->cm.type != NSS_IPV4_RX_CONN_STATS_SYNC_MSG) {
		return;
	}
	sync = &nim->msg.conn_stats;
	ecm_nss_ipv4_process_one_conn_sync_msg(sync);
}

/*
 * ecm_nss_ipv4_connection_sync_many_callback()
 *	Callback for conn_sync_many request message
 */
static void ecm_nss_ipv4_connection_sync_many_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_conn_sync_many_msg *nicsm = &nim->msg.conn_stats_many;
	int i;

	/*
	 * If ECM is terminating, don't process this final stats
	 */
	if (ecm_nss_ipv4_terminate_pending) {
		return;
	}

	if (nim->cm.response == NSS_CMN_RESPONSE_ACK) {
		for (i = 0; i < nicsm->count; i++) {
			ecm_nss_ipv4_process_one_conn_sync_msg(&nicsm->conn_sync[i]);
		}
		ecm_nss_ipv4_sync_req_msg->msg.conn_stats_many.index = nicsm->next;
	} else {
		/*
		 * We get a NACK from FW, which should not happen, restart the request
		 */
		DEBUG_WARN("IPv4 conn stats request failed, restarting\n");
		ecm_nss_ipv4_stats_request_nack++;
		ecm_nss_ipv4_sync_req_msg->msg.conn_stats_many.index = 0;
	}
	queue_delayed_work(ecm_nss_ipv4_workqueue, &ecm_nss_ipv4_work, 0);
}

/*
 * ecm_nss_ipv4_stats_sync_req_work()
 *      Schedule delayed work to process connection stats and request next sync
 */
static void ecm_nss_ipv4_stats_sync_req_work(struct work_struct *work)
{
	/*
	 * Prepare a nss_ipv4_msg with CONN_STATS_SYNC_MANY request
	 */
	struct nss_ipv4_conn_sync_many_msg *nicsm_req = &ecm_nss_ipv4_sync_req_msg->msg.conn_stats_many;
	nss_tx_status_t nss_tx_status;
	int retry = 3;
	unsigned long int current_jiffies;

	spin_lock_bh(&ecm_nss_ipv4_lock);
	if (ecm_nss_ipv4_accelerated_count == 0) {
		spin_unlock_bh(&ecm_nss_ipv4_lock);
		DEBUG_TRACE("There is no accelerated IPv4 connection\n");
		goto reschedule;
	}
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	msleep_interruptible(ECM_NSS_IPV4_STATS_SYNC_UDELAY / 1000);

	/*
	 * If index is 0, we are starting a new round, but if we still have time remain
	 * in this round, sleep until it ends
	 */
	if (nicsm_req->index == 0) {
		current_jiffies = jiffies;

		if (time_is_after_jiffies(ecm_nss_ipv4_roll_check_jiffies))  {
			ecm_nss_ipv4_next_req_time = jiffies + ECM_NSS_IPV4_STATS_SYNC_PERIOD;
		}

		if (time_after(ecm_nss_ipv4_next_req_time, current_jiffies)) {
			msleep_interruptible(jiffies_to_msecs(ecm_nss_ipv4_next_req_time - current_jiffies));
		}
		ecm_nss_ipv4_roll_check_jiffies = jiffies;
		ecm_nss_ipv4_next_req_time = ecm_nss_ipv4_roll_check_jiffies + ECM_NSS_IPV4_STATS_SYNC_PERIOD;
	}

	while (retry) {
		if (ecm_nss_ipv4_terminate_pending) {
			return;
		}
		nss_tx_status = nss_ipv4_tx_with_size(ecm_nss_ipv4_nss_ipv4_mgr, ecm_nss_ipv4_sync_req_msg, PAGE_SIZE);
		if (nss_tx_status == NSS_TX_SUCCESS) {
			ecm_nss_ipv4_stats_request_success++;
			return;
		}
		ecm_nss_ipv4_stats_request_fail++;
		retry--;
		DEBUG_TRACE("TX_NOT_OKAY, try again later\n");
		usleep_range(100, 200);
	}

reschedule:
	/*
	 * TX failed after retries, reschedule ourselves with fresh start
	 */
	nicsm_req->count = 0;
	nicsm_req->index = 0;
	queue_delayed_work(ecm_nss_ipv4_workqueue, &ecm_nss_ipv4_work, ECM_NSS_IPV4_STATS_SYNC_PERIOD);
}

/*
 * struct nf_hook_ops ecm_nss_ipv4_netfilter_hooks[]
 *	Hooks into netfilter packet monitoring points.
 */
static struct nf_hook_ops ecm_nss_ipv4_netfilter_hooks[] __read_mostly = {
	/*
	 * Post routing hook is used to monitor packets going to interfaces that are NOT bridged in some way, e.g. packets to the WAN.
	 */
	{
		.hook           = ecm_nss_ipv4_post_routing_hook,
		.pf             = PF_INET,
		.hooknum        = NF_INET_POST_ROUTING,
		.priority       = NF_IP_PRI_NAT_SRC + 1,
	},

	/*
	 * The bridge post routing hook monitors packets going to interfaces that are part of a bridge arrangement.
	 * For example Wireles LAN (WLAN) and Wired LAN (LAN).
	 */
	{
		.hook		= ecm_nss_ipv4_bridge_post_routing_hook,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

/*
 * ecm_nss_ipv4_get_accel_limit_mode()
 */
static int ecm_nss_ipv4_get_accel_limit_mode(void *data, u64 *val)
{
	*val = ecm_nss_ipv4_accel_limit_mode;

	return 0;
}

/*
 * ecm_nss_ipv4_set_accel_limit_mode()
 */
static int ecm_nss_ipv4_set_accel_limit_mode(void *data, u64 val)
{
	DEBUG_TRACE("ecm_nss_ipv4_accel_limit_mode = %x\n", (int)val);

	/*
	 * Check that only valid bits are set.
	 * It's fine for no bits to be set as that suggests no modes are wanted.
	 */
	if (val && (val ^ (ECM_FRONT_END_ACCEL_LIMIT_MODE_FIXED | ECM_FRONT_END_ACCEL_LIMIT_MODE_UNLIMITED))) {
		DEBUG_WARN("ecm_nss_ipv4_accel_limit_mode = %x bad\n", (int)val);
		return -EINVAL;
	}

	ecm_nss_ipv4_accel_limit_mode = (int)val;

	return 0;
}

/*
 * Debugfs attribute for accel limit mode.
 */
DEFINE_SIMPLE_ATTRIBUTE(ecm_nss_ipv4_accel_limit_mode_fops, ecm_nss_ipv4_get_accel_limit_mode, ecm_nss_ipv4_set_accel_limit_mode, "%llu\n");
/*
 * ecm_nss_ipv4_get_accel_cmd_avg_millis()
 */
static ssize_t ecm_nss_ipv4_get_accel_cmd_avg_millis(struct file *file,
								char __user *user_buf,
								size_t sz, loff_t *ppos)
{
	unsigned long set;
	unsigned long samples;
	unsigned long avg;
	char *buf;
	int ret;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	/*
	 * Operate under our locks.
	 * Compute the average of the samples taken and seed the next set of samples with the result of this one.
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	samples = ecm_nss_ipv4_accel_cmd_time_avg_samples;
	set = ecm_nss_ipv4_accel_cmd_time_avg_set;
	ecm_nss_ipv4_accel_cmd_time_avg_samples /= ecm_nss_ipv4_accel_cmd_time_avg_set;
	ecm_nss_ipv4_accel_cmd_time_avg_set = 1;
	avg = ecm_nss_ipv4_accel_cmd_time_avg_samples;
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Convert average jiffies to milliseconds
	 */
	avg *= 1000;
	avg /= HZ;

	ret = snprintf(buf, (ssize_t)PAGE_SIZE, "avg=%lu\tsamples=%lu\tset_size=%lu\n", avg, samples, set);
	if (ret < 0) {
		kfree(buf);
		return -EFAULT;
	}

	ret = simple_read_from_buffer(user_buf, sz, ppos, buf, ret);
	kfree(buf);
	return ret;
}

/*
 * File operations for accel command average time.
 */
static struct file_operations ecm_nss_ipv4_accel_cmd_avg_millis_fops = {
	.read = ecm_nss_ipv4_get_accel_cmd_avg_millis,
};

/*
 * ecm_nss_ipv4_get_decel_average_millis()
 */
static ssize_t ecm_nss_ipv4_get_decel_cmd_avg_millis(struct file *file,
								char __user *user_buf,
								size_t sz, loff_t *ppos)
{
	unsigned long set;
	unsigned long samples;
	unsigned long avg;
	char *buf;
	int ret;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	/*
	 * Operate under our locks.
	 * Compute the average of the samples taken and seed the next set of samples with the result of this one.
	 */
	spin_lock_bh(&ecm_nss_ipv4_lock);
	samples = ecm_nss_ipv4_decel_cmd_time_avg_samples;
	set = ecm_nss_ipv4_decel_cmd_time_avg_set;
	ecm_nss_ipv4_decel_cmd_time_avg_samples /= ecm_nss_ipv4_decel_cmd_time_avg_set;
	ecm_nss_ipv4_decel_cmd_time_avg_set = 1;
	avg = ecm_nss_ipv4_decel_cmd_time_avg_samples;
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Convert average jiffies to milliseconds
	 */
	avg *= 1000;
	avg /= HZ;

	ret = snprintf(buf, (ssize_t)PAGE_SIZE, "avg=%lu\tsamples=%lu\tset_size=%lu\n", avg, samples, set);
	if (ret < 0) {
		kfree(buf);
		return -EFAULT;
	}

	ret = simple_read_from_buffer(user_buf, sz, ppos, buf, ret);
	kfree(buf);
	return ret;
}

/*
 * File operations for decel command average time.
 */
static struct file_operations ecm_nss_ipv4_decel_cmd_avg_millis_fops = {
	.read = ecm_nss_ipv4_get_decel_cmd_avg_millis,
};

/*
 * ecm_nss_ipv4_get_stats_request_counter()
 */
static ssize_t ecm_nss_ipv4_get_stats_request_counter(struct file *file,
								char __user *user_buf,
								size_t sz, loff_t *ppos)
{
	char *buf;
	int ret;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	ret = snprintf(buf, (ssize_t)PAGE_SIZE, "success=%lu\tfail=%lu\tnack=%lu\t\n",
			ecm_nss_ipv4_stats_request_success, ecm_nss_ipv4_stats_request_fail,
			ecm_nss_ipv4_stats_request_nack);
	if (ret < 0) {
		kfree(buf);
		return -EFAULT;
	}

	ret = simple_read_from_buffer(user_buf, sz, ppos, buf, ret);
	kfree(buf);
	return ret;
}

/*
 * File operations for decel command average time.
 */
static struct file_operations ecm_nss_ipv4_stats_request_counter_fops = {
	.read = ecm_nss_ipv4_get_stats_request_counter,
};

/*
 * ecm_nss_ipv4_sync_queue_init
 *	Initialize the workqueue for ipv4 stats sync
 */
static bool ecm_nss_ipv4_sync_queue_init(void)
{
	struct nss_ipv4_conn_sync_many_msg *nicsm;

	/*
	 * Setup the connection sync msg/work/workqueue
	 */
	ecm_nss_ipv4_sync_req_msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ecm_nss_ipv4_sync_req_msg) {
		return false;
	}

	/*
	 * Register the conn_sync_many message callback
	 */
	nss_ipv4_conn_sync_many_notify_register(ecm_nss_ipv4_connection_sync_many_callback);

	nss_ipv4_msg_init(ecm_nss_ipv4_sync_req_msg, NSS_IPV4_RX_INTERFACE,
		NSS_IPV4_TX_CONN_STATS_SYNC_MANY_MSG,
		sizeof(struct nss_ipv4_conn_sync_many_msg) ,
		NULL,
		NULL);

	nicsm = &ecm_nss_ipv4_sync_req_msg->msg.conn_stats_many;

	/*
	 * Start with index 0 and calculate the size of the conn stats array
	 */
	nicsm->index = 0;
	nicsm->size = PAGE_SIZE;

	ecm_nss_ipv4_workqueue = create_singlethread_workqueue("ecm_nss_ipv4_workqueue");
	if (!ecm_nss_ipv4_workqueue) {
		nss_ipv4_conn_sync_many_notify_unregister();
		kfree(ecm_nss_ipv4_sync_req_msg);
		return false;
	}
	INIT_DELAYED_WORK(&ecm_nss_ipv4_work, ecm_nss_ipv4_stats_sync_req_work);
	queue_delayed_work(ecm_nss_ipv4_workqueue, &ecm_nss_ipv4_work, ECM_NSS_IPV4_STATS_SYNC_PERIOD);

	return true;
}

/*
 * ecm_nss_ipv4_sync_queue_exit
 *	 the workqueue for ipv4 stats sync
 */
static void ecm_nss_ipv4_sync_queue_exit(void)
{
	/*
	 * Unregister the conn_sync_many message callback
	 * Otherwise nss will call our callback which does not exist anymore
	 */
	nss_ipv4_conn_sync_many_notify_unregister();

	/*
	 * Cancel the conn sync req work and destroy workqueue
	 */
	cancel_delayed_work_sync(&ecm_nss_ipv4_work);
	destroy_workqueue(ecm_nss_ipv4_workqueue);
	kfree(ecm_nss_ipv4_sync_req_msg);
}

/*
 * ecm_nss_ipv4_init()
 */
int ecm_nss_ipv4_init(struct dentry *dentry)
{
	int result = -1;

	DEBUG_INFO("ECM NSS IPv4 init\n");

	ecm_nss_ipv4_dentry = debugfs_create_dir("ecm_nss_ipv4", dentry);
	if (!ecm_nss_ipv4_dentry) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 directory in debugfs\n");
		return result;
	}

	if (!debugfs_create_u32("no_action_limit_default", S_IRUGO | S_IWUSR, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_no_action_limit_default)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 no_action_limit_default file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("driver_fail_limit_default", S_IRUGO | S_IWUSR, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_driver_fail_limit_default)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 driver_fail_limit_default file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("nack_limit_default", S_IRUGO | S_IWUSR, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_nack_limit_default)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 nack_limit_default file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("accelerated_count", S_IRUGO, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_accelerated_count)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 accelerated_count file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("pending_accel_count", S_IRUGO, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_pending_accel_count)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 pending_accel_count file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("pending_decel_count", S_IRUGO, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_pending_decel_count)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 pending_decel_count file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_file("accel_limit_mode", S_IRUGO | S_IWUSR, ecm_nss_ipv4_dentry,
					NULL, &ecm_nss_ipv4_accel_limit_mode_fops)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 accel_limit_mode file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_file("accel_cmd_avg_millis", S_IRUGO, ecm_nss_ipv4_dentry,
					NULL, &ecm_nss_ipv4_accel_cmd_avg_millis_fops)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 accel_cmd_avg_millis file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_file("decel_cmd_avg_millis", S_IRUGO, ecm_nss_ipv4_dentry,
					NULL, &ecm_nss_ipv4_decel_cmd_avg_millis_fops)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 decel_cmd_avg_millis file in debugfs\n");
		goto task_cleanup;
	}

	if (!ecm_nss_ported_ipv4_debugfs_init(ecm_nss_ipv4_dentry)) {
		DEBUG_ERROR("Failed to create ecm ported files in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_file("stats_request_counter", S_IRUGO, ecm_nss_ipv4_dentry,
					NULL, &ecm_nss_ipv4_stats_request_counter_fops)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 stats request counter file in debugfs\n");
		goto task_cleanup;
	}

	if (!debugfs_create_u32("vlan_passthrough_set", S_IRUGO | S_IWUSR, ecm_nss_ipv4_dentry,
					(u32 *)&ecm_nss_ipv4_vlan_passthrough_enable)) {
		DEBUG_ERROR("Failed to create ecm nss ipv4 vlan passthrough file in debugfs\n");
		goto task_cleanup;
	}

#ifdef ECM_NON_PORTED_SUPPORT_ENABLE
	if (!ecm_nss_non_ported_ipv4_debugfs_init(ecm_nss_ipv4_dentry)) {
		DEBUG_ERROR("Failed to create ecm non-ported files in debugfs\n");
		goto task_cleanup;
	}
#endif

#ifdef ECM_MULTICAST_ENABLE
	if (!ecm_nss_multicast_ipv4_debugfs_init(ecm_nss_ipv4_dentry)) {
		DEBUG_ERROR("Failed to create ecm multicast files in debugfs\n");
		goto task_cleanup;
	}
#endif
	/*
	 * Register this module with the Linux NSS Network driver.
	 * Notify manager should be registered before the netfilter hooks. Because there
	 * is a possibility that the ECM can try to send acceleration messages to the
	 * acceleration engine without having an acceleration engine manager.
	 */
	ecm_nss_ipv4_nss_ipv4_mgr = nss_ipv4_notify_register(ecm_nss_ipv4_net_dev_callback, NULL);

	/*
	 * Register netfilter hooks
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
	result = nf_register_hooks(ecm_nss_ipv4_netfilter_hooks, ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#else
	result = nf_register_net_hooks(&init_net, ecm_nss_ipv4_netfilter_hooks, ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#endif
	if (result < 0) {
		DEBUG_ERROR("Can't register netfilter hooks.\n");
		goto task_cleanup_1;
	}

#ifdef ECM_MULTICAST_ENABLE
	result = ecm_nss_multicast_ipv4_init(ecm_nss_ipv4_dentry);
	if (result < 0) {
		DEBUG_ERROR("Failed to init ecm ipv4 multicast frontend\n");
		goto task_cleanup_2;
	}
#endif

	if (!ecm_nss_ipv4_sync_queue_init()) {
		DEBUG_ERROR("Failed to create ecm ipv4 connection sync workqueue\n");
		goto task_cleanup_3;
	}

#ifdef ECM_INTERFACE_OVS_BRIDGE_ENABLE
	ovsmgr_dp_hook_register(&ecm_nss_ipv4_dp_hooks);
#endif
	return 0;

task_cleanup_3:
#ifdef ECM_MULTICAST_ENABLE
		ecm_nss_multicast_ipv4_exit();
task_cleanup_2:
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
	nf_unregister_hooks(ecm_nss_ipv4_netfilter_hooks,
			    ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#else
	nf_unregister_net_hooks(&init_net, ecm_nss_ipv4_netfilter_hooks,
				ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#endif
task_cleanup_1:
	nss_ipv4_notify_unregister();

task_cleanup:

	debugfs_remove_recursive(ecm_nss_ipv4_dentry);
	return result;
}
EXPORT_SYMBOL(ecm_nss_ipv4_init);

/*
 * ecm_nss_ipv4_exit()
 */
void ecm_nss_ipv4_exit(void)
{
	DEBUG_INFO("ECM NSS IPv4 Module exit\n");

	spin_lock_bh(&ecm_nss_ipv4_lock);
	ecm_nss_ipv4_terminate_pending = true;
	spin_unlock_bh(&ecm_nss_ipv4_lock);

	/*
	 * Stop the network stack hooks
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
	nf_unregister_hooks(ecm_nss_ipv4_netfilter_hooks,
			    ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#else
	nf_unregister_net_hooks(&init_net, ecm_nss_ipv4_netfilter_hooks,
				ARRAY_SIZE(ecm_nss_ipv4_netfilter_hooks));
#endif
	/*
	 * Unregister from the Linux NSS Network driver
	 */
	nss_ipv4_notify_unregister();

	/*
	 * Remove the debugfs files recursively.
	 */
	if (ecm_nss_ipv4_dentry) {
		debugfs_remove_recursive(ecm_nss_ipv4_dentry);
	}

#ifdef ECM_MULTICAST_ENABLE
	ecm_nss_multicast_ipv4_exit();
#endif

	/*
	 * Clean up the stats sync queue/work
	 */
	ecm_nss_ipv4_sync_queue_exit();

#ifdef ECM_INTERFACE_OVS_BRIDGE_ENABLE
	ovsmgr_dp_hook_unregister(&ecm_nss_ipv4_dp_hooks);
#endif
}
EXPORT_SYMBOL(ecm_nss_ipv4_exit);
