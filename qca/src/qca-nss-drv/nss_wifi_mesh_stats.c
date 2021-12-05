/*
 **************************************************************************
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
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
 **************************************************************************
 */

#include "nss_core.h"
#include "nss_tx_rx_common.h"
#include "nss_wifi_mesh.h"
#include "nss_wifi_mesh_stats.h"
#include "nss_wifi_mesh_strings.h"

#define NSS_WIFI_MESH_OUTER_STATS 0
#define NSS_WIFI_MESH_INNER_STATS 1
#define NSS_WIFI_MESH_PATH_STATS 3
#define NSS_WIFI_MESH_PROXY_PATH_STATS 4

/*
 * Wi-Fi mesh stats dentry file size.
 */
#define NSS_WIFI_MESH_DENTRY_FILE_SIZE 19

/*
 * Spinlock for protecting tunnel operations colliding with a tunnel destroy
 */
static DEFINE_SPINLOCK(nss_wifi_mesh_stats_lock);

/*
 * Declare atomic notifier data structure for statistics.
 */
static ATOMIC_NOTIFIER_HEAD(nss_wifi_mesh_stats_notifier);

/*
 * Declare an array of Wi-Fi mesh stats handle.
 */
struct nss_wifi_mesh_stats_handle *nss_wifi_mesh_stats_hdl[NSS_WIFI_MESH_MAX_DYNAMIC_INTERFACE];

/**
 *  nss_wifi_mesh_stats_encap()
 *  	Get Wi-Fi mesh encap stats.
 */
static ssize_t nss_wifi_mesh_stats_encap(char *line, int len, int i, struct nss_wifi_mesh_stats_sync_msg *stats)
{
	uint32_t count;
	struct nss_wifi_mesh_encap_stats wmes = stats->mesh_encap_stats;
	struct nss_cmn_node_stats cns = stats->pnode_stats;

	switch (i) {
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PNODE_RX_PACKETS:
		count = cns.rx_packets;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PNODE_RX_BYTES:
		count = cns.rx_bytes;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PNODE_TX_PACKETS:
		count = cns.tx_packets;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PNODE_TX_BYTES:
		count = cns.tx_bytes;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PNODE_RX_DROPPED:
		count = cns.rx_dropped[0];
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_DEQUEUE_COUNT:
		count = wmes.dequeue_count;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MC_COUNT:
		count = wmes.mc_count;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MP_NOT_FOUND:
		count = wmes.mp_not_found;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MP_ACTIVE:
		count = wmes.mp_active;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MPP_NOT_FOUND:
		count = wmes.mpp_not_found;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MPP_FOUND:
		count = wmes.mpp_found;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_HDR_FAIL:
		count = wmes.encap_hdr_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MP_DEL_NOTIFY_FAIL:
		count = wmes.mp_del_notify_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_LINK_ENQUEUE:
		count = wmes.link_enqueue;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_LINK_ENQUEUE_FAIL:
		count = wmes.link_enq_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_RA_LOOKUP_FAIL:
		count = wmes.ra_lup_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_DUMMY_ADD_COUNT:
		count = wmes.dummy_add_count;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_MP_ADD_NOTIFY_FAIL:
		count = wmes.encap_mp_add_notify_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_DUMMY_ADD_FAIL:
		count = wmes.dummy_add_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_DUMMY_LOOKUP_FAIL:
		count = wmes.dummy_lup_fail;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PENDING_QLIMIT_DROP:
		count = wmes.pending_qlimit_drop;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_PENDING_ENQUEUE:
		count = wmes.pending_qenque;
		break;
	case NSS_WIFI_MESH_ENCAP_STATS_TYPE_EXPIRY_NOTIFY_FAIL:
		count = wmes.expiry_notify_fail;
		break;
	default:
		return 0;
	}

	return snprintf(line, len, "%s = %d\n", nss_wifi_mesh_strings_encap_stats[i].stats_name, count);
}

/**
 *  nss_wifi_mesh_stats_decap()
 *  	Get Wi-Fi mesh decap stats.
 */
static ssize_t nss_wifi_mesh_stats_decap(char *line, int len, int i, struct nss_wifi_mesh_stats_sync_msg *stats)
{
	struct nss_wifi_mesh_decap_stats wmds = stats->mesh_decap_stats;
	struct nss_cmn_node_stats cns = stats->pnode_stats;
	uint32_t count;

	switch(i) {
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_PNODE_RX_PACKETS:
		count = cns.rx_packets;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_PNODE_RX_BYTES:
		count = cns.rx_bytes;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_PNODE_TX_PACKETS:
		count = cns.tx_packets;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_PNODE_TX_BYTES:
		count = cns.tx_bytes;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_PNODE_RX_DROPPED:
		count = cns.rx_dropped[0];
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_ENQUEUE_COUNT_EXCEEDED:
		count = wmds.eq_cnt_exceeded;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_COUNT:
		count = wmds.deq_cnt;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MC_DROP:
		count = wmds.mc_drop;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_TTL0:
		count = wmds.ttl_0;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_LOOKUP_FAIL:
		count = wmds.mpp_lup_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_HDR_FAIL:
		count = wmds.decap_hdr_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_RX_FWD_FAIL:
		count = wmds.rx_fwd_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_RX_FWD_SUCCESS:
		count = wmds.rx_fwd_success;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MP_FWD_LOOKUP_FAIL:
		count = wmds.mp_fwd_lookup_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MP_FWD_INACTIVE:
		count = wmds.mp_fwd_inactive;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MNODE_FWD_SUCCESS:
		count = wmds.nxt_mnode_fwd_success;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MNODE_FWD_FAIL:
		count = wmds.nxt_mnode_fwd_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_ADD_FAIL:
		count = wmds.mpp_add_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_ADD_EVENT_TO_HOST_FAIL:
		count = wmds.mpp_add_event2host_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_UPDATE_FAIL:
		count = wmds.mpp_upate_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_UPDATE_EVENT_TO_HOST_FAIL:
		count = wmds.mpp_update_even2host_fail;
		break;
	case NSS_WIFI_MESH_DECAP_STATS_TYPE_MPP_LEARN_TO_HOST_FAIL :
		count = wmds.mpp_learn2host_fail;
		break;
	default:
		return 0;
	}

	return snprintf(line, len, "%s = %d\n", nss_wifi_mesh_strings_decap_stats[i].stats_name, count);;
}

/**
 *  nss_wifi_mesh_stats_path()
 *  	Get Wi-Fi mesh path stats.
 */
static ssize_t nss_wifi_mesh_stats_path(char *line, int len, int i, struct nss_wifi_mesh_stats_sync_msg *stats)
{
	struct nss_wifi_mesh_path_stats wmps = stats->mesh_path_stats;
	uint32_t count;

	if (i >= NSS_WIFI_MESH_PATH_STATS_TYPE_MAX) {
		return 0;
	}

	count = *(&wmps.alloc_failures + i);
	return snprintf(line, len, "%s = %d\n", nss_wifi_mesh_strings_path_stats[i].stats_name, count);
}

/**
 *  nss_wifi_mesh_stats_proxy_path()
 *  	Get Wi-Fi mesh proxy path stats.
 */
static ssize_t nss_wifi_mesh_stats_proxy_path(char *line, int len, int i, struct nss_wifi_mesh_stats_sync_msg *stats)
{
	struct nss_wifi_mesh_proxy_path_stats wmpps = stats->mesh_proxy_path_stats;
	uint32_t count;

	if (i >= NSS_WIFI_MESH_PROXY_PATH_STATS_TYPE_MAX) {
		return 0;
	}

	count = *(&wmpps.alloc_failures + i);
	return snprintf(line, len, "%s = %d\n", nss_wifi_mesh_strings_proxy_path_stats[i].stats_name, count);
}

/*
 * nss_wifi_mesh_stats_handle_alloc()
 *	Allocate Wi-Fi mesh tunnel instance
 */
bool nss_wifi_mesh_stats_handle_alloc(nss_if_num_t if_num)
{
	struct nss_wifi_mesh_stats_handle *h;
	uint32_t idx, idx1;

	/*
	 * Allocate a handle
	 */
	h = kzalloc(sizeof(struct nss_wifi_mesh_stats_handle), GFP_ATOMIC);
	if (!h) {
		nss_warning("Failed to allocate memory for Wi-Fi mesh instance for interface : 0x%x", if_num);
		return false;
	}

	spin_lock(&nss_wifi_mesh_stats_lock);
	for (idx = 0; idx < NSS_WIFI_MESH_MAX_DYNAMIC_INTERFACE; idx++) {
		if (nss_wifi_mesh_stats_hdl[idx]) {
			if ((nss_wifi_mesh_stats_hdl[idx]->if_num == if_num)) {
				spin_unlock(&nss_wifi_mesh_stats_lock);
				nss_warning("Already a handle present for this interface number: 0x%x", if_num);
				kfree(h);
				return false;
			}
		} else {
			h->if_num = if_num;
			h->mesh_idx = idx;
			for (idx1 = idx + 1; idx1 < NSS_WIFI_MESH_MAX_DYNAMIC_INTERFACE; idx1++) {
				if (nss_wifi_mesh_stats_hdl[idx1] && (nss_wifi_mesh_stats_hdl[idx1]->if_num == if_num)) {
					spin_unlock(&nss_wifi_mesh_stats_lock);
					nss_warning("Already a handle present for this interface number: 0x%x", if_num);
					kfree(h);
					return false;
				}
			}

			nss_wifi_mesh_stats_hdl[idx] = h;
			break;
		}
	}

	spin_unlock(&nss_wifi_mesh_stats_lock);

	if (idx == NSS_WIFI_MESH_MAX_DYNAMIC_INTERFACE) {
		nss_warning("No free index available for handle with ifnum: 0x%x", if_num);
		kfree(h);
		return false;
	}

	return true;
}

/*
 * nss_wifi_mesh_stats_handle_free()
 *	Free Wi-Fi mesh tunnel handle instance.
 */
bool nss_wifi_mesh_stats_handle_free(nss_if_num_t if_num)
{
	struct nss_wifi_mesh_stats_handle *h;

	spin_lock(&nss_wifi_mesh_stats_lock);
	h = nss_wifi_mesh_get_stats_handle(if_num);
	if (!h) {
		spin_unlock(&nss_wifi_mesh_stats_lock);
		nss_warning("Unable to free Wi-Fi mesh stats handle instance for interface number: 0x%x", if_num);
		return false;
	}

	nss_wifi_mesh_stats_hdl[h->mesh_idx] = NULL;
	spin_unlock(&nss_wifi_mesh_stats_lock);
	kfree(h);
	return true;
}

/**
 * nss_wifi_mesh_get_stats_handle()
 * 	Get Wi-Fi mesh stats handle from interface number.
 */
struct nss_wifi_mesh_stats_handle *nss_wifi_mesh_get_stats_handle(nss_if_num_t if_num)
{
	uint32_t idx;

	assert_spin_locked(&nss_wifi_mesh_stats_lock);

	for (idx = 0; idx < NSS_WIFI_MESH_MAX_DYNAMIC_INTERFACE; idx++) {
		if (nss_wifi_mesh_stats_hdl[idx]) {
			if (nss_wifi_mesh_stats_hdl[idx]->if_num == if_num) {
				struct nss_wifi_mesh_stats_handle *h = nss_wifi_mesh_stats_hdl[idx];
				return h;
			}
		}
	}
	return NULL;
}

/*
 * nss_wifi_mesh_get_stats()
 *	API for getting stats from a Wi-Fi mesh interface stats
 */
static bool nss_wifi_mesh_get_stats(nss_if_num_t if_num, struct nss_wifi_mesh_stats_sync_msg *stats)
{
	struct nss_wifi_mesh_stats_handle *h;

	if (!nss_wifi_mesh_verify_if_num(if_num)) {
		return false;
	}

	spin_lock(&nss_wifi_mesh_stats_lock);
	h = nss_wifi_mesh_get_stats_handle(if_num);
	if (!h) {
		spin_unlock(&nss_wifi_mesh_stats_lock);
		nss_warning("Invalid Wi-Fi mesh stats handle for interface number: %d", if_num);
		return false;
	}

	memcpy(stats, &h->stats, sizeof(*stats));
	spin_unlock(&nss_wifi_mesh_stats_lock);
	return true;
}

/**
 * nss_wifi_mesh_stats_read()
 * 	Read Wi-Fi Mesh stats.
 */
static ssize_t nss_wifi_mesh_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos, uint16_t type)
{
	struct nss_stats_data *data = fp->private_data;
	ssize_t bytes_read = 0;
	size_t bytes;
	char line[80];
	int stats_idx;
	uint32_t if_num = NSS_DYNAMIC_IF_START;
	uint32_t max_if_num = NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES;
	struct nss_wifi_mesh_stats_sync_msg *stats;

	if (data) {
		if_num = data->if_num;
	}

	/*
	 * If we are done accomodating all the Wi-Fi mesh interfaces.
	 */
	if (if_num > max_if_num) {
		return 0;
	}

	stats = kzalloc(sizeof(struct nss_wifi_mesh_stats_sync_msg), GFP_KERNEL);
	if (!stats) {
		nss_warning("%px: Failed to allocate stats memory for if_num: 0x%x", data, if_num);
		return 0;
	}

	for (; if_num <= max_if_num; if_num++) {
		enum nss_dynamic_interface_type dtype;
		bool ret;

		if (!nss_is_dynamic_interface(if_num)) {
			continue;
		}

		dtype = nss_dynamic_interface_get_type(nss_wifi_mesh_get_context(), if_num);

		if ((type == NSS_WIFI_MESH_OUTER_STATS) && (dtype != NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_OUTER)) {
			continue;
		}

		if ((type == NSS_WIFI_MESH_INNER_STATS) && (dtype != NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_INNER)) {
			continue;
		}

		if ((type == NSS_WIFI_MESH_PATH_STATS) && (dtype != NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_INNER)) {
			continue;
		}

		if ((type == NSS_WIFI_MESH_PROXY_PATH_STATS) && (dtype != NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_INNER)) {
			continue;
		}

		/*
		 * If Wi-Fi mesh tunnel does not exists, then ret will be false.
		 */
		ret = nss_wifi_mesh_get_stats(if_num, stats);
		if (!ret) {
			continue;
		}

		bytes = snprintf(line, sizeof(line), "----if_num : %2d----\n", if_num);
		if ((bytes_read + bytes) > sz) {
			break;
		}

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto fail;
		}
		bytes_read += bytes;
		stats_idx = 0;
		while (bytes_read < sz) {
			/*
			 * Read encap stats, path stats, proxy path stats from inner node and decap stats from outer node.
			 */
			switch (type) {
			case NSS_WIFI_MESH_INNER_STATS:
				bytes = nss_wifi_mesh_stats_encap(line, sizeof(line), stats_idx, stats);
				break;

			case NSS_WIFI_MESH_PATH_STATS:
				bytes = nss_wifi_mesh_stats_path(line, sizeof(line), stats_idx, stats);
				break;

			case NSS_WIFI_MESH_PROXY_PATH_STATS:
				bytes = nss_wifi_mesh_stats_proxy_path(line, sizeof(line), stats_idx, stats);
				break;

			case NSS_WIFI_MESH_OUTER_STATS:
				bytes = nss_wifi_mesh_stats_decap(line, sizeof(line), stats_idx, stats);
				break;

			default:
				nss_warning("%px: Invalid stats type: %d", stats, type);
				nss_assert(0);
				kfree(stats);
				return 0;
			}

			/*
			 * If we don't have any more lines in decap/encap.
			 */
			if (!bytes) {
				break;
			}

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto fail;
			}

			bytes_read += bytes;
			stats_idx++;
		}
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->if_num = if_num;
	}
fail:
	kfree(stats);
	return bytes_read;

}

/**
 * nss_wifi_mesh_decap_stats_read()
 *	Read Wi-Fi Mesh decap stats.
 */
static ssize_t nss_wifi_mesh_decap_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_wifi_mesh_stats_read(fp, ubuf, sz, ppos, NSS_WIFI_MESH_OUTER_STATS);
}

/**
 * nss_wifi_mesh_encap_stats_read()
 *	Read Wi-Fi Mesh encap stats
 */
static ssize_t nss_wifi_mesh_encap_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_wifi_mesh_stats_read(fp, ubuf, sz, ppos, NSS_WIFI_MESH_INNER_STATS);
}

/**
 * nss_wifi_mesh_path_stats_read()
 *	Read Wi-Fi Mesh path stats
 */
static ssize_t nss_wifi_mesh_path_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_wifi_mesh_stats_read(fp, ubuf, sz, ppos, NSS_WIFI_MESH_PATH_STATS);
}

/**
 * nss_wifi_mesh_proxy_path_stats_read()
 *	Read Wi-Fi Mesh proxy path stats
 */
static ssize_t nss_wifi_mesh_proxy_path_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_wifi_mesh_stats_read(fp, ubuf, sz, ppos, NSS_WIFI_MESH_PROXY_PATH_STATS);
}

/*
 * nss_wifi_mesh_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(wifi_mesh_encap);
NSS_STATS_DECLARE_FILE_OPERATIONS(wifi_mesh_decap);
NSS_STATS_DECLARE_FILE_OPERATIONS(wifi_mesh_path);
NSS_STATS_DECLARE_FILE_OPERATIONS(wifi_mesh_proxy_path);

/*
 * nss_wifi_mesh_get_interface_type()
 * 	Function to get the type of dynamic interface.
 */
static enum nss_dynamic_interface_type nss_wifi_mesh_get_interface_type(nss_if_num_t if_num)
{
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.wifi_handler_id];
	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	return nss_dynamic_interface_get_type(nss_ctx, if_num);
}

/*
 * nss_wifi_mesh_update_stats()
 *	Update stats for Wi-Fi mesh interface.
 */
void nss_wifi_mesh_update_stats(nss_if_num_t if_num, struct nss_wifi_mesh_stats_sync_msg *mstats)
{
	struct nss_wifi_mesh_stats_sync_msg *stats;
	struct nss_wifi_mesh_encap_stats *es;
	struct nss_wifi_mesh_decap_stats *ds;
	struct nss_wifi_mesh_path_stats *ps;
	struct nss_wifi_mesh_proxy_path_stats *pps;
	struct nss_wifi_mesh_stats_handle *handle;
	enum nss_dynamic_interface_type type;

	spin_lock(&nss_wifi_mesh_stats_lock);
	handle = nss_wifi_mesh_get_stats_handle(if_num);
	if (!handle) {
		spin_unlock(&nss_wifi_mesh_stats_lock);
		nss_warning("Invalid Wi-Fi mesh stats handle, if_num: %d", if_num);
		return;
	}

	type = nss_wifi_mesh_get_interface_type(handle->if_num);;
	stats = &handle->stats;
	es = &stats->mesh_encap_stats;
	ds = &stats->mesh_decap_stats;
	ps = &stats->mesh_path_stats;
	pps = &stats->mesh_proxy_path_stats;

	/* Update pnode Rx stats. */
	stats->pnode_stats.rx_packets += mstats->pnode_stats.rx_packets;
	stats->pnode_stats.rx_bytes += mstats->pnode_stats.rx_bytes;
	stats->pnode_stats.rx_dropped[0] += nss_cmn_rx_dropped_sum(&mstats->pnode_stats);


	/* Update pnode Tx stats. */
	stats->pnode_stats.tx_packets += mstats->pnode_stats.tx_packets;
	stats->pnode_stats.tx_bytes += mstats->pnode_stats.tx_bytes;

	switch (type) {
	case NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_INNER:
		es->dequeue_count += mstats->mesh_encap_stats.dequeue_count;
		es->mc_count += mstats->mesh_encap_stats.mc_count;
		es->mp_not_found += mstats->mesh_encap_stats.mp_not_found;
		es->mp_active += mstats->mesh_encap_stats.mp_active;
		es->mpp_not_found += mstats->mesh_encap_stats.mpp_not_found;
		es->mpp_found += mstats->mesh_encap_stats.mpp_found;
		es->encap_hdr_fail += mstats->mesh_encap_stats.encap_hdr_fail;
		es->mp_del_notify_fail += mstats->mesh_encap_stats.mp_del_notify_fail;
		es->link_enqueue += mstats->mesh_encap_stats.link_enqueue;
		es->link_enq_fail += mstats->mesh_encap_stats.link_enq_fail;
		es->ra_lup_fail += mstats->mesh_encap_stats.ra_lup_fail;
		es->dummy_add_count += mstats->mesh_encap_stats.dummy_add_count;
		es->encap_mp_add_notify_fail += mstats->mesh_encap_stats.encap_mp_add_notify_fail;
		es->dummy_add_fail += mstats->mesh_encap_stats.dummy_add_fail;
		es->dummy_lup_fail += mstats->mesh_encap_stats.dummy_lup_fail;
		es->pending_qlimit_drop += mstats->mesh_encap_stats.pending_qlimit_drop;
		es->pending_qenque += mstats->mesh_encap_stats.pending_qenque;
		es->expiry_notify_fail += mstats->mesh_encap_stats.expiry_notify_fail;

		/* Update mesh path stats. */
		ps->alloc_failures += mstats->mesh_path_stats.alloc_failures;
		ps->error_max_radio_count += mstats->mesh_path_stats.error_max_radio_count;
		ps->invalid_interface_failures += mstats->mesh_path_stats.invalid_interface_failures;
		ps->add_success += mstats->mesh_path_stats.add_success;
		ps->table_full_errors += mstats->mesh_path_stats.table_full_errors;
		ps->insert_failures += mstats->mesh_path_stats.insert_failures;
		ps->not_found += mstats->mesh_path_stats.not_found;
		ps->delete_success += mstats->mesh_path_stats.delete_success;
		ps->update_success += mstats->mesh_path_stats.update_success;

		/* Update mesh proxy path stats. */
		pps->alloc_failures += mstats->mesh_proxy_path_stats.alloc_failures;
		pps->entry_exist_failures += mstats->mesh_proxy_path_stats.entry_exist_failures;
		pps->add_success += mstats->mesh_proxy_path_stats.add_success;
		pps->table_full_errors += mstats->mesh_proxy_path_stats.table_full_errors;
		pps->insert_failures += mstats->mesh_proxy_path_stats.insert_failures;
		pps->not_found += mstats->mesh_proxy_path_stats.not_found;
		pps->unhashed_errors += mstats->mesh_proxy_path_stats.unhashed_errors;
		pps->delete_failures += mstats->mesh_proxy_path_stats.delete_failures;
		pps->delete_success += mstats->mesh_proxy_path_stats.delete_success;
		pps->update_success += mstats->mesh_proxy_path_stats.update_success;
		pps->lookup_success += mstats->mesh_proxy_path_stats.lookup_success;
		spin_unlock(&nss_wifi_mesh_stats_lock);
		break;

	case NSS_DYNAMIC_INTERFACE_TYPE_WIFI_MESH_OUTER:
		ds->eq_cnt_exceeded += mstats->mesh_decap_stats.eq_cnt_exceeded;
		ds->deq_cnt += mstats->mesh_decap_stats.deq_cnt;
		ds->mc_drop += mstats->mesh_decap_stats.mc_drop;
		ds->ttl_0 += mstats->mesh_decap_stats.ttl_0;
		ds->mpp_lup_fail += mstats->mesh_decap_stats.mpp_lup_fail;
		ds->decap_hdr_fail += mstats->mesh_decap_stats.decap_hdr_fail;
		ds->rx_fwd_fail += mstats->mesh_decap_stats.rx_fwd_fail;
		ds->rx_fwd_success += mstats->mesh_decap_stats.rx_fwd_success;
		ds->mp_fwd_lookup_fail += mstats->mesh_decap_stats.mp_fwd_lookup_fail;
		ds->mp_fwd_inactive += mstats->mesh_decap_stats.mp_fwd_inactive;
		ds->nxt_mnode_fwd_success += mstats->mesh_decap_stats.nxt_mnode_fwd_success;
		ds->nxt_mnode_fwd_fail += mstats->mesh_decap_stats.nxt_mnode_fwd_fail;
		ds->mpp_add_fail += mstats->mesh_decap_stats.mpp_add_fail;
		ds->mpp_add_event2host_fail += mstats->mesh_decap_stats.mpp_add_event2host_fail;
		ds->mpp_upate_fail += mstats->mesh_decap_stats.mpp_upate_fail;
		ds->mpp_update_even2host_fail += mstats->mesh_decap_stats.mpp_update_even2host_fail;
		ds->mpp_learn2host_fail += mstats->mesh_decap_stats.mpp_learn2host_fail;
		spin_unlock(&nss_wifi_mesh_stats_lock);
		break;

	default:
		spin_unlock(&nss_wifi_mesh_stats_lock);
		nss_warning("%px: Received invalid dynamic interface type: %d", handle, type);
		nss_assert(0);
	}
}

/*
 * nss_wifi_mesh_stats_notify()
 *	Sends notifications to the registered modules.
 *
 * Leverage NSS-FW statistics timing to update Netlink.
 */
void nss_wifi_mesh_stats_notify(nss_if_num_t if_num, uint32_t core_id)
{
	struct nss_wifi_mesh_stats_notification wifi_mesh_stats;

	if (!nss_wifi_mesh_get_stats(if_num, &wifi_mesh_stats.stats)) {
		nss_warning("No handle is present with ifnum: 0x%x", if_num);
		return;
	}

	wifi_mesh_stats.core_id = core_id;
	wifi_mesh_stats.if_num = if_num;
	atomic_notifier_call_chain(&nss_wifi_mesh_stats_notifier, NSS_STATS_EVENT_NOTIFY, (void *)&wifi_mesh_stats);
}

/*
 * nss_wifi_mesh_stats_dentry_create()
 *	Create Wi-Fi Mesh statistics debug entry
 */
struct dentry *nss_wifi_mesh_stats_dentry_create(void)
{
	struct dentry *stats_dentry_dir;
	struct dentry *stats_file;
	char dir_name[NSS_WIFI_MESH_DENTRY_FILE_SIZE] = {0};

	if (!nss_top_main.stats_dentry) {
		nss_warning("qca-nss-drv/stats is not present");
		return NULL;
	}

	snprintf(dir_name, sizeof(dir_name), "wifi_mesh");

	stats_dentry_dir = debugfs_create_dir(dir_name,  nss_top_main.stats_dentry);
	if (!stats_dentry_dir) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_mesh directory");
		return NULL;
	}

	stats_file = debugfs_create_file("encap_stats", 0400, stats_dentry_dir, &nss_top_main, &nss_wifi_mesh_encap_stats_ops);
	if (!stats_file) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_mesh/encap_stats file");
		goto fail;
	}

	stats_file = debugfs_create_file("decap_stats", 0400, stats_dentry_dir, &nss_top_main, &nss_wifi_mesh_decap_stats_ops);
	if (!stats_file) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_mesh/decap_stats file");
		goto fail;
	}

	stats_file = debugfs_create_file("path_stats", 0400, stats_dentry_dir, &nss_top_main, &nss_wifi_mesh_path_stats_ops);
	if (!stats_file) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_mesh/path_stats file");
		goto fail;
	}

	stats_file = debugfs_create_file("proxy_path_stats", 0400, stats_dentry_dir, &nss_top_main, &nss_wifi_mesh_proxy_path_stats_ops);
	if (!stats_file) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_mesh/proxy_path_stats file");
		goto fail;
	}
	return stats_dentry_dir;
fail:
	debugfs_remove_recursive(stats_dentry_dir);
	return NULL;
}

/**
 * nss_wifi_mesh_stats_register_notifier()
 *	Registers statistics notifier.
 */
int nss_wifi_mesh_stats_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&nss_wifi_mesh_stats_notifier, nb);
}
EXPORT_SYMBOL(nss_wifi_mesh_stats_register_notifier);

/**
 * nss_wifi_mesh_stats_unregister_notifier()
 *	Deregisters statistics notifier.
 */
int nss_wifi_mesh_stats_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&nss_wifi_mesh_stats_notifier, nb);
}
EXPORT_SYMBOL(nss_wifi_mesh_stats_unregister_notifier);
