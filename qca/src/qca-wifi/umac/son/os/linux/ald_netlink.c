/*
 * Copyright (c) 2015, 2017, 2019-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 *  Copyright (c) 2010, Atheros Communications Inc.
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
#include "linux/if.h"
#include "linux/socket.h"
#include <net/rtnetlink.h>
#include <net/sock.h>

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>

#if QCA_SUPPORT_SON
#include "ald_netlink.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif

#include <wlan_son_pub.h>
#include "wlan_son_internal.h"
#include <wlan_osif_priv.h>
#include <wlan_utility.h>
#include <dp_txrx.h>

struct ald_netlink *ald_nl = NULL;
unsigned int netlink_son_ald = NETLINK_ALD;
module_param(netlink_son_ald, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void son_ald_nl_receive(struct sk_buff *__skb);
#else
static void son_ald_nl_receive(struct sock *sk, int len);
#endif

int son_ald_init_netlink(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION (3,10,0)
	struct netlink_kernel_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.groups = 1;
	cfg.input = &son_ald_nl_receive;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	struct netlink_kernel_cfg cfg = {
		.groups = 1,
		.input  = son_ald_nl_receive,
	};
#endif

	if (ald_nl == NULL) {
		ald_nl = (struct ald_netlink *)qdf_mem_malloc(sizeof(struct ald_netlink));
		if(ald_nl == NULL)
			return -ENODEV;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)/* Also for >= 3,10,0 */
		ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, netlink_son_ald, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
		ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, netlink_son_ald,
									THIS_MODULE, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
		ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, netlink_son_ald, 1,
									&son_ald_nl_receive, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
		ald_nl->ald_sock = (struct sock *)netlink_kernel_create(netlink_son_ald, 1, &son_ald_nl_receive,
									(struct mutex *) NULL, THIS_MODULE);
#else
		ald_nl->ald_sock = (struct sock *)netlink_kernel_create(netlink_son_ald, 1, &son_ald_nl_receive,
									THIS_MODULE);
#endif

		if (ald_nl->ald_sock == NULL) {
			qdf_mem_free(ald_nl);
			ald_nl = NULL;
			SON_LOGE("%s NETLINK_KERNEL_CREATE FAILED\n", __func__);
			return -ENODEV;
		}

		atomic_set(&ald_nl->ald_refcnt, 1);
	} else {
		atomic_inc(&ald_nl->ald_refcnt);
	}

	return EOK;
}

int son_ald_destroy_netlink(void)
{
	if (ald_nl == NULL) {
		SON_LOGE("\n%s ald_nl is NULL\n", __func__);
		return -ENODEV;
	}

	if (!atomic_dec_return(&ald_nl->ald_refcnt)) {
		if (ald_nl->ald_sock)
			netlink_kernel_release(ald_nl->ald_sock);

		qdf_mem_free(ald_nl);
		ald_nl = NULL;
	}

	return EOK;
}


static void son_ald_notify(struct wlan_objmgr_vdev *vdev, u_int32_t info_cmd,
			   u_int32_t info_len, void *info_data)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;
	u_int8_t *nldata = NULL;
	struct son_vdev_priv *vd_priv = NULL;
	u_int32_t pid = WLAN_DEFAULT_NETLINK_PID;

	if (ald_nl == NULL || vdev == NULL)
		return;

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv)
		return;
	pid = vd_priv->ald_pid;

	if (pid == WLAN_DEFAULT_NETLINK_PID)
		return;

	skb = nlmsg_new(info_len, GFP_ATOMIC);
	if (!skb) {
		SON_LOGE("%s: No memory, info_cmd = %d\n",
			 __func__, info_cmd);
		return;
	}

	nlh = nlmsg_put(skb, pid, 0, info_cmd, info_len, 0);
	if (!nlh) {
		SON_LOGE("%s: nlmsg_put() failed, info_cmd = %d\n",
			 __func__, info_cmd);
		kfree_skb(skb);
		return;
	}

	nldata = NLMSG_DATA(nlh);
	qdf_mem_copy(nldata, info_data, info_len);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	NETLINK_CB(skb).pid = 0; /* from kernel */
#else
	NETLINK_CB(skb).portid = 0; /* from kernel */
#endif

	if (wlan_son_is_vdev_event_bcast_enabled(vdev)) {
		NETLINK_CB(skb).dst_group = QCA_ALD_GENERIC_EVENTS; /* broadcast */
		netlink_broadcast(ald_nl->ald_sock, skb, 0,
				  QCA_ALD_GENERIC_EVENTS, GFP_ATOMIC);
	} else {
		NETLINK_CB(skb).dst_group = 0;  /* unicast */
		netlink_unicast(ald_nl->ald_sock, skb, pid, MSG_DONTWAIT);
	}
}

static void son_ald_send_info_iter_func(struct wlan_objmgr_vdev *vdev)
{
	struct net_device *dev;
	struct ald_stat_info *info = NULL;
	struct son_vdev_priv *vd_priv = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	osif_dev *osifp = NULL;

	info = qdf_mem_malloc(sizeof(struct ald_stat_info));
	if (info == NULL)
		return;

	if ((vdev == NULL) ||
	    (wlan_vdev_is_delete_in_progress(vdev))) {
		goto err;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp)
		goto err;

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp)
		goto err;

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv)
		goto err;

	if ((wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS) &&
	    vd_priv->ald_pid != WLAN_DEFAULT_NETLINK_PID) {
		info->cmd = IEEE80211_ALD_ALL;

		dev = osifp->netdev;
		if (!dev)
			goto err;

		if (strlcpy(info->name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
			SON_LOGE("%s: source too long",__func__);
			goto err;
		}

		vd_priv->iv_ald->staticp = info;
		son_ald_get_statistics(vdev, NULL);
		vd_priv->iv_ald->staticp = NULL;

		son_ald_notify(vdev, IEEE80211_ALD_ALL, sizeof(struct ald_stat_info), info);
	}

err:
	qdf_mem_free(info);
}

static void son_ald_nl_hifitbl_update(struct wlan_objmgr_vdev *vdev, struct nlmsghdr *nlh)
{
	if ((vdev == NULL) || (nlh == NULL))
		return;

	wlan_update_hifitbl(vdev, nlh);
}

/* Note: This function takes RTNL lock */
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void son_ald_nl_receive(struct sk_buff *__skb)
#else
static void son_ald_nl_receive(struct sock *sk, int len)
#endif
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	struct net_device *dev = NULL;
	osif_dev *osifp = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	struct son_vdev_priv *vd_priv = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	u_int32_t pid;
	int32_t ifindex;

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
	if ((skb = skb_get(__skb)) != NULL) {
#else
	if ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
#endif
		nlh = nlmsg_hdr(skb);
		pid = nlh->nlmsg_pid;
		ifindex = nlh->nlmsg_flags;

		dev = dev_get_by_index(&init_net, ifindex);
		if (!dev) {
			SON_LOGE("%s: Invalid interface index:%d\n",
				 __func__, ifindex);
			kfree_skb(skb);
			return;
		}

		osifp = ath_netdev_priv(dev);
		if (!osifp) {
			SON_LOGE("%s: osifp is NULL", __func__);
			goto out;
		}

		if (osifp ->is_deleted) {
			SON_LOGE("%s: vap[%s] has been deleted",
				 __func__, dev->name);
			goto out;
		}

		vdev = osifp->ctrl_vdev;
		status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
		if (QDF_IS_STATUS_ERROR(status)) {
			SON_LOGE("%s: Unable to get reference", __func__);
			goto out;
		}

		vd_priv = wlan_son_get_vdev_priv(vdev);
		if (!vd_priv) {
			SON_LOGE("%s: SON vdev priv is NULL", __func__);
			wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
			goto out;
		}

		if(ald_nl == NULL) {
			SON_LOGE("%s: ald nl sock is NULL", __func__);
			wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
			goto out;
		}

		/* Take rtnl lock on ald netlink path, so no other thread queries in parallel
		 * Note: This lock needs to be removed when moving to nl80211 or IOCTL path.
		 */
		rtnl_lock();
		if (vd_priv->ald_pid != pid)
			vd_priv->ald_pid = pid;

		if (nlh->nlmsg_type == IEEE80211_ALD_ALL)
			son_ald_send_info_iter_func(vdev);
		else if (nlh->nlmsg_type == IEEE80211_ALD_MCTBL_UPDATE)
			son_ald_nl_hifitbl_update(vdev, nlh);
		rtnl_unlock();

		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
out:
		dev_put(dev);
		kfree_skb(skb);
	}
}

int son_ald_assoc_notify(struct wlan_objmgr_vdev *vdev, u_int8_t *macaddr,
			 u_int8_t aflag, u_int16_t reasonCode)
{
	struct net_device *dev = NULL;
	wlan_chan_t chan = NULL;
	struct ald_assoc_info info;
	struct vdev_osif_priv *vdev_osifp = NULL;
	osif_dev *osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_ASSOCIATE;
	if (strlcpy(info.name, dev->name , IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	chan = wlan_vdev_get_current_channel(vdev, true);
	if (!chan) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	if(chan->ic_freq * 100000 < 500000)
		info.afreq = ALD_FREQ_24G;
	else
		info.afreq = ALD_FREQ_5G;
	info.aflag = aflag;
	qdf_mem_copy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
	info.reasonCode = reasonCode;
	son_ald_notify(vdev, IEEE80211_ALD_ASSOCIATE, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function for 75% buffers full warning */
int son_ald_buffull_notify(struct wlan_objmgr_vdev *vdev)
{
	struct net_device *dev = NULL;
	struct ald_buffull_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_BUFFULL_WRN;
	if (strlcpy(info.name, dev->name , IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	info.resv = ATH_TXBUF;
	son_ald_notify(vdev, IEEE80211_ALD_BUFFULL_WRN, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function to notify CBS event */
int son_ald_cbs_notify(struct wlan_objmgr_vdev *vdev, ald_cbs_event_type type)
{
	struct net_device *dev = NULL;
	struct ald_cbs_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_CBS;
	if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	info.type = type;
	son_ald_notify(vdev, IEEE80211_ALD_CBS, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function to notify ACS Neighbour Scan complete */
int son_ald_acs_complete_notify(struct wlan_objmgr_vdev *vdev)
{
	struct net_device *dev = NULL;
	struct ald_cbs_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_ACS_COMPLETE;
	if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	info.type = ALD_CBS_COMPLETE;
	son_ald_notify(vdev, IEEE80211_ALD_ACS_COMPLETE, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	 return 0;
}

/* function to notify CAC complete */
int son_ald_cac_complete_notify(struct wlan_objmgr_vdev *vdev, u_int8_t radar_detected)
{
	struct net_device *dev = NULL;
	struct ald_cac_complete_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_CAC_COMPLETE;
	if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	info.radar_detected = radar_detected;
	son_ald_notify(vdev, IEEE80211_ALD_CAC_COMPLETE, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function to notify change in BSS assoc allowance status */
int son_ald_assoc_allowance_status_notify(struct wlan_objmgr_vdev *vdev,
					  u_int8_t *bssid, u_int8_t assoc_status)
{
	struct net_device *dev = NULL;
	struct ald_assoc_allowance_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = IEEE80211_ALD_ASSOC_ALLOWANCE_STATUS_CHANGE;
	if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	qdf_mem_copy(info.bssid, bssid, IEEE80211_ADDR_LEN);
	info.assoc_status = assoc_status;
	son_ald_notify(vdev, IEEE80211_ALD_ASSOC_ALLOWANCE_STATUS_CHANGE, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function to send WNM request frame to userspace */
int son_ald_wnm_frame_recvd_notify(struct wlan_objmgr_vdev *vdev, u_int8_t action,
				   u_int8_t *macaddr, u_int8_t *frame, uint16_t frame_len)
{
	struct net_device *dev = NULL;
	struct ald_wnm_frame_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	info.cmd = action;
	if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	qdf_mem_copy(info.macaddr, macaddr, IEEE80211_ADDR_LEN);
	qdf_mem_copy(info.frame, frame, frame_len);
	info.frameSize = frame_len;
	son_ald_notify(vdev, IEEE80211_ALD_WNM_FRAME_RECEIVED, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

/* function to send ANQP neighbor report request frame to userspace */
int son_ald_anqp_frame_recvd_notify(struct wlan_objmgr_vdev *vdev, u_int8_t *macaddr,
				    u_int8_t *frame, uint16_t frame_len)
{
	struct net_device *dev;
	struct ald_anqp_frame_info info;
	osif_dev *osifp = NULL;
	struct vdev_osif_priv *vdev_osifp = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -1;
	}

	vdev_osifp = wlan_vdev_get_ospriv(vdev);
	if (!vdev_osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	osifp = (osif_dev *)vdev_osifp->legacy_osif_priv;
	if (!osifp) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	dev = osifp->netdev;
	if (!dev) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}

	if ((frame_len > ALD_MAX_FRAME_SZ) ||
	    (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ)) {
		SON_LOGE("%s: source too long\n", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -1;
	}
	qdf_mem_copy(info.macaddr, macaddr, IEEE80211_ADDR_LEN);
	qdf_mem_copy(info.frame, frame, frame_len);
	info.frameSize = frame_len;
	son_ald_notify(vdev, IEEE80211_ALD_ANQP_FRAME_RECEIVED, sizeof(info), &info);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return 0;
}

int son_ioctl_ald_getStatistics(struct net_device *dev, void *vinfo, void *w, char *extra)
{
	osif_dev *osifp = NULL;
	int retv = 0;
	struct ald_stat_info *param = NULL;
	struct son_vdev_priv *vd_priv = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!dev)
		return -EINVAL;

	osifp = ath_netdev_priv(dev);
	if (!osifp)
		return -EINVAL;

	vdev = osifp->ctrl_vdev;
	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -EINVAL;
	}

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -EINVAL;
	}

	param = (struct ald_stat_info *)qdf_mem_malloc(sizeof(struct ald_stat_info));
	if (!param) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -ENOMEM;
	}

	if (copy_from_user(param, ((union iwreq_data *)w)->data.pointer,
			   sizeof(struct ald_stat_info))) {
		qdf_mem_free(param);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -EFAULT;
	}

	SON_LOGD("%s parameter is %s 0x%x get1\n", __func__, param->name, param->cmd);

	retv = son_ald_get_statistics(vdev, param);
	vd_priv->iv_ald->staticp = NULL;

	if(!copy_to_user(((union iwreq_data *)w)->data.pointer, param,
			 sizeof(struct ald_stat_info))) {
		SON_LOGE("%s:%d copy to user failed", __func__, __LINE__);
		retv = -EFAULT;
	}

	qdf_mem_free(param);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return retv;
}

static void son_bufful_iter(struct wlan_objmgr_pdev *pdev,
			    void *obj, void *arg)
{
	struct wlan_objmgr_vdev *vdev = obj;

	wlan_vdev_deliver_bufful_event(vdev);
}

void son_buffull_handler(struct wlan_objmgr_pdev *pdev)
{
	if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_SON_ID) !=
	    QDF_STATUS_SUCCESS) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return;
	}

	wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
					  son_bufful_iter,
					  NULL, 0, WLAN_SON_ID);

	wlan_objmgr_pdev_release_ref(pdev, WLAN_SON_ID);
}
qdf_export_symbol(son_buffull_handler);

#endif /* QCA_SUPPORT_SON */
