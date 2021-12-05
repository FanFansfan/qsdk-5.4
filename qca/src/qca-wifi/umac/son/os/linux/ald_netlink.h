/*
 * Copyright (c) 2014, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.

 *  2014 Qualcomm Atheros, Inc.  All rights reserved. 
 *
 *  Qualcomm is a trademark of Qualcomm Technologies Incorporated, registered in the United
 *  States and other countries.  All Qualcomm Technologies Incorporated trademarks are used with
 *  permission.  Atheros is a trademark of Qualcomm Atheros, Inc., registered in
 *  the United States and other countries.  Other products and brand names may be
 *  trademarks or registered trademarks of their respective owners. 
 */

#ifndef _ALD_NETLINK_H_
#define _ALD_NETLINK_H_

#include <osdep.h>
#include "osif_private.h"
#include "wlan_son_ald_external.h"



struct ald_netlink {
    struct sock             *ald_sock;
    struct sk_buff          *ald_skb;
    struct nlmsghdr         *ald_nlh;
    atomic_t                ald_refcnt;
};

extern struct net init_net;

#if QCA_SUPPORT_SON

#define QCA_ALD_GENERIC_EVENTS 1

int son_ald_init_netlink(void);
int son_ald_destroy_netlink(void);
int son_ald_assoc_notify(struct wlan_objmgr_vdev *vdev, u_int8_t *macaddr, u_int8_t aflag, u_int16_t reasonCode);
int son_ald_buffull_notify(struct wlan_objmgr_vdev *vdev);
int son_ioctl_ald_getStatistics(struct net_device *dev, void *info, void *w, char *extra);
void son_buffull_handler(struct wlan_objmgr_pdev *pdev);
int son_ald_cbs_notify(struct wlan_objmgr_vdev *vdev, ald_cbs_event_type type);
int son_ald_acs_complete_notify(struct wlan_objmgr_vdev *vdev);
int son_ald_cac_complete_notify(struct wlan_objmgr_vdev *vdev, u_int8_t radar_detected);
int son_ald_assoc_allowance_status_notify(struct wlan_objmgr_vdev *vdev, u_int8_t *bssid, u_int8_t assoc_status);
int son_ald_wnm_frame_recvd_notify(struct wlan_objmgr_vdev *vdev, u_int8_t action, u_int8_t *macaddr, u_int8_t *frame,
				   u_int16_t frame_len);
int son_ald_anqp_frame_recvd_notify(struct wlan_objmgr_vdev *vdev, u_int8_t *macaddr, u_int8_t *frame, u_int16_t frame_len);

#else /* QCA_SUPPORT_SON */

#define son_ald_init_netlink()   do{}while(0)
#define son_ald_destroy_netlink()    do{}while(0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
#define ald_nl_receive(a)    do{}while(0)
#else
#define ald_nl_receive(a, b) do{}while(0)
#endif
#define son_ald_assoc_notify(a, b, c, d)    do{}while(0)
#define son_ald_buffull_notify(a)    do{}while(0)
#define son_ald_cbs_notify(a, b)   do{}while(0)
#define son_ald_acs_complete_notify(a)   do{}while(0)
#define son_ald_cac_complete_notify(a, b) do{}while(0)
#define son_ald_assoc_allowance_status_notify(a, b, c) do{}while(0)
#define ald_assoc_disallowed_notiy(a, b, c) do{}while(0)
#define son_ald_wnm_frame_recvd_notify(a, b, c, d, e) do{}while(0)
#define son_ald_anqp_frame_recvd_notify(a, b, c, d) do{}while(0)
#define son_ioctl_ald_getStatistics(a, b, c, d)   do{}while(0)
#define son_buffull_handler(a) do{}while(0)

#endif /* QCA_SUPPORT_SON */
#endif /* _ALD_NETLINK_H_ */
