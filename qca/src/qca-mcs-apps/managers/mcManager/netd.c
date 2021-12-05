/*
 * @File: mcsNetScan.c
 *
 * @Abstract: Monitoring the bridge creationg and destroy
 *
 * @Notes:
 *
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <dbg.h>
#include <nlrd.h>
#include <evloop.h>
#include <cmd.h>
#include "module.h"
#include "mcManager.h"
#include "hashmap.h"
#include "mcif.h"

#ifndef MAX_PORTS
# define MAX_PORTS 32
#endif

/* netdState_t -- global data for netd
 */
static struct netdState_t {
	u_int32_t IsInit;		/* overall initialization done */
	struct nlrd BridgeLink;		/* netlink socket */
	struct dbgModule *DebugModule;	/* debug message context*/
} netdS;

/* Debugging options */
#define netdDebug(level, ...) \
                     dbgf(netdS.DebugModule,(level),__VA_ARGS__)

/* -D- netdIsOvsBridge -- Check the name if it is a real bridge in the ovs system.
 */
static int netdIsOvsBridge(const char *Name)
{
	char OvsCommand[128];
	int status;

	snprintf(OvsCommand, sizeof(OvsCommand), "ovs-vsctl br-exists %s >/dev/null 2>&1", Name);
	status = system(OvsCommand);
	if (status == 0)
		return 1;

	return 0;
}

/* -D- netdIsLinuxBridge -- Check the name if it is a bridge in linux
 * kernel.
 */
static int netdIsLinuxBridge(const char *Name)
{
	char Path[128];
	struct stat St = {/*0*/};

	snprintf(Path, sizeof(Path), "/sys/class/net/%s/bridge", Name);
	if (stat(Path, &St) == 0 && S_ISDIR(St.st_mode))
		return 1;

	return 0;
}

/* -D- netdIsBridge -- Check the name is of a linux bridge or ovs bridge
 */
static inline int netdIsBridge(const char *Name)
{
	return netdIsLinuxBridge(Name) || netdIsOvsBridge(Name);
}

/* -D- netdBridgeLinkNLCB -- netlink NEWLINK message handler
 * -- it start the snooper when it gets the new link and it is a bridge device
 */
static void netdBridgeLinkNLCB(void *Cookie)
{
	struct nlrd *R = Cookie;
	int Size = nlrdNBytesGet(R);
	struct nlmsghdr *NLHeader = nlrdBufGet(R);
	struct rtattr  *Ra;
	const char *Name;
	int Length;

	if (nlrdErrorGet(R)) {
		netdDebug(DBGERR, "%s Read error, Create it again", __func__);
		nlrdDestroy(R);
		nlrdCreate(&netdS.BridgeLink, "BridgeLink", NETLINK_ROUTE, RTNLGRP_LINK, netdBridgeLinkNLCB, &netdS.BridgeLink);
		return;
	}

	if (!Size)
		return;

	Length = Size;
	for (; NLMSG_OK(NLHeader, Length); NLHeader = NLMSG_NEXT(NLHeader, Length)) {
		switch(NLHeader->nlmsg_type) {
		case RTM_NEWLINK:
			Ra = nlrdGetRta(NLHeader, IFLA_IFNAME);
			if (Ra == NULL) {
				break;
			}

			Name = RTA_DATA(Ra);
			if (!netdIsBridge(Name)) {
				netdDebug(DBGDEBUG, "%s:%s is not a bridge, discard it", __func__, Name);
				break;
			}

			if (interface_isNonSnoopBridge(Name)) {
				netdDebug(DBGDEBUG, "%s:%s is non snooping bridge", __func__, Name);
				break;
			}

			mcManagerStart(Name);

			break;

		case RTM_DELLINK:
			Ra = nlrdGetRta(NLHeader, IFLA_IFNAME);
			if (Ra == NULL) {
				break;
			}
			Name = RTA_DATA(Ra);

			/* At this time, the bridge's attribute could be
			 * removed, let's check if any snooper has the same
			 * name.
			 */
			mcManagerStop(Name);

			break;
		default:
			netdDebug(DBGDEBUG, "%s: netlink message[%d] ignored",__func__, NLHeader->nlmsg_type);
			break;
		}
	}

	nlrdConsume(R, Size);
}

/* -F- netdInit -- first time init
 */
void netdInit(void)
{

	if (netdS.IsInit)
		return;

	memset(&netdS, 0, sizeof netdS);
	netdS.IsInit = 1;
	netdS.DebugModule = dbgModuleFind("netd");

	netdDebug(DBGDEBUG, "ENTER netdInit");

	/* Link ready event receiver*/
	nlrdCreate(&netdS.BridgeLink, "BridgeLink", NETLINK_ROUTE, RTNLGRP_LINK,
			netdBridgeLinkNLCB, &netdS.BridgeLink);

	/*Sent netlink message to dump existing network device*/
	nlrdDumpLinkReq(&netdS.BridgeLink);
}
