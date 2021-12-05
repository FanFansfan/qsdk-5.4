/*
 * @File: mcif.c
 *
 * @Abstract: multcast interface management module
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015, 2017, 2019, 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011, 2015, 2017 Qualcomm Atheros, Inc.
 * All rights reserved.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <interface.h>
#include <split.h>
#include <dbg.h>
#include "mcif.h"
#include "module.h"
#include "profile.h"
#include "mcnl.h"
#ifdef MCS_MODULE_WLAN
#include "wlanManager.h"
#endif
#include "hashmap.h"

static struct {
	struct dbgModule *DebugModule;
	u_int32_t IsInit;
	int32_t IoctlFd;
	struct hmap NonSnoopBridgeMap;		/*Bridge disabled snooping*/
	struct hmap BlockedInterfaceMap;	/*interface that multicast is not allowed */
	struct hmap WifiDeviceMap;		/*Wireless device container */
	struct hmap SwitchDeviceMap;		/*Switch device container*/
} interfaceS;

#define INTERFACE_GROUP_ID_NO_RELAY     0
#define INTERFACE_GROUP_ID_RELAY        1
static struct profileElement interfaceElementDefaultTable[] = {
	{NULL, NULL}
};

#define interfaceDebug(level, ...) \
        dbgf(interfaceS.DebugModule,(level),__VA_ARGS__)

#ifdef MCS_MODULE_WLAN
/*-D- interface_getWirelessFreqType -- return wireless frequence type
 * Could be 2G/5G.
 */
static int interface_getWirelessFreqType(const char *ifname)
{
	struct iwreq Wrq;
	int Ret = 0;

	if (!interfaceS.IsInit)
		return Ret;

	strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(interfaceS.IoctlFd, SIOCGIWFREQ, &Wrq) < 0)
		goto errout;

	if (Wrq.u.freq.m / 100000000 >= 5)
		Ret = interfaceType_WLAN5G;
	else
		Ret = interfaceType_WLAN2G;

errout:
	return Ret;
}

/*-D- interface_getWirelessDeviceType --return which wifi it belong
 * traverse all known wifi device.
 */
static int interface_getWirelessDeviceType(const char *ifname)
{
	char Path[256];
	struct stat Buf = {/*0*/};
	ino_t     Ino;
	struct hmap_node *Nd;

	snprintf(Path, 256, "/sys/class/net/%s/phy80211", ifname);
	if (stat(Path, &Buf) == -1) {
		interfaceDebug(DBGERR,"Error:%s", strerror(errno));
		return 0;
	}
	Ino = Buf.st_ino;

	HMapForEach(Nd, &interfaceS.WifiDeviceMap) {
		snprintf(Path, 256, "/sys/class/net/%s/phy80211", Nd->name);
		if (stat(Path, &Buf) != -1) {
			if (Ino == Buf.st_ino) {
				return interface_getWirelessFreqType(ifname);
			}
		}
	}

	return 0;
}
#endif

/*-F- interface_isNonSnoopBridge -- it is a non-snooping bridge or not
 */
int interface_isNonSnoopBridge(const char *Name)
{
	struct hmap_node *Pn;

	HMapForEach(Pn, &interfaceS.NonSnoopBridgeMap) {
		if (strncmp(Pn->name, Name, IFNAMSIZ) == 0) {
			interfaceDebug(DBGDEBUG, "%s:%s is a non snooping bridge.", __func__, Name);
			return 1;
		}
	}

	interfaceDebug(DBGDEBUG, "%s:%s is a spooping bridge.", __func__, Name);

	return 0;
}

/*-F- interface_isBlockedInterface -- it is a blocked interface or not
 */
int interface_isBlockedInterface(const char *Name)
{
	struct hmap_node *Pn;

	HMapForEach(Pn, &interfaceS.BlockedInterfaceMap) {
		if (strncmp(Pn->name, Name, IFNAMSIZ) == 0) {
			interfaceDebug(DBGDEBUG, "%s:%s is a blocked interface.", __func__, Name);
			return 1;
		}
	}

	interfaceDebug(DBGDEBUG, "%s:%s is a non-blocked interface.", __func__,	Name);

	return 0;
}

/*-D- interface_getEtherDeviceType -- it is an ethernet or switch device
 */
static int interface_getEtherDeviceType(const char *ifname)
{
	struct hmap_node *Pn;

	HMapForEach(Pn, &interfaceS.SwitchDeviceMap) {
		if (!strcmp(Pn->name, ifname)) {
			return interfaceType_ESWITCH;
		}
	}

	return interfaceType_ETHER;
}

/*-F- interface_getType -- get device type
 * It could be 2G/5G/ETHER/SWITCH
 */
interfaceType_e interface_getType(const char *ifname)
{
	int T;

	T = interface_getEtherDeviceType(ifname);
	if (T)
		return T;

#ifdef MCS_MODULE_WLAN
	return interface_getWirelessDeviceType(ifname);
#else
	return interfaceType_ETHER;
#endif
}

/*-D- interface_insertNodeToMapByString -- split the string by ","
 * Each single word will be treated as a node inserted to the map.
 */
static void interface_insertNodeToMapByString(struct hmap *Map, const char *Name)
{
	const char interfaceArray[INTERFACE_MAX_INTERFACES][IFNAMSIZ];
	struct hmap_node *Pn;
	u_int32_t C;
	int N;

	if (!interfaceS.IsInit)
		interface_init();

	interfaceDebug(DBGDEBUG, "%s: input string:%s", __func__, Name);
	C = splitByToken(Name, INTERFACE_MAX_INTERFACES,
			IFNAMSIZ,(char *)interfaceArray, ',');

	for(N = 0 ; N < C; N++) {
		Pn = calloc(1, sizeof(struct hmap_node));
		if (Pn == NULL) {
			interfaceDebug(DBGERR, "%s: Malloc failed", __func__);
			exit(1);
		}
		strlcpy(Pn->name, interfaceArray[N], IFNAMSIZ);
		interfaceDebug(DBGDEBUG, "%s:insert %s to map", __func__, Pn->name);
		hmapInsert(Map, Pn);
	}
}

/* -F- interface_init -- first time script
 */
void interface_init(void)
{
	const char *P;
	int32_t Fd;

	if (interfaceS.IsInit)
		return;

	interfaceS.IsInit = 1;

	interfaceS.DebugModule = dbgModuleFind("interface");

	interfaceDebug(DBGDEBUG, "%s Enter", __func__);

	hmapInit(&interfaceS.NonSnoopBridgeMap, 10);
	hmapInit(&interfaceS.BlockedInterfaceMap, 10);
	hmapInit(&interfaceS.WifiDeviceMap, 10);
	hmapInit(&interfaceS.SwitchDeviceMap, 10);

	/* Initialize bridge from configuration file */
	P = profileGetOpts(mdModuleID_Interface, "NonSnoopBridge", interfaceElementDefaultTable);
	/*prt won't be null*/
	if (P[0]) {
		interface_insertNodeToMapByString(&interfaceS.NonSnoopBridgeMap, P);
	}

	P = profileGetOpts(mdModuleID_Interface, "BlockedInterface", interfaceElementDefaultTable);
	if (P[0]) {
		interface_insertNodeToMapByString(&interfaceS.BlockedInterfaceMap, P);
	}

	P = profileGetOpts(mdModuleID_Interface, "WifiDevice", interfaceElementDefaultTable);
	if (P[0]) {
		interface_insertNodeToMapByString(&interfaceS.WifiDeviceMap, P);
	}

	P = profileGetOpts(mdModuleID_Interface, "SwitchDevice", interfaceElementDefaultTable);
	if (P[0]) {
		interface_insertNodeToMapByString(&interfaceS.SwitchDeviceMap, P);
	}

	Fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (Fd < 0) {
		interfaceDebug(DBGERR, "%s:%s", __func__, strerror(errno));
		return;
	}
	if (fcntl(Fd, F_SETFL, fcntl(Fd, F_GETFL) | O_NONBLOCK) < 0) {
		interfaceDebug(DBGERR, "%s:%s", __func__, strerror(errno));
		return;
	}

	interfaceS.IoctlFd = Fd;

	return;
}

#define IF_MAX_LINE_LENGTH    300
#define IF_STATS_DELIMITERS   "\n\t :"

/* -D- interface_getNextToken -- get next Token split by "\n\t :"
 */
static u_int64_t interface_getNextToken(char *SaveP, MCS_BOOL Conv)
{
	char *Token;
	u_int64_t Val = 0;

	Token = strtok_r(NULL, IF_STATS_DELIMITERS, &SaveP);

	if (Conv && Token) {
		/* Convert the ASCII value to a real number */
		Val = strtoul(Token, NULL, 10);
	}

	return Val;
}

MCS_STATUS interface_getInterfaceStats(interface_t *iface, interfaceStats_t *Stats)
{
	char buffer[IF_MAX_LINE_LENGTH];
	FILE *DevFile;
	MCS_STATUS retval = MCS_NOK;
	char *SaveP;

	/* The /proc/net/dev file contains a list of all interfaces and their statistics.
	 * Here's a snapshot of the format we expect to read.
	 *
	 * The interfaceStats_t structure is a one to one matching to this format.
	 *
	 * Inter-|   Receive                                                |  Transmit
	 *  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	 *     lo:    6121      73    0    0    0     0          0         0     6121      73    0    0    0     0       0          0
	 *   eth0: 1326887   13618    0    0    0     0          0      1219  1500147   13406    0    0    0     0       0          0
	 *
	 */
	if (!Stats || !(DevFile = fopen("/proc/net/dev", "r"))) {
		return MCS_NOK;
	}

	/* Skip the first two lines */
	fgets(buffer, IF_MAX_LINE_LENGTH, DevFile);
	fgets(buffer, IF_MAX_LINE_LENGTH, DevFile);

	/* Now read the statistics */
	while (fgets(buffer, IF_MAX_LINE_LENGTH, DevFile)) {
		char *Token;

		/* Tokenize the line */
		if (!(Token = strtok_r(buffer, IF_STATS_DELIMITERS, &SaveP))) {
			break;
		}

		/* Skip this line if not our interface */
		if (strcmp(Token, iface->name) != 0)
			continue;

		/* Read RX data */
		Stats->rxBytes = interface_getNextToken(SaveP, MCS_TRUE);
		Stats->rxPackets = interface_getNextToken(SaveP, MCS_TRUE);
		Stats->rxErrors = (u_int32_t) interface_getNextToken(SaveP, MCS_TRUE);
		Stats->rxDropped = (u_int32_t) interface_getNextToken(SaveP, MCS_TRUE);
		/* Don't care about fifo, frame, compressed */
		interface_getNextToken(SaveP, MCS_FALSE);
		interface_getNextToken(SaveP, MCS_FALSE);
		interface_getNextToken(SaveP, MCS_FALSE);
		Stats->rxMulticast = (u_int32_t) interface_getNextToken(SaveP, MCS_TRUE);
		Stats->rxUnicast = Stats->rxPackets - Stats->rxMulticast;

		/* Read TX data */
		Stats->txBytes = interface_getNextToken(SaveP, MCS_TRUE);
		Stats->txPackets = interface_getNextToken(SaveP, MCS_TRUE);
		Stats->txErrors = (u_int32_t) interface_getNextToken(SaveP, MCS_TRUE);
		Stats->txDropped = (u_int32_t) interface_getNextToken(SaveP, MCS_TRUE);
		Stats->txUnicast = Stats->txPackets;

		retval = MCS_OK;
	}

	fclose(DevFile);

	return retval;
}

