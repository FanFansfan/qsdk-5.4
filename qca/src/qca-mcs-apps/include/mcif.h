/*
 * @File: mcif.h
 *
 * @Abstract: mulitcast interface management module header
 *
 * @Notes:
 *
 * Copyright (c) 2012, 2015, 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2012, 2015 Qualcomm Atheros, Inc.
 *
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef mcif__h
#define mcif__h

#include <sys/types.h>
#include <net/if.h>
#include "internal.h"

/*
 * Maximum amount of interfaces
 */
#define INTERFACE_MAX_INTERFACES      ( 52 )

typedef enum interfaceType_e {
	interfaceType_ETHER,
	interfaceType_WLAN2G,
	interfaceType_WLAN5G,
	interfaceType_PLC,
	interfaceType_MOCA,
	interfaceType_BRIDGE,
	interfaceType_WLAN,
	interfaceType_ESWITCH,
	interfaceType_Reserved
} interfaceType_e;

#undef INTERFACE_ENTRY

typedef enum interfaceGroup_e {
	interfaceGroup_Relaying,
	interfaceGroup_NonRelaying,

	interfaceGroup_Reserved
} interfaceGroup_e;

typedef enum interfaceSync_e {
	interfaceSync_DONE,
	interfaceSync_NEW,
	interfaceSync_UPDATED,
} interfaceSync_e;

/* Interface flags */
#define INTERFACE_FLAGS_NON_QCA		(1 << 0)
#define INTERFACE_FLAGS_ESWITCH		(1 << 1)

typedef struct interface_t {
	u_int32_t index;	/* Internal indexing */
	char name[IFNAMSIZ];	/* Interface name */
	interfaceType_e type;	/* Interface media type */
	u_int32_t systemIndex;	/* Interface system index */
	interfaceGroup_e group;	/* Interface group */
	u_int32_t flags;	/* Flags */

	void *pcData;		/* Path characterization data */

} interface_t;

typedef struct interfaceStats_t {
	u_int64_t rxBytes;	/* RX Statistics */
	u_int64_t rxPackets;
	u_int32_t rxErrors;
	u_int32_t rxDropped;
	u_int32_t rxMulticast;
	u_int64_t rxUnicast;

	u_int64_t txBytes;	/* TX Statistics */
	u_int64_t txPackets;
	u_int32_t txErrors;
	u_int32_t txDropped;
	u_int32_t txMulticast;
	u_int64_t txUnicast;

} interfaceStats_t;

/*
 * API
 */
interfaceType_e interface_getType(const char *ifname);

int interface_isNonSnoopBridge(const char *Name);

int interface_isBlockedInterface(const char *Name);

void interface_init(void);

#endif /* mcif__h */
