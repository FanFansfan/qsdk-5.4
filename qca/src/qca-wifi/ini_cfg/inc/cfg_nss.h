/*
 *
 * Copyright (c) 2018 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef _CFG_NSS_H_
#define _CFG_NSS_H_

#include "cfg_define.h"

#define CFG_NSS_NEXT_HOP CFG_INI_BOOL("nss_wifi_nxthop_cfg", false, \
		"NSS Wifi next hop configuration")

#define CFG_NSS_WIFI_OL CFG_INI_UINT("nss_wifi_olcfg", 0x00 , 0x0f , 0x00, \
		CFG_VALUE_OR_DEFAULT, "NSS Wifi Offload Configuration")

#define CFG_NSS_WIFILI_OL CFG_INI_UINT("nss_wifili_olcfg", 0x00 , 0x07 , 0x00, \
		CFG_VALUE_OR_DEFAULT, "NSS Wifi Offload Configuration")

#define CFG_NSS_WIFILI_RADIO_SCHEME_ENABLE \
	CFG_INI_UINT("nss_wifi_radio_scheme_enable", \
	0, 1, 0, \
	CFG_VALUE_OR_DEFAULT, "NSS Wi-Fi radio scheme enable flag")

#define CFG_NSS_WIFILI_MAP_BITS_PER_RADIO \
	CFG_INI_UINT("nss_wifi_map_bits_per_radio", \
	0, 4, 4, \
	CFG_VALUE_OR_DEFAULT, "Total number of radios")

#define CFG_NSS_WIFILI_RADIO_PRI_MAP \
	CFG_INI_UINT("nss_wifi_radio_pri_map", \
	0, 65535, 0, \
	CFG_VALUE_OR_DEFAULT, "Priority of all radio modes")

#define CFG_NSS \
	CFG(CFG_NSS_NEXT_HOP) \
	CFG(CFG_NSS_WIFI_OL) \
	CFG(CFG_NSS_WIFILI_OL) \
	CFG(CFG_NSS_WIFILI_MAP_BITS_PER_RADIO) \
	CFG(CFG_NSS_WIFILI_RADIO_PRI_MAP) \
	CFG(CFG_NSS_WIFILI_RADIO_SCHEME_ENABLE)

#endif /* _CFG_NSS_H_ */
