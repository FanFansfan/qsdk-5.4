/*
 * @File: linux_netif.c
 *
 * @Abstract: Son CLI linux wrapper functions
 *
 * @Notes:
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include <net/if.h>

void convert_ifindex_to_ifname(int sys_index, char *ifname)
{
    if_indextoname(sys_index, ifname);
}

int convert_ifname_to_ifindex(const char *ifname)
{
    return if_nametoindex(ifname);
}
