#!/bin/sh
# Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

MAP_VLANMON_DEBUG_OUTOUT=0
NETWORK_TYPE_LAN=""
NETWORK_TYPE_GUEST1=""
NETWORK_TYPE_GUEST2=""
NETWORK_TYPE_GUEST3=""
NETWORK_TYPE_BACKHAUL=""
MAP_GET_STA_VLAN_IOCTL="get_map_sta_vlan"
num_guest_vlan=0
vid_lan=0 vid_guest1=0 vid_guest2=0 vid_guest3=0
sta_vid=0 map_primary_bsta_vid=0
vid_8021q=0
MAP_IS_GW_REACHABLE=0
upstream_version=0
map_my_version=0
map_ts_active=0
map_ts_apply=0
map_ts_remove=0
maplite_enabled=0
eth_iface="" sta_iface=""
map_bsta_backhaul=0
map_fh_bh_vap_up=1
map_onboarding_done=0
map_gw_reachable_confirm_attempts=1
map_enable_vlan_logs=0
map_single_r1r2_bh=0
config_changed=0
sta_config_changed=0
maplite_restart_config=1
config_load 'repacd'
config_get_bool ezmesh repacd 'Ezmesh' '0'
    if [ "$ezmesh" -eq 1 ]; then
        MAP='ezmesh'
    else
        MAP='hyd'
    fi

# Emit a message at debug level.
# input: $1 - the message to log
__repacd_map_vlanmon_debug() {
    if [ "$map_enable_vlan_logs" -eq 0 ]; then
        return
    fi

    local stderr=''
    if [ "$MAP_VLANMON_DEBUG_OUTOUT" -gt 0 ]; then
        stderr='-s'
    fi

    logger $stderr -t repacd.mapvlanmon -p user.debug "$1"
}

# Determine if the network is configured or not.
#
# input: $1 network name
# return: 0 if network exist; otherwise non-zero
__repacd_network_exist() {
    local lan_name=$1
    local no_network

    no_network=$(uci show "network.$lan_name" 2>&1 | grep 'Entry not found')
    [ -n "$no_network" ] && return 1

    return 0
}

# Add the given interface to the given network.
# input: $1 network name
# input: $2 interface name
__repacd_add_interface() {
    local name=$1 new_if="$2"
    local if_name iface_name iface_vid

    # ubus network reload might miss adding vlan config
    # Add this check to remove and add back interface in traffic
    # separation is active and apply is set to 1
    if [ "$map_ts_active" -eq 1 -a "$map_ts_apply" -eq 1 ]; then
        __repacd_delete_interface $name $new_if
    fi

    if __repacd_network_exist "$name"; then
        if [ -n "$new_if" ]; then
            if_name=$(uci get "network.$name.ifname")
            if [ -n "$if_name" ]; then
                if_name="$if_name $new_if"
            else
                if_name="$new_if"
            fi
            if_name=$(echo "$if_name" | xargs -n1 | sort -u | xargs)
            uci_set network "$name" ifname "$if_name"
            if [ "$maplite_enabled" -eq 1 ]; then
                iface_name=$(echo $new_if | cut -d '.' -f1 | awk '{$1=$1};1')
                iface_vid=$(echo $new_if | cut -d '.' -f2 | awk '{$1=$1};1')
                if [ -n "$iface_vid" ] && [[ "$iface_vid" != "$if_name" ]]; then
                    __repacd_map_vlanmon_debug "network $name $iface_name $iface_vid $new_if"
                    vconfig add "$iface_name" "$iface_vid"
                    ifconfig "$new_if" up
                    brctl addif "br-$name" "$new_if"
                fi
            fi
        fi
    fi

    uci_commit network

    if [ "$maplite_enabled" -ne 1 ]; then
        ubus call network reload
    fi
}

# Delete the given interface from the given network.
# input: $1 network name
# input: $2 interface name
__repacd_delete_interface() {
    local name=$1 interface="$2"
    local if_name
    local new_if=' '

    if __repacd_network_exist "$name"; then
        if [ -n "$interface" ]; then
            if_name=$(uci get "network.$name.ifname")
            uci_set network "$name" ifname ' '
            for iface in $if_name; do
                if [ "$interface" != "$iface" ]; then
                    if [ -n "$new_if" ]; then
                        new_if="$new_if $iface"
                    else
                        new_if="$iface"
                    fi
                fi
            done
            uci_set network "$name" ifname "$new_if"
        fi
    fi

    uci_commit network
    ubus call network reload
}

# Set egress and ingress priority map per VLAN interface
__repacd_map_set_egress_ingress_per_intf() {
    local ifname="$1"
    local vlan_id="$2"

    vconfig set_egress_map "$ifname.$vlan_id" 0 0
    vconfig set_egress_map "$ifname.$vlan_id" 1 1
    vconfig set_egress_map "$ifname.$vlan_id" 2 2
    vconfig set_egress_map "$ifname.$vlan_id" 3 3
    vconfig set_egress_map "$ifname.$vlan_id" 4 4
    vconfig set_egress_map "$ifname.$vlan_id" 5 5
    vconfig set_egress_map "$ifname.$vlan_id" 6 6
    vconfig set_egress_map "$ifname.$vlan_id" 7 7
    vconfig set_ingress_map "$ifname.$vlan_id" 0 0
    vconfig set_ingress_map "$ifname.$vlan_id" 1 1
    vconfig set_ingress_map "$ifname.$vlan_id" 2 2
    vconfig set_ingress_map "$ifname.$vlan_id" 3 3
    vconfig set_ingress_map "$ifname.$vlan_id" 4 4
    vconfig set_ingress_map "$ifname.$vlan_id" 5 5
    vconfig set_ingress_map "$ifname.$vlan_id" 6 6
    vconfig set_ingress_map "$ifname.$vlan_id" 7 7
}

# Create necessary VLAN interfaces for the backhaul vaps and add the
# created VLAN interfaces to the given network.
# VLAN interfaces are created by concatenating interface name and vlan id.
# input: $1 network name
# input: $2 iface name
# input: $3 VLAN id
__repacd_add_vlan_interfaces() {
    local network=$1
    local ifname=$2
    local id=$3
    local add_vlan=0
    local vlan_ifname vlan_ifname_brctl vlan_ifname_nw
    local iface_nw_list iface_name iface_vid
    local iface_nw

    if [ -z "$network" ] || [ -z "$ifname" ]; then
        __repacd_map_vlanmon_debug "Invalid network $network iface $ifname"
    fi

    # if current vlan is different from previous delete older vlan config
    iface_nw_list=$(uci get network.$network.ifname)
    for iface_nw in $iface_nw_list; do
        echo "$iface_nw" | grep '\.' >/dev/null 2>&1
        if [ "$?" -eq "0" ]; then
            iface_name=$(echo $iface_nw | cut -d '.' -f1 | awk '{$1=$1};1')
            iface_vid=$(echo $iface_nw | cut -d '.' -f2 | awk '{$1=$1};1')

            if [ "$iface_name" = "$ifname" ]; then
                if [ "$iface_vid" -eq "$id" ];then
                    continue
                else
                    __repacd_map_vlanmon_debug "removing vlan configured iface $iface_nw"
                    __repacd_delete_interface $network $iface_nw

                    # Check if VLAN interface is part of bridge
                    vlan_ifname_brctl=$(brctl show br-"$network" | grep -w "$iface_nw" | awk '{print $1}')
                    if [ -z "$vlan_ifname_brctl" ]; then
                        __repacd_map_vlanmon_debug "Delete interface $iface_nw from network config"
                        __repacd_delete_interface $network $iface_nw
                    fi
                fi
            fi
        fi
    done

    # if VLAN ID is 0 return
    if [ "$id" -eq 0 ]; then
        __repacd_map_vlanmon_debug "VLAN ID is 0 for network $network iface $ifname"
        return
    fi

    # Check if network is part of bridge
    brctl_nw=$(brctl show | grep -w "br-$network" | awk '{print $1}')
    if [ -z "$brctl_nw" ]; then
        __repacd_map_vlanmon_debug "br-$network not part of bridge"
        return
    fi

    # Check if VLAN interface is already created
    vlan_ifname=$(iwconfig 2>&1 | grep -o "$ifname.$id")
    if [ -z "$vlan_ifname" ]; then
        __repacd_map_vlanmon_debug "VLAN for Interface $ifname and $id not created"
        add_vlan=1
    fi

    # Check if VLAN interface is part of bridge
    vlan_ifname_brctl=$(brctl show br-"$network" | grep -w "$ifname.$id" | awk '{print $1}')
    if [ -z "$vlan_ifname_brctl" ]; then
        __repacd_map_vlanmon_debug "VLAN for Interface $ifname and $id not part of bridge"
        add_vlan=1
    fi

    # Check if VLAN interface is part of network
    vlan_ifname_nw=$(uci show network.$network.ifname 2>&1 | grep -w "$ifname.$id")
    if [ -z "$vlan_ifname_nw" ]; then
        __repacd_map_vlanmon_debug "VLAN for Interface $ifname and $id not part of $network"
        add_vlan=1
    fi

    # Apply VLAN
    if [ "$add_vlan" -eq 1 ]; then
        __repacd_map_vlanmon_debug "VLAN not set. Apply Vlan $ifname $id br-$network"
        map_ts_apply=1
        map_ts_remove=0
        config_changed=1
        __repacd_add_interface "$network" "$ifname.$id"

        # Check if SP is enabled
        config_load $MAP
        config_get sp_enabled MAPSPSettings 'EnableSP' '0'

        if [ "$sp_enabled" -eq 1 ]; then
            __repacd_map_set_egress_ingress_per_intf $ifname $id
            # Set priority maps for sta vap with primary VLAN ID.
            # Because sta vap with primary VLAN ID is created
            # when assoc response is recieved, after wifi restart
            # during onboarding, the priority map is changed to default.
            # For this reason, this VAP is specially handled.
            if [ "$map_bsta_backhaul" -eq 1 ]; then
                pm_already_set=$(cat /proc/net/vlan/"$sta_iface"."$map_primary_bsta_vid" | grep EGRESS \
                            | awk '{print $4}')
                if [ -z "$pm_already_set" ]; then
                    __repacd_map_set_egress_ingress_per_intf $sta_iface $map_primary_bsta_vid
                fi
            fi
        fi

    elif [ "$add_vlan" -eq 0 ]; then
        __repacd_map_vlanmon_debug " $id already applied on $ifname for $network"
        map_ts_active=1
        map_ts_apply=0
        map_ts_remove=0
    fi

    # Set Switch Config for ETH Interface for secondary VLANs
    if [ "$add_vlan" -eq 1 -a "$vid_lan" -ne "$id" ]; then
        __repacd_map_vlanmon_debug "Add VLAN $id for ethernet guest network support"
        swconfig dev switch0 vlan $id set ports "0t 1t 2t 3t 4t"
        swconfig dev switch0 vlan $id set ports "0t 1t 2t 3t 4t"
        swconfig dev switch0 set apply
    fi
}

# Create necessary VLAN interfaces for guest networks if they are valid
# input: $1 ifaceBH name
__repacd_add_guest_network_vlan_interfaces() {
    local ifaceBH="$1"

    if [ -n "$NETWORK_TYPE_GUEST1" ]; then
        __repacd_add_vlan_interfaces $NETWORK_TYPE_GUEST1 $ifaceBH $vid_guest1
    fi
    if [ -n "$NETWORK_TYPE_GUEST2" ]; then
        __repacd_add_vlan_interfaces $NETWORK_TYPE_GUEST2 $ifaceBH $vid_guest2
    fi
    if [ -n "$NETWORK_TYPE_GUEST3" ]; then
        __repacd_add_vlan_interfaces $NETWORK_TYPE_GUEST3 $ifaceBH $vid_guest3
    fi
}

# Remove VLAN interfaces for guest networks if they are valid
# input: $1 iface name
__repacd_delete_guest_nw_sta_vlan_interfaces() {
    local iface="$1"

    if [ -n "$NETWORK_TYPE_GUEST1" ]; then
        __repacd_delete_interface $NETWORK_TYPE_GUEST1 $iface.$vid_guest1
    fi
    if [ -n "$NETWORK_TYPE_GUEST2" ]; then
        __repacd_delete_interface $NETWORK_TYPE_GUEST2 $iface.$vid_guest2
    fi
    if [ -n "$NETWORK_TYPE_GUEST3" ]; then
        __repacd_delete_interface $NETWORK_TYPE_GUEST3 $iface.$vid_guest3
    fi
}

# Check if backhaul BSS are VLAN configured. If not apply VLAN read at init
# for each backhaul for primary and secondary networks
# input: $1 config
__repacd_map_vlanmon_check_bh_bss_vlan_config() {
    local config="$1"
    local iface network disabled device ifaceBH

    config_get iface "$config" ifname
    config_get network "$config" network
    config_get disabled "$config" disabled '0'
    config_get mode "$config" mode
    config_get mapVlanID "$config" mapVlanID '0'
    config_get MapBSSType "$config" MapBSSType '0'

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_BACKHAUL \
            -a "$mode" != "sta" ]; then

        # if r2 STA Assoc DisAllowed do not create vlan
        if [ $(($((MapBSSType&4)) >> 2)) -eq 1 ]; then
            return
        fi

        ifaceBH=$iface
        __repacd_map_vlanmon_debug "backhaul BSS $iface. Set VLAN"
        if [ -n "$NETWORK_TYPE_LAN" ]; then
            if [ "$map_single_r1r2_bh" -eq 1 ]; then
                if [ "$iface" != "$sta_iface" ]; then
                    ifconfig $iface up
                    __repacd_add_interface "$NETWORK_TYPE_LAN" "$iface"
                fi
            fi
            __repacd_add_vlan_interfaces $NETWORK_TYPE_LAN $iface $vid_lan
        fi

        __repacd_add_guest_network_vlan_interfaces $ifaceBH
    fi
}

# Check if backhaul link is VLAN configured.
# if backhaul is eth: apply vlan only on guest networks (per spec)
# if backhaul is sta: get vlan id from IOCTL set from assoc response
# and apply primary and secondary VLANs
__repacd_map_vlanmon_check_backhaul_vlan_config() {
    local ifaces_eth ifaces iface_wan

    __repacd_map_vlanmon_debug " [ Configure backhaul Link with VLAN ] "

    if [ "$map_bsta_backhaul" -eq 1 ]; then
        __repacd_map_vlanmon_debug "backhaul Type STA; iface: $sta_iface"
        eth_iface=""
        local staBitRate=$(repacdcli $sta_iface get_bitrate)
        if [ "$staBitRate" -eq 0 -o -z "$staBitRate" ]; then
            __repacd_map_vlanmon_debug "Sta Bit Rate Invalid"
            ifconfig $sta_iface up
            return
        fi

        if [ -n "$NETWORK_TYPE_LAN" ]; then
            # Apply VLAN on STA Interface
            if [ "$sta_vid" -gt 0 ]; then
                uci_set repacd MAPConfig MapTrafficSeparationActive '1'
                uci_commit repacd
                brctl delif br-$NETWORK_TYPE_LAN $sta_iface
                __repacd_map_vlanmon_debug "Apply STA Vlan Configuration"
                if [ "$sta_vid" -ne "$map_primary_bsta_vid" ]; then
                    __repacd_delete_interface $NETWORK_TYPE_LAN $sta_iface
                    __repacd_delete_guest_nw_sta_vlan_interfaces $sta_iface
                    map_primary_bsta_vid=$sta_vid
                    sta_config_changed=1
                fi
                __repacd_add_vlan_interfaces $NETWORK_TYPE_LAN $sta_iface $sta_vid
                __repacd_add_guest_network_vlan_interfaces $sta_iface
            fi

        fi
    fi

    # if backhaul is ETH wait for all AP vaps to be UP
    if [ "$map_fh_bh_vap_up" -eq 0 ]; then
        return
    fi

    __repacd_map_vlanmon_debug "ETH Iface to GW; iface: $eth_iface"
    ifaces_eth=$(ifconfig -a 2>&1 | grep eth)
    iface_wan=$(uci get network.wan.ifname)
    ifaces=$(echo "$ifaces_eth" | cut -d ' ' -f1)
    for iface in $ifaces; do
        echo "$iface" | grep '\.' >/dev/null 2>&1
        if [ "$?" -eq "0" ]; then
            # we will get valid eth interface without vlan as primary is untagged
            continue
        fi

        # Add ethernet lan interface to primary ifname if link is detected
        link_detected=$(ethtool $iface | grep Link | grep detected | awk -F':' '{print $2}' \
                            | awk '{$1=$1};1')
        link_up=$(ifconfig $iface | grep "UP[A-Z' ']*RUNNING")

        if [ -n "$link_up" -a "$link_detected" = "yes" ]; then
            gw_ip=$(route -n | grep ^0.0.0.0 | grep br-$NETWORK_TYPE_LAN | awk '{print $2}')
            if [ -z "$gw_ip" ]; then
                __repacd_map_vlanmon_debug "Could not respolve gw_ip; Check route"
            fi

            if [ "$MAP_IS_GW_REACHABLE" -eq 0 -o -z "$eth_iface" ]; then
                if __repacd_map_arping_confirm_gateway "br-$NETWORK_TYPE_LAN" $gw_ip $iface; then
                    eth_iface=$iface
                fi
            fi

            if [ "$eth_iface" != "iface" -a "$iface" != "$iface_wan" ]; then
                # Daisy RE might be connected on other ETH
                # On Ethernet Backhaul only secondary VLAN needs to be created
                __repacd_map_vlanmon_debug " Add Vlan for iface: $iface"
                __repacd_add_guest_network_vlan_interfaces $iface
                continue
            fi
        fi
    done

    __repacd_map_vlanmon_debug "___________________________________________________________________"
}

__repacd_map_vlanmon_get_wlan_vlan_config() {
    local config="$1"
    local iface network disabled device

    config_get iface "$config" ifname
    config_get network "$config" network
    config_get disabled "$config" disabled '0'
    config_get mapVlanID "$config" mapVlanID '0'
    config_get mode "$config" mode
    config_get MapBSSType "$config" MapBSSType '0'
    config_get device "$config" device

    config_get upstream_version "$device" upstream_version '1'

    # For PF we might have some bands teared down. Add Bit rate check to
    # get correct vlanID
    local bitRate=$(repacdcli $iface get_bitrate)
    if [ "$bitRate" -eq 0 -o -z "$bitRate" ]; then
        continue
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_LAN \
            -a "$mode" = "ap" -a "$mapVlanID" -gt 0 ]; then
        vid_lan=$mapVlanID
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$mode" = "sta" ]; then
        map_bsta_backhaul=1
        sta_iface=$iface
        sta_vid=$(eval cfg80211tool_mesh $sta_iface $MAP_GET_STA_VLAN_IOCTL \
                      | grep $MAP_GET_STA_VLAN_IOCTL | cut -d ':' -f2)
        if [ "$sta_vid" -gt 0 ]; then
            uci_set wireless "$config" network "$NETWORK_TYPE_BACKHAUL"
            uci_set wireless "$config" vlan_bridge "br-$NETWORK_TYPE_LAN"
        elif [ "$sta_vid" -eq 0 ]; then
            if [ "$maplite_enabled" -eq 1 -a "$upstream_version" -ge 2 -a "$vid_lan" -gt 0 ]; then
                sta_vid=$vid_lan
                uci_set wireless "$config" network "$NETWORK_TYPE_BACKHAUL"
                uci_set wireless "$config" vlan_bridge "br-$NETWORK_TYPE_LAN"
            else
                uci_set wireless "$config" network "$NETWORK_TYPE_LAN"
            fi
        fi

        uci_commit wireless
    fi

    # if iface is BH . it wont have vlanID in wireless configured
    if [ $(($((MapBSSType&32)) >> 5)) -eq 0 ]; then
        continue
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_BACKHAUL \
            -a "$mode" = "sta" -a "$mapVlanID" -gt 0 ]; then
        map_primary_bsta_vid=$mapVlanID
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_GUEST1 \
            -a "$mode" = "ap" -a "$mapVlanID" -gt 0 ]; then
        vid_guest1=$mapVlanID
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_GUEST2 \
            -a "$mode" = "ap" -a "$mapVlanID" -gt 0 ]; then
        vid_guest2=$mapVlanID
    fi

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$network" = $NETWORK_TYPE_GUEST3 \
            -a "$mode" = "ap" -a "$mapVlanID" -gt 0 ]; then
        vid_guest3=$mapVlanID
    fi

    # vid change is detected before wifi happens. Add sleep to let it go through wifi
    if [ "$vid_8021q" -ne "$vid_lan" ]; then
        __repacd_map_vlanmon_debug "vid_lan:$vid_lan , vid_8021q:$vid_8021q"
        __repacd_map_vlanmon_debug "VID Information Changing. Sleep for 3 Seconds"
        # Onboarding might be happening. Sleep to avoid race condn
        sleep 3
        vid_8021q=$vid_lan
    fi
}

__repacd_map_vlanmon_remove_vlan() {
    local ifaces_eth ifaces_ath ifaces iface_wan

    if [ -n "$NETWORK_TYPE_GUEST1" ]; then
        uci_set network "$NETWORK_TYPE_GUEST1" ifname ' '
    fi

    if [ -n "$NETWORK_TYPE_GUEST2" ]; then
        uci_set network "$NETWORK_TYPE_GUEST2" ifname ' '
    fi

    if [ -n "$NETWORK_TYPE_GUEST3" ]; then
        uci_set network "$NETWORK_TYPE_GUEST3" ifname ' '
    fi

    ifaces_ath=$(ifconfig -a 2>&1 | grep ath)
    ifaces=$(echo "$ifaces_ath" | cut -d ' ' -f1)
    for iface in $ifaces; do
        # Delete interface that is vlan configured
        echo "$iface" | grep '\.' >/dev/null 2>&1
        if [ "$?" -eq "0" ]; then
            __repacd_delete_interface $NETWORK_TYPE_LAN $iface
            continue
        fi
    done

    ifaces_eth=$(ifconfig 2>&1 | grep eth)
    iface_wan=$(uci get network.wan.ifname)
    ifaces=$(echo "$ifaces_eth" | cut -d ' ' -f1)
    for iface in $ifaces; do
        # Delete interface that is vlan configured
        echo "$iface" | grep '\.' >/dev/null 2>&1
        if [ "$?" -eq "0" ]; then
            __repacd_delete_interface $NETWORK_TYPE_LAN $iface
            continue
        fi

        # Add ethernet lan interface to primary ifname if link is detected
        link_detected=$(ethtool $iface | grep Link | grep detected | awk -F':' '{print $2}' \
                            | awk '{$1=$1};1')
        link_up=$(ifconfig $iface | grep "UP[A-Z' ']*RUNNING")

        if [ -n "$link_up" -a "$link_detected" = "yes" ]; then
            # Add ethernet lan interface to primary ifname if link is detected
            if [ "$iface" != "$iface_wan" ]; then
                __repacd_add_interface $NETWORK_TYPE_LAN $iface
            fi
        fi
    done

    uci_commit network
}

__repacd_map_vlan_monitor() {
    __repacd_map_vlanmon_debug " [[ Enter VLAN Monitoring ]] "

    vid_lan=0 vid_guest1=0 vid_guest2=0 vid_guest3=0

    config_load wireless
    config_foreach __repacd_map_vlanmon_get_wlan_vlan_config wifi-iface

    if [ "$map_bsta_backhaul" -eq 1 ]; then
        if [ "$sta_vid" -eq 0 ]; then
            if [ "$maplite_enabled" -eq 1 -a "$map_my_version" -ge 3 ]; then
                __repacd_map_vlanmon_debug "Apply Vlan on AP Vaps"
            else
                map_ts_apply=0
                map_ts_remove=1
                map_primary_bsta_vid=0
                vid_lan=0 vid_guest1=0 vid_guest2=0 vid_guest3=0
            fi
        fi
    elif [ "$vid_lan" -eq 0 -a "$vid_guest1" -eq 0 -a "$vid_guest2" -eq 0 -a \
                      "$vid_guest3" -eq 0 ]; then
        map_ts_apply=0
        map_ts_remove=1
    fi

    __repacd_map_vlanmon_debug "My Map Version: $map_my_version"
    __repacd_map_vlanmon_debug "Map upstream version: $upstream_version"
    __repacd_map_vlanmon_debug "VID Information"
    __repacd_map_vlanmon_debug "vid_lan:$vid_lan, vid_guest1: $vid_guest1"
    __repacd_map_vlanmon_debug "vid_guest2:$vid_guest2, vid_guest3: $vid_guest3"
    __repacd_map_vlanmon_debug "sta_assoc_vid:$sta_vid sta_primary_vid=$map_primary_bsta_vid"
    __repacd_map_vlanmon_debug "Traffic Separation Apply: $map_ts_apply"
    __repacd_map_vlanmon_debug "Traffic Separation Active: $map_ts_active"
    __repacd_map_vlanmon_debug "Map Onboarding Status: $map_onboarding_done"

    # check if bsta / eth is VLAN configurd
    __repacd_map_vlanmon_check_backhaul_vlan_config

    # Check if VAPs are UP
    __repacd_map_vlanmon_fronthaul_monitor

    if [ "$map_fh_bh_vap_up" -eq 0 ]; then
        __repacd_map_vlanmon_debug "AP Vaps not up"
        return
    fi

    if [ "$map_ts_active" -eq 1 ]; then
        uci_set repacd MAPConfig MapTrafficSeparationActive '1'
        __repacd_map_vlanmon_debug "Traffic Separation Remove: $map_ts_remove"
        if [ "$map_ts_remove" -eq 1 ]; then
            map_ts_active=0
            uci_set repacd MAPConfig MapTrafficSeparationActive '0'
            __repacd_map_vlanmon_debug "Removing Traffic Separation Settings"
            __repacd_map_vlanmon_remove_vlan
        fi
        uci_commit repacd
    fi

    # check if backhaul BSS is VLAN configured
    __repacd_map_vlanmon_debug " [ Configure backhaul BSS with VLAN ] "
    config_load wireless
    config_foreach __repacd_map_vlanmon_check_bh_bss_vlan_config wifi-iface

    __repacd_map_vlanmon_debug "___________________________________________________________________"
}

# Send consecutive ARPs to the gateway and expect replies to confirm it is
# indeed reachable and there was not a false positive due to the system also
# performing an ARP at the same time.
# input: $1 - bridge: the name of the bridge to use to listen for a response
# input: $2 - gw_ip: the IP address of the gateway to attempt to reach
# input: $3 - gw_iface: the iface through which the gateway can be reached
# return: 0 if the gateway is reachable, otherwise non-zero
__repacd_map_arping_confirm_gateway() {
    local bridge=$1
    local gw_ip=$2
    local gw_iface=$3

    local replies
    replies=$(arping -f -c "$map_gw_reachable_confirm_attempts" \
                     -w "$map_gw_reachable_confirm_attempts" \
                     -I "$gw_iface" -B "$bridge" "$gw_ip" |
                  grep 'Received' | awk '{print $2;}')

    if [ "$replies" -ge "$map_gw_reachable_confirm_attempts" ]; then
        __repacd_map_vlanmon_debug \
            "GW IP ($gw_ip) reachable on bridge $bridge, interface $gw_iface via $replies replies"
        MAP_IS_GW_REACHABLE=1
        return 0
    else
        __repacd_map_vlanmon_debug "GW IP ($gw_ip) not reachable on $bridge , iface: $gw_iface"
        MAP_IS_GW_REACHABLE=0
        return 1
    fi
}

# Send pings to the gateway and expect replies to confirm it is reachable
# input: $1 - gw_ip: the IP address of the gateway to attempt to reach
# return: 0 if the gateway is reachable, otherwise non-zero
__repacd_map_ping_confirm_gateway() {
    local gw_ip=$1

    # Other modules still need to know about overall GW reachability
    if ping -W 2 "$gw_ip" -c1 > /dev/null; then
        __repacd_map_vlanmon_debug "GW ($gw_ip) reachable"
        MAP_IS_GW_REACHABLE=1
        return 0
    else
        MAP_IS_GW_REACHABLE=0
        return 1
    fi
}

__repacd_map_vlanmon_backhaul_monitor() {
    local iface_gw
    local brlan_ip
    local gw_ip

    __repacd_map_vlanmon_debug " [[ Enter BackHaul Link Monitor ]] "

    brlan_ip=$(ifconfig br-$NETWORK_TYPE_LAN | grep Bcast | grep inet | awk '{print $2}' \
                   | cut -d ":" -f2)
    gw_ip=$(route -n | grep ^0.0.0.0 | grep br-$NETWORK_TYPE_LAN | awk '{print $2}')
    if [ -z "$gw_ip" ]; then
        __repacd_map_vlanmon_debug "Could not respolve gw_ip; Check route"
        return
    fi
    if [ -z "$brlan_ip" ]; then
        __repacd_map_vlanmon_debug "Could not resolve br-lan self IP"
        return
    fi

    if [ "$map_bsta_backhaul" -eq 1 ]; then
        iface_gw=$sta_iface
    else
        iface_gw=$eth_iface
    fi

    __repacd_map_ping_confirm_gateway $gw_ip

    if [ -n "$NETWORK_TYPE_LAN" -a "$map_bsta_backhaul" -eq 0 ]; then
        arp_entry=$(grep -w br-$NETWORK_TYPE_LAN /proc/net/arp | awk '{print $4}')
        if [ -z "$arp_entry" ]; then
            __repacd_map_arping_confirm_gateway "br-$NETWORK_TYPE_LAN" $gw_ip $iface_gw
        fi
    fi

    __repacd_map_vlanmon_debug "___________________________________________________________________"
}

__repacd_map_vlanmon_check_vaps() {
    local config="$1"
    local iface network disabled device

    config_get iface "$config" ifname
    config_get disabled "$config" disabled '0'
    config_get mode "$config" mode
    config_get MapBSSType "$config" MapBSSType '0'
    config_get network "$config" network

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$mode" = "ap" ]; then
        if [ $((MapBSSType & 0x20)) -eq 32 ] || [ $((MapBSSType & 0x40)) -eq 64 ]; then
            local bitRate=$(repacdcli $iface get_bitrate)
            if [ "$bitRate" -eq 0 -o -z "$bitRate" ]; then
                __repacd_map_vlanmon_debug " Iface $iface has invalid Bit Rate $bitRate"
                hapd $iface disable
                sleep 2
                hapd $iface enable
                map_fh_bh_vap_up=0
            else
                # If we find MapBSSType configured . we can mark onboarding done
                map_onboarding_done=1
            fi
        fi
    elif [ -n "$iface" -a "$disabled" -eq 0 -a "$mode" = "ap_smart_monitor" ]; then
            local bitRate=$(repacdcli $iface get_bitrate)
            if [ "$bitRate" -eq 0 -o -z "$bitRate" ]; then
                __repacd_map_vlanmon_debug " smart mon Iface $iface has invalid Bit Rate $bitRate"
                ifconfig $iface down
                sleep 2
                ifconfig $iface up
                map_fh_bh_vap_up=0
            fi
    fi
}

__repacd_map_vlanmon_fronthaul_monitor() {
    __repacd_map_vlanmon_debug " [[ Enter fronthaul Monitoring ]] "

    if [ "$map_ts_active" -eq 1 -a "$map_ts_remove" -eq 1 ]; then
        # there might be a race condition where VAPs are still up
        sleep 5
    fi

    map_fh_bh_vap_up=1
    config_load wireless
    config_foreach __repacd_map_vlanmon_check_vaps wifi-iface

    __repacd_map_vlanmon_debug " front haul VAPs are ready: $map_fh_bh_vap_up"

    __repacd_map_vlanmon_debug "___________________________________________________________________"
}

__repacd_map_vlanmon_start_dependencies() {
    #Check if HYD and WSPLCD are running
    wsplcdPID=$(ps | grep wsplcd-lan.conf | grep -v grep | awk '{print$1}')
    hydPID=$(ps | grep $MAP-lan.conf | grep -v grep | awk '{print$1}')

    config_load $MAP
    config_get_bool mapConfigServiceEnabled MAPConfigSettings 'EnableConfigService' '0'

    # Map Lite check to set flag to disable VLAN application from wsplcd
    # if it is already applied
    if [ "$maplite_enabled" -eq 1 -a "$maplite_restart_config" -eq 1 ]; then
        if [ "$map_onboarding_done" -eq 1 ]; then
            __repacd_map_vlanmon_debug " Map Lite mode and TS Enabled. Dont apply TS from WSPLCD"
            uci_set wsplcd config Map2TSSetFromHYD '1'
            uci_commit wsplcd
            /etc/init.d/wsplcd restart
            maplite_restart_config=0
        fi
    fi

    if [ "$sta_config_changed" -eq 1 ]; then
        sta_config_changed=0
    fi

    if [ "$MAP_IS_GW_REACHABLE" -eq 1 ]; then
        if [ -z "$hydPID" -o "$config_changed" -eq 1 ]; then
            if [ "$mapConfigServiceEnabled" -eq 1 ]; then
                uci_set $MAP MAPConfigSettings 'EnableConfigService' 1
                /etc/init.d/$MAP restart
            fi
        fi

        if [ -z "$wsplcdPID" -o "$config_changed" -eq 1 ]; then
            if [ "$mapConfigServiceEnabled" -eq 0 ]; then
                /etc/init.d/wsplcd restart
            fi
        fi

        if [ "$mapConfigServiceEnabled" -eq 1 ]; then
            uci_set wsplcd config 'HyFiSecurity' 0
            uci commit wsplcd
            /etc/init.d/wsplcd stop
        fi
    fi

    if [ -z "$hydPID" -o "$config_changed" -eq 1 ]; then
        /etc/init.d/hyfi-bridging start
        /etc/init.d/$MAP restart
    fi

    if [ "$config_changed" -eq 1 ]; then
        config_changed=0
    fi
}

# After adding VLAN check if bridges are in UP State . If not bring it UP
__repacd_map_vlanmon_bridge_monitor() {
    local brState brError
    local networkName

    __repacd_map_vlanmon_debug " [[ Enter Bridge Monitoring ]] "

    config_load repacd
    for i in Primary One Two Three; do
        config_get networkName MAPConfig "VlanNetwork"$i '0'
        brError=$(ifconfig br-$networkName 2>&1 | grep -w "Device not found")
        if [ -n "$brError" ]; then
            continue
        fi

        brState=$(ifconfig br-$networkName | grep -w "UP" | awk '{$1=$1};1' | awk '{print $1}')
        __repacd_map_vlanmon_debug "Bridge State for br-$networkName : $brState"
        if [ "$brState" != "UP" -o -z "$brState" ]; then
            __repacd_map_vlanmon_debug "Bridge br-$networkName is down. Bringing back UP"
            ifconfig br-$networkName up
        fi
    done

    __repacd_map_vlanmon_debug "___________________________________________________________________"
}

repacd_map_vlanmon_init() {
    # First resolve the config parameters.
    config_load repacd
    config_get_bool map_enable_vlan_monitor MAPConfig 'MapTrafficSeparationEnable' '0'
    config_get_bool map_single_r1r2_bh MAPConfig 'CombinedR1R2Backhaul' '0'
    config_get_bool maplite_enabled MAPConfig 'EnableLiteMode' '0'

    if [ "$maplite_enabled" -eq 1 ]; then
        config_load wsplcd
        uci_set wsplcd config Map2TSSetFromHYD '0'
        uci_commit wsplcd
        /etc/init.d/wsplcd restart
    fi

    if [ "$map_enable_vlan_monitor" -eq 0 ]; then
        return
    fi
    __repacd_map_vlanmon_debug "Map VLAN Monitor Init"

    config_load repacd
    config_load wsplcd
    config_get num_vlan_supported MAPConfig 'NumberOfVLANSupported' '0'
    uci_set wsplcd config 'NumberOfVLANSupported' "$num_vlan_supported"
    num_guest_vlan=$((num_vlan_supported-1))

    # Get BackHaul Name
    if [ "$num_vlan_supported" -gt 0 ]; then
        config_get networkName MAPConfig VlanNetworkBackHaul '0'
        NETWORK_TYPE_BACKHAUL=$networkName
        uci_set wsplcd config backhaul "$networkName"
        __repacd_map_vlanmon_debug "NETWORK_TYPE_BACKHAUL=$NETWORK_TYPE_BACKHAUL"
    fi

    # Get network names
    for i in Primary One Two Three; do
        if [ "$num_vlan_supported" -eq 0 ]; then
            break
        fi

        config_get networkName MAPConfig "VlanNetwork"$i '0'

        if [ "$i" = "Primary" ]; then
            NETWORK_TYPE_LAN=$networkName
            __repacd_map_vlanmon_debug "NETWORK_TYPE_LAN=$NETWORK_TYPE_LAN"
            uci_set wsplcd config bridge "$networkName"
        elif [ "$i" = "One" ]; then
            NETWORK_TYPE_GUEST1=$networkName
            __repacd_map_vlanmon_debug "NETWORK_TYPE_GUEST1=$NETWORK_TYPE_GUEST1"
            uci_set wsplcd config bridge1 "$networkName"
        elif [ "$i" = "Two" ]; then
            NETWORK_TYPE_GUEST2=$networkName
            __repacd_map_vlanmon_debug "NETWORK_TYPE_GUEST2=$NETWORK_TYPE_GUEST2"
            uci_set wsplcd config bridge2 "$networkName"
        elif [ "$i" = "Three" ]; then
            NETWORK_TYPE_GUEST3=$networkName
            __repacd_map_vlanmon_debug "NETWORK_TYPE_GUEST3=$NETWORK_TYPE_GUEST3"
            uci_set wsplcd config bridge3 "$networkName"
        fi

        num_vlan_supported=$((num_vlan_supported-1))
    done

    # Remove existing vlan config
    __repacd_map_vlanmon_remove_vlan

    uci_set repacd MAPConfig MapTrafficSeparationActive '0'
    map_ts_apply=0
    map_ts_active=0
    map_ts_remove=0
    uci_commit repacd
    uci_commit wsplcd
}
__repacd_map_vlanmon_wlan_network_monitor() {
    local config="$1"
    local iface network disabled device vlan_ifname vlan_ifname_id
    config_get iface "$config" ifname
    config_get network "$config" network
    config_get disabled "$config" disabled '0'

    if [ -z "$iface" -o "$disabled" -eq 1 ]; then
        return
    fi

    for i in Primary One Two Three; do
        config_get networkName MAPConfig "VlanNetwork"$i '0'
           vlan_ifname_id=$(brctl show br-"$networkName" | grep -cw "$iface" | awk '{print $1}')

           if [ "$vlan_ifname_id" -eq 0 ]; then
                continue
           fi

           if [ "$vlan_ifname_id" -gt 1 ] ;then
           __repacd_map_vlanmon_debug " dup present $iface Deleting "
               brctl delif br-$networkName $iface
           fi

           if [ "$network" = "backhaul" ]; then
                continue
           fi

           vlan_ifname_id=$(brctl show br-"$networkName" | grep -cw "$iface" | awk '{print $1}')
           if [ "$networkName" != "$network" -a "$vlan_ifname_id" -gt 0 ]; then
               brctl delif br-$networkName $iface
	       __repacd_map_vlanmon_debug " changing bridge  $vlan_ifname $vlan_ifname_id Deleting "
               brctl addif br-$network $iface
           fi

    done
}

__repacd_map_vlanmon_network_monitor() {
    config_load wireless
    config_foreach __repacd_map_vlanmon_wlan_network_monitor wifi-iface
}
repacd_map_vlanmon_check() {
    # First resolve the config parameters.
    config_load repacd
    config_get_bool map_enable_vlan_monitor MAPConfig 'MapTrafficSeparationEnable' '0'
    config_get_bool map_enable_vlan_logs MAPConfig 'EnableMapTSLogs' '0'
    config_get map_my_version MAPConfig 'MapVersionEnabled'

    if [ "$map_enable_vlan_monitor" -eq 0 ]; then
        return
    fi
    __repacd_map_vlanmon_debug "Map Vlan Monitor Check"

    __repacd_map_vlan_monitor

    # Check if we are able to reach the gateway
    __repacd_map_vlanmon_backhaul_monitor

    # Check the state of the bridge
    __repacd_map_vlanmon_bridge_monitor

    if [ "$maplite_enabled" -eq 1 ]; then
        __repacd_map_vlanmon_network_monitor
    fi
    # Restart Dependencies
    __repacd_map_vlanmon_start_dependencies

    __repacd_map_vlanmon_debug "####################################################################"
}
