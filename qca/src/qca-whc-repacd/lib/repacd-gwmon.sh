#!/bin/sh
# Copyright (c) 2017-2018 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#
# 2015-2016 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.

GWMON_DEBUG_OUTOUT=0
GWMON_SWITCH_CONFIG_COMMAND=swconfig

GWMON_MODE_NO_CHANGE=0
GWMON_MODE_CAP=1
GWMON_MODE_NON_CAP=2
GWMON_KERNEL="4.4.60"
GWMON_PLATFORM=QCA
backhaul_mode_single=SINGLE
backhaul_rate_zero=0

. /lib/functions.sh
. /lib/functions/hyfi-iface.sh
. /lib/functions/hyfi-network.sh

config_load 'repacd'
config_get_bool gwmon_wxt repacd 'ForceWextMode' '0'
config_get_bool ezmesh repacd 'Ezmesh' '0'
    if [ "$ezmesh" -eq 1 ]; then
        MAP='ezmesh'
    else
        MAP='hyd'
    fi


prev_gw_link='' router_detected=0 gw_iface="" gw_switch_port=""
managed_network='' switch_iface="" vlan_group="" switch_ports=''
cpu_portmap=0
eswitch_support="0"
switch_present="1"
gw_mac=""
last_hop_count=255
gw_unreachable_max_attempts=3
gw_reachable_confirm_attempts=5
gw_reachable_confirm_min_replies=4

# Globals exported to other modules for reachability over any interface
IS_GW_REACHABLE=0
GW_NOT_REACHABLE_TIMESTAMP=0

# Globals exported to other modules for reachability over an Ethernet
# interface
IS_GW_ETH_REACHABLE=0
GW_NOT_ETH_REACHABLE_TIMESTAMP=0
restart_count=0
restart_max_attempts=5
is_ip_resolved=0
#Check for Platform & Kernel version
dut_kernel=$(uname -a  | awk '{print $3}')
dut_platform=$(grep -w DISTRIB_RELEASE /etc/openwrt_release | awk -F "='" '{print $2}' | awk '{gsub(/.{3}/,"& ")}1' | awk '{print $1}')

# Emit a log message
# input: $1 - level: the symbolic log level
# input: $2 - msg: the message to log
__gwmon_log() {
    local stderr=''
    if [ "$GWMON_DEBUG_OUTOUT" -gt 0 ]; then
        stderr='-s'
    fi

    logger $stderr -t repacd.gwmon -p "user.$1" "$*"
}

# Emit a log message at debug level
# input: $1 - msg: the message to log
__gwmon_debug() {
    __gwmon_log 'debug' "$1"
}

# Emit a log message at info level
# input: $1 - msg: the message to log
__gwmon_info() {
    __gwmon_log 'info' "$1"
}

# Emit a log message at warning level
# input: $1 - msg: the message to log
__gwmon_warn() {
    __gwmon_log 'warn' "$1"
}

# Obtain a timestamp from the system.
#
# These timestamps will be monontonically increasing and be unaffected by
# any time skew (eg. via NTP or manual date commands).
#
# output: $1 - the timestamp as an integer (with any fractional time truncated)
__gwmon_get_timestamp() {
    timestamp=$(cut -d' ' -f1 < /proc/uptime | cut -d. -f 1)
    eval "$1=$timestamp"
}

__gwmon_find_switch() {
    local vlan_grp
    local switch_num

    #Ignore value returned by eswitch_support in repacd. It is to be used by hyd only.
    __hyfi_get_switch_iface switch_iface eswitch_support switch_num switch_present

    if [ -z "$switch_iface" ]; then
        __gwmon_debug "Switch interface not found [$switch_present]"
    fi

    if [ -n "$switch_iface" ]; then
        __gwmon_debug "Detected Switch Interface in [$switch_iface] switch_num[$switch_num] switch_present[$switch_present]"
        $GWMON_SWITCH_CONFIG_COMMAND dev switch$switch_num set flush_arl 2>/dev/null
        vlan_grp="$(echo $switch_iface | awk -F. '{print $2}' 2>/dev/null)"
    fi

    if [ -z "$vlan_grp" ]; then
        vlan_group="1"
    else
        vlan_group="$vlan_grp"
    fi
}

__gwmon_get_switch_ports() {
    local config="$1"
    local vlan_group="$2"
    local ports vlan cpu_port __cpu_portmap

    config_get vlan "$config" vlan
    config_get ports "$config" ports

    [ ! "$vlan" = "$vlan_group" ] && return

    cpu_port=$(echo "$ports" | awk '{print $1}')
    ports=$(echo "$ports" | sed "s/$cpu_port //g")
    eval "$3='$ports'"

    cpu_port=$(echo "$cpu_port" | awk -Ft '{print $1}')

    case $cpu_port in
        0) __cpu_portmap=0x01;;
        1) __cpu_portmap=0x02;;
        2) __cpu_portmap=0x04;;
        3) __cpu_portmap=0x08;;
        4) __cpu_portmap=0x10;;
        5) __cpu_portmap=0x20;;
        6) __cpu_portmap=0x40;;
        7) __cpu_portmap=0x80;;
    esac
    eval "$4='$__cpu_portmap'"
}

__gwmon_set_hop_count() {
    local config=$1
    local iface mode

    config_get mode "$config" mode
    config_get iface "$config" ifname

    if [ "$mode" = "ap" ] && [ "$gw_connected_mode" != "CAP" ]; then
        __gwmon_info "Setting intf [$iface] hop count $2"
        cfg80211tool_mesh "$iface" set_whc_dist "$2"
    fi
}

# Determine the number of hops a given AP interface of RE is from the
# root AP.
# input: $1 - iface: the name of the AP interface (eg. ath0)
__gwmon_get_hop_count() {
    local iface=$1
    local command_result

    if [ -z "$iface" ]; then
        return 0
    fi

    command_result=`cfg80211tool_mesh $iface get_whc_dist | awk -F':' '{print $2}'`

    if [ "$command_result" -eq 255 ]; then
        return 0
    fi
    return 1
}

# Check MAC learning in ssdk_sh command with Port Status
__gwmon_check_mac_portstatus() {
    local sh_ssdk
    local sh_mac

    sh_mac="$(echo "$1" | sed 's/:/-/g')"
    sh_ssdk=$(ssdk_sh fdb entry show |grep  $sh_mac | awk -F':' '{print $5}')
    for port_tmp in $sh_ssdk
    do
        if [ "$port_tmp" -gt 0 ]; then
            gw_switch_port=$port_tmp
            return 0
        fi
    done
    return 1
}

# __gwmon_check_gateway_iface_lan_iface
# input: $1 ethernet interfaces part of lan
# input: $2 Gateway interface
# returns: 0 if gateway interface matches with ether interface
# and assign gateway interface to swicth_iface
__gwmon_check_gateway_iface_lan_iface() {
    local ether_iface
    local gwiface

    # Get the parent interface if gwiface or ether_iface got created for vlan.
    gwiface=${1//.[0-9]*/}
    ether_iface=${2//.[0-9]*/}

    if [ "$ether_iface" = "$gwiface" ]; then
        return 0
    fi
    return 1
}

# Attempt to find the gateway's IP address on the given bridge
# input: $1 - bridge: the name of the bridge for which to find the gateway
# output: $2 - gw_ip: the parameter into which to place the gateway's IP
__gwmon_resolve_gw_ip() {
    local bridge=$1
    local resolved_ip=''

    resolved_ip=$(route -n | grep ^0.0.0.0 | grep "$bridge" | awk '{print $2}')
    if [ -n "$resolved_ip" ]; then
        eval "$2=$resolved_ip"
    else
        __gwmon_debug "Failed to resolve GW IP for $bridge"
    fi
}

# Check GW reachability over Ethernet backhaul,
# Set hop count correctly to prevent isolated island condition
# returns: 0 if gateway is still reachable; otherwise 1
__gwmon_prevent_island_loop() {
    local network=$1

    local retries="$gw_unreachable_max_attempts"
    local gw_ip next_hop_count=255
    local hop_count_5g hop_count_2g hop_count_6g invalid_hop_count=255

    while [ "$retries" -gt 0 ]; do
        __gwmon_resolve_gw_ip "br-$network" gw_ip
        [ -z "$gw_ip" ] && break

        # Ping returns zero if at least one response was heard from the specified host
        if ping -W 2 "$gw_ip" -c1 > /dev/null; then
            next_hop_count=1
            hop_count_2g=`cfg80211tool_mesh $ap_iface_24g get_whc_dist | awk -F':' '{print $2}'`
            hop_count_5g=`cfg80211tool_mesh $ap_iface_5g get_whc_dist | awk -F':' '{print $2}'`
            hop_count_6g=`cfg80211tool_mesh $ap_iface_6g get_whc_dist | awk -F':' '{print $2}'`
            if [ "$hop_count_2g" -eq "$invalid_hop_count" ] || [ "$hop_count_5g" -eq "$invalid_hop_count" ] || [ "$hop_count_6g" -eq "$invalid_hop_count" ]; then
                __gwmon_info "Changing hop_count to $next_hop_count "
                config_load wireless
                config_foreach __gwmon_set_hop_count wifi-iface $next_hop_count
                last_hop_count=$next_hop_count
            fi
            break
        else
            # no ping response was received, retry
            retries=$((retries - 1))
            __gwmon_debug "Ping to GW IP[$gw_ip] on $gw_iface failed ($retries retries left)"
        fi
    done

    if [ $last_hop_count -ne $next_hop_count ]; then
        __gwmon_info "Changing hop_count from $last_hop_count to $next_hop_count"
        config_load wireless
        config_foreach __gwmon_set_hop_count wifi-iface $next_hop_count
        last_hop_count=$next_hop_count
    fi

    if [ "$retries" -eq 0 ]; then
        __gwmon_info "GW IP[$gw_ip] no longer reachable via $gw_iface"
        return 1
    else
        return 0
    fi
}

# Check the link status of the interface connected to the gataway
# returns: 0 if gateway is detected; non-zero if it is not
__gwmon_check_gw_iface_link() {
    local ret

    if __gwmon_check_gateway_iface_lan_iface $gw_iface $switch_iface; then
        local link_status
        local switch_num

        # Before we check local link status, make sure gw_iface (eth) is up
        ret=$(ifconfig $gw_iface | grep "UP[A-Z' ']*RUNNING")
        [ -z "$ret" ] && prev_gw_link="down" && return 1

        __hyfi_get_switch_iface switch_iface eswitch_support switch_num switch_present
        link_status=$($GWMON_SWITCH_CONFIG_COMMAND dev switch$switch_num port $gw_switch_port get link |awk -F':' '{print $3}'|awk -F ' ' '{print $1}')
        if [ ! "$link_status" = "up" ]; then
            link_status="down"
        fi

        if [ ! "$link_status" = "down" ]; then
            # link is up
            if [ ! "$prev_gw_link" = "up" ]; then
                __gwmon_info "Link to GW UP"
                prev_gw_link="up"
            fi

            # Check if GW is reachable, set appropriate hop count to avoid
            # isolated island condition
            __gwmon_prevent_island_loop $managed_network
            return $?
        fi
    else
        ret=$(ifconfig $gw_iface | grep "UP[A-Z' ']*RUNNING")
        [ -z "$ret" ] && prev_gw_link="down" && return 1

        # Check if GW is reachable, set appropriate hop count to avoid
        # isolated island condition
        __gwmon_prevent_island_loop $managed_network
        return $?
    fi

    if [ ! "$prev_gw_link" = "down" ]; then
        __gwmon_info "Link to GW DOWN"
        prev_gw_link="down"
    fi
    return 1
}

# Determine if the gateway is reachable over the given interface using
# arping
# input: $1 - iface: the name of the egress interface to use for the arping
# input: $2 - bridge: the name of the bridge to use to listen for a response
# input: $3 - gw_ip: the IP address of the gateway to attempt to reach
# return: 0 if the gateway is reachable, otherwise non-zero
__gwmon_arping_gateway() {
    local iface=$1
    local bridge=$2
    local gw_ip=$3

    arping -f -c 1 -w 0 -I "$iface" -B "$bridge" "$gw_ip" > /dev/null
    return $?
}

# Send consecutive ARPs to the gateway and expect replies to confirm it is
# indeed reachable and there was not a false positive due to the system also
# performing an ARP at the same time.
# input: $1 - iface: the name of the egress interface to use for the arping
# input: $2 - bridge: the name of the bridge to use to listen for a response
# input: $3 - gw_ip: the IP address of the gateway to attempt to reach
# return: 0 if the gateway is reachable, otherwise non-zero
__gwmon_arping_confirm_gateway() {
    local iface=$1
    local bridge=$2
    local gw_ip=$3

    __gwmon_info "Confirming GW IP ($gw_ip) is reachable on $iface"
    local replies
    replies=$(arping -c "$gw_reachable_confirm_attempts" \
                     -w "$gw_reachable_confirm_attempts" \
                     -I "$iface" -B "$bridge" "$gw_ip" |
              grep 'Received' | awk '{print $2;}')
    if [ "$replies" -ge "$gw_reachable_confirm_min_replies" ]; then
        __gwmon_info "GW IP ($gw_ip) confirmed reachable on $iface via $replies replies"
        return 0
    else
        __gwmon_info "GW IP ($gw_ip) confirmed not reachable on $iface via $replies replies"
        return 1
    fi
}

# __gwmon_is_restart_required
# restarting wifi if there is a change in gateway
# input: $1 5g bit rate
# input: $2 2g bit rate
# returns: 0 if there is a change in gateway; non-zero otherwise
__gwmon_is_restart_required() {
    local rate_5g=$1
    local rate_2g=$2

    __gwmon_info "wait $restart_count rate_5g=$rate_5g rate_2g=$rate_2g is_ip=$is_ip_resolved"
    [ "$is_ip_resolved" -eq 0 ] && return 1
    if [ -n "$rate_5g" -o -n "$rate_2g" ]; then
        if [ "$rate_5g" != "0" -o "$rate_2g" != "0" ]; then
            restart_count=$((restart_count+1))
            if [ "$restart_count" -gt "$restart_max_attempts" ]; then
                restart_count=0
                is_ip_resolved=0
                return 0
            fi
        fi
    fi
    return 1
}

# __gwmon_check_gateway
# input: $1 1905.1 managed bridge
# output: $2 Gateway interface
# returns: 0 if gateway is detected; non-zero if not detected
__gwmon_check_gateway() {
    local network=$1

    local gw_ip gw_br_port __gw_iface
    local ether_ifaces_full ether_ifaces
    local ether_iface ret
    local interface_gw
    local switch_num
    current_backhaul_5g_rate=`repacdcli $sta_iface_5g get_bitrate`
    current_backhaul_24g_rate=`repacdcli $sta_iface_24g get_bitrate`

    __gwmon_resolve_gw_ip "br-$network" gw_ip
    if [ -z "$gw_ip" ]; then
        if __gwmon_is_restart_required "$current_backhaul_5g_rate" "$current_backhaul_24g_rate"; then
            return 0
        fi
        return 1
    fi
    is_ip_resolved=1
    # Other modules still need to know about overall GW reachability
    if ping -W 2 "$gw_ip" -c1 > /dev/null; then
        if [ "$IS_GW_REACHABLE" -eq 0 ]; then
            __gwmon_info "GW ($gw_ip) reachable"
        fi
        IS_GW_REACHABLE=1
        GW_NOT_REACHABLE_TIMESTAMP=0
    else
        if [ "$IS_GW_REACHABLE" -eq 1 ]; then
            __gwmon_info "GW ($gw_ip) NOT reachable"
            if [ "$backhaul_mode_configured" = "$backhaul_mode_single" ] && [ "$current_backhaul_5g_rate" = "$backhaul_rate_zero" ] && [ "$current_backhaul_24g_rate" = "$backhaul_rate_zero" ]; then
                __repacd_gwmon_bring_iface_up $sta_iface_24g
                __gwmon_debug "2g VAP brought up since 5g brought down & AP is operating in SINGLE backhaul mode"
            fi
        fi
        IS_GW_REACHABLE=0
        if [ "$GW_NOT_REACHABLE_TIMESTAMP" -eq 0 ]; then
            __gwmon_get_timestamp GW_NOT_REACHABLE_TIMESTAMP
        fi
    fi

    # Get all Ethernet interfaces
    hyfi_get_ether_ifaces "$1" ether_ifaces_full
    hyfi_strip_list "$ether_ifaces_full" ether_ifaces

    if [ "$IS_GW_ETH_REACHABLE" -eq 0 ]; then
        for ether_iface in $ether_ifaces; do
            # arping to iface that has link UP
            link_up=$(ifconfig $ether_iface | grep "UP[A-Z' ']*RUNNING")
            if [ -z "$link_up" ]; then
                continue
            fi

            if __gwmon_arping_gateway "$ether_iface" "br-$network" "$gw_ip" &&
                __gwmon_arping_confirm_gateway "$ether_iface" "br-$network" "$gw_ip"; then
                IS_GW_ETH_REACHABLE=1
                GW_NOT_ETH_REACHABLE_TIMESTAMP=0

                __gw_iface="$ether_iface"
                break
            fi
        done
    else  # Currently reachable; just check the last interface
        if ! __gwmon_arping_gateway "$gw_iface" "br-$network" "$gw_ip" &&
            ! __gwmon_arping_confirm_gateway "$ether_iface" "br-$network" "$gw_ip"; then
            __gwmon_info "GW ($gw_ip) no longer reachable on $gw_iface"
            IS_GW_ETH_REACHABLE=0
            if [ "$GW_NOT_ETH_REACHABLE_TIMESTAMP" -eq 0 ]; then
                __gwmon_get_timestamp GW_NOT_ETH_REACHABLE_TIMESTAMP
            fi
        fi
    fi

    gw_mac=$(grep -w "$gw_ip" /proc/net/arp | grep "br-$1" | awk '{print $4}')
    [ -z "$gw_mac" ] && return 1
    if [ -z "$__gw_iface" ]; then
        gw_br_port=$(brctl showmacs "br-$1" | grep -i "$gw_mac" | awk '{print $1}')
        [ -z "$gw_br_port" ] && return 1
        __gw_iface_2=$(brctl showstp "br-$1" | grep \("$gw_br_port"\) | awk '{print $1}')
        [ -z "$__gw_iface_2" ] && return 1
         __gw_iface=$__gw_iface_2
    fi

    # Check if this interface belongs to our network
    for ether_iface in $ether_ifaces; do
        if [ "$ether_iface" = "$__gw_iface" ]; then
            gw_iface=$__gw_iface
            __gwmon_info "Detected Gateway on interface $gw_iface"

            # Hawkeye platform has separate gmac for each switch port so gw_iface & switch_iface are same
            # For Maple+Spruce platform, Since switch is not present, skip assigning gateway interface as switch_iface
            __hyfi_get_switch_iface switch_iface eswitch_support switch_num switch_present

            if [ "$switch_present" -gt 0 ]; then
                if [ -z "$switch_iface" ]; then
                    if __gwmon_check_gateway_iface_lan_iface  "$gw_iface" "$ether_iface"; then
                        switch_iface="$gw_iface"
                    fi
                fi
            fi

            if __gwmon_check_gateway_iface_lan_iface "$gw_iface" "$switch_iface"; then
                if ! __gwmon_check_mac_portstatus $gw_mac; then
                    __gwmon_warn "invalid port map portmap"
                    gw_switch_port=9
                    # CAP <--eth--> RE1 <--eth--> RE2
                    # If eth disconnected between CAP and RE1, then topology will be
                    # CAP <--vap--> RE1 <--eth--> RE2 <--vap--> CAP
                    # this will form loop, RE1 and RE2 not able to reach gateway IP.
                    # RE1 become Non-Cap mode and Gateway mac still in eth port due to the loop.
                    # Hence ping fail observed.
                    # To avoid loop, bringing down the eth interface for 2 seconds and bringing back to up
                    ifconfig "$gw_iface" down
                    sleep 2
                    ifconfig "$gw_iface" up
                    return 1
                fi
                __gwmon_info "gwmon_check_gateway Detected over ethernet =$gw_switch_port"
            fi
            __repacd_gwmon_bring_iface_down $sta_iface_5g
            __repacd_gwmon_bring_iface_down $sta_iface_24g
            return 0
        fi
    done

    # also check the loop prevention code to see if it believes we have
    # an upstream facing Ethernet interface
    local num_upstream
    num_upstream=$(lp_numupstream)
    if [ "${num_upstream}" -gt 0 ]; then
        return 0
    fi

    return 1
}

# Determine if the GW is reachable and update the router_detected global
# variable accordingly.
__gwmon_update_router_detected() {
    if __gwmon_check_gateway "$managed_network"; then
        router_detected=1
    else
        router_detected=0
    fi
}

# Check whether the configured mode matches the mode that is determined by
# checking for connectivity to the gateway.
#
# input: $1 cur_role: the current mode that is configured
# input: $2 start_mode: the mode in which the auto-configuration script is being
#                       run; This is used by the init script to help indicate
#                       that it was an explicit change into this mode.
#                       If the mode was CAP, then it should take some time
#                       before it is willing to switch back to non-CAP due
#                       to lack of a gateway.
# input: $3 managed_network: the logical name for the network interfaces to
#                            monitor
#
# return: value indicating the desired mode of operation
#  - $GWMON_MODE_CAP to act as the main AP
#  - $GWMON_MODE_NON_CAP to switch to being a secondary AP
#  - $GWMON_MODE_NO_CHANGE for now change in the mode
__gwmon_init() {
    local cur_mode=$1
    local start_mode=$2
    local eth_mon_enabled

    managed_network=$3
    __gwmon_find_switch "$managed_network"
    [ -n "$switch_iface" ] && __gwmon_info "found switch on $switch_iface VLAN=$vlan_group"

    config_load repacd
    config_get gw_connected_mode repacd 'GatewayConnectedMode' 'AP'
    config_get eth_mon_enabled repacd 'EnableEthernetMonitoring' '0'
    config_get gw_unreachable_max_attempts GatewayLink 'UnreachableMaxAttempts' \
        "$gw_unreachable_max_attempts"
    config_get gw_reachable_confirm_attempts GatewayLink 'ReachableConfirmationAttempts' \
        "$gw_reachable_confirm_attempts"
    config_get gw_reachable_confirm_min_replies GatewayLink 'ReachableConfirmationReplies' \
        "$gw_reachable_confirm_min_replies"

    config_load $MAP
    config_get backhaul_mode_configured 'hy' 'ForwardingMode' 'APS'
    __gwmon_debug "Backhaul mode is $backhaul_mode_configured"

    config_load network
    config_foreach __gwmon_get_switch_ports switch_vlan "$vlan_group" switch_ports cpu_portmap
    __gwmon_info "switch ports in the $managed_network network: $switch_ports"

    __gwmon_update_router_detected

    if [ "$cur_mode" = "CAP" ]; then
        if [ "$router_detected" -eq 0 ]; then
            if [ "$eth_mon_enabled" -eq 0 ] && [ ! "$start_mode" = "CAP" ]; then
                return $GWMON_MODE_NON_CAP
            else
                local retries="$gw_unreachable_max_attempts"

                while [ "$retries" -gt 0 ]; do
                    __gwmon_update_router_detected
                    [ "$router_detected" -gt 0 ] && break
                    retries=$((retries - 1))
                    __gwmon_debug "redetecting gateway ($retries retries left)"
                done

                # If gateway was still not detected after our attempts,
                # indicate we should change to non-CAP mode.
                if [ "$router_detected" -eq 0 ]; then
                    if [ "$eth_mon_enabled" -eq 0 ]; then
                        return $GWMON_MODE_NON_CAP
                    else
                        return $GWMON_MODE_NO_CHANGE
                    fi
                fi
            fi
        fi
    else   # non-CAP mode
        if [ "$router_detected" -eq 1 ]; then
            local mixedbh
            mixedbh=$(uci get repacd.repacd.EnableMixedBackhaul 2>/dev/null)
            if [ "$mixedbh" != "1" ]; then
                return $GWMON_MODE_CAP
            fi
        fi
    fi

    return $GWMON_MODE_NO_CHANGE
}

# return: 2 to indicate CAP mode; 1 for non-CAP mode; 0 for no change
__gwmon_check() {
    if [ "$router_detected" -eq 0 ]; then
        __gwmon_update_router_detected

        if [ "$router_detected" -gt 0 ]; then
            local mixedbh
            mixedbh=$(uci get repacd.repacd.EnableMixedBackhaul 2>/dev/null)
            # if we want to support mixed backhaul, e.g., if we want to
            # enable both WiFi and Ethernet backhaul, then we stay in
            # non-cap mode so the STA interfaces remain up.  otherwise,
            # set to cap mode which brings down the STA interfaces.
            if [ "$mixedbh" != "1" ]; then
                return $GWMON_MODE_CAP
            fi
        fi
    else
        if ! __gwmon_check_gw_iface_link "$managed_network"; then
            # Gateway is gone
            router_detected=0
            gw_iface=""
            gw_switch_port=""
            return $GWMON_MODE_NON_CAP
        fi
    fi

    return $GWMON_MODE_NO_CHANGE
}

# input: $1 - sta interface: the name of the interface for bringing up.
__repacd_gwmon_bring_iface_up() {
    local sta_iface=$1

    if [ -n "$sta_iface" ];then
        network_id=`wpa_cli -p /var/run/wpa_supplicant-$sta_iface list_network | grep DISABLED | awk '{print $1}'`
        if [ -z  $network_id ]; then
            network_id=0
        fi
        wpa_cli -p /var/run/wpa_supplicant-$sta_iface enable_network $network_id
        __gwmon_info "Interface $sta_iface Brought up with network id $network_id"
        if [ "$backhaul_mode_configured" = "$backhaul_mode_single" ]; then
            [ ! -f /etc/init.d/wsplcd ] || /etc/init.d/wsplcd restart
        fi
        if [ "$sta_iface" = "$sta_iface_5g" ]; then
            force_down_5g=0
        else
            force_down_24g=0
            #if 2.4G interface up, force reset independent_channel parameters to 0
            is_24G_down_by_independent_channel=0
            uci_set wireless $wifi_2G_interface_name independent_channel_set '0'
            uci_commit wireless
        fi
        rssi_counter=0
        last_assoc_state=0
    fi
}

# Bring down sta vap interface.
# input: $1 - sta interface: the name of the interface for bringing down.
__repacd_gwmon_bring_iface_down() {
    local sta_iface=$1
    if [ -n "$sta_iface" ];then
        network_id=`wpa_cli -p /var/run/wpa_supplicant-$sta_iface list_network | grep CURRENT | awk '{print $1}'`
        if [ -z  $network_id ]; then
            network_id=0
        fi
        wpa_cli -p /var/run/wpa_supplicant-$sta_iface disable_network $network_id
        __gwmon_info "Interface $sta_iface Brought down with network id $network_id"
        if [ "$sta_iface" = "$sta_iface_5g" ]; then
            force_down_5g=1
            if [ -n "$force_down_5g_timestamp" ] ;then
                backhaul_eval_time=$config_long_eval_time5g
            else
                backhaul_eval_time=$config_short_eval_time5g
            fi
            force_down_5g_timestamp=`cat /proc/uptime | cut -d' ' -f1 | cut -d. -f 1`
        elif [ "$sta_iface" = "$sta_iface_5gl" ]; then
            force_down_5g=0
        elif [ "$sta_iface" = "$sta_iface_5g_backup" ]; then
            force_down_5g=0
        else
            force_down_24g=1
        fi
        rssi_counter=0
    fi
}
