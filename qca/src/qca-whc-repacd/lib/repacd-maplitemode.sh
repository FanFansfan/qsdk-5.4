#!/bin/sh
# Copyright (c) 2019 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

MAPLITEMODE_DEBUG_OUTOUT=0
chirp_count=0
search_hyd_restart=0
sta_iface=""
dpp_lite_sta_connector=0
config_get_bool ezmesh repacd 'Ezmesh' '0'
    if [ "$ezmesh" -eq 1 ]; then
        MAP='ezmesh'
    else
        MAP='hyd'
    fi

# Include to use vlan monitoring functionality
. /lib/functions/repacd-vlanmon-map.sh

# Emit a message at debug level.
# input: $1 - the message to log
__repacd_maplitemode_debug() {
    local stderr=''
    if [ "$MAPLITEMODE_DEBUG_OUTOUT" -gt 0 ]; then
        stderr='-s'
    fi

    logger $stderr -t repacd.maplitemode -p user.debug "$1"
}

__repacd_maplite_chirp() {
    local mod_value
    local staBitRate=$(repacdcli $sta_iface get_bitrate)
    local connectorFound

    if [ "$staBitRate" -eq 0 -o -z "$staBitRate" ]; then
        __repacd_maplitemode_debug "Sta Bit Rate Invalid"
        search_hyd_restart=0
        if [ "$chirp_count" -eq 0 ]; then
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_configurator_remove 1
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_bootstrap_gen type=qrcode
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_bootstrap_info 1
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_bootstrap_get_uri 1
        fi

        chirp_count=$((chirp_count + 1))
        mod_value=$((chirp_count % 8))

        # Send 2 chirps quickly
        if [ "$chirp_count" -eq 1 -o "$chirp_count" -eq 2 ]; then
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_stop_listen
            wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_chirp own=1
        fi

        if [ "$mod_value" -ne 0 ]; then
           return
        fi

        connectorFound=$(cat "/tmp/map_sta_info.tmp" | grep DPP_STA_CONNECTOR)
        __repacd_maplitemode_debug "$mod_value"
        __repacd_maplitemode_debug "Connector found file : $connectorFound"
        __repacd_maplitemode_debug "Connector found UCI : $dpp_lite_sta_connector"

        if [ -n "$connectorFound" -o "$dpp_lite_sta_connector" -ne 0 ]; then
            __repacd_maplitemode_debug "Conf Object received . Dont chirp"
           return
        fi

        __repacd_maplitemode_debug "Start Chirping on $sta_iface , count $chirp_count"
        wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_stop_listen
        wpa_cli -p /var/run/wpa_supplicant-$sta_iface dpp_chirp own=1
    else
        __repacd_maplitemode_debug "Valid STA BitRate $staBitRate"
        dpp_lite_sta_connector=0
        if [ "$search_hyd_restart" -eq 0 ]; then
            search_hyd_restart=1
            __repacd_maplitemode_debug "Restart HYD to send search"
            /etc/init.d/$MAP restart
        fi
    fi
}

__repacd_maplite_get_sta_iface() {
    local config="$1"
    local iface network disabled device

    config_get iface "$config" ifname
    config_get network "$config" network
    config_get disabled "$config" disabled '0'
    config_get mapVlanID "$config" mapVlanID '0'
    config_get mode "$config" mode
    config_get MapBSSType "$config" MapBSSType '0'

    if [ -n "$iface" -a "$disabled" -eq 0 -a "$mode" = "sta" ]; then
        sta_iface=$iface
        config_get dpp_lite_sta_connector "$config" dpp_connector
    fi
}

repacd_maplitemode_init() {
    __repacd_maplitemode_debug "Map Lite Mode Init"
    repacd_map_vlanmon_init
    chirp_count=0
}

repacd_maplitemode_check() {
    local restartWifi bh_type onboarding_type

    __repacd_maplitemode_debug "Map Lite Mode Checks"
    repacd_map_vlanmon_check

    # First resolve the config parameters.
    config_load repacd
    config_get_bool restartWifi MAPConfig 'restartWifiDPP' '0'
    config_get bh_type MAPConfig 'MapBackaulType'
    config_get onboarding_type MAPConfig 'OnboardingType'

    if [ "$bh_type" = "wifi" -a "$onboarding_type" = "dpp" ]; then
        config_load wireless
        config_foreach __repacd_maplite_get_sta_iface wifi-iface

        __repacd_maplite_chirp
    fi

    if [ "$restartWifi" -eq 1 ]; then
        uci set repacd.MAPConfig.restartWifiDPP='0'
        uci commit repacd

        wifi load
    fi
}
