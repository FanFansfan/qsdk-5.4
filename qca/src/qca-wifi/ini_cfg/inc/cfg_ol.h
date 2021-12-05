/*
 *
 * Copyright (c) 2018-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef _CFG_OL_H_
#define _CFG_OL_H_

#include "cfg_define.h"
#include "wmi_unified_param.h"
#include "ol_if_athvar.h"
#include "ieee80211.h"

#define MAX_CFG 0xffffffff

#define CFG_OL_ENABLE_11AX_STUB \
	CFG_INI_BOOL("enable_11ax_stub", false, \
	"Enable 802.11ax stubbing support for testing. Valid only for QCA9984")

#define CFG_OL_TX_TCP_CKSUM \
	CFG_INI_BOOL("enable_tx_tcp_cksum", false, \
	"Enable Tx TCP Checksum")

#define CFG_OL_VOW_CONFIG \
	CFG_INI_BOOL("vow_config", false, \
	"VoW Configuration")

#define CFG_OL_CARRIER_VOW_CONFIG \
	CFG_INI_BOOL("carrier_vow_config", false, \
	"Enable Vow stats and Configuration")

#define CFG_OL_FW_VOW_STATS_ENABLE \
	CFG_INI_BOOL("fw_vow_stats_enable", false, \
	"Firmware VoW stats control")

#define CFG_OL_QWRAP_ENABLE \
	CFG_INI_BOOL("qwrap_enable", false, \
	"Enable qwrap target config")

#define CFG_OL_CCE_DISABLE \
	CFG_INI_BOOL("cce_disable", false, \
	"Disable Hardware CCE Component")

#define CFG_OL_LOW_MEM_SYSTEM \
	CFG_INI_BOOL("low_mem_system", false, \
	"Low Memory System")

#define CFG_OL_BEACON_OFFLOAD_DISABLE \
	CFG_INI_BOOL("beacon_offload_disable", false, \
	"Beacon offload disable")

#define CFG_OL_ENABLE_UART_PRINT \
	CFG_INI_BOOL("enableuartprint", false, \
	"Enable uart/serial prints from target")

#define CFG_OL_ENABLE_MESH_SUPPORT \
	CFG_INI_BOOL("mesh_support", false, \
	"Configure Mesh support")

#define CFG_OL_EAPOL_MINRATE_SET \
	CFG_INI_BOOL("eapol_minrate_set", false, \
	"Enable/Disable EAPOL Minrate")

#define CFG_COMMAND_LOGGING_SUPPORT \
	CFG_INI_BOOL("config_logging_enable", false, \
	"Enable/Disable Config Logging")

#define CFG_OL_EAPOL_MINRATE_AC_SET \
	CFG_INI_UINT("eapol_minrate_ac_set", \
	0, 4, 0, \
	CFG_VALUE_OR_DEFAULT, "Set AC for the EAPOL minrate set")

#define CFG_OL_CFG80211_CONFIG \
	CFG_INI_BOOL("cfg80211_config", false, \
	"cfg80211 config(enable/disable)")

#define CFG_OL_CFG_IPHDR\
	CFG_INI_BOOL("iphdr_pad", true, \
	"Disable IP header padding to manage IP header unalignment")

#define CFG_OL_LTEU_SUPPORT \
	CFG_INI_UINT("lteu_support", \
	0, 0x4, 0, \
	CFG_VALUE_OR_DEFAULT, "LTEU support")

#define CFG_OL_BMI \
	CFG_INI_UINT("bmi", \
	0, 1, 0, \
	CFG_VALUE_OR_DEFAULT, "BMI Handling: 0 - Driver, 1 - User agent")

#define CFG_OL_MAX_DESC \
	CFG_INI_UINT("max_descs", \
	0, 2198, 0, \
	CFG_VALUE_OR_DEFAULT, "Override default max descriptors")

#define CFG_OL_MAX_PEERS \
	CFG_INI_UINT("max_peers", \
	0, 1024, 0, \
	CFG_VALUE_OR_DEFAULT, "Override default max peers")

#define CFG_OL_STRICT_CHANNEL_MODE \
	CFG_INI_UINT("strict_channel_mode", \
	0, 1, 0, \
	CFG_VALUE_OR_DEFAULT, "Do not implicitly change phymode or channel")

#define CFG_OL_ACBK_MIN_FREE \
	CFG_INI_UINT("OL_ACBKMinfree", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Min Free buffers reserved for AC-BK")

#define CFG_OL_ACBE_MIN_FREE \
	CFG_INI_UINT("OL_ACBEMinfree", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Min Free buffers reserved for AC-BE")

#define CFG_OL_ACVI_MIN_FREE \
	CFG_INI_UINT("OL_ACVIMinfree", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Min Free buffers reserved for AC-VI")

#define CFG_OL_ACVO_MIN_FREE \
	CFG_INI_UINT("OL_ACVOMinfree", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Min Free buffers reserved for AC-VO")

#define CFG_OL_OTP_MOD_PARAM \
	CFG_INI_UINT("otp_mod_param", \
	0, 0xffffffff, 0xffffffff, \
	CFG_VALUE_OR_DEFAULT, "OTP")

#define CFG_OL_EMU_TYPE \
	CFG_INI_UINT("emu_type", \
	0, 2, 0, \
	CFG_VALUE_OR_DEFAULT, "Emulation Type : 0-->ASIC, 1-->M2M, 2-->BB")

#define CFG_OL_MAX_ACTIVE_PEERS \
	CFG_INI_UINT("max_active_peers", \
	0, 50, 0, \
	CFG_VALUE_OR_DEFAULT, "Override max active peers in peer qcache")

#define CFG_OL_MAX_GROUP_KEYS \
	CFG_INI_UINT("max_group_keys", \
	0, 128, 0, \
	CFG_VALUE_OR_DEFAULT, "Set maximum number of Group keys supported")

#define CFG_OL_HW_MODE_ID \
	CFG_INI_UINT("hw_mode_id", \
	WMI_HOST_HW_MODE_SINGLE, WMI_HOST_HW_MODE_MAX, WMI_HOST_HW_MODE_MAX, \
	CFG_VALUE_OR_DEFAULT, "Preferred HW mode id")

#define CFG_OL_DYNAMIC_HW_MODE \
	CFG_INI_UINT("dynamic_hw_mode", \
	WMI_HOST_DYNAMIC_HW_MODE_DISABLED, (WMI_HOST_DYNAMIC_HW_MODE_MAX - 1), \
	WMI_HOST_DYNAMIC_HW_MODE_DISABLED, \
	CFG_VALUE_OR_DEFAULT, "Dynamic HW mode change support")

#define CFG_OL_DYNAMIC_HW_MODE_PRIMARY_IF \
	CFG_INI_STRING("dynamic_hw_mode_primary_if", \
	0, 64, "", \
	"Dynamic HW mode primary interface")

#define CFG_OL_TGT_SCHED_PARAM \
	CFG_INI_UINT("tgt_sched_params", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Target Scheduler Parameters")

#define CFG_OL_FW_CODE_SIGN \
	CFG_INI_UINT("fw_code_sign", \
	0, 3, 0, \
	CFG_VALUE_OR_DEFAULT, "FW Code Sign")

#define CFG_OL_ALLOCRAM_TRACK_MAX \
	CFG_INI_UINT("allocram_track_max", \
	0, MAX_CFG, 0, \
	CFG_VALUE_OR_DEFAULT, "Enable target allocram tracking")

#define CFG_OL_MAX_VAPS \
	CFG_INI_UINT("max_vaps", \
	1, 51, 16, \
	CFG_VALUE_OR_DEFAULT, \
	"Max vap nodes for which mempool is statically allocated")

#define CFG_OL_MAX_CLIENTS \
	CFG_INI_UINT("max_clients", \
	1, 1024, 124, \
	CFG_VALUE_OR_DEFAULT, \
	"Max client nodes for which mempoolis statically allocated")

#define CFG_OL_ASE_OVERRIDE \
	CFG_INI_BOOL("ase_override_enabled", false, \
	"Enable ase override")

#define CFG_OL_MODE_2G_PHYB \
	CFG_INI_BOOL("mode_2g_phyb", false, \
	"Special mode 2g phyb enabled")

#define CFG_TGT_MAX_WMI_CMDS_MIN 512
#define CFG_TGT_MAX_WMI_CMDS_MAX 4096

#ifdef QCA_LOWMEM_CONFIG
#define CFG_TGT_MAX_WMI_CMDS_DEFAULT 512
#elif defined QCA_512M_CONFIG
#define CFG_TGT_MAX_WMI_CMDS_DEFAULT 1024
#else
#define CFG_TGT_MAX_WMI_CMDS_DEFAULT 2048
#endif

#define CFG_OL_CARRIER_VOW_OPTIMIZATION \
	CFG_INI_BOOL("carrier_vow_optimization", false, \
	"Enable/Disable VoW optimization for carier usecases")

#define CFG_OL_MAX_WMI_CMDS \
	CFG_INI_UINT("max_wmi_cmds", \
	CFG_TGT_MAX_WMI_CMDS_MIN, CFG_TGT_MAX_WMI_CMDS_MAX, CFG_TGT_MAX_WMI_CMDS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max WMI commands ")

/* Number of Vdevs per radio */
#define CFG_TGT_VDEVS_MIN 1
#ifdef QCA_LOWMEM_CONFIG
#define CFG_TGT_VDEVS_MAX 9
#elif defined(QCA_512M_CONFIG)
#ifdef QCA_IPQ807X_E_BUILD
#define CFG_TGT_VDEVS_MAX 8
#else
#define CFG_TGT_VDEVS_MAX 9
#endif
#else
#define CFG_TGT_VDEVS_MAX 16
#endif
#define CFG_TGT_VDEVS_DEFAULT CFG_TGT_VDEVS_MAX

#define CFG_OL_MAX_VDEVS_PDEV0 \
	CFG_INI_UINT("num_vdevs_pdev0", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_VDEVS_MAX, CFG_TGT_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max vdevs for radio-0")

#define CFG_OL_MAX_VDEVS_PDEV1 \
	CFG_INI_UINT("num_vdevs_pdev1", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_VDEVS_MAX, CFG_TGT_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max vdevs for radio-1")

#define CFG_OL_MAX_VDEVS_PDEV2 \
	CFG_INI_UINT("num_vdevs_pdev2", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_VDEVS_MAX, CFG_TGT_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max vdevs for radio-2")

#define CFG_OL_MAX_VDEVS_AR9887 15
#define CFG_OL_MAX_VDEVS_AR9888 16

/* Number of Peers per radio */
#define CFG_TGT_PEERS_MIN 1
#if defined(QCA_LOWMEM_CONFIG) || defined(QCA_512M_CONFIG)
#define CFG_TGT_PEERS_MAX 128
#else
#define CFG_TGT_PEERS_MAX 512
#endif
#define CFG_TGT_PEERS_DEFAULT CFG_TGT_PEERS_MAX

#define CFG_OL_MAX_PEERS_PDEV0 \
	CFG_INI_UINT("num_peers_pdev0", \
	CFG_TGT_PEERS_MIN, CFG_TGT_PEERS_MAX, CFG_TGT_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max peers for radio-0")

#define CFG_OL_MAX_PEERS_PDEV1 \
	CFG_INI_UINT("num_peers_pdev1", \
	CFG_TGT_PEERS_MIN, CFG_TGT_PEERS_MAX, CFG_TGT_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max peers for radio-1")

#define CFG_OL_MAX_PEERS_PDEV2 \
	CFG_INI_UINT("num_peers_pdev2", \
	CFG_TGT_PEERS_MIN, CFG_TGT_PEERS_MAX, CFG_TGT_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max peers for radio-2")

/* Number of Monitor vaps per radio */
#define CFG_TGT_MONITOR_MIN 0
#if defined(QCA_LOWMEM_CONFIG) || (defined(QCA_512M_CONFIG) && !defined(QCA_IPQ807X_E_BUILD))
#define CFG_TGT_MONITOR_MAX 0
#else
#define CFG_TGT_MONITOR_MAX 1
#endif
#define CFG_TGT_MONITOR_DEFAULT CFG_TGT_MONITOR_MAX

#define CFG_OL_MONITOR_PDEV0 \
	CFG_INI_UINT("num_monitor_pdev0", \
	CFG_TGT_MONITOR_MIN, CFG_TGT_MONITOR_MAX, CFG_TGT_MONITOR_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"monitor vap for radio-0")

#define CFG_OL_MONITOR_PDEV1 \
	CFG_INI_UINT("num_monitor_pdev1", \
	CFG_TGT_MONITOR_MIN, CFG_TGT_MONITOR_MAX, CFG_TGT_MONITOR_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"monitor vap for radio-1")

#define CFG_OL_MONITOR_PDEV2 \
	CFG_INI_UINT("num_monitor_pdev2", \
	CFG_TGT_MONITOR_MIN, CFG_TGT_MONITOR_MAX, CFG_TGT_MONITOR_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"monitor vap for radio-2")

#define CFG_TGT_NUM_VDEV_MESH_MIN 1
#define CFG_TGT_NUM_VDEV_MESH_MAX 8
#define CFG_TGT_NUM_VDEV_MESH_DEFAULT CFG_TGT_NUM_VDEV_MESH_MAX

#define CFG_OL_NUM_VDEV_MESH \
	CFG_INI_UINT("num_mesh_vap", \
	CFG_TGT_NUM_VDEV_MESH_MIN, CFG_TGT_NUM_VDEV_MESH_MAX, CFG_TGT_NUM_VDEV_MESH_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"number of mesh vaps")

/* Qwrap max client vdev counts */
#define CFG_TGT_QWRAP_VDEVS_MAX 30
#define CFG_TGT_QWRAP_VDEVS_DEFAULT 24

#define CFG_OL_QWRAP_VDEVS_PDEV0 \
	CFG_INI_UINT("num_qwrap_vdevs_pdev0", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_QWRAP_VDEVS_MAX, CFG_TGT_QWRAP_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap vdevs for radio-0")

#define CFG_OL_QWRAP_VDEVS_PDEV1 \
	CFG_INI_UINT("num_qwrap_vdevs_pdev1", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_QWRAP_VDEVS_MAX, CFG_TGT_QWRAP_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap vdevs for radio-1")

#define CFG_OL_QWRAP_VDEVS_PDEV2 \
	CFG_INI_UINT("num_qwrap_vdevs_pdev2", \
	CFG_TGT_VDEVS_MIN, CFG_TGT_QWRAP_VDEVS_MAX, CFG_TGT_QWRAP_VDEVS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap vdevs for radio-2")

/* Qwrap max client peer counts */
#define CFG_TGT_QWRAP_PEERS_MAX 28
#define CFG_TGT_QWRAP_PEERS_DEFAULT 22

#define CFG_OL_QWRAP_PEERS_PDEV0 \
	CFG_INI_UINT("num_qwrap_peers_pdev0", \
	CFG_TGT_PEERS_MIN, CFG_TGT_QWRAP_PEERS_MAX, CFG_TGT_QWRAP_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap peers for radio-0")

#define CFG_OL_QWRAP_PEERS_PDEV1 \
	CFG_INI_UINT("num_qwrap_peers_pdev1", \
	CFG_TGT_PEERS_MIN, CFG_TGT_QWRAP_PEERS_MAX, CFG_TGT_QWRAP_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap peers for radio-1")

#define CFG_OL_QWRAP_PEERS_PDEV2 \
	CFG_INI_UINT("num_qwrap_peers_pdev2", \
	CFG_TGT_PEERS_MIN, CFG_TGT_QWRAP_PEERS_MAX, CFG_TGT_QWRAP_PEERS_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Max qwrap peers for radio-2")

#define CFG_OL_FW_DUMP_OPTIONS \
	CFG_INI_UINT("fw_dump_options", \
	FW_DUMP_TO_FILE, FW_DUMP_ADD_SIGNATURE, \
	FW_DUMP_TO_CRASH_SCOPE, \
	CFG_VALUE_OR_DEFAULT, "Firmware dump options")

#define CFG_OL_SRP_SR_CONTROL \
	CFG_INI_UINT("he_srp_sr_control", \
	0, 255, \
	IEEE80211_SRP_SR_CONTROL, \
	CFG_VALUE_OR_DEFAULT, "SR Control field in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_ALLOW_MON_VAPS_IN_SR \
	CFG_INI_UINT("allow_mon_vaps_in_sr", \
	0, 1, \
	IEEE80211_ALLOW_MON_VAPS_IN_SR, \
	CFG_VALUE_OR_DEFAULT,"Allow monitor vaps to be present " \
	"while using Spatial Reuse")

#define CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DB \
	CFG_INI_INT("self_non_srg_obss_pd_threshold_db", \
	SELF_OBSS_PD_LOWER_THRESH , SELF_OBSS_PD_UPPER_THRESH,\
	IEEE80211_SELF_NON_SRG_OBSS_PD_THRESHOLD_DB,\
	CFG_VALUE_OR_DEFAULT,"Self Non-SRG OBSS-PD Threshold in dB")

#define CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DBM \
	CFG_INI_INT("self_non_srg_obss_pd_threshold_dbm", \
	SELF_OBSS_PD_LOWER_THRESH , SELF_OBSS_PD_UPPER_THRESH,\
	IEEE80211_SELF_NON_SRG_OBSS_PD_THRESHOLD_DBM,\
	CFG_VALUE_OR_DEFAULT,"Self Non-SRG OBSS-PD Threshold in dBm")

#define CFG_OL_SELF_NON_SRG_OBSS_PD_ENABLE \
	CFG_INI_UINT("self_non_srg_obss_pd_tx_enable", \
	0, 1, \
	IEEE80211_SELF_NON_SRG_OBSS_PD_ENABLE, \
	CFG_VALUE_OR_DEFAULT, "Self Non-SRG OBSS PD Tx Enable")

#define CFG_OL_SELF_SRG_OBSS_PD_THRESHOLD_DB \
	CFG_INI_INT("self_srg_obss_pd_threshold_db", \
	SELF_OBSS_PD_LOWER_THRESH , SELF_OBSS_PD_UPPER_THRESH,\
	IEEE80211_SELF_SRG_OBSS_PD_THRESHOLD_DB,\
	CFG_VALUE_OR_DEFAULT,"Self SRG OBSS-PD Threshold in dB")

#define CFG_OL_SELF_SRG_OBSS_PD_THRESHOLD_DBM \
	CFG_INI_INT("self_srg_obss_pd_threshold_dbm", \
	SELF_OBSS_PD_LOWER_THRESH , SELF_OBSS_PD_UPPER_THRESH,\
	IEEE80211_SELF_SRG_OBSS_PD_THRESHOLD_DBM,\
	CFG_VALUE_OR_DEFAULT,"Self SRG OBSS-PD Threshold in dBm")

#define CFG_OL_SELF_SRG_OBSS_PD_ENABLE \
	CFG_INI_UINT("self_srg_obss_pd_tx_enable", \
	0, 1, \
	IEEE80211_SELF_SRG_OBSS_PD_ENABLE, \
	CFG_VALUE_OR_DEFAULT, "Self SRG OBSS PD Tx Enable")

#define CFG_OL_SRP_NON_SRG_OBSS_PD_MAX_OFFSET \
	CFG_INI_UINT("he_srp_non_srg_obss_pd_max_offset", \
	0, 1000, \
	IEEE80211_SRP_NON_SRG_OBSS_PD_MAX_OFFSET, \
	CFG_VALUE_OR_DEFAULT, "Non-SRG OBSS PD MAX Offset in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_OBSS_PD_MIN_OFFSET \
	CFG_INI_UINT("he_srp_srg_obss_pd_min_offset", \
	0, 1000, \
	IEEE80211_SRP_SRG_OBSS_PD_MIN_OFFSET, \
	CFG_VALUE_OR_DEFAULT, "SRG OBSS PD MIN Offset in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_OBSS_PD_MAX_OFFSET \
	CFG_INI_UINT("he_srp_srg_obss_pd_max_offset", \
	0, 1000, \
	IEEE80211_SRP_SRG_OBSS_PD_MAX_OFFSET, \
	CFG_VALUE_OR_DEFAULT, "SRG OBSS PD MAX Offset in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_HIGH \
	CFG_INI_UINT("he_srp_srg_bss_color_bitmap_high", \
	0,MAX_CFG, \
	IEEE80211_SRP_SRG_BSS_COLOR_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Higher 32 bits of SRG BSS Color Bitmap in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_LOW \
	CFG_INI_UINT("he_srp_srg_bss_color_bitmap_low", \
	0,MAX_CFG, \
	IEEE80211_SRP_SRG_BSS_COLOR_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Lower 32 bits of SRG BSS Color Bitmap in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_HIGH \
	CFG_INI_UINT("he_srp_srg_partial_bssid_bitmap_high", \
	0,MAX_CFG, \
	IEEE80211_SRP_SRG_PARTIAL_BSSID_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Higher 32 bits of SRG Partial BSSID Bitmap in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_LOW \
	CFG_INI_UINT("he_srp_srg_partial_bssid_bitmap_low", \
	0,MAX_CFG, \
	IEEE80211_SRP_SRG_PARTIAL_BSSID_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Lower 32 bits of SRG Partial BSSID Bitmap in" \
	"HE Spatial Reuse Parameter Set Element")

#define CFG_OL_SR_ENABLE_PER_AC \
	CFG_INI_UINT("sr_enable_per_ac", \
	0, 1000, \
	IEEE80211_SR_ENABLE_PER_AC, \
	CFG_VALUE_OR_DEFAULT, "ACs enabled for SR transmissions")

#define CFG_OL_SELF_PSR_TX_ENABLE \
	CFG_INI_UINT("self_psr_tx_enable", \
	0, 1, \
	IEEE80211_SELF_PSR_TX_ENABLE, \
	CFG_VALUE_OR_DEFAULT, "Self PSR Tx Enable")

#define CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_HIGH \
	CFG_INI_UINT("self_srg_bss_color_bitmap_high", \
	0, MAX_CFG, \
	IEEE80211_SELF_SRG_BSS_COLOR_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Self SRG BSS Color Bitmap upper 32-bits")

#define CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_LOW \
	CFG_INI_UINT("self_srg_bss_color_bitmap_low", \
	0, MAX_CFG, \
	IEEE80211_SELF_SRG_BSS_COLOR_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Self SRG BSS Color Bitmap lower 32-bits")

#define CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_HIGH \
	CFG_INI_UINT("self_srg_partial_bssid_bitmap_high", \
	0, MAX_CFG, \
	IEEE80211_SELF_SRG_PARTIAL_BSSID_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Self SRG Partial BSSID Bitmap upper 32-bits")

#define CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_LOW \
	CFG_INI_UINT("self_srg_partial_bssid_bitmap_low", \
	0, MAX_CFG, \
	IEEE80211_SELF_SRG_PARTIAL_BSSID_BITMAP, \
	CFG_VALUE_OR_DEFAULT, "Self SRG Partial BSSID Bitmap lower 32-bits")

#define CFG_OL_SELF_HESIGA_SR15_ENABLE \
	CFG_INI_UINT("self_hesiga_sr15_enable", \
	0, 1, \
	IEEE80211_SELF_HESIGA_SR15_ENABLE, \
	CFG_VALUE_OR_DEFAULT, "Self HE SIGA SR15 Enable")

#define CFG_OL_TWT_ENABLE \
	CFG_INI_BOOL("twt_enable", \
	true, \
	"TWT Enable/Disable")

#define CFG_OL_B_TWT_ENABLE \
	CFG_INI_BOOL("b_twt_enable", \
	false, \
	"Broadcast TWT Enable/Disable")

#define CFG_OL_TWT_STA_CONG_TIMER_MS \
	CFG_INI_UINT("twt_sta_config_timer_ms", \
	0, 0xFFFFFFFF, 5000, \
	CFG_VALUE_OR_DEFAULT, "TWT STa config timer (ms)")

#define CFG_OL_TWT_MBSS_SUPPORT \
	CFG_INI_BOOL("twt_mbss_support", false, \
	"Enable TWT MBSS support")

#define CFG_OL_TWT_DEFAULT_SLOT_SIZE \
	CFG_INI_UINT("twt_default_slot_size", \
	0, 0xFFFFFFFF, 10, \
	CFG_VALUE_OR_DEFAULT, "TWT default slot size")

#define CFG_OL_TWT_CONGESTION_THRESH_SETUP \
	CFG_INI_UINT("twt_congestion_thresh_setup", \
	0, 100, 50, \
	CFG_VALUE_OR_DEFAULT, "Minimum congestion required to setup TWT")

#define CFG_OL_TWT_CONGESTION_THRESH_TEARDOWN \
	CFG_INI_UINT("twt_congestion_thresh_teardown", \
	0, 100, 20, \
	CFG_VALUE_OR_DEFAULT, "Minimum congestion for TWT teardown")

#define CFG_OL_TWT_CONGESTION_THRESH_CRITICAL \
	CFG_INI_UINT("twt_congestion_thresh_critical", \
	0, 100, 100, \
	CFG_VALUE_OR_DEFAULT, "TWT teardown Threshold above which TWT will not be active")

#define CFG_OL_TWT_INTERFERENCE_THRESH_TEARDOWN \
	CFG_INI_UINT("twt_interference_thresh_teardown", \
	0, 100, 80, \
	CFG_VALUE_OR_DEFAULT, "Interference threshold in percentage")

#define CFG_OL_TWT_INTERFERENCE_THRESH_SETUP \
	CFG_INI_UINT("twt_interference_thresh_setup", \
	0, 100, 50, \
	CFG_VALUE_OR_DEFAULT, "TWT Setup Interference threshold in percentage")

#define CFG_OL_TWT_MIN_NUM_STA_SETUP \
	CFG_INI_UINT("twt_min_no_sta_setup", \
	0, 4096, 10, \
	CFG_VALUE_OR_DEFAULT, "Minimum num of STA required for TWT setup")

#define CFG_OL_TWT_MIN_NUM_STA_TEARDOWN \
	CFG_INI_UINT("twt_min_no_sta_teardown", \
	0, 4096, 2, \
	CFG_VALUE_OR_DEFAULT, "Minimum num of STA below which TWT will be torn down")

#define CFG_OL_TWT_NUM_BCMC_SLOTS \
	CFG_INI_UINT("twt_no_of_bcast_mcast_slots", \
	0, 100, 2, \
	CFG_VALUE_OR_DEFAULT, "num of bcast/mcast TWT slots")

#define CFG_OL_TWT_MIN_NUM_SLOTS \
	CFG_INI_UINT("twt_min_no_twt_slots", \
	0, 1000, 2, \
	CFG_VALUE_OR_DEFAULT, "Minimum num of TWT slots")

#define CFG_OL_TWT_MAX_NUM_STA_TWT \
	CFG_INI_UINT("twt_max_no_sta_twt", \
	0, 1000, 500, \
	CFG_VALUE_OR_DEFAULT, "Maximum num of STA TWT slots")

#define CFG_OL_TWT_MODE_CHECK_INTERVAL \
	CFG_INI_UINT("twt_mode_check_interval", \
	0, 0xFFFFFFFF, 10000, \
	CFG_VALUE_OR_DEFAULT, "Interval between two successive check for TWT mode")

#define CFG_OL_TWT_ADD_STA_SLOT_INTERVAL \
	CFG_INI_UINT("twt_add_sta_slot_interval", \
	0, 0xFFFFFFFF, 1000, \
	CFG_VALUE_OR_DEFAULT, "Interval between decision making for TWT slot creation")

#define CFG_OL_TWT_REMOVE_STA_SLOT_INTERVAL \
	CFG_INI_UINT("twt_remove_sta_slot_interval", \
	0, 0xFFFFFFFF, 5000, \
	CFG_VALUE_OR_DEFAULT, "Interval between decision making for TWT slot removal")

#define CFG_OL_AP_BSS_COLOR_COLLISION_DETECTION \
	CFG_INI_BOOL("ap_bss_color_collision_detection", false, \
	"AP BSS COLOR COLLISION DETECTION")

#define CFG_OL_STA_BSS_COLOR_COLLISION_DETECTION \
	CFG_INI_BOOL("sta_bss_color_collision_detection", true, \
	"STA BSS COLOR COLLISION DETECTION")

#define CFG_OL_BSS_COLOR_DEFAULT_VAL \
	CFG_INI_UINT("bss_color_default_val", \
	0, 255, 255, \
	CFG_VALUE_OR_DEFAULT, "Default value for BSS Color (0 means disable feature and val > 63 means pick dynamically)")

#define CFG_OL_SR_IE_ENABLE \
	CFG_INI_BOOL("he_srp_ie_enable", true, \
	"Enable HE Spatial Reuse Parameter Set Element")

#define CFG_TGT_RX_MCS_MAP_MIN 0
#define CFG_TGT_RX_MCS_MAP_MAX 1
#define CFG_TGT_RX_MCS_MAP_DEFAULT 0

#define CFG_OL_SET_MAX_RX_MCS_MAP \
	CFG_INI_UINT("set_max_rx_mcs_map", \
	CFG_TGT_RX_MCS_MAP_MIN, CFG_TGT_RX_MCS_MAP_MAX, CFG_TGT_RX_MCS_MAP_DEFAULT, \
	CFG_VALUE_OR_DEFAULT, \
	"Advertise max RX MCS map in vhtcap of Association request")

/* set max value supporting for 4 pdevs at the max */
#define CFG_OL_MBSS_IE_ENABLE \
	CFG_INI_UINT("mbss_ie_enable", 0, 0x000f000f, 0, \
	CFG_VALUE_OR_DEFAULT, "Enable MBSS IE")

#define CFG_OL_EMA_AP_VENDOR_IE_SIZE_LOW \
	CFG_INI_UINT("ema_ap_vendor_ie_size_low", 0, 0xffffffff, 0x77111111, \
	CFG_VALUE_OR_DEFAULT, "Low 32 bit of vendor ie size config for ema ap")

#define CFG_OL_EMA_AP_VENDOR_IE_SIZE_HIGH \
	CFG_INI_UINT("ema_ap_vendor_ie_size_high", 0, 0xffffffff, 0x07711177, \
	CFG_VALUE_OR_DEFAULT, "High 32 bit of vendor ie size config for ema ap")

/* Derived by:  Max mgmt frame size       1500
 *              RNR size                 - 214
 *              Mandatory IEs size       - 100
 *              Max common beacon size   - 600
 *              Optional IE headroom     -  30
 *              Optional IE max size     = 556
 */
#define CFG_OL_EMA_AP_OPTIONAL_IE_SIZE \
	CFG_INI_UINT("ema_ap_optional_ie_size", 0, 556, 100, \
	CFG_VALUE_OR_DEFAULT, "Size in bytes of Optional IE for ema ap")

#define CFG_OL_EMA_AP_BEACON_COMMON_PART_SIZE \
	CFG_INI_UINT("ema_ap_beacon_common_part_size", 200, 600, 600, \
	CFG_VALUE_OR_DEFAULT, "Max size of common part of ema ap beacon")

#define CFG_OL_EMA_AP_NUM_MAX_VAPS \
	CFG_INI_UINT("ema_ap_num_max_vaps", CFG_TGT_VDEVS_MIN, CFG_TGT_VDEVS_MAX, \
	CFG_TGT_VDEVS_DEFAULT, CFG_VALUE_OR_DEFAULT, \
		"Max vaps supported with ema ap enabled")

#define CFG_OL_ENABLE_EMA_EXT \
	CFG_INI_BOOL("enable_ema_ap_ext", true, \
		"Enable EMA-ext feature with generic IE support in non-Tx profile")

#define CFG_OL_SPLIT_NON_TX_PROFILE_ENABLED \
	CFG_INI_BOOL("enable_split_non_tx_profile", true, \
		"Split Non-Tx VAP profile if profile exceeds max IE size")

#define CFG_OL_EMA_AP_SUPPORT_WPS_IN_6GHZ \
	CFG_INI_BOOL("ema_ap_support_wps_in_6ghz", false, \
		"Support WPS in EMA mode in 6Ghz")

/* Following is relevant only if support_wps_in_ema_6ghz is true */
#define CFG_OL_EMA_AP_NUM_MAX_VAPS_WITH_WPS \
	CFG_INI_UINT("ema_ap_num_max_vaps_with_wps", 1, 5, 5, \
         CFG_VALUE_OR_DEFAULT, \
		"Max vaps supported with WPS in ema ap mode in 6Ghz")

/* 214 is the required number of bytes for supporting 16 6Ghz APs
 * in RNR IE */
#define CFG_OL_EMA_AP_RNR_FIELD_SIZE_LIMIT \
	CFG_INI_UINT("ema_ap_rnr_field_size_limit", 214, 514, 214, \
        CFG_VALUE_OR_DEFAULT, \
		"Max reserved bytes for RNR IEs in EMA beacons")

#define CFG_OL_6GHZ_RNR_ADV_OVERRIDE \
	CFG_INI_BOOL("rnr_6ghz_driver_override", false, \
		"Override default 6Ghz RNR advertisement in 6Ghz AP only case")

#define CFG_OL_6GHZ_SELECTIVE_NONTX_ADD \
	CFG_INI_BOOL("rnr_selective_nontx_add", false, \
		"Enable/Disable Selective Non Tx AP advertisement in RNR")

#define CFG_OL_MAX_RNR_IE_ALLOWED \
	CFG_INI_UINT("max_rnr_ie_allowed", 1, 2, 2, \
		CFG_VALUE_OR_DEFAULT,\
		"Max RNR IE allowed")

#define CFG_OL_PEER_STATS_MIN      0
#define CFG_OL_PEER_STATS_MAX      3
#define CFG_OL_PEER_STATS_DEFAULT  0

#define CFG_OL_PEER_RATE_STATS \
	CFG_INI_UINT("enable_rdk_stats", CFG_OL_PEER_STATS_MIN, CFG_OL_PEER_STATS_MAX, \
	CFG_OL_PEER_STATS_DEFAULT, CFG_VALUE_OR_DEFAULT, \
	"ENABLE RDK STATS")

#define CFG_OL_PRI20_CFG_BLOCKCHANLIST \
	CFG_INI_STRING("pri20_cfg_blockchanlist", \
		       0, 512, "", \
		       "Primary 20MHz CFG block channel list")

#define CFG_OL_PEER_DEL_WAIT_TIME \
	CFG_INI_UINT("g_peer_del_wait_time", \
	1000, 10000, 4000, \
	CFG_VALUE_OR_DEFAULT, "Timeout to del peer refs")

#define CFG_OL_OFFCHAN_SCAN_DWELL_TIME \
	CFG_INI_UINT("offchan_dwell_time", \
	0, 2000, 1500, \
	CFG_VALUE_OR_DEFAULT, "Offchan Scan Dwell Time")

#define CFG_OL_RE_UL_RESP \
	CFG_INI_UINT("re_ul_resp", \
	0, 0xFFFFFFFF, 0, \
	CFG_VALUE_OR_DEFAULT, "Enable UL MU-OFDMA/MIMO")

#define CFG_OL_MD_CP_EXT_PDEV \
	CFG_INI_BOOL("md_cp_ext_pdev", true, \
	"Enable ol_ath_softc_net80211")

#define CFG_OL_MD_CP_EXT_PSOC \
	CFG_INI_BOOL("md_cp_ext_psoc", true, \
	"Enable ol_ath_soc_softc")

#define CFG_OL_MD_CP_EXT_VDEV \
	CFG_INI_BOOL("md_cp_ext_vdev", true, \
	"Enable ieee80211vap")

#define CFG_OL_MD_CP_EXT_PEER \
	CFG_INI_BOOL("md_cp_ext_peer", false, \
	"Enable ieee80211_node")

#define CFG_OL_MD_DP_SOC \
	CFG_INI_BOOL("md_dp_soc", true, \
	"Enable dp_soc")

#define CFG_OL_MD_DP_PDEV \
	CFG_INI_BOOL("md_dp_pdev", true, \
	"Enable dp_pdev")

#define CFG_OL_MD_DP_PEER \
	CFG_INI_BOOL("md_dp_peer", false, \
	"Enable dp_peer")

#define CFG_OL_MD_DP_SRNG_REO \
	CFG_INI_BOOL("md_dp_srng_reo", false, \
	"Enable dp_srng_reo")

#define CFG_OL_MD_DP_SRNG_TCL \
	CFG_INI_BOOL("md_dp_srng_tcl", false, \
	"Enable dp_srng_tcl")

#define CFG_OL_MD_DP_SRNG_WBM \
	CFG_INI_BOOL("md_dp_srng_wbm", false, \
	"Enable dp_srng_wbm")

#define CFG_OL_MD_DP_SRNG_RXDMA \
	CFG_INI_BOOL("md_dp_srng_rxdma", false, \
	"Enable dp_srng_rxdma")

#define CFG_OL_MD_DP_LINK_DESC_BANK \
	CFG_INI_BOOL("md_dp_link_desc_bank", false, \
	"Enable dp_link_desc_bank")

#define CFG_OL_MD_DP_HAL_SOC \
	CFG_INI_BOOL("md_dp_hal_soc", true, \
	"Enable dp_hal_soc")

#define CFG_OL_MD_OBJMGR_PSOC \
	CFG_INI_BOOL("md_objmgr_psoc", true, \
	"Enable wlan_objmgr_psoc")

#define CFG_OL_MD_OBJMGR_PDEV \
	CFG_INI_BOOL("md_objmgr_pdev", true, \
	"Enable wlan_objmgr_pdev")

#define CFG_OL_MD_OBJMGR_VDEV \
	CFG_INI_BOOL("md_objmgr_vdev", true, \
	"Enable wlan_objmgr_vdev")

#define CFG_OL_CONSOLE_LOG_MASK \
	CFG_INI_UINT("logger_enable_mask", \
	0x0, 0x1E, 0x0, \
	CFG_VALUE_OR_DEFAULT, "Log levels to be printed on console")

#define CFG_OL_WIDEBAND_CSA \
	CFG_INI_UINT("wideband_csa", 0, 2, 0, \
	CFG_VALUE_OR_DEFAULT, "Support for wideband (5-7GHz) CSA")

#define CFG_OL_WDS_EXTENDED \
	CFG_INI_BOOL("wds_ext", false, \
	"Enable WDS Extended feature")

#define CFG_OL_EXTERNALACS_ENABLE \
	CFG_INI_BOOL("externalacs_enable", false, \
	"Enable external Auto Channel Selection")

#define CFG_OL_LED_GPIO_ENABLE_8074 \
	CFG_INI_BOOL("led_gpio_enable_8074", false, \
	"led is toggled using gpio")

#define CFG_OL \
	CFG(CFG_OL_ENABLE_11AX_STUB) \
	CFG(CFG_OL_TX_TCP_CKSUM) \
	CFG(CFG_OL_VOW_CONFIG) \
	CFG(CFG_OL_CARRIER_VOW_CONFIG) \
	CFG(CFG_OL_FW_VOW_STATS_ENABLE) \
	CFG(CFG_OL_QWRAP_ENABLE) \
	CFG(CFG_OL_CCE_DISABLE) \
	CFG(CFG_OL_LOW_MEM_SYSTEM) \
	CFG(CFG_OL_BEACON_OFFLOAD_DISABLE) \
	CFG(CFG_OL_ENABLE_UART_PRINT) \
	CFG(CFG_OL_ENABLE_MESH_SUPPORT) \
	CFG(CFG_OL_LTEU_SUPPORT) \
	CFG(CFG_OL_CFG80211_CONFIG) \
	CFG(CFG_OL_CFG_IPHDR) \
	CFG(CFG_OL_BMI) \
	CFG(CFG_OL_MAX_DESC) \
	CFG(CFG_OL_MAX_PEERS) \
	CFG(CFG_OL_STRICT_CHANNEL_MODE) \
	CFG(CFG_OL_ACBK_MIN_FREE) \
	CFG(CFG_OL_ACBE_MIN_FREE) \
	CFG(CFG_OL_ACVI_MIN_FREE) \
	CFG(CFG_OL_ACVO_MIN_FREE) \
	CFG(CFG_OL_OTP_MOD_PARAM) \
	CFG(CFG_OL_EMU_TYPE) \
	CFG(CFG_OL_MAX_ACTIVE_PEERS) \
	CFG(CFG_OL_MAX_GROUP_KEYS) \
	CFG(CFG_OL_HW_MODE_ID) \
	CFG(CFG_OL_DYNAMIC_HW_MODE) \
	CFG(CFG_OL_DYNAMIC_HW_MODE_PRIMARY_IF) \
	CFG(CFG_OL_TGT_SCHED_PARAM) \
	CFG(CFG_OL_FW_CODE_SIGN) \
	CFG(CFG_OL_ALLOCRAM_TRACK_MAX) \
	CFG(CFG_OL_MAX_VAPS) \
	CFG(CFG_OL_MAX_CLIENTS) \
	CFG(CFG_OL_MAX_VDEVS_PDEV0) \
	CFG(CFG_OL_MAX_VDEVS_PDEV1) \
	CFG(CFG_OL_MAX_VDEVS_PDEV2) \
	CFG(CFG_OL_MAX_PEERS_PDEV0) \
	CFG(CFG_OL_MAX_PEERS_PDEV1) \
	CFG(CFG_OL_MAX_PEERS_PDEV2) \
	CFG(CFG_OL_MONITOR_PDEV0) \
	CFG(CFG_OL_MONITOR_PDEV1) \
	CFG(CFG_OL_MONITOR_PDEV2) \
	CFG(CFG_OL_NUM_VDEV_MESH) \
	CFG(CFG_OL_QWRAP_VDEVS_PDEV0) \
	CFG(CFG_OL_QWRAP_VDEVS_PDEV1) \
	CFG(CFG_OL_QWRAP_VDEVS_PDEV2) \
	CFG(CFG_OL_QWRAP_PEERS_PDEV0) \
	CFG(CFG_OL_QWRAP_PEERS_PDEV1) \
	CFG(CFG_OL_QWRAP_PEERS_PDEV2) \
	CFG(CFG_OL_FW_DUMP_OPTIONS) \
	CFG(CFG_OL_SRP_SR_CONTROL) \
	CFG(CFG_OL_ALLOW_MON_VAPS_IN_SR) \
	CFG(CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DB) \
	CFG(CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DBM) \
	CFG(CFG_OL_SELF_NON_SRG_OBSS_PD_ENABLE) \
	CFG(CFG_OL_SELF_SRG_OBSS_PD_THRESHOLD_DB) \
	CFG(CFG_OL_SELF_SRG_OBSS_PD_THRESHOLD_DBM) \
	CFG(CFG_OL_SELF_SRG_OBSS_PD_ENABLE) \
	CFG(CFG_OL_SRP_NON_SRG_OBSS_PD_MAX_OFFSET) \
	CFG(CFG_OL_SRP_SRG_OBSS_PD_MIN_OFFSET) \
	CFG(CFG_OL_SRP_SRG_OBSS_PD_MAX_OFFSET)\
	CFG(CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_HIGH) \
	CFG(CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_LOW) \
	CFG(CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_HIGH) \
	CFG(CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_LOW) \
	CFG(CFG_OL_SR_ENABLE_PER_AC) \
	CFG(CFG_OL_SELF_PSR_TX_ENABLE) \
	CFG(CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_HIGH) \
	CFG(CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_LOW) \
	CFG(CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_HIGH) \
	CFG(CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_LOW) \
	CFG(CFG_OL_SELF_HESIGA_SR15_ENABLE) \
	CFG(CFG_OL_EAPOL_MINRATE_SET) \
	CFG(CFG_COMMAND_LOGGING_SUPPORT) \
	CFG(CFG_OL_EAPOL_MINRATE_AC_SET) \
	CFG(CFG_OL_TWT_ENABLE) \
	CFG(CFG_OL_B_TWT_ENABLE) \
	CFG(CFG_OL_TWT_STA_CONG_TIMER_MS) \
	CFG(CFG_OL_TWT_MBSS_SUPPORT) \
	CFG(CFG_OL_TWT_DEFAULT_SLOT_SIZE) \
	CFG(CFG_OL_TWT_CONGESTION_THRESH_SETUP) \
	CFG(CFG_OL_TWT_CONGESTION_THRESH_TEARDOWN) \
	CFG(CFG_OL_TWT_CONGESTION_THRESH_CRITICAL) \
	CFG(CFG_OL_TWT_INTERFERENCE_THRESH_TEARDOWN) \
	CFG(CFG_OL_TWT_INTERFERENCE_THRESH_SETUP) \
	CFG(CFG_OL_TWT_MIN_NUM_STA_SETUP) \
	CFG(CFG_OL_TWT_MIN_NUM_STA_TEARDOWN) \
	CFG(CFG_OL_TWT_NUM_BCMC_SLOTS) \
	CFG(CFG_OL_TWT_MIN_NUM_SLOTS) \
	CFG(CFG_OL_TWT_MAX_NUM_STA_TWT) \
	CFG(CFG_OL_TWT_MODE_CHECK_INTERVAL) \
	CFG(CFG_OL_TWT_ADD_STA_SLOT_INTERVAL) \
	CFG(CFG_OL_TWT_REMOVE_STA_SLOT_INTERVAL) \
	CFG(CFG_OL_AP_BSS_COLOR_COLLISION_DETECTION) \
	CFG(CFG_OL_STA_BSS_COLOR_COLLISION_DETECTION) \
	CFG(CFG_OL_BSS_COLOR_DEFAULT_VAL) \
	CFG(CFG_OL_MBSS_IE_ENABLE) \
	CFG(CFG_OL_EMA_AP_VENDOR_IE_SIZE_LOW) \
	CFG(CFG_OL_EMA_AP_VENDOR_IE_SIZE_HIGH) \
	CFG(CFG_OL_EMA_AP_OPTIONAL_IE_SIZE) \
	CFG(CFG_OL_EMA_AP_BEACON_COMMON_PART_SIZE) \
	CFG(CFG_OL_EMA_AP_NUM_MAX_VAPS) \
	CFG(CFG_OL_ENABLE_EMA_EXT) \
	CFG(CFG_OL_SPLIT_NON_TX_PROFILE_ENABLED) \
	CFG(CFG_OL_EMA_AP_SUPPORT_WPS_IN_6GHZ) \
	CFG(CFG_OL_EMA_AP_NUM_MAX_VAPS_WITH_WPS) \
	CFG(CFG_OL_EMA_AP_RNR_FIELD_SIZE_LIMIT) \
	CFG(CFG_OL_SET_MAX_RX_MCS_MAP) \
	CFG(CFG_OL_SR_IE_ENABLE) \
	CFG(CFG_OL_PEER_RATE_STATS) \
	CFG(CFG_OL_PRI20_CFG_BLOCKCHANLIST) \
	CFG(CFG_OL_PEER_DEL_WAIT_TIME) \
	CFG(CFG_OL_OFFCHAN_SCAN_DWELL_TIME) \
	CFG(CFG_OL_RE_UL_RESP) \
	CFG(CFG_OL_MD_CP_EXT_PDEV) \
	CFG(CFG_OL_MD_CP_EXT_PSOC) \
	CFG(CFG_OL_MD_CP_EXT_VDEV) \
	CFG(CFG_OL_MD_CP_EXT_PEER) \
	CFG(CFG_OL_MD_DP_SOC) \
	CFG(CFG_OL_MD_DP_PDEV) \
	CFG(CFG_OL_MD_DP_PEER) \
	CFG(CFG_OL_MD_DP_SRNG_REO) \
	CFG(CFG_OL_MD_DP_SRNG_TCL) \
	CFG(CFG_OL_MD_DP_SRNG_WBM) \
	CFG(CFG_OL_MD_DP_LINK_DESC_BANK) \
	CFG(CFG_OL_MD_DP_SRNG_RXDMA) \
	CFG(CFG_OL_MD_DP_HAL_SOC) \
	CFG(CFG_OL_MD_OBJMGR_PSOC) \
	CFG(CFG_OL_MD_OBJMGR_PDEV) \
	CFG(CFG_OL_MD_OBJMGR_VDEV) \
	CFG(CFG_OL_ASE_OVERRIDE) \
	CFG(CFG_OL_MODE_2G_PHYB) \
	CFG(CFG_OL_MAX_WMI_CMDS) \
	CFG(CFG_OL_CONSOLE_LOG_MASK) \
	CFG(CFG_OL_WIDEBAND_CSA) \
	CFG(CFG_OL_6GHZ_RNR_ADV_OVERRIDE) \
	CFG(CFG_OL_6GHZ_SELECTIVE_NONTX_ADD) \
	CFG(CFG_OL_WDS_EXTENDED) \
	CFG(CFG_OL_EXTERNALACS_ENABLE) \
	CFG(CFG_OL_CARRIER_VOW_OPTIMIZATION) \
	CFG(CFG_OL_LED_GPIO_ENABLE_8074) \
	CFG(CFG_OL_MAX_RNR_IE_ALLOWED)
#endif /*_CFG_OL_H_*/
