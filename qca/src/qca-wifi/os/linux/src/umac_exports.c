/*
 * Copyright (c) 2016-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <ieee80211_var.h>
#include <ieee80211_vap.h>
#include <ieee80211_defines.h>
#include <ieee80211_acs.h>
#include <ieee80211_extacs.h>
#include <ieee80211_cbs.h>
#include <ieee80211_channel.h>
#include <ieee80211_api.h>
#include <ieee80211_wds.h>
#include <ieee80211_regdmn.h>
#include <acfg_drv_event.h>
#include <ieee80211_proto.h>
#include <ieee80211_admctl.h>
#include <ieee80211_vi_dbg.h>
#include <ieee80211_acfg.h>
#include <ol_if_athvar.h>
#include <wdi_event_api.h>
#include <wlan_mgmt_txrx_utils_api.h>
#include <wlan_scan.h>
#include <wlan_scan_ucfg_api.h>
#include <wlan_utility.h>
#include <wlan_mlme_dispatcher.h>
#include <wlan_son_pub.h>
#include <osif_private.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <ieee80211_ucfg.h>

#if ATH_ACS_DEBUG_SUPPORT
#include <acs_debug.h>
#endif

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif /* MESH_MODE_SUPPORT */
#include <rawsim_api_defs.h>
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

qdf_export_symbol(ieee80211_bringdown_all_vaps);
qdf_export_symbol(ieee80211_bringup_all_vaps);

/* Export ieee80211_acs.c functions */
qdf_export_symbol(ieee80211_acs_set_param);
qdf_export_symbol(ieee80211_acs_get_param);
qdf_export_symbol(ieee80211_acs_stats_update);
qdf_export_symbol(wlan_acs_block_channel_list);
qdf_export_symbol(ieee80211_acs_get_chan_idx);
qdf_export_symbol(wlan_autoselect_register_event_handler);
qdf_export_symbol(wlan_autoselect_find_infra_bss_channel);

/* Export ieee80211_cbs.c functions */
qdf_export_symbol(ieee80211_cbs_set_param);
qdf_export_symbol(ieee80211_cbs_get_param);
qdf_export_symbol(ieee80211_cbs_api_change_home_channel);
qdf_export_symbol(wlan_bk_scan);
qdf_export_symbol(wlan_bk_scan_stop);

#if ATH_SUPPORT_ICM
qdf_export_symbol(ieee80211_extacs_record_schan_info);
#endif


/* Export ieee80211_ald.c functions */
#if QCA_SUPPORT_SON
qdf_export_symbol(son_ald_record_tx);
#endif

/* Export ieee80211_aow.c/ieee80211_aow_mck.c functions */
#if ATH_SUPPORT_AOW
qdf_export_symbol(wlan_get_tsf);
qdf_export_symbol(wlan_aow_set_audioparams);
qdf_export_symbol(wlan_aow_tx);
qdf_export_symbol(wlan_aow_dispatch_data);
qdf_export_symbol(wlan_aow_register_calls_to_usb);
qdf_export_symbol(aow_register_usb_calls_to_wlan);
#endif

qdf_export_symbol(ieee80211_channel_notify_to_app);

/* Export band_steering_direct_attach.c functions */

/* Export ieee80211_channel.c functions */
qdf_export_symbol(ieee80211_chan2mode);
qdf_export_symbol(ieee80211_chan2freq);
qdf_export_symbol(ieee80211_find_any_valid_channel);
qdf_export_symbol(ieee80211_find_channel);
qdf_export_symbol(ieee80211_doth_findchan);
qdf_export_symbol(ieee80211_find_dot11_channel);
qdf_export_symbol(wlan_get_desired_phymode);
qdf_export_symbol(wlan_get_dev_current_channel);
qdf_export_symbol(wlan_set_channel);
qdf_export_symbol(ieee80211_get_chan_width);
qdf_export_symbol(ieee80211_check_overlap);
qdf_export_symbol(ieee80211_sec_chan_offset);
qdf_export_symbol(wlan_get_current_phymode);
qdf_export_symbol(ieee80211_set_channel_for_cc_change);
qdf_export_symbol(ieee80211_setctry_tryretaining_curchan);
qdf_export_symbol(wlan_set_desired_phymode);
qdf_export_symbol(ieee80211_get_ath_channel_band);
qdf_export_symbol(reg_wifi_band_to_wlan_band_id);
qdf_export_symbol(ieee80211_dcs_acs_event_handler);

/* Export ieee80211_wireless.c functions */
qdf_export_symbol(phymode_to_htflag);

qdf_export_symbol(ieee80211_ifattach);
qdf_export_symbol(ieee80211_ifdetach);
qdf_export_symbol(ieee80211_start_running);
qdf_export_symbol(ieee80211_stop_running);
qdf_export_symbol(wlan_get_device_param);
qdf_export_symbol(wlan_get_device_mac_addr);
qdf_export_symbol(ieee80211_vaps_active);

/* Export ieee80211_msg.c functions */
qdf_export_symbol(ieee80211_note);
qdf_export_symbol(ieee80211_note_mac);
qdf_export_symbol(ieee80211_discard_frame);
qdf_export_symbol(ieee80211_discard_mac);

/* Export ieee80211_node.c functions */
#if WLAN_OBJMGR_REF_ID_TRACE
qdf_export_symbol(ieee80211_free_node_debug);
qdf_export_symbol(ieee80211_find_node_debug);
qdf_export_symbol(ieee80211_find_txnode_debug);
qdf_export_symbol(ieee80211_find_rxnode_debug);
qdf_export_symbol(ieee80211_find_rxnode_nolock_debug);
qdf_export_symbol(ieee80211_ref_bss_node_debug);
qdf_export_symbol(ieee80211_try_ref_bss_node_debug);
qdf_export_symbol(_ieee80211_find_logically_deleted_node_debug);
#else
qdf_export_symbol(ieee80211_free_node);
qdf_export_symbol(ieee80211_find_node);
qdf_export_symbol(ieee80211_find_txnode);
qdf_export_symbol(ieee80211_find_rxnode);
qdf_export_symbol(ieee80211_find_rxnode_nolock);
qdf_export_symbol(ieee80211_ref_bss_node);
qdf_export_symbol(ieee80211_try_ref_bss_node);
qdf_export_symbol(_ieee80211_find_logically_deleted_node);
#endif
qdf_export_symbol(wlan_node_peer_delete_response_handler);
#ifdef AST_HKV1_WORKAROUND
qdf_export_symbol(wlan_wds_delete_response_handler);
#endif
#if ATH_SUPPORT_WRAP
#if WLAN_OBJMGR_REF_ID_TRACE
qdf_export_symbol(ieee80211_find_wrap_node_debug);
#else
qdf_export_symbol(ieee80211_find_wrap_node);
#endif
#if WLAN_QWRAP_LEGACY
qdf_export_symbol(wlan_is_wrap);
#endif
#endif
qdf_export_symbol(wlan_iterate_station_list);
qdf_export_symbol(wlan_mlme_iterate_node_list);
qdf_export_symbol(ieee80211_has_weptkipaggr);

#if ATH_SUPPORT_AOW
extern void ieee80211_send2all_nodes(void *reqvap, void *data, int len, u_int32_t seqno, u_int64_t tsf);
qdf_export_symbol(ieee80211_send2all_nodes);
#endif

#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, uint16_t chan_freq, u_int8_t tbtt, u_int16_t ch_width);
#endif

/* Export ieee80211_node_ap.c functions */
qdf_export_symbol(ieee80211_tmp_node);

/* Export ieee80211_vap.c functions */
qdf_export_symbol(ieee80211_vap_setup);
qdf_export_symbol(ieee80211_vap_detach);
qdf_export_symbol(wlan_iterate_vap_list);
qdf_export_symbol(wlan_vap_get_hw_macaddr);
qdf_export_symbol(ieee80211_new_opmode);
qdf_export_symbol(ieee80211_get_vap_opmode_count);
qdf_export_symbol(wlan_vap_get_registered_handle);
qdf_export_symbol(ieee80211_mbssid_setup);
qdf_export_symbol(ieee80211_mbssid_del_profile);
qdf_export_symbol(ieee80211_mbssid_update_mbssie_cache);
qdf_export_symbol(ieee80211_mbssid_update_mbssie_cache_entry);
qdf_export_symbol(ieee80211_mbssid_get_num_vaps_in_mbss_cache);
qdf_export_symbol(ieee80211_mbss_is_beaconing_ap);
qdf_export_symbol(ieee80211_mbssid_beacon_control);

/* Export ieee80211_dfs.c functions */
qdf_export_symbol(ieee80211_dfs_action);
qdf_export_symbol(ieee80211_mark_dfs);

/* Export ieee80211_extap.c functions */
extern void compute_udp_checksum(qdf_net_iphdr_t *p_iph, unsigned short  *ip_payload);
qdf_export_symbol(compute_udp_checksum);

/* Export ieee80211_beacon.c functions */
qdf_export_symbol(ieee80211_beacon_alloc);
qdf_export_symbol(ieee80211_beacon_update);
qdf_export_symbol(wlan_pdev_beacon_update);
qdf_export_symbol(ieee80211_mlme_beacon_suspend_state);
qdf_export_symbol(ieee80211_csa_interop_phy_update);
qdf_export_symbol(ieee80211_prb_rsp_update);
qdf_export_symbol(ieee80211_prb_rsp_alloc_init);

/* Export ieee80211_mgmt.c functions */
qdf_export_symbol(ieee80211_send_deauth);
qdf_export_symbol(ieee80211_send_disassoc);
qdf_export_symbol(ieee80211_send_action);
qdf_export_symbol(ieee80211_prepare_qosnulldata);
qdf_export_symbol(ieee80211_recv_mgmt);
qdf_export_symbol(ieee80211_recv_ctrl);
qdf_export_symbol(ieee80211_dfs_cac_cancel);
qdf_export_symbol(ieee80211_dfs_cac_start);

qdf_export_symbol(check_inter_band_switch_compatibility);

qdf_export_symbol(ieee80211_ucfg_set_chanswitch);

/* Export ieee80211_mlme.c functions */
qdf_export_symbol(wlan_mlme_deauth_request);
qdf_export_symbol(sta_disassoc);
qdf_export_symbol(ieee80211_mlme_node_pwrsave);
qdf_export_symbol(cleanup_sta_peer);

/* Export ieee80211_mlme_sta.c functions */
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
qdf_export_symbol(mlme_set_stacac_valid);
#endif
qdf_export_symbol(ieee80211_indicate_sta_radar_detect);

/* Export ieee80211_proto.c functions */
qdf_export_symbol(ieee80211_wme_initglobalparams);
qdf_export_symbol(ieee80211_muedca_initglobalparams);
qdf_export_symbol(ieee80211_wme_updateparams_locked);
qdf_export_symbol(ieee80211_dump_pkt);

/* Export ieee80211_power_queue.c functions */
qdf_export_symbol(ieee80211_node_saveq_queue);
qdf_export_symbol(ieee80211_node_saveq_flush);

/* Export ieee80211_regdmn.c functions */
qdf_export_symbol(ieee80211_set_regclassids);
qdf_export_symbol(wlan_set_countrycode);
qdf_export_symbol(wlan_set_regdomain);
qdf_export_symbol(regdmn_update_ic_channels);
qdf_export_symbol(ieee80211_set_6G_opclass_triplets);
qdf_export_symbol(wlan_reg_is_24ghz_ch_freq);
qdf_export_symbol(wlan_reg_is_5ghz_ch_freq);
qdf_export_symbol(wlan_reg_is_6ghz_chan_freq);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
qdf_export_symbol(mlme_reset_mlme_req);
qdf_export_symbol(mlme_cancel_stacac_timer);
qdf_export_symbol(mlme_set_stacac_running);
#endif

#if UNIFIED_SMARTANTENNA
extern int register_smart_ant_ops(struct smartantenna_ops *sa_ops);
extern int deregister_smart_ant_ops(char *dev_name);
qdf_export_symbol(register_smart_ant_ops);
qdf_export_symbol(deregister_smart_ant_ops);
#endif

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
qdf_export_symbol(register_rawsim_ops);
qdf_export_symbol(deregister_rawsim_ops);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

/* Export ieee80211_txbf.c functions */
#ifdef ATH_SUPPORT_TxBF
qdf_export_symbol(ieee80211_set_TxBF_keycache);
qdf_export_symbol(ieee80211_request_cv_update);
#endif

/* Export ieee80211_input.c functions */
qdf_export_symbol(ieee80211_input);
qdf_export_symbol(ieee80211_input_all);
qdf_export_symbol(ieee80211_mgmt_input);

#ifdef ATH_SUPPORT_TxBF
extern void
ieee80211_tx_bf_completion_handler(struct ieee80211_node *ni,  struct ieee80211_tx_status *ts);
qdf_export_symbol(ieee80211_tx_bf_completion_handler);
#endif

#ifdef ATH_SUPPORT_QUICK_KICKOUT
qdf_export_symbol(ieee80211_kick_node);
#endif

qdf_export_symbol(ieee80211_complete_wbuf);
qdf_export_symbol(ieee80211_mgmt_complete_wbuf);
/* Export ieee80211_wds.c functions */
qdf_export_symbol(ieee80211_nawds_disable_beacon);

/* Export ieee80211_wnm.c functions */
qdf_export_symbol(wlan_wnm_tfs_filter);
qdf_export_symbol(ieee80211_timbcast_alloc);
qdf_export_symbol(ieee80211_timbcast_update);
qdf_export_symbol(ieee80211_wnm_timbcast_cansend);
qdf_export_symbol(ieee80211_wnm_timbcast_enabled);
qdf_export_symbol(ieee80211_timbcast_lowrateenable);
qdf_export_symbol(ieee80211_timbcast_highrateenable);
qdf_export_symbol(ieee80211_wnm_fms_enabled);

#if UMAC_SUPPORT_ACFG
/* Export acfg_net_event.c functions */
qdf_export_symbol(acfg_event_netlink_init);
qdf_export_symbol(acfg_event_netlink_delete);
#endif

/* Export adf_net_vlan.c functions */
#if ATH_SUPPORT_VLAN
qdf_export_symbol(qdf_net_get_vlan);
qdf_export_symbol(qdf_net_is_vlan_defined);
#endif

/* Export ald_netlink.c functions */
#if QCA_SUPPORT_SON
qdf_export_symbol(son_ald_init_netlink);
qdf_export_symbol(son_ald_destroy_netlink);
qdf_export_symbol(son_ald_update_phy_error_rate);
#endif

/* Export osif_umac.c functions */
extern struct ath_softc_net80211 *global_scn[10];
extern ol_ath_soc_softc_t *ol_global_soc[GLOBAL_SOC_SIZE];
extern int num_global_scn;
extern int ol_num_global_soc;
extern unsigned long ath_ioctl_debug;
qdf_export_symbol(global_scn);
qdf_export_symbol(num_global_scn);
qdf_export_symbol(ol_global_soc);
qdf_export_symbol(ol_num_global_soc);
qdf_export_symbol(ath_ioctl_debug);
#if ATH_DEBUG
extern unsigned long ath_rtscts_enable;
qdf_export_symbol(ath_rtscts_enable);
#endif
qdf_export_symbol(osif_restart_for_config);
qdf_export_symbol(osif_num_ap_up_vaps);
qdf_export_symbol(osif_pdev_restart_vaps);

/* Export ath_wbuf.c functions */
qdf_export_symbol(__wbuf_uapsd_update);

/* Export if_ath_pci.c functions */
extern unsigned int ahbskip;
qdf_export_symbol(ahbskip);

/* Export osif_proxyarp.c functions */
#if UMAC_SUPPORT_PROXY_ARP
int wlan_proxy_arp(wlan_if_t vap, wbuf_t wbuf);
qdf_export_symbol(wlan_proxy_arp);

int do_proxy_arp(wlan_if_t vap, qdf_nbuf_t netbuf);
qdf_export_symbol(do_proxy_arp);
#endif

/* Export ext_ioctl_drv_if.c functions */
qdf_export_symbol(ieee80211_extended_ioctl_chan_switch);
qdf_export_symbol(ieee80211_extended_ioctl_chan_scan);
qdf_export_symbol(ieee80211_extended_ioctl_rep_move);

#if UMAC_SUPPORT_ACFG
/* Export ieee80211_ioctl_acfg.c */
void acfg_convert_to_acfgprofile (struct ieee80211_profile *profile,
                                acfg_radio_vap_info_t *acfg_profile);
qdf_export_symbol(acfg_convert_to_acfgprofile);
#endif
/* Export ieee80211_admctl.c */
#if UMAC_SUPPORT_ADMCTL
qdf_export_symbol(ieee80211_admctl_classify);
#endif

/* ieee80211_vi_dbg.c */
#if UMAC_SUPPORT_VI_DBG
qdf_export_symbol(ieee80211_vi_dbg_input);
#endif

/* ieee80211_common.c */
qdf_export_symbol(ieee80211_vaps_ready);
qdf_export_symbol(IEEE80211_DPRINTF);

#if QCA_PARTNER_PLATFORM
qdf_export_symbol(wlan_vap_get_devhandle);
qdf_export_symbol(wlan_vap_unregister_mlme_event_handlers);
qdf_export_symbol(wlan_vap_register_mlme_event_handlers);
qdf_export_symbol(ieee80211_find_wds_node);
#endif
void ic_reset_params(struct ieee80211com *ic);
qdf_export_symbol(ic_reset_params);

qdf_export_symbol(IEEE80211_DPRINTF_IC);
qdf_export_symbol(IEEE80211_DPRINTF_IC_CATEGORY);
qdf_export_symbol(ieee80211_dfs_proc_cac);
qdf_export_symbol(ieee80211_bringup_ap_vaps);
#if QCA_SUPPORT_SON
qdf_export_symbol(son_ioctl_ald_getStatistics);
#endif
qdf_export_symbol(ieee80211_is_pmf_enabled);
qdf_export_symbol(wlan_get_operational_rates);
qdf_export_symbol(ieee80211_aplist_get_desired_bssid_count);
qdf_export_symbol(ieee80211_vap_get_opmode);
qdf_export_symbol(delete_default_vap_keys);
qdf_export_symbol(ieee80211_reset_erp);
qdf_export_symbol(ieee80211_wnm_bssmax_updaterx);
qdf_export_symbol(ieee80211_notify_michael_failure);
qdf_export_symbol(ieee80211_secondary20_channel_offset);
qdf_export_symbol(wlan_vap_get_opmode);
qdf_export_symbol(ieee80211_send_mgmt);
qdf_export_symbol(ieee80211_vap_mlme_inact_erp_timeout);
qdf_export_symbol(ieee80211_vap_is_any_running);
qdf_export_symbol(osif_restart_vaps);
qdf_export_symbol(ieee80211_wme_initparams);
qdf_export_symbol(wlan_deauth_all_stas);
qdf_export_symbol(ieee80211com_note);
qdf_export_symbol(ieee80211_setpuregbasicrates);
qdf_export_symbol(ieee80211_set_shortslottime);
qdf_export_symbol(ieee80211_set_protmode);
qdf_export_symbol(ieee80211_aplist_get_desired_bssid);
qdf_export_symbol(wlan_vap_get_bssid);
qdf_export_symbol(ieee80211_add_vhtcap);
qdf_export_symbol(ieee80211_get_chan_centre_freq);
#if UMAC_SUPPORT_ACFG
qdf_export_symbol(acfg_send_event);
qdf_export_symbol(acfg_chan_stats_event);
#endif
qdf_export_symbol(ieee80211_mlme_sta_swbmiss_timer_disable);
qdf_export_symbol(wlan_get_param);
qdf_export_symbol(wlan_get_key);
qdf_export_symbol(ieee80211_mlme_sta_bmiss_ind);
qdf_export_symbol(ieee80211_phymode_name);
qdf_export_symbol(ieee80211_mlme_sta_swbmiss_timer_alloc_id);
qdf_export_symbol(wlan_channel_ieee);

#if MESH_MODE_SUPPORT
extern void ieee80211_check_timeout_mesh_peer(void *arg, wlan_if_t vaphandle);
qdf_export_symbol(ieee80211_check_timeout_mesh_peer);
extern void os_if_tx_free_batch_ext(struct sk_buff *bufs, int tx_err);
qdf_export_symbol(os_if_tx_free_batch_ext);
#endif /* MESH_MODE_SUPPORT */
qdf_export_symbol(ieee80211_get_txstreams);
extern uint32_t promisc_is_active (struct ieee80211com *ic);
qdf_export_symbol(promisc_is_active);
#if UMAC_SUPPORT_VI_DBG
qdf_export_symbol(ieee80211_vi_dbg_print_stats);
#endif
qdf_export_symbol(ieee80211_getstreams);
qdf_export_symbol(ieee80211_vap_get_aplist_config);
qdf_export_symbol(ieee80211_add_htcap);
qdf_export_symbol(ieee80211_session_timeout);
qdf_export_symbol(ieee80211_noassoc_sta_timeout);
qdf_export_symbol(wlan_set_param);
qdf_export_symbol(transcap_dot3_to_eth2);
qdf_export_symbol(wlan_get_vap_opmode_count);
qdf_export_symbol(ieee80211_get_num_vaps_up);
qdf_export_symbol(ieee80211_get_num_ap_vaps_up);
qdf_export_symbol(ieee80211_get_num_beaconing_ap_vaps_up);
qdf_export_symbol(ieee80211_get_num_sta_vaps_up);
extern unsigned int enable_pktlog_support;
qdf_export_symbol(enable_pktlog_support);
qdf_export_symbol(wlan_mgmt_txrx_register_rx_cb);
qdf_export_symbol(wlan_mgmt_txrx_deregister_rx_cb);
qdf_export_symbol(wlan_mgmt_txrx_beacon_frame_tx);
qdf_export_symbol(wlan_mgmt_txrx_vdev_drain);
qdf_export_symbol(wlan_find_full_channel);
qdf_export_symbol(wlan_scan_update_channel_list);
qdf_export_symbol(util_wlan_scan_db_iterate_macaddr);
qdf_export_symbol(wlan_pdev_scan_in_progress);
qdf_export_symbol(wlan_scan_cache_update_callback);
qdf_export_symbol(ucfg_scan_register_bcn_cb);
qdf_export_symbol(wlan_chan_to_freq);
qdf_export_symbol(wlan_freq_to_chan);
qdf_export_symbol(ieee80211_compute_nss);
qdf_export_symbol(wlan_scan_update_wide_band_scan_config);
qdf_export_symbol(wlan_crypto_get_param);
qdf_export_symbol(wlan_crypto_delkey);
qdf_export_symbol(wlan_crypto_setkey);
qdf_export_symbol(wlan_crypto_getkey);
qdf_export_symbol(wlan_crypto_restore_keys);
qdf_export_symbol(wlan_crypto_is_pmf_enabled);
qdf_export_symbol(wlan_crypto_vdev_is_pmf_enabled);
#if DBDC_REPEATER_SUPPORT
qdf_export_symbol(wlan_update_radio_priorities);
#endif
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
qdf_export_symbol(osif_set_primary_radio_event);
#endif

#ifdef WLAN_SUPPORT_FILS
qdf_export_symbol(wlan_mgmt_txrx_fd_action_frame_tx);
#endif
qdf_export_symbol(wlan_objmgr_peer_obj_create);
qdf_export_symbol(ieee80211_try_mark_node_for_delayed_cleanup);

#if ATH_ACS_DEBUG_SUPPORT
/* Exporting Functions from ACS debug framework */
qdf_export_symbol(acs_debug_add_bcn);
qdf_export_symbol(acs_debug_add_chan_event_acs);
qdf_export_symbol(acs_debug_add_chan_event_icm);
qdf_export_symbol(acs_debug_cleanup);
#endif

qdf_export_symbol(is_node_self_peer);
#if WLAN_OBJMGR_REF_ID_TRACE
qdf_export_symbol(wlan_objmgr_free_node_debug);
#else
qdf_export_symbol(wlan_objmgr_free_node);
#endif
qdf_export_symbol(wlan_is_ap_cac_timer_running);
qdf_export_symbol(ieee80211_get_num_active_vaps);
qdf_export_symbol(wlan_is_non_beaconing_ap_vap);
qdf_export_symbol(wlan_pdev_mlme_vdev_sm_chan_change);
qdf_export_symbol(mlme_vdev_send_deauth);
qdf_export_symbol(ieee80211_update_vdev_chan);
qdf_export_symbol(ieee80211_update_peer_cw);
qdf_export_symbol(ieee80211_get_rnr_count);
qdf_export_symbol(ieee80211_display_rnr_stats);
qdf_export_symbol(ieee80211_is_phymode_supported_by_channel);
qdf_export_symbol(ieee80211_is_chan_radar);
qdf_export_symbol(ieee80211_is_chan_nol_history);

qdf_export_symbol(ieee80211_mbss_switch_mode);
qdf_export_symbol(ieee80211_mbss_handle_mode_switch);
qdf_export_symbol(ieee80211_mbss_mode_switch_sanity);
qdf_export_symbol(ieee80211_intersect_mcsnssmap);
