/*
 * Copyright (c) 2017-2018 Qualcomm Innovation Center, Inc..
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include <wlan_tgt_def_config.h>
#include <target_type.h>
#include <hif_hw_version.h>
#include <ol_if_athvar.h>
#include <target_if_sa_api.h>
#include <target_if.h>
#include <wlan_lmac_if_def.h>
#include <wlan_osif_priv.h>
#include <wlan_mlme_dispatcher.h>
#include <init_deinit_lmac.h>
#include <cdp_txrx_ctrl.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>

#define A_IO_READ32(addr)         ioread32((void __iomem *)addr)
#define A_IO_WRITE32(addr, value) iowrite32((u32)(value), (void __iomem *)(addr))

static int
target_if_smart_ant_dummy_assoc_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    return 0;
}

static int
target_if_smart_ant_assoc_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
	ol_ath_soc_softc_t *scn = (ol_ath_soc_softc_t *) sc;
	uint8_t peer_macaddr[QDF_MAC_ADDR_SIZE];
	uint32_t pdev_id = 0;
	wmi_sa_rate_cap rate_cap;
	struct wlan_objmgr_peer *peer_obj;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_pdev *pdev;
	wmi_unified_t tgt_if_handle = 0;
	QDF_STATUS status;

	psoc = scn->psoc_obj;
	if (NULL == psoc) {
		sa_api_err("psoc is NULL\n");
		return -EINVAL;
	}

	status = wlan_objmgr_psoc_try_get_ref(psoc, WLAN_SA_API_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		sa_api_err("Unable to get psoc reference");
		return -EINVAL;
	}


	tgt_if_handle = GET_WMI_HDL_FROM_PSOC(psoc);
	if (NULL == tgt_if_handle) {
		sa_api_err("tgt_if_handle is NULL\n");
		wlan_objmgr_psoc_release_ref(psoc, WLAN_SA_API_ID);
		return -EINVAL;
	}

	qdf_mem_zero(&rate_cap, sizeof(wmi_sa_rate_cap));
	if (wmi_extract_peer_ratecode_list_ev(tgt_if_handle,
				data, peer_macaddr, &pdev_id, &rate_cap) < 0) {
		sa_api_err("Unable to extract peer_ratecode_list_ev");
		wlan_objmgr_psoc_release_ref(psoc, WLAN_SA_API_ID);
		return -1;
	}

	pdev = wlan_objmgr_get_pdev_by_id(psoc, pdev_id, WLAN_SA_API_ID);
	if (NULL == pdev) {
		sa_api_err("pdev is %pK\n", pdev);
		wlan_objmgr_psoc_release_ref(psoc, WLAN_SA_API_ID);
		return -EINVAL;
	}

	peer_obj = wlan_objmgr_get_peer(psoc, pdev_id, peer_macaddr, WLAN_MLME_SB_ID);
	if (peer_obj == NULL) {
		sa_api_err("Unable to find peer object for MAC %s from pdev_id %d",
			   ether_sprintf(peer_macaddr), pdev_id);
		wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
		wlan_objmgr_psoc_release_ref(psoc, WLAN_SA_API_ID);
		return -1;
	}

	/* peer connect */
	target_if_sa_api_peer_assoc_hanldler(psoc, pdev, peer_obj, (struct sa_rate_cap *)&rate_cap);

	wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
	wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
	wlan_objmgr_psoc_release_ref(psoc, WLAN_SA_API_ID);

	return 0;
}

QDF_STATUS target_if_sa_api_process_rx_feedback(
	struct wlan_objmgr_pdev *pdev, struct cdp_rx_indication_ppdu *cdp_rx_ppdu)
{
	struct sa_rx_feedback feedback;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_peer *peer;
	uint8_t chain, index;
	uint32_t evm_count = 0;

	if (qdf_unlikely(!cdp_rx_ppdu)) {
		sa_api_err("Invalid cdp_rx_ppdu %p", cdp_rx_ppdu);
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_pdev_get_psoc(pdev);
	if (qdf_unlikely(!psoc)) {
		sa_api_err("Failed to get psoc");
		return QDF_STATUS_E_INVAL;
	}
	peer = wlan_objmgr_get_peer(psoc, wlan_objmgr_pdev_get_pdev_id(pdev),
				    cdp_rx_ppdu->mac_addr, WLAN_SA_API_ID);
	if (qdf_unlikely(!peer)) {
		sa_api_err("Failed to get peer for MAC %s", cdp_rx_ppdu->mac_addr);
		return QDF_STATUS_E_INVAL;
	}

	qdf_mem_zero(&feedback, sizeof(struct sa_rx_feedback));

	feedback.rx_rate_index = cdp_rx_ppdu->u.bw;
	feedback.rx_rate_mcs = cdp_rx_ppdu->rx_ratecode;
	feedback.npackets = cdp_rx_ppdu->num_msdu;
	feedback.rx_antenna = cdp_rx_ppdu->rx_antenna;
	for (chain = 0; chain < MAX_SA_RSSI_CHAINS; chain++) {
		for (index = 0; index < MAX_SA_BW; index++)
			feedback.rx_rssi[chain][index] = cdp_rx_ppdu->rssi_chain[chain][index];
	}
	evm_count = cdp_rx_ppdu->evm_info.pilot_count * cdp_rx_ppdu->evm_info.nss_count;
	if (evm_count > MAX_EVM_SIZE) {
		evm_count = MAX_EVM_SIZE;
	}
	for (index = 0; index < evm_count; index++) {
		feedback.rx_evm[index] = cdp_rx_ppdu->evm_info.pilot_evm[index];
	}

	target_if_sa_api_update_rx_feedback(psoc, pdev, peer, &feedback);
	wlan_objmgr_peer_release_ref(peer, WLAN_SA_API_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS target_if_sa_api_process_tx_feedback(
	struct wlan_objmgr_pdev *pdev, struct cdp_tx_completion_ppdu_user *ppdu_user)
{
	struct sa_tx_feedback feedback;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_peer *peer;
	uint32_t sa_mode = 0;
	uint8_t i = 0;

	if (qdf_unlikely(!ppdu_user)) {
		sa_api_err("Invalid ppdu_user %p", ppdu_user);
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_pdev_get_psoc(pdev);
	if (qdf_unlikely(!psoc)) {
		sa_api_err("Failed to get psoc");
		return QDF_STATUS_E_INVAL;
	}

	peer = wlan_objmgr_get_peer(psoc, wlan_objmgr_pdev_get_pdev_id(pdev),
				    ppdu_user->mac_addr, WLAN_SA_API_ID);
	if (qdf_unlikely(!peer)) {
		sa_api_err("Failed to get peer for MAC %s", ether_sprintf(ppdu_user->mac_addr));
		return QDF_STATUS_E_INVAL;
	}

	vdev = wlan_peer_get_vdev(peer);
	if (qdf_unlikely(!vdev)) {
		sa_api_err("Failed to get vdev");
		wlan_objmgr_peer_release_ref(peer, WLAN_SA_API_ID);
		return QDF_STATUS_E_INVAL;
	}

	if ((QDF_SAP_MODE == wlan_vdev_mlme_get_opmode(vdev)) &&
	    (peer == wlan_vdev_get_bsspeer(vdev))) {
		wlan_objmgr_peer_release_ref(peer, WLAN_SA_API_ID);
		return QDF_STATUS_E_NOSUPPORT;
	}

	sa_mode = target_if_sa_api_get_sa_mode(psoc, pdev);

	qdf_mem_zero(&feedback, sizeof(struct sa_tx_feedback));

	feedback.nPackets = ppdu_user->mpdu_success + ppdu_user->mpdu_failed;
	feedback.nBad = ppdu_user->mpdu_failed;
	feedback.rate_mcs[0] = ppdu_user->tx_ratecode;

	/* succes_idx is comming from Firmware,
	 * with recent changes success_idx is comming from bw_idx of ppdu stats
	 */
	feedback.rate_index = ppdu_user->bw;

	if (sa_mode == SMART_ANT_MODE_SERIAL) {
		/* Extract and fill
		 * index0 - s0_bw20,
		 * index1 - s0_bw40,
		 * index4 - s1_bw20,
		 * ...
		 * index7 - s1_bw160
		 */
		for (i = 0; i < MAX_RETRIES_INDEX; i++) {
			feedback.nlong_retries[i] =  ((ppdu_user->long_retries >> (i*SA_NIBBLE_BITS)) & SA_MASK_LOWER_NIBBLE);
			feedback.nshort_retries[i] = ((ppdu_user->short_retries >> (i*SA_NIBBLE_BITS)) & SA_MASK_LOWER_NIBBLE);
			/* HW gives try counts and for SA module we need to provide failure counts
			 * So manipulate short failure count accordingly.
			 */
			if (feedback.nlong_retries[i]) {
				if (feedback.nshort_retries[i] == feedback.nlong_retries[i]) {
					feedback.nshort_retries[i]--;
				}
			}
		}
		if (feedback.nPackets != feedback.nBad) {
			if (feedback.nlong_retries[feedback.rate_index]) {
				feedback.nlong_retries[feedback.rate_index] -= 1;
			}
			if (feedback.nshort_retries[feedback.rate_index]) {
				feedback.nshort_retries[feedback.rate_index] -= 1;
			}
		}
	}

	/* RSSI from peer tx RSSI chain */
	for (i = 0; i < MAX_SA_RSSI_CHAINS; i++)
		feedback.rssi[i] = ppdu_user->rssi_chain[i];
	/* Smart Antenna stats */
	feedback.tx_antenna[0] = ppdu_user->sa_tx_antenna;
	feedback.is_trainpkt = ppdu_user->sa_is_training;
	for (i = 0; i < MAX_RATE_COUNTERS; i++)
		feedback.ratemaxphy[i] = ppdu_user->sa_max_rates[i];
	feedback.goodput = ppdu_user->sa_goodput;

	target_if_sa_api_update_tx_feedback(psoc, pdev, peer, &feedback);
	wlan_objmgr_peer_release_ref(peer, WLAN_SA_API_ID);

	return QDF_STATUS_SUCCESS;
}

void target_if_sa_api_register_wmi_event_handler(struct wlan_objmgr_psoc *psoc)
{
	if (NULL == psoc) {
		sa_api_err("PSOC is NULL!\n");
		return;
	}

	if (target_if_sa_api_get_sa_enable(psoc)) {
	    wmi_unified_register_event_handler(
			get_wmi_unified_hdl_from_psoc(psoc),
			wmi_peer_ratecode_list_event_id,
			target_if_smart_ant_assoc_handler,
			WMI_RX_UMAC_CTX);
	} else {
	    wmi_unified_register_event_handler(
			get_wmi_unified_hdl_from_psoc(psoc),
			wmi_peer_ratecode_list_event_id,
			target_if_smart_ant_dummy_assoc_handler,
			WMI_RX_UMAC_CTX);

	}
}

void target_if_sa_api_unregister_wmi_event_handler(struct wlan_objmgr_psoc *psoc)
{
	if (NULL == psoc) {
		sa_api_err("PSOC is NULL!\n");
		return;
	}

	wmi_unified_unregister_event_handler(
			get_wmi_unified_hdl_from_psoc(psoc),
			wmi_peer_ratecode_list_event_id);
}


void target_if_sa_api_set_tx_antenna(struct wlan_objmgr_peer *peer, uint32_t *antenna_array)
{
	struct smart_ant_tx_ant_params param;
	uint8_t *mac = NULL;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;

	qdf_mem_set(&param, sizeof(param), 0);

	param.antenna_array = antenna_array;

	mac = wlan_peer_get_macaddr(peer);
	vdev = wlan_peer_get_vdev(peer);

	if (vdev == NULL) {
		sa_api_err("vdev is NULL!\n");
		return;
	}

	param.vdev_id = wlan_vdev_get_id(vdev);
	pdev = wlan_vdev_get_pdev(vdev);

	if (pdev == NULL) {
		sa_api_err("pdev is NULL!\n");
		return;
	}

	wmi_unified_smart_ant_set_tx_ant_cmd_send(lmac_get_pdev_wmi_handle(pdev), mac, &param);
}

void target_if_sa_api_set_rx_antenna(struct wlan_objmgr_pdev *pdev, uint32_t antenna)
{
	struct smart_ant_rx_ant_params param;

	qdf_mem_set(&param, sizeof(param), 0);
	param.antenna = antenna;

	wmi_unified_smart_ant_set_rx_ant_cmd_send(lmac_get_pdev_wmi_handle(pdev), &param);
}

int target_if_pdev_set_param(struct wlan_objmgr_pdev *pdev, /* can be moved to generic file */
		uint32_t param_id, uint32_t param_value)
{
	struct pdev_params pparam;
	uint32_t pdev_id;

	pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

	qdf_mem_set(&pparam, sizeof(pparam), 0);
	pparam.param_id = param_id;
	pparam.param_value = param_value;

	return wmi_unified_pdev_param_send(lmac_get_pdev_wmi_handle(pdev), &pparam, pdev_id);
}

static void target_if_sa_api_set_gpio(struct platform_device *plt_dev,
				      uint8_t *gpio_name, uint32_t value)
{
	int32_t mac_gpio = 0;

	mac_gpio = of_get_named_gpio(plt_dev->dev.of_node, gpio_name, 0);
	if (gpio_is_valid(mac_gpio)) {
		if (!value) {
			sa_api_info("Free GPIO %d", mac_gpio);
			gpio_direction_output(mac_gpio, 1);
			gpio_set_value(mac_gpio, value);
			devm_gpio_free(&plt_dev->dev, mac_gpio);
		} else if (!devm_gpio_request(&plt_dev->dev, mac_gpio, gpio_name)) {
			sa_api_info("Set MAC GPIO #%d", mac_gpio);
			gpio_direction_output(mac_gpio, 1);
			gpio_set_value(mac_gpio, value);
		} else {
			sa_api_err("failed to request mac-gpios %d", mac_gpio);
		}
	} else {
		sa_api_err("Invalid GPIO %d", mac_gpio);
	}
}

static void
target_if_sa_api_set_gpio_param(struct wlan_objmgr_pdev *pdev, uint32_t enable,
				bool is_ar900b, uint32_t target_type,
				struct smart_ant_enable_params *param)
{
	void __iomem *smart_antenna_gpio;
	uint32_t reg_value;
	struct platform_device *plt_dev;
	struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(pdev);

	if (!scn) {
		sa_api_err("Failed to get scn!");
		return;
	}
	plt_dev = (struct platform_device *)(scn->sc_osdev->bdev);

        if (!is_ar900b &&
	    (target_type != TARGET_TYPE_QCA8074) &&
	    (target_type != TARGET_TYPE_QCA8074V2) &&
	    (target_type != TARGET_TYPE_QCA6018) &&
	    (target_type != TARGET_TYPE_QCN9000)) {
		param->gpio_pin[0] = OL_SMART_ANTENNA_PIN0;
		param->gpio_func[0] = OL_SMART_ANTENNA_FUNC0;
		param->gpio_pin[1] = OL_SMART_ANTENNA_PIN1;
		param->gpio_func[1] = OL_SMART_ANTENNA_FUNC1;
		param->gpio_pin[2] = OL_SMART_ANTENNA_PIN2;
		param->gpio_func[2] = OL_SMART_ANTENNA_FUNC2;
		param->gpio_pin[3] = 0;  /*NA for !is_ar900b */
		param->gpio_func[3] = 0; /*NA for !is_ar900b */
	}
	if (target_type == TARGET_TYPE_IPQ4019) {
		smart_antenna_gpio = ioremap_nocache(IPQ4019_SMARTANTENNA_BASE_GPIO,
						     IPQ4019_SMARTANTENNA_GPIOS_REG_SIZE);
		if (smart_antenna_gpio) {
			if (enable) {
				/* Enable Smart antenna related GPIOs */
				if (wlan_pdev_in_gmode(pdev)) {
					sa_api_info("Enabling 2G Smart Antenna GPIO on ipq4019");
					reg_value = A_IO_READ32(smart_antenna_gpio);
					reg_value = (reg_value & ~0x1C) | 0xC;
					A_IO_WRITE32(smart_antenna_gpio, reg_value); /* gpio 44 2G Strobe */

					reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO45_OFFSET);
					reg_value = (reg_value & ~0x1C) | 0x10;
					A_IO_WRITE32(smart_antenna_gpio+0x1000, reg_value); /* gpio 45 2G Sdata */
				} else {
					sa_api_info("Enabling 5G Smart Antenna GPIO on ipq4019");
					reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO46_OFFSET);
					reg_value = (reg_value & ~0x1C) | 0xC;
					A_IO_WRITE32(smart_antenna_gpio+0x2000, reg_value); /* gpio 46 5G Strobe */

					reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO47_OFFSET);
					reg_value = (reg_value & ~0x1C) | 0xC;
					A_IO_WRITE32(smart_antenna_gpio+0x3000, reg_value); /* gpio 47 5G Sdata */
				}
			} else {
				/* Disable Smart antenna related GPIOs */
				if (wlan_pdev_in_gmode(pdev)) {
					sa_api_info("Disabling 2G Smart Antenna GPIO on ipq4019");
					reg_value = A_IO_READ32(smart_antenna_gpio);
					reg_value = (reg_value & ~0x1C);
					A_IO_WRITE32(smart_antenna_gpio, reg_value); /* gpio 44 2G Strobe */

					reg_value = A_IO_READ32(smart_antenna_gpio + 0x1000);
					reg_value = (reg_value & ~0x1C);
					A_IO_WRITE32(smart_antenna_gpio + 0x1000, reg_value); /* gpio 45 2G Sdata */
				} else {
					sa_api_info("Disabling 5G Smart Antenna GPIO on ipq4019");
					reg_value = A_IO_READ32(smart_antenna_gpio + 0x2000);
					reg_value = (reg_value & ~0x1C);
					A_IO_WRITE32(smart_antenna_gpio+0x2000, reg_value); /* gpio 46 5G Strobe */

					reg_value = A_IO_READ32(smart_antenna_gpio + 0x3000);
					reg_value = (reg_value & ~0x1C);
					A_IO_WRITE32(smart_antenna_gpio + 0x3000, reg_value); /* gpio 47 5G Sdata */
				}
			}
		}
		iounmap(smart_antenna_gpio);
	}
}

void target_if_sa_api_enable_sa(struct wlan_objmgr_pdev *pdev, uint32_t enable,
				uint32_t mode, uint32_t rx_antenna)
{
	/* Send WMI COMMAND to Enable */
	struct smart_ant_enable_params param;
	int ret;
	struct wlan_objmgr_psoc *psoc;
	bool is_ar900b;
	uint32_t target_type;
	ol_ath_soc_softc_t *soc;
	ol_txrx_soc_handle soc_txrx_handle;
	struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(pdev);

	if (!scn) {
		sa_api_err("Failed to get scn!");
		return;
	}

	qdf_mem_zero(&param, sizeof(param));
	param.enable = enable & SMART_ANT_ENABLE_MASK;
	param.mode = mode;
	param.rx_antenna = rx_antenna;

	param.pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

	psoc = wlan_pdev_get_psoc(pdev);

	is_ar900b = lmac_is_target_ar900b(psoc);
	target_type = lmac_get_tgt_type(psoc);

	target_if_sa_api_set_gpio_param(pdev, enable, is_ar900b, target_type, &param);

	/* Enable txfeed back to receive TX Control and Status descriptors from target */
	ret = wmi_unified_smart_ant_enable_cmd_send(lmac_get_pdev_wmi_handle(pdev), &param);
	if (ret == 0) {
		if (is_ar900b || (target_type == TARGET_TYPE_QCA8074V2) ||
		    (target_type == TARGET_TYPE_QCA6018) ||
		    (target_type == TARGET_TYPE_QCN9000)) {
			soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

			if (enable) {
#ifdef QCA_SUPPORT_CP_STATS
				if (!pdev_cp_stats_ap_stats_tx_cal_enable_get(pdev)) {
					scn->sc_ic.ic_ath_enable_ap_stats(&scn->sc_ic, 1);
					pdev_cp_stats_ap_stats_tx_cal_enable_update(pdev, 1);
				}
#endif
				if (target_if_sa_api_is_tx_feedback_enabled(psoc, pdev) ||
				    target_if_sa_api_is_rx_feedback_enabled(psoc, pdev)) {
					ol_ath_subscribe_ppdu_desc_info(scn, PPDU_DESC_SMART_ANTENNA);
				}
			} else {
#ifdef QCA_SUPPORT_CP_STATS
				if (pdev_cp_stats_ap_stats_tx_cal_enable_get(pdev)) {
					scn->sc_ic.ic_ath_enable_ap_stats(&scn->sc_ic, 0);
					pdev_cp_stats_ap_stats_tx_cal_enable_update(pdev, 0);
				}
#endif
				ol_ath_unsubscribe_ppdu_desc_info(scn, PPDU_DESC_SMART_ANTENNA);
			}
		} else {
			soc = (ol_ath_soc_softc_t *)lmac_get_psoc_feature_ptr(psoc);
			if (enable) {
				if (target_if_sa_api_is_tx_feedback_enabled(psoc, pdev)) {
					if(soc && soc->ol_if_ops->smart_ant_enable_txfeedback)
						soc->ol_if_ops->smart_ant_enable_txfeedback(pdev, 1);
				}
			} else {
				if(soc && soc->ol_if_ops->smart_ant_enable_txfeedback)
					soc->ol_if_ops->smart_ant_enable_txfeedback(pdev, 0);
			}
		}
	} else {
		sa_api_err("SMART ANTENNA Enable Command failed!");
	}
}

void target_if_sa_set_training_info(struct wlan_objmgr_peer *peer,
					uint32_t *rate_array,
					uint32_t *antenna_array,
					uint32_t numpkts)
{
	struct smart_ant_training_info_params param;
	uint8_t *mac = NULL;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;

	qdf_mem_set(&param, sizeof(param), 0);

	mac = wlan_peer_get_macaddr(peer);
	vdev = wlan_peer_get_vdev(peer);

	param.vdev_id = wlan_vdev_get_id(vdev);
	pdev = wlan_vdev_get_pdev(vdev);


	param.numpkts = numpkts;
	param.rate_array = rate_array;
	param.antenna_array = antenna_array;

	wmi_unified_smart_ant_set_training_info_cmd_send(lmac_get_pdev_wmi_handle(pdev), mac,
			&param);
}

void target_if_sa_api_set_peer_config_ops(struct wlan_objmgr_peer *peer,
					uint32_t cmd_id, uint16_t args_count,
					u_int32_t args_arr[])
{
	struct smart_ant_node_config_params param;
	uint8_t *mac = NULL;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;

	qdf_mem_set(&param, sizeof(param), 0);

	mac = wlan_peer_get_macaddr(peer);
	vdev = wlan_peer_get_vdev(peer);

	param.vdev_id = wlan_vdev_get_id(vdev);
	pdev = wlan_vdev_get_pdev(vdev);

	param.cmd_id = cmd_id;
	param.args_count = args_count;
	param.args_arr = args_arr;

	wmi_unified_smart_ant_node_config_cmd_send(lmac_get_pdev_wmi_handle(pdev), mac, &param);
}

void target_if_sa_api_tx_ops_register(struct wlan_lmac_if_tx_ops *tx_ops)
{
	tx_ops->sa_api_tx_ops.sa_api_register_event_handler =
				target_if_sa_api_register_wmi_event_handler;
	tx_ops->sa_api_tx_ops.sa_api_unregister_event_handler =
				target_if_sa_api_unregister_wmi_event_handler;

	tx_ops->sa_api_tx_ops.sa_api_set_tx_antenna =
				target_if_sa_api_set_tx_antenna;
	tx_ops->sa_api_tx_ops.sa_api_set_rx_antenna =
				target_if_sa_api_set_rx_antenna;
	tx_ops->sa_api_tx_ops.sa_api_set_tx_default_antenna =
				target_if_sa_api_set_rx_antenna;

	tx_ops->sa_api_tx_ops.sa_api_enable_sa = target_if_sa_api_enable_sa;

	tx_ops->sa_api_tx_ops.sa_api_set_training_info =
				target_if_sa_set_training_info;
	tx_ops->sa_api_tx_ops.sa_api_set_node_config_ops =
				target_if_sa_api_set_peer_config_ops;
}

