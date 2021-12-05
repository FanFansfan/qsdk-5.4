/*
 * Copyright (c) 2017, 2019 Qualcomm Innovation Center, Inc..
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include <../../core/sa_api_defs.h>
#include <wlan_sa_api_utils_api.h>
#include <qdf_module.h>
#include "../../core/sa_api_cmn_api.h"

/* Do sa_api Mode Configuration */
uint32_t sa_api_mode;
qdf_declare_param(sa_api_mode, uint);
qdf_export_symbol(sa_api_mode);

int sa_api_init(struct wlan_objmgr_pdev *pdev,
		struct wlan_objmgr_vdev *vdev,
		struct pdev_sa_api *pa, int new_init)
{
	struct sa_config sa_init_config;
	uint32_t rx_antenna;
	uint32_t antenna_array[SMART_ANTENNA_MAX_RATE_SERIES];
	int i = 0;
	uint8_t tx_chainmask = 0, rx_chainmask = 0;
	int ret = 0;
	uint32_t enable;
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_psoc *psoc;
	enum QDF_OPMODE opmode;
	struct sa_api_context *sc;

	if (g_sa_ops == NULL) {
		qdf_nofl_err("Smart Antenna functions are not registered !!! ");
		return QDF_STATUS_E_FAILURE;
	}

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		sa_api_err("psoc null !!! \n");
		return QDF_STATUS_E_FAILURE;
	}

	sc = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_SA_API);
	if (!sc || !sc->enable) {
		sa_api_err("SA is disabled!!! \n");
		return QDF_STATUS_E_FAILURE;
	}

	/*
	 * handling Multile VAP cases
	 */
	if (new_init & SMART_ANT_NEW_CONFIGURATION) {
		if (!(pa->state & SMART_ANT_STATE_INIT_DONE)) {
			qdf_atomic_inc(&g_sa_init);
		} else {
			return SMART_ANT_STATUS_SUCCESS;
		}
		pa->interface_id = tgt_get_if_id(psoc, pdev);
	}

	opmode = wlan_vdev_mlme_get_opmode(vdev);

	sa_api_info("opmode %d newinit %x", opmode, new_init);
	if ((QDF_SAP_MODE == opmode) || (QDF_STA_MODE == opmode)) {
		/* TODO: What abt repeater case, need to check calling place for repeater*/
		if (g_sa_ops->sa_init) {
			sa_init_config.radio_id = (pa->interface_id << SMART_ANT_INTERFACE_ID_SHIFT) | pa->radio_id;
			sa_init_config.max_fallback_rates = pa->max_fallback_rates;
			tx_chainmask = wlan_vdev_mlme_get_txchainmask(vdev);
			rx_chainmask = wlan_vdev_mlme_get_rxchainmask(vdev);
			sa_init_config.nss =  wlan_vdev_mlme_get_nss(vdev);
			sa_init_config.txrx_chainmask = (tx_chainmask | (rx_chainmask << 4));

			if (QDF_SAP_MODE == opmode) {
				sa_init_config.bss_mode = SMART_ANT_BSS_MODE_AP;
			} else {
				sa_init_config.bss_mode = SMART_ANT_BSS_MODE_STA;
			}

			if (new_init & SMART_ANT_STA_NOT_CONNECTED) {
				new_init &= ~SMART_ANT_STA_NOT_CONNECTED;
				/* Set Channel number to 0 ("zero") to request default params from SA module
				 * to help scanning while station is not connected.
				 * Helpful only in IEEE80211_M_STA mode.
				 */
				sa_init_config.channel_num = 0;
				sa_init_config.band = SA_BAND_UNSPECIFIED;
			} else {
				sa_init_config.channel_num = wlan_reg_freq_to_chan(pdev, wlan_vdev_get_chan_freq(vdev));
				sa_init_config.band = reg_wifi_band_to_sa_band_id(wlan_reg_freq_to_band(wlan_vdev_get_chan_freq(vdev)));
			}
			/* Assume smart antenna module requires both Tx and Rx feedback for now.
			 * smart antenna module can set these values to zero (0) if he doesn't
			 * need any of Tx feedback or Rx feedback or both.
			 */
			sa_init_config.txrx_feedback = SMART_ANT_TX_FEEDBACK_MASK | SMART_ANT_RX_FEEDBACK_MASK;
			ret = g_sa_ops->sa_init(&sa_init_config, new_init);
			ASSERT(ret < 0);  /* -ve value: init error */
			/* Bit 0 in ret is mode. all other bits are discarded. */
			pa->mode = ret & SMART_ANT_MODE;

			sa_api_get_rxantenna(pa, &rx_antenna);
			/*
			 * Create bitmap of smart antenna enabled and Tx/Rx feedback subscription
			 * state. bit 0 represents smart antenna enabled/disabled, bit 4 represents
			 * Tx subscription state and bit 5 represents Rx subscription state.
			 */
			enable = SMART_ANT_ENABLE_MASK | (sa_init_config.txrx_feedback &
					(SMART_ANT_TX_FEEDBACK_MASK | SMART_ANT_RX_FEEDBACK_MASK));
			pa->enable = enable; /*save smart antenna enable bitmap */
			/* Enable smart antenna for First new init */
			if (new_init & SMART_ANT_NEW_CONFIGURATION) {
				/* Enable smart antenna , params@ ic, enable, mode, RX antenna */
				tgt_sa_api_start_sa(psoc, pa->pdev_obj, enable, pa->mode, rx_antenna);
				pa->state |= SMART_ANT_STATE_INIT_DONE;
				pa->state &= ~(SMART_ANT_STATE_DEINIT_DONE); /* clear de init */
			} else {
				tgt_sa_api_set_rx_antenna(psoc, pdev, rx_antenna);
			}

			for (i = 0; i <= pa->max_fallback_rates; i++) {
				antenna_array[i] = rx_antenna;
			}

			/* set TX antenna to default antennas to BSS node */
			peer = wlan_vdev_get_bsspeer(vdev);
			if (!peer) {
				sa_api_err("Invalid BSS peer\n");
				return SMART_ANT_STATUS_FAILURE;
			}
			tgt_sa_api_set_tx_antenna(psoc, peer, &antenna_array[0]);
		}
	}
	return SMART_ANT_STATUS_SUCCESS;
}

int sa_api_deinit(struct wlan_objmgr_pdev *pdev,
		  struct wlan_objmgr_vdev *vdev,
		  struct pdev_sa_api *pa,
		  int notify)
{
	struct wlan_objmgr_psoc *psoc;
	struct sa_api_context *sc;

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		sa_api_err("psoc null !!! \n");
		return QDF_STATUS_E_FAILURE;
	}
	sc = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_SA_API);
	if (!sc) {
		sa_api_err("SA context null !!! \n");
		return QDF_STATUS_E_FAILURE;
	}

	if (SMART_ANTENNA_ENABLED(pa)) {
		if (pa->state & SMART_ANT_STATE_DEINIT_DONE) {
			sa_api_err("Deinit is already done !!! \n");
			return 0;
		}
		if (notify) {
			if (g_sa_ops && g_sa_ops->sa_deinit) {
				qdf_atomic_dec(&g_sa_init);
				g_sa_ops->sa_deinit(pa->interface_id);
			}
			if (sc->enable)
				tgt_sa_api_start_sa(psoc, pa->pdev_obj, 0, pa->mode, 0);
			pa->enable = 0;
			pa->state |= SMART_ANT_STATE_DEINIT_DONE;
			pa->state &= ~(SMART_ANT_STATE_INIT_DONE); /* clear init */
		}
	}
	return SMART_ANT_STATUS_FAILURE;
}

QDF_STATUS wlan_sa_api_init(void)
{
	sa_api_debug("+");

	if (wlan_objmgr_register_psoc_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_psoc_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering psoc create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_register_psoc_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_psoc_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering psoc destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_register_pdev_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_pdev_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering pdev create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_register_pdev_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_pdev_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering pdev destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_register_peer_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_peer_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering peer create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_register_peer_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_peer_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("registering peer destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	sa_api_debug("-");
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_sa_api_deinit(void)
{
	sa_api_debug("+");
	if (wlan_objmgr_unregister_psoc_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_psoc_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering psoc create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_unregister_psoc_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_psoc_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering psoc destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_unregister_pdev_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_pdev_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering pdev create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_unregister_pdev_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_pdev_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering pdev destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_unregister_peer_create_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_peer_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering peer create handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_unregister_peer_destroy_handler(WLAN_UMAC_COMP_SA_API,
				wlan_sa_api_peer_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		sa_api_err("deregistering peer destroy handler failed\n");
		return QDF_STATUS_E_FAILURE;
	}

	sa_api_debug("-");
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_sa_api_enable(struct wlan_objmgr_psoc *psoc)
{
	struct sa_api_context *sc = NULL;

	sa_api_debug("+");
	if (NULL == psoc) {
		sa_api_err("PSOC is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	sc = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_SA_API);
	if (NULL == sc) {
		sa_api_err("sa_api_context is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (sc->sa_api_enable)
		sc->sa_api_enable(psoc);

	sa_api_debug("-");
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_sa_api_disable(struct wlan_objmgr_psoc *psoc)
{
	struct sa_api_context *sc = NULL;

	sa_api_debug("+");
	if (NULL == psoc) {
		sa_api_err("PSOC is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	sc = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_SA_API);
	if (NULL == sc) {
		sa_api_err("sa_api_context is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	if (sc->sa_api_disable)
		sc->sa_api_disable(psoc);

	sa_api_debug("-");
	return QDF_STATUS_SUCCESS;
}

int wlan_sa_api_cwm_action(struct wlan_objmgr_pdev  *pdev)
{
	sa_api_debug("#");
	return sa_api_cwm_action(pdev);
}

int wlan_sa_api_get_bcn_txantenna(struct wlan_objmgr_pdev *pdev, uint32_t *ant)
{
	sa_api_debug("#");
	return sa_api_get_bcn_txantenna(pdev, ant);
}

void wlan_sa_api_channel_change(struct wlan_objmgr_pdev *pdev)
{
	sa_api_debug("#");
	sa_api_channel_change(pdev);
}

void wlan_sa_api_peer_disconnect(struct wlan_objmgr_peer *peer)
{
	sa_api_debug("#");
	sa_api_peer_disconnect(peer);
}

void wlan_sa_api_peer_connect(struct wlan_objmgr_pdev *pdev, struct wlan_objmgr_peer *peer, struct sa_rate_cap *rate_cap)
{
	sa_api_debug("#");
	sa_api_peer_connect(pdev, peer, rate_cap);
}

int wlan_sa_api_start(struct wlan_objmgr_pdev *pdev, struct wlan_objmgr_vdev *vdev, int new_init)
{
	struct pdev_sa_api *pa;

	sa_api_debug("#");
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_SA_API);
	if (pa == NULL) {
		sa_api_err("pa is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	return sa_api_init(pdev, vdev, pa, new_init);
}

int wlan_sa_api_stop(struct wlan_objmgr_pdev *pdev, struct wlan_objmgr_vdev *vdev, int notify)
{
	struct pdev_sa_api *pa;

	sa_api_debug("#");
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_SA_API);
	if (pa == NULL) {
		sa_api_err("pa is null!\n");
		return QDF_STATUS_E_FAILURE;
	}

	return sa_api_deinit(pdev, vdev, pa, notify);
}
