
/*
 * Testing tool for EAPOL-Key Supplicant/Authenticator routines
 * Copyright (c) 2006-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "rsn_supp/wpa.h"
#include "ap/wpa_auth.h"

#define RX_PORT 9900
#define TX_PORT 9901
#define MAX_AUTH 8

struct wpa_1905 {
	u8 auth_addr[ETH_ALEN];
	u8 supp_addr[MAX_AUTH][ETH_ALEN];

	struct wpa_auth_callbacks auth_cb;
	struct wpa_authenticator *auth_group;
	struct wpa_state_machine *auth[MAX_AUTH];

	u8 supp_ie[80];
	size_t supp_ie_len;
	u8 psk[PMK_LEN];
	u8 pmkid[PMKID_LEN];

	int sta_count;
};

struct sec_config {
	u8 auth_addr[ETH_ALEN];
	u8 psk[PMK_LEN];
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int wpa_proto;
	int mgmt_group_cipher;
	int ieee80211w;
} STRUCT_PACKED;

struct assoc {
	u8 mac_addr[ETH_ALEN];
	size_t supp_ie_len;
	u8 supp_ie[80];
	u8 pmkid[PMKID_LEN];
} STRUCT_PACKED;

struct key_params {
	u8 mac_addr[ETH_ALEN];
	int idx;
	u8 key_data[32];
	size_t key_len;
} STRUCT_PACKED;

enum events {
	EVENT_AP_SEC_CONFIG,
	EVENT_STA_SEC_CONFIG,
	EVENT_1905_ASSOC,
	EVENT_DISASSOC,
	EVENT_1905_EAPOL,
	EVENT_SETKEY,
	EVENT_GROUP_KEY,
};

int eapol_1905_sock = -1;
int eapol_1905_sock_tx = -1;

static struct wpa_1905 wpa;
struct wpa_auth_config conf;

static void auth_logger(void *ctx, const u8 *addr, logger_level level,
			const char *txt)
{
	if (addr)
		wpa_printf(MSG_DEBUG, "AUTH: " MACSTR " - %s",
			   MAC2STR(addr), txt);
	else
		wpa_printf(MSG_DEBUG, "AUTH: %s", txt);
}

static const u8 *auth_get_psk(void *ctx, const u8 *addr,
			       const u8 *p2p_dev_addr, const u8 *prev_psk,
			       size_t *psk_len, int *vlan_id)
{
	struct wpa_1905 *wpa = ctx;

	wpa_printf(MSG_DEBUG, "AUTH: %s (addr=" MACSTR " prev_psk=%p)",
		   __func__, MAC2STR(addr), prev_psk);
	if (vlan_id)
		*vlan_id = 0;
	if (psk_len)
		*psk_len = PMK_LEN;
	if (prev_psk)
		return NULL;
	return wpa->psk;
}

static int auth_set_key(void *ctx, int vlan_id, enum wpa_alg alg,
			const u8 *addr, int idx, u8 *key,
			size_t key_len, enum key_flag key_flag)
{
	struct wpa_1905 *wpa = ctx;
	char send_buffer[64] = {0} ;
	struct key_params key_param;
	os_memset(&key_param, 0, sizeof(key_param));

	wpa_printf(MSG_DEBUG, "AUTH: %s (vlan_id=%d alg=%d idx=%d key_len=%d)",
		   __func__, vlan_id, alg, idx, (int) key_len);
	if (addr)
		wpa_printf(MSG_DEBUG, "AUTH: addr=" MACSTR, MAC2STR(addr));

	if (!key_len || !addr)
		return 0;

	os_memcpy(key_param.mac_addr, addr, ETH_ALEN);
	key_param.idx =  idx;
	os_memcpy(key_param.key_data, key, key_len);
	key_param.key_len = key_len;

	os_memset(send_buffer, 0, 64);
	send_buffer[0] = EVENT_SETKEY;
	WPA_PUT_BE16(send_buffer+1, sizeof(key_param));
	os_memcpy(send_buffer+3, &key_param, sizeof(key_param));

	wpa_hexdump(MSG_ERROR, "SUPP: set_key - key", key, key_len);

	send(eapol_1905_sock_tx, send_buffer, 64, 0);

	if (!is_broadcast_ether_addr(addr)) {
		int i = 0;
		for (i = 0; i < wpa->sta_count; ) {
			if (wpa->auth[i]) {
				wpa_printf(MSG_DEBUG, "AUTH: i=%d addr= " MACSTR, i, MAC2STR(addr));
				if (!os_memcmp(wpa->supp_addr[i], addr, ETH_ALEN)) {
					wpa_auth_sta_deinit(wpa->auth[i]);
					wpa->sta_count--;
					break;
				}
				i++;
			}
		}
	}
	return 0;
}

static int wpa_1905_send_eapol(void *ctx, const u8 *addr, const u8 *data,
			   size_t data_len, int encrypt)
{
	struct wpa_1905 *wpa = ctx;
	u8 send_buffer[1024] = {0} ;
	os_memset(send_buffer, 0, 1024);
	send_buffer[0] = EVENT_1905_EAPOL;
	WPA_PUT_BE16(send_buffer + 1 , data_len + ETH_ALEN);

	wpa_printf(MSG_DEBUG, "AUTH: TX EAPOL addr=" MACSTR,
		   MAC2STR(addr));
	os_memcpy(send_buffer+3, addr, ETH_ALEN);
	os_memcpy(send_buffer+9, data, data_len);
	send(eapol_1905_sock_tx, send_buffer, 1024, 0);
	return 0;
}


static int assoc_init(struct wpa_1905 *wpa)
{
	int i = wpa->sta_count ;
	wpa->auth[i] = wpa_auth_sta_init(wpa->auth_group,
					 wpa->supp_addr[i], NULL);
	if (!wpa->auth[i]) {
		wpa_printf(MSG_DEBUG, "AUTH: wpa_auth_sta_init() failed");
		return -1;
	}

	if (wpa_auth_pmksa_add2(wpa->auth_group, wpa->supp_addr[i], wpa->psk,
				PMK_LEN, wpa->pmkid, 0,
				conf.wpa_key_mgmt) < 0) {
		wpa_printf(MSG_ERROR, "DPP: Failed to add PMKSA cache entry");
		return -1;
	}

	if (wpa_validate_wpa_ie(wpa->auth_group, wpa->auth[i], 2412,
				wpa->supp_ie, wpa->supp_ie_len, NULL, 0,
				NULL, 0, NULL, 0) != WPA_IE_OK) {
		wpa_printf(MSG_DEBUG, "AUTH: wpa_validate_wpa_ie() failed");
		wpa_auth_sta_deinit(wpa->auth[i]);
		wpa->sta_count--;
		return -1;
	}

	wpa_auth_sm_event(wpa->auth[i], WPA_ASSOC);

	wpa_auth_sta_associated(wpa->auth_group, wpa->auth[i]);

	return 0;
}

static int ap_init(struct wpa_1905 *wpa, struct sec_config *sec_conf)
{

	wpa_printf(MSG_DEBUG, "AUTH: Initializing group state machine");

	os_memcpy(wpa->auth_addr, sec_conf->auth_addr, ETH_ALEN);
	os_memcpy(wpa->psk, sec_conf->psk, PMK_LEN);

	os_memset(&conf, 0, sizeof(conf));
	conf.wpa = sec_conf->wpa_proto;
	conf.wpa_key_mgmt = sec_conf->key_mgmt;
	conf.wpa_pairwise = sec_conf->pairwise_cipher;
	conf.rsn_pairwise = sec_conf->pairwise_cipher;
	conf.wpa_group = sec_conf->group_cipher;
	conf.ieee80211w = sec_conf->ieee80211w;
	conf.group_mgmt_cipher = sec_conf->mgmt_group_cipher;
	conf.no_group_delay = 1;

	conf.eapol_version = 2;
	conf.wpa_group_update_count = 4;
	conf.wpa_pairwise_update_count = 4;

	wpa->auth_cb.logger = auth_logger;
	wpa->auth_cb.send_eapol = wpa_1905_send_eapol;
	wpa->auth_cb.get_psk = auth_get_psk;
	wpa->auth_cb.set_key = auth_set_key,


	wpa->auth_group = wpa_init(wpa->auth_addr, &conf, &wpa->auth_cb, wpa);


	wpa->sta_count = 0;
	if (!wpa->auth_group) {
		wpa_printf(MSG_DEBUG, "AUTH: wpa_init() failed");
		return -1;
	}

	return 0;
}

static void eapol_1905_rx_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	u8 buf[4096];
	int res;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	const int reply_size = 4096;
	int reply_len;
	int level = MSG_DEBUG;
	struct wpa_1905 *wpa = eloop_ctx;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
		       (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(ctrl_iface): %s",
			   strerror(errno));
		return;
	}

	buf[res] = '\0';

	wpa_printf(MSG_ERROR, "Event:%d", buf[0]);

	if (buf[0] == EVENT_1905_ASSOC) {
		struct assoc *new_assoc = (struct assoc *) &buf[1];

		if (wpa->sta_count < MAX_AUTH) {
			os_memcpy(wpa->supp_addr[wpa->sta_count],
				  new_assoc->mac_addr, ETH_ALEN);
			wpa->supp_ie_len = new_assoc->supp_ie_len;
			os_memcpy(wpa->supp_ie,
				  new_assoc->supp_ie, wpa->supp_ie_len);
			os_memcpy(wpa->pmkid, new_assoc->pmkid, PMKID_LEN);

			if (!assoc_init(wpa))
				wpa->sta_count++;
		} else {
			wpa_printf(MSG_ERROR, "STA Assoc max count reached");
		}
	} else if (buf[0] == EVENT_1905_EAPOL) {
		int i = 0;
/* Compare with src addr */

		for (i = 0; i < wpa->sta_count; i++) {
			if (!os_memcmp(wpa->supp_addr[i], buf + 3,  ETH_ALEN))
				break;
		}
		wpa_printf(MSG_DEBUG, "AUTH: RX EAPOL from i=%d addr=" MACSTR,
			   i, MAC2STR(wpa->supp_addr[i]));

		if (i == wpa->sta_count)
			return ;

		wpa_receive(wpa->auth_group, wpa->auth[i], buf + 9,
			    WPA_GET_BE16(&buf[1]) - ETH_ALEN);
	} else if (buf[0] == EVENT_AP_SEC_CONFIG) {
		int i = 0;
		if (wpa->sta_count > 0) {
			for (i = 0; i < wpa->sta_count; ) {
				if (wpa->auth[i]) {
					wpa_auth_sta_deinit(wpa->auth[i]);
					i++;
				}
			}
			wpa->sta_count = 0;
		}
		if (wpa->auth_group)
			wpa_deinit(wpa->auth_group);

		ap_init(wpa, (struct sec_config *) &buf[1]);
	} else if (buf[0] == EVENT_GROUP_KEY) {
		if (wpa->auth_group)
			wpa_auth_reconfig_group_keys(wpa->auth_group);
	}

}

int eapol_1905_init()
{
	struct sockaddr_in address;

	eapol_1905_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (eapol_1905_sock < 0) {
		wpa_printf(MSG_ERROR, "nl80211: socket(PF_PACKET, SOCK_DGRAM, 1905 ETH_P_PAE) failed: %s",
			   strerror(errno));
		return -1 ;
	}

	memset((char *)&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl((127 << 24) | 1);
	address.sin_port = htons(RX_PORT);

	if (bind(eapol_1905_sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
		wpa_printf(MSG_ERROR, "nl80211: socket(PF_PACKET, SOCK_DGRAM, 1905 ETH_P_PAE) failed: %s",
			   strerror(errno));
		close(eapol_1905_sock);
		return -1;
	}

	eapol_1905_sock_tx = socket(AF_INET, SOCK_DGRAM, 0);
	if (eapol_1905_sock_tx < 0) {
		wpa_printf(MSG_ERROR, "nl80211: socket(PF_PACKET, SOCK_DGRAM, 1905 ETH_P_PAE) failed: %s",
			   strerror(errno));
		return -1 ;
	}
	address.sin_port = htons(TX_PORT);

	if (connect(eapol_1905_sock_tx, (struct sockaddr *)&address, sizeof(address)) < 0) {
		wpa_printf(MSG_ERROR, " connect failed :%s ", strerror(errno));
		close(eapol_1905_sock_tx);
		return -1;
	}

	os_memset(&wpa, 0, sizeof(wpa));
	if (eloop_register_read_sock(eapol_1905_sock, eapol_1905_rx_receive, &wpa, NULL)) {
		close(eapol_1905_sock);
		wpa_printf(MSG_INFO, "nl80211: Could not register read socket for 1905 eapol");
		return -1;
	}

	return 0;
}

void eapol_1905_deinit(void *priv)
{
	int i = 0;
	wpa_printf(MSG_DEBUG, "EAPOL 1905_deinit");

	if (eapol_1905_sock_tx > 0) {
		close(eapol_1905_sock_tx);
		eapol_1905_sock_tx = -1;
	}

	if (eapol_1905_sock > -1) {
		eloop_unregister_read_sock(eapol_1905_sock);
		close(eapol_1905_sock);
		eapol_1905_sock = -1;
	}

	if (wpa.sta_count > 0) {
		for (i = 0; i < wpa.sta_count; ) {
			if (wpa.auth[i]) {
				wpa_auth_sta_deinit(wpa.auth[i]);
				i++;
			}
		}
		wpa.sta_count = 0;
	}

	if (wpa.auth_group)
		wpa_deinit(wpa.auth_group);
	return;

}

