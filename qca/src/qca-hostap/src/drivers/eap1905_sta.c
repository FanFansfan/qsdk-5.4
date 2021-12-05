
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
#include "rsn_supp/pmksa_cache.h"

#define RX_PORT 9902
#define TX_PORT 9903

struct wpa_1905 {
	int no_callback;
	u8 auth_addr[ETH_ALEN];
	u8 sta_supp_addr[ETH_ALEN];
	struct wpa_sm *supp;
	struct wpa_sm_ctx *ctx;

	u8 supp_ie[80];
	size_t supp_ie_len;
	u8 psk[PMK_LEN];
	u8 pmkid[PMKID_LEN];

};

struct sta_sec_config {
	u8 auth_addr[ETH_ALEN];
	u8 supp_addr[ETH_ALEN];
	u8 psk[PMK_LEN];
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int wpa_proto;
	int mgmt_group_cipher;
	int ieee80211w;
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
};

int eapol_1905_sock = -1;
int eapol_1905_sock_tx = -1;
static struct wpa_1905 wpa;

static int  supp_get_beacon_ie(void *ctx)
{
	struct wpa_1905 *wpa = ctx;
	const u8 *ie;

/* Beacon rsn IE must come from MAP */

	static const u8 rsne[] = {
		0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x0a,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x0a, 0x01, 0x00,
		0x50, 0x6f, 0x9a, 0x02, 0x00, 0x00
	};

	wpa_printf(MSG_ERROR, "SUPP: %s", __func__);

	ie = rsne;
	if (ie[0] == WLAN_EID_RSN)
		return wpa_sm_set_ap_rsn_ie(wpa->supp, ie, 2 + ie[1]);
	return wpa_sm_set_ap_wpa_ie(wpa->supp, ie, 2 + ie[1]);
}

static int supp_get_bssid(void *ctx, u8 *bssid)
{
	struct wpa_1905 *wpa = ctx;
	wpa_printf(MSG_ERROR, "SUPP: %s", __func__);
	os_memcpy(bssid, wpa->auth_addr, ETH_ALEN);
	return 0;
}

static void supp_set_state(void *ctx, enum wpa_states state)
{
	wpa_printf(MSG_ERROR, "SUPP: %s(state=%d)", __func__, state);
}

static int supp_ether_send(void *ctx, const u8 *dest, u16 proto, const u8 *buf,
			   size_t len)
{
	struct wpa_1905 *wpa = ctx;
	int i;

	u8 send_buffer[1024] = {0} ;
	send_buffer[0] = EVENT_1905_EAPOL;
	wpa_printf(MSG_DEBUG, "TX EPAOL : data_len:%lu ", (long unsigned int)len);

	wpa_printf(MSG_DEBUG, "AUTH: TX EAPOL dest addr=" MACSTR,
		   MAC2STR(dest));

	WPA_PUT_BE16(send_buffer + 1, len + ETH_ALEN);
	os_memcpy(send_buffer+3, wpa->sta_supp_addr, ETH_ALEN);
	os_memcpy(send_buffer+9, buf, len);

	send(eapol_1905_sock_tx, send_buffer , 1024 , 0);
	wpa_printf(MSG_ERROR, "SUPP: %s(dest=" MACSTR " proto=0x%04x len=%lu)",
		   __func__, MAC2STR(dest), proto, (unsigned long) len);
	/* Key info */
	if (WPA_GET_BE16(buf+sizeof(struct ieee802_1x_hdr)+1) & WPA_KEY_INFO_INSTALL)
		return 0;

	return 0;
}

static u8 * supp_alloc_eapol(void *ctx, u8 type, const void *data,
			     u16 data_len, size_t *msg_len, void **data_pos)
{
	struct ieee802_1x_hdr *hdr;
	wpa_printf(MSG_ERROR, "SUPP: %s(type=%d data_len=%d)",
		   __func__, type, data_len);

	*msg_len = sizeof(*hdr) + data_len;
	hdr = os_malloc(*msg_len);
	if (hdr == NULL)
		return NULL;

	hdr->version = 2;
	hdr->type = type;
	hdr->length = host_to_be16(data_len);

	if (data)
		os_memcpy(hdr + 1, data, data_len);
	else
		os_memset(hdr + 1, 0, data_len);

	if (data_pos)
		*data_pos = hdr + 1;

	return (u8 *) hdr;
}


static int supp_set_key(void *ctx, enum wpa_alg alg,
			const u8 *addr, int key_idx, int set_tx,
			const u8 *seq, size_t seq_len,
			const u8 *key, size_t key_len,  enum key_flag key_flag)
{
	char send_buffer[64] = {0} ;
	struct key_params key_param;
	os_memset(&key_param, 0, sizeof(key_param));

	if (!addr) {
		wpa_printf(MSG_ERROR, "SUPP: addr is NULL");
		return 0;
	}

	wpa_printf(MSG_ERROR, "SUPP: %s(alg=%d addr=" MACSTR " key_idx=%d set_tx=%d)",
			   __func__, alg, MAC2STR(addr), key_idx, set_tx);
	wpa_hexdump(MSG_ERROR, "SUPP: set_key - seq", seq, seq_len);
	wpa_hexdump(MSG_ERROR, "SUPP: set_key - key", key, key_len);

	if (!key_len)
		return 0;

	os_memcpy(key_param.mac_addr, addr, ETH_ALEN);
	key_param.idx =  key_idx;
	os_memcpy(key_param.key_data, key, key_len);
	key_param.key_len = key_len;

	os_memset(send_buffer, 0, 64);
	send_buffer[0] = EVENT_SETKEY;
	WPA_PUT_BE16(send_buffer+1, sizeof(key_param));
	os_memcpy(send_buffer+3, &key_param, sizeof(key_param));

	wpa_hexdump(MSG_ERROR, "SUPP: set_key - key", key, key_len);

	send(eapol_1905_sock_tx, send_buffer, 64, 0);

	return 0;
}


static int supp_mlme_setprotection(void *ctx, const u8 *addr,
				   int protection_type, int key_type)
{
	wpa_printf(MSG_ERROR, "SUPP: %s(addr=" MACSTR " protection_type=%d "
		   "key_type=%d)",
		   __func__, MAC2STR(addr), protection_type, key_type);

	if (protection_type == 3) {
		wpa_sm_notify_assoc(wpa.supp, wpa.auth_addr);
		wpa_printf(MSG_ERROR, "SUPP: Reinit assoc ");
	}
	return 0;
}


static void supp_cancel_auth_timeout(void *ctx)
{
	wpa_printf(MSG_ERROR, "SUPP: %s", __func__);
}


static void * supp_get_network_ctx(void *ctx)
{
	return (void *) 1;
}


static void supp_deauthenticate(void *ctx, u16 reason_code)
{
	wpa_printf(MSG_ERROR, "SUPP: %s(%d)", __func__, reason_code);
}

static enum wpa_states supp_get_state(void *ctx)
{
	return WPA_COMPLETED;
}

static int supp_add_pmkid(void *wpa_s, void *network_ctx,
			  const u8 *bssid, const u8 *pmkid,
			  const u8 *fils_cache_id,
			  const u8 *pmk, size_t pmk_len,
			  u32 pmk_lifetime, u8 pmk_reauth_threshold,
			  int akmp)

{
	wpa_printf(MSG_ERROR, "SUPP: Add PMKID ");
	return 0;
}

static int supp_remove_pmkid(void *_wpa_s, void *network_ctx,
				       const u8 *bssid, const u8 *pmkid,
				       const u8 *fils_cache_id)
{
	wpa_printf(MSG_ERROR, "SUPP: remove PMKID ");
	return 0;
}

void wpa_sm_inits(struct wpa_sm_ctx *ctx)
{
	printf("%p\n", ctx->set_rekey_offload);
}

void supp_rekey_offload(void *ctx, const u8 *kek, size_t kek_len,
			const u8 *kck, size_t kck_len,
			const u8 *replay_ctr)
{
	printf("**************\n");
	return;
}

static int sta_init(struct wpa_1905 *wpa, struct sta_sec_config *sec_conf)
{

	wpa->ctx = os_zalloc(sizeof(struct wpa_sm_ctx));

	if (!wpa->ctx) {
		wpa_printf(MSG_ERROR, "SUPP: malloc failed at sta_init");
		return -1;
	}

	wpa->ctx->ctx = wpa;
	wpa->ctx->msg_ctx = wpa;
	wpa->ctx->set_state = supp_set_state;
	wpa->ctx->get_bssid = supp_get_bssid;
	wpa->ctx->ether_send = supp_ether_send;
	wpa->ctx->get_beacon_ie = supp_get_beacon_ie;
	wpa->ctx->alloc_eapol = supp_alloc_eapol;
	wpa->ctx->set_key = supp_set_key;
	wpa->ctx->mlme_setprotection = supp_mlme_setprotection;
	wpa->ctx->cancel_auth_timeout = supp_cancel_auth_timeout;
	wpa->ctx->get_network_ctx = supp_get_network_ctx;
	wpa->ctx->deauthenticate = supp_deauthenticate;
	wpa->ctx->get_state = supp_get_state;
	wpa->ctx->set_rekey_offload = NULL;
	wpa->ctx->add_pmkid = supp_add_pmkid;
	wpa->ctx->remove_pmkid = supp_remove_pmkid;

	wpa->no_callback = 1 ;

	os_memcpy(wpa->auth_addr, sec_conf->auth_addr, ETH_ALEN);
	os_memcpy(wpa->sta_supp_addr, sec_conf->supp_addr, ETH_ALEN);
	os_memcpy(wpa->psk, sec_conf->psk, PMK_LEN);
	os_memcpy(wpa->pmkid, sec_conf->pmkid, PMKID_LEN);
	os_memcpy(wpa->supp_ie, sec_conf->supp_ie, sec_conf->supp_ie_len);
	wpa->supp_ie_len = sec_conf->supp_ie_len ;

	wpa->supp = wpa_sm_init(wpa->ctx);

	wpa_sm_set_pmk(wpa->supp, wpa->psk, PMK_LEN, NULL, NULL);

	if (!wpa->supp) {
		wpa_printf(MSG_ERROR, "SUPP: wpa_sm_init() failed");
		return -1;
	}

	wpa_sm_set_own_addr(wpa->supp, wpa->sta_supp_addr);
	{
		wpa_sm_set_param(wpa->supp, WPA_PARAM_RSN_ENABLED, 1);
		wpa_sm_set_param(wpa->supp, WPA_PARAM_PROTO, sec_conf->wpa_proto);
		wpa_sm_set_param(wpa->supp, WPA_PARAM_PAIRWISE,
				 sec_conf->pairwise_cipher);
		wpa_sm_set_param(wpa->supp, WPA_PARAM_GROUP, sec_conf->group_cipher);
		wpa_sm_set_param(wpa->supp, WPA_PARAM_KEY_MGMT,
				 sec_conf->key_mgmt);
		wpa_sm_set_param(wpa->supp, WPA_PARAM_MFP,
				 sec_conf->ieee80211w);
	}

	wpa_sm_pmksa_cache_add(wpa->supp, wpa->psk, PMK_LEN,  wpa->pmkid, wpa->auth_addr, NULL);

	if (wpa_sm_set_assoc_wpa_ie_default(wpa->supp, wpa->supp_ie,
					    &wpa->supp_ie_len) < 0) {
		wpa_printf(MSG_ERROR, "SUPP: wpa_sm_set_assoc_wpa_ie_default()"
			   " failed");
		return -1;
	}

	wpa_sm_notify_assoc(wpa->supp, wpa->auth_addr);

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

	wpa_printf(MSG_ERROR, "eapol_1905_rx_receive called ..");

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			(struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(ctrl_iface): %s",
			   strerror(errno));
		return;
	}
	buf[res] = '\0';

	wpa_printf(MSG_ERROR, "Event:%d ", buf[0]);

/* The first byte is type of info EAPOL / ASSOC. second byte is len of EAPOL or assoc info */

	if (buf[0] == EVENT_1905_EAPOL) {
		size_t len = 0;
		char *msg;

		if (!os_memcmp(wpa->sta_supp_addr, buf+9,  ETH_ALEN))
			wpa_printf(MSG_ERROR, "eapol_len:%d ", WPA_GET_BE16(&buf[1])-ETH_ALEN);

		wpa_printf(MSG_ERROR, "eapol_len:%d ", WPA_GET_BE16(&buf[1]) - ETH_ALEN);

		if (WPA_GET_BE16(&buf[1]) > ETH_ALEN)
			len = WPA_GET_BE16(&buf[1]) - ETH_ALEN ;
		else {
			wpa_printf(MSG_ERROR, "nl80211: eapol packet len is insufficent ");
			return;
		}

		if ( len && ((len + ETH_ALEN + 3) <= res)) {
			msg = os_malloc(len);
			if (msg) {
				os_memcpy(msg, buf+9, len);
				wpa_sm_rx_eapol(wpa->supp, wpa->auth_addr, (u8 *) msg, len);
				wpa_printf(MSG_ERROR, "wpa_sm_rx_eapol done ");
				os_free(msg);
			}
		}

	} else if (buf[0] == EVENT_STA_SEC_CONFIG) {
		if (wpa->supp)
			wpa_sm_deinit(wpa->supp);
		sta_init(wpa, (struct sta_sec_config *) &buf[1]);
	} else if (buf[0] == EVENT_1905_ASSOC) {
		if (wpa->supp)
			wpa_sm_notify_assoc(wpa->supp, wpa->auth_addr);
	}

}




int eapol_1905_init()
{
	struct sockaddr_in address;

	wpa_printf(MSG_INFO, "nl80211: eapol_1905_init");

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

	wpa_printf(MSG_INFO, "nl80211: eapol_1905_init done");
	return 0;
}

void eapol_1905_deinit(void *priv)
{
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
	wpa_sm_deinit(wpa.supp);
	return;
}

