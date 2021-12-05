/*
 * Copyright (c) 2016,2017,2020-2021 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#if UMAC_SUPPORT_CFG80211
#ifndef IEEE80211_CRYPTO_NL80211_H
#define IEEE80211_CRYPTO_NL80211_H
#define TKIP_RXMIC_OFFSET 24;
#define TKIP_TXMIC_OFFSET 16;

#define ELEM_LEN(x)                     ( x[1] )
#define IE_LEN(x)                       ( ELEM_LEN(x) + 2 )
#define MAX_SEQ_LEN                     sizeof(u_int64_t)


/* AKM suite selectors */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 24)
#define WLAN_AKM_SUITE_8021X            0x000FAC01
#define WLAN_AKM_SUITE_PSK              0x000FAC02
#define WLAN_AKM_SUITE_FT_8021X         0x000FAC03
#define WLAN_AKM_SUITE_FT_PSK           0x000FAC04
#define WLAN_AKM_SUITE_8021X_SHA256     0x000FAC05
#define WLAN_AKM_SUITE_PSK_SHA256       0x000FAC06
#define WLAN_AKM_SUITE_TPK_HANDSHAKE    0x000FAC07
#define WLAN_AKM_SUITE_SAE              0x000FAC08
#define WLAN_AKM_SUITE_FT_OVER_SAE      0x000FAC09
#define WLAN_AKM_SUITE_8021X_SUITE_B    0x000FAC0B
#define WLAN_AKM_SUITE_8021X_SUITE_B_192        0x000FAC0C
#define WLAN_AKM_SUITE_FILS_SHA256      0x000FAC0E
#define WLAN_AKM_SUITE_FILS_SHA384      0x000FAC0F
#define WLAN_AKM_SUITE_FT_FILS_SHA256   0x000FAC10
#define WLAN_AKM_SUITE_FT_FILS_SHA384   0x000FAC11
#endif

#define WLAN_AKM_SUITE_OWE              0x000FAC12
#define WLAN_AKM_SUITE_CCKM             0x00409600
#define WLAN_AKM_SUITE_OSEN             0x506F9A01
#define WLAN_AKM_WAPI_PSK               0x01721400
#define WLAN_AKM_SUITE_DPP              0x506F9A02

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 24)
/* cipher suite selectors */
#define WLAN_CIPHER_SUITE_USE_GROUP     0x000FAC00
#define WLAN_CIPHER_SUITE_WEP40         0x000FAC01
#define WLAN_CIPHER_SUITE_TKIP          0x000FAC02
/* reserved:                            0x000FAC03 */
#define WLAN_CIPHER_SUITE_CCMP          0x000FAC04
#define WLAN_CIPHER_SUITE_WEP104        0x000FAC05
#define WLAN_CIPHER_SUITE_AES_CMAC      0x000FAC06
#define WLAN_CIPHER_SUITE_NO_GROUP_ADDR 0x000FAC07
#define WLAN_CIPHER_SUITE_GCMP          0x000FAC08
#define WLAN_CIPHER_SUITE_GCMP_256      0x000FAC09
#define WLAN_CIPHER_SUITE_CCMP_256      0x000FAC0A
#define WLAN_CIPHER_SUITE_BIP_GMAC_128  0x000FAC0B
#define WLAN_CIPHER_SUITE_BIP_GMAC_256  0x000FAC0C
#define WLAN_CIPHER_SUITE_BIP_CMAC_256  0x000FAC0D
#define WLAN_CIPHER_SUITE_SMS4          0x00147201
#endif

#define SEQ_LEN_6 6
#define SEQ_LEN_8 8
#define KEYTSC_TO_PN(seq, seqlen, keytsc) {\
        if (seqlen == SEQ_LEN_8) { \
            (seq)[0] = ((keytsc) >> 56) & 0xFF; \
            (seq)[1] = ((keytsc) >> 48) & 0xFF; \
        } \
        (seq)[2] = ((keytsc) >> 40) & 0xFF; \
        (seq)[3] = ((keytsc) >> 32) & 0xFF; \
        (seq)[4] = ((keytsc) >> 24) & 0xFF; \
        (seq)[5] = ((keytsc) >> 16) & 0xFF; \
        (seq)[6] = ((keytsc) >> 8)  & 0xFF; \
        (seq)[7] = ((keytsc))       & 0xFF; \
}
int wlan_cfg80211_add_key(struct wiphy *wiphy, struct net_device *ndev, u8 key_index, bool pairwise, const u8 *mac_addr, struct key_params *params);
int wlan_cfg80211_get_key(struct wiphy *wiphy, struct net_device *ndev, u8 key_index, bool pairwise, const u8 *mac_addr, void *cookie, void (*callback)(void *cookie, struct key_params *));
int wlan_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev, u8 key_index, bool pairwise, const u8 *mac_addr);
int wlan_cfg80211_set_default_key(struct wiphy *wiphy, struct net_device *ndev, u8 key_index, bool unicast, bool multicast);

int wlan_6ghz_security_check(wlan_if_t vap, int key_mgmt, uint16_t rsn_caps);
int wlan_cfg80211_6ghz_security_check(wlan_if_t vap);
int wlan_cfg80211_mbssid_security_admission_control_sanity(struct ieee80211com *ic, uint8_t check_6g_comp);
int wlan_cfg80211_security_init(struct cfg80211_ap_settings *params,struct net_device *dev);
int wlan_cfg80211_crypto_setting(struct net_device *dev,
                                 struct cfg80211_crypto_settings *params,
                                 enum nl80211_auth_type auth_type);
bool wlan_cfg80211_vap_is_open(struct cfg80211_ap_settings *params,struct net_device *dev);
int wlan_set_beacon_ies(struct  net_device *dev, struct cfg80211_beacon_data *beacon);
#endif /* IEEE80211_CRYPTO_NL80211_H */
#endif /* UMAC_SUPPORT_CFG80211 */

