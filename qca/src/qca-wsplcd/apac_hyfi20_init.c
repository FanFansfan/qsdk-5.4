/* apac_hyfi20_init.c
 * @Notes:
 *
 * Copyright (c) 2011-2012, 2014-2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011-2012, 2014-2016 Qualcomm Atheros, Inc.
 *
 * Qualcomm Atheros Confidential and Proprietary.
 * All rights reserved.
 *
 */

#include "wsplcd.h"
#include "eloop.h"
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/wireless.h>
#include <ieee80211_external.h>
#include "apac_hyfi20_wps.h"

#include "apac_hyfi20_ctrl.h"
#include "apac_hyfi20_mib.h"
#include "apac_priv.h"

#include "wps_config.h"
#include "wps_parser.h"
#include "split.h"
#include "wlanif_cmn.h"
#if MAP_ENABLED
#include "apac_map.h"
#endif

#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#undef QCA_MOD_INPUT
#define QCA_MOD_INPUT QCA_MOD_WSPLCD
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */


#define MAXCHANONESTRLEN    8
#define MAXCHANLISTSTRLEN   1024
#define WMODE_NAMESIZE  16
#define WSPLCD_PLC_SOCKET_SERVER "/var/run/wsplcd_plc_socket_server"

#define RCVBUF_MULT_FACTOR  4

extern int debug_level;
extern apacHyfi20GlobalState_t apacS;
extern apacLogFileMode_e logFileMode;;
extern u16 apac_cfg_apply_interval;
extern u16 apac_cfg_restart_short_interval;
extern u16 apac_cfg_restart_long_interval;
u16 g_wsplcd_instance = APAC_WSPLCD_INSTANCE_PRIMARY;

/** is_char_significant() will make below checks
 *  checks if character has any space
 *  checks if character is unicode
 *  checks for any printable character except space.
 */
static inline apacBool_e is_char_significant(char *pos) {
              return ((unsigned char)*pos == ' ' || (unsigned char)*pos >= (unsigned char)UNICODE_START
                                                 || isgraph(*pos)) ? APAC_TRUE : APAC_FALSE;
}

struct wlanif_config *wlanIfWd=NULL;

// "auto" APAC standard used when no matching PHY mode is found
#define APAC_STD_AUTO "auto"

int wlanIfConfigInit(u32 isCfg80211)
{
    if (isCfg80211) {
        wlanIfWd = wlanif_config_init(WSPLCD_NL80211_CMD_SOCK,
                                      WSPLCD_NL80211_EVENT_SOCK);
    }

    if ( !wlanIfWd )
    {
        return -1;
    }
    return 0;
}

void wlanIfConfigExit()
{
    if(wlanIfWd) {
        wlanif_config_deinit(wlanIfWd);
    }
}

//No-op function defined to handle build/run-time link for SON libraries
void wlanifBSteerEventsMsgRx(wlanifBSteerEventsHandle_t state,
                             const ath_netlink_bsteering_event_t *event) {
    return;
}

/**************************************************************
 * Hyfi2.0 / IEEE1905 AP Auto-Configuration
 **************************************************************/
int apacHyfi20GetDeviceMode(apacHyfi20IF_t *pIF) {
    uint32_t result=0;
    char *ifName = pIF->ifName;

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto err;
    }
    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        return -1;
    }

    if (isAP_cfg80211(wlanIfWd->ctx, ifName, &result) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    if (result) {
        pIF->wlanDeviceMode = APAC_WLAN_AP;
    }
    else {
        pIF->wlanDeviceMode = APAC_WLAN_STA;
    }

    return 0;

err:
    return -1;
}

int apacHyfi20GetVAPIndex(apacHyfi20IF_t *pIF) {
    int vapIndex;

    vapIndex = apac_mib_get_vapindex(pIF->ifName);

    if (vapIndex < 0) {
        dprintf(MSG_ERROR, "%s, can't get VAP INDEX for %s! vapIndex: %d\n", __func__, pIF->ifName, vapIndex);
        return -1;
    }

    pIF->vapIndex = vapIndex;

    return 0;
}

/**
 * @brief Check if the given interface is marked as wsplcd unmanaged
 *
 * @param [in] pIF  the interface to check
 *
 * @return negative value if error reading config data;
 *         0 if it is not unmanaged;
 *         positive value if the interface is marked as unmanaged
 */
static int apacHyfi20IsWsplcdUnmanaged(apacHyfi20IF_t *pIF) {
    return apac_mib_get_wsplcdUnmanaged_by_vapindex(pIF->vapIndex);
}

int apacHyfi20GetBandFromMib(int vap_index, apacHyfi20WifiFreq_e *freq) {
    char standard[1024];
    int i;

    struct wlanBand_t
    {
        const char* name;
        apacHyfi20WifiFreq_e freq;

    } wlanBands[] =
        {
            { "axahe80_80_6g", APAC_WIFI_FREQ_6},
            { "axahe160_6g", APAC_WIFI_FREQ_6},
            { "axahe80_6g", APAC_WIFI_FREQ_6},
            { "axahe40plus_6g", APAC_WIFI_FREQ_6},
            { "axahe40minus_6g", APAC_WIFI_FREQ_6},
            { "axahe20_6g", APAC_WIFI_FREQ_6},
            { "axahe80_80low", APAC_WIFI_FREQ_5_OTHER},
            { "axahe160low", APAC_WIFI_FREQ_5_OTHER},
            { "axahe80low", APAC_WIFI_FREQ_5_OTHER},
            { "axahe40pluslow", APAC_WIFI_FREQ_5_OTHER},
            { "axahe40minuslow", APAC_WIFI_FREQ_5_OTHER},
            { "axahe20low", APAC_WIFI_FREQ_5_OTHER},
            { "acvht80_80low", APAC_WIFI_FREQ_5_OTHER},
            { "acvht160low", APAC_WIFI_FREQ_5_OTHER},
            { "acvht80low", APAC_WIFI_FREQ_5_OTHER},
            { "acvht40pluslow", APAC_WIFI_FREQ_5_OTHER},
            { "acvht40minuslow", APAC_WIFI_FREQ_5_OTHER},
            { "acvht20low", APAC_WIFI_FREQ_5_OTHER},
            { "axahe80_80", APAC_WIFI_FREQ_5},
            { "axahe160", APAC_WIFI_FREQ_5},
            { "axahe80", APAC_WIFI_FREQ_5},
            { "axahe40plus", APAC_WIFI_FREQ_5},
            { "axahe40minus", APAC_WIFI_FREQ_5},
            { "axahe20", APAC_WIFI_FREQ_5},
            { "acvht80_80", APAC_WIFI_FREQ_5},
            { "acvht160", APAC_WIFI_FREQ_5},
            { "acvht80", APAC_WIFI_FREQ_5},
            { "acvht40plus", APAC_WIFI_FREQ_5},
            { "na20", APAC_WIFI_FREQ_5},
            { "na40minus", APAC_WIFI_FREQ_5},
            { "na40plus", APAC_WIFI_FREQ_5},
            { "na40", APAC_WIFI_FREQ_5},
            { "na20low", APAC_WIFI_FREQ_5_OTHER},
            { "na40minuslow", APAC_WIFI_FREQ_5_OTHER},
            { "na40pluslow", APAC_WIFI_FREQ_5_OTHER},
            { "na40low", APAC_WIFI_FREQ_5_OTHER},
            { "ng20", APAC_WIFI_FREQ_2},
            { "ng40minus", APAC_WIFI_FREQ_2},
            { "ng40plus", APAC_WIFI_FREQ_2},
            { "ng40", APAC_WIFI_FREQ_2},
            { "axghe20", APAC_WIFI_FREQ_2},
            { "axghe40plus", APAC_WIFI_FREQ_2},
            { "axghe40minus", APAC_WIFI_FREQ_2},
            { "ng", APAC_WIFI_FREQ_2},
            { "na", APAC_WIFI_FREQ_5},
            { "nalow", APAC_WIFI_FREQ_5_OTHER},
            { "acvht", APAC_WIFI_FREQ_5},
            { "a", APAC_WIFI_FREQ_5},
            { "alow", APAC_WIFI_FREQ_5_OTHER},
            { "b", APAC_WIFI_FREQ_2},
            { "g", APAC_WIFI_FREQ_2},
            { "ahe", APAC_WIFI_FREQ_5},
            { "ghe", APAC_WIFI_FREQ_2},
        };

    if (apac_mib_get_wlan_standard_by_vapindex(vap_index, standard) < 0) {
        dprintf(MSG_ERROR, "%s, get wlan standard from mib error\n", __func__);
        return -1;
    }

    for(i = 0; i < sizeof(wlanBands)/sizeof(wlanBands[0]); i++)
    {
        /* Return correct type by string match */
        if( strstr( standard, wlanBands[ i ].name ) )
        {
            dprintf(MSG_DEBUG, "%s: WiFi name: %s\n", __func__, standard);
            *freq = wlanBands[i].freq;
            return 0;
        }
    }

    dprintf(MSG_ERROR, "%s, Can't find match. vap: %u, standard: %s\n", __func__, vap_index, standard);
    return -1;
}

int apacHyfi20GetFreq(apacHyfi20IF_t *pIF) {
    int32_t freq;

    if (!pIF->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto err;
    }

    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        return -1;
    }

    if (getFreq_cfg80211(wlanIfWd->ctx ,pIF->ifName , &freq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pIF->ifName);
        goto err;
    }

    if (freq / 100000000 >= 60)
        pIF->wifiFreq = APAC_WIFI_FREQ_60;
    else if (freq / 100000000 >= 5)
        pIF->wifiFreq = APAC_WIFI_FREQ_5;
    else
        pIF->wifiFreq = APAC_WIFI_FREQ_2;

    dprintf(MSG_MSGDUMP, "%s - Interface %s, frequency %uHz\n", __func__, pIF->ifName, freq);

    return 0;

err:
    return -1;
}


static uint32_t ieee80211_mhz2ieee(uint32_t freq)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
    if (freq < 2412)
        return 0;
    if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) +
                (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if (freq > 4900) {
            return (freq - 4000) / 5;
        } else {
            return 15 + ((freq - 2512) / 20);
        }
    }
    if ((freq >= 5180) && (freq <= 5895)){
        return (freq - 5000) / 5;
    }
    if ((freq > 5950) && (freq <= 7125)) {
        return (freq - 5950) / 5;
    }
    return 0;
}


int apacHyfi20GetChannel(apacHyfi20AP_t *pAP) {
    int32_t freq;

    if (!pAP->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto err;
    }

    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        return -1;
    }

    if (getFreq_cfg80211(wlanIfWd->ctx ,pAP->ifName , &freq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pAP->ifName);
        goto err;
    }

    pAP->channel = ieee80211_mhz2ieee(freq/100000);

    dprintf(MSG_MSGDUMP, "%s - Interface %s, channel %d\n", __func__, pAP->ifName, pAP->channel);

    return 0;

err:
    return -1;
}

/**
 * @brief Resolve Wlan Standard string from the mode returned from driver
 *
 * @param [in] mode  the mode string returned from driver
 * @param [in] chanInfo  channel information containing the actual OTA bandwidth
 *                       and channel offset
 * @param [out] std  the standard string resolved
 * @param [out] std_len  the length of the standard string
 */
static void apacHyfi20ResolveWlanStd(const char *mode, const apacHyfi20ChanInfo_t *chanInfo,
                                     char *std, u_int8_t *std_len) {
    size_t i, max_len;
    char *actual_std;
    for (i = 0; phy_to_std_mappings[i].phy_mode; ++i) {
        if (!strcmp(phy_to_std_mappings[i].phy_mode, mode)) {
            strlcpy(std, phy_to_std_mappings[i].apac_std, APAC_STD_MAX_LEN);
#define VHT_STD "acvht"
#define NGHT_STD "ng"
#define NAHT_STD "na"
#define AXAHE_STD "axahe"
#define AXGHE_STD "axghe"
            // Workaround to resolve actual OTA mode for HT/VHT
            if (strncmp(std, VHT_STD, strlen(VHT_STD)) == 0) {
                actual_std = std + strlen(VHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(VHT_STD);
            } else if (strncmp(std, NGHT_STD, strlen(NGHT_STD)) == 0) {
                actual_std = std + strlen(NGHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(NGHT_STD);
            } else if (strncmp(std, NAHT_STD, strlen(NAHT_STD)) == 0) {
                actual_std = std + strlen(NAHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(NAHT_STD);
            } else if (strncmp(std, AXGHE_STD, strlen(AXGHE_STD)) == 0) {
                actual_std = std + strlen(AXGHE_STD);
                max_len = APAC_STD_MAX_LEN - strlen(AXGHE_STD);
            } else if (strncmp(std, AXAHE_STD, strlen(AXAHE_STD)) == 0) {
                actual_std = std + strlen(AXAHE_STD);
                max_len = APAC_STD_MAX_LEN - strlen(AXAHE_STD);
            } else { // Non HT/VHT mode, do nothing
                break;
            }

            switch (chanInfo->width) {
                case IEEE80211_CWM_WIDTH20:
                    strlcpy(actual_std, "20", max_len);
                    break;
                case IEEE80211_CWM_WIDTH40:
                    strlcpy(actual_std, "40", max_len);
                    if (chanInfo->offset == 1) {
                        strlcpy(actual_std + 2, "plus", max_len - 2);
                    } else if (chanInfo->offset == -1) {
                        strlcpy(actual_std + 2, "minus", max_len - 2);
                    }
                    break;
                case IEEE80211_CWM_WIDTH80:
                    strlcpy(actual_std, "80", max_len);
                    break;
                case IEEE80211_CWM_WIDTH160:
                    if (chanInfo->ifreq2) {
                        strlcpy(actual_std, "80_80", max_len);
                    } else {
                        strlcpy(actual_std, "160", max_len);
                    }
                    break;
                default:
                    break;
            }
            break;
        }
    }

    if (!phy_to_std_mappings[i].phy_mode) {
        // If no matching mode, use "auto"
        strlcpy(std, APAC_STD_AUTO, APAC_STD_MAX_LEN);
    }

    *std_len = strlen(std);
}

int apacHyfi20GetAPMode(apacHyfi20AP_t *pAP) {
    char mode[20] = {0};
    apacHyfi20ChanInfo_t chanInfo = {0};

    if (!pAP->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto err;
    }

    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        goto err;
    }

    if (getWirelessMode_cfg80211(wlanIfWd->ctx,pAP->ifName,mode,sizeof(mode)) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pAP->ifName);
        goto err;
    }

    if (apacHyfi20GetAPChannelInfo(pAP->ifName, &chanInfo) != 0) {
        dprintf(MSG_ERROR, "%s: Failed to get channel info, ifName: %s.\n",
                __func__, pAP->ifName);
        goto err;
    }
    apacHyfi20ResolveWlanStd(mode, &chanInfo, pAP->standard, &pAP->standard_len);
    dprintf(MSG_MSGDUMP, "%s - Interface %s, standard %s\n",
            __func__, pAP->ifName, pAP->standard);

    return 0;
err:
    return -1;

}

static int get80211ChannelInfo(const char *ifName, struct ieee80211req_channel_list *chans) {
    size_t len = sizeof(*chans);

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL\n", __func__);
        goto err;
    }

    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        return -1;
    }

    if(getChannelInfo_cfg80211(wlanIfWd->ctx, ifName, chans, len) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    return 0;

err:
    return -1;
}

int apacHyfi20GetWlanBandCapacity(const char *ifName, char *chanlist, size_t listSize, apacBool_e *hasW2, apacBool_e *hasW5) {
    struct ieee80211req_channel_list *chans;
    int i;
    int ret = -1;
    char chanone[MAXCHANONESTRLEN + 1];

    /*size coped to user space:
     (sizeof(struct ieee80211req_channel_list)/sizeof(__u32)) + 1)
     */
    chans = malloc((sizeof(struct ieee80211req_channel_list)/sizeof(unsigned int) + 1) * sizeof(unsigned int));
    if (!chans)
    {
        dprintf(MSG_ERROR, "ERR to malloc channel_list buffer\n");
        return -1;
    }

    if (get80211ChannelInfo(ifName, chans) < 0) {
        dprintf(MSG_ERROR, "ERR, get80211ChannelInfo\n");
        goto err;
    }

    chanlist[0]='\0';   /*flush out the list*/
    *hasW2 = APAC_FALSE;
    *hasW5 = APAC_FALSE;

    for (i = 0; i < chans->nchans; i ++) {
        snprintf(chanone, MAXCHANONESTRLEN, "%u, ", chans->chans[i].freq);
        strlcat(chanlist, chanone, listSize);

        if ( (chans->chans[i].freq / 1000) == 2 ) {
            *hasW2 = APAC_TRUE;
        }
        else if ( (chans->chans[i].freq / 1000) == 5 ) {
            *hasW5 = APAC_TRUE;
        }
        else {
            dprintf(MSG_ERROR, "%s, invalid freq read: %u\n", __func__, chans->chans[i].freq);
            goto err;
        }
    }
    dprintf(MSG_MSGDUMP, "%s, channel info: %s\n", __func__, chanlist);
    ret = 0;

err:
    if (chans) {
        free(chans);
    }

    return ret;
}

int apacHyfi20GetWlanHWCapability(const int rindex, char *hwcaps)
{
    FILE *f;
    char fname[256];

    if (!hwcaps)
        return -1;

    snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/hwcaps", rindex -1);
    dprintf(MSG_DEBUG, "Reading HW Capacity from %s\n", fname);


    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open hwcaps file '%s' for reading.\n", fname);
        return -1;
    }

    if (fgets(hwcaps, 256, f) == NULL) {
        dprintf(MSG_ERROR,
            "Could not read hwcaps file '%s'.\n", fname);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/**
 * @brief Get the maximum channel width the radio is capable of
 *
 * @param [in] rindex  the radio index
 * @param [in] is2G  whether the radio is 2G or not (5G)
 * @param [out] maxChWidth  the maximum channel width capability
 *
 * @return 0 on success; otherwise return -1
 */
static int apacHyfi20GetWlanMaxChwidth(const int rindex, int is2G,
                                       enum ieee80211_cwm_width *maxChWidth) {
    FILE *f;
    char fname[256];
    int ret = 0;

    if (!maxChWidth) { return -1; }

    if (is2G) {
        snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/2g_maxchwidth", rindex -1);
    } else {
        snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/5g_maxchwidth", rindex -1);
    }
    dprintf(MSG_DEBUG, "Reading max channel width supported from %s\n", fname);

    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open maxchwidth file '%s' for reading.\n", fname);
        return -1;
    } else {
        char chwidthStr[256];
        if (fgets(chwidthStr, sizeof(chwidthStr), f) == NULL) {
            dprintf(MSG_ERROR, "Could not read maxchwidth file '%s'.\n", fname);
            ret = -1;
        } else {
            if (strcmp(chwidthStr, "20") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH20;
            } else if (strcmp(chwidthStr, "40") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH40;
            } else if (strcmp(chwidthStr, "80") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH80;
            } else if (strcmp(chwidthStr, "160") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH160;
            } else {
                dprintf(MSG_ERROR, "Invalid maxchwidth read: %s\n", chwidthStr);
                ret = -1;
            }
        }
    }

    fclose(f);
    return ret;
}

/*
GetWlanBestStandard
     Get a compatible standard according to current HW capacity
In:
    rindex: radio index
    chan:   channel
    regStd: registrar's standard
Return:
    -1: errors
     0: success, the compatible standard is stored in "bestStd"
*/
int apacHyfi20GetWlanBestStandard(const int rindex, int chan, char* regStd, char **bestStd/*out*/)
{
    char hwcaps[256];
    int  is2G;
    enum ieee80211_cwm_width maxChWidth = IEEE80211_CWM_WIDTHINVALID;
    static struct best11naMode{
        int channel;
        char *bestmode;
    } modes[] = {
        {36, "na40plus"},
        {40, "na40minus"},
        {44, "na40plus"},
        {48, "na40minus"},
        {52, "na40plus"},
        {56, "na40minus"},
        {60, "na40plus"},
        {64, "na40minus"},
        {100, "na40plus"},
        {104, "na40minus"},
        {108, "na40plus"},
        {112, "na40minus"},
        {116, "na40plus"},
        {120, "na40minus"},
        {124, "na40plus"},
        {128, "na40minus"},
        {132, "na40plus"},
        {136, "na40minus"},
        {140, "na20"},
        {149, "na40plus"},
        {153, "na40minus"},
        {157, "na40plus"},
        {161, "na40minus"},
        {165, "na20"},
        {0  , NULL}
    };

    if (!bestStd)
        return -1;
    *bestStd = NULL;

    /*QCA 2.4G implementation for 11ac*/
    if (chan > 0 && chan <= 14)
        is2G = 1;
    else
        is2G = 0;

    if (apacHyfi20GetWlanHWCapability(rindex, hwcaps) < 0)
        return -1;

    /*If peer is 11AC/11AXA, but we don't support it.
      11AC         -->     11NA
      acvht20              na20
      acvht40plus          na40plus
      acvht40minus         na40minus
      acvht40/80           select best mode from table

      11AC         -->     11NG
      acvht20              ng20
      acvht40plus          ng40plus
      acvht40minus         ng40minus
      1-4                  ng40plus
      5-9/10-14            ng40minus  //world safe

      11AXA        -->     11AC
      axahe20              acvht20
      axahe40plus          acvht40plus
      acahe40minus         acvht40minus
      axahe40/80           select best mode from table
      acahe160             acvht80
      acahe80_80           acvht80

      11AXG        -->     11NG
      axghe20              ng20
      axghe40plus          ng40plus
      axghe40minus         ng40minus
      1-4                  ng40plus
      5-9/10-14            ng40minus  //world safe
    */
    if (!strstr(regStd, "acvht")
        ||strstr(hwcaps, "ac"))
    {

        if (strcmp(regStd, "acvht160") == 0 ||
            strcmp(regStd, "acvht80_80") == 0) {
            // Currently only check max channel width supported when receives
            // 160 MHz mode from CAP, since there may not be strong needs for
            // other cases given the platform this code will be running on.
            if (apacHyfi20GetWlanMaxChwidth(rindex, is2G, &maxChWidth) < 0) {
                return -1;
            }

            if (maxChWidth < IEEE80211_CWM_WIDTH160) {
                *bestStd = (char *)calloc(APAC_STD_MAX_LEN, sizeof(char));
                if (!*bestStd) {
                    dprintf(MSG_ERROR, "%s: calloc failed\n", __func__);
                    return -1;
                }
                snprintf(*bestStd, APAC_STD_MAX_LEN, "acvht%d0", 2 << maxChWidth);
                goto out;
            }
        }

        if (strstr(regStd, "ax")
            &&(!strstr(hwcaps, "ax"))) {
            if (strcmp(regStd, "axahe80") == 0)
                *bestStd = strdup("acvht80");
            else if (strcmp(regStd, "axghe20") == 0)
                *bestStd = strdup("ng20");
            else if (strcmp(regStd, "axghe40plus") == 0)
                *bestStd = strdup("ng40plus");
            else if (strcmp(regStd, "axghe40minus") == 0)
                *bestStd = strdup("ng40minus");
            else if (strcmp(regStd, "axahe20") == 0)
                *bestStd = strdup("acvht20");
            else if (strcmp(regStd, "axahe40minus") == 0)
                *bestStd = strdup("acvht40minus");
            else if (strcmp(regStd, "axahe40plus") == 0)
                *bestStd = strdup("acvht40plus");
            else if (strcmp(regStd, "axahe160") == 0)
                *bestStd = strdup("acvht80");
            else if (strcmp(regStd, "axahe80_80") == 0)
                *bestStd = strdup("acvht80");
            goto out;
        } else {
            *bestStd = strdup(regStd);
            goto out;
            }
    }

    if (is2G) {
        if (strcmp(regStd, "acvht20") == 0)
            *bestStd = strdup("ng20");
        else if (strcmp(regStd, "acvht40plus") == 0)
            *bestStd = strdup("ng40plus");
        else if (strcmp(regStd, "acvht40minus") == 0)
            *bestStd = strdup("ng40minus");
        else if (strcmp(regStd, "axghe20") == 0)
            *bestStd = strdup("ng20");
        else if (strcmp(regStd, "axghe40plus") == 0)
            *bestStd = strdup("ng40plus");
        else if (strcmp(regStd, "axghe40minus") == 0)
            *bestStd = strdup("ng40minus");
        else if (chan <= 4)
            *bestStd = strdup("ng40plus");
        else
            *bestStd = strdup("ng40minus");;
    } else {
        if (strcmp(regStd, "acvht20") == 0)
            *bestStd = strdup("na20");
        else if (strcmp(regStd, "acvht40plus") == 0)
            *bestStd = strdup("na40plus");
        else if (strcmp(regStd, "acvht40minus") == 0)
            *bestStd = strdup("na40minus");
        else if (strcmp(regStd, "ahe20") == 0)
            *bestStd = strdup("na20");
        else if (strcmp(regStd, "ahe40minus") == 0)
            *bestStd = strdup("na40minus");
        else if (strcmp(regStd, "ahe40plus") == 0)
            *bestStd = strdup("na40plus");
        else /*acvht40, acvht80 or others*/
        {
            struct best11naMode *pMode;
            for(pMode = modes; pMode->channel; pMode++)
            {
                 if (pMode->channel == chan)
                 {
                     *bestStd = strdup(pMode->bestmode);
                     break;
                 }
            }
            if (!pMode->channel)
            {
                /*For auto channel, registrar should notify its channel soon*/
                if (chan == 0)
                    *bestStd = strdup("na20");
                else
                {
                    dprintf(MSG_ERROR, "%s: can't find the channel %d\n", __func__, chan);
                    return -1;
                }
            }
        }
    }

out:
    if (!*bestStd)
    {
        dprintf(MSG_ERROR, "%s: string allocation failed\n", __func__);
        return -1;
    }

    return 0;
}

int apacHyfi20GetAPChannelInfo( const char *iface, apacHyfi20ChanInfo_t *chaninfo)
{
    u_int8_t     channel;
    int          chwidth, choffset, offset, bandwidth;
    int32_t      cfreq2=0;
    int32_t      freq=0;

    if (!iface) {
        dprintf(MSG_ERROR, "%s: Invalid arguments", __func__);
        goto err;
    }

    if ( !wlanIfWd )
    {
        dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
        return -1;
    }

    if (getFreq_cfg80211(wlanIfWd->ctx ,iface , &freq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }

    channel = ieee80211_mhz2ieee(freq / 100000);
    dprintf(MSG_MSGDUMP, "%s: Interface %s, frequency %uHz channel %d\n", __func__, iface, freq, channel);

    if(getChannelWidth_cfg80211(wlanIfWd->ctx, iface, &chwidth) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }

    dprintf(MSG_MSGDUMP, "%s: Interface %s, channel width %d\n", __func__, iface, chwidth);
    if(getChannelExtOffset_cfg80211(wlanIfWd->ctx, iface, &choffset) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }
    dprintf(MSG_MSGDUMP, "%s: Interface %s, channel offset %d", __func__, iface, choffset);

    switch( chwidth )
    {
    case IEEE80211_CWM_WIDTH20:
        chaninfo->ifreq1 = channel;
        chaninfo->ifreq2 = 0;
        chaninfo->offset = 0;
        break;

    case IEEE80211_CWM_WIDTH40:
        chaninfo->ifreq2 = 0;
        if (choffset == 1)
            chaninfo->ifreq1 = channel + 2;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - 2;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s\n", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
        break;

    case IEEE80211_CWM_WIDTH80:
        chaninfo->ifreq2 = 0;
        if (choffset == 1)
            chaninfo->ifreq1 = channel + 4;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - 4;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s\n", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
        break;

    case IEEE80211_CWM_WIDTH160: //160MHz or 80p80MHz
        if (getChannelBandwidth_cfg80211(wlanIfWd->ctx ,iface, &bandwidth) < 0) {
            dprintf(MSG_ERROR, "%s: ioctl(GET IEEE80211_PARAM_BANDWIDTH) failed, ifName: %s.\n",
                             __func__, iface);
            goto err;
        }
        if ((bandwidth == 6) || (bandwidth == 11)) { // 80p80 MHz
            if (getCfreq2_cfg80211(wlanIfWd->ctx, iface, &cfreq2) < 0) {
                dprintf(MSG_ERROR, "%s: ioctl(IEEE80211_PARAM_SECOND_CENTER_FREQ) failed, "
                        "ifName: %s.\n", __func__, iface);
                goto err;
            }
        }
        chaninfo->ifreq2 = ieee80211_mhz2ieee(cfreq2);
        dprintf(MSG_MSGDUMP, "%s: Interface %s, 2nd center freq %d\n",
                __func__, iface, chaninfo->ifreq2);

        if (chaninfo->ifreq2) { // 80p80 MHz
            offset = 4;
        } else { // 160 MHz
            offset = 8;
        }
        if (choffset == 1)
            chaninfo->ifreq1 = channel + offset;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - offset;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
    	break;

    default:
    	dprintf(MSG_ERROR, "%s: Invalid channel width for interface: %s", __func__, iface);
        goto err;
    }
    chaninfo->width = chwidth;

    return 0;
err:
    return -1;
}

int apacHyfi20Set80211Channel(const char *ifName, apacHyfi20WifiFreq_e freq) {
    /* Choose ng20 for 2G, and na40plus for 5G */
    const char WMODE_5G[] = "11NAHT40PLUS";
    const char WMODE_2G[] = "11NGHT20";
    char wmode[WMODE_NAMESIZE];
    struct ieee80211req_channel_list *chans;
    int i;
    int32_t Sock;
    struct iwreq Wrq;
    apacBool_e found = APAC_FALSE;

    /*size coped to user space:
     (sizeof(struct ieee80211req_channel_list)/sizeof(__u32)) + 1)
     */
    chans = malloc((sizeof(struct ieee80211req_channel_list)/sizeof(unsigned int) + 1) * sizeof(unsigned int));
    if (!chans)
    {
        dprintf(MSG_ERROR, "ERR to malloc channel_list buffer\n");
        return -1;
    }

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL\n", __func__);
        goto out;
    }

    /* read available channel information */
    if (get80211ChannelInfo(ifName, chans) < 0) {
        dprintf(MSG_ERROR, "%s, getWlanBandCapacity error\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!\n", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    os_memset(&Wrq, 0, sizeof(Wrq));
    strlcpy(Wrq.ifr_name, ifName, IFNAMSIZ);

    /* alway set channel to 0 */
    Wrq.u.freq.m = 0;
    Wrq.u.freq.e = 0;
    Wrq.u.freq.flags = IW_FREQ_AUTO;

    if (ioctl(Sock, SIOCSIWFREQ, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: Set channel to 0 for %s failed", __func__, ifName);
        goto err;
    }

    /* set vap standard */
    for (i = 0; i < chans->nchans; i ++) {

        if ( (chans->chans[i].freq / 1000) == 2 && freq == APAC_WIFI_FREQ_2 ) {
            strlcpy(wmode, WMODE_2G, sizeof(wmode));
            found = APAC_TRUE;
            break;
        }
        else if ( (chans->chans[i].freq / 1000) == 5 && freq == APAC_WIFI_FREQ_5 ) {
            strlcpy(wmode, WMODE_5G, sizeof(wmode));
            found = APAC_TRUE;
            break;
        }
    }

    if (!found) {
        dprintf(MSG_ERROR, "%s, couldn't set freq %u!\n", __func__, freq);
        goto err;
    }

    Wrq.u.data.pointer = (void *)wmode;
    Wrq.u.data.length = sizeof(wmode);

    if (ioctl(Sock, IEEE80211_IOCTL_SETMODE, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s, ioctl setmode for '%s' failed: mode '%s'\n", __func__, wmode, ifName);
        goto err;
    }
    dprintf(MSG_DEBUG, "%s, ioctl setmode to '%s' for IF '%s' successful\n", __func__, wmode, ifName);

    free(chans);
    close(Sock);
    return 0;
err:
    free(chans);
    close(Sock);
out:
    return -1;
}

int apacHyfi20SetMediaTypeFromZeroStr(char *str, apacHyfi20Data_t *pData, int index, int band) {
    apacHyfi20IF_t *hyif = &(pData->hyif[index]);
    apacHyfi20AP_t *pAP = pData->ap;

    if (strcmp(str, "WLAN") == 0) {
        apacHyfi20WifiFreq_e freq;
        freq =  band;

        hyif->mediaType = APAC_MEDIATYPE_WIFI;
        hyif->nonPBC = APAC_FALSE;  /* PBC enabled by default */

        if (freq != APAC_WIFI_FREQ_INVALID ) {
          if (pAP[freq].valid) {
            if (freq == APAC_WIFI_FREQ_5) {
              freq = APAC_WIFI_FREQ_5_OTHER;

              dprintf(MSG_MSGDUMP, "%s: freq=%d\n", __func__, freq);
            } else {
              dprintf(
                  MSG_MSGDUMP,
                  "%s - Configuration: Freq %d has more than Two 1905 AP, previous\
                            information will be overwritten!\n",
                  __func__, freq);
            }
          }
          pAP[freq].freq = band;
          pAP[freq].ifName = hyif->ifName;
          pAP[freq].radioName = hyif->radioName;
          pAP[freq].valid = APAC_TRUE;
        }
    }
    return 0;
}

int apacHyfi20SetMediaTypeFromStr(char *str, apacHyfi20Data_t *pData, int index) {
    apacHyfi20IF_t *hyif = &(pData->hyif[index]);
    apacHyfi20AP_t *pAP = pData->ap;
    int radio_index = 0;

    if (strcmp(str, "WLAN") == 0) {
        apacHyfi20WifiFreq_e freq;

        hyif->mediaType = APAC_MEDIATYPE_WIFI;
        hyif->nonPBC = APAC_FALSE;  /* PBC enabled by default */
        if (apacHyfi20GetDeviceMode(hyif) < 0
                || apacHyfi20GetVAPIndex(hyif) < 0
                || apacHyfi20GetBandFromMib(hyif->vapIndex, &(hyif->wifiFreq)) < 0 )
        {
            return -1;
        }

        if (hyif->wlanDeviceMode != APAC_WLAN_AP) {
            return 0;   /* done with STA */
        }

        int unmanaged = apacHyfi20IsWsplcdUnmanaged(hyif);
        if (unmanaged < 0) {
            dprintf(MSG_ERROR, "%s: Failed to resolve wsplcd unmanaged flag on %s\n",
                    __func__, hyif->ifName);
            return -1;
        } else if (unmanaged) {
            dprintf(MSG_DEBUG, "%s: %s is marked as WSPLCD unmanaged\n",
                    __func__, hyif->ifName);
            return 0;
        }

        /* lei: Currently only one 1905 AP per band is supported. If there is more than
         * one AP per band found, information of the previous AP will be overwritten in pData->ap
         * (only remember the recent vap_index), but not pData->hyif
         */

        radio_index = apac_mib_get_radio_by_vapindex(hyif->vapIndex);
        if (radio_index == -1) {
            dprintf(MSG_ERROR, " Error getting radio index for vapIndex %d \n", hyif->vapIndex);
            return -1;
        }

        freq = hyif->wifiFreq;

        if (freq != APAC_WIFI_FREQ_INVALID) {
          if (pAP[freq].valid) {
            if (freq == APAC_WIFI_FREQ_5 &&
                radio_index != pAP[hyif->wifiFreq].radio_index) {
              freq = APAC_WIFI_FREQ_5_OTHER;

              dprintf(MSG_MSGDUMP, "Radio  index %d@vapIndex %d , freq %d\n",
                      radio_index, hyif->vapIndex, freq);
            } else {
              dprintf(
                  MSG_MSGDUMP,
                  "%s - Configuration: Freq %d has more than Two 1905 AP, previous\
                            information will be overwritten!\n",
                  __func__, freq);
            }
          }

#if SON_ENABLED
          if((freq == APAC_WIFI_FREQ_5 || freq == APAC_WIFI_FREQ_5_OTHER) &&
                  apacHyfi20GetLocalBandFromRadioName(hyif->radioName, APAC_WIFI_FREQ_5) == bandInfo_Full) {
              dprintf(MSG_MSGDUMP, "%s:%d Board supports 5G FULL-BAND, store VAPs only in APAC_WIFI_FREQ_5R\n",
                      __func__,__LINE__);
              freq=APAC_WIFI_FREQ_5;
              pAP[APAC_WIFI_FREQ_5].freq = APAC_WIFI_FREQ_5;
              pAP[APAC_WIFI_FREQ_5_OTHER].freq = APAC_WIFI_FREQ_5_OTHER;
          } else {
#endif
              pAP[freq].freq = hyif->wifiFreq;
#if SON_ENABLED
          }
#endif
          pAP[freq].vap_index = hyif->vapIndex;
          pAP[freq].radio_index = radio_index;
          pAP[freq].ifName = hyif->ifName;
          pAP[freq].radioName = hyif->radioName;
          pAP[freq].valid = APAC_TRUE;
#if SON_ENABLED
          u8 i, indx;
          u32 is_backhaul=0;

          if (apac_mib_get_bsstype_by_vapindex(hyif->vapIndex, &is_backhaul) == 0) {
              if( is_backhaul ) {
                  pAP[freq].is_bh_available = APAC_TRUE;
              }
          }

          for(i=0;i < MAX_VAP_PER_BAND;i++) {
              if(!pAP[freq].son_vap_index[i]) {
                  if(is_backhaul && i != 0) {
                      for(indx=0; indx < MAX_VAP_PER_BAND &&
                              pAP[freq].son_vap_index[indx] != 0; indx++);
                      if(indx >= MAX_VAP_PER_BAND) {
                          indx = MAX_VAP_PER_BAND - 1;
                      }
                      for(; indx > 1; indx--) {
                              pAP[freq].son_vap_index[indx] = pAP[freq].son_vap_index[indx-1];
                      }
                      pAP[freq].son_vap_index[1] = hyif->vapIndex; /* vap index of FH in 0th place, BH in 1st place followed by additional FH */
                  } else {
                      pAP[freq].son_vap_index[i] = hyif->vapIndex;
                  }
                  break;
              }
          }

#endif
          apacHyfi20GetChannel(&pAP[freq]);
          apacHyfi20GetAPMode(&pAP[freq]);
#if MAP_ENABLED
          hyif->channel = pAP[freq].channel;
#endif
        }
    } else if (strcmp(str, "PLC") == 0) {
      hyif->mediaType = APAC_MEDIATYPE_PLC;
      hyif->nonPBC = APAC_FALSE; /* PBC enabled by default */
    }
    else if (strcmp(str, "ETHER") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_ETH;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "ESWITCH") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_ETH;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "MOCA") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_MOCA;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "WLAN_VLAN") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_WIFI_VLAN;
        hyif->nonPBC = APAC_TRUE;
    }
    else {
        dprintf(MSG_ERROR, "Invalid Media type: %s!\n", str);
        return -1;
    }

    return 0;
}

#define WPA_GET_BE16(a) ((u16) (((a)[0] << 8) | (a)[1]))
#define WPA_PUT_BE16(a, val)            \
    do {                    \
            (a)[0] = ((u16) (val)) >> 8;    \
            (a)[1] = ((u16) (val)) & 0xff;  \
       } while (0)

int wps_dev_type_str2bin(const char *str, u8 dev_type[SIZE_8_BYTES])
{
	const char *pos;

	/* <categ>-<OUI>-<subcateg> */
	WPA_PUT_BE16(dev_type, atoi(str));
	pos = os_strchr(str, '-');
	if (pos == NULL)
		return -1;
	pos++;
	if (hexstr2bin(pos, &dev_type[2], 4))
		return -1;
	pos = os_strchr(pos, '-');
	if (pos == NULL)
		return -1;
	pos++;
	WPA_PUT_BE16(&dev_type[6], atoi(pos));

	return 0;
}

char * wps_dev_type_bin2str(const u8 dev_type[SIZE_8_BYTES], char *buf,
			    size_t buf_len)
{
	int ret;

	ret = os_snprintf(buf, buf_len, "%u-%08X-%u",
			  WPA_GET_BE16(dev_type), WPA_GET_BE32(&dev_type[2]),
			  WPA_GET_BE16(&dev_type[6]));
	if (ret < 0 || (unsigned int) ret >= buf_len)
		return NULL;

	return buf;
}

/*
 * Read interface names and types and store them
 * Sample string: ath0@wifi0&lan:WLAN,ath1@wifi1&lan:WLAN
 * return 0 for sucess, else for error
 */
static int apac_config_interfaces(char *buf, /* input */
        apacBool_e is1905Interface, /* input */
        apacHyfi20Data_t *pData/* output */ )
{
    const int TOKEN_LEN = IFNAMSIZ * 4; /*Increased the interface spacing token len*/
    char *token, *radioToken, *bridgeToken, *bandToken = NULL;
    char ifList[APAC_MAXNUM_HYIF + 1][TOKEN_LEN];
    int i, j, band = APAC_WIFI_FREQ_INVALID;
#if MAP_ENABLED
    int k;
#endif
    int num_if = splitByToken(buf, APAC_MAXNUM_HYIF, TOKEN_LEN, (char *)ifList, ',');
    apacHyfi20IF_t *pIF = pData->hyif;
    char *typeStr;


    for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
        if (!pIF[j].valid) {
            break;
        }
    }

    for (i = 0; i < num_if; i++) {
        dprintf(MSG_MSGDUMP, "read: %s\n", ifList[i]);

        if (j >= APAC_MAXNUM_HYIF) {
            dprintf(MSG_ERROR, "%s - Can't set interface(%s): out of range! j: %d \n", __func__, ifList[i], j);
            return -1;
        }

        token = strchr(ifList[i], ':');
        if (!token) {
            dprintf(MSG_ERROR, "split token error! string: %s, token: %s\n", ifList[i], token);
            return -1;
        }

        radioToken = strchr(ifList[i], '@');
        bandToken = strchr(ifList[i], '-');
        bridgeToken = strchr(ifList[i], '&');
        /* Sample string: ath0@wifi0&lan:WLAN */
        if (radioToken) {
            os_memcpy(pIF[j].ifName, ifList[i], (radioToken - ifList[i]));
            os_memcpy(pIF[j].radioName, ifList[i] + (radioToken - ifList[i]) + 1, 5);
        }

        if(bandToken && bridgeToken) {
            char bandStr[4] = {0};
            os_memcpy(bandStr, bandToken+1, strlen(bandToken) - strlen(bridgeToken) -1);
            if(bandToken && !strcmp(bandStr, "2")) {
                band = APAC_WIFI_FREQ_2;
            } else if(bandToken && !strcmp(bandStr, "5")){
                band = APAC_WIFI_FREQ_5;
            }
        }

        if (bridgeToken) {
            char networkName[IFNAMSIZ] = {0};
            os_memcpy(networkName, ifList[i] + (bridgeToken - ifList[i]) + 1,
                      strlen(bridgeToken) - strlen(token) - 1);
            snprintf(pIF[j].bridgeName, sizeof(pIF[j].bridgeName), "%s%s", "br-", networkName);
        }

        /* Sample string: eth1:ETHER */
        if (!radioToken && !bridgeToken) {
            os_memcpy(pIF[j].ifName, ifList[i], (token - ifList[i]));
        }

        /* Sample string: eth1&lan:ETHER */
        if (!radioToken && bridgeToken) {
            os_memcpy(pIF[j].ifName, ifList[i], (bridgeToken - ifList[i]));
        }

#if MAP_ENABLED
        if(!bandToken) {
            /* Mark Bridge as Valid if bridge name found in Interface List */
            for (k = 0; k < APAC_MAX_VLAN_SUPPORTED; k++) {
                if (pData->br_guest_list[k].valid || strlen(pData->br_guest_list[k].ifName) == 0) {
                    continue;
                }

                if (strcmp(pIF[j].bridgeName, pData->br_guest_list[k].ifName) == 0) {
                    pData->br_guest_list[k].valid = APAC_TRUE;
                }
            }
        }
#endif

        typeStr = token + 1;

        if (!bandToken && apacHyfi20SetMediaTypeFromStr(typeStr, pData, j) < 0) {
            return -1;
        } else if (apacHyfi20SetMediaTypeFromZeroStr(typeStr, pData, j, band) < 0) {
            return -1;
        }
        pIF[j].is1905Interface = is1905Interface;
        pIF[j].valid = APAC_TRUE;

        j++;
    }

    return 0;
}

/**
 * @brief Handle the interfaces that are marked as not push button
 *        configuration enabled, marking them as such so that PBC
 *        is skipped for them when activating it.
 *
 * @param [in] buf  the list of comma separated interfaces
 * @param [out] pData  the structure being populated
 *
 * @return 0 on success; non-zero on failure
 */
static int apac_config_nonpbc(char *buf, /* input */
        apacHyfi20Data_t *pData/* output */ )
{
    const int TOKEN_LEN = IFNAMSIZ * 4; /*Increased the interface spacing token len*/
    char ifList[APAC_MAXNUM_HYIF][TOKEN_LEN];
    int i, j, numValidIfaces;
    int num_if = splitByToken(buf, APAC_MAXNUM_HYIF, TOKEN_LEN, (char *)ifList, ',');
    apacHyfi20IF_t *pIF = pData->hyif;
    apacBool_e found;

    for (numValidIfaces = 0; numValidIfaces < APAC_MAXNUM_HYIF; numValidIfaces++) {
        if (!pIF[numValidIfaces].valid) {
            break;
        }
    }

    for (i = 0; i < num_if; i++) {
        dprintf(MSG_MSGDUMP, "Recording %s as non-PBC\n", ifList[i]);

        // Find the matching interface (if any) and mark it as non-PBC.
        found = APAC_FALSE;
        for (j = 0; j < numValidIfaces; ++j) {
            if (strncmp(pIF[j].ifName, ifList[i], IFNAMSIZ) == 0) {
                pIF[j].nonPBC = APAC_TRUE;
                found = APAC_TRUE;
                break;
            }
        }

        if (!found) {
            dprintf(MSG_ERROR, "%s: Failed to find interface: %s\n",
                    __func__, ifList[i]);
            return -1;
        }
    }

    return 0;
}


/* breaks up a configuration input line:
 *      -- empty lines, or with only a #... comment result in no error
 *              but result in return of empty string.
 *      -- lines of form tag=value are broken up; whitespace before
 *              and after tag and before and after value is discarded,
 *              but otherwise retained inside of value.
 *      -- other lines result in NULL return.
 *
 *      The tag pointer is the return value.
 */
char * apac_config_line_lex(
        char *buf,      /* input: modified as storage for results */
        char **value_out        /* output: pointer to value (null term) */
        )
{
        char *pos;
        char *value;

        /* Trim leading whitespace, including comment lines */
        for (pos = buf; ; pos++) {
                if (*pos == 0)  {
                        *value_out = pos;
                        return pos;
                }
                if (*pos == '\n' || *pos == '\r' || *pos == '#') {
                        *pos = 0;
                        *value_out = pos;
                        return pos;
                }
                buf = pos;
                if (is_char_significant(pos)) break;
        }
        while ( is_char_significant(pos) && *pos != '=') pos++;
        if (*pos == '=') {
                *pos++ = 0;     /* null terminate the tag */
                *value_out = value = pos;
        } else {
                return NULL;
        }
        /* Trim trailing whitepace. Spaces inside of a value are allowed,
         * as are other arbitrary non-white text, thus no comments on
         * end of lines.
         */
        for (pos += strlen(pos); --pos >= value; ) {
                if (is_char_significant(pos)) break;
                *pos = 0;
        }
        return buf;
}

/* apply a configuration line: for wsplcd.conf
 */
static int apac_config_apply_line(
        apacHyfi20Data_t* pData,
        char *tag,
        char *value,
        int line       /* for diagnostics */
        )
{
    apacHyfi20Config_t *pConfig = &pData->config;
    struct wps_config *pWpsConfig = pConfig->wpsConf;
    /*HyFi 1.0 compatability*/
    WSPLCD_CONFIG *hyfi10Config = &HYFI20ToHYFI10(pData)->wsplcConfig;
#if MAP_ENABLED
    apacMapData_t *mapData = HYFI20ToMAP(pData);
#endif

    dprintf(MSG_MSGDUMP, "%s, tag: %s, value: %s\n", __func__, tag, value);

    if (strcmp(tag, "role") == 0) {
        apacHyfi20Role_e role;
        role = atoi(value);
        pConfig->role = role;
    }
    else if (strcmp (tag, "designated_pb_ap") == 0) {
        pConfig->designated_pb_ap_enabled = (atoi(value) == 0 ? APAC_FALSE : APAC_TRUE);
    }
    else if (strcmp(tag, "debug_level") == 0) {
        pConfig->debug_level = atoi(value);
        debug_level = pConfig->debug_level;
    } else if (strcmp(tag, "bridge") == 0) {
        strlcpy((pData->bridge).ifName, value, IFNAMSIZ);
#if MAP_ENABLED
        strlcpy(mapData->br_names[0], value+3, IFNAMSIZ);
        dprintf(MSG_MSGDUMP, "%s, tag: %s, network: %s\n", __func__, tag, mapData->br_names[0]);
#endif
    } else if (strcmp(tag, "cfg_changed") == 0) {
        pConfig->cfg_changed = atoi(value);
    } else if (strcmp(tag, "cfg_apply_timeout") == 0) {
        pConfig->cfg_apply_timeout = atoi(value);
        apac_cfg_apply_interval = pConfig->cfg_apply_timeout;
    } else if (strcmp(tag, "cfg_restart_long_timeout") == 0) {
        pConfig->cfg_restart_long_timeout = atoi(value);
        apac_cfg_restart_long_interval = pConfig->cfg_restart_long_timeout;
    } else if (strcmp(tag, "cfg_restart_short_timeout") == 0) {
        pConfig->cfg_restart_short_timeout = atoi(value);
        apac_cfg_restart_short_interval = pConfig->cfg_restart_short_timeout;
    }
    else if (strncmp(tag, "1905Interfaces", 14) == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_interfaces(value, APAC_TRUE, pData) < 0) {
            goto failure;
        }
    }
    else if (strcmp(tag, "Non1905InterfacesWlan") == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_interfaces(value, APAC_FALSE, pData) < 0) {
            goto failure;
        }
    }
    else if (strncmp(tag, "ZeroWlanInterfaces", 18) == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_interfaces(value, APAC_FALSE, pData) < 0) {
            goto failure;
        }
    }
    else if (strcmp(tag, "NonPBCInterfaces") == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_nonpbc(value, pData) < 0) {
            goto failure;
        }
    }
    else if (strcmp(tag, "WPS_method") == 0) {
        if (strncmp(value, "M2", 2) == 0) {
            pConfig->wps_method = APAC_WPS_M2;
        }
        else {
            pConfig->wps_method = APAC_WPS_M8;
        }
    }
    else if (strcmp(tag, "config_station") == 0) {
        if (strncmp(value, "yes", 3) == 0) {
            pConfig->config_sta = APAC_TRUE;
        }
        else {
            pConfig->config_sta = APAC_FALSE;
        }
    }
    else if (strcmp(tag, "ssid_suffix") == 0) {
        if(strlcpy(pConfig->ssid_suffix, value, sizeof(pConfig->ssid_suffix)) >= sizeof(pConfig->ssid_suffix)) {
            dprintf(MSG_ERROR, "%s, ssid_suffix buffer overflow", __func__);
            goto failure;
        }
    }
    else if (strcmp(tag, "1905Nwkey") == 0) {
        if(strlcpy(pConfig->ucpk, value, sizeof(pConfig->ucpk)) >= sizeof(pConfig->ucpk)) {
            dprintf(MSG_ERROR, "%s, ucpk buffer overflow", __func__);
            goto failure;
        }
    }
    else if (strcmp(tag, "ucpk_salt") == 0) {
        if(strlcpy(pConfig->salt, value, sizeof(pConfig->salt)) >= sizeof(pConfig->salt)) {
            dprintf(MSG_ERROR, "%s, salt buffer overflow", __func__);
            goto failure;
        }
    }
    else if (strcmp(tag, "wpa_passphrase_type") == 0) {
        pConfig->wpa_passphrase_type = atoi(value);
    }
    else if (strcmp(tag, "APCloning") == 0) {
        pConfig->hyfi10_compatible = atoi(value);
    }
    else if (strcmp(tag, "search_timeout") == 0) {
        pConfig->search_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_session_timeout") == 0) {
        pConfig->wps_session_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_retransmission_timeout") == 0) {
        pConfig->wps_retransmit_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_per_message_timeout") == 0) {
        pConfig->wps_per_msg_to = atoi(value);
    }
    else if (strcmp(tag, "band_sel_enable") == 0) {
        pConfig->band_sel_enabled = atoi(value);
    }
    else if (strcmp(tag, "band_choice") == 0) {
        if (strncmp(value, "5G", 2) == 0) {
            pConfig->band_choice = APAC_WIFI_FREQ_5;
        }
        else if (strncmp(value, "2G", 2) == 0) {
            pConfig->band_choice = APAC_WIFI_FREQ_2;
        }
    }
    else if (strcmp(tag, "rm_collect_timeout") == 0) {
        pConfig->rm_collect_to = atoi(value);
    }
    else if (strcmp(tag, "deep_clone_enable") == 0) {
        pConfig->deep_clone_enabled = atoi(value);
    }
    else if (strcmp(tag, "deep_clone_no_bssid") == 0) {
        pConfig->deep_clone_no_bssid = atoi(value);
    }
    else if (strcmp(tag, "manage_vap_ind") == 0) {
        pConfig->manage_vap_ind = atoi(value);
    }
    else if (strcmp(tag, "wait_wifi_config_secs_other") == 0) {
        pConfig->wait_wifi_config_secs_other = atoi(value);
    }
    else if (strcmp(tag, "wait_wifi_config_secs_first") == 0) {
        pConfig->wait_wifi_config_secs_first = atoi(value);
    }
    else if (strcmp(tag, "prefered_low_channel") == 0) {
        pConfig->prefered_low_channel = atoi(value);
    }
    else if (strcmp(tag, "prefered_high_channel") == 0) {
        pConfig->prefered_high_channel = atoi(value);
    }
    else if (strcmp(tag, "prefered_6g_channel") == 0) {
        pConfig->prefered_6g_channel = atoi(value);
    }
    /* attributes for wps_config */
    else if (strcmp(tag, "version") == 0) {
        pWpsConfig->version = strtoul(value, NULL, 16);
    } else if (strcmp(tag, "uuid") == 0) {
        struct wps_config *wps = pWpsConfig;
        if (hexstr2bin(value, wps->uuid, SIZE_16_BYTES) ||
                value[SIZE_16_BYTES * 2] != '\0') {
            dprintf(MSG_ERROR, "Line %d: Invalid UUID '%s'.", line, value);
            goto failure;
        }
        wps->uuid_set = 1;
    }
    else if (strcmp(tag, "config_methods") == 0) {
        //printf("strtoul: %lu\n", strtoul(value, NULL, 16));

        //FIXME pWpsConfig->config_methods = 0; //strtoul(value, NULL, 16);
    }
    else if (strcmp(tag, "manufacturer") == 0) {
        if (pWpsConfig->manufacturer)
            free(pWpsConfig->manufacturer);
#if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->manufacturer_len = 64;        /* wps spec */
        if (((pWpsConfig->manufacturer = os_zalloc(64+1))) == NULL)
            goto failure;
        strlcpy(pWpsConfig->manufacturer, value, 64 + 1);
#else   /* original */
        if ((pWpsConfig->manufacturer = strdup(value)) == NULL)
            goto failure;
        pWpsConfig->manufacturer_len = strlen(pWpsConfig->manufacturer);
#endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "model_name") == 0) {
        if (pWpsConfig->model_name)
            free(pWpsConfig->model_name);
#if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->model_name_len = 32;  /* wps spec */
        if ((pWpsConfig->model_name = os_zalloc(32+1)) == NULL)
            goto failure;
        strlcpy(pWpsConfig->model_name, value, 32 + 1);
#else   /* original */
        if ((pWpsConfig->model_name = strdup(value)) == NULL)
            goto failure;
        pWpsConfig->model_name_len = strlen(pWpsConfig->model_name);
#endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "model_number") == 0) {
        if (pWpsConfig->model_number)
            free(pWpsConfig->model_number);
#if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->model_number_len = 32;        /* wps spec */
        if ((pWpsConfig->model_number = os_zalloc(32+1)) == NULL)
            goto failure;
        strlcpy(pWpsConfig->model_number, value, 32 + 1);
#else   /* original */
        if ((pWpsConfig->model_number = strdup(value)) == NULL)
            goto failure;
        pWpsConfig->model_number_len = strlen(pWpsConfig->model_number);
#endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "serial_number") == 0) {
        if (pWpsConfig->serial_number)
            free(pWpsConfig->serial_number);
#if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->serial_number_len = 32;       /* wps spec */
        if ((pWpsConfig->serial_number = os_zalloc(32+1)) == NULL)
            goto failure;
        strlcpy(pWpsConfig->serial_number, value, 32 + 1);
#else   /* original */
        if ((pWpsConfig->serial_number = strdup(value)) == NULL)
            goto failure;
        pWpsConfig->serial_number_len = strlen(pWpsConfig->serial_number);
#endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "device_type") == 0) {
        if (wps_dev_type_str2bin(value, pWpsConfig->prim_dev_type))
            goto failure;
    } else if (strcmp(tag, "device_name") == 0) {
        if (pWpsConfig->dev_name)
            free(pWpsConfig->dev_name);
#if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->dev_name_len = 32;
        if ((pWpsConfig->dev_name = os_zalloc(32+1)) == NULL)
            goto failure;
        strlcpy(pWpsConfig->dev_name, value, 32 + 1);
#else   /* original */
        if ((pWpsConfig->dev_name = strdup(value)) == NULL)
            goto failure;
        pWpsConfig->dev_name_len = strlen(pWpsConfig->dev_name);
#endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "os_version") == 0) {
        //pWpsConfig->os_version = strtoul(value, NULL, 16);
        //printf("osv: %lu\n", strtoul(value, NULL, 16)); //pWpsConfig->os_version);
    } else if (strcmp(tag, "clone_timeout") == 0) {  /*HyFi 1.0 compatability*/
        hyfi10Config->clone_timeout = atoi(value);
    } else if (strcmp(tag, "walk_timeout") == 0) {
        hyfi10Config->walk_timeout = atoi(value);
    } else if (strcmp(tag, "repeat_timeout") == 0) {
        hyfi10Config->repeat_timeout = atoi(value);
    } else if (strcmp(tag, "internal_timeout") == 0) {
        hyfi10Config->internal_timeout = atoi(value);
    } else if (strcmp(tag, "button_mode") == 0) {
        int mode;
        mode = atoi(value);
        if (mode != WSPLC_ONE_BUTTON && mode != WSPLC_TWO_BUTTON)
        {
            dprintf(MSG_ERROR,"INVALID button mode (%s)specified, exiting\n", value);
            goto failure;
        }
        hyfi10Config->button_mode = mode;
    } else if (strcmp(tag, "atf_config_en") == 0) {
        pConfig->atf_config_enabled = (atoi(value) == 0 ? APAC_FALSE : APAC_TRUE);
        dprintf(MSG_INFO,"atf_config set to %d \n", pConfig->atf_config_enabled);
    } else if (strcmp(tag, "TrafficSeparationEnabled") == 0) {
       pConfig->traffic_separation_enabled = atoi(value);
    }
#if MAP_ENABLED
    else if (strcmp(tag, "MapEnable") == 0) {
        mapData->vEnabled = atoi(value);
        if( mapData->vEnabled >= APAC_MAP_VERSION_2 ) {
            pWpsConfig->auth_type_flags = WPS_AUTHTYPE_WPA2PSK | WPS_AUTHTYPE_WPA3;
            pWpsConfig->encr_type_flags = WPS_ENCRTYPE_AES;
        }
    } else if (strcmp(tag, "MapMaxBss") == 0) {
        mapData->MapConfMaxBss =  atoi(value);
        if (mapData->MapConfMaxBss > 14) {
            /* Max BSS is 15 and bsta can be on any band */
            mapData->MapConfMaxBss = 14;
        }
    } else if (strcmp(tag, "MapPFCompliant") == 0) {
        mapData->mapPfCompliant = atoi(value);
    } else if (strcmp(tag, "MapConfigServiceEnabled") == 0) {
        mapData->mapConfigServiceEnabled = atoi(value);
    } else if (strcmp(tag, "Map2EnableMboOcePmf") == 0) {
        mapData->r2EnableMboOcePmf = atoi(value);
    } else if (strncmp(tag, "NumberOfVLANSupported", strlen("NumberOfVLANSupported")) == 0) {
        mapData->numVlanSupported = atoi(value);
    }
    else if (strncmp(tag, "bridge1", 7) == 0) {
        strlcpy(pData->br_guest_list[1].ifName, value, IFNAMSIZ);
        strlcpy(mapData->br_names[1], value+3, IFNAMSIZ);
        dprintf(MSG_MSGDUMP, "%s, tag: %s, network: %s\n", __func__, tag, mapData->br_names[1]);
    } else if (strncmp(tag, "bridge2", 7) == 0) {
        strlcpy(pData->br_guest_list[2].ifName, value, IFNAMSIZ);
        strlcpy(mapData->br_names[2], value+3, IFNAMSIZ);
        dprintf(MSG_MSGDUMP, "%s, tag: %s, network: %s\n", __func__, tag, mapData->br_names[2]);
    } else if (strncmp(tag, "bridge3", 7) == 0) {
        strlcpy(pData->br_guest_list[3].ifName, value, IFNAMSIZ);
        strlcpy(mapData->br_names[3], value+3, IFNAMSIZ);
        dprintf(MSG_MSGDUMP, "%s, tag: %s, network: %s\n", __func__, tag, mapData->br_names[3]);
    }
    else if (strncmp(tag, "backhaul", 8) == 0) {
        strlcpy(mapData->br_backhaul, value, IFNAMSIZ);
        dprintf(MSG_MSGDUMP, "%s, tag: %s, network: %s\n", __func__, tag, mapData->br_backhaul);
    } else if (strcmp(tag, "Map2TrafficSepEnabled") == 0) {
        mapData->map2TrafficSepEnabled = atoi(value);
    } else if (strcmp(tag, "MapR1R2MixNoSupport") == 0) {
        mapData->mapR1R2MixNotSupported = atoi(value);
    } else if (strcmp(tag, "MapMaxPriortizationRules") == 0) {
        mapData->mapMaxServicePRules = atoi(value);
    } else if (strcmp(tag, "MapAgentCouterValueUnit") == 0) {
        mapData->mapAgentCounterUnits =  atoi(value);
    } else if (strcmp(tag, "Map2TSSetFromHYD") == 0) {
        mapData->map2TSSetFromHYD = atoi(value);
    } else if (strcmp(tag, "IsZeroBssEnabled") == 0) {
        mapData->isZeroBssEnabled = atoi(value) ? APAC_TRUE : APAC_FALSE;
    }
#endif
    else if (strcmp(tag, "EnableNBTLV") == 0) {
        pConfig->enable_NB_tlv = atoi(value);
    } else if (strcmp(tag, "NBTLVbuff") == 0) {
        pConfig->nbtlvbuff = (char *)malloc(strlen(value)+1);
        if (!pConfig->nbtlvbuff) {
            perror("malloc failed in nbtlvbuff");
            exit(EXIT_FAILURE);
        }
        strlcpy(pConfig->nbtlvbuff, value, strlen(value)+1);
    }
#ifdef SON_MEMORY_DEBUG
    else if (strcmp(tag, "EnableMemDebug") == 0) {
        pConfig->enable_mem_debug = atoi(value);
    } else if (strcmp(tag, "MemDbgReportInterval") == 0) {
        pConfig->report_interval = atoi(value);
    } else if (strcmp(tag, "MemDbgWriteLogToFile") == 0) {
        pConfig->enable_log_write_to_file = atoi(value);
    } else if (strcmp(tag, "MemDbgAuditingOnly") == 0) {
        pConfig->enable_audit_only = atoi(value);
    } else if (strcmp(tag, "MemDbgFreedMemCount") == 0) {
        pConfig->free_tracking_max_entry = atoi(value);
    } else if (strcmp(tag, "MemDbgDisableModule") == 0) {
        pConfig->disable_module = atoi(value);
    } else if (strcmp(tag, "MemDbgEnableFilter") == 0) {
        pConfig->enable_filter = atoi(value);
    } else if (strcmp(tag, "MemDbgFilterFileName") == 0) {
        strlcpy(pConfig->filter_file, optarg, MEM_DBG_FILE_NAME_MAX_LEN);
    }
#endif
    return 0;

failure:
    dprintf(MSG_ERROR, "Config parse failure, line %d\n", line);
    return -1;
}

#ifdef SON_MEMORY_DEBUG
/*
 * @brief Initialize SON Memory debugging library based on input configuration
 *        and start tracking all the dynamic memory allocation
 */
static void apacSonMemoryDebugInitialization(apacHyfi20Data_t *pData)
{
    int lock_fd = -1, flck_ret = -1;
    FILE *filterfileptr = NULL;
    apacHyfi20Config_t *ptrConfig = &pData->config;

    dprintf(MSG_INFO,"Memory Debug Config: EnableMemoryDebug:%d AuditOnly:%d DisableModule:%llu MaxFreeTracking:%d WriteLogToFile:%d EnableFilter:%d ReportInterval:%d\n", ptrConfig->enable_mem_debug, ptrConfig->enable_audit_only, (long long unsigned int)ptrConfig->disable_module, ptrConfig->free_tracking_max_entry, ptrConfig->enable_log_write_to_file, ptrConfig->enable_filter, ptrConfig->report_interval);

    if (ptrConfig->enable_mem_debug != 0) {
        if (strlen(ptrConfig->filter_file) > 0) {
            lock_fd = open(APAC_LOCK_FILE_PATH, O_RDONLY);

            dprintf(MSG_INFO, "Filter File:%s\n", ptrConfig->filter_file);
            if (lock_fd < 0) {
                dprintf(MSG_ERROR, "Failed to open lock file %s \n", APAC_LOCK_FILE_PATH);
            } else {
                if ((flck_ret = flock(lock_fd, LOCK_EX)) == -1) {
                    dprintf(MSG_ERROR, "Failed to flock lock file %s\n", APAC_LOCK_FILE_PATH);
                    close(lock_fd);
                } else {
                    filterfileptr = fopen(ptrConfig->filter_file, "r");
                    if (filterfileptr == NULL)
                        dprintf(MSG_ERROR, "Failed file open %s errornum[%d]\n", ptrConfig->filter_file, errno);
                }
            }
            dprintf(MSG_INFO, "Filter File: %p\n", filterfileptr);
        }

        son_initialize_mem_debug(ptrConfig->enable_mem_debug, ptrConfig->enable_audit_only,
            ptrConfig->disable_module, ptrConfig->free_tracking_max_entry, ptrConfig->enable_log_write_to_file, ptrConfig->enable_filter, filterfileptr);

        if (strlen(ptrConfig->filter_file) > 0) {
            if(lock_fd > 0)
            {
                if (flck_ret == 0){
                    if (flock(lock_fd, LOCK_UN) == 1) {
                        dprintf(MSG_ERROR, "Failed to unlock file %s\n", APAC_LOCK_FILE_PATH);
                    }
                    if (filterfileptr)
                        fclose(filterfileptr);
                    close(lock_fd);
                }
            }
        }
    }
}
#endif


int apac_config_parse_file(apacHyfi20Data_t *pData, const char *fname)
{
    FILE *f;
    char buf[1024] = {0};
    int line = 0;
    int errors = 0;

    int lock_fd = open(APAC_LOCK_FILE_PATH, O_RDONLY);
    if (lock_fd < 0) {
        dprintf(MSG_ERROR, "Failed to open lock file %s\n", APAC_LOCK_FILE_PATH);
        return -1;
    }
    if (flock(lock_fd, LOCK_EX) == -1) {
        dprintf(MSG_ERROR, "Failed to flock lock file %s\n", APAC_LOCK_FILE_PATH);
        close(lock_fd);
        return -1;
    }

    dprintf(MSG_DEBUG, "Reading wsplcd 2.0 configuration file %s ...\n", fname);

    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open configuration file '%s' for reading.\n",
            fname);
        return -1;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        char *tag;
        char *value;

        line++;
        tag = apac_config_line_lex(buf, &value);
        if (tag == NULL) {
            //errors++;
            continue;
        }
        if (*tag == 0)
            continue;        /* empty line */
        if (apac_config_apply_line(pData, tag, value, line)) {
            dprintf(MSG_ERROR, "line %d error in configure file\n", line);
            errors++;
        }
    }
    if (flock(lock_fd, LOCK_UN) == 1) {
        dprintf(MSG_ERROR, "Failed to unlock file %s\n", APAC_LOCK_FILE_PATH);
        errors++;
    }
    close(lock_fd);
    fclose(f);
    if (errors) {
        dprintf(MSG_ERROR,
            "%d errors found in configuration file '%s'\n",
            errors, fname);
    }
    return (errors != 0);
}

void apacHyfi20ConfigInit(apacHyfi20Data_t *ptrData)
{
    apacHyfi20Config_t *ptrConfig = &ptrData->config;
    apacHyfi20IF_t *ptrIF = ptrData->hyif;
    apacHyfi20AP_t *pAP;
    int i, index;
    int num_radio;
#if MAP_ENABLED
    apacMapData_t *map = NULL;
#endif

    apacHyfi20TRACE();
#if MAP_ENABLED
    map = HYFI20ToMAP(ptrData);
#endif

#ifdef SON_MEMORY_DEBUG
    // Postpone memory allocation till config parsing and memory debug feature enabled
    // use local variable temporarily
    struct wps_config localwpsConf;
    ptrConfig->wpsConf = &localwpsConf;
#else
    ptrConfig->wpsConf = os_malloc(sizeof(struct wps_config));
    if (ptrConfig->wpsConf == NULL) {
        dprintf(MSG_ERROR, "Alloc failed!\n");
        return;
    }
#endif
    memset(ptrConfig->wpsConf, 0, sizeof(struct wps_config));

    /* Init MID */
    messageId_init();

    /* Init apacS */
    memset(&apacS, 0, sizeof(apacS));
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        ptrData->ap[i].freq = i;
        apacS.searchMidSent[i].freq = i;
        apacS.searchMidSent[i].nextHistoryIndex = 0;
    }
    apacS.pApacData = ptrData;

    /* Set configuration parameters */
    ptrConfig->role = APAC_REGISTRAR;
    ptrConfig->search_to = APAC_SEARCH_TIMEOUT;
    ptrConfig->pushbutton_to  = APAC_PUSHBUTTON_TIMEOUT;
    ptrConfig->pb_search_to = APAC_PB_SEARCH_TIMEOUT;
    ptrConfig->config_sta = APAC_CONFIG_STA;
    ptrConfig->wps_method = APAC_WPS_METHOD;
    ptrConfig->wps_session_to = APAC_WPS_SESSION_TIMEOUT;
    ptrConfig->wps_retransmit_to = APAC_WPS_RETRANSMISSION_TIMEOUT;
    ptrConfig->wps_per_msg_to = APAC_WPS_MSG_PROCESSING_TIMEOUT;
    ptrConfig->debug_level = MSG_INFO;
    ptrConfig->pbmode_enabled = APAC_FALSE;
    ptrConfig->hyfi10_compatible = APAC_FALSE;
    ptrConfig->band_sel_enabled = APAC_TRUE;
    ptrConfig->band_choice = APAC_WIFI_FREQ_5;
    ptrConfig->rm_collect_to = APAC_RM_COLLECT_TIMEOUT;
    ptrConfig->prefered_low_channel = APAC_Prefered5GLChannel;
    ptrConfig->prefered_high_channel = APAC_Prefered5GHChannel;
    ptrConfig->prefered_6g_channel = APAC_Prefered6GChannel;
    ptrConfig->deep_clone_enabled = APAC_TRUE;
    ptrConfig->deep_clone_no_bssid = APAC_TRUE;
    ptrConfig->manage_vap_ind = APAC_TRUE;
    ptrConfig->designated_pb_ap_enabled = APAC_FALSE;
    ptrConfig->wait_wifi_config_secs_first = APAC_WAIT_WIFI_CONFIG_SECS_FIRST;
    ptrConfig->wait_wifi_config_secs_other = APAC_WAIT_WIFI_CONFIG_SECS_OTHER;
    ptrConfig->atf_config_enabled = APAC_FALSE;
    ptrConfig->atfConf = NULL;

#if MAP_ENABLED
    // MAP V2 default values, its required as we have zero as valid values for these
    map->mapAgentCounterUnits = 0;  // default send it in byte count
    map->mapMaxServicePRules = 0;   // if not configured set it to zero
    map->isZeroBssEnabled = APAC_FALSE;
#endif /* MAP_ENABLED */

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        ptrIF[i].ifIndex = -1;
        ptrIF[i].ifName[0] = '\0';
    }

#if MAP_ENABLED
    for (i = 0; i < APAC_MAX_VLAN_SUPPORTED; i++) {
        ptrData->br_guest_list[i].valid = APAC_FALSE;
        ptrData->br_guest_list[i].ifIndex = -1;
        ptrData->br_guest_list[i].ifName[0] = '\0';
    }
#endif /* MAP_ENABLED */

    /* get configurable paramters, interface and other info from masterd */
    if (apac_config_parse_file(ptrData, g_cfg_file) < 0) {
        dprintf(MSG_ERROR, "parse config file (%s) error!\n", g_cfg_file);
        return;
    }

#ifdef SON_MEMORY_DEBUG
    // Initialize memory debug feature
    apacSonMemoryDebugInitialization(ptrData);

    // allocate memory after memory debug feature initialized
    // so that it is included in tracking
    struct wps_config *ptrwpsConf = os_malloc(sizeof(struct wps_config));
    if (ptrwpsConf == NULL) {
        dprintf(MSG_ERROR, "Alloc failed!\n");
        return;
    }

    memcpy(ptrwpsConf, &localwpsConf, sizeof(struct wps_config));
    ptrConfig->wpsConf = ptrwpsConf;
#endif

    if(ptrConfig->atf_config_enabled == APAC_TRUE)
    {
        dprintf(MSG_INFO, "ATF Configuration Enabled! Parsing ATF configuration File \n\r");
        ptrConfig->atfConf = os_malloc( (sizeof(ATF_REP_CONFIG) * ATF_MAX_REPEATERS) );

        if(ptrConfig->atfConf != NULL)
        {
            if (apac_atf_config_parse_file(ptrData, g_cfg_file) < 0) {
                dprintf(MSG_ERROR, "parse ATF config file (%s) error!\n", g_cfg_file);
                return;
            }
        } else {
            dprintf(MSG_ERROR, "Mem alloc for ATF Config structure failed!!\n\r");
            return;
        }
    }

    /* Now check config_sta: run APAC even if there is only STA (no AP) for a given band */
    if (ptrConfig->config_sta) {
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {

            /* for 1905 STA */
            if (ptrIF[i].valid &&
                ptrIF[i].is1905Interface &&
                ptrIF[i].mediaType == APAC_MEDIATYPE_WIFI &&
                ptrIF[i].wlanDeviceMode == APAC_WLAN_STA)
            {
                /* check if AP is there */
                apacHyfi20WifiFreq_e freq = ptrIF[i].wifiFreq;
                if (freq == APAC_WIFI_FREQ_INVALID)
                    continue;

                pAP = &(ptrData->ap[freq]);

                if (pAP->valid == APAC_FALSE) {
                    dprintf(MSG_INFO, "%s, Band %u has 1905 Station, but not 1905 AP. Enable APAC\n",
                            __func__, freq);
                    pAP->freq = freq;
                    pAP->isAutoConfigured = APAC_FALSE;
                    pAP->vap_index = ptrIF[i].vapIndex;
                    pAP->isStaOnly = APAC_TRUE;
                    pAP->valid = APAC_TRUE;
                }
            }

        }
    }

    /* Check DB band adaptation */
    num_radio = 0;
    index = -1;
    pAP = ptrData->ap;
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (pAP[i].valid) {
            num_radio++;

            if (num_radio == 1)
                index = i;
        }
    }

    if (num_radio < 0 || num_radio > 3) {
        dprintf(MSG_ERROR, "%s, number of radio is %u, invalid\n", __func__, num_radio);
        return;
    }

    /* For single radio, check if it is SB or DB */
    if (num_radio == 1) {
        char liststr[MAXCHANLISTSTRLEN];
        apacBool_e hasWlan2G = APAC_FALSE;
        apacBool_e hasWlan5G = APAC_FALSE;

        if (index == -1) {
            dprintf(MSG_ERROR, "%s, index is not assigned value!\n", __func__);
            return;
        }

        if (pAP[index].isStaOnly == APAC_FALSE) {
            if (apacHyfi20GetWlanBandCapacity(pAP[index].ifName, liststr, sizeof(liststr), &hasWlan2G, &hasWlan5G) < 0) {
                dprintf(MSG_ERROR, "%s, Failed to get Channel Info for %s\n", __func__, pAP[index].ifName);
                return;
            }
        }
        else {  /* Can't find ifName from pAP if band has only STA */
            int j;
            apacBool_e found = APAC_FALSE;

            for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
                if (ptrIF[j].wifiFreq == pAP[index].freq) {
                    found = APAC_TRUE;
                    break;
                }
            }

            if (!found) {
                dprintf(MSG_ERROR, "%s, Can't find IF on Freq %u!\n", __func__, pAP[index].freq);
                return;
            }

            if (apacHyfi20GetWlanBandCapacity(ptrIF[j].ifName, liststr, sizeof(liststr),  &hasWlan2G, &hasWlan5G) < 0) {
                dprintf(MSG_ERROR, "%s, Can't get Channel Info for %s\n", __func__, ptrIF[j].ifName);
                return;
            }
        }

        if (hasWlan2G && hasWlan5G) {
            pAP[index].isDualBand = APAC_TRUE;
            ptrConfig->wlan_chip_cap = APAC_DB;
            dprintf(MSG_DEBUG, "%s, IF %s is dual band\n", __func__, pAP[index].ifName);
        }
        else if (hasWlan2G || hasWlan5G) {
            ptrConfig->wlan_chip_cap = APAC_SB;
        }
        else {
            dprintf(MSG_ERROR, "%s, can't get channel capacity info for AP %s!\n", __func__, pAP[index].ifName);
            return;
        }
    } else if (num_radio >= 2) {
        ptrConfig->wlan_chip_cap = APAC_DBDC;
    }
}

void apacHyfi20ConfigDump(apacHyfi20Data_t *ptrData)
{
    apacHyfi20Config_t *ptrConfig = &ptrData->config;
    apacHyfi20AP_t *ptrAP = ptrData->ap;
    apacHyfi20IF_t *ptrIF = ptrData->hyif;
    //struct wps_config *pWpsConfig = ptrConfig->wpsConf;
    int dumpLevel = MSG_INFO;

    int i;

    dprintf(dumpLevel, "Configuration dump begin\n");
    if (ptrConfig->role == APAC_ENROLLEE) {
        dprintf(dumpLevel, "Device is Enrollee\n");
    }
    else if(ptrConfig->role == APAC_REGISTRAR) {
        dprintf(dumpLevel, "Device is Registrar\n");
    }
    else {
        dprintf(dumpLevel, "Device is neither Registrar nor Enrollee\n");
    }

    dprintf(dumpLevel, "Debug Level: %d\n", ptrConfig->debug_level);
    dprintf(dumpLevel, "WPS method: %s\n", (ptrConfig->wps_method == APAC_WPS_M2 ? "M2" : "M8"));
    dprintf(dumpLevel, "Config Station: %s\n", (ptrConfig->config_sta == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "SSID Suffix: '%s'\n", ptrConfig->ssid_suffix);
    dprintf(dumpLevel, "Search Timeout: %d\n", ptrConfig->search_to);
    dprintf(dumpLevel, "WPS Session Timeout: %d\n", ptrConfig->wps_session_to);
    dprintf(dumpLevel, "WPS Retransmission Timeout: %d\n", ptrConfig->wps_retransmit_to);
    dprintf(dumpLevel, "WPS Per-Message Timeout: %d\n", ptrConfig->wps_per_msg_to);
    dprintf(dumpLevel, "DB Band Adaptation: %s\n", (ptrConfig->band_sel_enabled == APAC_TRUE ? "YES" : "NO"));
    if (ptrConfig->band_sel_enabled) {
        dprintf(dumpLevel, "Preferred Band Choice: %s\n", (ptrConfig->band_choice == APAC_WIFI_FREQ_2 ? "2G" : "5G"));
        dprintf(dumpLevel, "Waiting Response Msg Interval: %u\n", ptrConfig->rm_collect_to);
    }
    dprintf(dumpLevel, "Deep Cloning: %s\n", (ptrConfig->deep_clone_enabled == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "Deep Cloning Without BSSID: %s\n", (ptrConfig->deep_clone_no_bssid == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "Manage VAP Independent: %s\n", (ptrConfig->manage_vap_ind == APAC_TRUE ? "YES" : "NO"));

    dprintf(dumpLevel, "1905.1 UCPK: %s\n", ptrConfig->ucpk);
    dprintf(dumpLevel, "1905.1 SALT: %s\n", ptrConfig->salt);
    dprintf(dumpLevel, "Compatiable with Hyfi1.0: %c\n", (ptrConfig->hyfi10_compatible == APAC_TRUE ? 'y':'n'));

#if 0
    dprintf(dumpLevel, "WPS info:\n");
    dprintf(dumpLevel, "version: %x\n", pWpsConfig->version);
    dprintf(dumpLevel, "config_methods: %u\n", pWpsConfig->config_methods);
    dprintf(dumpLevel, "manufacturer: %s\n", pWpsConfig->manufacturer);
    dprintf(dumpLevel, "model_name: %s\n", pWpsConfig->model_name);
    dprintf(dumpLevel, "model_number: %s\n", pWpsConfig->model_number);
    dprintf(dumpLevel, "serial_number: %s\n", pWpsConfig->serial_number);
    dprintf(dumpLevel, "dev_name: %s\n", pWpsConfig->dev_name);
    dprintf(dumpLevel, "os_version: %s\n", pWpsConfig->os_version);
#endif

#ifdef SON_MEMORY_DEBUG
    dprintf(dumpLevel, "Enable Memory Debug : %d\n", ptrConfig->enable_mem_debug);
    dprintf(dumpLevel, "Enable Auditing only  : %d\n", ptrConfig->enable_audit_only);
    dprintf(dumpLevel, "Disabled Module : %llu\n", (long long unsigned int)ptrConfig->disable_module);
    dprintf(dumpLevel, "Free Tracking Max Entry : %d\n", ptrConfig->free_tracking_max_entry);
    dprintf(dumpLevel, "Enable Log write to file  : %d\n", ptrConfig->enable_log_write_to_file);
    dprintf(dumpLevel, "Enable Filter : %d\n", ptrConfig->enable_filter);
    dprintf(dumpLevel, "Filter file name : %s\n", ptrConfig->filter_file);
    dprintf(dumpLevel, "Report Interval : %d\n", ptrConfig->report_interval);
#endif

    dprintf(dumpLevel, "1905 AP info:\n");
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (!ptrAP[i].valid)
            continue;

        dprintf(dumpLevel, "AP%d freq: %d, vap_index: %u\n", i, ptrAP[i].freq, ptrAP[i].vap_index);

        if (ptrConfig->role == APAC_ENROLLEE) {
            continue;
        }
    }
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!ptrIF[i].valid)
            continue;

        dprintf(dumpLevel, "Interface%d name: %s, 1905IF: %c \tmediatype: %u\n",
                            i, ptrIF[i].ifName, (ptrIF[i].is1905Interface ? 'y' : 'n'),
                            ptrIF[i].mediaType);
        if (strncmp(ptrIF[i].ifName, "ath", 3) == 0) {
            dprintf(dumpLevel, "\t\tWLAN device mode: %u \tfreq: %u \tvapIndex: %u\n",
                                ptrIF[i].wlanDeviceMode, ptrIF[i].wifiFreq, ptrIF[i].vapIndex);
        }
        else {
            dprintf(dumpLevel, "\n");
        }
    }

    dprintf(dumpLevel, "Configuration dump end\n");
}

void apacHyfi20CmdLogFileModeName(int argc, char **argv)
{
    int c;
    char* confExt;

    //init the global buff
    strlcpy(g_log_file_path, APAC_LOG_FILE_PATH, sizeof(g_log_file_path));

    for (;;) {
        c = getopt(argc, argv, "f:r:l:o:c:i:m:M:wa");
        if (c < 0)
            break;
        switch (c) {
        case 'w':
            /* Write debug log to file */
            logFileMode = APAC_LOG_FILE_TRUNCATE;
            break;
        case 'a':
            /* Append debug log to file */
            logFileMode = APAC_LOG_FILE_APPEND;
            break;
        case 'c':
            if(strncmp(optarg,"fg80211",7) == 0 ) {
                /*To address wrong file issue when starting in cfg80211 mode*/
                /*Discard -cfg80211 when checking for -c in log mode*/
            } else {
                //convert configure file name into log file name
                strlcpy(g_log_file_path, optarg,  sizeof(g_log_file_path));
                confExt = strstr(g_log_file_path, ".conf");
                if(confExt != NULL) {
                    strlcpy(confExt, ".log", strlen(".conf"));
                }
	    }
            break;
        default:
            /* Handled separately in apacHyfi20CmdConfig */
            break;
        }
    }

    if(logFileMode == APAC_LOG_FILE_APPEND) {
         printf("Append debug log to file: %s\n", g_log_file_path);
    }
    else if(logFileMode == APAC_LOG_FILE_TRUNCATE) {
         printf("Write debug log to file: %s\n", g_log_file_path);
    }
}


void apacHyfi20CmdConfig(apacHyfi20Data_t *pData, int argc, char **argv)
{
    apacHyfi20Config_t *pConfig = &(pData->config);
    char* val = NULL;
    int dlevel;
    int c;
#if MAP_ENABLED
    int custom_map_cfg_file = 0;
#endif
    int custom_cfg_file = 0;

    /* Find if CFG80211 support enabled */
    c = 0;
    pData->isCfg80211=0;

    while(c < argc) {
        if ( streq(argv[argc-1],"-cfg80211")) {
            pData->isCfg80211=1;
            argc--;
            break;
        }
        c++;
    }


    /* command line debug */
    for (;;) {
        c = getopt(argc, argv, "f:r:l:o:c:i:m:M:wa");
        if (c < 0)
            break;
        switch (c) {

        /* send unicast packets from ALL Interfaces. Debug only! */
        case 'f':
            printf("\n\nForward Unicast (Response/WPS) packets from ALL interfaces\n");
            pConfig->sendOnAllIFs = APAC_TRUE;
            break;

        case 'r':
            val = optarg;
            if (strncmp(val, "r", 1) == 0) {
                pConfig->role = APAC_REGISTRAR;
            }
            else if (strncmp(val, "e", 1) == 0) {
                pConfig->role = APAC_ENROLLEE;
            }
            else
            {
                printf("INVALID role (%s)specified, exiting\n", val);
                exit(1);
            }
            break;

        case 'l':
            dlevel = atoi(optarg);
            printf("debug level: %d\n", dlevel);

            if (dlevel < 0 || dlevel > 3) {
                printf("Invalid debug level: %d\n", dlevel);
                debug_level = pConfig->debug_level;
            }
            else {
                printf("change debug level from %d to %d\n", debug_level, dlevel);
                debug_level = dlevel;
            }
            break;

        case 'o':
            val = optarg;
            printf("option: %s\n", val);

            /* Virtually activate Push Button */
            if (strncmp(val, "p", 1) == 0) {
                printf("\n\nEnable Push Button function for wsplcd .... \n");

                pbcHyfi20EventPushButtonActivated(pData);
            }
            else if (strncmp(val, "v", 1) == 0) {
                /* print version */
                printf("wsplcd-2.0 IEEE1905 AP Auto-Configuration.\n");
                printf("Copyright (c) 2011-2012 Qualcomm Atheros, Inc.\n");
                printf("Qualcomm Atheros Confidential and Proprietary.\n");
                printf("All rights reserved.\n");
                printf("Additional copyright information:\n");
                printf("Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.\n");
                printf("Copyright (c) 2002-2007 Jouni Malinen <j@w1.fi> and contributors. All Rights Reserved.\n\n");
            }
            else {
                printf("invalid option: %s\n", val);
            }
            break;
        case 'c':
            /*configuration file path*/
            custom_cfg_file = 1;
            strlcpy(g_cfg_file, optarg, APAC_CONF_FILE_NAME_MAX_LEN);
            break;
#if MAP_ENABLED
        case 'm':
            // Multi-AP AL-specific BSS instantiation profiles
            custom_map_cfg_file = 1;
            g_map_cfg_file_format = APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC;
            strlcpy(g_map_cfg_file, optarg, APAC_CONF_FILE_NAME_MAX_LEN);
            break;
        case 'M':
            // Multi-AP generic BSS instantiation profiles
            custom_map_cfg_file = 1;
            g_map_cfg_file_format = APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC;
            strlcpy(g_map_cfg_file, optarg, APAC_CONF_FILE_NAME_MAX_LEN);
            break;
#endif
#if SON_ENABLED
        case 'i':
            //Network mode (private or Guest)
            g_wsplcd_instance = atoi(optarg);
            if(g_wsplcd_instance >= APAC_WSPLCD_INSTANCE_INVALID) {
                dprintf(MSG_DEBUG, "Invalid wsplcd instance :%d, switched to default\n", g_wsplcd_instance);
                g_wsplcd_instance = APAC_WSPLCD_INSTANCE_PRIMARY;
            }
            break;
#endif
        case 'w':
        case 'a':
            /* Handled separately in apacHyfi20CmdLogFileMode */
            break;
        default:
            printf("Invalid argument: %c\n", c);
            break;
        }
    }

    if (custom_cfg_file == 0) {
        /* use default config file if not specified by -c option */
        strlcpy(g_cfg_file, APAC_CONF_FILE_PATH, APAC_CONF_FILE_NAME_MAX_LEN);
    }

#if MAP_ENABLED
    if (custom_map_cfg_file == 0) {
        /* use default config file with AL-specific format (for backwards
         * compatibility) if not specified by -m/-M options */
        g_map_cfg_file_format = APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC;
        strlcpy(g_map_cfg_file, APAC_MAP_CONF_FILE, APAC_CONF_FILE_NAME_MAX_LEN);
    }
#endif

    if (optind != argc)
        return;

}

int apacHyfi20Init(apacHyfi20Data_t *pData) {
    s32 i;
    apacHyfi20IF_t *pIF = pData->hyif;

    apacHyfi20TRACE();

    if (apacHyfi20InitDeviceInfo(pData) < 0) {
        perror("InitDeviceInfo");
        return -1;
    }

    /* bridge */
    memcpy(pData->alid, pData->bridge.mac_addr, ETH_ALEN);

    pData->nlSock = apacHyfi20InitNLSock(pData);
    if (pData->nlSock < 0) {
        perror("InitNLSock");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "nl sock: %d\n", pData->nlSock);

    eloop_register_read_sock(pData->nlSock, pbcHyfi20GetNLMsgCB, pData, NULL);

    pData->pipeFd = apacHyfi20InitPipeFd();
    if (pData->pipeFd < 0) {
        perror("InitPipe");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "pipe FD: %d\n", pData->pipeFd);
    eloop_register_read_sock(pData->pipeFd, pbcHyfi20GetPipeMsgCB, pData, NULL);

#ifdef ENABLE_PLC
    pData->unPlcSock = apacHyfi20InitPlcUnixSock(pData);
    if (pData->unPlcSock < 0) {
        perror("Init Unix Sock for PLC");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "Unix Sock for PLC: %d\n", pData->unPlcSock);
    eloop_register_read_sock(pData->unPlcSock, pbcHyfi20GetUnixSockPlcMsgCB, pData, NULL);
#endif

    pData->bridge.sock = apacHyfi20InitIEEE1905Sock(pData->bridge.ifName);
    if (pData->bridge.sock < 0) {
        perror("InitIEEE1905Sock for bridge");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "bridge(hy0) sock: %d\n", pData->bridge.sock);
    eloop_register_read_sock(pData->bridge.sock, apacHyfi20GetIEEE1905PktCB, pData, NULL);

    /* 1905 interfaces */
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!pIF[i].valid || !pIF[i].is1905Interface) {
            continue;
        }

        pIF[i].sock = apacHyfi20InitIEEE1905Sock(pIF[i].ifName);
        if (pIF[i].sock < 0) {
            perror("InitIEEE1905Sock for tx");
            return -1;
        }
        dprintf(MSG_MSGDUMP, "if: %s, ifIndex: %d, sock: %d\n", pIF[i].ifName, pIF[i].ifIndex, pIF[i].sock);
    }

#if MAP_ENABLED
    dprintf(MSG_MSGDUMP, "%s: Map Version Enabled %d, Map Config Serivce Enabled %d\n", __func__,
            apacHyfiMapIsEnabled(HYFI20ToMAP(pData)),
            apacHyfiMapConfigServiceEnabled(HYFI20ToMAP(pData)));
    if (apacHyfiMapIsEnabled(HYFI20ToMAP(pData)) >= APAC_MAP_VERSION_3 &&
        apacHyfiMapConfigServiceEnabled(HYFI20ToMAP(pData))) {
        dprintf(MSG_MSGDUMP, "CTRL sock not required for DPP\n");
    } else {
        if (apac_ctrl_init(pData) < 0) {
            dprintf(MSG_ERROR, "CTRL sock failed\n");
            return -1;
        }
    }
#else
    if (apac_ctrl_init(pData) < 0)
    {
        dprintf(MSG_ERROR, "CTRL sock failed\n");
        return -1;
    }
#endif

    /* init sess data */
    pData->sess_list = NULL;
    pData->wpas = NULL;

    /* init WPS config*/
    if (!pData->config.wpsConf->uuid_set)
    {
        /*generate a uuid in rough compliance with rfc4122 based on mac address*/
        struct wps_config *wps = pData->config.wpsConf;
        memset(wps->uuid, 0, sizeof(wps->uuid));
        wps->uuid[6] = (1<<4);
        memcpy(wps->uuid+SIZE_UUID-6, pData->alid, 6);
        wps->uuid_set = 1;
    }

    /* init mib handle */
    pData->wifiConfigHandle = apac_mib_get_wifi_config_handle();
    pData->wifiConfigWaitSecs = 0;
    if (!pData->wifiConfigHandle)
    {
        dprintf(MSG_ERROR, "Get mib storage handle failed\n");
        return -1;
    }

    return 0;
}


int apacHyfi20InitDeviceInfo(apacHyfi20Data_t *ptrData) {
    s32 i;
    struct ifreq ifr;
    int sock = -1;
    apacHyfi20IF_t* ptrIF = ptrData->hyif;

    apacHyfi20TRACE();

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!ptrIF[i].is1905Interface) {
            ptrIF[i].ifIndex = -1;
            continue;
        }

        dprintf(MSG_MSGDUMP, "IF%d: %s\n", i, ptrIF[i].ifName);

        /* Get interface mac address */
        sock = socket(PF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket[PF_INET,SOCK_DGRAM]");
            return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ptrIF[i].ifName, sizeof(ptrIF[i].ifName));

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl[SIOCGIFHWADDR]");
            close(sock);
            return -1;
        }

        memcpy(ptrIF[i].mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        dprintf(MSG_MSGDUMP, "TxIF mac: ");
        printMac(MSG_MSGDUMP, ptrIF[i].mac_addr);

        /* get interface index */
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ptrIF[i].ifName, sizeof(ptrIF[i].ifName));
        if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
            perror("ioctl(SIOCGIFINDEX)");
            close (sock);
            return -1;
        }
        ptrIF[i].ifIndex = ifr.ifr_ifindex;
        dprintf(MSG_MSGDUMP,"TX ifname %s, ifindex %d\n", ptrIF[i].ifName, ptrIF[i].ifIndex);

        close (sock);
    }

    /* Get ALID (hy0)  and related info */
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket[PF_INET,SOCK_DGRAM]");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ptrData->bridge.ifName, sizeof(ptrData->bridge.ifName));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl[SIOCGIFHWADDR]");
        close(sock);
        return -1;
    }

    memcpy(ptrData->bridge.mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    dprintf(MSG_MSGDUMP, "BridgeIF mac: ");
    printMac(MSG_MSGDUMP, ptrData->bridge.mac_addr);

    /* get interface index */
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ptrData->bridge.ifName, sizeof(ptrData->bridge.ifName));
    if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close (sock);
        return -1;
    }
    ptrData->bridge.ifIndex = ifr.ifr_ifindex;
    dprintf(MSG_MSGDUMP,"TX ifname %s, ifindex %d\n", ptrData->bridge.ifName, ptrData->bridge.ifIndex);

    close (sock);

    return 0;
}

#ifdef ENABLE_PLC
int apacHyfi20InitPlcUnixSock() {
    int plcsock_len;
    struct sockaddr_un sockaddr_un = {
        AF_UNIX,
        WSPLCD_PLC_SOCKET_SERVER
    };
    signed Fd = -1;

    if ((Fd = socket (AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        perror("Socket Creation of Unix Socket Failed");
        return (-2);
    }
    memset(&sockaddr_un, 0, sizeof(sockaddr_un));
    sockaddr_un.sun_family = AF_UNIX;
    if(strlcpy(sockaddr_un.sun_path, WSPLCD_PLC_SOCKET_SERVER, sizeof(sockaddr_un.sun_path))
             >= sizeof(sockaddr_un.sun_path)) {
        perror("Socket Creation of Unix Socket Failed because of buffer overflow");
        return (-2);
    }

    plcsock_len = strlen(WSPLCD_PLC_SOCKET_SERVER);
    sockaddr_un.sun_path[plcsock_len] = '\0';
    if (unlink (sockaddr_un.sun_path)) {
        if (errno != ENOENT) {
            perror("Unlink of Unix Socket File Failed");
            return (-1);
        }
    }
    if (bind (Fd, (struct sockaddr *)(&sockaddr_un), sizeof (sockaddr_un)) == -1) {
        perror("Bind on Unix Socket Failed");
        return (-3);
    }
    if (chmod (sockaddr_un.sun_path, 0666) == -1) {
        perror("chmod on Unix Socket File Failed");
        return (-4);
    }
    return (Fd);
}
#endif

int apacHyfi20InitNLSock() {
    struct sockaddr_nl local;
    s32 sock;

    /* Initialize netlink socket */
    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind(netlink)");
        close(sock);
        return -1;
    }

    return sock;
}

int apacHyfi20InitPipeFd() {
    int err;
    int fd;

    // If the pipe does not exist or it is a regular file instead of a pipe,
    // create it. Otherwise, just open it. This allows wsplcd to be restarted
    // while reusing the existing pipe, which helps simplify other processes
    // which may want to keep a handle open to the pipe even during the restart.
    struct stat statbuf;
    char namePipe[APAC_PIPE_NAME_MAX_LEN] = {0};

    memset(&statbuf, 0, sizeof(statbuf));

    if(g_wsplcd_instance == APAC_WSPLCD_INSTANCE_PRIMARY) {
        strlcpy(namePipe,APAC_PIPE_PATH,sizeof(namePipe));
    } else {
        strlcpy(namePipe,APAC_PIPE_SECONDARY_PATH,sizeof(namePipe));
    }
    if (stat(namePipe, &statbuf) != 0 || !S_ISFIFO(statbuf.st_mode)) {
        unlink(namePipe);
        err = mkfifo(namePipe, 0666);
        if ((err == -1) && (errno != EEXIST)) {
            return -1;
        }
    }

    fd = open(namePipe, O_RDWR);

    if (fd == -1) {
        perror("open(pipe)");
        return -1;
    }

    return fd;
}

/* Initialize receiving/transmission socket */
int apacHyfi20InitIEEE1905Sock(char *ifname) {
    struct ifreq ifr;
    struct sockaddr_ll ll;
    struct packet_mreq mreq;
    s32 sock;
    u8 multicast_addr[ETH_ALEN] = APAC_MULTICAST_ADDR;
    int err;
    int optval = 0;
    socklen_t socklen = sizeof(optval);
    memset(&optval, 0, socklen);

    sock = socket(PF_PACKET, SOCK_RAW, htons(APAC_ETH_P_IEEE1905));
    if (sock < 0) {
        perror("socket(PF_ACKET)");
        return -1;
    }

    memset(&ifr, 0,sizeof(struct ifreq));
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl[SIOCGIFINDEX]");
        close(sock);
        return -1;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(APAC_ETH_P_IEEE1905);
    if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
        perror("bind[PF_PACKET]");
        close(sock);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = ETH_ALEN;
    memcpy(mreq.mr_address, multicast_addr, mreq.mr_alen);

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0 )
    {
        perror("setsockopt[SOL_SOCKET, PACKET_ADD_MEMBERSHIP]");
        close(sock);
        return -1;
    }

    err = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, &socklen);
    if (err < 0) {
        dprintf(MSG_ERROR, "%s getsockopt SO_RCVBUF failed\n", __func__);
    } else {
        dprintf(MSG_DEBUG, "%s ifname %s sock %d get SO_RCVBUF %d\n", __func__, ifname, sock, optval);
        optval *= RCVBUF_MULT_FACTOR;
        err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        if (err < 0) {
            dprintf(MSG_ERROR, "%s setsockopt SO_RCVBUF failed\n", __func__);
        } else {
            dprintf(MSG_DEBUG, "%s ifname %s sock %d set SO_RCVBUF %d\n", __func__, ifname, sock, optval);
        }
    }

    dprintf(MSG_MSGDUMP, "ifname: %s, ifIndex: %d, sock: %d\n", ifname, ifr.ifr_ifindex, sock);

    return sock;
}

int apacHyfi20ResetIeee1905TXSock(apacHyfi20IF_t *pIF)
{

    dprintf(MSG_ERROR, "Interface[%s] changed, reset ieee1905.1 socket \n", pIF->ifName);

    if (!pIF->valid || !pIF->is1905Interface) {
        return -1;
    }

    if (pIF->sock > 0 )
        close(pIF->sock);

    pIF->sock = apacHyfi20InitIEEE1905Sock(pIF->ifName);
    if (pIF->sock < 0) {
        perror("InitIEEE1905Sock for tx");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "if: %s, ifIndex: %d, sock: %d\n", pIF->ifName, pIF->ifIndex, pIF->sock);

    return 0;
}

static void apacHyfi20Ieee1905RXSockTimeout(void *eloop_ctx, void *timeout_ctx)
{
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20ResetIeee1905RXSock(pData);
}

int apacHyfi20ResetIeee1905RXSock(apacHyfi20Data_t *pData)
{
    if (pData->bridge.sock > 0 )
    {
        eloop_unregister_read_sock(pData->bridge.sock);
        close (pData->bridge.sock);
        pData->bridge.sock = -1;
    }

    pData->bridge.sock = apacHyfi20InitIEEE1905Sock(pData->bridge.ifName);
    if (pData->bridge.sock < 0) {
        perror("InitIEEE1905Sock for bridge");

        /*RX socket broken due to linux bridge changing, retry it later*/
        eloop_register_timeout(1, 0, apacHyfi20Ieee1905RXSockTimeout, pData, NULL);
        return -1;
    }

    eloop_register_read_sock(pData->bridge.sock, apacHyfi20GetIEEE1905PktCB, pData, NULL);
    return 0;
}

int apacHyfi20ResetPipeFd(apacHyfi20Data_t *pData)
{
    if (pData->pipeFd > 0 )
    {
        eloop_unregister_read_sock(pData->pipeFd);
        close (pData->pipeFd);
    }

    pData->pipeFd = apacHyfi20InitPipeFd();
    if (pData->pipeFd < 0) {
        perror("InitPipe");
        return -1;
    }
    dprintf(MSG_INFO, "Reset pipe FD: %d\n", pData->pipeFd);
    eloop_register_read_sock(pData->pipeFd, pbcHyfi20GetPipeMsgCB, pData, NULL);

    return 0;
}

/* destroy sockets */
void apacHyfi20DeinitSock(apacHyfi20Data_t *ptrData) {
    s32 i;
    apacHyfi20IF_t *pIF = ptrData->hyif;
    apacHyfi20Config_t *pConfig = &ptrData->config;

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (pIF[i].sock > 0)
            close (pIF[i].sock);
    }

    if (ptrData->bridge.sock > 0)
        close(ptrData->bridge.sock);

    if (ptrData->nlSock > 0)
        close(ptrData->nlSock );

    if (ptrData->pipeFd > 0)
        close(ptrData->pipeFd);

    if (ptrData->unPlcSock > 0)
        close(ptrData->unPlcSock);

    if (pConfig->wpsConf) {
        os_free(pConfig->wpsConf);
        pConfig->wpsConf = NULL;
    }

    if (pConfig->atfConf) {
        os_free(pConfig->atfConf);
        pConfig->atfConf = NULL;
    }

    if (ptrData->wifiConfigHandle) {
        apac_mib_apply_wifi_configuration(ptrData->wifiConfigHandle, APAC_FALSE);
    }

    apac_ctrl_deinit(ptrData);
}
