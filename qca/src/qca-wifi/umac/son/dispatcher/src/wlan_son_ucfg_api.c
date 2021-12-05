/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*/

/*
*This File provides framework user space ioctl handling for SON.
*/

#include <ieee80211_cfg80211.h>
#include "../../core/src/wlan_son_internal.h"
#include "wlan_son_ucfg_api.h"
#include <wlan_son_utils_api.h>
#include <wlan_son_pub.h>

#if QCA_SUPPORT_SON
#include <ieee80211_vap.h>
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif

#include <wlan_utility.h>
#include <wlan_cfg80211.h>

#define REPLY_SKB_SIZE ((2*sizeof(u_int32_t)) + NLMSG_HDRLEN)

/**
 * cfg80211_reply_son : reply skb to the user space
 * @wiphy: pointer to wiphy object
 * @length : data length
 * @data : point to data
 * @flag : flag value
 * return 0 on success and -1 on failure
 */
int
cfg80211_reply_son(struct wiphy *wiphy, int length, void *data, u_int32_t flag)
{
    struct sk_buff *reply_skb = NULL;
    QDF_STATUS status;

    reply_skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
            length +
            REPLY_SKB_SIZE);
    if (reply_skb) {
        if ((nla_put(reply_skb, QCA_WLAN_VENDOR_ATTR_PARAM_DATA, length, data)) ||
                (nla_put_u32(reply_skb, QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH, length))
                || (nla_put_u32(reply_skb, QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS, flag))){
            wlan_cfg80211_vendor_free_skb(reply_skb);
            return -EINVAL;
        }
        status = wlan_cfg80211_qal_devcfg_send_response((qdf_nbuf_t)reply_skb);
        return qdf_status_to_os_return(status);
    } else {
        return -ENOMEM;
    }
    return -EIO;
}

static char num_to_char(u_int8_t n)
{
    if ( n >= 10 && n <= 15  )
        return n  - 10 + 'A';
    if ( n >= 0 && n <= 9  )
        return n  + '0';
    return ' '; //Blank space
}

/* convert MAC address in array format to string format
 * inputs:
 *     addr - mac address array
 * output:
 *     macstr - MAC address string format */
static void macaddr_num_to_str(u_int8_t *addr, char *macstr)
{
    int i, j=0;

    for ( i = 0; i < QDF_MAC_ADDR_SIZE; i++  ) {
        macstr[j++] = num_to_char(addr[i] >> 4);
        macstr[j++] = num_to_char(addr[i] & 0xF);
    }
}

int wlan_mesh_getparam(struct wiphy *wiphy,
        struct wireless_dev *wdev,
        struct wlan_cfg8011_genric_params *params)
{
#define SIZE_OF_MAC_ADDR 13
    struct cfg80211_context *cfg_ctx = NULL;
    struct ieee80211com *ic = NULL;
    struct net_device *dev = NULL;
    osif_dev *osifp = NULL;
    int retv = 0, param = 0, reply_length;
    int char_value[16] = {0};
    int *data = NULL;
    int *value = NULL;
    wlan_if_t vap = NULL;
    char *extra = NULL;
    int  get_param[2] = {0};
    //wlan_dev_t ic = NULL;
    param = params->value;
    data = (int *) params->data;
    value = char_value;
    cfg_ctx = (struct cfg80211_context *)wiphy_priv(wiphy);
    ic = cfg_ctx->ic;
    param = params->value;
    if(data)
    {
        get_param[0] = param;
        get_param[1] = *data;
    }
    extra = (char *)value;

    if (ic->ic_wdev.netdev == wdev->netdev) {
        SON_LOGE("%s: Radio commands are not supported yet",__func__);
        retv = -EOPNOTSUPP;
    } else {
        dev = wdev->netdev;
        osifp = ath_netdev_priv(dev);
        vap = osifp->os_if;
        if (vap == NULL) {
            SON_LOGE("%s: VAP is null ", __func__);
            return -1;
        }
        reply_length = sizeof(u_int32_t);
        switch(param)
        {
            case MESH_WHC_APINFO_ROOT_DIST:
                *value = ucfg_son_get_root_dist(vap->vdev_obj);
                break;
            case MESH_WHC_APINFO_UPLINK_RATE:
                *value = ucfg_son_get_uplink_rate(vap->vdev_obj);
                break;
            case MESH_WHC_APINFO_UPLINK_SNR:
                *value = ucfg_son_get_uplink_snr(vap->vdev_obj);
                break;
            case MESH_WHC_APINFO_RATE:
                *value = (int)son_ucfg_rep_datarate_estimator(
                        son_get_backhaul_rate(vap->vdev_obj, true),
                        son_get_backhaul_rate(vap->vdev_obj, false),
                        (ucfg_son_get_root_dist(vap->vdev_obj) - 1),
                        ucfg_son_get_scaling_factor(vap->vdev_obj));
                break;
            case MESH_WHC_APINFO_BSSID:
                {
                    char addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
                    ieee80211_ssid  *desired_ssid = NULL;
                    int retval;
                    struct wlan_ssid ssidname;

                    OS_MEMSET(&ssidname, 0, sizeof(struct wlan_ssid));
                    retval = ieee80211_get_desired_ssid(vap, 0,&desired_ssid);
                    if (desired_ssid == NULL)
                        return -EINVAL;

                    OS_MEMCPY(&ssidname.ssid,&desired_ssid->ssid, desired_ssid->len);
                    ssidname.length = desired_ssid->len;
                    ucfg_son_find_best_uplink_bssid(vap->vdev_obj, addr,&ssidname);
                    macaddr_num_to_str(addr, extra);
                    reply_length = SIZE_OF_MAC_ADDR;
                }
                break;
            case MESH_WHC_APINFO_BEST_UPLINK_OTHERBAND_BSSID:
                {
                    u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

                    ucfg_son_get_best_otherband_uplink_bssid(vap->vdev_obj, addr);
                    macaddr_num_to_str(addr, extra);
                    reply_length = SIZE_OF_MAC_ADDR;
                }
                break;
            case MESH_WHC_APINFO_CAP_BSSID:
                {
                    u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

                    son_ucfg_find_cap_bssid(vap->vdev_obj, addr);
                    macaddr_num_to_str(addr, extra);
                    reply_length = SIZE_OF_MAC_ADDR;
                }
                break;
            case MESH_WHC_APINFO_OTHERBAND_UPLINK_BSSID:
                {
                    u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

                    ucfg_son_get_otherband_uplink_bssid(vap->vdev_obj, addr);
                    macaddr_num_to_str(addr, extra);
                    reply_length = SIZE_OF_MAC_ADDR;
                }
                break;
            case MESH_WHC_APINFO_SON:
                *value = son_has_whc_apinfo_flag(
                        vap->iv_bss->peer_obj, IEEE80211_NODE_WHC_APINFO_SON);
                break;
            case MESH_WHC_APINFO_WDS:
                *value = son_has_whc_apinfo_flag(
                        vap->iv_bss->peer_obj, IEEE80211_NODE_WHC_APINFO_WDS);
                break;
            case MESH_WHC_CURRENT_CAP_RSSI:
                ucfg_son_get_cap_snr(vap->vdev_obj, value);
                break;
            case MESH_WHC_CAP_RSSI:
                *value = ucfg_son_get_cap_rssi(vap->vdev_obj);
                break;
            case MESH_WHC_APINFO_SFACTOR:
                *value =  ucfg_son_get_scaling_factor(vap->vdev_obj);
                break;
            case MESH_WHC_SKIP_HYST:
                *value =  ucfg_son_get_skip_hyst(vap->vdev_obj);
                break;
            case MESH_WHC_MIXEDBH_ULRATE:
                *value = son_get_ul_mixedbh(vap->vdev_obj);
                break;
#if QCA_SUPPORT_SSID_STEERING
            case MESH_VAP_SSID_CONFIG:
                if ((*value = ucfg_son_get_ssid_steering_config(vap->vdev_obj)) != -EINVAL) {
                    qdf_info("This VAP's configuration value is %d ( %d-PRIVATE %d-PUBLIC  )",
                            *value, SON_SSID_STEERING_PRIVATE_VDEV, SON_SSID_STEERING_PUBLIC_VDEV);
                }
                else
                    return *value;
                break;
#endif
            case MESH_BEST_UL_HYST:
                *value = ucfg_son_get_bestul_hyst(vap->vdev_obj);
                break;
            case MESH_PARAM_MAP:
                *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY);
                break;
            case MESH_MAP_BSS_TYPE:
                *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY_VAP_TYPE);
                break;
            case MESH_MAP2_BSTA_VLAN_ID:
                *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY_BSTA_VLAN_ID);
                break;
            case MESH_SON_EVENT_BCAST:
                *value = wlan_son_is_vdev_event_bcast_enabled(vap->vdev_obj);
                break;
            case MESH_MAP_VAP_BEACONING:
                *value = son_vdev_map_capability_get(vap->vdev_obj,
                        SON_MAP_CAPABILITY_VAP_UP);
                break;
            default:
                SON_LOGE("%s: Unrecognized get param command",__func__);
                retv = -EOPNOTSUPP;
                break;
        }
        cfg80211_reply_son(wiphy, reply_length, &char_value, 0);
    }
    return retv;
}

int wlan_mesh_setparam(struct wiphy *wiphy,
        struct wireless_dev *wdev,
        struct wlan_cfg8011_genric_params *params)
{
#define SET_PARAM_INDEX 0
#define SET_VALUE_INDEX 1
#define SET_LENGTH_INDEX 2
#define SET_MAX_INDEX 4
    struct net_device *dev = NULL;
    osif_dev *osifp = NULL;
    int retv = 0;
    wlan_if_t vap = NULL;
    wlan_dev_t ic = NULL;
    int param = params->value;
    u_int32_t *data = (u_int32_t *) params->data;
    int value;
    int extra[SET_MAX_INDEX];

    if ( data == NULL ) {
        SON_LOGE("%s:%d> Invalid Arguments ", __func__, __LINE__);
        return -EINVAL;
    }

    value = *data;
    dev = wdev->netdev;
    osifp = ath_netdev_priv(dev);
    vap = osifp->os_if;
    if (vap == NULL) {
        SON_LOGE("%s: VAP is null ", __func__);
        return -1;
    }
    ic = wlan_vap_get_devhandle(vap);

    extra[SET_PARAM_INDEX] = param;
    extra[SET_VALUE_INDEX] = value;
    extra[SET_LENGTH_INDEX] = (int)params->length;

    switch (param) {
        case MESH_WHC_APINFO_ROOT_DIST:
            ucfg_son_set_root_dist(vap->vdev_obj, value);
            son_update_bss_ie(vap->vdev_obj);
            son_pdev_appie_update(ic);
            wlan_pdev_beacon_update(ic);
            break;
        case MESH_WHC_APINFO_UPLINK_RATE:
            ucfg_son_set_uplink_rate(vap->vdev_obj, value);
            son_pdev_appie_update(ic);
            wlan_pdev_beacon_update(ic);
            break;
        case MESH_WHC_APINFO_OTHERBAND_BSSID:
            ucfg_son_set_otherband_bssid(vap->vdev_obj, &extra[1]);
            son_update_bss_ie(vap->vdev_obj);
            son_pdev_appie_update(ic);
            wlan_pdev_beacon_update(ic);
            break;
        case MESH_WHC_APINFO_SFACTOR:
            ucfg_son_set_scaling_factor(vap->vdev_obj, value);
            break;
        case MESH_WHC_SKIP_HYST:
            ucfg_son_set_skip_hyst(vap->vdev_obj, value);
            break;
        case MESH_WHC_CAP_RSSI:
            ucfg_son_set_cap_rssi(vap->vdev_obj, value);
            break;
        case MESH_WHC_BACKHAUL_TYPE:
            if(!son_set_backhaul_type_mixedbh(vap->vdev_obj, value)) {
                SON_LOGE("%s Error, in setting backhaul type and sonmode",__func__);
            } else {
                son_update_bss_ie(vap->vdev_obj);
                wlan_pdev_beacon_update(ic);
            }
            break;
        case MESH_WHC_MIXEDBH_ULRATE:
            if(!son_set_ul_mixedbh(vap->vdev_obj, value)) {
                SON_LOGE("%s: Error, in setting uplink rate ",__func__);
            }
            break;
#if QCA_SUPPORT_SSID_STEERING
        case MESH_VAP_SSID_CONFIG:
            return ucfg_son_set_ssid_steering_config(vap->vdev_obj,value);
            break;
#endif
        case MESH_PARAM_MAP:
            retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY, value);
            break;
        case MESH_MAP_BSS_TYPE:
            retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY_VAP_TYPE, value);
            break;
        case MESH_MAP2_BSTA_VLAN_ID:
            retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY_BSTA_VLAN_ID, value);
            break;
        case MESH_BEST_UL_HYST:
            ucfg_son_set_bestul_hyst(vap->vdev_obj, value);
            break;
        case MESH_LOG_ENABLE_BSTEERING_RSSI:
            if(value == 0 || value == 1)
            {
                son_record_inst_rssi_log_enable(vap->vdev_obj, value);
            }
            else
                SON_LOGE("Incorrect value for bsteerrssi_log \n");
            break;
        case MESH_SON_EVENT_BCAST:
            son_core_enable_disable_vdev_bcast_events(vap->vdev_obj, !!value);
            break;
        case MESH_MAP_VAP_BEACONING:
            retv = son_vdev_map_capability_set(vap->vdev_obj,
                    SON_MAP_CAPABILITY_VAP_UP, value);
            break;
        default:
            SON_LOGE("%s: Unrecognized set param command",__func__);
            retv = -EOPNOTSUPP;
            break;
    }
    return retv;
}

int wlan_mesh_set_get_params(struct net_device *dev,
                             struct ieee80211req_athdbg *req,
                             void *wri_pointer)
{
	int ret = 0;
	int cmd = 0;
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT || UMAC_SUPPORT_RRM || QCA_LTEU_SUPPORT || DBDC_REPEATER_SUPPORT
	wlan_if_t vap = NETDEV_TO_VAP(dev);
#endif
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT
	osif_dev *osifp = ath_netdev_priv(dev);
	struct ieee80211com *ic = vap->iv_ic;
#endif
#if DBDC_REPEATER_SUPPORT
	struct wlan_objmgr_pdev *pdev;
	struct global_ic_list *ic_list;
#endif
	cmd = req->data.mesh_dbg_req.mesh_cmd;

	switch(cmd)
	{
		case MESH_BSTEERING_ENABLE:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_ENABLE,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT || UMAC_SUPPORT_RRM || QCA_LTEU_SUPPORT || DBDC_REPEATER_SUPPORT
			if (EOK == ret) {
				wlan_set_param(vap, IEEE80211_BSTEER_EVENT_ENABLE, 1);
			}
#endif
		}
		break;

		case MESH_BSTEERING_ENABLE_EVENTS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_ENABLE_EVENTS,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT && QCA_SUPPORT_SON
			if(EOK == ret) {
				if (ic->nss_vops) {
					ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_CFG_BSTEER);
				}
			}
#endif
		}
		break;

		case MESH_BSTEERING_SET_PARAMS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_PARAMS,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_GET_RSSI:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_TRIGGER_RSSI,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_SET_OVERLOAD:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_OVERLOAD,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_LOCAL_DISASSOCIATION:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_LOCAL_DISASSOC,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_SET_PROBE_RESP_WH:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTERRING_PROBE_RESP_WH,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_SET_AUTH_ALLOW:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTERING_AUTH_ALLOW,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_GET_DATARATE_INFO:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_DATARATE_INFO,
					SON_DISPATCHER_GET_CMD,
					(void *)req);
			if ((EOK == ret) && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ?
					-EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_SET_STEERING:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_INPROG_FLAG,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_SET_PROBE_RESP_ALLOW_24G:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_PROBE_RESP_ALLOW_24G,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_GET_PEER_CLASS_GROUP:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_PEER_CLASS_GROUP,
					SON_DISPATCHER_GET_CMD,
					(void *)req);
		}
		break;

		case MESH_ADD_MAC_VALIDITY_TIMER_ACL:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_SET_TIMER_POLICY,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_ENABLE_ACK_RSSI:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_ENABLE_ACK_RSSI,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_MAP_RADIO_HWCAP:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_GET_AP_HWCAP,
					SON_DISPATCHER_GET_CMD,
			(void *)req);
		}
		break;

		case MESH_MAP_CLIENT_CAP:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
				SON_DISPATCHER_CMD_MAP_GET_ASSOC_FRAME,
				SON_DISPATCHER_GET_CMD,
				(void *)req);
		}
		break;

		case MESH_MAP_GET_OP_CHANNELS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
				SON_DISPATCHER_CMD_MAP_GET_OP_CHANNELS,
				SON_DISPATCHER_GET_CMD,
				(void *)req);
		}
		break;

		case MESH_MAP_GET_ESP_INFO:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_GET_ESP_INFO,
					SON_DISPATCHER_GET_CMD,
					(void *)req);
		}
		break;

		case MESH_BSTEERING_MAP_SET_RSSI:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_SET_RSSI_POLICY,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_MAPV2_GET_RADIO_CAC_CAP:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_GET_CAC_CAP,
					SON_DISPATCHER_GET_CMD,
					(void *)req);
		}
		break;

		case MESH_MAP_GET_OP_CLASS_INFO:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_GET_OP_CLASS_INFO,
					SON_DISPATCHER_GET_CMD,
					(void *)req);
		}
		break;

		case MESH_MAP_WIFI6_STA_STATS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_MAP_WIFI6_STATS,
					SON_DISPATCHER_GET_CMD, (void *)req);
			if ((EOK == ret) && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ? -EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_GET_PARAMS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_PARAMS,
					SON_DISPATCHER_GET_CMD, (void *)req);
			if ((EOK == ret) && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ? -EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_SET_PEER_CLASS_GROUP:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_PEER_CLASS_GROUP,
					SON_DISPATCHER_SET_CMD, (void *)req);
		}
		break;

		case MESH_BSTEERING_GET_OVERLOAD:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_OVERLOAD,
					SON_DISPATCHER_GET_CMD, (void *)req);
			if (EOK == ret && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ? -EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_GET_PROBE_RESP_WH:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTERRING_PROBE_RESP_WH,
					SON_DISPATCHER_GET_CMD, (void *)req);
			if (EOK == ret && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ? -EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_SET_DBG_PARAMS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_DBG_PARAMS,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
#if DBDC_REPEATER_SUPPORT
			pdev = vap->iv_ic->ic_pdev_obj;
			if (pdev) {
				ic_list = vap->iv_ic->ic_global_list;
				/*Disable same ssid support when SON mode is enabled*/
				if (wlan_son_is_pdev_enabled(pdev)) {
					GLOBAL_IC_LOCK_BH(ic_list);
					ic_list->same_ssid_support = 0;
					GLOBAL_IC_UNLOCK_BH(ic_list);
				}
			}
#endif
		}
		break;

		case MESH_BSTEERING_GET_DBG_PARAMS:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_DBG_PARAMS,
					SON_DISPATCHER_GET_CMD,
					(void *)req);

			if ((EOK == ret) && wri_pointer) {
				ret = (copy_to_user(wri_pointer, req, sizeof(*req))) ? -EFAULT : 0;
			}
		}
		break;

		case MESH_BSTEERING_SET_DA_STAT_INTV:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_BSTEERING_DA_STAT_INTVL,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;

		case MESH_SET_ALD:
		{
			ret = ucfg_son_dispatcher(NETDEV_TO_VDEV(dev),
					SON_DISPATCHER_CMD_SET_ALD,
					SON_DISPATCHER_SET_CMD,
					(void *)req);
		}
		break;
	}
	return ret;
}


/**
 * @brief Enable/Disable SON events on a VAP
 *
 * @pre  wlan_son_enable must be called
 *
 * @param [inout] vdev  the VAP whose band steering status
 *                     changes
 * @param [in] req request from user space containing the flag
 *                 indicating enable or disable
 *
 * @return QDF_STATUS_E_INVAL if SON not initialized or enabled on
 *         the radio, QDF_STATUS_E_ALREADY if SON on the VAP is
 *         already in the requested state, otherwise return QDF_STATUS_SUCCESS
 */


/**
 * @brief Determine whether an ioctl request is valid or not, along with the
 *        associated parameters.
 *
 * @param [in] vap  the VAP on which the ioctl was made
 * @param [in] req  the parameters provided in the ioctl
 *
 * @return true if all parameters are valid; otherwise false
 */

bool wlan_son_is_req_valid(struct wlan_objmgr_vdev *vdev,
			   struct ieee80211req_athdbg *req)
{
	struct wlan_objmgr_pdev *pdev = NULL;
	/* Check in future if we can get psoc from vdev directly */

	if (wlan_son_is_vdev_valid(vdev)) {
		pdev = wlan_vdev_get_pdev(vdev);
		if (pdev) {
			return wlan_son_is_pdev_valid(pdev)
				&& NULL !=req;
		}
	}

	return false;
}

int son_enable_disable_vdev_events(struct wlan_objmgr_vdev *vdev,
				   void  *req)
{
	bool enabled;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid (vdev , req_t)) {
		return -EINVAL;
	}
	pdev = wlan_vdev_get_pdev(vdev);
	/* Make sure band steering is enabled at the radio level first */
	/* TO DO: Ensure whether the below check is required */
	if (pdev && !(wlan_son_is_pdev_enabled(pdev))) {
		return -EINVAL;
	}

	/* Make sure this isn't a set to the same state we are already in */
	enabled = wlan_son_is_vdev_enabled(vdev);

	if ((mesh_req->mesh_data.value && enabled) ||
	    (!mesh_req->mesh_data.value && !enabled)) {
		return -EALREADY;
	}

	return son_core_enable_disable_vdev_events(vdev,
						   mesh_req->mesh_data.value);
}

int8_t son_ucfg_set_get_peer_class_group(struct wlan_objmgr_vdev *vdev, void *data, bool set)
{
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;
	int8_t retv = -EINVAL;

	req_t = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t)) {
		return retv;
	}

	retv = son_core_set_get_peer_class_group(vdev,
					 req_t->dstmac,
					 &(mesh_req->mesh_data.value),
					 set);
	return retv;
}

int8_t son_ucfg_set_get_overload(struct wlan_objmgr_vdev *vdev, void *data, bool set)
{
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;
	int8_t retv = -EINVAL;

	req_t = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_set_get_overload(vdev,
					 &(mesh_req->mesh_data.value),
					 set);
	return retv;
}

int son_ucfg_send_event(struct  wlan_objmgr_vdev *vdev,
			SON_DISPATCHER_CMD cmd,
			void *data)
{
	return EOK;


}

int son_pdev_steering_enable_disable(struct wlan_objmgr_vdev *vdev, void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_pdev_enable_disable_steering(vdev,
						     mesh_req->mesh_data.value);
	return retv;
}

int son_pdev_steering_enable_ackrssi(struct wlan_objmgr_vdev *vdev, void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_pdev_enable_ackrssi(vdev, mesh_req->mesh_data.value);
	return retv;
}

int son_trigger_null_frame_tx(struct wlan_objmgr_vdev *vdev,
			      void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_null_frame_tx(vdev, req_t->dstmac,
				      mesh_req->mesh_data.value);

	return retv;
}


int son_pdev_set_dbg_param(struct wlan_objmgr_vdev *vdev,
			   void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_set_dbg_params(vdev, &mesh_req->mesh_data.bsteering_dbg_param);

	return retv;
}

int son_pdev_get_dbg_param(struct wlan_objmgr_vdev *vdev,
			   void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_get_dbg_params(vdev,
				       &mesh_req->mesh_data.bsteering_dbg_param);

	return retv;
}

int son_get_wifi6_sta_stats(struct wlan_objmgr_vdev *vdev, void *req) {
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t)) return -EINVAL;

	return son_core_get_wifi6_sta_stats(vdev, &mesh_req->mesh_data.map_wifi6_sta_stats);
}

int son_set_get_steering_params(struct wlan_objmgr_vdev *vdev, void *req, bool action) {
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t)) return retv;

	retv = son_core_set_get_steering_params(vdev, &mesh_req->mesh_data.bsteering_param, action);

	return retv;

}

int son_auth_allow(struct wlan_objmgr_vdev *vdev,
		   void *req,
		   bool set /*true means set */)
{
	struct ieee80211req_athdbg *req_t = NULL;

	req_t = (struct ieee80211req_athdbg *)req;

	if (!wlan_son_is_req_valid(vdev, req_t))
		return -EINVAL;

	return wlan_vdev_acl_auth(vdev, set, req_t);

}
int son_peer_set_probe_resp_allow_2G(struct wlan_objmgr_vdev *vdev,
				     void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	retv = son_core_peer_set_probe_resp_allow_2g(vdev,
						     req_t->dstmac,
						     mesh_req->mesh_data.value);

	return retv;
}

int son_probe_response_wh(struct wlan_objmgr_vdev *vdev,
			  void *req,
			  bool set /*true means set */)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;

	req_t = (struct ieee80211req_athdbg *)req;

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	return wlan_vdev_acl_probe(vdev, set, req_t);
}

int son_peer_set_stastats_intvl(struct wlan_objmgr_vdev *vdev,
				void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;
	struct wlan_objmgr_peer *peer = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	uint8_t pdev_id;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	psoc = wlan_vdev_get_psoc(vdev);

	pdev_id = wlan_objmgr_pdev_get_pdev_id(wlan_vdev_get_pdev(vdev));
	peer = wlan_objmgr_get_peer(psoc, pdev_id, req_t->dstmac, WLAN_SON_ID);
	if (!peer) {
		return retv;
	}

	retv = son_core_set_stastats_intvl(peer,
			   mesh_req->mesh_data.bsteering_sta_stats_update_interval_da);

	wlan_objmgr_peer_release_ref(peer, WLAN_SON_ID);

	return retv;
}



int son_peer_set_steering(struct wlan_objmgr_vdev *vdev,
			  void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;
	struct wlan_objmgr_peer *peer = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	uint8_t pdev_id;

	req_t = (struct ieee80211req_athdbg *)req;
	mesh_req = (struct mesh_dbg_req_t *)(&req_t->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	psoc = wlan_vdev_get_psoc(vdev);

	pdev_id = wlan_objmgr_pdev_get_pdev_id(wlan_vdev_get_pdev(vdev));
	peer = wlan_objmgr_get_peer(psoc, pdev_id, req_t->dstmac, WLAN_SON_ID);

	if (!peer) {
		if(mesh_req->mesh_data.value) {
			qdf_print("%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
				"associated", __func__, req_t->dstmac[0], req_t->dstmac[1],
				req_t->dstmac[2], req_t->dstmac[3], req_t->dstmac[4], req_t->dstmac[5]);
			return -EINVAL;
		} else {
			/* special case station is already left
			   still consider it valid case
			   for reseting flag */
			return EOK;
		}
	}

	retv = son_core_set_steer_in_prog(peer,
					  mesh_req->mesh_data.value);

	wlan_objmgr_peer_release_ref(peer, WLAN_SON_ID);

	return retv;

}

int son_peer_local_disassoc(struct wlan_objmgr_vdev *vdev,
			    void *req)
{
	int retv = -EINVAL;
	struct ieee80211req_athdbg *req_t = NULL;
	struct wlan_objmgr_peer *peer = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	uint8_t pdev_id;

	req_t = (struct ieee80211req_athdbg *)req;

	if (!wlan_son_is_req_valid(vdev, req_t))
		return retv;

	psoc = wlan_vdev_get_psoc(vdev);

	pdev_id = wlan_objmgr_pdev_get_pdev_id(wlan_vdev_get_pdev(vdev));
	peer = wlan_objmgr_get_peer(psoc, pdev_id, req_t->dstmac, WLAN_SON_ID);

	if (!peer)
		return retv;

	retv = wlan_vdev_local_disassoc(vdev, peer);
	wlan_objmgr_peer_release_ref(peer, WLAN_SON_ID);

	return retv;
}

u_int8_t ucfg_son_get_scaling_factor(struct wlan_objmgr_vdev *vdev)
{

	if (vdev)
		return(son_core_get_scaling_factor(vdev));
	else
		return 0;
}

u_int8_t ucfg_son_get_skip_hyst(struct wlan_objmgr_vdev *vdev)
{

	if (vdev)
		return(son_core_get_skip_hyst(vdev));
	else
		return 0;
}

int8_t ucfg_son_get_cap_rssi(struct wlan_objmgr_vdev *vdev)
{
	if (vdev &&
	    wlan_son_is_vdev_valid(vdev) &&
	    wlan_son_is_vdev_enabled(vdev))
		return son_core_get_cap_rssi(vdev);
	else
		return -EINVAL;
}

int ucfg_son_get_cap_snr(struct wlan_objmgr_vdev *vdev, int *cap_snr)
{
	if (vdev)
		son_core_get_cap_snr(vdev, cap_snr);

	return 0;

}

int8_t ucfg_son_set_cap_rssi(struct wlan_objmgr_vdev *vdev,
			     u_int32_t rssi)
{
	if (vdev)
		son_core_set_cap_rssi(vdev, (int8_t)rssi);
	else
		return -EINVAL;

	return EOK;
}


int8_t ucfg_son_set_uplink_rate(struct wlan_objmgr_vdev *vdev,
				u_int32_t uplink_rate)
{
	if (vdev)
		son_core_set_uplink_rate(vdev, uplink_rate);
	else
		return -EINVAL;

	return EOK;
}

int16_t ucfg_son_get_uplink_rate(struct wlan_objmgr_vdev *vdev)
{
	if (vdev)
		return son_core_get_uplink_rate(vdev);
	else
		return -EINVAL;
}

uint8_t ucfg_son_get_uplink_snr(struct wlan_objmgr_vdev *vdev)
{
	if (vdev)
		return son_core_get_uplink_snr(vdev);
	else
		return 0;
}

int8_t ucfg_son_set_scaling_factor(struct wlan_objmgr_vdev *vdev ,
				   int8_t scaling_factor)
{
	if (vdev &&
	    (wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) &&
	    (scaling_factor && scaling_factor <= 100)) {
			son_core_set_scaling_factor(vdev, scaling_factor);
			return EOK;
	}

	return -EINVAL;
}

int8_t ucfg_son_set_skip_hyst(struct wlan_objmgr_vdev *vdev ,
				   int8_t skip_hyst)
{
	if (vdev &&
	    ((skip_hyst == 0) || (skip_hyst == 1))) {
			son_core_set_skip_hyst(vdev, skip_hyst);
			return EOK;
	}

	return -EINVAL;
}


int son_get_peer_info(struct wlan_objmgr_vdev *vdev, void *data)
{

	struct ieee80211req_athdbg *req = NULL;

	req = (struct ieee80211req_athdbg *)data;

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return wlan_vdev_get_node_info(vdev, req);
}

int son_set_innetwork_2g_mac(struct wlan_objmgr_vdev *vdev, void *data)
{

	struct ieee80211req_athdbg *req = NULL;

	req = (struct ieee80211req_athdbg *)data;

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_set_innetwork_2g_mac(vdev, req->dstmac, req->data.param[0]);
}

int son_get_innetwork_2g_mac(struct wlan_objmgr_vdev *vdev, void *data)
{

	struct ieee80211req_athdbg *req = NULL;

	req = (struct ieee80211req_athdbg *)data;

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_innetwork_2g_mac(vdev, (void *)req->data.innetwork_2g_req.data_addr,
					     req->data.innetwork_2g_req.index,
					     req->data.innetwork_2g_req.ch);
}

int son_set_map_rssi_policy(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_set_map_rssi_policy(vdev, mesh_req->mesh_data.map_rssi_policy.rssi,
					    mesh_req->mesh_data.map_rssi_policy.rssi_hysteresis);
}

#if QCA_SUPPORT_SSID_STEERING
int ucfg_son_set_ssid_steering_config(struct wlan_objmgr_vdev *vdev,
				      uint8_t ssid_steering_config)
{
	if (vdev) {
		return son_core_set_ssid_steering_config(vdev,
							 ssid_steering_config);
	}

	return -EINVAL;
}

int ucfg_son_get_ssid_steering_config(struct wlan_objmgr_vdev *vdev)
{
	if (vdev)
		return son_core_get_ssid_steering_config(vdev);

	return -EINVAL;
}
#endif

int son_set_ald(struct wlan_objmgr_vdev *vdev, void *data)
{
	int ret = 0;
	wlan_if_t vap = NULL;
	struct ieee80211req_athdbg *req = NULL;
	mesh_ald_req *config = NULL;
	req = (struct ieee80211req_athdbg *)data;
	config = &(req->data.mesh_dbg_req.mesh_data.ald_req);
	vap = wlan_vdev_get_vap(vdev);

	if (!vap) {
		SON_LOGE("%s: vap is NULL", __func__);
		return -EINVAL;
        }
	switch (config->cmdtype) {
		case MESH_ALD_STA_ENABLE:
			ret = son_ald_sta_enable(vap->vdev_obj,
					config->data.ald_sta.macaddr,
					config->data.ald_sta.enable);
			break;
		default:
			return -ENXIO;
	}
	return ret;
}

int son_get_assoc_frame(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_assoc_frame(vdev, req->dstmac,
					mesh_req->mesh_data.mapclientcap.assocReqFrame,
					&mesh_req->mesh_data.mapclientcap.frameSize);
}

int son_get_map_esp_info(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_map_esp_info(vdev, &mesh_req->mesh_data.map_esp_info);
}

int son_set_map_timer_policy(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return wlan_vdev_add_acl_validity_timer(vdev,
						mesh_req->mesh_data.client_assoc_req_acl.stamac,
						mesh_req->mesh_data.client_assoc_req_acl.validity_period);
}

int son_get_map_operable_channels(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_map_operable_channels(vdev, &mesh_req->mesh_data.map_op_chan);
}

int son_get_map_apcap(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	return son_core_get_map_apcap(vdev, &mesh_req->mesh_data.mapapcap);
}

int son_get_map_cac_cap(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_map_cac_cap(vdev, &mesh_req->mesh_data.mapv2_cac_info);
}

int son_get_map_opclass_info(struct wlan_objmgr_vdev *vdev, void *data)
{
	struct ieee80211req_athdbg *req = NULL;
	struct mesh_dbg_req_t *mesh_req = NULL;

	req = (struct ieee80211req_athdbg *)data;
	mesh_req = (struct mesh_dbg_req_t *)(&req->data.mesh_dbg_req);

	if (!wlan_son_is_req_valid(vdev, req))
		return -EINVAL;

	return son_core_get_map_opclass_info(vdev, &mesh_req->mesh_data.map_op_class);
}

int son_ucfg_get_cmd(struct wlan_objmgr_vdev *vdev,
		     SON_DISPATCHER_CMD cmd,
		     void *data)
{
	int retv = true;

	switch(cmd) {
		/* Set/GET the static band steering parameters */
	case SON_DISPATCHER_CMD_BSTEERING_PARAMS:
		retv = son_set_get_steering_params(vdev, data, false);
		break;
		/* Set the static band steering parameters */
	case SON_DISPATCHER_CMD_BSTEERING_DBG_PARAMS:
		retv = son_pdev_get_dbg_param(vdev, data);
		break;
	case SON_DISPATCHER_CMD_MAP_WIFI6_STATS:
	    retv = son_get_wifi6_sta_stats(vdev, data);
	    break;
	/* Enable/Disable band steering */
        case SON_DISPATCHER_CMD_BSTEERING_ENABLE:
		/* Not required */
		break;
		/* Enable ackrssi */
	case SON_DISPATCHER_CMD_BSTEERING_ENABLE_ACK_RSSI:
		/* Not required */
		break;
		/* GET Peer Class Group */
	case SON_DISPATCHER_CMD_BSTEERING_PEER_CLASS_GROUP:
		retv = son_ucfg_set_get_peer_class_group(vdev, data, false /*get*/);
		break;
		/* SET/GET overload status */
	case SON_DISPATCHER_CMD_BSTEERING_OVERLOAD:
		retv = son_ucfg_set_get_overload(vdev, data, false /*get*/);
		break;
		/* Request RSSI measurement */
	case SON_DISPATCHER_CMD_BSTEERING_TRIGGER_RSSI:
		/* Not required */
		break;
		/* Control whether probe responses are withheld for a MAC */
	case SON_DISPATCHER_CMD_BSTERRING_PROBE_RESP_WH:
		retv = son_probe_response_wh(vdev, data ,false /*get */);
		break;
		/* Data rate info for node */
	case SON_DISPATCHER_CMD_BSTEERING_DATARATE_INFO:
		retv = son_get_peer_info(vdev, data);
		break;
		/* Enable/Disable Band steering events */
	case SON_DISPATCHER_CMD_BSTEERING_ENABLE_EVENTS:
		/* Not required */
		break;
		/* Set Local disassociation*/
	case SON_DISPATCHER_CMD_BSTEERING_LOCAL_DISASSOC:
		/* Not required */
		break;
		/* set steering in progress for node */
	case SON_DISPATCHER_CMD_BSTEERING_INPROG_FLAG:
		/* Not required */
		break;
		/* set stats interval for da */
	case SON_DISPATCHER_CMD_BSTEERING_DA_STAT_INTVL:
		/* Not required */
		break;
		/* AUTH ALLOW during steering prohibit time */
	case SON_DISPATCHER_CMD_BSTERING_AUTH_ALLOW:
		retv = son_auth_allow(vdev, data , false);
		break;
		/* Control whether probe responses are allowed for a MAC in 2.4g band */
	case SON_DISPATCHER_CMD_BSTEERING_PROBE_RESP_ALLOW_24G:
		/* Not required */
		break;
		/* get the in network MAC addresses in 2.4g band */
	case SON_DISPATCHER_CMD_BSTEERING_GET_INNETWORK_24G:
		retv = son_get_innetwork_2g_mac(vdev, data);
		break;
		/* get Client Assoc frame for MAP */
	case SON_DISPATCHER_CMD_MAP_GET_ASSOC_FRAME:
		retv = son_get_assoc_frame(vdev, data);
		break;
		/* get esp info for MAP */
	case SON_DISPATCHER_CMD_MAP_GET_ESP_INFO:
		retv = son_get_map_esp_info(vdev,data);
		break;
		/* get operable channels for MAP */
	case SON_DISPATCHER_CMD_MAP_GET_OP_CHANNELS:
		retv = son_get_map_operable_channels(vdev, data);
		break;
		/* get hardware ap capabilities for MAP */
	case SON_DISPATCHER_CMD_MAP_GET_AP_HWCAP:
		retv = son_get_map_apcap(vdev, data);
		break;
		/* get radio CAC capablities for MAPv2 */
	case SON_DISPATCHER_CMD_MAP_GET_CAC_CAP:
		retv = son_get_map_cac_cap(vdev, data);
		break;
		/* get opclass info for MAPv2 */
	case SON_DISPATCHER_CMD_MAP_GET_OP_CLASS_INFO:
		retv = son_get_map_opclass_info(vdev, data);
		break;

	default:
		SON_LOGF("Invalid cmd %d",cmd);
		retv = -EINVAL;
	}

	return retv;
}

int son_ucfg_set_cmd(struct  wlan_objmgr_vdev *vdev,
		     SON_DISPATCHER_CMD cmd,
		     void *data)
{
	int retv = EOK;

	switch(cmd) {
		/* Set/GET the static band steering parameters */
	case SON_DISPATCHER_CMD_BSTEERING_PARAMS:
		retv = son_set_get_steering_params(vdev, data, true);
		break;
		/* Set the static band steering parameters */
	case SON_DISPATCHER_CMD_BSTEERING_DBG_PARAMS:
		retv = son_pdev_set_dbg_param(vdev, data);
		break;
		/* Enable/Disable band steering */
	case SON_DISPATCHER_CMD_BSTEERING_ENABLE:
		retv = son_pdev_steering_enable_disable(vdev, data);
		break;
		/* Enable Ack Rssi for band steering */
	case SON_DISPATCHER_CMD_BSTEERING_ENABLE_ACK_RSSI:
		retv = son_pdev_steering_enable_ackrssi(vdev, data);
		break;
		/* SET Peer Class Group */
	case SON_DISPATCHER_CMD_BSTEERING_PEER_CLASS_GROUP:
		retv = son_ucfg_set_get_peer_class_group(vdev, data, true /*set*/);
		break;
		/* SET/GET overload status */
	case SON_DISPATCHER_CMD_BSTEERING_OVERLOAD:
		retv = son_ucfg_set_get_overload(vdev, data, true /*set*/);
		break;
		/* Request RSSI measurement */
	case SON_DISPATCHER_CMD_BSTEERING_TRIGGER_RSSI:
		retv = son_trigger_null_frame_tx(vdev, data);
		break;
		/* Control whether probe responses are withheld for a MAC */
	case SON_DISPATCHER_CMD_BSTERRING_PROBE_RESP_WH:
		retv = son_probe_response_wh(vdev, data , true);
		break;
		/* Data rate info for node */
	case SON_DISPATCHER_CMD_BSTEERING_DATARATE_INFO:
		/* Not required */
		break;
		/* Enable/Disable Band steering events */
	case SON_DISPATCHER_CMD_BSTEERING_ENABLE_EVENTS:
		retv = son_enable_disable_vdev_events(vdev, data);
		break;
		/* Set Local disassociation*/
	case SON_DISPATCHER_CMD_BSTEERING_LOCAL_DISASSOC:
		retv = son_peer_local_disassoc(vdev, data);
		break;
		/* set steering in progress for node */
	case SON_DISPATCHER_CMD_BSTEERING_INPROG_FLAG:
		retv = son_peer_set_steering(vdev, data);
		break;
		/* set stats interval for da */
	case SON_DISPATCHER_CMD_BSTEERING_DA_STAT_INTVL:
		retv = son_peer_set_stastats_intvl(vdev, data);
		break;
		/* AUTH ALLOW during steering prohibit time */
	case SON_DISPATCHER_CMD_BSTERING_AUTH_ALLOW:
		retv = son_auth_allow(vdev, data , true);
		break;
		/* Control whether probe responses are allowed for a MAC in 2.4g band */
	case SON_DISPATCHER_CMD_BSTEERING_PROBE_RESP_ALLOW_24G:
		retv = son_peer_set_probe_resp_allow_2G(vdev, data);
		break;
		/* set in network for a MAC in 2.4g band */
	case SON_DISPATCHER_CMD_BSTEERING_SET_INNETWORK_24G:
		retv = son_set_innetwork_2g_mac(vdev, data);
		break;
		/* set RSSI threshold and hysteresis for MAP*/
	case SON_DISPATCHER_CMD_MAP_SET_RSSI_POLICY:
		retv = son_set_map_rssi_policy(vdev, data);
		break;
		/* set acl timer policy for MAP */
	case SON_DISPATCHER_CMD_MAP_SET_TIMER_POLICY:
		retv = son_set_map_timer_policy(vdev, data);
		break;
		/* set ald commands */
	case SON_DISPATCHER_CMD_SET_ALD:
		retv = son_set_ald(vdev, data);
		break;
	default:
		SON_LOGF("Invalid cmd %d",cmd);
		retv = -EINVAL;
	}

	return retv;
}

int ucfg_son_dispatcher(struct wlan_objmgr_vdev *vdev,
		   SON_DISPATCHER_CMD cmd, SON_DISPATCHER_ACTION action,
		   void *data)
{
	int retv = QDF_STATUS_SUCCESS;

	switch (action) {
	case SON_DISPATCHER_SET_CMD:
		retv = son_ucfg_set_cmd(vdev, cmd, data);
		break;
	case SON_DISPATCHER_GET_CMD:
		retv = son_ucfg_get_cmd(vdev, cmd, data);
		break;

	case SON_DISPATCHER_SEND_EVENT:
		break;
		retv = son_ucfg_send_event(vdev, cmd, data);
		break;
	default:
		SON_LOGF("Invalid action %d",action);
		retv = -EINVAL;
	}

	return retv;
}

int son_ucfg_rep_datarate_estimator(u_int16_t backhaul_rate,
				    u_int16_t ap_rate,
				    u_int8_t root_distance,
				    u_int8_t scaling_factor)
{
	int rate;
	if (root_distance == 0) {
		/* Root AP, there is no STA backhaul link */
		return ap_rate;
	} else {
		if (!backhaul_rate || !ap_rate)
			return 0;

		/* Estimate the data rate of repeater AP, (a*b)/(a+b) * (factor/100).
		* 64-bit by 64-bit divison can be an issue in some platform */
		rate = (backhaul_rate * ap_rate)/(backhaul_rate + ap_rate);
		rate = (rate * scaling_factor)/100;
		return rate;
	}
}


static QDF_STATUS
ieee80211_get_bssid_info(void *arg, wlan_scan_entry_t se)
{
	struct ieee80211_uplinkinfo *bestUL = (struct ieee80211_uplinkinfo *)arg;
	struct ieee80211com *ic = NULL;
	u_int8_t se_ssid_len = 0;
	u_int8_t *se_ssid = util_scan_entry_ssid(se)->ssid;
	u_int8_t *se_bssid = util_scan_entry_bssid(se);
	struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
	u_int16_t se_uplinkrate, se_currentrate, tmprate;
	u_int8_t se_rootdistance;
	wlan_chwidth_e chwidth;
	struct wlan_objmgr_pdev *pdev = NULL;
	u_int8_t *se_otherband_bssid;
	u_int8_t se_snr = util_scan_entry_snr(se);
	wlan_chan_t chan = NULL;
	u_int8_t zero_bssid[QDF_MAC_ADDR_SIZE] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	u_int8_t nss;

	pdev = wlan_vdev_get_pdev(bestUL->vdev);

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
        if (!ic)
		return 0;

	/* make sure ssid is same */
	se_ssid_len = util_scan_entry_ssid(se)->length;

	if (se_ssid_len == 0 || (se_ssid_len != strlen(bestUL->essid)) || OS_MEMCMP(se_ssid, bestUL->essid, se_ssid_len) != 0)
		return 0;

	se_sonadv = (struct ieee80211_ie_whc_apinfo *)util_scan_entry_sonie(se);
	if (se_sonadv == NULL)
		return 0;

	/* Parse and get the hop count */
	se_rootdistance = se_sonadv->whc_apinfo_root_ap_dist;
	/* Get the backhaul rate from scan entry */
	se_uplinkrate = LE_READ_2(&se_sonadv->whc_apinfo_uplink_rate);

	if ((se_rootdistance == SON_INVALID_ROOT_AP_DISTANCE)
	    || (se_uplinkrate == 0)) {
		/* Isolated independent repeater entry, ignore it.
		 * Also, If currently associated with
		 * isolated independent repeater,
		 * mark it for recovery */
		if (IEEE80211_ADDR_EQ(wlan_vdev_mlme_get_macaddr(bestUL->vdev), se_bssid))
			bestUL->island_detected = 1;

		SON_LOGI("%s: Ignored, island detected %d rootdistance=%d uplinkrate=%d \n",
			 ether_sprintf(se_bssid),
			 bestUL->island_detected,
			 se_rootdistance,
			 se_uplinkrate);
		return 0;
	}

	/* Parse and get the uplink partner BSSID */
	chan = wlan_vdev_get_channel(bestUL->vdev);
	if (chan == NULL)
		se_otherband_bssid = zero_bssid;
	else if (IEEE80211_IS_CHAN_2GHZ(chan))
		se_otherband_bssid = se_sonadv->whc_apinfo_5g_bssid;
	else
		se_otherband_bssid = se_sonadv->whc_apinfo_24g_bssid;

	chwidth = (wlan_chwidth_e)wlan_vdev_get_chwidth(bestUL->vdev);

	/* Current scan entry bssid rate estimate*/
        nss = son_get_nss(bestUL->vdev);
	se_currentrate = son_SNRToPhyRateTablePerformLookup(se_snr,
				    nss,
				    convert_phymode(bestUL->vdev),
				    chwidth);

	if(se_rootdistance == 0) {
		/* Estimate the rate from RootAP beacon */
		if (son_core_get_cap_rssi(bestUL->vdev) &&
		    se_snr >= son_core_get_cap_rssi(bestUL->vdev))
			tmprate = 0xffff;/* Max data rate, so cap is always preferred */
		else
		    tmprate = se_currentrate;
	} else {
		wlan_if_t tmpvap = NULL;

		/* Get the uplink BSSID from scan entry and compare it with our VAPs BSSID.
		 * If it matches with any of our VAP's BSSID, discard this scan entry.
		 * This will avoid unnecessary restarts by repacd */
		TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
			if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP)
			{
				if (IEEE80211_ADDR_EQ(tmpvap->iv_myaddr, &se_sonadv->whc_apinfo_uplink_bssid))
					return 0;
			}
		}

		/* Estimate the rate from repeater AP beacon */
		tmprate = son_ucfg_rep_datarate_estimator(se_uplinkrate,
			  se_currentrate,
			  se_rootdistance,
			  ucfg_son_get_scaling_factor(bestUL->vdev));
	}

	qdf_print("%s: fronthaul_snr %d backhaul_rate %d fronthaul_rate %d estimate %d",
		  ether_sprintf(se_bssid),
		  se_snr,
		  se_uplinkrate,
		  se_currentrate,
		  tmprate);

	/* update the bssid if better than previous one */
	if(tmprate > bestUL->rate_estimate) {
		bestUL->rate_estimate = tmprate;
		qdf_mem_copy(bestUL->bssid, se_bssid, QDF_MAC_ADDR_SIZE);
		bestUL->root_distance = se_rootdistance;
		qdf_mem_copy(bestUL->otherband_bssid, se_otherband_bssid,
			     QDF_MAC_ADDR_SIZE);
	}
	return 0;
}


int ucfg_son_find_best_uplink_bssid(struct wlan_objmgr_vdev *vdev, char *bssid, struct wlan_ssid *ssidname)
{
	struct ieee80211_uplinkinfo bestUL = {0};
	u_int16_t current_rate, max_rate;
	u_int8_t hyst;
	struct wlan_objmgr_peer *bss_peer;
	u_int8_t bss_peer_mac[QDF_MAC_ADDR_SIZE];

	bestUL.vdev = vdev;
	OS_MEMCPY(&bestUL.essid, &ssidname->ssid[0], ssidname->length);
	max_rate = wlan_ucfg_get_maxphyrate(vdev)/ 1000;
	current_rate = son_ucfg_rep_datarate_estimator(
		son_get_backhaul_rate(vdev, true),
		son_get_backhaul_rate(vdev, false),
		(ucfg_son_get_root_dist(vdev) - 1),
		ucfg_son_get_scaling_factor(vdev));

	if (!ucfg_son_get_skip_hyst(vdev)) {
		hyst = ucfg_son_get_bestul_hyst(vdev);
	} else {
		hyst = 0;
	}

	bss_peer = wlan_vdev_get_bsspeer(vdev);
	if (!bss_peer)
		return -EINVAL;
	OS_MEMCPY(bss_peer_mac, wlan_peer_get_macaddr(bss_peer), QDF_MAC_ADDR_SIZE);
	if (ucfg_scan_db_iterate(wlan_vdev_get_pdev(vdev), ieee80211_get_bssid_info, &bestUL) == 0) {
		if ((wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS)
		    && !IEEE80211_ADDR_EQ(bss_peer_mac, &bestUL.bssid)
		    && !bestUL.island_detected) {
			if (bestUL.rate_estimate < (current_rate + ((max_rate * hyst) / 100))) {
				/* Keep currently serving AP as best bssid, populate otherband bssid as well */
				char ob_bssid[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
				ucfg_son_get_otherband_uplink_bssid(vdev, ob_bssid);
				son_core_set_best_otherband_uplink_bssid(vdev, &ob_bssid[0]);
				OS_MEMCPY(bssid, bss_peer_mac, QDF_MAC_ADDR_SIZE);
				return 0;
			}
		}
		OS_MEMCPY(bssid, &bestUL.bssid, QDF_MAC_ADDR_SIZE);
		son_core_set_best_otherband_uplink_bssid(vdev, &bestUL.otherband_bssid[0]);
	}

	return 0;
}

static QDF_STATUS
ieee80211_get_cap_bssid(void *arg, wlan_scan_entry_t se)
{
	struct ieee80211_uplinkinfo *rootinfo =
		(struct ieee80211_uplinkinfo *)arg;
	u_int8_t se_ssid_len = 0;
	u_int8_t  *se_ssid = util_scan_entry_ssid(se)->ssid;
	u_int8_t *se_bssid = util_scan_entry_bssid(se);
	struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
	u_int8_t se_rootdistance, se_isrootap;

	/* make sure ssid is same */
	se_ssid_len = util_scan_entry_ssid(se)->length;
	if(se_ssid_len == 0 || (se_ssid_len != strlen(rootinfo->essid)) || OS_MEMCMP(se_ssid, rootinfo->essid, se_ssid_len) != 0)
		return 0;

	se_sonadv = (struct ieee80211_ie_whc_apinfo *)util_scan_entry_sonie(se);
	if(se_sonadv == NULL)
		return 0;

	/* Parse and get the hop count */
	se_rootdistance = se_sonadv->whc_apinfo_root_ap_dist;
	se_isrootap = se_sonadv->whc_apinfo_is_root_ap;

	if(se_rootdistance == 0 && se_isrootap)
		OS_MEMCPY(rootinfo->bssid, se_bssid, QDF_MAC_ADDR_SIZE);

	return 0;
}

int son_ucfg_find_cap_bssid(struct wlan_objmgr_vdev *vdev, char *bssid)
{
	struct ieee80211_uplinkinfo rootinfo;
	uint8_t ssid[WLAN_SSID_MAX_LEN + 1] = {0};
	u_int8_t len = 0;

	if (QDF_STATUS_SUCCESS !=
			wlan_vdev_mlme_get_ssid(vdev, ssid, &len))
		return -EINVAL;

	memset(&rootinfo, 0, sizeof(struct ieee80211_uplinkinfo));

	OS_MEMCPY(&rootinfo.essid, &ssid[0], len);

	if (ucfg_scan_db_iterate(wlan_vdev_get_pdev(vdev),
			 ieee80211_get_cap_bssid, &rootinfo) == 0)
		OS_MEMCPY(bssid, &rootinfo.bssid, QDF_MAC_ADDR_SIZE);

	return 0;
}
int ucfg_son_set_otherband_bssid(struct wlan_objmgr_vdev *vdev, int *val)
{
	struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);

	if (pdev &&
	    wlan_son_is_pdev_valid(pdev))
		return(son_core_set_otherband_bssid(pdev, val));
	else {
		SON_LOGI("SON on Pdev Needs to be enabled for Setting otherband bssid");
		return 0;
	}
	return 0;
}

int ucfg_son_get_best_otherband_uplink_bssid(struct wlan_objmgr_vdev *vdev,
					     char *bssid)
{
	struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);

	if (pdev &&
	    wlan_son_is_pdev_valid(pdev))
		return(son_core_get_best_otherband_uplink_bssid(pdev, bssid));
	else {
		SON_LOGI("SON on Pdev Needs to be enabled for Setting otherband bssid");
		return 0;
	}

	return 0;
}
static QDF_STATUS
ieee80211_get_otherband_uplink_bssid(void *arg, wlan_scan_entry_t se)
{
	struct ieee80211_uplinkinfo *uplink =
		(struct ieee80211_uplinkinfo *)arg;
	struct wlan_objmgr_vdev *vdev = uplink->vdev;
	u_int8_t se_ssid_len = 0;
	u_int8_t *se_ssid = util_scan_entry_ssid(se)->ssid;
	u_int8_t *se_bssid = util_scan_entry_bssid(se);
	struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct wlan_objmgr_peer *peer;
	u_int8_t *se_otherband_bssid;
	wlan_chan_t chan = NULL;
	u_int8_t zero_bssid[QDF_MAC_ADDR_SIZE] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	pdev = wlan_vdev_get_pdev(vdev);

	/* make sure ssid is same */
	se_ssid_len = util_scan_entry_ssid(se)->length;

	if(se_ssid_len == 0 || (se_ssid_len != strlen(uplink->essid)) || OS_MEMCMP(se_ssid, uplink->essid, se_ssid_len) != 0)
		return 0;

	se_sonadv = (struct ieee80211_ie_whc_apinfo *)util_scan_entry_sonie(se);

	if(se_sonadv == NULL)
		return 0;

	peer = wlan_vdev_get_bsspeer(vdev);
	if(IEEE80211_ADDR_EQ(se_bssid, peer->macaddr)) {
		/* Parse and get the uplink partner BSSID */
		chan = wlan_vdev_get_channel(vdev);
		if (chan == NULL)
			se_otherband_bssid = zero_bssid;
		else if (IEEE80211_IS_CHAN_2GHZ(chan))
			se_otherband_bssid = se_sonadv->whc_apinfo_5g_bssid;
		else
			se_otherband_bssid = se_sonadv->whc_apinfo_24g_bssid;

		OS_MEMCPY(uplink->bssid, se_otherband_bssid, QDF_MAC_ADDR_SIZE);
	}

	return 0;
}

int ucfg_son_get_otherband_uplink_bssid(struct wlan_objmgr_vdev *vdev,
					char *addr)
{
	struct ieee80211_uplinkinfo uplink = {0};
	uint8_t ssid[WLAN_SSID_MAX_LEN + 1] = {0};
	u_int8_t len = 0;

	if (QDF_STATUS_SUCCESS !=
			wlan_vdev_mlme_get_ssid(vdev, ssid, &len))
		return -EINVAL;

	uplink.vdev = vdev;
	OS_MEMCPY(&uplink.essid, &ssid[0], len);

	if (ucfg_scan_db_iterate(wlan_vdev_get_pdev(vdev),
				 ieee80211_get_otherband_uplink_bssid,
				 &uplink) == 0) {
		qdf_mem_copy(addr, &uplink.bssid, QDF_MAC_ADDR_SIZE);
	}

	return 0;
}

u_int8_t ucfg_son_get_bestul_hyst(struct wlan_objmgr_vdev *vdev)
{
	return son_core_get_bestul_hyst(vdev);
}

void ucfg_son_set_bestul_hyst(struct wlan_objmgr_vdev *vdev, u_int8_t hyst)
{
	son_core_set_bestul_hyst(vdev, hyst);
}

#else

int wlan_mesh_set_get_params(struct net_device *dev,
                             struct ieee80211req_athdbg *req,
                             void *wri_pointer)
{
	return -EINVAL;
}

int ucfg_son_dispatcher(struct wlan_objmgr_vdev *vdev,
			SON_DISPATCHER_CMD cmd,
			SON_DISPATCHER_ACTION action, void *data)
{
	return -EINVAL;

}

int son_ucfg_rep_datarate_estimator(u_int16_t backhaul_rate,
				    u_int16_t ap_rate,
				    u_int8_t root_distance,
				    u_int8_t scaling_factor)
{
	return ap_rate;

}

static inline int wlan_son_enable_events(struct wlan_objmgr_vdev *vdev,
					 struct ieee80211req_athdbg *req)
{
	return -EINVAL;
}

u_int8_t ucfg_son_get_scaling_factor(struct wlan_objmgr_vdev *vdev)
{
	return 0;

}
int8_t ucfg_son_set_scaling_factor(struct wlan_objmgr_vdev *vdev , int8_t scaling_factor)
{
	return EOK;

}

u_int8_t ucfg_son_get_skip_hyst(struct wlan_objmgr_vdev *vdev)
{
	return 0;

}
int8_t ucfg_son_set_skip_hyst(struct wlan_objmgr_vdev *vdev , int8_t skip_hyst)
{
	return EOK;

}

int ucfg_son_find_best_uplink_bssid(struct wlan_objmgr_vdev *vdev, char *bssid, struct wlan_ssid *ssidname)
{
	return 0;

}

int son_ucfg_find_cap_bssid(struct wlan_objmgr_vdev *vdev, char *bssid)
{
	return 0;
}

int ucfg_son_set_otherband_bssid(struct wlan_objmgr_vdev *vdev, int *val)
{
	return EOK;
}

int ucfg_son_get_best_otherband_uplink_bssid(struct wlan_objmgr_vdev *vdev,
					     char *bssid)
{
	return EOK;
}
int ucfg_son_get_otherband_uplink_bssid(struct wlan_objmgr_vdev *vdev, char *addr)
{
	return EOK;
}

int8_t ucfg_son_set_uplink_rate(struct wlan_objmgr_vdev *vdev,
				u_int32_t uplink_rate)
{
	return EOK;
}
int8_t ucfg_son_get_cap_rssi(struct wlan_objmgr_vdev *vdev)
{
	return EOK;
}

int8_t ucfg_son_set_cap_rssi(struct wlan_objmgr_vdev *vdev,
			     u_int32_t rssi)
{
	return EOK;
}

int ucfg_son_get_cap_snr(struct wlan_objmgr_vdev *vdev, int *cap_snr)
{
	return 0;

}

u_int8_t ucfg_son_get_bestul_hyst(struct wlan_objmgr_vdev *vdev)
{
	return 0;
}

void ucfg_son_set_bestul_hyst(struct wlan_objmgr_vdev *vdev, u_int8_t hyst)
{
}

#endif
