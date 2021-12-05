/*
* Copyright (c) 2011, 2018, 2020 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 *
 *  all the IE parsing/processing routines.
 */
#include <ieee80211_var.h>
#include <ieee80211_ie_utils.h>
#include <acfg_api_types.h>

#define IEEE80211_SKIP_LEN(frm,efrm,skip_len) do { \
    if( ((efrm)-(frm)) < skip_len) {               \
          frm=NULL;                                \
     } else {                                      \
          frm += skip_len;                         \
     }                                             \
  } while(0)

/*
** return pointer to ie data portion of the management frame.
*/
u_int8_t *ieee80211_mgmt_iedata(wbuf_t wbuf, int subtype)
{
    struct ieee80211_frame *wh;
    u_int8_t *frm,*efrm;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
    frm = (u_int8_t *)&wh[1];

    switch(subtype) {
       case  IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
       IEEE80211_SKIP_LEN(frm ,efrm, 4);
       break;

       case  IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
       IEEE80211_SKIP_LEN( frm,efrm, 10);
       break;

       case  IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
       case  IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
       IEEE80211_SKIP_LEN( frm,efrm, 6);
       break;

       case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
       case IEEE80211_FC0_SUBTYPE_BEACON:
       IEEE80211_SKIP_LEN( frm,efrm, 12);
       break;

       case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
	/* ie data fllows at 0 offset */
       break;

       default:
         frm=NULL;
    }
    return frm;
}

int ieee80211_del_user_rnr_entry(struct ieee80211com *ic, u_int8_t uid)
{
    struct user_rnr_data *tmp_rnr_node = NULL, *tmp = NULL;

    if (uid > ACFG_USER_RNR_MAX_UID) {
        qdf_err("%s:uid %d bigger than max %d\n",__func__,uid,ACFG_USER_RNR_MAX_UID);
        return EINVAL;
    }

    TAILQ_FOREACH_SAFE(tmp_rnr_node, &ic->ic_user_neighbor_ap.user_rnr_data_list,
                       user_rnr_next_uid, tmp) {
        if (uid == tmp_rnr_node->uid) {
            qdf_spin_lock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
            TAILQ_REMOVE(&ic->ic_user_neighbor_ap.user_rnr_data_list, tmp_rnr_node,
                         user_rnr_next_uid);
            qdf_spin_unlock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
            ic->ic_user_neighbor_ap.running_length -= tmp_rnr_node->uid_buf_length;
            qdf_mem_free(tmp_rnr_node->user_buf);
            qdf_mem_free(tmp_rnr_node);
            break;
        }
    }
    ieee80211_user_rnr_frm_update(ic, ic->ic_user_rnr_frm_ctrl, true);
    return 0;
}
qdf_export_symbol(ieee80211_del_user_rnr_entry);

static void print_bss_params(ieee80211_rnr_tbtt_info_set_t *tbtt_info)
{
    qdf_nofl_info("    bss_params.oct_recommended=%d",
                    tbtt_info->bss_params.oct_recommended);
    qdf_nofl_info("    bss_params.same_ssid=%d",
                    tbtt_info->bss_params.same_ssid);
    qdf_nofl_info("    bss_params.mbssid_set=%d",
                    tbtt_info->bss_params.mbssid_set);
    qdf_nofl_info("    bss_params.tx_bssid=%d",tbtt_info->bss_params.tx_bssid);
    qdf_nofl_info("    bss_params.colocated_lower_band_ess=%d",
                    tbtt_info->bss_params.colocated_lower_band_ess);
    qdf_nofl_info("    bss_params.probe_resp_20tu_active=%d",
                    tbtt_info->bss_params.probe_resp_20tu_active);
    qdf_nofl_info("    bss_params.co_located_ap=%d",
                    tbtt_info->bss_params.co_located_ap);
}

static void ieee80211_dump_user_rnr_entry(struct user_rnr_data *rnr_node)
{
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    uint8_t cnt = 0;
    int tbtt_info_len = 0;

    qdf_nofl_info("====user RNR entry====uid%d",rnr_node->uid);
    qdf_nofl_info("is_copied=%d,ap_remaining=%d,ap_copied_cnt=%d,hdr_ap_length=%d",
                  rnr_node->is_copied, rnr_node->uid_ap_remaining,
                  rnr_node->uid_ap_copied_cnt, rnr_node->uid_hdr_ap_length);
    qdf_nofl_info("buf_length=%d,org_ap_cnt=%d",
                  rnr_node->uid_buf_length, rnr_node->uid_org_ap_cnt);

    ap_info = (ieee80211_rnr_nbr_ap_info_t *)rnr_node->user_buf;
    qdf_nofl_info("==op_class=%d, channel=%d, hdr_len=%d, hdr_cnt=%d",
              ap_info->op_class, ap_info->channel,
              ap_info->hdr_info_len, ap_info->hdr_info_cnt);

    tbtt_info_len = ap_info->hdr_info_len;
    while (cnt < ap_info->hdr_info_cnt+1) {
        tbtt_info = &(ap_info->tbtt_info[cnt]);
        qdf_nofl_info("  ==tbtt info %d==",cnt+1);
        qdf_nofl_info("    tbtt_offset=%d",tbtt_info->tbtt_offset);
        switch (tbtt_info_len) {
            case TBTT_INFO_LEN_2:
                print_bss_params(tbtt_info);
                break;
            case TBTT_INFO_LEN_5:
                qdf_nofl_info("    short_ssid=%d",tbtt_info->short_ssid);
                break;
            case TBTT_INFO_LEN_6:
                qdf_nofl_info("    short_ssid=%d",tbtt_info->short_ssid);
                print_bss_params(tbtt_info);
                break;
            case TBTT_INFO_LEN_7:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                break;
            case TBTT_INFO_LEN_8:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                print_bss_params(tbtt_info);
                break;
            case TBTT_INFO_LEN_9:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                print_bss_params(tbtt_info);
                qdf_nofl_info("    psd_20mhz=%d", tbtt_info->psd_20mhz);
                break;
            case TBTT_INFO_LEN_11:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                qdf_nofl_info("    short_ssid=%d",tbtt_info->short_ssid);
                break;
            case TBTT_INFO_LEN_12:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                qdf_nofl_info("    short_ssid=%d",tbtt_info->short_ssid);
                print_bss_params(tbtt_info);
                break;
            case TBTT_INFO_LEN_13:
                qdf_nofl_info("    bssid=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
                          tbtt_info->bssid[0], tbtt_info->bssid[1],
                          tbtt_info->bssid[2], tbtt_info->bssid[3],
                          tbtt_info->bssid[4], tbtt_info->bssid[5]);
                qdf_nofl_info("    short_ssid=%d",tbtt_info->short_ssid);
                print_bss_params(tbtt_info);
                qdf_nofl_info("    psd_20mhz=%d", tbtt_info->psd_20mhz);
                break;
            default:
                break;
        }
        cnt++;
    }
}

void ieee80211_dump_user_rnr_entries(struct ieee80211com *ic)
{
    struct user_rnr_data *rnr_node = NULL;

    TAILQ_FOREACH(rnr_node, &ic->ic_user_neighbor_ap.user_rnr_data_list,
                  user_rnr_next_uid) {
        ieee80211_dump_user_rnr_entry(rnr_node);
    }
}
qdf_export_symbol(ieee80211_dump_user_rnr_entries);


static struct user_rnr_data *alloc_user_rnr_node(uint32_t user_buf_len)
{
    struct user_rnr_data *ptr = NULL;

    if (user_buf_len == 0)
        return NULL;

    ptr = qdf_mem_malloc(sizeof(struct user_rnr_data));
    if (ptr == NULL)
        return NULL;

    ptr->user_buf = qdf_mem_malloc(user_buf_len);
    if (ptr->user_buf == NULL) {
        qdf_mem_free(ptr);
        return NULL;
    }

    return ptr;
}

int ieee80211_add_user_rnr_entry(struct ieee80211com *ic, u_int8_t uid,
                                  u_int8_t *buf, u_int32_t len)
{
    struct user_rnr_data *rnr_node = NULL;
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    acfg_rnr_nbr_ap_info_t *from_ap_info = NULL;
    uint16_t max_size;

    if (uid > ACFG_USER_RNR_MAX_UID) {
        qdf_err("uid %d bigger than max %d\n",uid,ACFG_USER_RNR_MAX_UID);
        return EINVAL;
    }

    /* search the uid, if found in list, delete the entry */
    ieee80211_del_user_rnr_entry(ic, uid);

    max_size = ieee80211_get_max_user_rnr_size_allowed(ic);
    if (buf == NULL ||
        len == 0 ||
        (len + ic->ic_user_neighbor_ap.running_length) >
         max_size) {
        qdf_err("buf NULL or wrong len, buf=0x%p, len=%d\n",buf,len);
        return EINVAL;
    }

    from_ap_info = (acfg_rnr_nbr_ap_info_t *)buf;
    if (from_ap_info->hdr_info_len > TBTT_INFO_LEN_13) {
        qdf_err("TBTT info len = %d too big\n", from_ap_info->hdr_info_len);
        return EINVAL;
    }

    rnr_node = alloc_user_rnr_node(len);
    if (rnr_node == NULL)
        return ENOMEM;

    rnr_node->uid = uid;
    rnr_node->uid_buf_length = len;
    rnr_node->uid_hdr_ap_length = from_ap_info->hdr_info_len;
    rnr_node->uid_org_ap_cnt = from_ap_info->hdr_info_cnt+1;

    ap_info = (ieee80211_rnr_nbr_ap_info_t *)rnr_node->user_buf;
    ap_info->hdr_info_len = from_ap_info->hdr_info_len;
    ap_info->hdr_info_cnt = from_ap_info->hdr_info_cnt;
    ap_info->op_class = from_ap_info->op_class;
    ap_info->channel = from_ap_info->channel;

    qdf_mem_copy(ap_info->tbtt_info,
                 from_ap_info->tbtt_info,
                 ap_info->hdr_info_len*(ap_info->hdr_info_cnt+1));
    qdf_spin_lock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
    TAILQ_INSERT_TAIL(&ic->ic_user_neighbor_ap.user_rnr_data_list,
                      rnr_node, user_rnr_next_uid);
    qdf_spin_unlock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
    ic->ic_user_neighbor_ap.running_length += len;
    ieee80211_user_rnr_frm_update(ic, ic->ic_user_rnr_frm_ctrl, true);
    return 0;
}
qdf_export_symbol(ieee80211_add_user_rnr_entry);
