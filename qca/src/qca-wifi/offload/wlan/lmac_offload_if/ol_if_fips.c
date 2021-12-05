/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2011, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ol_if_fips.h>

int ol_ath_fips_event_handler(ol_soc_t sc, u_int8_t *evt_buf, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct ieee80211com *ic;
    struct wmi_host_fips_event_param fips_ev= {0};
    u_int32_t output_len;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;
    QDF_STATUS status;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    status = wmi_extract_fips_event_data(wmi_handle, evt_buf, &fips_ev);
    if (status != QDF_STATUS_SUCCESS) {
            qdf_err("Unable to extract FIPS event");
            return qdf_status_to_os_return(status);
    }

    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(fips_ev.pdev_id),
                                      WLAN_MLME_SB_ID);
    if (!pdev) {
         qdf_err("pdev object (id: %d) is NULL", PDEV_UNIT(fips_ev.pdev_id));
         return -EINVAL;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("ic (id: %d) is NULL ", PDEV_UNIT(fips_ev.pdev_id));
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -EINVAL;
    }
    /* Set this flag to notify fips_event had occured */
    qdf_atomic_inc(&(ic->ic_fips_event));

    output_len = sizeof(struct ath_fips_output) + fips_ev.data_len;

    /* To pass the output data to application */
    ic->ic_output_fips = (struct ath_fips_output *) OS_MALLOC(ic->ic_osdev, output_len, GFP_KERNEL);
    if (!ic->ic_output_fips) {
        qdf_err("Invalid ic_output_fips");
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -EINVAL;
    }

    qdf_info("ic->ic_output_fips %pK", ic->ic_output_fips);
    ic->ic_output_fips->error_status = fips_ev.error_status;
    ic->ic_output_fips->data_len = fips_ev.data_len;
    print_hex_dump(KERN_DEBUG, "\t Handler Data: ", DUMP_PREFIX_NONE, 16, 1,
                                          fips_ev.data, fips_ev.data_len, true);
    OS_MEMCPY(ic->ic_output_fips->data, fips_ev.data, fips_ev.data_len);
    qdf_info("error_status %x data_len %x",
             ic->ic_output_fips->error_status, fips_ev.data_len);
    print_hex_dump(KERN_DEBUG, "Cipher text: ", DUMP_PREFIX_NONE, 16, 1,
               fips_ev.data, fips_ev.data_len, true);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    return 0;
}

int ol_ath_encrypt_decrypt_data_rsp_event_handler(ol_scn_t sc, u_int8_t *evt_buf, u_int32_t datalen)
{
    struct ieee80211com *ic;
    struct disa_encrypt_decrypt_resp_params disa_ev= {0};
    u_int32_t output_len;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct wmi_unified *wmi_handle;

    psoc = target_if_get_psoc_from_scn_hdl(sc);
    if (!psoc) {
        qdf_err("psoc is NULL");
        return -EINVAL;
    }

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi handle is NULL");
        return -EINVAL;
    }

    if (wmi_extract_encrypt_decrypt_resp_params(wmi_handle, evt_buf, &disa_ev) !=
                                                QDF_STATUS_SUCCESS) {
            qdf_err("Unable to extract DISA event");
            return -EINVAL;
    }

    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, disa_ev.vdev_id,
                                                WLAN_DISA_ID);
    if (!vdev) {
        qdf_err("null vdev");
        return -EINVAL;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        qdf_err("null pdev");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_DISA_ID);
        return -EINVAL;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);

    if (!ic) {
        qdf_err("ic NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_DISA_ID);
        return -EINVAL;
    }

    output_len = sizeof(struct ath_fips_output) + disa_ev.data_len;

    /* To pass the output data to application */
    ic->ic_output_fips = (struct ath_fips_output *) qdf_mem_malloc(output_len);
    if (!ic->ic_output_fips) {
        qdf_err("Invalid ic_output_disa");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_DISA_ID);
        return -EINVAL;
    }

    ic->ic_output_fips->error_status = disa_ev.status;
    ic->ic_output_fips->data_len = disa_ev.data_len;
    qdf_mem_copy(ic->ic_output_fips->data, disa_ev.data, disa_ev.data_len);

    /* Set this flag to notify disa_event had occured */
    if (qdf_atomic_read(&(ic->ic_fips_event)) == 1)
        qdf_atomic_inc(&(ic->ic_fips_event));

    qdf_info("error_status %x data_len %x",
             ic->ic_output_fips->error_status, disa_ev.data_len);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_DISA_ID);
    return 0;
}

void fips_data_dump(wlan_if_t vap, void *arg)
{
    struct ath_fips_cmd *afb = (struct ath_fips_cmd *)arg;
    int i;
    u_int8_t *ptr = (u_int8_t *) afb->data;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n ********Dumping FIPS structure********\n");
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n FIPS command: %d", afb->fips_cmd);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n Key Length: %d", afb->key_len);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n Data Length: %d", afb->data_len);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n************* KEY ************\n");
    for (i=0; i < afb->key_len; i++)
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%02x ",afb->key[i]);
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n************* DATA ***********\n");

    for (i=0; i < (afb->data_len); i++)
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%02x ", *(ptr + i));
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                      "\n************* IV  ***********\n");

    for (i=0; i < 16; i++)
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%02x ", afb->iv[i]);
    }
}

int ol_ath_fips_test(struct ieee80211com *ic, wlan_if_t vap,
                            struct ath_fips_cmd *fips_buf)
{
    int retval = 0;
    uint32_t pdev_idx;
    struct wlan_objmgr_vdev *vdev = NULL;

    if (fips_buf->mode == FIPS_MODE_ECB_AES) {
        fips_data_dump(vap, fips_buf);

        pdev_idx = lmac_get_pdev_idx(ic->ic_pdev_obj);
        if(pdev_idx < 0) {
            qdf_err("pdev_idx is invalid");
            return -EINVAL;
        }

        if (fips_buf->key_len <= MAX_KEY_LEN_FIPS) {
            retval = ol_ath_pdev_fips(ic->ic_pdev_obj, fips_buf->key,
                                      fips_buf->key_len,
                                      (uint8_t *)fips_buf->data,
                                       fips_buf->data_len, fips_buf->mode,
                                       fips_buf->fips_cmd, pdev_idx);
        } else {
            retval = -EINVAL;
        }
    } else if (fips_buf->mode == FIPS_MODE_CCM_GCM) {
        vdev = vap->vdev_obj;
        retval = ol_ath_vdev_disa(vdev, fips_buf);
    } else {
        qdf_err("Invalid fips mode");
        retval = -EINVAL;
    }

    if (-EINVAL == retval) {
        qdf_err("Data Len invalid: must be multiple of 16 bytes & < 1500 byte");
        retval = -EFAULT;
    }
    return retval;
}

