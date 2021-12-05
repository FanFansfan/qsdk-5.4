/*
 * Copyright (c) 2016-2017, 2019 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
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

#include <osdep.h>
#include <wbuf.h>
#include <ieee80211_var.h>


#define MIN_HEAD_ROOM  64
#define NBUF_ALLOC_FAIL_LIMIT 100


#ifdef NBUF_MEMORY_DEBUG
qdf_nbuf_t wbuf_alloc_debug(osdev_t os_handle, enum wbuf_type type,
			    u_int32_t len, const char *func, uint32_t line)
#else
qdf_nbuf_t wbuf_alloc(osdev_t os_handle, enum wbuf_type type, u_int32_t len)
#endif
{
    const u_int align = sizeof(u_int32_t);
    qdf_nbuf_t  nbf;
    u_int buflen, reserve;
#if defined(CONFIG_WIFI_EMULATION_WIFI_3_0) && defined (BUILD_X86)
    uint32_t lowmem_alloc_tries = 0;
#endif

    if ((type == WBUF_TX_DATA) || (type == WBUF_TX_MGMT) ||
            (type == WBUF_TX_BEACON) || (type == WBUF_TX_INTERNAL)
            || (type == WBUF_TX_CTL)) {
        reserve = MIN_HEAD_ROOM;
        buflen = roundup(len+MIN_HEAD_ROOM, 4);
    } else {
        reserve = 0;
        buflen = roundup(len, 4);
    }
#if defined(CONFIG_WIFI_EMULATION_WIFI_3_0) && defined (BUILD_X86)
realloc:
#endif

#ifdef NBUF_MEMORY_DEBUG
    nbf = qdf_nbuf_alloc_debug(NULL, buflen, 0, align, FALSE, func, line);
#else
    nbf = qdf_nbuf_alloc(NULL, buflen, 0, align, FALSE);
#endif

#if defined(CONFIG_WIFI_EMULATION_WIFI_3_0) && defined (BUILD_X86) && !defined (QCA_WIFI_QCN9000)
    /* Hawkeye M2M emulation cannot handle memory addresses below 0x50000000
     * Though we are trying to reserve low memory upfront to prevent this,
     * we sometimes see SKBs allocated from low memory.
     */
    if (nbf != NULL) {
        if (virt_to_phys(qdf_nbuf_data(nbf)) < 0x50000040) {
            lowmem_alloc_tries++;
            if (lowmem_alloc_tries > 100) {
                return NULL;
            } else {
               /* Not freeing to make sure it
                * will not get allocated again
                */
                goto realloc;
            }
        }
    }
#endif
    if (nbf != NULL)
    {
        if (wbuf_alloc_mgmt_ctrl_block(nbf) == NULL) {
#ifdef NBUF_MEMORY_DEBUG
            qdf_nbuf_free_debug(nbf, func, line);
#else
            qdf_nbuf_free(nbf);
#endif
            return NULL;
        }
        N_NODE_SET(nbf, NULL);
        N_FLAG_KEEP_ONLY(nbf, 0);
        N_TYPE_SET(nbf, type);
        N_COMPLETE_HANDLER_SET(nbf, NULL);
        N_COMPLETE_HANDLER_ARG_SET(nbf, NULL);
#if defined(ATH_SUPPORT_P2P)
        N_COMPLETE_HANDLER_SET(nbf, NULL);
        N_COMPLETE_HANDLER_ARG_SET(nbf, NULL);
#endif  /* ATH_SUPPORT_P2P */
        if (reserve)
            qdf_nbuf_reserve(nbf, reserve);
    }
    return nbf;
}
#ifdef NBUF_MEMORY_DEBUG
qdf_export_symbol(wbuf_alloc_debug);
#else
qdf_export_symbol(wbuf_alloc);
#endif

void
wbuf_dealloc_mgmt_ctrl_block(__wbuf_t wbuf)
{
    struct ieee80211_cb *mgmt_cb_ptr = qdf_nbuf_get_ext_cb(wbuf);

    if(mgmt_cb_ptr) {

        /*
         * Call the destructor in saved in ext_cb at
         * alloc time
         */
        if (mgmt_cb_ptr->destructor)
            mgmt_cb_ptr->destructor(wbuf);

        qdf_nbuf_set_ext_cb(wbuf, NULL);
        qdf_mem_free(mgmt_cb_ptr);
    }
    return;
}
qdf_export_symbol (wbuf_dealloc_mgmt_ctrl_block);

dma_addr_t
__wbuf_map_single_tx(osdev_t osdev, struct sk_buff *skb, int direction, dma_addr_t *pa)
{
    /*
     * NB: do NOT use skb->len, which is 0 on initialization.
     * Use skb's entire data area instead.
     */
    *pa = bus_map_single(osdev, skb->data, UNI_SKB_END_POINTER(skb) - skb->data, direction);

    return *pa;
}

void
__wbuf_uapsd_update(qdf_nbuf_t nbf)
{
    /* DO NOTHING */
}

#if ATH_PERF_PWR_OFFLOAD
qdf_export_symbol(__wbuf_map_single);
qdf_export_symbol(__wbuf_map_single_tx);
qdf_export_symbol(__wbuf_unmap_single);
#endif  /* ATH_PERF_PWR_OFFLOAD */

