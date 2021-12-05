/*
 * Copyright (c) 2012, 2017, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _WDI_EVENT_API_H_
#define _WDI_EVENT_API_H_

#include "athdefs.h"
#include "cdp_txrx_stats_struct.h"
#include "cdp_txrx_cmn_struct.h"
/*  In few of the  wdi event call backs, we don't require to pass few arguements,
    in that case we pass -1 so, here we #define -1 to WDI_NO_VAL, which
    means the WDI call back does not require that value.
*/
#define WDI_NO_VAL (-1)
struct wdi_event_rx_peer_invalid_msg {
    qdf_nbuf_t msdu;
    struct ieee80211_frame *wh;
    u_int8_t vdev_id;
};

#define WDI_NUM_EVENTS WDI_EVENT_LAST - WDI_EVENT_BASE

#define WDI_EVENT_NOTIFY_BASE 0x200
enum WDI_EVENT_NOTIFY {
    WDI_EVENT_SUB_DEALLOCATE = WDI_EVENT_NOTIFY_BASE,
    /* End of new notification types */

    WDI_EVENT_NOTIFY_LAST
};

/* Opaque event callback */
typedef void (*wdi_event_cb)(void *pdev, enum WDI_EVENT event, void *data,
                                u_int16_t peer_id, uint32_t status);

/* Opaque event notify */
typedef void (*wdi_event_notify)(enum WDI_EVENT_NOTIFY notify,
            enum WDI_EVENT event);
/**
 * @typedef wdi_event_subscribe
 * @brief Used by consumers to subscribe to WDI event notifications.
 * @details
 *  The event_subscribe struct includes pointers to other event_subscribe
 *  objects.  These pointers are simply to simplify the management of
 *  lists of event subscribers.  These pointers are set during the
 *  event_sub() function, and shall not be modified except by the
 *  WDI event management SW, until after the object's event subscription
 *  is canceled by calling event_unsub().
 */

typedef struct wdi_event_subscribe_t {
    wdi_event_cb callback; /* subscriber event callback structure head*/
    void *context; /* subscriber object that processes the event callback */
    struct {
        /* private - the event subscriber SW shall not use this struct */
        struct wdi_event_subscribe_t *next;
        struct wdi_event_subscribe_t *prev;
    } priv;
} wdi_event_subscribe;

struct wdi_event_pdev_t;
typedef struct wdi_event_pdev_t *wdi_event_pdev_handle;

/**
 * @brief Subscribe to a specified WDI event.
 * @details
 *  This function adds the provided wdi_event_subscribe object to a list of
 *  subscribers for the specified WDI event.
 *  When the event in question happens, each subscriber for the event will
 *  have their callback function invoked.
 *  The order in which callback functions from multiple subscribers are
 *  invoked is unspecified.
 *
 * @param soc - the event soc device
 * @param pdev_id - id of the event physical device
 * @param event_cb_sub - the callback and context for the event subscriber
 * @param event - which event's notifications are being subscribed to
 * @return error code, or A_OK for success
 */
A_STATUS
wdi_event_sub(struct cdp_soc_t *soc, uint8_t pdev_id,
    wdi_event_subscribe *event_cb_sub_handle,
    uint32_t event);

/**
 * @brief Unsubscribe from a specified WDI event.
 * @details
 *  This function removes the provided event subscription object from the
 *  list of subscribers for its event.
 *  This function shall only be called if there was a successful prior call
 *  to event_sub() on the same wdi_event_subscribe object.
 *
 * @param soc - the event soc device
 * @param pdev_id - id of the event physical device with the list of event subscribers
 * @param event_cb_sub - the event subscription object
 * @param event - which event is being unsubscribed
 * @return error code, or A_OK for success
 */
A_STATUS
wdi_event_unsub(struct cdp_soc_t *soc, uint8_t pdev_id,
    wdi_event_subscribe *event_cb_sub_handle,
    uint32_t event);

#endif /* _WDI_EVENT_API_H_ */
