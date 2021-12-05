/*
 * Copyright (c) 2011-2014, 2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef _WLAN_MLME_IF_H
#define _WLAN_MLME_IF_H

#include <qdf_types.h>
#include <qdf_trace.h>
#include <ieee80211_mlme_priv.h>
#include <ieee80211_objmgr_priv.h>
#include <wlan_serialization_api.h>
#include <wlan_cm_public_struct.h>
#include <wlan_cm_api.h>

#define wlan_mlme_err(format, args...) \
    QDF_TRACE_ERROR(QDF_MODULE_ID_MLME, format, ## args)
#define wlan_mlme_info(format, args...) \
    QDF_TRACE_INFO(QDF_MODULE_ID_MLME, format, ## args)
#define wlan_mlme_debug(format, args...) \
    QDF_TRACE_DEBUG(QDF_MODULE_ID_MLME, format, ## args)

#define wlan_mlme_nofl_err(format, args...) \
    QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_MLME, format, ## args)
#define wlan_mlme_nofl_info(format, args...) \
    QDF_TRACE_INFO_NO_FL(QDF_MODULE_ID_MLME, format, ## args)
#define wlan_mlme_nofl_debug(format, args...) \
    QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_MLME, format, ## args)

/* Serialization command timeout in milliseconds */
#define WLAN_MLME_SER_CMD_TIMEOUT_MS 65000
#define MLME_SER_RESTART_CMD_TIMEOUT_MS 90000

#define WLAN_SERIALZATION_CANCEL_WAIT_ITERATIONS 1000
#define WLAN_SERIALZATION_CANCEL_WAIT_TIME 100

/*
 * enum wlan_mlme_notify_mod - Call the notification cb
 * @WLAN_MLME_NOTIFY_NONE - No handlers
 * @WLAN_MLME_NOTIFY_MLME - Notify mlme layer
 * @WLAN_MLME_NOTIFY_OSIF - Notify osif layer
 */
enum wlan_mlme_notify_mod {
    WLAN_MLME_NOTIFY_NONE,
    WLAN_MLME_NOTIFY_MLME,
    WLAN_MLME_NOTIFY_OSIF,
};

/*
 * enum mlme_cmd_activation_ctx - Activation context of cmd
 * @MLME_CTX_DIRECT - Activated from caller context
 * @MLME_CTX_SCHED - Activated in scheduler context
 */
enum mlme_cmd_activation_ctx {
    MLME_CTX_DIRECT,
    MLME_CTX_SCHED,
};

/*
 * struct wlan_mlme_ser_data - Data in serialization command
 * @vdev: VDEV object associated to the command
 * @flags: Store restart or start status flag
 * @notify_osif: On completion of cmd execution indicate whether
 *  the post processing handlers to be called
 * @cmd_in_sched: Mark if a cmd is activated in scheduler context
 * @activation_ctx: Denote the context in which the cmd was activated
 */
struct wlan_mlme_ser_data {
    struct wlan_objmgr_vdev *vdev;
    int32_t flags;
    uint8_t notify_osif;
    uint8_t cmd_in_sched;
    uint8_t activation_ctx;
};

/*
 * struct wlan_mlme_sched_data - Scheduler context execution
 * @vdev: Objmgr vdev object
 * @cmd_type: Command type to be processed
 * @notify_status: Whether to notify MLME and OSIF
 */
struct wlan_mlme_sched_data {
    struct wlan_objmgr_vdev *vdev;
    enum wlan_serialization_cmd_type cmd_type;
    uint8_t notify_status;
};

/*
 * osif_get_num_active_vaps(): Get number of active vaps
 * @comhandle: legacy ic handle
 *
 * Return: number of active vaps
 */
u_int32_t osif_get_num_active_vaps(wlan_dev_t comhandle);

/*
 * osif_get_num_running_vaps(): Get number of running vaps
 * @comhandle: legacy ic handle
 *
 * Running vaps include vaps with tx_rx capability
 * Return: number of active vaps
 */
u_int16_t osif_get_num_running_vaps(wlan_dev_t comhandle);

/*
 * osif_ht40_event_handler(): Event handler
 * @channel: Channel configuration from the event notifier
 *
 * Return: void
 */
void osif_ht40_event_handler(void *arg, wlan_chan_t channel);

/*
 * osif_acs_event_handler(): ACS Event handler
 * @channel: Channel configuration from the event notifier
 *
 * Return: void
 */
void osif_acs_event_handler(void *arg, wlan_chan_t channel);

/*
 * osif_mlme_notify_handler(): Cmd post processing in OSIF layer
 * @vap: legacy vap handle
 * @cmd_type: Serialization cmd type for which the handler is called
 *
 * Return: void
 */
void osif_mlme_notify_handler(wlan_if_t vap,
        enum wlan_serialization_cmd_type cmd_type);

/*
 * osif_start_acs_on_other_vaps() - Check if ACS is needed for other vaps
 * @arg: Original vap on which this event is started
 * @vap: Legacy vap handle on which ACS will be registered
 *
 * Return: void
 */
void osif_start_acs_on_other_vaps(void *arg, wlan_if_t vap);

/*
 * wlan_mlme_vdev_cmd_handler(): Cmd post processing handler in mlme layer
 * @vdev: Objmgr vdev information
 * @cmd_type: Serialization cmd type for which the handler is called
 *
 * Return: void
 */
void
wlan_mlme_vdev_cmd_handler(struct wlan_objmgr_vdev *vdev,
                           enum wlan_serialization_cmd_type cmd_type);

/*
 * mlme_ser_proc_vdev_start(): Callback called for command activation from
 * serialization
 * @cmd: serialization command information
 * @reason: Callback reason on which the cb function should operate
 *
 * Return: status of command activation after processing
 */
QDF_STATUS
mlme_ser_proc_vdev_start(struct wlan_serialization_command *cmd,
                            enum wlan_serialization_cb_reason reason);

/*
 * mlme_ser_proc_vdev_stop(): Callback called for command activation from
 * serialization
 * @cmd: serialization command information
 * @reason: Callback reason on which the cb function should operate
 *
 * Return: status of command activation after processing
 */
QDF_STATUS
mlme_ser_proc_vdev_stop(struct wlan_serialization_command *cmd,
                           enum wlan_serialization_cb_reason reason);

/*
 * wlan_mlme_release_vdev_req() - Release a cmd from the serialization queue
 * @vdev: vdev object component
 * @cmd_type: serialization command type
 * @status: return value from the command execution
 *
 * Return: Success on command removal, else error value
 */
QDF_STATUS
wlan_mlme_release_vdev_req(struct wlan_objmgr_vdev *vdev,
                           enum wlan_serialization_cmd_type cmd_type,
                           int32_t status);

/*
 * wlan_mlme_start_vdev() - Send start request to a vdev
 * @vdev: vdev object component
 * @f_scan: forcescan flag indicate is rescan is required
 * @notify_osif: post processing handler to be called after cmd execution
 *
 * Return: Success on cmd addition to the serialization queue, else error value
 */
QDF_STATUS
wlan_mlme_start_vdev(struct wlan_objmgr_vdev *vdev,
                     uint32_t f_scan, uint8_t notify_osif);

/*
 * wlan_mlme_stop_vdev() - Send stop request to a vdev
 * @vdev: vdev object component
 * @flags: stop request flags to be sent to mlme
 * @notify_osif: post processing handler to be called after cmd execution
 *
 * Return: Success on cmd addition to the serialization queue, else error value
 */
QDF_STATUS
wlan_mlme_stop_vdev(struct wlan_objmgr_vdev *vdev,
                    uint32_t flags, uint8_t notify_osif);

/*
 * wlan_mlme_cm_start() - Start connection manager for STA vdev
 * @vdev: vdev object component
 * @source: Requestor source id
 *
 * Return: Success on connect request processed, else error value
 */
QDF_STATUS wlan_mlme_cm_start(struct wlan_objmgr_vdev *vdev,
                              enum wlan_cm_source source);

/*
 * wlan_mlme_cm_start() - Start connection manager for STA vdev
 * @vdev: vdev object component
 * @source: Requestor source id
 * @reason: Disconnect reason
 * @sync: Indicate if disconnect has to processed in sync mode
 *
 * Return: Success on connect request processed, else error value
 */
QDF_STATUS wlan_mlme_cm_stop(struct wlan_objmgr_vdev *vdev,
                             enum wlan_cm_source source,
                             enum wlan_reason_code reason,
                             bool sync);

/*
 * wlan_mlme_stop_start_vdev() - Send stop and start request to a vdev
 * with vdev command held.
 * @vdev: vdev object component
 * @f_scan: forcescan flag indicate is rescan is required
 * @notify_osif: post processing handler to be called after cmd execution
 *
 * Return: Success on cmd addition to the serialization queue, else error value
 */
QDF_STATUS wlan_mlme_stop_start_vdev(struct wlan_objmgr_vdev *vdev,
                                     uint32_t f_scan, uint8_t notify_osif);

/*
 * wlan_mlme_dev_restart() - Send restart request to a either pdev or vdev
 * @vdev: vdev object component
 * @type: indicate if it is pdev or vdev restart
 *
 * Return: Success on cmd addition to the serialization queue, else error value
 */
QDF_STATUS wlan_mlme_dev_restart(struct wlan_objmgr_vdev *vdev,
                                 enum wlan_serialization_cmd_type type);

/*
 * wlan_mlme_pdev_csa_restart() - Send csa restart request to pdev
 * @vdev: vdev object component
 * @flags: flags if required
 * @notify_osif: post processing handler to be called after cmd execution
 *
 * Return: Success on cmd addition to the serialization queue, else error value
 */
QDF_STATUS wlan_mlme_pdev_csa_restart(struct wlan_objmgr_vdev *vdev,
        uint32_t flags, uint8_t notify_osif);

/*
 * wlan_mlme_inc_act_cmd_timeout() - increase serialization active cmd timeout
 * @vdev: vdev object component
 * @cmd_type: serialization command type
 *
 * Return: void
 */
void
wlan_mlme_inc_act_cmd_timeout(struct wlan_objmgr_vdev *vdev,
                              enum wlan_serialization_cmd_type cmd_type);

/*
 * wlan_mlme_wait_for_cmd_completion() - wait for vdev active cmds completion
 * @vdev: vdev object component
 *
 * Return: void
 */
void wlan_mlme_wait_for_cmd_completion(struct wlan_objmgr_vdev *vdev);

/*
 * wlan_mlme_wait_for_scan_cmd_completion() - wait for scan cmds completion
 * @vdev: vdev object component
 *
 * This API is expected to be called from non-interrupt context only.
 * qdf_wait_single_event() called in this API asserts if it is called from
 * interrupt context.
 *
 * Return: void
 */
void wlan_mlme_wait_for_scan_cmd_completion(struct wlan_objmgr_vdev *vdev);

/*
 * mlme_vdev_add_stop_start_to_pq_head() - Add stop-start cmd to the head of the
 * pending queue.
 * @vdev: Object manager vdev
 *
 * Enqueue exception start followed by stop cmd to the head of the
 * pending queue (which results in stop-start sequence)
 *
 * Return: Success on adding the cmds to the pending queue.
 */
QDF_STATUS mlme_vdev_add_stop_start_to_pq_head(struct wlan_objmgr_vdev *vdev);

bool ieee80211_is_6g_valid_rate(struct ieee80211vap *vap, u_int32_t rate);
int ieee80211_rate_is_valid_basic(struct ieee80211vap *, u_int32_t);

void wlan_mlme_cm_event_init(struct ieee80211vap *vap);
void wlan_mlme_cm_event_deinit(struct ieee80211vap *vap);

#if SM_ENG_HIST_ENABLE
void wlan_mlme_cm_action_history_init(struct ieee80211vap *vap);
void wlan_mlme_cm_action_history_deinit(struct ieee80211vap *vap);
void wlan_mlme_cm_action_print_history(struct wlan_cm_action_history *cm_action_history);
#endif

QDF_STATUS wlan_mlme_cm_ext_bss_peer_create_req(struct wlan_objmgr_vdev *vdev,
						struct qdf_mac_addr *peer_mac);

QDF_STATUS wlan_mlme_cm_vdev_down(struct wlan_objmgr_vdev *vdev);

QDF_STATUS wlan_mlme_cm_bss_peer_delete_req(struct wlan_objmgr_vdev *vdev);

QDF_STATUS wlan_mlme_cm_join_start(struct wlan_objmgr_vdev *vdev,
				   struct wlan_cm_vdev_connect_req *req);

QDF_STATUS wlan_mlme_cm_reassoc_join_start(
                        struct wlan_objmgr_vdev *vdev,
                        struct wlan_cm_vdev_reassoc_req *req);

void mlme_cm_resp_timer(void *arg);

struct scan_cache_entry *mlme_cm_get_active_scan_entry(struct ieee80211vap *vap);

/*
 * wlan_mlme_cm_connect_start() - actions on connect request
 * @vdev: Object manager vdev
 * @req: Connect request parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_connect_start(struct wlan_objmgr_vdev *vdev,
				      struct wlan_cm_connect_req *req);

/*
 * wlan_mlme_cm_connect_active() - actions on connect acivation
 * @vdev: Object manager vdev
 * @req: Connect request parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_connect_active(struct wlan_objmgr_vdev *vdev,
				       struct wlan_cm_vdev_connect_req *req);

/*
 * wlan_mlme_cm_connect complete() - actions on connect complete
 * @vdev: Object manager vdev
 * @rsp: Connect response parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_connect_complete(struct wlan_objmgr_vdev *vdev,
					 struct wlan_cm_connect_resp *rsp);

/*
 * wlan_mlme_cm_disconnect_start() - actions on disconnect request
 * @vdev: Object manager vdev
 * @req: Connect request parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_disconnect_start(struct wlan_objmgr_vdev *vdev,
					 struct wlan_cm_disconnect_req *req);

/*
 * wlan_mlme_cm_disconnect_active() - actions on disconnect activation
 * @vdev: Object manager vdev
 * @req: Connect request parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_disconnect_active(struct wlan_objmgr_vdev *vdev,
					  struct wlan_cm_vdev_discon_req *req);

/*
 * wlan_mlme_cm_disconnect_complete() - actions on disconnect complete
 * @vdev: Object manager vdev
 * @rsp: Connect response parameters
 *
 * Return: QDF_STATUS_SUCCESS if no error in actions
 */
QDF_STATUS wlan_mlme_cm_disconnect_complete(struct wlan_objmgr_vdev *vdev,
					    struct wlan_cm_discon_rsp *rsp);

/**
 * wlan_mlme_cm_ext_hdl_create() - Connection manager callback to create ext
 * context
 * @vdev: VDEV object
 * @ext_cm_ptr: pointer to connection manager ext pointer
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_mlme_cm_ext_hdl_create(struct wlan_objmgr_vdev *vdev,
				       cm_ext_t **ext_cm_ptr);

/**
 * wlan_mlme_cm_ext_hdl_destroy() - Connection manager callback to create ext
 * context
 * @vdev: VDEV object
 * @ext_cm_ptr: connection manager ext pointer
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_mlme_cm_ext_hdl_destroy(struct wlan_objmgr_vdev *vdev,
				        cm_ext_t *ext_cm_ptr);
/*
 * wlan_mlme_dispatch_cm_resp() - dispatch cm resp in deferred context
 * @vap: vap handle
 * @cm_evt_id: CM resp event id
 *
 * Return: void
 */
static inline void wlan_mlme_dispatch_cm_resp(struct ieee80211vap *vap,
					      enum cm_resp_evt cm_evt_id)
{
	cm_ext_t *cm_ext_handle = NULL;
	cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);
	if (!cm_ext_handle)
		return;

	cm_ext_handle->cm_evt_id = cm_evt_id;
	if (qdf_timer_mod(&cm_ext_handle->cm_defer_resp, 0))
		QDF_ASSERT(0);
}

/*
 * wlan_mlme_get_assoc_sm_handle() - get assoc sm handle
 * @vdev: Vdev object
 *
 * Return: void
 */
static inline
wlan_assoc_sm_t wlan_mlme_get_assoc_sm_handle(struct wlan_objmgr_vdev *vdev)
{
     cm_ext_t *cm_ext_handle = NULL;
     cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
     if (!cm_ext_handle)
         return NULL;

     return cm_ext_handle->assoc_sm_handle;
}

#if WLAN_SER_DEBUG
extern void wlan_ser_print_history(struct wlan_objmgr_vdev *vdev, u_int8_t,
                                   u_int32_t);
#else
#define wlan_ser_print_history(params...)
#endif

#if SM_ENG_HIST_ENABLE
void wlan_mlme_print_all_sm_history(void);
void wlan_mlme_print_vdev_sm_history(struct wlan_objmgr_psoc *psoc,
                                     void *obj, void *arg);
#if SM_HIST_DEBUGFS_SUPPORT
/*
 * wlan_mlme_sm_debugfs_history() - Print VDEV SM history in debugfs
 * @m: debug fs file
 * @v: context
 *
 * Return: void
 */
int wlan_mlme_sm_debugfs_history(qdf_debugfs_file_t m, void *arg);
#endif
#else
static inline void wlan_mlme_print_all_sm_history(void) {}
static inline void wlan_mlme_print_vdev_sm_history(struct wlan_objmgr_psoc *psoc,
                                                   void *obj, void *arg) {}
#if SM_HIST_DEBUGFS_SUPPORT
static int wlan_mlme_sm_debugfs_history(qdf_debugfs_file_t m, void *arg) { return 0; }
#endif
#endif

#endif /* _WLAN_MLME_IF_H  */
