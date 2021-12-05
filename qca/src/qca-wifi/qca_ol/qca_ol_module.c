/*
 * Copyright (c) 2018 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#include <linux/module.h>

#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include "ol_if_athvar.h"
#include <pld_common.h>
#include <target_if.h>

#ifdef QCA_WIFI_MODULE_PARAMS_FROM_INI
/**
 * initialize_qca_ol_module_param_from_ini() - Update qca_ol module params
 *
 *
 * Read the file which has wifi module params, parse and update
 * qca_ol module params.
 *
 * Return: void
 */
extern void initialize_qca_ol_module_param_from_ini(void);
#endif

QDF_STATUS create_target_if_ctx(void);

/**
 * qca_ol_mod_init() - module initialization
 *
 * Return: int
 */
#ifndef QCA_SINGLE_WIFI_3_0
static int __init qca_ol_mod_init(void)
#else
int qca_ol_mod_init(void)
#endif
{
    QDF_STATUS status;
#ifdef QCA_WIFI_MODULE_PARAMS_FROM_INI
    initialize_qca_ol_module_param_from_ini();
#endif
    /* Create target interface global context */
    status = create_target_if_ctx();

    /* Register legacy WMI service ready event callback */
    if (status == QDF_STATUS_SUCCESS) {
        register_legacy_wmi_service_ready_callback();
    } else {
        qdf_print("%s Failed ",__func__);
    }

    /* Assign OL callback to tx ops registeration handler */
    wlan_global_lmac_if_set_txops_registration_cb(WLAN_DEV_OL, target_if_register_tx_ops);
    wlan_lmac_if_set_umac_txops_registration_cb(olif_register_umac_tx_ops);

    pld_init();

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    /* Initialize wifi mac database object */
    osif_nss_wifi_mac_db_obj_init();
#endif
	return 0;
}
#ifndef QCA_SINGLE_WIFI_3_0
module_init(qca_ol_mod_init);
#endif

/**
 * qca_ol_mod_exit() - module remove
 *
 * Return: int
 */
#ifndef QCA_SINGLE_WIFI_3_0
static void __exit qca_ol_mod_exit(void)
#else
void qca_ol_mod_exit(void)
#endif
{

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    /* Unregister bridge notifier if registered */
    osif_nss_br_fdb_update_notifier_unregister();
    osif_nss_br_fdb_notifier_unregister();
    osif_nss_wifi_mac_db_obj_deinit();
#endif

    /* Remove target interface global context */
    target_if_deinit();

    pld_deinit();
}
#ifndef QCA_SINGLE_WIFI_3_0
module_exit(qca_ol_mod_exit);
#endif
