/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <pld_ahb_fw_sim.h>
#include <pld_common.h>
#include <pld_internal.h>

#ifdef CONFIG_AHB_FW_SIM

#ifdef QCA_WIFI_3_0_ADRASTEA
#define CE_COUNT_MAX 12
#else
#define CE_COUNT_MAX 8
#endif

/**
 * pld_ahb_fw_sim_probe() - Probe function for AHB platform driver
 * @pdev: AHB device
 * @id: AHB device ID table
 *
 * The probe function will be called when AHB device provided
 * in the ID table is detected.
 *
 * Return: int
 */
static int pld_ahb_fw_sim_probe(struct pci_dev *pcidev,
                 const struct pci_device_id *id)
{
    struct pld_context *pld_context;
    int ret = 0;
    struct platform_device *pdev = pci_get_drvdata(pcidev);

    pld_context = pld_get_global_context();
    if (!pld_context) {
        ret = -ENODEV;
        goto out;
    }

    ret = pld_add_dev(pld_context, &pdev->dev,
              PLD_BUS_TYPE_AHB_FW_SIM);
    if (ret)
        goto out;

    return pld_context->ops->probe(&pcidev->dev,
                                   PLD_BUS_TYPE_AHB_FW_SIM,
                                   pdev,
                                   (void *)id);

out:
    return ret;
}

/**
 * pld_ahb_fw_sim_remove() - Remove function for AHB device
 * @pdev: AHB device
 *
 * The remove function will be called when AHB device is disconnected
 *
 * Return: void
 */
static void pld_ahb_fw_sim_remove(struct pci_dev *pdev)
{
    struct pld_context *pld_context;

    pld_context = pld_get_global_context();

    if (!pld_context)
        return;

    pld_context->ops->remove(pci_get_drvdata(pdev), PLD_BUS_TYPE_AHB_FW_SIM);

    pld_del_dev(pld_context, &pdev->dev);
}

/**
 * pld_ahb_fw_sim_idle_restart_cb() - Perform idle restart
 * @pdev: AHB device
 * @id: AHB device ID
 *
 * This function will be called if there is an idle restart request
 *
 * Return: int
 */
static int pld_ahb_fw_sim_idle_restart_cb(struct pci_dev *pdev,
                       const struct pci_device_id *id)
{
    return -ENODEV;
}

/**
 * pld_ahb_fw_sim_idle_shutdown_cb() - Perform idle shutdown
 * @pdev: AHB device
 * @id: AHB device ID
 *
 * This function will be called if there is an idle shutdown request
 *
 * Return: int
 */
static int pld_ahb_fw_sim_idle_shutdown_cb(struct pci_dev *pdev)
{
    return -ENODEV;
}

/**
 * pld_ahb_fw_sim_reinit() - SSR re-initialize function for AHB device
 * @pdev: AHB device
 * @id: AHB device ID
 *
 * During subsystem restart(SSR), this function will be called to
 * re-initialize ahb device.
 *
 * Return: int
 */
static int pld_ahb_fw_sim_reinit(struct pci_dev *pdev,
                  const struct pci_device_id *id)
{
    struct pld_context *pld_context;

    pld_context = pld_get_global_context();
    if (pld_context->ops->reinit)
        return pld_context->ops->reinit(&pdev->dev,
                PLD_BUS_TYPE_AHB_FW_SIM, pdev, (void *)id);

    return -ENODEV;
}

/**
 * pld_ahb_fw_sim_shutdown() - SSR shutdown function for AHB device
 * @pdev: AHB device
 *
 * During SSR, this function will be called to shutdown AHB device.
 *
 * Return: void
 */
static void pld_ahb_fw_sim_shutdown(struct pci_dev *pdev)
{
    struct pld_context *pld_context;

    pld_context = pld_get_global_context();
    if (pld_context->ops->shutdown)
        pld_context->ops->shutdown(&pdev->dev,
                        PLD_BUS_TYPE_AHB_FW_SIM);
}

/**
 * pld_ahb_fw_sim_crash_shutdown() - Crash shutdown function for AHB device
 * @pdev: AHB device
 *
 * This function will be called when a crash is detected, it will shutdown
 * the AHB device.
 *
 * Return: void
 */
static void pld_ahb_fw_sim_crash_shutdown(struct pci_dev *pdev)
{
    struct pld_context *pld_context;

    pld_context = pld_get_global_context();
    if (pld_context->ops->crash_shutdown)
        pld_context->ops->crash_shutdown(&pdev->dev,
                        PLD_BUS_TYPE_AHB_FW_SIM);
}

/**
 * pld_ahb_fw_sim_notify_handler() - Modem state notification callback function
 * @pdev: AHB device
 * @state: modem power state
 *
 * This function will be called when there's a modem power state change.
 *
 * Return: void
 */
static void pld_ahb_fw_sim_notify_handler(struct pci_dev *pdev, int state)
{
    struct pld_context *pld_context;

    pld_context = pld_get_global_context();
    if (pld_context->ops->modem_status)
        pld_context->ops->modem_status(&pdev->dev,
                           PLD_BUS_TYPE_AHB_FW_SIM, state);
}

/**
 * pld_ahb_fw_sim_uevent() - update wlan driver status callback function
 * @pdev: AHB device
 * @status driver uevent status
 *
 * This function will be called when platform driver wants to update wlan
 * driver's status.
 *
 * Return: void
 */
static void pld_ahb_fw_sim_uevent(struct pci_dev *pcidev, uint32_t status)
{
    struct pld_context *pld_context;
    struct platform_device *pdev = pci_get_drvdata(pcidev);

    pld_context = pld_get_global_context();
    if (pld_context->ops->update_status)
        pld_context->ops->update_status(&pdev->dev, status,
                PLD_BUS_TYPE_AHB, pdev, NULL);

    return;
}

static struct pci_device_id pld_ahb_fw_sim_id_table[] = {
    { 0x168c, 0x003c, PCI_ANY_ID, PCI_ANY_ID },
    { 0x168c, 0x003e, PCI_ANY_ID, PCI_ANY_ID },
    { 0x168c, 0x0041, PCI_ANY_ID, PCI_ANY_ID },
    { 0x168c, 0xabcd, PCI_ANY_ID, PCI_ANY_ID },
    { 0x168c, 0x7021, PCI_ANY_ID, PCI_ANY_ID },
    { 0 }
};

#ifdef MULTI_IF_NAME
#define PLD_AHB_FW_SIM_OPS_NAME "pld_ahb_fw_sim_" MULTI_IF_NAME
#else
#define PLD_AHB_FW_SIM_OPS_NAME "pld_ahb_fw_sim"
#endif

struct cnss_wlan_driver pld_ahb_fw_sim_ops = {
    .name       = PLD_AHB_FW_SIM_OPS_NAME,
    .id_table   = pld_ahb_fw_sim_id_table,
    .probe      = pld_ahb_fw_sim_probe,
    .remove     = pld_ahb_fw_sim_remove,
    .idle_restart  = pld_ahb_fw_sim_idle_restart_cb,
    .idle_shutdown = pld_ahb_fw_sim_idle_shutdown_cb,
    .reinit     = pld_ahb_fw_sim_reinit,
    .shutdown   = pld_ahb_fw_sim_shutdown,
    .crash_shutdown = pld_ahb_fw_sim_crash_shutdown,
    .modem_status   = pld_ahb_fw_sim_notify_handler,
    .update_status  = pld_ahb_fw_sim_uevent,
};

/**
 * pld_ahb_fw_sim_register_driver() - Register AHB device callback functions
 *
 * Return: int
 */
int pld_ahb_fw_sim_register_driver(void)
{
    return cnss_fw_sim_wlan_register_driver(&pld_ahb_fw_sim_ops);
}

/**
 * pld_ahb_fw_sim_unregister_driver() - Unregister AHB device callback
 *                   functions
 *
 * Return: void
 */
void pld_ahb_fw_sim_unregister_driver(void)
{
    cnss_fw_sim_wlan_unregister_driver(&pld_ahb_fw_sim_ops);
}

/**
 * pld_ahb_fw_sim_wlan_enable() - Enable WLAN
 * @dev: device
 * @config: WLAN configuration data
 * @mode: WLAN mode
 * @host_version: host software version
 *
 * This function enables WLAN FW. It passed WLAN configuration data,
 * WLAN mode and host software version to FW.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ahb_fw_sim_wlan_enable(struct device *dev,
                struct pld_wlan_enable_cfg *config,
                enum pld_driver_mode mode,
                const char *host_version)
{
    struct cnss_wlan_enable_cfg cfg;
    enum cnss_driver_mode cnss_mode;

    cfg.num_ce_tgt_cfg = config->num_ce_tgt_cfg;
    cfg.ce_tgt_cfg = (struct cnss_ce_tgt_pipe_cfg *)
        config->ce_tgt_cfg;
    cfg.num_ce_svc_pipe_cfg = config->num_ce_svc_pipe_cfg;
    cfg.ce_svc_cfg = (struct cnss_ce_svc_pipe_cfg *)
        config->ce_svc_cfg;
    cfg.num_shadow_reg_cfg = config->num_shadow_reg_cfg;
    cfg.shadow_reg_cfg = (struct cnss_shadow_reg_cfg *)
        config->shadow_reg_cfg;
    cfg.num_shadow_reg_v2_cfg = config->num_shadow_reg_v2_cfg;
    cfg.shadow_reg_v2_cfg = (struct cnss_shadow_reg_v2_cfg *)
        config->shadow_reg_v2_cfg;

    switch (mode) {
    case PLD_FTM:
        cnss_mode = CNSS_FTM;
        break;
    case PLD_EPPING:
        cnss_mode = CNSS_EPPING;
        break;
    default:
        cnss_mode = CNSS_MISSION;
        break;
    }
    return cnss_fw_sim_wlan_enable(dev, &cfg, cnss_mode, host_version);
}

/**
 * pld_ahb_fw_sim_wlan_disable() - Disable WLAN
 * @dev: device
 * @mode: WLAN mode
 *
 * This function disables WLAN FW. It passes WLAN mode to FW.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ahb_fw_sim_wlan_disable(struct device *dev, enum pld_driver_mode mode)
{
    return cnss_fw_sim_wlan_disable(dev, CNSS_OFF);
}

/**
 * pld_ahb_fw_sim_get_soc_info() - Get SOC information
 * @dev: device
 * @info: buffer to SOC information
 *
 * Return SOC info to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ahb_fw_sim_get_soc_info(struct device *dev, struct pld_soc_info *info)
{
    int ret = 0;
    struct cnss_soc_info cnss_info = {0};

    if (!info)
        return -ENODEV;

    ret = cnss_fw_sim_get_soc_info(dev, &cnss_info);
    if (ret)
        return ret;

    info->v_addr = cnss_info.va;
    info->p_addr = cnss_info.pa;
    info->chip_id = cnss_info.chip_id;
    info->chip_family = cnss_info.chip_family;
    info->board_id = cnss_info.board_id;
    info->soc_id = cnss_info.soc_id;
    info->fw_version = cnss_info.fw_version;
    strlcpy(info->fw_build_timestamp, cnss_info.fw_build_timestamp,
        sizeof(info->fw_build_timestamp));

    return 0;
}

/**
 * pld_ahb_fw_sim_get_platform_cap() - Get platform capabilities
 * @dev: device
 * @cap: buffer to the capabilities
 *
 * Return capabilities to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ahb_fw_sim_get_platform_cap(struct device *dev,
                     struct pld_platform_cap *cap)
{
    int ret = 0;
    struct cnss_platform_cap cnss_cap;

    if (!cap)
        return -ENODEV;

    ret = cnss_fw_sim_get_platform_cap(dev, &cnss_cap);
    if (ret)
        return ret;

    memcpy(cap, &cnss_cap, sizeof(*cap));
    return 0;
}

#endif

