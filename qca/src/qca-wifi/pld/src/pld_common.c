/*
 * Copyright (c) 2017-2021, Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
 */



#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/pm.h>

#if !CONFIG_PLD_STUB
#ifdef CONFIG_PLD_SDIO_CNSS
#include <net/cnss.h>
#endif
#ifdef CONFIG_CNSS2_SUPPORT
#include <linux/irq.h>
#include <net/cnss2.h>
#endif
#ifdef CONFIG_PLD_SNOC_ICNSS
#include <soc/qcom/icnss.h>
#endif
#include <qdf_lock.h>
#include <qdf_module.h>
#include <qdf_util.h>
#include "pld_ahb.h"
#include "pld_pcie.h"
#include "pld_ahb_fw_sim.h"
//#include "pld_snoc.h"
//#include "pld_sdio.h"
//#include "pld_usb.h"

#define PLD_PCIE_REGISTERED BIT(0)
#define PLD_SNOC_REGISTERED BIT(1)
#define PLD_SDIO_REGISTERED BIT(2)
#define PLD_USB_REGISTERED BIT(3)
#define PLD_AHB_REGISTERED BIT(4)
#define PLD_AHB_FW_SIM_REGISTERED BIT(5)
#define PLD_BUS_MASK 0x3f

static struct pld_context *g_pld_ctx;

/**
 * pld_init() - Initialize PLD module
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_init(void)
{
	struct pld_context *pld_context;

	pld_context = qdf_mem_malloc(sizeof(*pld_context));
	if (!pld_context)
		return -ENOMEM;

	qdf_spinlock_create(&pld_context->pld_lock);

	INIT_LIST_HEAD(&pld_context->dev_list);

	g_pld_ctx = pld_context;

	return 0;
}
qdf_export_symbol(pld_init);

/**
 * pld_deinit() - Uninitialize PLD module
 *
 * Return: void
 */
void pld_deinit(void)
{
	struct dev_node *dev_node;
	struct pld_context *pld_context;

	pld_context = g_pld_ctx;
	if (!pld_context) {
		g_pld_ctx = NULL;
		return;
	}

	qdf_spin_lock_irqsave(&pld_context->pld_lock);
	while (!list_empty(&pld_context->dev_list)) {
		dev_node = list_first_entry(&pld_context->dev_list,
					    struct dev_node, list);
		list_del(&dev_node->list);
		qdf_mem_free(dev_node);
	}
	qdf_spin_unlock_irqrestore(&pld_context->pld_lock);
        qdf_spinlock_destroy(&pld_context->pld_lock);
	qdf_mem_free(pld_context);

	g_pld_ctx = NULL;
}
qdf_export_symbol(pld_deinit);

/**
 * pld_get_global_context() - Get global context of PLD
 *
 * Return: PLD global context
 */
struct pld_context *pld_get_global_context(void)
{
	return g_pld_ctx;
}

/**
 * pld_add_dev() - Add dev node to global context
 * @pld_context: PLD global context
 * @dev: device
 * @type: Bus type
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_add_dev(struct pld_context *pld_context,
		struct device *dev, enum pld_bus_type type)
{
	struct dev_node *dev_node;

	dev_node = qdf_mem_malloc(sizeof(*dev_node));
	if (dev_node == NULL)
		return -ENOMEM;

	dev_node->dev = dev;
	dev_node->bus_type = type;

	qdf_spin_lock_irqsave(&pld_context->pld_lock);
	list_add_tail(&dev_node->list, &pld_context->dev_list);
	qdf_spin_unlock_irqrestore(&pld_context->pld_lock);

	return 0;
}

/**
 * pld_del_dev() - Delete dev node from global context
 * @pld_context: PLD global context
 * @dev: device
 *
 * Return: void
 */
void pld_del_dev(struct pld_context *pld_context,
		 struct device *dev)
{
	struct dev_node *dev_node, *tmp;

	qdf_spin_lock_irqsave(&pld_context->pld_lock);
	list_for_each_entry_safe(dev_node, tmp, &pld_context->dev_list, list) {
		if (dev_node->dev == dev) {
			list_del(&dev_node->list);
			qdf_mem_free(dev_node);
		}
	}
	qdf_spin_unlock_irqrestore(&pld_context->pld_lock);
}

enum pld_bus_type pld_get_bus_type(struct device *dev)
{
	struct pld_context *pld_context;
	struct dev_node *dev_node;

	pld_context = pld_get_global_context();

	if (dev == NULL || pld_context == NULL) {
		qdf_nofl_err("Invalid info: dev %pK, context %pK",
		       dev, pld_context);
		return PLD_BUS_TYPE_NONE;
	}

	qdf_spin_lock_irqsave(&pld_context->pld_lock);
	list_for_each_entry(dev_node, &pld_context->dev_list, list) {
		if (dev_node->dev == dev) {
			qdf_spin_unlock_irqrestore(&pld_context->pld_lock);
			return dev_node->bus_type;
		}
	}
	qdf_spin_unlock_irqrestore(&pld_context->pld_lock);

	if (memcmp(dev->bus->name, "pci", 3) == 0)
		return PLD_BUS_TYPE_PCIE;
	else if (memcmp(dev->bus->name, "platform", 8) == 0)
#ifdef CONFIG_AHB_FW_SIM
                return PLD_BUS_TYPE_AHB_FW_SIM;
#else
		return PLD_BUS_TYPE_AHB;
#endif

	return PLD_BUS_TYPE_NONE;
}

qdf_export_symbol(pld_get_bus_type);

/**
 * pld_register_driver() - Register driver to kernel
 * @ops: Callback functions that will be registered to kernel
 *
 * This function should be called when other modules want to
 * register platform driver callback functions to kernel. The
 * probe() is expected to be called after registration if the
 * device is online.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */

int pld_register_driver(struct pld_driver_ops *ops)
{
	int ret = 0;
	struct pld_context *pld_context;

	pld_context = pld_get_global_context();

	if (pld_context == NULL) {
		qdf_nofl_err("global context is NULL");
		ret = -ENODEV;
		goto out;
	}

	if (pld_context->ops) {
		qdf_nofl_err("driver already registered");
		ret = -EEXIST;
		goto out;
	}

	if (!ops || !ops->probe || !ops->remove ||
	    !ops->suspend || !ops->resume) {
		qdf_nofl_err("Required callback functions are missing");
		ret = -EINVAL;
		goto out;
	}

	pld_context->ops = ops;
	pld_context->pld_driver_state = 0;

#ifndef BUILD_X86
	ret = pld_ahb_register_driver();
	if (ret) {
		qdf_nofl_info("Fail to register ahb driver\n");
		goto fail_ahb;
	}
#ifndef CONFIG_AHB_FW_SIM
	pld_context->pld_driver_state |= PLD_AHB_REGISTERED;
#endif /* CONFIG_AHB_FW_SIM */

	ret = pld_ahb_fw_sim_register_driver();
	if (ret) {
		qdf_nofl_info("Fail to register ahb driver\n");
		goto fail_ahb_fw_sim;
	}
#ifdef CONFIG_AHB_FW_SIM
	pld_context->pld_driver_state |= PLD_AHB_FW_SIM_REGISTERED;
#endif /* CONFIG_AHB_FW_SIM */
#endif

#ifndef CONFIG_AHB_FW_SIM
	ret = pld_pcie_register_driver();
	if (ret) {
		qdf_nofl_info("Fail to register pcie driver\n");
		goto fail_pcie;
	}
	pld_context->pld_driver_state |= PLD_PCIE_REGISTERED;
#endif

#if 0
	ret = pld_snoc_register_driver();
	if (ret) {
		qdf_nofl_err("Fail to register snoc driver");
		goto fail_snoc;
	}
	pld_context->pld_driver_state |= PLD_SNOC_REGISTERED;

	ret = pld_sdio_register_driver();
	if (ret) {
		qdf_nofl_err("Fail to register sdio driver");
		goto fail_sdio;
	}
	pld_context->pld_driver_state |= PLD_SDIO_REGISTERED;

	ret = pld_usb_register_driver();
	if (ret) {
		qdf_nofl_err("Fail to register usb driver");
		goto fail_usb;
	}
	pld_context->pld_driver_state |= PLD_USB_REGISTERED;
#endif

	return ret;

//fail_usb:
//	pld_sdio_unregister_driver(); not supported now
//fail_sdio:
//	pld_snoc_unregister_driver(); not supported now
//fail_snoc:
#ifndef CONFIG_AHB_FW_SIM
fail_pcie:
	pld_ahb_unregister_driver();
#endif
#ifndef BUILD_X86
fail_ahb_fw_sim:
	pld_ahb_fw_sim_unregister_driver();
fail_ahb:
	pld_context->pld_driver_state = 0;
	pld_context->ops = NULL;
#endif
out:
	return ret;
}

/**
 * pld_unregister_driver() - Unregister driver to kernel
 *
 * This function should be called when other modules want to
 * unregister callback functions from kernel. The remove() is
 * expected to be called after registration.
 *
 * Return: void
 */
void pld_unregister_driver(void)
{
	struct pld_context *pld_context;

	pld_context = pld_get_global_context();

	if (pld_context == NULL) {
		qdf_nofl_err("global context is NULL");
		return;
	}

	if (pld_context->ops == NULL) {
		qdf_nofl_err("driver not registered");
		return;
	}

	pld_ahb_unregister_driver();
#ifndef CONFIG_AHB_FW_SIM
	pld_pcie_unregister_driver();
#endif
#ifndef BUILD_X86
	pld_ahb_fw_sim_unregister_driver();
#endif
	pld_context->pld_driver_state = 0;
	pld_context->ops = NULL;
}

/**
 * pld_wlan_enable() - Enable WLAN
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
int pld_wlan_enable(struct device *dev, struct pld_wlan_enable_cfg *config,
		    enum pld_driver_mode mode)
{
#define QWLAN_VERSIONSTR  "WIN"
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_wlan_enable(dev, config, mode, QWLAN_VERSIONSTR);
		break;
	case PLD_BUS_TYPE_AHB:
		ret = pld_ahb_wlan_enable(dev, config, mode, QWLAN_VERSIONSTR);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pld_ahb_fw_sim_wlan_enable(dev, config, mode,
                                                 QWLAN_VERSIONSTR);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_wlan_enable(config, mode, QWLAN_VERSIONSTR);
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_wlan_disable() - Disable WLAN
 * @dev: device
 * @mode: WLAN mode
 *
 * This function disables WLAN FW. It passes WLAN mode to FW.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_wlan_disable(struct device *dev, enum pld_driver_mode mode)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_wlan_disable(dev, mode);
		break;
	case PLD_BUS_TYPE_AHB:
		ret = pld_ahb_wlan_disable(dev, mode);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pld_ahb_fw_sim_wlan_disable(dev, mode);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_wlan_disable(mode);
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_set_fw_log_mode() - Set FW debug log mode
 * @dev: device
 * @fw_log_mode: 0 for No log, 1 for WMI, 2 for DIAG
 *
 * Switch Fw debug log mode between DIAG logging and WMI logging.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_set_fw_log_mode(struct device *dev, u8 fw_log_mode)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_set_fw_log_mode(fw_log_mode);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_set_fw_log_mode(fw_log_mode);
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

void *pld_subsystem_get(struct device *dev, int device_id)
{
	void *ret = NULL;
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_AHB:
		ret = pld_ahb_subsystem_get(dev, device_id);
		break;
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_subsystem_get(dev, device_id);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pld_ahb_fw_sim_subsystem_get(dev);
		break;

	default:
		ret = NULL;
		break;
	}
	return ret;
}
void *pld_get_pci_dev_from_plat_dev(void *pdev)
{
	return cnss_get_pci_dev_from_plat_dev(pdev);
}

void *pld_get_pci_dev_id_from_plat_dev(void *pdev)
{
	return cnss_get_pci_dev_id_from_plat_dev(pdev);
}

void pld_subsystem_put(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_AHB:
		pld_ahb_subsystem_put(dev);
		break;
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_subsystem_put(dev);
		break;
	default:
		break;
	}
}

/**
 * pld_get_default_fw_files() - Get default FW file names
 * @pfw_files: buffer for FW file names
 *
 * Return default FW file names to the buffer.
 *
 * Return: void
 */
void pld_get_default_fw_files(struct pld_fw_files *pfw_files)
{
	memset(pfw_files, 0, sizeof(*pfw_files));

	strlcpy(pfw_files->image_file, PLD_IMAGE_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->board_data, PLD_BOARD_DATA_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->otp_data, PLD_OTP_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->utf_file, PLD_UTF_FIRMWARE_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->utf_board_data, PLD_BOARD_DATA_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->epping_file, PLD_EPPING_FILE,
		PLD_MAX_FILE_NAME);
	strlcpy(pfw_files->setup_file, PLD_SETUP_FILE,
		PLD_MAX_FILE_NAME);
}

/**
 * pld_get_fw_files_for_target() - Get FW file names
 * @dev: device
 * @pfw_files: buffer for FW file names
 * @target_type: target type
 * @target_version: target version
 *
 * Return target specific FW file names to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_get_fw_files_for_target(struct device *dev,
				struct pld_fw_files *pfw_files,
				u32 target_type, u32 target_version)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_fw_files_for_target(dev, pfw_files,
				       target_type, target_version);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
//		ret = pld_sdio_get_fw_files_for_target(pfw_files,
//				       target_type, target_version);
		break;
	case PLD_BUS_TYPE_USB:
//	ret = pld_usb_get_fw_files_for_target(pfw_files,
//				target_type, target_version);
        break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_is_pci_link_down() - Notification for pci link down event
 * @dev: device
 *
 * Notify platform that pci link is down.
 *
 * Return: void
 */
void pld_is_pci_link_down(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_link_down(dev);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}


/**
 * pld_shadow_control() - Control pci shadow registers
 * @dev: device
 * @enable: 0 for disable, 1 for enable
 *
 * This function is for suspend/resume. It can control if we
 * use pci shadow registers (for saving config space) or not.
 * During suspend we disable it to avoid config space corruption.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_shadow_control(struct device *dev, bool enable)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_shadow_control(enable);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_set_wlan_unsafe_channel() - Set unsafe channel
 * @dev: device
 * @unsafe_ch_list: unsafe channel list
 * @ch_count: number of channel
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_set_wlan_unsafe_channel(struct device *dev,
				u16 *unsafe_ch_list, u16 ch_count)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_set_wlan_unsafe_channel(unsafe_ch_list,
						       ch_count);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_set_wlan_unsafe_channel(unsafe_ch_list,
//						       ch_count);
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do get unsafe channel via cnss sdio API */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_wlan_unsafe_channel() - Get unsafe channel
 * @dev: device
 * @unsafe_ch_list: buffer to unsafe channel list
 * @ch_count: number of channel
 * @buf_len: buffer length
 *
 * Return WLAN unsafe channel to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_get_wlan_unsafe_channel(struct device *dev, u16 *unsafe_ch_list,
				u16 *ch_count, u16 buf_len)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_wlan_unsafe_channel(unsafe_ch_list,
						       ch_count, buf_len);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_get_wlan_unsafe_channel(unsafe_ch_list,
//						       ch_count, buf_len);
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do get unsafe channel via cnss sdio API */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_wlan_set_dfs_nol() - Set DFS info
 * @dev: device
 * @info: DFS info
 * @info_len: info length
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_wlan_set_dfs_nol(struct device *dev, void *info, u16 info_len)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_wlan_set_dfs_nol(info, info_len);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_wlan_set_dfs_nol(info, info_len);
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do get nol via cnss sdio API */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_wlan_get_dfs_nol() - Get DFS info
 * @dev: device
 * @info: buffer to DFS info
 * @info_len: info length
 *
 * Return DFS info to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_wlan_get_dfs_nol(struct device *dev, void *info, u16 info_len)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_wlan_get_dfs_nol(info, info_len);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_wlan_get_dfs_nol(info, info_len);
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_schedule_recovery_work() - Schedule recovery work
 * @dev: device
 * @reason: recovery reason
 *
 * Schedule a system self recovery work.
 *
 * Return: void
 */
void pld_schedule_recovery_work(struct device *dev,
				enum pld_recovery_reason reason)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_schedule_recovery_work(dev, reason);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_wlan_pm_control() - WLAN PM control on PCIE
 * @dev: device
 * @vote: 0 for enable PCIE PC, 1 for disable PCIE PC
 *
 * This is for PCIE power collaps control during suspend/resume.
 * When PCIE power collaps is disabled, WLAN FW can access memory
 * through PCIE when system is suspended.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_wlan_pm_control(struct device *dev, bool vote)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_wlan_pm_control(vote);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_virt_ramdump_mem() - Get virtual ramdump memory
 * @dev: device
 * @size: buffer to virtual memory size
 *
 * Return: virtual ramdump memory address
 */
void *pld_get_virt_ramdump_mem(struct device *dev, unsigned long *size)
{
	void *mem = NULL;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		mem = pld_pcie_get_virt_ramdump_mem(size);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}

	return mem;
}

/**
 * pld_device_crashed() - Notification for device crash event
 * @dev: device
 *
 * Notify subsystem a device crashed event. A subsystem restart
 * is expected to happen after calling this function.
 *
 * Return: void
 */
void pld_device_crashed(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_device_crashed();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_device_self_recovery() - Device self recovery
 * @dev: device
 * @reason: recovery reason
 *
 * Return: void
 */
void pld_device_self_recovery(struct device *dev,
			      enum pld_recovery_reason reason)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_device_self_recovery(dev, reason);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_intr_notify_q6() - Notify Q6 FW interrupts
 * @dev: device
 *
 * Notify Q6 that a FW interrupt is triggered.
 *
 * Return: void
 */
void pld_intr_notify_q6(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_intr_notify_q6();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_request_pm_qos() - Request system PM
 * @dev: device
 * @qos_val: request value
 *
 * It votes for the value of aggregate QoS expectations.
 *
 * Return: void
 */
void pld_request_pm_qos(struct device *dev, u32 qos_val)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_request_pm_qos(qos_val);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do Add call cns API */
		break;
	case PLD_BUS_TYPE_USB:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_remove_pm_qos() - Remove system PM
 * @dev: device
 *
 * Remove the vote request for Qos expectations.
 *
 * Return: void
 */
void pld_remove_pm_qos(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_remove_pm_qos();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do Add call cns API */
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_request_bus_bandwidth() - Request bus bandwidth
 * @dev: device
 * @bandwidth: bus bandwidth
 *
 * Votes for HIGH/MEDIUM/LOW bus bandwidth.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_request_bus_bandwidth(struct device *dev, int bandwidth)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_request_bus_bandwidth(bandwidth);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		/* To do Add call cns API */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_platform_cap() - Get platform capabilities
 * @dev: device
 * @cap: buffer to the capabilities
 *
 * Return capabilities to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_get_platform_cap(struct device *dev, struct pld_platform_cap *cap)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_platform_cap(dev, cap);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_set_driver_status() - Set driver status
 * @dev: device
 * @status: driver status
 *
 * Return: void
 */
void pld_set_driver_status(struct device *dev, enum pld_driver_status status)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_set_driver_status(status);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_get_sha_hash() - Get sha hash number
 * @dev: device
 * @data: input data
 * @data_len: data length
 * @hash_idx: hash index
 * @out:  output buffer
 *
 * Return computed hash to the out buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_get_sha_hash(struct device *dev, const u8 *data,
		     u32 data_len, u8 *hash_idx, u8 *out)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_sha_hash(data, data_len,
					    hash_idx, out);
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_fw_ptr() - Get secure FW memory address
 * @dev: device
 *
 * Return: secure memory address
 */
void *pld_get_fw_ptr(struct device *dev)
{
	void *ptr = NULL;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ptr = pld_pcie_get_fw_ptr();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}

	return ptr;
}

/**
 * pld_auto_suspend() - Auto suspend
 * @dev: device
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_auto_suspend(struct device *dev)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_auto_suspend();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_auto_resume() - Auto resume
 * @dev: device
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_auto_resume(struct device *dev)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_auto_resume();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_ce_request_irq() - Register IRQ for CE
 * @dev: device
 * @ce_id: CE number
 * @handler: IRQ callback function
 * @flags: IRQ flags
 * @name: IRQ name
 * @ctx: IRQ context
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ce_request_irq(struct device *dev, unsigned int ce_id,
		       irqreturn_t (*handler)(int, void *),
		       unsigned long flags, const char *name, void *ctx)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_ce_request_irq(ce_id, handler, flags, name, ctx);
		break;
	case PLD_BUS_TYPE_PCIE:
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_ce_free_irq() - Free IRQ for CE
 * @dev: device
 * @ce_id: CE number
 * @ctx: IRQ context
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_ce_free_irq(struct device *dev, unsigned int ce_id, void *ctx)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_ce_free_irq(ce_id, ctx);
		break;
	case PLD_BUS_TYPE_PCIE:
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_enable_irq() - Enable IRQ for CE
 * @dev: device
 * @ce_id: CE number
 *
 * Return: void
 */
void pld_enable_irq(struct device *dev, unsigned int ce_id)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		pld_snoc_enable_irq(ce_id);
		break;
	case PLD_BUS_TYPE_PCIE:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_disable_irq() - Disable IRQ for CE
 * @dev: device
 * @ce_id: CE number
 *
 * Return: void
 */
void pld_disable_irq(struct device *dev, unsigned int ce_id)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		pld_snoc_disable_irq(ce_id);
		break;
	case PLD_BUS_TYPE_PCIE:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_get_soc_info() - Get SOC information
 * @dev: device
 * @info: buffer to SOC information
 *
 * Return SOC info to the buffer.
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_get_soc_info(struct device *dev, struct pld_soc_info *info)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_get_soc_info(info);
		break;
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_soc_info(dev, info);
		break;
	case PLD_BUS_TYPE_AHB:
		ret = pld_ahb_get_soc_info(dev, info);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pld_ahb_fw_sim_get_soc_info(dev, info);
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_ce_id() - Get CE number for the provided IRQ
 * @dev: device
 * @irq: IRQ number
 *
 * Return: CE number
 */
int pld_get_ce_id(struct device *dev, int irq)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_get_ce_id(irq);
		break;
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_ce_id(irq);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_irq() - Get IRQ number for given CE ID
 * @dev: device
 * @ce_id: CE ID
 *
 * Return: IRQ number
 */
int pld_get_irq(struct device *dev, int ce_id)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_get_irq(ce_id);
		break;
	case PLD_BUS_TYPE_PCIE:
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
qdf_export_symbol(pld_get_irq);

/**
 * pld_lock_pm_sem() - Lock PM semaphore
 * @dev: device
 *
 * Return: void
 */
void pld_lock_pm_sem(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_lock_pm_sem();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	case PLD_BUS_TYPE_USB:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_release_pm_sem() - Release PM semaphore
 * @dev: device
 *
 * Return: void
 */
void pld_release_pm_sem(struct device *dev)
{
	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_release_pm_sem();
		break;
	case PLD_BUS_TYPE_SNOC:
		break;
	case PLD_BUS_TYPE_SDIO:
		break;
	case PLD_BUS_TYPE_USB:
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}
}

/**
 * pld_power_on() - Power on WLAN hardware
 * @dev: device
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_power_on(struct device *dev, enum pld_bus_type type, int device_id)
{
	int ret = 0;
	enum pld_bus_type pld_type;

	if(dev)
		pld_type = pld_get_bus_type(dev);
	else
		pld_type = type;

	switch (pld_type) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_power_on(dev, device_id);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_power_on(dev);
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}

	return ret;
}
qdf_export_symbol(pld_power_on);

/**
 * pld_power_off() - Power off WLAN hardware
 * @dev: device
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_power_off(struct device *dev, enum pld_bus_type type, int device_id)
{
	int ret = 0;
	enum pld_bus_type pld_type;

	if(dev)
		pld_type = pld_get_bus_type(dev);
	else
		pld_type = type;

	switch (pld_type) {
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_power_off(dev, device_id);
		break;
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_power_off(dev);
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}

	return ret;
}
qdf_export_symbol(pld_power_off);

/**
 * pld_athdiag_read() - Read data from WLAN FW
 * @dev: device
 * @offset: address offset
 * @memtype: memory type
 * @datalen: data length
 * @output: output buffer
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_athdiag_read(struct device *dev, uint32_t offset,
		     uint32_t memtype, uint32_t datalen,
		     uint8_t *output)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_athdiag_read(dev, offset, memtype,
//					    datalen, output);
		break;
	case PLD_BUS_TYPE_PCIE:
	case PLD_BUS_TYPE_AHB:
		ret = cnss_athdiag_read(dev, offset, memtype,
					datalen, output);
	case PLD_BUS_TYPE_SDIO:
	case PLD_BUS_TYPE_USB:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_athdiag_write() - Write data to WLAN FW
 * @dev: device
 * @offset: address offset
 * @memtype: memory type
 * @datalen: data length
 * @input: input buffer
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_athdiag_write(struct device *dev, uint32_t offset,
		      uint32_t memtype, uint32_t datalen,
		      uint8_t *input)
{
	int ret = 0;

	switch (pld_get_bus_type(dev)) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_athdiag_write(dev, offset, memtype,
//					     datalen, input);
		break;
	case PLD_BUS_TYPE_PCIE:
	case PLD_BUS_TYPE_AHB:
		ret = cnss_athdiag_write(dev, offset, memtype,
					     datalen, input);
		break;
	case PLD_BUS_TYPE_SDIO:
	case PLD_BUS_TYPE_USB:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_smmu_get_mapping() - Get SMMU mapping context
 * @dev: device
 *
 * Return: Pointer to the mapping context
 */
void *pld_smmu_get_mapping(struct device *dev)
{
	void *ptr = NULL;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_SNOC:
//		ptr = pld_snoc_smmu_get_mapping(dev);
		break;
	case PLD_BUS_TYPE_PCIE:
		qdf_nofl_err("Not supported on type %d", type);
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		break;
	}

	return ptr;
}

/**
 * pld_smmu_map() - Map SMMU
 * @dev: device
 * @paddr: physical address that needs to map to
 * @iova_addr: IOVA address
 * @size: size to be mapped
 *
 * Return: 0 for success
 *         Non zero failure code for errors
 */
int pld_smmu_map(struct device *dev, phys_addr_t paddr,
		 uint32_t *iova_addr, size_t size)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_smmu_map(dev, paddr, iova_addr, size);
		break;
	case PLD_BUS_TYPE_PCIE:
		qdf_nofl_err("Not supported on type %d", type);
		ret = -ENODEV;
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pld_get_user_msi_assignment() - Get MSI assignment information
 * @dev: device structure
 * @user_name: name of the user who requests the MSI assignment
 * @num_vectors: number of the MSI vectors assigned for the user
 * @user_base_data: MSI base data assigned for the user, this equals to
 *                  endpoint base data from config space plus base vector
 * @base_vector: base MSI vector (offset) number assigned for the user
 *
 * Return: 0 for success
 *         Negative failure code for errors
 */
int pld_get_user_msi_assignment(struct device *dev, char *user_name,
				int *num_vectors, uint32_t *user_base_data,
				uint32_t *base_vector)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	/* Adding for qcn6122 which is hybrid bus type
	 * i.e. pci attached device which will list
	 * as AHB device from host perspective
	 */
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_user_msi_assignment(dev, user_name,
						       num_vectors,
						       user_base_data,
						       base_vector);
		break;
        case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = -EINVAL;
		break;
	case PLD_BUS_TYPE_SNOC:
	case PLD_BUS_TYPE_SDIO:
	case PLD_BUS_TYPE_USB:
		qdf_nofl_err("Not supported on type %d", type);
		ret = -ENODEV;
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}
qdf_export_symbol(pld_get_user_msi_assignment);

/**
 * pld_get_msi_irq() - Get MSI IRQ number used for request_irq()
 * @dev: device structure
 * @vector: MSI vector (offset) number
 *
 * Return: Positive IRQ number for success
 *         Negative failure code for errors
 */
int pld_get_msi_irq(struct device *dev, unsigned int vector)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	/* Adding for qcn6122 which is hybrid bus type
	 * i.e. pci attached device which will list
	 * as AHB device from host perspective
	 */
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = pld_pcie_get_msi_irq(dev, vector);
		break;
	case PLD_BUS_TYPE_SNOC:
	case PLD_BUS_TYPE_SDIO:
	case PLD_BUS_TYPE_USB:
		qdf_nofl_err("Not supported on type %d", type);
		ret = -ENODEV;
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}
qdf_export_symbol(pld_get_msi_irq);

/**
 * pld_get_msi_address() - Get the MSI address
 * @dev: device structure
 * @msi_addr_low: lower 32-bit of the address
 * @msi_addr_high: higher 32-bit of the address
 *
 * Return: Void
 */
void pld_get_msi_address(struct device *dev, uint32_t *msi_addr_low,
			 uint32_t *msi_addr_high)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	/* Adding for qcn6122 which is hybrid bus type
	 * i.e. pci attached device which will list
	 * as AHB device from host perspective
	 */
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_get_msi_address(dev, msi_addr_low, msi_addr_high);
		break;
	case PLD_BUS_TYPE_SNOC:
	case PLD_BUS_TYPE_SDIO:
	case PLD_BUS_TYPE_USB:
		qdf_nofl_err("Not supported on type %d", type);
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		break;
	}
}
qdf_export_symbol(pld_get_msi_address);

/**
 * pld_socinfo_get_serial_number() - Get SOC serial number
 * @dev: device
 *
 * Return: SOC serial number
 */
unsigned int pld_socinfo_get_serial_number(struct device *dev)
{
	unsigned int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_socinfo_get_serial_number(dev);
		break;
	case PLD_BUS_TYPE_PCIE:
		qdf_nofl_err("Not supported on type %d", type);
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		break;
	}

	return ret;
}

/*
 * pld_get_wlan_mac_address() - API to query MAC address from Platform
 * Driver
 * @dev: Device Structure
 * @num: Pointer to number of MAC address supported
 *
 * Platform Driver can have MAC address stored. This API needs to be used
 * to get those MAC address
 *
 * Return: Pointer to the list of MAC address
 */
uint8_t *pld_get_wlan_mac_address(struct device *dev, uint32_t *num)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_PCIE:
		return pld_pcie_get_wlan_mac_address(dev, num);
	case PLD_BUS_TYPE_SDIO:
//		return pld_sdio_get_wlan_mac_address(dev, num);
	case PLD_BUS_TYPE_SNOC:
//		return pld_snoc_get_wlan_mac_address(dev, num);
	case PLD_BUS_TYPE_USB:
		qdf_nofl_err("Not supported on type %d", type);
		break;
	default:
		qdf_nofl_err("Invalid device type");
		break;
	}

	*num = 0;
	return NULL;
}

/**
 * pld_is_qmi_disable() - Check QMI support is present or not
 * @dev: device
 *
 *  Return: 1 QMI is not supported
 *          0 QMI is supported
 *          Non zero failure code for errors
 */
int pld_is_qmi_disable(struct device *dev)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_SNOC:
//		ret = pld_snoc_is_qmi_disable();
		break;
	case PLD_BUS_TYPE_PCIE:
	case PLD_BUS_TYPE_SDIO:
		qdf_nofl_err("Not supported on type %d", type);
		ret = -EINVAL;
		break;
	default:
		qdf_nofl_err("Invalid device type %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

void pld_wait_for_fw_ready(struct device *dev)
{
	cnss_wait_for_fw_ready(dev);
}

bool pld_is_dev_initialized(struct device *dev)
{
	return cnss_is_dev_initialized(dev);
}
void pld_wait_for_cold_boot_cal_done(struct device *dev)
{
	cnss_wait_for_cold_boot_cal_done(dev);
}

void *pld_get_pdev_device_id(int device_id, enum pld_bus_type type)
{
	switch (type) {
	case PLD_BUS_TYPE_PCIE:
		return pld_get_pci_dev_by_device_id(device_id);
	default:
		break;
	}
	return NULL;
}

int pld_rescan_bus(enum pld_bus_type type)
{
	switch (type) {
	case PLD_BUS_TYPE_PCIE:
		return  pld_pcie_rescan();
	default:
		break;
	}
	return -EINVAL;

}
qdf_export_symbol(pld_rescan_bus);

u64 pld_get_q6_time(struct device *dev)
{
	return cnss_get_q6_time(dev);
}
qdf_export_symbol(pld_get_q6_time);

void pld_remove_bus(enum pld_bus_type type)
{
	switch (type) {
	case PLD_BUS_TYPE_PCIE:
		pld_pcie_remove_bus();
		break;
	default:
		break;
	}
}
qdf_export_symbol(pld_remove_bus);
bool pld_have_platform_driver_support(struct device *dev)
{
#ifdef CONFIG_PLD_PCIE_CNSS
	return true;
#else
	return false;
#endif
}

void pld_set_recovery_enabled(struct device *dev, bool enabled)
{
	cnss_set_recovery_enabled(dev, enabled);
}

void pld_get_ramdump_device_name(struct device *dev, char *ramdump_dev_name,
				 size_t ramdump_dev_name_len)
{
	cnss_get_ramdump_device_name(dev, ramdump_dev_name,
				     ramdump_dev_name_len);
}
unsigned int pld_get_driver_mode(void)
{
	return cnss_get_driver_mode();
}
qdf_export_symbol(pld_get_driver_mode);

int pld_set_driver_mode(unsigned int mode)
{
	return cnss_set_driver_mode(mode);
}
qdf_export_symbol(pld_set_driver_mode);
#endif
