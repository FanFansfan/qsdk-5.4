/*
 * Copyright (c) 2017-2018 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
 */

#ifndef __PLD_COMMON_STUB_H__
#define __PLD_COMMON_STUB_H__

#if CONFIG_PLD_STUB
#include <platform_device.h>
#include <qdf_module.h>
static inline u64 pld_get_q6_time(struct device *dev)
{
	return 0;
}
static inline int pld_init(void) {return 0;}
static inline void pld_deinit(void) { }

static inline int pld_register_driver(struct pld_driver_ops *ops)
{
	return 0;
}

static inline void pld_unregister_driver(void){ }

static inline bool pld_is_dev_initialized(struct device *dev)
{
	return false;
}

static inline int pld_wlan_enable(struct device *dev,
				  struct pld_wlan_enable_cfg *config,
				  enum pld_driver_mode mode)
{
	return 0;
}
static inline int pld_wlan_disable(struct device *dev,
				   enum pld_driver_mode mode)
{
	return 0;
}
static inline void pld_is_pci_link_down(struct device *dev)
{
}
static inline int pld_wlan_pm_control(struct device *dev, bool vote)
{
	return 0;
}
static inline void pld_intr_notify_q6(struct device *dev)
{
}

static inline int pld_get_user_msi_assignment(struct device *dev,
			char *user_name, int *num_vectors,
			uint32_t *user_base_data, uint32_t *base_vector)
{
	return -EINVAL;
}

/* should not be called if pld_get_user_msi_assignment returns error */
static inline int pld_get_msi_irq(struct device *dev, unsigned int vector)
{
	return -EINVAL;
}

/* should not be called if pld_get_user_msi_assignment returns error */
static inline void pld_get_msi_address(struct device *dev,
				       uint32_t *msi_addr_low,
				       uint32_t *msi_addr_high)
{
	return;
}

static inline int pld_get_irq(struct device *dev, int ce_id)
{
	return -EINVAL;
}

static inline int pld_ce_request_irq(struct device *dev, unsigned int ce_id,
				     irqreturn_t (*handler)(int, void *),
				     unsigned long flags, const char *name,
				     void *ctx)
{
	return 0;
}

static inline void pld_wait_for_fw_ready(struct device *dev)
{
}

static inline void pld_wait_for_cold_boot_cal_done(struct device *dev)
{
}
static inline void *pld_subsystem_get(struct device *dev, int device_id)
{
	return NULL;
}
static inline void pld_subsystem_put(struct device *dev)
{

}

static inline void *pld_get_pci_dev_from_plat_dev(void *pdev)
{
	return NULL;
}

static inline void *pld_get_pci_dev_id_from_plat_dev(void *pdev)
{
	return NULL;
}

static inline int pld_ce_free_irq(struct device *dev,
				  unsigned int ce_id, void *ctx)
{
	return 0;
}
static inline int pld_get_soc_info(struct device *dev,
				   struct pld_soc_info *info)
{
	return 0;
}
static inline int pld_get_ce_id(struct device *dev, int irq)
{
	return 0;
}
static inline void pld_runtime_init(struct device *dev, int auto_delay)
{
}
static inline void pld_runtime_exit(struct device *dev)
{
}
static inline int pld_athdiag_read(struct device *dev,
				   uint32_t offset, uint32_t memtype,
				   uint32_t datalen, uint8_t *output)
{
	return 0;
}
static inline int pld_athdiag_write(struct device *dev,
				    uint32_t offset, uint32_t memtype,
				    uint32_t datalen, uint8_t *input)
{
	return 0;
}
static inline struct sk_buff *pld_nbuf_pre_alloc(size_t size)
{
	return NULL;
}
static inline int pld_nbuf_pre_alloc_free(struct sk_buff *skb)
{
	return 0;
}
static inline void *pld_get_pdev_device_id(int device_id, enum pld_bus_type type)
{
	return NULL;
}
static inline void pld_remove_bus(enum pld_bus_type type)
{

}
static inline int pld_rescan_bus(enum pld_bus_type type)
{
	return -EINVAL;
}

static inline bool pld_have_platform_driver_support(struct device *dev)
{
	return false;
}

static inline enum pld_bus_type pld_get_bus_type(struct device *dev)
{
	return PLD_BUS_TYPE_NONE;
}

static inline void pld_set_recovery_enabled(struct device *dev, bool enabled)
{
}

static inline void pld_get_ramdump_device_name(struct device *dev,
					char *ramdump_dev_name,
					size_t ramdump_dev_name_len)
{
}
static inline unsigned int pld_get_driver_mode(void)
{
	return PLD_MISSION;
}
static inline int pld_set_driver_mode(unsigned int mode)
{
	return -EINVAL;
}
#endif
#endif
