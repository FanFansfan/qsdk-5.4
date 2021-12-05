/*
 * Copyright (c) 2020  Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */
#ifndef __ATH_PFRM_SIM_H__
#define __ATH_PFRM_SIM_H__

#include <linux/device.h>
#include <linux/interrupt.h>

#define HIF_IC_CE0_IRQ_OFFSET 4
#define CE_COUNT_MAX 12

#ifndef CONFIG_AHB_FW_SIM
int pfrm_ahb_sim_get_irq(struct device *dev, const char *irq_name,
			 int irq_offset)
{
	return 0;
}

int pfrm_ahb_sim_request_irq(struct device *dev,
			     int irq,
			     irq_handler_t handler,
			     unsigned long irqflags,
			     const char *devname,
			     void *dev_data)
{
	return 0;
}

int pfrm_ahb_sim_free_irq(struct device *dev, int irq, void *dev_data)
{
	return 0;
}

void pfrm_ahb_sim_enable_irq(struct device *dev, int irq)
{
}

void pfrm_ahb_sim_disable_irq(struct device *dev, int irq)
{
}

#else

#include <net/cnss2.h>
static inline int pfrm_ahb_sim_get_irq(struct device *dev,
				       const char *irq_name,
				       int irq_offset)
{
	return cnss_fw_sim_get_msi_irq(dev, irq_offset);
}

static inline int pfrm_ahb_sim_request_irq(struct device *dev,
					   int irq,
					   irq_handler_t handler,
					   unsigned long irqflags,
					   const char *devname,
					   void *dev_data)
{
	return cnss_fw_sim_request_irq(dev, irq, handler,
					irqflags, devname, dev_data);
}

static inline int pfrm_ahb_sim_free_irq(struct device *dev, int irq,
					void *dev_data)
{
	return cnss_fw_sim_free_irq(dev, irq, dev_data);
}

static inline void pfrm_ahb_sim_enable_irq(struct device *dev, int irq)
{
	cnss_fw_sim_enable_irq(dev, irq);
}

static inline void pfrm_ahb_sim_disable_irq(struct device *dev, int irq)
{
	cnss_fw_sim_disable_irq(dev, irq);
}

#endif /* CONFIG_AHB_FW_SIM */
#endif /* __ATH_PFRM_SIM_H__ */
