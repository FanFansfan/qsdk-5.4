/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
 */

#ifndef __PLD_AHB_FW_SIM_H__
#define __PLD_AHB_FW_SIM_H__

#include "pld_internal.h"

#ifndef CONFIG_AHB_FW_SIM
static inline void pld_ahb_fw_sim_link_down(struct device *dev)
{
    return;
}

static inline int pld_ahb_fw_sim_is_fw_down(struct device *dev)
{
    return 0;
}

static inline int pld_ahb_fw_sim_get_user_msi_assignment(struct device *dev,
                              char *user_name,
                              int *num_vectors,
                              uint32_t *base_data,
                              uint32_t *base_vector)
{
    return -EINVAL;
}

static inline int pld_ahb_fw_sim_get_msi_irq(struct device *dev,
                          unsigned int vector)
{
    return 0;
}

static inline void pld_ahb_fw_sim_get_msi_address(struct device *dev,
                           uint32_t *msi_addr_low,
                           uint32_t *msi_addr_high)
{
    return;
}

static inline int pld_ahb_fw_sim_idle_shutdown(struct device *dev)
{
    return 0;
}

static inline int pld_ahb_fw_sim_idle_restart(struct device *dev)
{
    return 0;
}

static inline int pld_ahb_fw_sim_register_driver(void)
{
    return 0;
}

static inline void pld_ahb_fw_sim_unregister_driver(void)
{
    return;
}

static inline int pld_ahb_fw_sim_wlan_enable(struct device *dev,
                          struct pld_wlan_enable_cfg *cfg,
                          enum pld_driver_mode mode,
                          const char *host_version)
{
    return 0;
}

static inline int pld_ahb_fw_sim_wlan_disable(struct device *dev,
                           enum pld_driver_mode mode)
{
    return 0;
}


static inline int pld_ahb_fw_sim_get_platform_cap(struct device *dev,
                           struct pld_platform_cap *cap)
{
    return 0;
}
static inline void *pld_ahb_fw_sim_subsystem_get(struct device *dev)
{
    return NULL;
}
static inline int pld_ahb_fw_sim_get_soc_info(struct device *dev,
                                              struct pld_soc_info *info)
{
    return 0;
}
#else
#include <net/cnss2.h>

int pld_ahb_fw_sim_wlan_enable(struct device *dev,
                struct pld_wlan_enable_cfg *config,
                enum pld_driver_mode mode,
                const char *host_version);
int pld_ahb_fw_sim_wlan_disable(struct device *dev, enum pld_driver_mode mode);
int pld_ahb_fw_sim_register_driver(void);
void pld_ahb_fw_sim_unregister_driver(void);
int pld_ahb_fw_sim_get_platform_cap(struct device *dev,
                     struct pld_platform_cap *cap);

static inline int pld_ahb_fw_sim_get_user_msi_assignment(struct device *dev,
                              char *user_name,
                              int *num_vectors,
                              uint32_t *base_data,
                              uint32_t *base_vector)
{
    return cnss_fw_sim_get_user_msi_assignment(dev, user_name, num_vectors,
                        base_data, base_vector);
}

static inline int pld_ahb_fw_sim_get_msi_irq(struct device *dev,
                          unsigned int vector)
{
    return cnss_fw_sim_get_msi_irq(dev, vector);
}

static inline void pld_ahb_fw_sim_get_msi_address(struct device *dev,
                           uint32_t *msi_addr_low,
                           uint32_t *msi_addr_high)
{
    cnss_fw_sim_get_msi_address(dev, msi_addr_low, msi_addr_high);
}

static inline int pld_ahb_fw_sim_idle_shutdown(struct device *dev)
{
    return 0;
}

static inline int pld_ahb_fw_sim_idle_restart(struct device *dev)
{
    return 0;
}

static inline void *pld_ahb_fw_sim_subsystem_get(struct device *dev)
{
    /*FW SIM expects a valid device handle */
    return (void*)dev;
}

int pld_ahb_fw_sim_get_soc_info(struct device *dev, struct pld_soc_info *info);

#endif
#endif
