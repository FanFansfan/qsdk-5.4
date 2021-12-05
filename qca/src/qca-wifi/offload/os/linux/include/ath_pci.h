/*
 * Copyright (c) 2013,2017 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __ATH_PCI_H__
#define __ATH_PCI_H__

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <osif_bus.h>

#if DUMP_FW_RAM
#if ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS
#include <linux/ath79_wlan.h>
#endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#define ath_dma_sync_single	pci_dma_sync_single_for_device
#else
#define ath_dma_sync_single pci_dma_sync_single_for_cpu
#endif
#define	PCI_SAVE_STATE(a,b)	pci_save_state(a)
#define	PCI_RESTORE_STATE(a,b)	pci_restore_state(a)
#else
#define ath_dma_sync_single	pci_dma_sync_single
#define	PCI_SAVE_STATE(a,b)	pci_save_state(a,b)
#define	PCI_RESTORE_STATE(a,b)	pci_restore_state(a,b)
#endif

/* Maximum amount of time in micro seconds before which the CE per engine service
 * should yield. ~1 jiffie.
 */
#define CE_PER_ENGINE_SERVICE_MAX_YIELD_TIME (4 * 1000)

#ifndef CONFIG_WIFI_EMULATION_WIFI_3_0
#define PDEV_SUSPEND_TIMEOUT 200
#else
#define PDEV_SUSPEND_TIMEOUT 200000
#endif
typedef struct pld_plat_data pci_priv_data;


/*pci*/
extern void pci_defer_reconnect(void *pci_reconnect_work);
void pci_reconnect_cb(ol_ath_soc_softc_t *soc);
int ath_pci_recover(struct ol_ath_soc_softc *soc);


/*ahb*/
int init_ath_ahb(void);
int ol_ath_ahb_probe(struct platform_device *pdev,
					 const struct platform_device_id *id);
int ath_ahb_recover(struct ol_ath_soc_softc *soc);
void ol_ath_ahb_remove(struct platform_device *pdev);

void ol_hif_close(void *hif_ctx);
extern bool ol_ath_supported_dev(const struct platform_device_id *id);
extern uint32_t ol_ath_get_hw_mode_id(void *bdev);

#endif /* __ATH_PCI_H__ */
