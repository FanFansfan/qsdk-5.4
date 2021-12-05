/*
 * Copyright (c) 2013-2018, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013-2016 Qualcomm Atheros, Inc.
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

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include "ol_if_athvar.h"
#include "ath_pci.h"
#include <pld_common.h>

extern struct semaphore reset_in_progress;
extern bool driver_registered;
extern unsigned int testmode;

extern struct nss_wifi_soc_ops nss_wifili_soc_ops;
extern void osif_nss_register_module(OL_WIFI_DEV_TYPE target_type,
                                     struct nss_wifi_soc_ops *soc_ops);

void wmi_tlv_init(void);
void ce_service_srng_init(void);
int ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ath_pci_remove(struct pci_dev *pdev);
int
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,10)
ath_pci_suspend(struct pci_dev *pdev, pm_message_t state);
#else
ath_pci_suspend(struct pci_dev *pdev, u32 state);
#endif
int ath_pci_resume(struct pci_dev *pdev);
int ol_ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ol_ath_pci_remove(struct pci_dev *pdev);
int ol_ath_pci_suspend(struct pci_dev *pdev, pm_message_t state);
int ol_ath_pci_resume(struct pci_dev *pdev);
#if UMAC_SUPPORT_WEXT
void ol_ath_iw_detach(struct net_device *dev);
void ol_ath_iw_attach(struct net_device *dev);
#endif
QDF_STATUS create_target_if_ctx(void);
void ol_if_register_wifi3_0(void);
#ifdef ATH_AHB
extern int wifi3_ko_exit_in_progress;
#endif
#include "osif_bus.h"
#include "osif_private.h"
#include <acfg_api_types.h>   /* for ACFG_WDT_REINIT_DONE */
#include <acfg_drv_event.h>
#include <wlan_cmn.h>

#ifndef ATH_BUS_PM
#ifdef CONFIG_PM
#define ATH_BUS_PM
#endif /* CONFIG_PM */
#endif /* ATH_BUS_PM */

#ifdef WIFI_TARGET_TYPE_3_0
/*
 * Use a static table of PCI id's for now.  While this is the
 * "new way" to do things, we may want to switch back to having
 * the HAL check them by defining a probe method.
 */
#if defined(ATH_PCI) && !defined(CONFIG_AHB_FW_SIM)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
const struct pci_device_id ath_pci_id_table_3_0[] = {
#else
DEFINE_PCI_DEVICE_TABLE(ath_pci_id_table_3_0) = {
#endif
    { 0xbeaf, 0xabc0, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0xbeaf, 0xabc1, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0xbeaf, 0xabc2, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0xbeaf, 0xabc3, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0xbeaf, 0xaa10, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0xbeaf, 0xaa11, PCI_ANY_ID, PCI_ANY_ID }, /* Emulation PCIE  */
    { 0 }
};

MODULE_DEVICE_TABLE(pci, ath_pci_id_table_3_0);

static struct pci_driver ol_ath_pci_driver = {
    .name       = "ath_ol_3_0_pci",
    .id_table   = ath_pci_id_table_3_0,
    .probe      = ath_pci_probe,
    .remove     = ath_pci_remove,
#ifdef ATH_BUS_PM
    .suspend    = ath_pci_suspend,
    .resume     = ath_pci_resume,
#endif /* ATH_BUS_PM */
    /* Linux 2.4.6 has save_state and enable_wake that are not used here */
};
#endif
#endif

#include <linux/ethtool.h>

/*
 * Module glue.
 */
#include "version.h"
#ifdef WIFI_TARGET_TYPE_3_0
static char *version = ATH_PCI_VERSION " (Atheros/multi-bss)";
static char *dev_info = "ath_ol_pci_wifi3.0";
#endif

#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

#ifdef QCA_SINGLE_WIFI_3_0
int qdf_mod_init(void);
int qdf_mod_exit(void);
int init_asf(void);
int exit_asf(void);
int init_umac(void);
void exit_umac(void);
int qca_ol_mod_init(void);
void qca_ol_mod_exit(void);
int spectral_init_module(void);
void spectral_exit_module(void);
#endif

#ifndef QCA_SINGLE_WIFI_3_0
static void __exit exit_ath_pci_3_0(void)
#else
void exit_ath_pci_3_0(void)
#endif
{
#ifdef WIFI_TARGET_TYPE_3_0
#ifdef ATH_AHB
    void exit_ath_ahb_3_0(void);
    wifi3_ko_exit_in_progress = 1;
#endif

    if (down_interruptible(&reset_in_progress))
        return;
    if (testmode != PLD_COLDBOOT_CALIBRATION &&
        testmode != PLD_FTM_COLDBOOT_CALIBRATION)
#if defined(ATH_PCI) && !defined(CONFIG_AHB_FW_SIM)
        pci_unregister_driver(&ol_ath_pci_driver);
#endif

    driver_registered = false;
    up(&reset_in_progress);

#ifdef ATH_AHB
        exit_ath_ahb_3_0();
#else
    qdf_info(KERN_INFO "%s: driver unloaded", dev_info);
#endif /* ATH_AHB */

#ifdef QCA_SINGLE_WIFI_3_0
    qca_ol_mod_exit();
    spectral_exit_module();
    exit_umac();
    exit_asf();
    qdf_mod_exit();
#endif /* QCA_SINGLE_WIFI_3_0 */
    wifi3_ko_exit_in_progress = 0;
#endif
}
module_exit(exit_ath_pci_3_0);

#ifndef QCA_SINGLE_WIFI_3_0
static int __init init_ath_pci_3_0(void)
#else
int init_ath_pci_3_0(void)
#endif
{
#ifdef WIFI_TARGET_TYPE_3_0
#ifdef ATH_AHB
    int pciret = 0, ahbret = 0;
    int init_ath_ahb_3_0(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    int ret = 0;

reinit:
    /* For kernel 5.4 and above, insmod of the wifi modules happens from
     * kmodloader on first boot. testmode module param would not be set
     * when module is loaded from kmodloader, so get the mode from PLD
     */
    testmode = pld_get_driver_mode();
    qdf_info("Driver Mode: %d", testmode);
#endif
#ifdef QCA_SINGLE_WIFI_3_0
    qdf_mod_init();
    init_asf();
    init_umac();
    spectral_init_module();
    qca_ol_mod_init();
#endif

    qdf_debug("WIFI3.0 Registration");
    /* If ahb not enabled then initialize offload ops for 3.0 */
    ol_if_register_wifi3_0();
    wmi_tlv_init();
    ce_service_srng_init();
#if QCA_NSS_WIFILI_OFFLOAD_SUPPORT
    osif_nss_register_module(OL_WIFI_3_0, &nss_wifili_soc_ops);
#endif
#ifdef ATH_AHB
    ahbret = init_ath_ahb_3_0();
    if(ahbret < 0 ) {
        qdf_info("ath_ahb: Error while registering ath wlan ahb driver");
    }
#endif

    qdf_info(KERN_INFO "%s : %s", dev_info, version);

    if (testmode != PLD_COLDBOOT_CALIBRATION &&
        testmode != PLD_FTM_COLDBOOT_CALIBRATION) {
#if defined(ATH_PCI) && !defined(CONFIG_AHB_FW_SIM)
        if (pci_register_driver(&ol_ath_pci_driver) < 0) {
            qdf_err("ath_pci: No devices found, driver not installed.");
            pci_unregister_driver(&ol_ath_pci_driver);
            return (-ENODEV);
        }
#else
        pciret = -ENODEV;
#endif
    }

#ifdef ATH_AHB
    /*
     * Return failure only when there is no wlan device
     * on both pci and ahb buses.
     */
      if (ahbret && pciret) {
              /* which error takes priority ?? */
              return ahbret;
      }
#endif

    driver_registered = true;
    sema_init(&reset_in_progress, 1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 24)
    /* Call the rmmod function from here to wait for coldboot
     * calibration to be complete. Once coldboot calibration is done
     * reset the driver mode to Mission mode or FTM Mode and go back
     * to the start of this function to enter into Mission or FTM mode.
     */
    if (testmode == PLD_COLDBOOT_CALIBRATION ||
        testmode == PLD_FTM_COLDBOOT_CALIBRATION) {
            exit_ath_pci_3_0();
            if (testmode == PLD_COLDBOOT_CALIBRATION)
                ret = pld_set_driver_mode(PLD_MISSION);
            else if (testmode == PLD_FTM_COLDBOOT_CALIBRATION)
                ret = pld_set_driver_mode(PLD_FTM);

            if (ret) {
                qdf_err("Failed to set driver_mode after mode %d",
                        testmode);
                return ret;
            }
#ifdef ATH_AHB
            pciret = 0;
            ahbret = 0;
#endif
            goto reinit;
    }
#endif
#endif
    return 0;
}
module_init(init_ath_pci_3_0);
