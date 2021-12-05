/*
 * Copyright (c) 2020  Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef __ATH_PFRM_H__
#define __ATH_PFRM_H__

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <qal_vbus_dev.h>

/**
 * pfrm_get_irq - wrapper API to get irq number based on bus type
 * @dev: pointer to device structure
 * @pdev: pointer to platform device structure
 * @irqname: irq name as provided in dts file
 * @irq_offset: irq name offset index in hif layer
 * @irq: irq number to be filled and sent
 *
 * Return: 0 on SUCCESS
 *         EINVAL on FAILURE
 */
int pfrm_get_irq(struct device *dev, struct qdf_pfm_hndl *pdev,
		 const char *irq_name,
		 int irq_offset, int *irq);

/**
 * pfrm_request_irq - wrapper API to request irq based on bus type
 * @dev: pointer to device structure
 * @irq: irq number
 * @handler: irq handler to be registered
 * @irqflags: irq flags
 * @devname: device name
 * @dev_data: device data for irq handler callback
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_request_irq(struct device *dev, int irq, irq_handler_t handler,
		     unsigned long irqflags,
		     const char *devname,
		     void *dev_data);

/**
 * pfrm_free_irq - wrapper API to free irq based on bus type
 * @dev: pointer to device structure
 * @irq: irq number
 * @dev_data: device data for irq handler callback
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_free_irq(struct device *dev, int irq, void *dev_data);

/**
 * pfrm_enable_irq - wrapper API to enable irq based on bus type
 * @dev: pointer to device structure
 * @irq: irq number
 *
 * Return: NA
 */
void pfrm_enable_irq(struct device *dev, int irq);

/**
 * pfrm_disable_irq - wrapper API to disable irq based on bus type
 * @dev: pointer to device structure
 * @irq: irq number
 *
 * Return: NA
 */
void pfrm_disable_irq(struct device *dev, int irq);

/**
 * pfrm_disable_irq_nosync - wrapper API to disable irq based on bus type
 * @dev: pointer to device structure
 * @irq: irq number
 *
 * Return: NA
 */
void pfrm_disable_irq_nosync(struct device *dev, int irq);

/**
 * pfrm_platform_get_resource - wrapper API to get platform resource
 * @dev: pointer to device structure
 * @pfhndl: pointer to platform handle
 * @mem_rsrc: pointer to platform resource to be filled and sent
 * @res_type: platform resource type
 * @res_idx: platform resource index
 *
 * Return: QDF_STATUS_SUCCESS on success
 *         QDF_STATUS_FAILURE on failure
 */
QDF_STATUS pfrm_platform_get_resource(struct device *dev,
				      struct qdf_pfm_hndl *pfhndl,
				      struct qdf_vbus_resource **mem_rsrc,
				      uint32_t res_type,
				      uint32_t res_idx);

/**
 * pfrm_dma_set_mask - wrapper API to set dma streaming mappings
 * @dev: pointer to device structure
 * @dma_mask: DMA mask
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_dma_set_mask(struct device *dev, uint64_t dma_mask);

/**
 * pfrm_dma_set_mask_and_coherent - wrapper API to set dma mask for
 * streaming and coherent
 * @dev: pointer to device structure
 * @dma_mask: DMA mask
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_dma_set_mask_and_coherent(struct device *dev, uint64_t dma_mask);

/**
 * pfrm_dma_set_coherent_mask - wrapper API to set dma mak for consistent
 * allocations
 * @dev: pointer to device structure
 * @dma_mask: DMA mask
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_dma_set_coherent_mask(struct device *dev, uint64_t dma_mask);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
/**
 * pfrm_devm_ioremap_resource - wrapper API to ioremap platform mem resource
 * @dev: pointer to device structure
 * @mem_rsrc: resource to be handled
 * @ioremap_mem: pointer to remapped memory resource
 *
 * Return: QDF_STATUS_SUCCESS on success
 *         QDF_STATUS_FAILURE on failure
 */
QDF_STATUS pfrm_devm_ioremap_resource(struct device *dev,
				      struct qdf_vbus_resource *mem_rsrc,
				      void __iomem **ioremap_mem);
#else
/**
 * pfrm_devm_request_and_ioremap - wrapper API to request and ioremap resource
 * @dev: pointer to device structure
 * @mem_rsrc: resource to be handled
 * @ioremap_mem: pointer to remapped memory resource
 *
 * Return: QDF_STATUS_SUCCESS on success
 *         QDF_STATUS_FAILURE on failure
 */
QDF_STATUS pfrm_devm_request_and_ioremap(struct device *dev,
					 struct qdf_vbus_resource *mem_rsrc,
					 void __iomem **ioremap_mem);
#endif

/**
 * pfrm_devm_iounmap - wrapper API to unmap mem resource
 * @dev: pointer to device structure
 * @mem: pointer to mem to be handled
 *
 * Return: NA
 */
void pfrm_devm_iounmap(struct device *dev, void __iomem *mem);

/**
 * pfrm_devm_release_mem_region - wrapper API to release device mem
 * @dev: pointer to device structure
 * @mem_start: pointer to start of mem address
 * @mem_size: memory size
 *
 * Return: NA
 */
void pfrm_devm_release_mem_region(
		struct device *dev,
		qdf_dma_addr_t mem_start,
		int mem_size);

/**
 * pfrm_read_config_word - wrapper API to read config word
 * @dev: pointer to pci_dev
 * @offset: off set value
 * @val: value read
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_read_config_word(struct pci_dev *pdev, int offset, uint16_t *val);

/**
 * pfrm_write_config_word - wrapper API to write config word
 * @dev: pointer to pci_dev
 * @offset: off set value
 * @val: value to write
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_write_config_word(struct pci_dev *pdev, int offset, uint16_t val);

/**
 * pfrm_read_config_dword - wrapper API to read config dword
 * @dev: pointer to pci_dev
 * @offset: off set value
 * @val: value read
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_read_config_dword(struct pci_dev *pdev, int offset, uint32_t *val);

/**
 * pfrm_write_config_dword - wrapper API to write config dword
 * @dev: pointer to pci_dev
 * @offset: off set value
 * @val: value to write
 *
 * Return: 0 on SUCCESS
 *	   EINVAL on FAILURE
 */
int pfrm_write_config_dword(struct pci_dev *pdev, int offset, uint32_t val);

#endif /* __ATH_PFRM_H__ */
