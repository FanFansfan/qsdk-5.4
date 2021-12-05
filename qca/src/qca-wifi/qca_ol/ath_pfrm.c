/*
 * Copyright (c) 2020  Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */
#include <ath_pfrm.h>
#include <ath_pfrm_sim.h>
#include <pld_common.h>
#include <linux/version.h>
#include <qdf_mem.h>

void *g_fwsim_pfrm_ctx = NULL;

int pfrm_get_irq(struct device *dev,
		 struct qdf_pfm_hndl *pdev,
		 const char *irq_name, int irq_offset,
		 int *irq)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		qal_vbus_get_irq(pdev, irq_name, irq);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		if (irq_offset < (HIF_IC_CE0_IRQ_OFFSET + CE_COUNT_MAX))
                    irq_offset = irq_offset - HIF_IC_CE0_IRQ_OFFSET;
		else
		    irq_offset = irq_offset;

                *irq = pfrm_ahb_sim_get_irq(dev, irq_name, irq_offset);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int pfrm_request_irq(struct device *dev, int irq,
		     irq_handler_t handler,
		     unsigned long irqflags,
		     const char *devname,
		     void *dev_data)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = request_irq(irq, handler, irqflags, devname, dev_data);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pfrm_ahb_sim_request_irq(dev, irq, handler,
					       irqflags, devname, dev_data);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int pfrm_free_irq(struct device *dev, int irq, void *dev_data)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		free_irq(irq, dev_data);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		ret = pfrm_ahb_sim_free_irq(dev, irq, dev_data);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

void pfrm_enable_irq(struct device *dev, int irq)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		enable_irq(irq);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		pfrm_ahb_sim_enable_irq(dev, irq);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}
}

void pfrm_disable_irq(struct device *dev, int irq)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		disable_irq(irq);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		pfrm_ahb_sim_disable_irq(dev, irq);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}
}

void pfrm_disable_irq_nosync(struct device *dev, int irq)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		disable_irq_nosync(irq);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		pfrm_ahb_sim_disable_irq(dev, irq);
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}
}

QDF_STATUS pfrm_platform_get_resource(struct device *dev,
				      struct qdf_pfm_hndl *pfhndl,
				      struct qdf_vbus_resource **mem_rsrc,
				      uint32_t res_type,
				      uint32_t res_idx)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		return qal_vbus_get_resource(pfhndl, mem_rsrc,
					     res_type, res_idx);
	case PLD_BUS_TYPE_AHB_FW_SIM:
		if(!g_fwsim_pfrm_ctx){
			g_fwsim_pfrm_ctx =
			(void *)qdf_mem_malloc(sizeof(struct resource));
			*mem_rsrc = (struct qdf_vbus_resource *)g_fwsim_pfrm_ctx;
		} else {
			*mem_rsrc = (struct qdf_vbus_resource *)g_fwsim_pfrm_ctx;
		}
		return QDF_STATUS_SUCCESS;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}

	return QDF_STATUS_E_FAILURE;
}

int pfrm_dma_set_mask(struct device *dev, uint64_t dma_mask)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = dma_set_mask(dev, DMA_BIT_MASK(dma_mask));
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int pfrm_dma_set_mask_and_coherent(struct device *dev, uint64_t dma_mask)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(dma_mask));
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int pfrm_dma_set_coherent_mask(struct device *dev, uint64_t dma_mask)
{
	int ret = 0;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(dma_mask));
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
QDF_STATUS pfrm_devm_ioremap_resource(struct device *dev,
				      struct qdf_vbus_resource *mem_rsrc,
				      void __iomem **ioremap_mem)
{
	void __iomem *mem = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	enum pld_bus_type type = pld_get_bus_type(dev);
	struct pld_soc_info soc_info;
	struct resource *tmp_rsrc;
	int ret = -1;

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		mem = devm_ioremap_resource(dev, (struct resource *)mem_rsrc);
		if (IS_ERR(mem))
			status = QDF_STATUS_E_FAILURE;
		else
			*ioremap_mem = mem;
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		qdf_mem_zero(&soc_info, sizeof(soc_info));

		ret = pld_get_soc_info(dev, &soc_info);
                if (ret < 0) {
			pr_err("pld_get_soc_info error = %d", ret);
			return QDF_STATUS_E_FAILURE;
		}

		*ioremap_mem = (void __iomem *)soc_info.v_addr;
		tmp_rsrc = (struct resource *)mem_rsrc;
		tmp_rsrc->start = (phys_addr_t)soc_info.p_addr;
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		status = QDF_STATUS_E_INVAL;
		break;
	}

	return status;
}
#else
QDF_STATUS pfrm_devm_request_and_ioremap(struct device *dev,
					 struct qdf_vbus_resource *mem_rsrc,
					 void __iomem **ioremap_mem)
{
	void __iomem *mem = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
	case PLD_BUS_TYPE_PCIE:
		mem = devm_request_and_ioremap(dev, mem_rsrc);
		if (IS_ERR(mem))
			status = QDF_STATUS_E_FAILURE;
		else
			*ioremap_mem = mem;
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		status = QDF_STATUS_E_INVAL;
		break;
	}

	return status;
}
#endif

void pfrm_devm_iounmap(struct device *dev, void __iomem *mem)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
		devm_iounmap(dev, mem);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}
}

void pfrm_devm_release_mem_region(
		struct device *dev,
		qdf_dma_addr_t mem_start,
		int mem_size)
{
	enum pld_bus_type type = pld_get_bus_type(dev);

	switch (type) {
	case PLD_BUS_TYPE_AHB:
		devm_release_mem_region(dev, mem_start, mem_size);
		break;
	case PLD_BUS_TYPE_AHB_FW_SIM:
		if(g_fwsim_pfrm_ctx) {
			qdf_mem_free(g_fwsim_pfrm_ctx);
			g_fwsim_pfrm_ctx = NULL;
		}
		break;
	default:
		pr_err("Invalid device type %d\n", type);
		break;
	}
}

int pfrm_read_config_word(struct pci_dev *pdev, int offset, uint16_t *val)
{
	int ret = 0;

	switch (pld_get_bus_type(&pdev->dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pci_read_config_word(pdev, offset, val);
		break;
	default:
		pr_err("Invalid device type\n");
		break;
	}

	return ret;
}

int pfrm_write_config_word(struct pci_dev *pdev, int offset, uint16_t val)
{
	int ret = 0;

	switch (pld_get_bus_type(&pdev->dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pci_write_config_word(pdev, offset, val);
		break;
	default:
		pr_err("Invalid device type\n");
		break;
	}

	return ret;
}

int pfrm_read_config_dword(struct pci_dev *pdev, int offset, uint32_t *val)
{
	int ret = 0;

	switch (pld_get_bus_type(&pdev->dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pci_read_config_dword(pdev, offset, val);
		break;
	default:
		pr_err("Invalid device type\n");
		break;
	}

	return ret;
}

int pfrm_write_config_dword(struct pci_dev *pdev, int offset, uint32_t val)
{
	int ret = 0;

	switch (pld_get_bus_type(&pdev->dev)) {
	case PLD_BUS_TYPE_PCIE:
		ret = pci_write_config_dword(pdev, offset, val);
		break;
	default:
		pr_err("Invalid device type\n");
		break;
	}

	return ret;
}
