ifeq ($(obj),)
obj := .
endif

DEPTH := ..

#
# Path to the QTI driver framework source base
#
QDF := $(src)/../cmn_dev/qdf

ifeq ($(strip ${QCA_PARTNER_MAKE_F_SUPPORT}),1)
export QCA_PARTNER_MAKE_F_INC=1
endif
include $(obj)/$(DEPTH)/os/linux/Makefile-linux.common

ifeq ($(strip ${QCA_SUPPORT_RAWMODE_PKT_SIMULATION}), 1)
INCS += -I$(src)/include -I$(QDF)/inc -I$(src)/../pld/inc
INCS += -I$(src)/../component_dev/qal/inc -I$(src)/../cmn_dev/qal/inc/ -I$(src)/../cmn_dev/qal/linux/src
INCS += -I$(obj)/
INCS += -I$(obj)/../direct_attach/hal/linux
obj-m += rawmode_sim.o

EXTRA_CFLAGS+= $(INCS) $(COPTS)
endif

