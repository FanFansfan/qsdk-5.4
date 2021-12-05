PLUGINS:= manager mcfwdtbl-eswitch
ifeq ($(MCS_MODULE_WLAN),y)
PLUGINS+=  mcfwdtbl-wlan5g mcfwdtbl-wlan2g
endif

all: $(PLUGINS)

manager:
	@$(MAKE) -C manager all

mcfwdtbl-wlan5g:
	@$(MAKE) -C mcfwdtbl-wlan5g all

mcfwdtbl-wlan2g:
	@$(MAKE) -C mcfwdtbl-wlan2g all

mcfwdtbl-eswitch:
	@$(MAKE) -C mcfwdtbl-eswitch all

clean:
	@$(MAKE) -C manager clean
ifeq ($(MCS_MODULE_WLAN),y)
	@$(MAKE) -C mcfwdtbl-wlan5g clean
	@$(MAKE) -C mcfwdtbl-wlan2g clean
endif
	@$(MAKE) -C mcfwdtbl-eswitch clean

.PHONY: manager mcfwdtbl-wlan5g mcfwdtbl-wlan2g mcfwdtbl-eswitch
