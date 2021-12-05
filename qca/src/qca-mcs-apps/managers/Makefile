TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

SRCDIRS = mcManager
ifeq ($(MCS_MODULE_WLAN),y)
SRCDIRS +=wlanManager
endif


all:
	@for dir in $(SRCDIRS) ; do (cd $$dir && $(MAKE) all) || exit 1; done

clean:
	@for dir in $(SRCDIRS)  ; do (cd $$dir && $(MAKE) clean) || exit 1; done


.PHONY: all clean

