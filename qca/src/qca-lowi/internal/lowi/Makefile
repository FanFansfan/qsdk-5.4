# ---------------------------------------------------------------------------------
# 			Top level makefile to help compile lowi binaries on INFRA platform
# ---------------------------------------------------------------------------------
SUBDIRS=./lowi_server ./test/lowi_test
SHAREDLIBS=./lowi_client

LOWI_MAKE_OPTS=\
    LOCAL_PATH_UTILS=$(LOWI_SRC_PATH)/util/native/ \
    LOCAL_PATH_INC=$(LOWI_SRC_PATH)/internal/lowi/inc/ \
    LOCAL_PATH_INC_INFRA=$(LOWI_SRC_PATH)/internal/lowi/inc/infra/ \
    LOCAL_PATH_COMMON_INFRA+=$(LOWI_SRC_PATH)/internal/lowi/common/infra/ \

all: lowi
lowi:
	for dir in $(SHAREDLIBS) ; do (cd $$dir && $(MAKE) all $(LOWI_MAKE_OPTS)) || exit 1; done
	for dir in $(SUBDIRS) ; do (cd $$dir && $(MAKE) all $(LOWI_MAKE_OPTS)) || exit 1; done

clean:
	for dir in $(SHAREDLIBS) ; do (cd $$dir && $(MAKE) clean $(LOWI_MAKE_OPTS)) || exit 1; done
	for dir in $(SUBDIRS) ; do (cd $$dir && $(MAKE) clean $(LOWI_MAKE_OPTS)) || exit 1; done
	rm -f *~

install:
	for dir in $(SUBDIRS) ; do (cd $$dir && $(MAKE) install $(LOWI_MAKE_OPTS)) || exit 1; done
