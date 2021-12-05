# ---------------------------------------------------------------------------------
# 			Makefile to compile lowi_test binary on INFRA platform
# ---------------------------------------------------------------------------------

ifneq ($(strip $(TOOLPREFIX)),)
CROSS:=$(TOOLPREFIX)
endif

CC= $(CROSS)gcc

INC_DIRS+= -I. \
    -I./infra \
    -I../.. \
    -I../../inc \
    -I../../inc/infra \
    -I../../common \
    -I../../.. \
    -I$(LOCAL_PATH_UTILS)


STATIC_LIBS= \
  $(LOCAL_PATH_UTILS)/base_util/libloc_base_util.a \
  $(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a

SHARED_LIB_PATH= \
    -L$(INSTALL_ROOT)/lib -Wl,-rpath=/usr/lib/lowi

SHARED_LIBS= \
  -llowi_client

CFLAGS+= ${INC_DIRS} -MMD -O2 -g -lm -lpthread -lroxml

CFLAGS+= -fpie
LDFLAGS = -pie

$(LOCAL_PATH_UTILS)base_util/libloc_base_util.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/base_util
$(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_client

HEADERS=$(wildcard *.h)
COMMON_HEADERS=$(wildcard ../inc/*.h)

%.o: %.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<

ifndef CONFIG_OS
CONFIG_OS=unix
endif

LIB_OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard infra/*.cpp))

ALL= lowi-test

all: ${ALL}

lowi-test: $(LIB_OBJS) $(STATIC_LIBS)
	$(CXX) $(SHARED_LIB_PATH) -o $@ ${CXXFLAGS} ${CFLAGS} ${LDFLAGS} -Wall -Werror $(LIB_OBJS) $(STATIC_LIBS) $(SHARED_LIBS)

clean:
	$(MAKE) -C $(LOCAL_PATH_UTILS)base_util clean
	$(MAKE) -C $(LOCAL_PATH_UTILS)mq_client clean
	rm -f ${ALL}
