# ---------------------------------------------------------------------------------
# 			Makefile to compile lowi server on INFRA platform
# ---------------------------------------------------------------------------------
ifneq ($(strip $(TOOLPREFIX)),)
CROSS:=$(TOOLPREFIX)
endif

CC= $(CROSS)gcc

INC_DIRS+= -I. \
    -I./infra \
    -I./wifidriver/fakewifidriver \
    -I./wifidriver/util \
    -I./wifidriver/util/infra \
    -I./wifidriver/romewifidriver \
    -I./wifidriver/ranging \
    -I./wifidriver/ranging/infra \
    -I.. \
    -I../inc \
    -I../common \
    -I../.. \
    -I$(LOCAL_PATH_UTILS) \
    -I$(LOCAL_PATH_INC) \
    -I$(LOCAL_PATH_INC_INFRA) \
    -I$(LOCAL_PATH_COMMON_INFRA)

STATIC_LIBS= \
  $(LOCAL_PATH_UTILS)/base_util/libloc_base_util.a \
  $(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a \
  $(LOCAL_PATH_UTILS)/mq_server/libloc_mq_server.a \
  wifidriver/romewifidriver/libwifidriver_rome.a \
  wifidriver/util/libwifidriver_util.a \
  wifidriver/ranging/libwifidriver_ranging.a

CFLAGS+= ${INC_DIRS} -MMD -O2 -g -lpthread -lnl-3 -lnl-genl-3 -lm -ldl
ifneq ($(ARCH),mips)
CFLAGS += -fpie
LDFLAGS+= -pie
endif

$(LOCAL_PATH_UTILS)/base_util/libloc_base_util.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/base_util
$(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_client
$(LOCAL_PATH_UTILS)/mq_server/libloc_mq_server.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_server
wifidriver/romewifidriver/libwifidriver_rome.a:
	$(MAKE) -C wifidriver/romewifidriver
wifidriver/util/libwifidriver_util.a:
	$(MAKE) -C wifidriver/util
wifidriver/ranging/libwifidriver_ranging.a:
	$(MAKE) -C wifidriver/ranging

HEADERS=$(wildcard *.h)
COMMON_HEADERS=$(wildcard ../inc/*.h)

%.o: %.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<
../common/%.o: ../common/%.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<

ifndef CONFIG_OS
CONFIG_OS=unix
endif

LIB_OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard infra/*.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard ../common/*.cpp))

ALL= lowi-server

all: ${ALL}

lowi-server: $(LIB_OBJS) $(STATIC_LIBS)
	${CXX} -o $@ ${CXXFLAGS} ${CFLAGS} ${LDFLAGS} -Wall -Werror $^

clean:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/base_util clean
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_client clean
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_server clean
	$(MAKE) -C wifidriver/romewifidriver clean
	$(MAKE) -C wifidriver/util clean
	$(MAKE) -C wifidriver/ranging clean
	rm -f ${ALL}
