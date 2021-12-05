# ---------------------------------------------------------------------------------
# 			makefile to compile LOWI client shared library on INFRA platform
# ---------------------------------------------------------------------------------
ALL= liblowi_client.so  install
all: ${ALL}

clean:
	rm -f ${ALL}

ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -Werror -g
endif

CFLAGS += -I. \
    -I.. \
    -I../.. \
    -I$(LOCAL_PATH_UTILS) \
    -I$(LOCAL_PATH_COMMON_INFRA) \
    -I$(LOCAL_PATH_INC_INFRA)

STATIC_LIBS= \
  $(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a

$(LOCAL_PATH_UTILS)/mq_client/libloc_mq_client.a:
	$(MAKE) -C $(LOCAL_PATH_UTILS)/mq_client

LIB_OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard ../common/*.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard ../common/infra/*.cpp))
%.o: %.cpp
	$(CXX) -c -fPIC -o $@ $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<
../common/%.o: ../common/%.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<

liblowi_client.so: $(LIB_OBJS) $(STATIC_LIBS)
	$(CXX) -shared -fPIC -Wl,-soname,$@ -o $@ -Wl,-whole-archive $? -Wl,-no-whole-archive -lc -znow -zrelro

install:
	cp -a -f liblowi_client.so $(INSTALL_ROOT)/lib

-include $(BASE_UTIL_LIB_OBJS:%.o=%.d)
