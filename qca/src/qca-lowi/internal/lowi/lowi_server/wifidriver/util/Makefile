# ---------------------------------------------------------------------------------
# 			Makefile to compile utils library on INFRA platform
# ---------------------------------------------------------------------------------

ALL= libwifidriver_util.a
all: ${ALL}

clean:
	rm -f ${ALL}

install:
	@echo Nothing to be made.

INC_DIRS+= -I. \
    -I./infra \
    -I../../.. \
    -I../../infra/ \
    -I../../../.. \
    -I../ranging/ \
    -I../ranging/infra/ \
    -I$(STAGING_DIR)/usr/include/libnl3 \
    -I$(LOCAL_PATH_UTILS) \
    -I$(LOCAL_PATH_INC) \
    -I$(LOCAL_PATH_INC_INFRA) \


STATIC_LIBS= \
  $(LOCAL_PATH_UTILS)/base_util/libloc_base_util.a

CFLAGS+= ${INC_DIRS} -MMD -O2 -Wall -Werror -g
CFLAGS_IGNORE= -Wno-format -Wno-unused-but-set-variable -Wno-unused-variable
HEADERS=$(wildcard *.h)

%.o: %.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) ${COPTS} $<
	@echo "  CXX " $<
%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $(CFLAGS_IGNORE) ${COPTS} $<
	@echo "  CC " $<

LIB_OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard infra/*.cpp))
LIB_OBJS+=$(patsubst %.c,%.o,$(wildcard *.c))

libwifidriver_util.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(LIB_OBJS:%.o=%.d)


