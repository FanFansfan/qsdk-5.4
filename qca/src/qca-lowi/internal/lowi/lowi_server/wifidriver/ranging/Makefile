# ---------------------------------------------------------------------------------
# 			Makefile to compile ranging library on INFRA platform
# ---------------------------------------------------------------------------------

ALL= libwifidriver_ranging.a
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
    -I../util/ \
    -I../util/infra/ \
    -I$(LOCAL_PATH_UTILS)

CFLAGS+= ${INC_DIRS} -MMD -O2 -Wall -Werror -g
CFLAGS_IGNORE= -Wno-format -Wno-unused-but-set-variable -Wno-unused-variable

HEADERS=$(wildcard *.h)

%.o: %.cpp
	$(CXX) -c -o $@ ${CXXFLAGS} $(CFLAGS) $(CFLAGS_IGNORE) ${COPTS} $<
	@echo "  CXX " $<
%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $(CFLAGS_IGNORE) ${COPTS} $<
	@echo "  CXX " $<

LIB_OBJS=$(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIB_OBJS+=$(patsubst %.cpp,%.o,$(wildcard infra/*.cpp))
LIB_OBJS+=$(patsubst %.c,%.o,$(wildcard *.c))

libwifidriver_ranging.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(LIB_OBJS:%.o=%.d)


