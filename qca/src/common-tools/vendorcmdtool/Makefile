CC ?= gcc

OBJS = ven_cmd_tool.o nl_cmd_wrapper.o
CFLAGS += -Wall -Werror
all: cfg80211tool.1

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $< $(LDFLAGS)

ifeq ($(CONFIG_SUPPORT_LIBROXML),1)
cfg80211tool.1: $(OBJS)
	$(CC) $(LDFLAGS) -lroxml  -o $@ $(OBJS)
else
cfg80211tool.1: $(OBJS)
	$(CC) $(LDFLAGS)  -o $@ $(OBJS)
endif

clean:
	rm -rf *.o
