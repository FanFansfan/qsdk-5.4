CFLAGS += -Wall -Werror

repacdcli: repacdcli.c
	${CC} -o repacdcli ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} repacdcli.c ${TARGET_LDFLAGS}

clean: repacdcli_clean
	rm -rf *.o
