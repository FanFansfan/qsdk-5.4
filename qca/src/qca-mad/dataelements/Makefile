TOP_SRCDIR = ../
include $(TOP_SRCDIR)/Makefile.defs

INSTALLHEADERS = dataElements.h
TARGET_LIB = libdataelements.a
TARGET_OBJECTS = dataElements.$(OBJEXT) dataElementsUtil.$(OBJEXT) dataElementsJson.$(OBJEXT) dataElementsHyd.$(OBJEXT) dataElementsWlan.$(OBJEXT)

all: $(TARGET_LIB) de_nb_client install

CFLAGS += -Wall -Werror

de_nb_client: de_nb_client.c
	${CC} -o de_nb_client ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} de_nb_client.c  ${TARGET_LDFLAGS}

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(MALIB_STATIC)/.
	@cp de_nb_client $(INSTALL_ROOT)/sbin
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(MAINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~

.PHONY: all clean

