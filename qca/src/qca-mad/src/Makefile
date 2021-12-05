TOP_SRCDIR = ..

include $(TOP_SRCDIR)/Makefile.defs

LIBS += -lieee1905 -lpthread -lhyficommon -ljansson -lnl-3 -lnl-genl-3 -lqca_nl80211_wrapper

TARGET_OBJECTS = mesh_app.$(OBJEXT)

INSTALLHEADERS = mesh_app.h
MESH_APP_LIBS = -lmeshEvent \
		-lmeshIeee1905 \
		-ldataelements

LIBS += $(MESH_APP_LIBS)

all: mesh_app$(EXEEXT) install

mesh_app$(EXEEXT): $(TARGET_OBJECTS) $(MESH_APP_LIBS)
	$(LINK) -o $@ $(TARGET_OBJECTS) -Xlinker --start-group $(LIBS) -Xlinker --end-group

.c.o:
	$(COMPILE) -c $<

install:
	@cp mesh_app$(EXEEXT) $(INSTALL_ROOT)/sbin
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(MAINCLUDE)/. ; done

clean:
	@rm -f *.o *~ mesh_app$(EXEEXT)


.PHONY: all clean install

