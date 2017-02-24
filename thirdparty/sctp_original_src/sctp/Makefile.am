EXTRA_DIST             = Makefile.nmake

lib_LTLIBRARIES        = libsctplib.la
libsctplib_la_SOURCES  = adaptation.c adaptation.h \
                         auxiliary.c auxiliary.h  \
                         bundling.h \
                         chunkHandler.c chunkHandler.h \
                         distribution.c distribution.h \
                         errorhandler.c errorhandler.h \
                         flowcontrol.c flowcontrol.h \
                         globals.c globals.h \
                         md5.c md5.h \
                         messages.h \
                         pathmanagement.c pathmanagement.h \
                         rbundling.c \
                         recvctrl.c recvctrl.h \
                         reltransfer.c reltransfer.h \
                         sbundling.c  \
                         streamengine.c streamengine.h \
                         timer_list.c timer_list.h \
                         SCTP-control.c SCTP-control.h

include_HEADERS        = sctp.h
libsctplib_la_LIBADD   = @glib_LIBS@
libsctplib_la_LDFLAGS  = \
   -version-info $(SCTPLIB_CURRENT):$(SCTPLIB_REVISION):$(SCTPLIB_AGE)
