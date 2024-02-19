ACLOCAL_AMFLAGS = -I m4

root_libdir = "/lib"

AM_CFLAGS = -Wall \
        -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs

subsystem_ramdump_SOURCES = subsystem_ramdump.c

if USE_GLIB
subsystem_ramdump_CFLAGS  = $(AM_CFLAGS) -DUSE_GLIB @GLIB_CFLAGS@
subsystem_ramdump_LDFLAGS = -lpthread -lrt @GLIB_LIBS@
else
subsystem_ramdump_LDFLAGS = -lpthread -lrt
endif

bin_PROGRAMS = subsystem_ramdump

if USE_SYSTEMD
subsystem_ramdump_systemddir    = $(root_libdir)/systemd/system
subsystem_ramdump_systemd_DATA  = subsystem-ramdump.service
endif
