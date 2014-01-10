
ACLOCAL_AMFLAGS = -I m4

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example.conf m4/gnulib-cache.m4 linux-usb-yacminer \
		  ADL_SDK/readme.txt api-example.php miner.php	\
		  API.class API.java api-example.c windows-build.txt \
		  bitstreams/* API-README FPGA-README SCRYPT-README \
		  bitforce-firmware-flash.c hexdump.c ASIC-README \
		  01-yacminer.rules GPU-README

SUBDIRS		= lib compat ccan

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= yacminer

bin_SCRIPTS	= $(top_srcdir)/*.cl

yacminer_LDFLAGS	= $(PTHREAD_FLAGS)
yacminer_LDADD	= $(DLOPEN_FLAGS) @LIBCURL_LIBS@ @JANSSON_LIBS@ @PTHREAD_LIBS@ \
		  @OPENCL_LIBS@ @NCURSES_LIBS@ @PDCURSES_LIBS@ @WS2_LIBS@ \
		  @LIBUSB_LIBS@ @MM_LIBS@ \
		  @MATH_LIBS@ lib/libgnu.a ccan/libccan.a

if HAVE_WINDOWS
yacminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib @OPENCL_FLAGS@ @LIBUSB_CFLAGS@
else
yacminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib @OPENCL_FLAGS@ @LIBUSB_CFLAGS@ @LIBCURL_CFLAGS@
endif

yacminer_CPPFLAGS += $(ADL_CPPFLAGS)

# common sources
yacminer_SOURCES := yacminer.c

yacminer_SOURCES	+= elist.h miner.h compat.h bench_block.h	\
		   util.c util.h uthash.h logging.h		\
		   sha2.c sha2.h api.c usbutils.h

yacminer_SOURCES	+= logging.c

# GPU sources, TODO: make them selectable
# the GPU portion extracted from original main.c
yacminer_SOURCES += driver-opencl.h driver-opencl.c

# the original GPU related sources, unchanged
yacminer_SOURCES += ocl.c ocl.h findnonce.c findnonce.h
yacminer_SOURCES += adl.c adl.h adl_functions.h
yacminer_SOURCES += *.cl

if HAS_SCRYPT
yacminer_SOURCES += scrypt.c scrypt.h
endif

if NEED_FPGAUTILS
yacminer_SOURCES += fpgautils.c fpgautils.h
endif

if NEED_USBUTILS_C
yacminer_SOURCES += usbutils.c
endif

if HAS_BFLSC
yacminer_SOURCES += driver-bflsc.c
endif

if HAS_BITFORCE
yacminer_SOURCES += driver-bitforce.c
endif

if HAS_ICARUS
yacminer_SOURCES += driver-icarus.c
endif

if HAS_AVALON
yacminer_SOURCES += driver-avalon.c driver-avalon.h
endif

if HAS_MODMINER
yacminer_SOURCES += driver-modminer.c
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = $(top_srcdir)/bitstreams/*
endif

if HAS_ZTEX
yacminer_SOURCES += driver-ztex.c libztex.c libztex.h
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = $(top_srcdir)/bitstreams/*
endif
