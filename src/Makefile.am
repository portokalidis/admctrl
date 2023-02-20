## Process this file with automake to produce Makefile.in

RESOURCE_CONTROL_SRCS = resource_ctrl.c resource_ctrl.h \
	arith_parser.c arith_parser.h \
	string_buf.c string_buf.h \
	stack.c stack.h 

RESOURCE_CONTROL_OBJS = resource_ctrl.o arith_parser.o string_buf.o stack.o


## Things to be build
sbin_PROGRAMS = authd @AUTHDB_MANAGE@
if AUTHDFE
sbin_PROGRAMS += authdfe
endif
include_HEADERS = admctrlcl.h admctrl_req.h adm_ctrl.h admctrl_config.h \
	bytestream.h admctrl_errno.h admctrl_argtypes.h
EXTRA_PROGRAMS = authdfe authdb_manage
EXTRA_DIST = Doxyfile
lib_LIBRARIES=
noinst_LIBRARIES=

if CLIENTLIB
lib_LIBRARIES += libadmctrlcl.a
else
noinst_LIBRARIES += libadmctrlcl.a
endif

if RESCTRL
include_HEADERS += resource_ctrl.h
noinst_LIBRARIES += libresourcectrl.a
endif


### Sources

authd_SOURCES = authd.c admctrl_errno.h admctrl_argtypes.h debug.h bytestream.h \
  adm_ctrl.c adm_ctrl.h \
  admctrl_comm.c admctrl_comm.h \
  shm.c shm.h \
	shm_sync.c shm_sync.h
authd_LDFLAGS = @keynote_ldflags@
authd_LDADD = @keynote_libs@
if RESCTRL
authd_LDFLAGS += @db_ldflags@ @snprintfv_ldflags@
authd_LDADD +=  libresourcectrl.a @db_libs@ @snprintfv_libs@ 
authd_DEPENDENCIES = libresourcectrl.a
endif
if EXT_KEYNOTE_H
BUILT_SOURCES = keynote.h
CLEANFILES = keynote.h
keynote.h: Makefile
	ln -s -f @keynote_h@/keynote.h
endif


libadmctrlcl_a_SOURCES = admctrlcl.c admctrlcl.h \
  admctrl_req.c admctrl_req.h \
	iolib.c iolib.h \
  shm.c shm.h \
  shm_sync.c shm_sync.h
if RESCTRL
libadmctrlcl_a_LIBADD = $(RESOURCE_CONTROL_OBJS)
libadmctrlcl_a_DEPENDENCIES = $(RESOURCE_CONTROL_OBJS)
endif


libresourcectrl_a_SOURCES = $(RESOURCE_CONTROL_SRCS)


authdfe_SOURCES = authdfe.c mt_server.c mt_server.h admctrlcl.h \
	filei.c filei.h \
  admctrl_config.h debug.h iolib.h
authdfe_CPPFLAGS = @pthread_cppflags@
authdfe_LDFLAGS = @pthread_ldflags@ @openssl_ldflags@
authdfe_LDADD = libadmctrlcl.a @pthread_libs@ @openssl_libs@
authdfe_DEPENDENCIES = libadmctrlcl.a


authdb_manage_SOURCES = authdb_manage.c
authdb_manage_LDFLAGS = @db_ldflags@ @snprintfv_ldflags@
authdb_manage_LDADD = libresourcectrl.a @db_libs@ @snprintfv_libs@
authdb_manage_DEPENDENCIES = libresourcectrl.a


## Documentation

docs:
	doxygen
