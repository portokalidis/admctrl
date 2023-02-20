## Process this file with automake to produce Makefile.in

AM_CFLAGS = -I$(top_builddir)/src

EXTRA_DIST = pub priv conds server.key client.key server.pem README

noinst_PROGRAMS = client authenticate enc_nonce

client_SOURCES = client.c $(top_builddir)/src/admctrl_argtypes.h \
	$(top_builddir)/src/admctrl_config.h $(top_builddir)/src/admctrlcl.h \
	$(top_builddir)/src/admctrl_req.h
client_CFLAGS = -I$(top_builddir)/src
client_LDFLAGS = @keynote_ldflags@ @openssl_ldflags@
client_LDADD = $(top_builddir)/src/libadmctrlcl.a @keynote_libs@ @openssl_libs@
client_DEPENDENCIES = $(top_builddir)/src/libadmctrlcl.a

authenticate_SOURCES = authenticate.c $(top_builddir)/src/bytestream.h \
	$(top_builddir)/src/admctrl_config.h
authenticate_CFLAGS = -I$(top_builddir)/src
authenticate_LDFLAGS = @keynote_ldflags@
authenticate_LDADD = @keynote_libs@

enc_nonce_SOURCES = enc_nonce.c ../src/adm_ctrl.h
enc_nonce_CPPFLAGS = -I../src
enc_nonce_LDFLAGS = @keynote_ldflags@
enc_nonce_LDADD =  @keynote_libs@

if AUTHDFE
client_LDFLAGS += @openssl_ldflags@
client_LDADD += @openssl_libs@
endif

if RESCTRL
client_LDFLAGS += @db_ldflags@ @snprintfv_ldflags@
client_LDADD += @db_libs@ @snprintfv_libs@

noinst_PROGRAMS += calc_test snprintfv_test

calc_test_SOURCES = calc_test.c
calc_test_LDADD = $(top_builddir)/src/libresourcectrl.a -lm
calc_test_DEPENDENCIES = $(top_builddir)/src/libresourcectrl.a

snprintfv_test_SOURCES = snprintfv_test.c
snprintfv_test_LDFLAGS = @snprintfv_ldflags@
snprintfv_test_LDADD = @snprintfv_libs@
endif
