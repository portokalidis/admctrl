SUBDIRS = src tests man

sbin_SCRIPTS = authd_setup.sh

EXTRA_DIST = kernel doc TODO RELEASE $(sbin_SCRIPTS)

CLEANFILES = kernel/*.o kernel/*.ko kernel/*.mod.c kernel/.*.cmd \
										 kernel/dummy_authd

module:
	cd kernel && ./compile.sh @KERNEL_VERSION@

docs:
	cd src && make docs

docsclean:
	rm -rf doc/html doc/latex
