#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(admctrl, 0.8.9, digital_bull@users.sourceforge.net)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE

AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LN_S


#
# Optional features
#



# KEYNOTE
AC_ARG_WITH([keynote],
    [AC_HELP_STRING([--with-keynote=DIR],[directory where keynote headers and library are located])],
    keynote_h="$withval" keynote_ldflags="-L$withval"
    )
AC_ARG_WITH([keynote-includes],
    [AC_HELP_STRING([--with-keynote-includes=DIR],[directory where keynote headers are located])],
    keynote_h="$withval"
    )
AC_ARG_WITH([keynote-lib],
    [AC_HELP_STRING([--with-keynote-lib=DIR],[directory where keynote library is located])],
    keynote_ldflags="-L$withval"
    )
AM_CONDITIONAL([EXT_KEYNOTE_H],test -n "$keynote_h")

# KERNEL MODULE
AC_ARG_WITH([kernel-ver],
    [AC_HELP_STRING([--with-kernel-ver=VERSION],[Use linux kernel version VERSION, to compile the kernel module device driver [OPTIONAL]])],
    KERNEL_VERSION="$withval",
    KERNEL_VERSION=`uname -r`
    )

# BERKELEY DB
AC_ARG_WITH([berkeley-db-lib],
    AC_HELP_STRING([--with-berkeley-db-lib=DIR],[directory where berkeley db library is located]),
    db_ldflags="-L$withval",
    db_ldflags=""
    )
AC_ARG_WITH([berkeley-db-includes],
    AC_HELP_STRING([--with-berkeley-db-includes=DIR],[directory where berkeley db headers are located]),
    CPPFLAGS="-I$withval $CPPFLAGS"
    )

# SNPRINTFV
AC_ARG_WITH([snprintfv-lib],
    [AC_HELP_STRING([--with-snprintfv-lib=DIR],[directory where snprintfv library is located])],
		snprintfv_ldflags="-L$withval",
    )
AC_ARG_WITH([snprintfv-includes],
    [AC_HELP_STRING([--with-snprintfv-includes=DIR],[directory where snprintfv headers are located])],
		CPPFLAGS="-I$withval $CPPFLAGS",
    )

# PTHREAD
AC_ARG_WITH([pthread-lib],
    [AC_HELP_STRING([--with-pthread-lib=DIR],[directory where pthread library is located])],
    pthread_ldflags="-L$withval"
    )
AC_ARG_WITH([pthread-includes],
    [AC_HELP_STRING([--with-pthread-includes=DIR],[directory where pthread headers are located])],
    CPPFLAGS="-I$withval $CPPFLAGS"
    )

# OPENSSL
AC_ARG_WITH([openssl-lib],
    [AC_HELP_STRING([--with-openssl-lib=DIR],[directory where openSSL library is located])],
    openssl_ldflags="-L$withval"
    )
AC_ARG_WITH([openssl-includes],
    [AC_HELP_STRING([--with-openssl-includes=DIR],[directory where openSSL headers are located])],
    CPPFLAGS="-I$withval $CPPFLAGS"
    )

# SYSLOG
AC_ARG_ENABLE([syslog],
    [AC_HELP_STRING([--enable-syslog],[enable logging using syslog, default no])],
    usesyslog="$enableval",
    usesyslog="no"
    )
if ( test "x$usesyslog" = "xyes" ); then
  AC_DEFINE([WITH_SYSLOG],[1],[Define this to enable logging using syslog])
fi

# DEBUG
AC_ARG_ENABLE([debug],
    [AC_HELP_STRING([--enable-debug@<:@=0|1|2@:>@],[enable debug messages (0=none,1=normal,2=extensive), default 0])],
    debug="$enableval",
    debug="0")
if ( test $debug -gt 0 ); then
  CPPFLAGS="-Wall $CPPFLAGS"
fi
AC_DEFINE_UNQUOTED([DEBUG],$debug,[Define this to the debugging level(0=none,1=normal,2=extensive)])

# CLIENT LIBRARY
AC_ARG_ENABLE([clientlib],
    [AC_HELP_STRING([--disable-clientlib],[don't install the client library, default yes])],
    clientlib="$enableval",
    clientlib="yes"
    )
AM_CONDITIONAL(CLIENTLIB,test "x$clientlib" = "xyes")

# FRONT-END
AC_ARG_ENABLE([front-end],
    [AC_HELP_STRING([--enable-front-end],[build the front-end, default no])],
		buildfe="$enableval",
    buildfe="no"
    )
AM_CONDITIONAL(AUTHDFE,test "x$buildfe" = "xyes")

# RESOURCE CONTROL
AC_ARG_ENABLE([resource-control],
    [AC_HELP_STRING(--enable-resource-control,[include resource control, default no [EXPERIMENTAL]])],
		buildrc="$enableval",
    buildrc="no"
    )
if ( test "x$buildrc" = "xyes" ); then
  AC_DEFINE([WITH_RESOURCE_CONTROL],[1],[Define to enable resource control])
	AUTHDB_MANAGE="authdb_manage"
fi
AM_CONDITIONAL(RESCTRL,test "x$buildrc" = "xyes")
AM_CONDITIONAL(RESCTRL,test "x$buildrc" = "xyes")



#
# Checks for libraries.
#



# KEYNOTE
AC_CHECK_LIB([m], [asin],
    keynote_libs="-lm",
    [AC_MSG_ERROR([could not find -lm])],
    []
    )
AC_CHECK_LIB([crypto], [RSA_public_decrypt],
    keynote_libs="-lcrypto $keynote_libs",
    [AC_MSG_ERROR([could not find -lcrypto],"1")],
    []
    )
AC_CHECK_LIB([keynote], [kn_decode_key],
    keynote_libs="-lkeynote $keynote_libs",
    [AC_MSG_ERROR([could not find libkeynote try --with-keynote, or --with-keynote-lib options],"1")],
    $keynote_ldflags $keynote_libs
    )

# PTHREAD
if ( test "x$buildfe" = "xyes" ); then
  AC_CHECK_LIB([pthread], [pthread_create],
      pthread_libs="-lpthread" pthread_cppflags="-D_REENTRANT",
      [AC_MSG_ERROR([[could not fine libpthread, try using --with-pthread options]],"1")],
      $pthread_ldflags
      )
fi

# OPENSSL
if ( test "x$buildfe" = "xyes" || test "x$clientlib" = "xyes" ); then
  AC_CHECK_LIB([ssl],[SSL_read],
      hasSSL="yes",
      hasSSL="no",
      $openssl_ldflags
      )
  if ( test "x$hasSSL" = "xyes" ); then
    openssl_libs="-lssl"
    AC_DEFINE([HAVE_LIBSSL],[1],[Define to 1 if you have the ssl library (-lssl)])
  else
    AC_MSG_WARN([[libssl not found, SSL will be disabled for the front-end and client library]])
  fi
fi


if ( test "x$buildrc" = "xyes" ); then
# BERKELEY DB
  AC_CHECK_LIB([db], [db_env_create],
      db_libs="-ldb",
      [AC_MSG_ERROR([[could not find libdb, try using --with-berkeley-db options or disable resource control]],"1")],
      $db_ldflags
      )

# SNPRINTFV
  AC_CHECK_LIB([snprintfv], [printf],
      snprintfv_libs="-lsnprintfv",
      [AC_MSG_ERROR([[could not find libsnprintfv, try using --with-snprintfv options, or disable resource control]],"1")],
      $snprintfv_ldflags
      )
fi



#
# Checks for header files.
#

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h limits.h netdb.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/param.h sys/socket.h sys/time.h unistd.h])

# KEYNOTE
AC_MSG_CHECKING([for keynote.h])
if (! test -f "$keynote_h/keynote.h" ); then
  AC_MSG_ERROR([[couldn't locate keynote.h, use option --with-keynote or --with-keynote-includes]])
fi
AC_MSG_RESULT([yes])


# SYSLOG
if ( test "x$usesyslog" = "xyes" ); then
  AC_CHECK_HEADER([syslog.h],[],
      [AC_MSG_ERROR([[couldn't locate syslog.h, don't use option --enable-syslog]])]
      )
fi

# PTHREAD / OPENSSL
if ( test "x$buildfe" = "xyes" ); then
  AC_CHECK_HEADER([pthread.h],
      [],
      [AC_MSG_ERROR([[couldn't locate header, disable building front-end]])]
      )
  if ( test "x$hasSSL" = "xyes" ); then 
    AC_CHECK_HEADER([openssl/ssl.h],
      [],
      [AC_MSG_ERROR([[couldn't locate header, disable building front-end]])]
      )
  fi
fi

# BERKELEY DB / SNPRINTFV
if ( test "x$buildrc" = "xyes" ); then
  AC_CHECK_HEADERS([float.h db.h snprintfv/compat.h printf.h],
    [],
    [AC_MSG_ERROR([[couldn't locate header, disable resource control]],"1")]
    )
fi



#
# Checks for typedefs, structures, and compiler characteristics.
#

AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_HEADER_TIME
AC_STRUCT_TM



#
# Checks for library functions.
#
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_TYPE_SIGNAL
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday memset select socket strcasecmp strdup strstr strtol strtoul strtoull]) 



#
# Substitutions
#
AC_SUBST([keynote_h])
AC_SUBST([keynote_ldflags])
AC_SUBST([keynote_libs])
AC_SUBST([KERNEL_VERSION])
AC_SUBST([db_ldflags])
AC_SUBST([db_libs])
AC_SUBST([snprintfv_ldflags])
AC_SUBST([snprintfv_libs])
AC_SUBST([pthread_ldflags])
AC_SUBST([pthread_cppflags])
AC_SUBST([pthread_libs])
AC_SUBST([openssl_ldflags])
AC_SUBST([openssl_libs])
AC_SUBST([AUTHDB_MANAGE])
  


AC_CONFIG_FILES([Makefile
                 src/Makefile
								 tests/Makefile
								 man/Makefile])

AC_OUTPUT
