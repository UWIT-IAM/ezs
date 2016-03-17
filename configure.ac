AC_INIT(ezs, 1.4.2)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(ezs, 1.4.2)
AC_PROG_CC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

# look for openssl install
AC_ARG_WITH(ssl,
    AC_HELP_STRING([--with-ssl=PATH], [openssl install path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval/lib"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     ;;
  esac ])

# see if version string is available
AC_CHECK_LIB(ssl, SSL_version_str,,
 [ CPPFLAGS="$CPPFLAGS -IHAVE_LIBSSL_VERSION"],
)

AC_OUTPUT(Makefile example/Makefile test/Makefile ezs.h)

