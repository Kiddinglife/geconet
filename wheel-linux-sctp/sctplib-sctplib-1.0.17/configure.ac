# ###########################################################################
# sctplib package configuration
# $Id$
# ###########################################################################

AC_INIT([sctplib], [1.0.17], [dreib@iem.uni-due.de])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AC_PREFIX_DEFAULT(/usr/local)
if test "x$prefix" = "xNONE"; then
  prefix=$ac_default_prefix
  ac_configure_args="$ac_configure_args --prefix $prefix"
fi
AM_CONFIG_HEADER(config.h)


# ###### Checks for programs ################################################
AC_PROG_CC
AC_PROG_LIBTOOL

# ###### Compiler checks ####################################################
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_STRUCT_TM

# ###### Check for Headers ##################################################
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/time.h)
AC_HEADER_TIME

# ###### Checks for library functions #######################################
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset select socket strerror strtol strtoul])


# ###### colorgcc ###########################################################
AC_CHECK_PROG([COLORGCC], [colorgcc], [yes], [no])
if test "$COLORGCC" == "yes"
then
   AC_MSG_NOTICE([Compiling using colorgcc])
   CC=colorgcc
   CXX=colorgcc
fi


# ###### Options ############################################################
AC_ARG_ENABLE([sctp-over-udp],
[  --enable-sctp-over-udp            enable SCTP over UDP mode ],
AC_DEFINE(SCTP_OVER_UDP, 1, "Define to 1 if you want SCTP over UDP"), )

if test "$enable_sctp_over_udp" = "yes" ; then
   AC_MSG_CHECKING([port number for SCTP over UDP])
   AC_ARG_WITH(sctp_over_udp_port,AC_HELP_STRING(
      [--with-sctp-over-udp-port=FLAGS],
      [SCTP over UDO port (default: 9899).]),
      sctp_over_udp_port="$withval", sctp_over_udp_port="9899")
   if test "$sctp_over_udp_port" -lt 1 ; then
      AC_ERROR([SCTP over UDP port too small!])
   elif test "$sctp_over_udp_port" -gt 65535 ; then
      AC_ERROR([SCTP over UDP port too large!])
   fi
   AC_MSG_RESULT($sctp_over_udp_port)
   AC_DEFINE_UNQUOTED(SCTP_OVER_UDP_UDPPORT, $sctp_over_udp_port, [UDP port for SCTP over UDP tunneling])
fi

AC_ARG_ENABLE([maintainer-mode],
[  --enable-maintainer-mode            enable maintainer mode ]
[default=yes]],enable_maintainer_mode=$enableval,enable_maintainer_mode=yes)

AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          turn off IPv6 support ])


# ###### IPv6 checks ########################################################
AC_MSG_CHECKING(whether this OS does have IPv6 stack)
if test "${enable_ipv6}" = "no"; then
   AC_MSG_RESULT(disabled)
else
   # ----------
   # INRIA IPv6
   # ----------
   if grep IPV6_INRIA_VERSION /usr/include/netinet/in.h >/dev/null 2>&1; then
      cv_ipv6=yes
      AC_DEFINE(HAVE_IPV6, 1, "Define to 1 if IPv6 is supported.")
      AC_DEFINE(INRIA_IPV6, 1, "Define to 1 if it is a INRIA IPv6 stack.")
      LIB_IPV6=""
      AC_MSG_RESULT(INRIA IPv6)
   fi

   # ---------
   # KAME IPv6
   # ---------
   if grep WIDE /usr/include/netinet6/in6.h >/dev/null 2>&1; then
      cv_ipv6=yes
      AC_DEFINE(HAVE_IPV6, 1, "Define to 1 if IPv6 is supported.")
      AC_DEFINE(KAME, 1, "Define to 1 if the KAME implementation is used.")
      if test -d /usr/local/v6/lib -a -f /usr/local/v6/lib/libinet6.a; then
         LIB_IPV6="-L/usr/local/v6/lib -linet6"
      fi
      AC_MSG_RESULT(KAME)
   fi

   # ---------
   # NRL check
   # ---------
   if grep NRL /usr/include/netinet6/in6.h >/dev/null 2>&1; then
      cv_ipv6=yes
      AC_DEFINE(HAVE_IPV6, 1, "Define to 1 if IPv6 is supported.")
      AC_DEFINE(NRL, 1, "Define to 1 if NRL is used.")
      if test x"$opsys" = x"bsdi";then
         AC_DEFINE(BSDI_NRL, 1, "Define to 1 if BSDI NRL is used.")
         AC_MSG_RESULT(BSDI_NRL)
      else
          AC_MSG_RESULT(NRL)
      fi
   fi

   # ----------
   # Linux IPv6
   # ----------
   AC_EGREP_CPP(yes, [#
#include <linux/version.h>
/* 2.1.128 or later */
#if LINUX_VERSION_CODE >= 0x020180
yes
#endif],
   [cv_ipv6=yes; cv_linux_ipv6=yes; AC_MSG_RESULT(Linux IPv6)])
   if test "$cv_linux_ipv6" = "yes"; then
      AC_DEFINE(HAVE_IPV6, 1, "Define to 1 if IPv6 is supported.")
      AC_MSG_CHECKING(for GNU libc 2.1)
      AC_EGREP_CPP(yes, [
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
      yes
#endif], [glibc=yes; AC_MSG_RESULT(yes)], AC_MSG_RESULT(no))
      AC_DEFINE(LINUX_IPV6, 1, "Define to 1 if the Linux IPv6 implementation is used.")
      if test "$glibc" != "yes"; then
         INCLUDES="-I/usr/inet6/include"
         if test x`ls /usr/inet6/lib/libinet6.a 2>/dev/null` != x;then
            LIB_IPV6="-L/usr/inet6/lib -linet6"
         fi
      fi
   fi
fi

LIBS="$LIB_IPV6 $LIBS"
AC_SUBST(LIB_IPV6)


# ###### Check for sin6_scope_id of sockaddr_in6 ############################
if test "$cv_ipv6" = yes; then
   AC_MSG_CHECKING(whether struct sockaddr_in6 has a sin6_scope_id field)
   AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in6 ac_i;int ac_j = sizeof(ac_i.sin6_scope_id);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN6_SCOPE_ID, 1, "Define to 1 if sin6_scope_id is supported.")],
 AC_MSG_RESULT(no))
fi


# ###### Check for IPV6_PKTINFO #############################################
AC_MSG_CHECKING(for IPV6_PKTINFO)
AC_TRY_COMPILE([#include <arpa/inet.h>
#include <netinet/in.h>], [
    int level = IPV6_PKTINFO;
], [
    # Yes, we have it...
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_IPV6_PKTINFO], [], [IPV6_PKTINFO has been found!])
], [
    AC_MSG_RESULT(no)
])


# ###### Check for IPV6_RECVPKTINFO #########################################
AC_MSG_CHECKING(for IPV6_RECVPKTINFO)
AC_TRY_COMPILE([#include <arpa/inet.h>
#include <netinet/in.h>], [
    int level = IPV6_RECVPKTINFO;
], [
    # Yes, we have it...
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_IPV6_RECVPKTINFO], [], [IPV6_RECVPKTINFO has been found!])
], [
    AC_MSG_RESULT(no)
])


# ###### Check for glib #####################################################
AM_PATH_GLIB_2_0(2.0.0, [ glib_is_okay=yes ], [ glib_is_okay=no ])
if test "x$glib_is_okay" = "xno"; then
   AC_MSG_ERROR(GLib distribution not found.)
fi

CFLAGS="$CFLAGS $GLIB_CFLAGS"
CPPFLAGS="$CPPFLAGS $GLIB_CFLAGS"
glib_LIBS="$GLIB_LIBS"
AC_SUBST(glib_LIBS)


# ###### Operating system checks ############################################
case $host_os in
bsdi*)
    CFLAGS="$CFLAGS -DBSDI"
    thread_LIBS="-lpthread"
    CFLAGS="$CFLAGS `glib-config --cflags`"
    LDFLAGS="$LDFLAGS `glib-config --libs`"
    ;;
freebsd*)
    CFLAGS="$CFLAGS -DFreeBSD -D_PTHREADS -pthread -I/usr/local/include"
    CXXFLAGS="$CXXFLAGS -DFreeBSD -D_PTHREADS -pthread -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/v6/lib"
    thread_LIBS=""
    ;;
hpux*)
    CFLAGS="$CFLAGS -DSNAKE"
    test -z "$GCC" && TRY_CFLAGS="$TRY_CFLAGS -Wp,-H600000"
    thread_LIBS="-lpthread"
   ;;
linux*)
    CFLAGS="$CFLAGS -DLINUX"
    CXXFLAGS="$CXXFLAGS -DLINUX"
    LDFLAGS="$LDFLAGS"
    thread_LIBS="-lpthread"
    ;;
openbsd*)
    LIBS="$LIBS -lcompat"
    thread_LIBS="-lpthread"
    ;;
solaris*)
    CFLAGS="$CFLAGS -D_XPG4_2 -D__EXTENSIONS__ -DSOLARIS -D__sun -DSUN -DSUNOS_5"
    CXXFLAGS="$CXXFLAGS -D_XPG4_2 -D__EXTENSIONS__ -DSOLARIS -D__sun -DSUN -DSUNOS_5"
    thread_LIBS="-lpthread"
    LDFLAGS="$LDFLAGS -lsocket -lnsl -lrt -lresolv"
    ;;
sunos4*)
    CFLAGS="$CFLAGS -DSUN -DSUN4"
    thread_LIBS="-lpthread"
    ;;
darwin7*)
    CFLAGS="$CFLAGS -DDARWIN"
    CXXFLAGS="$CXXFLAGS -DDARWIN"
    thread_LIBS="-lpthread"
    ;;
darwin8*)
    CFLAGS="$CFLAGS -DDARWIN -DUSE_SELECT"
    CXXFLAGS="$CXXFLAGS -DDARWIN"
    thread_LIBS="-lpthread"
    ;;
esac
AC_SUBST(thread_LIBS)


# ###### Maintainer mode ####################################################
if test "$enable_maintainer_mode" = "yes"; then
   CFLAGS="$CFLAGS -Wall -Wunreachable-code -g3 -O0 -D_REENTRANT -D_THREAD_SAFE"
   CXXFLAGS="$CXXFLAGS -Wall -Wunreachable-code -g3 -O0 -D_REENTRANT -D_THREAD_SAFE"
else
   CFLAGS="$CFLAGS -Wall -Wunreachable-code -O3 -g0 -D_REENTRANT -D_THREAD_SAFE"
   CXXFLAGS="$CXXFLAGS -Wall -Wunreachable-code -O3 -g0 -D_REENTRANT -D_THREAD_SAFE"
fi


# ###### Version information ################################################
SCTPLIB_CURRENT=1
SCTPLIB_REVISION=8
SCTPLIB_AGE=0

AC_SUBST(SCTPLIB_CURRENT)
AC_SUBST(SCTPLIB_REVISION)
AC_SUBST(SCTPLIB_AGE)


# ###### Makefiles ##########################################################
AC_OUTPUT(Makefile sctplib/Makefile sctplib/docs/Makefile sctplib/docs/en/Makefile sctplib/docs/sctplib/Makefile sctplib/manual/Makefile sctplib/programs/Makefile sctplib/sctp/Makefile )


# ###### Configuration results ##############################################
echo ""
echo "The sctplib package has been configured with the following options:"
echo ""
echo "   Build with Maintainer Mode : $enable_maintainer_mode"
echo "   Build with SCTP over UDP   : $enable_sctp_over_udp"
echo ""
echo "   glib_LIBS                  : $glib_LIBS"
echo ""
echo "   CFLAGS                     : $CFLAGS"
echo "   CXXFLAGS                   : $CXXFLAGS"
echo "   LDFLAGS                    : $LDFLAGS"
