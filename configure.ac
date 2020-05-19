AC_INIT([nfc-iclass],[0.1.1],[adam@algroup.co.uk])

AC_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])

# SVN Revision
define([svn_revision], esyscmd([sh -c "svnversion -n"]))
SVN_REVISION=svn_revision
AC_DEFINE_UNQUOTED([SVN_REVISION], ["$SVN_REVISION"], [SVN revision])

# Automake
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_LANG([C])
AC_PROG_CC
AC_PROG_MAKE_SET

AC_PATH_PROG(PKG_CONFIG, pkg-config, [AC_MSG_ERROR([pkg-config not found.])])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([stdio.h stdlib.h stdint.h stddef.h stdbool.h])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup], [AC_DEFINE([_XOPEN_SOURCE], [600], [Enable POSIX extensions if present])])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_HEADERS([syslog.h])
AC_C_CONST
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_HEADER_SYS_WAIT

# Checks for types
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT32_T

# --enable-debug support (default:no)
AC_ARG_ENABLE([debug],AS_HELP_STRING([--enable-debug],[Debug flags]),[enable_debug=$enableval],[enable_debug="no"])
 
AC_MSG_CHECKING(for debug flag)
AC_MSG_RESULT($enable_debug)
 
if test x"$enable_debug" = "xyes"
then
  CFLAGS="$CFLAGS -O0 -g3 -Wall -DDEBUG -pedantic"
fi
AC_SUBST([DEBUG_CFLAGS])

# Checks for pkg-config modules.
LIBNFC_REQUIRED_VERSION=1.7.0
PKG_CHECK_MODULES([libnfc], [libnfc >= $LIBNFC_REQUIRED_VERSION], [], [AC_MSG_ERROR([libnfc >= $LIBNFC_REQUIRED_VERSION is mandatory.])])

AC_SUBST(libnfc_LIBS)
AC_SUBST(libnfc_CFLAGS)

# Set C standard to C99
CFLAGS="$CFLAGS -std=c99"

AC_CONFIG_FILES([
		Makefile
		src/Makefile
		])

AC_OUTPUT

