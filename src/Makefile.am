AM_CFLAGS  = @libnfc_CFLAGS@
AM_CPPFLAGS = $(all_includes) -I @srcdir@/../loclass/loclass

bin_PROGRAMS = nfc-iclass
VPATH = @srcdir@:@srcdir@/../loclass/loclass
nfc_iclass_SOURCES = nfc-iclass.c iclass.c iclass.h nfc-utils.c nfc-utils.h \
                     ikeys.c cipher.c optimized_cipher.c cipherutils.c elite_crack.c des.c fileutils.c
nfc_iclass_LDADD = @libnfc_LIBS@

dist_man_MANS = nfc-iclass.1
