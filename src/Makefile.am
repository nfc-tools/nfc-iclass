AM_CFLAGS  = @libnfc_CFLAGS@
AM_CPPFLAGS = $(all_includes) -I ../loclass/loclass

bin_PROGRAMS = nfc-iclass

nfc_iclass_SOURCES = nfc-iclass.c iclass.c iclass.h nfc-utils.c nfc-utils.h
nfc_iclass_LDADD = ../loclass/loclass/ikeys.o \
                   ../loclass/loclass/cipher.o \
                   ../loclass/loclass/optimized_cipher.o \
                   ../loclass/loclass/cipherutils.o \
                   ../loclass/loclass/elite_crack.o \
                   ../loclass/loclass/des.o \
                   ../loclass/loclass/fileutils.o\
		   @libnfc_LIBS@

dist_man_MANS = nfc-iclass.1
