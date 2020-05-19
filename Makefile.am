AM_CFLAGS = $(LIBNFC_CFLAGS)

SUBDIRS = src

style:
	find . -path ./loclass -prune -o -name "*.[ch]" -exec perl -pi -e 's/[ \t]+$$//' {} \;
	find . -path ./loclass -prune -o -name "*.[ch]" -exec astyle --formatted --mode=c --suffix=none \
	    --indent=spaces=2 --indent-switches --indent-preprocessor \
	    --keep-one-line-blocks --max-instatement-indent=60 \
	    --brackets=linux --pad-oper --unpad-paren --pad-header \
	    --align-pointer=name {} \;
