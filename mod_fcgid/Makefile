#
#  Makefile for Apache2
#

builddir     = .

top_dir      = /usr/local/apache2

top_srcdir   = ${top_dir}
top_builddir = ${top_dir}
VPATH = arch/unix/

include ${top_builddir}/build/special.mk

APXS      = apxs
APACHECTL = apachectl
EXTRA_CFLAGS = -I$(builddir)

all: local-shared-build

clean:
	rm -f *.o *.lo *.slo *.la arch/unix/*.o arch/unix/*.lo arch/unix/*.slo arch/unix/*.la .libs/* arch/unix/.libs/*

