#	$OpenBSD: Makefile,v 1.16 2019/05/11 17:46:02 rob Exp $

PROG=		snmpd
MAN=		snmpd.8 snmpd.conf.5
SRCS=		parse.y log.c control.c snmpe.c \
		    mps.c trap.c mib.c smi.c kroute.c snmpd.c timer.c \
		    pf.c proc.c usm.c agentx.c traphandler.c util.c

LDADD=		-levent -lutil -lkvm -lcrypto
DPADD=		${LIBEVENT} ${LIBUTIL}
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
YFLAGS=

CFLAGS+=	-O0 -ggdb3  # or: make COPTS='-O0 -ggdb3'
CFLAGS+=	-fstack-protector-strong
CPPFLAGS+=	-D_FORTIFY_SOURCE=2
CPPLLAGS+=	-DDEBUG=2
CPPFLAGS+=	-DYYDEBUG=1

.include <bsd.prog.mk>
