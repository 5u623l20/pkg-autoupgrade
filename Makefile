# pkg-autoupgrade: automated pkg upgrade plugin.
# Provides `pkg autoupgrade`: refreshes repos, upgrades packages, creates a
# ZFS boot environment (or /boot/kernel backup on UFS) beforehand, restarts
# whitelisted services, and stamps /var/run/motd with pending-restart /
# pending-reboot notices.

.include <bsd.own.mk>

PREFIX?=	/usr/local
LOCALBASE?=	/usr/local

SHLIB_NAME=	autoupgrade.so
NO_SHLIB_LINKS=	yes

.PATH:		${.CURDIR}/src

SRCS=		pkg-autoupgrade.c \
		config.c \
		upgrade.c \
		services.c \
		be_support.c \
		motd.c \
		audit.c \
		mail.c

WARNS?=		6

CFLAGS+=	-I${.CURDIR}/include
CFLAGS+=	-I${LOCALBASE}/include	# dependency headers (libpkg, libbe)
LDFLAGS+=	-L${LOCALBASE}/lib
LDADD+=		-lpkg -lbe -lprocstat

# Plugins live in ${PREFIX}/lib/pkg/ - pkg(8) discovers them by name.
SHLIBDIR=	${PREFIX}/lib/pkg

MAN=		man/pkg-autoupgrade.8
MANDIR=		${PREFIX}/share/man

PERIODIC_DIR=	${PREFIX}/etc/periodic/daily
RCDIR=		${PREFIX}/etc/rc.d
CONFDIR=	${PREFIX}/etc/pkg

beforeinstall:
	${INSTALL} -d -m 0755 ${DESTDIR}${SHLIBDIR}
	${INSTALL} -d -m 0755 ${DESTDIR}${MANDIR}/man8
	${INSTALL} -d -m 0755 ${DESTDIR}${PERIODIC_DIR}
	${INSTALL} -d -m 0755 ${DESTDIR}${RCDIR}
	${INSTALL} -d -m 0755 ${DESTDIR}${CONFDIR}

afterinstall:
	${INSTALL} -m 0755 ${.CURDIR}/periodic/500.pkg-autoupgrade \
	    ${DESTDIR}${PERIODIC_DIR}/500.pkg-autoupgrade
	${INSTALL} -m 0755 ${.CURDIR}/rc.d/pkg-autoupgrade-motd \
	    ${DESTDIR}${RCDIR}/pkg-autoupgrade-motd
	${INSTALL} -m 0644 ${.CURDIR}/conf/autoupgrade.conf.sample \
	    ${DESTDIR}${CONFDIR}/autoupgrade.conf.sample

CLEANFILES+=	*.pico *.pieo *.so *.so.debug *.so.full
CLEANFILES+=	pkg-autoupgrade.8.gz
CLEANFILES+=	.depend.*

.include <bsd.lib.mk>
