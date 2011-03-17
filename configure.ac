#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([oflops], [0.01], [rob.sherwood@stanford.edu])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])


AC_DEFUN([OPENFLOWSRC_DEFAULT],[`pwd`/../openflow])


dnl Give option to change location of openflow directory
AC_ARG_WITH(openflow-src-dir,
        [  --with-openflow-src-dir=PATH    Specify path to OpenFlow Source Directory (default: OPENFLOWSRC_DEFAULT) ],
	[ 
		case "$withval" in
			# Relative paths
			./*|../*)       withval="`pwd`/$withval"
		esac
		if test "x$withval" = "x" ; then
			AC_MSG_ERROR([--with-openflow-src-dir needs an argument],[1])
		fi
		OPENFLOWSRC=$withval
	 ],
	[OPENFLOWSRC=OPENFLOWSRC_DEFAULT]
)

dnl Make sure we have the openflow source somewhere
AC_CHECK_FILE(
	[$OPENFLOWSRC/include/openflow/openflow.h],
	[],
	[AC_MSG_ERROR(
		[Could not find openflow source at $OPENFLOWSRC -- please install]
		,[1])
	])

dnl Define $(openflowsrc) in makefile
AC_SUBST([openflowsrc],$OPENFLOWSRC)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_LIBTOOL
## Lame... -Im4 does not do what I think on all versions of autoconf
AC_DEFUN([AC_PROG_DOXYGEN],[
        AC_PATH_PROG([DOXYGEN],[doxygen])
        if test -z "$DOXYGEN" ; then
                AC_MSG_WARN([cannot find doxygen. Will not build source documentation])
        fi
        AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
])
AC_PROG_DOXYGEN

# Checks for header files.
AC_CHECK_HEADERS([config.h net/bpf.h])

# Check for the SNMP headers
AC_CHECK_HEADERS([net-snmp/net-snmp-config.h], [],
	[AC_MSG_ERROR(
		[Could not find SNMP headers from net-snmp package -- please install]
		,[1])
	])
AC_CHECK_HEADERS([net-snmp/net-snmp-includes.h], [],
	[AC_MSG_ERROR(
		[Could not find SNMP headers from net-snmp package -- please install]
		,[1])
	],
	[
#ifdef HAVE_NET_SNMP_NET_SNMP_CONFIG_H
# include <net-snmp/net-snmp-config.h>
#endif
	])

# Check whether we have ofp_flow_expired or ofp_flow_removed
AC_EGREP_HEADER(ofp_flow_expired, [$OPENFLOWSRC/include/openflow/openflow.h],
		[AC_DEFINE([HAVE_OFP_FLOW_EXPIRED], [],
			   [Have ofp_flow_expired structure])
		])
AC_EGREP_HEADER(ofp_flow_removed, [$OPENFLOWSRC/include/openflow/openflow.h],
		[AC_DEFINE([HAVE_OFP_FLOW_REMOVED], [],
			   [Have ofp_flow_removed structure])
		])

# Check whether we have OFPT_FLOW_REMOVED/OFPT_FLOW_EXPIRED
AC_EGREP_HEADER(OFPT_FLOW_EXPIRED, [$OPENFLOWSRC/include/openflow/openflow.h],
	[],
	[AC_EGREP_HEADER(OFPT_FLOW_REMOVED, [$OPENFLOWSRC/include/openflow/openflow.h],
			[AC_DEFINE([OFPT_FLOW_EXPIRED], [OFPT_FLOW_REMOVED],
				   [OFPT_FLOW_REMOVED substitute])
			],
			[AC_MSG_ERROR(
			        [Could not find appropriate OFPT_FLOW_EXPIRED substitute in openflow.h]
				,[1])
			])
	])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strerror])


AC_CONFIG_FILES([Makefile \
		doc/doxygen.conf\
		cbench/Makefile \
		example_modules/Makefile \
		example_modules/oflops_debug/Makefile \
                example_modules/openflow_action_install/Makefile \
                example_modules/openflow_action_measurement/Makefile \
                example_modules/openflow_path_delay/Makefile \
                example_modules/openflow_flow_dump_test/Makefile \
                example_modules/openflow_packet_in/Makefile \
                example_modules/openflow_port_status/Makefile \
                example_modules/snmp_cpu/Makefile


		])

AC_OUTPUT
