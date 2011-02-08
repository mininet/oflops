#ifndef USAGE_H
#define USAGE_H

#include <libconfig.h>

#include "oflops.h"

#define SNMP_DELIMITER ":"

int parse_args(oflops_context * ctx, int argc, char * argv[]);
void usage(char * s1, char *s2);

#endif
