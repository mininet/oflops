#ifndef MODULE_RUN_H
#define MODULE_RUN_H

#include "oflops.h"
#include "test_module.h"

int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr);
int run_test_module(oflops_context *ctx, test_module * mod);


#endif
