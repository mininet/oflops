#ifndef MODULE_RUN_H
#define MODULE_RUN_H

#include "oflops.h"
#include "test_module.h"

int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr);
int run_test_module(oflops_context *ctx, int ix_test); //, test_module * mod);
int setup_test_module(oflops_context *ctx, int ix_mod);
int run_traffic_generation(oflops_context *ctx, int ix_mod);

#endif
