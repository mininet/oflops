#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "oflops.h"
#include "usage.h"
#include "control.h"
#include "context.h"
#include "module_run.h"

int main(int argc, char * argv[])
{
	int i;
	oflops_ctx * ctx = oflops_default_context();
	parse_args(ctx, argc, argv);

	setup_control_channel(ctx);

	for(i=0;i<ctx->n_tests;i++)
	{
		reset_context(ctx);
		run_test_module(ctx, ctx->tests[i]);
	}
	return 0;
}
