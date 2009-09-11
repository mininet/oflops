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
	oflops_context * ctx = oflops_default_context();
	parse_args(ctx, argc, argv);

	if(ctx->n_tests == 0 )
		usage("Need to specify at least one module to run\n",NULL);

	setup_control_channel(ctx);

	fprintf(stderr, "Running %d Test%s\n", ctx->n_tests, ctx->n_tests>1?"s":"");

	for(i=0;i<ctx->n_tests;i++)
	{
		fprintf(stderr, "-----------------------------------------------\n");
		fprintf(stderr, "------------ TEST %s ----------\n", (*(ctx->tests[i]->name))());
		fprintf(stderr, "-----------------------------------------------\n");
		reset_context(ctx);
		ctx->curr_test = ctx->tests[i];
		run_test_module(ctx, ctx->tests[i]);
	}
	fprintf(stderr, "-----------------------------------------------\n");
	fprintf(stderr, "---------------    Finished   -----------------\n");
	fprintf(stderr, "-----------------------------------------------\n");
	return 0;
}
