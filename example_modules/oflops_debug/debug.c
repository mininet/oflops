#include <stdio.h>
#include <stdlib.h>

#include <test_module.h>

char * name()
{
	return "Debug_module";
}

int start(struct oflops_context * ctx)
{
	end_test(ctx);
}
