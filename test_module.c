#include "test_module.h"

char * oflops_channel_names[] = 
{
	"control",
	"send",
	"recv",
	"bad_channel!",
};

int end_test(struct oflops_context *ctx)
{
	ctx->should_end = 1;
	return 0;
}
