#include <string.h>

#include "context.h"
#include "timer_event.h"
#include "utils.h"

#include <pcap.h>

#include <openflow/openflow.h>


// Create a default context

oflops_context * oflops_default_context(void)
{
	oflops_context * ctx = malloc_and_check(sizeof(oflops_context));
	bzero(ctx, sizeof(*ctx));
	ctx->max_tests = 10 ;
	ctx->tests = malloc_and_check(ctx->max_tests * sizeof(test_module *));

	ctx->listen_port = OFP_TCP_PORT;	// listen on default port

	ctx->listen_fd   = -1;
	ctx->snaplen = -1;

	ctx->n_channels=1;
	ctx->max_channels=10;
	ctx->channels = malloc_and_check(sizeof(struct channel_info)* ctx->max_channels);
	
	ctx->channels[OFLOPS_CONTROL].raw_sock = -1;
	// initalize other channels later

	return ctx;
}

// Reset any counters in the context
// 	run me between tests
int reset_context(oflops_context * ctx)
{
	// TODO: reset any state between experiments
	timer_init(ctx);
	return 0;
}
