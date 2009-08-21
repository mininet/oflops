#include <string.h>

#include "context.h"
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
	
	ctx->channels[OFLOPS_CONTROL].raw_sock = -1;
	ctx->channels[OFLOPS_SEND].raw_sock = -1;
	ctx->channels[OFLOPS_RECV].raw_sock = -1;

	return ctx;
}

// Reset any counters in the context
// 	run me between tests
int reset_context(oflops_context * ctx)
{

	return 0;
}
