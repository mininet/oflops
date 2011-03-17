#include <string.h>
#include <dlfcn.h>

#include "context.h"
#include "timer_event.h"
#include "utils.h"
#include "log.h"

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
	ctx->snaplen = 100; //65535;

	ctx->n_channels=1;
	ctx->max_channels=10;
	ctx->channels = malloc_and_check(sizeof(struct channel_info)* ctx->max_channels);

	ctx->control_outgoing = msgbuf_new(4096);       // dynamically sized
	
	ctx->snmp_channel_info = malloc_and_check(sizeof(struct snmp_channel));
	ctx->snmp_channel_info->hostname = NULL;
	ctx->snmp_channel_info->community_string = NULL;

	ctx->channels[OFLOPS_CONTROL].raw_sock = -1;
	// initalize other channels later

	ctx->log = malloc(sizeof(DEFAULT_LOG_FILE));
	strcpy(ctx->log, DEFAULT_LOG_FILE);

	ctx->trafficGen = PKTGEN;

	ctx->dump_controller = 0;
	ctx->cpuOID_len = MAX_OID_LEN;

	return ctx;
}

// Reset any counters in the context
// 	run me between tests
int reset_context(oflops_context * ctx)
{
	// reset any state between experiments
	//timer_init(ctx);
	// clean up after test (each test does its own cleanup, except for the 
	// 	stuff oflops allocated)
	if(ctx->curr_test)
		dlclose(ctx->curr_test->symbol_handle);
	return 0;
}
