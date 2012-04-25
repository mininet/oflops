
#include <sys/time.h>

#include "timer_event.h"


int timer_get_next_event(struct oflops_context *ctx)
{
	struct timeval tv;
	int ret;
	ret=wc_get_next_event_delta(ctx->timers, &tv);
	if(ret == 0)
	{
	  return tv.tv_sec * 1000000 + tv.tv_usec;	// next event
	}
	else if(ret == -1)
		return 1000000;		// no events; just say 1 sec
	else 
		return -1;		// next event timer already passed... 
}


int timer_run_next_event(struct oflops_context *ctx)
{
	void (* func)(void *);
	void * val;
	int id;
	struct timeval t;
	int err;
	timer_event te;

	err = wc_queue_extract(ctx->timers, &id, &t, &func, &val);
	te.timer_id = id;
	te.arg = val;
	te.sched_time  = t;
	// func is ignored by oflops
	ctx->curr_test->handle_timer_event(ctx, &te);
	
	return 0;
}


int timer_init(struct oflops_context *ctx)
{
	if(ctx->timers)
		wc_queue_free(ctx->timers);
	ctx->timers = wc_queue_init(10);	// 10 == initial size; gets dynamically resized so it don't matter
	return 0;
}
