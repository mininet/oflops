#ifndef TIMER_EVENT_H
#define TIMER_EVENT_H

#include <time.h>

struct timer_event;

#include "oflops.h"
#include "wc_event.h"

typedef struct timer_event
{
	int timer_id;
	void * arg;
	struct timeval sched_time;
} timer_event;

int timer_init(struct oflops_context *ctx);
int timer_get_next_event(struct oflops_context *ctx);

int timer_run_next_event(struct oflops_context *ctx);


#endif
