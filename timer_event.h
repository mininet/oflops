#ifndef TIMER_EVENT_H
#define TIMER_EVENT_H

#include <time.h>

typedef struct timer_event
{
	int timer_id;
	void * arg;
	struct timeval sched_time;
} timer_event;


#endif
