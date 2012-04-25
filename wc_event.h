#ifndef WC_EVENT_H
#define WC_EVENT_H

#include <time.h>
#include <sys/time.h>

/***************************************************
 * HIGH LEVEL DESCRIPTION
 * 	two ways of using this:
 * 		1) with SIGALRM and setitimer
 * 			a) call wc_enable_timers(struct wc_queue *) to start the SIGALRM
 * 				for events
 * 			b) call wc_disabled_timers() before adding events, and recall
 * 				wc_enable_timers() to restart handling events
 * 			c) wc_run_next_event() will get called from signal handler;
 * 				don't invoke manually
 * 	 	2) with select()
 * 	 		a) never call wc_enable_timers() -- i.e., leave timers off 
 * 	 		b) call err==wc_get_next_event_delta() to get time until next event
 * 	 		c) if while err == -1, wc_run_next_event()
 * 	 		d) timeout=select(*,*,*,time_delta)
 * 	 		e) if timeout==-1, wc_run_next_event()
 */

struct wc_queue;

struct wc_queue * wc_queue_init(int initSize);
void wc_queue_free(/*@only@*/ struct wc_queue * );

int wc_event_add(struct wc_queue*, void (*fun)(void *), void *arg, struct timeval key);
int wc_event_remove(struct wc_queue *,int id, /*@out@*/ void (**fun)(void *), /*@out@*/ void **arg);

/// select() style
// get the time until the next event
int wc_get_next_event_delta(struct wc_queue *, struct timeval *delta);
// run the next event; returns the id of the event that was run
int wc_run_next_event(struct wc_queue *);
int wc_queue_extract(struct wc_queue *pq , int *, struct timeval * key, void (**fun)(void *), void **arg);


void *event_loop(void *param);

/******************
 * Don't use... slow on planetlab
/// SIGALRM style
// enable/disable SIGALRM lock; starts disabled
void wc_disable_timers(struct wc_queue *);
void wc_enable_timers(struct wc_queue *);
*/



void wc_queue_unit_test();
#endif
