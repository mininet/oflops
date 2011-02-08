#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

// modified pqueue.h ; lots of references to 'pq' still exist
// Uncomment for heap debugging
// #define HEAP_DEBUG

/**************************************************************************
 * using alg from CLR p 152;
 * 	*NOTE* we do NOT use index zero; we just start at pq->array[1];
 * 	that way we skip all kinds of off by 1 errors	(and create others!)
 */

#include "wc_event.h"
#include "utils.h"
#include "context.h"


/***************************** local types
 */
typedef struct wc_event
{
	struct timeval eventtime;
	void (*fun)(void *);
	void * arg;
} wc_event;

typedef struct qelm {
	int id;
	struct timeval key;
	struct wc_event * data;
} qelm;


typedef struct wc_queue {
	qelm * array;
	int length;
	int size;
	int timersEnabled;
} wc_queue;

/*************************** protos
 */

static int wc_queue_isempty(struct wc_queue *);
static void wc_event_handler(int );
int wc_run_next_event(wc_queue *);
static void heapify(wc_queue * pq, int i);
static void wc_queue_double(wc_queue *);
// schedule the next event with SIGALRM
static void wc_schedule_next_event(struct wc_queue *);


static int WC_EVENT_ID=0;
static wc_queue * WC_Queue;
#ifdef HEAP_DEBUG
static void verify_heap(wc_queue *);
#endif

#define PARENT(x) ((x)/2)
#define LEFT(x) ((x)<<1)
#define RIGHT(x) (((x)<<1)+1)



/******************************** functions
 */

wc_queue * wc_queue_init(int initSize){
	wc_queue *pq;

	pq = malloc_and_check(sizeof(wc_queue));
	if(pq==NULL){
		perror("wc_queue_init:: malloc");
		return NULL;
	}
	pq->array = malloc_and_check(sizeof(qelm)*initSize);
	if(pq->array == NULL){
		perror("wc_queue_init:: malloc");
        free(pq);
		return NULL;
	}
	pq->size=0;
	pq->length=initSize;
	pq->timersEnabled=0;	// start with timers disabled

	WC_Queue=pq;
	return pq;
}

void wc_queue_free(/*@only@*/ wc_queue * pq){
	assert(pq);
	free(pq->array);
	free(pq);
}


int wc_queue_isempty(wc_queue *pq){
	assert(pq);
	return (pq->size<1);
}

#ifdef __LCLINT__
# define timercmp(a, b, CMP)                                                  \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((a)->tv_sec CMP (b)->tv_sec))
#endif


void heapify(wc_queue * pq, int i){
	int l,r;
	int largest;
	qelm tmp;
	
	assert(pq);
	l = LEFT(i);
	r = RIGHT(i);
	if((l<= pq->size)&& (timercmp(&pq->array[l].key,&pq->array[i].key,<)))
		largest=l;
	else largest=i;
	if((r<= pq->size)&& (timercmp(&pq->array[r].key,&pq->array[largest].key,<)))
		largest=r;
	if(largest!=i){
		// swap 'em
		tmp=pq->array[i];
		pq->array[i]=pq->array[largest];
		pq->array[largest]=tmp;
		heapify(pq,largest);
	}
}

// void wc_queue_insert(wc_queue* pq,wc_event * data,struct timeval key){
int wc_event_add(wc_queue* pq, void (*fun)(void *), void *arg, struct timeval key){
	int i;
	wc_event * data;
	int id;

	assert(pq->timersEnabled==0);		// only allow adds when timers are off
	if((pq->size+1)>=pq->length)		// the "+1" is critical, b/c we start at array[1]
		wc_queue_double(pq);
	pq->size++;
	i=pq->size;
	data = malloc_and_check(sizeof(wc_event));
    assert(data != NULL);
	data->fun=fun;
	data->eventtime=key;
	data->arg=arg;
	while((i>1)&&(timercmp(&pq->array[PARENT(i)].key,&key,>))){	// search heap
		pq->array[i]=pq->array[PARENT(i)];	// copy the parent's data down one level
		i=PARENT(i);
	}
	pq->array[i].key=key;
	pq->array[i].data=data;
	id=pq->array[i].id=WC_EVENT_ID++;
	// Do no scheduling here; will be handled elsewhere
	return id;
}

// void wc_schedule_next_event(wc_queue *pq)
static void wc_schedule_next_event(wc_queue *pq)
{
	struct timeval now,diff;
	struct itimerval itv;
	qelm *data;
	assert(pq->timersEnabled);	// should only be called when timers are enabled
	assert(pq->size>0);

	diff.tv_sec = diff.tv_usec = 0;

	while(!wc_queue_isempty(pq))		
	{
		// grab first element
		data=&pq->array[1];		// DUMBASS: we skip array[0] b/c it makes the math easier
		gettimeofday(&now,NULL);
		if(timercmp(&now,&data->key,>))
		{	// event already should have happened; sched for NOW
			fprintf(stderr,"Scheduling event %d NOW b/c it has passed already\n",data->id);
			wc_run_next_event(pq);
			continue;
		}
		// schedule event for some amount of time in future
		timersub(&data->key,&now,&diff);
		break;
	}
	if(wc_queue_isempty(pq))
		return;		// nothing to schedule

	itv.it_value=diff;
	itv.it_interval.tv_sec = itv.it_interval.tv_usec=0;
	signal(SIGALRM,wc_event_handler);	// set this here...
	assert(setitimer(ITIMER_REAL,&itv,NULL)==0);
}
/**************************************************************************
 * int wc_queue_extract(wc_queue *pq , struct timeval * key, wc_event * wc){
 * 	remove from the top of the heap and reheap 
 * 		ASSUMES timer will not go off, which is true if called from signal handler
 */
 	
int wc_queue_extract(wc_queue *pq , int * id, struct timeval * key,void (**fun)(void *), void **arg) {
	wc_event * data;
	assert(pq);
	assert(pq->timersEnabled==0);
	if(pq->size<1){		//empty
		return -1;
	}
	data=pq->array[1].data;
	*key=pq->array[1].key;
	*id=pq->array[1].id;
	pq->array[1]=pq->array[pq->size];	// move first elm to end
	pq->size--;
	heapify(pq,1);

	*fun=data->fun;
	*arg=data->arg;
	free(data);
	return 0;

}
/***********************************************************************
 * int wc_event_remove(wc_queue * pq, int id);
 * 	remove the event specified by id
 *
 * 		YES this is a linear search; but hopefully it won't matter (GULP)
 * 	alg: move last elm to deleted elm slot, then call heapify on deleted slot
 * 		
 */
int wc_event_remove(wc_queue * pq, int id,void (**fun)(void *),void **arg)
{
	int i;
	struct wc_event * data;
	assert(pq->timersEnabled==0);
	for(i=1;i<=pq->size;i++)
		if(pq->array[i].id==id)
			break;
	if(i>pq->size)
		return -1;	// tried to delete something that didn't exist
#ifdef HEAP_DEBUG
	verify_heap(pq);
#endif
	data = pq->array[i].data;
	*fun=data->fun;
	*arg=data->arg;
	free(data);
	pq->array[i]=pq->array[pq->size];
	pq->size--;
	do
	{	// need to fix up the entire heap after arbitary delete
		heapify(pq,i);		// this is a log(log(n)) op, 
		i=PARENT(i);		// but that is the cost of arbt dels in a heap
	} while(i>0);
#ifdef HEAP_DEBUG
	verify_heap(pq);
#endif
	// don't worry about deleting the currently scheduled event;
	//  that will be rescheduled elsewhere
	return 0;
}


/************************************************************************8
 * void wc_run_next_event(wc_queue *);
 * 	dequeue and run the first event off the top of the queue
 */
int wc_run_next_event(wc_queue * pq)
{
	void (*fun)(void *);
	void*arg;
	struct timeval key,now,diff;
	static struct timeval last = {0,0};
	int id;

	diff.tv_sec = diff.tv_usec = 0;

	if(wc_queue_isempty(pq))
		return -1;				// event queue empty
	wc_queue_extract(pq,&id,&key,&fun,&arg);	// get event off top of heap
	// ASSERT events monotonically increase
	gettimeofday(&now,NULL);
	// Don't do this, because time on Planet-lab can roll backwards; and yes, that's a problem here
	// assert(timercmp(&key,&last,>=));	// assert that this event happens after the last one
	timersub(&now,&key,&diff);
	last=key;
	/*
	if(diff.tv_sec<1)			// that this event went off less then 1 sec after it was 
		logtype=LOGDEBUG2;
	else 
		logtype=LOGCRIT;
	*/
						// intended to

	if(diff.tv_sec>0)			// that this event went off more then 1 sec after it was 
		fprintf(stderr," issuing LATE timer %d for %ld.%.6ld (%ld.%.6ld late)\n",
				id,(long)key.tv_sec,(long)key.tv_usec,(long)diff.tv_sec,(long)diff.tv_usec);
	fun(arg);				// call event
	return id;
}

/**************************************************************************
 * int wc_get_next_event_delta(struct wc_queue *, struct timeval *delta);
 * 	return the time delta (not absolute time) until the next event
 * 		- used for select()
 * 		- return: 	
 * 			0 if *delta is valid
 * 			-1 if no event exists
 * 			1 if first event has already passed
 */
int wc_get_next_event_delta(struct wc_queue * pq, struct timeval *delta)
{
	struct timeval now;
	qelm *data;
	assert(pq->timersEnabled==0);	// should only be called when timers are disabled
	if(wc_queue_isempty(pq))
		return -1;
	data=&pq->array[1];		// DUMBASS: we skip array[0] b/c it makes the math easier
	gettimeofday(&now,NULL);
	if(timercmp(&now,&data->key,>)) {
	  return 1;		// event already should have happened; sched for NOW
	}
	// schedule event for some amount of time in future
	timersub(&data->key,&now,delta);
	return 0;			// there exists an event in the future
}



/************************************************************************
 * void wc_event_handler(int );
 * 	SIGALRM handler
 */

void wc_event_handler(int ignore)
{
	wc_queue *pq=WC_Queue;		// HACK; how do we pass state to a signal handler?; need to use globalvar

	assert(pq->timersEnabled);	// it would suck if this went off when timers were disabled
	pq->timersEnabled=0;		// mark timers as disabled (they can't go off anyway while we are here)
	wc_run_next_event(pq);
	pq->timersEnabled=1;		// re-enabled them
	if(!wc_queue_isempty(pq))
		wc_schedule_next_event(pq);	// schedule next event, if exists
						// this will also reset the SIGALRM handler and call setitimer()
}

/*******************************************************
 * void wc_queue_double(wc_queue *pq){
 * 	dynamically double the size of the heap
 */

void wc_queue_double(wc_queue *pq){
	qelm * neoarray;
	/*
	fprintf(stderr,"wc_queue_double: increasing wc_queue from %d to %d\n",
			pq->length, pq->length*2);*/
	neoarray = malloc_and_check(sizeof(qelm)*pq->length*2);
	assert(neoarray);
	memcpy(neoarray,pq->array,pq->length*sizeof(qelm));
	pq->length*=2;
	if(pq->array)
		free(pq->array);
	pq->array=neoarray;
}
/******************************************************
 * void wc_disable_timers(struct timeval *timers,struct timeval *now);
 * 	set setittimer to 0, set timersEnabled to 0
 */
void wc_disable_timers(struct wc_queue *pq)
{
	struct itimerval stop,old;
	memset(&stop,0,sizeof(struct itimerval));
	signal(SIGALRM,SIG_IGN);			// this should stop a race condition of
							// the timer has expired, but the signal has not yet
							// been proceeded; won't drop event, b/c it will
							// be resched when we re-enable
	assert(setitimer(ITIMER_REAL,&stop,&old)==0);	// stop the current timer, so it doesn't go 
	fprintf(stderr," timers disabled\n");
	pq->timersEnabled=0;
}

/*************************************************
 *  The main event loop of the event subsystem. 
 */
void *event_loop(void *param) {
  int next_event;
  struct run_module_param* state = (struct run_module_param *)param;
  
  //timer_init(state->ctx);
  printf("event loop\n");

  while(state->ctx->should_end == 0) {
    next_event = timer_get_next_event(state->ctx);
    if(next_event <= 0 ) {
      pthread_yield();
      timer_run_next_event(state->ctx);
      //next_event = timer_get_next_event(ctx);
    }
  };
  return NULL;
}

/******************************************************
 * void wc_enable_timers(struct timeval *timers,struct timeval *now);
 *	set setitimer to timers-(elapsed time)
 */

void wc_enable_timers(struct wc_queue *pq)
{
	pq->timersEnabled=1;
	fprintf(stderr," timers enabled\n");
	if(!wc_queue_isempty(pq))
		wc_schedule_next_event(pq);
}

/*************************************************
 * static void verify_heap(wc_queue *);
 * 	sanity check of the heap property
 */

#ifdef HEAP_DEBUG
static void verify_heap(wc_queue *pq)
{
	int i;
	for(i=1;i<=pq->size;i++)
	{
		if(LEFT(i)<=pq->size)
			assert( timercmp(&pq->array[LEFT(i)].key,&pq->array[i].key,>=));
		if(RIGHT(i)<=pq->size)
			assert( timercmp(&pq->array[RIGHT(i)].key,&pq->array[i].key,>=));
	}
}
#endif


/*************************************************************
 * unittests
 */

static int test_fun_counter=10;
extern void test_fun(void *arg)
{
	unsigned int i;
	i = *( unsigned int *) arg;
	test_fun_counter--;
	printf("wv_event:: test_fun: got %u ; %d left\n",i, test_fun_counter);
}


void wc_queue_unit_test(){
	wc_queue *pq;
	void (*fun)(void *);
	void *arg;
	int i,j,tmp;
	struct timeval k,k_old,now;
	int t[10];
	struct timeval times[10];


	gettimeofday(&now,NULL);
	pq = wc_queue_init(5);
	// init
	for(i=0;i<10;i++){
		times[i].tv_sec=now.tv_sec+i;
		times[i].tv_usec=now.tv_usec;
		t[i]=i;
	}
	// randomize order
	srand(time(NULL));
	for(i=0;i<10;i++)
	{
		// pick rand
		j = (rand()%(10-i))+i;	// [i..9]
		// swap i and j
		k  = times[j];
		tmp = t[j];
		times[j]=times[i];
		t[j]=t[i];
		times[i]=k;
		t[i]=tmp;
	}
	printf("wc_queue_unit_test:\n--------------------------\n");
	// insert
	for(i=0;i<10;i++){
		printf("Adding event %d with id==%d\n",t[i],
				wc_event_add(pq,test_fun, (void *)&t[i],times[i]));
	}
	// delete 3 things
	assert(wc_event_remove(pq,3,&fun,&arg)==0);
	assert(wc_event_remove(pq,0,&fun,&arg)==0);
	assert(wc_event_remove(pq,7,&fun,&arg)==0);
	j=1;
	k_old.tv_sec=k_old.tv_usec=0;
	test_fun_counter=7;
	while(test_fun_counter>0);	// can't use sleep() without screwing up the SIGALRM handler
	printf("\n");
	wc_queue_free(pq);
}


