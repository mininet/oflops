#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test_module.h>

#define BYESTR "bye bye"

char * name()
{
	return "Debug_module";
}

int start(struct oflops_context * ctx)
{
	struct timeval now;
	struct ofp_header ofph;
	gettimeofday(&now, NULL);
	now.tv_sec ++;	
	schedule_timer_event(ctx,&now, "1 sec");
	now.tv_sec ++;	
	schedule_timer_event(ctx,&now, "2 sec");
	now.tv_sec ++;	
	schedule_timer_event(ctx,&now, "3 sec");
	now.tv_sec ++;	
	schedule_timer_event(ctx,&now, "4 sec");
	now.tv_sec ++;	// 5 secs on the future, stop this module
	schedule_timer_event(ctx,&now, BYESTR);
	// send a friendly hello
	ofph.length = htons(sizeof(struct ofp_header));
	ofph.xid = 0;
	ofph.type = OFPT_HELLO;
	ofph.version = OFP_VERSION;
	send_of_mesg(ctx,&ofph);
	// send a features request, to stave off timeout
	ofph.length = htons(sizeof(struct ofp_header));
	ofph.xid = 0;
	ofph.type = OFPT_FEATURES_REQUEST;
	ofph.version = OFP_VERSION;
	send_of_mesg(ctx,&ofph);
}

int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
	struct timeval now;
	char * str;
	str = (char *) te->arg;
	gettimeofday(&now,NULL);
	fprintf(stderr, "At %ld.%.6ld (sched for %ld.%.6ld) : Got timer_event %s \n",now.tv_sec, now.tv_usec, te->sched_time.tv_sec, 
			te->sched_time.tv_usec, str);
	if(!strcmp(str,BYESTR))
		end_test(ctx);
}
