#include <stdio.h>
#include <stdlib.h>

#include <test_module.h>

char * name()
{
	return "Debug_module";
}

int start(struct oflops_context * ctx)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	now.tv_sec +=5;
	schedule_timer_event(ctx,&now, "bye bye");
}

int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
	char * str;
	str = (char *) te->arg;
	fprintf(stderr, "Got timer_event %s \n",str);
	end_test(ctx);
}
