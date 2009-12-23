#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test_module.h>

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define WRITEPACKET "write packet"

/** @ingroup modules
 * SNMP CPU module.
 * The module sends SNMP requests to probe CPU load of switches.
 *
 * Copyright (C) Stanford University, 2009
 * @author ykk
 * @date December, 2009
 * 
 * @return name of module
 */
char * name()
{
	return "Snmp_cpu_module";
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx)
{
  struct timeval now;
  struct ofp_header ofph;
  gettimeofday(&now, NULL);

  //Schedule start
  now.tv_sec +=5;	
  oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  
  //Schedule end
  now.tv_sec += 5;	// 0.5 min on the future, stop this module
  oflops_schedule_timer_event(ctx,&now, BYESTR);

  // send a friendly hello
  ofph.length = htons(sizeof(struct ofp_header));
  ofph.xid = 0;
  ofph.type = OFPT_HELLO;
  ofph.version = OFP_VERSION;
  oflops_send_of_mesg(ctx,&ofph);

  // send a features request, to stave off timeout (ignore response)
  ofph.length = htons(sizeof(struct ofp_header));
  ofph.xid = 0;
  ofph.type = OFPT_FEATURES_REQUEST;
  ofph.version = OFP_VERSION;
  oflops_send_of_mesg(ctx,&ofph);

  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  char * str;
  struct timeval now;

  str = (char *) te->arg;
  oid query[] = { 1, 3, 6, 1, 4, 1, 21839, 2, 2, 11, 2, 1, 2, 1, 11, 1 };
  gettimeofday(&now, NULL);

  if(!strcmp(str,WRITEPACKET))
  {
    fprintf(stderr, "Send SNMP request\n");
    oflops_snmp_get(ctx, query,sizeof(query)/sizeof(oid));
    now.tv_sec +=1;	
    oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  }
  else if(!strcmp(str,BYESTR))
  {
    //End experiment
    oflops_end_test(ctx,1);
  }
  else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

int handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se)
{
  char buf[1024];
  snprint_variable(buf, sizeof(buf), se->reply->name, se->reply->name_length, se->reply);
  fprintf(stderr,"SNMP response: %s\n",buf);
  return 0;
}

