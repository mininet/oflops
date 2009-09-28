#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <test_module.h>

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define PACKET_IN_DEBUG 1

/** Interval to send packet
 */
#define SEND_INTERVAL 500000

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define WRITEPACKET "write packet"

/** Packet length
 */
int len;
/** Packet buffer
 */
char buf[BUFLEN];

/** Send sequence
 */
uint32_t sendno;
/** Send time
 */
struct timeval sendtime;
/** Receive time
 */
struct timeval receivetime;

/** Packet in module.
 * The module sends packet into a port to generate packet-in events.
 * The rate, count and delay then determined.
 *
 * Copyright (C) Stanford University, 2009
 * @author ykk
 * @date September, 2009
 * 
 * @return name of module
 */
char * name()
{
	return "Pkt_in_module";
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx)
{
  struct timeval now;
  struct ofp_header ofph;
  struct  ether_header  * eth = (struct ether_header * ) buf;
  gettimeofday(&now, NULL);

  //Schedule start
  now.tv_sec +=1;	
  oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  
  //Schedule end
  now.tv_sec += 4;	// 5 secs on the future, stop this module
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
  len =64;
  bzero(buf,BUFLEN);
  eth->ether_dhost[5]=2;
  eth->ether_shost[5]=1;
  eth->ether_type = htons(12345);

  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  static uint32_t i=0;
  //struct ether_header  * eth = (struct ether_header * ) buf;
  int err;
  struct timeval now;
  char * str;

  gettimeofday(&now,NULL);
  str = (char *) te->arg;
  if (PACKET_IN_DEBUG)
    fprintf(stderr, "At %ld.%.6ld (sched for %ld.%.6ld) : Got timer_event %s \n",
	    now.tv_sec, now.tv_usec, te->sched_time.tv_sec, te->sched_time.tv_usec, str);
 
  if(!strcmp(str,WRITEPACKET))
  {
    //Send message
    sprintf(&buf[sizeof(struct ether_header)],"%i",i);
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Sending message %u\n", i);
    err = oflops_send_raw_mesg(ctx,OFLOPS_DATA1,buf,len);
    if(err < 0)
      perror("write");
    //Schedule next one
    i++;
    now.tv_usec += SEND_INTERVAL;	
    oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  }
  else if(!strcmp(str,BYESTR))
  {
    //End experiment
    oflops_end_test(ctx);
  }
  else
    perror("Unknown timer event");
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param pkt_in pointer to packet in event
 */
int of_event_packet_in(struct oflops_context *ctx, struct ofp_packet_in * pkt_in)
{
  fprintf(stderr, "Got an of_packet_in event on port %d\n", ntohs(pkt_in->in_port));
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
  if(ofc == OFLOPS_CONTROL)	// pcap dump the control channel
    return snprintf(filter,buflen,"tcp port 6633");
  else if(ofc == OFLOPS_DATA1)	// pcap dump data channel 1
    return snprintf(filter,buflen," ");
  else 
    return 0;
}


/** Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  if (ch == OFLOPS_DATA1)
  {
    sendno = (uint32_t) atoi(&(pe->data)[sizeof(struct ether_header)]);
    sendtime = pe->pcaphdr.ts;
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Got data packet of length %u (seq %u) at %ld.%.6ld\n",
	      pe->pcaphdr.caplen,
	      sendno,
	      receivetime.tv_sec, receivetime.tv_usec);      
  }
  else if (ch == OFLOPS_CONTROL)
  {
    receivetime = pe->pcaphdr.ts;
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Got OpenFlow packet at %ld.%.6ld\n", 
	      receivetime.tv_sec, receivetime.tv_usec);
  }
  else
    perror("wtf!  why this channel?");

  return 0;
}



