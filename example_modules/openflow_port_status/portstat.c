#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <test_module.h>

#define PACKET_IN_DEBUG 0

/** Interval to send packet
 */
//#define MIN_SEND_INTERVAL 500000
//#define MIN_SEND_INTERVAL 2000
#define MIN_SEND_INTERVAL 2000

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define WRITEPACKET "write packet"

/** OpenFlow packet buffer
 */
struct ofp_stats_request buf;

/** Start time
 */
struct timeval starttime;

/** Sending.
 */
int sending = 0;
/** Send xid
 */
uint32_t sendxid;
/** Send time
 */
struct timeval sendtime;

/** Send counter
 */
uint64_t sendcounter = 0;
/** Receive counter
 */
uint64_t receivecounter = 0;
/** Total delay
 */
uint64_t totaldelay = 0;
/** Delay packet counter
 */
uint64_t delaycounter = 0;
/** Delay file
 */
FILE* delayfile;

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
  gettimeofday(&now, NULL);

  //Open delay file
  delayfile = fopen("statdelayfile", "w");

  //Schedule start
  now.tv_sec +=10;	
  oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  
  //Schedule end
  now.tv_sec += 60;	// 1 min on the future, stop this module
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

  // build port stat request
  buf.header.length = htons(sizeof(struct ofp_stats_request));
  buf.header.xid = 0;
  buf.header.type = OFPT_STATS_REQUEST;
  buf.header.version = OFP_VERSION;
  buf.type = htons(OFPST_PORT);
  buf.flags = 0;

  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
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
    if (sendcounter == 0)
    {
      gettimeofday(&starttime, NULL);
      fprintf(stderr, "Start...\n");
    }
    if (!sending)
    {
      buf.header.xid = htonl((uint32_t) sendcounter);
      if (PACKET_IN_DEBUG)
	fprintf(stderr, "Sending message %lld\n", sendcounter);
      oflops_send_of_mesg(ctx,(struct ofp_header *) &buf);
    }

    //Schedule next one
    now.tv_usec += MIN_SEND_INTERVAL;	
    oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  }
  else if(!strcmp(str,BYESTR))
  {
    //End experiment
    if (sending)
      sendcounter--;
    fprintf(stderr, "Experiment has %lld packets sent (rate %f) and %lld received",
	    sendcounter,
	    (float) (((double) sendcounter)/((double) (now.tv_sec - starttime.tv_sec))),
	    receivecounter);
    fprintf(stderr, " (i.e., loss = %lld) with average delay of %f us.\n", 
	    (sendcounter-receivecounter),
	    ((float) ((double) totaldelay)/((double) delaycounter)));
    fclose(delayfile);
    oflops_end_test(ctx);
  }
  else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param pkt_in pointer to packet in event
 */
int of_event_packet_in(struct oflops_context *ctx, struct ofp_packet_in * pkt_in)
{
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
  if (ch == OFLOPS_CONTROL)
  {
    //See packet received
    uint8_t type = pe->data[67];
    struct timeval ptime = pe->pcaphdr.ts;
    uint32_t xid  = ntohl(*((uint32_t*) &(pe->data)[70]));
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Got OpenFlow packet of length %u type %u at %ld.%.6ld of xid %u\n", 
	      pe->pcaphdr.len, type,
	      ptime.tv_sec, ptime.tv_usec, 
	      xid);

    //Handle stat request and stat reply
    if (type == 16)
    {
      //Record sending
      sending = 1;
      sendtime = ptime;
      sendxid = xid;
      sendcounter++;
      if (PACKET_IN_DEBUG)
	fprintf(stderr, "Send stat request at %ld.%.6ld of xid %u\n", 
		ptime.tv_sec, ptime.tv_usec, 
		xid);
    }
    else if (type ==17)
    {
      sending = 0;
      if (PACKET_IN_DEBUG)
	fprintf(stderr, "Receive stat reply at %ld.%.6ld of xid %u\n", 
		ptime.tv_sec, ptime.tv_usec, 
		xid);

      //Check xid
      if (xid != sendxid)
      {
	fprintf(stderr, "Send xid %u and receive xid %u, wtf?!",
		sendxid, xid);
	return 0;
      }

      //Calculate time difference
      struct timeval timediff;
      timersub(&ptime, &sendtime, &timediff);
      if (timediff.tv_sec != 0)
      {
	  fprintf(stderr, "Delay of > 1 sec!");
	  return 0;
      }
      fprintf(delayfile, "%ld\n", timediff.tv_usec);
      totaldelay += (uint64_t) timediff.tv_usec;
      delaycounter++;      
      receivecounter++;

      if (PACKET_IN_DEBUG)
      {
	fprintf(stderr, "Got stat of xid %u with delay %ld.%.6ld\n", 
	    xid,
	    timediff.tv_sec, timediff.tv_usec);
	fprintf(stderr, "\twith %lld packets sent and %lld received.\n", 
		sendcounter, receivecounter);
      }
    }
  }

  else
    fprintf(stderr, "wtf! why channel %u?", ch);

  return 0;
}



