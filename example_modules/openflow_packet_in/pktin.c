#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <test_module.h>

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define GET_NUMBER 0

#define PACKET_IN_DEBUG 0

/** Interval to send packet
 */
//#define SEND_INTERVAL 500000
//#define SEND_INTERVAL 2000
#define SEND_INTERVAL 40000

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define WRITEPACKET "write packet"
#define PRINTCOUNT "print"

/** Experiment Ethertype
 */
#define EXPT_ET 12345

/** Packet length
 */
int len;
/** Packet buffer
 */
char buf[BUFLEN];

/** Start time
 */
struct timeval starttime;

/** Send sequence
 */
uint32_t sendno;
/** Send time
 */
struct timeval sendtime[65536];
/** Receive time
 */
struct timeval receivetime[65536];
/** Receive toggle
 */
uint32_t pcapreceiveseq = 0;

/** Send counter
 */
uint64_t sendcounter = 0;
/** Receive counter
 */
uint64_t receivecounter = 0;
/** Total delay
 */
double totaldelay = 0;
/** Delay packet counter
 */
uint64_t delaycounter = 0;
/** Delay file
 */
FILE* delayfile;

/** @ingroup modules
 * Packet in module.
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
  delayfile = fopen("delayfile", "w");

  //Schedule start
  now.tv_sec +=10;	
  oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  oflops_schedule_timer_event(ctx,&now, PRINTCOUNT);
  
  //Schedule end
  now.tv_sec += 120;	// 1 min on the future, stop this module
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

  //Pack packet
  len=54;
  bzero(buf,BUFLEN);
  struct  ether_header  * eth = (struct ether_header * ) buf;
  eth->ether_dhost[5]=2;
  eth->ether_shost[5]=1;
  eth->ether_type = htons(0x0800);
  struct iphdr * ip = (struct iphdr *) &buf[sizeof(struct ether_header)];
  ip->protocol=1;
  ip->ihl=5;
  ip->version=5;
  ip->tot_len=htons(40);
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
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
    if (sendcounter == 0)
    {
      gettimeofday(&starttime, NULL);
      fprintf(stderr, "Start...\n");
    }
    sprintf(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)],"%u",(uint32_t) sendcounter);
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Sending message %lld\n", sendcounter);
    err = oflops_send_raw_mesg(ctx,OFLOPS_DATA1,buf,len);
    if(err < 0)
      perror("write");
    //Schedule next one
    sendcounter++;
    now.tv_usec += SEND_INTERVAL;	
    oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
  }
  else if(!strcmp(str,PRINTCOUNT))
  {
    fprintf(stderr, "Experiment has %lld packets sent and %lld received\n",
	    sendcounter,
	    receivecounter);
    now.tv_sec++;
    oflops_schedule_timer_event(ctx,&now, PRINTCOUNT);
  }
  else if(!strcmp(str,BYESTR))
  {
    if (GET_NUMBER)
      if (delaycounter < GET_NUMBER)
      {
	fprintf(stderr, "Received %lld\n", delaycounter);
	gettimeofday(&now,NULL);
	now.tv_sec++;
	oflops_schedule_timer_event(ctx,&now, BYESTR);
	return 0;
      }
	
    //End experiment
    fprintf(stderr, "Experiment has %lld packets sent (rate %f) and %lld received",
	    sendcounter,
	    (float) (((double) sendcounter)/((double) (now.tv_sec - starttime.tv_sec))),
	    receivecounter);
    fprintf(stderr, " (i.e., loss = %lld) with average delay of %f us.\n", 
	    (sendcounter-receivecounter),
	    ((float) (totaldelay/((double) delaycounter))));
    fclose(delayfile);
    oflops_end_test(ctx,1);
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
	// nothing to do here, see handle_pcap_event() below.
	return 0;
}

static int record_time_diff (struct oflops_context *ctx, uint32_t seqno)
{
  //Check receive sequence
  uint32_t receiveno = seqno;
  
  if (receiveno > sendno)
  {
    fprintf(stderr, "Send sequence %u < receive sequence %u => wtf!\n", 
	    sendno, receiveno);
    return 0;
  }
  receivecounter++;
  if ((receiveno+65536) < sendno)
  {
    fprintf(stderr, "Send sequence %u > receive sequence %u => send time lost!\n", 
	    sendno, receiveno);
    return 0;
  }
  if (pcapreceiveseq > receiveno)
  {
    fprintf(stderr, "OpenFlow packet's capture time is lost!");
    fprintf(stderr, "With seq %u recorded and %u wanted.\n",
	    pcapreceiveseq, receiveno);
    return 0;
  }

  //Calculate time difference
  struct timeval timediff;
  timersub(&receivetime[(uint16_t)receiveno], &sendtime[(uint16_t)receiveno], &timediff);
  /*  if (timediff.tv_sec != 0)
  {
    fprintf(stderr, "Delay of > %u sec!\n", timediff.tv_sec);
    return 0;
    }*/
  fprintf(delayfile, "%ld.%.6ld\n", timediff.tv_sec, timediff.tv_usec);
  totaldelay += ((double) timediff.tv_usec)+((double) timediff.tv_sec*10e6);
  delaycounter++;

  if (PACKET_IN_DEBUG)
  {
    fprintf(stderr, "Got an of_packet_in event for seq %u with delay %ld.%.6ld\n", 
	    receiveno,
	    timediff.tv_sec, timediff.tv_usec);
    fprintf(stderr, "\twith %lld packets sent and %lld received.\n", 
	    sendcounter, receivecounter);
  }

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
    return snprintf(filter,buflen,"tcp dst port 6633");
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
  if (ch == OFLOPS_DATA1)
  {
    //See packet sent
    sendno = (uint32_t) atoi((char *)&(pe->data)[sizeof(struct ether_header)+sizeof(struct iphdr)]);
    sendtime[((uint16_t) sendno)] = pe->pcaphdr.ts;
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Got data packet of length %u (seq %u) at %ld.%.6ld\n",
	      pe->pcaphdr.caplen,
	      sendno,
	      pe->pcaphdr.ts.tv_sec, pe->pcaphdr.ts.tv_usec);      
  }
  else if (ch == OFLOPS_CONTROL)
  {
    //See packet received
    uint8_t et = *((uint8_t *) &(pe->data)[107]);
    if (et != 1)
    {
      fprintf(stderr, "Ether type %u received != %u sent\n", et, 1);
      return 0;
    }

    pcapreceiveseq  = (uint32_t) atoi((char *)&(pe->data)[118]);
    receivetime[(uint16_t) pcapreceiveseq] = pe->pcaphdr.ts;
    if (PACKET_IN_DEBUG)
      fprintf(stderr, "Got OpenFlow packet of length %u at %ld.%.6ld of seq %u\n", 
	      pe->pcaphdr.len,
	      pe->pcaphdr.ts.tv_sec, pe->pcaphdr.ts.tv_usec, 
	      pcapreceiveseq);
    record_time_diff(ctx, pcapreceiveseq);
  }
  else
    fprintf(stderr, "wtf! why channel %u?", ch);

  return 0;
}



