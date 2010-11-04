#include <assert.h>
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
int min_send_interval= 2000;

/** String for scheduling events
 */
#define NEWRATE "newrate"
#define WRITEPACKET "write packet"

typedef struct probe {
	int in_use;
	struct timeval sent;
} probe;

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define MAX_OUTSTANDING 65536
probe probes[MAX_OUTSTANDING];


int probes_per_second=1;
int seconds_per_rate=5;
int max_rate=1024;
struct timeval starttime, end_time;

/** OpenFlow packet buffer
 */
struct ofp_stats_request buf;

/** index of next probe
 */
int next_index=0;
/** Send counter
 */
uint64_t sentcounter = 0;
uint64_t pcap_sentcounter = 0;
/** Receive counter
 */
uint64_t receivecounter = 0;
/** Total delay
 */
/** Delay packet counter
 */
uint64_t totaldelay = 0;
/** Delay file
 */
FILE* delayfile =NULL;

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
	return "port_status_module";
}

void new_rate(oflops_context * ctx)	// worst side effect evar
{
	char fbuf[BUFLEN];
	struct timeval now;
	int i;

	if(delayfile)	
	{
		for(i=0;i<next_index;i++)
		{
			if(probes[i].in_use)	// expire unreturned probes
				fprintf(delayfile,"%d -1\n",i);
		}
		fclose(delayfile);
	}
	next_index=0;
	probes_per_second*=2;

	if(probes_per_second > max_rate)
	{
		gettimeofday(&now,NULL);
		//End experiment
		fprintf(stderr, "Experiment has %lld packets sent and %lld received -- %f dropped",
			(long long int)sentcounter, (long long int)receivecounter , 
			(long long int)(sentcounter-receivecounter)/(float)sentcounter);
		fprintf(stderr, " (i.e., loss = %lld) with average delay of %f us.\n", 
				(long long int)(sentcounter-receivecounter),
				((float) ((double) totaldelay)/((double) receivecounter)));
		oflops_end_test(ctx,1);
		return;
	}
	//Open delay file
	snprintf(fbuf,BUFLEN,"statdelayfile.rate=%d",probes_per_second);
	delayfile = fopen(fbuf, "w+");
	fprintf(stderr,"---- Sending port_stats_requests at rate %d per second for %d seconds\n", probes_per_second, seconds_per_rate);
	gettimeofday(&now,NULL);
	end_time = now;
	end_time.tv_sec += seconds_per_rate;
	oflops_schedule_timer_event(ctx,&now, WRITEPACKET);
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx)
{
	struct ofp_header ofph;
	gettimeofday(&starttime,NULL);
	starttime.tv_sec += 10;

	bzero(probes,sizeof(probe)*MAX_OUTSTANDING);

	
	oflops_schedule_timer_event(ctx,&starttime, NEWRATE);
	//Schedule first event

	// send a friendly hello
	ofph.length = htons(sizeof(struct ofp_header));
	ofph.xid = 0;
	ofph.type = OFPT_HELLO;
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
		if (sentcounter == 0)
		{
			gettimeofday(&starttime, NULL);
			fprintf(stderr, "Start...\n");
		}
		buf.header.xid = next_index;
		if (PACKET_IN_DEBUG)
			fprintf(stderr, "Sending message %lld\n", (long long int)sentcounter);
		if(probes[next_index].in_use)
			fprintf(delayfile,"%d %d\n",next_index, -1);
		bzero(&probes[next_index],sizeof(probe));
		probes[next_index].in_use=1;
		next_index++;
		next_index %= MAX_OUTSTANDING;
		oflops_send_of_mesg(ctx,(struct ofp_header *) &buf);
		sentcounter++;
		//Schedule next one; using sched time to avoid creep
		te->sched_time.tv_usec += 1000000/probes_per_second;;	
		if(te->sched_time.tv_usec >= 1000000)
		{
			te->sched_time.tv_sec++;
			te->sched_time.tv_usec-=1000000;
		}
		if(timercmp(&end_time, &te->sched_time, >))
			// have time to fire off another probe
			oflops_schedule_timer_event(ctx,&te->sched_time, WRITEPACKET);
		else
		{
			te->sched_time.tv_sec++;	// give some time for probes to drain
			oflops_schedule_timer_event(ctx,&te->sched_time, NEWRATE);
		}
	}
	else if(!strcmp(str,NEWRATE))
		new_rate(ctx);
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
	uint8_t type;
	struct timeval ptime;
	int probe_index;
	probe * p;
	if (ch != OFLOPS_CONTROL)
	{
		fprintf(stderr, "wtf! why channel %u?", ch);
		return 0;
	}
	//See packet received
	if(pe->pcaphdr.caplen <70)
		return 0;	// not for us
	type = pe->data[67];
	if(type != 16 && type != 17)
		return 0;
	ptime = pe->pcaphdr.ts;
	probe_index  = *((uint32_t*) &(pe->data)[70]);
	assert(probe_index>=0);
	assert(probe_index<MAX_OUTSTANDING);
	p = &probes[probe_index];
	fprintf(stderr, "Found unmarked probe.");
	if (PACKET_IN_DEBUG)
		fprintf(stderr, "Got OpenFlow packet of length %u type %u at %ld.%.6ld of probe_index %d\n", 
				pe->pcaphdr.len, type,
				ptime.tv_sec, ptime.tv_usec, 
				probe_index);

	//Handle stat request and stat reply
	if (type == 16)
	{
		//Record sending
		p->sent = ptime;
		pcap_sentcounter++;
		if (PACKET_IN_DEBUG)
			fprintf(stderr, "Send stat request at %ld.%.6ld of probe_index %d\n", 
					ptime.tv_sec, ptime.tv_usec, 
					probe_index);
	}
	else if (type ==17)
	{
		
		if (PACKET_IN_DEBUG)
			fprintf(stderr, "Receive stat reply at %ld.%.6ld of probe_index %d\n", 
					ptime.tv_sec, ptime.tv_usec, 
					probe_index);

		//Calculate time difference
		struct timeval timediff;
		timersub(&ptime, &p->sent, &timediff);
		if (timediff.tv_sec != 0)
		{
			fprintf(stderr, "Delay of > 1 sec!\n");
			return 0;
		}
		fprintf(delayfile, "%d %ld.%.6ld\n", probe_index, timediff.tv_sec, timediff.tv_usec);
		totaldelay += (uint64_t) timediff.tv_usec;
		receivecounter++;
		p->in_use=0;

		if (PACKET_IN_DEBUG)
		{
			fprintf(stderr, "Got stat of probe_index %d with delay %ld.%.6ld\n", 
					probe_index,
					timediff.tv_sec, timediff.tv_usec);
			fprintf(stderr, "\twith %lld packets sent and %lld received.\n", 
					(long long int)sentcounter, (long long int)receivecounter);
		}
	}
	return 0;
}



