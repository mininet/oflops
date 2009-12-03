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

#define HISTR "Oh... hello there"
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
	oflops_schedule_timer_event(ctx,&now, "1 sec");
	now.tv_sec ++;	
	oflops_schedule_timer_event(ctx,&now, "2 sec");
	now.tv_sec ++;	
	oflops_schedule_timer_event(ctx,&now, "3 sec");
	now.tv_sec ++;	
	oflops_schedule_timer_event(ctx,&now, "4 sec");
	now.tv_sec ++;	// 5 secs on the future, stop this module
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
	// get a udp file descriptor from one of the data channels
	do {
		char buf[BUFLEN];
		struct  ether_header  * eth = (struct ether_header * ) buf;
		int err, len;
	
		len =64;
		bzero(buf,BUFLEN);
		eth->ether_dhost[5]=2;
		eth->ether_shost[5]=1;
		eth->ether_type = htons(12345);	// shrug.. shouldn't matter
		memcpy(&buf[sizeof(struct ether_header)], HISTR, strlen(HISTR));
		err = oflops_send_raw_mesg(ctx,OFLOPS_DATA1,buf,len);
		if(err < 0)
			perror("write");
		err = oflops_send_raw_mesg(ctx,OFLOPS_DATA2,buf,len);
		if(err < 0)
			perror("write");
	} while(0);
	return 0;
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
		oflops_end_test(ctx,1);
	return 0;
}

int of_event_packet_in(struct oflops_context *ctx, struct ofp_packet_in * pkt_in)
{
	struct pcap_pkthdr hdr;
	if( oflops_get_timestamp(ctx,pkt_in, ntohs(pkt_in->header.length), &hdr, OFLOPS_CONTROL))
		fprintf(stderr, "Got an of_packet_in event on port %d :: ts=%ld.%.6ld\n", 
				ntohs(pkt_in->in_port), hdr.ts.tv_sec, hdr.ts.tv_usec);
	return 0;
}
