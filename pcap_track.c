#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <net/ethernet.h>

#include <openflow/openflow.h>

#include "pcap_track.h"
#include "utils.h"

#ifndef PTRACK_MAX_LEN
#define PTRACK_MAX_LEN	256
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

struct ptrack_entry {
	char * data;
	int len;
	struct pcap_pkthdr hdr;
};

struct ptrack_list {
	struct ptrack_entry entries[PTRACK_MAX_LEN];
	int count, head;
};

static unsigned int tcp_payload_offset(void * data, int len);


/*************************************************************/

struct ptrack_list * ptrack_new()
{
	struct ptrack_list * neo;
	neo = malloc_and_check(sizeof(struct ptrack_list));
	bzero(neo,sizeof(struct ptrack_list));
	return neo;
}


/***********************************************************
 *	FIXME: make it possible to track non-openflow streams
 ***/

int ptrack_add_of_entry( struct ptrack_list * ptl, void * data, int len, struct pcap_pkthdr hdr)
{
	struct ptrack_entry * ent;	
	int add_count=0;
	int add_len;
	int offset = tcp_payload_offset(data, len);
	if(offset >= len)	// nothing to add
		return add_count;
	len-=offset;	// jump to just the tcp payload part
	data+=offset;
	while(len>0 ) 
	{
		struct ofp_header * ofph= data;
		add_len= ntohs(ofph->length);
		if(add_len > len)
		{
			fprintf(stderr, "ptrack_add_entry: unable to track timestamp for partial openflow message\n");
			return add_count;
		}
		ent = &ptl->entries[ptl->head];
		ent->data = malloc_and_check(add_len);
		memcpy(ent->data, data, add_len);
		ent->len = add_len;
		ent->hdr=hdr;
		ptl->head++;
		if(ptl->head >= PTRACK_MAX_LEN)
			ptl->head=0;
		if(ptl->count < PTRACK_MAX_LEN)
			ptl->count++;
		add_count++;
		len -=add_len;
		data += add_len;
	}
	return add_count;
}

/********************************************************/

int ptrack_lookup(struct ptrack_list * ptl, void * data, int len, struct pcap_pkthdr * hdr)
{
	int i, idx;
	struct ptrack_entry * ent;
	for( i = 0 ; i < ptl->count ; i ++)
	{
		idx = ptl-> head -1 - ptl->count;
		if(idx<0)
			idx+=PTRACK_MAX_LEN;
		ent = & ptl->entries[idx];
		if((len <= ent-> len) && (memcmp(data, ent->data, MIN(len,ent->len))==0))
		{
			*hdr = ent->hdr;
			ptl->head--;
			if(ptl->head<0)
				ptl->head+=PTRACK_MAX_LEN;
			ptl->count--;
			assert(ptl->count >=0);
			return 1;
		}
	}
	return 0;
}

/*********************************************************/

void ptrack_free(struct ptrack_list * ptl)
{
	int i, idx;
	struct ptrack_entry * ent;
	for(i = 0; i < ptl->count ; i ++)
	{
		idx = ptl-> head -1 - ptl->count;
		if(idx<0)
			idx+=PTRACK_MAX_LEN;
		ent = & ptl->entries[idx];
		free(ent->data);
	}
	free(ptl);
}


/*********************************************************/
static unsigned int tcp_payload_offset(void * data, int len)
{
	 int offset=0;
	 struct iphdr * ip;
	 struct tcphdr * tcp;
	 struct ether_header * eth = data+offset;
	 if(eth->ether_type == htons(ETHERTYPE_VLAN))
	 {
		offset+=4;
	 	eth = data+offset;
	 }
	 if((offset>=len)||(eth->ether_type != htons(ETHERTYPE_IP)))
		 return INT_MAX;
	 offset+=sizeof(struct ether_header);
	 ip = data + offset;
	 if((offset>=len) || (ip->protocol != IPPROTO_TCP))
		 return INT_MAX;
	 offset += ip->ihl *4;
	 tcp = data + offset;
	 offset += tcp->doff*4;
	 return offset;
}
