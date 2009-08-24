#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oflops_pcap.h"
#include "utils.h"


void pcap_event_free(pcap_event * pe)
{
	assert(pe);
	free(pe->data);
	free(pe);
}


/***************************************************************************************
 * void oflops_pcap_handler(u_char * pcap_event_wrapper_arg, const struct pcap_pkthdr *h, const u_char *bytes)
 * 	copy the call back info into the pcap_event structure
 */

void oflops_pcap_handler(u_char * pcap_event_wrapper_arg, const struct pcap_pkthdr *h, const u_char *bytes)
{	
	struct pcap_event_wrapper * wrap = (struct pcap_event_wrapper *) pcap_event_wrapper_arg;
	// malloc the event
	wrap->pe = malloc_and_check(sizeof(pcap_event));
	memcpy(&wrap->pe->pcaphdr,h, sizeof(struct pcap_pkthdr));
	// copy the data
	wrap->pe->data = malloc_and_check(h->caplen);
	memcpy(wrap->pe->data, bytes, h->caplen);
}
