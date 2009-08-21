#ifndef OFLOPS_PCAP_H
#define OFLOPS_PCAP_H

#include <pcap.h>

struct pcap_event;

#include "test_module.h"

typedef struct pcap_event
{
	oflowps_channel channel;
	const struct pcap_pkthdr pcaphdr;
	// NOTE: full packet capture NOT guaranteed; need to check pcaphdr to see
	// 	how much was captured
	unsigned char * data;
} pcap_event;

#endif
