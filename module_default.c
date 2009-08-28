
#include "module_default.h"

// Set of default operations for modules; just NOOPs

int default_module_init(char * init)
{
	return 0;
}

int default_module_get_pcap_filter(oflops_channel ofc, char * filter, int buflen)
{
	return 0;
}


int default_module_start(struct oflops_context * ctx)
{
	return 0;
}


int default_module_pcap_event(struct pcap_event * pe, oflops_channel ch)
{
	return 0;
}



int default_module_of_event_packet_in(struct ofp_packet_in * pktin)
{
	return 0;
}



#if OFP_VERSION == 0x97
	int default_module_of_event_flow_removed(struct ofp_flow_expired * ofph)
#elif OFP_VERSION == 0x98
	int default_module_of_event_flow_removed(struct ofp_flow_removed * ofph)
#else
#error "Unknown version of openflow"
#endif
{
	return 0;
}

int default_module_of_event_port_status(struct ofp_port_status * ofph)
{
	return 0;
}
int default_module_of_event_other(struct ofp_header * ofph)
{
	return 0;
}
int default_module_timer_event(struct timer_event * te)
{
	return 0;
}
