#ifndef PCAP_TRACK_H
#define PCAP_TRACK_H

#include <pcap.h>
/**** ptrack_list:
 * 	used to map timestamps from pcap to openflow messages
 * 	so that every module doesn't have to do it
 * 	@author: Rob Sherwood
 * 	@date: Tue Apr 28 05:20:09 PDT 2009
 ***/
struct ptrack_list;




//  Create a new ptrack_list; \return new ptrack list
struct ptrack_list *  	ptrack_new();
/// Add a new timestamp to track 
/// @param ptl	A ptrack_list structure
/// @param data Ethernet header pointer from pcap
/// @param len  length of captured data
/// @param hdr  pcap header from pcap
/// @return 	zero... always
int 			ptrack_add_of_entry( struct ptrack_list * ptl, void * data, int len, struct pcap_pkthdr hdr);
/// Lookup a timestamp from the tcp payload data
/// @param ptl	A ptrack_list structure
/// @param data Ethernet header pointer from pcap
/// @param len  length of captured data
/// @param hdr   write timestamp info into *hdr if found
/// @return	zero if not found, one if timestamp found
int 			ptrack_lookup(struct ptrack_list * ptl, void * data, int len, struct pcap_pkthdr * hdr);

/// Free a ptrack_list
void ptrack_free(struct ptrack_list * ptl); 



#endif
