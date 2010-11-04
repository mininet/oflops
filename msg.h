#ifndef MSG_H
#define MSG_H 1

#ifndef  __BYTE_ORDER
    #define  __BYTE_ORDER == __LITTLE_ENDIAN
    #define __LITTLE_ENDIAN_BITFIELD 1
#endif

#include <stdint.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <openflow/openflow.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "test_module.h"
#include "log.h"
#include "utils.h"

//packet header size including ethernet/ip/udp
#define MEASUREMENT_PACKET_HEADER 46 

struct flow {
  uint32_t mask;              /* The mask used to define 
				 which fields will be matched */
  uint16_t in_port;           /* Input switch port. */
  uint8_t dl_src[6];          /* Ethernet source address. */
  uint8_t dl_dst[6];          /* Ethernet destination address. */
  uint16_t dl_vlan;           /* Input VLAN. */
  uint16_t dl_type;           /* Ethernet frame type. */
  uint32_t nw_src;            /* IP source address. */
  uint32_t nw_dst;            /* IP destination address. */
  uint8_t nw_proto;           /* IP protocol. */
  uint16_t tp_src;            /* TCP/UDP source port. */
  uint16_t tp_dst;            /* TCP/UDP destination port. */
  uint8_t reserved;           /* Pad to 32-bit alignment. */
};

struct ether_vlan_header {  
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t tpid;
  uint8_t pcp:3;
  uint8_t cfi:1;
  uint16_t vid:12;
  u_int16_t ether_type;                 /* packet type ID field */
};

struct net_header{
  struct ether_header *ether;
  struct ether_vlan_header *ether_vlan;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp; 
};

void* xmalloc(size_t len);

int make_ofp_hello(void **b);
int make_ofp_feat_req(void **b);
int make_ofp_flow_stat(void **b);
int make_ofp_flow_add(void **buferp,  struct flow *fl, uint32_t out_port, 
		      uint32_t buffer_id, uint16_t idle_timeout);

int make_ofp_flow_modify(void **buferp, struct flow *fl, 
			 char *actions,  uint16_t action_len, uint32_t buffer_id, 
			 uint16_t idle_timeout);

int make_ofp_flow_del(void **buferp);
int make_ofp_flow_get_stat(void **buferp, int xid);
int make_ofp_port_get_stat(void **buferp);

int append_data_to_flow(const  void *b, struct pcap_pkthdr hdr);
int contains_next_msg(int dir);
int get_next_msg(int dir, struct pcap_event **opf);

//void print_ofp_msg(const void *b, size_t len);

void msg_init();
int ofp_msg_log(const void *b,  struct pcap_pkthdr hdr);
char *generate_packet(struct flow fl, size_t len);
uint32_t extract_pkt_id(const char *b, int len);

#endif

