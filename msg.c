#include "msg.h"
#include "utils.h"

#define INITIAL_BUF_SIZE 5120

/* 
 * A buffer to store temporary tcp stream data
 */
void *buff[2];
/* 
 * the total size of the buffer
 */
size_t buff_size[2];

/*
 * the size of the data currently in the buffer. 
 */
size_t content_length[2];

#define MAX_OFP_SIZE 10240
struct timeval last_pkt_ts;
struct pcap_event *ofp_msg;

void 
msg_init() {
  buff[0] = xmalloc(INITIAL_BUF_SIZE);
  buff[1] = xmalloc(INITIAL_BUF_SIZE);

  buff_size[0] = INITIAL_BUF_SIZE;
  buff_size[1] = INITIAL_BUF_SIZE;
  content_length[0] = 0;
  content_length[1] = 0;
  ofp_msg = (struct pcap_event *)xmalloc(sizeof(struct pcap_event));
  ofp_msg->data = xmalloc(MAX_OFP_SIZE);
}

void
ofp_init(struct ofp_header *oh, int type, int len) {
  oh->version = OFP_VERSION;
  oh->type = type;
  oh->length = htons(len);
  oh->xid = 0;
}

int
make_ofp_hello(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_HELLO, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}

int
make_ofp_feat_req(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_FEATURES_REQUEST, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}

/*
 * A simple function to strip the ethernet/ip/tcp header from an 
 * openflow packet. 
 * @param b the data of the packet
 * @param len the size of the packet
 */
int 
parse_ip_packet_header(const void *b, int len, struct flow *fl) {
  // assume we have ethernet packets.
  // skip first bytes of the ether because they are
  // in the simple case of static length.
  if (len < sizeof(struct ether_header))
    return -1;
  b = b + sizeof(struct ether_header);
  len -= sizeof(struct ether_header);
  if (len < sizeof(struct iphdr))
    return -1;
  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl)
    return -1;
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;
  
  if(ip_p->protocol != IPPROTO_TCP)
    return -1;
  fl->nw_src = ip_p->saddr;
  fl->nw_dst = ip_p->daddr;
  
  if(len <  sizeof(struct tcphdr))
    return -1;
  struct tcphdr *tcp_p = (struct tcphdr *)b;
  if (len < 4*tcp_p->doff)
    return -1;
  b = b + 4*tcp_p->doff;
  len -=  4*tcp_p->doff;
  fl->tp_src = tcp_p->source;
  fl->tp_dst = tcp_p->dest;
  return sizeof(struct ether_header) + 4*ip_p->ihl + 4*tcp_p->doff;
}

/*
 * A simple function to print the message received for debugging purposes. 
 * @param b The data of the packet we are parsing
 * @param len The size of the packet we received 
 */

/* void */
/* print_ofp_msg(const void *b, size_t len) { */
/*   struct ofp_error_msg *err_p = NULL; */
/*   struct flow fl;  */

/*   //printf("received %d bytes message\n", (int)len); */

/*   //since this is a packet capture, strip packet from all the l1-l4 headers. */
/*   int start = parse_ip_packet_header(b, len, &fl); */

/*   //cast the data of the of packet to the header structure to parse the message */
/*   //typr */
/*   struct ofp_header *ofp = (struct ofp_header *)(b + start); */

/*   //A bit of information about the packet. */
/*   //printf("header_size : %d, version: %d, type: %d, xid:%d \n",  */
/*   //	 start, ofp->version, ofp->type, ofp->xid); */
/*   //based on the message type perform the appropriate analysis.  */
/*   switch(ofp->type) { */
/*   case OFPT_HELLO: */
/*     printf("OFPT_HELLO\n"); */
/*     break; */
/*   case OFPT_ECHO_REPLY: */
/*     printf("OFPT_ECHO_REPLY\n"); */
/*     break; */
/*   case OFPT_ECHO_REQUEST: */
/*     printf("OFPT_ECHO_REQUEST\n"); */
/*     break; */
/*   case OFPT_FEATURES_REPLY: */
/*     printf("OFPT_FEATURES_REPLY\n"); */
/*     break; */
/*   case OFPT_STATS_REQUEST: */
/*     printf("OFPT_STATS_REQUEST\n"); */
/*     break; */
/*   case OFPT_STATS_REPLY: */
/*     printf("OFPT_STATS_REPLY\n"); */
/*     break; */
/*   case OFPT_ERROR: */
/*     err_p = (struct ofp_error_msg *)(b + start); */
/*     printf("OFPT_ERROR(type: %d, code: %d)\n",  */
/* 	   ntohs(err_p->type), ntohs(err_p->code)); */
/*     break; */
/*   default: */
/*     printf("Unimplemented message code: %d\n", ofp->type); */
/*   } */
/*   return; */
/* } */

/*
 * A function the creates a simple flow modification message 
 * based on the content of the  flow structure and the mask details.
 * @param ofp The bufer where we create the packet.
 * @param command the type of message we want to create. 
 * @param flow The flow structure from we create the match rule.
 * @param mask T
 */
int
make_flow_mod(void *ofp, uint16_t command, uint32_t len, 
	      struct flow *flow) {
  struct ofp_flow_mod *ofm = ofp;
  memset(ofp, 0, len);
  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(len);
  ofm->match.wildcards = htonl(flow->mask);
  ofm->match.in_port = flow->in_port;
  memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
  memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
  ofm->match.dl_vlan = flow->dl_vlan;
  ofm->match.dl_type = flow->dl_type;
  ofm->match.nw_src = flow->nw_src;
  ofm->match.nw_dst = flow->nw_dst;
  ofm->match.nw_proto = flow->nw_proto;
  ofm->match.tp_src = flow->tp_src;
  ofm->match.tp_dst = flow->tp_dst;
  ofm->command = htons(command);
  return 0;
}

int
append_data_to_flow(const  void *b, struct pcap_pkthdr hdr) {
  size_t len = hdr.caplen;
  //struct ofp_header *ofp = NULL;
  struct flow fl;
  int dir = 0;
  
  //since this is a packet capture, strip packet from all the l1-l4 headers.
  int start = parse_ip_packet_header(b, len, &fl);
  if(ntohs(fl.tp_src) < ntohs(fl.tp_dst))
    dir = 1; //switch to controller 
  if(len - start == 0) 
    return -1;

  b += start;
  len -= start;
  while(buff_size[dir] < content_length[dir] + len) {
    buff_size[dir] += INITIAL_BUF_SIZE;
    buff[dir] = realloc(buff[dir], buff_size[dir]);
  }
  //append new packet to the buffer
  memcpy(buff[dir] + content_length[dir], b, len);
  content_length[dir] += len;
  
  last_pkt_ts.tv_sec = hdr.ts.tv_sec;
  last_pkt_ts.tv_usec = hdr.ts.tv_usec;

  return dir;
}

int 
contains_next_msg(int dir) {
  if ((dir < 0) || (dir > 1))
     return 0;
  struct ofp_header *ofp = (struct ofp_header *)buff[dir];
  if ((content_length[dir] >= sizeof(struct ofp_header)) 
      && (ntohs(ofp->length) <= content_length[dir]))
	  return 1;
  return 0;
}


/*
 * @TODO : the function breaks if retransmition occur. A better approach should be used
 * that takes under consideration the window. 
 */
int 
get_next_msg(int dir, struct pcap_event **pe) {
  int count = 0;
  struct ofp_header *ofp =  buff[dir];

  if ((content_length[dir] < sizeof(struct ofp_header)) 
      || (ntohs(ofp->length) > content_length[dir]))
    return -1;
  
  assert(ntohs(ofp->length));
  count = ntohs(ofp->length);
  *pe = ofp_msg;
  memcpy(ofp_msg->data, buff[dir], count);
  (*pe)->pcaphdr.len = count;
  (*pe)->pcaphdr.caplen = count;
  memcpy(&ofp_msg->pcaphdr.ts, &last_pkt_ts, sizeof(struct timeval));
  content_length[dir] -= count;
  memmove(buff[dir], buff[dir] + count,  content_length[dir]);

  return count;
}


int
ofp_msg_log(const void *b, struct pcap_pkthdr hdr) {
  size_t len = hdr.caplen;
  struct ofp_error_msg *err_p = NULL;
  struct ofp_header *ofp = NULL;
  int ret = GENERIC_MSG;
  struct flow fl;

  struct ofp_stats_request *reqp = NULL;
  struct ofp_stats_reply *repp = NULL;
  int count = 0;
  //random inary value to distinguish wether the packet is from the larger
  //port number to the lowest or vice versa. 
  int dir = 0; //client to server

  //since this is a packet capture, strip packet from all the l1-l4 headers.
  int start = parse_ip_packet_header(b, len, &fl);
  if(ntohs(fl.tp_src) < ntohs(fl.tp_dst))
    dir = 1; //server to client 
  if(len - start == 0) {
    //printf("no data in tcp packet\n");
    return -1;
  }
  //printf("initial length: %d, packet length = %d, direction: %d\n", content_length[dir], len - start, dir);

  b += start;
  len -= start;
  while(buff_size[dir] < content_length[dir] + len) {
    buff_size[dir] += INITIAL_BUF_SIZE;
    buff[dir] = realloc(buff[dir], buff_size[dir]);
  }
  //append new packet to the buffer
  memcpy(buff[dir] + content_length[dir], b, len);
  content_length[dir] += len;

  ofp = (struct ofp_header *)buff[dir];

  while((content_length[dir] - count >= sizeof(struct ofp_header)) 
	&& (ntohs(ofp->length) <= (content_length[dir] - count))) {
    //printf("start length: %d, count: %d, length: %d\n", ntohs(ofp->length), count, (content_length[dir] - count));
    assert(ntohs(ofp->length));
//	exit(1);
    switch(ofp->type) {
    case OFPT_HELLO:
      //printf("ofp hello\n");
      oflops_log(hdr.ts, OFPT_HELLO_MSG, "hello message");
      ret = OFPT_HELLO_MSG;
      break;
    case OFPT_STATS_REQUEST:
      reqp = (struct ofp_stats_request *) ofp;
      //printf("stats request\n");
      if (ntohs(reqp->type) == OFPST_FLOW) {
        oflops_log(hdr.ts, OFPT_STATS_REQUEST_FLOW, "stats request send");
        ret = OFPT_STATS_REQUEST_FLOW;
      } 
      break;
    case OFPT_STATS_REPLY:
      repp = (struct ofp_stats_reply *) ofp;
      printf("stats reply\n");
      if (ntohs(repp->type) == OFPST_FLOW) {
        oflops_log(hdr.ts, OFPT_STATS_REPLY_FLOW, "flow stats reply received");
        ret = OFPT_STATS_REPLY_FLOW;
      } else if (ntohs(repp->type) == OFPST_PORT) {
        oflops_log(hdr.ts, OFPT_STATS_REPLY_PORT, "port stats reply received");
        ret = OFPT_STATS_REPLY_PORT;
      }
      break;
    case OFPT_ERROR:
      err_p = (struct ofp_error_msg *)ofp;
      char *msg = xmalloc(sizeof("OFPT_ERROR(type: XXXXXXXXXX, code: XXXXXXXXXX)"));
      sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
      oflops_log(hdr.ts, OFPT_ERROR_MSG, msg);
      ret = OFPT_ERROR_MSG;
      break;   
    //default:
    //  printf("msg type: %d, length: %d, code: %d\n", ofp->type, ntohs(ofp->length), count);
    }  
    count += ntohs(ofp->length);
    ofp = (struct ofp_header *)(buff[dir] + count);
    //printf("end length: %d, count: %d, length: %d\n", ntohs(ofp->length), count, (content_length[dir]- count));
  }

  //need to rearrange buffer
  if(count < content_length[dir]) {
    memmove(buff[dir], buff[dir] + count, (content_length[dir] - count));
    content_length[dir] -= count;
  } else
    content_length[dir] = 0;
  return ret;
}

/*
 * This function can be used to create a flow modification message that creates
 * a match regarding the source and destination i pgiven as parameters. The packet 
 * matched is forwarded to the out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param dst_ip a string of the destination ip to which the rule will reference. 
 */
int
make_ofp_flow_add(void **buferp, struct flow *fl, uint32_t out_port,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action_output);
  struct ofp_action_output *p = NULL;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_ADD, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  p = (struct ofp_action_output *)ofm->actions;
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  ofm->command = htons(OFPFC_ADD);
  p->type = htons(OFPAT_OUTPUT);
  p->len = htons(8);
  p->port = htons(out_port);
  p->max_len = htons(0);
  return len;
}

int
make_ofp_flow_modify(void **buferp, struct flow *fl, char *actions,  uint16_t action_len,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + action_len;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_ADD, len, fl) < 0 ) 
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  memcpy(ofm->actions, actions, action_len);
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  //add is the approach to this problem
  ofm->command = htons(OFPFC_ADD);
  //  p->type = htons(OFPAT_OUTPUT);
  //  p->len = htons(8);
  //  p->port = htons(out_port);
  //  p->max_len = htons(0);
  return len;
}


/*
 * This function can be used to create a flow modification message that creates
 * a match regarding the source and destination i pgiven as parameters. The packet 
 * matched is forwarded to the out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param dst_ip a string of the destination ip to which the rule will reference. 
 */
int
make_ofp_flow_del(void **buferp) {
  // the field I am interested to check on the TCAM
  uint32_t mask = OFPFW_ALL;

  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod);
  *buferp = xmalloc(len);
  struct ofp_flow_mod *ofm = *buferp;
  memset(ofm, 0, len);

  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(len);

  ofm->match.wildcards = htonl(mask);

  ofm->idle_timeout = 0;
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1);
  ofm->priority = htons(32768);
  ofm->command = htons(OFPFC_DELETE);
  ofm->out_port = htons(OFPP_NONE); //htons(OFPP_NONE); //

  return len;
}



int
make_ofp_flow_get_stat(void **buferp, int trans_id) {
  struct ofp_flow_stats_request *reqp = NULL;
  struct ofp_stats_request *headp = NULL;
  
  int len = sizeof(struct ofp_stats_request) + sizeof(struct ofp_flow_stats_request);

  //allocate memory
  *buferp = xmalloc(len);
  memset(*buferp, 0, len);
  headp =  (struct ofp_stats_request *)*buferp;

  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(len);
  headp->header.xid = htonl(trans_id);
  headp->type = htons(OFPST_FLOW);

  reqp = (struct ofp_flow_stats_request *)(*(buferp)+sizeof(struct ofp_stats_request));
  reqp->match.wildcards = htonl(OFPFW_ALL);
  reqp->table_id = 0xFF;
  reqp->out_port = OFPP_NONE;

  return len;
  
}

int 
make_ofp_port_get_stat(void **buferp) {
#if OFP_VERSION == 0x97
  struct ofp_stats_request *headp = NULL;
  *buferp = xmalloc(sizeof(struct ofp_stats_request));
  headp =  (struct ofp_stats_request *)*buferp;
  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(sizeof(struct ofp_stats_request));
  headp->type = htons(OFPST_PORT);
  return sizeof(struct ofp_stats_request);
#elif OFP_VERSION == 0x01  
  struct ofp_stats_request *headp = NULL;
  struct ofp_port_stats_request *port = NULL;
  int len = sizeof(struct ofp_stats_request) + sizeof(struct ofp_port_stats_request);
  *buferp = xmalloc(len);
  headp =  (struct ofp_stats_request *)*buferp;
  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_STATS_REQUEST;
  headp->header.length = htons(len);
  headp->type = htons(OFPST_PORT);
  port = (struct ofp_port_stats_request *)(*buferp+sizeof(struct ofp_stats_request));
  port->port_no = htons(OFPP_NONE);
  return len;
#endif
} 

char *
generate_packet(struct flow test, size_t len) {
  char *buf = (char *)xmalloc(len); 
  printf("flow:%x\n", test.dl_dst[5]);
  bzero((void *)buf, len);
  if(len < sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
    printf("packet size is too small\n");
    return NULL;
  }

  //ethernet header with default values
  struct ether_vlan_header * eth = (struct ether_vlan_header * ) buf;
  memcpy(eth->ether_dhost, test.dl_dst,  OFP_ETH_ALEN);
  memcpy(eth->ether_shost, test.dl_src,  OFP_ETH_ALEN);
  eth->tpid = htons(0x8100);
  eth->vid = test.dl_vlan>>4;
  eth->ether_type = test.dl_type;
  //ip header with default values
  struct iphdr * ip = (struct iphdr *) (buf + sizeof(struct ether_vlan_header));
  ip->protocol=1;
  ip->ihl=5;
  ip->version=4;
  ip->check = htons(0x9a97);
  //total packet size without ethernet header
  ip->tot_len=htons(len - sizeof(struct ether_vlan_header)); 
  ip->ttl = 10;
  ip->protocol = test.nw_proto; //udp protocol
  ip->saddr = test.nw_src; 
  ip->daddr = test.nw_dst;

  if(test.nw_proto == IPPROTO_UDP) {
    //  case IPPROTO_UDP:
    //udp header with default values
    struct udphdr *udp = (struct udphdr *)
      (buf + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
    udp->source = test.tp_src;
    udp->dest = test.tp_dst;
    udp->len = htons(len - sizeof(struct ether_vlan_header) - sizeof(struct iphdr));
    //   break;
    //default:
  } else {
    printf("unimplemented protocol %x\n", test.nw_proto);
    return NULL;
  }
  return buf;
  
}

uint32_t
extract_pkt_id(const char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct ether_vlan_header *ether_vlan = (struct ether_vlan_header *)b;
  
  //  printf("%x %x\n",ntohl(ether->ether_type),ntohl(ether_vlan->ether_type));

  if( (ntohs(ether->ether_type) == 0x8100) && (ntohs(ether_vlan->ether_type) == 0x0800)) {
    b = b + sizeof(struct ether_vlan_header);
    len -= sizeof(struct ether_vlan_header);
  } else if(ntohs(ether->ether_type) == 0x0800) {
    b = b + sizeof(struct ether_header);
    len -= sizeof(struct ether_header);
  } else {
    return 0;
  }

  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl)
    return 0;
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;
  
  b += sizeof(struct udphdr);
  uint32_t ret = *((uint32_t *)b); 
  return ret;
}
