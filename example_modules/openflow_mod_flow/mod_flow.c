#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <math.h>
#include <limits.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>


#include <arpa/inet.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** @ingroup modules
 * Openflow action install.
 * A module to measure delay and swiutching perfomance of the openflow actions.
 * The rate, count and delay then determined.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 * @return name of module
 */
char * name() {
	return "openflow_add_flow";
}

/*
 * TODO:
 * - install singlw default route and at the event start sending the individual flows.
 * 
 */

/** 
 * String for scheduling events
 */
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SNMPGET "snmp get"
#define SEND_ECHO_REQ "send echo request"

//logging filename
#define LOG_FILE "action_aggregate.log"
char *logfile = LOG_FILE;

/** 
 * Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/**
 * Probe packet size
 */
uint32_t pkt_size = 1500;

/** 
 * A variable to inform when the module is over.
 */
int finished, first_pkt = 0;

/**
 * The file where we write the output of the measurement process.
 */
FILE *measure_output;

uint64_t proberate = 100; 
uint64_t datarate = 100; 

/**
 * calculated sending time interval (measured in usec). 
 */
uint64_t probe_snd_interval;
uint64_t data_snd_interval;

int table = 0;
char *network = "192.168.2.0";

//control if a per packet measurement trace is stored
int print = 0;

/**
 * Number of flows to send. 
 */
int flows = 100;
char *cli_param;
int trans_id = 0;
struct flow *fl_probe; 
int send_flow_mod = 0, stored_flow_mod_time = 0;
int count[] = {0,0,0};
struct timeval flow_mod_timestamp, pkt_timestamp;

//char local_mac[] = {0x00, 0x04, 0x23, 0xb4, 0x74, 0x95};
char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;
			    
			    
struct entry echo_data[100];
int echo_data_count = 0;
int *ip_received;
int ip_received_count;

/**
 * Initialization
 * @param ctx pointer to opaque context
 */
int 
start(struct oflops_context * ctx) {  
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  fl_probe = (struct flow*)xmalloc(sizeof(struct flow));
  void *b; //somewhere to store message data
  int res, len, i;
  struct timeval now;
  char msg[1024];

  //init h
  TAILQ_INIT(&head); 

  //Initialize pap-based  tcp flow reassembler for the communication 
  //channel
  msg_init();  
  snprintf(msg, 1024,  "Intializing module %s", name());

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA2].dev,
	 (unsigned char)local_mac[0], (unsigned char)local_mac[1], (unsigned char)local_mac[2], 
	 (unsigned char)local_mac[3], (unsigned char)local_mac[4], (unsigned char)local_mac[5]);
  get_mac_address(ctx->channels[OFLOPS_DATA2].dev, data_mac);

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now,GENERIC_MSG , cli_param);

  //start openflow session with switch
  make_ofp_hello(&b);
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);  
  
  //send a message to clean up flow tables. 
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  res = oflops_send_of_mesg(ctx, b);  
  free(b);
  
  /**
   * Send flow records to start routing packets.
   */
  printf("Sending measurement probe flow...\n");
  bzero(fl, sizeof(struct flow));
  if(table == 0)
    fl->mask = 0; //if table is 0 the we generate an exact match */
  else 
    fl->mask = OFPFW_DL_DST | OFPFW_DL_SRC | (32 << OFPFW_NW_SRC_SHIFT) | 
      (32 << OFPFW_NW_DST_SHIFT) | OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO | 
      OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_type = htons(ETHERTYPE_IP);         
  memcpy(fl->dl_src, data_mac, 6);
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);

  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->tp_src = htons(8080);
  fl->tp_dst = htons(8080);

  uint32_t ip = ntohl(inet_addr(network));
  for(i=0; i< flows; i++) {
    fl_probe->nw_dst =  htonl(ip);
    len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 120);
    oflops_send_of_mesgs(ctx, b, len);
    free(b);
    ip++;
  }

  fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
  memcpy(fl->dl_src, local_mac, 6);
  fl->nw_dst =  inet_addr("10.1.1.2");
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 120);
  res = oflops_send_of_mesg(ctx, b);
  free(b);

  //store locally the probe to manipulate it later during the modification phase
  memcpy(fl_probe, fl, sizeof(struct flow));

  ip_received = xmalloc(flows*sizeof(int));
  memset(ip_received, 0, flows*sizeof(int));
  ip_received_count++;

  /**
   * Shceduling events
   */
  //send the flow modyfication command in 30 seconds. 
  gettimeofday(&now, NULL);
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, SND_ACT);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //end process 
  gettimeofday(&now, NULL);
  add_time(&now, 60, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);
  return 0;
}

int destroy(struct oflops_context *ctx) {
  FILE *out;
  struct entry *np;
  int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
  int ix[] = {0,0,0};

  int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch, i;
  char msg[1024];
  struct timeval now;
  double **data;
  uint32_t mean, std, median;
  float loss;

  //get what time we start printin output
  gettimeofday(&now, NULL);

  //open log file if required
  if(print) {
    out = fopen(logfile, "w");
    if(out == NULL)
      perror_and_exit("fopen_logfile", 1);
  }

  //init tmp data storage
  data = xmalloc(3*sizeof(double *));
  for(ch = 0; ch < 3; ch++) {
    data[ch] = xmalloc(count[ch]*sizeof(double));
  }

  // for every measurement save the delay in the appropriate entry on the 
  // measurement matrix
  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    ch = np->ch - 1;
    min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
    max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
    data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
    //print also packet details on otuput if required
    if(print)
      if(fprintf(out, "%lu;%lu.%06lu;%lu.%06lu;%d\n", 
		 (long unsigned int)np->id,  
		 (long unsigned int)np->snd.tv_sec, 
		 (long unsigned int)np->snd.tv_usec,
		 (long unsigned int)np->rcv.tv_sec, 
		 (long unsigned int)np->rcv.tv_usec,  np->ch) < 0)  
	perror_and_exit("fprintf fail", 1); 

    free(np);
  }
  
  for(ch = 0; ch < 3; ch++) {
    if(ix[ch] > 0) {
      gsl_sort (data[ch], 1, ix[ch]);
      mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
      std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
      median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
      loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);
      
      snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d", 
	       ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
      printf("statistics:port:%d:%u:%u:%u:%.4f:%d\n", 
	     ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
      oflops_log(now, GENERIC_MSG, msg);
    }
  }
  
  free(data[0]);
  data[0] = xmalloc(echo_data_count * sizeof(double));
  for(i = 1; i <= echo_data_count; i++) {
    snprintf(msg, 1024, "OFP_ECHO:%d:%ld.%06ld:%ld.%06ld", i, echo_data[i].snd.tv_sec, echo_data[i].snd.tv_usec, 
	     echo_data[i].rcv.tv_sec, echo_data[i].rcv.tv_usec);
    oflops_log(now, GENERIC_MSG, msg);
    data[0][i-1] = time_diff(& echo_data[i].snd, &echo_data[i].rcv);
  }
  if(echo_data_count > 0) {
    gsl_sort (data[0], 1, echo_data_count);
    mean = (uint32_t)gsl_stats_mean(data[0], 1, echo_data_count);
    std = (uint32_t)sqrt(gsl_stats_variance(data[0], 1, echo_data_count));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[0], 1, echo_data_count);
    printf("statistics:echo:%u:%u:%u:%d\n", mean, median, std, echo_data_count);
    snprintf(msg, 1024, "statistics:echo:%u:%u:%u:%d", mean, median, std, echo_data_count);
    oflops_log(now, GENERIC_MSG, msg);
  }

  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {  
  char *str = te->arg; 
  int len, i;
  void *b;
  struct timeval now;
  struct in_addr ip_addr;

  //terminate process 
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    finished = 0;    
    return 0;    
  } else if (strcmp(str, SND_ACT) == 0) {
    //first create new rules
    send_flow_mod = 1;
    //if(table == 1)
    //  inc = inc << 8;
    if(table == 0)
      fl_probe->mask = 0; //if table is 0 the we generate an exact match */
    else 
      fl_probe->mask = OFPFW_DL_DST | OFPFW_DL_SRC | (32 << OFPFW_NW_SRC_SHIFT) | 
	(32 << OFPFW_NW_DST_SHIFT) | OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO | 
	OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

    memcpy(fl_probe->dl_src, data_mac, 6);
    memcpy(fl_probe->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
    fl_probe->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
    ip_addr.s_addr =  ntohl(inet_addr(network));
    for(i=0; i< flows; i++) {
    fl_probe->nw_dst =  htonl(ip_addr.s_addr);
      len = make_ofp_flow_modify_output_port(&b, fl_probe, OFPP_IN_PORT, 1, 1200);
      oflops_send_of_mesgs(ctx, b, len);
      free(b);
      ip_addr.s_addr++;
    }
    memcpy(fl_probe->dl_src, local_mac, 6);
    fl_probe->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
    fl_probe->nw_dst =  inet_addr("10.1.1.2");
    len = make_ofp_flow_modify_output_port(&b, fl_probe, OFPP_IN_PORT,
					   1, 1200);
    oflops_send_of_mesg(ctx, b);
    free(b);
    printf("sending flow modifications ....\n"); 

  } else if(strcmp(str, SNMPGET) == 0) {
    for(i = 0; i < ctx->cpuOID_count; i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }      
    gettimeofday(&now, NULL);
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  } else if(strcmp(str, SEND_ECHO_REQ) == 0) {
    struct ofp_header *p;
    make_ofp_echo_req(&p);
    p->xid = htonl(++echo_data_count);
    oflops_send_of_mesg(ctx, p);
    free(p);
    gettimeofday(&now, NULL);
    add_time(&now, 4, 0);
    oflops_schedule_timer_event(ctx,&now, SEND_ECHO_REQ);
    
  }
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap * @param buflen length of buffer
 */
int 
get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, 
		char * filter, int buflen) {
  if (ofc == OFLOPS_CONTROL) {
    //return 0;
    return snprintf(filter, buflen, "port %d",  ctx->listen_port);
  } else if ((ofc == OFLOPS_DATA1) ||  (ofc == OFLOPS_DATA2) || (ofc == OFLOPS_DATA3)) {
    return snprintf(filter, buflen, "udp");
  }
  return 0;
}

/** Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int 
handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  int dir, len;
  struct ofp_header *ofp;
  struct pcap_event *ofp_msg;
  struct ofp_error_msg *err_p = NULL;
  char msg[1024];

  if (ch == OFLOPS_CONTROL) {
    dir = append_data_to_flow(pe->data,pe->pcaphdr);
    while(contains_next_msg(dir) > 0) {
      len = get_next_msg(dir, &ofp_msg);
      ofp = (struct ofp_header *)ofp_msg->data;
      switch(ofp->type) {
      case OFPT_FLOW_MOD:
	if((send_flow_mod) && (!stored_flow_mod_time)) {
	  memcpy(&flow_mod_timestamp, &pe->pcaphdr.ts, sizeof(struct timeval));
	  stored_flow_mod_time = 1;
	}
	oflops_log(pe->pcaphdr.ts,OFPT_FLOW_MOD_ADD, "flow modification send");
	break;  
      case OFPT_ERROR:
	err_p = (struct ofp_error_msg *)ofp;
	snprintf(msg, 1024, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
	oflops_log(pe->pcaphdr.ts, OFPT_ERROR_MSG, msg);
	fprintf(stderr, "%s\n", msg);
	break;   
      case  OFPT_ECHO_REQUEST:
	err_p = (struct ofp_error_msg *)ofp;
	printf("%ld.%06ld: OFPT_ECHO_REQUEST %d\n", pe->pcaphdr.ts.tv_sec, pe->pcaphdr.ts.tv_usec, ntohl(ofp->xid));
	if((ntohl(ofp->xid) < 100) && (ntohl(ofp->xid) > 0))
	  memcpy(&echo_data[ntohl(ofp->xid)].snd, &pe->pcaphdr.ts, sizeof(struct timeval));
	break;   
      case  OFPT_ECHO_REPLY:
	err_p = (struct ofp_error_msg *)ofp;
	printf("%ld.%06ld: OFPT_ECHO_REPLY %d\n", pe->pcaphdr.ts.tv_sec, pe->pcaphdr.ts.tv_usec, ntohl(ofp->xid));
	if( (ntohl(ofp->xid) < 100) && (ntohl(ofp->xid) > 0))
	  memcpy(&echo_data[ntohl(ofp->xid)].rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
	break;  
      }
    }
  } else if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA3)) {
    struct flow fl;
    struct timeval now;
    pktgen = extract_pktgen_pkt(pe->data, pe->pcaphdr.caplen, &fl);
    if((ch == OFLOPS_DATA1) && (!first_pkt)) {
      oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "FIRST_PKT_RCV");
      oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
      printf("INSERT_DELAY:%d\n", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
      snprintf(msg, 1024, "INSERT_DELAY:%d", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
      oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
      first_pkt = 1;
      gettimeofday(&now, NULL);
      add_time(&now, 1, 0);
      //oflops_schedule_timer_event(ctx,&now, BYESTR);
    } else if (ch == OFLOPS_DATA2) {
      int id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
      //printf("id %d %x %x\n", id, ntohl(fl.nw_dst),  ntohl(inet_addr(network)));
      if ((id >= 0) && (id < flows) && (!ip_received[id])) {
	ip_received_count++;
	ip_received[id] = 1;
	if (ip_received_count == flows) {
	  gettimeofday(&now, NULL);
	  add_time(&now, 1, 0);
	  oflops_schedule_timer_event(ctx,&now, BYESTR);
	  printf("Received all packets to channel 2\n");
	  oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "LAST_PKT_RCV");
	  oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);

	  printf("COMPLETE_INSERT_DELAY:%u\n", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
	  snprintf(msg, 1024, "INSERT_DELAY:%u", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
	  oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
	}
      }
    }
    if(htonl(pktgen->seq_num) % 100000 == 0)
      printf("data packet received %d\n", htonl(pktgen->seq_num));
    
    struct entry *n1 = malloc(sizeof(struct entry));
    n1->snd.tv_sec = htonl(pktgen->tv_sec);
    n1->snd.tv_usec = htonl(pktgen->tv_usec);
    memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    n1->id = htonl(pktgen->seq_num);
    n1->ch = ch;
    count[ch - 1]++;
    TAILQ_INSERT_TAIL(&head, n1, entries);
  }
  return 0;
}

int 
of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * pkt_in) {  
  switch(pkt_in->reason) {
  case  OFPR_NO_MATCH:
  /*   printf("OFPR_NO_MATCH: %d bytes\n", ntohs(pkt_in->total_len)); */
    break; 
  case OFPR_ACTION:
    printf("OFPR_ACTION: %d bytes\n", ntohs(pkt_in->total_len));
    break;
  default:
    printf("Unknown reason: %d bytes\n", ntohs(pkt_in->total_len));
  }
  return 0;
}

int 
of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  void *b;
  int res;

  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);
  return 0;
}

int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024, i;
  char msg[1024], log[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(log, len, "cpu:%ld:%d:%s",
		 se->pdu->reqid, 
		 (int)vars->name[ vars->name_length - 1], msg);
	oflops_log(now, SNMP_MSG, log);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,  
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(log, len, "port:rx:%ld:%d:%s",  
		 se->pdu->reqid, 
		 (int)(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
	
      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,  
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(log, len, "port:tx:%ld:%d:%s",  
		 se->pdu->reqid, 
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	//	printf("port %d : tx %s pkts\n",  (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip_addr;

  //background data
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.2.0");

  ip_addr.s_addr = ntohl(inet_addr("192.168.2.0"));
  //if(table == 1)
  //  ip_addr.s_addr += ((flows-1) << 8);
  //else 
  ip_addr.s_addr += (flows-1);
  ip_addr.s_addr = htonl(ip_addr.s_addr);
  //str_ip = inet_ntoa(ip_addr);
  strcpy(det.dst_ip_max,  inet_ntoa(ip_addr));
  strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA2, &det);

  init_traf_gen(ctx);
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  strcpy(det.mac_src,"00:00:00:00:00:00");
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = probe_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);  
  
  start_traffic_generator(ctx);
  return 1;
}

/**
 * Initialization code with parameters
 * @param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  //init counters
  finished = 0;

  gettimeofday(&now, NULL);

  cli_param = strdup(config_str);


  while(*config_str == ' ') {
    config_str++;
  }
  param = config_str;
  while(1) {
    pos = index(param, ' ');

    if((pos == NULL)) {
      if (*param != '\0') {
        pos = param + strlen(param) + 1;
      } else
        break;
    }
    *pos='\0';
    pos++;
    value = index(param,'=');
    *value = '\0';
    value++;
    //fprintf(stderr, "param = %s, value = %s\n", param, value);
    if(value != NULL) {
      if(strcmp(param, "pkt_size") == 0) {
        //parse int to get pkt size
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
          perror_and_exit("Invalid packet size value", 1);
      }  else if(strcmp(param, "probe_rate") == 0) {
        //parse int to get measurement probe rate
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) 
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
      }  else if(strcmp(param, "data_rate") == 0) {
        //parse int to get measurement probe rate
        datarate = strtol(value, NULL, 0);
        if((datarate <= 0) || (datarate >= 1010)) 
          perror_and_exit("Invalid data rate param(Value between 1 and 1010)", 1);
      } else if(strcmp(param, "table") == 0) {
	//parse int to get pkt size
        table = strtol(value, NULL, 0);
        if((table < 0) && (table > 2))  
          perror_and_exit("Invalid table number", 1);
      } else if(strcmp(param, "flows") == 0) {
	//parse int to get pkt size
        flows = strtol(value, NULL, 0);
        if(flows <= 0)  
          perror_and_exit("Invalid flow number", 1);
      } else if(strcmp(param, "print") == 0) {
	//parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else 
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  } 

  //calculate sendind interval
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  return 0;
}
