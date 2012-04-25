#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <math.h>
#include <limits.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** @ingroup modules
 * Packet in module.
 * The module sends packet into a port to generate packet-in events.
 * The rate, count and delay then determined.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 * @return name of module
 */
char * name() {
	return "openflow_action_measurement";
}

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define GETPORTSTAT "port stat"
#define SND_ACT "send action"
#define SND_FALSE_ACT "send false action"
#define SND_PKT "send pkt"
#define SNMPGET "snmp get"
#define OFP_PING "of ping"

//logging filename
#define LOG_FILE "action_generic.log"

/** Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/** packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/** Send sequence
 */
uint32_t sendno;

/**
 * Probe packet size
 */
uint32_t pkt_size = 1500;

/**
 * Buffer to store the content of the action of the flow mod message.
 */
void *command = NULL;
int command_len = 0;

/** A variable to inform when the module is over.
 */
int finished, first_pkt = 0;

/** The file where we write the output of the measurement process.
 */
FILE *measure_output;

uint64_t datarate = 100;
uint64_t proberate = 100; 

/**
 * calculated sending time interval (measured in usec). 
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

int table = 0; 
char *network = "192.168.3.0";
int send_mod = 0; //a flag that we send the modification rule to the switch
int send_false_mod = 0; //a flag that we send the modification rule to the switch


int count[] = {0,0,0}; // counting how many packets where received over a 
                       // specific channel
/**
 * Number of flows to send. 
 */
int flows = 100;

/**
 * storing the argument list passed to the module
 */
char *cli_param;
char *logfile = LOG_FILE;
int print = 0;

int trans_id = 0;

//the local mac address of the probe 
char probe_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/**
 *  Storing the details for the of_ping
 */
struct timeval ofp_ping_timestamp[100];
struct timeval false_modification, true_modification;
double delay[100];
uint32_t delay_false_modificaton,  delay_modificaton;

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;

int is_hex(const char *data, int len);
uint8_t read_hex(const char *data);
int append_action(int action, const char *action_param);
uint32_t extract_pkt_id(const char *b, int len);

struct flow *fl_probe; 

/** Initialization
 * @param ctx pointer to opaque context
 */
int 
start(struct oflops_context * ctx) {  
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  fl_probe = (struct flow*)xmalloc(sizeof(struct flow));
  void *b; //somewhere to store message data
  int res, len, i;
  struct timeval now;
  struct in_addr ip_addr;

  //init measurement queue
  TAILQ_INIT(&head); 

  //init logging service
  msg_init();

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now,GENERIC_MSG , "Intializing module openflow_action_measurement");
  oflops_log(now,GENERIC_MSG , cli_param);

  //make filedescriptor blocking
  int saved_flags = fcntl(ctx->control_fd, F_GETFL);
  fcntl(ctx->control_fd, F_SETFL, saved_flags & ~O_NONBLOCK);

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA1].dev,
	 (unsigned char)data_mac[0], (unsigned char)data_mac[1], 
	 (unsigned char)data_mac[2], (unsigned char)data_mac[3], 
	 (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

  get_mac_address(ctx->channels[OFLOPS_DATA2].dev, probe_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA2].dev,
	 (unsigned char)probe_mac[0], (unsigned char)probe_mac[1], 
	 (unsigned char)probe_mac[2], (unsigned char)probe_mac[3], 
	 (unsigned char)probe_mac[4], (unsigned char)probe_mac[5]);


  make_ofp_hello(&b);
  //res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  res = write(ctx->control_fd, b, sizeof(struct ofp_hello));
  free(b);  

  // send a feature request to see what the switch can do and os that the connection
  // is kept open.
  make_ofp_feat_req(&b);
  //res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  res = write(ctx->control_fd, b, sizeof(struct ofp_hello));
  free(b);
  
  //send a message to clean up flow tables. 
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  res = write(ctx->control_fd, b, res);
  free(b);
  
  /**
   * Send flow records to start routing packets.
   */
  printf("Sending new flow rules...\n");
  bzero(fl, sizeof(struct flow));
  printf("table value:%d\n", table);
  if(table == 0) 
     fl->mask = 0; //if table is 0 the we generate an exact match */
  else  
    fl->mask = OFPFW_IN_PORT | OFPFW_DL_VLAN | OFPFW_TP_DST;
  fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
  fl->dl_type = htons(ETHERTYPE_IP);          
  memcpy(fl->dl_src, probe_mac, ETH_ALEN);
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);            
  fl->tp_dst = htons(8080);  
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA1].of_port, 1, 1200);
  res = write(ctx->control_fd, b, len);
  free(b);
  
  //storelocally the applied rule of the data stream
  memcpy(fl_probe, fl, sizeof(struct flow));

  ip_addr.s_addr = inet_addr(network);
  ip_addr.s_addr =  ntohl(ip_addr.s_addr);
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_vlan = 0xffff;
  fl->dl_src[5] = 0x74;  
  memcpy(fl->dl_src, data_mac, ETH_ALEN);
  memcpy(fl->dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN);
  fl->mask = 0;
  for(i=0; i< flows; i++) {
    ip_addr.s_addr += 1;
    fl->nw_dst =  htonl(ip_addr.s_addr);
    len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 2, 1200);
    res = write(ctx->control_fd, b, len);
    free(b);
  }
  
  len = make_ofp_port_get_stat(&b);
  free(b);

  saved_flags = fcntl(ctx->control_fd, F_GETFL);
  fcntl(ctx->control_fd, F_SETFL, saved_flags & O_NONBLOCK);

  /**
   * Shceduling events
   */
  //SND_FALSE_ACT
  gettimeofday(&now, NULL);
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, SND_FALSE_ACT);


  //send the flow modyfication command in 30 seconds. 
  gettimeofday(&now, NULL);
  add_time(&now, 30, 0);
  oflops_schedule_timer_event(ctx,&now, SND_ACT);

  //action of ping request 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, OFP_PING);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 10, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  //end process 
  gettimeofday(&now, NULL);
  add_time(&now, 60, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);
  return 0;
}

int 
destroy(struct oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  FILE *out = fopen(logfile, "w");
  struct entry *np;
  int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
  int ix[] = {0,0,0};
  int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch, xid;
  uint32_t mean, std, median;
  float loss;
  double **data;

  gettimeofday(&now, NULL);
  printf("destroying code\n");
  snprintf(msg, 1024, "OFPT_ERROR_DELAY:%lu", (long unsigned)delay_false_modificaton);
  oflops_log(now, GENERIC_MSG, msg);
  snprintf(msg, 1024, "OFPT_INSERT_DELAY:%lu", (long unsigned)delay_modificaton);
  oflops_log(now, GENERIC_MSG, msg);

  //insert delay
  data = xmalloc(3*sizeof(double *));
  for(ch = 0; ch < 3; ch++) 
    data[ch] = xmalloc(count[ch]*sizeof(double));

  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    ch = np->ch - 1;
    min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
    max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
    data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
    if(print)
      if(fprintf(out, "%lu;%lu.%06lu;%lu.%06lu;%d\n", 
		 (long unsigned int)np->id,  
		 (long unsigned int)np->snd.tv_sec, 
		 (long unsigned int)np->snd.tv_usec,
		 (long unsigned int)np->rcv.tv_sec, 
		 (long unsigned int)np->rcv.tv_usec,  np->ch) < 0)  
	perror_and_exit("fprintf fail", 1); 

    //release memory
    free(np);
  }

  for(ch = 0; ch < 3; ch++) {
    if(ix[ch] == 0) continue;
    gsl_sort (data[ch], 1, ix[ch]);
    mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
    std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
    loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);

    //print summarization data
    snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d", 
	     ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
    printf("statistics:port:%d:%u:%u:%u:%.4f:%d\n", 
	   ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
    oflops_log(now, GENERIC_MSG, msg);
  }

  //print echo delay per packet information 
  if(print) {
    for (xid = 1 ; xid < trans_id; xid++) {
      snprintf(msg, 1024, "%u", (uint32_t)delay[xid]);
      oflops_log(now, OFPT_ECHO_REPLY_MSG, msg);
    }
  }

  //claculate echo statistcs
  gsl_sort (delay, 1, (trans_id - 1));
  mean = (uint32_t)gsl_stats_mean(delay, 1, (trans_id - 1));
  std = (uint32_t)sqrt(gsl_stats_variance(delay, 1, (trans_id - 1)));
  median = (uint32_t)gsl_stats_median_from_sorted_data (delay, 1, (trans_id - 1));

  printf("statistics:echo:%u:%u:%u:%d\n", mean, median, std, (trans_id-1));
  snprintf(msg, 1024, "statistics:echo:%u:%u:%u:%d", mean, median, std, (trans_id - 1));
  oflops_log(now, GENERIC_MSG, msg);
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
  struct ofp_flow_mod *ofp;
  struct ofp_header *ofph;

  //terminate process 
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    finished = 0;
    return 0;    
  } else if(strcmp(str, OFP_PING) == 0) {
    len = make_ofp_hello(&b);
    ofph = (struct ofp_header *)b;
    ofph->type = OFPT_ECHO_REQUEST;
    ofph->xid = htonl(trans_id++);
    oflops_send_of_mesgs(ctx, b, len);
    free(b);
    gettimeofday(&now, NULL);
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx,&now, OFP_PING);


  } else if  (strcmp(str, SND_FALSE_ACT) == 0) {
    struct ofp_action_output *cmd;
    int cmd_len;
    uint32_t tmp = fl_probe->nw_src;
    fl_probe->nw_src = inet_addr("10.5.5.5");
    cmd_len = sizeof(struct ofp_action_output);
    cmd = (struct ofp_action_output *)xmalloc(cmd_len);
    cmd->type = htons(0);
    cmd->len = htons(8);
    cmd->max_len = htons(0);
    cmd->port = htons(50);
    len = make_ofp_flow_modify(&b, fl_probe, (char *)cmd, cmd_len, 
			       1, 1200);
    ofp = (struct ofp_flow_mod *) b;
    ofp->buffer_id = htonl(1);
    send_false_mod= 1;
    printf("sending false modification to measure delay\n");
    oflops_send_of_mesg(ctx, b);
    free(b);
    free(cmd);
    fl_probe->nw_src = tmp;
  } else if (strcmp(str, SND_ACT) == 0) {
    len = make_ofp_flow_modify(&b, fl_probe, command, command_len, 
			       1, 1200);
    send_mod= 1;
    oflops_send_of_mesg(ctx, b);
    free(b);
    printf("sending correct modification to measure delay\n");
  } else if(strcmp(str, SNMPGET) == 0) {
    for(i=0;i<ctx->cpuOID_count;i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }    
    gettimeofday(&now, NULL);
    add_time(&now, 10, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
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
  } else if((ofc == OFLOPS_DATA1) || (ofc == OFLOPS_DATA2) || (ofc == OFLOPS_DATA3)) {
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
	if (send_false_mod) {
	  if(send_mod) {
	    memcpy(&true_modification, &pe->pcaphdr.ts, sizeof(struct timeval));
	  } else {
	    memcpy(&false_modification, &pe->pcaphdr.ts, sizeof(struct timeval));
	  }
	}
	if(send_mod) {
	  oflops_log(pe->pcaphdr.ts,OFPT_FLOW_MOD_ADD, "flow modification send");
	}
	break;
      case OFPT_ECHO_REQUEST:
	if(ntohl(ofp->xid) < 100) 
	  memcpy(&ofp_ping_timestamp[ntohl(ofp->xid)], &pe->pcaphdr.ts, sizeof(struct timeval));
	break;
      case OFPT_ECHO_REPLY:
	if(ntohl(ofp->xid) < 100 && ntohl(ofp->xid) > 0) {
	  delay[ntohl(ofp->xid)] = time_diff(&ofp_ping_timestamp[ntohl(ofp->xid)], &pe->pcaphdr.ts);
	}
	break;    
      case OFPT_ERROR:
	err_p = (struct ofp_error_msg *)ofp;
	if(send_false_mod)  {
	  delay_false_modificaton = time_diff(&false_modification, &pe->pcaphdr.ts);
	} else {
	  snprintf(msg, 1024, "%d:%d", ntohs(err_p->type), ntohs(err_p->code));
	  oflops_log(pe->pcaphdr.ts, OFPT_ERROR_MSG, msg);
	  fprintf(stderr, "OFPT_ERROR_MSG:%s\n", msg);
	  break;   
	}
      }
    }
  } else if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA3)) {
    struct flow fl;
    pktgen = extract_pktgen_pkt(pe->data, pe->pcaphdr.caplen, &fl);
    if((ch == OFLOPS_DATA3) && (!first_pkt)) {
      delay_modificaton = time_diff(&true_modification, &pe->pcaphdr.ts);
      oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "PACKET_NEW_PORT");
      //printf("first packet on new port\n");
      first_pkt = 1;
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
of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}

int 
of_event_port_status(struct oflops_context *ctx, const struct ofp_port_status * ofph) {   
  return 0;
}

int 
of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  void *b;
  int res;
  switch(ofph->type) {
  case OFPT_ECHO_REQUEST:
    make_ofp_hello(&b);
    ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
    res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);
  }
  return 0;
}

int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024;
  char msg[1024], out_buf[1024];
  struct timeval now;
  int i;
  gettimeofday(&now, NULL);

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);
    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(out_buf, len, "cpu : %s %%", msg);
	oflops_log(now, SNMP_MSG, out_buf);
      }
    } 

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,  
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(out_buf, len, "port %d : rx %s pkts",  
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, out_buf);
	break;
      }
      
      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,  
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(out_buf, len, "port %d : tx %s pkts",  
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, out_buf);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  char *str_ip;
  struct in_addr ip;

  init_traf_gen(ctx);
  if (data_snd_interval > 0) { 
    strcpy(det.src_ip,"10.1.1.1");
    strcpy(det.dst_ip_min,"192.168.3.1");
    ip.s_addr = ntohl(inet_addr("192.168.3.1"));
    ip.s_addr += flows;
    ip.s_addr = htonl(ip.s_addr);
    str_ip = inet_ntoa(ip);
    strcpy(det.dst_ip_max, str_ip);
    //strcpy(det.mac_src,"00:1e:68:9a:c5:74");
    strcpy(det.mac_src,"00:00:00:00:00:00");
    strcpy(det.mac_dst,"00:1e:68:9a:c5:75");
    det.vlan = 0xffff;
    det.vlan_p = 1;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = pkt_size;
    det.delay = data_snd_interval*1000;
    strcpy(det.flags, "IPDST_RND");
    add_traffic_generator(ctx, OFLOPS_DATA1, &det);  
  }

  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  //strcpy(det.mac_src,"00:1e:68:9a:c5:75");
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
  add_traffic_generator(ctx, OFLOPS_DATA2, &det);  
  
  start_traffic_generator(ctx);
  return 1;
}


/*
 * read the first 2 hex characters and return the byte.
 */
uint8_t
read_hex(const char *data) {
  uint8_t ret = 0;
  int i;

  for(i = 0 ; i < 2 ; i++) {
    ret = ret << 4;
    if((*data >= 'A') && (*data <= 'F')) {
      ret += 10 + (*data - 'A');
    } else if((*data >= 'a') && (*data <= 'f')) {
      ret += 10 + ((*data) - 'a');
    } else if((*data >= '0') && (*data <= '9')) {
      ret += ((*data) - '0');
    }
    data++;
  }
  return ret;
}

/**
 * Initialization code with parameters
 * @param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  int len = strlen(config_str);
  char *value = NULL;
  char *action;

  //init counters
  finished = 0;

  struct timeval now;
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
      } else if(strcmp(param, "data_rate") == 0) {
        //parse int to get rate of background data
        datarate = strtol(value, NULL, 0);
        if((datarate < 0) || (datarate > 1010))
          perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
      }  else if(strcmp(param, "probe_rate") == 0) {
        //parse int to get measurement probe rate
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) 
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
      }  else if(strcmp(param, "action") == 0) {
	char *p = value;
	while((*p != ' ') && (*p != '\0') && (config_str + len > p)) {
	  action = p;
	  //find where value ends and set it to null to extract the string.
	  p = index(p, ',');
	  if(p == NULL) {
	    p = config_str + len + 1;
	    *p='\0';
	  } else {
	    *p = '\0'; 
	    p++;
	  }
	  
	  //set null char to split action param and action value
	  param = index(action, '/');
	  if(param != NULL) {
	    *param = '\0';
	    param++;
	  }

	  //check if action value is correct and append it at the end of the action list
	  if(*action >= '0' && *action <= '9') {
	      append_action((*action) - '0', param);
	    } else if (*action == 'a') {
	      append_action(10, param);
	    } else { 
	      printf("invalid action: %1s", action); 
	      continue;
	    } 	  
	}
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
      }else if(strcmp(param, "print") == 0) { 
	//parse int to check whether per packet statistics should be stored 
        print = strtol(value, NULL, 0);
      } else 
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }
  } 

  //calculate sendind interval
  if(datarate > 0) {
    data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
    fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	    (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  } else {
    fprintf(stderr, "background data probe is disabled\n");
    data_snd_interval = 0;
  }
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

  //by default the new rule should be redirected to port 2 to make the measurement easier
  /* fprintf(stderr, "by default output packet to port 1\n"); */
/*   command_len += sizeof(struct ofp_action_output); */
/*   command = realloc(command, command_len); */
/*   act_out = (struct ofp_action_output *) */
/*     (command + (command_len - sizeof(struct ofp_action_output))); */
/*   act_out->type = htons(0); */
/*   act_out->len = htons(8); */
/*   act_out->max_len = htons(0); */
/*   act_out->port = htons(ctx->channels[OFLOPS_DATA3].of_port); */
  return 0;
}

/*
 * Helping function
 */
/*
 * Given the global variables buffer and buffer_len, append at their end
 * the commands that with type action and action param action_param.
 * @param action the id of the action.
 * @param action_param the parameter of the action
 * @todo code is very dirty. Needs to be refactored. 
 */
int
append_action(int action, const char *action_param) {
  struct ofp_action_output *act_out;
  struct ofp_action_vlan_vid *act_vid;
  struct ofp_action_vlan_pcp *act_pcp;
  struct ofp_action_header *act;
  struct ofp_action_dl_addr *act_dl;
  struct ofp_action_nw_addr *act_nw;
  struct ofp_action_tp_port *act_port;
  switch(action) {
  case OFPAT_OUTPUT:
    fprintf(stderr, "output packet to port %s\n", action_param);
    command_len += sizeof(struct ofp_action_output);

    command = realloc(command, command_len);
    act_out = (struct ofp_action_output *)
      (command + (command_len - sizeof(struct ofp_action_output)));
    act_out->type = htons(action);
    act_out->len = htons(8);
    act_out->max_len = htons(0);
    act_out->port = htons((uint16_t)strtol(action_param, NULL, 16));
    break;
  case OFPAT_SET_VLAN_VID:
    if( (strtol(action_param, NULL, 16) < 0) || (strtol(action_param, NULL, 16) >= 0xFFF)) {
      printf("invalid vlan id\n");
      return -1;
    }
    fprintf(stderr, "change vlan to %ld\n", strtol(action_param, NULL, 16));
    command_len += sizeof(struct ofp_action_vlan_vid);
    command = realloc(command, command_len);
    act_vid = (struct ofp_action_vlan_vid *)
      (command+(command_len-sizeof(struct ofp_action_vlan_vid)));
    act_vid->type = htons(action);
    act_vid->len = htons(8);
    act_vid->vlan_vid = htons((uint16_t)strtol(action_param, NULL, 16));
    break;
  case OFPAT_SET_VLAN_PCP:
    if( (strtol(action_param, NULL, 16) < 0) || (strtol(action_param, NULL, 16) > 7)) {
      printf("invalid vlan pcp\n");
      return -1;
    }
    printf("change vlan pcp %ld\n", strtol(action_param, NULL, 16));
    command_len += sizeof(struct ofp_action_vlan_pcp);
    command = realloc(command, command_len);
    act_pcp = (struct ofp_action_vlan_pcp *)
      (command + (command_len - sizeof(struct ofp_action_vlan_pcp)));
    act_pcp->type = htons(action);
    act_pcp->len = htons(8);
    act_pcp->vlan_pcp = (uint8_t)strtol(action_param, NULL, 16); 
    break;
  case OFPAT_STRIP_VLAN:
    printf("strip vlan header\n");
    command_len += sizeof(struct ofp_action_header);
    command = realloc(command, command_len);
    act = (struct ofp_action_header *)
      (command + (command_len - sizeof(struct ofp_action_header)));
    act->type = htons(action);
    act->len = htons(8);
    break;
  case OFPAT_SET_DL_SRC:
  case OFPAT_SET_DL_DST:
    printf("Change ethernet address to %s\n", action_param);
    if((strlen(action_param) != 12) || (is_hex(action_param, 12) == 0)) {
      printf("invalid mac address\n");
      return -1;
    }
    command_len += sizeof(struct ofp_action_dl_addr);
    command = realloc(command, command_len);
    act_dl = (struct ofp_action_dl_addr *)
      (command + (command_len - sizeof(struct ofp_action_dl_addr)));
    act_dl->type = htons(action);
    act_dl->len = htons(16);
    int i;
    for(i = 0 ; i < 6; i++) {
      act_dl->dl_addr[i] = read_hex(action_param);
      action_param += 2;
    }
    break;
  case OFPAT_SET_NW_SRC:
  case OFPAT_SET_NW_DST:
    printf("Change ip address to %s\n", action_param);
    if((strlen(action_param) != 8) || (is_hex(action_param, 8) == 0)) {
      printf("invalid ip address\n");
      return -1;
    }
    command_len += sizeof(struct ofp_action_nw_addr);
    command = realloc(command, command_len);
    act_nw = (struct ofp_action_nw_addr *)
      (command + (command_len - sizeof(struct ofp_action_nw_addr)));
    act_nw->type = htons(action);
    act_nw->len = htons(8);
    act_nw->nw_addr = htonl(strtol(action_param, NULL, 16));
    break;
  case OFPAT_SET_TP_SRC:
  case OFPAT_SET_TP_DST:
    printf("change port to %ld\n", strtol(action_param, NULL, 16));
    command_len += sizeof(struct ofp_action_tp_port);
    command = realloc(command, command_len);
    act_port = (struct ofp_action_tp_port *)
      (command + (command_len - sizeof(struct ofp_action_tp_port)));
    act_port->type = htons(action);
    act_port->len = htons(8);
    act_port->tp_port = htons((uint16_t)strtol(action_param, NULL, 16));
    break;
  }    
  return 0;
}


/*
 * check if the char array contains hex like characters only.
 */
int
is_hex(const char *data, int len) {
  int i;
  for(i = 0 ; i < len; i++) {
    if(!( ((*data >= 'A') && (*data <= 'F')) ||
	  ((*data >= 'a') && (*data <= 'f')) || 
	  ((*data >= '0') && (*data <= '9')) )) 
      return 0;
    data++;
  }
  return 1;
}


void 
print_hex(char *data) {
  int i,j;
  for (i = 1; i <= 5; i++) {
    for(j = 0; j < 8; j++) {
      printf("%02x%02x ", (uint8_t)*(data+(16*i+2*j)), (uint8_t)*(data+(16*i+2*j+1)) );
    }
    printf("\n");
  }
}
