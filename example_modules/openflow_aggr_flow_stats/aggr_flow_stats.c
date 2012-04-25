#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"

#ifndef BUFLEN
#define BUFLEN 4096
#endif

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define GETSTAT "getstat"
#define WRITEPACKET "write packet"
#define PRINTCOUNT "print"
#define SND_PKT "send pkt"
#define SNMPGET "snmp get"

/** packet size constants
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

#define LOG_FILE "measure.log"

/*
 * Number of flow rules we send to the switch
 */
int flows = 128;
int flows_exponent, query_exponent;
int query = 64;
/** The iniitial ip from which we start
 */
char *network = "192.168.2.0";

/** Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/** The rate at which data will be send between the data ports (In Mbits per sec.). 
 */
uint64_t datarate = 100;
uint64_t proberate = 100;

/** pkt sizes. 
 */
uint64_t pkt_size = 1500;
int finished; 

/*
 * calculated sending time interval (measured in usec). 
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

struct timeval stats_start;
int trans_id=0;

char *logfile = LOG_FILE;

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;

struct stats_entry {
  struct timeval rcv;
  int id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(stats_tailhead, stats_entry) stats_head;
int stats_count = 0;

// control whether detailed packet information is printed
int print = 0;
int count[] = {0,0,0}; // counting how many packets where received over a 
                       // specific channel
//the local mac address of the probe 
char probe_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};



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
char * name()
{
  return "openflow_flow_dump_test";
}

int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  double exponent;

  printf("log initialized\n");

  //init measurement queue
  TAILQ_INIT(&head); 
  TAILQ_INIT(&stats_head); 

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
    if(value != NULL) {
      if(strcmp(param, "flows") == 0) {
        flows = atoi(value);
        if(flows <= 0)
          perror_and_exit("Invalid flow number",1);
      } else if(strcmp(param, "query") == 0) {
        query = atoi(value);
        if(query <= 0)
          perror_and_exit("Invalid flow number",1);

	exponent = log2(query);
	if(exponent - floor(exponent) != 0) {
	  printf("query=%d, exponent=%f, floor exponent:%f\n", query, exponent, floor(exponent));
	  query = (int)pow(2, ceil(exponent));
	  printf("query size must be a power of 2. converting to %d\n", query);
	}

      } else if(strcmp(param, "network") == 0) {
        network = (char *)xmalloc(strlen(value) + 1);
        strcpy(network, value);
      } else if(strcmp(param, "pkt_size") == 0) {
        //parse int to get pkt size
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))  {
          perror_and_exit("Invalid packet size value", 1);
        }
      } else if(strcmp(param, "data_rate") == 0) {
        //parse int to get pkt size
        datarate = strtol(value, NULL, 0);
        if((datarate <= 0) || (datarate > 1010))  {
          perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
        }
      } else if(strcmp(param, "probe_rate") == 0) {
        //parse int to get pkt size
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }
      } else if(strcmp(param, "print") == 0) {
        //parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  } 

  //calculating interpacket gap
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
	  (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

  return 0;
}


int destroy(struct oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  FILE *out = fopen(logfile, "w");
  struct entry *np;
  struct stats_entry *stats_np;
  uint32_t mean, median, std;
  int min_id[] = {INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX}, 
    max_id[] = {INT_MIN, INT_MIN, INT_MIN, INT_MIN, INT_MIN, INT_MIN},
      ix[] = {0, 0, 0, 0, 0, 0}, delay;
  int ch, i, first=1;
  float loss;
  double **data;

  gettimeofday(&now, NULL);
  fprintf(stderr, "This is the destroy code of the module\n");

  data = (double **)malloc(6*sizeof(double*));
  for(ch = 0; ch < 6; ch++) 
    data[ch] = (double *)malloc(count[(int)(ch/2)] * sizeof(double));
    
  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    
    if(print)
      if(fprintf(out, "%lu;%lu.%06lu;%lu.%06lu;%d\n", 
		 (long unsigned int)np->id,  
		 (long unsigned int)np->snd.tv_sec, 
		 (long unsigned int)np->snd.tv_usec,
		 (long unsigned int)np->rcv.tv_sec, 
		 (long unsigned int)np->rcv.tv_usec,  np->ch) < 0)  
	perror_and_exit("fprintf fail", 1); 

    i = (time_cmp(&stats_start,&np->snd)<=0)?0:1;
    ch = 2*(np->ch - 1) + i;
    ix[ch]++; 
    min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
    max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
    data[ch][ix[ch]] = (double) time_diff(&np->snd, &np->rcv);
    free(np);
  }

  for(ch = 0; ch < 6; ch++) {
      if(ix[ch] == 0) continue;
      gsl_sort (data[ch], 1, ix[ch]);
      mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
      std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
      median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
      loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);
      snprintf(msg, 1024, "statistics:port:%d.%d:%u:%u:%u:%.4f:%d", 
	       (ch/2),(ch%2), mean, median, std, loss, ix[ch]);
      printf("%s\n", msg);
      oflops_log(now, GENERIC_MSG, msg);
      
  }

  ix[0] = 0;
  min_id[0] =  INT_MAX;
  max_id[0] =  INT_MIN;
  free(data[0]);
  data[0] = (double *)malloc(sizeof(double)*(stats_count));

  for (stats_np = stats_head.tqh_first; 
       stats_np != NULL; stats_np = stats_np->entries.tqe_next) {
    delay = time_diff(&now, &stats_np->rcv);
    memcpy(&now,&stats_np->rcv, sizeof(struct timeval));
    if((print) && (ix[0] > 0)) {
      snprintf(msg, 1024, "STATS_REPLY:%d:%lu.%06lu:%u", 
	       stats_np->id, stats_np->rcv.tv_sec, stats_np->rcv.tv_usec, delay);
      oflops_log(now, GENERIC_MSG, msg);
      
    }
    
    if(ix[0] > 0) {
      data[0][ix[0] - 1] = delay;
    }
    ix[0]++;
  }

  ix[0]--; //we have added 1 on the last round which we have to remove
  if(ix[0] > 0) {
      gsl_sort (data[0], 1, ix[0]);
      mean = (uint32_t)gsl_stats_mean(data[0], 1, ix[0]);
      std = (uint32_t)sqrt(gsl_stats_variance(data[0], 1, ix[0]));
      median = (uint32_t)gsl_stats_median_from_sorted_data (data[0], 1, ix[0]);
      loss = (float)ix[0]/(float)(max_id[0] - min_id[0]);
      snprintf(msg, 1024, "statistics:stats:%u:%u:%u:%.4f:%d", 
	       mean, median, std, loss, ix[0]);
      printf("%s\n", msg);
      oflops_log(now, GENERIC_MSG, msg);
  } else {
      oflops_log(now, GENERIC_MSG, "stats_stats:fail");
  }
  return 0;
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx)
{
  int res = -1, i, len = 0;
  struct timeval now;
  struct in_addr ip_addr;
  struct pollfd * poll_set = malloc(sizeof(struct pollfd));
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  int ret = 0;

  // a genric structure with which 
  // we can create and send messages. 
  void *b;

  msg_init();

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

  gettimeofday(&now, NULL);
  oflops_log(now,GENERIC_MSG , "Intializing module openflow_flow_dump_test");

  make_ofp_hello(&b);
  ret = write(ctx->control_fd, b, sizeof(struct ofp_hello));
  printf("sending %d bytes\n", ret);
  free(b);  

  // send a delete all message to clean up flow table.
  make_ofp_feat_req(&b);
  printf("sending %d bytes\n", ret);
  free(b);

  // send a features request, to stave off timeout (ignore response)
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  ret = write(ctx->control_fd, b, res);
  printf("sending %d bytes\n", ret);
  free(b);

  //Send a singe ruke to route the traffic we will generate
  bzero(fl, sizeof(struct flow));
  fl->mask = OFPFW_IN_PORT | OFPFW_TP_DST; 
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
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 1200);
  write(ctx->control_fd, b, len);
  free(b);
 
  printf("Sending new flow rules...\n");
  ip_addr.s_addr = inet_addr(network);
  ip_addr.s_addr =  ntohl(ip_addr.s_addr);
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_vlan = 0xffff; 
  memcpy(fl->dl_src, data_mac, ETH_ALEN); 
  memcpy(fl->dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN); 
  fl->mask = 0; 
  for(i=0; i< flows; i++) {
    ip_addr.s_addr += 1;
    fl->nw_dst =  htonl(ip_addr.s_addr);
    do {
      bzero(poll_set, sizeof(struct pollfd));
      poll_set[0].fd = ctx->control_fd;
      poll_set[0].events = POLLOUT;
      ret = poll(poll_set, 1, -1);
    } while ((ret == 0) || ((ret > 0) && !(poll_set[0].revents & POLLOUT)) );
    
    if(( ret == -1 ) && ( errno != EINTR))
      perror_and_exit("poll",1);
    
    len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 1200);
    ret = write(ctx->control_fd, b, len);
    free(b);
  }

  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REQUEST;
  free(b);  

  //Schedule end
  gettimeofday(&now, NULL);
  add_time(&now, 20, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);

  //the event to request the flow statistics. 
  gettimeofday(&now, NULL);
  add_time(&now, 10, 0);
  oflops_schedule_timer_event(ctx,&now, GETSTAT);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  flows_exponent = (int)floor(log2(flows));
  query_exponent = (int)log2(query);

  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  int res = -1, len, i;
  void *b = NULL;
  char *str = te->arg;
  struct timeval now;
  char msg[100];
  uint32_t netmask = 0;
  //send flow statistics request. 
  if(strcmp(str, GETSTAT) == 0) {
    sprintf(msg, "%d", trans_id);
    printf("flow stats request send with xid %s\n", msg);  
    memcpy(&stats_start, &te->sched_time, sizeof(struct timeval));
    oflops_log(te->sched_time, OFPT_STATS_REQUEST_FLOW, msg);
    len = make_ofp_aggr_flow_stats(&b, trans_id++);
    struct ofp_aggregate_stats_request *reqp = (struct ofp_aggregate_stats_request *)
      (b + sizeof(struct ofp_stats_request));
    printf("query length : %d\n", query_exponent);
    reqp->match.wildcards = htonl(OFPFW_IN_PORT | OFPFW_DL_VLAN |  OFPFW_DL_SRC |
      OFPFW_DL_DST |  OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC |
      OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS | OFPFW_TP_DST |
     (32 << OFPFW_NW_SRC_SHIFT) | ((query_exponent) << OFPFW_NW_DST_SHIFT));
    reqp->match.nw_dst = 
      htonl(ntohl(inet_addr(network)) & ((0xFFFFFFFF)<<query_exponent) );
    res = oflops_send_of_mesg(ctx, b);
    free(b);
    //terminate programm execution 
  } else if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
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

int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int i, len = 1024;
  char msg[1024], log[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {    
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(log, len, "cpu : %s %%", msg);
	oflops_log(now, SNMP_MSG, log);
      }
    }
    
    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,  
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(log, len, "port %d : rx %s pkts",  
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], 
		 msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
      
      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,  
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(log, len, "port %d : tx %s pkts",  
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, log);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
  if(ofc == OFLOPS_CONTROL) {
    return 0;
    return snprintf(filter,buflen,"port %d", ctx->listen_port);
  } else if ( (ofc == OFLOPS_DATA3) || (ofc == OFLOPS_DATA2)) {
    return snprintf(filter,buflen,"udp");
    return 0;
  }
  return 0;
}

/** Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event *pe,
		      oflops_channel_name ch) {
    if ( (ch == OFLOPS_DATA3) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA1)){
    struct pktgen_hdr *pktgen;
    pktgen = extract_pktgen_pkt((unsigned char *)pe->data, pe->pcaphdr.caplen, NULL);
    if(pktgen == NULL) //skip non IP packets
      return 0;

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
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  char *str_ip;
  struct in_addr ip;
  init_traf_gen(ctx);

  //background data
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.2.1");

  ip.s_addr = ntohl(inet_addr("192.168.2.1"));
  ip.s_addr += flows;
  ip.s_addr = htonl(ip.s_addr);
  str_ip = inet_ntoa(ip);
  strcpy(det.dst_ip_max, str_ip);
  strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
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

  //measurement probe
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:75");
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.delay = probe_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA2, &det);
  start_traffic_generator(ctx);
  return 1;
}

int 
dummy_parse_packet(void *data, int len) {
  // assume we have ethernet packets.
  // skip first bytes of the ether because they are
  // in the simple case of static length.
  struct ether_header *eth = (struct ether_header *) data;
  if (len < sizeof(struct ether_header))
    return -1;
  data += sizeof(struct ether_header);
  if(ntohs(eth->ether_type) != ETHERTYPE_IP) {
    return -1;
  }
  if (len < sizeof(struct iphdr))
    return -1;
  struct iphdr *ip_p = (struct iphdr *)data;
  if (len < 4*ip_p->ihl)
    return -1;
  data += 4*ip_p->ihl;

  if(ip_p->protocol != IPPROTO_UDP)
    return -1;

  if(len <  sizeof(struct tcphdr))
    return -1;
  struct udphdr *udp_p = (struct udphdr *)data;
  if (len < sizeof(struct udphdr))
    return -1;

  if((ntohs(udp_p->source) == 8080) && 
     (ntohs(udp_p->dest) == 8080))
    return 0;
  else 
    return -1;

};

int
of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  struct timeval now;
  char msg[100];
  struct ofp_error_msg *err_p;
  int len, res;
  void *b;

  if(ofph->type == OFPT_STATS_REPLY) {
    struct ofp_stats_reply *ofpr = (struct ofp_stats_reply *)ofph;
    if(ntohs(ofpr->type) == OFPST_AGGREGATE) {
      sprintf(msg, "%d", ntohl(ofph->xid));
      gettimeofday(&now, NULL);
      oflops_log(now, OFPT_STATS_REPLY_FLOW, msg);
      if((ntohs(ofpr->flags) & OFPSF_REPLY_MORE) == 0) {
	len = make_ofp_aggr_flow_stats(&b, trans_id++);

	struct ofp_aggregate_stats_request *reqp = (struct ofp_aggregate_stats_request *)
	  (b + sizeof(struct ofp_stats_request));
	reqp->match.wildcards = htonl(OFPFW_IN_PORT |  OFPFW_DL_VLAN |   OFPFW_DL_DST |
				      OFPFW_DL_SRC |  OFPFW_DL_TYPE | OFPFW_DL_VLAN_PCP |
				      OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST |
				      OFPFW_NW_TOS | (32 << OFPFW_NW_SRC_SHIFT) |
				      ((query_exponent) << OFPFW_NW_DST_SHIFT));

	uint32_t flow_netmask = (ntohl(inet_addr(network)) & ((0xFFFFFFFF)<<flows_exponent));
	
	//in case query range is smaller that flow range, round robin around ips for more
	// variability.
	if(query_exponent < flows_exponent) 
	  flow_netmask += (stats_count%(0x1 <<(flows_exponent-query_exponent)) << query_exponent);
	reqp->match.nw_dst = htonl(flow_netmask);

	res = oflops_send_of_mesg(ctx, b);
	free(b);
      }
      struct stats_entry *n1 = malloc(sizeof(struct stats_entry));
      memcpy(&n1->rcv, &now, sizeof(struct timeval));
      n1->id =  ntohl(ofph->xid);
      stats_count++;
      TAILQ_INSERT_TAIL(&stats_head, n1, entries); 
    }
  } else if (ofph->type == OFPT_ERROR) {
    err_p = (struct ofp_error_msg *)ofph;
    sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
    fprintf(stderr, "%s\n", msg);
    perror_and_exit(msg, 1);
  }
  return 0;
}
