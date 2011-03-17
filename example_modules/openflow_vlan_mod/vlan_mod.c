#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>

#include <float.h>
#include <math.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
#include "context.h"

/** @ingroup modules
 * Vlan modification module.
 * A module to measure the delay imposed by vlan modification actions on 
 * packets from openflow switch.
 * The rate, count and delay then determined.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 * @return name of module
 */
char * name() {
	return "openflow_flow_mod";
}

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SND_PKT "send pkt"


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


int data_send=OFLOPS_DATA1,data_receive=OFLOPS_DATA4;
int probe_send=OFLOPS_DATA2, probe_receive_1 = OFLOPS_DATA1, probe_receive_2 = OFLOPS_DATA3;

/** structure to store the measurements of the measuring probe.
 */
struct measure {
  uint32_t id;
  struct timeval scheduled, send,received; 
};

struct tailq_entry {
  struct measure value;
  TAILQ_ENTRY(tailq_entry) entries;
};

TAILQ_HEAD(, tailq_entry) my_tailq_head;

/** A variable to inform when the module is over.
 */
int finished;

/** The file where we write the output of the measurement process.
 */
FILE *measure_output;

uint64_t datarate = 10;
uint64_t proberate = 10; 

pthread_mutex_t mutex1;

/*
 * calculated sending time interval (measured in usec). 
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

/**
 * A place to store the measurement packets. 
 */
char *buf = NULL;

int table = 0;
char *network = "192.168.3.0";

char *new_vlan_id = "10";
int vlan_id = 0;

char *new_vlan_pcp = "3";
int vlan_pcp = 0;

int vlan_strip = 0;

/**
 * Number of flows to send. 
 */
int flows = 100;

/**
 * statistics variables
 */
long long unsigned int sum[2], sum_square[2], count[2];

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

  //init mutex for the thread sync.
  pthread_mutex_init(&mutex1, NULL);

  measure_output = fopen("action.log", "w");
  if(measure_output == NULL)
    perror_and_exit("failed to open measure log file", 1);

  //init logging service
  msg_init();

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now,GENERIC_MSG , "Intializing module openflow_action_measurement");

  make_ofp_hello(&b);
  res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);  

  // send a feature request to see what the switch can do and os that the connection
  // is kept open.
  make_ofp_feat_req(&b);
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
  printf("Sending new flow rules...\n");
  bzero(fl, sizeof(struct flow));
  printf("table value:%d\n", table);
  if(table == 0)
    fl->mask = 0; //if table is 0 the we generate an exact match
  else 
    fl->mask = OFPFW_DL_VLAN;
    //fl->mask = (8 << OFPFW_NW_SRC_SHIFT) |(8 << OFPFW_NW_DST_SHIFT)|OFPFW_DL_SRC|OFPFW_IN_PORT|
    //  OFPFW_DL_DST|OFPFW_TP_SRC|OFPFW_TP_DST|OFPFW_DL_VLAN;
  fl->in_port = htons(probe_send - 1);
  fl->dl_type = htons(ETHERTYPE_IP);          
  fl->dl_src[5] = 0; 
  fl->dl_dst[5] = 2; 
  fl->dl_vlan = htons(1);
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);            
  fl->tp_dst = htons(8080);  
  len = make_ofp_flow_add(&b, fl, probe_receive_1 - 1, 1, 1200);
  res = oflops_send_of_mesg(ctx, b);
  free(b);

  buf = generate_packet(*fl, pkt_size);
  memcpy(fl_probe, fl, sizeof(struct flow));

  ip_addr.s_addr = inet_addr(network);
  ip_addr.s_addr =  ntohl(ip_addr.s_addr);
  fl->in_port = htons(data_send - 1); 
  fl->dl_vlan = htons(1);
  fl->mask = 0;
  for(i=0; i< flows; i++) {
    ip_addr.s_addr += 1;
    fl->nw_dst =  htonl(ip_addr.s_addr);
    len = make_ofp_flow_add(&b, fl, data_receive - 1, 1, 1200);
    res = oflops_send_of_mesgs(ctx, b, len);
    free(b);
  }
  
  /**
   * Shceduling events
   */
  //start sending measurement probes in 2 minutes 
  gettimeofday(&now, NULL);
  add_time(&now, 2, 0);
  //oflops_schedule_timer_event(ctx,&now, SND_PKT);

  //send the flow modyfication command in 30 seconds. 
  gettimeofday(&now, NULL);
  add_time(&now, 30, 0);
  oflops_schedule_timer_event(ctx,&now, SND_ACT);

  
  //end process 
  gettimeofday(&now, NULL);
  add_time(&now, 60, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);
  return 0;
}

int destroy(struct oflops_context *ctx) {
  printf("destroying code\n");
  fclose(measure_output);  
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {  
  char *str = te->arg; 
  struct timeval now;
  struct tailq_entry *item;
  int len;
  void *b;
  int i;

  //terminate process 
  if (strcmp(str, BYESTR) == 0) {
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
    finished = 0;

    for (i = 0; i < 2;i++) {
      
      float mean = ((count[i] == 0)?FLT_MAX:sum[i]/count[i]);
      float var = ((count[i] == 0)?FLT_MAX:(sum_square[i]/count[i]) - mean*mean);
      char msg[400];
      gettimeofday(&now, NULL);
      snprintf(msg, 400, "case %d : mean = %f, var=%f", i, mean, var); //, sqrt(var));
      oflops_log(now, GENERIC_MSG, msg);
    }
    return 0;    
  } else if (strcmp(str, SND_PKT) == 0) {
    sendno++;
    *((uint32_t *)(buf + MEASUREMENT_PACKET_HEADER)) = sendno;
    
    gettimeofday(&now, NULL);
    
    item = xmalloc(sizeof(struct tailq_entry));
    set_timeval(&item->value.scheduled, &now);
    item->value.id = sendno;
    pthread_mutex_lock(&mutex1);
    TAILQ_INSERT_TAIL(&my_tailq_head, item, entries);
    pthread_mutex_unlock(&mutex1);
    oflops_send_raw_mesg(ctx, probe_send/*OFLOPS_DATA1*/, buf, pkt_size);
    
    if(sendno % 10000 == 0) 
      printf("send id : %d\n", sendno);
    
    //schedule next packet send
    if(!finished) {
      add_time(&te->sched_time, 0, probe_snd_interval);
      oflops_schedule_timer_event(ctx,&te->sched_time, SND_PKT);
    }
  } else if (strcmp(str, SND_ACT) == 0) {
    printf("sending flow modification\n");
    len = make_ofp_flow_modify(&b, fl_probe, command, command_len, 
			       1, 1200);
    oflops_send_of_mesg(ctx, b);
    free(b);
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
    snprintf(filter, buflen, "port 6633");
    return 1;
  } else if ((ofc == probe_receive_1) || (ofc == probe_receive_2)) {
    memcpy(filter, "", sizeof(""));
    return 1;
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
  int dir, len, res;
  void *b;
  struct ofp_header *ofp;
  struct pcap_event *ofp_msg;
  struct ofp_error_msg *err_p = NULL;

  if (ch == OFLOPS_CONTROL) {
    dir = append_data_to_flow(pe->data,pe->pcaphdr);
    while(contains_next_msg(dir) > 0) {
      len = get_next_msg(dir, &ofp_msg);
      ofp = (struct ofp_header *)ofp_msg->data;
      switch(ofp->type) {
      case OFPT_FLOW_MOD:
	oflops_log(pe->pcaphdr.ts,OFPT_FLOW_MOD_ADD, "stats request send");
      case OFPT_ECHO_REQUEST:
	make_ofp_hello(&b);
	((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
	res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
	free(b);
	break;  
      case OFPT_ERROR:
	err_p = (struct ofp_error_msg *)ofp;
	char *msg = xmalloc(sizeof("OFPT_ERROR(type: XXXXXXXXXX, code: XXXXXXXXXX)"));
	sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
	oflops_log(pe->pcaphdr.ts, OFPT_ERROR_MSG, msg);
	fprintf(stderr, "%s\n", msg);
	break;   
      }
    }
  } else if ((ch == probe_receive_1) || (ch == probe_receive_2)) {
    //if(dummy_parse_packet(pe->data, pe->pcaphdr.caplen) == 0) {
    struct flow fl;
    int c = 0;
    pktgen = extract_pktgen_pkt(pe->data, pe->pcaphdr.caplen, &fl);
    if(((vlan_id) && (fl.dl_vlan == 16)) ||
       ((vlan_strip) && (fl.dl_vlan == 0))) {
      c = 1;
    }
    //printf("%d %d %x %d\n", vlan_id, vlan_strip, fl.dl_vlan, c);
    uint64_t diff = 1000000*(pe->pcaphdr.ts.tv_sec - htonl(pktgen->time.tv_sec)) +
      (pe->pcaphdr.ts.tv_usec - htonl(pktgen->time.tv_usec));
    sum[c] += diff;
    sum_square[c] += diff*diff;
    count[c]++;
    if(htonl(pktgen->seq_num) % 100000 == 0)
      printf("data packet received %llu\n", (long long unsigned int)ntohl(pktgen->seq_num));
    if(fprintf(measure_output, "%lu;%lu.%06lu;%lu.%06lu;%d\n", 
	       (long unsigned int)htonl(pktgen->seq_num),  
	       (long unsigned int)htonl(pktgen->time.tv_sec), 
	       (long unsigned int)htonl(pktgen->time.tv_usec), 
	       (long unsigned int)pe->pcaphdr.ts.tv_sec, 
	       (long unsigned int)pe->pcaphdr.ts.tv_usec, c) < 0)  
      perror_and_exit("fprintf fail", 1); 
    fflush(measure_output);
  }
  return 0;
}

int 
of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * pkt_in) {  
  switch(pkt_in->reason) {
  case  OFPR_NO_MATCH:
    printf("OFPR_NO_MATCH: %d bytes\n", ntohs(pkt_in->total_len));
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
  return 0;
}

int 
of_event_port_status(struct oflops_context *ctx, const struct ofp_port_status * ofph) {
  return 0;
}

int 
of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}

int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  return 0;
}

int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  init_traf_gen(ctx);

  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.3.1");
  strcpy(det.dst_ip_max,"192.168.3.5");
  strcpy(det.mac_src,"00:00:00:00:00:00");
  strcpy(det.mac_dst,"00:00:00:00:00:02");
  det.vlan = 1;
  det.vlan_p = 1;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval*1000;
  add_traffic_generator(ctx, data_send, &det);  
  
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  strcpy(det.mac_src,"00:00:00:00:00:00");
  strcpy(det.mac_dst,"00:00:00:00:00:02"); 
  det.vlan = 1;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = probe_snd_interval*1000;
  add_traffic_generator(ctx, probe_send, &det);  
  
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

  struct ofp_action_output *act_out;

  //init counters
  sendno = 0;
  TAILQ_INIT(&my_tailq_head);
  finished = 0;

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
    if(value != NULL) {
      *value = '\0';
      value++;
    }
    fprintf(stderr, "param = %s, value = %s\n", param, value);
    if(strcmp(param, "pkt_size") == 0) {
      //parse int to get pkt size
      pkt_size = strtol(value, NULL, 0);
      if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
	perror_and_exit("Invalid packet size value", 1);
    } else if(strcmp(param, "data_rate") == 0) {
      //parse int to get rate of background data
      datarate = strtol(value, NULL, 0);
      if((datarate <= 0) || (datarate > 1010))
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
	  
	  printf("%s : %s\n", action, param);
	  
	  //check if action value is correct
	  if(*action < '0' || *action > '9') { printf("invalid action: %1s", action); continue; }
	  //append the action to the action list.
	  append_action((*action) - '0', param);
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
      } else if(strcmp(param, "vlan_id") == 0) {
	//change vlan_id
      //      char test = ('0' + new_vlan_id);
	append_action(1, new_vlan_id);
	vlan_id = 1;
      } else if(strcmp(param, "vlan_pcp") == 0) {
	//change vlan_id
	append_action(2, new_vlan_pcp);
	vlan_pcp = 1;
      } else if(strcmp(param, "vlan_strip") == 0) {
	//change vlan_id
	append_action(3, NULL);
	vlan_strip = 1;
      } else 
        fprintf(stderr, "Invalid parameter:%s\n", param);
      param = pos;
    }

  //calculate sendind interval
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

  //by default the new rule should be redirected to port 2 to make the measurement easier
  fprintf(stderr, "by default output packet to port 1\n");
  command_len += sizeof(struct ofp_action_output);
  command = realloc(command, command_len);
  act_out = (struct ofp_action_output *)
    (command + (command_len - sizeof(struct ofp_action_output)));
  act_out->type = htons(0);
  act_out->len = htons(8);
  act_out->max_len = htons(0);
  act_out->port = htons(probe_receive_2 - 1);

  count[0] = 0;
  count[1] = 0;
  sum_square[0] = 0;
  sum_square[1] = 0;
  sum[0] = 0;
  sum[1] = 0;
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
  //printf("action %d : %s\n", action, action_param);

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
