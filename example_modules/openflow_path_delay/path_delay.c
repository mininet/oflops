#include <sys/queue.h>
 
#include "context.h"
#include "utils.h"
#include "log.h"

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
	return "openflow_path_delay";
}

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
uint32_t pkt_size;

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

int finished;

FILE *measure_output;

uint64_t datarate;
uint64_t proberate; 

/*
 * calculated sending time interval (measured in usec). 
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

int flows = 100;
char *network = "192.168.3.0";
/**
 * Initialization code with parameters
 * @param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  //init counters
  sendno = 0;
  TAILQ_INIT(&my_tailq_head);
  finished = 0;
  //open file for storing measurement
  measure_output = fopen("measure.log", "w");

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
      if(strcmp(param, "flows") == 0) {
        flows = atoi(value);
        if(flows <= 0)
          perror_and_exit("Invalid flow number",1);
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
      }  else if(strcmp(param, "probe_rate") == 0) {
        //parse int to get pkt size
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }
      } else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  } 

  //calculate sendind interval
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);

  return 0;
}

/** Initialization
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
  return 0;
}

/** Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen) {
  return snprintf(filter,buflen," ");
}


/** Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch) {
  return 0;
}

int of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * ofph) {
  return 0;
}

int of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}

int of_event_port_status(struct oflops_context *ctx, const struct ofp_port_status * ofph) {
  return 0;
}

int of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}

int handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  return 0;
}
                        
