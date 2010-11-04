#include <sys/queue.h>
 
#include "context.h"
#include "utils.h"
#include "log.h"

/** @ingroup modules
 * Dummy module.
 * This module implements all the functions of the oflops modules.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 * @return name of module */
char * name() {
	return "openflow_dummy";
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
      printf("value : %s \n", value);
    }
  } 

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
                        
