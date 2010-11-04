#ifndef LOG_H_
#define LOG_H_ 1

#include <stdio.h>

#include "utils.h"

#define DEFAULT_LOG_FILE "oflops.log"

enum log_types {
  OFPT_FLOW_MOD_ADD,
  OFPT_STATS_REQUEST_FLOW,
  OFPT_STATS_REPLY_FLOW,
  OFPT_STATS_REQUEST_PORT,
  OFPT_STATS_REPLY_PORT,
  OFPT_HELLO_MSG,
  OFPT_ECHO_REPLY_MSG,
  OFPT_ECHO_REQUEST_MSG,
  OFPT_ERROR_MSG,
  GENERIC_MSG,
  SNMP_MSG,
  PCAP_MSG,
  OFPT_PACKET_IN_MSG,
  PKTGEN_MSG
};

void oflops_log_init(const char *filename);
int oflops_log(struct timeval, int type, char *details);
void oflops_log_close();

#endif
