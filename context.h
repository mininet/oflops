#ifndef CONTEXT_H
#define CONTEXT_H

struct oflops_context;

#include "oflops.h"
#include "test_module.h"
#include "wc_event.h"
#include "channel_info.h"
#include "oflops_snmp.h"
#include <pcap.h>

typedef struct oflops_context
{
  //how many tests I watn to run?
  int n_tests;
  int max_tests;	// size of the tests array
  // an array of strings to store the tests
  struct test_module ** tests;
  // the test that we are currently handling
  struct test_module * curr_test;
  // which is the interface related t ocontrol 
  char * controller_port;
  // the filedescriptor of the socket of 
  // the control connection to the openflow
  int listen_fd;
  // a list of ports on which I listen for data
  uint16_t listen_port;
  // how match data we capture
  int snaplen;

  int control_fd; 
  struct msgbuf * control_outgoing;
  int n_channels;
  int max_channels;
  struct channel_info * channels;	// control, send, recv,etc.
  /** Pointers to SNMP channel
   */
  struct snmp_channel* snmp_channel_info;
  int should_end;
  int should_continue;
  struct wc_queue * timers;
  int dump_controller;
  /**
   * The location to output logging information
   */
  char *log; 
  /**
   * the traffic generation method we choose. 
   */
  int trafficGen;
  /**
   * The switch cpu mib
   */
  oid cpuOID[MAX_OID_LEN];
  size_t cpuOID_len;

} oflops_context;

enum trafficGenValues {
  USER_SPACE=1,
  PKTGEN,
};

oflops_context * oflops_default_context(void);

int reset_context(oflops_context * ctx);


#endif
