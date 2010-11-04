#ifndef TRAFFIC_GENERATOR_H
#define TRAFFIC_GENERATOR_H 1

#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <stdint.h>
#include "oflops.h"
#include "context.h"
#include "utils.h"
#include "msg.h"

struct traf_gen_det {
  char intf_name[20];
  char src_ip[20], dst_ip_max[20], dst_ip_min[20];
  char mac_dst[20], mac_src[20];
  uint16_t udp_src_port, udp_dst_port;
  uint32_t pkt_size;
  uint16_t vlan;
  uint16_t vlan_p;
  uint16_t vlan_cfi;
  uint32_t delay;
};

struct pktgen_hdr {
  uint32_t magic;
  uint32_t seq_num;
  uint32_t tv_sec;
  uint32_t tv_usec;
  struct timeval time;
};

int init_traf_gen(struct oflops_context *ctx);
int add_traffic_generator(struct oflops_context *ctx, int channel, struct traf_gen_det *det);
int start_traffic_generator();
int stop_traffic_generator();

char *report_traffic_generator(oflops_context *ctx);

struct pktgen_hdr *extract_pktgen_pkt(unsigned char *b, int len, struct flow *fl);

#endif
