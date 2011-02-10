#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "common/nf2util.h"

#include "reg_defines_packet_generator.h"

#define DEFAULT_IFACE	"nf2c3"

//Total memory size in NetFPGA (words)
#define MEM_SIZE 0x80000

//Number of ports
#define NUM_PORTS 4

//Queue sizes (words)
//Xmit queue is used for transmission during setup
#define XMIT_QUEUE_SIZE 4096
//Min RX queue size is the minimum size for the RX queue.
//    - we have 2 * NUM_PORTS queues (tx + rx)
//    - arbitrarily chosen 1/2 * fair sharing b/w all queues
#define MIN_RX_QUEUE_SIZE MEM_SIlabZE/(2*NUM_PORTS)/2

#define MIN_TX_QUEUE_SIZE 4
#define MAX_TX_QUEUE_SIZE MEM_SIZE - NUM_PORTS * (MIN_RX_QUEUE_SIZE + XMIT_QUEUE_SIZE + MIN_TX_QUEUE_SIZE)

//Clock frequency (Hz)
#define CLK_FREQ 125*(10**6)

//Time between bytes
#define USEC_PER_BYTE 0.008
#define NSEC_PER_BYTE USEC_PER_BYTE*1000

//Various overheads
#define FCS_LEN 4
#define PREAMBLE_LEN 8
#define INTER_PKT_GAP 12
#define OVERHEAD_LEN PREAMBLE_LEN+INTER_PKT_GAP

//Minimum packet size
#define MIN_PKT_SIZE 60

struct ether_vlan_header {  
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t tpid;
  uint8_t pcp:3;
  uint8_t cfi:1;
  uint16_t vid:12;
  u_int16_t ether_type;                 /* packet type ID field */
};

struct pkt_details {
  int traffic_gen;
  uint32_t seq_num;
  struct timeval timestamp;
  struct ether_header *eth;
  struct ether_vlan_header *eth_vlan;
  struct iphdr *ip;
  struct udphdr *udp;
  void *data;
  int data_len;
  struct pktgen_hdr *pktgen;
};

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

/* Global vars */
static struct nf2device nf2;
static int verbose = 0;
static int force_cnet = 0;

struct pkt_details state;
struct traf_gen_det det;

void init_data(struct traf_gen_det *det);
int innitialize_generator_packet(struct pkt_details *state, struct traf_gen_det *det);
uint16_t ip_sum_calc(uint16_t len_ip_header, uint16_t buff[]);
int read_mac_addr(uint8_t *addr, char *str);

int 
main() {
  unsigned val;
  int i;
  uint32_t queue_addr_offset = OQ_QUEUE_1_ADDR_LO_REG - OQ_QUEUE_0_ADDR_LO_REG;
  uint32_t curr_addr = 0;
  uint32_t rx_queue_size = (MEM_SIZE - 4*XMIT_QUEUE_SIZE)/8;

  uint32_t src_port = 0, dst_port = 0x100;
  uint32_t word_len = 0, len = 0x100;
  uint32_t queue_base_addr[] = {0,0,0,0};

  char *data;
  uint32_t data_len, rate_limit_offset;
  uint32_t pointer = 0, pkt_pointer = 0;
  uint32_t drop;

  nf2.device_name = DEFAULT_IFACE;
  if (check_iface(&nf2)) 
    exit(1);

  if (openDescriptor(&nf2))
    exit(1);

  // Disable the output queues by writing 0x0 to the enable register
  writeReg(&nf2, PKT_GEN_CTRL_ENABLE_REG,  0x00);

  //generate the data we want to send
  init_data(&det);
  innitialize_generator_packet(&state, &det);

  // Disable output queues
  // Note: 3 queues per port -- rx, tx and tx-during-setup
  for (i = 0; i < 3 * NUM_PORTS; i++) {
    writeReg (&nf2, (OQ_QUEUE_0_CTRL_REG + i*queue_addr_offset), 0x00);
  }

  //Set queue sizes thourght the relevant registers
  for (i = 0; i<NUM_PORTS; i++) {
    //set queue sizes for tx-during-setup
    writeReg (&nf2, (OQ_QUEUE_0_ADDR_LO_REG + (i*2)*queue_addr_offset), curr_addr);
    writeReg (&nf2, (OQ_QUEUE_0_ADDR_HI_REG + (i*2)*queue_addr_offset), curr_addr + XMIT_QUEUE_SIZE - 1);
    writeReg (&nf2, (OQ_QUEUE_0_CTRL_REG + (i*2)*queue_addr_offset), 0x02);
    curr_addr += XMIT_QUEUE_SIZE;

    //Set queue sizes for RX queues
    writeReg (&nf2,OQ_QUEUE_0_ADDR_LO_REG + (i*2+1)*queue_addr_offset, curr_addr);
    writeReg (&nf2,OQ_QUEUE_0_ADDR_HI_REG + (i*2+1)*queue_addr_offset, curr_addr+rx_queue_size-1);
    writeReg (&nf2,OQ_QUEUE_0_CTRL_REG + (i*2+1)*queue_addr_offset, 0x02);
    curr_addr += rx_queue_size;

  }
  
  for (i = 0; i < NUM_PORTS; i++) {
    //Set queue sizes for TX queues
    writeReg (&nf2, OQ_QUEUE_0_ADDR_LO_REG + (i + 2*NUM_PORTS)*queue_addr_offset, curr_addr);
    writeReg (&nf2, OQ_QUEUE_0_ADDR_HI_REG + (i + 2*NUM_PORTS)*queue_addr_offset, curr_addr + ((i == 3)?  
											       det.pkt_size + ceil(det.pkt_size/8) + 1:1) - 1);
    writeReg (&nf2,OQ_QUEUE_0_CTRL_REG + (i+2*NUM_PORTS)*queue_addr_offset,  0x02);
    queue_base_addr[i] = curr_addr;
    curr_addr += ((i == 3)? det.pkt_size + ceil(det.pkt_size/8) + 1:1);

    //$queue_base_addr[$i] = $curr_addr;
    //$curr_addr += $queue_size;
  }

  //data + netfpga packet length + 1 byte for the ctrl part for each word
  data_len = state.data_len + 9 + ceil((float)state.data_len/8);
  data = malloc(data_len);
  bzero(data, data_len);
  pointer = 0;
  pkt_pointer = 0;

  //append netfpga header
  data[pointer] = IO_QUEUE_STAGE_NUM;
  pointer++;
  *(uint16_t *)(data + pointer ) = 0x0;
  pointer+=2;
  *(uint16_t *)(data + pointer ) = (uint16_t)ceil((float)state.data_len/8);
  pointer+=2;
  *(uint16_t *)(data + pointer ) = (uint16_t)(0x100 << 3);
  pointer+=2;
  *(uint16_t *)(data + pointer ) = (uint16_t)state.data_len;
  pointer+=2;

  printf("size: %d %d output: %d\n", (uint16_t)ceil((float)state.data_len/8), state.data_len, (uint16_t)(0x100 << 3));
  
  //put data
  queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;

  for(i = 0; i < floor((float)state.data_len/8); i++) {
    data[pointer] = 0x0;
    pointer++;
    memcpy(data+pointer, state.data + pkt_pointer, 8);
    pkt_pointer += 8;
    pointer += 8;
  }
  data[pointer] = state.data_len - pkt_pointer;
  pointer++;
  memcpy(data+pointer, state.data + pkt_pointer, state.data_len - pkt_pointer); 
  pointer+= state.data_len - pkt_pointer;
  

  uint32_t sram_addr = SRAM_BASE_ADDR + queue_base_addr[3]*16;
  
  //finally copy data on the SRAM
  for (i = 0; i < data_len; i+=3) {
    writeReg (&nf2,sram_addr + 0x0, *((uint32_t *)(data + 4*i)));
    writeReg (&nf2,sram_addr + 0x4, *((uint32_t *)(data + 4*(i + 1))));
    writeReg (&nf2,sram_addr + 0x8, *((uint32_t *)(data + 4*(i + 2))));
    int j;
    if (4*i < 64) {
      for (j = 4*i; (j < 4*i+16); j+=4) {
	printf("%02x%02x%02x%02x ", (uint8_t)data[j], (uint8_t)data[j+1], (uint8_t)data[j+2], (uint8_t)data[j+3]);
      }
      printf("\n");
    }
    sram_addr += 12;
  }

  //ff 0000 af00 0008 7805 0000 15

  // Set the rate limiter for CPU queues
/*   for (i = 0; i < 4; i++) { */
/*     rate_limiter_set(i * 2 + 1, 200000); */
/*   } */

  queue_addr_offset = OQ_QUEUE_GROUP_INST_OFFSET;
  // Set the number of iterations for the queues with pcap files
  for (i = 0; i < NUM_PORTS; i++) {
    // rate_limiter_disable($i * 2);
    rate_limit_offset = RATE_LIMIT_1_CTRL_REG - RATE_LIMIT_0_CTRL_REG;

    //disable repetition
    writeReg(&nf2, OQ_QUEUE_0_CTRL_REG + (i + 2 * NUM_PORTS) * queue_addr_offset, 0x0);
    //
    writeReg (&nf2, RATE_LIMIT_0_CTRL_REG + 2 * i * rate_limit_offset, 0x0);
    // disable rate limit on CPU queues
    writeReg (&nf2, RATE_LIMIT_0_CTRL_REG + (2*i + 1) * rate_limit_offset, 0x0);
  }

  //set queue 3 to repeat once
  writeReg(&nf2, OQ_QUEUE_0_CTRL_REG + (3 + 2 * NUM_PORTS) * queue_addr_offset, 0x1);
  writeReg(&nf2, OQ_QUEUE_0_MAX_ITER_REG + (3 + 2 * NUM_PORTS) * queue_addr_offset, 1);


  //Enable the packet generator hardware to send the packets
  drop = 0;
/*   for (i = 0; i < NUM_PORTS; i++) { */
/*       drop = drop | (1 << i); */
    
/*     drop = drop << 8; */
/*   } */
  printf("drop 0x%X...\n", drop | 0xF);
  //packet_generator_enable (drop | 0xF);
  writeReg(&nf2, PKT_GEN_CTRL_ENABLE_REG,  drop | 0xF);

  sleep(10);

  //Finish up
  writeReg(&nf2, PKT_GEN_CTRL_ENABLE_REG, 0x0);
  for (i = 0; i < 1024; i++) {
    //    reset_delay();
    writeReg(&nf2, DELAY_RESET_REG, 1);
  }

  //display_xmit_metrics();
  printf("Transmit statistics:\n");
  printf("====================\n\n");

  for (i = 0; i < NUM_PORTS; i++) {
    uint32_t pkt_cnt, iter_cnt;
    readReg(&nf2, OQ_QUEUE_0_NUM_PKTS_REMOVED_REG + (i + 8) * queue_addr_offset, &pkt_cnt);
    readReg(&nf2, OQ_QUEUE_0_CURR_ITER_REG + (i + 8) * queue_addr_offset, &iter_cnt);
      
      printf("%d:\n", i + 8);
      printf("\tPackets: %u\n", pkt_cnt);
      printf("\tCompleted iterations: %u\n", iter_cnt);
  }
  printf("\n\n");

  //display_capture_metrics();
  
  printf("sending packet completed...");
  
  closeDescriptor(&nf2);
  
  printf("Test successful\n");  
  
}

void
init_data(struct traf_gen_det *det) {
  strcpy(det->src_ip,"10.1.1.1");
  strcpy(det->dst_ip_min,"10.1.1.2");
  strcpy(det->dst_ip_max,"10.1.1.2");
  strcpy(det->mac_src,"00:1e:68:9a:c5:75");
  strcpy(det->mac_dst,"00:15:17:7b:92:0a");
  det->vlan = 0xffff;
  det->vlan_p = 0;
  det->vlan_cfi = 0;
  det->udp_src_port = 8080;
  det->udp_dst_port = 8080;
  det->pkt_size = 1400;
  det->delay = 100*1000;
}


int
innitialize_generator_packet(struct pkt_details *state, struct traf_gen_det *det) {  
  state->data = (void *)malloc(det->pkt_size); 
  state->data_len = det->pkt_size;

  bzero((void *)state->data, state->data_len);
  if(state->data_len < sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
    printf("packet size is too small\n");
    return 0;
  }
  //ethernet header with default values
  state->eth_vlan = (struct ether_vlan_header *) state->data;
  state->eth = (struct ether_header *) state->data;
  read_mac_addr(state->eth_vlan->ether_dhost, det->mac_dst);
  read_mac_addr(state->eth_vlan->ether_shost, det->mac_src);
  if(det->vlan != 0 && det->vlan != 0xffff) {
    state->eth_vlan->tpid = htons(0x8100);
    state->eth_vlan->vid = htons(det->vlan) >>4;
    state->eth_vlan->ether_type = htons(ETHERTYPE_IP);
    state->ip = (struct iphdr *)(state->data + sizeof(struct ether_vlan_header));
    state->ip->tot_len=htons(state->data_len - sizeof(struct ether_vlan_header)); 
    state->udp = (struct udphdr *)
      (state->data + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
    state->udp->len = htons(state->data_len - sizeof(struct ether_vlan_header) - sizeof(struct iphdr));
    state->pktgen = (struct pktgen_hdr *)
      (state->data + sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
  } else {
    state->eth->ether_type = htons(ETHERTYPE_IP);
    state->ip = (struct iphdr *)(state->data + sizeof(struct ether_header));
    state->ip->tot_len=htons(state->data_len - sizeof(struct ether_header)); 
    state->udp = (struct udphdr *)
      (state->data + sizeof(struct ether_header) + sizeof(struct iphdr));
    state->udp->len = htons(state->data_len - sizeof(struct ether_header) - sizeof(struct iphdr));
    state->pktgen = (struct pktgen_hdr *)
      (state->data + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
  }
  //ip header with default values
  state->ip->protocol=1;
  state->ip->ihl=5;
  state->ip->version=4;
  //state->ip->check = htons(0x9a97);
  //total packet size without ethernet header
  state->ip->ttl = 100;
  state->ip->protocol = IPPROTO_UDP; //udp protocol
  state->ip->saddr = inet_addr(det->src_ip); 
  state->ip->daddr = inet_addr(det->dst_ip_min); //test.nw_dst;
  
  state->ip->check=ip_sum_calc(20, (uint16_t *) state->ip);

  state->udp->source = htons(det->udp_src_port);
  state->udp->dest = htons(det->udp_dst_port);
  
  state->pktgen->magic = 0xbe9be955;

  return 1;
}

int 
read_mac_addr(uint8_t *addr, char *str) {
  char *p = str, *tmp;
  int i = 0;
  do {    
    tmp = index(p, ':');
    if(tmp != NULL) {
      *tmp = '\0';
      tmp++;
    }
    addr[i] = (uint8_t)strtol(p, NULL, 16);
    i++;
    p = tmp;
  } while (p!= NULL);

  //fprintf(stderr, "mac %x:%x:%x:%x:%x:%x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  return 0;
}

uint16_t ip_sum_calc(uint16_t len_ip_header, uint16_t buff[]) {
  uint16_t word16;
  uint32_t sum=0;
  uint16_t i;
  
  // make 16 bit words out of every two adjacent 8 bit words in the packet
  // and add them up
  for (i=0;i<len_ip_header;i=i+2){
    word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    sum = sum + (uint32_t) word16;	
  }
  
  // take only 16 bits out of the 32 bit sum and add up the carries
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);
  
  // one's complement the result
  sum = ~sum;
  
  return ((uint16_t) sum);
}
