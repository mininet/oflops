#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openflow/openflow.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include "config.h"
#include "cbench.h"
#include "fakeswitch.h"

static int debug_msg(struct fakeswitch * fs, char * msg, ...);
static int make_features_reply(int switch_id, int xid, char * buf, int buflen);
static int make_stats_desc_reply(struct ofp_stats_request * req, char * buf, int buflen);
static int parse_set_config(struct ofp_header * msg);
static int make_config_reply( int xid, char * buf, int buflen);
static int make_vendor_reply(int xid, char * buf, int buflen);
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address);
static int packet_out_is_lldp(struct ofp_packet_out * po);
static void fakeswitch_handle_write(struct fakeswitch *fs);
static void fakeswitch_learn_dstmac(struct fakeswitch *fs);
void fakeswitch_change_status_now (struct fakeswitch *fs, int new_status);
void fakeswitch_change_status (struct fakeswitch *fs, int new_status);

static struct ofp_switch_config Switch_config = {
	.header = { 	OFP_VERSION,
			OFPT_GET_CONFIG_REPLY,
			sizeof(struct ofp_switch_config),
			0},
	.flags = 0,
	.miss_send_len = 0,
};

static inline uint64_t htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t ntohll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}

void fakeswitch_init(struct fakeswitch *fs, int dpid, int sock, int bufsize, int debug, int delay, enum test_mode mode, int total_mac_addresses, int learn_dstmac)
{
    char buf[BUFLEN];
    struct ofp_header ofph;
    fs->sock = sock;
    fs->debug = debug;
    fs->id = dpid;
    fs->inbuf = msgbuf_new(bufsize);
    fs->outbuf = msgbuf_new(bufsize);
    fs->probe_state = 0;
    fs->mode = mode;
    fs->probe_size = make_packet_in(fs->id, 0, 0, buf, BUFLEN, fs->current_mac_address++);
    fs->count = 0;
    fs->switch_status = START;
    fs->delay = delay;
    fs->total_mac_addresses = total_mac_addresses;
    fs->current_mac_address = 0;
    fs->xid = 1;
    fs->learn_dstmac = learn_dstmac;
    fs->current_buffer_id = 1;
  
    ofph.version = OFP_VERSION;
    ofph.type = OFPT_HELLO;
    ofph.length = htons(sizeof(ofph));
    ofph.xid   = htonl(1);

    // Send HELLO
    msgbuf_push(fs->outbuf,(char * ) &ofph, sizeof(ofph));
    debug_msg(fs, " sent hello");
}

/***********************************************************************/

void fakeswitch_learn_dstmac(struct fakeswitch *fs)
{
    // thanks wireshark
    char gratuitous_arp_reply [] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x0c, 
        0x29, 0x1a, 0x29, 0x1a, 0x08, 0x06, 0x00, 0x01, 
        0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x0c, 
        0x29, 0x1a, 0x29, 0x1a, 0x7f, 0x00, 0x00, 0x01, 
        0x00, 0x0c, 0x29, 0x1a, 0x29, 0x1a, 0x7f, 0x00, 
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    char mac_address_to_learn[] = { 0x80, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01 };
    char ip_address_to_learn[] = { 192, 168 , 1, 40 };

    char buf [512];
    int len = sizeof( struct ofp_packet_in ) + sizeof(gratuitous_arp_reply);
    struct ofp_packet_in *pkt_in;
    struct ether_header * eth;
    void * arp_reply;

    memset(buf, 0, sizeof(buf));
    pkt_in = ( struct ofp_packet_in *) buf;

    pkt_in->header.version = OFP_VERSION;
    pkt_in->header.type = OFPT_PACKET_IN;
    pkt_in->header.length = htons(len);
    pkt_in->header.xid = htonl(fs->xid++);

    pkt_in->buffer_id = -1;
    pkt_in->total_len = htons(sizeof(gratuitous_arp_reply));
    pkt_in->in_port = htons(2);
    pkt_in->reason = OFPR_NO_MATCH;

    memcpy(pkt_in->data, gratuitous_arp_reply, sizeof(gratuitous_arp_reply));

    mac_address_to_learn[5] = fs->id;
    ip_address_to_learn[2] = fs->id;

    eth = (struct ether_header * ) pkt_in->data;
    memcpy (eth->ether_shost, mac_address_to_learn, 6);

    arp_reply =  ((void *)  eth) + sizeof (struct ether_header);
    memcpy ( arp_reply + 8, mac_address_to_learn, 6);
    memcpy ( arp_reply + 14, ip_address_to_learn, 4);
    memcpy ( arp_reply + 18, mac_address_to_learn, 6);
    memcpy ( arp_reply + 24, ip_address_to_learn, 4);

    msgbuf_push(fs->outbuf,(char * ) pkt_in, len);
    debug_msg(fs, " sent gratuitous ARP reply to learn about mac address: version %d length %d type %d eth: %x arp: %x ", pkt_in->header.version, len, buf[1], eth, arp_reply);
}


/***********************************************************************/

void fakeswitch_set_pollfd(struct fakeswitch *fs, struct pollfd *pfd)
{
    pfd->events = POLLIN|POLLOUT;
    /* if(msgbuf_count_buffered(fs->outbuf) > 0)
        pfd->events |= POLLOUT; */
    pfd->fd = fs->sock;
}

/***********************************************************************/

int fakeswitch_get_count(struct fakeswitch *fs)
{
    int ret = fs->count;
    int count;
    int msglen;
    struct ofp_header * ofph;
    fs->count = 0;
    fs->probe_state = 0;        // reset packet state
    // keep reading until there is nothing to clear out the queue
    while( (count = msgbuf_read(fs->inbuf,fs->sock)) > 0) {
        while(count > 0) {
            // need to read msg by msg to ensure framing isn't broken
            ofph = msgbuf_peek(fs->inbuf);
            msglen = ntohs(ofph->length);
            if(count < msglen)
                break;     // msg not all there yet; 
            msgbuf_pull(fs->inbuf, NULL, ntohs(ofph->length));
            count -= msglen;
        }
    }
    return ret;
}

/***********************************************************************/
static int parse_set_config(struct ofp_header * msg) {
	struct ofp_switch_config * sc; 
	assert(msg->type == OFPT_SET_CONFIG);
	sc = (struct ofp_switch_config *) msg;
	memcpy(&Switch_config, sc, sizeof(struct ofp_switch_config));

	return 0;
}


/***********************************************************************/
static int make_config_reply( int xid, char * buf, int buflen) {
	int len = sizeof(struct ofp_switch_config);
	assert(buflen >= len);
	Switch_config.header.type = OFPT_GET_CONFIG_REPLY;
	Switch_config.header.xid = xid;
	memcpy(buf, &Switch_config, len);

	return len;
}

/***********************************************************************/
static int              make_features_reply(int id, int xid, char * buf, int buflen)
{
    struct ofp_switch_features * features;
    const char fake[] =     // stolen from wireshark
    {

      0x97,0x06,0x00,0xe0,0x04,0x01,0x00,0x00,0x00,0x00,0x76,0xa9,
      0xd4,0x0d,0x25,0x48,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x07,0xff,0x00,0x01,0x1a,0xc1,0x51,0xff,0xef,0x8a,0x76,0x65,0x74,0x68,
      0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x02,0xce,0x2f,0xa2,0x87,0xf6,0x70,0x76,0x65,0x74,0x68,
      0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x03,0xca,0x8a,0x1e,0xf3,0x77,0xef,0x76,0x65,0x74,0x68,
      0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x04,0xfa,0xbc,0x77,0x8d,0x7e,0x0b,0x76,0x65,0x74,0x68,
      0x37,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00
    };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    features = (struct ofp_switch_features *) buf;
    features->header.version = OFP_VERSION;
    features->header.xid = xid;
    features->datapath_id = htonll(id);
    return sizeof(fake);
}
/***********************************************************************/
static int      make_stats_desc_reply(struct ofp_stats_request * req, 
        char * buf, int buflen) {
    static struct ofp_desc_stats cbench_desc = { 
        .mfr_desc = "Cbench - controller I/O benchmark",
        .hw_desc  = "this is actually software...",
        .sw_desc  = "version " VERSION,
        .serial_num= "none",
        .dp_desc  = "none"
    };
    struct ofp_stats_reply * reply;
    int len = sizeof(struct ofp_stats_reply) + 
                sizeof(struct ofp_desc_stats);
    assert(BUFLEN > len);
    assert(ntohs(req->type) == OFPST_DESC);

    memcpy( buf, req, sizeof(*req));
    reply = (struct ofp_stats_reply *) buf;
    reply->header.type = OFPT_STATS_REPLY;
    reply->header.length = htons(len);
    reply->flags = 0;
    memcpy(reply->body, &cbench_desc, sizeof(cbench_desc));

    return len;
}
/***********************************************************************/
static int make_vendor_reply(int xid, char * buf, int buflen)
{
    struct ofp_error_msg * e;
    assert(buflen> sizeof(struct ofp_error_msg));
    e = (struct ofp_error_msg *) buf;
    e->header.type = OFPT_ERROR;
    e->header.version = OFP_VERSION;
    e->header.length = htons(sizeof(struct ofp_error_msg));
    e->header.xid = xid;
    e->type = htons(OFPET_BAD_REQUEST);
    e->code = htons(OFPBRC_BAD_VENDOR);
    return sizeof(struct ofp_error_msg);
}
/***********************************************************************
 *  return 1 if the embedded packet in the packet_out is lldp
 * 
 */

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

static int packet_out_is_lldp(struct ofp_packet_out * po){
	char * ptr = (char *) po;
	ptr += sizeof(struct ofp_packet_out) + ntohs(po->actions_len);
	struct ether_header * ethernet = (struct ether_header *) ptr;
	unsigned short ethertype = ntohs(ethernet->ether_type);
	if (ethertype == ETHERTYPE_VLAN) {
		ethernet = (struct ether_header *) ((char *) ethernet) +4;
		ethertype = ntohs(ethernet->ether_type);
	}
	
	return ethertype == ETHERTYPE_LLDP;
}

/***********************************************************************/
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address)
{
    struct ofp_packet_in * pi;
    struct ether_header * eth;
    const char fake[] = {
                0x97,0x0a,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
		0x01,0x00,0x40,0x00,0x01,0x00,0x00,0x80,0x00,0x00,0x00,
		0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x02,0x08,0x00,0x45,
		0x00,0x00,0x32,0x00,0x00,0x00,0x00,0x40,0xff,0xf7,0x2c,
		0xc0,0xa8,0x00,0x28,0xc0,0xa8,0x01,0x28,0x7a,0x18,0x58,
                0x6b,0x11,0x08,0x97,0xf5,0x19,0xe2,0x65,0x7e,0x07,0xcc,
                0x31,0xc3,0x11,0xc7,0xc4,0x0c,0x8b,0x95,0x51,0x51,0x33,
                0x54,0x51,0xd5,0x00,0x36};
    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    pi = (struct ofp_packet_in *) buf;
    pi->header.version = OFP_VERSION;
    pi->header.xid = htonl(xid);
    pi->buffer_id = htonl(buffer_id);
    eth = (struct ether_header * ) pi->data;
    // copy into src mac addr; only 4 bytes, but should suffice to not confuse
    // the controller; don't overwrite first byte
    memcpy(&eth->ether_shost[1], &mac_address, sizeof(mac_address));
    // mark this as coming from us, mostly for debug
    eth->ether_dhost[5] = switch_id;
    eth->ether_shost[5] = switch_id;
    return sizeof(fake);
}

void fakeswitch_change_status_now (struct fakeswitch *fs, int new_status) {
    fs->switch_status = new_status;
    if(new_status == READY_TO_SEND) {
        fs->count = 0;
        fs->probe_state = 0;
    }
        
}

void fakeswitch_change_status(struct fakeswitch *fs, int new_status) {
    if( fs->delay == 0) {
        fakeswitch_change_status_now(fs, new_status);
        debug_msg(fs, " switched to next status %d", new_status);
    } else {
        fs->switch_status = WAITING;
        fs->next_status = new_status;
        gettimeofday(&fs->delay_start, NULL);
        fs->delay_start.tv_sec += fs->delay / 1000;
        fs->delay_start.tv_usec += (fs->delay % 1000 ) * 1000;
        debug_msg(fs, " delaying next status %d by %d ms", new_status, fs->delay);
    }

}


/***********************************************************************/
void fakeswitch_handle_read(struct fakeswitch *fs)
{
    int count;
    struct ofp_header * ofph;
    struct ofp_header echo;
    struct ofp_header barrier;
    char buf[BUFLEN];
    count = msgbuf_read(fs->inbuf, fs->sock);   // read any queued data
    if (count <= 0)
    {
        fprintf(stderr, "controller msgbuf_read() = %d:  ", count);
        if(count < 0)
            perror("msgbuf_read");
        else
            fprintf(stderr, " closed connection ");
        fprintf(stderr, "... exiting\n");
        exit(1);
    }
    while((count= msgbuf_count_buffered(fs->inbuf)) >= sizeof(struct ofp_header ))
    {
        ofph = msgbuf_peek(fs->inbuf);
        if(count < ntohs(ofph->length))
            return;     // msg not all there yet
        msgbuf_pull(fs->inbuf, NULL, ntohs(ofph->length));
        switch(ofph->type)
        {
            struct ofp_flow_mod * fm;
            struct ofp_packet_out *po;
            struct ofp_stats_request * stats_req;
            case OFPT_PACKET_OUT:
                po = (struct ofp_packet_out *) ofph;
                if ( fs->switch_status == READY_TO_SEND && ! packet_out_is_lldp(po)) { 
                    // assume this is in response to what we sent
                    fs->count++;        // got response to what we went
                    fs->probe_state--;
                }
                break;
            case OFPT_FLOW_MOD:
                fm = (struct ofp_flow_mod *) ofph;
                if(fs->switch_status == READY_TO_SEND && (fm->command == htons(OFPFC_ADD) || 
                        fm->command == htons(OFPFC_MODIFY_STRICT)))
                {
                    fs->count++;        // got response to what we went
                    fs->probe_state--;
                }
                break;
            case OFPT_FEATURES_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got feature_req");
                // Send features reply
                count = make_features_reply(fs->id, ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent feature_rsp");
                fakeswitch_change_status(fs, fs->learn_dstmac ? LEARN_DSTMAC : READY_TO_SEND);
                break;
            case OFPT_SET_CONFIG:
                // pull msgs out of buffer
                debug_msg(fs, "parsing set_config");
		parse_set_config(ofph);
                break;
            case OFPT_GET_CONFIG_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got get_config_request");
                count = make_config_reply(ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
		if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 1 )) {     
		    fs->probe_state = 0;       // restart probe state b/c some 
					       // controllers block on config
                	debug_msg(fs, "reset probe state b/c of get_config_reply");
		}
                debug_msg(fs, "sent get_config_reply");
                break;
            case OFPT_VENDOR:
                // pull msgs out of buffer
                debug_msg(fs, "got vendor");
                count = make_vendor_reply(ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent vendor");
                // apply nox hack; nox ignores packet_in until this msg is sent
                fs->probe_state=0;
                break;
            case OFPT_HELLO:
                debug_msg(fs, "got hello");
                // we already sent our own HELLO; don't respond
                break;
            case OFPT_ECHO_REQUEST:
                debug_msg(fs, "got echo, sent echo_resp");
                echo.version= OFP_VERSION;
                echo.length = htons(sizeof(echo));
                echo.type   = OFPT_ECHO_REPLY;
                echo.xid = ofph->xid;
                msgbuf_push(fs->outbuf,(char *) &echo, sizeof(echo));
                break;
            case OFPT_BARRIER_REQUEST:
                debug_msg(fs, "got barrier, sent barrier_resp");
                barrier.version= OFP_VERSION;
                barrier.length = htons(sizeof(barrier));
                barrier.type   = OFPT_BARRIER_REPLY;
                barrier.xid = ofph->xid;
                msgbuf_push(fs->outbuf,(char *) &barrier, sizeof(barrier));
                break;
            case OFPT_STATS_REQUEST:
                stats_req  = (struct ofp_stats_request *) ofph;
                if ( ntohs(stats_req->type) == OFPST_DESC ) {
                    count = make_stats_desc_reply(stats_req, buf, BUFLEN);
                    msgbuf_push(fs->outbuf, buf, count);
                    debug_msg(fs, "sent description stats_reply");
                    if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 1 )) {     
                        fs->probe_state = 0;       // restart probe state b/c some 
                                       // controllers block on config
                                debug_msg(fs, "reset probe state b/c of desc_stats_request");
                    }
                } else {
                    debug_msg(fs, "Silently ignoring non-desc stats_request msg\n");
                }
                break;
            default: 
    //            if(fs->debug)
                    fprintf(stderr, "Ignoring OpenFlow message type %d\n", ofph->type);
        };
        if(fs->probe_state < 0)
        {
                debug_msg(fs, "WARN: Got more responses than probes!!: : %d",
                            fs->probe_state);
                fs->probe_state =0;
        }
    }
}
/***********************************************************************/
static void fakeswitch_handle_write(struct fakeswitch *fs)
{
    char buf[BUFLEN];
    int count ;
    int send_count = 0 ;
    int throughput_buffer = BUFLEN;
    int i;
    if( fs->switch_status == READY_TO_SEND) 
    {
        if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 0 ))      
            send_count = 1;                 // just send one packet
        else if ((fs->mode == MODE_THROUGHPUT) && 
                (msgbuf_count_buffered(fs->outbuf) < throughput_buffer))  // keep buffer full
            send_count = (throughput_buffer - msgbuf_count_buffered(fs->outbuf)) / fs->probe_size;
        for (i = 0; i < send_count; i++)
        {
            // queue up packet
            
            fs->probe_state++;
            // TODO come back and remove this copy
            count = make_packet_in(fs->id, fs->xid++, fs->current_buffer_id, buf, BUFLEN, fs->current_mac_address);
            fs->current_mac_address = ( fs->current_mac_address + 1 ) % fs->total_mac_addresses;
            fs->current_buffer_id =  ( fs->current_buffer_id + 1 ) % NUM_BUFFER_IDS;
            msgbuf_push(fs->outbuf, buf, count);
            debug_msg(fs, "send message %d", i);
        }
    } else if( fs->switch_status == WAITING) 
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (timercmp(&now, &fs->delay_start, > ))
        {
            fakeswitch_change_status_now(fs, fs->next_status);
            debug_msg(fs, " delay is over: switching to state %d", fs->next_status);
        }
    } else if (  fs->switch_status == LEARN_DSTMAC) 
    {
        // we should learn the dst mac addresses
        fakeswitch_learn_dstmac(fs);
        fakeswitch_change_status(fs, READY_TO_SEND);
    }
    // send any data if it's queued
    if( msgbuf_count_buffered(fs->outbuf) > 0)
        msgbuf_write(fs->outbuf, fs->sock, 0);
}
/***********************************************************************/
void fakeswitch_handle_io(struct fakeswitch *fs, const struct pollfd *pfd)
{
    if(pfd->revents & POLLIN)
        fakeswitch_handle_read(fs);
    if(pfd->revents & POLLOUT)
        fakeswitch_handle_write(fs);
}
/************************************************************************/
static int debug_msg(struct fakeswitch * fs, char * msg, ...)
{
    va_list aq;
    if(fs->debug == 0 )
        return 0;
    fprintf(stderr,"\n-------Switch %d: ", fs->id);
    va_start(aq,msg);
    vfprintf(stderr,msg,aq);
    if(msg[strlen(msg)-1] != '\n')
        fprintf(stderr, "\n");
    // fflush(stderr);     // should be redundant, but often isn't :-(
    return 1;
}
