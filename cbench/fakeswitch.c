#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openflow/openflow.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include "cbench.h"
#include "fakeswitch.h"


static int make_features_reply(int switch_id, int xid, char * buf, int buflen);
static int make_packet_in(int switch_id, int buffer_id, char * buf, int buflen);

void fakeswitch_init(struct fakeswitch *fs, int sock, int bufsize, int debug)
{
    static int ID =1 ;
    struct ofp_header * ofphptr;
    struct ofp_header ofph;
    char buf[BUFLEN];
    int count;
    fs->sock = sock;
    fs->debug = debug;
    fs->id = ID++;
    fs->inbuf = msgbuf_new(bufsize);
    fs->outbuf = msgbuf_new(bufsize);
    fs->packet_sent = 0;
    fs->count = 0;

    ofph.version = OFP_VERSION;
    ofph.type = OFPT_HELLO;
    ofph.length = htons(sizeof(ofph));
    ofph.xid   = htonl(1);

    // Send ofph
    msgbuf_push(fs->outbuf,(char * ) &ofph, sizeof(ofph));
    msgbuf_write_all(fs->outbuf, fs->sock);
    if(fs->debug)
        fprintf(stderr, " sent hello");
    fflush(stderr);

    // Recv HELLO
    if(msgbuf_read_all(fs->inbuf, fs->sock, sizeof(ofph)) < 0)
    {
        perror("msgbuf_read_all");
        exit(1);
    }
    msgbuf_pull( fs->inbuf, (char * ) &ofph, sizeof(ofph));
    if( ofph.type != OFPT_HELLO)
    {
        fprintf(stderr, "Got unexpected openflow msg type %d on init: giving up..\n", ofph.type);
        exit(1);
    }
    if(fs->debug)
        fprintf(stderr, ", got hello");
    fflush(stderr);
    // Recv next msgs
    count = msgbuf_count_buffered(fs->inbuf);
    if(count < sizeof(ofph))
    {
        if(msgbuf_read_all(fs->inbuf, fs->sock, sizeof(ofph)) < 0)
        {
            perror("msgbuf_read_all");
            exit(1);
        }
    }

    while(msgbuf_count_buffered(fs->inbuf) > 0 )
    {
        ofphptr  = msgbuf_peek( fs->inbuf);
        switch(ofphptr->type)
        {
            case OFPT_FEATURES_REQUEST:
                // pull msgs out of buffer
                msgbuf_pull(fs->inbuf, NULL, sizeof(struct ofp_header));
                if(fs->debug)
                    fprintf(stderr, ", got feature_req");
                fflush(stderr);
                // Send features reply
                count = make_features_reply(fs->id, ofph.xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                msgbuf_write_all(fs->outbuf, fs->sock);
                if(fs->debug)
                    fprintf(stderr, ", sent feature_rsp");
                fflush(stderr);
                break;
            case OFPT_SET_CONFIG:
                // pull msgs out of buffer
                msgbuf_pull(fs->inbuf, NULL, sizeof(struct ofp_switch_config));
                if(fs->debug)
                    fprintf(stderr, ", got config ");
                fflush(stderr);
                break;
            default:
                fprintf(stderr, "Got unexpected openflow msg type %d on init: giving up..\n", ofph.type);
            exit(1);
        };
    }
}

/***********************************************************************/

void fakeswitch_set_pollfd(struct fakeswitch *fs, struct pollfd *pfd)
{
    pfd->events = POLLIN|POLLOUT;
    pfd->fd = fs->sock;
}

/***********************************************************************/

int fakeswitch_get_count(struct fakeswitch *fs)
{
    int ret = fs->count;
    fs->count = 0;
    fs->packet_sent = 0;
    usleep(100000); // sleep for 100 ms
    msgbuf_read(fs->inbuf,fs->sock);     // try to clear out anything in the queue
    msgbuf_clear(fs->inbuf);
    msgbuf_clear(fs->outbuf);
    return ret;
}

/***********************************************************************/
static int              make_features_reply(int id, int xid, char * buf, int buflen)
{
    struct ofp_switch_features * features;
    const char fake[] =     // stolen from wireshark
    {
        0x97,0x06,0x00,0xe0,0x04,0x01,0x00,0x00,0x00,0x00,0x76,0xa9,
        0xd4,0x0d,0x25,0x48,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x1f,
        0x00,0x00,0x03,0xff,0x00,0x00,0x1a,0xc1,0x51,0xff,0xef,0x8a,0x76,0x65,0x74,0x68,
        0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x01,0xce,0x2f,0xa2,0x87,0xf6,0x70,0x76,0x65,0x74,0x68,
        0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x02,0xca,0x8a,0x1e,0xf3,0x77,0xef,0x76,0x65,0x74,0x68,
        0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x03,0xfa,0xbc,0x77,0x8d,0x7e,0x0b,0x76,0x65,0x74,0x68,
        0x37,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    features = (struct ofp_switch_features *) buf;
    features->header.version = OFP_VERSION;
    features->header.xid = xid;
    features->datapath_id = id + (id<<2) + (id<< 3) + (id << 4) + (id << 5);    // hack for nox; 
                                                                        // make sure not just the top two bytes are non-zero
    return sizeof(fake);
}
/***********************************************************************/
static int make_packet_in(int switch_id, int buffer_id, char * buf, int buflen)
{
    struct ofp_packet_in * pi;
    struct ether_header * eth;
    const char fake[] = {
                0x97,0x0a,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
                0x01,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
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
    pi->buffer_id = htonl(buffer_id);
    eth = (struct ether_header * ) pi->data;
    eth->ether_shost[5] = switch_id;     // mark this as coming from us, mostly for debug
    return sizeof(fake);
}
/***********************************************************************/
void fakeswitch_handle_read(struct fakeswitch *fs)
{
    int count;
    struct ofp_header * ofph;
    struct ofp_header echo;
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
    while((count= msgbuf_count_buffered(fs->inbuf)) > sizeof(struct ofp_header ))
    {
        ofph = msgbuf_peek(fs->inbuf);
        if(count < ntohs(ofph->length))
            return;     // msg not all there yet
        count = msgbuf_pull(fs->inbuf, buf, BUFLEN);
        ofph = (struct ofp_header * ) buf;
        switch(ofph->type)
        {
            struct ofp_flow_mod * fm;
            case OFPT_FLOW_MOD:
                fm = (struct ofp_flow_mod *) ofph;
                if(ntohl(fm->buffer_id) == fs->packet_sent)
                {
                    fs->count++;        // got response to what we went
                    fs->packet_sent = 0;
                }
                else 
                {
                    if(fs->debug)
                        fprintf(stderr, "Ignoring unsolicited flow_mod %d was looking for %d \n", 
                                    ntohl(fm->buffer_id),
                                    fs->packet_sent);
                }
                break;
            case OFPT_ECHO_REQUEST:
                echo.version= OFP_VERSION;
                echo.length = htons(sizeof(echo));
                echo.type   = OFPT_ECHO_REPLY;
                echo.xid = ofph->xid;
                break;
            default: 
                if(fs->debug)
                    fprintf(stderr, "Ignoring OpenFlow message type %d\n", ofph->type);
        };
    }
}
/***********************************************************************/
void fakeswitch_handle_write(struct fakeswitch *fs)
{
    static int BUFFER_ID=256;
    char buf[BUFLEN];
    int count ;
    if( fs->packet_sent == 0)
    {
        // queue up packet
        if(BUFFER_ID < 256)     // prevent wrapping
            BUFFER_ID = 256;
        fs->packet_sent = BUFFER_ID++;
        count = make_packet_in(fs->id, fs->packet_sent, buf, BUFLEN);
        msgbuf_push(fs->outbuf, buf, count);
    }
    // send any data if it's queued
    if( msgbuf_count_buffered(fs->outbuf) > 0)
        msgbuf_write(fs->outbuf, fs->sock);
}
/***********************************************************************/
void fakeswitch_handle_io(struct fakeswitch *fs, const struct pollfd *pfd)
{
    if(pfd->revents & POLLIN)
        fakeswitch_handle_read(fs);
    if(pfd->revents & POLLOUT)
        fakeswitch_handle_write(fs);
}

