#ifndef OFLOPS_SNMP_H
#define OFLOPS_SNMP_H

struct snmp_channel;
struct snmp_event;

#include "context.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/** Structure to hold SNMP reply.
 *
 * @date December, 2009
 * @author ykk (Stanford University)
 */
typedef struct snmp_event
{
  /** SNMP variable list
   */
  struct variable_list* reply;
  /** Pointer to SNMP reply
   */
  struct snmp_pdu* pdu;
} snmp_event;

/** Structure to hold SNMP channel information.
 *
 * @date December 2009
 * @author ykk (Stanford University)
 */
typedef struct snmp_channel
{
  /** Hostname of SNMP agent.
   */
  char* hostname;
  /** SNMP community string.
   */
  char* community_string;
  /** Reference to session.
   */
  struct snmp_session session;
  /** Reference to packet
   */
  struct snmp_pdu* req;
} snmp_channel;

/** Initialize SNMP channel.
 * @param host IP address of SNPM agent
 * @param community_string
 * @return 0
 */
int snmp_channel_init(struct snmp_channel* channel, 
		      char* host, char* community_string);

/** Setup SNMP session.
 * @param ctx context (includes reference to SNMP session/setup)
 */
void setup_snmp_channel(struct oflops_context* ctx);

/** Callback function for SNMP
 * @param operation type of SNMP operation
 * @param sp pointer to SNMP session
 * @param reqid required id
 * @param pdu pointer to SNMP PDU
 * @param magic magic object with request
 * @return 0
 */
int snmp_response(int operation, struct snmp_session *sp, int reqid,
		  struct snmp_pdu *pdu, void *magic);

/** Teardown SNMP session.
 * @param ctx context (includes reference to SNMP session/setup)
 */
void teardown_snmp_channel(struct oflops_context* ctx);
#endif
