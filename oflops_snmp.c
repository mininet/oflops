#include "oflops_snmp.h"
#include <utils.h>

int snmp_channel_init(struct snmp_channel* channel, 
		      char* host, char* community_string)
{
  bzero(channel, sizeof(snmp_channel));
  channel->hostname = strdup(host);
  channel->community_string = strdup(community_string);
  return 0;
}

void setup_snmp_channel(struct oflops_context* ctx)
{
  if ((ctx->snmp_channel_info->hostname == NULL) ||
      (ctx->snmp_channel_info->community_string == NULL))
    return;

  fprintf(stderr, "Setting up SNMP\n");

  init_snmp("oflops");
  init_mib();
  add_mibdir("/var/lib/mibs/ietf/");
  snmp_sess_init(&ctx->snmp_channel_info->session);
  ctx->snmp_channel_info->session.version = SNMP_VERSION_2c;
  ctx->snmp_channel_info->session.peername = \
    ctx->snmp_channel_info->hostname;
  ctx->snmp_channel_info->session.community = \
    (unsigned char*) ctx->snmp_channel_info->community_string;
  ctx->snmp_channel_info->session.community_len = \
    strlen(ctx->snmp_channel_info->community_string);
  ctx->snmp_channel_info->session.callback = snmp_response;
  ctx->snmp_channel_info->session.callback_magic = ctx;

  ctx->snmp_channel_info->req = NULL;
}

int snmp_response(int operation, struct snmp_session *sp, int reqid,
		  struct snmp_pdu *pdu, void * magic)
{
  struct oflops_context* ctx = (struct oflops_context*) magic;
  if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE)
  {
    struct snmp_event* se = malloc_and_check(sizeof(snmp_event));
    se->pdu = pdu;
    se->reply = pdu->variables;
    ctx->curr_test->handle_snmp_event(ctx, se);
    free(se);
  }
  return 0;
}

void teardown_snmp_channel(struct oflops_context* ctx)
{
  if (ctx->snmp_channel_info->req != NULL)
    snmp_free_pdu(ctx->snmp_channel_info->req);

  if ((ctx->snmp_channel_info->hostname == NULL) ||
      (ctx->snmp_channel_info->community_string == NULL))
    return;

  fprintf(stderr, "Tearing down SNMP\n");
  snmp_close(&ctx->snmp_channel_info->session);
}

