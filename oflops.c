#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <pcap.h>

#include "oflops.h"
#include "usage.h"
#include "control.h"
#include "context.h"
#include "module_run.h"
#include "log.h"
#include "signal.h"
#include "traffic_generator.h"


void * 
run_module(void *param) {
  struct run_module_param* tmp = (struct run_module_param *)param;
  return (void *)run_test_module(tmp->ctx, tmp->ix_mod);
}

void *
start_traffic_thread(void *param) {
  struct run_module_param* tmp = (struct run_module_param *)param;
  return (void *)run_traffic_generation(tmp->ctx, tmp->ix_mod);

}

int main(int argc, char * argv[])
{
  int i, j;
  struct pcap_stat ps;
  pthread_t *thread, event_thread, traffic_gen;
  struct run_module_param *param =  malloc_and_check(sizeof(struct run_module_param));
  char msg[1024];
  struct timeval now;

  // create the default context
  oflops_context * ctx = oflops_default_context();
  param->ctx = ctx;
  parse_args(ctx, argc, argv);

  if(ctx->n_tests == 0 )
    usage("Need to specify at least one module to run\n",NULL);

  oflops_log_init(ctx->log);
  setup_control_channel(ctx);

  fprintf(stderr, "Running %d Test%s\n", ctx->n_tests, ctx->n_tests>1?"s":"");

  for(i=0;i<ctx->n_tests;i++)
  {
    fprintf(stderr, "-----------------------------------------------\n");
    fprintf(stderr, "------------ TEST %s ----------\n", (*(ctx->tests[i]->name))());
    fprintf(stderr, "-----------------------------------------------\n");
    reset_context(ctx);
    ctx->curr_test = ctx->tests[i];
    param->ix_mod = i;
    setup_test_module(ctx,i);
    thread =  malloc_and_check(sizeof(pthread_t));
    pthread_create(thread, NULL, run_module, (void *)param);
    pthread_create(&traffic_gen, NULL, start_traffic_thread, (void *)param);
    pthread_create(&event_thread, NULL, event_loop, (void *)param);
    pthread_join(*thread, NULL);
    pthread_join(event_thread, NULL);
    pthread_cancel(traffic_gen); 
    free(thread);
    gettimeofday(&now, NULL);
    for(j = 0 ; j < ctx->n_channels;j++) {
      if(ctx->channels[j].pcap_handle == NULL) continue;
      pcap_stats(ctx->channels[j].pcap_handle, &ps);
      snprintf(msg, 1024, "%s:%u:%u",ctx->channels[j].dev, ps.ps_recv, ps.ps_drop);
      oflops_log(now, PCAP_MSG, msg);
      printf("%s\n", msg);
    }

    oflops_log(now, PKTGEN_MSG, report_traffic_generator(ctx));
    printf("%s\n", report_traffic_generator(ctx));
  }

  oflops_log_close();

  fprintf(stderr, "-----------------------------------------------\n");
  fprintf(stderr, "---------------    Finished   -----------------\n");
  fprintf(stderr, "-----------------------------------------------\n");
  return 0;
}
