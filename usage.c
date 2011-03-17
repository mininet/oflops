#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openflow/openflow.h"
#include "context.h"


#include "usage.h"
#include "utils.h"
#include "module_run.h"
#include "log.h"


struct option oflops_options[] = {
  // 	name	, has_arg,  *var, val
  {"control-dev", required_argument, NULL, 'c'},     // --control-dev eth0
  {"snmp-dev", optional_argument, NULL, 's'}, 	     // --snmp-dev necsw.openflow.org
  {"data-dev", required_argument, NULL, 'd'},        // --data-dev eth1
  {"port", required_argument, NULL, 'p'}, 	     // --port 6633
  {"log", required_argument, DEFAULT_LOG_FILE, 'o'}, // --log oflops.log
  {"generator", required_argument, 2, 'g'}, 	     // -g 1
  {"trace", no_argument, 2, 't'}, 		     // -t 1
  {"input_config", required_argument, NULL, 'i'},    // -i 1
  { 0 , 0 , 0, 0}
};

char * option_args[] =  {
  "",			// no argument
  "<required_arg>",	//required arg
  "[optional arg]",	// optional arg
};

static char * make_short_from_long(struct option long_options[]);
static void parse_test_module(oflops_context * ctx, int argc, char * argv[]);

/*****************************************************************************
 * int parse_args(oflops_context * ctx, int argc, char * argv[])
 * 	
 **/

int parse_args(oflops_context * ctx, int argc, char * argv[])
{
  int c;
  int snmp_arg = 0;
  int options_index;
  char* snmp_client;
  char* snmp_community;
  char * short_options = make_short_from_long(oflops_options);

  while(1)
    {
      c = getopt_long(argc, argv, short_options, oflops_options, &options_index);
      if( c == -1 )
	break;	// done args parsing
      switch(c)
	{
	case 'c':
	  assert(OFLOPS_CONTROL == 0);
	  assert(ctx->n_channels > 0);
	  if(!optarg)
	    usage(argv[optind], "requires argument");
	  channel_info_init(&ctx->channels[OFLOPS_CONTROL],optarg);
	  fprintf(stderr,"Setting control channel to %s\n", optarg);
	  break;
	case 's':
	  snmp_arg++;
	  assert(snmp_arg < 2);
	  if(!optarg)
	    usage(argv[optind], "requires argument");
	  snmp_client = strtok(optarg, SNMP_DELIMITER);
	  snmp_community = strtok(NULL, SNMP_DELIMITER);
	  snmp_channel_init(ctx->snmp_channel_info, snmp_client, snmp_community);
	  fprintf(stderr,"Adding SNMP channel on %s with community string %s.\n", 
		  snmp_client, snmp_community);
	  break;
	case 'd':
	  if(ctx->n_channels >= ctx->max_channels)	// resize array if needed
	    {
	      ctx->max_channels *= 2;
	      ctx->channels = realloc_and_check(ctx->channels, ctx->max_channels * sizeof(channel_info));
	    }
	  if(!optarg)
	    usage(argv[optind], "requires argument");
	  channel_info_init(&ctx->channels[ctx->n_channels++], optarg);
	  if(ctx->channels[ctx->n_channels-1].of_port == -1)
	    ctx->channels[ctx->n_channels-1].of_port = ctx->n_channels-1;
	  fprintf(stderr,"Adding a data channel on %s\n", optarg);
	  break;
	case 'p':
	  ctx->listen_port = atoi(optarg);
	  fprintf(stderr,"Setting Control listen port to %d\n", ctx->listen_port);
	  break;
	case 'o':
	  free(ctx->log);
	  ctx->log = malloc(strlen(optarg) + 1);
	  strcpy(ctx->log, optarg);
	  fprintf(stderr,"Setting log file to %s\n", optarg);
	  break;
	case 'g':
	  ctx->trafficGen = strtol(optarg, NULL, 10);
	  if((ctx->trafficGen < 1) || (ctx->trafficGen > 2)) {
	    fprintf(stderr,"traffic generator %d is invalid\n", ctx->trafficGen);
	    ctx->trafficGen = 2;
	  } else {
	    fprintf(stderr,"Using traffic generator %d\n", ctx->trafficGen);
	  }
	  break;
	case 'i':
	  printf("configuration file: %s\n", optarg);
	  load_config_file(ctx, optarg);
	  break;
	case 't':
	  ctx->dump_controller = 1;
	  break;
	default:
	  usage("unknown option", argv[optind]);
	}
    }

  // skip ahead to any other args
  argc-=optind;
  argv+=optind;
  if(argc > 0)
    parse_test_module(ctx, argc, argv);
  return 0;
}

/****************************************************************************
 * static char * make_short_from_long(struct option long_options[]);
 **/
static char * make_short_from_long(struct option long_options[])
{
  static char buf[BUFLEN];
  int buf_index=0;
  int opt_index=0;

  bzero(buf,BUFLEN);
  while(oflops_options[opt_index].name != NULL)
    {
      buf[buf_index++] = oflops_options[opt_index].val;
      if(oflops_options[opt_index].has_arg)
	buf[buf_index++] = ':';
      opt_index++;
    }
  return buf;
}

/***************************************************************
 * void usage(char * s1, char *s2);
 * 	print usage information and exit
 **/
void usage(char * s1, char *s2)
{
  struct option * o;
  int i = 0;
  if(s1)
    fprintf(stderr, "%s",s1);
  if(s2)
    fprintf(stderr, " %s",s2);
  if (s1|| s2)
    fprintf(stderr, "\n");
  fprintf( stderr, "Usage:\noflops [options]\n");
  o = &oflops_options[i];
  do {
    fprintf(stderr, "\t-%c|--%s\t%s\n",
	    o->val,
	    o->name,
	    option_args[o->has_arg]
	    );

    i++;
    o = &oflops_options[i];
  } while(o->name);

  fprintf(stderr, "\n\nExample invocation:\n"
	  "oflops -o oflops.log -c eth0 -s 10.2.3.4:public -d eth1 -d eth2 -p 6633 liboflops_debug.so test_args\n");

  exit(1);
}
/**************************************************************************
 * static void parse_test_module(oflops_context * ctx, int argc, char * argv[]);
 * 	parse a test module from argc/argv and try loading it
 **/
static void parse_test_module(oflops_context * ctx, int argc, char * argv[])
{
  char buf[BUFLEN];
  int count=0;
  int i;

  if(argc==0)
    usage("need to specify a test_module to load\n",NULL);
  // turn all of the args into a single string
  for(i=1;((count < BUFLEN) && (i<argc)); i++)
    count += snprintf((buf+count),BUFLEN-count-1, " %s", argv[i]);
  if(load_test_module(ctx,argv[0],buf))
    fprintf(stderr, "Failed to load test_module %s\n", argv[0]);
}

int 
load_config_file(oflops_context * ctx, const char *config) {
  config_t conf;
  config_setting_t *elem, *data;
  char *snmp_client, *snmp_community;
  int i, len, argc = 0;
  char *path, **argv, *in_oid, *out_oid;

  config_init(&conf);
  if(config_read_file(&conf, config) == CONFIG_FALSE) {
    fprintf(stderr, "failed %s:%d %s\n", config, config_error_line(&conf), config_error_text(&conf));
    return -1;
  }

  //reading the traffic generator paramters
  elem = config_lookup(&conf, "oflops.traffic_generator");
  if(elem != NULL) {
    if(config_setting_get_int(elem) != 0)
    ctx->trafficGen = config_setting_get_int(elem);
  }

  //reading the traffic generator paramters
  elem = config_lookup(&conf, "oflops.dump_control_channel");
  if(elem != NULL) {
    if(config_setting_get_int(elem) != 0)
      ctx->dump_controller = config_setting_get_int(elem);
  }

  elem = config_lookup(&conf, "oflops.control.control_dev");
  if(elem != NULL) {
    if(config_setting_get_string(elem) != NULL) {
      printf("Setting up control channel on %s\n", config_setting_get_string(elem));
      channel_info_init(&ctx->channels[OFLOPS_CONTROL], config_setting_get_string(elem));
    }
  }

  elem = config_lookup(&conf, "oflops.control.control_port");
  if(elem != NULL) {
    if(config_setting_get_int(elem) != 0) {
      ctx->listen_port = config_setting_get_int(elem);
    }
  } //oflops.control.control_port

  elem = config_lookup(&conf, "oflops.control.snmp_addr");
  if(elem != NULL) {
    if(config_setting_get_string(elem) != NULL) {
      snmp_client = malloc(strlen(config_setting_get_string(elem)) + 1);
      strcpy(snmp_client, config_setting_get_string(elem));
      if( (elem = config_lookup(&conf, "oflops.control.snmp_community")) != NULL) {
	snmp_community = malloc(strlen(config_setting_get_string(elem)) + 1);
	strcpy(snmp_community, config_setting_get_string(elem));
      }
      snmp_channel_init(ctx->snmp_channel_info, snmp_client, snmp_community);
      fprintf(stderr,"Adding SNMP channel on %s with community string %s.\n", 
	      snmp_client, snmp_community);

      free(snmp_client);
      free(snmp_community);
    }
  } //oflops.control.snmp_addr

  //reading snmp mib for ports of the control channel
  if(in_oid != NULL) free(in_oid);
  in_oid = NULL;
  if(out_oid != NULL) free(out_oid);
  out_oid = NULL;
	
  if(((elem = config_lookup(&conf, "oflops.control.in_mib")) != NULL) && 
     (strlen( config_setting_get_string(elem)) > 0) ) {
    in_oid = malloc(strlen(config_setting_get_string(elem)) + 1);
    strcpy(in_oid,config_setting_get_string(elem));
  } 
  if( ((elem = config_lookup(&conf, "oflops.control.out_mib")) != NULL) && 
      (strlen(config_setting_get_string(elem)) > 0) ) {
    out_oid = malloc(strlen(config_setting_get_string(elem)) + 1);
    strcpy(out_oid,config_setting_get_string(elem));
  } 
  setup_channel_snmp(ctx, OFLOPS_CONTROL, in_oid, out_oid);
  
  if(((elem = config_lookup(&conf, "oflops.control.cpu_mib")) != NULL) && 
     (strlen( config_setting_get_string(elem)) > 0) ) {
    out_oid = malloc(strlen(config_setting_get_string(elem)) + 1);
    strcpy(out_oid,config_setting_get_string(elem));

    if(!my_read_objid(out_oid, ctx->cpuOID, &ctx->cpuOID_len)) 
      //    if(snmp_parse_oid(out_oid, ctx->cpuOID, &ctx->cpuOID_len) == NULL)
      perror_and_exit("read_objid failed", 1);  
  } 
  
  //setting up details regarding the data ports from the data 
  if((data = config_lookup(&conf, "oflops.data") ) != NULL ) {
    for (i=0; i < config_setting_length(data); i++) {
      elem = config_setting_get_elem(data, i);
      if(config_setting_get_member(elem, "dev") != NULL) {
	if(ctx->n_channels >= ctx->max_channels) {
	  ctx->max_channels *= 2;
	  ctx->channels = realloc_and_check(ctx->channels, ctx->max_channels * sizeof(channel_info));
	}
	channel_info_init(&ctx->channels[ctx->n_channels++], config_setting_get_string(config_setting_get_member(elem, "dev")));
	fprintf(stderr,"Adding a data channel on %s\n", config_setting_get_string(config_setting_get_member(elem, "dev")));
	if(config_setting_get_member(elem, "port_num") != NULL) {
	  ctx->channels[ctx->n_channels-1].of_port = config_setting_get_int(config_setting_get_member(elem, "port_num"));
	} else
	  ctx->channels[ctx->n_channels-1].of_port = ctx->n_channels-1;

	//reading snmp mib for ports
	if(in_oid != NULL) free(in_oid);
	in_oid = NULL;
	if(out_oid != NULL) free(out_oid);
	out_oid = NULL;
	
	if((config_setting_get_member(elem, "in_snmp_mib") != NULL) && 
	   (strlen( config_setting_get_string(config_setting_get_member(elem, "in_snmp_mib"))) > 0) ) {
	  in_oid = malloc(strlen(config_setting_get_string(config_setting_get_member(elem, "in_snmp_mib"))) + 1);
	  strcpy(in_oid,config_setting_get_string(config_setting_get_member(elem, "in_snmp_mib")));
	} 
	if((config_setting_get_member(elem, "out_snmp_mib") != NULL) && 
	   (strlen( config_setting_get_string(config_setting_get_member(elem, "out_snmp_mib"))) > 0) ) {
	  out_oid = malloc(strlen(config_setting_get_string(config_setting_get_member(elem, "out_snmp_mib"))) + 1);
	  strcpy(out_oid,config_setting_get_string(config_setting_get_member(elem, "out_snmp_mib")));
	} 
	setup_channel_snmp(ctx, ctx->n_channels-1, in_oid, out_oid);
	
	//TODO: fixe how we assign the SNMP MIB "snmp_mib"
      }
    }
  } //data

  if((data = config_lookup(&conf, "oflops.module") ) != NULL ) {
    for (i=0; i < config_setting_length(data); i++) {
      elem = config_setting_get_elem(data, i);

      if(config_setting_get_member(elem, "path") != NULL)  {
	path = config_setting_get_string(config_setting_get_member(elem, "path"));
	argc++;
	len = strlen(path);
	argv = malloc(1);
	argv[0] = malloc(len + 1);
	strcpy(argv[0], path);
	if(config_setting_get_member(elem, "param") != NULL)  {
	  path = config_setting_get_string(config_setting_get_member(elem, "param"));
	  argv = realloc(argv, 2);
	  argc++; //[len] = ' ';
	  argv[1] = malloc(strlen(path) + 1);
	  strcpy(argv[1], path);
	}

	parse_test_module(ctx, argc, argv);
	for (i=0;i<argc;i++)
	  free(argv[i]);
	free(argv);
      }
    }
  }
  
  config_destroy(&conf); 
};
