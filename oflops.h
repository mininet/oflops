#ifndef OFLOPS_H
#define OFLOPS_H

struct oflops_context;

#include "test_module.h"

typedef struct oflops_context
{
	int n_tests;
	struct test_module ** tests;
	char * controller_port;
	char * send_dev;
	char * recv_dev;
	int control_fd;
	int listen_fd;
	int state;
};


#endif
