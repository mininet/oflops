#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>

#include "control.h"
#include "utils.h"

int setup_control_channel(oflops_context *ctx)
{
	struct sockaddr_in sin;
	char buf[BUFLEN];
	unsigned int len;
	fprintf(stderr, "Creating server socket...\n");
	ctx->listen_fd = socket( AF_INET, SOCK_STREAM, 0);
	if(ctx->listen_fd == -1)
		perror_and_exit("socket",1);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(ctx->listen_port);
	fprintf(stderr, "Listenning on port %d \n", ctx->listen_port);
	if(bind( ctx->listen_fd, (struct sockaddr *) &sin, sizeof(sin)))
		perror_and_exit("binding listen port",1);
	if(listen( ctx->listen_fd,16))
		perror_and_exit("listen",1);
	fprintf( stderr, "Waiting for a switch to connect...\n");
	len = sizeof(sin);
	if((ctx->control_fd=
			accept( ctx->listen_fd, (struct sockaddr *) &sin, &len)) == -1)
		perror_and_exit("accept",1);
	inet_ntop(AF_INET,&sin.sin_addr,buf,BUFLEN);
	fprintf( stderr, "Got connection from %s:%d \n",
			buf, htons(sin.sin_port));
	return 0;
}


