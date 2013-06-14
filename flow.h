#ifndef _FLOW_H
#define _FLOW_H

#include "analyse.h"

#define TCP		0x06

#define HTTP		80
#define SSH			22
#define SMTP		25
#define FTP			20
#define TELNET		23
#define DNS			53

typedef struct _TCP_flow {
	int http;	
	int ssh;
	int smtp;
	int telnet;
	int ftp;
	int dns;
}TCP_flow;

extern TCP_flow *g_tcp_inflow;
extern TCP_flow *g_tcp_outflow;

extern void analyse_flow_init();
extern void analyse_flow( frame_t *frame );

#endif
