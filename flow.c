#include "flow.h"
#include "analyse.h"

TCP_flow *g_tcp_inflow = NULL;
TCP_flow *g_tcp_outflow = NULL;

void
analyse_flow_init()
{
	g_tcp_inflow = ( TCP_flow * )malloc( sizeof( TCP_flow ) );	
	g_tcp_outflow = ( TCP_flow * )malloc( sizeof( TCP_flow ) );

	memset( g_tcp_inflow, 0, sizeof( g_tcp_inflow ) );	
	memset( g_tcp_outflow, 0, sizeof( g_tcp_outflow ) );
}

void
analyse_flow( frame_t *frame )
{
	TCP_flow *flow = NULL;	
	int port;
	int bytes;

	if( !memcmp( frame->sa, user_stmac, 6 ) ) {
		flow = g_tcp_inflow;		
	} else {
		flow = g_tcp_outflow;
	}
	
	bytes = frame->bytes[2] * 256 + frame->bytes[3];

	if( TCP == frame->bytes[17] ) {
		port = frame->bytes[30] * 256 + frame->bytes[31];

		switch( port ) {
			case SMTP:
					flow->smtp += ( double )( bytes + 20 ) / KB;
					break;
			case TELNET:
					flow->telnet += ( double )( bytes + 20 ) / KB;
					break;
			case SSH:
					flow->ssh += ( double )( bytes + 20 ) / KB;
					break;
			case HTTP:
					flow->http += ( double )( bytes + 20 ) / KB;
					break;
			case FTP:
					flow->ftp += ( double )( bytes + 20 ) / KB;
					break;
			case DNS:
					flow->dns += ( double )( bytes + 20 ) / KB;
					break;
		} 
	}
}

