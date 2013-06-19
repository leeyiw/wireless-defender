#include "flow.h"
#include "analyse.h"
#include "decrypt.h"

TCP_flow *g_tcp_inflow = NULL;
TCP_flow *g_tcp_outflow = NULL;

void
analyse_flow_init()
{
	g_tcp_inflow = ( TCP_flow * )malloc( sizeof( TCP_flow ) );	
	g_tcp_outflow = ( TCP_flow * )malloc( sizeof( TCP_flow ) );

	memset( g_tcp_inflow, 0, sizeof( g_tcp_inflow ) );	
	memset( g_tcp_outflow, 0, sizeof( g_tcp_outflow ) );

	pthread_rwlock_init( &g_tcp_inflow->flow_lock, NULL );
	pthread_rwlock_init( &g_tcp_outflow->flow_lock, NULL );
}

void
analyse_flow( frame_t *frame , int encrypt )
{
	TCP_flow *flow = NULL;	
	int port = 0;
	int bytes;
	int z = ( frame->bytes[1] & 3 ) == 3 ? 30 : 24;

	if( !memcmp( frame->sa, user_stmac, 6 ) ) {
		flow = g_tcp_inflow;		
	} else {
		flow = g_tcp_outflow;
	}
	
	if( WPA_ENCRYPT == encrypt ) {
		z += 8;	
	}
	z += 8;

	bytes = frame->bytes[z + 2] * 256 + frame->bytes[z + 3];

	if( TCP == frame->bytes[z + 9] ) {
		port = frame->bytes[z + 20] * 256 + frame->bytes[z + 21];
		pthread_rwlock_wrlock( &flow->flow_lock );
		switch( port ) {
			case SMTP:
					flow->smtp += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->smtp );
					break;
			case TELNET:
					flow->telnet += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->telnet );
					break;
			case SSH:
					flow->ssh += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->ssh );
					break;
			case HTTP:
					flow->http += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->http );
					break;
			case FTP:
					flow->ftp += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->ftp );
					break;
			case DNS:
					flow->dns += ( double )( bytes + 20 ) / KB;
					printf( "%lf\n", flow->dns );
					break;
		} 
		pthread_rwlock_unlock( &flow->flow_lock );
	}
}

