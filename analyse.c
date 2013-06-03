#include "analyse.h"
#include "preprocess.h"

AP_info *ap_head = NULL;
AP_info *ap_cur = NULL;
AP_info *ap_tail = NULL;

void 
WD_analyse_test( u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes ) 
{
	frame_t *frame = ( frame_t * )malloc( sizeof( frame_t ) );

	if( user != ( u_char * ) 1 )  {
		return;
	}
	user_info1( "capture packet len: %d, packet len: %d", 
			h->caplen, h->len ) ;
	frame->bytes = bytes;
	frame->len = h->caplen;
	
	if( ( ( queue->tail + 2 ) % CACHE_SIZE ) == front ) {
		user_exit( "queue is full!" );	
	}
	tail = ( tail + 1 ) % CACHE_SIZE;
	queue[tail] = frame;

	frame = queue[head];
	head = ( head + 1 ) % CACHE_SIZE;
	pipe_send( frame );
}

//void WD_analyse( u_char *user, const struct pcap_pkthdr *h, const u_char *bytes )
//{
//	//struct frame_info *fi = NULL;
//
//	//fi = deal_frame_info( ( const u_char * )bytes, h->caplen );
//	//if( fi->type == MANAGE_TYPE && fi->subtype == BEACON ) {
//	//	user_info( "beacon frame detected!" );
//	//}
//	//free( fi );
//}

/* 解密wep加密的内容，为无线流量分析 */

//void
//decrypt_wep( struct frame_info **fi_ptr, u_char *passwd ) 
//{
//	int i, j = 3;
//	RC4_KEY s;
//	u_char key[10];
//	struct frame_info *fi = *fi_ptr;
//
//	/* iv和密码合成密钥 */
//
//	memcpy( key, fi->db->data, 3 ) ;
//	for( i = 0; i < 10; i += 2 )  {
//		key[j++] = passwd[i]*16 + passwd[i+1];
//	}
//
//	/* 使用openssl带的RC4算法 */
//
//	RC4_set_key( &s, 8, key ) ;
//	RC4( &s, fi->frame_len - 4, &fi->db->data[4], &fi->db->data[4] ) ;
//}

/* 帧处理的开始 */
int
is_exist( u_char *bssid ) 
{
	AP_info *temp = ap_head;	

	while( temp != NULL ) {
		if( !memcmp( temp->bssid, bssid, 6 ) ) {
			ap_cur = temp;
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

void *
deal_frame_info( void *arg ) 
{
	int status;
	stage_t *stage = ( stage * )arg;
	frame_t *frame = stage->frame;

	while(1) {
		status = pthread_mutex_lock( &stage->mutex );	
		if( status ) {
			user_exit( "Cannot lock mutex!" );	
		}

		while( !stage->is_ready ) {
			status = pthread_cond_wait(	&stage->cond_is_ready,
							&stage->mutex );
			if( status ) {
				user_exit( "Cannot wait!" );
			}
		}
			
		/* 去除捕获的包的头部信息 */
		frame->len -= ( int )bytes[2];
		status = deal_type( &( frame->bytes[bytes[2]] ), frame->len );
		stage->is_ready = 0;
		gtstage->is_finished = 1;

		if( !status ) {
			pipe_send( stage->next, );		
		}

	}

	return NULL;
}

/* 解析帧中的类型和子类型信息 */

int
deal_type( const u_char *bytes, int frame_len )  
{
	int type = bytes[0] % 16;
	int subtype = ( bytes[0] / 16 ) % 16;

	if( type == MANAGE_TYPE && subtype == BEACON ) {
		frame_len -= 10;
		deal_beacon_mac( &bytes[10], frame_len );
	} //else if( type == DATA_TYPE && subtype == DATA ) {
		//TODO
	//}
	
}

/* 不加密的SNAP开头为AA AA 03 00 00 00.... */

//void
//deal_data( const u_char *bytes, int frame_len )
//{
//	AP_info *ap_cur = ap_head;
//	u_char bssid[6];
//
//	switch( bytes[0] & 3 ) {
//		case 0: 								/* IBSS */	
//				memcpy( bssid, &bytes[15], 6 );
//				break;	
//		case 1: 								/* TODS */	
//				memcpy( bssid, &bytes[3], 6 );
//				break;						
//		case 2: 								/* FROMDS */
//				memcpy( bssid, &bytes[9], 6 ); 
//				break;
//		case 3: 								/* WDS */
//				memcpy( 	bssid, &bytes[9], 6 );
//				break;	
//	}
//	
//	if( !is_exist( bssid ) ) {
//		if(  )	
//	}
//}

void
deal_beacon_mac( const u_char *bytes, int frame_len )
{
	AP_info *temp;
	u_char bssid[6];
	memcpy( bssid, &bytes[6], 6 );
	
	if( !is_exist( bssid ) ) {
		temp = ( AP_info * )malloc( sizeof( AP_info ) );

		memcpy( temp->sa, bytes, 6 );
		memcpy( temp->bssid, &bytes[6], 6 );
		temp->next = NULL;
		frame_len -= 14;

		if( NULL == ap_head ) {
			ap_head = temp;
			ap_tail = temp;
		} else {
			ap_tail->next = temp;
			ap_tail = ap_tail->next;
		}

		deal_timestamp( &bytes[14], frame_len );
	}
}

void
deal_timestamp( const u_char *bytes, int frame_len ) 
{
	memcpy( ap_tail->timestamp, bytes, 8 );		
	frame_len -= 12;

	deal_ssid( &bytes[12], frame_len );
}

void
deal_ssid( const u_char *bytes, int frame_len ) 
{
	ap_tail->ssid = ( char * )malloc( sizeof( bytes[1] + 1 ) );
	
	memcpy( ap_tail->ssid, &bytes[2], bytes[1] );
	ap_tail->ssid[bytes[1]] = '\0';
}
