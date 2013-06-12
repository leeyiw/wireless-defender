#include "analyse.h"
#include "preprocess.h"
#include "decrypt.h"

u_char *eapol[CACHE_SIZE];
int eapol_cur = 0;

static u_char ZERO[32] = 
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

void 
WD_analyse_test( u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes ) 
{
	frame_t *frame = ( frame_t * )malloc( sizeof( frame_t ) );

	if( user != ( u_char * ) 1 )  {
		return;
	}
//	user_info1( "capture packet len: %d, packet len: %d", 
//			h->caplen, h->len ) ;
	frame->bytes = ( u_char * )malloc( h->caplen );
	memcpy( frame->bytes, bytes, h->caplen );
	frame->len = h->caplen;
	
	if( ( ( q->tail + 2 ) % CACHE_SIZE ) == q->head ) {
 		user_exit( "q is full!" );	
 	}
 	q->tail = ( q->tail + 1 ) % CACHE_SIZE;
 	q->array[q->tail] = frame;
 
 	frame = q->array[q->head];
 	q->head = ( q->head + 1 ) % CACHE_SIZE;
	pipe_send( &( prepline.head ), frame );
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
	AP_info *temp = AP_list->head;	

	while( temp != NULL ) {
		if( !memcmp( temp->bssid, bssid, 6 ) ) {
			AP_list->cur = temp;
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

int
is_eapol( const u_char *bytes )
{
	if( SNAP_DSAP == bytes[24] && SNAP_SSAP == bytes[25] 
					&& SNAP_CONTROL == bytes[26] 
					&& ETHERNET_TYPE_ONE == bytes[30] 
					&& ETHERNET_TYPE_ONE == bytes[31] ) {
		return 1;	
	}
	return 0;
}

int
eapol_cache( const u_char *bytes )
{
	eapol[eapol_cur++] = ( u_char * )bytes;
	return 0;
}

int
deal_eapol( const u_char *bytes )
{	
	if( bytes[1] != TYPE_KEY && 
		bytes[4] != EAPOL_WPA_KEY && 
		bytes[4] != RSN ) {

		return 0;
	}

	if( ( bytes[6] & PAIRWISE ) != 0 && 
		( bytes[6] & INSTALL ) == 0 &&
		( bytes[6] & ACK ) != 0 && 
		( bytes[5] & MIC ) == 0 ) {

		memcpy( wpa->anonce, &bytes[17], 32 );	
	}

	if( ( bytes[6] & PAIRWISE ) != 0 && 
		( bytes[6] & INSTALL ) == 0 &&
		( bytes[6] & ACK ) == 0 && 
		( bytes[5] & MIC ) != 0 ) {
		
		if( !memcmp( &bytes[17], ZERO, 32 ) ) {
			memcpy( wpa->snonce, &bytes[17], 32 );	
		}
        memcpy( wpa->keymic, &bytes[81], 16 );
		wpa->key_version = bytes[6] & KEY_VERSION;
	}

	if( ( bytes[6] & PAIRWISE ) != 0 && 
		( bytes[6] & INSTALL ) != 0 &&
		( bytes[6] & ACK ) != 0 && 
		( bytes[5] & MIC ) != 0 ) {
		
		if( !memcmp( &bytes[17], ZERO, 32 ) ) {
			memcpy( wpa->anonce, &bytes[17], 32 );	
		}
        memcpy( wpa->keymic, &bytes[81], 16 );
		wpa->key_version = bytes[6] & KEY_VERSION;
	}

	return 0;
}

int
deal_normal_data( const u_char *bytes )
{
	AP_list->cur->encrypt = (bytes[27] == WPA_FLAG )?
							WPA_ENCRYPT : WEP_ENCRYPT;

	if( WEP_ENCRYPT == AP_list->cur->encrypt ) {
		return 1;	
	}

	if( !AP_list->cur->is_eapol ) {
		/* 可能在缓存的eapol包中 */
			
		return 0;
	} else {
		/* 可以被解密 */
		return 1;
	}
}

void *
deal_frame_info( void *arg ) 
{
	int status, return_val, head_len;
	stage_t *stage = ( stage_t * )arg;

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
		frame_t *frame = stage->frame;
		head_len = ( int )frame->bytes[2];
		frame->len -= head_len;
		memcpy( frame->bytes, &frame->bytes[head_len], frame->len );
		
		status = pthread_mutex_lock( &AP_list->lock );
		if( status ) {
			user_exit( "Cannot lock mutex!" );		
		}
		return_val = deal_type( &frame->bytes, &frame->len );
		
		status = pthread_mutex_unlock( &AP_list->lock );
		if( status ) {
			user_exit( "Cannot lock mutex!" );		
		}

		if( 0 == return_val ) {
			//free( frame );
			frame = NULL;
		}
		if( return_val >= 0 ) {
			pipe_send( &( stage->next ), frame );
		}

		stage->is_ready = 0;
		stage->is_finished = 1;

		status = pthread_cond_signal( &stage->cond_is_finished );
		if( status ) {
			user_exit( "Cannot send signal to pthread!" );
		}
		status = pthread_mutex_unlock( &stage->mutex );
		if( status ) {
			user_exit( "Cannot unlock mutex!" );	
		}
	}

	return NULL;
}

/* 解析帧中的类型和子类型信息 */

int
deal_type( u_char **bytes, int *frame_len )  
{
	u_char *bytes_bak = *bytes;
	int type = bytes_bak[0] % 16;
	int subtype = ( bytes_bak[0] / 16 ) % 16;

	if( type == MANAGE_TYPE && subtype == BEACON ) {
		*frame_len -= 10;
		return deal_beacon_mac( &bytes_bak[10], frame_len );
	} 
	
	if( type == DATA_TYPE && subtype == DATA ) {
		return deal_data( bytes, frame_len );
	}

	return -1;	
}

/* 不加密的SNAP开头为AA AA 03 00 00 00.... */

int
deal_data( u_char **bytes, int *frame_len )
{
	u_char bssid[6];
	u_char *bytes_bak = *bytes;
	int ret_eapol, ret_exist;

	switch( bytes_bak[1] & 3 ) {
		case 0: 								/* IBSS */	
				memcpy( bssid, &bytes_bak[16], 6 );
				break;	
		case 1: 								/* TODS */	
				memcpy( bssid, &bytes_bak[4], 6 );
				break;						
		case 2: 								/* FROMDS */
				memcpy( bssid, &bytes_bak[10], 6 ); 
				break;
		case 3: 								/* WDS */
				memcpy( bssid, &bytes_bak[10], 6 );
				break;	
	}
	
	if( 3 == ( bytes_bak[1] & 3 ) ) {
		*frame_len -= 30;
		memcpy( bytes_bak, &bytes_bak[30], *frame_len );
	} else {
		*frame_len -= 24;	
		memcpy( bytes_bak, &bytes_bak[24], *frame_len );
	}

	if( memcmp( ssid, bssid, 6 ) ) {
		return 0;
	}
	
	ret_eapol = is_eapol( bytes_bak );
	ret_exist = is_exist( bssid );

	if( ret_exist && ret_eapol ) {
		AP_list->cur->is_eapol = 1;
		return deal_eapol( bytes_bak ); 
	} 
	
	if( ret_exist && !ret_eapol ) {
		return deal_normal_data( bytes_bak );	
	}
	
	if( !ret_exist && ret_eapol ) {
		return eapol_cache( bytes_bak ); 
	}
	
	return 0;
}


int
deal_beacon_mac( const u_char *bytes, int *frame_len )
{
	AP_info *temp;
	u_char bssid[6];
	memcpy( bssid, &bytes[6], 6 );
	
	if( !is_exist( bssid ) ) {
		temp = ( AP_info * )malloc( sizeof( AP_info ) );

		memcpy( temp->sa, bytes, 6 );
		memcpy( temp->bssid, &bytes[6], 6 );
		temp->next = NULL;
		*frame_len -= 14;

		if( NULL == AP_list->head ) {
			AP_list->head = temp;
			AP_list->tail = temp;
		} else {
			AP_list->tail->next = temp;
			AP_list->tail = AP_list->tail ->next;
		}

		deal_timestamp( &bytes[14],frame_len ); 
	}
	return 0;
}

void
deal_timestamp( const u_char *bytes , int *frame_len ) 
{ 
	memcpy( AP_list->tail->timestamp, bytes, 8); 
	*frame_len -= 12 ;

	deal_ssid( &bytes[12],frame_len ); 
}

void
deal_ssid( const u_char *bytes , int *frame_len ) 
{ 
	AP_list->tail->ssid= ( char * )malloc( bytes[1] + 1 ); 
	
	memcpy( AP_list->tail->ssid, &bytes[2],bytes [1] );
	AP_list->tail->ssid[bytes[1]]= '\0';
}
