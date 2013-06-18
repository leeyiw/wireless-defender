#include "analyse.h"
#include "preprocess.h"
#include "decrypt.h"

queue_t *q = NULL;
AP_list_t *AP_list = NULL;

int eapol_cur = 0;
u_char *eapol[CACHE_SIZE];

static u_char ZERO[32] = 
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

static const unsigned int crc_table[256] =
{
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

void
analyse_init()
{
	q = ( queue_t *)malloc( sizeof( queue_t ) );	
	q->head = 1;
	q->tail = 0;

	AP_list = ( AP_list_t * )malloc( sizeof( AP_list_t ) );
	AP_list->head = NULL;
	AP_list->tail = NULL;
	AP_list->cur = NULL;

	pthread_mutex_init( &AP_list->lock, NULL );
}

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

unsigned long
crc32( unsigned long crc, const unsigned char *buffer, unsigned int size ) 
{
	for( ; size > 0; size--, buffer++ ) {
		crc = crc_table[( crc ^ *buffer ) & 0xff] ^ ( crc >> 8 );	
	}

	return ~crc;
}

int
check_fcs( const u_char *bytes, int len )
{
	unsigned long crc_code = 0xffffffff;	

	crc_code = crc32( crc_code, bytes , len - 4 );

	return ( ( ( crc_code & 0xff ) ) == bytes[len - 4] ) &&
			( ( ( crc_code >> 8 ) & 0xff ) == bytes[len - 3] ) &&
			( ( ( crc_code >> 16 ) & 0xff ) == bytes[len - 2] ) &&
			( ( ( crc_code >> 24 ) & 0xff ) == bytes[len - 1] );
}

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
	if( SNAP_DSAP == bytes[0] && 
		SNAP_SSAP == bytes[1] && 
		SNAP_CONTROL == bytes[2] && 
		ETHERNET_TYPE_ONE == bytes[6] && 
		ETHERNET_TYPE_SECOND == bytes[7] ) {
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
	char *essid = { "wfaye" };
	char *passwd = { "wufeishizhu."}; 

	calc_pmk( passwd, essid, pmk );

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
		
		if( memcmp( &bytes[17], ZERO, 32 ) != 0 ) {
			memcpy( wpa->snonce, &bytes[17], 32 );	
		}
	
		wpa->eapol_size = ( bytes[2] << 8 ) + bytes[3] + 4;
		
        memcpy( wpa->keymic, &bytes[81], 16 );
		memcpy( wpa->eapol, bytes, wpa->eapol_size );
		memset( wpa->eapol + 81, 0, 16 );

		wpa->keyver = bytes[6] & KEY_VERSION;
	}

	if( ( bytes[6] & PAIRWISE ) != 0 && 
		( bytes[6] & INSTALL ) != 0 &&
		( bytes[6] & ACK ) != 0 && 
		( bytes[5] & MIC ) != 0 ) {
		
		if( memcmp( &bytes[17], ZERO, 32 ) != 0 ) {
			memcpy( wpa->anonce, &bytes[17], 32 );	
		}

		wpa->eapol_size = bytes[2] * 256 + bytes[3] + 4;
		
        memcpy( wpa->keymic, &bytes[81], 16 );
		memcpy( wpa->eapol, bytes, wpa->eapol_size );
		memset( wpa->eapol + 81, 0, 16 );

		wpa->keyver = bytes[6] & KEY_VERSION;
	}

	wpa->valid_ptk = calc_ptk( pmk );
	if( wpa->valid_ptk ) {
		printf( "hello world\n" );
	}

	return 0;
}

int
deal_normal_data( const u_char *bytes )
{
	AP_list->cur->encrypt = (bytes[3] == WPA_FLAG )?
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
		memmove( frame->bytes, &frame->bytes[head_len], frame->len );
		
		status = pthread_mutex_lock( &AP_list->lock );
		if( status ) {
			user_exit( "Cannot lock mutex!" );		
		}
		return_val = deal_type( &frame );
		
		status = pthread_mutex_unlock( &AP_list->lock );
		if( status ) {
			user_exit( "Cannot lock mutex!" );		
		}

		if( 0 == return_val ) {
			//free( frame );
			frame = NULL;
		}
//		if( return_val >= 0 ) {
//			pipe_send( &( stage->next ), frame );
//		}

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
deal_type( frame_t **frame )  
{
	u_char *bytes_bak = ( *frame )->bytes;
	
	int	*frame_len = &( ( *frame )->len ); 
	int type = bytes_bak[0] % 16;
	int subtype = ( bytes_bak[0] / 16 ) % 16;

	if( type == MANAGE_TYPE && subtype == BEACON ) {
		/* 检查FCS */
		if ( !check_fcs( bytes_bak, *frame_len ) ) {
			return -1;
		}

		*frame_len -= 10;
		return deal_beacon_mac( &bytes_bak[10], frame_len );
	} 
	
	if( type == DATA_TYPE && subtype == DATA ) {
		return deal_data( frame );
	}

	return -1;	
}

/* 不加密的SNAP开头为AA AA 03 00 00 00.... */

int
deal_data( frame_t **frame )
{
	u_char bssid[6];
	u_char stmac[6];
	u_char sa[6];
	u_char da[6];
	u_char *bytes_bak = ( *frame )->bytes;
	int ret_eapol, ret_exist;

	switch( bytes_bak[1] & 3 ) {
		case 0: 								/* IBSS */	
				memcpy( da, &bytes_bak[4], 6 );
				memcpy( sa, &bytes_bak[10], 6 );
				memcpy( bssid, &bytes_bak[16], 6 );
				break;	
		case 1: 								/* TODS */	
				memcpy( bssid, &bytes_bak[4], 6 );
				memcpy( sa, &bytes_bak[10], 6 );
				memcpy( da, &bytes_bak[16], 6 );
				break;						
		case 2: 								/* FROMDS */
				memcpy( da, &bytes_bak[4], 6 );
				memcpy( bssid, &bytes_bak[10], 6 );
				memcpy( sa, &bytes_bak[16], 6 );
				break;
		case 3: 								/* WDS */
				memcpy( bssid, &bytes_bak[10], 6 );
				memcpy( da, &bytes_bak[16], 6 );
				memcpy( sa, &bytes_bak[22], 6 );
				break;	
	}
	
	switch( bytes_bak[1] & 3 ) {
		case 1: 								/* TODS */	
				memcpy( stmac, &bytes_bak[10], 6 );
				break;						
		case 2: 								/* FROMDS */
				memcpy( stmac, &bytes_bak[4], 6 ); 
				break;
		case 3: 								/* WDS */
				memcpy( stmac, &bytes_bak[10], 6 );
				break;	
	}

	if( memcmp( stmac, user_stmac, 6 ) ) {
		return 0;
	}

	memcpy( wpa->stmac, stmac, 6 );
	memcpy( wpa->bssid, bssid, 6 );

	memcpy( ( *frame )->da, da, 6 );
	memcpy( ( *frame )->sa, sa, 6 );

	if( 3 == ( bytes_bak[1] & 3 ) ) {
		( *frame )->len -= 30;
		memmove( bytes_bak, &bytes_bak[30], ( *frame )->len );
	} else {
		( *frame )->len -= 24;
		memmove( bytes_bak, &bytes_bak[24], ( *frame )->len );
	}

	ret_eapol = is_eapol( bytes_bak );
	ret_exist = is_exist( bssid );

	if( ret_exist && ret_eapol ) {
		( *frame )->len -= 8; 
		memmove( bytes_bak, &bytes_bak[8], ( *frame )->len );
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

		memcpy( temp->bssid, &bytes[6], 6 );
		temp->next = NULL;
		*frame_len -= 14;

		if( NULL == AP_list->head ) {
			AP_list->head = temp;
			AP_list->tail = temp;
		} else {
			AP_list->tail->next = temp;
			AP_list->tail = AP_list->tail->next;
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
	AP_list->tail->ssid_len = bytes[1]; 
	AP_list->tail->ssid = ( char * )malloc( bytes[1] + 1 ); 
	
	memcpy( AP_list->tail->ssid, &bytes[2], bytes[1] );
	AP_list->tail->ssid[bytes[1]] = '\0';
}
