#include "preprocess.h"
#include "wireless-defender.h"
#include "analyse.h"
#include "decrypt.h"

void
wep_decrypt( u_char *bytes, int frame_len )
{
	RC4_KEY rc4_key;
	u_char key[40];
	int i, j = 3;

	memcpy( key, bytes, 3 );
	for( i = 0; i < user->passwd_len; i += 2 ) {
		key[j++] = user->passwd[i]*16 + user->passwd[i+1];	
	}

	RC4_set_key( &rc4_key, IV_LEN + ( user->passwd_len ) / 2,
					key );
	RC4( &rc4_key, frame_len, &bytes[4], bytes );
}

void 
calc_pmk( char *key, char *essid_pre, u_char pmk[40] ) 
{
	int i, j, slen;
	u_char buffer[65];
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	memset( essid, 0, sizeof( essid ) );
	memcpy( essid, essid_pre, strlen( essid_pre ) );
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ ) {
		buffer[i] ^= 0x36;
	}

	SHA1_Init( &ctx_ipad );
	SHA1_Update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ ) {
		buffer[i] ^= 0x6A;
	}

	SHA1_Init( &ctx_opad );
	SHA1_Update( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC( EVP_sha1(), ( u_char * )key, strlen( key ), 
				( u_char* )essid, slen, pmk, NULL );
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ ) {
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ ) {
			pmk[j] ^= buffer[j];
		}
	}

	essid[slen - 1] = '\2';
	HMAC( EVP_sha1(), ( u_char * )key, strlen( key ), 
					( u_char* )essid, slen, pmk+20, NULL );
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ ) {
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ ) {
			pmk[j + 20] ^= buffer[j];
		}
	}
}

//int
//calc_ptk()
//{
//	u_char pmk[40];	
//	char *ssid;
//
//	memcpy( ssid, AP_list->cur->ssid, sizeof( AP_list->cur->ssid ) - 1 );
//	calc_pmk( user->passwd, ssid, pmk );
//}

void *
pre_encrypt( void *arg )
{
	int status;
	stage_t *stage = ( stage_t * )arg;
	AP_info *cur;

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

		frame_t *frame = stage->frame;

		if( frame != NULL ) {
			status = pthread_mutex_lock( &AP_list->lock );
			is_exist( ssid );
			cur = AP_list->cur;
			status = pthread_mutex_unlock( &AP_list->lock );

			if( WEP_ENCRYPT == cur->encrypt ) {
				wep_decrypt( frame->bytes, frame->len );	
			} else if( WPA_ENCRYPT == cur->encrypt ) {
					
			} 
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

