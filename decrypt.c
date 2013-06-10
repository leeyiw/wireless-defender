#include "preprocess.h"
#include "wireless-defender.h"
#include "analyse.h"
#include "decrypt.h"

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
		}

		if( WEP_ENCRYPT == cur->encrypt ) {
			wep_decrypt( frame->bytes, frame->len );	
		} else if( WPA_ENCRYPT == cur->encrypt ) {
			
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

void
wep_decrypt( u_char *bytes, int frame_len )
{
	RC4_KEY rc4_key;
	u_char key[40];
	int i, j = 3;

	memcpy( key, bytes, 3 );
	for( i = 0; i < wep->passwd_len; i += 2 ) {
		key[j++] = wep->passwd[i]*16 + wep->passwd[i+1];	
	}

	RC4_set_key( &rc4_key, IV_LEN + ( wep->passwd_len ) / 2,
					key );
	RC4( &rc4_key, frame_len, &bytes[4], bytes );
}
