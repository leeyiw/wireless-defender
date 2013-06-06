#include "preprocess.h"
#include "analyse.h"
#include "decrypt.h"

void *
pre_encrypt( void *arg )
{
	int status;
	stage_t *stage = ( stage_t * )arg;
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

		if( frame->bytes != NULL ) {
			status = pthread_mutex_lock( &AP_list->lock );
			is_exist( ssid );
			printf( "ssid: %s encrypt is: %d", AP_list->cur->ssid, 
							AP_list->cur->encrypt );
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
