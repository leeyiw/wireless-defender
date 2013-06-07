#include "preprocess.h"
#include "decrypt.h"

pipe_t prepline;

void
WD_pipe_create( pipe_t *prepline )
{
	int status, i;
	stage_t *new_stage, **link = &( prepline->head );

	for( i = 0; i < STAGE_NUM; i++ ) {
		new_stage = ( stage_t * )malloc( sizeof( stage_t ) );	
		if( NULL == new_stage ) {
			user_exit( "Cannot malloc!\n" );	
		}
		status = pthread_mutex_init( &new_stage->mutex, NULL );
		if( status ) 	{
			user_exit( "Cannot init mutex!\n" );
		}
		status = pthread_cond_init( &new_stage->cond_is_ready, NULL );
		if( status ) {
			user_exit( "Cannot init cond!\n" );
		}
		status = pthread_cond_init( &new_stage->cond_is_finished, NULL );
		if( status ) {
			user_exit( "Cannot init cond!\n" );
		}

		switch( i ) {
			case 0:	
					new_stage->func = &deal_frame_info;
					break;
			case 1:
					new_stage->func = &pre_encrypt;
					break;
		} 

		new_stage->is_ready = 0;
		new_stage->is_finished = 1;
		new_stage->frame = ( frame_t *)malloc( sizeof( frame_t ) );
		
		status = pthread_create( &new_stage->tid, NULL, 
										new_stage->func, new_stage );
		if( status ) {
			user_exit( "Cannot create the pthread!" );	
		}

		new_stage->next = NULL;
		*link = new_stage;
		link = &( new_stage->next );
	}

	prepline->tail = new_stage;
	*link = NULL;

}

void
pipe_send( stage_t **stage, frame_t *frame )
{
	int status;

	status = pthread_mutex_lock( &( *stage )->mutex );
	if( status ) {
		user_exit( "Cannot lock mutex!" );
	}

	while( !( *stage )->is_finished ) {
		status = pthread_cond_wait( &( *stage )->cond_is_finished, 
						&( *stage )->mutex );
		if( status ) {
			user_exit( "Cannot wait!" );
		}
	}

	( *stage )->is_ready = 1;
	( *stage )->is_finished = 0;
	memcpy( ( *stage )->frame, frame, sizeof( frame ) );

	status = pthread_cond_signal( &( *stage )->cond_is_ready );
	if( status ) {
		user_exit( "Cannot send signal to pthread!" );
	}
	status = pthread_mutex_unlock( &( *stage )->mutex );
	if( status ) {
		user_exit( "Cannot unlock mutex!" );
	}
}
