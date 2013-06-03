#include "preprocess.h"
#include "analyse.h"

queue_t *queue = NULL;

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
		new_stage->is_ready = 0;
		new_stage->is_finished = 1;
	
		new_stage->next = NULL;
		*link = new_stage;
		link = &( new_stage->next );
	}

	(*link)->head->pipe_stage =	 
}
