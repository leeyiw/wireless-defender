#ifndef _PRRPROCESS_H
#define _PRRPROCESS_H

#include "analyse.h"

#define STAGE_NUM		2
#define CACHE_SIZE		100		/* 待测试 */

typedef void *( *PF )( void *arg );

typedef struct stage {
	pthread_t tid;
	pthread_mutex_t mutex;	
	pthread_cond_t cond_is_ready;
	pthread_cond_t cond_is_finished;
	frame_t *frame;
	int is_ready;
	int is_finished;
	PF func;
	struct stage *next;
} stage_t;

typedef struct pipe {
	stage_t *head;	
	stage_t *tail;
	int stage_num;
} pipe_t;

extern pipe_t prepline;

extern void WD_pipe_create(pipe_t * prepline);
extern void pipe_send( stage_t **stage, frame_t *frame );
#endif
