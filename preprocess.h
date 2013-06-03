#ifndef _PRRPROCESS_H
#define _PRRPROCESS_H

#include "analyse.h"

#define STAGE_NUM		3
#define CACHE_SIZE		100		/* 待测试 */

typedef void *( *PF )( void *arg );

typedef struct stage {
	pthread_t tid;
	pthread_mutex_t mutex;	
	pthread_cond_t is_ready;
	pthread_cond_t is_finished;
	frame_t *frame;
	int ready;
	int finished;
	PF pipe_stage;
	AP_info *head;
	struct stage *next;
} stage_t;

typedef struct pipe {
	stage_t *head;	
	stage_t *tail;
	int stage_num;
} pipe_t;

typedef struct queue {
	u_char *array[CACHE_SIZE];
	int head;
	int tail;
} queue_t;

extern queue_t *queue;

extern WD_pipe_create(pipe_t * prepline);

#endif
