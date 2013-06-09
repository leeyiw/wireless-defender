#include <time.h>

#include "wireless-defender.h"
#include "config.h"
#include "utils.h"
#include "capture.h"
#include "server.h"
#include "utils.h"
#include "analyse.h"
#include "preprocess.h"

/* 起始运行时间 */
time_t WD_start_time;
AP_list_t *AP_list = NULL;
queue_t *q = NULL;
u_char ssid[105] = { 0x38, 0x83, 0x45, 0xc3, 0xf8, 0x98 };

/**
 * 主程序全局初始化函数
 */
void
WD_init()
{
	// 记录起始运行时间
	if(-1 == time(&WD_start_time)) {
		err_exit("get start time error");
	}
	// 初始化配置文件模块
	WD_config_init();
	analyse_init();
}

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
show_ap_list()
{
	AP_info *cur = AP_list->head;

	while( cur != NULL ) {
		printf( "%s\n", cur->ssid );	
		cur = cur->next;
	}
}

/**
 * 主程序全局清理函数
 */
void
WD_destory()
{
}

int
main(int argc, char *argv[])
{

	WD_init();
	// 初始化服务器模块
	//WD_server_init();

	// 初始化抓包模块
	WD_capture_init(WD_analyse_test, 5, (u_char *)1);
	//启动预处理模块
	WD_pipe_create(&prepline);	
	// 启动抓包
	WD_capture_start();
	//
	show_ap_list();	
	// 关闭抓包模块
	WD_capture_destory();
	// 清理抓包模块
	WD_destory();
	
	pthread_exit( NULL );
	return EXIT_SUCCESS;
}
