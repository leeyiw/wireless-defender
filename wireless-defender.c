#include <time.h>

#include "config.h"
#include "utils.h"
#include "capture.h"
#include "analyse.h"
#include "server.h"
#include "utils.h"
#include "analyse.h"

/* 起始运行时间 */
time_t WD_start_time;

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
	WD_server_init();

	// 初始化抓包模块
	WD_capture_init(WD_analyse_test, 1, (u_char *)1);
	// 启动抓包
	WD_capture_start();

	WD_capture_start();
	// 关闭抓包模块
	WD_capture_destory();
	// 清理抓包模块
	WD_destory();

	return EXIT_SUCCESS;
}
