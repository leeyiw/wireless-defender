#include "wireless-defender.h"

void
WD_init()
{
	// 初始化配置文件模块
	WD_config_init();

	// 初始化抓包模块
	WD_capture_init(WD_analyse_test, 10, (u_char *)1);
}

int
main(int argc, char *argv[])
{
	WD_capture_start();

	return 0;
}
