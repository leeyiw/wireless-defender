#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <unistd.h>

#include "server.h"
#include "config.h"
#include "wdcp.h"

int client_fd;
/* server模块子进程id号 */
pid_t server_pid;

static int listen_fd;

static void WD_server_handle_connection();

/**
 * 初始化服务器模块
 */
void
WD_server_init()
{
	struct ifreq ifr;
	struct sockaddr_in *listen_addr;

	// 创建监听描述符
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == listen_fd) {
		err_exit("server open socket error");
	}
	// 使用ioctl取网卡地址
	strncpy(ifr.ifr_name, g_server_interface, IFNAMSIZ);
	if(-1 == ioctl(listen_fd, SIOCGIFADDR, &ifr)) {
		err_exit1("get interface '%s' address error",
			g_server_interface);
	}
	// 设置网卡地址
	listen_addr = (struct sockaddr_in *)&ifr.ifr_addr;
	listen_addr->sin_family = AF_INET;
	listen_addr->sin_port = htons(WD_SERVER_LISTEN_PORT);
	// bind网卡地址
	if(-1 == bind(listen_fd, (struct sockaddr *)listen_addr,
		sizeof(struct sockaddr_in))) {
		err_exit1("bind interface '%s' error", g_server_interface);
	}
}

/**
 * 监听并处理客户端请求函数
 */
void
WD_server_main_loop()
{
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	pid_t pid;

	// 监听
	if(-1 == listen(listen_fd, 64)) {
		err_exit("listen socket error");
	}
	// 循环接收连接并fork
	while(1) {
		client_fd = accept(listen_fd,
			(struct sockaddr *)&client_addr, &client_addr_len);
		if(client_fd == -1) {
			err_info("accept new connection error");
		}
		pid = fork();
		if(pid == 0) {
			// 子进程
			WD_server_handle_connection();
			return;
		} else if(pid == -1) {
			err_info("fork for client new connection error");
		}
		// 父进程继续接收连接
	}
}

/**
 * 处理客户端的请求
 */
void
WD_server_handle_connection()
{
	// 如果应用层建立连接失败则返回
	if(WDCP_CONNECTION_SUCCESS != WD_wdcp_build_connection()) {
		return;
	}
	// 如果应用层建立连接成功则进行认证，如果验证失败则返回
	if(WDCP_AUTHENTICATE_SUCCESS != WD_wdcp_authenticate()) {
		return;
	}
}
