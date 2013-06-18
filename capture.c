#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "capture.h"
#include "config.h"
#include "log.h"

static pcap_t *device;
static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_handler capture_callback;
static int capture_cnt;
static u_char *capture_callback_arg;

#ifdef WD_DUMP
static pcap_dumper_t *dump;
#endif

#ifndef WD_OFFLINE
static void WD_capture_set_interface_mode(const char *interface, void *mode);
#endif

/** 
 * 初始化capture模块
 * @param callback 捕获数据包后的回调函数
 * @param cnt 捕获数据包的个数，抓到cnt个数据包后抓包停止
 * @param callback_arg 捕获数据包后回调函数的参数
 */
void
WD_capture_init(pcap_handler callback, int cnt, u_char *callback_arg)
{

#ifndef WD_OFFLINE
	// 将网卡改为Monitor模式
	WD_capture_set_interface_mode(g_capture_interface,
		(void *)IW_MODE_MONITOR);
#endif

	// 初始化libpcap抓包设备
#ifdef WD_OFFLINE
	device = pcap_open_offline(WD_OFFLINE_FILE, errbuf);
	if(device == NULL) {
		user_exit1("open offline file %s error: %s",
			WD_OFFLINE_FILE, errbuf);
	}
#else
	device = pcap_open_live(g_capture_interface, 65535, 0, 0, errbuf);
	if(device == NULL) {
		user_exit1("open interface '%s' for capturing error: %s",
			g_capture_interface, errbuf);
	}
#endif

#ifdef WD_DUMP
	dump = pcap_dump_open(device, WD_OFFLINE_FILE);
	if(dump == NULL) {
		user_exit1("%s", pcap_geterr(device));
	}
#endif

	// 给内部变量赋值
	capture_callback = callback;
	capture_cnt = cnt;
	capture_callback_arg = callback_arg;
}

/**
 * 设置捕获数据包后的回调函数
 * @param callback 捕获数据包后的回调函数
 */
void
WD_capture_set_callback(pcap_handler callback)
{
	capture_callback = callback;
}

/**
 * 设置捕获数据包的个数
 * @param cnt 捕获数据包的个数，抓到cnt个数据包后抓包停止
 * cnt为-1或0时代表不设置个数限制
 */
void
WD_capture_set_cnt(int cnt)
{
	capture_cnt = cnt;
}

/**
 * 设置捕获数据包后回调函数的参数
 * @param callback_arg 捕获数据包后回调函数的参数
 */
void
WD_capture_set_callback_arg(u_char *callback_arg)
{
	capture_callback_arg = callback_arg;
}

/**
 * 启动抓包
 */
void
WD_capture_start()
{
	int ret;

	WD_log_info("capture started");

#ifdef WD_DUMP
	ret = pcap_loop(device, capture_cnt, pcap_dump, (u_char *)dump);
#else
	ret = pcap_loop(device, capture_cnt, capture_callback,
		capture_callback_arg);
#endif
	if(ret == 0) {
		WD_log_info("capture finish");
	} else if(ret == -2) {
		WD_log_info("capture was breaked");
	} else if(ret == -1) {
		WD_log_info("capture packets error: %s", pcap_geterr(device));
	}
}

/**
 * 关闭抓包模块
 */
void
WD_capture_destory()
{
	//关闭libpcap抓包设备
	pcap_close(device);

#ifdef WD_DUMP
	// 关闭dump文件
	pcap_dump_close(dump);
#endif

#ifndef WD_OFFLINE
	// 将网卡改为Managed模式
	WD_capture_set_interface_mode(g_capture_interface,
		(void *)IW_MODE_INFRA);
#endif
}

/**
 * 设置网卡的运行模式
 */
#ifndef WD_OFFLINE
static void
WD_capture_set_interface_mode(const char *interface, void *mode)
{
	int sockfd;
	struct ifreq ifr, ifr_mode;

	// 创建套接字描述符，为调用ioctl做准备
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == sockfd) {
		err_exit("open socket error");
	}

	// 使用ioctl将网卡改为monitor模式
	// 设置两个ifreq结构体的网卡名字
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	strncpy(ifr_mode.ifr_name, interface, IFNAMSIZ);
	// 先将网卡关闭
	if(-1 == ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		err_exit1("get interface '%s' flags error", interface);
	}
	ifr.ifr_flags &= ~IFF_UP;
	if(-1 == ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
		err_exit1("set interface '%s' flags error", interface);
	}
	// 再将网卡模式设置为Monitor模式
	ifr_mode.ifr_data = mode;
	if(-1 == ioctl(sockfd, SIOCSIWMODE, &ifr_mode)) {
		err_exit1("set interface '%s' mode error", interface);
	}
	// 最后将网卡启用
	ifr.ifr_flags |= IFF_UP;
	if(-1 == ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
		err_exit1("set interface '%s' flags error", interface);
	}

	// 关闭套接字描述符
	close(sockfd);
}
#endif
