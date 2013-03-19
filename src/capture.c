#include "capture.h"

static pcap_t *device;
static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_handler capture_callback;
static int capture_cnt;
static u_char *capture_callback_arg;

/** \brief 初始化capture模块
 *
 */
void
WD_capture_init(pcap_handler callback, int cnt, u_char *callback_arg)
{
	int sockfd;
	struct ifreq ifr;

	// 创建套接字描述符，为调用ioctl做准备
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == sockfd) {
		err_exit("open socket error");
	}

	// 使用ioctl将网卡改为monitor模式
	if(-1 == ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		err_exit1("get interface '%s' flags error", g_interface);
	}

	// 初始化libpcap抓包设备
	device = pcap_open_live(g_interface, 65535, 0, 0, errbuf);
	if(device == NULL) {
		user_exit1("open interface '%s' for capturing error: %s",
			g_interface, errbuf);
	}
	capture_callback = callback;
	capture_cnt = cnt;
	capture_callback_arg = callback_arg;
}

void
WD_capture_set_callback(pcap_handler callback)
{
	capture_callback = callback;
}

void
WD_capture_set_cnt(int cnt)
{
	capture_cnt = cnt;
}

void
WD_capture_set_callback_arg(u_char *callback_arg)
{
	capture_callback_arg = callback_arg;
}

void
WD_capture_start()
{
	int ret;

	ret = pcap_loop(device, capture_cnt, capture_callback,
		capture_callback_arg);
	if(ret == 0) {
		user_info("capture count exhausted");
	} else if(ret == -2) {
		user_info("capture was breaked");
	} else if(ret == -1) {
		pcap_perror(device, "capture error");
	}
}
