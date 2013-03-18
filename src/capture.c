#include "capture.h"

static pcap_t *device;
static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_handler capture_callback;
static int capture_cnt;
static u_char *capture_callback_arg;

void
WD_capture_init(pcap_handler callback, int cnt, u_char *callback_arg)
{
	device = pcap_open_live(g_interface, 65535, 0, 0, errbuf);
	if(device == NULL) {
		user_exit1("open device '%s' for capturing error: %s",
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
