#ifndef _CAPTURE_H
#define _CAPTURE_H

#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "config.h"

extern void WD_capture_init(pcap_handler callback, int cnt,
	u_char *callback_arg);
extern void WD_capture_set_callback(pcap_handler callback);
extern void WD_capture_set_cnt(int cnt);
extern void WD_capture_set_callback_arg(u_char *callback_arg);
extern void WD_capture_start();
extern void WD_capture_destory();

#endif
