#ifndef _CAPTURE_H
#define _CAPTURE_H

#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

/* Basic operations */
#define SIOCSIWNAME	0x8B00		/* Unused */
#define SIOCGIWNAME	0x8B01		/* get name == wireless protocol */
#define SIOCSIWNWID	0x8B02		/* set network id (the cell) */
#define SIOCGIWNWID	0x8B03		/* get network id */
#define SIOCSIWFREQ	0x8B04		/* set channel/frequency (Hz) */
#define SIOCGIWFREQ	0x8B05		/* get channel/frequency (Hz) */
#define SIOCSIWMODE	0x8B06		/* set operation mode */
#define SIOCGIWMODE	0x8B07		/* get operation mode */
#define SIOCSIWSENS	0x8B08		/* set sensitivity (dBm) */
#define SIOCGIWSENS	0x8B09		/* get sensitivity (dBm) */

extern void WD_capture_init(pcap_handler callback, int cnt,
	u_char *callback_arg);
extern void WD_capture_set_callback(pcap_handler callback);
extern void WD_capture_set_cnt(int cnt);
extern void WD_capture_set_callback_arg(u_char *callback_arg);
extern void WD_capture_start();

#endif
