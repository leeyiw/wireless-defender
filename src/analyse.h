#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>

#include "utils.h"

extern void WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes);

#endif
