#include "analyse.h"

void
WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	if(user != (u_char *)1) {
		return;
	}
	user_info1("capture packet len: %d, packet len: %d", h->caplen, h->len);
}
