#include "wireless-defender.h"

void
test_capture(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	if(user != (u_char *)1) {
		return;
	}
	user_info1("capture packet len: %d, packet len: %d", h->caplen, h->len);
}

int
main(int argc, char *argv[])
{
	WD_config_init();

	WD_capture_init(test_capture, 10, (u_char *)1);
	WD_capture_start();

	return 0;
}
