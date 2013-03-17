#include "capture.h"

static pcap_t *device;
static char errbuf[PCAP_ERRBUF_SIZE];

void
WD_capture_init()
{
	device = pcap_open_live(g_interface, 65535, 0, 0, errbuf);
	if(device == NULL) {
		user_exit1("open device '%s' for capturing error: %s",
			g_interface, errbuf);
	}
}
