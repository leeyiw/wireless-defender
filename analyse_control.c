#include "analyse_control.h"

void
deal_control_mac(frame_info **fi_ptr, const u_char *bytes) 
{
	switch((*fi_ptr)->subtype) {
		case 5:
			memcpy((*fi_ptr)->bssid, &bytes[22], 6);
			memcpy((*fi_ptr)->ta, &bytes[28], 6);
			(*fi_ptr)->loc = 34;
			break;

		case 11:
			memcpy((*fi_ptr)->ra, &bytes[22], 6);
			(*fi_ptr)->loc = 28;
			break;
		case 12:
			memcpy((*fi_ptr)->ra, &bytes[22], 6);
			(*fi_ptr)->loc = 28;
			break;
		case 13:
			memcpy((*fi_ptr)->ra, &bytes[22], 6);
			memcpy((*fi_ptr)->ta, &bytes[28], 6);
			(*fi_ptr)->loc = 34;
			break;
	}
}
