#include "analyse_data.h"

void
deal_data_mac(frame_info **fi_ptr, const u_char *bytes) 
{
	if((*fi_ptr)->flag[0]) {
		if((*fi_ptr)->flag[1]) {
			memcpy((*fi_ptr)->ra, &bytes[22], 6);		
			memcpy((*fi_ptr)->ta, &bytes[28], 6);
			memcpy((*fi_ptr)->da, &bytes[34], 6);
			memcpy((*fi_ptr)->ta, &bytes[40], 6);
			(*fi_ptr)->loc = 46;
		} else {
			memcpy((*fi_ptr)->bssid, &bytes[22], 6);
			memcpy((*fi_ptr)->sa, &bytes[28], 6);
			memcpy((*fi_ptr)->da, &bytes[34], 6);
			(*fi_ptr)->loc = 40;
		}
	} else {
		if((*fi_ptr)->flag[1]) {
			memcpy((*fi_ptr)->da, &bytes[22], 6);	
			memcpy((*fi_ptr)->bssid, &bytes[28], 6);
			memcpy((*fi_ptr)->sa, &bytes[34], 6);
			(*fi_ptr)->loc = 40;
		} else {
			memcpy((*fi_ptr)->da, &bytes[22], 6);
			memcpy((*fi_ptr)->sa, &bytes[28], 6);
			memcpy((*fi_ptr)->bssid, &bytes[34], 6);
			(*fi_ptr)->loc = 40;
		}
	}	
}
