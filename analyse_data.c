#include "analyse_data.h"

void
deal_data_mac(struct frame_info **fi_ptr, const uint8_t *bytes) 
{
	if((*fi_ptr)->flag & TODS) {
		if((*fi_ptr)->flag & FROMDS) {
			memcpy((*fi_ptr)->ra, &bytes[0], 6);		
			memcpy((*fi_ptr)->ta, &bytes[6], 6);
			memcpy((*fi_ptr)->da, &bytes[12], 6);
			memcpy((*fi_ptr)->sa, &bytes[18], 6);
			(*fi_ptr)->frame_len -= 30;
			deal_seq_ctl(fi_ptr, &bytes[24]);
		} else {
			memcpy((*fi_ptr)->bssid, &bytes[0], 6);
			memcpy((*fi_ptr)->sa, &bytes[6], 6);
			memcpy((*fi_ptr)->da, &bytes[12], 6);
			(*fi_ptr)->frame_len -= 24;
			deal_seq_ctl(fi_ptr, &bytes[18]);
		}
	} else {
		if((*fi_ptr)->flag & FROMDS) {
			memcpy((*fi_ptr)->da, &bytes[0], 6);	
			memcpy((*fi_ptr)->bssid, &bytes[6], 6);
			memcpy((*fi_ptr)->sa, &bytes[12], 6);
			(*fi_ptr)->frame_len -= 24;
			deal_seq_ctl(fi_ptr, &bytes[18]);
		} else {
			memcpy((*fi_ptr)->da, &bytes[0], 6);
			memcpy((*fi_ptr)->sa, &bytes[6], 6);
			memcpy((*fi_ptr)->bssid, &bytes[12], 6);
			(*fi_ptr)->frame_len -= 24;
			deal_seq_ctl(fi_ptr, &bytes[18]);
		}
	}	
}

void
deal_data_body(struct frame_info **fi_ptr, const uint8_t *bytes)
{
	(*fi_ptr)->db->data = (uint8_t *)
				malloc((*fi_ptr)->frame_len);
	memcpy((*fi_ptr)->db->data, bytes, (*fi_ptr)->frame_len);
}
