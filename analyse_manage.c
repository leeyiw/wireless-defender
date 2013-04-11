#include "analyse_manage.h"
#include "analyse.h"

void
deal_manage_mac(frame_info **fi_ptr, const u_char *bytes) 
{
	memcpy((*fi_ptr)->da, &bytes[22], 6);
	memcpy((*fi_ptr)->sa, &bytes[28], 6);
	memcpy((*fi_ptr)->bssid, &bytes[34], 6);
	(*fi_ptr)->loc = 40;
}

void
deal_manage_body(frame_info **fi_ptr, const u_char *bytes)
{
	deal_fix_param(fi_ptr, bytes);
	deal_ssid_param(fi_ptr, bytes);
	deal_support_rates(fi_ptr, bytes);
	deal_ds_param(fi_ptr, bytes);
}

void
deal_fix_param(frame_info **fi_ptr, const u_char *bytes)
{
	int loc = (*fi_ptr)->loc;
	int i;
	
	memcpy((*fi_ptr)->mb->timestamp, &bytes[loc], 8);	
	memcpy((*fi_ptr)->mb->interval, &bytes[loc+8], 2);

	int temp = (int)bytes[loc+11]*256+(int)bytes[loc+10];

	for(i = 0; i < 16; i++) {
		(*fi_ptr)->mb->cap_info[i] = temp%2;
		temp /= 2;
	}

	(*fi_ptr)->loc += 12;
}

void 
deal_ssid_param(frame_info **fi_ptr, const u_char *bytes)
{	
	int loc = (*fi_ptr)->loc;

	(*fi_ptr)->mb->s_tag_num = (uint8_t)bytes[loc];
	(*fi_ptr)->mb->s_tag_len = (uint8_t)bytes[loc+1];
	(*fi_ptr)->mb->ssid = (char *)malloc((*fi_ptr)->mb->s_tag_len);
	memcpy((*fi_ptr)->mb->ssid, &bytes[loc+2], 
				(*fi_ptr)->mb->s_tag_len);

	(*fi_ptr)->loc += (*fi_ptr)->mb->s_tag_len+2;
}

void 
deal_support_rates(frame_info **fi_ptr, const u_char *bytes)
{
	int loc = (*fi_ptr)->loc;	

	(*fi_ptr)->mb->sr_tag_num = (uint8_t)bytes[loc];
	(*fi_ptr)->mb->sr_tag_len = (uint8_t)bytes[loc+1];
	(*fi_ptr)->mb->support_rates = (uint8_t *)
				malloc((*fi_ptr)->mb->sr_tag_len);
	memcpy((*fi_ptr)->mb->support_rates, &bytes[loc+2],
				(*fi_ptr)->mb->sr_tag_len);

	(*fi_ptr)->loc += (*fi_ptr)->mb->sr_tag_len+2;
}

void
deal_ds_param(frame_info **fi_ptr, const u_char *bytes)
{
	int loc = (*fi_ptr)->loc;	
	
	(*fi_ptr)->mb->ds_tag_num = (uint8_t)bytes[loc];
	(*fi_ptr)->mb->ds_tag_len = (uint8_t)bytes[loc+1];
	(*fi_ptr)->mb->channel = (uint8_t)bytes[loc+3];

	(*fi_ptr)->loc += 4;
}

void
deal_tim(frame_info **fi_ptr, const u_char *bytes)
{
	int loc = (*fi_ptr)->loc;	
	
}
