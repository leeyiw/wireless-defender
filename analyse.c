#include "analyse.h"
#include "analyse_manage.h"
#include "analyse_data.h"
#include "analyse_control.h"

void 
WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	int i;

	if(user != (u_char *)1) {
		return;
	}
	user_info1("capture packet len: %d, packet len: %d", 
			h->caplen, h->len);

	struct frame_info *fi = deal_frame_info((uint8_t *)bytes, 
							(int)h->caplen);
	
	/*printf("%d ", fi->frame_len);
	printf("%x %x %x ", fi->type, fi->subtype, fi->flag);
	for(i = 0; i < 6; i++) {
		printf("%x ", fi->bssid[i]);	
	}
	printf("%d %d\n", fi->frame_num, fi->seq_num);
	for(i = 0; i < 2; i++) {
		printf("%x ", fi->mb->interval[i]);
	}
	
	printf("%x %x", fi->mb->cap_info[0], fi->mb->cap_info[1]);
	printf("%s\n", fi->mb->ssid);
	
	printf("%d ", fi->mb->sr_tag_num);
	
	for(i = 0; i < 8; i++) {
		printf("%x ", fi->mb->support_rates[i]);	
	}

	printf("%d ", fi->mb->channel);
	
	printf("%d %d %d ", fi->mb->tim_tag_num, fi->mb->tim_tag_len,
			fi->mb->count);
	printf("%d ", fi->mb->bmap_ctrl);
	printf("%d ", fi->mb->vbmap);
	printf("%d ", fi->mb->erp_len);
	printf("%x ", fi->mb->erp_info);

	printf("%d ", fi->mb->esr_len);
	for(i = 0; i < 4; i++) {
		printf("%x ", fi->mb->esr[i]);	
	}
	for(i = 0; i < fi->frame_len; i++) {
		printf("%x ", fi->db->data[i]);	
	}*/
}

struct frame_info*
deal_frame_info(const uint8_t *bytes, int len)
{
	struct frame_info *fi = (struct frame_info *)
					malloc(sizeof(struct frame_info));
	fi->frame_len = len - 18;
	deal_type(&fi, &bytes[18]);

	return fi;
}

void 
deal_type(struct frame_info **fi_ptr, const uint8_t *bytes) 
{
	uint8_t temp = bytes[0];

	if(temp%16 == 0 || temp%16 == 4 || temp%16 == 8) {
		(*fi_ptr)->type = temp%16;
		temp /= 16;
		(*fi_ptr)->subtype = temp%16;
		deal_flag(fi_ptr, &bytes[1]);
		return;
	}
	*fi_ptr = NULL;
}

void
deal_flag(struct frame_info **fi_ptr, const uint8_t *bytes) 
{
	(*fi_ptr)->flag = bytes[0];
	deal_duration(fi_ptr, &bytes[1]);
}

void
deal_duration(struct frame_info **fi_ptr, const uint8_t *bytes)
{
	memcpy((*fi_ptr)->duration, bytes, 2);
	deal_mac(fi_ptr, &bytes[2]);
}

void
deal_mac(struct frame_info **fi_ptr, const uint8_t *bytes)
{
	switch((*fi_ptr)->type) {
		case MANAGE_TYPE:
			deal_manage_mac(fi_ptr, bytes);
			break;
		case CONTROL_TYPE:
			deal_control_mac(fi_ptr, bytes);
			break;
		case DATA_TYPE:
			deal_data_mac(fi_ptr, bytes);
			break;
		default:
			*fi_ptr = NULL;
			break;
	}
}

void
deal_seq_ctl(struct frame_info **fi_ptr, const uint8_t *bytes)
{
	uint8_t temp = bytes[0];

	(*fi_ptr)->frame_num = temp%16;	
	temp /= 16;	
	(*fi_ptr)->seq_num = bytes[1]*16+temp;

	deal_frame_body(fi_ptr, &bytes[2]);	
}

void 
deal_frame_body(struct frame_info **fi_ptr, const uint8_t *bytes)
{
	switch((*fi_ptr)->type) {
		case MANAGE_TYPE:
			(*fi_ptr)->mb = (struct manage_body *)
				malloc(sizeof(struct manage_body));
			deal_manage_body(fi_ptr, bytes);
			break;
		case CONTROL_TYPE:
			break;
		case DATA_TYPE:
			(*fi_ptr)->db = (struct data_body *)
				malloc(sizeof(struct data_body));
			deal_data_body(fi_ptr, bytes);
			break;
		default:
			*fi_ptr = NULL;
			break;
	}
}
