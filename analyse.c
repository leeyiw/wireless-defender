#include "analyse.h"
#include "analyse_manage.h"
#include "analyse_data.h"
#include "analyse_control.h"

/*void
WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{

	if(user != (u_char *)1) {
		return;
	}
	user_info1("capture packet len: %d, packet len: %d", 
			h->caplen, h->len);
	//deal_frame_info(bytes);
}*/

frame_info*
deal_frame_info(const u_char *bytes)
{
	int i;
	frame_info *fi = (frame_info *)malloc(sizeof(frame_info));
	
	PF analyse_chain[6] = {&deal_type, &deal_flag, &deal_duration,
		&deal_mac, &deal_seq_ctl, &deal_frame_body};
	for(i = 0; i < sizeof(analyse_chain)/sizeof(analyse_chain[0]);
			i++) {
		analyse_chain[i](&fi, bytes);	
	}

	return fi;
}

void 
deal_type(frame_info **fi_ptr, const u_char *bytes) 
{
	uint8_t temp = (uint8_t)bytes[18];

	(*fi_ptr)->type = temp%16;
	temp /= 16;
	(*fi_ptr)->subtype = temp%16;
}

void
deal_flag(frame_info **fi_ptr, const u_char *bytes) 
{
	int i;
	uint8_t temp = (uint8_t)bytes[19];

	for(i = 0; i < 8; i++) {
		(*fi_ptr)->flag[i] = temp%2;
		temp /= 2;
	}
}

void
deal_duration(frame_info **fi_ptr, const u_char *bytes)
{
	int i;
	int temp = (int)bytes[21]*256+(int)bytes[20];

	for(i = 0; i < 16; i++) {
		(*fi_ptr)->duration[i] = temp%2;
		temp /= 2;
	}
}

void
deal_mac(frame_info **fi_ptr, const u_char *bytes)
{
	switch((*fi_ptr)->type) {
		case 8:
			deal_data_mac(fi_ptr, bytes);
			break;
		case 0:
			deal_manage_mac(fi_ptr, bytes);
			break;
		case 4:
			deal_control_mac(fi_ptr, bytes);
			break;
	}
}

void
deal_seq_ctl(frame_info **fi_ptr, const u_char *bytes)
{
	int temp = bytes[(*fi_ptr)->loc];

	if(!(*fi_ptr)->type) {
		(*fi_ptr)->frame_num = temp%16;	
		temp /= 16;	
		(*fi_ptr)->seq_num = bytes[(*fi_ptr)->loc+1]*16+temp;
		(*fi_ptr)->loc += 2;
	}
}

void 
deal_frame_body(frame_info **fi_ptr, const u_char *bytes)
{
	switch((*fi_ptr)->type) {
		case 8:
			//(*fi_ptr)->db = (data_body *)
				//malloc(sizeof(data_body));
			//deal_data_body(fi_ptr, bytes);
			break;
		case 0:
			(*fi_ptr)->mb = (manage_body *)
				malloc(sizeof(manage_body));
			deal_manage_body(fi_ptr, bytes);
			break;
		case 4:
			//(*fi_ptr)->cb = (control_body *)
				//malloc(sizeof(control_body));
			//deal_control_body(fi_ptr, bytes);
			break;
	}
}

int
main(int argc, char *argv[])
{
	/*WD_config_init();

	WD_capture_init(WD_analyse_test, 1, (u_char *)1);
	WD_capture_start();
	WD_capture_destory();
	FILE *fp = fopen("offline.pcap", "r");
	unsigned char a[105];
	u_char b[605];
	int i;
	
	fread(a, sizeof(unsigned char), 40, fp);
	fread(b, sizeof(u_char), 600, fp);

	frame_info *fi = deal_frame_info(b);

	for(i = 0; i < 6; i++) {
		printf("%x ", fi->da[i]);	
	}
	printf("%d %d\n", fi->frame_num, fi->seq_num);
	for(i = 0; i < 2; i++) {
		printf("%x ", fi->mb->interval[i]);
	}*/

	/*for(i = 0; i < 16; i++) {
		printf("%x ", fi->mb->cap_info[i]);	
	}*/

	//printf("%s\n", fi->mb->ssid);
	
	//printf("%d ", fi->mb->sr_tag_num);
	
	/*for(i = 0; i < 8; i++) {
		printf("%x ", fi->mb->support_rates[i]);	
	}*/

	/*printf("%d ", fi->mb->channel);*/
	return 0;
}
