#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "utils.h"
#include "capture.h"

typedef struct Manage_body {
	uint8_t timestamp[8];	
	uint8_t interval[2]; 
	uint8_t cap_info[16];

	uint8_t s_tag_num;
	uint8_t s_tag_len;
	char *ssid;

	uint8_t sr_tag_num;
	uint8_t sr_tag_len;
	uint8_t *support_rates; 

	uint8_t ds_tag_num;
	uint8_t ds_tag_len;
	uint8_t channel;
	
	uint8_t tim_num;
	uint8_t tim_len;
	uint8_t count;
	uint8_t period;
}manage_body;

//todo:是否过界
typedef struct Frame_info {
	uint8_t type;
	uint8_t subtype;
	uint8_t flag[8];
	uint8_t duration[16];
	uint8_t bssid[6];
	uint8_t sa[6];
	uint8_t da[6];
	uint8_t ra[6];
	uint8_t ta[6];
	uint8_t loc;
	uint8_t frame_num;
	int seq_num;
	//todo:考虑要不要分开
	manage_body *mb;
	//data_body *db;
	//control_body *cb;
}frame_info;

typedef void (*PF)(frame_info **, const u_char *); 

extern void WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes);
extern frame_info *deal_frame_info(const u_char *bytes);
extern void deal_type(frame_info **fi_ptr, const u_char *bytes);
extern void deal_flag(frame_info **fi_ptr, const u_char *bytes);
extern void deal_duration(frame_info **fi_ptr, const u_char *bytes);
extern void deal_mac(frame_info **fi_ptr, const u_char *bytes);
extern void deal_seq_ctl(frame_info **fi_ptr, const u_char *bytes); 
extern void deal_frame_body(frame_info **fi_ptr, const u_char *bytes); 

#endif
