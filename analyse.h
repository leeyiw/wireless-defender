#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "utils.h"
#include "capture.h"

#define MANAGE_TYPE 0 
#define CONTROL_TYPE 4
#define DATA_TYPE 8

#define ASSOCIATION_REQUEST 0
#define ASSOCIATION_RESPONSE 1
#define REASSOCIATION_REQUEST 2
#define REASSOCIATION_RESPONSE 3
#define PROBE_REQUEST 4
#define PROBE_RESPONCE 5
#define BEACON 8
#define ATIM 9
#define DISASSOCIATION 10
#define AUTHENTICATION 11
#define DEAUTHENTICATION 12

#define DATA 0
#define DATA_CF_ACK 1
#define DATA_CF_POLL 2
#define NULL_DATA 4
#define CF_ACK 5
#define CF_POLL 6
#define QOSDATA 8
#define QOSDATA_CF_ACK 9

#define TODS 0x00000001
#define FROMDS 0x00000010

struct manage_body {
	uint8_t timestamp[8];	
	uint8_t interval[2]; 
	uint8_t cap_info[2];

	uint8_t s_tag_num;
	uint8_t s_tag_len;
	char *ssid;

	uint8_t sr_tag_num;
	uint8_t sr_tag_len;
	uint8_t *support_rates; 

	uint8_t ds_tag_num;
	uint8_t ds_tag_len;
	uint8_t channel;
	
	uint8_t tim_tag_num;
	uint8_t tim_tag_len;
	uint8_t count;
	uint8_t period;
	uint8_t bmap_ctrl;
	uint8_t vbmap;
	
	uint8_t erp_num;
	uint8_t erp_len;
	uint8_t erp_info;

	uint8_t esr_num;
	uint8_t esr_len;
	uint8_t *esr;
};

struct data_body {
	uint8_t *data;
};

//TODO :是否过界
struct frame_info {
	int frame_len;

	uint8_t type;
	uint8_t subtype;
	uint8_t flag;
	uint8_t duration[2];
	uint8_t bssid[6];
	uint8_t sa[6];
	uint8_t da[6];
	uint8_t ra[6];
	uint8_t ta[6];
	uint8_t loc;
	uint8_t frame_num;
	int seq_num;
	//TODO:考虑要不要分开
	struct manage_body *mb;
	struct data_body *db;
};

//typedef void (*PF)(frame_info **, const u_char *); 

extern void WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
					const u_char *bytes);
extern struct frame_info *deal_frame_info(const uint8_t *bytes, int len);
extern void deal_type(struct frame_info **fi_ptr, 
       		const uint8_t *bytes);
extern void deal_flag(struct frame_info **fi_ptr, const uint8_t *bytes);
extern void deal_duration(struct frame_info **fi_ptr, const uint8_t *bytes);
extern void deal_mac(struct frame_info **fi_ptr, const uint8_t *bytes);
extern void deal_seq_ctl(struct frame_info **fi_ptr, const uint8_t *bytes); 
extern void deal_frame_body(struct frame_info **fi_ptr, 
						const uint8_t *bytes); 

#endif
