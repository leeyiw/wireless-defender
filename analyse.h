#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rc4.h>

#include "config.h"
#include "utils.h"
#include "capture.h"

/**
 * frame_info->type
 */
#define MANAGE_TYPE				0 
#define CONTROL_TYPE			4
#define DATA_TYPE				8

/**
 * frame_info->type == MANAGE_TYPE
 * frame_info->subtype
 */
#define ASSOCIATION_REQUEST		0
#define ASSOCIATION_RESPONSE	1
#define REASSOCIATION_REQUEST	2
#define REASSOCIATION_RESPONSE	3
#define PROBE_REQUEST 			4
#define PROBE_RESPONCE 			5
#define BEACON 					8
#define ATIM 					9
#define DISASSOCIATION			10
#define AUTHENTICATION			11
#define DEAUTHENTICATION		12

/**
 * frame_info->type == CONTROL_TYPE
 * frame_info->subtype
 */
#define PS_POLL 10
#define RTS 11
#define CTS 12
#define ACK 13

/**
 * frame_info->type == DATA_TYPE
 * frame_info->subtype
 */
#define DATA 0
#define DATA_CF_ACK 1
#define DATA_CF_POLL 2
#define NULL_DATA 4
#define CF_ACK 5
#define CF_POLL 6
#define QOSDATA 8
#define QOSDATA_CF_ACK 9

#define TODS 1
#define FROMDS 2

#define u_char unsigned char

/* 具体每个代表什么去抓包吧咩哈哈哈哈 */
struct manage_body {
	u_char timestamp[8];	
	u_char interval[2]; 
	u_char cap_info[2];

	u_char s_tag_num;
	u_char s_tag_len;
	char *ssid;

	u_char sr_tag_num;
	u_char sr_tag_len;
	u_char *support_rates; 

	u_char ds_tag_num;
	u_char ds_tag_len;
	u_char channel;
	
	u_char tim_tag_num;
	u_char tim_tag_len;
	u_char count;
	u_char period;
	u_char bmap_ctrl;
	u_char vbmap;
	
	u_char erp_num;
	u_char erp_len;
	u_char erp_info;

	u_char esr_num;
	u_char esr_len;
	u_char *esr;
};

struct data_body {
	u_char *data;
};

//TODO :是否过界
struct frame_info {
	int frame_len;

	u_char type;
	u_char subtype;
	u_char flag;
	u_char duration[2];
	u_char bssid[6];
	u_char sa[6];
	u_char da[6];
	u_char ra[6];
	u_char ta[6];
	u_char loc;
	u_char frame_num;
	int seq_num;
	//TODO:考虑要不要分开
	struct manage_body *mb;
	struct data_body *db;
};

extern void WD_analyse_test( u_char *user, const struct pcap_pkthdr *h,
					const u_char *bytes );
extern void WD_analyse(u_char *user, const struct pcap_pkthdr *h,
					const u_char *bytes);
extern void deal_frame_info( struct frame_info **fi_ptr, 
					const u_char *bytes, int len );
extern void deal_type( struct frame_info **fi_ptr, 
       				const u_char *bytes );
extern void deal_flag( struct frame_info **fi_ptr, const u_char *bytes );
extern void deal_duration( struct frame_info **fi_ptr, 
					const u_char *bytes );
extern void deal_mac( struct frame_info **fi_ptr, const u_char *bytes );
extern void deal_seq_ctl( struct frame_info **fi_ptr, 
					const u_char *bytes ); 
extern void deal_frame_body( struct frame_info **fi_ptr, 
					const u_char *bytes ); 

extern void decrypt_wep( struct frame_info **fi_ptr, u_char *passwd );
extern void destroy( struct frame_info *fi_old );
#endif
