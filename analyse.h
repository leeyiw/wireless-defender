#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rc4.h>
#include <pthread.h>

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
#define PS_POLL		10
#define RTS 		1
#define CTS 		12
#define ACK 		13

/**
 * frame_info->type == DATA_TYPE
 * frame_info->subtype
 */
#define DATA 			0
#define DATA_CF_ACK 	1
#define DATA_CF_POLL 	2
#define NULL_DATA 		4
#define CF_ACK			5
#define CF_POLL 		6
#define QOSDATA 		8
#define QOSDATA_CF_ACK 	9

#define TODS 	1
#define FROMDS 	2

#define NO_ENCRYPT		0
#define WEP_ENCRYPT		1 
#define WPA_ENCRYPT		2

#define SNAP_DSAP 				0xaa
#define SNAP_SSAP				0xaa
#define SNAP_CONTROL			0x03
#define ETHERNET_TYPE_ONE		0x88
#define ETHERNET_TYPE_SECOND	0x8e

#define WPA_FLAG		0x20

#define CACHE_SIZE		100		/* 待测试 */

typedef unsigned char u_char;

typedef struct _AP_info {
	char *ssid;		
	u_char timestamp[8];
	u_char bssid[6];
	u_char sa[6];
	int encrypt;
	int is_eapol;
	//WPA_info *wpa;
	struct _AP_info *next;
} AP_info;

typedef struct AP_list {
	AP_info *head;	
	AP_info *tail;
	AP_info *cur;
	pthread_mutex_t lock;
} AP_list_t;

typedef struct frame {
	u_char *bytes;
	int len;
} frame_t;

typedef struct queue {
	frame_t *array[CACHE_SIZE];
	int head;
	int tail;
} queue_t;

extern queue_t *q;
extern AP_list_t *AP_list; 
extern u_char ssid[105];

extern u_char *eapol[CACHE_SIZE];
extern int eapol_cur;

extern void WD_analyse_test(u_char *user, const struct pcap_pkthdr *h,
			   	const u_char *bytes);
extern int is_exist(u_char *bssid);
extern int is_eapol( const u_char *bytes );
extern int eapol_cache( const u_char *bytes );
extern void *deal_frame_info( void *arg );
extern int deal_type( u_char **bytes, int *packet_len );
extern int deal_beacon_mac( const u_char *bytes, int *packet_len );
extern int deal_data( u_char **bytes, int *packet_len );
extern int deal_eapol( const u_char *bytes );
extern int deal_data_noeapol( const u_char *bytes );
extern void deal_timestamp( const u_char *bytes, int *packet_len ); 
extern void deal_ssid( const u_char *bytes, int *packet_len );

#endif
