#ifndef _ANALYSE_H
#define _ANALYSE_H

#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
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

#define DATA					0
#define BEACON					8

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

#define	TYPE_KEY				0x03 
#define	EAPOL_WPA_KEY			0xfe
#define	RSN						0x02 

#define	PAIRWISE				0x08
#define INSTALL					0x40	
#define ACK						0x80
#define MIC						0x01
#define	KEY_VERSION				0x07 

#define CACHE_SIZE		100		/* 待测试 */

typedef unsigned char u_char;

typedef struct _AP_info {
	char *ssid;		
	u_char timestamp[8];
	u_char bssid[6];
	u_char sa[6];
	int encrypt;
	int is_eapol;
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
extern int deal_normal_data( const u_char *bytes );
extern void deal_timestamp( const u_char *bytes, int *packet_len ); 
extern void deal_ssid( const u_char *bytes, int *packet_len );

#endif
