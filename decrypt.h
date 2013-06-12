#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "analyse.h"
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>

#define IV_LEN		3 

/* 保存WEP机密的信息 */

typedef struct user_info {
	u_char passwd[30];		/* 密码最大是( 256 - 24 ) / 8字节 */
	int passwd_len;
} user_info_t;

/* 保存WAP加密的信息 */

typedef struct WPA_info {
	u_char snonce[32];
	u_char anonce[32];
	u_char stmac[6];
	u_char bssid[6];
	u_char keymic[20];
	u_char ptk[80];
	int key_version;
	int valid_ptk;
} WPA_info_t;

extern user_info_t *user; 
extern WPA_info_t *wpa;
extern void *pre_encrypt( void *arg );
extern void wep_decrypt( u_char *bytes, int frame_len );
extern void calc_pmk( char *key, char *essid_pre, u_char pmk[40] );

#endif
