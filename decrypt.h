#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "analyse.h"
#include "flow.h"
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>

#define IV_LEN		3 

#define TKIP		1

#define ROTR1(x)      ((((x) >> 1) & 0x7FFF) ^ (((x) & 1) << 15))
#define LO8(x)        ( (x) & 0x00FF )
#define LO16(x)       ( (x) & 0xFFFF )
#define HI8(x)        ( ((x) >>  8) & 0x00FF )
#define HI16(x)       ( ((x) >> 16) & 0xFFFF )
#define MK16(hi,lo)   ( (lo) ^ ( LO8(hi) << 8 ) )
#define TK16(N)       MK16(TK1[2*(N)+1],TK1[2*(N)])
#define _S_(x)        (TkipSbox[0][LO8(x)] ^ TkipSbox[1][HI8(x)])

/* 保存WEP机密的信息 */

typedef struct user_info {
	u_char passwd[30];		/* 密码最大是( 256 - 24 ) / 8字节 */
	int passwd_len;
} user_info_t;

/* 保存WAP加密的信息 */

typedef struct WPA_info {
	u_char snonce[32];
	u_char anonce[32];
	u_char keymic[20];
	u_char bssid[6];
	u_char stmac[6];
	u_char ptk[80];
	u_char eapol[256];
	int eapol_size;
	int keyver;
	int valid_ptk;
} WPA_info_t;

extern user_info_t *user; 
extern WPA_info_t *wpa;
extern void merge_iv( u_char *bytes, int frame_len,	u_char key[40] );
extern void wep_decrypt( u_char *data, u_char *key, int len, int keylen );
extern void calc_pmk( char *key, char *essid_pre, u_char pmk[40] );
extern int calc_ptk( u_char pmk[40] );
extern void *pre_encrypt( void *arg );
extern int calc_tkip_ppk( u_char *bytes, int caplen, u_char TK1[16], 
														u_char key[16] );
extern void decrypt_tkip( u_char *bytes, int len, u_char TK1[16] );

#endif
