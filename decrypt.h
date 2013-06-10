#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "analyse.h"

#define IV_LEN		3 

/* 保存WEP机密的信息 */

typedef struct WEP_info {
	u_char passwd[30];		/* 密码最大是( 256 - 24 ) / 8字节 */
	int passwd_len;
} WEP_info_t;

/* 保存WAP加密的信息 */

typedef struct WAP_info {
	int is_cap_auth;		/* 是否捕捉到身份验证的标志位 */
} WPA_info_t;

extern WEP_info_t *wep; 
extern void *pre_encrypt( void *arg );
extern void wep_decrypt( u_char *bytes, int frame_len );

#endif
