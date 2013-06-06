#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "analyse.h"

/* 保存WEP机密的信息 */

struct WEP_info {
	u_char IV[4];			/* WEP的IV是三个字节 */
	u_char passwd[30];		/* 密码最大是( 256 - 24 ) / 8字节 */
} WEP_info_t;

/* 保存WAP加密的信息 */

struct WAP_info {
	int is_cap_auth;		/* 是否捕捉到身份验证的标志位 */
} WPA_info_t;

extern void *pre_encrypt( void *arg );
#endif
