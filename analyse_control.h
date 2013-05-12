#ifndef _ANALYSE_CONCTROL_H_
#define _ANALYSE_CONCTROL_H_

#include "analyse.h"

/* 具体control帧的内容 */
extern void deal_control_mac(struct frame_info **fi_ptr, 
													const u_char *bytes);

#endif
