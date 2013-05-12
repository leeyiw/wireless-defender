#ifndef _ANALYSE_DATA_H_
#define _ANALYSE_DATA_H_

#include <stdio.h>
#include "analyse.h"

/* 具体处理data帧的部分 */

extern void deal_data_mac( struct frame_info **fi_ptr, 
													const u_char *bytes );
extern void deal_data_body( struct frame_info **fi_ptr, 
													const u_char *bytes );

#endif
