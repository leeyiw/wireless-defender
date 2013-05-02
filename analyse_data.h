#ifndef _ANALYSE_DATA_H_
#define _ANALYSE_DATA_H_

#include <stdio.h>
#include "analyse.h"

extern void deal_data_mac( struct frame_info **fi_ptr, 
													const uint8_t *bytes );
extern void deal_data_body( struct frame_info **fi_ptr, 
													const uint8_t *bytes );

#endif
