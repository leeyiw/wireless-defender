#ifndef _ANALYSE_MANAGE_H_
#define _ANALYSE_MANAGE_H_

#include <stdio.h>
#include "analyse.h"

extern void deal_manage_mac(frame_info **fi_ptr, const u_char *bytes);
extern void deal_manage_body(frame_info **fi_ptr, const u_char *bytes);
extern void deal_fix_param(frame_info **fi_ptr, const u_char *bytes);
extern void deal_ssid_param(frame_info **fi_ptr, const u_char *bytes);
extern void deal_support_rates(frame_info **fi_ptr, const u_char *bytes);
extern void deal_ds_param(frame_info **fi_ptr, const u_char *bytes);

#endif
