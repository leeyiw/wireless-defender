#include "analyse_control.h"

void
deal_control_mac( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	/* 根据控制帧的子类型进行不同的解析 */
	switch( ( *fi_ptr )->subtype ) {
		case PS_POLL:
			memcpy( ( *fi_ptr )->bssid, &bytes[22], 6 );
			memcpy( ( *fi_ptr )->ta, &bytes[28], 6 );
			( *fi_ptr )->loc = 34;
			break;

		case ACK:
			memcpy( ( *fi_ptr )->ra, &bytes[22], 6 );
			( *fi_ptr )->loc = 28;
			break;
		case CTS:
			memcpy( ( *fi_ptr )->ra, &bytes[22], 6 );
			( *fi_ptr )->loc = 28;
			break;
		case RTS:
			memcpy( ( *fi_ptr )->ra, &bytes[22], 6 );
			memcpy( ( *fi_ptr )->ta, &bytes[28], 6 );
			( *fi_ptr )->loc = 34;
			break;
		default:
			//TODO:考虑
			*fi_ptr = NULL;
	}
}
