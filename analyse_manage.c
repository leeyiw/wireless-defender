#include "analyse_manage.h"
#include "analyse.h"

/* 解析管理帧的mac信息 */
void
deal_manage_mac( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	/* 三个地址分别6字节 */
	memcpy( ( *fi_ptr )->da, &bytes[0], 6 );
	memcpy( ( *fi_ptr )->sa, &bytes[6], 6 );
	memcpy( ( *fi_ptr )->bssid, &bytes[12], 6 );
	deal_seq_ctl( fi_ptr, &bytes[18] );
}

/* 解析管理帧的主体 */
void
deal_manage_body( struct frame_info **fi_ptr, const u_char *bytes )
{
	/* 管理帧的类型不同主体不同 */
	switch ( ( *fi_ptr )->subtype ) {
		case ATIM:
			break;
		case BEACON:
			deal_fix_param( fi_ptr, bytes );
			break;
		case PROBE_REQUEST:
			deal_ssid_param( fi_ptr, bytes );
			break;
		case PROBE_RESPONCE:
			deal_fix_param( fi_ptr, bytes );
			break;
		case DEAUTHENTICATION:
			//TODO
			//deal_reason_code( fi_ptr, bytes );
			break;
		case DISASSOCIATION:
			//TODO
			//deal_reason_code( fi_ptr, bytes );
			break;
		case AUTHENTICATION:
			//TODO
			//deal_auth_algo_num( fi_ptr, bytes );
			break;
		default:
			deal_cap_info( fi_ptr, bytes );
			break;
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * 以下是那些恶心的具体要看书和协议的管理帧body里的内容
 * 具体需要再讨论
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void
deal_fix_param( struct frame_info **fi_ptr, const u_char *bytes )
{
	memcpy( ( *fi_ptr )->mb->timestamp, &bytes[0], 8 );	
	memcpy( ( *fi_ptr )->mb->interval, &bytes[8], 2 );

	deal_cap_info( fi_ptr, &bytes[10] );
}

void
deal_cap_info( struct frame_info **fi_ptr, const u_char *bytes )
{
	memcpy( ( *fi_ptr )->mb->cap_info, bytes, 2 );

	switch ( ( *fi_ptr )->subtype ) {
		case BEACON:
			deal_ssid_param( fi_ptr, &bytes[2] );
			break;
		case PROBE_RESPONCE:
			deal_ssid_param( fi_ptr, &bytes[2] );
			break;
		case ASSOCIATION_REQUEST:
			//TODO
			//deal_listen_interval( fi_ptr, &bytes[2] );
			break;
		case REASSOCIATION_REQUEST:
			//TODO
			//deal_listen_interval( fi_ptr, &bytes[2] );
			break;
		default:
			//TODO
			//deal_status_code( fi_ptr, &bytes[2] );
			break;
	}
}

void 
deal_ssid_param( struct frame_info **fi_ptr, const u_char *bytes )
{	
	( *fi_ptr )->mb->s_tag_num = bytes[0];
	( *fi_ptr )->mb->s_tag_len = bytes[1];
	( *fi_ptr )->mb->ssid = ( char * )malloc( ( *fi_ptr )->mb->s_tag_len );
	memcpy( ( *fi_ptr )->mb->ssid, &bytes[2], 
				( *fi_ptr )->mb->s_tag_len );

	deal_support_rates( fi_ptr, &bytes[2+( *fi_ptr )->mb->s_tag_len] );
}

void 
deal_support_rates( struct frame_info **fi_ptr, const u_char *bytes )
{
	( *fi_ptr )->mb->sr_tag_num = bytes[0];
	( *fi_ptr )->mb->sr_tag_len = bytes[1];
	( *fi_ptr )->mb->support_rates = ( u_char * )
				malloc( ( *fi_ptr )->mb->sr_tag_len );
	memcpy( ( *fi_ptr )->mb->support_rates, &bytes[2],
				( *fi_ptr )->mb->sr_tag_len );

	deal_ds_param( fi_ptr, &bytes[2+( *fi_ptr )->mb->sr_tag_len] );
}

void
deal_ds_param( struct frame_info **fi_ptr, const u_char *bytes )
{
	( *fi_ptr )->mb->ds_tag_num = bytes[0];
	( *fi_ptr )->mb->ds_tag_len = bytes[1];
	( *fi_ptr )->mb->channel = bytes[2];

	deal_tim( fi_ptr, &bytes[3] );
}

void
deal_tim( struct frame_info **fi_ptr, const u_char *bytes )
{
	( *fi_ptr )->mb->tim_tag_num = bytes[0];
	( *fi_ptr )->mb->tim_tag_len = bytes[1];

	( *fi_ptr )->mb->count = bytes[2];
	( *fi_ptr )->mb->period = bytes[3];
	( *fi_ptr )->mb->bmap_ctrl = bytes[4];
	( *fi_ptr )->mb->vbmap = bytes[5]; 

	deal_erp( fi_ptr, &bytes[6] );
}

void
deal_erp( struct frame_info **fi_ptr, const u_char *bytes )
{
	( *fi_ptr )->mb->erp_num = bytes[0];
	( *fi_ptr )->mb->erp_len = bytes[1];
	( *fi_ptr )->mb->erp_info = bytes[2];

	deal_ext_support_rates( fi_ptr, &bytes[3] );
}

void
deal_ext_support_rates( struct frame_info **fi_ptr, const u_char *bytes )
{
	( *fi_ptr )->mb->esr_num = bytes[0];
	( *fi_ptr )->mb->esr_len = bytes[1];
	( *fi_ptr )->mb->esr = ( u_char * )malloc( ( *fi_ptr )->mb->esr_len );
	memcpy( ( *fi_ptr )->mb->esr, &bytes[2], ( *fi_ptr )->mb->esr_len );

	//deal_rsn
}
