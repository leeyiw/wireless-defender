#include "analyse.h"
#include "analyse_manage.h"
#include "analyse_data.h"
#include "analyse_control.h"

void 
WD_analyse_test( u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes ) 
{
	if( user != ( u_char * ) 1 )  {
		return;
	}
	user_info1( "capture packet len: %d, packet len: %d", 
			h->caplen, h->len ) ;

	struct frame_info *fi = deal_frame_info( ( u_char * ) bytes, 
									( int ) h->caplen ) ;

/* for test */

//	u_char optarg[] = { 0x01, 0x02, 0x03, 0x04, 0x05,
//						0x06, 0x07, 0x08, 0x09, 0x00 };
//	decrypt_wep( &fi, optarg );
//
//	int i;
//	for( i = 4; i < fi->frame_len; i++ ) {
//		printf( "%x ", fi->db->data[i] );
//	}
//  printf( "%d ", fi->frame_len ) ;
 	printf( "%x %x %x ", fi->type, fi->subtype, fi->flag ) ;
//	printf( "%x %x", fi->duration[0], fi->duration[1] ) ;
// 	for( i = 0; i < 6; i++ )  {
// 		printf( "%x ", fi->bssid[i] ) ;	
//	}
// 	printf( "%d %d\n", fi->frame_num, fi->seq_num ) ;
// 	for( i = 0; i < 2; i++ )  {
// 		printf( "%x ", fi->mb->interval[i] ) ;
// 	}
// 	
// 	printf( "%x %x", fi->mb->cap_info[0], fi->mb->cap_info[1] ) ;
// 	printf( "%s\n", fi->mb->ssid ) ;
// 	
// 	printf( "%d ", fi->mb->sr_tag_num ) ;
// 	
// 	for( i = 0; i < 8; i++ )  {
// 		printf( "%x ", fi->mb->support_rates[i] ) ;	
// 	}
// 
// 	printf( "%d ", fi->mb->channel ) ;
// 	
// 	printf( "%d %d %d ", fi->mb->tim_tag_num, fi->mb->tim_tag_len,
// 			fi->mb->count ) ;
// 	printf( "%d ", fi->mb->bmap_ctrl ) ;
// 	printf( "%d ", fi->mb->vbmap ) ;
// 	printf( "%d ", fi->mb->erp_len ) ;
// 	printf( "%x ", fi->mb->erp_info ) ;
// 
// 	printf( "%d ", fi->mb->esr_len ) ;
// 	for( i = 0; i < 4; i++ )  {
// 		printf( "%x ", fi->mb->esr[i] ) ;	
// 	}
// 	for( i = 0; i < fi->frame_len; i++ )  {
// 		printf( "%x ", fi->db->data[i] ) ;	
//	}
}

void WD_analyse(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	//struct frame_info *fi = NULL;

	//fi = deal_frame_info((const u_char *)bytes, h->caplen);
	//if(fi->type == MANAGE_TYPE && fi->subtype == BEACON) {
	//	user_info("beacon frame detected!");
	//}
	//free(fi);
}

/* 解密wep加密的内容，为无线流量分析 */

void
decrypt_wep( struct frame_info **fi_ptr, u_char *passwd ) {
	int i, j = 3;
	RC4_KEY s;
	u_char key[10];
	struct frame_info *fi = *fi_ptr;

	/* iv和密码合成密钥 */

	memcpy( key, fi->db->data, 3 ) ;
	for( i = 0; i < 10; i += 2 )  {
		key[j++] = passwd[i]*16 + passwd[i+1];
	}

	/* 使用openssl带的RC4算法 */

	RC4_set_key( &s, 8, key ) ;
	RC4( &s, fi->frame_len - 4, &fi->db->data[4], &fi->db->data[4] ) ;
}

/* 帧处理的开始 */

struct frame_info*
deal_frame_info( const u_char *bytes, int len ) 
{
	struct frame_info *fi = ( struct frame_info * ) 
					malloc( sizeof( struct frame_info )  ) ;

	/* 捕获的包的长度减去18个字节的头部信息 */

	fi->frame_len = len - 18;
	deal_type( &fi, &bytes[18] ) ;

	return fi;
}

/* 解析帧中的类型和子类型信息 */

void 
deal_type( struct frame_info **fi_ptr, const u_char *bytes )  
{
	u_char temp = bytes[0] % 16;

	/* 如果不属于三种类型之一，则返回NULL */ 
	if( temp == MANAGE_TYPE || temp == CONTROL_TYPE 
			|| temp == DATA_TYPE )  {

		( *fi_ptr ) ->type = temp;
		( *fi_ptr ) ->subtype = ( bytes[0] / 16 ) % 16;
		deal_flag( fi_ptr, &bytes[1] ) ;
		return;
	}
	*fi_ptr = NULL;
}

/* 解析帧内一组标志位信息 */

void
deal_flag( struct frame_info **fi_ptr, const u_char *bytes )  
{
	( *fi_ptr ) ->flag = bytes[0];
	deal_duration( fi_ptr, &bytes[1] ) ;
}

/* 解析duration/id信息 */

void
deal_duration( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	memcpy( ( *fi_ptr ) ->duration, bytes, 2 ) ;
	deal_mac( fi_ptr, &bytes[2] ) ;
}

/* 解析mac信息 */

void
deal_mac( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	/* 根据帧的类型不同 */

	switch( ( *fi_ptr ) ->type )  {
		case MANAGE_TYPE:
			deal_manage_mac( fi_ptr, bytes ) ;
			break;
		case CONTROL_TYPE:
			deal_control_mac( fi_ptr, bytes ) ;
			break;
		case DATA_TYPE:
			deal_data_mac( fi_ptr, bytes ) ;
			break;
		default:
			*fi_ptr = NULL;
			break;
	}
}

/* 解析帧的顺序控制字段 */

void
deal_seq_ctl( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	u_char temp = bytes[0];

	( *fi_ptr ) ->frame_num = temp%16;	
	temp /= 16;	
	( *fi_ptr ) ->seq_num = bytes[1]*16+temp;

	deal_frame_body( fi_ptr, &bytes[2] ) ;	
}

/* 解析帧主体 */

void 
deal_frame_body( struct frame_info **fi_ptr, const u_char *bytes ) 
{
	/* 根据帧类型不同分别解析 */

	switch( ( *fi_ptr ) ->type )  {
		case MANAGE_TYPE:
			( *fi_ptr ) ->mb = ( struct manage_body * ) 
				malloc( sizeof( struct manage_body ) ) ;
			deal_manage_body( fi_ptr, bytes ) ;
			break;
		/* 控制帧没有帧主体 */
		case CONTROL_TYPE:
			break;
		case DATA_TYPE:
			( *fi_ptr ) ->db = ( struct data_body * ) 
				malloc( sizeof( struct data_body ) ) ;
			deal_data_body( fi_ptr, bytes ) ;
			break;
		default:
			*fi_ptr = NULL;
			break;
	}
}
