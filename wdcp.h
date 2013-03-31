#ifndef _WDCP_H
#define _WDCP_H

#define WDCP_CONNECTION_SUCCESS		1
#define WDCP_CONNECTION_FAIL		0

#define WDCP_AUTHENTICATE_SUCCESS	1
#define WDCP_AUTHENTICATE_FAIL		0

#define WDCP_CONN_REQ_PKT_LEN		9

#define CONN_REQ_PKT			0x01
#define CONN_RSP_PKT			0x02
#define CONN_FAIL_PKT			0x03

#define SEC_TYPE_STANDARD		0x00000000
#define SEC_TYPE_SSL			0x00000001

#define FAILED_PROTOCOL_ERR		0x00000001
#define FAILED_SSL_REQUIRED_BY_SERVER	0x00000002

#define WDCP_PACKET_LEN			4096

struct packet {
	uint8_t *buf;
	uint8_t *p;
	uint32_t len;
};

/**
 * 与客户端建立应用层连接
 * @return 返回WDCP_CONNECTION_SUCCESS为成功
 *         返回WDCP_CONNECTION_FAIL为失败
 */
extern int WD_wdcp_build_connection();

/**
 * 对客户端进行身份验证
 * @return 返回WDCP_AUTHENTICATE_SUCCESS为成功
 *         返回WDCP_AUTHENTICATE_FAIL为失败
 */
extern int WD_wdcp_authenticate();

#endif
