#ifndef _WDCP_H
#define _WDCP_H

#define WDCP_PACKET_LEN				4096

/* 连接过程中的宏定义 */
#define WDCP_CONNECTION_SUCCESS		1
#define WDCP_CONNECTION_FAIL		0

#define WDCP_CONN_REQ_PKT_LEN		9

#define CONN_REQ_PKT				0x01
#define CONN_RSP_PKT				0x02
#define CONN_FAIL_PKT				0x03

#define SEC_TYPE_STANDARD			0x00000000
#define SEC_TYPE_SSL				0x00000001

#define FAILED_PROTOCOL_ERR			0x00000001
#define FAILED_SSL_REQUIRED			0x00000002

/* 认证过程中的宏定义 */
#define WDCP_AUTHENTICATE_SUCCESS	1
#define WDCP_AUTHENTICATE_FAIL		0

#define AUTH_REQ_PKT				0x01
#define AUTH_RSP_PKT				0x02
#define AUTH_FAIL_PKT				0x03

#define AUTH_DEFAULT_USERNAME		"wdadmin"
#define AUTH_DEFAULT_PASSWORD		"wdadmin"

#define AUTH_CHECK_SUCCESS			1
#define AUTH_CHECK_FAIL				0

#define FAILED_AUTH_CHECK			0x00000002

/* 通信过程中的宏定义 */
#define WDCP_PROCESS_SUCCESS		1
#define WDCP_PROCESS_FAIL			0

#define DATA_REQ_PKT				0x01
#define DATA_RSP_PKT				0x02

#define REQ_TYPE_BASIC_INFO			0x00
#define REQ_TYPE_AP_LIST			0x01
#define REQ_TYPE_FAKE_AP			0x02


struct packet {
	uint8_t *buf;
	uint8_t *p;
	uint32_t len;
};

/**
 * 与客户端建立应用层连接
 * @param fd 与客户端通信的套接字
 * @return 返回WDCP_CONNECTION_SUCCESS为成功
 *         返回WDCP_CONNECTION_FAIL为失败
 */
extern int WD_wdcp_build_connection(int fd);

/**
 * 对客户端进行身份验证
 * @param fd 与客户端通信的套接字
 * @return 返回WDCP_AUTHENTICATE_SUCCESS为成功
 *         返回WDCP_AUTHENTICATE_FAIL为失败
 */
extern int WD_wdcp_authenticate(int fd);

/**
 * 与客户端进行数据通信
 * @param fd 与客户端通信的套接字
 * @return 返回WDCP_PROCESS_SUCCESS为成功
 *         返回WDCP_PROCESS_FAIL为失败
 */
extern int WD_wdcp_process(int fd);

#endif
