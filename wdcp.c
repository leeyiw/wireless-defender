#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#include "wdcp.h"
#include "server.h"
#include "utils.h"

static ssize_t WD_wdcp_recv(int sockfd, void *buf, size_t len, int flags);
static ssize_t WD_wdcp_send(int sockfd, void *buf, size_t len, int flags);
static void WD_wdcp_new_pkt(struct packet *p);
static void WD_wdcp_del_pkt(struct packet *p);
static void WD_wdcp_rst_pkt(struct packet *p);
static void WD_wdcp_send_pkt(struct packet *p);
static void WD_wdcp_recv_pkt(struct packet *p);
static void WD_wdcp_packet_write_n(struct packet *p, void *data, size_t len);
static void WD_wdcp_packet_write_u8(struct packet *p, uint8_t data);
static void WD_wdcp_packet_write_u32(struct packet *p, uint32_t data);
static void WD_wdcp_packet_read_n(struct packet *p, void *data, size_t len);
static void WD_wdcp_packet_read_u8(struct packet *p, uint8_t *data);
static void WD_wdcp_packet_read_u32(struct packet *p, uint32_t *data);

static void WD_wdcp_send_conn_fail_pkt(uint32_t failure_code);

int
WD_wdcp_build_connection()
{
	struct packet p;
	uint8_t type;
	uint32_t version, security_type;


	WD_wdcp_new_pkt(&p);
	// 接收请求连接数据包
	WD_wdcp_recv_pkt(&p);
	// 如果数据包长度大于规定长度则发送连接失败数据包
	if(p.len != WDCP_CONN_REQ_PKT_LEN) {
		WD_wdcp_del_pkt(&p);
		WD_wdcp_send_conn_fail_pkt(FAILED_PROTOCOL_ERR);
		return WDCP_CONNECTION_FAIL;
	}
	// 如果数据包类型不为请求连接数据包则发送连接失败数据包
	WD_wdcp_packet_read_u8(&p, &type);
	if(type != CONN_REQ_PKT) {
		WD_wdcp_del_pkt(&p);
		WD_wdcp_send_conn_fail_pkt(FAILED_PROTOCOL_ERR);
		return WDCP_CONNECTION_FAIL;
	}
	// 如果版本号不为0x00010000则发送连接失败数据包
	WD_wdcp_packet_read_u32(&p, &version);
	if(version != 0x00010000) {
		WD_wdcp_del_pkt(&p);
		WD_wdcp_send_conn_fail_pkt(FAILED_PROTOCOL_ERR);
		return WDCP_CONNECTION_FAIL;
	}
	// 记录客户支持的加密方式
	WD_wdcp_packet_read_u32(&p, &security_type);
	

	// 发送连接响应数据包
	WD_wdcp_rst_pkt(&p);
	WD_wdcp_packet_write_u8(&p, CONN_RSP_PKT);
	WD_wdcp_packet_write_u32(&p, SEC_TYPE_STANDARD);
	WD_wdcp_send_pkt(&p);

	return WDCP_CONNECTION_SUCCESS;
}

ssize_t
WD_wdcp_recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t n;

	n = recv(client_fd, buf, sizeof(buf), 0);
	if(n == -1) {
		err_exit("receive data from client error");
	}

	return n;
}

ssize_t
WD_wdcp_send(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t n;

	n = send(client_fd, buf, sizeof(buf), 0);
	if(n == -1) {
		err_exit("send data to client error");
	}

	return n;
}

void
WD_wdcp_new_pkt(struct packet *p)
{
	p->buf = malloc(WDCP_PACKET_LEN);
	if(p->buf == NULL) {
		err_exit("create new packet error");
	}
	p->p = p->buf;
}

void
WD_wdcp_del_pkt(struct packet *p)
{
	free(p->buf);
}

void
WD_wdcp_rst_pkt(struct packet *p)
{
	p->p = p->buf;
	p->len = 0;
}

void
WD_wdcp_send_pkt(struct packet *p)
{
	WD_wdcp_send(client_fd, p->buf, p->p - p->buf, 0);
}

void
WD_wdcp_recv_pkt(struct packet *p)
{
	p->len = WD_wdcp_recv(client_fd, p->buf, WDCP_PACKET_LEN, 0);
	p->p = p->buf;
}

void
WD_wdcp_packet_write_n(struct packet *p, void *data, size_t len)
{
	memcpy(p->p, data, len);
	p->p += len;
}

void
WD_wdcp_packet_write_u8(struct packet *p, uint8_t data)
{
	WD_wdcp_packet_write_n(p, &data, sizeof(data));
}

void
WD_wdcp_packet_write_u32(struct packet *p, uint32_t data)
{
	WD_wdcp_packet_write_n(p, &data, sizeof(data));
}

void
WD_wdcp_packet_read_n(struct packet *p, void *data, size_t len)
{
	memcpy(data, p->p, len);
	p->p += len;
}

void
WD_wdcp_packet_read_u8(struct packet *p, uint8_t *data)
{
	WD_wdcp_packet_read_n(p, data, sizeof(*data));
}

void
WD_wdcp_packet_read_u32(struct packet *p, uint32_t *data)
{
	WD_wdcp_packet_read_n(p, data, sizeof(*data));
}

void
WD_wdcp_send_conn_fail_pkt(uint32_t failure_code)
{
	struct packet pkt;

	WD_wdcp_new_pkt(&pkt);

	WD_wdcp_packet_write_u8(&pkt, CONN_FAIL_PKT);
	WD_wdcp_packet_write_u32(&pkt, failure_code);
	WD_wdcp_send_pkt(&pkt);

	WD_wdcp_del_pkt(&pkt);
}
