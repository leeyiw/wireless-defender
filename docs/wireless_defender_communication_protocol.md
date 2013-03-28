# wireless-defender通信协议

## 目录
* [1 协议简介](#introduction)
 - [1.1 通用规范](#common-specification)
 - [1.2 连接建立过程](#connection-sequence)
* [2 协议定义](#protocol-definition)
 - [2.1 请求连接数据包](#connection-request-packet)
 - [2.2 连接响应数据包](#connection-response-packet)
 - [2.3 连接失败数据包](#connection-failure-packet)

<a name="introduction"></a>
## 1 协议简介
本协议规范了wireless-defender通信过程中的通信流程和数据包格式。

<a name="common-specification"></a>
### 1.1 通用规范
1. 本协议中的多字节位除了特别说明的以外，均采用__小端序__传输

<a name="connection-sequence"></a>
### 1.2 连接建立过程
client        ---->        server  
发送[请求连接数据包](#connection-request-packet)，服务器进行验证

client        <----        server  
如果连接成功，发送[连接响应数据包](#connection-response-packet)，完成连接建立  
如果连接失败，发送[连接失败数据包](#connection-failure-packet)，然后断开TCP连接


<a name="protocol-definition"></a>
## 2 协议定义

<a name="connection-request-packet"></a>
### 2.1 请求连接数据包
请求连接数据包是客户端和服务器建立TCP连接后，客户端发往服务器的第一个数据包。内容如下：

type (1 byte): 一字节无符号整形。连接请求数据包的类型，这个字段的值必须为0x01(CONN_REQ_PKT)。

version (4 bytes): 四字节无符号整形。标识了客户端使用的协议版本号。目前这个值为0x00010000。

security_type (4 bytes): 四字节无符号整形，标识了客户端支持的加密方式。取值如下：

<table>
	<tr>
		<td>security_type</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>SEC_TYPE_STANDARD</td>
		<td>0x00000000</td>
		<td>&#19981;&#21152;&#23494;</td>
	</tr>
	<tr>
		<td>SEC_TYPE_SSL</td>
		<td>0x00000001</td>
		<td>&#20351;&#29992;SSL&#21152;&#23494;</td>
	</tr>
</table>

<a name="connection-response-packet"></a>
### 2.2 连接响应数据包
连接响应数据包是服务器收到客户端发出的[连接请求数据包](#connection-request-packet)后，服务器判断可以与客户端连接，然后发送给客户端的数据包。数据包内容如下：

type (1 byte): 一字节无符号整形。连接响应数据包的类型，这个字段的值必须为0x02(CONN_RSP_PKT)。

security_type (4 bytes): 四字节无符号整形，标识了服务器选择的加密方式。取值如下：

<table>
	<tr>
		<td>security_type</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>SEC_TYPE_STANDARD</td>
		<td>0x00000000</td>
		<td>&#19981;&#21152;&#23494;</td>
	</tr>
	<tr>
		<td>SEC_TYPE_SSL</td>
		<td>0x00000001</td>
		<td>&#20351;&#29992;SSL&#21152;&#23494;</td>
	</tr>
</table>

<a name="connection-failure-packet"></a>
### 2.3 连接失败数据包
连接失败数据包是服务器收到客户端发出的[连接请求数据包](#connection-request-packet)后，服务器判断不能与客户端连接，然后发送给客户端的数据包。服务器发送完本数据包后，应该关闭TCP连接的读和写。客户端收到本数据包后，应该关闭TCP连接的读和写。数据包内容如下：

type (1 byte): 一字节无符号整形。连接响应数据包的类型，这个字段的值必须为0x03(CONN_FAIL_PKT)。

failure_code (4 bytes): 四字节无符号整形，连接失败的错误码，取值如下：

<table>
	<tr>
		<td>failure_code</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>FAILED_PROTOCOL_ERR</td>
		<td>0x00000001</td>
		<td>&#21327;&#35758;&#38169;&#35823;</td>
	</tr>
	<tr>
		<td>FAILED_SSL_REQUIRED_BY_SERVER</td>
		<td>0x00000002</td>
		<td>&#26381;&#21153;&#22120;&#24517;&#39035;&#35201;&#27714;&#23458;&#25143;&#31471;&#25903;&#25345;SSL</td>
	</tr>
</table>
