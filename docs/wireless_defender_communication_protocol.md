# wireless-defender通信协议

## 目录
* [1 协议简介](#introduction)
 - [1.1 通用规范](#common-specification)
 - [1.2 连接建立过程简介](#connection-sequence-introduction)
 - [1.3 客户端认证过程简介](#client-authenticate-introduction)
* [2 连接建立过程](#connection-sequence)
 - [2.1 连接请求数据包](#connection-request-packet)
 - [2.2 连接响应数据包](#connection-response-packet)
 - [2.3 连接失败数据包](#connection-failure-packet)
* [3 客户端认证过程](#client-authenticate)
 - [3.1 认证请求数据包](#authenticate-request-packet)
 - [3.2 认证响应数据包](#authenticate-response-packet)
 - [3.3 认证失败数据包](#authenticate-failure-packet)

<a name="introduction"></a>
## 1 协议简介
本协议规范了wireless-defender通信过程中的通信流程和数据包格式。

<a name="common-specification"></a>
### 1.1 通用规范
1. 本协议中的多字节位除了特别说明的以外，均采用 **小端序** 传输
2. 本协议中客户端与服务器通信采用TCP协议，服务器监听的端口号为9387

<a name="connection-sequence-introduction"></a>
### 1.2 连接建立过程简介
client        ---->        server  
发送[连接请求数据包](#connection-request-packet)，服务器进行验证

client        <----        server  
如果连接成功，发送[连接响应数据包](#connection-response-packet)，完成连接建立  
如果连接失败，发送[连接失败数据包](#connection-failure-packet)，然后断开TCP连接

详细的连接建立通信格式参见[连接建立过程](#connection-sequence)。

<a name="client-authenticate-introduction"></a>
### 1.3 客户端认证过程简介
client        ---->        server  
发送[认证请求数据包](#authenticate-request-packet)，服务器进行认证

client        <----        server  
如果认证成功，发送[认证响应数据包](#authenticate-response-packet)，完成认证  
如果认证失败，发送[认证失败数据包](#authenticate-failure-packet)，然后断开TCP连接

详细的客户端认证通信格式参见[客户端认证过程](#client-authenticate)。


<a name="connection-sequence"></a>
## 2 连接建立过程

<a name="connection-request-packet"></a>
### 2.1 连接请求数据包
连接请求数据包是客户端和服务器建立TCP连接后，客户端发往服务器的第一个数据包。内容如下：

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
		<td>FAILED_SSL_REQUIRED</td>
		<td>0x00000002</td>
		<td>&#26381;&#21153;&#22120;&#24517;&#39035;&#35201;&#27714;&#23458;&#25143;&#31471;&#25903;&#25345;SSL</td>
	</tr>
</table>


<a name="client-authenticate"></a>
## 3 客户端认证过程

<a name="authenticate-request-packet"></a>
### 3.1 认证请求数据包
认证请求数据包是服务器用于认证客户端合法性的数据包，这个数据包是连接建立之后客户端发送的第一个数据包。包含了管理服务器的用户名与加密后的密码。数据包内容如下：

type (1 byte): 一字节无符号整形。认证请求数据包的类型，这个字段的值必须为0x01(AUTH_REQ_PKT)。

username_len (1 byte): 一字节无符号整形。username字段的长度，包括结尾的'\0'字符。

username (variable): 用户名字段，使用ASCII码表示，以'\0'字符结尾。

password (32 bytes): 32字节的密码字段，密码使用MD5加密，使用ASCII码小写字母表示。

<a name="authenticate-response-packet"></a>
### 3.2 认证响应数据包
认证响应数据包是服务器收到客户端发出的[认证请求数据包](#authenticate-request-packet)后，服务器判断客户端账户合法，然后发送给客户端的数据包。数据包内容如下：

type (1 byte): 一字节无符号整形。认证响应数据包的类型，这个字段的值必须为0x02(AUTH_RSP_PKT)。

<a name="authenticate-failure-packet"></a>
### 3.3 认证失败数据包
认证失败数据包是服务器收到客户端发出的[认证请求数据包](#authenticate-request-packet)后，服务器判断客户端账户不合法，然后发送给客户端的数据包。服务器发送完本数据包后，应该关闭TCP认证的读和写。客户端收到本数据包后，应该关闭TCP认证的读和写。数据包内容如下：

type (1 byte): 一字节无符号整形。认证响应数据包的类型，这个字段的值必须为0x03(AUTH_FAIL_PKT)。
