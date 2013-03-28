# wireless-defender通信协议

## 目录
* [1 协议简介](#introduction)
 - [1.1 通用规范](#common-specification)
 - [1.2 连接建立过程](#connection-sequence)
* [2 协议定义](#protocol-definition)
 - [2.1 请求连接数据包](#connection-request-packet)

<a name="introduction"></a>
## 1 协议简介
本协议规范了wireless-defender通信过程中的通信流程和数据包格式。

<a name="common-specification"></a>
### 1.1 通用规范
1. 本协议中的多字节位除了特别说明的以外，均采用**小端序**传输

<a name="connection-sequence"></a>
### 1.2 连接建立过程
client        ---->        server  
发送请求连接数据包，服务器进行验证

client        <----        server
发送连接响应数据包，拒绝连接或者完成连接建立


<a name="protocol-definition"></a>
## 2 协议定义

<a name="connection-request-packet"></a>
### 2.1 请求连接数据包
请求连接数据包是客户端和服务器建立TCP连接后，客户端发往服务器的第一个数据包。内容如下：

magic (4 bytes): 四字节无符号整形。连接数据包的魔数，这个字段的值必须为0x1DFBDF1E。

version (4 bytes): 四字节无符号整形。标识了客户端支持的协议版本号。目前这个值为0x00010000。

security_type (4 bytes): 四字节无符号整形，标识了客户端支持的加密方式。取值如下：

<table>
	<tr>
		<td>security_type</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>SEC_TYPE_STANDARD</td>
		<td>0x00000001</td>
		<td>&#19981;&#21152;&#23494;&#25968;&#25454;&#20256;&#36755;</td>
	</tr>
</table>
