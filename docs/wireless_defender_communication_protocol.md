# wireless-defender通信协议

## 目录
* [1 协议简介][协议简介]
 - [1.1 通用规范][通用规范]
 - [1.2 连接建立过程简介][连接建立过程简介]
 - [1.3 客户端认证过程简介][客户端认证过程简介]
 - [1.4 数据请求过程简介][数据请求过程简介]
* [2 连接建立过程][连接建立过程]
 - [2.1 连接请求数据包][连接请求数据包]
 - [2.2 连接响应数据包][连接响应数据包]
 - [2.3 连接失败数据包][连接失败数据包]
* [3 客户端认证过程][客户端认证过程]
 - [3.1 认证请求数据包][认证请求数据包]
 - [3.2 认证响应数据包][认证响应数据包]
 - [3.3 认证失败数据包][认证失败数据包]
* [4 数据请求过程][数据请求过程]
 - [4.1 数据请求头部][数据请求头部]
 - [4.2 数据响应头部][数据响应头部]
 - [4.3 设备基本信息数据包][设备基本信息数据包]
 - [4.4 AP列表数据包][AP列表数据包]
     + [4.4.1][AP结构定义][AP结构定义]

[协议简介]: #introduction  "协议简介"
[通用规范]: #common-specification  "通用规范"
[连接建立过程简介]: #connection-sequence-introduction  "连接建立过程简介"
[客户端认证过程简介]: #client-authenticate-introduction  "客户端认证过程简介"
[数据请求过程简介]: #data-request-introduction  "数据请求过程简介"

[连接建立过程]: #connection-sequence  "连接建立过程"
[连接请求数据包]: #connection-request-packet  "连接请求数据包"
[连接响应数据包]: #connection-response-packet  "连接响应数据包"
[连接失败数据包]: #connection-failure-packet  "连接失败数据包"

[客户端认证过程]: #client-authenticate  "客户端认证过程"
[认证请求数据包]: #authenticate-request-packet  "认证请求数据包"
[认证响应数据包]: #authenticate-response-packet  "认证响应数据包"
[认证失败数据包]: #authenticate-failure-packet  "认证失败数据包"

[数据请求过程]: #data-request  "数据请求过程"
[数据请求头部]: #data-request-packet-header  "数据请求头部"
[数据响应头部]: #data-response-packet-header "数据响应头部"
[设备基本信息数据包]: #basic-info-packet "设备基本信息数据包"
[AP列表数据包]: #ap-list-packet "AP列表数据包"
[AP结构定义]: #ap-structure-def "AP结构定义"


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
发送[连接请求数据包][]，服务器进行验证

client        <----        server  
如果连接成功，发送[连接响应数据包][]，完成连接建立  
如果连接失败，发送[连接失败数据包][]，然后断开TCP连接

详细的连接建立通信格式参见[连接建立过程][]。

<a name="client-authenticate-introduction"></a>
### 1.3 客户端认证过程简介
client        ---->        server  
发送[认证请求数据包][]，服务器进行认证

client        <----        server  
如果认证成功，发送[认证响应数据包][]，完成认证  
如果认证失败，发送[认证失败数据包][]，然后断开TCP连接

详细的客户端认证通信格式参见[客户端认证过程][]。

<a name="data-request-introduction"></a>
### 1.4 数据请求过程简介
client        ---->        server  
发送含有[数据请求头部][]的数据包，向服务器请求数据

client        <----        server  
如果请求成功，发送含有[数据响应头部](#data-response-packet-header)的数据包，返回数据  
如果请求失败，发送[数据请求失败数据包](#data-failure-packet)，然后继续监听后续请求

详细的数据请求通信格式参见[数据请求过程][]。

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
连接响应数据包是服务器收到客户端发出的[连接请求数据包][]后，服务器判断可以与客户端连接，然后发送给客户端的数据包。数据包内容如下：

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
连接失败数据包是服务器收到客户端发出的[连接请求数据包][]后，服务器判断不能与客户端连接，然后发送给客户端的数据包。服务器发送完本数据包后，应该关闭TCP连接的读和写。客户端收到本数据包后，应该关闭TCP连接的读和写。数据包内容如下：

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
认证响应数据包是服务器收到客户端发出的[认证请求数据包][]后，服务器判断客户端账户合法，然后发送给客户端的数据包。数据包内容如下：

type (1 byte): 一字节无符号整形。认证响应数据包的类型，这个字段的值必须为0x02(AUTH_RSP_PKT)。

<a name="authenticate-failure-packet"></a>
### 3.3 认证失败数据包
认证失败数据包是服务器收到客户端发出的[认证请求数据包][]后，服务器判断客户端账户不合法，然后发送给客户端的数据包。服务器发送完本数据包后，应该关闭TCP认证的读和写。客户端收到本数据包后，应该关闭TCP认证的读和写。数据包内容如下：

type (1 byte): 一字节无符号整形。认证失败数据包的类型，这个字段的值必须为0x03(AUTH_FAIL_PKT)。

failure_code (4 bytes): 四字节无符号整形，认证失败的错误码，取值如下：

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
		<td>FAILED_AUTH_CHECK</td>
		<td>0x00000002</td>
		<td>&#36523;&#20221;&#39564;&#35777;&#38169;&#35823;</td>
	</tr>
</table>


<a name="data-request"></a>
## 4 数据请求过程

<a name="data-request-packet-header"></a>
### 4.1 数据请求头部
数据请求数据包是通信过程中，经过[连接建立过程][]与[客户端认证过程][]后，客户端向设备请求与设备、无线网络相关的数据时发送的数据包。

数据请求头部是客户端发出的所有数据请求数据包的公共头部，标识了数据请求数据包的类型。

type (1 byte): 一字节无符号整形。数据请求数据包的类型，这个字段的值必须为0x01(DATA_REQ_PKT)。

request_type (1 byte): 一字节无符号整形。请求的数据类型，取值如下：

<table>
	<tr>
		<td>request_type</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>REQ_TYPE_BASIC_INFO</td>
		<td>0x00</td>
		<td>&#33719;&#21462;&#24403;&#21069;&#35774;&#22791;&#22522;&#26412;&#20449;&#24687;</td>
	</tr>
	<tr>
		<td>REQ_TYPE_AP_LIST</td>
		<td>0x01</td>
		<td>&#33719;&#21462;&#24403;&#21069;&#35774;&#22791;&#26816;&#27979;&#21040;&#30340;AP&#21015;&#34920;</td>
	</tr>
</table>

<a name="data-response-packet-header"></a>
### 4.2 数据响应头部
数据响应头部是服务器在收到包含[数据请求头部][]的数据请求数据包后，发出的数据响应数据包的头部。头部内容如下：

type (1 byte): 一字节无符号整形。数据响应数据包的类型，这个字段的值必须为0x02(DATA_RSP_PKT)。

request_type (1 byte): 一字节无符号整形。客户端请求的数据类型，取值见[4.1 数据请求头部][数据请求头部]节中的request_type表格。

<a name="basic-info-packet"></a>
### 4.3  设备基本信息数据包
设备基本信息数据包是服务器在收到客户端的请求类型为REQ_TYPE_BASIC_INFO的数据请求数据包后，向客户端返回设备基本信息的数据包。数据包内容如下：

run_time (8 bytes): 8字节无符号整形，从设备启动到当前时刻经过的秒数。

<a name="ap-list-packet"></a>
### 4.4 AP列表数据包
AP列表数据包是服务器在收到客户端的请求类型为REQ_TYPE_AP_LIST的数据请求数据包后，向客户端返回设备监测到的当前区域内的AP的列表的数据包。数据包内容如下：

n_ap (1 byte): 1字节无符号整形，AP列表中AP结构的个数。

ap_list (variable): 一个变长的AP结构体列表。AP结构体的个数在 *n_ap* 字段中给出。AP结构体的内容参见[AP结构定义][]。

<a name="ap-structure-def"></a>
#### 4.4.1 AP结构定义
ssid_len (1 byte): 1字节无符号整形，AP的SSID的字符串长度。

ssid (variable): 变长的SSID字段，长度由ssid_len说明。无线网络的SSID。

encrypt_type (1 byte): AP的加密方式。取值如下：

<table>
	<tr>
		<td>encrypt_type</td>
		<td>&#20540;</td>
		<td>&#21547;&#20041;</td>
	</tr>
	<tr>
		<td>ENC_TYPE_NONE</td>
		<td>0x00</td>
		<td>&#26410;&#21152;&#23494;</td>
	</tr>
	<tr>
		<td>ENC_TYPE_WEP</td>
		<td>0x01</td>
		<td>&#37319;&#29992;WEP&#21152;&#23494;</td>
	</tr>
	<tr>
		<td>ENC_TYPE_WPA</td>
		<td>0x02</td>
		<td>&#37319;&#29992;WPA&#21152;&#23494;</td>
	</tr>
</table>
