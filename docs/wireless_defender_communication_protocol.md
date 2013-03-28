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
<table>
   <tr>
      <td>&#23383;&#27573;&#21517;</td>
      <td>&#20540;</td>
      <td>&#38271;&#24230;/&#23383;&#33410;</td>
      <td>&#22791;&#27880;</td>
   </tr>
   <tr>
      <td>magic</td>
      <td>0x1DFBDF1E</td>
      <td>4</td>
      <td>&#39764;&#25968;</td>
   </tr>
   <tr>
      <td></td>
   </tr>
</table>
