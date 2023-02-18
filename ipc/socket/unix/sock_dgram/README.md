# 客户端/服务器通信

客户端与服务端通信流程:
![image](https://github.com/kyrie-z/c-example/blob/master/ipc/socket/unix/sock_dgram/socket.png)



服务端创建socket /tmp/server_dgram.sock
每个客户端创建自己的管道 /tmp/client_pipe.pid

## 场景

解释器(客户端)运行脚本文件时，需要服务端验证脚本文件完整性。解释器将脚本文件和pid通过socket发送给服务端，服务端对脚本文件进行完整性校验后将结果通过解释器FIFO发送给解释器。由结果来决定是否允许运行。

**安全增强**
 1. 客户端在与服务端建立连接时协商密钥，通信间通过密钥加密消息。
 2. 客户端发送请求时添加随机数，服务端给客户端发送消息时附带随机数。客户端在收到结果时验证随机数是否一致。
