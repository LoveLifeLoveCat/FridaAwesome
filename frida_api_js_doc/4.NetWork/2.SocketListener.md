#### SocketListener

所有方法都是完全异步的，并返回Promise对象。

- path: 被监听的路径
- port: 被监听的IP端口
- close(): 关闭监听器，释放与之相关的资源。一旦监听器被关闭，所有其他操作都将失败。多次关闭监听器是允许的，不会导致错误。
- accept(): 等待下一个客户端的连接。返回的Promise接收一个SocketConnection。