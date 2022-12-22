### Socket.listen([options])
打开一个TCP或UNIX监听套接字。返回一个接收SocketListener的Promise。
如果支持的话，默认为同时监听IPv4和IPv6，并在所有接口上随机选择一个TCP端口进行绑定。
可选的选项参数是一个对象，可能包含以下一些键。
- family: 作为一个字符串的地址族。支持的值是: 1.unix 2.ipv4 3.ipv6 如果支持的话，默认为同时监听ipv4和ipv6。
- host: (IP族) IP地址是一个字符串。默认为所有接口。
- port: (IP族) IP端口为数字。默认为任何可用的。
type: (UNIX系列) UNIX套接字类型，作为一个字符串。支持的类型有:
1.anonymous 2.path 3.abstract 4.abstract-padded Defaults to path.
- path: (UNIX系列)UNIX套接字路径，作为一个字符串。
- backlog: 听取 backlog 的数字。默认为10。
### Socket.connect(options)
连接到一个TCP或UNIX服务器。返回一个接收SocketConnection的Promise。
选项参数是一个对象，应该包含以下一些键值:
- family：作为字符串的地址族。支持的值是。 1 unix 2 ipv4 3 ipv6 根据指定的主机，默认为一个IP族。
- host: (IP族) IP地址，作为一个字符串。默认为localhost。
- port: (IP族) IP端口，作为数字。
- type: (UNIX族) UNIX套接字类型，作为一个字符串。支持的类型有。1.anonymous 2.path 3.abstract 4.abstract-padded 默认为path。
- path：（UNIX系列）UNIX套接字路径，作为一个字符串。

### Socket.type(handle)
检查操作系统的套接字句，并将其类型作为一个字符串返回，这个字符串要么是
tcp, udp, tcp6, udp6, unix:stream, unix:dgram, 或者 如果无效或未知，则为null。 

### Socket.localAddress(handle),Socket.peerAddress(handle)
检查操作系统的套接字句柄，并返回其本地或对等地址，如果无效或未知，则为null。
返回的对象有几个字段:
- ip: (IP sockets) IP地址，作为一个字符串。
- port: (IP sockets) IP端口，作为一个数字。
- path: (UNIX套接字) UNIX路径，作为一个字符串。

