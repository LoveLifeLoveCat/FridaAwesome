#### SocketConnection

继承自IOStream。所有方法都是完全异步的，并返回Promise对象。

- setNoDelay(noDelay): 如果noDelay为真，就禁用Nagle算法，否则就启用它。Nagle算法默认是启用的，所以只有在你希望优化低延迟而不是高吞吐量时才有必要调用这个方法。