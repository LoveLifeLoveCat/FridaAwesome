### Interceptor

Interceptor:native注入拦截hook

#### 1.`Interceptor.attach(target, callbacks[, data])`

核心方法，用于注入函数进行回调

传入两个参数:

参数 target: 标记 用于找到注入点 使用地址找到注入函数。这是一个`NativePointer`用于指定要截获调用的函数的地址。

请注意，在 32 位 ARM 上，对于 ARM 函数，此地址的最低有效位必须设置为 0，对于 `Thumb` 函数必须将其最低有效位设置为 1。(即加1)

如果您从 `Frida API` 获取地址（例如 Module.getExportByName（）），Frida 会为您处理此详细信息。

也就是说如果直接使用地址需要处理thumb的+1情况，如果使用模块查找函数名称则不需要。


参数 callbacks: 回调


回调接口的几个回调函数:

onEnter(args):

进入函数，args为参数数组可以按照 `NativePointer` 对象数组读取出来。

onLeave(retval):

离开函数,回调函数给定一个参数 retval，该参数是包含原始返回值的 NativePointer 派生对象。

同样的你可以调用类似 

`retval.replace(1337)`的方式来替换返回结果为int 1337
`retval.replace(ptr("0x1234"))`的方式替换为一个指针 0x1234

>请注意，此对象在 onLeave 调用中回收，因此不要在回调之外存储和使用它。如果需要存储包含的值，请创建深层副本，例如：ptr(retval.toString())。


//额外的说明补充





基本写法:

```
Interceptor.attach(Module.getExportByName('libc.so', 'read'), {
  onEnter(args) {
    this.fileDescriptor = args[0].toInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() > 0) {
      /* do something with this.fileDescriptor */
    }
  }
});
```

此外，该对象(this对象)还包含一些有用的属性:

- returnAddress: 当成NativePointer返回当前地址
- context: 带有键 pc 和 sp 的对象，它们是分别为 ia32/x64/arm 指定 EIP/RIP/PC 和 ESP/RSP/SP 的 NativePointer 对象。其他特定于处理器的键也可用，例如 eax、rax、r0、x0 等。您还可以通过分配给这些键来更新寄存器值。
- errno: (UNIX) 当前 errno 值 可以替换
- lastError: (Windows) 当前 errno 值 可以替换
- threadId: 系统线程ID
- depth: 相对于其他调用的调用深度

```
Interceptor.attach(Module.getExportByName(null, 'read'), {
  onEnter(args) {
    console.log('Context information:');
    console.log('Context  : ' + JSON.stringify(this.context));
    console.log('Return   : ' + this.returnAddress);
    console.log('ThreadId : ' + this.threadId);
    console.log('Depth    : ' + this.depth);
    console.log('Errornr  : ' + this.err);

    // Save arguments for processing in onLeave.
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.count = args[2].toInt32();
  },
  onLeave(result) {
    console.log('----------')
    // Show argument 1 (buf), saved during onEnter.
    const numBytes = result.toInt32();
    if (numBytes > 0) {
      console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
    }
    console.log('Result   : ' + numBytes);
  }
})
```

> 提示

>提供的回调对性能有重大影响。如果你只需要检查参数而不关心返回值，或者相反，请确保省略不需要的回调;即避免将您的逻辑放在 onEnter 中并将 onLeave 留在那里作为空回调。

>在iPhone 5S上，仅提供onEnter时的基本开销可能是6微秒，而同时提供onEnter和onLeave时为11微秒。

>还要小心拦截对称为每秒无数次的函数的调用;虽然 send()是异步的，但发送单个消息的总开销并未针对高频进行优化，因此这意味着 Frida 允许您根据是否需要低延迟或高吞吐量将多个值批处理到单个 send() 调用中。
但是，在挂接热函数时，您可以将拦截器与 CModule 结合使用来实现 C 语言中的回调。


#### 2.Interceptor.detachAll()