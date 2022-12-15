
### 功能介绍

Stalker是Frida的代码追踪引擎。它允许跟踪线程，捕获每个函数，每个块，甚至执行的每个指令

### API文档说明

#### 1.Stalker.exclude(range) 屏蔽区块函数

使用range标记一个范围作为排除，参数 range  对象包括 base(基址)和size(偏移大小) 类似于 Process.getModuleByName() 返回的对象.


这意味着 Stalker 将不会跟踪执行这个范围内的指令调用. 您将因此可以观察或者修改传入的参数以及返回的结果, 但不会看到指令之间发生了什么.

这对提升性能以及降噪很有用.


#### 2.*Stalker.follow([threadId, options]) 追踪线程函数


开始跟踪 threadId（如果省略，则为当前线程），可以选择启用事件的选项。

示例:

```
const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
  events: {
    call: true, // CALL instructions: yes please

    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },

  //
  // Only specify one of the two following callbacks.
  // (See note below.)
  //

  //
  // onReceive: Called with `events` containing a binary blob
  //            comprised of one or more GumEvent structs.
  //            See `gumevent.h` for details about the
  //            format. Use `Stalker.parse()` to examine the
  //            data.
  //
  //onReceive(events) {
  //},
  //

  //
  // onCallSummary: Called with `summary` being a key-value
  //                mapping of call target to number of
  //                calls, in the current time window. You
  //                would typically implement this instead of
  //                `onReceive()` for efficiency, i.e. when
  //                you only want to know which targets were
  //                called and how many times, but don't care
  //                about the order that the calls happened
  //                in.
  //
  onCallSummary(summary) {
  },

  //
  // Advanced users: This is how you can plug in your own
  //                 StalkerTransformer, where the provided
  //                 function is called synchronously
  //                 whenever Stalker wants to recompile
  //                 a basic block of the code that's about
  //                 to be executed by the stalked thread.
  //
  //transform(iterator) {
  //  let instruction = iterator.next();
  //
  //  const startAddress = instruction.address;
  //  const isAppCode = startAddress.compare(appStart) >= 0 &&
  //      startAddress.compare(appEnd) === -1;
  //
  //  do {
  //    if (isAppCode && instruction.mnemonic === 'ret') {
  //      iterator.putCmpRegI32('eax', 60);
  //      iterator.putJccShortLabel('jb', 'nope', 'no-hint');
  //
  //      iterator.putCmpRegI32('eax', 90);
  //      iterator.putJccShortLabel('ja', 'nope', 'no-hint');
  //
  //      iterator.putCallout(onMatch);
  //
  //      iterator.putLabel('nope');
  //    }
  //
  //    iterator.keep();
  //  } while ((instruction = iterator.next()) !== null);
  //},
  //
  // The default implementation is just:
  //
  //   while (iterator.next() !== null)
  //     iterator.keep();
  //
  // The example above shows how you can insert your own code
  // just before every `ret` instruction across any code
  // executed by the stalked thread inside the app's own
  // memory range. It inserts code that checks if the `eax`
  // register contains a value between 60 and 90, and inserts
  // a synchronous callout back into JavaScript whenever that
  // is the case. The callback receives a single argument
  // that gives it access to the CPU registers, and it is
  // also able to modify them.
  //
  // function onMatch (context) {
  //   console.log('Match! pc=' + context.pc +
  //       ' rax=' + context.rax.toInt32());
  // }
  //
  // Note that not calling keep() will result in the
  // instruction getting dropped, which makes it possible
  // for your transform to fully replace certain instructions
  // when this is desirable.
  //

  //
  // Want better performance? Write the callbacks in C:
  //
  // /*
  //  * const cm = new CModule(\`
  //  *
  //  * #include <gum/gumstalker.h>
  //  *
  //  * static void on_ret (GumCpuContext * cpu_context,
  //  *     gpointer user_data);
  //  *
  //  * void
  //  * transform (GumStalkerIterator * iterator,
  //  *            GumStalkerOutput * output,
  //  *            gpointer user_data)
  //  * {
  //  *   cs_insn * insn;
  //  *
  //  *   while (gum_stalker_iterator_next (iterator, &insn))
  //  *   {
  //  *     if (insn->id == X86_INS_RET)
  //  *     {
  //  *       gum_x86_writer_put_nop (output->writer.x86);
  //  *       gum_stalker_iterator_put_callout (iterator,
  //  *           on_ret, NULL, NULL);
  //  *     }
  //  *
  //  *     gum_stalker_iterator_keep (iterator);
  //  *   }
  //  * }
  //  *
  //  * static void
  //  * on_ret (GumCpuContext * cpu_context,
  //  *         gpointer user_data)
  //  * {
  //  *   printf ("on_ret!\n");
  //  * }
  //  *
  //  * void
  //  * process (const GumEvent * event,
  //  *          GumCpuContext * cpu_context,
  //  *          gpointer user_data)
  //  * {
  //  *   switch (event->type)
  //  *   {
  //  *     case GUM_CALL:
  //  *       break;
  //  *     case GUM_RET:
  //  *       break;
  //  *     case GUM_EXEC:
  //  *       break;
  //  *     case GUM_BLOCK:
  //  *       break;
  //  *     case GUM_COMPILE:
  //  *       break;
  //  *     default:
  //  *       break;
  //  *   }
  //  * }
  //  * `);
  //  */
  //
  //transform: cm.transform,
  //onEvent: cm.process,
  //data: ptr(1337) /* user_data */
  //
  // You may also use a hybrid approach and only write
  // some of the callouts in C.
  //
});
```
>性能注意事项

>回调对象对性能有显著的影响. 如果您只需要周期性的调用简介但不关心原始事件, 或者相反, 请确保您忽略您不需要的回调. 例如, 避免将您的逻辑放到 onCallSummary 并且让 onReceive 是一个空回调.
同样请注意可以将 Stalker 与 CModule 结合以使用在 C 中实现的回调.



#### 3.Stalker.unfollow([threadId]) 停止跟踪

停止跟踪线程 ID（如果省略，则停止跟踪当前线程）。



#### 4.Stalker.parse(events[, options])

解析 GumEvent 二进制 blob，可选择使用用于自定义输出的选项。

示例

```
onReceive(events) {
    console.log(Stalker.parse(events, {
      annotate: true, // to display the type of event
      stringify: true
        // to format pointer values as strings instead of `NativePointer`
        // values, i.e. less overhead if you're just going to `send()` the
        // thing not actually parse the data agent-side
    }));
  },
```

定义追踪事件输出的格式，这对于显示非常有用


#### 5.Stalker.flush() 清除缓冲事件

清除所有缓冲事件。当您不想等到下一个 Stalker.queueDrainInterval tick 时很有用。

#### 6.Stalker.garbageCollect() 释放内存

在 Stalker#unfollow 后的安全点释放累积的内存。这是为了避免竞争条件所必需的，其中刚刚取消关注的线程正在执行其最后的指令。

#### 7.Stalker.invalidate(address)


使给定基本块的当前线程的翻译代码失效。

在提供转换回调并希望针对给定的基本块动态调整检测时很有用。

这比取消关注和重新关注线程要有效得多，后者会丢弃所有缓存的翻译，并要求从头开始编译所有遇到的基本块。


#### 8.Stalker.invalidate(threadId, address)

和7一样的作用 多加了指定threadId指定其他线程

使给定基本块的特定线程的翻译代码失效。

示例:

```
const basicBlockStartAddress = ptr("0x400000");
Stalker.invalidate(basicBlockStartAddress);
Stalker.invalidate(Process.getCurrentThreadId(), basicBlockStartAddress);
```

可以看出 7/8 用于指定某些地方的翻译失效来过检测。比直接取消注入要消耗少得多。




#### 9.Stalker.addCallProbe(address, callback[, data])

当 address 处的方法被调用时触发 callback, callback 的签名与 `Interceptor#attach#onEnter` 相同. 返回一个稍后可以传递给 `Stalker#removeCallProbe` 的 id.

当然, 您也可以通过 CModule 在 C 语言中实现的 callback, 只需要指明一个 NativePointer 而不是一个方法. 它的签名是:

- void onCall (GumCallSite * site, gpointer user_data)

在这种情况下, 第三个可选参数 data 应当是一个 NativePointer, 它的值将作为 user_data 被传入回调中.



#### 10.Stalker.removeCallProbe(id)

移除一个通过 Stalker#addCallProbe 添加的调用检测器.

示例 

```
Stalker.removeCallProbe(probe.id);
```
#### 11.Stalker.trustThreshold

一个整型数字, 指明了一段代码需要被运行多少次才能被假定为可认为是不变的.
-1 意味着不信任 (慢), 0 意味着在调用时被信任, N 意味着它在执行 N 次以后才获得信任. 默认是 1.

#### 12.Stalker.queueCapacity

一个整形数字, 指明了事件队列中事件的容量. 默认是 16384 个事件.

#### 13.Stalker.queueDrainInterval

一个整型数字, 指明了每次事件队列发送事件之间的毫秒数. 默认 250 毫秒, 这意味着事件队列每秒发送 4 次事件. 您可以将这个值设为 0 来禁止周期性的发送事件, 取而代之的是当您想要获得事件时调用 Stalker.flush().


#### 14.Stalker.flush() 清空队列

当您希望排空队列时。