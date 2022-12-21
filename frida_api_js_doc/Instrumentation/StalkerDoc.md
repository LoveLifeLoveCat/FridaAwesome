#### Stalker原理与使用


>作为一个特色功能 frida有一个专门的页面介绍stalker的使用
https://frida.re/docs/stalker/ 在该页面有更详细的使用和原理讲解


##### Introduction(介绍)


Stalker是Frida的代码追踪引擎。它允许线程被跟踪，捕捉每一个函数、每一个块，甚至每一条被执行的指令。这里提供了Stalker引擎的一个非常好的概述，我们建议你先仔细阅读。

很明显，该实现在某种程度上是特定的架构，尽管它们之间有很多共同点。Stalker目前支持运行Android或iOS的手机和平板电脑上常见的AArch64架构，以及台式机和笔记本电脑上常见的Intel 64和IA-32架构。本页旨在将事情推向更高的层次，它剖析了Stalker的ARM64实现，并更详细地解释了它的具体工作方式。希望这能帮助未来将Stalker移植到其他硬件架构上的努力。

>这里很关键的是Stalker对ARM64的支持很好，ARM32基本不考虑。原理上也是以arm64为讲解。

#### Disclaimer(免责声明)

虽然这篇文章将涵盖Stalker内部运作的许多细节，但它不会真正详细地介绍反向补丁。它的目的是作为一个起点，帮助其他人了解这项技术，而Stalker已经够复杂了，不需要再介绍了 但公平地说，这种复杂性不是没有原因的，它的存在是为了尽量减少固有的昂贵操作的开销。最后，虽然本文将涵盖实现的关键概念，并将提取实现的一些关键部分进行逐行分析，但还有一些实现的最后细节留给读者通过阅读源代码来发现。然而，我们希望这将被证明是一个非常有用的开端。


#### Use Cases(使用案例)

要开始理解Stalker的实现，我们必须首先详细了解它为用户提供了什么。虽然Stalker可以通过其本地Gum接口直接调用，但大多数用户会通过JavaScript API调用它，而JavaScript API会代表他们调用这些Gum方法。Gum的TypeScript类型定义有很好的注释，并提供了更多细节。

js stalker 核心的方法:

`Stalker.follow([threadId, options])` 开始跟踪threadId（如果省略，则为当前线程）。


让我们考虑一下何时可以使用这些调用。

##### 追踪指定线程

当你有一个感兴趣的线程并想知道它在做什么的时候，你提供线程ID的跟踪可能会被使用。

也许它有一个有趣的名字？

线程名称可以通过 `cat /proc/PID/tasks/TID/comm`找到。

或者你用Frida JavaScript API `Process.enumerateThreads()` 走了进程中的线程，然后用`NativeFunction`来调用下面这个方法来获取线程的名字:

```
int pthread_getname_np(pthread_t thread,char *name, size_t len);
```

将此与Thread.backtrace()一起用于转储线程堆栈，可以让你很好地了解一个进程正在做什么。

>上面的情况是追踪一个线程的调用，配合 Thread.backtrace() 输出


##### 追踪某个函数

你可能调用Stalker.follow()的另一种情况是，可能来自一个被拦截或替换的函数。在这种情况下，你发现了一个感兴趣的函数，你想了解它的行为方式，你想看看线程在调用一个给定的函数后会采取哪些函数，甚至是代码块。也许你想比较代码在不同的输入下所采取的方向，或者你想修改输入，看看你是否能让代码采取一个特定的路径。

### Following(线程跟踪)

当用户调用Stalker.follow()时，在后台，JavaScript引擎通过调用gum_stalker_follow_me()来跟踪当前线程，或者通过gum_stalker_follow(thread_id)来跟踪进程中的另一个线程。

#### gum_stalker_follow_me

在gum_stalker_follow_me()的情况下，链接寄存器被用来决定在哪个指令上开始跟踪。在AArch64架构中，链接寄存器（LR）被设置为从函数调用返回后继续执行的指令的地址，它被BL和BLR等指令设置为下一条指令的地址。由于只有一个链接寄存器，如果被调用的函数要调用另一个例程，那么LR的值必须被储存起来（通常是在堆栈中）。这个值随后将被从堆栈中加载到一个寄存器中，RET指令用于将控制权返回给调用者。

让我们看一下gum_stalker_follow_me()的代码。这是该函数的原型。

```
GUM_API void gum_stalker_follow_me (GumStalker * self,GumStalkerTransformer * transformer, GumEventSink * sink);
```

因此，我们可以看到该函数被QuickJS或V8运行时调用，并传递3个参数。
第一个是Stalker实例本身。注意，如果同时加载多个脚本，可能有多个这样的参数。
第二个是转化器，这可用于转化正在编写的工具化代码（后面会有更多介绍）。
最后一个参数是事件汇，这是在Stalker引擎运行时生成的事件被传递的地方。

函数

```
#ifdef __APPLE__
  .globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
  .globl gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
#endif
  stp x29, x30, [sp, -16]!
  mov x29, sp
  mov x3, x30
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  ldp x29, x30, [sp], 16
  br x0
```

我们可以看到，第一条指令STP将一对寄存器存储到堆栈中。我们可以注意到表达式[sp, -16]！。这是一个预减法，意味着堆栈首先被提前16个字节，然后存储两个8字节的寄存器值。我们可以在函数的底部看到相应的指令ldp x29, x30, [sp], 16。这是将这两个寄存器的值从堆栈中恢复到寄存器中。但这两个寄存器是什么呢？

嗯，X30是链接寄存器，X29是帧指针寄存器。回顾一下，如果我们想调用另一个函数，我们必须将链接寄存器存储到堆栈中，因为这将导致它被覆盖，我们需要这个值，以便我们能够返回到我们的调用者。

帧指针用来指向函数被调用时的堆栈顶部，这样所有堆栈传递的参数和基于堆栈的局部变量就可以在帧指针的一个固定偏移处被访问。我们需要再次保存和恢复这个寄存器，因为每个函数都会有它的值，所以我们需要保存调用者放在那里的值，并在返回之前恢复它。事实上你可以看到在下一条指令mov x29, sp中，我们将帧指针设置为当前的堆栈指针。

我们可以看到下一条指令mov x3, x30, 将链接寄存器的值放入X3。AArch64的前8个参数是在寄存器X0-X7中传递的。所以这被放入用于第四个参数的寄存器中。然后我们调用（带链接的分支）函数_gum_stalker_do_follow_me()。所以我们可以看到，我们在X0-X2中传递了前三个参数，没有进行任何处理，所以_gum_stalker_do_follow_me()收到了与我们被调用时相同的值。最后，我们可以看到在这个函数返回后，我们将分支到我们收到的地址作为其返回值。(在AArch64中，一个函数的返回值在X0中返回）。


后续调用函数

```
gpointer
_gum_stalker_do_follow_me (GumStalker * self,GumStalkerTransformer * transformer,GumEventSink * sink,gpointer ret_addr)
```

#### gum_stalker_follow

这个例程的原型与gum_stalker_follow_me()非常相似，但有一个额外的thread_id参数。事实上，如果要求跟踪当前线程，那么它将调用该函数。让我们看一下指定另一个线程ID的情况。

```
void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}
```

我们可以看到，这调用了函数`gum_process_modify_thread()`。
这并不是Stalker的一部分，而是Gum本身的一部分。
这个函数需要一个带有上下文参数的回调，以调用传递线程上下文结构。
这个回调可以修改GumCpuContext结构，然后gum_process_modify_thread()会把修改写回去。
我们可以看到下面的上下文结构，你可以看到它包含了AArch64 CPU中所有寄存器的字段。我们还可以看到下面是我们回调的函数原型。

```
typedef GumArm64CpuContext GumCpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};
```
```
static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
```

那么，gum_process_modify_thread()是如何工作的？嗯，这取决于不同的平台。在Linux（和Android）上，它使用 ptrace API（与GDB使用的相同）来附加到线程并读写寄存器。但是这里面有很多复杂的问题。在Linux上，你不能跟踪你自己的进程（或同一进程组中的任何进程），所以Frida在它自己的进程组中创建了一个当前进程的克隆，并共享相同的内存空间。它使用UNIX套接字与之进行通信。这个克隆的进程作为一个调试器，读取原始目标进程的寄存器并将其存储在共享的内存空间中，然后根据需要将其写回进程。哦，还有PR_SET_DUMPABLE和PR_SET_PTRACER，它们控制着允许谁跟踪我们的原始进程的权限。

现在你会看到，gum_stalker_infect()的功能实际上与我们前面提到的_gum_stalker_do_follow_me()非常相似。两个函数执行的工作基本相同，尽管_gum_stalker_do_follow_me()在目标线程上运行，但gum_stalker_infect()不是，所以它必须编写一些代码，由目标线程使用GumArm64Writer调用，而不是直接调用函数。

我们将在短期内更详细地介绍这些函数，但首先我们需要了解更多的背景。

### Basic Operation(基本操作)

代码可以被认为是一系列的指令块（也被称为基本块）。每个块以一系列可选的指令开始（我们可能有两个连续的分支语句），这些指令依次运行，当我们遇到一条指令，导致（或可以导致）执行继续进行，而不是紧随其后的内存中的指令时，就会结束。

潜行者一次只对一个块工作。它从调用gum_stalker_follow_me()的返回后的块开始，或者从调用gum_stalker_follow()时目标线程的指令指针所指向的代码块开始。

Stalker的工作方式是分配一些内存，并向其写入原始代码块的一个新的工具化副本。可以添加指令来生成事件，或执行Stalker引擎提供的任何其他功能。Stalker也必须在必要时重新定位指令。考虑一下下面的指令。

```
ADR 在与PC相关的偏移处的标签地址。

ADR Xd, label

Xd是通用目的寄存器的64位名称，范围是0到31。

label 是要计算其地址的程序标签。它是本指令地址的偏移量，范围是±1MB。
```

如果这条指令被复制到内存中的不同位置并被执行，那么由于标签的地址是通过在当前指令指针上增加一个偏移量来计算的，那么这个值将是不同的。幸运的是，Gum有一个Relocator就是为了这个目的，它能够修改给定新位置的指令，以便计算出正确的地址。

现在，记得我们说过，Stalker一次只工作一个块。那么，我们如何对下一个块进行编程？我们还记得，每个块也是以一个分支指令结束的，如果我们修改这个分支，使其返回到Stalker引擎，但确保我们存储了分支打算结束的目的地，我们就可以对下一个块进行编程，并将执行重新导向那里。这个简单的过程可以在一个又一个的区块中继续。

现在，这个过程可能有点慢，所以我们可以应用一些优化措施。首先，如果我们不止一次地执行同一个代码块（例如一个循环，或者只是一个多次调用的函数），我们就不必再重新编制它。我们只需重新执行相同的工具化代码即可。出于这个原因，我们会保留一个哈希表，记录所有我们以前遇到过的区块，以及我们将该区块的仪器化副本放在哪里。

其次，当遇到一个调用指令时，在发出仪器化的调用后，我们再发出一个着陆点，我们可以返回到这个着陆点，而不需要重新进入Stalker。Stalker建立了一个侧堆栈，使用GumExecFrame结构，记录真正的返回地址（real_address）和这个着陆点（code_address）。当一个函数返回时，我们发出的代码将检查侧堆栈中的返回地址和real_address，如果匹配，它可以简单地返回到code_address，而不必重新进入运行时。这个着陆点最初将包含进入Stalker引擎对下一个块进行检测的代码，但它后来可以被回调，直接分支到这个块。这意味着整个返回序列可以被处理，而不需要进入和离开Stalker。

如果返回地址与存储在GumExecFrame的real_address不匹配，或者我们在侧堆栈中用完了空间，我们只需从头开始重新建立一个新的。我们需要在应用程序代码执行时保留LR的值，以便应用程序不能使用它来检测Stalker的存在（反调试），或者在它除了简单地返回外还用于其他目的时（例如，在代码部分引用内联数据）。另外，我们希望Stalker能够在任何时候取消跟踪，所以我们不希望不得不回到我们的堆栈中去纠正我们沿途修改过的LR值。

最后，虽然我们总是用调用Stalker来检测下一个块来代替分支，但根据Stalker.trustThreshold的配置，我们可以回补这样的检测代码，用一个直接的分支代替对下一个检测块的调用。确定性分支（例如，目的地是固定的，分支没有条件）很简单，我们可以用一个到下一个块的分支来代替到Stalker的分支。但我们也可以处理有条件的分支，如果我们把两个代码块（如果分支被采纳的那块和没有被采纳的那块）做成仪器。那么我们就可以用一个条件分支来代替原来的条件分支，将控制流引向分支发生时遇到的那个代码块的工具化版本，然后用一个无条件分支引向另一个工具化的代码块。我们还可以部分地处理目标不是静态的分支。假设我们的分支是这样的

```
br x0
```

这种指令在调用一个函数指针或类方法时很常见。虽然X0的值可能会改变，但很多时候它实际上总是相同的。在这种情况下，我们可以用代码代替最后的分支指令，将X0的值与我们已知的函数进行比较，如果匹配，则分支到代码的工具化副本的地址。然后，如果不匹配，可以无条件地返回到Stalker引擎。因此，如果函数指针的值改变了，那么代码仍将工作，我们将重新进入Stalker，并对我们最后的地方进行检测。然而，如果正如我们所期望的那样，它保持不变，那么我们可以完全绕过Stalker引擎，直接进入被检测的函数。


### Options(选择)

现在让我们来看看当我们用Stalker跟踪一个线程时有哪些选项。当被跟踪的线程被执行时，Stalker会产生事件，这些事件被放在队列中，并定期或由用户手动刷新。这不是由Stalker本身完成的，而是由`EventSink::process` vfunc完成的，因为重新进入JavaScript运行时一次处理事件的成本太高了。大小和时间段可以通过选项进行配置。事件可以在每个指令的基础上生成，无论是调用、返回还是所有指令。或者它们可以在块的基础上产生，要么在块被执行时，要么在它被Stalker引擎检测时。

我们还可以提供两个回调`onReceive`或`onCallSummary`中的一个。前者将非常简单地提供一个二进制的blob，包含由Stalker产生的原始事件，并按事件产生的顺序排列。(`Stalker.parse()`可以用来把它变成代表事件的JS数组。)。第二部分汇总这些结果，简单地返回每个函数被调用的次数。这比`onReceive`更有效，但数据的粒度要小得多。

### Terminology(术语)

