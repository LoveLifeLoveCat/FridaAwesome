### 前言

在 https://frida.re/docs/examples/android/ 中引入了 frida 的python

接口，但是没有详细的地方解析python这些接口的使用与作用。

在github 有仓库 https://github.com/frida/frida-python 提供了相关的源码和使用案例

可以作为重要的参考资料

### frida python

首先明确 frida是一款基于python + javascript 的hook框架。
js代码需要打入到目标程序中。
所以python在这里负责处理脚本注入之外的事情，比如

- 读取js代码到内存再传递
- 链接手机应用启动应用
- 获取返回的数据结果
- 进行方法调用和RPC

>值得注意的是，我们可以完全脱离python进行注入，也就是我们常用的CLI模式，直接在
命令行输入注入代码。如果你使用python，那python就承接了cli的这部分功能。

使用案例:

```python
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(() => {
  // Function to hook is defined here
  const MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');

  // Whenever button is clicked
  const onClick = MainActivity.onClick;
  onClick.implementation = function (v) {
    // Show a message to know that the function got called
    send('onClick');

    // Call the original onClick handler
    onClick.call(this, v);

    // Set our values after running the original onClick handler
    this.m.value = 0;
    this.n.value = 1;
    this.cnt.value = 999;

    // Log to the console that it's done, and we should have the flag!
    console.log('Done:' + JSON.stringify(this.cnt));
  };
});
"""

process = frida.get_usb_device().attach('com.example.seccon2015.rock_paper_scissors')
script = process.create_script(jscode)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
```


### frida python api

下面三个查找设备的方法 使用 frida-ls-devices 可以查询当前链接的设备和类型

```commandline
>frida-ls-devices
Id                  Type    Name
------------------  ------  ------------
local               local   Local System
192.168.20.21:5555  usb     M1852
socket              remote  Local Socket
```

#### 1.frida.get_local_device() 

获取local设备 一般就是当前系统

#### 2.frida.get_remote_device() 

获取远程设备 

#### 3.frida.get_usb_device() 

获取usb设备

#### 4.frida.get_device() 

使用设备id获取设备，一般我们要用其他方法获取设备id

比如cmd 输入adb devices/frida-ls-devices

同样的frida提供了方法查询 `frida.enumerate_devices()`返回一个设备数组

```commandline
[Device(id="local", name="Local System", type='local'), Device(id="socket", name="Local Socket", type='remote'), Device(id="192.168.20.21:5555", name="M1852", type='usb')]
```

下面是启动模式的封装

#### frida.attach()

附加模式 直接注入当前进程

#### frida.spawn()

Frida会自行启动并注入进目标App 时机很早

#### frida.resume()

重新注入脚本

#### frida.kill() 

结束进程

杀死


frida.inject_library_file()

frida.inject_library_blob()
