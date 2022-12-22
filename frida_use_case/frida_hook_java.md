### Frida启动

#### attach 附加模式启动 

直接注入 不会杀死进程 需要进程开启

直接附加到指定包名的应用中 `frida -U com.kevin.android -l hook.js`

直接附加到当前应用中 `frida -UF -l hook.js` 

**python code**

```python
import sys
import time
import frida

def on_message(message,data):
    print("message",message)
    print("data",data)

device = frida.get_usb_device()
session = device.attach("com.kevin.demo1")

with open("./demo1.js","r") as f:
    script = session.create_script(f.read())

script.on("message",on_message)
script.load()
sys.stdin.read()
```

#### spawn 孵化模式启动

杀死包名进程后 注入启动 `frida -U -f com.kevin.android -l demo1.js --no-pause`

**python code**

```python
import sys
import time
import frida

def on_message(message,data):
    print("message",message)
    print("data",data)

device = frida.get_usb_device()
pid = device.spawn(["com.kevin.demo1"])
device.resume(pid)
session = device.attach(pid)

with open("./rpc_demo.js",'r') as f:
    script = session.create_script(f.read())

script.on("message",on_message)
script.load()

sys.stdin.read()
```
### frida-server 自定义端口

#### frida server 

更改 frida server 默认端口: 27042 并开启远程连接

```commandline
adb shell
su -
cd /data/local/tmp

# 输入 wifiadb 对应的 ip 和自定义端口
./frida-server -l 192.168.0.1:6666

# 也可以使用默认端口启动
./frida-server -l 192.168.0.1
```


#### frida

frida 远程连接自定义端口 对接上改了端口的frida-service

```commandline
# 连接指定 6666 端口
frida -H 192.168.0.1:6666 com.demo1.app -l demo1.js

# 默认使用端口 27042
frida -H 192.168.0.1 -l demo1.js
```

**python code**

```python
# -*- coding: UTF-8 -*-

import frida, sys

jsCode = """
console.log("test");
"""

def message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)
# ./fs120800 -l "0.0.0.0:6666"
# adb wifi 10.0.0.23
process = frida.get_device_manager().add_remote_device('127.0.0.1:6666').attach('com.kevin.app')
script = process.create_script(jsCode)
script.on("message",message)
script.load()
input()
```

### frida rpc 远程调用

**python code**

```python
import frida
import json
from flask import Flask, jsonify, request

def message(message, data):
  if message['type'] == 'send':
    print(f"[*] {message['payload']}")
  else:
    print(message)

# ./fs120800 -l "0.0.0.0:6666"
# adb wifi 10.0.0.123
# 远程 frida-server 路径 adb wifi 的 ip : frida-server 启动的端口
session = frida.get_device_manager().add_remote_device('10.0.0.123:6666').attach('com.example.demoso1')
with open("/Users/zhangyang/codes/fridaProject/rpcDemo/hook.js") as f:
    jsCode = f.read()

# print("加载代码", jsCode)
script = session.create_script(jsCode)
script.on("message",message)
script.load()

# print("加密","1213")
# encodeResult = script.exports.invokemethod01("123")
# decodeResult = script.exports.invokemethod02(encodeResult)
# print(decodeResult)

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])#data解密
def decrypt_class():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    postdata = json_data.get("data")
    res = script.exports.invokemethod01(postdata)
    return res
 
 
@app.route('/decrypt', methods=['POST'])#url加密
def encrypt_class():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    postdata = json_data.get("data")
    print(postdata)
    res = script.exports.invokemethod02(postdata)
    return res

if __name__ == "__main__":
  app.run()
```

**js code**

```js
///<reference path='/Users/zhangyang/node_modules/@types/frida-gum/index.d.ts'/>

// 先 hook 方法 method01
// function hookmethod1(){
//     Java.perform(function(){
//         var targetClass = Java.use("com.example.demoso1.MainActivity");
//         targetClass.method01.implementation = function(str){
//             console.log("str is ", str);
//             var result = this.method01(str);
//             console.log("result is ", result);
//             return result;
//         }
//     })
// };

// 主动调用
function fridamethod01(inputStr){
    var result = null;
    Java.perform(function(){
        var targetClass = Java.use("com.example.demoso1.MainActivity");
        result = targetClass.method01(inputStr);
    });
    return result;
}

function fridamethod02(inputStr){
    var result = null;
    // public native String method02(String str);
    Java.perform(function(){
        Java.choose("com.example.demoso1.MainActivity",{
            onMatch: function(ins){
                result = ins.method02(inputStr);
            },
            onComplete: function(){}
        })
    });
    return result;
}

// 优先测试 js 中的主动调用
// function main(){
//     console.log("你好 -> 结果为:", fridamethod01("你好"));
//     console.log("27cae29a0913f6791705ca10be31a3e0 -> 结果为", fridamethod02("27cae29a0913f6791705ca10be31a3e0"))
    
// }
// setImmediate(main);

// 基于主动调用设置 rpc
rpc.exports = {
    invokemethod01: fridamethod01,
    invokemethod02: fridamethod02,
}
```

#### 压力测试

tmp.json
`{"data": "62feb9a98a01945ab06c0dd7823adc57"}`

测试命令
`siege -c30 -r1 "<http://127.0.0.1:5000/encrypt> POST < tmp.json"`

#### nps 进行内网穿透

https://ehang-io.github.io/nps 说明文档

1. 启动nps ` sudo nps start`
2. 新建客户端 安卓手机连接客户端 `./npc -server=10.0.0.124:8024 -vkey=hm40rtjpf2j3c1up -type=tcp`
![2022-02-18-083034.png](..%2Fimage%2F2022-02-18-083034.png)
3. 给客户端添加和 frida server 的端口映射
安卓手机启动 frida-server: ./fs12800 -l 0.0.0.0:6666
将目标 frida-server 的端口映射到 56666 端口上
![2022-02-18-083032.png](..%2Fimage%2F2022-02-18-083032.png)
4. python 脚本更改和 frida-server 的连接
此时就可以将 frida-server 开放到公网了;
`session = frida.get_device_manager().add_remote_device('10.0.0.124:56666').attach('com.example.demoso1')`

### Hook 普通方法

```js
function main(){
    Java.perform(function(){
        var UtilsClass = Java.use("com.kevin.app.Utils");
        UtilsClass.getCalc.implementation = function (a,b){
          // 打印信息
          console.log('a:' + a + ' ' + 'b:' + b);
          // 调用原方法获取结果
          var value = this.getCalc(a, b);
          console.log('result:',value);
            // 修改返回值
          return 123456;    
        }
    })
}

setImmediate(main);
```

### Hook 重载方法

```js
function main(){
    Java.perform(function(){
        var UtilsClass = Java.use("com.kevin.app.Utils");

        // 重载无参方法
        UtilsClass.test.overload().implementation = function () {
            console.log("hook overload no args");
            return this.test();
        }
        
        // 重载有参方法 - 基础数据类型
    UtilsClass.test.overload('int').implementation = function(num){
            console.log("hook overload int args");
            var myNum = 9999;
            var oriResult = this.test(num);
            console.log("oriResult is :" + oriResult);
            return this.test(myNum);
        }
        
        // 重载有参方法 - 引用数据类型
        UtilsClass.test.overload('com.kevin.app.Money').implementation = function(money){
            console.log("hook Money args");
            return this.test(money);
        }
        
        // hook 指定方法的所有重载
        var ClassName = Java.use("com.xiaojianbang.app.Utils");
        var overloadsLength = ClassName.test.overloads.length;
        for (var i = 0; i < overloadsLength; i++){
            ClassName.test.overloads[i].implementation = function () {
                // 遍历打印 arguments 
                for (var a = 0; a < arguments.length; a++){
                    console.log(a + " : " + arguments[a]);
                }
                // 调用原方法
                return this.test.apply(this,arguments);
            }
        }
    })
}

setImmediate(main);
```
### Hook 构造方法

```js
function main(){
    Java.perform(function (){
        // hook 构造方法 $init
        var MoneyClass = Java.use("com.kevin.app.Money");
        MoneyClass.$init.overload().implementation = function(){
            console.log("hook Money $init");
            this.$init();
        }
    })
}

setImmediate(main);
```

### Hook 对象

1. 通过 Java.choose找到指定对象
2. 通过Java.use找到对应的类, 在手动调用构造方法构造对象
3. hook 动态方法, 此时的this就是对象本身;
4. hook 以目标对象作为参数的方法, 此时该参数就是对象;

使用 choose 查找对象

```js
function main(){
    Java.perform(function(){
        // hook instance
        Java.choose("com.xiaojianbang.app.Money",{
            onMatch : function(instance){
                console.log("find it!!", instance.getInfo());
                // something to do...
            },
            
            onComplete: function(){
                console.log("compelete!!!");
            }
        })
    })
}

setImmediate(main);
```


### 参考资料

https://kevinspider.github.io/frida/frida-hook-java/

