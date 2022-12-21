#### 获取所有 JNI 函数函数地址

通过 hook ArtMethod 的 RegisterNative 函数, 可以监控所有的静态注册和动态注册的 JNI 函数的地址;

```js
/*
frida14
仅在Android 8.1下测试成功，其他版本可能需要重新修改适配
原作者: Simp1er
*/
const STD_STRING_SIZE = 3 * Process.pointerSize;

class StdString {
    constructor() {
        this.handle = Memory.alloc(STD_STRING_SIZE);
    }

    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny) {
            Java.api.$delete(data);
        }
    }

    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }

    toString() {
        const [data] = this._getData();
        return data.readUtf8String();
    }

    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}


function prettyMethod(method_id, withSignature) {
    const result = new StdString();
    Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
    return result.disposeToString();
}

function readStdString(str) {
    if ((str.readU8() & 1) === 1) { // size LSB (=1) indicates if it's a long string
        return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
    }
    return str.add(1).readUtf8String();
}

function attach(addr) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.arg0 = args[0]; // this
        },
        onLeave: function (retval) {
            var modulemap = new ModuleMap()
            modulemap.update()
            var module = modulemap.find(retval)
            // var string = Memory.alloc(0x100)
            // ArtMethod_PrettyMethod(string, this.arg0, 1)
            if (module != null) {
                console.log('<' + module.name + '> method_name =>',
                    prettyMethod(this.arg0, 1),
                    ',offset=>', ptr(retval).sub(module.base), ',module_name=>', module.name)
            } else {
                console.log('<anonymous> method_name =>', readStdString(string), ', addr =>', ptr(retval))
            }
        }
    });
}

function hook_RegisterNative() {
    var libart = Process.findModuleByName('libart.so')
    var symbols = libart.enumerateSymbols()
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name.indexOf('RegisterNative') > -1 && symbols[i].name.indexOf('ArtMethod') > -1 && symbols[i].name.indexOf('RuntimeCallbacks') < 0) {
            //art::RuntimeCallbacks::RegisterNativeMethod(art::ArtMethod*, void const*, void**)
            attach(symbols[i].address)
        }
    }

}

function main() {
    hook_RegisterNative()
}

setImmediate(main)
```

#### 枚举内存中的 so 文件

用于查看目标 module 是否被正常加载, 使用 Process.enumerateModules() 将当前加载的所有 so 文件打印出来

```js
function hook_native() {
    var modules = Process.enumerateModules();
    for (var i in modules) {
        var module = modules[i];
        console.log(module.name);
        if (module.name.indexOf("target.so") > -1) {
            console.log(module.base);
        }
    }
}
```

#### 获取指定 so 文件的基地址

```js
function hook_module() {
    var baseAddr = Module.findBaseAddress("libnative-lib.so");
    console.log("baseAddr", baseAddr);
}
```

#### 获取指定 so 文件的函数

通过导出函数名定位 native 方法

```js
function hook_func_from_exports() {
    var add_c_addr = Module.findExportByName("libnative-lib.so", "add_c");
    console.log("add_c_addr is :", add_c_addr);
}
```

#### 通过 symbols 符号定位 native 方法

```js
function find_func_from_symbols() {
    var NewStringUTF_addr = null;
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    for (var i in symbols) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0
        ) {
            if (symbol.name.indexOf("NewStringUTF") >= 0) {
                console.log("find target symbols", symbol.name, "address is ", symbol.address);
                NewStringUTF_addr = symbol.address;
            }
        }
    }

    console.log("NewStringUTF_addr is ", NewStringUTF_addr);

    Interceptor.attach(NewStringUTF_addr, {
        onEnter: function (args) {
            console.log("args0", args[0])
            console.log("args0", args[0], hexdump(args[0]));
            console.log("args1", args[1], hexdump(args[1]));
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                // 直接读取 c 里面的 char
                console.log("Memory readCstring is :", Memory.readCString(args[1]));
            } else {
                console.log("get env error");
            }
        },
        onLeave: function (returnResult) {
            console.log("result: ", Java.cast(returnResult, Java.use("java.lang.String")));
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                var jstring = env.newStringUtf("修改返回值");
                returnResult.replace(ptr(jstring));
            }
        }
    })
}
```

#### 通过地址偏移 inline-hook 任意函数

```js
function main() {
    // get base address of target so;
    var libnative_lib_addr = Module.findBaseAddress("libnative-lib.so");
    console.log("base module addr ->", libnative_lib_addr);
    if (libnative_lib_addr) {
        var add_addr1 = Module.findExportByName("libnative-lib.so", "_Z5r0addii");
        var add_addr2 = libnative_lib_addr.add(0x94B2 + 1); // 32位需要加1
        console.log(add_addr1);
        console.log(add_addr2);
    }

    // 主动调用
    var add1 = new NativeFunction(add_addr1, "int", ["int", "int"]);
    var add2 = new NativeFunction(add_addr2, "int", ["int", "int"]);

    console.log("add1 result is ->" + add1(10, 20));
    console.log("add2 result is ->" + add2(10, 20));

}

setImmediate(main);

/*
base module addr -> 0xd430b000
0xd43144b3
0xd43144b3
add1 result is ->30
add2 result is ->30
*/
```

#### 通过 Intercept 拦截器打印 native 方法参数和返回值, 并修改返回值


- onEnter: 函数(args) : 回调函数, 给定一个参数 args, 用于读取或者写入参数作为 NativePointer 对象的指针;

- onLeave: 函数(retval) : 回调函数给定一个参数 retval, 该参数是包含原始返回值的 NativePointer 派生对象; 可以调用 retval.replace(1234) 以整数 1234 替换返回值, 或者调用retval.replace(ptr("0x1234")) 以替换为指针;

- 注意: retval 对象会在 onLeave 调用中回收, 因此不要将其存储在回调之外使用, 如果需要存储包含的值, 需要制作深拷贝, 如 ptr(retval.toString())

```js
function find_func_from_exports() {
    var add_c_addr = Module.findExportByName("libnative-lib.so", "add_c");
    console.log("add_c_addr is :", add_c_addr);
    // 添加拦截器
    Interceptor.attach(add_c_addr, {
        // 打印入参
        onEnter: function (args) {
            console.log("add_c called");
            console.log("arg1:", args[0].toInt32());
            console.log("arg2", args[1].toInt32());
        },
        // 打印返回值
        onLeave: function (returnValue) {
            console.log("add_c result is :", returnValue.toInt32());
            // 修改返回值
            returnValue.replace(100);
        }
    })
}
```

#### 通过 Intercept 拦截器替换原方法

```js
function frida_Interceptor() {
    Java.perform(function () {
        //这个c_getSum方法有两个int参数、返回结果为两个参数相加
        //这里用NativeFunction函数自己定义了一个c_getSum函数
        var add_method = new NativeFunction(Module.findExportByName('libhello.so', 'c_getSum'),
            'int', ['int', 'int']);
        //输出结果 那结果肯定就是 3
        console.log("result:", add_method(1, 2));
        //这里对原函数的功能进行替换实现
        Interceptor.replace(add_method, new NativeCallback(function (a, b) {
            //h不论是什么参数都返回123
            return 123;
        }, 'int', ['int', 'int']));
        //再次调用 则返回123
        console.log("result:", add_method(1, 2));
    });
}
```

#### inline hook

通俗点说, inline hook就是通过内存地址, 进行 hook;
```js
function inline_hook() {
    var libnative_lib_addr = Module.findBaseAddress("libnative-lib.so");
    if (libnative_lib_addr) {
        console.log("libnative_lib_addr:", libnative_lib_addr);
        var addr_101F4 = libnative_lib_addr.add(0x102BC);
        console.log("addr_101F4:", addr_101F4);

        Java.perform(function () {
            Interceptor.attach(addr_101F4, {
                onEnter: function (args) {
                    console.log("addr_101F4 OnEnter :", this.context.PC,
                        this.context.x1, this.context.x5,
                        this.context.x10);
                },
                onLeave: function (retval) {
                    console.log("retval is :", retval)
                }
            }
            )
        })
    }
}
```

#### so 层方法注册到 js 中, 主动调用

文档: 
> new NativeFunction(address, returnType, argTypes[, options])


- address : 函数地址
	
- returnType : 指定返回类型
	
- argTypes : 数组指定参数类型 类型可选: void, pointer, int, uint, long, ulong, char, uchar, float, double, int8, uint8, int16, int32, uint32, int64, uint64; 参照函数所需的 type 来定义即可;

```js
function invoke_native_func() {
    var baseAddr = Module.findBaseAddress("libnative-lib.so");
    console.log("baseAddr", baseAddr);
    var offset = 0x0000A28C + 1;
    var add_c_addr = baseAddr.add(offset);
    var add_c_func = new NativeFunction(add_c_addr, "int", ["int", "int"]);
    var result = add_c_func(1, 2);
    console.log(result);
}
Java.perform(function () {
    // 获取 so 文件基地址
    var base = Module.findBaseAddress("libnative-lib.so");
    // 获取目标函数偏移
    var sub_834_addr = base.add(0x835) // thumb 需要 +1
    // 使用 new NativeFunction 将函数注册到 js
    var sub_834 = new NativeFunction(sub_834_addr, 'pointer', ['pointer']);
    // 开辟内存, 创建入参
    var arg0 = Memory.alloc(10);
    ptr(arg0).writeUtf8String("123");
    var result = sub_834(arg0);
    console.log("result is :", hexdump(result));
})
```

#### hook libc 中的系统方法

`/system/lib(64)/libc.so` 导出的符号没有进行 `namemanline` , 直接过滤筛选即可

```js
// hook libc.so
var pthread_create_addr = null;

// console.log(JSON.stringify(Process.enumerateModules()));
// Process.enumerateModules() 枚举加载的so文件
var symbols = Process.findModuleByName("libc.so").enumerateSymbols();
for (var i = 0; i < symbols.length; i++) {
    if (symbols[i].name === "pthread_create") {
        // console.log("symbols name is -> " + symbols[i].name);
        // console.log("symbols address is -> " + symbols[i].address);
        pthread_create_addr = symbols[i].address;
    }
}

Interceptor.attach(pthread_create_addr, {
    onEnter: function (args) {
        console.log("args is ->" + args[0], args[1], args[2], args[3]);
    },
    onLeave: function (retval) {
        console.log(retval);
    }
});
```

libc.so 中方法替换

```js 
// hook 检测frida 的方法
function main() {
    // var exports = Process.findModuleByName("libnative-lib.so").enumerateExports(); 导出
    // var imports = Process.findModuleByName("libnative-lib.so").enumerateImports(); 导入
    // var symbols = Process.findModuleByName("libnative-lib.so").enumerateSymbols(); 符号

    var pthread_create_addr = null;
    var symbols = Process.getModuleByName("libc.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name === "pthread_create") {
            pthread_create_addr = symbol.address;
            console.log("pthread_create name is ->", symbol.name);
            console.log("pthread_create address is ->", pthread_create_addr);
        }
    }

    Java.perform(function () {
        // 定义方法 之后主动调用的时候使用
        var pthread_create = new NativeFunction(pthread_create_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])
        Interceptor.replace(pthread_create_addr, new NativeCallback(function (a0, a1, a2, a3) {
            var result = null;
            var detect_frida_loop = Module.findExportByName("libnative-lib.so", "_Z17detect_frida_loopPv");
            console.log("a0,a1,a2,a3 ->", a0, a1, a2, a3);
            if (String(a2) === String(detect_frida_loop)) {
                result = 0;
                console.log("阻止frida反调试启动");
            } else {
                result = pthread_create(a0, a1, a2, a3);
                console.log("正常启动");
            }
            return result;
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    })
}
```

#### hook native 调用栈

```
Interceptor.attach(f, {
    onEnter: function (args) {
        console.log('RegisterNatives called from:n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('n') + 'n');
    }
});
```