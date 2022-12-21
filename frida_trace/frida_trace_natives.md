文档地址: https://frida.re/docs/frida-trace/

https://github.com/Pr0214/trace_natives


需要切换到 frida14 版本
- 1.将traceNatives.py丢进IDA plugins目录中 
在ida 的python console中运行如下命令即可找到plugins目录：os.path.join(idaapi.get_user_idadir(), "plugins")


- 2.IDA中，Edit-Plugins-traceNatives –> IDA输出窗口就会显示如下字眼：使用方法如下： frida-trace -UF -O C:UsersLenovoDesktop2021mtlibmtguard.txt