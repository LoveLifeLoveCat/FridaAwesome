 



#### 如何升级frida版本

直接从12升级15

pip install frida==15.2.2
 
成功了

Successfully installed frida-15.2.2

但是提示一行报错信息

frida-tools 5.3.0 requires frida<13.0.0,>=12.7.3, but you have frida 15.2.2 which is incompatible.

去frida页面搜索该版本对于的frida-tools版本升级

frida15.2.2对于frida-tools 11.0.0

pip install frida-tools=11.0.0

又提示了 objection 错误 

