下载地址: https://github.com/lasting-yang/frida_hook_libart

hook art

`frida -U --no-pause -f package_name -l hook_art.js`

hook_RegisterNatives

`frida -U --no-pause -f package_name -l hook_RegisterNatives.js`

hook_artmethod

init libext first time

use hook_artmethod.js

```commandline
frida -U --no-pause -f package_name -l hook_artmethod.js
# or
frida -U --no-pause -f package_name -l hook_artmethod.js > hook_artmethod.log
```
