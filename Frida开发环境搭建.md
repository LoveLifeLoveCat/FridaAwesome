### 选择编译器和开发语言

frida工程一般由 js+python组成

所以可以使用 vscode+pychrame 组合开发

在 https://frida.re/docs/javascript-api/ 的介绍中

> 为了提高工作效率，我们强烈建议使用我们的TypeScript绑定。这意味着你可以获得代码完成、类型检查、内联文档、重构工具等。
这里有一个简短的预告视频，展示了编辑器的体验。
> 
> 克隆这个 [repo](https://github.com/oleavr/frida-agent-example) 来开始工作。

所以使用ts+python开发体验会更好

#### 搭建开发环境

安装所需软件 vscode python 

ts驱动需要node 安装nodejs

- git clone git://github.com/oleavr/frida-agent-example.git
- cd frida-agent-example/
- npm install
- frida -U -f com.example.android --no-pause -l _agent.js

开启监控 

- npm run watch 
实时转换ts为js代码
最终使用 _agent.js 注入 

或者直接编辑 _agent.js 也可以