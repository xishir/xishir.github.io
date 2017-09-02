---
title: 渗透神器合体：在BurpSuite中集成Sqlmap
tags:
  - burpsuite
  - sqlmap
  - 插件
  - 工具
date: 2017-07-13 10:44:25
---

参考链接：http://www.freebuf.com/sectool/45239.html
<!-- more -->
首先安装sqlmap，传送门：http://sqlmap.org/
将sqlmap.py加入到path中（在cmd中输入sqlmap.py不会报找不到文件）
下载依赖的jar包： `commons-io-2.4.jar`，
配置路径为：`extender-->options-->Java Environment`，选择该jar包所在目录

下载`sqlmap4burp`：
github: https://github.com/difcareer/sqlmap4burp
编译此项目为单独的一个jar文件（编译前先导入所需的jar包，`commons-lang3`和`commons-io`），添加到burpsuite的java插件中，
配置路径为：extender-->extentions-->add
之后你将会看到在主页面中会新增一个tab，名字叫做Sqlmap

插件原理是将目标请求的数据存放到临时文件中，然后调用`"sqlmap.py -r $file"`来启动对请求的sql注入检测 在Sqlmap tab中，你可以配置sqlmap除 -r外的其他参数，比如：
加入配置中写：`"--level 3"`,真实执行时是：`sqlmap.py -r $file --level 3`
回到burpsuite主页面，在任何请求连接上右键，会看到新增`"send to Sqlmap"`，点击后会开启cmd窗口，针对此请求进行sql注入检测

![](http://ovm02pvss.bkt.clouddn.com/burp+sqlmap.png)