---
title: 2017 XMUT第一届网络信息安全大赛 WriteUp
tags:
  - Crypto
  - CTF
  - Misc
  - Web
  - WriteUp
date: 2017-05-06 20:51:00
---

因为是赛后写的，有部分拿到flag后需要栅栏解密和凯撒解密的我真的忘了，见谅。
<!-- more -->
## Web1 签到
右键源代码即可看到flag

## Web2 从哪来
要求从英国访问

抓包，修改http协议头部的`Accept-Language`为`en-GB`
然后提示ip为`1.1.1.1`，添加`X-forwarded-for:1.1.1.1` ，提交即可返回flag

## Web3 前端！前端！
右键源代码看到一个eval函数，用浏览器控制台`console.log(eval函数中的内容)`，即可看到一段源码，输入源码中的密码即可拿到flag

## Web4 只有管理员才能拿到flag
直接访问提示只有管理员可以访问，抓包看到`cookie`很可疑，base64解码看到user=test;
改成`user=admin;` 再base64加密替换原来的cookie访问页面即可得到flag

## Web5 百战天虫
源代码提示`<meta name="ROBOTS"`
访问`robots.txt`即可得到密码，回主页输入密码拿到flag

## Web6 上传
随便抓包上传一个图片，返回了flag

## Web7 你有密码吗
右键源码可以看到php源代码，构造万能密码 `admin') or 1=1#`，账号密码都输入这个即可返回flag

## Web8 注入
过滤了空格，用`/**/`来代替，又过滤了union，select ，`双写`也能绕过，然后猜测flag在flag表的flag字段
payload：
```
id=1/**/ununionion/**/seselectlect/**/1,flag/**/from/**/flag
```
post提交就能拿到flag

## Web9 上传，又是上传！
上传一个jpg后缀的图马，抓包改后缀为`pht`就能拿到flag

## Web10 你懂伪协议吗？
右键源码可以看到源代码，get的user参数的值为admin时，可以包含file参数的值那个文件，还提示了flag在`fla9.php`，直接`file=fla9.php`没有显示，想到用伪协议将fla9的源码base64后包含
payload：`?user=admin&amp;file=php://filter/read=convert.base64-encode/resource=fla9.php`
得到一串base64，base64解密即可得到flag

## Misc1 注意看仔细了
队友做的，winhex打开图片，flag在最后面

## Misc2 密码就在图片上
唯一一道没做出来的题，`f5隐写术`，比赛的时候硬是无数次错过那套工具，
提示了密码在图片上，图中最显眼的字符为password，
用`F5-steganography` 工具解密即可拿到flag

`java Extract f5.jpg -p password`

## Misc3 照着题目做
队友做的，听说照着题目说的点了100次然后拿到flag

## Misc4 你不可能拿得到flag
猜测是`zip伪加密`，winhex打开可以看到文件头的标记为没有加密，但是却提示输入密码，定位

`50 4B 01 02`

压缩源文件目录区：
50 4B 01 02：目录中文件文件头标记(0x02014b50)
1F 00：压缩使用的 pkware 版本
14 00：解压文件所需 pkware 版本
09 00：全局方式位标记（有无加密，这个更改这里进行伪加密，改为09 00打开就会提示有密码了）

把这里改成`0000`保存即可解压，是个二维码，用`ps取反`后扫描，

提示这里没有flag，winhex打开二维码图片在最后面找到flag

## Crypto1 base？
粘贴到`hackbar`，一直`base64解密`几次就看到flag了

## Crypto2 你是一名合格的特工吗
`摩尔密码`解密，得到一串疑似培根密码的东西
解密得到`thisisflag`，加上`gctf{}`就是flag了

## Crypto3 这是什么鬼？
`jsfuck`，直接粘贴到浏览器控制台就alert弹出flag了

## Crypto4 隔壁班妹子的表白
提示妹子大二，天蝎座好像，是要我们手动输日期爆破，但是队友直接用od打开就看到了flag

## 综合题
观察网站，写着TBLOG，没听过，百度有源码但是懒得下载，
博客唯一一篇文章提示后台在/admin，访问得到管理员登录页面，下意识输入a`dmin admin`弱密码登进后台
后来发现登陆页面源码里好像也有写密码
进后台后观察后台结构，没有数据库备份，没有网站配置，找到一个发布文章的地方，有一个fckeditor编辑器，版本2.6.4.1，找到上传点，一开始各种上传，但是1.php.jpg传上去变成了1_php.jpg，无法达到畸形解析，各种截断也失败了，创建1.php目录也会被过滤成1_php，最后发现上传1.jpg网马后，访问 `1.jpg/1.php`可以解析php网马，接下来菜刀连接，直接就system权限，在菜刀中查看管理员桌面的`flag.txt`文件拿到flag

## 总结
最后剩一题f5没做出来很难受，没有逆向没有pwn，所以还是拿了第一，奖金1200还是很美滋滋的。