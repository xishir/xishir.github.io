---
title: 2017 第三届福建省高校网络空间安全大赛 WriteUp
tags:
  - CTF
  - AWD
  - WriteUp

date: 2017-10-31 22:15:27
---

10月27参加的省赛，今年难度较之去年提高了不少，最终拿到了一等奖，算是比较满意了，但是AWD场打的还是不够好，还需要不断学习，WriteUp如下（后续会补上赛后做出的题）：
<!-- more -->

# 上午CTF场

## 要想会，先学会
官方提示`ping`，在流量包文件中找`icmp协议`，
![](/img/2017byb1.png)
按照时间排序，得到一串奇怪的东西，转ascii有很多字符不可见，猜测是有一些偏移，于是写了个py脚本暴力所以可能的偏移，得到flag
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

a=[144,150,150,139,145,165,120,139,91,160,93,167,70]
for j in range(-50,50):
  flag=''
  for i in a:
    flag+=chr(i+j)
  print flag
```
![](/img/2017byb2.png)


## upload
上传题，限制了后缀，burp抓包，`%00截断`上传网马，菜刀连接，在config里找到数据库配置，在数据库中找到flag，手快一血


## sqli
Fuzz的时候发现%25会报错`sprintf`，就猜测是格式化漏洞，但是没有网查资料，后来官方的提示竟然直接给了payload：
使用了两次sprintf导致格式化字符串漏洞（可构造`admin%1$' and 1=1#`与`admin%1$' and 1=2#`），sql盲注，flag在flag表flag列，flag的字符集为0123456789abcdeflg{}-
脚本撸出来单线程太慢，于是用burpsuite一个一个字符爆破的
```
admin%1$' and (ascii(mid((select flag from flag limit 1),{0},1))={1})#
```

# AWD
给了两个靶机，一个web，一个pwn，到最后pwn也没人做出来
Web大致有两个利用方向，一个是common目录下的home.php存在反序列化漏洞，
```php
$a=@$_POST['a'];
@unserialize($a);
```
因为对这块不熟所以没利用成功，又翻啊翻，在lib/User.php 里发现了上传部分的逻辑
```php
    function upload(){
        if(isset($_SESSION['username']) and $_SESSION['username']==="admin"){
            include_once __DIR__."/File.php";
            $up=new File();
            if($up->save()){
                $this->tp->display("success.tpl");
            }       
        }else{
            $this->tp->display("error.tpl");
        }
    }

    function logout(){
        $_SESSION=array();
        session_destroy();
        header("location: ./index.php");
    }

    function updatepass(){

        if (!empty($_POST['username']) and !empty($_POST['password'])){
            $username=addslashes($_POST['username']);
            $password=md5($_POST['password']);
            $sql="update user set password='$password' where username='$username' ";
            if (mysql_query($sql)){
                $this->tp->display("success.tpl");
            }
        }
    }
```
重点在`upload函数`和`updatepass函数`，upload限制了只有`admin`账号才能上传文件，而updatepass可以`修改任意用户密码`，这里就有了思路
1. 通过updatepass函数`修改admin密码`
2. 登录admin账号`上传shell`（shell的后缀要大小写绕过黑名单限制）
3. 通过shell`读取flag并提交`

思路很清晰，然而脚本是个大问题，登录上传弄得手忙脚乱，前期很长一段时间全靠队友手动传shell，提交flag，脚本憋出来后大部分人都修复漏洞了，就很难受，最后基本是打npc和其他几个队，需要好好反思，权限维持这一块没弄，就在一台电脑试验了一下，准备好的代码提交框架也没用上，总之AWD还是很刺激的，最终的成绩也满理想，就是一等的奖金缩水了有点扎心。

比赛界面如下
![](/img/2017byb3.png)
