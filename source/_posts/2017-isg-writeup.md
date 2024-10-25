---
title: 2017 ISG信息安全技能大赛线上赛 WriteUp
tags:
  - CTF
  - WriteUp
  - 审计
  - 注入
date: 2017-08-31 23:05:27
---

## 签到

加群在公告得到一串字符，16进制转字符串得到flag
<!-- more -->

## ISGCoinMarket

很有意思的题，初始给你1元人民币和0.0056个ISG币，你可以发布交易，也可以和别人交易，通过交易得到2000人民币和2000ISG币即可得到flag。

这里主要是没有限制负数，我的解法是创建4个号

u1-&gt;u2   把u1的ISG币刷到4000000，汇率为0.0059，可以看作`u1低价买入ISG`

u3-&gt;u4   把u3的ISG币刷到40000000，人民币为负数，u4则相反

然后利用u4的人民币去买u1的ISG，汇率位0.0054，可以看作`u1高价卖出ISG`

一买一卖u1就挣到了足够的钱

![](/img/2017isg1.png) 

## Remix

可以读取图片并base64解码，并不知道后台逻辑，右键查看源代码提示flag在7827端口（我也不记得是不是这个端口），于是想到SSRF，构造
`?targe=http://localhost:7827`,
将得到的base64解码即可得到flag

## wmwcms

robots.txt提示给了个rar，下载下来是网站源码，审计发现连接数据库时存在注入，
```php
<?php
include_once 'func.php';
if (isset($_REQUEST['dsn'])){
    $dsn = $_REQUEST['dsn'];
} else{
    $dsn = "wmwcms";
}
$dsn = "mysql:dbname={$dsn}";
$username = 'wmwcms';
$password = '%glVYKTkLtQ22';
$options = array(
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET names utf8',
    );
$dbh = new PDO($dsn, $username, $password, $options);
```
第8行的数据库连接可以由用户控制，于是我们在远程服务器搭建相同的数据库、用户密码也相同、表名和字段也相同，然后构造
`dsn=wmwcms;8.8.8.8`  
即可让这道题连接到你的服务器，然后使用`action=img`读取数据库中`portrait`字段所在位置的文件，即可读取到flag

## BMP Wannacry-2

大佬说是`bmp隐写`，没做出来，留坑待填

[https://doegox.github.io/ElectronicColoringBook/](https://doegox.github.io/ElectronicColoringBook/)

## 感想

这个比赛难度中上，参赛对象为各大企业安全团队，看到了许多大佬，膜

![](/img/2017isg2.png)