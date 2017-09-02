---
title: 升级博客为https
tags:
  - apache
  - https
date: 2017-04-11 20:38:42
---

## 博客环境
```
Centos6.5
Apache httpd
Wordpress
```
<!-- more -->
##  升级步骤

#### 0x00 获取证书免费SSL证书

因为是个人博客，所以我用的是腾讯云提供的免费SSL证书，申请成功后上传到云服务器中

#### 0x01 安装apache的ssl模块
`yum install mod_ssl -y`
这里遇到了一个问题，yum失效，后来用以下代码解决的
```bash
rm -f /var/lib/rpm/__db*
rpm -vv --rebuilddb
```

#### 0x02 配置ssl.conf
主要修改的配置如下：
```xml
<VirtualHost _default_:443>
DocumentRoot "/******"  #你的网站路径
ServerName www.***********.cn #你的域名
    <Directory "/******">
        Options Indexes FollowSymLinks
        AllowOverride All
        Order allow,deny
        Allow from all
    </Directory>
SSLCertificateFile /***/2_域名.crt
SSLCertificateKeyFile /***3_域名.key
SSLCertificateChainFile /***/1_root_bundle.crt
</VirtualHost>
```

####  0x03 配置.htaccess 使http转跳到https
```
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
RewriteCond %{HTTPS} !on [NC]
RewriteRule (.*) https://www.codemonster.cn%{REQUEST_URI} [R=301,NC,L]
</IfModule>
# END WordPress
```
然后wordpress后台设置中的网站地址也全部加上`https`