---
title: Centos7搭建LAMP环境
tags:
  - 运维
  - LAMP
date: 2017-11-16 22:40:09
---

很久之前帮老师写的LAMP（linux+apache+mysql+php）教程，自己也用这个方法配了好多台服务器，发到博客记录一下，也希望能给大家带来一些帮助。
<!-- more -->

# 更新yum
以全新centos7系统为例子（确保自己拥有root权限）
```
yum update
```

# PHP5.6安装
## 1、百度搜索webtatic  根据系统版本号选择yum源并安装
```
https://webtatic.com/packages/php56/
```
这里我选择了centos7的`php56`版本
运行如下语句
```shell
rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
```
 
## 2、安装php及其拓展
```she
yum install php56w
yum install php56w-devel
yum install php56w-mysqli
yum install php56w-mbstring
yum install php56w-gd
yum install php56w-xmlwriter
```
一路按Y同意安装
以上安装会`默认执行编译安装Apache`
若不确定自己服务器重使用了什么php拓展，请执行`yum install php56w*`
 
# Apache 配置
进入`/etc/httpd/conf.d`目录下，删除除`php.conf`以外文件
然后进行虚拟主机配置
在`/etc/httpd/conf.d/`目录新建任意一个conf文件，如`test.conf`
创建的.conf文件内容如下，后续绑定域名什么的也是在这里
```xml
<VirtualHost *:80>
     ServerName 127.0.0.1:80   
     DocumentRoot /work/WEBROOT/default/
     ErrorLog  /work/log/default_error.log
     CustomLog  /work/log/default_access.log combined
     <Directory "/work/WEBROOT/default">
         AllowOverride All
        Order allow,deny
        Require all granted
        Allow from all
     </Directory>
</VirtualHost>
```
并根据实际情况建立web目录，如`/work/`
```
mkdir /work/WEBROOT/default -p
mkdir /work/log/default -p
```
并将网站文件放入`/work/WEBROOT/default/`
 请确保web目录所属用户和所属用户组为`apache`,可用`chown`与`chgrp`命令更改
```
chown apache /work -R
chgrp apache /work -R
```

服务启动前，请确保防火墙对apache为开放权限，若不想配置防火墙策略，
请关闭selinux 与firewalld.service
分别为
修改`/etc/selinux/config`文件中设置`SELINUX=disabled` ，然后重启服务器。
和`systemctl disable firewalld`
执行后请重启服务器
 
启动服务
```
systemctl start httpd.service
```
加入开机启动
```
systemctl enable httpd.service
```

# Mysql配置
先安装带有可用的mysql5系列社区版资源的rpm包
```
rpm -Uvh http://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm
```
查看当前可用的mysql安装资源
```
yum repolist enabled | grep "mysql.*-community.*"
```
直接使用yum的方式安装MySQL
```
yum -y install mysql-community-server     #这一步很慢
```
加入开机启动
```
systemctl enable mysqld
```
启动服务
```
systemctl start mysqld
```
初始化（重置密码，删除匿名用户，远程登录配置等）
```
mysql_secure_installation
```
登录数据库
```
mysql -uroot -p
```
选择数据库
```mysql
use database；
```
导入sql
```mysql
source /work/xxx.sql
```

# 配置网站数据库信息
根据要搭建的网站来配置
