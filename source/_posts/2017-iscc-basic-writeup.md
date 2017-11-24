---
title: 2017 ISCC Basic WriteUp
date: 2017-06-26 13:29:39
tags:
  - CTF
  - WriteUp
  - MISC
---

由于网站备案原因，博客停止更新了一个月，接下来会陆续把中间积累下的比赛writeup和学习经验补上。
<!-- more -->

## Basic 1 Wheel Cipher （50）

加密表：
```
ZWAXJGDLUBVIQHKYPNTCRMOSFE
KPBELNACZDTRXMJQOYHGVSFUWI
BDMAIZVRNSJUWFHTEQGYXPLOCK
RPLNDVHGFCUKTEBSXQYIZMJWAO
IHFRLABEUOTSGJVDKCPMNZQWXY
AMKGHIWPNYCJBFZDRUSLOQXVET
GWTHSPYBXIZULVKMRAFDCEONJQ
NOZUTWDCVRJLXKISEFAPMYGHBQ
XPLTDSRFHENYVUBMCQWAOIKZGJ
UDNAJFBOWTGVRSCZQKELMXYIHP
MNBVCXZQWERTPOIUYALSKDJFHG
LVNCMXZPQOWEIURYTASBKJDFHG
JZQAWSXCDERFVBGTYHNUMKILOP
```
密钥为：`2，3，7，5，13,12,9，1，8，10，4，11，6`<br>
密文为：`NFQKSEVOQOFNP`<br>
新神告诉我这是
[杰弗逊轮盘](https://en.wikipedia.org/wiki/Jefferson_disk)
编写python脚本如下
```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
# by: CodeMonster

import requests
import base64

s=["ZWAXJGDLUBVIQHKYPNTCRMOSFE","KPBELNACZDTRXMJQOYHGVSFUWI","BDMAIZVRNSJUWFHTEQGYXPLOCK","RPLNDVHGFCUKTEBSXQYIZMJWAO","IHFRLABEUOTSGJVDKCPMNZQWXY","AMKGHIWPNYCJBFZDRUSLOQXVET","GWTHSPYBXIZULVKMRAFDCEONJQ","NOZUTWDCVRJLXKISEFAPMYGHBQ","XPLTDSRFHENYVUBMCQWAOIKZGJ","UDNAJFBOWTGVRSCZQKELMXYIHP","MNBVCXZQWERTPOIUYALSKDJFHG","LVNCMXZPQOWEIURYTASBKJDFHG","JZQAWSXCDERFVBGTYHNUMKILOP"]
num=[2,3,7,5,13,12,9,1,8,10,4,11,6]

a="NFQKSEVOQOFNP"

for k in range(26):
    flag=""
    for i in range(len(num)):
        for j in range(26):
            if a[i]==s[num[i]-1][j]:
                if  j-k&gt;=0:
                    flag=flag+s[num[i]-1][j-k]
                else:
                    flag=flag+s[num[i]-1][j+26-k]
                break
    print flag
```
运行后找到最像flag的一条，flag为 `FIREINTHEHOLE`

![](/img/2017iscc1.jpg)

## Basic 2 你猜猜。。 （100）

打开里面是这样一段代码
```
504B03040A0001080000626D0A49F4B5091F1E0000001200000008000000666C61672E7478746C9F170D35D0A45826A03E161FB96870EDDFC7C89A11862F9199B4CD78E7504B01023F000A0001080000626D0A49F4B5091F1E00000012000000080024000000000000002000000000000000666C61672E7478740A0020000000000001001800AF150210CAF2D1015CAEAA05CAF2D1015CAEAA05CAF2D101504B050600000000010001005A000000440000000000`</pre>
```
看到504B0304，很明显的zip压缩文件头，粘贴到winhex保存为zip文件，zip里有个`flag.txt`文件

但是有密码，爆破得到密码123456，flag为`daczcasdqwdcsdzasd`

## Basic 3 神秘图片 （100）

给了一张png的图片，直接用`ExtractPNG.exe`工具，从图片中提取出了flag，flag为`goodlcuk`

## Basic 4 告诉你个秘密 （100）

给了这样一段东西
```
636A56355279427363446C4A49454A7154534230526D684356445A31614342354E326C4B4946467A5769426961453067
```
16进制转ascii，然后再base64解码得到`r5yG lp9I BjM tFhB T6uh y7iJ QsZ bhM`
这里卡了好久，后来发现键盘中 r5yG圈着T，lp9I圈着O，以此类推，flag为`TONGYUAN`

## Basic 5 二维码

扫描二维码提示flag是路由器密码
binwalk分析二维码发现隐藏了一个压缩文件，分离出来后看到里面有两个文件，一个cap，一个破解记录
爆破zip密码得到密码，解压后根据破解记录的提示，路由器密码前四位为ISCC，后四位大写字母加数字。
用kali自带的aircrack-ng进行爆破
```bash
aircrack-ng wifi.cap -w dic.txt
```
其中dic.txt是字典，wifi.cap就是那个cap文件

![](/img/2017iscc2.jpg)

爆破出路由器密码，所以flag为 `ISCC16BA`