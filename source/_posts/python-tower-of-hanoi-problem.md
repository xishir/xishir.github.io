---
title: 汉诺塔问题（python版）
tags:
  - python
  - 算法
  - 递归
date: 2017-04-30 18:14:40
---

## 目的

将n个盘子从初塔A移动到目的塔C，借用塔B
<!-- more -->
## 规则

一次只能移动一个盘子，大盘子不能放在小盘子上方

## 思路

递归实现
编写`move(n, a, b, c)`函数，参数`n`表示3个柱子A、B、C中第1个柱子A的盘子数量
要将A的n个盘子移动到C，就要先将上面的n-1个盘子移动到B，最底下的大盘子才能移动到C
然后再将B的n-1个盘子借助A移动到C

## 代码
```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

#def normalize(name):
def move(n, a, b, c):
    if n==1:
        print '%s--&gt;%s' %(a,c)
    else:
        move(n-1,a,c,b)
        print '%s--&gt;%s' %(a,c)
        move(n-1,b,a,c)
move(3, 'A', 'B', 'C')
```