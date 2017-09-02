---
title: EXCEL学生随机分组算法实现（python版）
tags:
  - excel
  - python
  - 算法
date: 2017-05-07 20:50:09
---

## 需求分析

* 算法集中分在2组，就是W老师和Y老师那两组，
* 指导老师不能答辩自己指导的学生。
* 每个指导老师的学生最好不要扎堆（小于等于2）
<!-- more -->
## 算法思路

* 把所有学生分配到七个组中，每一组有26个空位填补学生
* excel每一行学生读取进来，判断“毕业设计题目”是否包含关键词“算法”
    * 若包含关键词，则进行分配，
        * 分配规则：`random（W组空位*100+Y组空位*100+其他组空位之和）`生成一个随机数
        * 判断落在哪个区间之中，
        * 若该学生指导老师等于这个组的老师、或指导老师在该组的学生大于2、或该组人数已满26
        * 则重新生成随机数
        * 否则学生放入该组，该组剩余空位减1
* 分配“毕业设计题目”不包含“算法”的学生
    * 分配规则：random（所有组空位之和）生成一个随机数
    * 判断落在哪个区间之中，
    * 若该学生指导老师等于这个组的老师、或指导老师在该组的学生大于2、或该组人数已满26
    * 则重新生成随机数
    * 否则学生放入该组，该组剩余空位减1

## 算法实现

考虑到要对excel进行读写，原来想用VBS实现，但是没有学过，实现成本太高了，发现python有对excel操作的现成的库，于是就直接拿过来用

### 0x00 xlrd模块与xlwt的安装

xlrd模块是用来读取excel表格的，
xlwt模块用来生成新的excel表格
安装方法也很简单，在有pip的windows下

```
pip install xlrd
pip install xlwt
```

### 0x01 xlrd模块
1. 导入模块
`import xlrd`
2. 打开Excel文件读取数据
`data = xlrd.open_workbook('excelFile.xls')`
3. 使用技巧
获取一个工作表
```python
table = data.sheets()[0] #通过索引顺序获取
table = data.sheet_by_index(0) #通过索引顺序获取
table = data.sheet_by_name(u'Sheet1') #通过名称获取
#获取整行和整列的值（数组）
table.row_values(i)
table.col_values(i)
#获取行数和列数
nrows = table.nrows
ncols = table.ncols
#循环行列表数据
for i in range(nrows ):
    print table.row_values(i)
```

### 0x02 xlwt模块

1. 导入模块
`import xlwt`
2. 创建excel
`workbook = xlwt.Workbook(encoding = 'ascii')`
3. 创建表
`worksheet = workbook.add_sheet('Sheet1')`
4. 往单元格内写入内容
`worksheet.write(0, 0, label = 'Row 0, Column 0 Value')`
5. 保存
`workbook.save('Excel.xls')`

### 0x03 实现算法
实现过程遇到最坑的问题就是编码了，utf-8和gbk各种坑，各种乱码，最后全部采用gbk
然后读取的有些单元格是浮点型，不能转换编码类型，加个特殊判断就行，实现代码如下，算法不算复杂，需要的是耐心和细节把握
```python
#!/usr/bin/python
# -*- coding: gbk -*-
# By CodeMonster

import random
import xlrd
import xlwt

data = xlrd.open_workbook('test.xls')  #读取excel
table = data.sheets()[0]               #读取第一个表

nrows = table.nrows  #读取行数
ncols = table.ncols  #读取列数

teacher=["xxx"，"xxx"，"xxx"，"xxx","xxx","xxx","xxx"]
mat=[26 for i in range(7)]   #生成空位数组
key="算法"                   #关键词：算法
grp1=5                       #W组
grp2=6                       #Y组
stu=[['' for i in range(ncols+1)] for j in range(7*27)]   #生成空表
for i in range(nrows-1):
	if key in table.row_values(i+1)[4].encode("gbk"):   #如果包含关键字
		s=mat[grp1]*100+mat[grp2]*100
		for j in range(5):
			s+=mat[j]
		while 1==1:
			num=random.randint(0,s-1)
			if num&lt;mat[grp1]*100:      #W组
				num=5
			elif num&lt;mat[grp1]*100+mat[grp2]*100:    #Y组
				num=6
			else:                      #其他组
				num=num-(mat[grp1]*100+mat[grp2]*100)
				for k in range(5):
					if num &lt; mat[k]:
						num=k
						break
					else:
						num-=mat[k]
			teach=table.row_values(i+1)[8].encode("gbk")
			teach_num=1
			for j in range(26):
				if stu[num*26+j][8]==teach:
					teach_num=teach_num+1
			if teach_num&gt;2:
				print "too much same teacher!"
				continue
			elif teach in teacher[num]:
				print "same teacher!"
				continue
			elif mat[num]==0:
				print "no place!"
				continue
			else:
				n=num*26+26-mat[num]
				for k in range(ncols-2):
					stu[n][k]=table.row_values(i+1)[k].encode("gbk")
				stu[n][13]=str(num)
				mat[num]=mat[num]-1
				break
for i in range(nrows-1):
	if key not in table.row_values(i+1)[4].encode("gbk"):   #如果不包含关键字
		s=0
		for j in range(7):
			s+=mat[j]
		while 1==1:
			num=random.randint(0,s-1)
			for k in range(7):
				if num &lt; mat[k]:
					num=k
					break
				else:
					num-=mat[k]
			teach=table.row_values(i+1)[8].encode("gbk")
			teach_num=1
			for j in range(26):
				if stu[num*26+j][8]==teach:
					teach_num=teach_num+1
			if teach_num&gt;2:
				continue
			elif teach in teacher[num]:
				continue
			elif mat[num]==0:
				continue
			else:
				n=num*26+26-mat[num]
				for k in range(ncols-2):
					try:
						stu[n][k]=table.row_values(i+1)[k].encode("gbk")
					except AttributeError,e:
						stu[n][k]=str(int(table.row_values(i+1)[k]))
				stu[n][13]=str(num)
				mat[num]=mat[num]-1
				break

workbook = xlwt.Workbook(encoding = 'gbk')
worksheet = workbook.add_sheet('Sheet1')

for j in range(ncols): 
	worksheet.write(0, j, label = table.row_values(0)[j].encode("gbk"))
n=1
for i in range(len(stu)):
	if '1' in stu[i][0]:
		#print stu[i][0]
		for j in range(ncols+1): 
			worksheet.write(n, j, label = stu[i][j])
		n+=1

workbook.save('Workbook.xls')
print "success!"
```