---
title: JAVA反序列化漏洞系列之—基础知识
tags:
  - JAVA
  - 反序列化

date: 2019-01-24 16:15:27
toc: true
---

JAVA反序列化漏洞近几年来十分热门，于是打算记录下从零开始学习JAVA反序列化漏洞的过程，于是就有了本系列文章，写的不好欢迎师傅们斧正。
本篇文章主要介绍JAVA的基础知识，不定时会补充一些新的知识点。
<!-- more --> 
<!-- 本系列所有源码与poc&exp：https://github.com/xishir/ -->

# 前置知识  
普通语法就不需要多讲了吧，JAVA基础差同学可以先过一下菜鸟课程  
http://www.runoob.com/java/java-tutorial.html  
这边简单列举一下需要掌握的点
- 安装jdk
- 基础语法
- 对象和类
- IO流、文件操作
- 异常处理
- 封装继承多态、抽象、接口
- 泛型
- 网络编程
- Servlet
- SSH、SSM框架
- Maven的使用
- 主流中间件
- 主流IDE的使用

# 实验环境
- java环境：jdk1.8.0_162
- 电脑系统：macOS Mojave 10.14.3
- IDE：IntelliJ IDEA

# 序列化与反序列化  
## 基本概念  
序列化（Serialization）是将对象的状态信息转换为可以存储或传输的形式的过程。一般将一个对象存储至一个储存媒介，例如档案或是记亿体缓冲等。在网络传输过程中，可以是字节或是XML等格式。而字节的或XML编码格式可以还原完全相等的对象。这个相反的过程又称为反序列化。
什么情况下需要序列化
- 将内存中的对象保存到文件中或者数据库
- 用套接字在网络上传送对象
- 通过RMI传输对象  

序列化的作用就是对象的`持久化`和`传递`。 

类通过实现`java.io.Serializable`接口以启用其序列化功能。未实现此接口的类将无法使其任何状态序列化或反序列化。可序列化类的所有子类型本身都是可序列化的。序列化接口没有方法或字段，仅用于标识可序列化的语义。  

## 简单实例
对象序列化包括如下步骤：
1. 创建一个对象输出流，它可以包装一个其他类型的目标输出流，如文件输出流；
2. 通过对象输出流的writeObject()方法写对象。  

对象反序列化的步骤如下：
1. 创建一个对象输入流，它可以包装一个其他类型的源输入流，如文件输入流；
2. 通过对象输入流的readObject()方法读取对象。
简单举个🌰：
```java
package com.xishir.serialize;

import java.io.*;

public class Test implements Serializable {

    private static final long serialVersionUID = 1L;

    private String n;

    public Test(String n) {
        this.n = n;
    }

    @Override
    public String toString() {
        return this.n;
    }

    public static void main(String[] args) throws Exception {
        //实例化一个对象
        Test obj = new Test("Serialize Test");

        //序列化对象
        ObjectOutputStream output = new ObjectOutputStream(new FileOutputStream("test.obj"));
        output.writeObject(obj);
        output.flush();
        output.close();

        //反序列化对象
        File file = new File("test.obj");
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file));
        Object x = ois.readObject();
        System.out.print(x);
        ois.close();
    }
}
```
运行结果  
![](/img/ser/ser0-2.png)

对象序列化后存储为`test.obj`，内容是这样的  
![](/img/ser/ser0-1.png)
可以看到二进制文件是以`aced 0005`开头的，如果是base64就是以`rO0a`开头的（划重点！见到类似的数据传输操起键盘就是一梭子payload过去
![](/img/ser/ser0-3.png)

## 自定义反序列化行为
自定义序列化和反序列化过程，就是重写`writeObject`和`readObject`方法。  
国际惯例，弹个计算器
![](/img/ser/ser0-4.png)
readObject的代码为：
```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    Runtime.getRuntime().exec("open -a calculator");
}
```
当序列化对象的时候就会执行writeObject方法，反序列化对象的时候就会执行readObject方法，从而控制能够反序列化的行为。

## serialVersionUID
serialVersionUID的取值是Java运行时环境根据类的内部细节自动生成的。如果对类的源代码作了修改，再重新编译，新生成的类文件的serialVersionUID的取值有可能也会发生变化，会导致之前序列化的类无法再反序列化回来。  
类的serialVersionUID的默认值完全依赖于Java编译器的实现，对于同一个类，用不同的Java编译器编译，有可能会导致不同的 serialVersionUID，也有可能相同。为了提高serialVersionUID的独立性和确定性，强烈建议在一个可序列化类中显示的定义serialVersionUID，为它赋予明确的值。

## 安全风险
联想php的反序列化漏洞，可以发现readObject方法和php中的魔术方法异曲同工，而大部分Java反序列化漏洞的原理就是某个类重写了`readObject`方法，在


# Java反射机制
## 基本概念  
Java反射机制
- 指的是可以于运行时加载,探知和使用编译期间完全未知的类.
- 程序在运行状态中, 可以动态加载一个只有名称的类, 对于任意一个已经加载的类,都能够知道这个类的所有属性和方法; 对于任意一个对象,都能调用他的任意一个方法和属性;
- 加载完类之后, 在堆内存中会产生一个Class类型的对象(一个类只有一个Class对象), 这个对象包含了完整的类的结构信息,而且这个Class对象就像一面镜子,透过这个镜子看到类的结构,所以被称之为:反射.
- 每个类被加载进入内存之后,系统就会为该类生成一个对应的java.lang.Class对象,通过该Class对象就可以访问到JVM中的这个类.

Class对象的获取方法
- 实例对象的getClass()方法;
- 类的.class(最安全/性能最好)属性;
- 运用Class.forName(String className)动态加载类,className需要是类的全限定名(最常用).
注意，使用功能”.class”来创建Class对象的引用时，不会自动初始化该Class对象，使用forName()会自动初始化该Class对象

## 简单实例
这里我只举个最简单的例子：
```java
package com.xishir.reflection;

import java.io.IOException;
import java.lang.reflect.Method;

public class ReflectionTest {

    public static void main(String[] args){

        Class test = Test.class;
        System.out.println("I am:" + test.getName());

        Method[] methods = test.getMethods();
        for(Method method : methods) {
            System.out.println("I have this method:" + method.getName());
        }


        try {
            Method method = test.getMethod("hack", String.class);
            Object x = method.invoke(new Test("xishir"), "233333");//第一个参数是类的对象。第二参数是函数的参数
            System.out.println(x);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class Test{
    private String a;

    public Test(String a){
        this.a = a;
    }
    public String hack(String b) throws IOException {
        System.out.println("test " + this.a + " and " + b);
        Runtime.getRuntime().exec("open -a calculator");
        return b;
    }
}
```
运行结果：
![](/img/ser/ser0-5.png)
可以看到，我们成功用`Test.class`取到了Test类的Class对象，然后列出Test的所有方法，最后用invoke调用了一个Test对象的hack方法。