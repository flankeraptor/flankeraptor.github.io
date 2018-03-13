---
layout: post
title: 关于QT5下malloc与PUCHAR的一个问题
subtitle: 2018/02/12
date: 2018-02-12
author: FR
header-img: img/depot/post-banner.jpg
catalog: true
tags:
    - coding
    - qt5
---

- **来自ME [【ME链接】](http://myself)**

  > 最近在用QT5编写UI，在调用C语言API malloc的时候遇到一个情况，记录一下。
  
#### 代码
```
DWORD dwSize = 13579;
LPVOID lpPointer = NULL;
PUCHAR puPointer = NULL;

lpPointer = malloc( dwSize );
puPointer = (PUCHAR)malloc( dwSize );
``` 

#### 问题描述
malloc成功分配到内存空间后，返回的lpPointer是正常的指向堆空间的地址；而puPointer则是返回了一个很小的地址数值，指向内存的代码空间，为非法指针。后来将代码调整为如下：
```
DWORD dwSize = 13579;
LPVOID lpPointer = NULL;
PUCHAR puPointer = NULL;

lpPointer = malloc( dwSize );
puPointer = (PUCHAR)lpPointer;
```
所得到的结果跟修改之前的代码一致。

#### 问题分析
通过以上两段代码比对，初步判断是malloc成功返回后，赋值操作过程中的强制类型转换出现了问题。

在使用Qt Creator自带的GDB调试器进行调试的时候，查看Memory功能右键菜单中有两类选项，一类为Object's Address，一类为Pointer's Address。这类地址所指向的内存空间地址是不同的。

Object's Address：对于指针类型的变量，它表示的地址是指以该指针对象的 **值** 为地址；

Pointer's Address：对于指针类型的变量，它表示的地址是指存储该变量的内存地址；

对于LPVOID指针，没有定义指针指向数据的类型，在Qt Creator上GDB中，调试过程显示的变量值为该变量指向的地址值；而对于PUCHAR指针，定义了指向数据的类型，在调试过程中显示的内容则是该指针指向的unsigned char类型的数据内容。