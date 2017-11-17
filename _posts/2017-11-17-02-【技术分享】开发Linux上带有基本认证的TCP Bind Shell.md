---
layout: post
title: 【技术分享】开发Linux上带有基本认证的TCP Bind Shell
subtitle: 2017/11/17
date: 2017-11-17
author: FR
header-img: img/depot/post-butiao.jpg
catalog: true
tags:
    - linux
    - shell
---

- **来自安全客 [【安全客链接】](http://bobao.360.cn/learning/detail/4696.html)**  

## 一、前言
本文的目标是使用x64汇编语言开发一个带有密码认证的tcp_bind_shell，并且程序中不包含任何null字节。

## 二、找到落脚点
万事开头难，首先我们得找到一个落脚点。先来看看如何使用C语言编写tcp_bind_shell，程序源码请参考此处链接，C代码如下所示：






![img/2017-11-09/15083896142390.png](http://image.3001.net/images/20171019/15083896142390.png)

    基于磁盘的顺序存储。
    基于Hash算法的存储。
    基于MD5压缩映射的存储。
    基于嵌入式Berkeley DB的存储。
    基于布隆过滤器（Bloom Filter）的存储。

对于 URL 直接去重，主要涉及的是存储优化方面，对于本文不是重点，这里不再细说。

**而对于 URL 逻辑上的去重，则需要更多地追求数据的可用性，这是做测试工作需要去考量的。**
