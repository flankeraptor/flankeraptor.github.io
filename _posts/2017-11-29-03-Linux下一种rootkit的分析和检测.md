---
layout: post
title: Linux下一种rootkit的分析和检测 
subtitle: 2017/11/29
date: 2017-11-29
author: FR
header-img: img/depot/post-butiao.jpg
catalog: true
tags:
    - linux
    - rootkit
---

在FreeBuf上看到一篇关于Linux下rootkit代码的分析和检测文章，觉得不错，但文章是FreeBuf原创奖励计划的，标明禁止转载，这里就记下要点。

先附上原文链接：**[【FreeBuf链接】](http://www.freebuf.com/articles/system/154039.html)**

文章介绍的是R0级的rootkit，所讨论的rootkit源代码来自github一个开源项目[链接](https://github.com/ivyl/rootkit)。

编译安装完成后，通过/proc/rtkit和内核进行交互，内核模块默认隐藏，通过命令`cat /proc/rtkit`可以查看具体信息。

创建文件的时候以__rt或-__rt开头即可默认隐藏。
