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

以前在做漏洞Fuzz爬虫时，曾做过URL去重相关的工作，当时是参考了seay法师的文章以及网上零碎的一些资料，感觉做的很简单。近来又遇到相关问题，于是乎有了再次改进算法的念头。

![img/2017-11-09/15083896142390.png](http://image.3001.net/images/20171019/15083896142390.png)

    基于磁盘的顺序存储。
    基于Hash算法的存储。
    基于MD5压缩映射的存储。
    基于嵌入式Berkeley DB的存储。
    基于布隆过滤器（Bloom Filter）的存储。

对于 URL 直接去重，主要涉及的是存储优化方面，对于本文不是重点，这里不再细说。

**而对于 URL 逻辑上的去重，则需要更多地追求数据的可用性，这是做测试工作需要去考量的。**
