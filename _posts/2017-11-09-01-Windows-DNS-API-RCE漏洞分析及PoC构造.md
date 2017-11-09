---
layout: post
title: Windows DNS API RCE漏洞分析及PoC构造
subtitle: 2017/11/09
date: 2017-11-09
author: FR
header-img: img/depot/post-butiao.jpg
catalog: true
tags:
    - windows
    - dns
    - 漏洞
    - RCE漏洞
    - PoC
---

- **来自FreeBuf [【FreeBuf链接】](http://www.freebuf.com/articles/system/151161.html)**  

在分析koadic渗透利器时，发现它有一个注入模块，其DLL注入实现方式和一般的注入方式不一样。搜索了一下发现是由HarmanySecurity的Stephen Fewer提出的ReflectiveDLL Injection. 由于目前互联网上有关这个反射式DLL注入的分析并不多，也没有人分析其核心的ReflectiveLoader具体是怎么实现的，因此我就在这抛砖引玉了。

## 0×00 引言
常规的DLL注入方式相信大家都很熟悉了，利用CreateRemoteThread这一函数在目标进程中开始一个新的线程，这个线程执行系统的API函数LoadLibrary，之后DLL就被装载到目标进程中了。然而，由于这一技术被大量的恶意软件利用，各种安全对DLL注入这一块自然是严加看守，而常规的注入方式太过于套路化(CreateRemoteThread+ LoadLibrary)，导致它十分容易被检测出来。同时，常规的DLL注入方式还需要目标DLL必须存在磁盘上，而文件一旦“落地”就也存在着被杀毒软件查杀的风险。
