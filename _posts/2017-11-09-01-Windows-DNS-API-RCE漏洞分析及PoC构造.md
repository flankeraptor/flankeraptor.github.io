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

- **来自FreeBuf [【FreeBuf链接】](http://www.freebuf.com/vuls/151050.html)**  

根据 Microsoft 2017年10月安全通告，多个版本 Windows 中的 dnsapi.dll 在处理 DNS response 时可导致 SYSTEM 权限 RCE 。

需要注意的是，不是 Windows 系统中所有 DNS 解析都有问题，比如 nslookup 并不解析 DNSSEC，所以没有问题，同时，也不是所有能触发漏洞的地方都能在 SYSTEM 权限下执行代码，只有像 Windows Update 这样的 SYSTEM 权限进程才能成为 SYSTEM 权限 RCE 的攻击入口。

以 DNS Client API DLL 10.0.15063.0 与 10.0.15063.674 为例，补丁对比，

![img/2017-11-09/15084703471529.png](http://image.3001.net/images/20171020/15084703471529.png)

可知漏洞存在于 dnsapi.dll 中的 Nsec3_RecordRead 函数，那么可以确定问题就是出在解析 DNS response 的 NSEC3 Resource record，为了构造 PoC，先得了解这个 “NSEC3″ 的背景。首先，DNS 协议数据结构如下图所示，

![img/2017-11-09/15084703547099.png](http://image.3001.net/images/20171020/15084703547099.png)

例如，当访问[http://justanotherbuganalysis.github.io/](http://justanotherbuganalysis.github.io/) 时， DNS query 如下，

>`9d 4b 01 00 00 01 00 00 00 00 00 00 16 6a 75 73  .K...........jus
 74 61 6e 6f 74 68 65 72 62 75 67 61 6e 61 6c 79  tanotherbuganaly
 73 69 73 06 67 69 74 68 75 62 02 69 6f 00 00 01  sis.github.io...
 00 01                                            ..              `
