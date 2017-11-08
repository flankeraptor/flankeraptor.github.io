---
layout: post
title: 对ShadowBrokers Envison Collision漏洞的利用分析
subtitle: 2017/11/08
date: 2017-11-08
author: FR
header-img:
catalog: true
tags:
    - ShadowBrokers
    - 漏洞
---
- **转自FreeBuf [【FreeBuf链接】](http://www.freebuf.com/vuls/152427.html)**  
- **原文来自steemit[【原文链接】](https://steemit.com/security/@shadoweye/analysis-of-the-shadowbrokers-envisoncollision-exploit)**

目前我们正在对ShadowBrokers公开的利用工具以及脚本等进行了全方位的分析和分类工作，所以写一篇关于Linux下“envisioncollision”漏洞利用的简单介绍是非常值得的。我们之前已经对所公开文件中的[PHPBB](https://steemit.com/security/@shadoweye/analysis-of-the-shadowbrokers-xpphpbb-pl-exploit)漏洞进行披露，当时的文章中提到这个漏洞非常受网络犯罪组织的欢迎，因为很多web论坛都存在“有效”的SIGINT目标，所以接下来披露另一个web论坛漏洞合情合理。

## 基本介绍
对于“envisioncollision”，我们不仅发现了工具本身，还发现了一个用户手册 – “user.tool.envisioncollision.COMMON”，其中说明该工具于2011年左右被开发，我们将其上传到了包含原始漏洞利用以及一个用于演示的修改版本的[Github repo](https://github.com/x0rz/EQGRP)。

除了一些使用“重定向器”入侵目标，以及在目标机器得到一个反向shell或者生成一个主动连接的bind-shell的介绍，这本用户手册并没有引起我们太大的兴趣。另外，“envisioncollision”漏洞利用并不会具体利用某些漏洞，它使用管理员凭据，通过一个“hook”将后门安装在Invision Power Board（IPBoard）上，用于在主机上执行命令。IPBoard中的“hook”是一种非常有效的插件，它可以用于向论坛中添加额外的功能。据我所知， 它们基本上是一些包含PHP代码的XML（我不是IPBoard管理员/开发人员）。

漏洞利用工具会登录到Web论坛的管理面板并得到一个会话ID，然后部署一个含有PHP代码的“hook”，之后“hook”会被调用，等待10秒钟代码即可执行，它还会通过卸载“hook”来“删除”（实际上并没有删除）后门。让我们觉得特别有趣的事情是，它没有安装一个允许动态执行代码的后门，而是使用了硬编码的那种，这让我们很不高兴，改天我们会改进一下，然后发布动态执行代码的版本。

此外，不同于phpBB漏洞利用，”envisioncollision”的使用说明并没有演示如何部署“nopen”后门，但展示了各种方法从目标获取反向shell。我们假设你已经通过这些shell获取论坛服务器访问权限并部署了“nopen”后门（反向shell是广为人知的方法），作为参考，我们在文章最后添加了“Pentest Monkeys”的反向shell参考表链接。

下面是一个屏幕截图，展示了使用漏洞利用工具在IPBoard上获得反向shell。 由于我们只有IPBoard 3.4，因为登录流程不同，所以我们不得不修改漏洞利用代码。在TAO写的这个漏洞利用的任何版本中，IPBoard都会发送一个带有可点击链接的“登陆页面”。

![img/2017-11-08/15094231128320.png!small.jpeg](http://image.3001.net/images/20171031/15094231128320.png!small)

在IPBoard 3.4中，它们使用了302重定向。我们开始修改工具时很明显地感觉NSA的开发人员（或者承包商therof）在组合这些工具的时候心情一定很糟糕。演示中使用的版本是[github repo](https://github.com/x0rz/EQGRP)中的“envisioncollision2”，为了更清楚地展示，我们将开发者的所有调试信息都注释出来了。

你可能会注意到，后门和hook都可以被删除了，而之前卸载hook实际上不会删除的PHP文件。另外，我们最近打算使用Python3编写更好版本的工具，并发布它来展示这种工具应该怎么做才算最好。

## 被入侵的明显标志
如上所述，这个漏洞会留下了很多证据表明它已在该台服务器上被使用。 它会留下了PHP后门/hook文件，如果根据说明使用，则会包含一个漏洞使用的回调IP/端口。 此外，它没有清除Apache日志文件以及由漏洞利用工具创建的活动会话。 它还会在MySQL服务器中留下日志。用户手册中也没有关于擦除日志文件的内容，所以会留下相当明显的日志。

## References
> [IPBoard Hook Creation (Forum Thread)](https://theadminzone.com/threads/how-to-create-your-own-hooks.112698/)  
> [IPBoard Hook Creation (IPBoard Documentation)](https://invisioncommunity.com/4docs/advanced-usage/development/plugins-an-example-r72/)  
> [Our Modified “envisioncollision” Exploit](https://github.com/ShadowEye/envisioncollision)  
> [PentestMonkey’s Reverse-Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
