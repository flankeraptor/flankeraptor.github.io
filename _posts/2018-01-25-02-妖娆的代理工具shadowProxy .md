---
layout: post
title: 妖娆的代理工具shadowProxy 
subtitle: 2018/01/25
date: 2018-01-25
author: FR
header-img: img/depot/post-banner.jpg
catalog: true
tags:
    - proxy
---

- **来自猎户安全实验室 [【猎户安全实验室链接】](https://mp.weixin.qq.com/s/ENjRuI5FZArtzV5H4LbJng)**

## 1 概述
作为一个九流白帽子，迫于对鸡腿的渴望，终于鼓起勇气去挖挖洞。好不容易发现个漏洞点，帅不过半秒，咔，IP被封了，好气哦！！！

这种情况下，很自然的想到通过网上大量的免费代理进行IP隐匿。那么问题来了，难道拿到哪些代理（不一定存活），每用一次手动换下一个代理？这太像火铳的工作方式了，想想就心累了，所以这些让人心累的事情就让工具来搞定吧。

伊始的免费的代理是无法直接接收返回数据的，为进一步自动化解决， So 我想说的是这个工具跟普通的代理不一样。

## 2 实现思路
一般情况下，我们直接对目标进行测试，触发某些安全策略，导致IP被干掉。
![/img/2018-01-25/mmbiz.qpic.cn.jpeg](http://mmbiz.qpic.cn/mmbiz_png/ic56Y1PMq5MUw1lx42h2EgBIibFJZJq7wg9EGz7tT5azKmy7pOlAVz60sc5fEHxoKoAGzJID8quZyicPpYXLlGHeA/?wx_fmt=png&wxfrom=5&wx_lazy=1)

而网络上存在众多的免费代理资源，如果加以利用，我们将也便拥有了众多的IP。思路对了，但却没有好的办法/工具，我们不可能那么频繁的手工切换代理地址。如此，这种简单、重复、苦逼的工作就交给工具来做吧，那就是shadowProxy。
![/img/2018-01-25/mmbiz.qpic.cn-1.jpeg](http://mmbiz.qpic.cn/mmbiz_png/ic56Y1PMq5MUw1lx42h2EgBIibFJZJq7wggVaQia9yianyHup0uyicIibtIrA5SMZOQNicRt80rPHUeFmLBX8pGEbedaQ/?wx_fmt=png&wxfrom=5&wx_lazy=1)

## 3 实现功能
根据上面的思路，我们要实现的功能其实就是简单的代理转发功能和代理资源的校验、管理、分配功能。

### 3.1 HTTP/HTTPS代理功能
主要使用python内建的http.server和http.client库实现。

先看一下http.server中的关键函数handle_one_request()：
```
def handle_one_request(self):

   """Handle a single HTTP request.

   You normally don't need to override this method; see the class

   __doc__ string for information on how to handle specific HTTP

   commands such as GET and POST.

   """

   try:

       self.raw_requestline = self.rfile.readline(65537)

       if len(self.raw_requestline) > 65536:

           self.requestline = ''

           self.request_version = ''

           self.command = ''

           self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)

           return

       if not self.raw_requestline:

           self.close_connection = True

           return

       # parse_request() 解析request报文，提取command, path, version, headers等数据。

       if not self.parse_request():  

           # An error code has been sent, just exit

           return

       mname = 'do_' + self.command    # 如果command为GET，那么后续就调用do_GET()

       if not hasattr(self, mname):

           self.send_error(

               HTTPStatus.NOT_IMPLEMENTED,

               "Unsupported method (%r)" % self.command)

           return

       method = getattr(self, mname) # 获取方法

       method()  # 调用方法

       self.wfile.flush() #actually send the response if not already done.

   except socket.timeout as e:

       #a read or a write timed out.  Discard this connection

       self.log_error("Request timed out: %r", e)

       self.close_connection = True

       return
```

可以清晰看出，如果我们需要处理HTTP的COMMAND方法，那么在代码中实现do_COMMAND()即可。在本工具中，实现了do_GET()：

  - 读取请求数据包  
  - 调用proxyCoordinator实例的方法取得一个代理  
  - 通过代理发起请求  
  - 接收响应包并发送给原始请求者

```
def do_GET(self):

   if self.path == 'http://shadow.proxy/':

       self.send_cacert()

       return

   ...

   ...

   proxy = proxyCoor.dispatchProxy(target)

   ...

   ...

   if proxy.split("://")[0] == "http":

       conn = http.client.HTTPConnection(proxy.split("://")[1], timeout=self.timeout)

   elif proxy.split("://")[0] == "https":

       conn = http.client.HTTPSConnection(proxy.split("://")[1], timeout=self.timeout)

   ...

   conn.request(self.command, req.path, req_body, dict(req.headers))

   res = conn.getresponse()

   res_body = res.read()

   ...

   ...

   self.wfile.write(res_body)

   self.wfile.flush()


do_HEAD = do_GET

do_POST = do_GET

do_PUT = do_GET

do_DELETE = do_GET

do_OPTIONS = do_GET

do_TRACE = do_GET
```

### 3.2 代理协调
代理地址的导入、管理、分配相对于代理本身来讲是一个独立的功能，故而单独封装成一个类，这其实才是工具的核心部分，但实现起来却比代理部分容易太多。

主要功能：

  - 导入代理列表。  
  - 验证代理的可用性和匿名性。  
  - 维护目标站点可用代理的信息表。  
  - 参考信息表，反馈可用的代理地址。

## 4 跑起来
### 4.1 效果验证
使用默认代理列表进行测试，自动选择不同的代理。（默认情况下每个代理会被重复使用，如果需要指定代理次数，可设置 -t 参数。）
![/img/2018-01-25/mmbiz.qpic.cn-2.jpeg](http://mmbiz.qpic.cn/mmbiz_png/ic56Y1PMq5MUw1lx42h2EgBIibFJZJq7wgcmSGpCfYQIFyunBHAtXXwZzTUxr8X3Xna5OZHibellSyQ8mXlibOWMSg/?wx_fmt=png&wxfrom=5&wx_lazy=1)

### 4.2 结合burpsuite使用
在Burp Suite的User options标签页下Upstream Proxy Servers中添加代理，指向shadowProxy开放的端口。由于免费代理的不稳定性，所以建议指明目标主机，只对特定主机的请求进行代理。
![/img/2018-01-25/mmbiz.qpic.cn-3.jpeg](http://mmbiz.qpic.cn/mmbiz_png/ic56Y1PMq5MUw1lx42h2EgBIibFJZJq7wguAN8XdibNnyEZz0Qck39pLH1QRBKFkCniaibVVE83iaWibKdCmDibV2jj7Fg/?wx_fmt=png&wxfrom=5&wx_lazy=1)

动态效果图：
![/im/g2018-01-25/mmbiz.qpic.cn-4.gif](https://mmbiz.qpic.cn/mmbiz_gif/ic56Y1PMq5MUw1lx42h2EgBIibFJZJq7wg7Wny7kOurzHoCqcFIxSd3eZsic0tPUoMtxjxZD3rXiaCf4trvGweLmLA/?wx_fmt=gif&wxfrom=5&wx_lazy=1)

## 5 友情提醒
  - 不要将工具用于非法用途。  
  - 网络上的免费代理可能是别人的蜜罐之类的，请注意好使用场景。  
  - 代码开源地址如下：  
      https://github.com/odboy/shadowProxy  
  - (话说点进去的人都会给我Star)
