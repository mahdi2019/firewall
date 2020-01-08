# Firewall loadable kernel module (LKM) [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/MaryamSaeedmehr/PacketFilteringKernelModule)


## Table of contents
- [Firewall loadable kernel module (LKM)](#firewall-loadable-kernel-module-lkm)
  - [General info](#general-info)
  - [What is a Kernel Module?](#what-is-a-kernel-module)
  - [Source Code for this Discussion](#source-code-for-this-discussion)
  - [Prepare the System for Building LKMs](#prepare-the-system-for-building-lkms)
  - [A Warning!](#a-warning)
  - [A kernel module is not an application](#a-kernel-module-is-not-an-application)
  - [how to write firewall v1.0](#how-to-write-firewall-v10)
    - [what is NetFilter](#what-is-netfilter)
    - [packet path (point of Receiving packet)](#packet-path-point-of-receiving-packet)
    - [Hook Decision](#hook-decision)
    - [Hook priority](#hook-priority)
    - [Hook Function](#hook-function)
    - [Hook registration](#hook-registration)
  - [Building the Module Code](#building-the-module-code)
  - [Testing the LKM](#testing-the-lkm)
  - [Authors](#authors)
  - [License](#license)
  - [Task-Lists](#task-lists)
  - [Realted Link](#realted-link)

---
## General info
> I write program with C for LKM to filtering input packet.  
> I use netfilter to check packet ip and port,to check what to do with this packet by Rules set.  
> I write character driver too.for Receiving congif for filtering policy from user space.  
> at first by default our program policy is blacklist with 0 ip:port to blocking. so **at first all packet Accepted !!**  
> after running test.c, it sent text in config.txt.  
> our firewall check what text receiving.if its equal to "blacklist" , our policy changed to black list ,  
> if text contain "whitelist" , our policy changed to white list ,  
> and if is contain "ip:port" , its add to list of our last policy.  
> ***NOTE** : if policy chaned , list will be empty!!!*

---

## What is a Kernel Module?
A loadable kernel module (LKM) is a mechanism for adding code to, or removing code from, the Linux kernel at run time. They are ideal for device drivers, enabling the kernel to communicate with the hardware without it having to know how the hardware works. The alternative to LKMs would be to build the code for each and every driver into the Linux kernel.

---

### Source Code for this Discussion  
```bash
$ sudo apt-get install git
$ git clone https://github.com/mahdi2019/firewall.git
```
---

## Prepare the System for Building LKMs
The system must be prepared to build kernel code, and to do this you must have the Linux headers installed on your device. On a typical Linux desktop machine you can use your package manager to locate the correct package to install. For example, under 64-bit Debian you can use :

first know your current kernel version :
```bash
$ uname -r
```

then check linux-header installed or not :
```bash
$ ls -l /usr/src/linux-headers-$(uname -r)
```
if not installed , so should installed :
```bash
$ sudo apt update
$ apt search linux-headers-$(uname -r)
$ sudo apt install linux-headers-$(uname -r)

```

##### You must install the headers for the exact version of your kernel build

---
## *A Warning!*
It is very easy to crash the system when you are writing and testing LKMs. It is always possible that such a system crash could corrupt your file system — it is unlikely, but it is possible. Please back up your data and/or use an Virtual Machine, 

---

## A kernel module is not an application
Some of the key differences are that kernel modules:
* for a start there is no main() function! 
* **do not execute sequentially** — a kernel module registers itself to handle requests using its initialization function, which runs and then terminates. The type of requests that it can handle are defined within the module code. This is quite similar to the event-driven programming model that is commonly utilized in graphical-user interface (GUI) applications.
* **do not have automatic cleanup** — any resources that are allocated to the module must be manually released when the module is unloaded, or they may be unavailable until a system reboots.
* **do not have printf() functions** — kernel code cannot access libraries of code that is written for the Linux user space. The kernel module lives and runs in kernel space, which has its own memory address space. The interface between kernel space and user space is clearly defined and controlled. We do however have a printk() function that can output information, which can be viewed from within user space.
* **can be interrupted** — one conceptually difficult aspect of kernel modules is that they can be used by several different programs/processes at the same time. We have to carefully construct our modules so that they have a consistent and valid behavior when they are interrupted.
* **have a higher level of execution privilege** — typically, more CPU cycles are allocated to kernel modules than to user-space programs. This sounds like an advantage, however, you have to be very careful that your module does not adversely affect the overall performance of your system.
* **do not have floating-point support** — it is kernel code that uses traps to transition from integer to floating-point mode for your user space applications. However, it is very difficult to perform these traps in kernel space. The alternative is to manually save and restore floating point operations — a task that is best avoided and left to your user-space code.

## how to write firewall v1.0
> my solution isn't the best way , but it's work :D  

### what is **NetFilter**
Netfilter is a packet filtering subsystem in the Linux kernel stack and has been there since kernel 2.4.x. Netfilter's core consists of five hook functions declared in linux / netfilter_ipv4.h. Although these functions are for IPv4, they are not much different from those used in the IPv6 counterpart. The hooks are used to analyze packets in various locations on the network stack.  
that can declaration hook in path of network packets.
With the help of this hooks , at different points of the packet path in the Linux kernel , can get them and check or modify them as needed, then return them or delete them from the continue.  
This hooks only can use in *kernel space* and can not use in *user space*.

### packet path (point of Receiving packet)
```
  [INPUT]--->[1]--->[ROUTE]--->[3]--->[4]--->[OUTPUT]
                       |            ^
                       |            |
                       |         [ROUTE]
                       v            |
                      [2]          [5]
                       |            ^
                       |            |
                       v            |
                    [INPUT*]    [OUTPUT*]
                    
[1]  NF_IP_PRE_ROUTING (Right after the packets have been received. )
[2]  NF_IP_LOCAL_IN (Packets addressed to the network stack. )
[3]  NF_IP_FORWARD (Packets that should be forwarded. )
[4]  NF_IP_POST_ROUTING (Packets that have been routed and are ready to leave)
[5]  NF_IP_LOCAL_OUT (Packets from our own network stack)
[*]  Network Stack
```
### Hook Decision 

* **NF_DROP** : drop the packet (don't continue trip)
* **NF_ACCEPT** : accept the packet (continue network stack trip)
* **NF_STOLEN** : hook steals the packet (don't continue trip)
* **NF_QUEUE** : queue the packet to userspace
* **NF_REPEAT** : repeat the hook function

### Hook priority
declarated in linux/netfilter_ipv4.h([Link](http://lxr.linux.no/#linux+v3.5/include/linux/netfilter_ipv4.h#L58))
```C
enum nf_ip_hook_priorities {
          NF_IP_PRI_FIRST = INT_MIN,
          NF_IP_PRI_CONNTRACK_DEFRAG = -400,
          NF_IP_PRI_RAW = -300,
          NF_IP_PRI_SELINUX_FIRST = -225,
          NF_IP_PRI_CONNTRACK = -200,
          NF_IP_PRI_MANGLE = -150,
          NF_IP_PRI_NAT_DST = -100,
          NF_IP_PRI_FILTER = 0,
          NF_IP_PRI_SECURITY = 50,
          NF_IP_PRI_NAT_SRC = 100,
          NF_IP_PRI_SELINUX_LAST = 225,
          NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
          NF_IP_PRI_LAST = INT_MAX,
  };
```

### Hook Function
```C
typedef unsigned int nf_hookfn(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));
```
* hooknum : Indicates the point at which the hook is recorded
* skb : A pointer to a structure that contains packet information
* in : Indicates the input network interface
* out : Indicates the output network interface
* The last parameter : The pointer to a function called by the netfilter itself after all the hooks are done and usually the hook functions are not called it because it causes the other hooks can't do their job.

### Hook registration
We do this using the ```nf_register_hook``` function. The input parameter of this function is a variable of type ```nf_hook_ops```. All the hook information is set to this variable and then the function is recorded in the netfilter subsystem.

```C
struct nf_hook_ops {
        struct list_head list;

        /* User fills in from here down. */
        nf_hookfn *hook;
        struct module *owner;
        u_int8_t pf;
        unsigned int hooknum;
        /* Hooks are ordered in ascending priority. */
        int priority;
};
```
* **hook** : pointer to hook finction
* **owner** : Indicates a module in which this function is defined and registered. The THIS_MODULE macro is usually used for this area.
* **pd** : The protocol specifies the packets the function wants to receive, and here we use NFPROTO_IPV4 to receive IPv4 packets.(The rest of the protocols can be found in the [linux/socket.h](https://github.com/torvalds/linux/blob/master/include/linux/socket.h) file.
* **hooknum** : Indicates the point where you want to record the hook. Must be one of the values mentioned above. Here we use ```NF_INET_PRE_ROUTING``` to get all incoming packets.
* **priority** : To specify the priority of this hook, we use the ```NF_IP_PRI_FIRST``` macro value here.

## Linux/netfilter.h([Link](https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h))

---

## Building the Module Code
A Makefile is required to build the kernel module — in fact, it is a special kbuild Makefile. The kbuild Makefile required to build the kernel module.
Makefile Required to Build the LKM

```Makefile
obj-m+=module_name.o

all:
 make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
 make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
 ```
 The first line of this Makefile is called a goal definition and it defines the module to be built (module_name.o).  
 The syntax is surprisingly intricate, for example ```obj-m ```defines a ```loadable module``` goal, whereas ```obj-y``` indicates a ```built-in object``` goal. The syntax becomes more complex when a module is to be built from multiple objects, but this is sufficient to build this example LKM.  
   
The reminder of the Makefile is similar to a regular Makefile.  
The ```$(shell uname -r)``` is a useful call to return the current kernel build version — this ensures a degree of portability for the Makefile.  
The ```-C``` option switches the directory to the kernel directory before performing any make tasks.  
The ```M=$(PWD)``` variable assignment tells the **make** command where the actual project files exist.  
The ```modules``` target is the default target for external kernel modules.  
An alternative target is ```modules_install``` which would install the module (the **make** command would have to be executed with superuser permissions and the module installation path is required).

---

## Testing the LKM
This module can now be loaded using the kernel module tools as follows:
```bash
$ make
$ sudo insmod module_name.ko
```

To see list of all module :
```bash
$ lsmod
```
You can get information about the module using the modinfo command, which will identify the description, author and any module parameters that are defined:
```bash
$ modinfo module_name.ko
```
### The module can be unloaded using the rmmod command:
```bash
$ sudo rmmod module_name.ko
```
You can repeat these steps and view the output in the kernel log that results from the use of the ```printk()``` function. I recommend that you use a second terminal window and view the output as your LKM is loaded and unloaded, as follows:
```bash
$ journalctl -f
```

#### To clean up the module :
```bash
$ make clean
```
------


## Authors

**mahdi heidari** - [mahdi2019](https://github.com/mahdi2019)

---

## License

This project is licensed under the MIT License. [![License](https://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

---

## Task-Lists
- [x] complete code
- [ ] complete Document

---

## Realted Link
* Writing a Linux Kernel Module — Part 1: Introduction([Link](http://derekmolloy.ie/writing-a-linux-kernel-module-part-1-introduction/))
* Writing a Linux Kernel Module — Part 2: A Character Device[Link](http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/))  
* Roll Your Own Firewall with Netfilter([Link](https://www.linuxjournal.com/article/7184l))  
* چگونه یک فایروال بنویسیم؟([Link](http://zaghaghi.blog.ir/1392/10/19/how-to-write-your-own-firewall))  
=========================================  
   ## Printk
1. How to get printk format specifiers right([Link](https://www.kernel.org/doc/Documentation/printk-formats.txt))
2. Debugging by Printing([Link](http://www.makelinux.net/ldd3/chp-4-sect-2.shtml))
3. Debugging by printing([Link](https://elinux.org/Debugging_by_printing))  
=========================================


