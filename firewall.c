/**
 * @file    firewall.c
 * @author  mahdi heidari
 * @date    7 January 2020
 * @version 0.1
 * @brief  A network loadable kernel module (LKM) that can filtering receiving packet
 *    first read config file that in 
 *       first line Specify what type of filtering -whitelist or blacklist
 *       then each line have foramat of : source_ip:source_port
 * @see https://github.com/mahdi2019/firewall for a full description and follow-up descriptions.
*/
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/uaccess.h>        // Required for the copy to user function
#include <linux/time.h>
#include <linux/init.h>             // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>           // Core header for loading LKMs into the kernel    // Needed by all modules
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel   // Needed for KERN_INFO
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>     //Provides declarations for udp header
#include <linux/tcp.h>     //Provides declarations for tcp header
#include <linux/icmp.h>
#include <linux/ip.h>     //Provides declarations for ip header
#include <linux/inet.h>
#include <linux/if.h>
#include <linux/fs.h>      // Needed by filp
#include <linux/string.h>
#include <linux/semaphore.h>     //Provides declarations for semaphore
#include <linux/cdev.h>
#define  DEVICE_NAME "Mfirewall"    ///< The device will appear at /dev/Mfirewall using this value
#define  CLASS_NAME  "fire"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");              ///< The license type -- this affects runtime behavior
MODULE_AUTHOR("Mahdi Heidari");      ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux firewall(v1.0).");  ///< The description -- see modinfo
MODULE_VERSION("1.0");              ///< The version of the module

static char *name = "ٌWorld";        ///< An example LKM argument -- default value is "world"
module_param(name, charp, S_IRUGO); ///< Param desc. charp = char ptr, S_IRUGO can be read/not changed
MODULE_PARM_DESC(name, "The name to display in 'journalctl -f'");  ///< parameter description

static struct semaphore sem; // for time that two person want to set policy

static struct timespec time;  // for get time of receiving packet to print

static int    majorNumber;                   ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is received from userspace
static struct class*  MfirewallClass  = NULL; ///< The device-driver class struct pointer
static struct device* MfirewallDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int  dev_Open(struct inode *, struct file *);
static int  dev_release(struct inode *, struct file *);
//static ssize_t dev_read(struct file *, char *, size_t, loff_t *);  // not needed in this module
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops ={
   .open = dev_Open,
   .write = dev_write,
   .release = dev_release,
   //   .read = dev_read,     // not needed in this module
};


unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,const struct net_device *in, const struct net_device *out,int(*okfn)(struct sk_buff *));

static struct nf_hook_ops icmp_drop __read_mostly = {
        .pf = NFPROTO_IPV4,  // for set type of ip to hook
        .priority = NF_IP_PRI_FIRST, 
        .hooknum =NF_INET_LOCAL_IN,  
        .hook = (nf_hookfn *) icmp_hook
};

int No; // 0 for whitelist & 1 for blacklist
int list_num; // number of list
char list[100][25];  // limitation for list


/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init icmp_drop_init(void){
   int ret;
   sema_init( &sem, 1);  // initialized semaphore 
   printk(KERN_INFO "Mfirewall: Hello %s from the Mfirewall!\n", name);

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ERR "Mfirewall: failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "Mfirewall: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   MfirewallClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(MfirewallClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ERR "Mfirewall: Failed to register device class\n");
      return PTR_ERR(MfirewallClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "Mfirewall: device class registered correctly\n");

   // Register the device driver
   MfirewallDevice = device_create(MfirewallClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(MfirewallDevice)){               // Clean up if there is an error
      class_destroy(MfirewallClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ERR "Mfirewall: Failed to create the device\n");
      return PTR_ERR(MfirewallDevice);
   }
   printk(KERN_INFO "Mfirewall: device class created correctly\n"); // Made it! device was initialized



   ret = nf_register_net_hook(&init_net,&icmp_drop); /*Record in net filtering */
   if(ret)
      printk(KERN_INFO "FAILED");
   No = 1;  // default black list
   list_num = 0;  // at begin 0 itam for blocking
   return  ret;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit  icmp_drop_exit(void){  
   device_destroy(MfirewallClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(MfirewallClass);                          // unregister the device class
   class_destroy(MfirewallClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "Mfirewall: Bye %s from the Mfirewall! module unloaded\n", name);

   nf_unregister_net_hook(&init_net,&icmp_drop); /*UnRecord in net filtering */
}

static int dev_Open(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "Mfirewall: Device has been opened \n");
   down( &sem );  // Wait for semaphore to just one person can open character device for this module at same time
   return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   int i;
   int error_count = 0;
   // unsigned long copy_from_user( void *to, const void __user *from,unsigned long n);
   error_count = copy_from_user(message, buffer, len);
   if(message[0]=='b')
   {
      if(!No)
      {
         list_num=0;
         printk(KERN_ALERT "Mfirewall: policy changed to blacklist\n");
      }
      No = 1;
   }
   else if(message[0]=='w')
   {
      if(No)
      {
         list_num=0;
         printk(KERN_ALERT "Mfirewall: policy changed to whitelist\n");
      }
      No = 0;
   }
   else
   {
      message[len]='\0';
      for(i=0;i<list_num ;i++)
      {
         if( !strcmp(message ,list[i]))
         {
            printk(KERN_ALERT "Mfirewall: %s added later\n",message);
            return len;
         }
      }

      strncpy(list[list_num++],message,len);
      if(No)
         printk(KERN_ALERT "Mfirewall: add %s to %s\n",message , "blacklist");
      else
         printk(KERN_ALERT "Mfirewall: add %s to %s\n",message , "whitelist");
   }
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "Mfirewall: Device successfully closed\n");
   up( &sem );
   return 0;
}


unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,const struct net_device *in, const struct net_device *out,int(*okfn)(struct sk_buff *)){

   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;

   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;

   int i;
   char SOurce[25];

   if(!skb) 
      return NF_DROP;

   getnstimeofday(&time);
   printk(KERN_INFO "Mfirewall: received packet at time : %.2lu:%.2lu:%.2lu ", (time.tv_sec / 3600) % 24 , (time.tv_sec / 60) % 60, (time.tv_sec) % 60);
   if (ip_header->protocol==17)   // UDP
   {
      udp_header = (struct udphdr *)skb_transport_header(skb);
      src_port = (unsigned int)ntohs(udp_header->source);
      printk(KERN_DEBUG "Mfirewall: (UDP)IP addres = %pI4(%u)  DEST = %pI4\n", &src_ip, src_port , &dest_ip);
   } 
   else if (ip_header->protocol == 6)   // TCP
   { 
      tcp_header = (struct tcphdr *)skb_transport_header(skb);
      src_port = (unsigned int)ntohs(tcp_header->source);
      dest_port = (unsigned int)ntohs(tcp_header->dest);
      printk(KERN_DEBUG "Mfirewall: (TCP)IP addres = %pI4(%u)  DEST = %pI4\n", &src_ip, src_port , &dest_ip);
   }

   snprintf(SOurce, 25, "%pI4:%u", &ip_header->saddr, src_port); // Mind the &!
   if(No)
   {
      for(i=0;i<list_num ;i++)
         if( !strcmp(SOurce ,list[i]) )
         {
            printk(KERN_ALERT "Mfirewall: packet drop - %s is in black list", SOurce);
            return NF_DROP;
         }
      printk(KERN_DEBUG "Mfirewall: packet accept - %s isn't in black list", SOurce);
      return NF_ACCEPT;
   }
   else
   {
      for(i=0;i<list_num ;i++)
         if( !strcmp(SOurce ,list[i]) )
         {
            printk(KERN_DEBUG "Mfirewall: packet accept - %s is in white list", SOurce);
            return NF_ACCEPT;
         }
      printk(KERN_ALERT "Mfirewall: packet drop - %s isn't in white list", SOurce);
      return NF_DROP;
   }
   return NF_ACCEPT;

}



/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(icmp_drop_init);
module_exit(icmp_drop_exit);
