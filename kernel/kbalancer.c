/*
 *  kbalancer - Balance IPv6 Traffic between different Interfaces on Kernel Space.
 *
 *  Copyright (C) 2007 Luis Campo Giralte <luis.camp0.2009@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  In addition:
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
/*
 *  Changes:
 *
 *
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/kernel.h>   	/* printk() */
#include <linux/slab.h>   	/* kmalloc() */
#include <linux/proc_fs.h>	/* access /proc */
#include <linux/fs.h>       	/* everything... */
#include <linux/errno.h>    	/* error codes */
#include <linux/types.h>    	/* size_t */
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/list.h>

/* includes de networking */
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/dccp.h>

#include "kbalancer.h"
#include "../include/ioctlkbalancer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luis Campo Giralte (luis.camp0.2009@gmail.com)");
MODULE_DESCRIPTION("Balance IPv6 packets on Wireless Interfaces");

#define MAX_DEVICES 5 
#define MAX_LINK_QUALITY 100
#define MAX_BURST_ADAPTATIVE_PACKETS 10

#ifdef KBALANCER_DEBUG
# 	define KDEBUG(fmt, args...) printk( KERN_DEBUG MODULE_NAME ": " fmt, ## args) 
#else
#  	define KDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define KINFO(fmt, args...) printk (KERN_INFO MODULE_NAME ": " fmt, ## args) 

static struct nf_hook_ops netfilter_ops;
static char *device_name = "kbalancer";
static char *banner = "Mobile Ipv6 Balancer Module";
static int device_major = KBALANCER_MAJOR;
static int device_minor = 0;
static char *interface = NULL;
static char *ipv6_interface = NULL;
static struct in6_addr ipv6nemoaddr;

static int last_global_policy = GLOBAL_POLICY_MASTER_SLAVE;
static int global_policy = GLOBAL_POLICY_MASTER_SLAVE;
struct sk_buff *sock_buff;
struct kbalancer_rule k_rule_list;

struct kbalancer_device k_devices[MAX_DEVICES];
static int k_devices_n = 0;
static long dropped_packets = 0;
static long frag_dropped_packets = 0;

module_param (interface, charp, S_IRUSR);
MODULE_PARM_DESC(interface, "The main Interface");

module_param (ipv6_interface, charp, S_IRUSR);
MODULE_PARM_DESC(ipv6_interface,"The IPv6 Interface Address");

module_param (global_policy, int , S_IRUSR);
MODULE_PARM_DESC(global_policy, "The Global Policy");

static struct cdev kbalancerDev;
static struct proc_dir_entry *kbalancer_proc_entry;
static struct proc_dir_entry *kbalancer_proc_policy_entry;
static struct proc_dir_entry *kbalancer_proc_rules_entry;

/* Function Headers */
int PL_GetGlobalPolicy(int masters, int slaves);


/*
 * Utils Funcions 
 *
 */

int find_slot_device(char *name) {
        register int i;

        for (i= 0;i<MAX_DEVICES;i++)
                if (k_devices[i].used)
                        if(strcmp(k_devices[i].dev->name,name)== 0)
                                return i;
        return -1;
}

/*
 * Functions for Adaptative Management
 *
 */
static int CurrentAdaptativePacket = 0;
static int MaxAdaptativePackets = 0;

void kbalancer_update_adaptative_packets(char *by) {
	register int i;
	int ndevs = 0;

	CurrentAdaptativePacket = 0;
	MaxAdaptativePackets = 0;
	for (i = 0; i< MAX_DEVICES; i++) 
		if  ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev))){
			MaxAdaptativePackets +=  k_devices[i].__link_quality;
			ndevs ++;
			k_devices[i].__last_adaptative_packets = 0;
			k_devices[i].__balancer_flag = 0;
		}
	KINFO("Rechecking %d Devs for Adaptative %s Packets(%d)\n",ndevs,by,MaxAdaptativePackets);
	return;
}

/* 
 *
 * Functions for Manage the Policyes
 *
 */
static int PreviousPolicy = 0;
static int LastRunByPolicy = 0;

void *PL_PolicyAdaptative(int *value) {
        register int i;
	int available = 0;
	int choose = 0;
	int looplimit = 0;

	if (CurrentAdaptativePacket == MaxAdaptativePackets ) 
		kbalancer_update_adaptative_packets("Automatic");

	CurrentAdaptativePacket ++;

reschedule:

        for (i=0;i< k_devices_n ;i++)
                if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev)))
			if((k_devices[i].__last_adaptative_packets < k_devices[i].__link_quality)&&(k_devices[i].__balancer_flag == 0)){
				available ++;
				choose = i;
				break;
			}
	looplimit ++;
	if (available == 0){
		if (looplimit > 1) {
			KINFO("DROPING Packets on Adaptative Mode\n");
			(*value) = -1;
			return 0;
		}
               	for(i = 0;i<k_devices_n; i++) k_devices[i].__balancer_flag = 0;
		goto reschedule;
	}
	k_devices[choose].__balancer_flag = 1;
	k_devices[choose].__last_adaptative_packets ++;
	(*value) = choose;
	return 0;
}

/* One Master and One Slave */
void *PL_PolicyMasterSlave(int *value) {
        register int i;

	(*value) = PreviousPolicy;
	for (i=0;i< k_devices_n;i++)
               	if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)){
			if ((k_devices[i].policy == DEVICE_POLICY_MASTER)&&
				netif_carrier_ok(k_devices[i].dev))
			{
                        	
				(*value) = i;
				k_devices[i].__balancer_flag = 0;
				PreviousPolicy = i;
                        	return 0; 
                	}else
				(*value) = i;
		}
        
        KDEBUG("OverFlow on PL_PolicyMasterSlave, dev = %d\n",(*value));
        return 0;
}

void *PL_PolicyBalancer(int *value) {
        register int i;

        for (i=0;i< k_devices_n ;i++) 
               	if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev))) 
			if (!(k_devices[i].__balancer_flag))
			{
				k_devices[i].__balancer_flag = 1;
				(*value) = i;
				PreviousPolicy = i;
				if ( i + 1 == k_devices_n)
					for(i = 0;i<k_devices_n; i++) k_devices[i].__balancer_flag = 0;
				return 0;
			}
        
        (*value) = PreviousPolicy;
        KDEBUG("OverFlow on PL_PolicyBalancer!\n");
        return 0;
}

void *PL_PolicyBalancerAndSlave(int *value)  { /* 2 masters and 1 slave */
	register int i;

	for (i = 0;i< k_devices_n ;i++)
		if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev)))
			if (k_devices[i].policy == DEVICE_POLICY_MASTER)
				if ( i != PreviousPolicy ) {
					(*value ) = i;
					PreviousPolicy = i;
					return 0 ;
				}
	
	(*value ) = PreviousPolicy;
	return 0;
}

void *PL_PolicyBalancerAndMaster(int *value) { /* 2 slaves and 1 master */
	register int i;

	/* search if master is enabled */
        for (i = 0;i< k_devices_n ;i++)
                if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev)))
                        if (k_devices[i].policy == DEVICE_POLICY_MASTER)
			{
				(*value) = i;
				PreviousPolicy = i;
				return 0;
			}

	/* choose a slave device */	
        for (i = 0;i< k_devices_n ;i++)
                if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0)&&(netif_carrier_ok(k_devices[i].dev)))
                        if (k_devices[i].policy == DEVICE_POLICY_SLAVE)
                                if ( i != PreviousPolicy ) {
                                        (*value ) = i; 
                                        PreviousPolicy = i;
                                        return 0;
                                }

        (*value ) = PreviousPolicy;
        return 0;
}

void *PL_PolicySingle(int *value) {
        register int i;

        for (i=0;i< k_devices_n ;i++) 
               	if (k_devices[i].used) 
			if (k_devices[i].__link_quality > 0){
                        	(*value) = i;
                        	PreviousPolicy = i;
                        	return 0;
               		}
        
        KDEBUG("OverFlow on PL_PolicySingle!\n");
        (*value) = PreviousPolicy;
        return 0;
}

void *PL_PolicyDrop(int *value) {
	(*value) = 0; 
        KDEBUG("Dropping Packets!\n");
	return 0;
}

int PL_GetGlobalPolicy(int masters, int slaves) {
	register int i;

	for (i = 0 ; i < KBALANCER_MAX_POLICY_DESCRIPTIONS ;i ++)
		if ((kbalancer_policy_descriptions[i].masters == masters)&&
			(kbalancer_policy_descriptions[i].slaves == slaves))
			return kbalancer_policy_descriptions[i].global_policy;
	return GLOBAL_POLICY_SINGLE; 
}


void PL_UpdateGlobalPolicy() {
        register int i;
        int masters, slaves;
        int policy;

        masters = 0;
	slaves = 0;

        for (i=0;i< MAX_DEVICES ;i++)
		if(k_devices[i].used) 
                	if (k_devices[i].__link_quality > 0){
                        	if (k_devices[i].policy == DEVICE_POLICY_MASTER) masters++;
                        	if (k_devices[i].policy == DEVICE_POLICY_SLAVE) slaves++;
                	}
        
	KDEBUG("Updating Global Policy Master=%d, Slaves= %d\n",masters,slaves);
        policy = PL_GetGlobalPolicy (masters,slaves);
        global_policy = policy;

        return;
}

struct kbalancer_policy kpolicies [] = {
        { GLOBAL_POLICY_MASTER_SLAVE,           "Master and Slave         ",    (void*)&PL_PolicyMasterSlave },
        { GLOBAL_POLICY_SINGLE,                 "Single                   ",    (void*)&PL_PolicySingle } ,
        { GLOBAL_POLICY_BALANCER,               "Balancer                 ",    (void*)&PL_PolicyBalancer },
        { GLOBAL_POLICY_BALANCER_SLAVE,         "Balancer and Slave       ",    (void*)&PL_PolicyBalancerAndSlave },
        { GLOBAL_POLICY_BALANCER_MASTER,        "Balancer and Master      ",    (void*)&PL_PolicyBalancerAndMaster },
        { GLOBAL_POLICY_ADAPTATIVE,        	"Adaptative               ",    (void*)&PL_PolicyAdaptative },
        { GLOBAL_POLICY_DROP,                   "Warning: Drop            ",    (void*)&PL_PolicyDrop }
};

int PL_GetPolicyIndex() {
        int index;

        kpolicies[global_policy].function(&index);
        return index;
}

/* 
 * Functions for Manage the /proc files
 *
 *
 */

int kbalancer_proc_rules_read(char *buf, char **start, off_t offset, int count, int *eof, void *data){ 
	int len;
        struct kbalancer_rule *rule;
        struct list_head *pos;
	
	len = 0;
        list_for_each (pos, &k_rule_list.list) {
                rule = list_entry(pos, struct kbalancer_rule, list);
		len += sprintf(buf + len,"%d %d %d %d\n",rule->protocol,rule->destination_port,rule->policy,rule->__matches);
        }
	*eof = 1;	
	return len;
}

int kbalancer_proc_policy_read(char *buf, char **start, off_t offset, int count, int *eof, void *data){ 
	int len;

	len = sprintf(buf,"Policy:%s Dropped Packets:%06d",kpolicies[global_policy].name,dropped_packets);

	return len;
}

int kbalancer_proc_read(char *buf, char **start, off_t offset, int count, int *eof, void *data){ 
	int slot = (long)data;
	int len;
	char *strpolicy = "";

	if (k_devices[slot].policy == DEVICE_POLICY_MASTER)
		strpolicy = "Master";
	if (k_devices[slot].policy == DEVICE_POLICY_SLAVE)
		strpolicy = "Slave";

        len = sprintf(buf,"%d %d %d %d %d %d %d %d %d %d %d\n",
                        (int)k_devices[slot].bid,
                        (int)k_devices[slot].policy,
                        (int)k_devices[slot].__tcp_packets,
                        (int)k_devices[slot].__dccp_packets,
                        (int)k_devices[slot].__udp_packets,
                        (int)k_devices[slot].__icmpv6_packets,
                        (int)k_devices[slot].__link_quality,
                        (int)k_devices[slot].__tcp_bytes,
                        (int)k_devices[slot].__dccp_bytes,
                        (int)k_devices[slot].__udp_bytes,
                        (int)k_devices[slot].__icmpv6_bytes);

	return len;
}

/*
 * Functions for Manage the Array of kbalancer_devices 
 *
 */
void init_kbalancer_devices() {
	register int i;

	for (i = 0;i< MAX_DEVICES;i++){
		k_devices[i].used = 0;	
		k_devices[i].dev = NULL;
		k_devices[i].policy = 0;
		k_devices[i].bid = 0;
		k_devices[i].__link_quality = MAX_LINK_QUALITY;
		k_devices[i].__balancer_flag = 0;
		k_devices[i].__last_adaptative_packets = 0;
		k_devices[i].__max_adaptative_packets = 0;
	}
	return;
}

int find_free_device() {
	register int i;

	for (i = 0;i<MAX_DEVICES;i++)
		if (k_devices[i].dev == NULL)
			return i;

	return -1;
}

void __free_device(int slot) {
	
	remove_proc_entry("stats",k_devices[slot].proc_entry);
        remove_proc_entry(k_devices[slot].dev->name,kbalancer_proc_entry);

        k_devices[slot].used = 0;
        k_devices[slot].dev = NULL;
        k_devices_n --;
	return ;
}

int del_kbalancer_device (char *name) {
	int slot;

	slot = find_slot_device(name);
	if (slot == -1) 
		return -1;	

	__free_device(slot);
	
	return 0;
}

int mod_kbalancer_device (char *name, int policy, int bid) {
	int slot;

	slot = find_slot_device(name);
	if (slot == -1)
		return -EINVAL;

	if ((policy != DEVICE_POLICY_MASTER)&&(policy != DEVICE_POLICY_SLAVE)) {
                KDEBUG("Unknown Policy\n");
                return -EINVAL;
        }
	
	k_devices[slot].policy = policy;
	k_devices[slot].__balancer_flag = 0;
	return 0;
}

int mod_linkquality_devices (char *name, int link_quality) {
	int slot;

	slot = find_slot_device(name);
	if (slot == -1)
		return -EINVAL;

	k_devices[slot].__balancer_flag = 0;	
	k_devices[slot].__last_adaptative_packets = 0;
	k_devices[slot].__link_quality = (long)link_quality;
	k_devices[slot].__max_adaptative_packets = (long)link_quality;

	kbalancer_update_adaptative_packets("Manual");
	return 0;
}	

int add_kbalancer_device (char *name, int policy ,int bid) {
	int slot ;

	if (strcmp(name,interface) == 0) {
		KINFO("Device %s can not be Inside Nemo Device\n",name);
		return -EINVAL;
	}

	if ((policy != DEVICE_POLICY_MASTER)&&(policy != DEVICE_POLICY_SLAVE)) {
		KINFO("Unknown Policy\n");
		return -EINVAL; 
	}

	slot = find_free_device();
	k_devices[slot].dev = DEV_GET_BY_NAME(name);
	if (k_devices[slot].dev == NULL) {
		KINFO("Unknown %s Device\n",name);
                return -EINVAL;
        }
	k_devices[slot].__tcp_packets = 0;	
	k_devices[slot].__dccp_packets = 0;	
	k_devices[slot].__udp_packets = 0;	
	k_devices[slot].__icmpv6_packets = 0;
	k_devices[slot].__tcp_bytes = 0;	
	k_devices[slot].__dccp_bytes = 0;	
	k_devices[slot].__udp_bytes = 0;	
	k_devices[slot].__icmpv6_bytes = 0;
	k_devices[slot].__link_quality = MAX_LINK_QUALITY;	
	k_devices[slot].__balancer_flag = 0;
	
	k_devices[slot].proc_entry = proc_mkdir(name,kbalancer_proc_entry);
	k_devices[slot].proc_stats = create_proc_read_entry("stats",
		0,k_devices[slot].proc_entry,kbalancer_proc_read,(void*)slot);
	
	k_devices[slot].used = 1;	
	k_devices[slot].policy = policy;
	k_devices[slot].bid = bid;
	k_devices_n ++;
	return 0;
} 

int find_running_device_by_policy(int policy) {
	register int i;
	int value = -1;
	int n_devices = 0;

	if (global_policy == GLOBAL_POLICY_BALANCER)
		return -1; 

	for (i= 0;i< k_devices_n ;i++) 
		if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0))
			if (netif_carrier_ok(k_devices[i].dev))
				if (k_devices[i].policy == policy) {
					value = i;
					n_devices ++;
				}

	if (n_devices == 1)
		return value;

	/* more devices to choose */

	for (i= 0;i< k_devices_n ;i++) 
		if ((k_devices[i].used)&&(k_devices[i].__link_quality > 0))
			if (k_devices[i].dev->flags & IFF_RUNNING){
				if ((k_devices[i].policy == policy)&&(LastRunByPolicy != i)){
					LastRunByPolicy = i; 
					return i;
				}
			}
	return value;
}	

void free_all_devices() {
	register int i;

	for (i = 0;i<k_devices_n;i++) 
		__free_device(i);
	return;
}	

/*
 * Functions for manages the Linked Rule List 
 *
 */

static void init_kbalancer_rules () {
	INIT_LIST_HEAD(&k_rule_list.list);
}

static void free_kbalancer_rules() {
	struct kbalancer_rule *rule;
	struct list_head *pos, *q;

	list_for_each_safe(pos,q,&k_rule_list.list) {
		rule = list_entry(pos, struct kbalancer_rule, list);
		list_del(pos);
		kfree(rule);
	}
}

int add_kbalancer_rule(int protocol, int destination_port, int policy) {
	struct kbalancer_rule *rule;
	struct list_head *pos;

	list_for_each (pos, &k_rule_list.list) {
		rule = list_entry(pos, struct kbalancer_rule, list);
		if ((rule->protocol == protocol )&&(rule->destination_port == destination_port))
			return -1;
	}
	rule = (struct kbalancer_rule*)kmalloc(sizeof(struct kbalancer_rule),GFP_KERNEL);
	if (rule == NULL)
		return -1;
	rule->protocol = protocol;
	rule->destination_port = destination_port;
	rule->policy = policy;
	rule->__matches = 0;	
	list_add(&(rule->list),&(k_rule_list.list));
	return 0;
}

int del_kbalancer_rule (int protocol,int destination_port) {
	struct kbalancer_rule *rule;
	struct list_head *pos,*q;

	list_for_each_safe(pos,q,&k_rule_list.list) {
		rule = list_entry(pos, struct kbalancer_rule, list);
               	if ((rule->protocol == protocol)&&(rule->destination_port == destination_port)) {
			list_del(pos);
                	kfree(rule);
			return 0;
		}
        }
	return -1;
}

struct kbalancer_rule *search_kbalancer_policy_rule ( int protocol, int destination_port) {
	struct kbalancer_rule *rule;
        struct list_head *pos;

        list_for_each (pos, &k_rule_list.list) {
                rule = list_entry(pos, struct kbalancer_rule, list);
              	if ((rule->protocol == protocol )&&(rule->destination_port == destination_port)) {
	//		KDEBUG("Search Rule for Protocol = %d and Destination Port = %d\n",protocol,destination_port,NULL);	
			return rule;
		}
        }
	return NULL;
}


/*
 *
 *
 *
 */

void kbalancer_reset_counters() {
	register int i;
	struct kbalancer_rule *rule;
        struct list_head *pos;

        list_for_each (pos, &k_rule_list.list) {
                rule = list_entry(pos, struct kbalancer_rule, list);
                rule->__matches = 0;
        }

	dropped_packets = 0;
	frag_dropped_packets = 0;
	for (i = 0 ;i < k_devices_n ;i++) { 
		k_devices[i].__tcp_packets = 0;
		k_devices[i].__dccp_packets = 0;
        	k_devices[i].__udp_packets = 0;
        	k_devices[i].__icmpv6_packets = 0;	
		k_devices[i].__tcp_bytes = 0;
		k_devices[i].__dccp_bytes = 0;
        	k_devices[i].__udp_bytes = 0;
        	k_devices[i].__icmpv6_bytes = 0;	
	}
	return;
}

/*
 * Functions for Accesing to the Driver
 *
 */

static int kbalancer_device_open (struct inode *inode, struct file *filp)
{
	return 0;
}

static int kbalancer_device_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int kbalancer_device_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long args) {
	int retval;
	struct user_kbalancer_dev user_data;
	struct user_kbalancer_rule user_rule;

	retval = -ENOTTY;
	switch(cmd) {
		case KBALANCER_IOADDDEV :
			if (! capable (CAP_SYS_ADMIN))
                       		return -EPERM;	
			retval = copy_from_user(&user_data,(void*)args,sizeof(struct user_kbalancer_dev));
			if (retval == 0) {
				retval = add_kbalancer_device(user_data.dev_name,user_data.policy,user_data.bid);
				if (retval == 0) {
					KINFO("Adding %s Device, Policy = %d, Bid = %d\n",
						user_data.dev_name,user_data.policy,user_data.bid);
					PL_UpdateGlobalPolicy();
					return 0;
				} 
			}	
			break;
		case KBALANCER_IODELDEV:
			if (! capable (CAP_SYS_ADMIN))
                                return -EPERM;
                        retval = copy_from_user(&user_data,(void*)args,sizeof(struct user_kbalancer_dev));
                        if (retval == 0) {
				retval = del_kbalancer_device (user_data.dev_name);
				if (retval == 0) {
					KINFO("Removing %s Device\n",user_data.dev_name);
					PL_UpdateGlobalPolicy();
					return 0;
				}		
				KINFO("Can not Remove %s Device\n",user_data.dev_name);	
			}
			break;
		case KBALANCER_IOMODDEV:
			if (! capable (CAP_SYS_ADMIN))
                                return -EPERM;
                        retval = copy_from_user(&user_data,(void*)args,sizeof(struct user_kbalancer_dev));
                        if (retval == 0) {
                                retval = mod_kbalancer_device (user_data.dev_name,user_data.policy,user_data.bid);
                                if (retval == 0) {
                                        KINFO("Change %s Device, Policy = %d, Bid = %d\n",user_data.dev_name,
						user_data.policy,user_data.bid);
                                        PL_UpdateGlobalPolicy();
                                        return 0;
                                }
                                KINFO("Can not Change %s Device\n",user_data.dev_name);
                        }
                        break;
		case KBALANCER_IOSETQOS:
		case KBALANCER_IOINITQOS:
			if (! capable (CAP_SYS_ADMIN))
				return -EPERM;
                        retval = copy_from_user(&user_data,(void*)args,sizeof(struct user_kbalancer_dev));
                        if (retval == 0) {
                                retval = mod_linkquality_devices (user_data.dev_name,user_data.link_quality);
                                if (retval == 0) {
                                        KINFO("Init %s Device, Link Quality = %d\n",user_data.dev_name,
						user_data.link_quality);
					return 0;
				}
				KINFO("Can not Init %s Device Link Quality\n",user_data.dev_name);
			}
			break;
		case KBALANCER_IOADDRULE:
			if (! capable (CAP_SYS_ADMIN))
                                return -EPERM;
                        retval = copy_from_user(&user_rule,(void*)args,sizeof(struct user_kbalancer_rule));
                        if (retval == 0) {
                                retval = add_kbalancer_rule (user_rule.protocol,user_rule.destination_port,user_rule.to_device);
                                if (retval == 0) {
                                        KINFO("Adding Rule, Protocol %d Port %d Policy %d\n",user_rule.protocol,
                                                user_rule.destination_port,user_rule.to_device);
                                        return 0;
                                }
                                KINFO("Can not Add Rule\n"); 
                        }
			break;
		case KBALANCER_IODELRULE:
			if (! capable (CAP_SYS_ADMIN))
                                return -EPERM;
                        retval = copy_from_user(&user_rule,(void*)args,sizeof(struct user_kbalancer_rule));
                        if (retval == 0) {
                                retval = del_kbalancer_rule (user_rule.protocol,user_rule.destination_port);
                                if (retval == 0) {
                                        KINFO("Deleting Rule, Protocol %d Port %d\n",user_rule.protocol,
                                                user_rule.destination_port);
                                        return 0;
                                }
                                KINFO("Can not Delete Rule\n"); 
                        }
			break;
		case KBALANCER_IORESET:
			 if (! capable (CAP_SYS_ADMIN))
                                return -EPERM;
			kbalancer_reset_counters();
			retval = 0;
			break;
		case KBALANCER_IOADAPON:
			if (! capable (CAP_SYS_ADMIN))
				return -EPERM;
			if (global_policy == GLOBAL_POLICY_ADAPTATIVE) 
				return 0;
			last_global_policy = global_policy;
			global_policy = GLOBAL_POLICY_ADAPTATIVE;
			kbalancer_update_adaptative_packets("Starting");
			KINFO("Adaptative Mode On\n");
			retval = 0;
			break;
		case KBALANCER_IOADAPOFF:
			if (! capable (CAP_SYS_ADMIN))
				return -EPERM;
			if (global_policy == GLOBAL_POLICY_ADAPTATIVE) {
				global_policy = last_global_policy;
				KINFO("Adaptative Mode Off\n");
				retval = 0;
			}
			break;	
		default:
			return -ENOTTY;
	}	
	return retval;
}

/*
 * Set up the cdev structure for a device.
 */
static void kbalancer_setup_cdev(struct cdev *dev,
		struct file_operations *fops)
{
	int err, devno = MKDEV(device_major, device_minor);
    
	cdev_init(dev, fops);
	dev->owner = THIS_MODULE;
	dev->ops = fops;
	err = cdev_add (dev, devno, 1);
	/* Fail gracefully if need be */
	if (err)
		KINFO("Error %d adding %s%d", err,device_name, device_minor);
}


static struct file_operations kbalancer_file_operations = {
	.owner   = THIS_MODULE,
	.open    = kbalancer_device_open,
	.ioctl	 = kbalancer_device_ioctl,
	.release = kbalancer_device_release,
};

void kbalancer_packet_update_stats( int slot, int icmpv6,int tcp,int udp,int dccp,
	int icmpv6_bytes,int tcp_bytes,int udp_bytes,int dccp_bytes) {
	k_devices[slot].__tcp_packets += tcp; 
	k_devices[slot].__dccp_packets += dccp; 
	k_devices[slot].__udp_packets += udp; 
	k_devices[slot].__icmpv6_packets += icmpv6; 
	k_devices[slot].__tcp_bytes += tcp_bytes; 
	k_devices[slot].__dccp_bytes += dccp_bytes; 
	k_devices[slot].__udp_bytes += udp_bytes; 
	k_devices[slot].__icmpv6_bytes += icmpv6_bytes; 
	return;
}

static inline int ipv6_addr_equal(const struct in6_addr *a1,
				const struct in6_addr *a2)
{
	return (a1->s6_addr32[0] == a2->s6_addr32[0] &&
		a1->s6_addr32[1] == a2->s6_addr32[1] &&
                a1->s6_addr32[2] == a2->s6_addr32[2] &&
                a1->s6_addr32[3] == a2->s6_addr32[3]);
}

unsigned int kbalancer_packet_handler_hook(unsigned int hooknum,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
                  struct sk_buff *skb,
#else
                  struct sk_buff **skb,
#endif
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	struct ipv6hdr *ip6;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct dccp_hdr *dccp;
	int to_device;
	unsigned long mark = 0;
	int destination_port;
	int device_rule;
	char *proto_str = "none";
	char *rule_str = "";	
	int icmpv6_packet,icmpv6_packet_bytes;
	int tcp_packet,tcp_packet_bytes;
	int dccp_packet,dccp_packet_bytes;
	int udp_packet,udp_packet_bytes;
	struct kbalancer_rule *rule;
	
  	if(strcmp(in->name,interface) == 0){
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
		sock_buff = skb;
#else
		sock_buff = *skb;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21))	
		ip6 = (struct ipv6hdr*)sock_buff->network_header;
#else
		ip6 = sock_buff->nh.ipv6h;
#endif
		if (ipv6_addr_equal(&ipv6nemoaddr,&ip6->daddr)) {
			return NF_ACCEPT;
		}

		to_device = PL_GetPolicyIndex();
		if((global_policy == GLOBAL_POLICY_DROP)||(to_device == -1)){
			dropped_packets ++;
			return NF_DROP;
		}	
		if (to_device != -1) {
			mark = k_devices[to_device].bid;
			destination_port = 0;
			icmpv6_packet = 0;
			tcp_packet = 0;
			udp_packet = 0;
			dccp_packet = 0;
			icmpv6_packet_bytes = 0;
			tcp_packet_bytes = 0;
			udp_packet_bytes = 0;
			dccp_packet_bytes = 0;
			switch(ip6->nexthdr){
				case IPPROTO_ICMPV6:
					icmpv6_packet = 1;
					icmpv6_packet_bytes = sock_buff->len;
					proto_str = "icmpv6";
					break;
				case IPPROTO_TCP:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21))
					tcp = (struct tcphdr*)(sock_buff->transport_header);
#else
					tcp = (struct tcphdr*)(ip6 + sizeof(struct ipv6hdr));
#endif
					destination_port = ntohs(tcp->dest);
					proto_str = "tcp";
					tcp_packet_bytes = sock_buff->len;
					tcp_packet = 1;
					break;
				case IPPROTO_UDP:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21))
					udp = (struct udphdr*)(sock_buff->transport_header);
#else
					udp = (struct udphdr*)(ip6 + sizeof(struct ipv6hdr));
#endif
					destination_port = ntohs(udp->dest);
					proto_str = "udp";
					udp_packet_bytes = sock_buff->len;
					udp_packet = 1;
					break;
				case IPPROTO_DCCP:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21))
					dccp = (struct dccp_hdr*)(sock_buff->transport_header);
#else
					dccp = (struct dccp_hdr*)(ip6 + sizeof(struct dccp_hdr));
#endif
					destination_port = ntohs(dccp->dccph_dport);
					dccp_packet_bytes = sock_buff->len;
					proto_str = "dccp";
					dccp_packet = 1;
					break;
				case IPPROTO_FRAGMENT:
					frag_dropped_packets ++;
                        		return NF_DROP;
			}
			rule = search_kbalancer_policy_rule(ip6->nexthdr,destination_port); 	
			if (rule != NULL){
				device_rule = find_running_device_by_policy(rule->policy);
			//	printk("find_running (%d)\n",device_rule);
				if (device_rule != -1) {
			//		if (k_devices[device_rule].policy != k_devices[to_device].policy) {
						mark = k_devices[device_rule].bid;
						to_device = device_rule;
						rule->__matches ++;
						rule_str = "Rule Match ";
				}
			}

			kbalancer_packet_update_stats(to_device,icmpv6_packet,tcp_packet,udp_packet,dccp_packet,
				icmpv6_packet_bytes,tcp_packet_bytes,udp_packet_bytes,dccp_packet_bytes);	

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,16))
			sock_buff->nfmark = mark;
#else
			sock_buff->mark = mark;
#endif
//			KDEBUG("%sPacket %s:%d To device %s bid %d\n",rule_str,
//				proto_str,destination_port,k_devices[to_device].dev->name,(int)mark,NULL);
		}
		
	 }
	return NF_ACCEPT;
}


static int kbalancer_init(void)
{
	int result;
	dev_t dev = MKDEV(device_major, device_minor);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))&&(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
	KINFO("Kernel Version not supported for Kbalancer\n");
	return -1;
#endif
	if((interface == NULL)||(ipv6_interface == NULL)) {
                KINFO("Use insmod kbalancer interface=<dev> ipv6_interface=<ipv6address>\n");
                return -EINVAL;
        }
	result = in6_pton(ipv6_interface,-1,&ipv6nemoaddr,-1,NULL);
	if (result == 0) {
                KINFO("Can not assing address %s\n",ipv6_interface);
                return -EINVAL;
        }

	if (device_major)
		result = register_chrdev_region(dev, 1, device_name);
	else {
		result = alloc_chrdev_region(&dev, device_minor, 1, device_name);
		device_major = MAJOR(dev);
	}
	if (result < 0) {
		KINFO("%s: unable to get major %d\n",device_name, device_major);
		return result;
	}
	if (device_major == 0)
		device_major = result;

	kbalancer_setup_cdev(&kbalancerDev, &kbalancer_file_operations);

	netfilter_ops.hook              =       kbalancer_packet_handler_hook;
        netfilter_ops.pf                =       AF_INET6;
        netfilter_ops.hooknum           =       NF_IP6_PRE_ROUTING;
        netfilter_ops.priority          =       NF_IP6_PRI_FIRST;

	init_kbalancer_devices();

	init_kbalancer_rules();

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
	kbalancer_proc_entry = proc_mkdir(device_name,init_net.proc_net);
#else
	kbalancer_proc_entry = proc_mkdir(device_name,proc_net);
#endif
	kbalancer_proc_policy_entry = create_proc_read_entry("stats",0,kbalancer_proc_entry,kbalancer_proc_policy_read,NULL); 
	kbalancer_proc_rules_entry = create_proc_read_entry("rules",0,kbalancer_proc_entry,kbalancer_proc_rules_read,NULL); 
	
	nf_register_hook(&netfilter_ops);

	KINFO("Running %s with major = %d\n",banner,device_major);	
	KINFO("Nemo on %s with IPv6 %s\n",interface,ipv6_interface);	
	return 0;
}


static void kbalancer_cleanup(void)
{
	nf_unregister_hook(&netfilter_ops);
	cdev_del(&kbalancerDev);
	free_all_devices();
	unregister_chrdev_region(MKDEV(device_major, device_minor), 1); 
	free_kbalancer_rules();
	remove_proc_entry(device_name, kbalancer_proc_policy_entry);
	remove_proc_entry(device_name, kbalancer_proc_rules_entry);
	remove_proc_entry(device_name, NULL);	
	//remove_proc_entry(device_name, proc_net);	
	KINFO("Unload %s\n",banner);	
}

module_init(kbalancer_init);
module_exit(kbalancer_cleanup);
