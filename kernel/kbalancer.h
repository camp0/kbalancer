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
#define TRUE 1
#define FALSE 0

#define MODULE_NAME "kbalancer"

#define KBALANCER_MAJOR 0 /* Dynamic Registration */

#define MAX_PROC_BUFFER 256

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)) 
#define DEV_GET_BY_NAME(DEV_NAME) dev_get_by_name(&init_net, DEV_NAME) 
#else 
#define DEV_GET_BY_NAME(DEV_NAME) dev_get_by_name(DEV_NAME) 
#endif 

#ifndef NF_IP6_PRE_ROUTING
#define NF_IP6_PRE_ROUTING	0
#endif

/* Global Policies */
enum {
        GLOBAL_POLICY_MASTER_SLAVE = 0,
        GLOBAL_POLICY_SINGLE,
        GLOBAL_POLICY_BALANCER,
	GLOBAL_POLICY_BALANCER_SLAVE, 	/* when 2 masters works and 1 slave */
	GLOBAL_POLICY_BALANCER_MASTER, 	/* when 2 slaves works and 1 master */
	GLOBAL_POLICY_ADAPTATIVE,	/* for adaptative management */
	GLOBAL_POLICY_ADAPTATIVE_DROP,	/* drop adaptative */
	GLOBAL_POLICY_DROP
};

struct kbalancer_policy_description {
	int masters;
	int slaves;
	int global_policy;
};

struct kbalancer_policy_description kbalancer_policy_descriptions [] = {
/*    Master  Slave 	Policie */	
	{0,	0,	GLOBAL_POLICY_DROP },
	{0,	1,	GLOBAL_POLICY_SINGLE },
	{1,	0,	GLOBAL_POLICY_SINGLE },
	{1,	1,	GLOBAL_POLICY_MASTER_SLAVE},
	{2,	0,	GLOBAL_POLICY_BALANCER },
	{0,	2,	GLOBAL_POLICY_BALANCER },
	{2,	1,	GLOBAL_POLICY_BALANCER_SLAVE }, 
	{1,	2,	GLOBAL_POLICY_BALANCER_MASTER },
	{3,	0,	GLOBAL_POLICY_BALANCER },
	{0,	3,	GLOBAL_POLICY_BALANCER }	
};

#define KBALANCER_MAX_POLICY_DESCRIPTIONS 10 


struct kbalancer_policy {
        int policy;
        char *name;
        void (*function)(int *value);
};

struct kbalancer_device {
	int used; /* 0 used, 1 free */
        struct net_device *dev;
	struct proc_dir_entry *proc_entry;
	struct proc_dir_entry *proc_stats; /* for number of packets */
        int policy; /* 0 master, 1 slave */
        int bid;
	unsigned long __tcp_packets;
	unsigned long __dccp_packets;
	unsigned long __udp_packets;
	unsigned long __icmpv6_packets;
	unsigned long __tcp_bytes;
	unsigned long __dccp_bytes;
	unsigned long __udp_bytes;
	unsigned long __icmpv6_bytes;
	unsigned long __link_quality;
	int __balancer_flag;
	int __last_adaptative_packets;
	int __max_adaptative_packets;
};

struct kbalancer_rule {
	int protocol;
	int destination_port;
	int policy; 
	unsigned long __matches;
	struct list_head list;
};
