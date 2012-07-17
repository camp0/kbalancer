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

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../include/ioctlkbalancer.h"
#include <errno.h>
#define ERROR -1

#define VERSION "0.1"
#define IPPROTO_DCCP 33

void help(char *binary) {
	fprintf(stderr,"Device KBalancer Manager Control Rule "VERSION"\n");
	fprintf(stderr,"Use: %s <operation> [options]\n"
		"\tadd <protocol> <destination port> <to device>\n" 
		"\tdel <protocol> <destination port> <to device>\n" 
		"Examples:\n"
		"\t %s add tcp 80 master\n"
		"\t %s add dccp 800 master\n"
		"\t %s add icmpv6 0 slave\n"
		"\t %s add udp 5060 slave\n"
		"\t %s del tcp 22 master\n"
		,binary,binary,binary,binary,binary,binary); 
	return;
}

void send_to_driver(int cmd,struct user_kbalanacer_rule *user) {
	int fd;

	fd = open("/dev/kbalancer",O_RDWR);
        if (fd == ERROR) {
                perror("open:");
                exit(-2);
        }
	ioctl(fd,cmd,user);
        
        close(fd);
	return;
}

void main (int argc, char **argv) {
	int fd,ret,cmd;
	struct user_kbalancer_rule user;

	if (argc != 5) {
		help(argv[0]);
		exit(-1);
	}

	if (strcmp(argv[1],"add")== 0) 
		cmd = KBALANCER_IOADDRULE;
	if (strcmp(argv[1],"del") == 0) 
		cmd = KBALANCER_IODELRULE;

	if (strcmp(argv[2],"tcp") == 0) user.protocol = IPPROTO_TCP;
	if (strcmp(argv[2],"dccp") == 0) user.protocol = IPPROTO_DCCP;
	if (strcmp(argv[2],"udp") == 0) user.protocol = IPPROTO_UDP;
	if (strcmp(argv[2],"icmpv6") == 0) user.protocol = IPPROTO_ICMPV6;

	user.destination_port = atoi(argv[3]);
	user.to_device = -1;
	if (strcmp(argv[4],"master") == 0) 
		user.to_device = DEVICE_POLICY_MASTER;
	if (strcmp(argv[4],"slave") == 0)
		user.to_device = DEVICE_POLICY_SLAVE; 

	if (user.to_device == -1) {
		fprintf(stderr,"Unknow Policy\n");
		exit(-1);
	}
	send_to_driver(cmd,&user);
}	
