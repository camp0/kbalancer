/*
 *  kbalancer - Balance IPv6 Traffic between different Interfaces on Kernel Space.
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
 *  Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2007 
 *
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../include/ioctlkbalancer.h"
#include <errno.h>
#define ERROR -1
#define VERSION "0.1"

void help(char *binary) {
	fprintf(stderr,"Device KBalancer Manager Control "VERSION"\n");
	fprintf(stderr,"Use: %s <operation> [options]\n"
		"\tadd <device> <policy> <bid>\n" 
		"\tdel <device> \n" 
		"\tmod <device> <policy> <bid>\n"
		"\treset\n"
		"\tadaptative <on|off>\n\n"
		"Examples:\n"
		"\t %s add eth0 master 201\n"
		"\t %s del eth2 \n"
		"\t %s mod eth0 slave 203\n"
		"\t %s reset\n"
		,binary,binary,binary,binary,binary); 
	return;
}

void send_to_driver(int cmd,struct user_kbalanacer_dev *user) {
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
	int fd,ret,cmd,policy = -1;
	struct user_kbalancer_dev user;
	int adapctl;

	if (argc == 1) {
		help(argv[0]);
		exit(-1);
	}

	if (strcmp(argv[1],"add")== 0) {
		if (argc != 5) {
			help(argv[0]);
			exit(-1);
		}	
		cmd = KBALANCER_IOADDDEV;
	} 
	if (strcmp(argv[1],"del") == 0) {
		if (argc != 2) {
			help(argv[0]);
			exit(-1);
		} 
		cmd = KBALANCER_IODELDEV;
	}
	if (strcmp(argv[1],"mod") == 0) {
		if (argc != 5) {
			help(argv[0]);
			exit(-1);
		}	
		cmd = KBALANCER_IOMODDEV;
	}
	if (strcmp(argv[1],"reset") == 0) {
		cmd = KBALANCER_IORESET;
		send_to_driver(cmd,&user);
		exit (0);
	}	

	if (strcmp(argv[1],"adaptative") == 0) {
		if (argc != 3) {
			help(argv[0]);
			exit(-1);
		}
		if (strcmp(argv[2],"on")== 0)
			cmd = KBALANCER_IOADAPON;
		if (strcmp(argv[2],"off") == 0) 
			cmd = KBALANCER_IOADAPOFF;
		send_to_driver(cmd,&user);
		exit(0);
	}

	if (strcmp(argv[3],"master") == 0) 
		policy = DEVICE_POLICY_MASTER;
	if (strcmp(argv[3],"slave") == 0)
		policy = DEVICE_POLICY_SLAVE; 

	if (policy == -1) {
		fprintf(stderr,"Unknow Policy\n");
		exit(-1);
	}

	snprintf(user.dev_name,MAX_NAME,"%s",argv[2]);
	user.policy = policy; 
	user.bid = atoi(argv[4]);

	send_to_driver(cmd,&user);
}	
