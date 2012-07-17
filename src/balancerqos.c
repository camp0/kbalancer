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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../include/ioctlkbalancer.h"
#include <errno.h>
#define ERROR -1

extern int errno;

void main (int argc, char **argv) {
	int fd,ret,cmd,policy;
	struct user_kbalancer_dev user;

	if (argc != 4) {
		fprintf(stderr,"Use: %s <init|set> <device> <linkquality>\n",argv[0]);
		exit(-1);
	}
	fd = open("/dev/kbalancer",O_RDWR);
	if (fd == ERROR) {
		perror("open:");
		exit(-1);
	}
	cmd = -1;
	if (strcmp(argv[1],"set") == 0)
		cmd = KBALANCER_IOSETQOS;
	if (strcmp(argv[1],"init") == 0)
		cmd = KBALANCER_IOINITQOS;	

	snprintf(user.dev_name,MAX_NAME,"%s",argv[2]);
	user.policy = 0; 
	user.bid = 0;
	user.link_quality = atoi(argv[3]);

	ioctl(fd,cmd,&user);
	 
	close(fd);
}	
