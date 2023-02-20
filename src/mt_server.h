/* mt_server.h

  Copyright 2004  Georgios Portokalidis <digital_bull@users.sourceforge.net>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef MT_SERVER_H
#define MT_SERVER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

#define IDLE 0
#define BUSY 1

typedef ssize_t (*client_thread_op)(const unsigned char *,size_t,unsigned char *);

struct client_thread
{
	pthread_t thread;
	pthread_attr_t thread_attr;

	int socket;
	struct timeval timeout;
	size_t rd_size;
	unsigned char *buffer;
	client_thread_op bufop;

	unsigned int state;
	char persistent;
	sem_t awake;
	sem_t *isthreadalive;

#ifdef HAVE_LIBSSL
	SSL_CTX *ssl_ctx;
	SSL *ssl;
#endif
};

typedef struct client_thread client_thread_t;

struct mt_server
{
	pthread_t thread;
	pthread_attr_t thread_attr;

	unsigned int t_num;
	client_thread_t *c_threads;
	sem_t ct_status;

	int socket;
	struct sockaddr_in addr;

#ifdef HAVE_LIBSSL
	SSL_CTX *ssl_ctx;
#endif
};

typedef struct mt_server mt_server_t;

mt_server_t *mt_server_new(const char *,int,unsigned int);
int mt_server_use_SSL(mt_server_t *,const char *,const char *);
extern inline void mt_server_free(mt_server_t *);
int mt_server_start(mt_server_t *,size_t,struct timeval *,char,client_thread_op);
extern inline void mt_server_stop(mt_server_t *);

#endif
