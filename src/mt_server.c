/* mt_server.c

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

#include "mt_server.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "debug.h"
#include "iolib.h"

#define MAX_THREAD_WAIT 3

static void
client_thread_cleanup(void *arg)
{
	client_thread_t *ct = (client_thread_t *)arg;

	DEBUG_CMD(printf("client_thread_cleanup: cleaning up ...\n"));

	close(ct->socket);
	if ( ct->buffer )
		free(ct->buffer);
	sem_destroy(&ct->awake);
	sem_wait(ct->isthreadalive);
}

static inline void
client_handle(client_thread_t *ct)
{
	ssize_t wr_size;

	do {
		DEBUG_CMD2(printf("client_handle: reading ...\n"));
		if ( iolib_read(ct->socket,ct->buffer,ct->rd_size,&ct->timeout) <= 0 )
			break;
		DEBUG_CMD2(printf("client_handle: calling buffer operation ...\n"));
		if ( (wr_size = ct->bufop(ct->buffer,ct->rd_size,ct->buffer)) <= 0 )
			break;
		DEBUG_CMD2(printf("client_handle: writing ...\n"));
		if ( iolib_write(ct->socket,ct->buffer,wr_size,&ct->timeout) < (int)wr_size )
			break;
	} while( ct->persistent );
}

#ifdef HAVE_LIBSSL
static inline void
client_handle_ssl(client_thread_t *ct)
{
	ssize_t wr_size;

	do {
		DEBUG_CMD2(printf("client_handle_ssl: reading ...\n"));
		if ( iolib_ssl_read(ct->ssl,ct->socket,ct->buffer,ct->rd_size,&ct->timeout) < (int)ct->rd_size )
			break;
		DEBUG_CMD2(printf("client_handle_ssl: calling buffer operation ...\n"));
		if ( (wr_size = ct->bufop(ct->buffer,ct->rd_size,ct->buffer)) <= 0 )
			break;
		DEBUG_CMD2(printf("client_handle_ssl: writing ...\n"));
		if ( iolib_ssl_write(ct->ssl,ct->socket,ct->buffer,wr_size,&ct->timeout) < (int)wr_size )
			break;

	} while( ct->persistent );
}

static inline void
client_ssl_destroy(client_thread_t *ct)
{
	SSL_shutdown(ct->ssl);
	SSL_free(ct->ssl);
}

static inline int
client_ssl_init(client_thread_t *ct)
{
	BIO *sbio = NULL;
	if ( (ct->ssl = SSL_new(ct->ssl_ctx)) == NULL )
		return -1;
	if ( (sbio = BIO_new_socket(ct->socket,BIO_NOCLOSE)) == NULL )
	{
		SSL_free(ct->ssl);
		return -1;
	}
	SSL_set_bio(ct->ssl,sbio,sbio);
	if ( iolib_ssl_accept(ct->ssl,ct->socket,&ct->timeout) <= 0 )
	{
		client_ssl_destroy(ct);
		return -1;
	}
	return 0;
}
#endif

static void *
client_thread_run(void *arg)
{
	sigset_t blksigs;
	client_thread_t *ct = (client_thread_t *)arg;

	DEBUG_CMD(printf("client_thread_run: running ...\n"));

	sigemptyset(&blksigs);
	sigaddset(&blksigs,SIGINT);
	sigaddset(&blksigs,SIGQUIT);
	sigaddset(&blksigs,SIGHUP);
	pthread_sigmask(SIG_BLOCK,&blksigs,NULL);

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	pthread_cleanup_push(client_thread_cleanup,arg);
	sem_post(ct->isthreadalive);
	while( 1 )
	{
		sem_wait(&ct->awake);

		DEBUG_CMD2(printf("client_thread_run: handling client ...\n"));
#ifdef HAVE_LIBSSL
		if ( ct->ssl_ctx && client_ssl_init(ct) == 0 )
		{
			client_handle_ssl(ct);
			client_ssl_destroy(ct);
		}
		else
#endif
			client_handle(ct);
		DEBUG_CMD2(printf("client_thread_run: closing client ...\n"));
		close(ct->socket);
		ct->socket = -1;
		ct->state = IDLE;
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static int
client_thread_start(client_thread_t *ct,sem_t *st,size_t rd_size,struct timeval *timeout,char persistent,client_thread_op op)
{
	if ( (ct->buffer = malloc(rd_size)) == NULL )
		return -1;
	ct->state = IDLE;
	ct->isthreadalive = st;
	ct->rd_size = rd_size;
	ct->persistent = persistent;
	ct->bufop = op;
	memcpy(&ct->timeout,timeout,sizeof(struct timeval));
	pthread_attr_init(&ct->thread_attr);
	if ( sem_init(&ct->awake,0,0) != 0 )
		goto error;
	if ( pthread_create(&ct->thread,&ct->thread_attr,client_thread_run,ct) != 0 )
		goto thread_error;
	return 0;

thread_error:
	sem_destroy(&ct->awake);
error:
	free(ct->buffer);
	return -1;
}

static void
client_threads_stop(mt_server_t *server,unsigned int n)
{
	unsigned int i;
	int sem_val;

	if ( server->c_threads == NULL )
		return;
	// Sleep until all threads report in
	do {
		if ( sem_getvalue(&server->ct_status,&sem_val) != 0 )
			break;
		if ( sem_val < 0 || sem_val == (int)server->t_num )
			break;
		sleep(1);
	} while( 1 );
	for(i = 0; i < n ;i++)
		pthread_cancel(server->c_threads[i].thread);
	// Sleep until all threads have terminated
	for(i = 0 ; i < MAX_THREAD_WAIT ;i++)
	{
		if ( sem_getvalue(&server->ct_status,&sem_val) != 0 )
			break;
		if ( sem_val <= 0)
			break;
		sleep(1);
	}
}

/*
static void
server_thread_cleanup(void *arg)
{
	mt_server_t *server = (mt_server_t *)arg;

	DEBUG_CMD2(printf("server_thread_cleanup: cleaning up ...\n"));
}
*/

static inline client_thread_t *
get_idle_thread(mt_server_t *server)
{
	unsigned int i;

	for(i = 0; i < server->t_num ;i++)
		if ( server->c_threads[i].state == IDLE )
			return &server->c_threads[i];
	return NULL;
}

static void *
server_thread_run(void *arg)
{
	sigset_t blksigs;
	int cli_sock;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len;
	client_thread_t *assigned_thread;
	mt_server_t *server = (mt_server_t *)arg;

	DEBUG_CMD(printf("server_thread_run: running ...\n"));

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	sigemptyset(&blksigs);
	sigaddset(&blksigs,SIGINT);
	sigaddset(&blksigs,SIGQUIT);
	sigaddset(&blksigs,SIGHUP);
	pthread_sigmask(SIG_BLOCK,&blksigs,NULL);

	//pthread_cleanup_push(server_thread_cleanup,arg);
	//pause();
	do {
		cli_addr_len = sizeof(cli_addr);
		if ( (cli_sock = accept(server->socket,(struct sockaddr *)&cli_addr,&cli_addr_len)) < 0 )
		{
			perror("server_thread_run: accept");
			break;
		}
		if ( (assigned_thread = get_idle_thread(server)) == NULL )
		{
			DEBUG_CMD(printf("server_thread_run: no available threads for client\n"));
			continue;
		}
		assigned_thread->state = BUSY;
		assigned_thread->socket = cli_sock;
		if ( assigned_thread->timeout.tv_sec || assigned_thread->timeout.tv_usec )
			fcntl(assigned_thread->socket,F_SETFL,O_NONBLOCK);
		sem_post(&assigned_thread->awake);
	} while( 1 );
	//pthread_cleanup_pop(1);

	return NULL;
}

static inline void
server_thread_stop(mt_server_t *server)
{
	pthread_cancel(server->thread);
}

static inline int
server_listen(mt_server_t *server)
{
	if ( (server->socket = socket(PF_INET,SOCK_STREAM,0)) < 0 )
		return -1;
	if ( bind(server->socket,(struct sockaddr *)&server->addr,sizeof(struct sockaddr_in)) < 0 )
		goto error;
	if ( listen(server->socket,(int)server->t_num) != 0 )
		goto error;
	return 0;

error:
	close(server->socket);
	server->socket = -1;
	return -1;
}



void
mt_server_stop(mt_server_t *server)
{
	server_thread_stop(server);
	client_threads_stop(server,server->t_num);
	close(server->socket);
}

int
mt_server_start(mt_server_t *server,size_t rd_size,struct timeval *timeout,char persistent,client_thread_op op)
{
	unsigned int i;

	if ( server_listen(server) != 0 )
		return -1;

	for(i = 0; i < server->t_num ;i++)
		if ( client_thread_start(&server->c_threads[i],&server->ct_status,rd_size,timeout,persistent,op) != 0 )
			goto client_thread_error;
	pthread_attr_init(&server->thread_attr);
	if ( pthread_create(&server->thread,&server->thread_attr,server_thread_run,server) != 0 )
		goto server_thread_error;
	return 0;

server_thread_error:
	server_thread_stop(server);
client_thread_error:
	client_threads_stop(server,i);
	return -1;
}

void
mt_server_free(mt_server_t *server)
{
	if ( server )
	{
		if ( server->c_threads )
			free(server->c_threads);
#ifdef HAVE_LIBSSL
		if ( server->ssl_ctx )
			SSL_CTX_free(server->ssl_ctx);
#endif 
		free(server);
		sem_destroy(&server->ct_status);
	}
}

mt_server_t *
mt_server_new(const char *hostname,int port,unsigned int t_num)
{
	mt_server_t *s;

	if ( (s = calloc(1,sizeof(mt_server_t))) == NULL )
		goto error;
	if ( (s->c_threads = calloc(t_num,sizeof(client_thread_t))) == NULL )
		goto error;
	if ( sem_init(&s->ct_status,0,0) != 0 )
		goto error;

	if ( hostname )
	{
		struct hostent *host;

		if ( (host = gethostbyname(hostname)) == NULL )
			goto error;
		memcpy(&s->addr.sin_addr.s_addr,host->h_addr,host->h_length);
	}
	else
		s->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	s->addr.sin_port = htons((unsigned short)port);
	s->addr.sin_family = PF_INET;
	s->t_num = t_num;
	s->socket = -1;
	
	return s;

error:
	mt_server_free(s);
	return NULL;
}

int
mt_server_use_SSL(mt_server_t *server,const char *keyfl,const char *certfl)
{
	unsigned int i;

#ifndef HAVE_LIBSSL
	errno = ENOPROTOOPT;
	return -1;
#else
	if ( server->socket >= 0 )
	{
		errno = EISCONN;
		return -1;
	}

  SSL_load_error_strings();
  SSL_library_init();

  if ( (server->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL )
  {
    errno = ENOMEM;
    return -1;
  }

  if ( SSL_CTX_use_PrivateKey_file(server->ssl_ctx,keyfl,SSL_FILETYPE_PEM) <= 0 )
    goto ssl_error;
  if ( SSL_CTX_use_certificate_chain_file(server->ssl_ctx,certfl) <= 0 )
    goto ssl_error;

	for(i = 0; i < server->t_num ;i++)
		server->c_threads[i].ssl_ctx = server->ssl_ctx;

  return 0;

ssl_error:
	errno = EPROTO;
	return -1;
#endif
}
