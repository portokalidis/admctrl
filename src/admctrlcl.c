/* admctrlcl.c

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#if DEBUG > 1
#include <openssl/err.h>
#endif
#endif
#include "admctrlcl.h"
#include "shm.h"
#include "shm_sync.h"
#include "iolib.h"
#include "debug.h"

/*! \file admctrlcl.c
  \brief Contains the implementation for admission control clients
  \author Georgios Portokalidis
*/

/*************************************************************************/
/*                     	INTERNAL DATA STRUCTURES                         */
/*************************************************************************/

// Data for IPC communication
struct ipc_data
{
  int shm_id, //!< Shared memory id
  sem_id; //!< Semaphores id
  key_t key; //!< IPC id
  void *addr; //! Attached shared memory address
};

// Data for communication through sockets
struct socket_data
{
	char *server_hostname; //!< Server hostname
	int socket; //! Socket with server
	struct sockaddr_in in_addr; //! Internet address of server
#ifdef HAVE_LIBSSL
  SSL_CTX *ssl_ctx; //!< SSL context
  SSL *ssl; //!< SSL session
  //BIO *sbio; //! BIO for communication with server
	char use_CA; //! Use accepted CAs list
#endif
};


/*************************************************************************/
/*               	STATIC FUNCTIONS IMPLEMENTATION                        */
/*************************************************************************/

static void
free_socket_client(admctrlcl_t *client)
{	
	if ( client )
	{
		struct socket_data *sd = (struct socket_data *)client->comm;
		if ( sd )
		{
			if ( sd->server_hostname )
				free(sd->server_hostname);
			free(sd);
		}
		free(client);
	}
}

#ifdef HAVE_LIBSSL
static void
free_ssl_client(admctrlcl_t *client)
{
		struct socket_data *sd = (struct socket_data *)client->comm;

		if ( sd->ssl_ctx )
		{
			if ( sd->ssl )
				SSL_free(sd->ssl);
			SSL_CTX_free(sd->ssl_ctx);
		}
}
#endif

static void
free_ipc_client(admctrlcl_t *client)
{	
	if ( client )
	{
		if ( client->comm )
			free(client->comm);
		free(client);
	}
}

static int
socket_connect(admctrlcl_t *client)
{
	struct socket_data *sd = (struct socket_data *)client->comm;

	if ( (sd->socket = socket(PF_INET,SOCK_STREAM,0)) < 0 )
		return -1;
	if ( connect(sd->socket,(struct sockaddr *)&sd->in_addr,sizeof(struct sockaddr_in)) != 0 )
	{
		close(sd->socket);
		sd->socket = -1;
		return -1;
	}
	if ( client->timeout.tv_sec || client->timeout.tv_usec )
		fcntl(sd->socket,F_SETFL,O_NONBLOCK);

	DEBUG_CMD2(printf("socket_connect: connected\n"));

	return 0;
}

#ifdef HAVE_LIBSSL
static int
check_cert(SSL *ssl,const char *host)
{
	X509 *peer;
	char peer_CN[256];

	if( SSL_get_verify_result(ssl) != X509_V_OK )
	{
		DEBUG_CMD(fprintf(stderr,"check_cert: failed to verify servert certificate as X509\n"));
		return -1;
	}

	peer = SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName,
			peer_CN, 256);
	if ( strcasecmp(peer_CN,host) != 0 )
	{
		DEBUG_CMD(fprintf(stderr,"check_cert: certificate common name doesn't match host name"));
		return -1;
	}
	return 0;
}
#endif

#ifdef HAVE_LIBSSL
static int
ssl_connect(admctrlcl_t *client)
{
	BIO *sbio = NULL;
	struct socket_data *sd = (struct socket_data *)client->comm;

	if ( (sbio = BIO_new_socket(sd->socket,BIO_NOCLOSE)) == NULL )
	{
		errno = EPROTO;
		return -1;
	}
	SSL_set_bio(sd->ssl,sbio,sbio);
	if ( iolib_ssl_connect(sd->ssl,sd->socket,&client->timeout) <= 0 )
		goto shutdown;
	if ( sd->use_CA && check_cert(sd->ssl,sd->server_hostname) != 0 )
		goto shutdown;

	DEBUG_CMD2(printf("ssl_connect: handshake completed\n"));
	return 0;

shutdown:
	SSL_shutdown(sd->ssl);
	return -1;
}
#endif

static int
socket_close(admctrlcl_t *client)
{
	int e = 0;
	struct socket_data *sd = (struct socket_data *)client->comm;

	DEBUG_CMD2(printf("socket_close: closing ...\n"));
	e = close(sd->socket);
	sd->socket = -1;
	return e;
}

static void
ipc_expired(int data) 
{
	errno = ETIME;
}

static int
ipc_init(admctrlcl_t *client)
{
	struct ipc_data *id = (struct ipc_data *)client->comm;

	if ( (id->addr = shm_create(id->key,MAX(sizeof(adm_ctrl_request_t),sizeof(adm_ctrl_result_t)),&id->shm_id)) == NULL )
	{
		DEBUG_CMD2(perror("shm_create"));
		return -1;
	}
	if ( (id->sem_id = shm_create_sem(id->key)) < 0 )
	{
		DEBUG_CMD2(perror("shm_create_sem"));
		shm_destroy(id->addr,id->shm_id);
		return -1;
	}
	signal(SIGALRM,ipc_expired);
	return 0;
}

static int
ipc_destroy(admctrlcl_t *client)
{
	struct ipc_data *id = (struct ipc_data *)client->comm;

	signal(SIGALRM,SIG_DFL);

	if ( shm_destroy(id->addr,id->shm_id) )
		return -1;
	if ( shm_destroy_sem(id->sem_id) )
		return -1;

	return 0;
}

static int
do_comm_open(admctrlcl_t *client)
{
	struct socket_data *sd;

	switch( client->type )
	{
		case SOCKET_CL:
			sd = (struct socket_data *)client->comm;
			return socket_connect(client);
		case SSL_CL:
#ifdef HAVE_LIBSSL
			sd = (struct socket_data *)client->comm;
			if ( socket_connect(client) != 0 )
				return -1;
			if ( ssl_connect(client) != 0 )
			{
				socket_close(client);
				return -1;
			}
			return 0;
#else
			break;
#endif
		case IPC_CL:
			return ipc_init(client);
	}

	errno = ENOPROTOOPT;
	return -1;
}

#ifdef HAVE_LIBSSL
static void
ssl_close(admctrlcl_t *client)
{
	struct socket_data *sd = (struct socket_data *)client->comm;
	SSL_shutdown(sd->ssl);
}
#endif

static int
do_comm_close(admctrlcl_t *client)
{
	switch( client->type )
	{
		case SSL_CL:
#ifdef HAVE_LIBSSL
			ssl_close(client);
#else
			break;
#endif
		case SOCKET_CL:
			return socket_close(client);
		case IPC_CL:
			return ipc_destroy(client);
	}

	errno = ENOPROTOOPT;
	return -1;
}

static int
set_data(admctrlcl_t *client,adm_ctrl_request_t *req,adm_ctrl_result_t *res)
{
	if ( req )
		client->data.request = req;
	else 
	{
		if ( (client->data.request = calloc(1,sizeof(adm_ctrl_request_t))) == NULL )
			goto mem_error;
		client->data.free_request = 1;
	}

	if ( res )
		client->data.result = res;
	else 
	{
		if ( (client->data.result = calloc(1,sizeof(adm_ctrl_result_t))) == NULL )
			goto mem_error;
		client->data.free_result = 1;
	}

	return 0;

mem_error:
	if ( req == NULL && client->data.request )
	{
		free(client->data.request);
		client->data.request = NULL;
	}
	if ( res == NULL && client->data.result )
	{
		free(client->data.result);
		client->data.result = NULL;
	}
	return -1;
}

static int
ipc_submit(admctrlcl_t *client)
{
	int e = -1;
	struct ipc_data *id = (struct ipc_data *)client->comm;
	struct itimerval timer = { {0,0},
		{client->timeout.tv_sec,client->timeout.tv_usec} };

	if ( shm_lock(id->sem_id) != 0 )
		return -1;
	memcpy(id->addr,client->data.request,sizeof(adm_ctrl_request_t));
	if ( shm_data_ready(id->sem_id) != 0 )
		goto ipc_fail;
	setitimer(ITIMER_REAL,&timer,NULL);
	e = shm_result_wait(id->sem_id);
	bzero(&timer,sizeof(struct itimerval));
	setitimer(ITIMER_REAL,&timer,NULL);
	if ( e == 0 )
		memcpy(client->data.result,id->addr,sizeof(adm_ctrl_result_t));

ipc_fail:
	shm_unlock(id->sem_id);

	return e;
}



/*************************************************************************/
/*               	PUBLIC FUNCTIONS IMPLEMENTATION                        */
/*************************************************************************/


/** \brief Create a new admission control client that will be using IPC

	\param pathname pathname to use for IPC key generation
	\param id project id to use for IPC key generation
	\param persistent open a persistent connection to server, on admctrlcl_comm_open()
	\param timeout timeout to use when waiting for server response
	\param req reference to request structure to be used instead of allocating a new one (set to NULL to allocate)
	\param res reference to results structure to be used instead of allocating a new one (set to NULL to allocate)

	\return a new admission control client structure, or NULL on error. 
	errno is set by ftok() if the IPC key couldn't be generated
*/
admctrlcl_t *
admctrlcl_new_ipc(const char *pathname,int id,char persistent,struct timeval *timeout,adm_ctrl_request_t *req,adm_ctrl_result_t *res)
{
	key_t key;
	admctrlcl_t *client;
	struct ipc_data *comm = NULL;

	if ( (key = ftok(pathname,id)) < 0 )
		return NULL;

	if ( (client = calloc(1,sizeof(admctrlcl_t))) == NULL )
		goto mem_error;

	if ( (comm = calloc(1,sizeof(struct ipc_data))) == NULL )
		goto mem_error;

	if ( set_data(client,req,res) != 0 )
		goto mem_error;
	
	client->type = IPC_CL;
	comm->key = key;
	client->comm = comm;
	client->persistent = persistent;
	memcpy(&client->timeout,timeout,sizeof(struct timeval));

	return client;

mem_error:
	errno = ENOMEM;
	if ( client )
	{
		if ( comm )
			free(comm);
		free(client);
	}
	return NULL;
}

/** \brief Create a new admission control client that will be using sockets

	\param hostname server hostname
	\param port server port number
	\param persistent open a persistent connection to server, on admctrlcl_init()
	\param timeout timeout to use on I/O operations
	\param req reference to request structure to be used instead of allocating a new one (set to NULL to allocate)
	\param res reference to results structure to be used instead of allocating a new one (set to NULL to allocate)

	\return a new admission control client structure, or NULL on error. 
	errno is set to ENOMEM if no memory was available, 
	or is set by gethostbyname() if there was an error resolving the hostname
*/
admctrlcl_t *
admctrlcl_new_socket(const char *hostname,int port,char persistent,struct timeval *timeout,adm_ctrl_request_t *req,adm_ctrl_result_t *res)
{
	admctrlcl_t *client;
	struct socket_data *comm;
	struct hostent *hostaddr;

	if ( (client = calloc(1,sizeof(admctrlcl_t))) == NULL )
		goto mem_error;
	if ( (comm = calloc(1,sizeof(struct socket_data))) == NULL )
		goto mem_error;
	if ( (comm->server_hostname = strdup(hostname)) == NULL )
		goto mem_error;
	if ( set_data(client,req,res) != 0 )
		goto mem_error;

	if ( (hostaddr = gethostbyname(hostname)) == NULL )
		goto mem_error;
	bzero(&comm->in_addr,sizeof(struct sockaddr_in));
	memcpy(&comm->in_addr.sin_addr.s_addr,hostaddr->h_addr,hostaddr->h_length);
	comm->in_addr.sin_port = htons(port);
	comm->in_addr.sin_family = PF_INET;
	comm->socket = -1;

	memcpy(&client->timeout,timeout,sizeof(struct timeval));
	client->type = SOCKET_CL;
	client->persistent = persistent;
	client->comm = comm;

	return client;

mem_error:
	free_socket_client(client);
	errno = ENOMEM;
	return NULL;
}

/** \brief Enable SSL for an admission control client

	\param cl reference to admission control client
	\param key file containing SSL private key
	\param ca file containing SSL list of accepted CAs. Set to NULL to disable 

	\return 0 on success, or -1 on error.
	errno is set to ENOPROTOOPT if SSL was not enabled at compiled time,
	EISCONN if client is already connected, or to EPROTO if an SSL error occured.
	Use SSL library error functions to get exact error
*/
int
admctrlcl_use_SSL(admctrlcl_t *cl,const char *key,const char *ca)
{
#ifdef HAVE_LIBSSL
	if ( cl->type == SOCKET_CL )
	{
		struct socket_data *sd = (struct socket_data *)cl->comm;

		if ( sd->socket >= 0 )
		{
			errno = EISCONN;
			return -1;
		}

		SSL_load_error_strings();
		SSL_library_init();

		if ( (sd->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL )
			goto ssl_error;
		if ( (sd->ssl = SSL_new(sd->ssl_ctx)) == NULL )
			goto ssl_error;

		if ( SSL_CTX_use_PrivateKey_file(sd->ssl_ctx,key,SSL_FILETYPE_PEM) <= 0 )
			goto ssl_error;
		if ( ca )
		{
			if ( SSL_CTX_load_verify_locations(sd->ssl_ctx,ca,0) <= 0 )
				goto ssl_error;
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
			SSL_CTX_set_verify_depth(sd->ssl_ctx,1);
#endif
			sd->use_CA = 1;
		}

		cl->type = SSL_CL;
		return 0;

ssl_error:
		free_ssl_client(cl);
		errno = EPROTO;
#if DEBUG > 1
		{
			char buf[120];

			if ( ERR_error_string(ERR_get_error(),buf) )
				printf("SSL proto error: %s\n",buf);
		}
#endif
		return -1;
	}
#endif
	errno = ENOPROTOOPT;
	return -1;
}

/** \brief Destroy an admission control client structure

	\param cl reference to admission control client
*/
void
admctrlcl_destroy(admctrlcl_t *cl)
{
	if ( cl->data.free_request && cl->data.request )
		free(cl->data.request);
	if ( cl->data.free_result && cl->data.result )
		free(cl->data.result);

	switch( cl->type )
	{
		case IPC_CL:
			free_ipc_client(cl);
			break;
		case SSL_CL:
#ifdef HAVE_LIBSSL
			free_ssl_client(cl);
#endif
		case SOCKET_CL:
			free_socket_client(cl);
			break;
	}
}

/** \brief Set the request to be send by an admission control client

	\param client reference to admission control client
	\param req reference to request to be send
*/
void
admctrlcl_set_request(admctrlcl_t *client,const adm_ctrl_request_t *req)
{
	memcpy(client->data.request,req,sizeof(adm_ctrl_request_t));
}

/** \brief Get the result received by an admission control client

	\param client reference to admission control client

	\return reference to returned result
*/
adm_ctrl_result_t *
admctrlcl_get_result(admctrlcl_t *client)
{
	return client->data.result;
}

/** \brief Open an admission control client's communication
	If persistent connections were disabled for the client at creation time,
  it does nothing. Communication will established on request submission.

	\param client reference to admission control client

	\return 0 on success, or -1 on error. errno is set by IPC, socket I/O or SSL
	calls depending on admission control client type
*/
int
admctrlcl_comm_open(admctrlcl_t *client)
{
	if ( client->persistent == 0 )
		return 0;
	return do_comm_open(client);
}

/** \brief Close an admission control client's communication
	If the client is of type SOCKET_CL or SSL_CL and persistent connection was 
	disabled at creation time, it does nothing. Communication was terminated
	after receiving results.

	\param client reference to admission control client

	\return 0 on success, or -1 on error. errno is set by IPC, socket I/O or SSL
	calls depending on admission control client type
*/
int
admctrlcl_comm_close(admctrlcl_t *client)
{

	DEBUG_CMD2(printf("admctrlcl_comm_close: shutting down communication\n"));
	if ( client->persistent == 0 )
		return 0;
	return do_comm_close(client);
}

/** \brief Reset a client's request and results structures

	\param client reference to admission control client
*/
void
admctrlcl_reset(admctrlcl_t *client)
{
	bzero(client->data.request,sizeof(adm_ctrl_request_t));
	bzero(client->data.result,sizeof(adm_ctrl_result_t));
}

/** \brief Submit the client's request to admission control
  Communication is established and closed each time its called,
  if a persistent connection is not used.

  \param client reference to admission control client

	\return 0 on success, or -1 on error. errno is set by IPC, socket I/O or SSL
	calls depending on admission control client type
*/
int
admctrlcl_submit_request(admctrlcl_t *client)
{
	struct socket_data *sd;
	int e = -1;

	if ( client->persistent == 0 && do_comm_open(client) != 0 )
	{
		DEBUG_CMD2(printf("Initialising communications failed\n"));
		return -1;
	}

	switch( client->type )
	{
		case SOCKET_CL:
			sd = (struct socket_data *)client->comm;
			if ( iolib_write(sd->socket,(unsigned char *)client->data.request,sizeof(adm_ctrl_request_t),&client->timeout) <= 0 )
				goto fail;
			if ( iolib_read(sd->socket,(unsigned char *)client->data.result,sizeof(adm_ctrl_result_t),&client->timeout) <= 0 )
				goto fail;
			break;
		case SSL_CL:
#ifdef HAVE_LIBSSL
			sd = (struct socket_data *)client->comm;
			if ( iolib_ssl_write(sd->ssl,sd->socket,client->data.request,sizeof(adm_ctrl_request_t),&client->timeout) < (int)sizeof(adm_ctrl_request_t) )
				goto fail;
			if ( iolib_ssl_read(sd->ssl,sd->socket,client->data.result,sizeof(adm_ctrl_result_t),&client->timeout) < (int)sizeof(adm_ctrl_result_t) )
				goto fail;
			break;
#else
			e = -1;
			errno = ENOPROTOOPT;
			goto fail;
#endif
		case IPC_CL:
			if ( ipc_submit(client) != 0 )
				goto fail;
			break;
		default:
			break;
	}
	e = 0;
fail:
	if ( client->persistent == 0 && do_comm_close(client) != 0 )
	{
		DEBUG_CMD(printf("WARNING admctrlcl_submit_request: communication not closed cleanly\n"));
	}
	return e;
}
