/* authdfe.c

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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include "admctrl_config.h"
#include "admctrlcl.h"
#include "mt_server.h"
#include "filei.h"
#include "debug.h"

/************************************************/
/*         CONFIGURATION VARIABLES              */
/************************************************/
static char *server_hostname = "localhost";
static int server_port = 7914;
static int threads_number = 5;
static char *ipc_pathname = DEFAULT_SHM_FILE;
static int ipc_project_id = DEFAULT_SHM_PROJECT_ID;
static long in_timeout = 0;
static long ipc_timeout = 1;
static char allow_persistent = 0;
static char *dev_filename = NULL;
static char *ssl_cert_file = "server.pem";
static char *ssl_pk_file = "server.key";
static char use_ssl = 0;

/************************************************/
/*                GLOBAL VARIABLES              */
/************************************************/
static pthread_spinlock_t submit_lock;
static admctrlcl_t *server_client = NULL;

static void
print_usage(void)
{
	printf("Usage:\n");
	printf("  -H  --host=HOSTNAME        Server port binded to HOSTNAME\n");
	printf("  -p  --port=PORT_NUNBER     Set port number\n");
	printf("  -e  --threads=THREADS_NUM  Set number of threads\n");
	printf("  -n  --nettimeout=TIMEOUT   Set network I/O timeout\n");
	printf("  -t  --servtimeout=TIMEOUT  Set admission control server timeout\n");
	printf("  -P  --ipcpath=PATH         Pathname to use for IPC with authd \n");
	printf("  -i  --ipcid=NUMBER         Project id to use for IPC with authd\n");
	printf("  -r  --persistent           Allow persistent connections with clients\n");
	printf("  -d  --dev=DEVNAME          Start a thread reading requests from\n");
  printf("                             charecter device DEVNAME\n");
#ifdef HAVE_LIBSSL
	printf("  -s  --ssl                  Use SSL\n");
	printf("  -c  --cert=FILENAME        File containining server certificate\n");
	printf("  -k  --priv=FILENAME        File containining server private key\n");
#endif
	printf("  -h  --help                 Display this message\n\n");
}

static void
parse_arguments(int argc,char **argv)
{
	int c;
	const char optstring[] = "H:p:e:n:t:P:i:rsc:k:d:";
	const struct option longopts[] = {
		{ "host", required_argument, NULL, 'H' },
		{ "port", required_argument, NULL, 'p' },
		{ "threads", required_argument, NULL, 'e' },
		{ "nettimeout", required_argument, NULL, 'n' },
		{ "servtimeout", required_argument, NULL, 't' },
		{ "ipcpath", required_argument, NULL, 'P' },
		{ "ipcid", required_argument, NULL, 'i' },
		{ "persistent", no_argument, NULL, 'r' },
    { "dev", required_argument, NULL, 'd' },
		{ "ssl", no_argument, NULL, 's' },
		{ "cert", required_argument, NULL, 'c' },
		{ "priv", required_argument, NULL, 'k' },
		{ "help", no_argument, NULL, 'h' },
		{ "", 0, NULL , '\0' }
	};

	while ( (c = getopt_long(argc,argv,optstring,longopts,NULL)) >= 0 )
		switch( c )
		{
			case 'H':
				server_hostname = optarg;
				break;
			case 'p':
				server_port = atoi(optarg);
				break;
			case 'e':
				threads_number = atoi(optarg);
			case 'n':
				in_timeout = strtol(optarg,NULL,10);
				break;
			case 't':
				ipc_timeout = strtol(optarg,NULL,10);
				break;
			case 'P':
				ipc_pathname = optarg;
				break;
			case 'i':
				ipc_project_id= atoi(optarg);
				break;
			case 'r':
				allow_persistent = 1;
				break;
      case 'd':
        dev_filename = optarg;
        break;
#ifdef HAVE_LIBSSL
			case 's':
				use_ssl = 1;
				break;
			case 'c':
				ssl_cert_file = optarg;
				break;
			case 'k':
				ssl_pk_file = optarg;
				break;
#else
			case 's':
			case 'c':
			case 'k':
				fprintf(stderr,"SSL support has not been enabled at compile time\n");
				exit(1);
#endif
			case 'h':
			default:
				print_usage();
				exit(1);
				break;
		}
}

#if DEBUG > 1
static void
print_hex(const unsigned char *buf,size_t len)
{
  size_t i;

  printf("Size of encrypted nonce %u\n",len);
  putchar('"');
  for(i = 0; i < len ;i++)
    if ( buf[i] > 0x10 )
      printf("\\x%X",buf[i]);
    else
      printf("\\x0%X",buf[i]);
  printf("\"\n");
}

void
print_request(const adm_ctrl_request_t *req)
{
  printf("PUB: %s\n\n",req->pubkey);
  printf("CREDS:\n%s\n\n",req->credentials);
  printf("NONCE: %u\n",req->nonce);
  print_hex(req->encrypted_nonce,req->encrypted_nonce_len);
}
#endif

static ssize_t
submit_request(const unsigned char *src,size_t bufsize,unsigned char *dest)
{
	int e;

	DEBUG_CMD2(printf("submit_request: in\n"));

	if ( bufsize != sizeof(adm_ctrl_request_t) )
		return 0;

	DEBUG_CMD2(print_request((const adm_ctrl_request_t *)src));

	pthread_spin_lock(&submit_lock);
	admctrlcl_set_request(server_client,(const adm_ctrl_request_t *)src);
	if ( (e = admctrlcl_submit_request(server_client)) != 0 )
		goto fail;
	e = sizeof(adm_ctrl_result_t);
	memcpy(dest,admctrlcl_get_result(server_client),e);
fail:
	pthread_spin_unlock(&submit_lock);
	return e;
}

int
main(int argc,char **argv)
{
	mt_server_t *in_server;
  filei_thread_t *dev_server = NULL;
	sigset_t waitsigs;
	struct timeval timeout;
	adm_ctrl_request_t request;
	adm_ctrl_result_t result;
	int esig,e = -1;

	parse_arguments(argc,argv);

	timeout.tv_sec = ipc_timeout;
	timeout.tv_usec = 0;
	if ( (server_client = admctrlcl_new_ipc(ipc_pathname,ipc_project_id,1,&timeout,&request,&result)) == NULL )
	{
		perror("admcrtrlcl_new_ipc");
		return 1;
	}

	pthread_spin_init(&submit_lock,1);

	if ( admctrlcl_comm_open(server_client) != 0 )
	{
		perror("admctrlcl_comm_open");
		goto admcl_open_error;
	}

	sigemptyset(&waitsigs);
	sigaddset(&waitsigs,SIGINT);
	sigaddset(&waitsigs,SIGQUIT);
	sigaddset(&waitsigs,SIGHUP);

  if ( dev_filename && (dev_server = filei_thread_new(dev_filename,sizeof(adm_ctrl_request_t),submit_request)) == NULL )
  {
    perror("filei_thread_new");
		goto filei_error;
  }

	if ( (in_server = mt_server_new(server_hostname,server_port,threads_number)) == NULL )
	{
		perror("mt_server_new");
    goto mt_server_error;
	}

	timeout.tv_sec = in_timeout;

  if ( dev_filename && filei_thread_start(dev_server) != 0 )
  {
    perror("filei_thread_start");
    goto dev_server_start_error;
  }

	if ( use_ssl && mt_server_use_SSL(in_server,ssl_pk_file,ssl_cert_file) != 0 )
	{
		perror("mt_server_use_SSL");
		goto mt_server_start_error;
	}


	if ( mt_server_start(in_server,sizeof(adm_ctrl_request_t),&timeout,allow_persistent,submit_request) != 0 )
	{
		perror("mt_server_start");
		goto mt_server_start_error;
	}


	sigwait(&waitsigs,&esig);
	e = 0;
	mt_server_stop(in_server);

mt_server_start_error:
  if ( dev_filename )
    filei_thread_stop(dev_server);
dev_server_start_error:
	mt_server_free(in_server);
mt_server_error:
  if ( dev_filename )
    filei_thread_destroy(dev_server);
filei_error:
	admctrlcl_comm_close(server_client);
admcl_open_error:
	admctrlcl_destroy(server_client);
	pthread_spin_destroy(&submit_lock);

	exit(e);
}
