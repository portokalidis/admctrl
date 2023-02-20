/* client.c

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
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <regex.h>
#include <keynote.h>
#include <openssl/rsa.h>

#include "admctrl_argtypes.h"
#include "admctrl_config.h"
#include "admctrlcl.h"
#include "admctrl_req.h"

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#endif

#define MAX_STRING_LEN 1024
#define MAX_ARGS_LEN 2048

#define ZNONCE "\x0C\xF4\x5F\x12\x72\x16\xB5\x84\x7E\x2D\x5C\x96\x62\x54\xF0\xCA\x12\x50\x60\xE5\x14\x6F\x4A\xCF\x65\x2C\xCD\x39\xDB\xEA\xC9\xAB\xBD\x61\xA7\xD7\x6A\xFD\x6F\xB9\xE9\xF2\x01\x1A\x2D\xA6\xD4\x87\xCA\xA4\xD2\xF5\x01\x59\xB5\x8A\x53\xFD\x7D\xE7\x9E\x06\x8A\x4B\x5D\xC9\x75\xE2\x6F\x27\x64\x84\xDD\x40\xC1\x70\xF6\x64\x8F\xBE\xC0\x5C\x8B\x7\xA3\x95\x84\xD2\x53\xFF\x57\x36\x61\x6D\x6B\x3A\x63\xBF\xD9\x70\x7C\xD7\x21\x9B\x57\xAD\x8C\xEA\xC0\x7B\xAC\x42\x8C\xC3\x33\x11\xD4\x8C\x11\xBC\xC2\x1F\x6A\x4D\x75\x26\x76\x25"

static char pubfile[MAX_STRING_LEN] = "pub";
static char privfile[MAX_STRING_LEN] = "priv";
static char credsfile[MAX_STRING_LEN] = "creds";
static bytestream pub,creds;

#ifdef WITH_RESOURCE_CONTROL
static resource_ctrl_db_t db;
static char *dbhome = NULL;
static char db_needs_closing = 0;
#endif

struct function
{
  int id;
  char *name,
  *arg_types;
};
typedef struct function function_t;

typedef enum {
  PKT_COUNTER = 0, /* Count the packet */
  STR_SEARCH,  /* Search the specified string */
  BPF_FILTER,  /* Filter the packet */
  TO_BUFFER,    /* Copies packets to a buffer that can be read by user applications */
  ETHEREAL,     /* ethereal filter, uses the ethereal display filter to filter packets */
  TO_TCPDUMP,   /* Create tcpdump file format from captured packages */
  BYTE_COUNTER,  /* Count the bytes passing through the filter */
  TO_BUCKET,     /* Store function results periodically to a bucket */
  TIMEDIFF     /*Measures time difference between packet arrival */
} function_id;

static const function_t functions_array[] = {
  { PKT_COUNTER,  "PKT_COUNTER",  ""    },
  { STR_SEARCH,   "STR_SEARCH",   "sii" },
  { BPF_FILTER,   "BPF_FILTER",   "s"   },
  { TO_BUFFER,    "TO_BUFFER",    ""    },
  { ETHEREAL,     "ETHEREAL",     "s"   },
  { TO_TCPDUMP,   "TO_TCPDUMP",   "sL"  },
  { BYTE_COUNTER, "BYTE_COUNTER", ""    },
  { TO_BUCKET,    "TO_BUCKET",    "iF"  },
  { TIMEDIFF,     "TIMEDIFF",     "d"   },
  { -1,           "",             ""    }
};

static char *libs_array[] = { "stdlib", "dag", NULL };

static char *shm_pathname = NULL;
static int shm_project_id = 'A';
static char *server_host = NULL;
static unsigned int server_port = 7914;
static char use_ssl = 0;
static char *ssl_pk_file = "client_key.pem";
static char *ssl_ca_file = NULL;
static struct timeval timeout = { 0, 0 };
static char persistent = 0;

static admctrlcl_t *client = NULL;
static adm_ctrl_request_t request;
static adm_ctrl_result_t result;
static size_t flist_off = 0;

static void
print_ssl_error(int e)
{
#ifdef HAVE_LIBSSL
	char errbuf[120];
	if ( e == EPROTO && ERR_error_string(ERR_get_error(),errbuf) )
			fprintf(stderr,"%s\n",errbuf);
#endif
}

static int
read_file(const char *fn,bytestream *bs)
{
  int fp,r;
  
  if ( (fp = open(fn,O_RDONLY)) < 0 )
    return -1;
  r = read(fp,bs->data,bs->length);
  close(fp);
  return r;
}

/** \brief Encrypt a nonce with an RSA private key

	\param enc_nonce reference to pointer that will be set to the allocated
  buffer containing the encrypted nonce
	\param nonce nonce to encrypt
  \param priv file containing private key

	\return the size of the encrypted nonce on success, or 0 on error
*/
static size_t
encrypt_nonce(unsigned char **enc_nonce,unsigned int nonce,const char *priv)
{
  bytestream privkey;
  char *pkstring;
  struct keynote_deckey priv_dk;
  RSA *rsa;
  int enc_len = 0;

  BS_NEW(privkey,MAX_PRIVKEY_SIZE);
  if ( BS_ISNULL(privkey) )
  {
    errno = ENOMEM;
    return 0;
  }
  if ( read_file(priv,&privkey) < 0 )
    goto ret;

  if ( (pkstring = kn_get_string(privkey.data)) == NULL )
    goto ret;

  // Decode private key
  if ( kn_decode_key(&priv_dk,pkstring,KEYNOTE_PRIVATE_KEY) != 0 )
    goto ret;
  if ( priv_dk.dec_algorithm != KEYNOTE_ALGORITHM_RSA )
    goto dec_error;

  rsa = (RSA *)priv_dk.dec_key;

  // Allocate memory
  if ( (*enc_nonce = malloc(RSA_size(rsa))) == NULL )
  {
    errno = ENOMEM;
    goto dec_error;
  }

  enc_len = RSA_private_encrypt(sizeof(unsigned int),(unsigned char *)&nonce,
      *enc_nonce,rsa,RSA_PKCS1_PADDING);

  if ( enc_len <= 0 )
  {
    free(*enc_nonce);
    enc_len = 0;
  }

dec_error:
  kn_free_key(&priv_dk);
ret:
  BS_FREE(privkey);
  return (size_t)enc_len;
}

static int
get_selection(const char *message,int min,int max)
{
	int selection,c;

	// Get a valid selection
	do {
		printf("%s",message);
		selection = getchar() - '0';
	} while( selection < min || selection > max);

	// Ignore until EOF or newline
	while ( (c = getchar()) != EOF && c != '\n' )
		;
	return selection;
}

static int
get_int(const char *message)
{
	char buf[64];
	int c,i;

	printf("%s",message);

	i = 0;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < 63 )
			buf[i++] = (char)c;
	buf[i] = '\0';
	return atoi(buf);
}

static double
get_double(const char *message)
{
	char buf[64];
	int c,i;

	printf("%s",message);

	i = 0;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < 63 )
			buf[i++] = (char)c;
	buf[i] = '\0';
	return strtod(buf,NULL);
}

static unsigned long long
get_ull(const char *message)
{
	char buf[128];
	int c,i;

	printf("%s",message);

	i = 0;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < 127 )
			buf[i++] = (char)c;
	buf[i] = '\0';
	return strtoull(buf,NULL,10);

}

static void
get_string(const char *message,size_t max,char *buf)
{
	int c;
	unsigned int i;

	printf("%s",message);

	i = 0;
	--max;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < max )
			buf[i++] = (char)c;
	buf[i] = '\0';
}

static void
print_menu(void)
{
	printf("\nMENU\n");
	printf("1. Set public key (%s)\n",pubfile);
	printf("2. Set private key (%s)\n",privfile);
	printf("3. Set credentials (%s)\n",credsfile);
  printf("4. Add name-value pair action\n");
	printf("5. Add function call action\n");
	printf("6. Send to admission control\n");
	printf("7. Reset\n");
	printf("0. Exit\n");
	printf("\n");
}

/*
static int
add_namevalue_pair(void)
{
  char name[MAX_STRING_LEN],value[MAX_STRING_LEN];

	if ( admctrl_req_add_nvpair(&request,name,value) != 0 )
		return -1;

  return 0;
}
*/

static void
reset(void)
{
  bzero(&request,sizeof(adm_ctrl_request_t));
}


static ssize_t
get_arguments(char *argt,char *args,size_t len)
{
  int i,l,f,j;

  for(i = l = f = 0; argt[i] != '\0' ;i++)
  {
		printf("Argument %d(%c): ",i,argt[i]);
		switch( argt[i] )
		{
			case STRING_TYPE:
				get_string("",MAX_STRING_LEN,args + len);
				len += strlen(args + len) + 1;
				break;
			case INT_TYPE:
				*(int *)(args+len) = get_int("");
				len += sizeof(int);
				break;
      case DOUBLE_TYPE:
        *(double *)(args+len) = get_double("");
        len += sizeof(double);
        break;
			case ULONG_LONG_TYPE:
				*(unsigned long long *)(args+len) = get_ull("");
				len += sizeof(unsigned long long);
				break;
      case FUNCTION_TYPE:
        printf("Available libraries:\n");
        for(j = 0 ; libs_array[j] != NULL ; j++)
          printf("%d: %s\n",j,libs_array[j]);
        l = get_selection("Select library:",0,j-1);
        printf("Available functions:\n");
        for(j = 0 ; functions_array[j].id >= 0 ; j++)
          printf("%d: %s\t%s\n",j,functions_array[j].name,functions_array[j].arg_types);
        f = get_selection("Select function:",0,j-1);

        strcpy(args+len,functions_array[f].name);
        len += strlen(functions_array[f].name) + 1;
        strcpy(args+len,libs_array[l]);
        len += strlen(libs_array[l]) + 1;
        strcpy(args+len,functions_array[f].arg_types);
        len += strlen(functions_array[f].arg_types) + 1;

        if ( (j = get_arguments(functions_array[f].arg_types,args,len)) < 0 )
          return -1;

        len = (size_t)j;
        
        break;
			default:
				fprintf(stderr,"Unknown argument type encountered\n");
				return -1;
		}
  }
  return (ssize_t)len;
}

static void
add_function(void)
{
	int f,l,i;
	char args[MAX_ARGS_LEN];
	ssize_t len;

	printf("Available libraries:\n");
	for(i = 0 ; libs_array[i] != NULL ; i++)
		printf("%d: %s\n",i,libs_array[i]);
	l = get_selection("Select library:",0,i-1);

	printf("Available functions:\n");
	for(i = 0 ; functions_array[i].id >= 0 ; i++)
		printf("%d: %s\t%s\n",i,functions_array[i].name,functions_array[i].arg_types);
	f = get_selection("Select function:",0,i-1);

#if 0
	for(i = 0,l = 0,len = 0; functions_array[f].arg_types[i] != '\0' ;i++)
	{
		printf("Argument %d(%c): ",i,functions_array[f].arg_types[i]);
		switch( functions_array[f].arg_types[i] )
		{
			case STRING_TYPE:
				get_string("",MAX_STRING_LEN,args + len);
				len += strlen(args + len) + 1;
				break;
			case INT_TYPE:
				*(int *)(args+len) = get_int("");
				len += sizeof(int);
				break;
      case DOUBLE_TYPE:
        *(double *)(args+len) = get_double("");
        len += sizeof(double);
        break;
			case ULONG_LONG_TYPE:
				*(unsigned long long *)(args+len) = get_ull("");
				len += sizeof(unsigned long long);
				break;
			default:
				fprintf(stderr,"Unknown argument type encountered\n");
				return;
		}
	}
#endif
  if ( (len = get_arguments(functions_array[f].arg_types,args,0)) < 0 )
  {
    fprintf(stderr,"Error while getting arguments\n");
    return ;
  }

	if ( admctrl_req_add_sfunction(&request,&flist_off,functions_array[f].name,
			libs_array[l],functions_array[f].arg_types,args,(size_t)len) != 0 )
		perror("admctrl_req_add_sfunction");
}

static void
submit(void)
{
  unsigned char *enc_nonce;
  size_t enc_nonce_len;
  unsigned int nonce = 3208030;

  if ( read_file(pubfile,&pub) <= 0 )
  {
    perror("read_file");
    return;
  }
  if ( read_file(credsfile,&creds) <= 0 )
  {
    perror("read_file");
    return;
  }
  
  if ( (enc_nonce_len = encrypt_nonce(&enc_nonce,nonce,privfile)) == 0 )
  {
    perror("encrypt_nonce");
    return;
  }

  // This is done here to reflect changes to authorisation info after 
  // adding assertions
	admctrl_req_set_authinfo(&request,pub.data,creds.data,0/*nonce*/,ZNONCE/*enc_nonce*/,128/*enc_nonce_len*/);

	if ( admctrlcl_submit_request(client) != 0 )
	{
		perror("admctrlcl_submit_request");
    if ( use_ssl )
      print_ssl_error(errno);
    goto ret;
	}

  // Result is a local variable. We don't need to copy it from the library
	//res = admctrlcl_get_result(client);
	printf("PCV = %d, errno = %d\n",result.PCV,result.error);

#ifdef WITH_RESOURCE_CONTROL
  if ( dbhome )
  {
    if ( resource_ctrl_allocate(&db,result.required,result.resources_num) != 0 )
      perror("resource_ctrl_allocate");
    if ( resource_ctrl_deallocate(&db,result.required,result.resources_num) != 0 )
      perror("resource_ctrl_deallocate");
  }
#endif

  bzero(&result,sizeof(adm_ctrl_result_t));
ret:
  free(enc_nonce);
}

static void
process_selection(int s)
{
	char buf[MAX_STRING_LEN],buf2[MAX_STRING_LEN];

	switch( s )
	{
		case 0:
			break;
		case 1:
			get_string("Enter file containing public key:",128,buf);
      strcpy(pubfile,buf);
			break;
		case 2:
			get_string("Enter file containing private key:",128,buf);
      strcpy(privfile,buf);
			break;
		case 3:
			get_string("Enter file containing credentials:",128,buf);
      strcpy(credsfile,buf);
			break;
    case 4:
			get_string("Enter name for action:",MAX_ACTION_NAME_SIZE,buf);
			get_string("Enter value for action:",MAX_ACTION_VALUE_SIZE,buf2);
      if ( admctrl_req_add_nvpair(&request,buf,buf2) != 0 )
        perror("admctrl_req_add_nvpair");
      break;
		case 5:
			add_function();
			break;
		case 6:
			submit();
			break;
		case 7:
			reset();
			break;
		default:
			fprintf(stderr,"Illegal selection\n");
			break;
	}
}

static void
block_ctrl_c(int data)
{
	printf("\nUse selection 0 to exit\n");
}

static void
print_usage(void)
{
	printf("Usage:\n");
	printf("  -H  --host=HOSTNAME      Server port binded to HOSTNAME\n");
	printf("  -p  --port=PORT          Use port number PORT \n");
	printf("  -r  --persistent         Use persistent communication with server\n");
	printf("  -t  --timeout=TIMEOUT    Set admission control timeout to TIMEOUT\n");
	printf("  -P  --shmpath=path       Pathname to use for IPC with authd \n");
	printf("  -i  --shmid=project id   Project id to use for IPC with authd\n");
#ifdef WITH_RESOURCE_CONTROL
	printf("  -D  --dbhome=path        Set resource control DB home to path\n");
#endif
#ifdef HAVE_LIBSSL
	printf("  -s  --ssl                Use SSL\n");
	printf("  -k  --priv=FILENAME      Set file containing SSL private key\n");
	printf("  -c  --ca=FILENAME        Set file containing SSL CA's\n");
#endif
	printf("  -h  --help               Display this message\n\n");
}

static void
parse_arguments(int argc,char **argv)
{
	int c;
	const char optstring[] = "H:p:hP:i:sk:c:t:rD:";
	const struct option longopts[] = {
		{ "host", required_argument, NULL, 'H' },
		{ "port", required_argument, NULL, 'p' },
		{ "persistent", no_argument, NULL, 'r' },
		{ "timeout", required_argument, NULL, 't' },
		{ "shmpath", required_argument, NULL, 'P' },
		{ "shmid", required_argument, NULL, 'i' },
#ifdef WITH_RESOURCE_CONTROL
    { "dbhome",required_argument,NULL,'D' },
#endif
#ifdef HAVE_LIBSSL
		{ "ssl", no_argument, NULL, 's' },
		{ "priv", required_argument, NULL, 'k' },
		{ "ca", required_argument, NULL, 'c' },
#endif
		{ "help", no_argument, NULL, 'h' },
		{ "", 0, NULL , '\0' }
	};

	while ( (c = getopt_long(argc,argv,optstring,longopts,NULL)) >= 0 )
		switch( c )
		{
			case 'H':
				server_host = optarg;
				break;
			case 'r':
				persistent = 1;
				break;
			case 'p':
				server_port = (unsigned int)atoi(optarg);
				break;
			case 'P':
				shm_pathname = optarg;
				break;
			case 'i':
				shm_project_id = atoi(optarg);
				break;
			case 't':
				timeout.tv_sec = labs(strtol(optarg,NULL,10));
				break;
#ifdef WITH_RESOURCE_CONTROL
      case 'D':
        dbhome = optarg;
        break;
#endif
#ifdef HAVE_LIBSSL
			case 's':
				use_ssl = 1;
				break;
			case 'k':
				ssl_pk_file = optarg;
				break;
			case 'c':
				ssl_ca_file = optarg;
				break;
#endif
			case 'h':
			default:
				print_usage();
				exit(1);
				break;
		}
}



int
main(int argc,char **argv)
{
	int selection = 0;

  BS_NEW(pub,MAX_PUBKEY_SIZE);
  BS_NEW(creds,MAX_CREDENTIALS_SIZE);
  if ( BS_ISNULL(pub) || BS_ISNULL(creds) )
  {
    perror(*argv);
    return 1;
  }

	signal(SIGINT,block_ctrl_c);
	signal(SIGQUIT,block_ctrl_c);

	parse_arguments(argc,argv);

	// USE shared memory
	if ( shm_pathname )
	{
		if ( (client = admctrlcl_new_ipc(shm_pathname,shm_project_id,persistent,&timeout,&request,&result)) == NULL )
		{
			perror("admctrlcl_new_ipc");
			return 1;
		}
		printf("Using IPC\n");
	}
	// USE sockets
	else if ( server_host )
	{
		if ( (client = admctrlcl_new_socket(server_host,server_port,persistent,&timeout,&request,&result)) == NULL )
		{
			perror("admctrlcl_new_socket");
			return 1;
		}
		printf("Using sockets\n");

		// SSL
		if ( use_ssl )
		{
			if (admctrlcl_use_SSL(client,ssl_pk_file,ssl_ca_file) != 0 )
			{
				perror("admctrlcl_use_ssl");
        if ( use_ssl )
          print_ssl_error(errno);
				goto cleanup;
			}
			printf("SSL enabled\n");
		}
	}
	else
	{
		fprintf(stderr,"No server has been specified\n");
		return 1;
	}

	if ( admctrlcl_comm_open(client) != 0 )
	{
		perror("admctrlcl_comm_open");
    if ( use_ssl )
      print_ssl_error(errno);
		goto cleanup;
	}

#ifdef WITH_RESOURCE_CONTROL
  if ( dbhome )
  {
    if ( resource_ctrl_dbinit(&db) != 0 )
      goto cleanup;
    if ( resource_ctrl_dbopen(&db,dbhome,DEFAULT_RESOURCE_DBNAME,
          RESOURCE_DB_CREATE,RESOURCE_DB_CREATE | RESOURCE_DB_RECOVER) != 0 )
      goto cleanup;
    db_needs_closing = 1;
  }
#endif

	bzero(&request,sizeof(request));

	do 
	{
		print_menu();
		selection = get_selection("Selection:",0,7);
		putchar('\n');
		process_selection(selection);
	} while( selection != 0 );

cleanup:
	admctrlcl_comm_close(client);
	admctrlcl_destroy(client);
  BS_FREE(pub);
  BS_FREE(creds);
#ifdef WITH_RESOURCE_CONTROL
  if ( db_needs_closing )
  {
    printf("Closing db\n");
    resource_ctrl_dbclose(&db);
  }
#endif

	return 0;
}
