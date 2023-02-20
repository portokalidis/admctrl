#include <stdio.h>
#include <regex.h>
#include <keynote.h>
#include <openssl/rsa.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "adm_ctrl.h"

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

int
main(int argc,char **argv)
{
  unsigned char *enc_nonce;
  size_t nonce_len;
  int nonce;

  if ( argc != 3 )
  {
    fprintf(stderr,"Invalid number of arguments\n");
    fprintf(stderr,"Usage: %s <integer> <private key file>\n\n",argv[0]);
    exit(1);
  }

  nonce = atoi(argv[1]);

  printf("Encrypting nonce %d with private key located in %s\n",nonce,argv[2]);

  nonce_len = encrypt_nonce(&enc_nonce,nonce,argv[2]);
  if ( nonce_len == 0 )
  {
    fprintf(stderr,"encrypt_nonce() failed\n");
    exit(1);
  }

  print_hex(enc_nonce,nonce_len);
  
  free(enc_nonce);

  exit(0);
}
