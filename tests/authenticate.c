#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>
#include <keynote.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include "bytestream.h"
#include "admctrl_config.h"

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

int
main(int argc,char **argv)
{
  bytestream pub,priv;
  char *pubstr,*privstr;
  unsigned int nonce,dec_nonce;
  unsigned char *enc_nonce;
  int enc_nonce_len,dec_nonce_len;
  struct keynote_deckey pub_dk,priv_dk;
  RSA *pub_rsa,*priv_rsa;
  int ret = 1;

  if ( argc < 4 )
  {
    printf("Usage: %s nonce pub_key_file priv_key_file\n",*argv);
    return 1;
  }

  BS_NEW(pub,MAX_PUBKEY_SIZE);
  BS_NEW(priv,MAX_PRIVKEY_SIZE);
  if ( read_file(argv[2],&pub) <= 0 )
  {
    printf("error reading public key\n");
    goto ret;
  }
  if ( read_file(argv[3],&priv) <= 0 )
  {
    printf("error reading private key\n");
    goto ret;
  }
  nonce = (unsigned int)atoi(argv[1]);

  if ( (pubstr = kn_get_string(pub.data)) == NULL )
  {
    printf("error getting public key string\n");
    goto ret;
  }
  if ( (privstr = kn_get_string(priv.data)) == NULL )
  {
    printf("error getting private key string\n");
    goto ret;
  }

  if ( kn_decode_key(&pub_dk,pubstr,KEYNOTE_PUBLIC_KEY) != 0 )
  {
    printf("error decoding public key\n");
    goto dec_error;
  }
  if ( kn_decode_key(&priv_dk,privstr,KEYNOTE_PRIVATE_KEY) != 0 )
  {
    printf("error decoding private key\n");
    goto dec_error;
  }

  if ( pub_dk.dec_algorithm != KEYNOTE_ALGORITHM_RSA )
  {
    printf("public key is not RSA\n");
    goto dec_error;
  }
  else
    pub_rsa = (RSA *)pub_dk.dec_key;
  if ( priv_dk.dec_algorithm != KEYNOTE_ALGORITHM_RSA )
  {
    printf("private key is not RSA\n");
    goto dec_error;
  }
  else
    priv_rsa = (RSA *)priv_dk.dec_key;

  enc_nonce = (unsigned char *)malloc(RSA_size(priv_rsa));

  enc_nonce_len = RSA_private_encrypt(sizeof(unsigned int),(unsigned char *)&nonce,enc_nonce,
      priv_rsa,RSA_PKCS1_PADDING);
  if ( enc_nonce_len < 0 )
  {
    printf("error encrypting nonce\n");
    goto enc_error;
  }

  dec_nonce_len = RSA_public_decrypt(enc_nonce_len,enc_nonce,
      (unsigned char *)&dec_nonce, pub_rsa,RSA_PKCS1_PADDING);
  if ( dec_nonce_len < 0 )
  {
    printf("error decrypting nonce\n");
    goto enc_error;
  }

  printf("Original nonce %u\n",nonce);
  printf("Decoded nonce size %d\n",dec_nonce_len);
  printf("Decoded nonce %u\n",dec_nonce);

  ret = 0;

enc_error:
  free(enc_nonce);
dec_error:
  kn_free_key(&pub_dk);
  kn_free_key(&priv_dk);
ret:
  BS_FREE(pub);
  BS_FREE(priv);
  return ret;
}
