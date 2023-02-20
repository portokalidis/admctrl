/* encrypt_nonce.c

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

#include <stddef.h>
#include <regex.h>
#include <keynote.h>
#include <openssl/rsa.h>
#include <bytestream.h>
#include <admctrl_config.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
