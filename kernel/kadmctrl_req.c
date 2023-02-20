/* kadmctrl_req.c

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

#define EXPORT_SYMTAB

#if defined(CONFIG_MODVERSIONS) && ! defined(MODVERSIONS)
#include <linux/modversions.h>
#define MODVERSIONS
#endif

#include <stdarg.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/string.h>

#include "kadmctrl_req.h"
#include "admctrl_argtypes.h"


// Module meta-data
MODULE_AUTHOR("G Portokalidis");
MODULE_DESCRIPTION("Admission control request manipulation functions");
MODULE_LICENSE("GPL");

/*! \file kadmctrl_req.c
  \brief Declaration of functions to construct an admission control request 
  [KERNEL]
  \author Georgios Portokalidis
*/


static int
append_string(const char *s,unsigned char *buf,size_t *buf_size)
{
	size_t len;

	// Copy function name
	len = strlen(s) + 1;
	if ( (len + *buf_size) > MAX_FUNCTION_LIST_SIZE )
		return -1;
	strcpy(buf + *buf_size,s);
	*buf_size += len;
	return 0;
}



/** \brief Set authentication and authorisation information for an admission 
  control request

	\param request reference to admission control request structure
	\param nonce nonce used for client authentication
  \param pub buffer containing client's public key
  \param creds buffer containing client's credentials
  \param enc_nonce buffer containing nonce encrypted with user's private key
  \param enc_nonce_len size of encrypted nonce
*/
void
admctrl_req_set_authinfo(adm_ctrl_request_t *request,const unsigned char *pub,
    const unsigned char *creds,unsigned int nonce,
    const unsigned char *enc_nonce,size_t enc_nonce_len)
{
  strncpy(request->pubkey,pub,MAX_PUBKEY_SIZE);
  strncpy(request->credentials,creds,MAX_PUBKEY_SIZE);
  request->nonce = nonce;
  request->encrypted_nonce_len = enc_nonce_len;
  memcpy(request->encrypted_nonce,enc_nonce,
      MIN(enc_nonce_len,MAX_ENC_NONCE_SIZE));
}



/** \brief Add a name value pair to an admission control request

	\param request reference to admission control request structure
	\param name name of value to add
	\param value value to add

	\return 0 on success, or -1 if the maximum number of pairs has been reached
*/
int
admctrl_req_add_nvpair(adm_ctrl_request_t *request, const char *name, 
const char *value)
{
	if ( request->pairs_num >= MAX_PAIR_ASSERTIONS )
		return -1;
	strncpy(request->pair_assertions[request->pairs_num].name,
			name,MAX_PAIR_NAME);
	strncpy(request->pair_assertions[request->pairs_num].value,
			value,MAX_PAIR_VALUE);
	request->pairs_num++;
	return 0;
}



/** \brief Add a function with serialised arguments to an admission control 
  request

	\param request reference to admission control request structure
	\param fbuf_off reference to offset in request's serialised functions list
	\param fname function name
	\param lname library name function belongs to
	\param argt function's arguments' types specification string
	\param args buffer containing serialised arguments
	\param args_size size of the serialised arguments

	\return 0 on success, or -1 on error
*/
int
admctrl_req_add_sfunction(adm_ctrl_request_t *request,size_t *fbuf_off,
    const char *fname,const char *lname,const char *argt,
    const unsigned char *args,size_t args_size)
{
	if ( append_string(fname,request->function_list,fbuf_off) != 0 )
		return -1;
	if ( append_string(lname,request->function_list,fbuf_off) != 0 )
		return -1;
	if ( append_string(argt,request->function_list,fbuf_off) != 0 )
		return -1;
	if ( args_size > 0 )
	{
		if ( (args_size + *fbuf_off) > MAX_FUNCTION_LIST_SIZE )
			return -1;
		memcpy(request->function_list + *fbuf_off,args,args_size);
		*fbuf_off += args_size;
	}
	request->functions_num++;

	return 0;
}

/** \brief Add a function to the session's request

	\param request reference to an admission control request structure
	\param fbuf_off reference to offset in request's serialised functions list
	\param fname function name
	\param lname library name function belongs to
	\param argt function's arguments' types specification string
	\param ... variable list containing function's arguments

	\return 0 on success, or -1 on failure
*/
int
admctrl_req_add_function(adm_ctrl_request_t *request,size_t *fbuf_off,
    const char *fname,const char *lname,const char *argt,...)
{
	va_list ap;
	size_t len;
	int integer;
	unsigned long long ullong;
	double doubleval;
	char *string;

	// Copy function name
	if ( append_string(fname,request->function_list,fbuf_off) != 0 )
		return -1;

	// Copy function name
	if ( append_string(lname,request->function_list,fbuf_off) != 0 )
		return -1;

	// Copy argument types string
	if ( append_string(argt,request->function_list,fbuf_off) != 0 )
		return -1;

	// Copy arguments
	va_start(ap,argt);
	while( *argt != '\0' )
		switch( *argt )
		{
			case INT_TYPE:
				integer = va_arg(ap,int);
				if ( (*fbuf_off + sizeof(int)) > MAX_FUNCTION_LIST_SIZE )
					goto fail;
				memcpy(request->function_list + *fbuf_off,&integer,sizeof(int));
				*fbuf_off += sizeof(int);
				break;
			case ULONG_LONG_TYPE:
				ullong = va_arg(ap,unsigned long long);
				if ( (*fbuf_off + sizeof(unsigned long long)) > MAX_FUNCTION_LIST_SIZE )
					goto fail;
				memcpy(request->function_list + *fbuf_off,&ullong,
            sizeof(unsigned long long));
				*fbuf_off += sizeof(unsigned long long);
				break;
			case DOUBLE_TYPE:
				doubleval = va_arg(ap,double);
				if ( (*fbuf_off + sizeof(double)) > MAX_FUNCTION_LIST_SIZE )
					goto fail;
				memcpy(request->function_list + *fbuf_off,&doubleval,sizeof(double));
				*fbuf_off += sizeof(double);
				break;
			case STRING_TYPE:
				string = va_arg(ap,char *);
				len = strlen(string) + 1;
				if ( (len + *fbuf_off) > MAX_FUNCTION_LIST_SIZE )
					return -1;
				strcpy(request->function_list + *fbuf_off,string);
				*fbuf_off += len;
				break;
			default:
				return -1;
		}
	va_end(ap);
	request->functions_num++;
	
	return 0;

fail:
	va_end(ap);
	return -1;
}

int
kadmctrl_req_init(void)
{
  return 0;
}

void
kadmctrl_req_exit(void) { }

module_init(kadmctrl_req_init);
module_exit(kadmctrl_req_exit);

EXPORT_SYMBOL(admctrl_req_set_authinfo);
EXPORT_SYMBOL(admctrl_req_add_nvpair);
EXPORT_SYMBOL(admctrl_req_add_function);
EXPORT_SYMBOL(admctrl_req_add_sfunction);
