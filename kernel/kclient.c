/* kclient.c

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

// Standard module headers
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/string.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include <asm/errno.h>
#include <asm/param.h>
#endif

// Admission control headers
#include "kadm_ctrl.h"
#include "kadmctrl_req.h"
#include "authdev.h"

// Module meta-data
MODULE_AUTHOR("G Portokalidis");
MODULE_DESCRIPTION("Test client for the admission control kernel driver");
MODULE_LICENSE("GPL");

#define PUB "\"rsa-base64:MIGJAoGBALFFnb0MCAblW1PGff6naNomQwVQB4dFKtf8tXGqt36yyJdVtkd+ovWp4804KpIi7YPcJgt0U4awBxI0CeUT2H90Se5Ys5531GyR113GV74/2ID2MIGkHmQMVsWmbH/e85NFqXvRm443gWjqr5K01/zV6SLrRojs2XZRc3JIOkkhAgMBAAE=\""

#define CREDS "KeyNote-Version: 2\n"\
"Authorizer:             \"rsa-base64:MIGJAoGBALkWp6kaeoMVvFshJ9V2axWwoEExC\\\n"\
"            xGL4ubAYEKyDIyqEIcnViEWf5ASPzLygPawSH9py3E04lzS0/\\\n"\
"            9Usz+VT0xbgPZJ+eP20my6LcuGv6dgO5taBsLdsOPZwl+gAPL\\\n"\
"            jpC3qlnv3HI7jg5ftQ64VoHP4ZRNycUWiNtaA8iTE+LonAgMB\\\n"\
"            AAE=\"\n"\
"Licensees:             \"rsa-base64:MIGJAoGBALFFnb0MCAblW1PGff6naNomQwVQB\\\n"\
"            4dFKtf8tXGqt36yyJdVtkd+ovWp4804KpIi7YPcJgt0U4awBx\\\n"\
"            I0CeUT2H90Se5Ys5531GyR113GV74/2ID2MIGkHmQMVsWmbH/\\\n"\
"            e85NFqXvRm443gWjqr5K01/zV6SLrRojs2XZRc3JIOkkhAgMB\\\n"\
"            AAE=\"\n"\
"Conditions: app_domain == \"FFPF\" -> \"true\";\n"\
"Signature:             \"sig-rsa-sha1-base64:iQq/Mmb/vyYGQbsNUkpnKB5X3lv5\\\n"\
"            H0/Y5T60uJe6Whm9LZYwhdABQLhYaW/cZ+NW0mcfvpY49ERcV\\\n"\
"            DTl1aMEYNKmLScRDx+cZRdgdhMjs7it1HkTKQ3a0kuLZqSyxT\\\n"\
"            HXV5yvVc+txcc3OWVJJJrvSTbpSZnWm/Wf8NwWvzRzEHQ=\""

#define NONCE 0
#define ENC_NONCE  "\x0C\xF4\x5F\x12\x72\x16\xB5\x84\x7E\x2D\x5C\x96\x62\x54\xF0\xCA\x12\x50\x60\xE5\x14\x6F\x4A\xCF\x65\x2C\xCD\x39\xDB\xEA\xC9\xAB\xBD\x61\xA7\xD7\x6A\xFD\x6F\xB9\xE9\xF2\x01\x1A\x2D\xA6\xD4\x87\xCA\xA4\xD2\xF5\x01\x59\xB5\x8A\x53\xFD\x7D\xE7\x9E\x06\x8A\x4B\x5D\xC9\x75\xE2\x6F\x27\x64\x84\xDD\x40\xC1\x70\xF6\x64\x8F\xBE\xC0\x5C\x8B\x7\xA3\x95\x84\xD2\x53\xFF\x57\x36\x61\x6D\x6B\x3A\x63\xBF\xD9\x70\x7C\xD7\x21\x9B\x57\xAD\x8C\xEA\xC0\x7B\xAC\x42\x8C\xC3\x33\x11\xD4\x8C\x11\xBC\xC2\x1F\x6A\x4D\x75\x26\x76\x25"

static adm_ctrl_request_t request;
static adm_ctrl_result_t result;

static void
run_test(void)
{
  size_t boff = 0;
  int e;
  unsigned char enc_nonce[128];

  memset(&request,0,sizeof(request));
  memset(&result,0,sizeof(result));
  memcpy(enc_nonce,ENC_NONCE,128);

  // Set authentication/authorisation information
  printk(KERN_DEBUG "calling admctrl_req_set_authinfo()\n");
  admctrl_req_set_authinfo(&request,PUB,CREDS,NONCE,enc_nonce,128);

  // Add a name-value pair
  printk(KERN_DEBUG "calling admctrl_req_add_nvpair()\n");
  if ( admctrl_req_add_nvpair(&request,"app_domain","FFPF") != 0 )
  {
    printk(KERN_ERR "admctrl_req_add_nvpair() failed\n");
    return ;
  }

  // Add a function
  printk(KERN_DEBUG "calling admctrl_req_add_function()\n");
  if ( admctrl_req_add_function(&request,&boff,"pktcount","ixplib","") != 0 )
  {
    printk(KERN_ERR "admctrl_req_add_function() failed\n");
    return ;
  }

  // Submit data to admission control
  printk(KERN_DEBUG "calling authdev_submit()\n");
  if ( (e = authdev_submit(&request,&result,2 * HZ)) != 0 )
  {
    switch( e )
    {
      case - ETIME:
        printk(KERN_ERR "admctrl_req_add_function() timed out\n");
        break;
      case - EAGAIN:
        printk(KERN_ERR "admctrl_req_add_function() try again\n");
        break;
      case - EINTR:
        printk(KERN_ERR "admctrl_req_add_function() interrupted\n");
        break;
      default:
        printk(KERN_ERR "admctrl_req_add_function() failed\n");
        break;
    }
  }
}

/** \brief Module initialisation function 
*/
static int
test_cl_init(void)
{
  run_test();
  return 0;
}

//! Module exit function
static void
test_cl_exit(void)
{
}

module_init(test_cl_init);
module_exit(test_cl_exit);
