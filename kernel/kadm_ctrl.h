/* kadm_ctrl.h

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

#ifndef KADM_CTRL_H
#define KADM_CTRL_H

#include "admctrl_config.h"
#include "bytestream.h"

/*! \file kadm_ctrl.h
 *  \brief Datatype and function definitions for using & applying 
 *  admission control [KERNEL]
 *  \author Georgios Portokalidis
 */


//! Macro that returns largest number
#ifndef MAX
#define MAX(x,y) (x>y)?x:y
#endif

//! Macro that returns smallest number
#ifndef MIN
#define MIN(x,y) (x>y)?y:x
#endif


//! Admission control policy structure
struct adm_ctrl_policy
{
	char data[MAX_POLICY_SIZE]; //!< The policy data as read from the file
	char **assertions; //!< An array pointing to the different assertions in the policy
	int assertions_num; //!< The number of assertions in the policy
};
//! Admission control policy datatype
typedef struct adm_ctrl_policy adm_ctrl_policy_t;


//! Admission control results structure
/** Used to returned admission control results. */
struct adm_ctrl_result
{
  int PCV; //!< The compliance value of a flow, as returned by keynote
	int error; //!< Error feedback
	size_t resources_num; //!< Number of required resources
};
//! Admission control results datatype
typedef struct adm_ctrl_result adm_ctrl_result_t;

//! Admission control name-value pair
struct adm_ctrl_pair
{
	char name[MAX_PAIR_NAME];
	char value[MAX_PAIR_VALUE];
};
//! Admission control name-value pair datatype
typedef struct adm_ctrl_pair adm_ctrl_pair_t;

//! Admission control request structure
/** Contains all the required data for a client's request to be authenticated
 * and authorized. */
struct adm_ctrl_request
{
  //! Public key
  unsigned char pubkey[MAX_PUBKEY_SIZE];
  //! Credentials
  unsigned char credentials[MAX_CREDENTIALS_SIZE];
  //! Random number provided by mapi
  unsigned int nonce;
  //! Encrypted nonce with private key
  unsigned char encrypted_nonce[MAX_ENC_NONCE_SIZE];
  //! The length of the encrypted nonce
	size_t encrypted_nonce_len;

	//! The number of name-value pair assertions
	unsigned int pairs_num;
	//! The name-value pair assertions
	adm_ctrl_pair_t pair_assertions[MAX_PAIR_ASSERTIONS];

	//! The number of the serialized functions in the buffer
  unsigned int functions_num;
  //! The buffer with the serialized function list
  unsigned char function_list[MAX_FUNCTION_LIST_SIZE];
};
//! The scampi authorization datatype
typedef struct adm_ctrl_request adm_ctrl_request_t;

#endif
