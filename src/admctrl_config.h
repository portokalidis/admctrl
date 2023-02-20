/* admctrl_config.h

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

#ifndef ADMCTRL_CONFIG_H
#define ADMCTRL_CONFIG_H

/*! \file admctrl_config.h
 *  \brief Definitions of constants,pathnames etc.
 *  \author Georgios Portokalidis
 */

/***** ADMISSION CONTROL CONFIGURATION *****/
//! Maximum size of public key string
#define MAX_PUBKEY_SIZE 4096
//! Maximum size of private key string
#define MAX_PRIVKEY_SIZE 4096
//! Maximum size of credentials string
#define MAX_CREDENTIALS_SIZE 8192
//! Maximum size of encoded nonce
#define MAX_ENC_NONCE_SIZE 256
//#define MAX_DEVICE_NAME_SIZE 256
//! Maximum size of function list
#define MAX_FUNCTION_LIST_SIZE 65536
//! Maximum size of policy string
#define MAX_POLICY_SIZE 65536
//! Maximum action name size. Used for function assertions
#define MAX_ACTION_NAME_SIZE 64
//! Maximum action value size. Used for function assertions
#define MAX_ACTION_VALUE_SIZE 512
//! Maximum number of arguments a function can have 
#define MAX_ARGUMENTS_NUMBER 12
#define MAX_PAIR_NAME 64
#define MAX_PAIR_VALUE 512
#define MAX_PAIR_ASSERTIONS 16
/******************************************/



/**** DEFAULT CONFIGURABLE VALUES FOR AUTHD ****/
//! The filename to use for shared memory
#define DEFAULT_SHM_FILE "/tmp/.authd"
//! The project id to use for shared memory
#define DEFAULT_SHM_PROJECT_ID 'A'
//! The file where scampi's policy is defined
#define DEFAULT_POLICY_FILE "/etc/authd/policy"
//! Resource control home
#define DEFAULT_RESOURCE_CTRL_HOME "/etc/authd/resourcectrl"
//! Resource control database name
#define DEFAULT_RESOURCE_DBNAME "resource.db"
//! The string to prepended to SYSLOG entries
#define SYSLOG_PREPEND "authd"
/***********************************************/


#ifdef WITH_RESOURCE_CONTROL
/**** RESOURCE CONTROL CONFIGURATION ****/
//! Maximum length of variable cost formula string
#define RESOURCE_CTRL_MAX_VAR_FORM_LEN 64
//! Maximum length of resource type description string
#define RESOURCE_CTRL_MAX_RES_DESCR_LEN 64
//! Maximum number of resource types a request can consume
#define RESOURCE_CTRL_MAX_RESOURCES 32
/****************************************/
#endif

#endif
