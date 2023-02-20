/* admctrlcl.h

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

#ifndef ADMCTRLCL_H
#define ADMCTRLCL_H

#include <sys/time.h>
#include <adm_ctrl.h>

/*! \file admctrlcl.h
  \brief Definition of methods for admission control clients
  \author Georgios Portokalidis
*/

typedef enum { SOCKET_CL, SSL_CL, IPC_CL } admctrlcl_type;

//! Data used by an admission control client to store active request and result
struct admctrlcl_data
{
	//size_t fbuf_size; //!< Used size of function list buffer in request
	char free_request; //!< Free request on destroy
	adm_ctrl_request_t *request; //!< Admission control request
	char free_result; //!< Free result on destroy
	adm_ctrl_result_t *result; //!< Admission control result
};
typedef struct admctrlcl_data admctrlcl_data_t;

//! Data describing an admission control client
struct admctrlcl
{
	admctrlcl_type type; //! Type of client
	struct timeval timeout; //! Timeout used for communication with server
	admctrlcl_data_t data; //! Data of active request and result
	char persistent; //! Persistent connection with server
	void *comm; //! Data concerning the communication with the server
};
typedef struct admctrlcl admctrlcl_t;

admctrlcl_t *admctrlcl_new_ipc(const char *,int,char,struct timeval *,adm_ctrl_request_t *,adm_ctrl_result_t *);
admctrlcl_t *admctrlcl_new_socket(const char *,int,char,struct timeval *,adm_ctrl_request_t *,adm_ctrl_result_t *);
int admctrlcl_use_SSL(admctrlcl_t *,const char *,const char *);
void admctrlcl_destroy(admctrlcl_t *);
extern inline void admctrlcl_set_request(admctrlcl_t *,const adm_ctrl_request_t *);
extern inline adm_ctrl_result_t *admctrlcl_get_result(admctrlcl_t *);
int admctrlcl_comm_open(admctrlcl_t *);
int admctrlcl_comm_close(admctrlcl_t *);
extern inline void admctrlcl_reset(admctrlcl_t *);
int admctrlcl_submit_request(admctrlcl_t *);

#endif
