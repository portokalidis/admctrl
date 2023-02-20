/* admctrl_comm.c

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

#include <stddef.h>

#include "shm.h"
#include "shm_sync.h"
#include "adm_ctrl.h"
#include "admctrl_comm.h"


/** \file admctrl_comm.c
	\brief Admission control IPC communication implementation
	\author Georgios Portokalidis
*/


/** \brief Initialise IPC communication

	\param comm Reference to store IPC information

	\return zero on success, or less than zero on failure
*/
int
admctrl_comm_init(admctrl_comm_t *comm)
{
	size_t shm_size = MAX(sizeof(adm_ctrl_request_t),sizeof(adm_ctrl_result_t));

	if ( (comm->shm_addr = shm_create(comm->key,shm_size,&comm->shm_id)) == NULL )
		return - ADMCTRL_COMM_SHM_ERROR;

	if ( (comm->sem_id = shm_create_sem(comm->key)) < 0 )
	{
		shm_destroy(comm->shm_addr,comm->shm_id);
		return - ADMCTRL_COMM_SEM_ERROR;
	}

	return 0;
}


/** \brief Uninitialise IPC communication

	\param comm Reference to IPC information
*/
void
admctrl_comm_uninit(admctrl_comm_t *comm)
{
  if ( shm_destroy(comm->shm_addr,comm->shm_id) <= 0 )
    shm_destroy_sem(comm->sem_id);
}
