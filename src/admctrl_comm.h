/* admctrl_comm.h

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

#ifndef ADMCTRL_COMM_H
#define ADMCTRL_COMM_H

#include <sys/types.h>

/** \file admctrl_comm.h
	\brief Admission control IPC communication definitions
	\author Georgios Portokalidis
*/

//! Errors definitions
enum { 
	ADMCTRL_COMM_SHM_ERROR = 1,
	ADMCTRL_COMM_SEM_ERROR
};


// IPC information structure
struct admctrl_comm
{
	key_t key;
	int shm_id;
	void *shm_addr;
	int sem_id;
};
// IPC communication datatype
typedef struct admctrl_comm admctrl_comm_t;

int admctrl_comm_init(admctrl_comm_t *);
void admctrl_comm_uninit(admctrl_comm_t *);

#endif
