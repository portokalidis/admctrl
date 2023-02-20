/* shm.c

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
#include <sys/ipc.h>
#include <sys/shm.h>

#include "shm.h"

/*! \file shm.c
 *  \brief Routines to create and access shared memory segments
 *  \author Georgios Portokalidis
 */

/** \brief Create a shared memory segment
 *
 * If the segment already exists it returns it. The access permissions
 * for the segment are set to SHM_PERMS.
 *
 * \param key The key of the segment as returned from ftok()
 * \param size The size of the segment to be created
 * \param id Pointer to integer, used to return the id of the segment created
 *
 * \return The address where the segment was attached in the processe's memory
 * space, or NULL on failure
 */
void *
shm_create(key_t key,int size,int *id)
{
	void *addr = NULL;

	if ( key == IPC_PRIVATE || key < 0 )
		return NULL;

	if ( (*id = shmget(key,size,SHM_PERMS | IPC_CREAT)) < 0 )
		return NULL;

	if ( (addr = shmat(*id,0,SHM_PERMS)) <= (void *)0 )
		return NULL;

	return addr;
}


/** \brief Open a shared memory segment
 *
 * Opens an already existing segment. If the segment doesn't exist it fails.
 *
 * \param key The key of the segment as returned from ftok()
 *
 * \return The address where the segment was attached in the process'es memory
 * space, or NULL on failure
 */
void *
shm_open(key_t key)
{
	int id;
	void *addr;

	if ( (id = shmget(key,0,0)) < 0 )
		return NULL;

	if ( (addr = shmat(id,0,0600)) < (void *)0 )
		return NULL;

	return addr;
}


/** \brief Close a shared memory segment
 * 
 * \param addr The address where the segment is attached in the process'es
 * memory space
 *
 * \return 0 on success, or -1 on failure
 */
int 
shm_close(const void *addr)
{
	if ( shmdt(addr) < 0 )
		return -1;

	return 0;
}


/** \brief Close and destroy a shared memory segment
 *
 * Detaches a shared memory segment and issues a control command 
 * to be destroyed when all processes have detached.
 *
 * \param addr The address where the segment is attached in the process'es
 * memory space
 * \param id The id of the segment
 *
 * \return the number of processes still attached to the segment (0 means
 *	that the segment was actually destroyed), or -1 on failure
 */
int 
shm_destroy(const void *addr,int id)
{
	struct shmid_ds buf;

	if ( id <= 0 )
		return -1;

	if ( shmdt(addr) < 0 )
		return -1;

	if ( shmctl(id,IPC_STAT,&buf) < 0 )
		return -1;

	if ( buf.shm_nattch == 0 )
		if ( shmctl(id,IPC_RMID,0) < 0 )
			return -1;

	return (int)buf.shm_nattch;
}
