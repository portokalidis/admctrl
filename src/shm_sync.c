/* shm_sync.c

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

#include <errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include "shm_sync.h"

/*! \file shm_sync.c
 *  \brief Synchronization routines for accessing a shared memory segment
 *  \author Georgios Portokalidis
 *
 *  These routines aim to provide synchronization for client-server processes
 *  accessing a shared memory segment.
 *  Multiple clients can use the locking routines to gain access to the server.
 *  The signaling routines consist a control path with the server.
 */

//! Number of semaphore operations for mapi lock
#define MAPI_LOCK_OPS 2

//! Try lock and lock operation 
/** Try semaphore 0 and increase it */
static struct sembuf op_mapi_lock[MAPI_LOCK_OPS] = {
	{ 0, 0, 0 },
  { 0, 1, SEM_UNDO }
};

//! Number of semaphore operations for mapi unlock
#define MAPI_UNLOCK_OPS 1

//! Unlock operation
/** Consume semaphore 0. */
static struct sembuf op_mapi_unlock[MAPI_UNLOCK_OPS] = {
	{ 0, -1, IPC_NOWAIT | SEM_UNDO }
};

//! Number of semaphore operations for wait data ready signal
#define DATA_WAIT_OPS 2

//! Wait signal data ready operation
/** Consume semaphore 1, increase sem 0 */
static struct sembuf op_data_wait[DATA_WAIT_OPS] = {
	{ 1, -1, 0 },          
	{ 0, 1, SEM_UNDO }    
};

//! Number of semaphore operations for wait data ready signal
#define RESULT_READY_OPS 2

//! Transmit signal result ready operation
/** Consume semaphore 0, increase semaphore 2 */
static struct sembuf op_result_ready[RESULT_READY_OPS] = {
	{ 0, -1, SEM_UNDO },
  { 2, 1, 0 }
};

//! Number of semaphore operations for transmitting data ready signal
#define DATA_READY_OPS 1

//! Transmit signal data ready operation
/** Increase semaphore 1. */
static struct sembuf op_data_ready[DATA_READY_OPS] = {
	{ 1, 1, 0 }  
};

//! Number of semaphore operations for wait result ready signal
#define RESULT_WAIT_OPS 1

//! Wait signal result ready
//** Consume semaphore 2 */
static struct sembuf op_result_wait[RESULT_WAIT_OPS] = {
	{ 2, -1, 0 }
};


#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
  int val;                  /* value for SETVAL */
  struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
  unsigned short *array;    /* array for GETALL, SETALL */
                           /* Linux specific part: */
  struct seminfo *__buf;    /* buffer for IPC_INFO */
};
#endif



/** \brief Create a semaphore set to synchronize processes 
 * accessing a shared memory segment
 *
 * \param key The key of the semaphore set as returned from ftok()
 *
 * \return The id of the semaphore set on success, or -1 on failure
 */
int 
shm_create_sem(key_t key)
{
	int id;

	if ( key == IPC_PRIVATE || key < 0 )
		return -1;

	if ( (id = semget(key,3,0600 | IPC_CREAT )) < 0 )
		return -1;

	return id;
}


/** \brief Open a semaphore set created with shm_create_sem
 *
 *\param key The key of the semaphore set as returned from ftok()
 *
 *\return The id of the semaphore set on success, or -1 on failure
 */
int 
shm_open_sem(key_t key)
{
	int id;

	if ( key == IPC_PRIVATE || key <= 0 )
		return -1;

	if ( (id = semget(key,0,0)) < 0 )
	{
		return -1;
	}

	return id;
}


/** \brief Destroy a semaphore set created using shm_create_sem
 *
 * \param id The index number of the semaphore set
 *
 * \return Zero on success, or -1 on failure
 */
int 
shm_destroy_sem(int id)
{
	if ( semctl(id,0,IPC_RMID) < 0 )
		return -1;
	
	return 0;
}


/** \brief Lock the shared memory
 *
 * Should be called from the requesting side, if it is multiprocessed.
 * Blocks if shared memory is already locked.
 *
 *\param id The index number of the semaphore set
 *
 *\return 0 on success, or -1 on failure
 */
int
shm_lock(int id)
{
  union semun s;

  // Lock
	if ( semop(id,op_mapi_lock,MAPI_LOCK_OPS) < 0 )
		return -1;

  // Reset semaphores 1 & 2
  s.val = 0;
  if ( semctl(id,1,SETVAL,s) < 0 || semctl(id,2,SETVAL,s) < 0 )
    return -1;

	return 0;
}


/** \brief Unlock the shared memory
 *
 * Should be called when the requesting side has finished, and it 
 * used shm_lock earlier.
 *
 *\param id The index number of the semaphore set
 *
 *\return 0 on success, or -1 on failure
 */
int
shm_unlock(int id)
{

	if ( semop(id,op_mapi_unlock,MAPI_UNLOCK_OPS) < 0 )
    // If it is not locked don't fail
		if ( errno != EAGAIN )
      return -1;

	return 0;
}


/** \brief  Wait for the data ready signal
 *
 * Blocks the serving side until the request data have been placed in
 * shared memory and shm_data_ready() is called
 *
 *\param id The index number of the semaphore set
 *
 * \return 0 on success, or -1 on failure
 */
int
shm_data_wait(int id)
{
	if ( semop(id,op_data_wait,DATA_WAIT_OPS) < 0 )
		return -1;

	return 0;
}


/** \brief Transmits the data ready signal
 *
 * Should be called after the requesting side has placed the data
 * in shared memory.
 *
 * \param id The index number of the semaphore set
 *
 * \return 0 on success, or -1 on failure
 */
int 
shm_data_ready(int id)
{
	if ( semop(id,op_data_ready,DATA_READY_OPS) < 0 )
		return -1;

	return 0;
}


/** \brief Transmit the result ready signal
 *
 * Should be called when the result has been placed in shared memory, 
 * by the serving side
 *
 * \param id is the index number of the semaphore set
 *
 * Returns 0 on success, or -1 on failure
 */
int 
shm_result_ready(int id)
{
	if ( semop(id,op_result_ready,RESULT_READY_OPS) < 0 )
		return -1;

	return 0;
}

/** \brief Wait for the result ready signal
 *
 * Blocks the requesting side until a valid result has been 
 * placed in shared memory and shm_result_ready() is called.
 *
 *\param id The index number of the semaphore set
 *
 *\return 0 on success, or -1 on failure
 */
int 
shm_result_wait(int id)
{
	if ( semop(id,op_result_wait,RESULT_WAIT_OPS) < 0 )
		return -1;

	return 0;
}
