/* shm.h

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

#ifndef SHM_H
#define SHM_H

#include <sys/types.h>

/*! \file shm.h
 *  \brief Definitions of the routines in shm.c
 *  \author Georgios Portokalidis
 */

//! The access permissions used to create or open a shared memory segment
#define SHM_PERMS 0600

void *shm_create(key_t key,int size,int *id);
void *shm_open(key_t key);
int shm_destroy(const void *addr,int id);
int shm_close(const void *addr);

#endif
