/* shm_sync.h

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

#ifndef SHM_SYNC_H
#define SHM_SYNC_H

#include <sys/types.h>

/*! \file shm_sync.h
 *  \brief Definitions of the routines in shm_sync.h
 *  \author Georgios Portokalidis
 */

int shm_create_sem(key_t key);
int shm_open_sem(key_t key);
int shm_destroy_sem(int id);
int shm_data_ready(int id);
int shm_result_ready(int id);
int shm_data_wait(int id);
int shm_result_wait(int id);
int shm_lock(int id);
int shm_unlock(int id);

#endif
