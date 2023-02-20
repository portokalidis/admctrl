/* filei.h

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

#ifndef FILEI_H
#define FILEI_H

#include <pthread.h>

//! File interaction thread operation type
typedef ssize_t (*filei_thread_op)(const unsigned char *,size_t,unsigned char *);

//! File interaction thread structure
struct filei_thread {
  pthread_t thread; //!< Thread
  pthread_attr_t thread_attr; //!< Thread attributes

  char *filename; //!< Filename to use
  int fd; //!< File descriptor of opened file
  size_t rd_size; //!< Number of bytes to read each time
  unsigned char *buffer; //!< Buffer to store data read
  filei_thread_op bufop; //!< Operation to call on stored data
};

typedef struct filei_thread filei_thread_t;

filei_thread_t *filei_thread_new(const char *,size_t,filei_thread_op);
void filei_thread_destroy(filei_thread_t *);
int filei_thread_start(filei_thread_t *);
int filei_thread_stop(filei_thread_t *);

#endif
