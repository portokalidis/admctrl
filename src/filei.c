/* filei.c

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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "filei.h"
#include "debug.h"


/** \brief Allocate and initialise a new file interaction  thread structure

  \param fn filename that the thread is going to use
  \param rd_size the amount of bytes to read each time
  \param op the operation to call after reading

  \return a new filei_thread structure, or NULL if memory couldn't be allocated
*/
filei_thread_t *
filei_thread_new(const char *fn,size_t rd_size,filei_thread_op op)
{
  filei_thread_t *ft;

  if ( (ft = calloc(1,sizeof(filei_thread_t))) == NULL )
  {
    errno = ENOMEM;
    return NULL;
  }

  ft->rd_size = rd_size;
  if ( (ft->buffer = malloc(rd_size)) == NULL )
    goto buffer_error;

  if ( (ft->filename = strdup(fn)) == NULL )
    goto filename_error;

  ft->bufop = op;

  return ft;

filename_error:
  free(ft->buffer);
buffer_error:
  free(ft);
  errno = ENOMEM;
  return NULL;
}


/** \brief Destroy a file interaction thread structure, de-allocating its memory

  \param ft reference to file interaction thread structure
*/
void
filei_thread_destroy(filei_thread_t *ft)
{
  free(ft->buffer);
  free(ft->filename);
  free(ft);
}


/** \brief file interaction thread work routine
  It reads data from file, calls the assigned operation on the data read and
  writes results to file. Normally it should be used with device file.

  \param arg reference to file interaction thread structure

  \return always NULL
*/
static void *
filei_thread_run(void *arg)
{
  filei_thread_t *ft = (filei_thread_t *)arg;
  ssize_t wr_size;
  int e;
  sigset_t blksigs;

  // Ignore these signals. Only control thread needs to capture these.
  sigemptyset(&blksigs);
  sigaddset(&blksigs,SIGINT);
  sigaddset(&blksigs,SIGQUIT);
  sigaddset(&blksigs,SIGHUP);
  pthread_sigmask(SIG_BLOCK,&blksigs,NULL);

  // Cancel as soon as we receive a cancelation
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

  while( 1 )
  {
    DEBUG_CMD2(printf("DEBUG filei: reading ...\n"));
    if ( (e = read(ft->fd,ft->buffer,ft->rd_size)) < ft->rd_size )
    {
#if DEBUG > 1
      if ( e < 0 )
      {
        perror("read");
        break;
      }
      else
        fprintf(stderr,"read returned less than %u bytes\n",ft->rd_size);
#endif
      continue;
    }
    DEBUG_CMD2(printf("DEBUG filei: calling operation ...\n"));
    if ( (wr_size = ft->bufop(ft->buffer,ft->rd_size,ft->buffer)) <= 0 )
    {
      DEBUG_CMD(fprintf(stderr,"filei->bufop returned error\n"));
      continue;
    }
    DEBUG_CMD2(printf("DEBUG filei: writing ...\n"));
    if ( (e = write(ft->fd,ft->buffer,wr_size)) < wr_size )
    {
#if DEBUG >1 
      if ( e < 0 )
      {
        perror("write");
        break;
      } 
      else
        fprintf(stderr,"write less than %d bytes\n",wr_size);
#endif
    }
  }

  return NULL;
}


/** \brief Start a file interaction thread

  \param ft reference to file interaction structure
  
  \return 0 on success, or -1 on failure. errno is set appropriately
*/
int
filei_thread_start(filei_thread_t *ft)
{
  if ( (ft->fd = open(ft->filename,O_RDWR)) == -1 )
    return -1;
  pthread_attr_init(&ft->thread_attr);
  if ( pthread_create(&ft->thread,&ft->thread_attr,filei_thread_run,ft) != 0 )
    goto thread_error;
  return 0;

thread_error:
  close(ft->fd);
  return -1;
}


/** \brief Stop a file interaction thread

  \param ft reference to file interaction structure

  \return 0 on success, or -1 on failure. errno is set appropriately
*/
int
filei_thread_stop(filei_thread_t *ft)
{
  if ( pthread_cancel(ft->thread) != 0 )
    return -1;
  return close(ft->fd);
}
