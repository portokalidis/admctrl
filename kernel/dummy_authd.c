/* dummy_authd.c

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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "adm_ctrl.h"

static char *device_name = NULL;

static inline void
parse_arguments(int argc,char **argv)
{
  if ( argc < 2 )
  {
    fprintf(stderr,"%s: Missing argument(s)\n",*argv);
    fprintf(stderr,"Usage: %s DEVICE_NAME\n",*argv);
    exit(1);
  }
  device_name = argv[1];
}

static int fd;

static void
cleanup(int data)
{
  printf("\nClosing device %s ...",device_name);
  if ( close(fd) != 0 )
  {
    putchar('\n');
    perror("close");
    data = 1;
  }
  putchar('\n');
  exit(data);
}
  
int 
main(int argc,char **argv)
{
  adm_ctrl_request_t request;
  adm_ctrl_result_t result;

  parse_arguments(argc,argv);

  printf("Opening device %s ...",device_name);
  if ( (fd = open(device_name,O_RDWR)) == -1 )
  {
    putchar('\n');
    perror("open");
    return 1;
  }
  putchar('\n');

  signal(SIGHUP,cleanup);
  signal(SIGTERM,cleanup);
  signal(SIGQUIT,cleanup);
  signal(SIGINT,cleanup);

  while( 1 )
  {
    printf("Reading ..."); fflush(stdout);
    if ( read(fd,&request,sizeof(adm_ctrl_request_t)) < sizeof(adm_ctrl_request_t) )
    {
      putchar('\n');
      perror("read");
      break;
    }
    memcpy(&result,&request,sizeof(adm_ctrl_result_t));
    printf("\nWriting ..."); fflush(stdout);
    if ( write(fd,&result,sizeof(adm_ctrl_result_t)) < sizeof(adm_ctrl_result_t) )
    {
      putchar('\n');
      perror("write");
      break;
    }
    putchar('\n');
  }

  cleanup(1);
  return 0;
}
