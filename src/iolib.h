/* iolib.h

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

#ifndef IOLIB_H
#define IOLIB_H

/*! \file iolib.h
  \brief Definition of I/O library functions
  \author Georgios Portokalidis
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <sys/time.h>

ssize_t iolib_read(int,unsigned char *,size_t,struct timeval *);
ssize_t iolib_write(int,unsigned char *,size_t,struct timeval *);

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>

int iolib_ssl_accept(SSL *,int,struct timeval *);
int iolib_ssl_connect(SSL *,int,struct timeval *);
int iolib_ssl_read(SSL *,int,unsigned char *,size_t,struct timeval *);
int iolib_ssl_write(SSL *,int,void *,size_t,struct timeval *);

#endif

#endif
