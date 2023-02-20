/* iolib.c

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

#include "iolib.h"
#include <errno.h>
#include <string.h>
#include "debug.h"

/** \brief Read from a socket
	Reads data from socket into provided buffer. Keeps reading until size
	bytes have been read, EOF is received, or timeout is exceeded. 
	A zero timeout implies blocking I/O.

	\param sock socket to read from
	\param buf buffer to read into
	\param size number of bytes to read
	\param tm timeout of operation

	\return the number of bytes read on success, 0 if blocking I/O has been
	selected and EOF has been received, or -1 on error.
	errno is set by read(), or select() in the case of non-blocking I/O
*/
ssize_t
iolib_read(int sock,unsigned char *buf,size_t size,struct timeval *tm)
{
	fd_set fds;
	struct timeval timer;
	int e;
	ssize_t r,bytes_read = 0;

	FD_ZERO(&fds);
	FD_SET(sock,&fds);
	memcpy(&timer,tm,sizeof(timer));

	do {
		if ( timer.tv_sec || timer.tv_usec )
		{
			if ( (e = select(sock + 1,&fds,NULL,NULL,&timer)) <= 0 )
			{
				if ( e == 0 )
					errno = ETIME;
				return -1;
			}
		}
		if ( (r = read(sock,buf + bytes_read,size - (size_t)bytes_read)) == 0 )
		{
			errno = ENOTCONN;
			return 0;
		}
		else if ( r < 0 )
			return -1;
		bytes_read += r;
	} while( (size_t)bytes_read < size );

	return bytes_read;
}

/** \brief Write to a socket
	Writes data in provided buffer to socket. Keeps writing until size
	bytes have been written, or operation exceeds tm microseconds.
	A zero timeout implies blocking I/O.

	\param sock socket to write to
	\param buf buffer to write 
	\param size number of bytes to write
	\param tm timeout of operation

	\return the number of bytes written on success, or -1 on error.
	errno is set by write(), or select() in the case of non-blocking I/O
*/
ssize_t
iolib_write(int sock,unsigned char *buf,size_t size,struct timeval *tm)
{
	fd_set fds;
	int e;
	struct timeval timer;
	ssize_t w,bytes_written = 0;

	FD_ZERO(&fds);
	FD_SET(sock,&fds);
	memcpy(&timer,tm,sizeof(timer));

	do {
		if ( timer.tv_sec || timer.tv_usec )
		{
			if ( (e = select(sock + 1,NULL,&fds,NULL,&timer)) <= 0 )
			{
				if ( e == 0 )
					errno = ETIME;
				return -1;
			}
		}
		if ( (w = write(sock,buf + bytes_written,size - (size_t)bytes_written)) < 0 )
			return -1;
		bytes_written += w;
	} while( (size_t)bytes_written < size );

	return bytes_written;
}

#ifdef HAVE_LIBSSL
static int
ssl_needs_data(SSL *ssl,int e,int sock,fd_set *rdfds,fd_set *wrfds)
{
	FD_CLR(sock,rdfds);
	FD_CLR(sock,wrfds);

	switch( SSL_get_error(ssl,e) )
	{
		case SSL_ERROR_WANT_READ:
			FD_SET(sock,rdfds);
			break;
		case SSL_ERROR_WANT_WRITE:
			FD_SET(sock,wrfds);
			break;
		default:
			errno = EPROTO;
			return -1;
	}
	return 0;
}

static int
iolib_ssl_call1(SSL *ssl,int sock,struct timeval *tm,int (*fcall)(SSL *))
{
	fd_set rdfds,wrfds;
	int e;
	struct timeval timer;

	// BLOCKING
	if ( tm->tv_sec == 0 && tm->tv_usec == 0 )
		return fcall(ssl);

	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_SET(sock,&rdfds);
	FD_SET(sock,&wrfds);
	memcpy(&timer,tm,sizeof(timer));

	while( 1 )
	{	
		if ( (e = select(sock + 1,NULL,&rdfds,&wrfds,&timer)) <= 0 )
		{
			if ( e == 0 )
				errno = ETIME;
			return -1;
		}
		switch( (e = fcall(ssl)) )
		{
			// Complete
			case 1:
				return 1;
			// Shutdown
			case 0:
				errno = ENOTCONN;
				return 0;
			// Non-blocking I/O - Update FD sets
			default:
				if ( ssl_needs_data(ssl,e,sock,&rdfds,&wrfds) != 0 )
					return -1;
				break;
		}
	}
}

typedef enum { READ, WRITE } ssl_io_t;

static int
do_ssl_call(ssl_io_t call,SSL *ssl,unsigned char *buf,size_t size)
{
	switch( call )
	{
		case READ:
			return SSL_read(ssl,buf,size);
		case WRITE:
			return SSL_write(ssl,buf,size);
		default:
			return -1;
	}
}

static int
iolib_ssl_call2(SSL *ssl,int sock,struct timeval *tm,unsigned char *data,size_t size,ssl_io_t iocall)
{
	fd_set rdfds,wrfds;
	struct timeval timer;
	int e;
	int b,b_done = 0;

	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_SET(sock,&rdfds);
	FD_SET(sock,&wrfds);
	memcpy(&timer,tm,sizeof(timer));

	do {
		if ( timer.tv_sec || timer.tv_usec )
		{
			if ( (e = select(sock + 1,&rdfds,&wrfds,NULL,&timer)) <= 0 )
			{
				if ( e == 0 )
					errno = ETIME;
				return -1;
			}
		}
		b = do_ssl_call(iocall,ssl,data + b_done,size);
		if ( b == 0 )
		{
			errno = ENOTCONN;
			DEBUG_CMD2(printf("iolib_ssl_call2: connection closed\n"));
			return 0;
		}
		else if ( b < 0 )
		{
			if ( ssl_needs_data(ssl,b,sock,&rdfds,&wrfds) != 0 )
			{
				DEBUG_CMD2(printf("iolib_ssl_call2: error returned\n"));
				return -1;
			}
			else
			{
				DEBUG_CMD2(printf("iolib_ssl_call2: needs more data\n"));
				continue;
			}
		}
		b_done += b;
		DEBUG_CMD2(printf("iolib_ssl_call2: bytes %d\n",b));
	} while( (size_t)b_done < size );

	return b_done;
}

/** \brief Perform SSL handshake for server
	Performs SSL handshake in a given time span or fails.
	A zero timeout implies blocking I/O.

	\param ssl SSL session
	\param sock socket used by session
	\param tm timeout of operation in seconds

	\return 1 on success, 0 if the connection was shutdown according to
	protocol, and -1 if operation has timed out or an error has occured (errno
	is set appropriately)
*/
int
iolib_ssl_accept(SSL *ssl,int sock,struct timeval *tm)
{
	return iolib_ssl_call1(ssl,sock,tm,SSL_accept);
}

/** \brief Perform SSL handshake for client
	Performs SSL handshake in a given time span or fails.
	A zero timeout implies blocking I/O.

	\param ssl SSL session
	\param sock socket used by session
	\param tm timeout of operation in seconds

	\return 1 on success, 0 if the connection was shutdown according to
	protocol, and -1 if operation has timed out or an error has occured (errno
	is set appropriately)
*/
int
iolib_ssl_connect(SSL *ssl,int sock,struct timeval *tm)
{
	return iolib_ssl_call1(ssl,sock,tm,SSL_connect);
}

/** \brief Read from an SSL socket
	Tries to read size bytes, before the given timeout.
	A zero timeout implies blocking I/O.

	\param ssl SSL session to use for reading
	\param sock socket used by session
	\param tm timeout of operation in seconds
	\param data memory location reference to store data
	\param size number of bytes to read

	\return the number of bytes read on success, 0 if the connection was shutdown
	according to protocol, and -1 if operation has timed out or an error has
	occured (errno is set appropriately)
*/
int
iolib_ssl_read(SSL *ssl,int sock,unsigned char *data,size_t size,struct timeval *tm)
{
	return iolib_ssl_call2(ssl,sock,tm,data,size,READ);
#if 0
	fd_set fds;
	struct timeval timer;
	int e;
	ssize_t r,bytes_read = 0;

	FD_ZERO(&fds);
	FD_SET(sock,&fds);
	memcpy(&timer,tm,sizeof(timer));

	do {
		if ( timer.tv_sec || timer.tv_usec )
		{
			if ( (e = select(sock + 1,&fds,NULL,NULL,&timer)) <= 0 )
			{
				if ( e == 0 )
					errno = ETIME;
				return -1;
			}
		}
		if ( (r = SSL_read(ssl,data + bytes_read,size)) == 0 )
		{
			errno = ENOTCONN;
			DEBUG_CMD2(printf("iolib_ssl_read: connection closed\n"));
			return 0;
		}
		else if ( r < 0 && ssl_needs_data(ssl,r,sock,&fds,NULL) != 0 )
		{
			DEBUG_CMD2(printf("iolib_ssl_read: error returned\n"));
			return -1;
		}
		bytes_read += r;
		DEBUG_CMD2(printf("iolib_ssl_read: read %d\n",r));
	} while( (size_t)bytes_read < size );

	return bytes_read;
#endif
}

/** \brief Write to an SSL socket
	Tries to write size bytes, before the given timeout.
	A zero timeout implies blocking I/O.

	\param ssl SSL session to use for writing
	\param sock socket used by session
	\param tm timeout of operation in seconds
	\param data data to write
	\param size number of bytes to write

	\return the number of bytes written on success, 0 if the connection was shutdown
	according to protocol, and -1 if operation has timed out or an error has
	occured (errno is set appropriately)
*/
int
iolib_ssl_write(SSL *ssl,int sock,void *data,size_t size,struct timeval *tm)
{
	return iolib_ssl_call2(ssl,sock,tm,data,size,WRITE);
	//return SSL_write(ssl,data,size);
	/*
	fd_set fds;
	struct timeval timer;
	int e;
	ssize_t r,bytes_read = 0;

	FD_ZERO(&fds);
	FD_SET(sock,&fds);
	memcpy(&timer,tm,sizeof(timer));

	do {
		if ( timer.tv_sec || timer.tv_usec )
		{
			if ( (e = select(sock + 1,&fds,NULL,NULL,&timer)) <= 0 )
			{
				if ( e == 0 )
					errno = ETIME;
				return -1;
			}
		}
		if ( (r = SSL_read(ssl,data + bytes_read,size)) == 0 )
		{
			errno = ENOTCONN;
			DEBUG_CMD2(printf("iolib_ssl_read: connection closed\n"));
			return 0;
		}
		else if ( r < 0 && ssl_needs_data(ssl,r,sock,&fds,NULL) != 0 )
		{
			DEBUG_CMD2(printf("iolib_ssl_read: error returned\n"));
			return -1;
		}
		bytes_read += r;
		DEBUG_CMD2(printf("iolib_ssl_read: read %d\n",r));
	} while( (size_t)bytes_read < size );

	return bytes_read;
	*/
}
#endif
