/* bytestream.h

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

#ifndef BYTESTREAM_H
#define BYTESTREAM_H

/*! \file bytestream.h
 *  \brief The definition of the bytestream datatype
 */

//! Bytestream stucture
struct bytestream_struct
{
	unsigned char *data; //!< The actual data contained in the stream
	unsigned int length; //!< The length of the stream
};

//! Bytestream datatype
typedef struct bytestream_struct bytestream;

//! Set a bytestream to NULL
#define BS_NULL (bytestream){(unsigned char *)0,0}
//! Checks if a bytestream is NULL
#define BS_ISNULL(bs) (!(bs.data && bs.length))
//! Free the data of a bytestream and set it to NULL
#define BS_FREE(bs) if (bs.data!=NULL) free(bs.data); bs.data = (char *)0; bs.length = 0;
//! Allocate a new bytestream
#define BS_NEW(bs,x) bs.data=(unsigned char *)malloc(x*sizeof(unsigned char)); bs.length=x;

#endif
