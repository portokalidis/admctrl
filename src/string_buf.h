/* string_buf.h

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

#ifndef STRING_BUF_H
#define STRING_BUF_H

/** \file string_buf.h
	\brief Definition of a growable string buffer type */
	
//! Specifies the growth rate of the string buffer when it is full
#define STRING_BUF_GROW_RATE 80

//! The string buffer structure
struct string_buf_struct
{
	unsigned int length;
	unsigned int size;
	char *data;
};

//! The string buffer datatype
typedef struct string_buf_struct string_buf_t;

char string_buf_init(string_buf_t *,const char *);
inline void string_buf_destroy(string_buf_t *);
char string_buf_push_s(string_buf_t *,const char *);
char string_buf_push_c(string_buf_t *,const char);
inline char *string_buf_get(string_buf_t *);
inline void string_buf_reset(string_buf_t *);

#endif
