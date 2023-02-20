/* string_buf.c

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

#include <string.h>
#include <stdlib.h>
#ifdef DEBUG
#include <stdio.h>
#endif

#include "string_buf.h"

/** \brief Initialize a string buffer
	\param s Pointer to a string buffer
	\param d Initial value for string buffer, or NULL for an empty one

	\return 0 on success, or 1 on failure
	*/
char
string_buf_init(string_buf_t *s,const char *d)
{
	size_t t,size = STRING_BUF_GROW_RATE;

	if ( d != NULL && (t = strlen(d)) > size )
		size = t + 1;

	if ( (s->data = (char *)malloc(size * sizeof(char))) == NULL )
	{
		s->size = 0;
		return 1;
	}

	s->size = size;
	if ( d == NULL )
	{
		s->data[0] = '\0';
		s->length = 0;
	}
	else
	{
		strcpy(s->data,d);
		s->length = size - 1;
	}
	return 0;
}


/** \brief Destroy a string buffer
	\param s Pointer to a string buffer
	*/
void
string_buf_destroy(string_buf_t *s)
{
	free(s->data);
	s->length = s->size = 0;
}


/** \brief Push a string to the end of the string buffer
	\param s Pointer to the string buffer
	\param d The string to push

	\return 0 on success, or 1 on failure
	*/
char
string_buf_push_s(string_buf_t *s,const char *d)
{
	char *t;
	size_t size,length;

	length = strlen(d);

	// Grow string buffer
	if ( (size = length + s->length + 1) > s->size )
	{
		if ( (s->size + STRING_BUF_GROW_RATE) > size )
			size = s->size + STRING_BUF_GROW_RATE;
		if ( (t = (char *)realloc(s->data,size * sizeof(char))) == NULL )
		{
#ifdef DEBUG
			printf("DEBUG string_buf_push_s: attemp to grow string_buf failed\n");
#endif
			return 1;
		}
		s->data = t;
		s->size = size;
#ifdef DEBUG
		printf("DEBUG string_buf_push_s: string_buf has grown\n");
#endif
	}

	strcpy(s->data + s->length,d);
	s->length += length;
	return 0;
}


/** \brief Push a character to the end of the string buffer
	\param s Pointer to the string buffer
	\param c The character to push

	\return 0 on success, or 1 on failure
	*/
char
string_buf_push_c(string_buf_t *s,const char c)
{
	char *t;

	// Grow string buffer
	if ( s->size == (s->length - 1) )
	{
		if ( (t = (char *)realloc(s->data,(s->size + STRING_BUF_GROW_RATE) * sizeof(char))) == NULL )
		{
#ifdef DEBUG
			printf("DEBUG string_buf_push_c: attemp to grow string_buf failed\n");
#endif
			return 1;
		}
		s->data = t;
		s->size += STRING_BUF_GROW_RATE;
#ifdef DEBUG
		printf("DEBUG string_buf_push_c: string_buf has grown\n");
#endif
	}

	s->data[s->length++] = c;
	s->data[s->length] = '\0';
	return 0;
}


/** \brief Get the data of the string buffer
	\param s Pointer to the string buffer

	\return A pointer to the string buffer's data
	*/
char *
string_buf_get(string_buf_t *s)
{
	return s->data;
}

void
string_buf_reset(string_buf_t *s)
{
	s->data[0] = '\0';
	s->length = 0;
}
