/* stack.c

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

#include <stdlib.h>
#include <string.h>

#include "stack.h"


/** \brief Initialize a stack
	\param s Pointer to a stack
	\param us Unit size of item stored on stack

	\return 0 on success, or 1 on failure
	*/
char
stack_init(stack *s,size_t us)
{
	s->head = 0;
	s->unit_size = us;
	if ( (s->data = (unsigned char *)malloc(STACK_GROW_RATE * sizeof(unsigned char) * us)) == NULL )
	{
		s->size = 0;
		return 1;
	}
	s->size = STACK_GROW_RATE;
	return 0;
}


/** \brief Destroy a stack
	\param s Pointer to a stack

	\return 0 on success, or 1 on failure
	*/
void
stack_destroy(stack *s)
{
		free(s->data);
		s->size = s->unit_size = 0;
		s->head = 0;
}


/** \brief Push an item to the stack
	\param s Pointer to stack
	\param n Item to push

	\return 0 on success, or 1 on failure
	*/
char
stack_push(stack *s,const void *n)
{
	// Check if stack needs growing
	if ( s->head >= s->size )
	{
		unsigned char *t;
		if ( (t = (unsigned char *)realloc(s->data,(s->size + STACK_GROW_RATE) * sizeof(unsigned char) * s->unit_size)) == NULL )
			return 1;
		s->data = t;
		s->size += STACK_GROW_RATE;
	}

	memcpy(s->data + s->head++ * s->unit_size,n,s->unit_size);
	return 0;
}


/** \brief Pop the item on the head of the stack
	\param s Pointer to stack

	\return The item on the head of the stack, or NULL if the stack
	is empty
	*/
void *
stack_pop(stack *s)
{
	return (s->head == 0)? NULL:s->data + --s->head * s->unit_size;
}


/** \brief Peek the item on the head of the stack
	\param s Pointer to stack

	\return The item on the head of the stack, or NULL if the stack
	is empty
	*/
void *
stack_peek(stack *s)
{
	return (s->head == 0)? NULL:s->data + (s->head - 1) * s->unit_size; 
}


/** \brief Checks whether the stack is empty
	\param s Pointer to stack

	\return 1 if the stack is empty, or 0 if not
	*/
char
stack_isempty(stack *s)
{
	return (s->head == 0)? 1:0;
}
