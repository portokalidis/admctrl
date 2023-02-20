/* stack.h

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

#ifndef STACK_H
#define STACK_H

/** \file stack.h
	\brief Definition of a simple stack */

//! Specifies the growth rate of a stack when it is full
#define STACK_GROW_RATE 20

//! The stack structure
struct stack_struct
{
	size_t size; //!< The size of the stack
	size_t unit_size; //!< The size of stored units
	unsigned int head; //!< The head of the stack
	unsigned char *data; //!< Memory area for stack
};

//! The stack datatype
typedef struct stack_struct stack;

char stack_init(stack *,size_t);
void stack_destroy(stack *);
char stack_push(stack *,const void *);
inline void *stack_pop(stack *);
inline void *stack_peek(stack *);
inline char stack_isempty(stack *);

#endif
