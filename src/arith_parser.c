/* arith_parser.c

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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <math.h>

#include "stack.h"
#include "string_buf.h"
#include "arith_parser.h"
#include "debug.h"


/** \file arith_parser.c
 * \brief Arithmetic expressions parsing library using unsigned long long numbers
 *  \author Georgios Portokalidis
 */

static char *stream_p = NULL;

/** \brief Extract an arithmetical expression token from string

	The first call should have s set to the string containing the tokens 
	to be extracted. Subsequent calls should have the first argument set
	to NULL to continue processing the first call's argument until no 
	more tokens are available.
	When token NUM is returned the string representing the number read is
	stored in numbuf.

	\param s String to be tokenized, or NULL to use the string from a previous calll
	\param numbuf Buffer where numbers read are going to be stored
	\param maxnum Size of numbuf buffer

	\return The type of the token read, or INV if there was an invalid token, 
	or EMPTY if the end of the string was encountered
	*/
arith_op_t
arith_parser_token(char *s,char *numbuf,size_t maxnum)
{
	size_t i;
	arith_op_t ret;

	if ( s != NULL )
		stream_p = s;
	else if ( stream_p == NULL )
		return INV;

	// Skip spaces
	for( ; isspace(*stream_p) ; ++stream_p )
		;

	for(i = 0; *stream_p != '\0' ; ++stream_p)
	{
		// Part of a number [0-9] or '-','.'
		if ( isdigit(*stream_p) || *stream_p == '.' ||
				((*stream_p == '-' || *stream_p == '+') && isdigit(*(stream_p+1))) )
		{
			if ( i >= (maxnum - 1) )
      {
        DEBUG_CMD2(printf("DEBUG arith_parser: too many digits\n"));
				return INV;
      }
			else
				numbuf[i++] = *stream_p;
		}
		// Number ends
		else if ( i > 0 )
			break;
		// Operator
		else
		{
			switch( *stream_p )
			{
				case '+':
					ret = ADD;
					break;
				case '-':
					ret = SUB;
					break;
				case '*':
					ret = MUL;
					break;
				case '/':
					ret = DIV;
					break;
				case '(':
					ret = LPAR;
					break;
				case ')':
					ret = RPAR;
					break;
				default:
					ret = INV;
					break;
			}
			++stream_p;
			return ret;
		}
	}//End for

	// Return number
	if ( i > 0 )
	{
		numbuf[i] = '\0';
		return NUM;
	}

	return EMPTY;
}

static char fpe_exception = 0;

static void
fpe_handler(int data)
{
  DEBUG_CMD2(printf("DEBUG arith_parser: FPE exception\n"));
	fpe_exception = 1;
}

/** \brief Parse a postfix arithmetic expression
  Empty strings are treated as valid expressions and are evaluated as 0.
	\param s String containing the expression
	\param res Reference where result is going to be placed

	\return 0 on success, or -1 on failure
	*/
int
postfix_expr_parse(char *s,double *res)
{
	stack st;
	double n,n1,n2;;
	arith_op_t e;
	char buf[MAX_NUMBER_SIZE];

  if ( *s == '\0' )
  {
    *res = 0.0;
    return 0;
  }

  if ( stack_init(&st,sizeof(double)) )
		return -1;

	fpe_exception = 0;
	signal(SIGFPE,fpe_handler);

	e = arith_parser_token(s,buf,MAX_NUMBER_SIZE);
	while ( e != EMPTY && e != INV )
	{
		// Push number to stack
		if ( e == NUM )
		{
			n = strtod(buf,NULL);
			if ( stack_push(&st,&n) )
				goto error;
		}
		// Pop 2 numbers, apply operator and push result
		else
		{
			if ( stack_isempty(&st) )
				goto error;
			n2 = *(double *)stack_pop(&st);
			if ( stack_isempty(&st) )
				goto error;
			n1 = *(double *)stack_pop(&st);
			switch( e )
			{
				case ADD:
					n = n1 + n2;
					break;
				case SUB:
					n = n1 - n2;
					break;
				case MUL:
					n = n1 * n2;
					break;
				case DIV:
					n = n1 / n2;
					break;
				default:
					goto error;
			}
			if ( fpe_exception || fpclassify(n) != FP_NORMAL )
				goto error;
			if ( stack_push(&st,&n) )
				goto error;
		}
		// Get next token
		e = arith_parser_token(NULL,buf,MAX_NUMBER_SIZE);
	}// End while()
  

	if ( stack_isempty(&st) )
		goto error;
  *res = *(double *)stack_pop(&st);
	stack_destroy(&st);
	signal(SIGFPE,SIG_DFL);
	return e;

error:
	stack_destroy(&st);
	signal(SIGFPE,SIG_DFL);
	return -1;
}


/** \brief Parse an infix arithmetic expression
  Empty strings are treated as valid expressions and are evaluated as 0.
	\param s String containing the expression
	\param res Reference where result is going to be placed

	\return 0 on success, or -1 on failure
	*/
int 
infix_expr_parse(char *s,double *res)
{
  char buf[MAX_NUMBER_SIZE];
	string_buf_t str_buf;
	stack st;
	char t,t1,t2;
	arith_op_t e;

  if ( *s == '\0' )
  {
    *res = 0.0;
    return 0;
  }

  if ( stack_init(&st,sizeof(char)) )
		return -1;
	if ( string_buf_init(&str_buf,NULL) )
	{
		stack_destroy(&st);
		return -1;
	}

	e = arith_parser_token(s,buf,MAX_NUMBER_SIZE);
	while( e != EMPTY && e != INV )
	{
		// Append number and space to string buffer
		if ( e == NUM )
		{
			if ( string_buf_push_s(&str_buf,buf) )
				goto error;
			if ( string_buf_push_c(&str_buf,' ') )
				goto error;
		}
		else
		{
			t1 = '/';
			t2 = '-';
			switch( e )
			{
				case LPAR:
					t = '(';
					if ( stack_push(&st,&t) )
						goto error;
					break;
				case RPAR:
					while( 1 )
					{
						if ( stack_isempty(&st) )
							goto error;
						t = *(char *)stack_pop(&st);
						if ( t != '(' )
						{
							if ( string_buf_push_c(&str_buf,t) )
								goto error;
							if ( string_buf_push_c(&str_buf,' ') )
								goto error;
						}
						else
							break;
					}
					break;
				case MUL:
					t1 = '*';
				case DIV:
					if ( stack_push(&st,&t1) )
						goto error;
					break;
				case ADD:
					t2 = '+';
				case SUB:
					while ( stack_isempty(&st) == 0 )
					{
						if ( (t = *(char *)stack_peek(&st)) == '*' || t == '/' )
						{
							stack_pop(&st);
							if ( string_buf_push_c(&str_buf,t) )
								goto error;
							if ( string_buf_push_c(&str_buf,' ') )
								goto error;
						}
						else
							break;
					}
					if ( stack_push(&st,&t2) )
						goto error;
					break;
				default:
					goto error;
			}
		}
		// Get next token
		e = arith_parser_token(NULL,buf,MAX_NUMBER_SIZE);
	}//End while

	if ( e != EMPTY )
		goto error;

	// Push stack to string
	while( stack_isempty(&st) == 0 )
	{
		t = *(char *)stack_pop(&st);
		if ( string_buf_push_c(&str_buf,t) )
			goto error;
		if ( string_buf_push_c(&str_buf,' ') )
			goto error;
	}

	if ( postfix_expr_parse(string_buf_get(&str_buf),res) != 0 )
		goto error;

	return 0;

error:
	stack_destroy(&st);
	string_buf_destroy(&str_buf);
	return -1;
}
