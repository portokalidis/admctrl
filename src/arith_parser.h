/* arith_parser.h

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

#ifndef ARITH_PARSER_H
#define ARITH_PARSER_H

/** \file arith_parser.h
 * \brief Definitions for the arithmetic expression library 
 * \author Georgios Portokalidis
 */


//! Specifies the maximum length of supported numbers
#define MAX_NUMBER_SIZE 512
#define ARITH_PARSER_MAX_NUMBER_SIZE MAX_NUMBER_SIZE

typedef enum { INV = -1, EMPTY, NUM, ADD, SUB, MUL, DIV, LPAR, RPAR } arith_op_t;

arith_op_t arith_parser_token(char *,char *,size_t);
int postfix_expr_parse(char *,double *);
int infix_expr_parse(char *,double *);

#endif
