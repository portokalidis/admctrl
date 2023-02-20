/* calc_test.c

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
#include <string.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <signal.h>

#include "arith_parser.h"

/** \file calc_test.c
 * \brief Arithmetic parser test app
 */

int 
main(int argc,char **argv)
{
	int e;
	double res = 0.0;
	char expr_type = 0;
	char buf[1024];

	if ( argc > 1 )
	{
		if ( strcmp(argv[1],"postfix") == 0 )
			expr_type = 0;
		else if ( strcmp(argv[1],"infix") == 0 )
			expr_type = 1;
		else
		{
			printf("%s: Illegal argument\n",argv[0]);
			printf("Usage: %s [postfix|infix]\n",argv[0]);
			return 1;
		}
	}
	printf("Using %s expressions\n",(expr_type == 0)? "postfix":"infix");
	printf("Max DOUBLE %f\n",DBL_MAX);
	printf("Max UNSIGNED LONG LONG %llu\n",ULONG_LONG_MAX);

	while( fgets(buf,1024,stdin) != NULL )
	{
		switch( expr_type )
		{
			case 0:
				e = postfix_expr_parse(buf,&res);
				break;
			case 1:
				e = infix_expr_parse(buf,&res);
				break;
			default:
				e = 1;
		}
		if ( e != 0 )
		{
			fprintf(stderr,"%s: error parsing string\n",argv[0]);
			return 1;
		}
		printf("%f\n",res);
    if ( isless(res,4294967296.0) )
      printf("%lu\n",lround(res));
    else
      printf("Number too large\n");
	}

	return 0;
}
