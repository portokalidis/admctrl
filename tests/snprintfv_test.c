/* snprintfv_test.c

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

#include <printf.h>
#include <float.h>
#include <limits.h>

/** \file snprintfv_test.c
 * \brief snprintfv library test app
 */

int
main()
{
  char buffer[1024];
  snv_constpointer *args;
  const char *string = "port 80";
	int integer = INT_MAX;
  double g = DBL_MAX;
  unsigned long long ullong = ULONG_LONG_MAX;

  args = snv_new(snv_constpointer,4);
  args[0] = &g;
  args[1] = SNV_INT_TO_POINTER(integer);
  args[2] = &ullong;
	args[3] = string;

  printf("sizeof(int)=%d, sizeof(double)=%d, sizeof(unsigned long long)=%d\n",sizeof(int),sizeof(float),sizeof(unsigned long long));
	printf("Values:\n\tULL = %3$llu, INT = %2$d, DOUBLE = %4$f, STR = %1$s\n",string,integer,ullong,g);
  snprintfv(buffer,1024,"ULL = %3$llu, INT = %2$d, DOUBLE = %1$f, STR = %4$s\n",args);
  printf("snprintfv result:\n\t%s\n",buffer);
  
  snv_delete(args);

  return 0;
}
