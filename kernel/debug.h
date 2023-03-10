/* debug.h

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

#ifndef DEBUG_H
#define DEBUG_H

/** \file debug.h
	\brief Defines MACROS to include commands or exclude instructions depending on DEBUG level
	\author Georgios Portokalidis
	*/

#if DEBUG > 0
#define DEBUG_CMD(x) x
#else
#define DEBUG_CMD(x)
#endif

#if DEBUG > 1
#define DEBUG_CMD2(x) x
#else
#define DEBUG_CMD2(x)
#endif

#endif
