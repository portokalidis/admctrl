/* admctrl_req.h

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

#ifndef ADMCTRL_REQ_H
#define ADMCTRL_REQ_H

#include <adm_ctrl.h>

/*! \file admctrl_req.h
  \brief Definition of methos to help construct an admission control request
  \author Georgios Portokalidis
*/

void admctrl_req_set_authinfo(adm_ctrl_request_t *,const unsigned char *,const unsigned char *,unsigned int,const unsigned char *,size_t);
int admctrl_req_add_nvpair(adm_ctrl_request_t *,const char *,const char *);
int admctrl_req_add_function(adm_ctrl_request_t *,size_t *,const char *,const char *,const char *,...);
int admctrl_req_add_sfunction(adm_ctrl_request_t *,size_t *,const char *,const char *,const char *,const unsigned char *,size_t);

#endif
