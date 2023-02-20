/* resource_ctrl.h

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

#ifndef RESOURCE_CTRL_H
#define RESOURCE_CTRL_H

#include <snprintfv/compat.h>
#include <db.h>
#include <admctrl_config.h>

/** \file resource_ctrl.h
	\brief Definitions of datatypes and functions for resource control
	\author Georgios Portokalidis
	*/

//! Defines that encapsulate DB defines
#define RESOURCE_DB_RDONLY DB_RDONLY
#define RESOURCE_DB_CREATE DB_CREATE
#define RESOURCE_DB_RECOVER DB_RECOVER
#define RESOURCE_DB_NOTFOUND DB_NOTFOUND

#define RESOURCE_CTRL_FAIL -1

//! Defines the number of DBs encapsulated by the resource_ctrl_db_t type
#define RESOURCES_DB_NUM 4

//! Resource consumption of a function in a specific library
struct resource_consumption
{
	u_int32_t rkey; //!< Referred resource key
	u_int32_t fixed_cost; //!< Fixed cost of function
	char variable_cost_formula[RESOURCE_CTRL_MAX_VAR_FORM_LEN]; //!< Formula string that calculates the resource consumption depending on function parameters
};
//! Resource consumption datatype
typedef struct resource_consumption resource_consumption_t;

//! The amount of a resource that is requires
struct resource_required
{
	u_int32_t rkey; //!< Referred resource key
	u_int32_t required; //!< Amount of required resource
};


//! Required resource datatype
typedef struct resource_required resource_required_t;

//! Resource control database structure
struct resource_ctrl_db
{
	DB *DB[RESOURCES_DB_NUM]; //!< Array of DBs
	DB_ENV *ENV; //!< The environment for the DBs
};
// Resource control database datatype
typedef struct resource_ctrl_db resource_ctrl_db_t;

//! Resources' information
struct resource
{
	u_int32_t available; //!< Availability of resource
	char description[RESOURCE_CTRL_MAX_RES_DESCR_LEN]; //!< Description of resource
};
//! Resource datatype
typedef struct resource resource_t;



int resource_ctrl_dbinit(resource_ctrl_db_t *);
int resource_ctrl_dbopen(resource_ctrl_db_t *,const char *,const char *,u_int32_t,u_int32_t);
void resource_ctrl_dbclose(resource_ctrl_db_t *);

int resource_ctrl_resourcekey(resource_ctrl_db_t *,char *,char *,u_int32_t *);
int resource_ctrl_resourceconsumption(resource_ctrl_db_t *,u_int32_t,resource_consumption_t *,size_t *);
int resource_ctrl_aggregate(resource_consumption_t *,size_t,resource_required_t *,size_t *,snv_constpointer *);
int resource_ctrl_check(resource_ctrl_db_t *,resource_required_t *,size_t);
extern inline int resource_ctrl_allocate(resource_ctrl_db_t *,resource_required_t *,size_t);
extern inline int resource_ctrl_deallocate(resource_ctrl_db_t *,resource_required_t *,size_t);

extern inline int resource_ctrl_display_functions(resource_ctrl_db_t *);
extern inline int resource_ctrl_display_libraries(resource_ctrl_db_t *);
int resource_ctrl_display_consumption(resource_ctrl_db_t *,u_int32_t);
extern inline int resource_ctrl_display_resources(resource_ctrl_db_t *);

extern inline int resource_ctrl_add_function(resource_ctrl_db_t *,char *,u_int32_t);
extern inline int resource_ctrl_add_library(resource_ctrl_db_t *,char *,u_int32_t);
extern inline int resource_ctrl_add_consumption(resource_ctrl_db_t *,u_int32_t,resource_consumption_t *);
extern inline int resource_ctrl_add_resource(resource_ctrl_db_t *,u_int32_t,resource_t *);

int resource_ctrl_del_function(resource_ctrl_db_t *,char *);
int resource_ctrl_del_library(resource_ctrl_db_t *,char *);
int resource_ctrl_del_resource(resource_ctrl_db_t *,u_int32_t);
int resource_ctrl_del_consumption(resource_ctrl_db_t *,u_int32_t,u_int32_t);
#endif
