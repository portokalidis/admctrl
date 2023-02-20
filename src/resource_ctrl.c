/* resource_ctrl.c

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

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>
#include <printf.h>

#include "resource_ctrl.h"
#include "arith_parser.h"
#include "debug.h"

/** \file resource_ctrl.c 
	\brief Implementation of resource control library
  \author Georgios Portokalidis
*/

//! Mode of file containing the database
#define DB_FILE_MODE 0600

#define SNV_BUFFER_SIZE (RESOURCE_CTRL_MAX_VAR_FORM_LEN + MAX_ARGUMENTS_NUMBER * 64)

typedef enum { INCREASE, DECREASE } ADJ_TYPE;

typedef void (*dbt_print_t)(const DBT *,const DBT *);

#define ENV_FLAGS DB_INIT_LOG | DB_INIT_TXN | DB_INIT_MPOOL

struct db_conf
{
	const char *name;
	DBTYPE type;
	u_int32_t flags;
};

static const struct db_conf db_meta[] = {
	{ "functiondb", DB_HASH, 0 },
	{ "librarydb", DB_HASH, 0 },
	{ "resourcecondb", DB_BTREE, DB_DUP | DB_DUPSORT },
	{ "resourcedb", DB_HASH, 0 }
};


/** \brief Initialise a resource control database
 *
 * Generates structures for the envirnoment and the databases.
 *
 * \param db Reference to a resource control database
 *
 * \return zero on success, or non-zero on failure
 */
int
resource_ctrl_dbinit(resource_ctrl_db_t *db)
{
	int e,i;

	if ( (e = db_env_create(&db->ENV,0)) != 0 )
		return e;

	for(i = 0 ; i < RESOURCES_DB_NUM ; i++)
	{
		if ( (e = db_create(&db->DB[i],db->ENV,0)) != 0 )
			return e;
		db->DB[i]->set_flags(db->DB[i],db_meta[i].flags);
	}
	return 0;
}


/** \brief Open a resource control database
 *
 * Opens the environment and database files.
 *
 * \param db Reference to a resource control database
 * \param home Pathname of the DB environment home directory
 * \param fn Filename that contains the DB
 * \param flags Additional flags passed to DB->open(). 0 or bitwise OR of one of the following values:
 * \li RESOURCE_DB_CREATE Database file will be created if necessary
 * \li RESOURCE_DB_RDONLY Database will be opened read-only
 * \param envfl Enironment flags passed to DB_ENV->open(). 0 or one of the following values:
 * \li RESOURCE_DB_CREATE Database environment will be created if necessary
 * \li RESOURCE_DB_RECOVER Try to recover database. RESOURCE_DB_CREATE has to be defined as well
 *
 * \return zero on success, or non-zero on failure
 */
int
resource_ctrl_dbopen(resource_ctrl_db_t *db,const char *home,const char *fn,u_int32_t flags,u_int32_t envfl)
{
	int e,i;

	if ( (e = db->ENV->open(db->ENV,home,ENV_FLAGS | envfl,0)) != 0 )
		goto error;

	for(i = 0 ; i < RESOURCES_DB_NUM ; i++)
		if ( (e = db->DB[i]->open(db->DB[i],fn,db_meta[i].name,db_meta[i].type,flags,0)) != 0 )
			goto error;

	return 0;

error:
	//resource_ctrl_dbclose(db);
#if DEBUG > 1
	if ( e != 0 )
		db->DB[0]->err(db->DB[0],e,"resource_ctrl_dbopen");
#endif
	return e;
}


/** \brief Close a resource control database 

	\param db Reference to a resource control database
 */
void
resource_ctrl_dbclose(resource_ctrl_db_t *db)
{	
	int i;

	for(i = 0 ; i < RESOURCES_DB_NUM ; i++)
		db->DB[i]->close(db->DB[i],0);

	db->ENV->close(db->ENV,0);
}


int
resource_ctrl_aggregate(resource_consumption_t *con,size_t con_size,resource_required_t *req,size_t *req_size,snv_constpointer *args)
{
	size_t i,j;
	char buf[SNV_BUFFER_SIZE];
	double var_result;

	for(i = 0 ; i < con_size ; ++i)
	{
		for(j = 0 ; j < *req_size ; j++)
			if ( con[i].rkey == req[j].rkey )
				break;
		// Fixed cost
		if ( j >= *req_size )
		{
			if ( j >= RESOURCE_CTRL_MAX_RESOURCES )
				return - 1;
			req[j].rkey = con[i].rkey;
			req[j].required = con[i].fixed_cost;
			++*req_size;
		}
		else
			req[j].required += con[i].fixed_cost;

		// Variable cost
		if ( snprintfv(buf,SNV_BUFFER_SIZE,con[i].variable_cost_formula,args) >= SNV_BUFFER_SIZE )
		{
			DEBUG_CMD2(printf("DEBUG resource_ctrl_aggregate: variable cost formula exceeds %d characters\n",SNV_BUFFER_SIZE));
			return -1;
		}
		if ( infix_expr_parse(buf,&var_result) != 0 )
    {
			DEBUG_CMD2(printf("DEBUG resource_ctrl_aggregate: failed to calculate variable cost formula\n"));
			return -1;
    }
    if ( var_result < 0.0 )
    {
      DEBUG_CMD2(printf("DEBUG resource_ctrl_aggregate: negative variable cost returned\n"));
      return -1;
    }
    if ( isless(var_result,4294967296.0) )
      req[j].required += (uint32_t)lround(var_result);
    else
    {
      DEBUG_CMD2(printf("DEBUG resource_ctrl_aggregate: variable cost exceeds maximum unsigned int\n"));
      return -1;
    }
		DEBUG_CMD2(printf("DEBUG resource_ctrl_aggregate: variable formula=%s --> %u\n",con[i].variable_cost_formula,(uint32_t)lround(var_result)));
	}

	return 0;
}

/** \brief Looks up a key for a specific library function
  \param db Reference to a resource control database
	\param func The name of the function
	\param lib The name of the library
	\param rkey Reference where the key for resource consumption is going to be stored

	\return zero on success, or non-zero on failure. 
	 If there was no matching key RESOURCE_DB_NOTFOUND is returned.
*/
int
resource_ctrl_resourcekey(resource_ctrl_db_t *db,char *func,char *lib,u_int32_t *rkey)
{	
	DBT key,data;
	int e;

	// Retrieve function part of key
	bzero(&key,sizeof(key));
	key.data = func;
	key.size = strlen(func) + 1;
	bzero(&data,sizeof(data));
	if ( (e = db->DB[0]->get(db->DB[0],NULL,&key,&data,0)) != 0 )
		goto error;
	*rkey = *(u_int32_t *)data.data;
	
	// Retrieve lib part of key
	key.data = lib;
	key.size = strlen(lib) + 1;
	bzero(&data,sizeof(data));
	if ( (e = db->DB[1]->get(db->DB[1],NULL,&key,&data,0)) != 0 )
		goto error;
	*rkey |= *(u_int32_t *)data.data << 16;

error:
#if DEBUG > 1
	if ( e != 0 )
		db->DB[0]->err(db->DB[0],e,"resource_ctrl_resourcekey");
#endif
	return e;
}

#if 0
/** \brief Initialise a resource_ctrl_DBT

	Allocates user memory in the DBT where DB results can be stored.

	\param data A reference to a resource_ctrl_DBT
	\param size The amount of memory to allocate for the DBT

	\return zero on success, or non-zero on failure
*/
int
resource_ctrl_DBT_init(resource_ctrl_DBT *data,size_t size)
{
	bzero(data,sizeof(DBT));
	if ( (data->data = malloc(size)) == NULL )
		return - ENOMEM;
	data->ulen = size;
	data->flags = DB_DBT_USERMEM;
	return 0;
}


/** \brief Destroys a resource_ctrl_DBT

	Frees the memory allocated for DBT.

	\param \data A reference to a resource_ctrl_DBT
*/
void
resource_ctrl_DBT_destroy(resource_ctrl_DBT *data)
{
	free(data->data);
}
#endif


/** \brief Retrieve resource consumption for a key

  \param db Reference to a resource control database
	\param rckey Key as returned by resource_ctrl_resourcekey()
	\param con Array to place resource consumption records
	\param con_size Number of records returned

	\return zero on success, or non-zero on failure.
	 If there was no matching key RESOURCE_DB_NOTFOUND is returned.
*/
int
resource_ctrl_resourceconsumption(resource_ctrl_db_t *db,u_int32_t rckey,resource_consumption_t *con,size_t *con_size)
{
	DBT key,data;
	DBC *dbc = NULL;
	int e;

	if ( (e = db->DB[2]->cursor(db->DB[2],NULL,&dbc,0)) != 0 )
		goto ret;

	bzero(&key,sizeof(key));
	key.data = &rckey;
	key.size = sizeof(rckey);
	bzero(&data,sizeof(data));

	*con_size = 0;

	// Get first record
	if ( (e = dbc->c_get(dbc,&key,&data,DB_SET)) != 0 )
		goto ret;

	do {
		memcpy(con + *con_size,data.data,sizeof(resource_consumption_t));
		++*con_size;
	} while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT_DUP)) == 0 );
	if ( e == DB_NOTFOUND )
		e = 0;

ret:
	if ( dbc )
		dbc->c_close(dbc);
#if DEBUG > 1
	if ( e != 0 )
		db->DB[2]->err(db->DB[2],e,"resource_ctrl_resourceconsumption");
#endif
	return e;
}


/** \brief Check that required resources are available
  \param db Reference to a resource control database
	\param rr Array of required resources
	\param rr_size Size of rr array

	\return zero on success, or non-zero on failure
	A positive value indicates the resource that failed, 
	while a negative a DB error
*/
int
resource_ctrl_check(resource_ctrl_db_t *db,resource_required_t *rr,size_t rr_size)
{
	DBT key,data;
	size_t i;
	int e;

	bzero(&key,sizeof(key));
	key.size = sizeof(u_int32_t);
	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);

	for(i = 0 ; i < rr_size ; i++)
	{
		key.data = &(rr[i].rkey);
		if ( (e = db->DB[3]->get(db->DB[3],NULL,&key,&data,0)) != 0 )
		{
			DEBUG_CMD2(db->DB[3]->err(db->DB[3],e,"resource_ctrl_check"));
			return e;
		}
		if ( rr[i].required > *(u_int32_t *)data.data )
			return (int)i;
	}
	return 0;
}


/** \brief Adjusts available resources values

  \param db Reference to a resource control database
	\param rr Required resources that indicate adjustment to be made
	\param rr_size Size of rr array
	\param type Type of adjustment:
	\li INCREASE Increase resource values
	\li DECREASE Decrease resource values

	\return zero on success, or non-zero on failure
	 If there was no matching resource RESOURCE_DB_NOTFOUND is returned.
	*/
static int
resource_ctrl_adjust(resource_ctrl_db_t *db,resource_required_t *rr,size_t rr_size,ADJ_TYPE type)
{
	DBT key,data;
	size_t i;
	u_int32_t new_value;
	DB_TXN *tid;
	int e;

	bzero(&key,sizeof(key));
	key.size = sizeof(u_int32_t);
	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);
	data.size = sizeof(u_int32_t);

	// BEGIN transaction
	if ( (e = txn_begin(db->ENV,NULL,&tid,0)) != 0 )
		return e;

	for(i = 0 ; i < rr_size ; i++)
	{
		key.data = &rr[i].rkey;
		// Read available resources
		if ( (e = db->DB[3]->get(db->DB[3],tid,&key,&data,0)) != 0 )
			goto abort;
		if ( type == DECREASE &&  rr[i].required > *(u_int32_t *)data.data )
		{
			e = RESOURCE_CTRL_FAIL;
			goto abort;
		}
		// Store new value for available resources
		if ( type == DECREASE )
			new_value = *(u_int32_t *)data.data - rr[i].required;
		else 
			new_value = *(u_int32_t *)data.data + rr[i].required;
		data.data = &new_value;
		if ( (e = db->DB[3]->put(db->DB[3],tid,&key,&data,0)) != 0 )
			goto abort;
	}

	// COMMIT transaction
	e = txn_commit(tid,0);
	return e;

abort:
	// ABORT transaction
	txn_abort(tid);
	return e;
}


/** \brief Allocate required resources
  \param db Reference to a resource control database
	\param rr Array of required resources
	\param rr_size Size of rr array

	\return zero on success, or non-zero on failure.
	 If there was no matching resource RESOURCE_DB_NOTFOUND is returned.
*/
int
resource_ctrl_allocate(resource_ctrl_db_t *db,resource_required_t *rr,size_t rr_size)
{
	return resource_ctrl_adjust(db,rr,rr_size,DECREASE);
}


/** \brief Deallocate assigned resources

  \param db Reference to a resource control database
	\param rr Array of required resources
	\param rr_size Size of rr array

	\return zero on success, or non-zero on failure.
	 If there was no matching resource RESOURCE_DB_NOTFOUND is returned.
*/
int
resource_ctrl_deallocate(resource_ctrl_db_t *db,resource_required_t *rr,size_t rr_size)
{
	return resource_ctrl_adjust(db,rr,rr_size,INCREASE);
}

/**
	Prints function and library records
	*/
static void
DBT_print_key_string(const DBT *key,const DBT *data)
{
	printf("%s --> %u\n",(char *)key->data,*(u_int32_t *)data->data);
}


/**
	Displays function and library records
	*/
static int
resource_ctrl_display_db(resource_ctrl_db_t *db,unsigned int db_index,dbt_print_t print_func)
{
	DBT key,data;
	DBC *dbc;
	int e;

	if ( (e = db->DB[db_index]->cursor(db->DB[db_index],NULL,&dbc,0)) != 0 )
	{
		DEBUG_CMD(db->DB[db_index]->err(db->DB[db_index],e,"DB->cursor"));
		return e;
	}

	bzero(&key,sizeof(key));
	bzero(&data,sizeof(data));
	
	while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT)) == 0 )
		print_func(&key,&data);
	if ( e != DB_NOTFOUND )
	{
		DEBUG_CMD(db->DB[db_index]->err(db->DB[db_index],e,"DBcursor->c_get"));
	}
	else
		e = 0;
	dbc->c_close(dbc);
	return 0;
}


/** \brief Display all functions in database

  \param db Reference to a resource control database

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_display_functions(resource_ctrl_db_t *db)
{
	return resource_ctrl_display_db(db,0,DBT_print_key_string);
}


/** \brief Display all libraries in database

  \param db Reference to a resource control database

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_display_libraries(resource_ctrl_db_t *db)
{
	return resource_ctrl_display_db(db,1,DBT_print_key_string);
}


/**
	Prints resource records
	*/
static void
DBT_print_resource(const DBT *key,const DBT *data)
{
	resource_t *resource = (resource_t *)data->data;
	printf("%u: %u %s\n",*(u_int32_t *)key->data,resource->available,resource->description);
}


/** \brief Display all resources in database

  \param db Reference to a resource control database

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_display_resources(resource_ctrl_db_t *db)
{
	return resource_ctrl_display_db(db,3,DBT_print_resource);
}


/** \brief Display resource consumption for a specific library function

  \param db Reference to a resource control database
	\param pk key of library function(as returned resource_ctrl_resourcekey())

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_display_consumption(resource_ctrl_db_t *db,u_int32_t pk)
{
	DBC *dbc;
	DBT key1,data1,key2,data2;
	resource_consumption_t *consumption;
	resource_t *resource;
	int e;

	bzero(&key1,sizeof(key1));
	key1.data = &pk;
	key1.size = sizeof(pk);
	bzero(&data1,sizeof(data1));


	if ( (e = db->DB[2]->cursor(db->DB[2],NULL,&dbc,0)) != 0 )
		goto ret;

	if ( (e = dbc->c_get(dbc,&key1,&data1,DB_SET)) != 0 )
		goto ret;

	bzero(&key2,sizeof(key2));
	key2.size = sizeof(u_int32_t);
	bzero(&data2,sizeof(data2));

	do {
		consumption = (resource_consumption_t *)data1.data;
		key2.data = &(consumption->rkey);
		if ( (e = db->DB[3]->get(db->DB[3],NULL,&key2,&data2,0)) != 0 )
			goto ret;
		resource = (resource_t *)data2.data;
		printf("%u: %u(%s) FIXED=%u VARIABLE=\"%s\"\n",pk,consumption->rkey,resource->description,consumption->fixed_cost,consumption->variable_cost_formula);
	} while( (e = dbc->c_get(dbc,&key1,&data1,DB_NEXT_DUP)) == 0 );

ret:
	if ( e != 0 && e != DB_NOTFOUND)
	{
		DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"DB->cursor"));
		return e;
	}
	return e;
}


/**
	Stores functions and libraries in database
	*/
static int
resource_ctrl_put_key_str(resource_ctrl_db_t *db,unsigned int db_index,char *str,u_int32_t pkey)
{
	DBT key,data;
	int e;

	bzero(&key,sizeof(key));
	key.data = str;
	key.size = strlen(str) + 1;
	bzero(&data,sizeof(data));
	data.data = &pkey;
	data.size = sizeof(pkey);

	if ( (e = db->DB[db_index]->put(db->DB[db_index],NULL,&key,&data,0)) != 0 )
		db->DB[db_index]->err(db->DB[db_index],e,"DB->put");

	return e;
}


/** \brief Add a function in database

  \param db Reference to a resource control database
	\param fname Function name
	\param fkey Associated key

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_add_function(resource_ctrl_db_t *db,char *fname,u_int32_t fkey)
{
	return resource_ctrl_put_key_str(db,0,fname,fkey);
}


/** \brief Add a library in database

  \param db Reference to a resource control database
	\param libname Library name
	\param lkey Associated key

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_add_library(resource_ctrl_db_t *db,char *libname,u_int32_t lkey)
{
	return resource_ctrl_put_key_str(db,1,libname,lkey);
}


/**
	Stores structures in db
	*/
static int
resource_ctrl_put_struct(resource_ctrl_db_t *db,unsigned int db_index,u_int32_t pk,void *d,size_t dsize)
{
	DBT key,data;
	int e;

	bzero(&key,sizeof(key));
	key.data = &pk;
	key.size = sizeof(pk);
	bzero(&data,sizeof(data));
	data.data = d;
	data.size = dsize;

	if ( (e = db->DB[db_index]->put(db->DB[db_index],NULL,&key,&data,0)) != 0 )
		db->DB[db_index]->err(db->DB[db_index],e,"DB->put");

	return e;
}


/** \brief Add a resource consumption record in database

  \param db Reference to a resource control database
	\param pk Primary key for record
	\param consumption Reference to the record to be stored

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_add_consumption(resource_ctrl_db_t *db,u_int32_t pk,resource_consumption_t *consumption)
{
	return resource_ctrl_put_struct(db,2,pk,consumption,sizeof(resource_consumption_t));
}


/** \brief Add a resource in database

  \param db Reference to a resource control database
	\param rkey Key for resource
	\param resource Reference to the resource to be stored

	\return zero on success, or non-zero on failure
	*/
int 
resource_ctrl_add_resource(resource_ctrl_db_t *db,u_int32_t rkey,resource_t *resource)
{
	return resource_ctrl_put_struct(db,3,rkey,resource,sizeof(resource_t));
}


/** \brief Delete function from database
	Also deletes all the resource consumption records associated with
	the function.

  \param db Reference to a resource control database
	\param func Function to delete

	\return zero on success, or non-zero on failure
	*/
int 
resource_ctrl_del_function(resource_ctrl_db_t *db,char *func)
{
	DB_TXN *tid;
	DBT key,data;
	DBC *dbc;
	int e;
	u_int32_t pk;

	bzero(&key,sizeof(key));
	key.data = func;
	key.size = strlen(func) + 1;
	bzero(&data,sizeof(data));

	// Get function part key
	if ( (e = db->DB[0]->get(db->DB[0],NULL,&key,&data,0)) != 0 )
		return e;

	pk = *(u_int32_t *)data.data;

	// BEGIN transaction
	if ( (e = txn_begin(db->ENV,NULL,&tid,0)) != 0 )
		return e;

	if ( (e = db->DB[2]->cursor(db->DB[2],tid,&dbc,0)) != 0 )
		goto ret;
	
	// Delete function
	if ( (e = db->DB[0]->del(db->DB[0],tid,&key,0)) != 0 )
		goto ret;

	key.data = &pk;
	key.size = sizeof(pk);
	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);

	// Delete matching resource consumption
	while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT)) == 0 )
		if ( (*(u_int32_t *)key.data & pk) == pk )
			if ( (e = dbc->c_del(dbc,0)) != 0 )
				goto ret;

ret:
	dbc->c_close(dbc);

	if ( e != DB_NOTFOUND )
	{
		DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_function"));
		e = txn_abort(tid);
	}
	else
		if ( (e = txn_commit(tid,0)) != 0 )
		{
			DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_function"));
		}

	return e;
}


/** \brief Delete library from database
	Also deletes all the resource consumption records associated with
	the library.

  \param db Reference to a resource control database
	\param lib Library to delete

	\return zero on success, or non-zero on failure
	*/
int 
resource_ctrl_del_library(resource_ctrl_db_t *db,char *lib)
{
	DB_TXN *tid;
	DBT key,data;
	DBC *dbc;
	int e;
	u_int32_t pk;

	bzero(&key,sizeof(key));
	key.data = lib;
	key.size = strlen(lib) + 1;
	bzero(&data,sizeof(data));

	// Get function part key
	if ( (e = db->DB[1]->get(db->DB[1],NULL,&key,&data,0)) != 0 )
		return e;

	pk = *(u_int32_t *)data.data;

	// BEGIN transaction
	if ( (e = txn_begin(db->ENV,NULL,&tid,0)) != 0 )
		return e;

	if ( (e = db->DB[2]->cursor(db->DB[2],tid,&dbc,0)) != 0 )
		goto ret;
	
	// Delete function
	if ( (e = db->DB[1]->del(db->DB[1],tid,&key,0)) != 0 )
		goto ret;

	key.data = &pk;
	key.size = sizeof(pk);
	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);

	// Delete matching resource consumption
	while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT)) == 0 )
		if ( ((*(u_int32_t *)key.data >> 16) ^ pk) == 0 )
			if ( (e = dbc->c_del(dbc,0)) != 0 )
				goto ret;

ret:
	dbc->c_close(dbc);

	if ( e != DB_NOTFOUND )
	{
		DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_library"));
		e = txn_abort(tid);
	}
	else
		if ( (e = txn_commit(tid,0)) != 0 )
		{
			DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_library"));
		}

	return e;
}


/** \brief Delete a resource consumption record from database

  \param db Reference to a resource control database
	\param pk Key of record
	\param rkey Resource key of record

	\return zero on success, or non-zero on failure
	*/
int
resource_ctrl_del_consumption(resource_ctrl_db_t *db,u_int32_t pk,u_int32_t rkey)
{
	DBT key,data;
	DBC *dbc;
	int e;

	bzero(&key,sizeof(key));
	key.data = &pk;
	key.size = sizeof(pk);
	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);

	if ( (e = db->DB[2]->cursor(db->DB[2],NULL,&dbc,0)) != 0 )
	{
		DEBUG_CMD(db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_consumption"));
		return e;
	}
	
	// Delete matching resource consumption record
	if ( (e = dbc->c_get(dbc,&key,&data,DB_SET)) != 0 )
		goto error;

	do {
		if ( *(u_int32_t *)data.data == rkey )
			if ( (e = dbc->c_del(dbc,0)) != 0 )
				goto error;
		e = dbc->c_get(dbc,&key,&data,DB_NEXT_DUP);
	} while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT_DUP)) == 0 );

	if ( e == DB_NOTFOUND )
		e = 0;

error:
	dbc->c_close(dbc);
#if DEBUG > 0
	if ( e != 0 )
		db->DB[2]->err(db->DB[2],e,"resource_ctrl_del_resource");
#endif
	return e;
}


/** \brief Delete a resource from database

  \param db Reference to a resource control database
	\param rkey Resource key

	\return zero on success, or non-zero on failure
	*/
int 
resource_ctrl_del_resource(resource_ctrl_db_t *db,u_int32_t rkey)
{
	DB_TXN *tid;
	DBT key,data;
	DBC *dbc;
	int e;

	bzero(&key,sizeof(key));
	key.data = &rkey;
	key.size = sizeof(rkey);

	// BEGIN transaction
	if ( (e = txn_begin(db->ENV,NULL,&tid,0)) != 0 )
		return e;

	if ( (e = db->DB[2]->cursor(db->DB[2],tid,&dbc,0)) != 0 )
		goto ret;
	
	// Delete resource
	if ( (e = db->DB[3]->del(db->DB[3],tid,&key,0)) != 0 )
		goto ret;

	bzero(&data,sizeof(data));
	data.flags = DB_DBT_PARTIAL;
	data.doff = 0;
	data.dlen = sizeof(u_int32_t);

	// Delete matching resource consumption
	while( (e = dbc->c_get(dbc,&key,&data,DB_NEXT)) == 0 )
		if ( *(u_int32_t *)key.data == rkey )
			if ( (e = dbc->c_del(dbc,0)) != 0 )
				goto ret;

ret:
	dbc->c_close(dbc);

	if ( e != DB_NOTFOUND )
	{
		DEBUG_CMD(db->DB[3]->err(db->DB[3],e,"resource_ctrl_del_resource"));
		e = txn_abort(tid);
	}
	else
		if ( (e = txn_commit(tid,0)) != 0 )
		{
			DEBUG_CMD(db->DB[3]->err(db->DB[3],e,"resource_ctrl_del_resource"));
		}

	return e;
}
