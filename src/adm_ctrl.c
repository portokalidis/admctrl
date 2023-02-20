/* adm_ctrl.c

  Copyright 2004 Georgios Portokalidis <digital_bull@users.sourceforge.net>

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
#include <limits.h>
#include <sys/time.h>
#include <openssl/rsa.h>
#include <regex.h>

#include "keynote.h"
#include "admctrl_config.h"
#include "adm_ctrl.h"
#include "admctrl_argtypes.h"
#include "admctrl_errno.h"
#include "debug.h"

#ifdef WITH_RESOURCE_CONTROL
#include "resource_ctrl.h"
#endif


/*! \file adm_ctrl.c
 *  \brief Authorization routines for authd
 *  \author Georgios Portokalidis
 */

//! Function argument value
union adm_ctrl_funcarg_value
{
	int integer; //!< Holds and integer
	char *cstring; //!< Holds a C string
	double dbl; //!< Holds a double
	unsigned long long ullong; //!< Holds an unsigned long long
};
//! Function argument value datatype
typedef union adm_ctrl_funcarg_value adm_ctrl_funcarg_value_t;


//! Function argument definition
/** It holds all the necessary information for a function argument */
struct adm_ctrl_funcarg
{
	char type; //!< The type of the argument
	adm_ctrl_funcarg_value_t value; //!< The value of the argument
	//struct adm_ctrl_funcarg *next; //!< Pointer to next function argument
};
//! Function arguments datatype
typedef struct adm_ctrl_funcarg adm_ctrl_funcarg_t;


//! Function instance structure
/** Contains information about the instances of a function. */
struct adm_ctrl_func_instance
{
	unsigned int pos; //!< The position of the function in the list of functions
	//! The number of arguments this instance has.
	/** It should be the same as the args field in adm_ctrl_func */
	unsigned int args;
	adm_ctrl_funcarg_t *arg; //!< Array containing the arguments this instance was called with. Note that it is also a valid single linked list
	struct adm_ctrl_func_instance *next; //!< Pointer to next instance
};
//! Function instances datatype
typedef struct adm_ctrl_func_instance adm_ctrl_func_instance_t;

struct adm_ctrl_lib
{
	char *name;
	unsigned int num,
	first,
	last;
	adm_ctrl_func_instance_t *instances;
	struct adm_ctrl_lib *next;
};
typedef struct adm_ctrl_lib adm_ctrl_lib_t;

//! Function type definition
/** List of function types passed to admission control. Contains one entry for each distinct function used. */
struct adm_ctrl_func
{
	char *name; //<! The name of the function type
	unsigned int num, //!< Number of instances that it has
	first, //!< The position of the first instance
	last; //!< The position of the last instance
	//! The number of arguments this function accepts.
	/** All the instances of this function should have the same number of
	 * arguments, but we set the smallest value here to be safe. */
	unsigned int args;
	//adm_ctrl_func_instance_t *instances; //!< Pointer to function instances
	adm_ctrl_lib_t *library; //! Library implementations of this function type
	struct adm_ctrl_func *next; //!< Pointer to next function
};
//! Function type datatype
typedef struct adm_ctrl_func adm_ctrl_func_t;


//! \brief Number of policy comply values we are going to use 
#define NUMBER_OF_PCV 2
//! The policy comply values used with keynote 
static char *default_PCV[NUMBER_OF_PCV] = { "false", "true" };


#if 0
/** \brief print keynote error messages, for debugging purposes
 *
 * \param o the origin of the message
 */
static void
keynote_debug(const char *o)
{
	switch( keynote_errno )
	{
		case ERROR_MEMORY:
			printf("DEBUG %s: out of memory\n",o);
			return;
		case ERROR_SYNTAX:
			printf("DEBUG %s: syntax error\n",o);
			return;
		case ERROR_NOTFOUND:
			printf("DEBUG %s: session not found\n",o);
			return;
		default:
			printf("DEBUG %s: nobody knows what happened\n",o);
			return;
	}
}
#endif


/**\brief Load a keynote policy and extract the assertions
 *
 * \param fn the filename to read the policy from
 * \param policy the structure to store the policy loaded
 *
 * \return 0 on success, or -1 on failure
 */
int
adm_ctrl_load_policy(const char *fn,adm_ctrl_policy_t *policy)
{
  FILE *fl;
  char error = 0;

  // Read policy from file
  if ( (fl = fopen(fn,"r")) == NULL )
	  return -1;

  if ( fread(policy->data,1,MAX_POLICY_SIZE,fl) == 0 )
	  error = 1;
  else if ( ferror(fl) != 0)
	  error = 1;
  if ( error )
	  return -1;
  fclose(fl);

  // Read assertions
  if ( (policy->assertions = kn_read_asserts(policy->data,strnlen(policy->data,MAX_POLICY_SIZE),&(policy->assertions_num))) == NULL )
  {
	  DEBUG_CMD(fprintf(stderr,"adm_ctrl_load_policy: couldn't extract assertions from policy\n"));
	  return -1;
  }

  return 0;
}


/** \brief Decrypt the nonce provided by client
 * Decrypts the bytestream using a keynote public key. The bytestream should
 * contain an unsigned integer encrypted with a private key.
 * 
 * \param src the encrypted bytestream containing the nonce
 * \param dest the pointer to store the decrypted unsinged integer
 * \param pub the keynote public key to use for decryption
 *
 * \return 0 on success, or a negative error code on failure.
 */
int 
adm_ctrl_decrypt_nonce(bytestream *src,unsigned int *dest,char *pub)
{
  struct keynote_deckey dk;
  char *pkstring;
  unsigned char *dec_nonce = NULL;
  int dec_len = 0;
  RSA *rsa;

  if ( (pkstring = kn_get_string(pub)) == NULL )
    return - ADMCTRL_PUBKEY_ERROR;

  if ( kn_decode_key(&dk,pkstring,KEYNOTE_PUBLIC_KEY) < 0 )
  {
    DEBUG_CMD(fprintf(stderr,"adm_ctrl_decrypt_nonce: keynote couldn't decode key\n"));
    return - ADMCTRL_PUBKEY_ERROR;
  }

  if ( dk.dec_algorithm == KEYNOTE_ALGORITHM_RSA )
  {
    rsa = (RSA *)dk.dec_key;
    if ( (dec_nonce = malloc(RSA_size(rsa)-11)) != NULL )
    {
      if ( (dec_len = RSA_public_decrypt(src->length,src->data,dec_nonce,rsa,RSA_PKCS1_PADDING)) == sizeof(unsigned int) )
        *dest = *(unsigned int *)dec_nonce;
      else
			{
        DEBUG_CMD(fprintf(stderr,"adm_ctrl_decrypt_nonce: decryption with public key didn't return unsigned int\n"));
			}
      free(dec_nonce);
    }
  }
  else
	{
    DEBUG_CMD(fprintf(stderr,"adm_ctrl_decrypt_nonce: key is not RSA\n"));
	}
  kn_free_key(&dk);
  return (dec_len == sizeof(unsigned int))?0:- ADMCTRL_AUTHENTICATION_ERROR;
}


/** \brief Deallocates all the memory reserved for functions
 * 
 * \param list a pointer to functions
 */
static void 
adm_ctrl_free_functions(adm_ctrl_func_t *list)
{
	adm_ctrl_func_t *lt;
	adm_ctrl_lib_t *libt;
	adm_ctrl_func_instance_t *ft;

	// adm_ctrl_func
	while( list != NULL )
	{
		lt = list;
		list = list->next;
		// adm_ctrl_func.adm_ctrl_lib
		while( lt->library != NULL )
		{
			libt = lt->library;
			lt->library = lt->library->next;
			// adm_ctrl_func.adm_ctrl_lib.adm_ctrl_func_instance
			while( libt->instances != NULL )
			{
				ft = libt->instances;
				libt->instances = libt->instances->next;
				if ( ft->arg != NULL )
					free(ft->arg);
				free(ft);
			}// End adm_ctrl_func.adm_ctrl_lib.adm_ctrl_func_instance
			free(libt);
		}// End adm_ctrl_func.adm_ctrl_lib
		free(lt);
	}// End adm_ctrl_func
}


/** \brief Add a function instance for assertion generation
 *
 * Allocates a new list, if called with a NULL list argument.
 * If it fails due to lack of memory it deallocates the whole list.
 *
 * \param list a pointer to a function type list
 * \param func_name name of the function type to add
 * \param lib_name name of the library the functions belongs to
 * \param func function instance data
 *
 * \return a pointer to the list on success, or NULL on failure
 */
static adm_ctrl_func_t *
add_function_instance(adm_ctrl_func_t *list,char *func_name,char *lib_name,adm_ctrl_func_instance_t *func)
{
  adm_ctrl_func_t *l;
	adm_ctrl_lib_t *lib;
	adm_ctrl_func_instance_t *inst;

  // Try to locate function type & library
  for(l = list,lib = NULL ; l != NULL ; l = l->next)
		// Located function type
		if ( strcmp(func_name,l->name) == 0 )
		{
			for(lib = l->library ; lib != NULL ; lib = lib->next)
				// Located library
				if ( strcmp(lib_name,lib->name) == 0 )
					break;
			break;
		}
  
  // New function type
  if ( l == NULL )
  {
		// Generic values
    if ( ( l = (adm_ctrl_func_t *)malloc(sizeof(adm_ctrl_func_t))) == NULL )
			goto fail;
		l->name = func_name;
    l->num = 1;
    l->first = l->last = func->pos;
		l->library = NULL;
		l->args = func->args;
		// Connect to list
		l->next = list;
		list = l;
  }
  // Already existing function type
  else
  {
		// Generic values
    l->num++;
		l->first = MIN(func->pos,l->first);
		l->last = MAX(func->pos,l->last);
		// Same function different number of arguments
		if ( l->args != func->args )
			goto fail;
  }

	// New Function library
	if ( lib == NULL )
	{
		if ( (lib = (adm_ctrl_lib_t *)malloc(sizeof(adm_ctrl_lib_t))) == NULL )
			goto fail;
		lib->name = lib_name;
		lib->num = 1;
    lib->first = lib->last = func->pos;
		lib->instances = func;
		// Connect to list
		lib->next = l->library;
		l->library = lib;
	}
	else
	// Already existing function library
	{
		lib->num++;
		lib->first = MIN(lib->first,func->pos);
		lib->last = MAX(lib->last,func->pos);
		// Connect to list
		for(inst = lib->instances ; inst->next != NULL ; inst = inst->next)
			;
		inst->next = func;
		/*
		func->next = lib->instances;
		lib->instances = func;
		*/
	}


  return list;

fail:
	if ( l )
		free(l);
	if ( lib )
		free(lib);
	adm_ctrl_free_functions(list);
	return NULL;
}


/** \brief Deserializes a function from the buffer
 *
 * Deserializes a function from the buffer and inserts it to the provided list.
 * If the list doesn't exist it is created.
 * No data are copied from the buffer and the user has to free the list
 * when it is not needed anymore. If it fails for some reason, it 
 * deallocates the whole list.
 * Functions that have other functions as arguments, cause a recursive call
 * that results in the insertion of the argument function in the list with the
 * same index as the calling function.
 *
 * FORMAT: name + library + arguments type string + argument + ... 
 *
 * \param list The list to insert
 * \param index The index of the function being deserialized
 * \param buf Reference to the the buffer containing the serialized form.
 * It is updated to point to the next unprocessed serialized function
 * \param buf_size reference to the size of buf. It is updated when the 
 * reference to buf is updated
 *
 * \return The updated function list, or NULL on failure
 */
static adm_ctrl_func_t *
deserialize_function(adm_ctrl_func_t *list,unsigned int index,unsigned char **buf,size_t *buf_size)
{
	adm_ctrl_func_instance_t *f;
	char *name,*lib,*argt;
	unsigned int j;
	size_t l;

	if ( (f = (adm_ctrl_func_instance_t *)malloc(sizeof(adm_ctrl_func_instance_t))) == NULL )
		goto error;
	f->next = NULL;
	f->arg = NULL;

	// Index of function
	f->pos = index;
		
	// Function name
	name = (char *)*buf;
	if ( (l = strnlen(name,*buf_size)) == *buf_size )
		goto error;
	*buf_size -= l;
	*buf += l + 1;

	// Library name
	lib = (char *)*buf;
	if ( (l = strnlen(lib,*buf_size)) == *buf_size )
		goto error;
	*buf_size -= l;
	*buf += l + 1;

	// Number of arguments
	argt = (char *)*buf;
	if ( (l = strnlen(argt,*buf_size)) == *buf_size )
		goto error;
	*buf_size -= l;
	f->args = l;
	if ( f->args > MAX_ARGUMENTS_NUMBER )
		goto error;
	*buf += f->args + 1;

	// Arguments
	// At this point to avoid allocating memory for each argument,
	// we allocate once an array for all of them
	if ( f->args > 0 )
	{
		if ( (f->arg = (adm_ctrl_funcarg_t *)malloc(f->args * sizeof(adm_ctrl_funcarg_t))) == NULL )
			goto error;
	}

	for( j = 0 ; j < f->args ; j++ )
	{
		// Parameter type
		f->arg[j].type = argt[j];
		
		switch( f->arg[j].type )
		{
			case STRING_TYPE:
				f->arg[j].value.cstring = (char *)*buf;
				if ( (l = strnlen(f->arg[j].value.cstring,*buf_size)) == *buf_size )
					goto error;
				*buf_size -= l;
				*buf += l + 1;
				break;
			case INT_TYPE:
				f->arg[j].value.integer = *(int *)*buf;
				if ( *buf_size <= sizeof(int) )
					goto error;
				*buf_size -= sizeof(int);
				*buf += sizeof(int);
				break;
			case DOUBLE_TYPE:
				f->arg[j].value.dbl = *(double *)*buf;
				if ( *buf_size <= sizeof(double) )
					goto error;
				*buf_size -= sizeof(double);
				*buf += sizeof(double);
				break;
			case ULONG_LONG_TYPE:
				f->arg[j].value.ullong = *(unsigned long long *)*buf;
				if ( *buf_size <= sizeof(unsigned long long) )
					goto error;
				*buf_size -= sizeof(unsigned long long);
				*buf += sizeof(unsigned long long);
				break;
			case FUNCTION_TYPE:
				f->arg[j].value.cstring = (char *)*buf;
				// deserialize_function()advances buf pointer
				if ( (list = deserialize_function(list,index,buf,buf_size)) == NULL )
					goto error;
				break;
			default:
				goto error;
		}
	}// End of parameters loop

	if ( (list = add_function_instance(list,name,lib,f)) != NULL )
		return list;

error:
	if ( f )
	{
		if ( f->arg )
			free(f->arg);
		free(f);
	}
	if ( list )
		adm_ctrl_free_functions(list);
	return NULL;
}


/** \brief Deserialize a function list
 *
 * Deserializes a function list to a adm_ctrl_func_t structure
 * No data are copied from the buffer and the user has to free the list
 * when it is not needed anymore. If it fails for some reason, it 
 * deallocates the whole list.
 *
 * FORMAT: name + arguments type string + argument + ... 
 *
 * \param buf the buffer containing the serialized function definitions
 * \param num the number of functions contained in the buffer
 * \param buf_size the size of buf
 *
 * \return the deserialized function list, or NULL on failure
 *
 */
static adm_ctrl_func_t *
adm_ctrl_deserialize_functions(unsigned char *buf,unsigned int num,size_t buf_size)
{
  adm_ctrl_func_t *list = NULL;
	unsigned char *buf_i = buf;
	unsigned int i;

  if ( num == 0 )
    return NULL;

  // Functions
  for( i = 0 ; i < num ; i++ )
		if ( (list = deserialize_function(list,i,&buf_i,&buf_size)) == NULL)
			return NULL;

  return list;
}


/** \brief Processes a function list and generates assertions and resource consumption
 *
 * Function type actions:
 * \li (function_name) = "defined"
 * \li (function_name).num = (number_of_instances)
 * \li (function_name).first = (position_of_first_instance)
 * \li (function_name).last = (position_of_last_instance)
 * \li (function_name).(lib_name) = "defined"
 * \li (function_name).(lib_name).num = (number_of_instances)
 * \li (function_name).(lib_name).first = (position_of_first_instance)
 * \li (function_name).(lib_name).last = (position_of_last_instance)
 *
 * Function instance actions:
 * \li (function_name).(function_instance_no).pos = (position_of_instance)[DEPRECATED]
 * \li func.(function_position).name = "(function_name)"
 *
 * Function parameters actions:
 * \li (function_name).(function_instance_no).param.(parameter_number) = (parameter_value)[DEPRECATED]
 * \li func.(function_position).param.(parameter_number) = (parameter_value)
 * \li (function_name).param.(parameter_number).min = (parameter_min_value)
 * \li (function_name).param.(parameter_number).max = (parameter_max_value)
 * \li (function_name).(lib_name).param.(parameter_number).min = (parameter_min_value)
 * \li (function_name).(lib_name).param.(parameter_number).max = (parameter_max_value)
 *
 * \param id keynote session id
 * \param list list of function types & their instances
 *
 * \return 0 on success, or -1 on failure
 *
 */
static int
#ifdef WITH_RESOURCE_CONTROL
adm_ctrl_flist_process(int id,adm_ctrl_func_t *list,adm_ctrl_result_t *res,resource_ctrl_db_t *db)
{
	u_int32_t reskey;
	snv_constpointer snv_arguments[MAX_ARGUMENTS_NUMBER];
	resource_consumption_t consumption[RESOURCE_CTRL_MAX_RESOURCES];
	size_t con_size = 0;
	int db_status = 0;
	char has_resources = 0;
#else
adm_ctrl_flist_process(int id,adm_ctrl_func_t *list)
{
#endif
  char action_name[MAX_ACTION_NAME_SIZE],action_value[MAX_ACTION_VALUE_SIZE];
  adm_ctrl_funcarg_value_t arg_max[MAX_ARGUMENTS_NUMBER],arg_min[MAX_ARGUMENTS_NUMBER];
  adm_ctrl_funcarg_value_t lib_max[MAX_ARGUMENTS_NUMBER],lib_min[MAX_ARGUMENTS_NUMBER];
  adm_ctrl_func_instance_t *inst;
	adm_ctrl_lib_t *lib;
	unsigned int j,instance_no,libinst_no;
	int sz;

  // FUNCTION TYPES
  for(; list != NULL ; list = list->next)
  {
    // function_name = defined
    //sprintf(action_value,"\"defined\"");
    DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==defined\n",list->name));
    if ( kn_add_action(id,list->name,"defined",0) < 0 )
      return - ADMCTRL_MEMORY_ERROR;

    // function_name.num = number_of_instances
    snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.num",list->name);
    snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",list->num);
    DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
    if ( kn_add_action(id,action_name,action_value,0) < 0 )
      return - ADMCTRL_MEMORY_ERROR;

    // function_name.first = position_of_first_instance
    snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.first",list->name);
    snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",list->first);
    DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
    if ( kn_add_action(id,action_name,action_value,0) < 0 )
      return - ADMCTRL_MEMORY_ERROR;

    // function_name.last = position_of_last_instance
    snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.last",list->name);
    snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",list->last);
    DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
    if ( kn_add_action(id,action_name,action_value,0) < 0 )
      return - ADMCTRL_MEMORY_ERROR;


		// FUNCTION LIBRARIES
		for(lib = list->library,instance_no = 0 ; lib != NULL ; lib = lib->next,++instance_no)
		{
			// function_name.lib_name = defined
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s",list->name,lib->name);
			//sprintf(action_value,"\"defined\"");
			DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==defined\n",action_name));
			if ( kn_add_action(id,list->name,"defined",0) < 0 )
				return - ADMCTRL_MEMORY_ERROR;

			// function_name.lib_name.num = number_of_instances
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s.num",list->name,lib->name);
			snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",lib->num);
			DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
			if ( kn_add_action(id,action_name,action_value,0) < 0 )
				return - ADMCTRL_MEMORY_ERROR;

			// function_name.lib_name.first = position_of_first_instance
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s.first",list->name,lib->name);
			snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",lib->first);
			DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
			if ( kn_add_action(id,action_name,action_value,0) < 0 )
				return - ADMCTRL_MEMORY_ERROR;

			// function_name.lib_name.last = position_of_last_instance
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s.last",list->name,lib->name);
			snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",lib->last);
			DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
			if ( kn_add_action(id,action_name,action_value,0) < 0 )
				return - ADMCTRL_MEMORY_ERROR;

			// FUNCTION INSTANCES
#ifdef WITH_RESOURCE_CONTROL
			has_resources = 0;
#endif
			for(inst = lib->instances,libinst_no = 0 ; inst != NULL ; inst = inst->next,++libinst_no)
			{
#ifdef WITH_RESOURCE_CONTROL
				// Fetch function resource consumption information for 1st instance
				if ( db && libinst_no == 0 )
				{
					db_status = resource_ctrl_resourcekey(db,list->name,lib->name,&reskey);
					switch( db_status )
					{
						case 0:
							has_resources = 1;
							break;
						case RESOURCE_DB_NOTFOUND:
							has_resources = 0;
							break;
						default:
							return - ADMCTRL_RESOURCE_CTRL_ERROR;
					}

					if ( has_resources && (db_status = resource_ctrl_resourceconsumption(db,reskey,consumption,&con_size)) != 0 )
					{
            if ( db_status == RESOURCE_DB_NOTFOUND )
              has_resources = 0;
            else
            {
              DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: resource control failure\n"));
              return - ADMCTRL_RESOURCE_CTRL_ERROR;
            }
					}
				}
#endif

				// function_name.function_instance.pos = position_of_instance
				snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%u.pos",list->name,instance_no);
				snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",inst->pos);
				DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
				if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
					return - ADMCTRL_MEMORY_ERROR;

				// func.function_position.name = function_name
				snprintf(action_name,MAX_ACTION_NAME_SIZE,"func.%u.name",inst->pos);
				//snprintf(action_value,MAX_ACTION_VALUE_SIZE,"\"%s\"",list->name);
				DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,list->name));
				if ( kn_add_action(id,action_name,list->name,0) < 0 ) 
					return - ADMCTRL_MEMORY_ERROR;

				// INSTANCE ARGUMENTS
				for(j = 0 ; j < list->args ; j++)
				{
					switch( inst->arg[j].type )
					{
						case INT_TYPE:
							snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%d",inst->arg[j].value.integer);
							// Function type MIN-MAX
							if ( lib == list->library && inst == lib->instances )
								arg_max[j].integer = arg_min[j].integer = inst->arg[j].value.integer;
							else
							{
								arg_max[j].integer = MAX(arg_max[j].integer,inst->arg[j].value.integer);
								arg_min[j].integer = MIN(arg_min[j].integer,inst->arg[j].value.integer);
							}
							// Library function MIN-MAX
							if ( inst == lib->instances )
								lib_max[j].integer = lib_min[j].integer = inst->arg[j].value.integer;
							else
							{
								lib_max[j].integer = MAX(lib_max[j].integer,inst->arg[j].value.integer);
								lib_min[j].integer = MIN(lib_min[j].integer,inst->arg[j].value.integer);
							}
#ifdef WITH_RESOURCE_CONTROL
							if ( has_resources )
								snv_arguments[j] = SNV_INT_TO_POINTER(inst->arg[j].value.integer);
#endif
							break;
						case DOUBLE_TYPE:
							snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%f",inst->arg[j].value.dbl);
							// Function type MIN-MAX
							if ( lib == list->library && inst == lib->instances )
								arg_max[j].dbl = arg_min[j].dbl = inst->arg[j].value.dbl;
							else
							{
								arg_max[j].dbl = MAX(arg_max[j].dbl,inst->arg[j].value.dbl);
								arg_min[j].dbl = MIN(arg_min[j].dbl,inst->arg[j].value.dbl);
							}
							// Library function MIN-MAX
							if ( inst == lib->instances )
								lib_max[j].dbl = lib_min[j].dbl = inst->arg[j].value.dbl;
							else
							{
								lib_max[j].dbl = MAX(lib_max[j].dbl,inst->arg[j].value.dbl);
								lib_min[j].dbl = MIN(lib_min[j].dbl,inst->arg[j].value.dbl);
							}
#ifdef WITH_RESOURCE_CONTROL
							if ( has_resources )
								snv_arguments[j] = &inst->arg[j].value.dbl;
#endif
							break;
						case STRING_TYPE:
							snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%s",inst->arg[j].value.cstring);
							sz = (int)strlen(inst->arg[j].value.cstring);
							// Function type MIN-MAX
							if ( lib == list->library && inst == lib->instances )
								arg_max[j].integer = arg_min[j].integer = sz;
							else
							{
								arg_max[j].integer = MAX(arg_max[j].integer,sz);
								arg_min[j].integer = MIN(arg_min[j].integer,sz);
							}
							// Library function MIN-MAX
							if ( inst == lib->instances )
								lib_max[j].integer = lib_min[j].integer = sz;
							else
							{
								lib_max[j].integer = MAX(lib_max[j].integer,sz);
								lib_min[j].integer = MIN(lib_min[j].integer,sz);
							}
#ifdef WITH_RESOURCE_CONTROL
							if ( has_resources )
								snv_arguments[j] = SNV_INT_TO_POINTER(sz);
#endif
							break;
						case ULONG_LONG_TYPE:
							snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%llu",inst->arg[j].value.ullong);
							// Function type MIN-MAX
							if ( lib == list->library && inst == lib->instances )
								arg_max[j].ullong = arg_min[j].ullong = inst->arg[j].value.ullong;
							else
							{
								arg_max[j].ullong = MAX(arg_max[j].ullong,inst->arg[j].value.ullong);
								arg_min[j].ullong = MIN(arg_min[j].ullong,inst->arg[j].value.ullong);
							}
							// Library function MIN-MAX
							if ( inst == lib->instances )
								lib_max[j].ullong = lib_min[j].ullong = inst->arg[j].value.ullong;
							else
							{
								lib_max[j].ullong = MAX(lib_max[j].ullong,inst->arg[j].value.ullong);
								lib_min[j].ullong = MIN(lib_min[j].ullong,inst->arg[j].value.ullong);
							}
#ifdef WITH_RESOURCE_CONTROL
							if ( has_resources )
								snv_arguments[j] = &inst->arg[j].value.ullong;
#endif
							break;
            case FUNCTION_TYPE:
              snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%s",inst->arg[j].value.cstring);
#ifdef WITH_RESOURCE_CONTROL
							if ( has_resources )
								snv_arguments[j] = SNV_INT_TO_POINTER(0);
#endif
              break;
						default:
							return - ADMCTRL_INTERNAL_ERROR;
					}

					// function_name.instance_no.param.parameter_no == parameter_value
					sprintf(action_name,"%s.%u.param.%u",list->name,instance_no,j);
					DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
					if ( kn_add_action(id,action_name,action_value,0) < 0 )
						return - ADMCTRL_MEMORY_ERROR;

					// func.function_position.param.parameter_number = parameter_value
					sprintf(action_name,"func.%u.param.%u",inst->pos,j);
					DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
					if ( kn_add_action(id,action_name,action_value,0) < 0 )
						return - ADMCTRL_MEMORY_ERROR;
	 
				}//End instance arguments for()

#ifdef WITH_RESOURCE_CONTROL
				if ( has_resources && resource_ctrl_aggregate(consumption,con_size,res->required,&res->resources_num,snv_arguments) != 0 )
					return - ADMCTRL_RESOURCE_CTRL_ERROR;
#endif

			}//End function instances for()


			// Library instances MIN-MAX
			for(j = 0 ; j < lib->instances->args ; j++)
			{
				// function_name.lib_name.param.param_no.max = maximum_value
				snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s.param.%u.max",list->name,lib->name,j);
				switch( lib->instances->arg[j].type )
				{
					case INT_TYPE:
					case STRING_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%d",lib_max[j].integer);
						break;
					case DOUBLE_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%f",lib_max[j].dbl);
						break;
					case ULONG_LONG_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%llu",lib_max[j].ullong);
						break;
          case FUNCTION_TYPE:
            break;
					default:
						return - ADMCTRL_INTERNAL_ERROR;;
				}
        if ( lib->instances->arg[j].type != FUNCTION_TYPE )
        {
          DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
          if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
            return -1;
        }

				// function_name.lib_name.param.param_no.min = minimum_value
				snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.%s.param.%u.min",list->name,lib->name,j);
				switch( lib->instances->arg[j].type )
				{
					case INT_TYPE:
					case STRING_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%d",lib_min[j].integer);
						break;
					case DOUBLE_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%f",lib_min[j].dbl);
						break;
					case ULONG_LONG_TYPE:
						snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%llu",lib_min[j].ullong);
						break;
          case FUNCTION_TYPE:
            break;
					default:
						return - ADMCTRL_INTERNAL_ERROR;
				}
        if ( lib->instances->arg[j].type != FUNCTION_TYPE )
        {
          DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
          if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
            return -1;
        }
			} // End library intances MIN-MAX for()

		}// End function libraries for()

		// Function type MIN-MAX
		for(j = 0 ; j < list->library->instances->args ; j++)
		{
			// function_name.param.param_no.max = maximum_value
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.param.%u.max",list->name,j);
			switch( list->library->instances->arg[j].type )
			{
				case INT_TYPE:
				case STRING_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%d",arg_max[j].integer);
					break;
				case DOUBLE_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%f",arg_max[j].dbl);
					break;
				case ULONG_LONG_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%llu",arg_max[j].ullong);
					break;
        case FUNCTION_TYPE:
          break;
				default:
					return - ADMCTRL_INTERNAL_ERROR;
			}
      if ( list->library->instances->arg[j].type != FUNCTION_TYPE )
      {
        DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
        if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
          return -1;
      }

			// function_name.param.param_no.min = minimum_value
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"%s.param.%u.min",list->name,j);
			switch( list->library->instances->arg[j].type )
			{
				case INT_TYPE:
				case STRING_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%d",arg_min[j].integer);
					break;
				case DOUBLE_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%f",arg_min[j].dbl);
					break;
				case ULONG_LONG_TYPE:
					snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%llu",arg_min[j].ullong);
					break;
        case FUNCTION_TYPE:
          break;
				default:
					return - ADMCTRL_INTERNAL_ERROR;
			}
      if ( list->library->instances->arg[j].type != FUNCTION_TYPE )
      {
        DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
        if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
          return - ADMCTRL_MEMORY_ERROR;
      }
    } // End function types MIN-MAX for()

  }// End function types for()

#ifdef WITH_RESOURCE_CONTROL
	//if ( has_resources )
		for(j = 0 ; j < res->resources_num ; ++j)
		{
			snprintf(action_name,MAX_ACTION_NAME_SIZE,"RESOURCE.%u",res->required[j].rkey);
			snprintf(action_value,MAX_ACTION_VALUE_SIZE,"%u",res->required[j].required);
			DEBUG_CMD2(printf("DEBUG adm_ctrl_flist_process: %s==%s\n",action_name,action_value));
			if ( kn_add_action(id,action_name,action_value,0) < 0 ) 
				return - ADMCTRL_MEMORY_ERROR;
		}
#endif

	return 0;
}

/** \brief Generates assertions from name-value pairs
 *
 * \param id The id of the keynote session to use
 * \param pairs The number of pairs contained in the array
 * \param pair Array of name-value pairs
 *
 * \return zero on success, or less than zero on failure
 */
static int
adm_ctrl_generate_pair_assertions(int id,unsigned int pairs,adm_ctrl_pair_t pair[MAX_PAIR_ASSERTIONS])
{
	unsigned int i;

	for(i = 0 ; i < pairs ;i++)
	{
		DEBUG_CMD2(printf("DEBUG adm_ctrl_generate_pair_assertions: %s==%s\n",pair[i].name,pair[i].value));
		if ( kn_add_action(id,pair[i].name,pair[i].value,0) < 0 )
			switch( keynote_errno )
			{ 
				case ERROR_SYNTAX:
					return - ADMCTRL_PAIR_ERROR;
				case ERROR_MEMORY:
					return ADMCTRL_MEMORY_ERROR;
				default:
					return ADMCTRL_INTERNAL_ERROR;
			}
	}
	return 0;
}


static int
add_default_assertions(int id)
{
  struct timeval tm;
  char buf[MAX_ACTION_VALUE_SIZE];
  int err;

  // Add timestamp
  gettimeofday(&tm,NULL);
  snprintf(buf,MAX_ACTION_VALUE_SIZE,"%lu",tm.tv_sec);
  DEBUG_CMD2(printf("adm_ctrl_authorise: TIMESTAMP = \"%s\"\n",buf));
  if ( (err = kn_add_action(id,"TIMESTAMP",buf,0)) < 0 )
  {
    DEBUG_CMD2(fprintf(stderr,"adm_ctrl_authorise: error while adding timestamp\n"));
  }
  return err;
}

/** \brief Checks the credentials and resource consumption of request against a policy
 *
 * \param auth admission control request
 * \param policy admission control policy
 * \param res admission control result datatype where results are going to be stored
 * \param db reference to resource control database
 *
 * \return the index of the PCV that corresponds to the provided credentials,
 *  or less that zero for error
 */
int
#ifdef WITH_RESOURCE_CONTROL
adm_ctrl_authorise(adm_ctrl_request_t *auth,adm_ctrl_policy_t *policy,adm_ctrl_result_t *res,resource_ctrl_db_t *db)
#else
adm_ctrl_authorise(adm_ctrl_request_t *auth,adm_ctrl_policy_t *policy,adm_ctrl_result_t *res)
#endif
{
	int kn_session_id,i,creds_num = 0;
	char **credentials = NULL;
  char *pkstring;
	adm_ctrl_func_t *flist = NULL;
	int auth_error = 0;

  res->PCV = 0;
	res->error = 0;

	// Initialize session
	if ( (kn_session_id = kn_init()) < 0 )
	{
		DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: couldn't start a keynote session\n"));
		return - ADMCTRL_MEMORY_ERROR;
	}

	// Add assertions to keynote session
	for( i = 0; i < policy->assertions_num ; i++ )
	{
		if ( kn_add_assertion(kn_session_id,policy->assertions[i],strlen(policy->assertions[i]),ASSERT_FLAG_LOCAL) < 0 )
		{
      DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: error adding policy assertions\n"));
			switch( keynote_errno )
			{
				case ERROR_SYNTAX:
					auth_error = - ADMCTRL_POLICY_ERROR;
					break;
				case ERROR_MEMORY:
					auth_error = - ADMCTRL_MEMORY_ERROR;
					break;
				default:
					auth_error = - ADMCTRL_INTERNAL_ERROR;
					break;
			}
			goto error;
		}
	}

	// Add credentials
	if ( (credentials = kn_read_asserts(auth->credentials,strnlen(auth->credentials,MAX_CREDENTIALS_SIZE),&creds_num)) == NULL )
	{
		DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: couldn't extract credential assertions\n"));
		auth_error = - ADMCTRL_MEMORY_ERROR;
		goto error;
	}
	
	// Add credential assertions to keynote session
	for( i = 0; i < creds_num ; i++ )
		if ( kn_add_assertion(kn_session_id,credentials[i],strlen(credentials[i]),0) < 0 )
		{
			DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: error when adding credential assertion\n"));
			switch( keynote_errno )
			{
				case ERROR_SYNTAX:
					auth_error = - ADMCTRL_CREDS_ERROR;
					break;
				case ERROR_MEMORY:
					auth_error = - ADMCTRL_MEMORY_ERROR;
					break;
				default:
					auth_error = - ADMCTRL_INTERNAL_ERROR;
					break;
			}
			goto error;
		}

	// Add authorizer
  if ( (pkstring = kn_get_string(auth->pubkey)) == NULL )
  {
		DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: couldn't get authorizer's string\n"));
    auth_error = - ADMCTRL_PUBKEY_ERROR;
    goto error;
  }

	if ( kn_add_authorizer(kn_session_id,pkstring) < 0 )
	{
		DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: couldn't add authorizer\n"));
		switch( keynote_errno )
		{
			case ERROR_SYNTAX:
				auth_error = - ADMCTRL_PUBKEY_ERROR;
				break;
			case ERROR_MEMORY:
				auth_error = - ADMCTRL_MEMORY_ERROR;
				break;
			default:
				auth_error = - ADMCTRL_INTERNAL_ERROR;
				break;
		}
		goto error;
	}

	// Add the device name action
	if ( (auth_error = adm_ctrl_generate_pair_assertions(kn_session_id,auth->pairs_num,auth->pair_assertions)) < 0 )
	{
		DEBUG_CMD2(fprintf(stderr,"adm_ctrl_authorise: error while adding name-value pairs\n"));
		goto error;
	}

  if ( add_default_assertions(kn_session_id) < 0 )
    goto error;

	// Add the functions' specifications
	if ( auth->functions_num > 0 )
	{
		DEBUG_CMD2(printf("DEBUG adm_ctrl_authorise: calling adm_ctrl_deserialize_functions\n"));
		if ( (flist = adm_ctrl_deserialize_functions(auth->function_list,auth->functions_num,MAX_FUNCTION_LIST_SIZE)) == NULL )
		{
			DEBUG_CMD2(fprintf(stderr,"adm_ctrl_authorise: deserialization gobacked\n"));
			auth_error = - ADMCTRL_FUNCFORMAT_ERROR;
			goto error;
		}
		DEBUG_CMD2(printf("DEBUG adm_ctrl_authorise: calling adm_ctrl_generate_func_assertions\n"));
#ifdef WITH_RESOURCE_CONTROL
		if ( (auth_error = adm_ctrl_flist_process(kn_session_id,flist,res,db)) != 0 )
#else
		if ( (auth_error = adm_ctrl_flist_process(kn_session_id,flist)) != 0 )
#endif
		{
			DEBUG_CMD(fprintf(stderr,"adm_ctrl_authorise: processing function list failed\n"));
			goto error;
		}
	}

	// Finally do the checking
	if ( (res->PCV = kn_do_query(kn_session_id,default_PCV,NUMBER_OF_PCV)) < 0 )
	{
		DEBUG_CMD2(fprintf(stderr,"adm_ctrl_authorise: keynote query failed\n"));
		switch( keynote_errno )
		{
			case ERROR_MEMORY:
				auth_error = - ADMCTRL_MEMORY_ERROR;
				break;
			default:
				auth_error = - ADMCTRL_INTERNAL_ERROR;
				break;
		}
		goto error;
	}
	else if ( res->PCV == 0 )
	{
		if ( kn_get_failed(kn_session_id,KEYNOTE_ERROR_SIGNATURE,0) < 0 )
			res->error = - ADMCTRL_SIGNATURE_ERROR;
		else if ( kn_get_failed(kn_session_id,KEYNOTE_ERROR_SYNTAX,0) < 0 )
			res->error = - ADMCTRL_SYNTAX_ERROR;
	}
#ifdef WITH_RESOURCE_CONTROL
	else if ( res->PCV == 1 && db )
	{
		if ( (auth_error = resource_ctrl_check(db,res->required,res->resources_num)) > 0 )
		{
			DEBUG_CMD2(printf("DEBUG adm_ctrl_authorise: required resource %d unavailable\n",auth_error));
			res->resources_num = (size_t)auth_error;
			auth_error = res->PCV = 0;
			res->error = - ADMCTRL_RESOURCE_CTRL_FAIL;
		}
		else if ( auth_error < 0 )
		{
			DEBUG_CMD2(printf("DEBUG adm_ctrl_authorise: error while checking resources availability\n"));
			auth_error = - ADMCTRL_RESOURCE_CTRL_ERROR;
			res->PCV = 0;
		}
	}
#endif

error:
	if ( res->error == 0 )
		res->error = auth_error;

	if ( credentials )
	{
		for(i = 0 ; i < creds_num ; ++i)
			free(credentials[i]);
		free(credentials);
	}

	if ( flist )
		adm_ctrl_free_functions(flist);

	kn_close(kn_session_id);

	return auth_error;
}


/** \brief Authenticates a user
 *
 * Checks that the encrypted number provided by the user, is actually the 
 * number sent by mapi. The number will be decrypted using the public key
 * we are trying to authenticate, since it should be encrypted with the
 * corresponsing private key.
 *
 * \param a the structure containing the authentication data
 *
 * \return 1 on successful authentication, or a negative error code in case of
 * failure.
 */
int 
adm_ctrl_authenticate(adm_ctrl_request_t *a)
{
	bytestream enc_nonce;
  unsigned int dec_nonce;
  int e;

	enc_nonce.data = a->encrypted_nonce;
	enc_nonce.length = a->encrypted_nonce_len;
	if ( (e = adm_ctrl_decrypt_nonce(&enc_nonce,&dec_nonce,a->pubkey)) != 0 )
  {
    DEBUG_CMD(fprintf(stderr,"adm_ctrl_authenticate(): decryption failed\n"));
		return e;
  }

	// Check the nonce
	return (a->nonce != dec_nonce)? - ADMCTRL_AUTHENTICATION_ERROR : 1;
}
