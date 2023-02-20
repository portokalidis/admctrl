/* authdb_manage.c

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

/** \file authdb_manage.c
	\brief Simple resource control db management application
  \author Georgios Portokalidis
	*/

#include "resource_ctrl.h"

static char *db_dir,*db_fn;
static resource_ctrl_db_t db;
static u_int32_t recover;

static void
process_args(int argc,char **argv)
{
	if ( argc < 3 || (argc > 3 && *argv[1] != 'R') )
	{
		fprintf(stderr,"%s: Illegal arguments\n",argv[0]);
		fprintf(stderr,"Syntax: %s [R] (db directory) (db filename)\n",argv[0]);
		exit(1);
	}

	if ( argc == 3 )
	{
		db_dir = argv[1];
		db_fn = argv[2];
	}
	else
	{
		recover = DB_RECOVER;
		db_dir = argv[2];
		db_fn = argv[3];
	}
}

static int
get_selection(const char *message,int min,int max)
{
	int selection,c;

	// Get a valid selection
	do {
		printf("%s",message);
		selection = getchar() - '0';
	} while( selection < min || selection > max);

	// Ignore until EOF or newline
	while ( (c = getchar()) != EOF && c != '\n' )
		;
	return selection;
}

static uint32_t
get_uint32(const char *message)
{
	char buf[64];
	int c,i;

	printf("%s",message);

	i = 0;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < 63 )
			buf[i++] = (char)c;
	buf[i] = '\0';
	return strtoul(buf,NULL,10);
}

static void
get_string(const char *message,size_t max,char *buf)
{
	int c;
	unsigned int i;

	printf("%s",message);

	i = 0;
	--max;
	while( (c = getchar()) != EOF && c != '\n' )
		if ( i < max )
			buf[i++] = (char)c;
	buf[i] = '\0';
}

static int
confirm(const char *message,int sel1)
{
	int c;
	int ret = -1;

	printf("%s",message);
	if ( getchar() == sel1 )
		ret = 0;

	// Ignore until EOF or newline
	while ( (c = getchar()) != EOF && c != '\n' )
		;

	return ret;
}

static void
print_menu()
{
	printf("MAIN MENU\n");
	printf("1. Functions\n");
	printf("2. Libraries\n");
	printf("3. Resources\n");
	printf("4. Resource consumption\n");
	printf("0. Exit\n");
}

static void
print_menu2()
{
	printf(" ACTIONS\n");
	printf("1. List\n");
	printf("2. Insert\n");
	printf("3. Delete\n");
	printf("0. Return\n");
}


static void
functions()
{
	int sel;
	u_int32_t uint;
	char buf[MAX_ACTION_NAME_SIZE];

	do {
		printf("FUNCTIONS");
		print_menu2();
		printf("Selection:");
		sel = get_selection("Selection:",0,3);
		putchar('\n');
		switch( sel )
		{
			case 0:
				break;
			case 1:
				printf("Function list:\n");
				resource_ctrl_display_functions(&db);
				break;
			case 2:
				printf("Adding new function...\nExisting functions:\n");
				resource_ctrl_display_functions(&db);
				get_string("Insert new function name:",MAX_ACTION_NAME_SIZE,buf);
				uint = get_uint32("Insert new function key:");
        if ( confirm("Is this function's resource consumption global(Y/N)? ",'Y') == 0 )
          uint |= (~0U) << 16;
        else
          uint &= (~0U) >> 16;
				if ( resource_ctrl_add_function(&db,buf,uint) == 0 )
					printf("Function added!\n");
				else
					printf("Insertion failed!\n");
				break;
			case 3:
				printf("Deleting function...\nExisting functions:\n");
				resource_ctrl_display_functions(&db);
				get_string("Enter function to delete:",MAX_ACTION_NAME_SIZE,buf);
				if ( confirm("Are you sure(Y/N)?",'Y') != 0 )
					break;
				if ( resource_ctrl_del_function(&db,buf) == 0 )
					printf("Function and associated resource consumption has been deleted!\n");
				else
					printf("Deletion failed!\n");
				break;
			default:
				printf("Invalid selection!\n");
		}
		putchar('\n');
	} while (sel != 0);
}

static void
libraries()
{
	int sel;
	u_int32_t uint;
	char buf[MAX_ACTION_NAME_SIZE];

	do {
		printf("LIBRARIES");
		print_menu2();
		sel = get_selection("Selection:",0,3);
		putchar('\n');
		switch( sel )
		{
			case 0:
				break;
			case 1:
				printf("Libraries list:\n");
				resource_ctrl_display_libraries(&db);
				break;
			case 2:
				printf("Adding new library:\nExisting libraries:\n");
				resource_ctrl_display_libraries(&db);
				get_string("Insert new library name:",MAX_ACTION_NAME_SIZE,buf);
				uint = get_uint32("Insert new library key:");
        uint &= (~0) >> 16;
				if ( resource_ctrl_add_library(&db,buf,uint) == 0 )
					printf("Library added!\n");
				else
					printf("Insertion failed!\n");
				break;
			case 3:
				printf("Deleting library...\nExisting libraries:\n");
				resource_ctrl_display_libraries(&db);
				get_string("Enter library to delete:",MAX_ACTION_NAME_SIZE,buf);
				fgets(buf,MAX_ACTION_NAME_SIZE,stdin);
				if ( confirm("Are you sure(Y/N)?",'Y') != 0 )
					break;
				if ( resource_ctrl_del_library(&db,buf) == 0 )
					printf("Library and associated resource consumption has been deleted!\n");
				else
					printf("Deletion failed!\n");
				break;
			default:
				printf("Invalid selection!\n");
		}
		putchar('\n');
	} while (sel != 0);
}

static void
consumption()
{
	int sel;
	u_int32_t pk,rkey;
	char func[MAX_ACTION_NAME_SIZE],lib[MAX_ACTION_NAME_SIZE];
	resource_consumption_t consumption;

	do {
		printf("RESOURCE CONSUMPTION");
		print_menu2();
		sel = get_selection("Selection:",0,3);
		if ( sel <= 0 )
			break;
		printf("Existing functions:\n");
		resource_ctrl_display_functions(&db);
		get_string("Select function:",MAX_ACTION_NAME_SIZE,func);
		printf("Existing libraries:\n");
		resource_ctrl_display_libraries(&db);
		get_string("Select library:",MAX_ACTION_NAME_SIZE,lib);
		if ( resource_ctrl_resourcekey(&db,func,lib,&pk) != 0 )
		{
			printf("Error acquiring key for supplied combination!\n\n");
			continue;
		}
		switch( sel )
		{
			case 1:
				printf("Resource consumption list:\n");
				resource_ctrl_display_consumption(&db,pk);
				break;
			case 2:
				printf("Adding resource consumption...\nExisting resources:\n");
				resource_ctrl_display_resources(&db);
				consumption.rkey = get_uint32("Select resource key:");
				consumption.fixed_cost = get_uint32("Enter new resource consumption fixed cost:");
				get_string("Enter new resource consumption variable cost formula:",RESOURCE_CTRL_MAX_VAR_FORM_LEN,consumption.variable_cost_formula);
				if ( resource_ctrl_add_consumption(&db,pk,&consumption) == 0 )
					printf("Resource consumption added!\n");
				else
					printf("Insertion failed!\n");
				break;
			case 3:
				printf("Deleting resource consumption..\nExisting:\n");
				resource_ctrl_display_consumption(&db,pk);
				rkey = get_uint32("Enter resource key to delete:");
				if ( confirm("Are you sure(Y/N)?",'Y') != 0 )
					break;
				if ( resource_ctrl_del_consumption(&db,pk,rkey) == 0 )
					printf("Resource consumption has been deleted!\n");
				else
					printf("Deletion failed!\n");
				break;
			default:
				printf("Invalid selection!\n");
		}
		putchar('\n');
	} while (sel != 0);
}

static void
resources()
{
	int sel;
	u_int32_t uint;
	resource_t resource;

	do {
		printf("RESOURCES");
		print_menu2();
		sel = get_selection("Selection:",0,3);
		putchar('\n');
		switch( sel )
		{
			case 0:
				break;
			case 1:
				printf("Resources list:\n");
				resource_ctrl_display_resources(&db);
				break;
			case 2:
				printf("Adding new resource...\nExisting resources:\n");
				resource_ctrl_display_resources(&db);
				uint = get_uint32("Insert new resource key:");
				resource.available = get_uint32("Insert new resource availability:");
				get_string("Insert new resource description:",RESOURCE_CTRL_MAX_RES_DESCR_LEN,resource.description);
				if ( resource_ctrl_add_resource(&db,uint,&resource) == 0 )
					printf("Resource added!\n");
				else
					printf("Insertion failed!\n");
				break;
			case 3:
				printf("Deleting resource...\nExisting resources:\n");
				resource_ctrl_display_resources(&db);
				uint = get_uint32("Enter resource key to delete:");
				if ( confirm("Are you sure(Y/N)?",'Y') != 0 )
					break;
				if ( resource_ctrl_del_resource(&db,uint) == 0 )
					printf("All resource records have been removed!\n");
				else
					printf("Deletion failed!\n");
				break;
			default:
				printf("Invalid selection!\n");
				break;
		}
		putchar('\n');
	} while (sel != 0);
}

static void
process_selection(int sel)
{
	switch( sel )
	{
		case 0:
			break;
		case 1:
			functions();
			break;
		case 2:
			libraries();
			break;
		case 3:
			resources();
			break;
		case 4:
			consumption();
			break;
		default:
			break;
	}
}


int 
main(int argc,char **argv)
{
	int e,selection;

	process_args(argc,argv);

	if ( (e = resource_ctrl_dbinit(&db)) != 0 )
	{
		fprintf(stderr,"%s: Error initialising DB\n",argv[0]);
		return 1;
	}

	if ( (e = resource_ctrl_dbopen(&db,db_dir,db_fn,DB_CREATE,DB_CREATE | recover)) != 0 )
	{
		fprintf(stderr,"%s: Error opening DB\n",argv[0]);
		return 1;
	}

	do {
		print_menu();
		selection = get_selection("Selection:",0,4);
		process_selection(selection);
	} while( selection != 0 );

	resource_ctrl_dbclose(&db);
	
	return 0;
}
