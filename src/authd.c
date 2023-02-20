/* authd.c

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef WITH_SYSLOG
#include <syslog.h>
#else
enum { LOG_INFO, LOG_CRIT, LOG_WARNING, LOG_ERR };
#endif

#include "shm_sync.h"
#include "shm.h"
#include "adm_ctrl.h"
#include "admctrl_errno.h"
#include "admctrl_comm.h"


/*! \file authd.c
 *  \brief The authd admission control daemon
 *  \author Georgios Portokalidis
 */


/**** Global variables ****/
//! Admission control IPC communication data
static admctrl_comm_t comm;
//! Policy
static adm_ctrl_policy_t policy;
//! Executable's name, used for error reporting
static const char *exec_name;

#ifdef WITH_RESOURCE_CONTROL
#include "resource_ctrl.h"

//! Resource control db
static resource_ctrl_db_t resctrl_db;
//! Location of resource control home
static char *resource_ctrl_home = DEFAULT_RESOURCE_CTRL_HOME;
//! Database file name
static char *resource_ctrl_name = DEFAULT_RESOURCE_DBNAME;

#endif


/**** Configurable values ****/
//! Daemon process flag
static char isdaemon = 0;
//! Resource control status flag
static char resource_control = 0;
//! Verbocity flag
static char verbose = 0;
//! Filename containing the policy
static char *policy_fn = DEFAULT_POLICY_FILE;
//! Filename to access shared memory
static char *shm_fn = DEFAULT_SHM_FILE;
//! Project id to access shared memory
static char shm_pid = DEFAULT_SHM_PROJECT_ID;


/** \brief Prints messages to syslog and additionally to stdout 
	*	if the process isn't running as a daemon
	*
	*	\param type the type of the message, passed to syslog
	* \param s the actual message to print
	*/
static inline void
print_msg(int type,const char *s)
{
#ifdef WITH_SYSLOG
	syslog(type,s);
#endif
	if ( isdaemon == 0 )
		printf("%s: %s\n",exec_name,s);
}


/** \brief Shutdown the process
 *
 * Gracefully ends this process by closing the shared memory segment,
 * deallocating memory and calling exit()
 */
static void 
shutdown(int data)
{
	if ( comm.shm_id >= 0 )
		admctrl_comm_uninit(&comm);
#ifdef WITH_RESOURCE_CONTROL
	if ( resource_control )
		resource_ctrl_dbclose(&resctrl_db);
#endif
	if ( policy.assertions )
		free(policy.assertions);
	print_msg(LOG_INFO,"Exiting");
#ifdef SYSLOG
	closelog();
#endif
	exit((data == 0 )?1:0);
}


/** \brief Display usage information
	
	\param name Name of executable
*/
static void
print_usage(const char *name)
{
	printf("Usage: %s [OPTIONS]\n\n",name);
	printf("  -d, --daemon                  Run as a daemon in the background\n");
	printf("  -p, --policy  (filename)      Read policy from filename\n");
	printf("  -s, --shmpath (pathname)      Use pathname for shared memory\n");
	printf("  -i, --shmid   (id character)  Use id for shared memory\n");
#ifdef WITH_RESOURCE_CONTROL
	printf("  -D, --dbhome  (pathname)      Set resource control DB home to pathname\n");
	printf("  -b, --dbname  (name)          Set resource control DB file name\n");
	printf("  -R, --rc                      Enable resource control\n");
#endif
	printf("  -v, --verbose                 Be verbose with clients' requests\n");
	printf("  -h, --help                    Display this message\n");
}


/** \brief Parse command line arguments

	\param argc Number of arguments
	\param argv String array containing the arguments
*/
static void
parse_arguments(int argc,char **argv)
{
	int c;
	const char optstring[] = "dp:s:i:D:hvRb:";
	const struct option longopts[] = {
		{"daemon",no_argument,NULL,'d'},
		{"policy",required_argument,NULL,'p'},
		{"shmpath",required_argument,NULL,'s'},
		{"shmid",required_argument,NULL,'i'},
		{"dbhome",required_argument,NULL,'D'},
		{"dbname",required_argument,NULL,'b'},
		{"rc",no_argument,NULL,'R'},
		{"help",no_argument,NULL,'h'},
		{"verbose",no_argument,NULL,'v'},
		{"",0,NULL,0}
	};

	while( (c = getopt_long(argc,argv,optstring,longopts,NULL)) >= 0 )
		switch( c )
		{
			case 'd':
				isdaemon = 1;
				break;
			case 'p':
				policy_fn = optarg;
				break;
			case 's':
				shm_fn = optarg;
				break;
			case 'i':
				shm_pid = *optarg;
				break;
#ifdef WITH_RESOURCE_CONTROL
			case 'D':
				resource_ctrl_home = optarg;
				break;
			case 'R':
				resource_control = 1;
				break;
      case 'b':
        resource_ctrl_name = optarg;
        break;
#endif
			case 'v':
				verbose = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				exit(0);
			default:
				exit(1);
		}
}


//! The main function of the process
int 
main(int argc,char **argv)
{
	int pid,i;
	adm_ctrl_request_t *auth_request;
  adm_ctrl_result_t auth_result;
#ifdef WITH_RESOURCE_CONTROL
	resource_ctrl_db_t *DB = NULL;
#endif

	parse_arguments(argc,argv);

	// Init some values
	exec_name = *argv;
	bzero(&policy,sizeof(adm_ctrl_policy_t));
	comm.shm_id = -1;


	// Generate key for shared memory communication
	if ( (comm.key = ftok(shm_fn,shm_pid)) < 0 )
	{
		fprintf(stderr,"%s: Couldn't generate shared memory key(%s,%c)\n",exec_name,shm_fn,shm_pid);
		perror("ftok");
		return 1;
	}

	// Load policy from file
	if ( adm_ctrl_load_policy(policy_fn,&policy) < 0 )
	{
		fprintf(stderr,"%s: Couldn't load policy from %s\n",argv[0],policy_fn);
		perror("adm_ctrl_load_policy");
		return 1;
	}

#ifdef WITH_RESOURCE_CONTROL
	resctrl_db.ENV = NULL;
	// Initialise resource control
	if ( resource_control )
	{
		if ( resource_ctrl_dbinit(&resctrl_db) != 0 )
		{
			fprintf(stderr,"%s: Error initialising resource control DB\n",argv[0]);
			perror("resource_ctrl_dbinit");
			resctrl_db.ENV = NULL;
			shutdown(0);
		}
		if ( resource_ctrl_dbopen(&resctrl_db,resource_ctrl_home,resource_ctrl_name,RESOURCE_DB_RDONLY,0) != 0 )
		{
			fprintf(stderr,"%s: Error opening resource control DB in %s\n",argv[0],resource_ctrl_home);
			perror("resource_ctrl_dbopen");
			resctrl_db.ENV = NULL;
			shutdown(0);
		}
		DB = &resctrl_db;
	}
#endif

	// Initialise IPC
	switch( admctrl_comm_init(&comm) )
	{
		case -ADMCTRL_COMM_SHM_ERROR:
			fprintf(stderr,"%s: Error while initialising shared memory IPC\n",argv[0]);
			perror("admctrl_comm_init");
			shutdown(0);
		case -ADMCTRL_COMM_SEM_ERROR:
			fprintf(stderr,"%s: Error initialising semaphores for IPC\n",argv[0]);
			perror("admctrl_comm_init");
			shutdown(0);
	}
	auth_request = comm.shm_addr;

	// Go daemon
	if ( getppid() != 1 && isdaemon == 1 )
	{
		if ( (pid = fork()) < 0 )
		{
			perror(argv[0]);
			shutdown(0);
		}
		else if ( pid > 0 )
			exit(0);
		if ( setpgrp() < 0 )
		{
			perror(argv[0]);
			shutdown(0);
		}
		chdir("/");
		umask(0);

#if DEBUG == 0
		for(i = 0 ; i < NOFILE ; i++)
			close(i);
#else
    printf("DEBUG messages enabled\n");
#endif
	}

	signal(SIGTERM,shutdown);
	if ( isdaemon == 0 )
	{
		signal(SIGINT,shutdown);
		signal(SIGQUIT,shutdown);
	}

#ifdef SYSLOG
	openlog(SYSLOG_PREPEND,LOG_CONS|LOG_PID,LOG_AUTHPRIV);
#endif

	print_msg(LOG_INFO,"Running");

	// Start processing data
	while( shm_data_wait(comm.sem_id) == 0 )
	{
		bzero(&auth_result,sizeof(adm_ctrl_result_t));
		if ( (i = adm_ctrl_authenticate(auth_request)) == 1 )
		{
#ifdef WITH_RESOURCE_CONTROL
			switch( adm_ctrl_authorise(auth_request,&policy,&auth_result,DB) )
#else
			switch( adm_ctrl_authorise(auth_request,&policy,&auth_result) )
#endif
			{
				case ADMCTRL_MEMORY_ERROR:
					print_msg(LOG_CRIT,"runned out of memory");
					break;
				case ADMCTRL_INTERNAL_ERROR:
					print_msg(LOG_CRIT,"unexpected internal error");
					break;
			}
		}
		else
			auth_result.error = i;

		memcpy(comm.shm_addr,&auth_result,sizeof(adm_ctrl_result_t));
		if ( shm_result_ready(comm.sem_id) < 0 )
			break;

		// Verbose error reporting
		if ( verbose )
		{
			if ( i == ADMCTRL_AUTHENTICATION_ERROR )
				print_msg(LOG_WARNING,"request authentication failed");
			else if ( i < 0 )
				print_msg(LOG_ERR,"error while authenticating request");
			else if ( auth_result.PCV < 1 )
				print_msg(LOG_ERR,"request authorisation failed");
			else
				print_msg(LOG_INFO,"request authenticated & authorised successfully");
		}
	}

	print_msg(LOG_CRIT,"IPC failed");
	
	shutdown(0);
	return 0;// Never reaches this, but it makes gcc happy ;)
}
