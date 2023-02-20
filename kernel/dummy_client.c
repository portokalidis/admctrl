/* dummy_client.c

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

// Standard module headers
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
// Module parameters headers
#include <linux/moduleparam.h>
// Proc fs headers
#include <linux/proc_fs.h>
// Workqueue headers
#include <linux/workqueue.h>
// User-space access
#include <asm/uaccess.h>
// Spinlock headers
#include <linux/spinlock.h>

// Admission control header
#include "kadm_ctrl.h"
// authdev_submit
#include "authdev.h"
// request manipulation
#include "kadmctrl_req.h"

// Debug macros
#define DEBUG 1
#include "debug.h"

// Module meta-data
MODULE_AUTHOR("G Portokalidis");
MODULE_DESCRIPTION("Dummy client for the admission control kernel driver");
MODULE_LICENSE("GPL");

//! Macro that points to this module's name
#define MODNAME THIS_MODULE->name
//! Proc file name
#define PROC_NAME "authdev_client"
//! Proc file permissions
#define PROC_PERM 0644
//! Maximum number of threads that can be started
#define MAX_THREADS_NUM 5U
//! Maximum period (in seconds) that can be used
#define MAX_PERIOD 120LU
//! Maximum timeout (in seconds) for requests submission
#define MAX_TIMEOUT 10L

//! Proc file structure
static struct proc_dir_entry *proc_file = NULL;
//! Specifies if the period of request submissions. 0 de-activates. Trasformed to jiffies at init time
static unsigned long period = 0;
//! Number of threads
static unsigned int threads = 1;
//! Timeout used for request submissions. Trasformed to jiffies at init time
static long timeout = 2; 
//! Work queues array
static struct workqueue_struct *thread[MAX_THREADS_NUM];
//! Threads number queue
static spinlock_t tn_lock;

struct mywork
{
  unsigned int id;
  char active;
  struct work_struct work;
  adm_ctrl_request_t request;
  adm_ctrl_result_t result;
};
//! Work array
static struct mywork thread_work[MAX_THREADS_NUM];

//!< Support major device number parameter
module_param(period,ulong,0);
module_param(threads,uint,0);
module_param(timeout,long,0);


static void
work_run(void *d)
{
  struct mywork *work = (struct mywork *)d;

  memset(&work->result,0,sizeof(adm_ctrl_result_t));
  if ( authdev_submit(&work->request,&work->result,timeout) != 0 )
    printk(KERN_INFO "%s: (%u)submission failed\n",MODNAME,work->id);
  else
  {
    printk(KERN_INFO "%s: (%u)submission succeeded\n",MODNAME,work->id);
    if ( memcmp(&work->request,&work->result,sizeof(adm_ctrl_result_t)) == 0 )
      printk(KERN_INFO "%s: (%u)results valid\n",MODNAME,work->id);
    else
      printk(KERN_INFO "%s: (%u)results invalid!\n",MODNAME,work->id);
  }
  if ( work->active && period > 0 )
    queue_delayed_work(thread[work->id],&work->work,period);
}

static inline void
start_threads(unsigned int from,unsigned int to)
{
  unsigned int i;

  printk(KERN_DEBUG "%s: starting threads %u-%u\n",MODNAME,from,to);

  // Add work to do
  for(i = from; i <= to ;i++)
  {
    thread_work[i].active = 1;
    queue_work(thread[i],&thread_work[i].work);
  }
}

static inline void
stop_threads(unsigned int from,unsigned int to)
{
  unsigned int i;

  printk(KERN_DEBUG "%s: stopping threads %u-%u\n",MODNAME,from,to);

  for(i = from; i <= to ;i++)
  {
    thread_work[i].active = 0;
    cancel_delayed_work(&thread_work[i].work);
  }
}

static inline void
destroy_threads(unsigned int from,unsigned int to)
{
  unsigned int i;

  printk(KERN_DEBUG "%s: killing threads %u-%u\n",MODNAME,from,to);
  for(i = from; i <= to ;i++)
  {
    cancel_delayed_work(&thread_work[i].work);
    destroy_workqueue(thread[i]);
  }
}

static inline void
restart_threads(unsigned int old_threads,unsigned int new_threads)
{
  if ( old_threads < new_threads )
    start_threads(old_threads,new_threads-1);
  else if ( old_threads > new_threads )
    stop_threads(new_threads,old_threads-1);
}


static inline unsigned long
check_period(unsigned long period)
{
  if ( period > MAX_PERIOD )
  {
    printk(KERN_INFO "%s: invalid period specified. Using %lu\n",MODNAME,MAX_PERIOD);
    return MAX_PERIOD;
  }
  return period;
}

static inline unsigned int
check_threads(unsigned int threads)
{
  if ( threads > MAX_THREADS_NUM )
  {
    printk(KERN_INFO "%s: invalid number of threads specified. Using %u\n",MODNAME,MAX_THREADS_NUM);
    return MAX_THREADS_NUM;
  }
  return threads;
}

static inline long
check_timeout(long timeout)
{
  if ( timeout > MAX_TIMEOUT || timeout < 0 )
  {
    printk(KERN_INFO "%s: invalid submission timeout specified. Using %ld\n",MODNAME,MAX_TIMEOUT);
    return MAX_TIMEOUT;
  }
  return timeout;
}

/** \brief Proc file read operation
*/
static int
proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
  int len;
  
  if ( period > 0 )
    len = sprintf(page,"Period: %lu\n",period / HZ);
  else
    len = sprintf(page,"Period: INACTIVE\n");
  len += sprintf(page+len,"Threads number: %u\n",threads);
  len += sprintf(page+len,"Submission timeout: %ld\n",timeout / HZ);
  *eof = 1;
  return len;
}

/** \brief Proc file write operation
*/
static int
proc_write(struct file *filp, const char *buf, unsigned long count, void *data)
{
  int e;
  char *str,*k;

  // Allocate a buffer to use
  if ( (str = kmalloc(count,GFP_KERNEL)) == NULL )
    return - ENOMEM;
  // Copy the buffer
  if ( copy_from_user(str,buf,count) )
  {
    e = - EFAULT;
    goto ret;
  }
  str[count-1] = '\0';

  // Period
  if ( count > 7 && (k = strstr(str,"period")) != NULL )
  {
    unsigned long new_period = simple_strtoul(k + 7,NULL,10);
    if ( (new_period = check_period(new_period) * HZ) > 0 && period == 0 )
    {
      period = new_period;
      start_threads(0,threads-1);
    }
    else if ( new_period == 0 )
    {
      period = 0;
      stop_threads(0,threads-1);
    }
    else
      period = new_period;
  }
  // Threads number
  else if ( count > 8 && (k = strstr(str,"threads")) != NULL )
  {
    unsigned int new_threads = (unsigned int)simple_strtoul(k + 8,NULL,10);
    new_threads = check_threads(new_threads);
    spin_lock(&tn_lock);
    if ( period > 0 )
      restart_threads(threads,new_threads);
    threads = new_threads;
    spin_unlock(&tn_lock);
  }
  // Timeout
  else if ( count > 9 && (k = strstr(str,"timeout")) != NULL )
  {
    long new_timeout = simple_strtol(k + 9,NULL,10);
    timeout = check_timeout(new_timeout);
  }

  e = count;

ret:
  kfree(str);
  return e;
}

/** \brief Module initialisation function 
*/
static int
dummy_cl_init(void)
{
  unsigned int i;
  char name[11];

  // Check parameters
  period = check_period(period);
  threads = check_threads(threads);
  timeout = check_timeout(timeout);
  // Transform seconds to jiffies
  period *= HZ;
  timeout *= HZ;

  spin_lock_init(&tn_lock);

  // Create proc file
  if ( (proc_file = create_proc_entry(PROC_NAME,PROC_PERM,NULL)) == NULL )
    return - EAGAIN;
  proc_file->read_proc = proc_read;
  proc_file->write_proc = proc_write;

  // Initialise threads
  for(i = 0; i < MAX_THREADS_NUM ;i++)
  {
    snprintf(name,10,"authcl%u\n",i);
    if ( (thread[i] = create_workqueue(name)) == NULL )
      goto thread_err;
    thread_work[i].id = i;
    thread_work[i].active = 0;
    INIT_WORK(&thread_work[i].work,work_run,&thread_work[i]);
  }

  if ( period > 0 )
  {
    // Start threads
    start_threads(0,threads-1);
    printk(KERN_INFO "%s: started %u threads,period=%lu,timeout=%ld\n",MODNAME,threads,period/HZ,timeout/HZ);
  }

  printk(KERN_INFO "%s: initialized\n",MODNAME);

  return 0;

thread_err:
  if ( i > 0 )
    destroy_threads(0,i-1);
  remove_proc_entry(PROC_NAME,NULL);
  return - ENOMEM;
}

//! Module exit function
static void
dummy_cl_exit(void)
{
  remove_proc_entry(PROC_NAME,NULL);
  destroy_threads(0,MAX_THREADS_NUM-1);
  printk(KERN_INFO "%s: exits\n",MODNAME);
}

module_init(dummy_cl_init);
module_exit(dummy_cl_exit);
