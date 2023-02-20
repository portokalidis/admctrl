/* authdev.c

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

#define EXPORT_SYMTAB

#if defined(CONFIG_MODVERSIONS) && ! defined(MODVERSIONS)
#include <linux/modversions.h>
#define MODVERSIONS
#endif

// Standard module headers
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
// Character device headers
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/cdev.h>
// Module parameters headers
#include <linux/moduleparam.h>
#else
#include <linux/kdev_t.h>
#endif
// Proc fs headers
#include <linux/proc_fs.h>
// Spinlock headers
#include <linux/spinlock.h>
// Semaphore headers
#include <asm/semaphore.h>
// User-space access headers
#include <asm/uaccess.h>
// Wait queues headers
#include <linux/wait.h>

// Admission control header
#include "kadm_ctrl.h"

// Debug macros
#define DEBUG 1
#include "debug.h"

// Module meta-data
MODULE_AUTHOR("G Portokalidis");
MODULE_DESCRIPTION("Kernel device driver to enable communication between with the admission control daemon in user-space");
MODULE_SUPPORTED_DEVICE("/dev/authdev");
MODULE_LICENSE("GPL");

//! Macro that points to this module's name
#define MODNAME THIS_MODULE->name
//! Device name
#define DEVICE_NAME "authdev"
//! Proc file name
#define PROC_NAME DEVICE_NAME
//! Proc file permissions
#define PROC_PERM 0444
//! Device major number
#define MAJOR_NUM 250
//! Device minor number
#define MINOR_NUM 0

typedef enum { IDLE = 0, READING, WRITING } device_state_t;

//! Device major number
static unsigned int major_num = MAJOR_NUM;
//! Device variable
static dev_t device;
//! Character device object
static struct cdev *cdevice = NULL;
//! Proc file structure
static struct proc_dir_entry *proc_file = NULL;
//! Device operations lock
static spinlock_t device_lock;
//! Specifies if the device is open
static char device_open = 0;
//! Pending requests
static unsigned int pending = 0;
//! Submitted requests queue
DECLARE_WAIT_QUEUE_HEAD(request_queue);
//! Device access queue
DECLARE_WAIT_QUEUE_HEAD(device_queue);

//!< Support major device number parameter
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
module_param(major_num,uint,0);
#else
MODULE_PARM(major_num,"i");
#endif

//! Serving client structure
static struct client_struct
{
  device_state_t state; //!< State of client
  adm_ctrl_request_t request; //!< Request data
  adm_ctrl_result_t result; //!< Result data
  struct semaphore sem, //!< Availability semaphore
  mutex; //!< State access mutex
} client;

/** \brief Device open operation
  Opens the device. Only one process at a time can open the device.
  \return 0 on success, or - EBUSY of the device has already been opened
*/
static int
authdev_open(struct inode *i,struct file *filp)
{
  int e = 0;

  spin_lock(&device_lock);
  if ( device_open )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: device is already open\n",MODNAME));
    e = - EBUSY;
    goto ret;
  } else if ( (filp->f_flags & O_ACCMODE) != O_RDWR )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: device has to be opened in RW mode\n",
          MODNAME));
    e = - EACCES;
    goto ret;
  }
  device_open = 1;
  DEBUG_CMD(printk(KERN_DEBUG "%s: device opened\n",MODNAME));

ret:
  spin_unlock(&device_lock);
  return e;
}

/** \brief Device release operation
  Releases the device.
  \return always 0
*/
static int
authdev_release(struct inode *i,struct file *filp)
{
  if ( down_interruptible(&client.mutex) )
    return - ERESTARTSYS;
  spin_lock(&device_lock);
  DEBUG_CMD(printk(KERN_DEBUG "%s: device closed\n",MODNAME));
  device_open = 0;
  client.state = IDLE;
  spin_unlock(&device_lock);
  up(&client.mutex);
  return 0;
}

/** \brief Device read operation
*/
static ssize_t
authdev_read(struct file *filp,char *buf,size_t count,loff_t *f_pos)
{
  DEBUG_CMD(printk(KERN_DEBUG "%s: entering read\n",MODNAME));
  
  // Wait if we are not supposed to read
  if ( wait_event_interruptible(device_queue,client.state == READING) != 0 )
    return - ERESTARTSYS;

  DEBUG_CMD(printk(KERN_DEBUG "%s: performing read\n",MODNAME));

  // Do some boundary checking
  if ( *f_pos >= sizeof(adm_ctrl_request_t) )
    return 0;
  if ( (count + *f_pos) > sizeof(adm_ctrl_request_t) )
    count = sizeof(adm_ctrl_request_t) - *f_pos;

  // Copy data to user-space
  if ( copy_to_user(buf,&client.request + *f_pos,count) )
    return - EFAULT;

  if ( down_interruptible(&client.mutex) )
    return - ERESTARTSYS;
  *f_pos += count;
  // Check if we reached the end of the structure
  if ( *f_pos == sizeof(adm_ctrl_request_t) )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: read complete\n",MODNAME));

    if ( client.state == READING )
      client.state = WRITING;
    // Wake up anyone waiting to write
    wake_up_interruptible_sync(&device_queue);
  }
  up(&client.mutex);
  
  DEBUG_CMD(printk(KERN_DEBUG "%s: exiting read\n",MODNAME));
  
  return count;
}

/** \brief Device write operation
*/
static ssize_t
authdev_write(struct file *filp,const char *buf,size_t count,loff_t *f_pos)
{
  DEBUG_CMD(printk(KERN_DEBUG "%s: entering write\n",MODNAME));

  // Wait if we are not supposed to write
  if ( wait_event_interruptible(device_queue,client.state == WRITING) != 0 )
    return - ERESTARTSYS;

  DEBUG_CMD(printk(KERN_DEBUG "%s: performing write\n",MODNAME));

  // Do some boundary checking
  if ( *f_pos >= (sizeof(adm_ctrl_request_t) + sizeof(adm_ctrl_result_t)) )
    return 0;
  if ( (count + *f_pos) > (sizeof(adm_ctrl_request_t) + 
        sizeof(adm_ctrl_result_t)) )
    count = (sizeof(adm_ctrl_request_t) + sizeof(adm_ctrl_result_t)) - *f_pos;

  // Copy data from user-space
  if ( copy_from_user(&client.result,buf,count) )
    return - EFAULT;

  if ( down_interruptible(&client.mutex) )
    return - ERESTARTSYS;
  *f_pos += count;
  if ( *f_pos == (sizeof(adm_ctrl_request_t) + sizeof(adm_ctrl_result_t)) )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: write complete\n",MODNAME));
    // Rewind
    *f_pos = 0;
    if ( client.state == WRITING )
      client.state = IDLE;
    // Wake up anyone waiting to get results
    wake_up_interruptible_sync(&request_queue);
  }
  up(&client.mutex);

  DEBUG_CMD(printk(KERN_DEBUG "%s: exiting write\n",MODNAME));
  
  return count;
}

//! Device file operations structure
static struct file_operations dev_ops = {
read: authdev_read,
write: authdev_write,
open: authdev_open,
release: authdev_release,
owner: THIS_MODULE
};

int
authdev_submit(adm_ctrl_request_t *request,adm_ctrl_result_t *result,
    long timeout)
{
  int e = - ERESTARTSYS;

  if ( try_module_get(THIS_MODULE) == 0 )
    return - EAGAIN;

  pending++;
  DEBUG_CMD(printk(KERN_DEBUG "%s: submitting request %u\n",MODNAME,pending));
  
  if ( device_open == 0 )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: device is not open\n",MODNAME));
    e = - EAGAIN;
    goto ret;
  }

  if ( down_interruptible(&client.sem) )
    goto ret;

  memcpy(&client.request,request,sizeof(adm_ctrl_request_t));
  memset(result,0,sizeof(adm_ctrl_result_t));
  client.state = READING;
  // Wake any processes waiting to read
  wake_up_interruptible(&device_queue);

  DEBUG_CMD(printk(KERN_DEBUG "%s: waiting for result\n",MODNAME));

  if ( (e = wait_event_interruptible_timeout(request_queue,client.state == IDLE,
          timeout)) == 0 )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: submission timed out\n",MODNAME));
    e = - ETIME;
  }
  else if ( e < 0 )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: submission interrupted\n",MODNAME));
    goto int_ret;
  }
  else
    e = 0;

  /*
  // Check state. If we were in the process of completetion return the result
  // else set state to idle and fail
  down(&client.mutex);
  if ( client.state == IDLE )
    e = 0;
  client.state = IDLE;
  up(&client.mutex);
  */

  if ( e == 0 )
  {
    DEBUG_CMD(printk(KERN_DEBUG "%s: copying result\n",MODNAME));
    memcpy(result,&client.result,sizeof(adm_ctrl_result_t));
  }
 
int_ret:
  up(&client.sem);
ret:
  module_put(THIS_MODULE);
  DEBUG_CMD(printk(KERN_DEBUG "%s: submission finished %u\n",MODNAME,pending));
  pending--;
  return e;
}

/** \brief Proc file read operation
*/
static int
proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
  int len;
  char *cur_state = NULL;

  len = sprintf(page,"Device open: %s\n",(device_open==0)?"NO":"YES");
  len += sprintf(page+len,"Requests pending: %u\n",pending);
  switch( client.state )
  {
    case IDLE:
      cur_state = "IDLE";
      break;
    case READING:
      cur_state = "READING";
      break;
    case WRITING:
      cur_state = "WRITING";
      break;
  }
  len += sprintf(page+len,"Current state: %s\n",cur_state);
  *eof = 1;
  return len;
}

/** \brief Module initialisation function 
*/
static int
authdev_init(void)
{
  int e = - EAGAIN;

  // Initialise variables
  client.state = IDLE;
  sema_init(&client.sem,1);
  init_MUTEX(&client.mutex);
  spin_lock_init(&device_lock);

  // Create proc file
  if ( (proc_file = create_proc_read_entry(PROC_NAME,PROC_PERM,NULL,proc_read,
          NULL)) == NULL )
    return - EAGAIN;

  // Register device region
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0)
  device = MKDEV(major_num,MINOR_NUM);
  if ( (e = register_chrdev_region(device,1,DEVICE_NAME)) != 0 )
    goto reg_dev_error;

  // Allocate character device structure
  if ( (cdevice = cdev_alloc()) == NULL )
  {
    e = - ENOMEM;
    goto error;
  }
  cdevice->owner = THIS_MODULE;
  cdevice->ops = &dev_ops;

  // Activate character device
  kobject_set_name(&cdevice->kobj,DEVICE_NAME);
  if ( (e = cdev_add(cdevice,device,1)) != 0 )
    goto error;
#else
  if ( (e = register_chrdev(major_num,DEVICE_NAME,&dev_ops)) != 0 )
    goto reg_dev_error;
#endif

  
  printk(KERN_INFO "%s initialised using dev %d/%d\n",MODNAME,major_num,
      MINOR_NUM);

  return 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0)
error:
  if ( cdevice )
    kobject_put(&cdevice->kobj);
#endif
  unregister_chrdev_region(device,1);
reg_dev_error:
  remove_proc_entry(PROC_NAME,NULL);
  printk(KERN_INFO "%s failed to initialise\n",MODNAME);
  return e;
}

//! Module exit function
static void
authdev_exit(void)
{
  cdev_del(cdevice);
  unregister_chrdev_region(device,1);
  remove_proc_entry(PROC_NAME,NULL);
  printk(KERN_INFO "%s exiting\n",MODNAME);
}

module_init(authdev_init);
module_exit(authdev_exit);
EXPORT_SYMBOL(authdev_submit);
