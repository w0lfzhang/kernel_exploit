/**
 * Vulnerable kernel driver
 *
 * This module is vulnerable to OOB access and allows arbitrary code
 * execution.
 * An arbitrary offset can be passed from user space via the provided ioctl().
 * This offset is then used as an index for the 'ops' array to obtain the
 * function address to be executed.
 * 
 *
 * Full article: https://cyseclabs.com/page?n=17012016
 *
 * Author: Vitaly Nikolenko
 * Email: vnik@cyseclabs.com
 **/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "drv.h"

#define DEVICE_NAME "vulndrv"
#define DEVICE_PATH "/dev/vulndrv"

static int device_open(struct inode *, struct file *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_release(struct inode *, struct file *f);

static struct class *class;
unsigned long *ops[3];
static int major_no;

static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};


static int device_release(struct inode *i, struct file *f) {
	printk(KERN_INFO "device released!\n");
	return 0;
}

static int device_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "device opened!\n");
	return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct drv_req *req;
	void (*fn)(void);
	
	switch(cmd) {
	case 0:
		req = (struct drv_req *)args;
		printk(KERN_INFO "size = %lx\n", req->offset);
                printk(KERN_INFO "fn is at %p\n", &ops[req->offset]);
		fn = &ops[req->offset];
		fn();
		break;
	default:
		break;
	}

	return 0;
}

static int m_init(void) {
	printk(KERN_INFO "addr(ops) = %p\n", &ops);
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(class, NULL, MKDEV(major_no, 0), NULL, DEVICE_NAME);

	return 0;
}

static void m_exit(void) {
	device_destroy(class, MKDEV(major_no, 0));
	class_unregister(class);
	class_destroy(class);
	unregister_chrdev(major_no, DEVICE_NAME);
	printk(KERN_INFO "Driver unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
