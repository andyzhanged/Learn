
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/splice.h>
#include <linux/pfn.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <uapi/linux/magic.h>
#include <linux/mount.h>
#include <linux/module.h>

static struct class *mem_class;
#define ZHANG_MEM_MAJOR		511
#define ZHANG_MEM_MINOR		0

#define open_mem	open_port

int __weak phys_mem_access_prot_allowed(struct file *file,
	unsigned long pfn, unsigned long size, pgprot_t *vma_prot)
{
	return 1;
}

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return 1;
}

#ifdef CONFIG_STRICT_DEVMEM
/* This check is done in drivers/char/mem.c in case of STRICT_DEVMEM */
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	return 1;
}
#else
/* This check is needed to avoid cache aliasing when PAT is enabled */
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	if (!pat_enabled())
		return 1;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn))
			return 0;
		cursor += PAGE_SIZE;
		pfn++;
	}
	return 1;
}
#endif /* CONFIG_STRICT_DEVMEM */


// static int __weak valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
// {
// 	return 1;
// }

#if 1
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn)){
		printk("pfn valid\n");
		return pgprot_noncached(vma_prot);
	}
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
#endif

static int zhanged_mmap_mem(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	/* Turn a kernel-virtual address into a physical page frame */
	printk("vm_pgoff %llx\n", vma->vm_pgoff);
	pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;
	printk("pfn %llx\n", pfn);

	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
    printk("11111111111111111111\n");
	/* Does it even fit in phys_addr_t? */
	if (offset >> PAGE_SHIFT != vma->vm_pgoff)
		return -EINVAL;

    printk("22222222222222222222\n");
	/* It's illegal to wrap around the end of the physical address space. */
	if (offset + (phys_addr_t)size - 1 < offset)
		return -EINVAL;

	// if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
	// 	return -EINVAL;

    printk("3333333333333333333\n");
	if (!private_mapping_ok(vma))
		return -ENOSYS;

    printk("4444444444444444444\n");
	if (!range_is_allowed(vma->vm_pgoff, size))
		return -EPERM;

    printk("5555555555555555555\n");
	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
						&vma->vm_page_prot))
		return -EINVAL;

	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
						 size,
						 vma->vm_page_prot);

	//vma->vm_ops = &mmap_mem_ops;
    printk("Error Error Error\n");
    pr_info("vma->vm_start %llx, vm_pgoff %llx, vm_page_prot %llx\n", vma->vm_start, vma->vm_pgoff, vma->vm_page_prot);
	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}


static int zhanged_open(struct inode *inode, struct file *filp)
{
	printk("open open open\n");
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	// rc = security_locked_down(LOCKDOWN_DEV_MEM);
	// if (rc)
	// 	return rc;

	/*
	 * Use a unified address space to have a single point to manage
	 * revocations when drivers want to take over a /dev/mem mapped
	 * range.
	 */
	// inode->i_mapping = devmem_inode->i_mapping;
	filp->f_mapping = inode->i_mapping;
	printk("open open open     11111111111111\n");
	return 0;
}

static const struct file_operations mem_fops = {
	.owner =	THIS_MODULE,
	.mmap		= zhanged_mmap_mem,
	.open		= zhanged_open,
};

static int zhanged_major = -1;
static int __init chr_dev_init(void)
{
	zhanged_major = register_chrdev(0, "zhanged_mem", &mem_fops);
	if(zhanged_major < 0){
		printk("unable to get major %d for memory devs\n", zhanged_major);
		return -1;
	}
    printk("module init zhanged\n");
    mem_class = class_create(THIS_MODULE, "zhanged_mem_new");
	if (IS_ERR(mem_class))
		return PTR_ERR(mem_class);
	
	device_create(mem_class, NULL, MKDEV(zhanged_major, ZHANG_MEM_MINOR), NULL, "%s%d",
				"zhanged_mem", ZHANG_MEM_MINOR);
	return 0;
}

static void __exit chr_dev_exit(void)
{
	device_destroy(mem_class, MKDEV(zhanged_major, ZHANG_MEM_MINOR));
	class_destroy(mem_class);
	unregister_chrdev(zhanged_major, "zhanged_mem");
}

module_init(chr_dev_init);
module_exit(chr_dev_exit);
MODULE_LICENSE("GPL");
