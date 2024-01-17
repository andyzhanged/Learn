// SPDX-License-Identifier: GPL-2.0
/*
 * This is a module to test the HMM (Heterogeneous Memory Management)
 * mirror and zone device private memory migration APIs of the kernel.
 * Userspace programs can register with the driver to mirror their own address
 * space and can use the device to read/write any valid virtual address.
 */
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/memremap.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/pagemap.h>
#include <linux/hmm.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/sched/mm.h>
#include <linux/platform_device.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>

#include "test_hmm_uapi.h"

#define DMIRROR_NDEVICES		4
#define DMIRROR_RANGE_FAULT_TIMEOUT	1000
#define DEVMEM_CHUNK_SIZE		(256 * 1024 * 1024U)
#define DEVMEM_CHUNKS_RESERVE		16

/*
 * For device_private pages, dpage is just a dummy struct page
 * representing a piece of device memory. dmirror_devmem_alloc_page
 * allocates a real system memory page as backing storage to fake a
 * real device. zone_device_data points to that backing page. But
 * for device_coherent memory, the struct page represents real
 * physical CPU-accessible memory that we can use directly.
 */
#define BACKING_PAGE(page) (is_device_private_page((page)) ? \
			   (page)->zone_device_data : (page))

static unsigned long spm_addr_dev0;
module_param(spm_addr_dev0, long, 0644);
MODULE_PARM_DESC(spm_addr_dev0,
		"Specify start address for SPM (special purpose memory) used for device 0. By setting this Coherent device type will be used. Make sure spm_addr_dev1 is set too. Minimum SPM size should be DEVMEM_CHUNK_SIZE.");

static unsigned long spm_addr_dev1;
module_param(spm_addr_dev1, long, 0644);
MODULE_PARM_DESC(spm_addr_dev1,
		"Specify start address for SPM (special purpose memory) used for device 1. By setting this Coherent device type will be used. Make sure spm_addr_dev0 is set too. Minimum SPM size should be DEVMEM_CHUNK_SIZE.");

static const struct dev_pagemap_ops dmirror_devmem_ops;
static const struct mmu_interval_notifier_ops dmirror_min_ops;
static dev_t dmirror_dev;

struct dmirror_device;

struct dmirror_bounce {
	void			*ptr;
	unsigned long		size;
	unsigned long		addr;
	unsigned long		cpages;
};

#define DPT_XA_TAG_ATOMIC 1UL
#define DPT_XA_TAG_WRITE 3UL

/*
 * Data structure to track address ranges and register for mmu interval
 * notifier updates.
 */
struct dmirror_interval {
	struct mmu_interval_notifier	notifier;
	struct dmirror			*dmirror;
};

/*
 * Data attached to the open device file.
 * Note that it might be shared after a fork().
 */
struct dmirror {
	struct dmirror_device		*mdevice;
	struct xarray			pt;
	struct mmu_interval_notifier	notifier;
	struct mutex			mutex;
};

/*
 * ZONE_DEVICE pages for migration and simulating device memory.
 */
struct dmirror_chunk {
	struct dev_pagemap	pagemap;
	struct dmirror_device	*mdevice;
	bool remove;
};

/*
 * Per device data.
 */
struct dmirror_device {
	struct cdev		cdevice;
	unsigned int            zone_device_type;
	struct device		device;

	unsigned int		devmem_capacity;
	unsigned int		devmem_count;
	struct dmirror_chunk	**devmem_chunks;
	struct mutex		devmem_lock;	/* protects the above */

	unsigned long		calloc;
	unsigned long		cfree;
	struct page		*free_pages;
	spinlock_t		lock;		/* protects the above */
};

static struct dmirror_device dmirror_devices[DMIRROR_NDEVICES];

static int dmirror_bounce_init(struct dmirror_bounce *bounce,
			       unsigned long addr,
			       unsigned long size)
{
	bounce->addr = addr;
	bounce->size = size;
	bounce->cpages = 0;
	bounce->ptr = vmalloc(size);
	if (!bounce->ptr)
		return -ENOMEM;
	return 0;
}

static bool dmirror_is_private_zone(struct dmirror_device *mdevice)
{
	return (mdevice->zone_device_type ==
		HMM_DMIRROR_MEMORY_DEVICE_PRIVATE) ? true : false;
}

static enum migrate_vma_direction
dmirror_select_device(struct dmirror *dmirror)
{
	return (dmirror->mdevice->zone_device_type ==
		HMM_DMIRROR_MEMORY_DEVICE_PRIVATE) ?
		MIGRATE_VMA_SELECT_DEVICE_PRIVATE :
		MIGRATE_VMA_SELECT_DEVICE_COHERENT;
}

static void dmirror_bounce_fini(struct dmirror_bounce *bounce)
{
	vfree(bounce->ptr);
}

static int dmirror_fops_open(struct inode *inode, struct file *filp)
{
	struct cdev *cdev = inode->i_cdev;
	struct dmirror *dmirror;
	int ret;

	/* Mirror this process address space */
	dmirror = kzalloc(sizeof(*dmirror), GFP_KERNEL);
	if (dmirror == NULL)
		return -ENOMEM;

	dmirror->mdevice = container_of(cdev, struct dmirror_device, cdevice);
	mutex_init(&dmirror->mutex);
	xa_init(&dmirror->pt);

	ret = mmu_interval_notifier_insert(&dmirror->notifier, current->mm,
				0, ULONG_MAX & PAGE_MASK, &dmirror_min_ops);
	if (ret) {
		kfree(dmirror);
		return ret;
	}

	filp->private_data = dmirror;
	return 0;
}

static int dmirror_fops_release(struct inode *inode, struct file *filp)
{
	struct dmirror *dmirror = filp->private_data;

	mmu_interval_notifier_remove(&dmirror->notifier);
	xa_destroy(&dmirror->pt);
	kfree(dmirror);
	return 0;
}

static struct dmirror_chunk *dmirror_page_to_chunk(struct page *page)
{
	return container_of(page->pgmap, struct dmirror_chunk, pagemap);
}

static struct dmirror_device *dmirror_page_to_device(struct page *page)
{
	return dmirror_page_to_chunk(page)->mdevice;
}

/**
 * 模拟dev建立页表
*/
__attribute__((__noinline__)) static int
dmirror_do_fault(struct dmirror *dmirror, struct hmm_range *range)
{
	unsigned long *pfns = range->hmm_pfns;
	unsigned long pfn;

	for (pfn = (range->start >> PAGE_SHIFT);
	     pfn < (range->end >> PAGE_SHIFT);
	     pfn++, pfns++) {
		struct page *page;
		void *entry;

		/*
		 * Since we asked for hmm_range_fault() to populate pages,
		 * it shouldn't return an error entry on success.
		 */
		WARN_ON(*pfns & HMM_PFN_ERROR);
		WARN_ON(!(*pfns & HMM_PFN_VALID));

		/*cpu mem对应的page*/
		page = hmm_pfn_to_page(*pfns);
		WARN_ON(!page);

		entry = page;
		if (*pfns & HMM_PFN_WRITE)
			entry = xa_tag_pointer(entry, DPT_XA_TAG_WRITE);
		else if (WARN_ON(range->default_flags & HMM_PFN_WRITE))
			return -EFAULT;

		/*存储页表
		* pfn相当于dev访问cpu mem时对应的va
		* entry为cpu mem的page
		*/
		entry = xa_store(&dmirror->pt, pfn, entry, GFP_ATOMIC);
		if (xa_is_err(entry))
			return xa_err(entry);
	}

	return 0;
}

/*
*  该函数主要清除device的页表
*   当cpu尝试访问dev内存时，将dev mem迁移到cpu mem，之后调用该函数，清除页表
migrate_fault test case 访问迁移到dev的cpu mem触发如下回溯。
26464   26464   hmm-tests       dmirror_interval_invalidate
        b'dmirror_interval_invalidate+0x1 [test_hmm]'
        b'migrate_vma_setup+0x20c [kernel]'
        b'dmirror_devmem_fault+0xc6 [test_hmm]'
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'

*/
static void dmirror_do_update(struct dmirror *dmirror, unsigned long start,
			      unsigned long end)
{
	unsigned long pfn;
	void *entry;

	/*
	 * The XArray doesn't hold references to pages since it relies on
	 * the mmu notifier to clear page pointers when they become stale.
	 * Therefore, it is OK to just clear the entry.
	 */
	xa_for_each_range(&dmirror->pt, pfn, entry, start >> PAGE_SHIFT,
			  end >> PAGE_SHIFT)
		xa_erase(&dmirror->pt, pfn);
}

/* 该函数主要是清dev的页表
* 
unmap内存时，清dev的页表
68205   68205   hmm-tests       dmirror_interval_invalidate
        b'dmirror_interval_invalidate+0x1 [test_hmm]'
        b'unmap_vmas+0x15a [kernel]'
        b'unmap_region+0xb3 [kernel]'
        b'do_mas_align_munmap+0x2d6 [kernel]'
        b'do_mas_munmap+0xe9 [kernel]'
        b'__vm_munmap+0xbd [kernel]'
        b'__x64_sys_munmap+0x1b [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'

68205   68205   hmm-tests       dmirror_interval_invalidate
        b'dmirror_interval_invalidate+0x1 [test_hmm]'
        b'try_to_migrate_one+0xbe7 [kernel]'
        b'rmap_walk_anon+0x16b [kernel]'
        b'try_to_migrate+0x9a [kernel]'
        b'migrate_device_unmap+0x399 [kernel]'
        b'migrate_device_range+0x8b [kernel]'
        b'dmirror_device_remove_chunks+0x11c [test_hmm]'
        b'dmirror_fops_unlocked_ioctl+0x2b3 [test_hmm]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]

cpu访问mem，迁移会cpu时，清dev页表：
130593  130593  hmm-tests       dmirror_interval_invalidate ret 1
        b'__mmu_notifier_invalidate_range_start+0x1a5 [kernel]'
        b'wp_page_copy+0x5f5 [kernel]'
        b'do_wp_page+0x205 [kernel]'
        b'handle_pte_fault+0x25e [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'

130593  130593  hmm-tests       dmirror_interval_invalidate ret 1
        b'__mmu_notifier_invalidate_range_start+0x1a5 [kernel]'
        b'migrate_vma_setup+0x20c [kernel]'
        b'dmirror_migrate_to_device.constprop.0+0x1bc [test_hmm]'
        b'dmirror_fops_unlocked_ioctl+0x27c [test_hmm]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]

130593  130593  hmm-tests       dmirror_interval_invalidate ret 1
        b'__mmu_notifier_invalidate_range_start+0x1a5 [kernel]'
        b'__split_huge_pmd+0x298 [kernel]'
        b'vma_adjust_trans_huge+0x179 [kernel]'
        b'__vma_adjust+0x1c2 [kernel]'
        b'__split_vma+0x1b7 [kernel]'
        b'do_mas_align_munmap+0x3e9 [kernel]'
        b'do_mas_munmap+0xe9 [kernel]'
        b'__vm_munmap+0xbd [kernel]'
        b'__x64_sys_munmap+0x1b [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'
*/
static bool dmirror_interval_invalidate(struct mmu_interval_notifier *mni,
				const struct mmu_notifier_range *range,
				unsigned long cur_seq)
{
	struct dmirror *dmirror = container_of(mni, struct dmirror, notifier);

	/*
	 * Ignore invalidation callbacks for device private pages since
	 * the invalidation is handled as part of the migration process.
	 */
	if (range->event == MMU_NOTIFY_MIGRATE &&
	    range->owner == dmirror->mdevice)
		return true;

	if (mmu_notifier_range_blockable(range))
		mutex_lock(&dmirror->mutex);
	else if (!mutex_trylock(&dmirror->mutex))
		return false;

	mmu_interval_set_seq(mni, cur_seq);
	dmirror_do_update(dmirror, range->start, range->end);

	mutex_unlock(&dmirror->mutex);
	return true;
}

static const struct mmu_interval_notifier_ops dmirror_min_ops = {
	.invalidate = dmirror_interval_invalidate,
};

/*查找cpu页表，得到start对应的pfn
* 建立dev和pfn的映射页表
*/
__attribute__((__noinline__)) static int
dmirror_range_fault(struct dmirror *dmirror, struct hmm_range *range)
{
	struct mm_struct *mm = dmirror->notifier.mm;
	unsigned long timeout =
		jiffies + msecs_to_jiffies(HMM_RANGE_DEFAULT_TIMEOUT);
	int ret;

	while (true) {
		if (time_after(jiffies, timeout)) {
			ret = -EBUSY;
			goto out;
		}

		range->notifier_seq = mmu_interval_read_begin(range->notifier);
		mmap_read_lock(mm);

		/**
		 * 根据range->start查找cpu页表，并将结果保存到range->hmm_pfns中
		*/
		ret = hmm_range_fault(range);
		mmap_read_unlock(mm);

		if (ret) {
			if (ret == -EBUSY)
				continue;
			goto out;
		}

		mutex_lock(&dmirror->mutex);
		if (mmu_interval_read_retry(range->notifier,
					    range->notifier_seq)) {
			mutex_unlock(&dmirror->mutex);
			continue;
		}
		break;
	}

	/**
	 * 模拟缺页中断，为dev建立页表
	*/
	ret = dmirror_do_fault(dmirror, range);

	mutex_unlock(&dmirror->mutex);
out:
	return ret;
}

/*
* 模拟dev访问cpu mem时的缺页中断
* 1. 根据start和flags调用hmm_range_fault查找对应的src pfn
* 2. start和src pfn之间建立映射关系(即页表)
*/
static int dmirror_fault(struct dmirror *dmirror, unsigned long start,
			 unsigned long end, bool write)
{
	struct mm_struct *mm = dmirror->notifier.mm;
	unsigned long addr;
	unsigned long pfns[64];
	struct hmm_range range = {
		.notifier = &dmirror->notifier,
		.hmm_pfns = pfns,
		.pfn_flags_mask = 0,
		.default_flags =
			HMM_PFN_REQ_FAULT | (write ? HMM_PFN_REQ_WRITE : 0),
		.dev_private_owner = dmirror->mdevice,
	};
	int ret = 0;

	/* Since the mm is for the mirrored process, get a reference first. */
	if (!mmget_not_zero(mm))
		return 0;

	for (addr = start; addr < end; addr = range.end) {
		range.start = addr;
		range.end = min(addr + (ARRAY_SIZE(pfns) << PAGE_SHIFT), end);

		ret = dmirror_range_fault(dmirror, &range);
		if (ret)
			break;
	}

	mmput(mm);
	return ret;
}


/*
* 模拟dev读取cpu mem，如果dev页表不存在，返回-ENOENT
*/
static int dmirror_do_read(struct dmirror *dmirror, unsigned long start,
			   unsigned long end, struct dmirror_bounce *bounce)
{
	unsigned long pfn;
	void *ptr;

	ptr = bounce->ptr + ((start - bounce->addr) & PAGE_MASK);

	for (pfn = start >> PAGE_SHIFT; pfn < (end >> PAGE_SHIFT); pfn++) {
		void *entry;
		struct page *page;
		void *tmp;

		/*模拟dev查找页表*/
		entry = xa_load(&dmirror->pt, pfn);
		page = xa_untag_pointer(entry);
		/*没有页表，返回-ENOENT*/
		if (!page)
			return -ENOENT;

		/*page 为sys memory*/
		tmp = kmap(page);

		/*该步模拟dev读取cpu mem，保存到dev mem*/
		memcpy(ptr, tmp, PAGE_SIZE);
		kunmap(page);

		ptr += PAGE_SIZE;
		bounce->cpages++;
	}

	return 0;
}

/*
 * 模拟dev读cpu mem
*/
__attribute__((__noinline__)) static int
dmirror_read(struct dmirror *dmirror, struct hmm_dmirror_cmd *cmd)
{
	struct dmirror_bounce bounce;
	unsigned long start, end;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	int ret;

	start = cmd->addr;
	end = start + size;
	if (end < start)
		return -EINVAL;

	ret = dmirror_bounce_init(&bounce, start, size);
	if (ret)
		return ret;

	while (1) {
		mutex_lock(&dmirror->mutex);
		/*
		* 模拟dev读取cpu mem
		*/
		ret = dmirror_do_read(dmirror, start, end, &bounce);
		mutex_unlock(&dmirror->mutex);
		if (ret != -ENOENT)
			break;

		start = cmd->addr + (bounce.cpages << PAGE_SHIFT);

		/**
		 * 模拟dev的缺页中断，分配dev物理内存，建立页表
		*/
		ret = dmirror_fault(dmirror, start, end, false);
		if (ret)
			break;
		cmd->faults++;
	}

	if (ret == 0) {
		if (copy_to_user(u64_to_user_ptr(cmd->ptr), bounce.ptr,
				 bounce.size))
			ret = -EFAULT;
	}
	cmd->cpages = bounce.cpages;
	dmirror_bounce_fini(&bounce);
	return ret;
}

/*
 * 模拟dev写cpu mem
*/
__attribute__((__noinline__)) static int
dmirror_do_write(struct dmirror *dmirror, unsigned long start,
		 unsigned long end, struct dmirror_bounce *bounce)
{
	unsigned long pfn;
	void *ptr;

	ptr = bounce->ptr + ((start - bounce->addr) & PAGE_MASK);

	for (pfn = start >> PAGE_SHIFT; pfn < (end >> PAGE_SHIFT); pfn++) {
		void *entry;
		struct page *page;
		void *tmp;

		/*查找start对应的页表*/
		entry = xa_load(&dmirror->pt, pfn);
		page = xa_untag_pointer(entry);
		if (!page || xa_pointer_tag(entry) != DPT_XA_TAG_WRITE)
			return -ENOENT;
		tmp = kmap(page);

		/*模拟dev写cpu mem*/
		memcpy(tmp, ptr, PAGE_SIZE);
		kunmap(page);

		ptr += PAGE_SIZE;
		bounce->cpages++;
	}

	return 0;
}

/*
 * 模拟dev写cpu mem
 * 1. dev尝试写cpu mem，没有页表，返回-ENOENT
 * 2. dev发现没有页表，中断建立dev页表
 * 3. 回到步骤1
*/
static int dmirror_write(struct dmirror *dmirror, struct hmm_dmirror_cmd *cmd)
{
	struct dmirror_bounce bounce;
	unsigned long start, end;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	int ret;

	start = cmd->addr;
	end = start + size;
	if (end < start)
		return -EINVAL;

	ret = dmirror_bounce_init(&bounce, start, size);
	if (ret)
		return ret;
	if (copy_from_user(bounce.ptr, u64_to_user_ptr(cmd->ptr),
			   bounce.size)) {
		ret = -EFAULT;
		goto fini;
	}

	while (1) {
		mutex_lock(&dmirror->mutex);
		ret = dmirror_do_write(dmirror, start, end, &bounce);
		mutex_unlock(&dmirror->mutex);
		if (ret != -ENOENT)
			break;

		start = cmd->addr + (bounce.cpages << PAGE_SHIFT);
		ret = dmirror_fault(dmirror, start, end, true);
		if (ret)
			break;
		cmd->faults++;
	}

fini:
	cmd->cpages = bounce.cpages;
	dmirror_bounce_fini(&bounce);
	return ret;
}

/*
* dev内存初始化
*/
static int dmirror_allocate_chunk(struct dmirror_device *mdevice,
				   struct page **ppage)
{
	struct dmirror_chunk *devmem;
	struct resource *res = NULL;
	unsigned long pfn;
	unsigned long pfn_first;
	unsigned long pfn_last;
	void *ptr;
	int ret = -ENOMEM;

	devmem = kzalloc(sizeof(*devmem), GFP_KERNEL);
	if (!devmem)
		return ret;

	/**
	 * 申请内存，用于模拟dev mem。
	*/
	switch (mdevice->zone_device_type) {
	case HMM_DMIRROR_MEMORY_DEVICE_PRIVATE:
		/*
		* 申请mem region，可通过cat /proc/iomem查看区间
		*/
		res = request_free_mem_region(&iomem_resource, DEVMEM_CHUNK_SIZE,
					      "hmm_dmirror");
		if (IS_ERR_OR_NULL(res))
			goto err_devmem;
		devmem->pagemap.range.start = res->start;
		devmem->pagemap.range.end = res->end;
		devmem->pagemap.type = MEMORY_DEVICE_PRIVATE;
		break;
	case HMM_DMIRROR_MEMORY_DEVICE_COHERENT:
		devmem->pagemap.range.start = (MINOR(mdevice->cdevice.dev) - 2) ?
							spm_addr_dev0 :
							spm_addr_dev1;
		devmem->pagemap.range.end = devmem->pagemap.range.start +
					    DEVMEM_CHUNK_SIZE - 1;
		devmem->pagemap.type = MEMORY_DEVICE_COHERENT;
		break;
	default:
		ret = -EINVAL;
		goto err_devmem;
	}

	devmem->pagemap.nr_range = 1;
	devmem->pagemap.ops = &dmirror_devmem_ops;
	devmem->pagemap.owner = mdevice;

	mutex_lock(&mdevice->devmem_lock);

	if (mdevice->devmem_count == mdevice->devmem_capacity) {
		struct dmirror_chunk **new_chunks;
		unsigned int new_capacity;

		new_capacity = mdevice->devmem_capacity +
				DEVMEM_CHUNKS_RESERVE;
		new_chunks = krealloc(mdevice->devmem_chunks,
				sizeof(new_chunks[0]) * new_capacity,
				GFP_KERNEL);
		if (!new_chunks)
			goto err_release;
		mdevice->devmem_capacity = new_capacity;
		mdevice->devmem_chunks = new_chunks;
	}

	/*
	 * 对于MEMORY_DEVICE_PRIVATE的dev memory，申请特殊的struct page(该page有别于正常的ram page)
	 * cpu无法直接映射dev mem的struct page，当cpu访问时，会触发从dev mem迁移回cpu mem。
	 */
	ptr = memremap_pages(&devmem->pagemap, numa_node_id());
	if (IS_ERR_OR_NULL(ptr)) {
		if (ptr)
			ret = PTR_ERR(ptr);
		else
			ret = -EFAULT;
		goto err_release;
	}

	devmem->mdevice = mdevice;
	pfn_first = devmem->pagemap.range.start >> PAGE_SHIFT;
	pfn_last = pfn_first + (range_len(&devmem->pagemap.range) >> PAGE_SHIFT);
	mdevice->devmem_chunks[mdevice->devmem_count++] = devmem;

	mutex_unlock(&mdevice->devmem_lock);

	pr_info("added new %u MB chunk (total %u chunks, %u MB) PFNs [0x%lx 0x%lx)\n",
		DEVMEM_CHUNK_SIZE / (1024 * 1024),
		mdevice->devmem_count,
		mdevice->devmem_count * (DEVMEM_CHUNK_SIZE / (1024 * 1024)),
		pfn_first, pfn_last);

	spin_lock(&mdevice->lock);

	/*
	* 将所有的dev mem page通过链表串联起来
	*/
	for (pfn = pfn_first; pfn < pfn_last; pfn++) {
		/*该page即是管理dev mem的专属page*/
		struct page *page = pfn_to_page(pfn);
		page->zone_device_data = mdevice->free_pages;
		mdevice->free_pages = page;
	}
	if (ppage) {
		*ppage = mdevice->free_pages;
		mdevice->free_pages = (*ppage)->zone_device_data;
		mdevice->calloc++;
	}
	spin_unlock(&mdevice->lock);

	return 0;

err_release:
	mutex_unlock(&mdevice->devmem_lock);
	if (res && devmem->pagemap.type == MEMORY_DEVICE_PRIVATE)
		release_mem_region(devmem->pagemap.range.start,
				   range_len(&devmem->pagemap.range));
err_devmem:
	kfree(devmem);

	return ret;
}

/*
* 申请dev mem struct page 以及对应的物理内存
*/
static struct page *dmirror_devmem_alloc_page(struct dmirror_device *mdevice)
{
	struct page *dpage = NULL;
	struct page *rpage = NULL;

	/*
	 * For ZONE_DEVICE private type, this is a fake device so we allocate
	 * real system memory to store our device memory.
	 * For ZONE_DEVICE coherent type we use the actual dpage to store the
	 * data and ignore rpage.
	 */
	if (dmirror_is_private_zone(mdevice)) {
		/*
		* 该测试是模拟的dev private memory，所以page后面并没有实际对应物理页。
		* 因此申请cpu mem来模拟dev private mem
		*/
		rpage = alloc_page(GFP_HIGHUSER);
		if (!rpage)
			return NULL;
	}
	spin_lock(&mdevice->lock);

	/*
	* dpage可以理解为dev memory的page结构体
	* 由 dmirror_allocate_chunk创建
	*/
	if (mdevice->free_pages) {
		dpage = mdevice->free_pages;
		mdevice->free_pages = dpage->zone_device_data;
		mdevice->calloc++;
		spin_unlock(&mdevice->lock);
	} else {
		spin_unlock(&mdevice->lock);
		if (dmirror_allocate_chunk(mdevice, &dpage))
			goto error;
	}

	zone_device_page_init(dpage);

	/*再迁移cpu mem到dev mem时，用的就是dpage->zone_device_data*/
	dpage->zone_device_data = rpage;
	return dpage;

error:
	if (rpage)
		__free_page(rpage);
	return NULL;
}

/*分配dev mem，并且拷贝src mem到dev mem*/
static void dmirror_migrate_alloc_and_copy(struct migrate_vma *args,
					   struct dmirror *dmirror)
{
	struct dmirror_device *mdevice = dmirror->mdevice;
	const unsigned long *src = args->src;
	unsigned long *dst = args->dst;
	unsigned long addr;

	for (addr = args->start; addr < args->end; addr += PAGE_SIZE,
						   src++, dst++) {
		struct page *spage;
		struct page *dpage;
		struct page *rpage;

		if (!(*src & MIGRATE_PFN_MIGRATE))
			continue;

		/*
		 * Note that spage might be NULL which is OK since it is an
		 * unallocated pte_none() or read-only zero page.
		 */
		/*cpu source page*/
		spage = migrate_pfn_to_page(*src);
		if (WARN(spage && is_zone_device_page(spage),
		     "page already in device spage pfn: 0x%lx\n",
		     page_to_pfn(spage)))
			continue;
		
		/*分配dev的dst page*/
		dpage = dmirror_devmem_alloc_page(mdevice);
		if (!dpage)
			continue;
  		rpage = BACKING_PAGE(dpage);

		/*如果src page存在，拷贝到rpage*/
		if (spage)
			copy_highpage(rpage, spage);
		else{
			/*如果src page不存在，把rpage清空为0*/	
			clear_highpage(rpage);
		}
		/*
		 * Normally, a device would use the page->zone_device_data to
		 * point to the mirror but here we use it to hold the page for
		 * the simulated device memory and that page holds the pointer
		 * to the mirror.
		 */
		rpage->zone_device_data = dmirror;

		pr_info("migrating from sys to dev pfn src: 0x%lx pfn dst: 0x%lx\n",
			 page_to_pfn(spage), page_to_pfn(dpage));
		*dst = migrate_pfn(page_to_pfn(dpage));
		if ((*src & MIGRATE_PFN_WRITE) ||
		    (!spage && args->vma->vm_flags & VM_WRITE))
			*dst |= MIGRATE_PFN_WRITE;
	}
}

static int dmirror_check_atomic(struct dmirror *dmirror, unsigned long start,
			     unsigned long end)
{
	unsigned long pfn;

	for (pfn = start >> PAGE_SHIFT; pfn < (end >> PAGE_SHIFT); pfn++) {
		void *entry;

		entry = xa_load(&dmirror->pt, pfn);
		if (xa_pointer_tag(entry) == DPT_XA_TAG_ATOMIC)
			return -EPERM;
	}

	return 0;
}

static int dmirror_atomic_map(unsigned long start, unsigned long end,
			      struct page **pages, struct dmirror *dmirror)
{
	unsigned long pfn, mapped = 0;
	int i;

	/* Map the migrated pages into the device's page tables. */
	mutex_lock(&dmirror->mutex);

	for (i = 0, pfn = start >> PAGE_SHIFT; pfn < (end >> PAGE_SHIFT); pfn++, i++) {
		void *entry;

		if (!pages[i])
			continue;

		entry = pages[i];
		entry = xa_tag_pointer(entry, DPT_XA_TAG_ATOMIC);
		entry = xa_store(&dmirror->pt, pfn, entry, GFP_ATOMIC);
		if (xa_is_err(entry)) {
			mutex_unlock(&dmirror->mutex);
			return xa_err(entry);
		}

		mapped++;
	}

	mutex_unlock(&dmirror->mutex);
	return mapped;
}

/*当cpu mem迁移到dev之后，该函数负责建立dev mem和addr之间的映射页表*/
static int dmirror_migrate_finalize_and_map(struct migrate_vma *args,
					    struct dmirror *dmirror)
{
	unsigned long start = args->start;
	unsigned long end = args->end;
	const unsigned long *src = args->src;
	const unsigned long *dst = args->dst;
	unsigned long pfn;

	/* Map the migrated pages into the device's page tables. */
	mutex_lock(&dmirror->mutex);

	for (pfn = start >> PAGE_SHIFT; pfn < (end >> PAGE_SHIFT); pfn++,
								src++, dst++) {
		struct page *dpage;
		void *entry;

		if (!(*src & MIGRATE_PFN_MIGRATE))
			continue;

		dpage = migrate_pfn_to_page(*dst);
		if (!dpage)
			continue;

		entry = BACKING_PAGE(dpage);
		if (*dst & MIGRATE_PFN_WRITE)
			entry = xa_tag_pointer(entry, DPT_XA_TAG_WRITE);

		/*建立dev页表*/
		entry = xa_store(&dmirror->pt, pfn, entry, GFP_ATOMIC);
		if (xa_is_err(entry)) {
			mutex_unlock(&dmirror->mutex);
			return xa_err(entry);
		}
	}

	mutex_unlock(&dmirror->mutex);
	return 0;
}

/*标记该段cpu mem当前由dev访问
* 和hmm_range_fault的区别是，当cpu再次访问cpu mem时，cpu mem
* 对应的物理pfn和迁移到dev mem之前的pfn一致。
*/
static int dmirror_exclusive(struct dmirror *dmirror,
			     struct hmm_dmirror_cmd *cmd)
{
	unsigned long start, end, addr;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	struct mm_struct *mm = dmirror->notifier.mm;
	struct page *pages[64];
	struct dmirror_bounce bounce;
	unsigned long next;
	int ret;

	start = cmd->addr;
	end = start + size;
	if (end < start)
		return -EINVAL;

	/* Since the mm is for the mirrored process, get a reference first. */
	if (!mmget_not_zero(mm))
		return -EINVAL;

	mmap_read_lock(mm);
	for (addr = start; addr < end; addr = next) {
		unsigned long mapped = 0;
		int i;

		if (end < addr + (ARRAY_SIZE(pages) << PAGE_SHIFT))
			next = end;
		else
			next = addr + (ARRAY_SIZE(pages) << PAGE_SHIFT);

		/*查找addr对应的页表，并保存到pages，标记该段mem专用于dev访问
		* cpu在访问该段mem时，将addr和之前的pages映射。也就是说addr对应的
		* pfn值，在dev访问前后是一样的，这点和hmm_range_fault不同。
		*/
		ret = make_device_exclusive_range(mm, addr, next, pages, NULL);
		/*
		 * Do dmirror_atomic_map() iff all pages are marked for
		 * exclusive access to avoid accessing uninitialized
		 * fields of pages.
		 */
		if (ret == (next - addr) >> PAGE_SHIFT)
			mapped = dmirror_atomic_map(addr, next, pages, dmirror);
		for (i = 0; i < ret; i++) {
			if (pages[i]) {
				unlock_page(pages[i]);
				put_page(pages[i]);
			}
		}

		if (addr + (mapped << PAGE_SHIFT) < next) {
			mmap_read_unlock(mm);
			mmput(mm);
			return -EBUSY;
		}
	}
	mmap_read_unlock(mm);
	mmput(mm);

	/* Return the migrated data for verification. */
	ret = dmirror_bounce_init(&bounce, start, size);
	if (ret)
		return ret;
	mutex_lock(&dmirror->mutex);
	ret = dmirror_do_read(dmirror, start, end, &bounce);
	mutex_unlock(&dmirror->mutex);
	if (ret == 0) {
		if (copy_to_user(u64_to_user_ptr(cmd->ptr), bounce.ptr,
				 bounce.size))
			ret = -EFAULT;
	}

	cmd->cpages = bounce.cpages;
	dmirror_bounce_fini(&bounce);
	return ret;
}

/*
* 1. src为dev mem
* 2. 申请cpu mem
* 3. 清除dev页表
* 4. 拷贝dev mem到cpu mem
*/
static vm_fault_t dmirror_devmem_fault_alloc_and_copy(struct migrate_vma *args,
						      struct dmirror *dmirror)
{
	const unsigned long *src = args->src;
	unsigned long *dst = args->dst;
	unsigned long start = args->start;
	unsigned long end = args->end;
	unsigned long addr;

	for (addr = start; addr < end; addr += PAGE_SIZE,
				       src++, dst++) {
		struct page *dpage, *spage;

		spage = migrate_pfn_to_page(*src);
		if (!spage || !(*src & MIGRATE_PFN_MIGRATE))
			continue;

		if (WARN_ON(!is_device_private_page(spage) &&
			    !is_device_coherent_page(spage)))
			continue;
		spage = BACKING_PAGE(spage);

		/*申请cpu mem*/
		dpage = alloc_page_vma(GFP_HIGHUSER_MOVABLE, args->vma, addr);
		if (!dpage)
			continue;
		pr_debug("migrating from dev to sys pfn src: 0x%lx pfn dst: 0x%lx\n",
			 page_to_pfn(spage), page_to_pfn(dpage));

		lock_page(dpage);
		
		/*
		*清除dev的页表
		*/
		xa_erase(&dmirror->pt, addr >> PAGE_SHIFT);

		/*将dev mem的内容迁移到cpu mem*/
		copy_highpage(dpage, spage);
		*dst = migrate_pfn(page_to_pfn(dpage));
		if (*src & MIGRATE_PFN_WRITE)
			*dst |= MIGRATE_PFN_WRITE;
	}
	return 0;
}

/*计算成功迁移内存的页数*/
static unsigned long
dmirror_successful_migrated_pages(struct migrate_vma *migrate)
{
	unsigned long cpages = 0;
	unsigned long i;

	for (i = 0; i < migrate->npages; i++) {
		if (migrate->src[i] & MIGRATE_PFN_VALID &&
		    migrate->src[i] & MIGRATE_PFN_MIGRATE)
			cpages++;
	}
	return cpages;
}

/*模拟迁移dev mem到cpu mem*/
static int dmirror_migrate_to_system(struct dmirror *dmirror,
				     struct hmm_dmirror_cmd *cmd)
{
	unsigned long start, end, addr;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	struct mm_struct *mm = dmirror->notifier.mm;
	struct vm_area_struct *vma;
	unsigned long src_pfns[64] = { 0 };
	unsigned long dst_pfns[64] = { 0 };
	struct migrate_vma args = { 0 };
	unsigned long next;
	int ret;

	start = cmd->addr;
	end = start + size;
	if (end < start)
		return -EINVAL;

	/* Since the mm is for the mirrored process, get a reference first. */
	if (!mmget_not_zero(mm))
		return -EINVAL;

	cmd->cpages = 0;
	mmap_read_lock(mm);
	for (addr = start; addr < end; addr = next) {
		vma = vma_lookup(mm, addr);
		if (!vma || !(vma->vm_flags & VM_READ)) {
			ret = -EINVAL;
			goto out;
		}
		next = min(end, addr + (ARRAY_SIZE(src_pfns) << PAGE_SHIFT));
		if (next > vma->vm_end)
			next = vma->vm_end;

		args.vma = vma;
		args.src = src_pfns;
		args.dst = dst_pfns;
		args.start = addr;
		args.end = next;
		args.pgmap_owner = dmirror->mdevice;
		args.flags = dmirror_select_device(dmirror); /*该flag表明迁移的源方向为dev mem*/

		/*查找addr对应的device memory pfn*/
		ret = migrate_vma_setup(&args);
		if (ret)
			goto out;

		pr_debug("Migrating from device mem to sys mem\n");
		dmirror_devmem_fault_alloc_and_copy(&args, dmirror);

		migrate_vma_pages(&args);
		cmd->cpages += dmirror_successful_migrated_pages(&args);
		migrate_vma_finalize(&args);
	}
out:
	mmap_read_unlock(mm);
	mmput(mm);

	return ret;
}

/*迁移cpu mem到dev mem*/
static int dmirror_migrate_to_device(struct dmirror *dmirror,
				struct hmm_dmirror_cmd *cmd)
{
	unsigned long start, end, addr;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	struct mm_struct *mm = dmirror->notifier.mm;
	struct vm_area_struct *vma;
	unsigned long src_pfns[64] = { 0 };
	unsigned long dst_pfns[64] = { 0 };
	struct dmirror_bounce bounce;
	struct migrate_vma args = { 0 };
	unsigned long next;
	int ret;

	start = cmd->addr;
	end = start + size;
	if (end < start) 
		return -EINVAL;

	/* Since the mm is for the mirrored process, get a reference first. */
	if (!mmget_not_zero(mm))
		return -EINVAL;

	mmap_read_lock(mm);
	for (addr = start; addr < end; addr = next) {
		vma = vma_lookup(mm, addr);
		if (!vma || !(vma->vm_flags & VM_READ)) {
			ret = -EINVAL;
			goto out;
		}
		next = min(end, addr + (ARRAY_SIZE(src_pfns) << PAGE_SHIFT));
		if (next > vma->vm_end)
			next = vma->vm_end;

		args.vma = vma;
		args.src = src_pfns;
		args.dst = dst_pfns;
		args.start = addr;
		args.end = next;
		args.pgmap_owner = dmirror->mdevice;
		args.flags = MIGRATE_VMA_SELECT_SYSTEM;  /*表示迁移的源方向为sys*/

		/**
		* 注意该函数很重要
		* 该函数将会根据args.start查找页表，找到start对应的pfn
		* 将以下printk打印的*args.src，右移6bit，即和userspace pagemap工具读出来的pfn一致。
		* 至于为什么要由移6bit，见函数migrate_vma_collect_pmd中的代码：
		* mpfn = migrate_pfn(page_to_pfn(page))
		* 另外，如果args->src没有对应的物理页，那么并不会触发缺页中断分配物理内存。
		*/
		ret = migrate_vma_setup(&args);
		if (ret)
			goto out;

		pr_debug("Migrating from sys mem to device mem\n");
		
		/*申请dev mem, 并执行迁移内容到dev mem*/
		dmirror_migrate_alloc_and_copy(&args, dmirror);
		
		migrate_vma_pages(&args);
		/*
		* cpu mem已经迁移到dev mem，下面建立dev页表
		*/
		dmirror_migrate_finalize_and_map(&args, dmirror);
		migrate_vma_finalize(&args);
	}
	mmap_read_unlock(mm);
	mmput(mm);

	/*
	 * Return the migrated data for verification.
	 * Only for pages in device zone
	 */
	ret = dmirror_bounce_init(&bounce, start, size);
	if (ret)
		return ret;
	mutex_lock(&dmirror->mutex);
	ret = dmirror_do_read(dmirror, start, end, &bounce);
	mutex_unlock(&dmirror->mutex);
	if (ret == 0) {
		if (copy_to_user(u64_to_user_ptr(cmd->ptr), bounce.ptr,
				 bounce.size))
			ret = -EFAULT;
	}
	cmd->cpages = bounce.cpages;
	dmirror_bounce_fini(&bounce);
	return ret;

out:
	mmap_read_unlock(mm);
	mmput(mm);
	return ret;
}

/*从entry中读取页表属性，填写到perm*/
__attribute__((__noinline__)) static void
dmirror_mkentry(struct dmirror *dmirror, struct hmm_range *range,
		unsigned char *perm, unsigned long entry)
{
	struct page *page;

	if (entry & HMM_PFN_ERROR) {
		*perm = HMM_DMIRROR_PROT_ERROR;
		return;
	}
	if (!(entry & HMM_PFN_VALID)) {
		*perm = HMM_DMIRROR_PROT_NONE;
		return;
	}

	page = hmm_pfn_to_page(entry);

	/**
	 * 由于page 被迁移到device 0，因此is_zone_device_page(page)返回1
	 * 且 page->pgmap->type == MEMORY_DEVICE_PRIVATE 也是1。case中的其他
	 * 几个page, 这两个值全是0.
	*/
	if (is_device_private_page(page)) {
		/* Is the page migrated to this device or some other? */
		if (dmirror->mdevice == dmirror_page_to_device(page))
			*perm = HMM_DMIRROR_PROT_DEV_PRIVATE_LOCAL;
		else
			*perm = HMM_DMIRROR_PROT_DEV_PRIVATE_REMOTE;
	} else if (is_device_coherent_page(page)) {
		/* Is the page migrated to this device or some other? */
		if (dmirror->mdevice == dmirror_page_to_device(page))
			*perm = HMM_DMIRROR_PROT_DEV_COHERENT_LOCAL;
		else
			*perm = HMM_DMIRROR_PROT_DEV_COHERENT_REMOTE;
	} else if (is_zero_pfn(page_to_pfn(page)))
		*perm = HMM_DMIRROR_PROT_ZERO;
	else
		*perm = HMM_DMIRROR_PROT_NONE;
	if (entry & HMM_PFN_WRITE)
		*perm |= HMM_DMIRROR_PROT_WRITE;
	else
		*perm |= HMM_DMIRROR_PROT_READ;
	if (hmm_pfn_to_map_order(entry) + PAGE_SHIFT == PMD_SHIFT)
		*perm |= HMM_DMIRROR_PROT_PMD;
	else if (hmm_pfn_to_map_order(entry) + PAGE_SHIFT == PUD_SHIFT)
		*perm |= HMM_DMIRROR_PROT_PUD;
}

static bool dmirror_snapshot_invalidate(struct mmu_interval_notifier *mni,
				const struct mmu_notifier_range *range,
				unsigned long cur_seq)
{
	struct dmirror_interval *dmi =
		container_of(mni, struct dmirror_interval, notifier);
	struct dmirror *dmirror = dmi->dmirror;

	if (mmu_notifier_range_blockable(range))
		mutex_lock(&dmirror->mutex);
	else if (!mutex_trylock(&dmirror->mutex))
		return false;

	/*
	 * Snapshots only need to set the sequence number since any
	 * invalidation in the interval invalidates the whole snapshot.
	 */
	mmu_interval_set_seq(mni, cur_seq);

	mutex_unlock(&dmirror->mutex);
	return true;
}

static const struct mmu_interval_notifier_ops dmirror_mrn_ops = {
	.invalidate = dmirror_snapshot_invalidate,
};

/*读取页表属性*/
static int dmirror_range_snapshot(struct dmirror *dmirror,
				  struct hmm_range *range,
				  unsigned char *perm)
{
	struct mm_struct *mm = dmirror->notifier.mm;
	struct dmirror_interval notifier;
	unsigned long timeout =
		jiffies + msecs_to_jiffies(HMM_RANGE_DEFAULT_TIMEOUT);
	unsigned long i;
	unsigned long n;
	int ret = 0;

	notifier.dmirror = dmirror;
	range->notifier = &notifier.notifier;

	ret = mmu_interval_notifier_insert(range->notifier, mm,
			range->start, range->end - range->start,
			&dmirror_mrn_ops);
	if (ret)
		return ret;

	while (true) {
		if (time_after(jiffies, timeout)) {
			ret = -EBUSY;
			goto out;
		}

		range->notifier_seq = mmu_interval_read_begin(range->notifier);

		mmap_read_lock(mm);
		ret = hmm_range_fault(range);
		mmap_read_unlock(mm);
		if (ret) {
			if (ret == -EBUSY)
				continue;
			goto out;
		}

		mutex_lock(&dmirror->mutex);
		if (mmu_interval_read_retry(range->notifier,
					    range->notifier_seq)) {
			mutex_unlock(&dmirror->mutex);
			continue;
		}
		break;
	}

	n = (range->end - range->start) >> PAGE_SHIFT;
	for (i = 0; i < n; i++)
		dmirror_mkentry(dmirror, range, perm + i, range->hmm_pfns[i]);

	mutex_unlock(&dmirror->mutex);
out:
	mmu_interval_notifier_remove(range->notifier);
	return ret;
}

static int dmirror_snapshot(struct dmirror *dmirror,
			    struct hmm_dmirror_cmd *cmd)
{
	struct mm_struct *mm = dmirror->notifier.mm;
	unsigned long start, end;
	unsigned long size = cmd->npages << PAGE_SHIFT;
	unsigned long addr;
	unsigned long next;
	unsigned long pfns[64];
	unsigned char perm[64];
	char __user *uptr;
	struct hmm_range range = {
		.hmm_pfns = pfns,
		.dev_private_owner = dmirror->mdevice,
	};
	int ret = 0;

	start = cmd->addr;
	end = start + size;
	if (end < start)
		return -EINVAL;

	/* Since the mm is for the mirrored process, get a reference first. */
	if (!mmget_not_zero(mm))
		return -EINVAL;

	/*
	 * Register a temporary notifier to detect invalidations even if it
	 * overlaps with other mmu_interval_notifiers.
	 */
	uptr = u64_to_user_ptr(cmd->ptr);
	for (addr = start; addr < end; addr = next) {
		unsigned long n;

		next = min(addr + (ARRAY_SIZE(pfns) << PAGE_SHIFT), end);
		range.start = addr;
		range.end = next;

		ret = dmirror_range_snapshot(dmirror, &range, perm);
		if (ret)
			break;

		n = (range.end - range.start) >> PAGE_SHIFT;
		if (copy_to_user(uptr, perm, n)) {
			ret = -EFAULT;
			break;
		}

		cmd->cpages += n;
		uptr += n;
	}
	mmput(mm);

	return ret;
}

/*
* 拷贝所有的dev mem到cpu mem
* 释放dev mem
*/
static void dmirror_device_evict_chunk(struct dmirror_chunk *chunk)
{
	unsigned long start_pfn = chunk->pagemap.range.start >> PAGE_SHIFT;
	unsigned long end_pfn = chunk->pagemap.range.end >> PAGE_SHIFT;
	unsigned long npages = end_pfn - start_pfn + 1;
	unsigned long i;
	unsigned long *src_pfns;
	unsigned long *dst_pfns;

	src_pfns = kcalloc(npages, sizeof(*src_pfns), GFP_KERNEL);
	dst_pfns = kcalloc(npages, sizeof(*dst_pfns), GFP_KERNEL);

	/**
	 * 根据start_pfn查找src_pfns
	*/
	migrate_device_range(src_pfns, start_pfn, npages);
	for (i = 0; i < npages; i++) {
		struct page *dpage, *spage;

		spage = migrate_pfn_to_page(src_pfns[i]);
		if (!spage || !(src_pfns[i] & MIGRATE_PFN_MIGRATE))
			continue;

		if (WARN_ON(!is_device_private_page(spage) &&
			    !is_device_coherent_page(spage)))
			continue;
		spage = BACKING_PAGE(spage);

		/**
		 * 申请cpu mem，用于将dev mem迁移到cpu mem
		 * 注意，这个dpage, 最终映射到user space的buffer->ptr
		 * 可见hmm.migrate_release 测试case, 在HMM_DMIRROR_RELEASE之后
		 * buffer->ptr对应的pfn 就是dpage.
		*/
		dpage = alloc_page(GFP_HIGHUSER_MOVABLE | __GFP_NOFAIL);
		lock_page(dpage);

		/*将内存从dev mem拷贝会cpu mem*/
		copy_highpage(dpage, spage);
		printk("dmirror_device_evict_chunk pfn %#lx\n",
		       page_to_pfn(dpage));
		dst_pfns[i] = migrate_pfn(page_to_pfn(dpage));
		if (src_pfns[i] & MIGRATE_PFN_WRITE)
			dst_pfns[i] |= MIGRATE_PFN_WRITE;
	}

	migrate_device_pages(src_pfns, dst_pfns, npages);

	/**
	 * 完成页迁移
	 *  将会触发 dmirror_devmem_free, 释放dev memory.
	 */
	migrate_device_finalize(src_pfns, dst_pfns, npages);
	kfree(src_pfns);
	kfree(dst_pfns); 
}

/* Removes free pages from the free list so they can't be re-allocated */
static void dmirror_remove_free_pages(struct dmirror_chunk *devmem)
{
	struct dmirror_device *mdevice = devmem->mdevice;
	struct page *page;

	/*将mdevice->free_pages指向了list的末尾，使得无法申请内存*/
	for (page = mdevice->free_pages; page; page = page->zone_device_data)
		if (dmirror_page_to_chunk(page) == devmem)
			mdevice->free_pages = page->zone_device_data;
}

static void dmirror_device_remove_chunks(struct dmirror_device *mdevice)
{
	unsigned int i;

	mutex_lock(&mdevice->devmem_lock);
	if (mdevice->devmem_chunks) {
		for (i = 0; i < mdevice->devmem_count; i++) {
			struct dmirror_chunk *devmem =
				mdevice->devmem_chunks[i];

			spin_lock(&mdevice->lock);
			devmem->remove = true;
			/*清空free page list*/
			dmirror_remove_free_pages(devmem);
			spin_unlock(&mdevice->lock);

			dmirror_device_evict_chunk(devmem);
			memunmap_pages(&devmem->pagemap);
			if (devmem->pagemap.type == MEMORY_DEVICE_PRIVATE)
				release_mem_region(devmem->pagemap.range.start,
						   range_len(&devmem->pagemap.range));
			kfree(devmem);
		}
		mdevice->devmem_count = 0;
		mdevice->devmem_capacity = 0;
		mdevice->free_pages = NULL;
		kfree(mdevice->devmem_chunks);
		mdevice->devmem_chunks = NULL;
	}
	mutex_unlock(&mdevice->devmem_lock);
}

static long dmirror_fops_unlocked_ioctl(struct file *filp,
					unsigned int command,
					unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct hmm_dmirror_cmd cmd;
	struct dmirror *dmirror;
	int ret;

	dmirror = filp->private_data;
	if (!dmirror)
		return -EINVAL;

	if (copy_from_user(&cmd, uarg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.addr & ~PAGE_MASK)
		return -EINVAL;
	if (cmd.addr >= (cmd.addr + (cmd.npages << PAGE_SHIFT)))
		return -EINVAL;

	cmd.cpages = 0;
	cmd.faults = 0;

	switch (command) {
	case HMM_DMIRROR_READ:
		ret = dmirror_read(dmirror, &cmd);
		break;

	case HMM_DMIRROR_WRITE:
		ret = dmirror_write(dmirror, &cmd);
		break;

	case HMM_DMIRROR_MIGRATE_TO_DEV:
		ret = dmirror_migrate_to_device(dmirror, &cmd);
		break;

	case HMM_DMIRROR_MIGRATE_TO_SYS:
		ret = dmirror_migrate_to_system(dmirror, &cmd);
		break;

	case HMM_DMIRROR_EXCLUSIVE:
		ret = dmirror_exclusive(dmirror, &cmd);
		break;

	case HMM_DMIRROR_CHECK_EXCLUSIVE:
		ret = dmirror_check_atomic(dmirror, cmd.addr,
					cmd.addr + (cmd.npages << PAGE_SHIFT));
		break;

	case HMM_DMIRROR_SNAPSHOT:
		ret = dmirror_snapshot(dmirror, &cmd);
		break;

	case HMM_DMIRROR_RELEASE:
		dmirror_device_remove_chunks(dmirror->mdevice);
		ret = 0;
		break;

	default:
		return -EINVAL;
	}
	if (ret)
		return ret;

	if (copy_to_user(uarg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}

/*
* PID     TID     COMM            FUNC             -
12908   12908   hmm-tests       dmirror_fops_mmap ret 0
        b'mmap_region+0x26d [kernel]'
        b'do_mmap+0x3d4 [kernel]'
        b'vm_mmap_pgoff+0xe3 [kernel]'
        b'ksys_mmap_pgoff+0x1cc [kernel]'
        b'__x64_sys_mmap+0x33 [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'
*/
static int dmirror_fops_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long addr;

	for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
		struct page *page;
		int ret;

		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return -ENOMEM;

		/*插入page，即建立页表*/
		ret = vm_insert_page(vma, addr, page);
		if (ret) {
			__free_page(page);
			return ret;
		}
		put_page(page);
	}

	return 0;
}

static const struct file_operations dmirror_fops = {
	.open		= dmirror_fops_open,
	.release	= dmirror_fops_release,
	.mmap		= dmirror_fops_mmap,
	.unlocked_ioctl = dmirror_fops_unlocked_ioctl,
	.llseek		= default_llseek,
	.owner		= THIS_MODULE,
};

/*
* 释放内存
* hmm-tests中常见的几种call stack如下：
69340   69340   hmm-tests       dmirror_devmem_free
        b'dmirror_devmem_free+0x1 [test_hmm]'
        b'__folio_put+0x55 [kernel]'
        b'migrate_device_finalize+0x273 [kernel]'
        b'dmirror_device_remove_chunks+0x24d [test_hmm]'
        b'dmirror_fops_unlocked_ioctl+0x2b3 [test_hmm]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'


* hmm-tests，访问已经迁移到dev mem的cpu mem时
69970   69970   hmm-tests       dmirror_devmem_free
        b'dmirror_devmem_free+0x1 [test_hmm]'
        b'__folio_put+0x55 [kernel]'
        b'put_page+0x60 [kernel]'
        b'do_swap_page+0x7c3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'

* hmm-tests, buffer->ptr unmap时
69970   69970   hmm-tests       dmirror_devmem_free
        b'dmirror_devmem_free+0x1 [test_hmm]'
        b'__folio_put+0x55 [kernel]'
        b'put_page+0x60 [kernel]'
        b'zap_pte_range+0x4a7 [kernel]'
        b'zap_pmd_range.isra.0+0x1b6 [kernel]'
        b'unmap_page_range+0x2ae [kernel]'
        b'unmap_single_vma+0x7e [kernel]'
        b'unmap_vmas+0xe5 [kernel]'
        b'unmap_region+0xb3 [kernel]'
        b'do_mas_align_munmap+0x2d6 [kernel]'
        b'do_mas_munmap+0xe9 [kernel]'
        b'__vm_munmap+0xbd [kernel]'
        b'__x64_sys_munmap+0x1b [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'
*/
static void dmirror_devmem_free(struct page *page)
{
	struct page *rpage = BACKING_PAGE(page);
	struct dmirror_device *mdevice;

	if (rpage != page)
		__free_page(rpage);

	mdevice = dmirror_page_to_device(page);
	spin_lock(&mdevice->lock);

	/* Return page to our allocator if not freeing the chunk */
	/*
	* 释放已经申请的dev page
	*/
	if (!dmirror_page_to_chunk(page)->remove) {
		mdevice->cfree++;
		/*
		* 更新mdevice->free_pages的头，指向新释放的page
		*/
		page->zone_device_data = mdevice->free_pages;
		mdevice->free_pages = page;
	}
	spin_unlock(&mdevice->lock);
}

/*
*  cpu缺页中断，当cpu访问被迁移到dev的mem时，将mem从dev迁移回cpu,
常见的callback如下

105506  105506  hmm-tests       dmirror_devmem_fault
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'

105514  105514  hmm-tests       dmirror_devmem_fault
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'hmm_vma_fault+0x64 [kernel]'
        b'hmm_vma_handle_pte.isra.0+0x6d [kernel]'
        b'hmm_vma_walk_pmd+0x4f6 [kernel]'
        b'walk_pmd_range.isra.0+0x113 [kernel]'
        b'walk_pud_range.isra.0+0x1c6 [kernel]'
        b'walk_p4d_range+0xe1 [kernel]'
        b'walk_pgd_range+0x157 [kernel]'
        b'__walk_page_range+0x17a [kernel]'
        b'walk_page_range+0x16a [kernel]'
        b'hmm_range_fault+0x52 [kernel]'
        b'dmirror_fault+0x154 [test_hmm]'
        b'dmirror_fops_unlocked_ioctl+0x40b [test_hmm]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'		

PID     TID     COMM            FUNC             -
5747    5747    hmm-tests       dmirror_devmem_fault ret 0
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'__get_user_pages+0x247 [kernel]'
        b'__gup_longterm_locked+0x218 [kernel]'
        b'get_user_pages_unlocked+0x78 [kernel]'
        b'internal_get_user_pages_fast+0xba [kernel]'
        b'pin_user_pages_fast+0x21 [kernel]'
        b'gup_test_ioctl+0x50a [gup_test]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'

5747    5747    hmm-tests       dmirror_devmem_fault ret 0
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'__get_user_pages+0x247 [kernel]'
        b'__gup_longterm_locked+0x218 [kernel]'
        b'pin_user_pages+0x3b [kernel]'
        b'gup_test_ioctl+0x1e9 [gup_test]'
        b'__x64_sys_ioctl+0x9a [kernel]'
        b'do_syscall_64+0x59 [kernel]'
        b'entry_SYSCALL_64_after_hwframe+0x72 [kernel]'
*/

static vm_fault_t dmirror_devmem_fault(struct vm_fault *vmf)
{
	struct migrate_vma args = { 0 };
	unsigned long src_pfns = 0;
	unsigned long dst_pfns = 0;
	struct page *rpage;
	struct dmirror *dmirror;
	vm_fault_t ret;

	/*
	 * Normally, a device would use the page->zone_device_data to point to
	 * the mirror but here we use it to hold the page for the simulated
	 * device memory and that page holds the pointer to the mirror.
	 */
	rpage = vmf->page->zone_device_data;
	dmirror = rpage->zone_device_data;

	/* FIXME demonstrate how we can adjust migrate range */
	args.vma = vmf->vma;
	args.start = vmf->address;
	args.end = args.start + PAGE_SIZE;
	args.src = &src_pfns;
	args.dst = &dst_pfns;
	args.pgmap_owner = dmirror->mdevice;
	args.flags = dmirror_select_device(dmirror);
	args.fault_page = vmf->page;

	/*
	 * 根据args.start查找cpu的页表，找到对应的page，填充到args.src
	*/
	if (migrate_vma_setup(&args))
		return VM_FAULT_SIGBUS;

	/*填充dst_pfns*/
	ret = dmirror_devmem_fault_alloc_and_copy(&args, dmirror);
	if (ret)
		return ret;
	migrate_vma_pages(&args);
	/*
	 * No device finalize step is needed since
	 * dmirror_devmem_fault_alloc_and_copy() will have already
	 * invalidated the device page table.
	 */
	migrate_vma_finalize(&args);
	return 0;
}

static const struct dev_pagemap_ops dmirror_devmem_ops = {
	.page_free	= dmirror_devmem_free,
	.migrate_to_ram	= dmirror_devmem_fault,
};

static int dmirror_device_init(struct dmirror_device *mdevice, int id)
{
	dev_t dev;
	int ret;

	dev = MKDEV(MAJOR(dmirror_dev), id);
	mutex_init(&mdevice->devmem_lock);
	spin_lock_init(&mdevice->lock);

	/**
	 * 初始化、创建字符设备
	*/
	cdev_init(&mdevice->cdevice, &dmirror_fops);
	mdevice->cdevice.owner = THIS_MODULE;
	device_initialize(&mdevice->device);
	mdevice->device.devt = dev;

	ret = dev_set_name(&mdevice->device, "hmm_dmirror%u", id);
	if (ret)
		return ret;

	ret = cdev_device_add(&mdevice->cdevice, &mdevice->device);
	if (ret)
		return ret;

	/* Build a list of free ZONE_DEVICE struct pages */
	return dmirror_allocate_chunk(mdevice, NULL);
}

static void dmirror_device_remove(struct dmirror_device *mdevice)
{
	dmirror_device_remove_chunks(mdevice);
	cdev_device_del(&mdevice->cdevice, &mdevice->device);
}

static int __init hmm_dmirror_init(void)
{
	int ret;
	int id = 0;
	int ndevices = 0;

	ret = alloc_chrdev_region(&dmirror_dev, 0, DMIRROR_NDEVICES,
				  "HMM_DMIRROR");
	if (ret)
		goto err_unreg;

	memset(dmirror_devices, 0, DMIRROR_NDEVICES * sizeof(dmirror_devices[0]));
	dmirror_devices[ndevices++].zone_device_type =
				HMM_DMIRROR_MEMORY_DEVICE_PRIVATE;
	dmirror_devices[ndevices++].zone_device_type =
				HMM_DMIRROR_MEMORY_DEVICE_PRIVATE;
	if (spm_addr_dev0 && spm_addr_dev1) {
		dmirror_devices[ndevices++].zone_device_type =
					HMM_DMIRROR_MEMORY_DEVICE_COHERENT;
		dmirror_devices[ndevices++].zone_device_type =
					HMM_DMIRROR_MEMORY_DEVICE_COHERENT;
	}
	for (id = 0; id < ndevices; id++) {
		ret = dmirror_device_init(dmirror_devices + id, id);
		if (ret)
			goto err_chrdev;
	}

	pr_info("HMM test module loaded. This is only for testing HMM.\n");
	return 0;

err_chrdev:
	while (--id >= 0)
		dmirror_device_remove(dmirror_devices + id);
	unregister_chrdev_region(dmirror_dev, DMIRROR_NDEVICES);
err_unreg:
	return ret;
}

static void __exit hmm_dmirror_exit(void)
{
	int id;

	for (id = 0; id < DMIRROR_NDEVICES; id++)
		if (dmirror_devices[id].zone_device_type)
			dmirror_device_remove(dmirror_devices + id);
	unregister_chrdev_region(dmirror_dev, DMIRROR_NDEVICES);
}

module_init(hmm_dmirror_init);
module_exit(hmm_dmirror_exit);
MODULE_LICENSE("GPL");
