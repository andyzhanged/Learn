#include <linux/module.h>
#include <linux/pci.h>
#include <linux/mman.h>
#include <linux/dma-mapping.h>

#define __SIZE_TO_PAGE_NUM(a)   ((a) >> PAGE_SHIFT)
#define XFER_PAGE_NUM __SIZE_TO_PAGE_NUM(xfer->size)
#define MAX_PIN_SIZE SZ_1G
#define MAX_PIN_PAGE_NUM	__SIZE_TO_PAGE_NUM(MAX_PIN_SIZE)

static struct sg_table sgt;
static struct page** pages = NULL;
static int probe_status = 0;
static u64 addr = 0;
static u64 size = SZ_16G;

static struct pci_device_id dma_test_dev_id[] = {
	{
		PCI_DEVICE(0x1e3e, 0x2),
	},
	{}
};

static int dma_test_probe(struct pci_dev *pdev,
			     const struct pci_device_id *pent)
{
	u64 buf;
	u32 page_num;
	u32 index;
	int n;
	int ret;
	u32 page_num_pinned = 0;

	/* init dma*/
	ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(48));
	if (ret) {
		printk("dma_set_mask failed\n");
		return ret;
	}
	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(48));
	if (ret) {
		printk("dma_set_coherent_mask failed\n");
		return ret;
	}

	// alloc va
	addr = vm_mmap(NULL, 0, size,
				PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, 0);
	if (IS_ERR(ERR_PTR(addr))) {
		printk("vm_mmap alloc va failed\n");
		return -EFAULT;
	}
	printk("alloc va success\n");

	page_num = size >> PAGE_SHIFT;
	pages = vmalloc(page_num * sizeof(struct pages *));
	if (!pages) {
		vm_munmap(addr, size);
		printk("vmalloc alloc memory failed\n");
		return -ENOMEM;
	}

	// pin memory
	buf = addr;
	while (page_num) {
		// n = min_t(typeof(n), page_num, MAX_PIN_PAGE_NUM);
		n = get_user_pages_fast(buf, page_num, FOLL_WRITE, (pages + page_num_pinned));
		if (n < 0) {
			printk("pin pages failed %d\n", n);
			goto unpin_dma_pages;
		}
		page_num_pinned += n;
		page_num  -= n;
		buf += (unsigned long)n << PAGE_SHIFT;
	}
	printk("pin pages success\n");

	/*create sg table*/
	ret = sg_alloc_table_from_pages(&sgt, pages, size >> PAGE_SHIFT,
					0, size, GFP_KERNEL);
	if(ret) {
		printk("alloc sg_table failed %d\n", ret);
		goto unpin_dma_pages;
	}
	printk("alloc sg table success\n");

	// dma map
	ret = dma_map_sg(&pdev->dev, sgt.sgl, sg_nents(sgt.sgl), DMA_BIDIRECTIONAL);
    if (unlikely(!ret)) {
		printk("dma map sg failed %d\n", ret);
        ret = -ENOMEM;
		goto free_sg;
    }
	probe_status = 1;

	printk("dma map success\n");
	return 0;

free_sg:
	sg_free_table(&sgt);

unpin_dma_pages:
	for (index = 0; index < page_num_pinned; index++) {
		put_page(pages[index]);
	}

	vfree(pages);
	vm_munmap(addr, size);

	return ret;
}

void dma_test_remove(struct pci_dev *pdev)
{
	int index;
	if (probe_status)
		dma_unmap_sg(&pdev->dev, sgt.sgl, sg_nents(sgt.sgl), DMA_BIDIRECTIONAL);

	sg_free_table(&sgt);



	for (index = 0; index < (size >> PAGE_SHIFT); index++) {
		put_page(pages[index]);
	}

	if (addr)
		vm_munmap(addr, size);

	if (pages)
		vfree(pages);

	printk("remove dma-test module\n");
}
static struct pci_driver dma_test_pci_driver = {
	.name = "dma-test",
	.id_table = dma_test_dev_id,
	.probe = dma_test_probe,
	.remove = dma_test_remove,
};


static int __init dma_map_test_init(void)
{
	return pci_register_driver(&dma_test_pci_driver);
}

static void __exit dma_map_test_exit(void)
{
    pci_unregister_driver(&dma_test_pci_driver);
}

module_init(dma_map_test_init);
module_exit(dma_map_test_exit);

MODULE_DEVICE_TABLE(pci, dma_test_dev_id);
MODULE_AUTHOR("zhanged");
MODULE_DESCRIPTION("zhanged Test dma_map_sg for large size");
MODULE_LICENSE("GPL and additional rights");