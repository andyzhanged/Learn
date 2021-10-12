#include <linux/dma-buf.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sizes.h>

extern struct dma_buf *dmabuf_exported;
static int importer_test(struct dma_buf *dmabuf)
{
    struct dma_buf_attachment *attachment;
    struct sg_table *table;
    struct device *dev;
    unsigned int reg_addr, reg_size;
    dma_addr_t dma_addr;
    void * cpu_addr;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    dev_set_name(dev, "importer");
    dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
    cpu_addr = dma_alloc_coherent(dev, SZ_4K, &dma_addr, GFP_KERNEL);
    if(!cpu_addr)
        pr_err("dma_alloc_coherent failed\n");

#if 0
    attachment = dma_buf_attach(dmabuf, dev);
    table = dma_buf_map_attachment(attachment, DMA_BIDIRECTIONAL);

    reg_addr = sg_dma_address(table->sgl);
    reg_size = sg_dma_len(table->sgl);

    pr_info("reg_addr = 0x%08x, reg_size = 0x%08x\n", reg_addr, reg_size);

    dma_buf_unmap_attachment(attachment, table, DMA_BIDIRECTIONAL);
    dma_buf_detach(dmabuf, attachment);
#endif

    return 0;
}

static int __init importer_init(void)
{
    return importer_test(dmabuf_exported);
}

module_init(importer_init);
MODULE_AUTHOR("zhanged");
MODULE_DESCRIPTION("Dma Buf Learn");
MODULE_LICENSE("GPL v2");
