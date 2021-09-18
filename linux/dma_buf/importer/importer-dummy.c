#include <linux/dma-buf.h>
#include <linux/module.h>
#include <linux/slab.h>

extern struct dma_buf *dmabuf_exported;
static int importer_test(struct dma_buf *dmabuf)
{
    void *vaddr;
    vaddr = dma_buf_kmap(dmabuf, 0);
    pr_info("read form dmabuf kmap: %s\n", (char *)vaddr);
    dma_buf_kunmap(dmabuf, 0, vaddr);

    vaddr = dma_buf_vmap(dmabuf);
    pr_info("read form dmabuf vmap: %s\n", (char *)vaddr);
    dma_buf_vunmap(dmabuf, vaddr);

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