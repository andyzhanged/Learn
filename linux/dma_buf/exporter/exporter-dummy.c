#include <linux/dma-buf.h>
#include <linux/module.h>
#include <linux/slab.h>

struct dma_buf *dmabuf_exported;
EXPORT_SYMBOL(dmabuf_exported);

static struct sg_table *exporter_map_dma_buf(struct dma_buf_attachment *attach,
											 enum dma_data_direction dir)
{
	return NULL;
}

static void exporter_unmap_dma_buf(struct dma_buf_attachment *attach,
        struct sg_table *table, enum dma_data_direction dir)
{

}

static void exporter_release(struct dma_buf *dmabuf)
{
	kfree(dmabuf->priv);
}

static void *exporter_kmap(struct dma_buf *dmabuf, unsigned long page_num)
{
	return dmabuf->priv;
}

static const struct dma_buf_ops exp_dmabuf_ops = {
	.map_dma_buf = exporter_map_dma_buf,
	.unmap_dma_buf = exporter_unmap_dma_buf,
	.release = exporter_release,
	.map = exporter_kmap,
};

struct dma_buf *exporter_alloc_page(void)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	
	void *vaddr;
	vaddr = kzalloc(PAGE_SIZE, GFP_KERNEL);

	exp_info.ops = &exp_dmabuf_ops;
	exp_info.size = PAGE_SIZE;
	exp_info.flags = O_CLOEXEC;
	exp_info.priv = vaddr;
	
	sprintf(vaddr, "Hello world\n");
	
	return dma_buf_export(&exp_info);
}

static int __init exporter_init(void)
{
	dmabuf_exported = exporter_alloc_page();
	return 0;
}

module_init(exporter_init)

MODULE_AUTHOR("zhanged");
MODULE_DESCRIPTION("Dma Buf Learn");
MODULE_LICENSE("GPL v2");