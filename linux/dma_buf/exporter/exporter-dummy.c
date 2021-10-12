#include <linux/dma-buf.h>
#include <linux/module.h>
#include <linux/slab.h>

struct dma_buf *dmabuf_exported;
EXPORT_SYMBOL(dmabuf_exported);

static int exporter_attach(struct dma_buf *dmabuf, struct device *dev,
		struct dma_buf_attachment *attachment)
{
	pr_info("dmabuf attach device: %s\n", dev_name(dev));
	return 0;
}

static void exporter_detach(struct dma_buf *dmabuf, struct dma_buf_attachment *attachment)
{
	pr_info("dmabuf attach device: %s\n", dev_name(attachment->dev));
}

static struct sg_table *exporter_map_dma_buf(struct dma_buf_attachment *attach,
											 enum dma_data_direction dir)
{
	void *vaddr = attach->dmabuf->priv;
	struct sg_table *table;
	table = kmalloc(sizeof(*table), GFP_KERNEL);

	sg_alloc_table(table, 1, GFP_KERNEL);
	sg_dma_len(table->sgl) = PAGE_SIZE;
	sg_dma_address(table->sgl) = dma_map_single(attach->dev, vaddr, PAGE_SIZE, dir);
	return table;
}

static void exporter_unmap_dma_buf(struct dma_buf_attachment *attach,
        struct sg_table *table, enum dma_data_direction dir)
{
	dma_unmap_single(NULL, sg_dma_address(table->sgl), PAGE_SIZE, dir);
	sg_free_table(table);
	kfree(table);
}

static void exporter_release(struct dma_buf *dmabuf)
{
	kfree(dmabuf->priv);
}

static void *exporter_kmap(struct dma_buf *dmabuf, unsigned long page_num)
{
	return dmabuf->priv;
}

static void *exporter_vmap(struct dma_buf *dmabuf)
{
	return dmabuf->priv;
}

static int exporter_mmap(struct dma_buf *dmabuf,  struct vm_area_struct *vma)
{
	return 0;
}



static const struct dma_buf_ops exp_dmabuf_ops = {
	.attach = exporter_attach,
	.detach = exporter_detach,
	.map_dma_buf = exporter_map_dma_buf,
	.unmap_dma_buf = exporter_unmap_dma_buf,
	.release = exporter_release,
	.map = exporter_kmap,
	.map_atomic = exporter_kmap,
	.mmap = exporter_mmap,
	.vmap = exporter_vmap,
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
	pr_info("vaddr is %p\n", vaddr);	
	sprintf(vaddr, "Hello world\n");
	
	pr_info("11111111111111");	
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
