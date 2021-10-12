#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/page.h>
#include <linux/mm.h>

static int misc_mmap(struct file *file, struct vm_area_struct *vma)
{
    void *k_buffer;
    void *v_buffer;
    
    k_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    v_buffer  = vmalloc(PAGE_SIZE);
  
    pr_info("k_buffer %px\n", k_buffer);
    pr_info("v_buffer %px\n", v_buffer);
    pr_info("is vmalloc addr %d\n", is_vmalloc_addr(v_buffer));
    pr_info("k_page is %px\n", virt_to_page(k_buffer));
    pr_info("v_page is %px\n", virt_to_page(v_buffer));

    pr_info("vmalloc start: %lx --> %lx\n", VMALLOC_START, VMALLOC_END);
    return 0;
}


static const struct file_operations mmap_fops = {
    .mmap = misc_mmap
};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "mmap_test",
    .fops = &mmap_fops,
};

static int __init zhanged_init(void)
{
    return misc_register(&misc_dev);
}

static void __exit zhanged_exit(void)
{
    misc_deregister(&misc_dev);
}

module_init(zhanged_init);
module_exit(zhanged_exit);
MODULE_AUTHOR("zhanged");
MODULE_DESCRIPTION("Dma Buf Learn");
MODULE_LICENSE("GPL v2");
