#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("Red-Black Tree Range Management");
MODULE_VERSION("0.1");

// 定义结构体表示一个range
struct vma_range {
    unsigned long start;
    unsigned long end;
    struct rb_node rb_node;
    struct list_head list_node;
};

// 红黑树根节点
static struct rb_root range_tree = RB_ROOT;

// 插入 range 到红黑树
static void insert_range(struct vma_range *new_range)
{
    struct rb_node **node = &range_tree.rb_node;
    struct rb_node *parent = NULL;
    struct vma_range *this_range;

    // 查找插入位置
    while (*node) {
        parent = *node;
        this_range = rb_entry(parent, struct vma_range, rb_node);

        if (new_range->start < this_range->start)
            node = &(*node)->rb_left;
        else if (new_range->start > this_range->start)
            node = &(*node)->rb_right;
        else {
            // 如果start相等，则插入到右子树
            node = &(*node)->rb_right;
        }
    }

    // 插入新的节点
    rb_link_node(&new_range->rb_node, parent, node);
    rb_insert_color(&new_range->rb_node, &range_tree);
}

// 遍历红黑树并打印所有range
static void dump_range_tree(void)
{
    struct rb_node *node;
    struct vma_range *range;

    for (node = rb_first(&range_tree); node; node = rb_next(node)) {
        range = rb_entry(node, struct vma_range, rb_node);
        pr_info("Range: [0x%lx, 0x%lx]\n", range->start, range->end);
    }
}

// 查找与给定范围相交的所有range
static void find_overlapping_ranges(unsigned long start, unsigned long end, struct list_head *list_head)
{
    struct rb_node *node = range_tree.rb_node;
    struct vma_range *range;

    INIT_LIST_HEAD(list_head);

    // 遍历树进行范围查找
    while (node) {
        range = rb_entry(node, struct vma_range, rb_node);

        // 如果当前节点的结束地址在查询范围之前，跳过
        if (range->end < start) {
            node = node->rb_right;
        }
        // 如果当前节点的起始地址在查询范围之后，跳过
        else if (range->start > end) {
            node = node->rb_left;
        }
        // 如果当前节点与查询范围有重叠
        else {
            list_add_tail(&range->list_node, list_head);
            // 继续查找左右子树中的重叠
            if (node->rb_left)
                node = node->rb_left;
            else
                node = node->rb_right;
        }
    }
}

// 测试函数，初始化并插入数据
static int __init range_test_init(void)
{
    struct vma_range *range1, *range2, *range3, *range4, *range5;
    LIST_HEAD(overlap_list);

    // 插入 range1
    range1 = kmalloc(sizeof(*range1), GFP_KERNEL);
    range1->start = 0x1000;
    range1->end = 0x2000;
    INIT_LIST_HEAD(&range1->list_node);
    insert_range(range1);

    // 插入 range2
    range2 = kmalloc(sizeof(*range2), GFP_KERNEL);
    range2->start = 0x2000;
    range2->end = 0x3000;
    INIT_LIST_HEAD(&range2->list_node);
    insert_range(range2);

    // 插入 range3
    range3 = kmalloc(sizeof(*range3), GFP_KERNEL);
    range3->start = 0x3000;
    range3->end = 0x4000;
    INIT_LIST_HEAD(&range3->list_node);
    insert_range(range3);

    // 插入 range4
    range4 = kmalloc(sizeof(*range4), GFP_KERNEL);
    range4->start = 0x5000;
    range4->end = 0x6000;
    INIT_LIST_HEAD(&range4->list_node);
    insert_range(range4);

    // 插入 range5 (新的重合范围)
    range5 = kmalloc(sizeof(*range5), GFP_KERNEL);
    range5->start = 0x2500;  // 新范围开始位置
    range5->end = 0x3500;    // 新范围结束位置
    INIT_LIST_HEAD(&range5->list_node);
    insert_range(range5);

    // 查找与范围 [0x2000, 0x3500] 重叠的节点
    find_overlapping_ranges(0x2000, 0x3500, &overlap_list);

    // 打印重叠的范围
    pr_info("Overlapping ranges with [0x2000, 0x3500]:\n");
    struct vma_range *range;
    list_for_each_entry(range, &overlap_list, list_node) {
        pr_info("Range: [0x%lx, 0x%lx]\n", range->start, range->end);
    }

    // 打印所有的范围
    dump_range_tree();

    return 0;
}

// 清理函数
static void __exit range_test_exit(void)
{
    pr_info("Exiting module\n");
}

module_init(range_test_init);
module_exit(range_test_exit);
