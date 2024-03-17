#include <linux/module.h>

static int __init mod_init(void) {
  pr_info("First kernel module: Hello World!\n");
  return 0;
}

static void __exit mod_exit(void) {
  pr_info("First kernel module has been removed\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
