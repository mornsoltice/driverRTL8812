#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/ioctl.h>
#include <linux/workqueue.h>
#include <linux/kfifo.h>

#define DRIVER_NAME "ambarusdi"

#define REG_CONTROL     0x00
#define REG_STATUS      0x04
#define REG_DATA_IN     0x08
#define REG_DATA_OUT    0x0C
#define REG_IRQ_ENABLE  0x10
#define REG_IRQ_STATUS  0x14
#define REG_DMA_CONTROL 0x18
#define REG_DMA_ADDR    0x1C

#define DMA_BUFFER_SIZE 8192

#define IRQ_NUM         42

struct ambarusdi_driver_data {
    void __iomem* regs_base;
    struct mutex lock;
    struct cdev cdev;
    struct class* class;
    struct device* device;
    struct workqueue_struct* workqueue;
    struct kfifo dma_buffer;
    dma_addr_t dma_phys_addr;
};

static struct ambarusdi_driver_data* dev_data;

static irqreturn_t ambarusdi_driver_irq_handler(int irq, void* dev_id) {
    unsigned long flags;
    int status;

    spin_lock_irqsave(&dev_data->lock, flags);
    status = readl(dev_data->regs_base + REG_IRQ_STATUS);
    if (status & IRQ_ERROR_BIT) {
        dev_err(dev_data->device, "Error interrupt occurred\n");
        return IRQ_HANDLED;
    }

    writel(status, dev_data->regs_base + REG_IRQ_STATUS);
    spin_unlock_irqrestore(&dev_data->lock, flags);
    return IRQ_HANDLED;
}

static void ambarusdi_driver_dma_complete(struct dma_chan* chan, void* completion_cookie, dma_cookie_t cookie, dma_async_tx_callback callback) {
    unsigned long flags;
    struct dma_tx_state state;

    dmaengine_tx_status(chan, cookie, &state);
    if (state.status != DMA_COMPLETE) {
        dev_err(dev_data->device, "DMA transfer error\n");
        return;
    }
   
}

static void ambarusdi_driver_work(struct work_struct* work) {
    int ret;

    mutex_lock(&dev_data->lock);
    ret = kfifo_out_locked(&dev_data->dma_buffer, NULL, 0, &dev_data->lock);
    if (ret < 0) {
        dev_err(dev_data->device, "Failed to read from DMA buffer\n");
        mutex_unlock(&dev_data->lock);
        return;
    }

    mutex_unlock(&dev_data->lock);
}

static int ambarusdi_driver_open(struct inode* inode, struct file* file) {
    if (!mutex_trylock(&dev_data->lock)) {
        dev_err(dev_data->device, "Device is busy\n");
        return -EBUSY;
    }

    return 0;
}

static int ambarusdi_driver_release(struct inode* inode, struct file* file) {
    
    mutex_unlock(&dev_data->lock);  
    return 0;
}

static ssize_t ambarusdi_driver_read(struct file* file, char __user* user_buf, size_t count, loff_t* ppos) {
    int ret;

    mutex_lock(&dev_data->lock);
    ret = kfifo_to_user(&dev_data->dma_buffer, user_buf, count, &count);
    if (ret < 0) {
        dev_err(dev_data->device, "Failed to read data from DMA buffer\n");
        mutex_unlock(&dev_data->lock);
        return ret;
    }

    mutex_unlock(&dev_data->lock);
    return count;
}

static ssize_t ambarusdi_driver_write(struct file* file, const char __user* user_buf, size_t count, loff_t* ppos) {
    int ret;

    mutex_lock(&dev_data->lock);
    ret = kfifo_from_user(&dev_data->dma_buffer, user_buf, count, &count);
    if (ret < 0) {
        dev_err(dev_data->device, "Failed to write data to DMA buffer\n");
        mutex_unlock(&dev_data->lock);
        return ret;
    }

    mutex_unlock(&dev_data->lock);
    return count;
}

static long ambarusdi_driver_ioctl(struct file* file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case IOCTL_GET_DATA:
        if (copy_to_user((void __user*)arg, &dev_data->dma_buffer, sizeof(struct kfifo))) {
            dev_err(dev_data->device, "Failed to copy data to user\n");
            return -EFAULT;
        }
        break;
    default:
        dev_err(dev_data->device, "Unsupported ioctl command\n");
        return -EINVAL;
    }

    return 0;
}

static const struct file_operations ambarusdi_driver_fops = {
    .owner = THIS_MODULE,
    .open = ambarusdi_driver_open,
    .release = ambarusdi_driver_release,
    .read = ambarusdi_driver_read,
    .write = ambarusdi_driver_write,
    .unlocked_ioctl = ambarusdi_driver_ioctl,
};

static int __init ambarusdi_driver_init(void) {
    int ret;

    dev_data = kzalloc(sizeof(struct ambarusdi_driver_data), GFP_KERNEL);
    if (!dev_data)
        return -ENOMEM;

    mutex_init(&dev_data->lock);

    if (!kfifo_alloc(&dev_data->dma_buffer, DMA_BUFFER_SIZE, GFP_KERNEL)) {
        kfree(dev_data);
        return -ENOMEM;
    }

    dev_data->workqueue = create_workqueue(DRIVER_NAME);
    if (!dev_data->workqueue) {
        kfifo_free(&dev_data->dma_buffer);
        kfree(dev_data);
        return -ENOMEM;
    }

    ret = alloc_chrdev_region(&dev_data->cdev.dev, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        destroy_workqueue(dev_data->workqueue);
        kfifo_free(&dev_data->dma_buffer);
        kfree(dev_data);
        return ret;
    }

    cdev_init(&dev_data->cdev, &ambarusdi_driver_fops);
    dev_data->cdev.owner = THIS_MODULE;

    ret = cdev_add(&dev_data->cdev, dev_data->cdev.dev, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_data->cdev.dev, 1);
        destroy_workqueue(dev_data->workqueue);
        kfifo_free(&dev_data->dma_buffer);
        kfree(dev_data);
        return ret;
    }

    if (!request_region(0x1000, 0x100, DRIVER_NAME)) {
        cdev_del(&dev_data->cdev);
        unregister_chrdev_region(dev_data->cdev.dev, 1);
        destroy_workqueue(dev_data->workqueue);
        kfifo_free(&dev_data->dma_buffer);
        kfree(dev_data);
        return -EBUSY;
    }

    ret = request_irq(IRQ_NUM, ambarusdi_driver_irq_handler, IRQF_SHARED, DRIVER_NAME, dev_data);
    if (ret < 0) {
        release_region(0x1000, 0x100);
        cdev_del(&dev_data->cdev);
        unregister_chrdev_region(dev_data->cdev.dev, 1);
        destroy_workqueue(dev_data->workqueue);
        kfifo_free(&dev_data->dma_buffer);
        kfree(dev_data);
        return ret;
    }

    // dma_chan = dma_request_channel(dma_filter_fn, NULL, NULL);

    // dev_data->dma_buffer = dma_alloc_coherent(dev_data->device, DMA_BUFFER_SIZE, &dev_data->dma_phys_addr, GFP_KERNEL);

    return 0;
}

static void __exit ambarusdi_driver_exit(void) {
    // dma_free_coherent(dev_data->device, DMA_BUFFER_SIZE, dev_data->dma_buffer, dev_data->dma_phys_addr);

    free_irq(IRQ_NUM, dev_data);

    release_region(0x1000, 0x100);
        
    cdev_del(&dev_data->cdev);

    unregister_chrdev_region(dev_data->cdev.dev, 1);

    destroy_workqueue(dev_data->workqueue);

    kfifo_free(&dev_data->dma_buffer);

    kfree(dev_data);
}

module_init(ambarusdi_driver_init);
module_exit(ambarusdi_driver_exit);
