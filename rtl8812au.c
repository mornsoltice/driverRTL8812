// SPDX-License-Identifier: GPL-2.0
/*
 * RTL8812 USB driver.
 * Copyright (C) 2024 Khairandra Muhamad Nandyka <khairandramnandyka@gmail.com>
 *
 * based on RackMac vu-meter driver
 * (c) Copyright 2006 Benjamin Herrenschmidt, IBM Corp. <benh@kernel.crashing.org>
 *
 * based on USB Skeleton driver - 2.2
 * Copyright (C) 2001-2004 Greg Kroah-Hartman (greg@kroah.com)
 *
 * Author: Khairandra Muhamad Nandyka <khairandramnandyka@gmail.com>
 * Just A 13 yo Linux Kernel Driver Developer From Indonesia
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include <linux/cpufreq.h>

#define RTL8812_VENDOR 0x0bda // Realtek
#define RTL8812_PRODUCT 0x8812 // RTL8812AU
#define RTL8812_CONFIG 0
#define RTL8812_DATA_SIZE 512

 /* Define USB device table */
static const struct usb_device_id rtl8812_table[] = {
    { USB_DEVICE(RTL8812_VENDOR, RTL8812_PRODUCT) },
    { } /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, rtl8812_table);

#define WRITES_IN_FLIGHT 8 /* Arbitrarily chosen */

/* Structure to hold all of our device specific stuff */
struct usb_rtl8812 {
    struct usb_device* udev; /* the usb device for this device */
    struct usb_interface* interface; /* the interface for this device */
    struct semaphore limit_sem; /* limiting the number of writes in progress */
    struct usb_anchor submitted; /* in case we need to retract our submissions */
    int errors; /* the last request tanked */
    spinlock_t err_lock; /* lock for errors */
    struct kref kref;
    struct mutex io_mutex; /* synchronize I/O with disconnect */
    __u8 bulk_out_endpointAddr; /* the address of the bulk out endpoint */
    unsigned long disconnected : 1;
};

#define to_rtl8812_dev(d) container_of(d, struct usb_rtl8812, kref)

static void rtl8812_draw_down(struct usb_rtl8812* dev);

static void rtl8812_delete(struct kref* kref)
{
    struct usb_rtl8812* dev = to_rtl8812_dev(kref);

    usb_put_intf(dev->interface);
    usb_put_dev(dev->udev);
    kfree(dev);
}

static void rtl8812_write_bulk_callback(struct urb* urb)
{
    struct usb_rtl8812* dev;
    unsigned long flags;

    dev = urb->context;

    if (urb->status) {
        if (!(urb->status == -ENOENT ||
            urb->status == -ECONNRESET ||
            urb->status == -ESHUTDOWN))
            dev_err(&dev->interface->dev,
                "%s - nonzero write bulk status received: %d\n",
                __func__, urb->status);

        spin_lock_irqsave(&dev->err_lock, flags);
        dev->errors = urb->status;
        spin_unlock_irqrestore(&dev->err_lock, flags);
    }

    usb_free_coherent(urb->dev, urb->transfer_buffer_length,
        urb->transfer_buffer, urb->transfer_dma);
    up(&dev->limit_sem);
}

static ssize_t rtl8812_write(struct usb_rtl8812* dev, const char* buffer, size_t count)
{
    int retval = 0;
    struct urb* urb = NULL;
    char* buf = NULL;
    size_t writesize = min_t(size_t, count, RTL8812_DATA_SIZE);

    if (down_trylock(&dev->limit_sem)) {
        retval = -EAGAIN;
        goto exit;
    }

    spin_lock_irq(&dev->err_lock);
    retval = dev->errors;
    if (retval < 0) {
        dev->errors = 0;
        retval = (retval == -EPIPE) ? retval : -EIO;
    }
    spin_unlock_irq(&dev->err_lock);
    if (retval < 0)
        goto error;

    urb = usb_alloc_urb(0, GFP_KERNEL);
    if (!urb) {
        retval = -ENOMEM;
        goto error;
    }

    buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
        &urb->transfer_dma);
    if (!buf) {
        retval = -ENOMEM;
        goto error;
    }

    memcpy(buf, buffer, writesize);

    mutex_lock(&dev->io_mutex);
    if (dev->disconnected) {
        mutex_unlock(&dev->io_mutex);
        retval = -ENODEV;
        goto error;
    }

    usb_fill_bulk_urb(urb, dev->udev,
        usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
        buf, writesize, rtl8812_write_bulk_callback, dev);
    urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
    usb_anchor_urb(urb, &dev->submitted);

    retval = usb_submit_urb(urb, GFP_KERNEL);
    mutex_unlock(&dev->io_mutex);
    if (retval) {
        dev_err(&dev->interface->dev,
            "%s - failed submitting write urb, error %d\n",
            __func__, retval);
        goto error_unanchor;
    }

    usb_free_urb(urb);

    return writesize;

error_unanchor:
    usb_unanchor_urb(urb);
error:
    if (urb) {
        usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
        usb_free_urb(urb);
    }
    up(&dev->limit_sem);

exit:
    return retval;
}

static ssize_t rtl8812_read(struct usb_rtl8812* dev, char* buffer, size_t count)
{
    int retval;
    int bytes_read;
    struct urb* urb = NULL;
    char* buf = NULL;
    size_t readsize = min_t(size_t, count, RTL8812_DATA_SIZE);

    // Allocate a URB
    urb = usb_alloc_urb(0, GFP_KERNEL);
    if (!urb) {
        retval = -ENOMEM;
        goto error;
    }

    // Allocate a buffer for the data
    buf = usb_alloc_coherent(dev->udev, readsize, GFP_KERNEL, &urb->transfer_dma);
    if (!buf) {
        retval = -ENOMEM;
        goto error;
    }

    // Set up the URB
    usb_fill_bulk_urb(urb, dev->udev,
        usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
        buf, readsize, rtl8812_read_bulk_callback, dev);
    urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

    retval = usb_submit_urb(urb, GFP_KERNEL);
    if (retval) {
        dev_err(&dev->interface->dev,
            "%s - failed submitting read urb, error %d\n",
            __func__, retval);
        goto error;
    }

    retval = wait_for_completion_timeout(&dev->bulk_in_completion, HZ);
    if (retval == 0) {
        usb_kill_urb(urb);
        retval = -ETIMEDOUT;
        goto error;
    }

    bytes_read = urb->actual_length;
    if (copy_to_user(buffer, buf, bytes_read))
        retval = -EFAULT;
    else
        retval = bytes_read;

error:
    if (urb) {
        if (buf)
            usb_free_coherent(dev->udev, readsize, buf, urb->transfer_dma);
        usb_free_urb(urb);
    }

    return retval;
}

static int rtl8812_probe(struct usb_interface* interface,
    const struct usb_device_id* id)
{
    struct usb_rtl8812* dev;
    struct usb_endpoint_descriptor* bulk_out;
    int retval;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;

    kref_init(&dev->kref);
    sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
    mutex_init(&dev->io_mutex);
    spin_lock_init(&dev->err_lock);
    init_usb_anchor(&dev->submitted);

    dev->udev = usb_get_dev(interface_to_usbdev(interface));
    dev->interface = usb_get_intf(interface);

    retval = usb_find_common_endpoints(interface->cur_altsetting,
        NULL, &bulk_out, NULL, NULL);
    if (retval) {
        dev_err(&interface->dev,
            "Could not find bulk-out endpoints\n");
        goto error;
    }

    dev->bulk_out_endpointAddr = bulk_out->bEndpointAddress;

    usb_set_intfdata(interface, dev);

    return 0;

error:
    kref_put(&dev->kref, rtl8812_delete);

    return retval;
}

static void rtl8812_disconnect(struct usb_interface* interface)
{
    struct usb_rtl8812* dev;
    dev = usb_get_intfdata(interface);

    mutex_lock(&dev->io_mutex);
    dev->disconnected = 1;
    mutex_unlock(&dev->io_mutex);

    usb_kill_anchored_urbs(&dev->submitted);

    kref_put(&dev->kref, rtl8812_delete);
}

static void rtl8812_draw_down(struct usb_rtl8812* dev)
{
    int time;

    time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
    if (!time)
        usb_kill_anchored_urbs(&dev->submitted);
}

static int rtl8812_suspend(struct usb_interface* intf, pm_message_t message)
{
    struct usb_rtl8812* dev = usb_get_intfdata(intf);

    if (!dev)
        return 0;
    rtl8812_draw_down(dev);
    return 0;
}

static int rtl8812_resume(struct usb_interface* intf)
{
    return 0;
}

static int rtl8812_pre_reset(struct usb_interface* intf)
{
    struct usb_rtl8812* dev = usb_get_intfdata(intf);

    mutex_lock(&dev->io_mutex);
    rtl8812_draw_down(dev);

    return 0;
}

static int rtl8812_post_reset(struct usb_interface* intf)
{
    struct usb_rtl8812* dev = usb_get_intfdata(intf);

    dev->errors = -EPIPE;
    mutex_unlock(&dev->io_mutex);

    return 0;
}

static struct usb_driver rtl8812_driver = {
    .name = "rtl8812",
    .probe = rtl8812_probe,
    .disconnect = rtl8812_disconnect,
    .suspend = rtl8812_suspend,
    .resume = rtl8812_resume,
    .pre_reset = rtl8812_pre_reset,
    .post_reset = rtl8812_post_reset,
    .id_table = rtl8812_table,
};

module_usb_driver(rtl8812_driver);

MODULE_AUTHOR("Khairandra Muhamad Nandyka");
MODULE_DESCRIPTION("RTL8812 USB driver");
MODULE_LICENSE("GPL v2");
