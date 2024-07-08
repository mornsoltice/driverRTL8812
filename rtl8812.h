#ifndef RTL8812_H
#define RTL8812_H

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>

#define DRIVER_NAME "rtl8812"
#define PCI_VENDOR_ID_REALTEK 0x10ec
#define PCI_DEVICE_ID_RTL8812 0x8812

struct rtl8812_priv {
    struct net_device* netdev;
    void __iomem* mmio;
    struct pci_dev* pdev;
    spinlock_t lock;
};

int rtl8812_open(struct net_device* dev);
int rtl8812_stop(struct net_device* dev);
netdev_tx_t rtl8812_start_xmit(struct sk_buff* skb, struct net_device* dev);
void rtl8812_set_multicast_list(struct net_device* dev);
void rtl8812_tx_timeout(struct net_device* dev);
irqreturn_t rtl8812_interrupt(int irq, void* dev_id);

#endif 
