#pragma once

#include <stdint.h>

typedef struct {
        unsigned long refcount;

        char *name;
        uint8_t busnum;
        uint8_t devnum;
        uint16_t id_vendor;
        uint16_t id_product;
        char *product;
        char *manufacturer;
        char *serial;

        int interface;
        char *devnode;
        int fd;
} USBDevice;

USBDevice *usb_device_ref(USBDevice *device);
USBDevice *usb_device_unref(USBDevice *device);
void usb_device_unrefp(USBDevice **devicep);
long usb_device_sysfs_enumerate(long (*callback)(USBDevice *device, void *userdata), void *userdata);
long usb_device_sysfs_find(USBDevice **devicep, uint8_t busnum, uint8_t devnum);
long usb_device_uevent_connect(int *socketp);
long usb_device_uevent_receive(int sk, char **actionp, USBDevice **devicep);
long usb_device_claim_interface(USBDevice *device, uint8_t num);
long usb_device_call(USBDevice *device,
                     uint8_t out_ep,
                     void *out,
                     unsigned long out_len,
                     uint8_t in_ep,
                     void *in,
                     unsigned long in_size,
                     unsigned long *in_lenp,
                     uint64_t timeout_usec);
