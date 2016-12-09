#include "usb-device.h"
#include "util.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/usbdevice_fs.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static void usb_device_free(USBDevice *device) {
        if (device->fd >= 0)
                close(device->fd);

        free(device->name);
        free(device->product);
        free(device->manufacturer);
        free(device->serial);
        free(device->devnode);

        free(device);
}

USBDevice *usb_device_ref(USBDevice *device) {
        device->refcount += 1;

        return device;
}

USBDevice *usb_device_unref(USBDevice *device) {
        device->refcount -= 1;

        if (device->refcount == 0)
                usb_device_free(device);

        return NULL;
}

void usb_device_unrefp(USBDevice **devicep) {
        if (*devicep)
                usb_device_unref(*devicep);
}

static long usb_device_new(USBDevice **devicep) {
        USBDevice *device;

        device = calloc(1, sizeof(USBDevice));
        device->refcount = 1;
        device->fd = -1;

        *devicep = device;

        return 0;
}

static char *sysfs_read_attribute(DIR *dir, const char *device, const char *attribute) {
        _cleanup_(closep) int fd = -1;
        _cleanup_(fclosep) FILE *f = NULL;
        _cleanup_(freep) char *path = NULL;
        char line[4096];
        char *s;

        asprintf(&path, "%s/%s", device, attribute);

        fd = openat(dirfd(dir), path, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
        if (fd < 0)
                return NULL;

        f = fdopen(fd, "re");
        if (!f)
                return NULL;

        fd = -1;

        if (!fgets(line, sizeof(line), f))
                return NULL;

        s = strdup(line);
        s[strcspn(s, "\n")] = '\0';

        return s;
}

static long sysfs_enumerate(USBDevice **devicep, uint8_t busnum, uint8_t devnum,
                            long (*callback)(USBDevice *device, void *userdata), void *userdata) {
        _cleanup_(closep) int dfd = -1;
        _cleanup_(closedirp) DIR *dir = NULL;
        long r;

        assert(!!devicep ^ !!callback);

        dfd = openat(AT_FDCWD, "/sys/bus/usb/devices", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC);
        if (dfd < 0)
                return -errno;

        dir = fdopendir(dfd);
        if (!dir)
                return -errno;

        dfd = -1;

        for (struct dirent *d = readdir(dir); d; d = readdir(dir)) {
                _cleanup_(freep) char *uevent = NULL;
                int fd;
                _cleanup_(fclosep) FILE *f = NULL;
                char line[4096];
                _cleanup_(usb_device_unrefp) USBDevice *device = NULL;
                bool is_usb_device = false;

                if (d->d_name[0] == '.')
                        continue;

                asprintf(&uevent, "%s/uevent", d->d_name);

                fd = openat(dirfd(dir), uevent, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
                if (fd < 0)
                        continue;

                f = fdopen(fd, "re");
                if (!f)
                        continue;

                r = usb_device_new(&device);
                if (r < 0)
                        return r;

                while (fgets(line, sizeof(line), f) != NULL) {
                        char *value;
                        char *end;

                        value = strchr(line, '=');
                        if (!value)
                                continue;
                        *value = '\0';
                        value++;

                        end = strchr(value, '\n');
                        if (!end)
                                continue;
                        *end = '\0';

                        if (strcmp(line, "DEVTYPE") == 0) {
                                if (strcmp(value, "usb_device") == 0)
                                        is_usb_device = true;

                        } else if (strcmp(line, "BUSNUM") == 0) {
                                device->busnum = strtoul(value, NULL, 10);

                        } else if (strcmp(line, "DEVNAME") == 0) {
                                asprintf(&device->devnode, "/dev/%s", value);

                        } else if (strcmp(line, "DEVNUM") == 0) {
                                device->devnum = strtoul(value, NULL, 10);

                        } else if (strcmp(line, "PRODUCT") == 0) {
                                unsigned int vendor, product, version;

                                if (sscanf(value, "%x/%x/%x", &vendor, &product, &version) != 3)
                                        continue;

                                device->id_vendor = vendor;
                                device->id_product = product;
                        }
                }

                if (!is_usb_device)
                        continue;

                device->name = strdup(d->d_name);
                device->product = sysfs_read_attribute(dir, d->d_name, "product");
                device->manufacturer = sysfs_read_attribute(dir, d->d_name, "manufacturer");
                device->serial = sysfs_read_attribute(dir, d->d_name, "serial");

                if (callback) {
                        r = callback(device, userdata);
                        if (r != 0)
                                return r;
                }

                if (devicep) {
                        if (device->busnum == busnum && device->devnum == devnum) {
                                *devicep = device;
                                device = NULL;

                                return 0;
                        }
                }
        }

        if (devicep)
                return -ENODEV;

        return 0;
}

long usb_device_sysfs_enumerate(long (*callback)(USBDevice *device, void *userdata), void *userdata) {
        return sysfs_enumerate(NULL, 0, 0, callback, userdata);
}

long usb_device_sysfs_find(USBDevice **devicep, uint8_t busnum, uint8_t devnum) {
        return sysfs_enumerate(devicep, busnum, devnum, NULL, NULL);
}

enum {
        UEVENT_BROADCAST_KERNEL = 1
};

long usb_device_uevent_connect(int *socketp) {
        _cleanup_(closep) int sk = -1;
        struct sockaddr_nl nl = {};
        const int on = 1;

        sk = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
        if (sk < 0)
                return -errno;

        if (setsockopt(sk, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0)
                return -errno;

        nl.nl_family = AF_NETLINK;
        nl.nl_groups = UEVENT_BROADCAST_KERNEL;
        if (bind(sk, (struct sockaddr *)&nl, sizeof(struct sockaddr_nl)) < 0)
                return -errno;

        *socketp = sk;
        sk = -1;

        return 0;
}

long usb_device_uevent_receive(int sk, char **actionp, USBDevice **devicep) {
        char buf[4096];
        long buflen;
        struct iovec iov = {
                .iov_base = buf,
                .iov_len = sizeof(buf)
        };
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        struct sockaddr_nl nl = {
                .nl_family = AF_NETLINK,
                .nl_groups = UEVENT_BROADCAST_KERNEL
        };
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,

                .msg_control = cred_msg,
                .msg_controllen = sizeof(cred_msg),

                .msg_name = &nl,
                .msg_namelen = sizeof(nl)
        };
        struct cmsghdr *cmsg;
        struct ucred *cred;
        const char *s;
        bool is_usb_device = false;
        _cleanup_(freep) char *action = NULL;
        _cleanup_(usb_device_unrefp) USBDevice *device = NULL;
        int i;
        _cleanup_(closep) int dfd = -1;
        _cleanup_(closedirp) DIR *dir = NULL;
        long r;

        r = usb_device_new(&device);
        if (r < 0)
                return r;

        buflen = recvmsg(sk, &smsg, 0);
        if (buflen < 32 || (smsg.msg_flags & MSG_TRUNC))
                return -EBADMSG;

        if (nl.nl_groups != UEVENT_BROADCAST_KERNEL)
                return -EIO;

        if (nl.nl_pid > 0)
                return -EIO;

        cmsg = CMSG_FIRSTHDR(&smsg);
        if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS)
                return -EBADMSG;

        cred = (struct ucred *)CMSG_DATA(cmsg);
        if (cred->uid != 0)
                return -EIO;

        /* skip header */
        s = memchr(buf, '\0', buflen);
        if (!s)
                return -EBADMSG;

        i = s + 1 - buf;

        while (i < buflen) {
                char *key;
                const char *end;
                char *value;

                key = (char *)&buf[i];
                end = memchr(key, '\0', buflen - i);
                if (!end)
                        return -EINVAL;
                i += end - key + 1;

                value = strchr(key, '=');
                if (!value)
                        return -EINVAL;

                *value = '\0';
                value++;

                if (strcmp(key, "ACTION") == 0) {
                        action = strdup(value);

                } else if (strcmp(key, "DEVPATH") == 0) {
                        s = strrchr(value, '/');
                        if (!s)
                                return -EBADMSG;

                        device->name = strdup(s + 1);

                } else if (strcmp(key, "DEVTYPE") == 0) {
                        if (strcmp(value, "usb_device") == 0)
                                is_usb_device = true;

                } else if (strcmp(key, "BUSNUM") == 0) {
                        device->busnum = strtoul(value, NULL, 10);

                } else if (strcmp(key, "DEVNUM") == 0) {
                        device->devnum = strtoul(value, NULL, 10);

                } else if (strcmp(key, "PRODUCT") == 0) {
                        unsigned int vendor, product, version;

                        if (sscanf(value, "%x/%x/%x", &vendor, &product, &version) != 3)
                                continue;

                        device->id_vendor = vendor;
                        device->id_product = product;
                }
        }

        if (!is_usb_device)
                return 0;

        if (!action)
                return -EBADMSG;

        dfd = openat(AT_FDCWD, "/sys/bus/usb/devices", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC);
        if (dfd < 0)
                return -errno;

        dir = fdopendir(dfd);
        if (!dir)
                return -errno;

        dfd = -1;

        device->product = sysfs_read_attribute(dir, device->name, "product");
        device->manufacturer = sysfs_read_attribute(dir, device->name, "manufacturer");
        device->serial = sysfs_read_attribute(dir, device->name, "serial");

        *devicep = device;
        device = NULL;

        *actionp = action;
        action = NULL;

        return 1;
}

long usb_device_claim_interface(USBDevice *device, uint8_t num) {
        _cleanup_(closep) int fd = -1;
        unsigned long n = num;
        long r;

        if (device->fd >= 0)
                return -EBUSY;

        fd = open(device->devnode, O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &n);
        if (r < 0)
                return -errno;

        device->fd = fd;
        fd = -1;
        device->interface = num;

        return 0;
}

long usb_device_call(USBDevice *device,
                     uint8_t out_ep,
                     void *out,
                     unsigned long out_len,
                     uint8_t in_ep,
                     void *in,
                     unsigned long in_size,
                     unsigned long *in_lenp,
                     uint64_t timeout_usec) {
        struct usbdevfs_urb urb_out = {
                .type = USBDEVFS_URB_TYPE_BULK,
                .endpoint = out_ep,
                .buffer = out,
                .buffer_length = out_len,
        };
        struct usbdevfs_urb urb_in = {
                .type = USBDEVFS_URB_TYPE_BULK,
                .endpoint = in_ep,
                .buffer = in,
                .buffer_length = in_size,
        };
        struct pollfd pfd[] = {
                {
                        .fd = device->fd,
                        .events = POLLOUT,
                },
        };
        struct usbdevfs_urb *u;
        long r;

        r = ioctl(device->fd, USBDEVFS_SUBMITURB, &urb_out);
        if (r < 0)
                return -errno;

        r = poll(pfd, ARRAY_SIZE(pfd), timeout_usec / 1000);
        if (r < 0)
                return -errno;

        r = ioctl(device->fd, USBDEVFS_REAPURBNDELAY, &u);
        if (r < 0)
                return -errno;

        r = ioctl(device->fd, USBDEVFS_SUBMITURB, &urb_in);
        if (r < 0)
                return -errno;

        r = poll(pfd, ARRAY_SIZE(pfd), timeout_usec / 1000);
        if (r < 0)
                return -errno;

        r = ioctl(device->fd, USBDEVFS_REAPURBNDELAY, &u);
        if (r < 0)
                return -errno;

        if (in_lenp)
                *in_lenp = urb_in.actual_length;

        return 0;
}
