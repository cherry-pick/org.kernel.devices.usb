#include "org.kernel.devices.usb.varlink.h"
#include "usb-device.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <varlink.h>

typedef struct {
        VarlinkServer *server;

        int epoll_fd;
        int signal_fd;
        int uevent_fd;
} Manager;

static void manager_free(Manager *m) {
        if (m->epoll_fd >= 0)
                close(m->epoll_fd);

        if (m->signal_fd >= 0)
                close(m->signal_fd);

        if (m->uevent_fd >= 0)
                close(m->uevent_fd);

        if (m->server)
                varlink_server_free(m->server);

        free(m);
}

static void manager_freep(Manager **mp) {
        if (*mp)
                manager_free(*mp);
}

static long manager_new(Manager **mp) {
        _cleanup_(manager_freep) Manager *m = NULL;

        m = calloc(1, sizeof(Manager));
        m->epoll_fd = -1;
        m->signal_fd = -1;
        m->uevent_fd = -1;

        *mp = m;
        m = NULL;

        return 0;
}

static long org_kernel_devices_usb_Info(VarlinkConnection *connection,
                                        VarlinkStruct *parameters,
                                        void *userdata) {
        int64_t busnum, devnum;
        _cleanup_(usb_device_unrefp) USBDevice *usb_device = NULL;
        _cleanup_(varlink_struct_unrefp) VarlinkStruct *device = NULL;
        long r;

        if (varlink_struct_get_int(parameters, "bus_nr", &busnum) < 0 ||
            varlink_struct_get_int(parameters, "device_nr", &devnum) < 0)
                return varlink_connection_reply_error(connection, "Invalid arguments");

        r = usb_device_sysfs_find(&usb_device, busnum, devnum);
        if (r < 0)
                return varlink_connection_reply_error(connection, "Error finding device: %s", strerror(-r));

        if (varlink_struct_new(&device) < 0 ||
            varlink_struct_set_int(device, "vendor_id", usb_device->id_vendor) < 0 ||
            varlink_struct_set_int(device, "product_id", usb_device->id_product) < 0 ||
            varlink_struct_set_int(device, "bus_nr", usb_device->busnum) < 0 ||
            varlink_struct_set_int(device, "device_nr", usb_device->devnum) < 0 ||
            varlink_struct_set_string(device, "product", usb_device->product ?: "") < 0 ||
            varlink_struct_set_string(device, "manufacturer", usb_device->manufacturer ?: "") < 0 ||
            varlink_struct_set_string(device, "serial", usb_device->serial ?: "") < 0)
                return -EUCLEAN;

        return varlink_connection_reply(connection, device);
}

static long usb_device_add(USBDevice *usb_device, void *userdata) {
        VarlinkArray *devices = userdata;
        _cleanup_(varlink_struct_unrefp) VarlinkStruct *device = NULL;

        if (varlink_struct_new(&device) < 0 ||
            varlink_struct_set_int(device, "vendor_id", usb_device->id_vendor) < 0 ||
            varlink_struct_set_int(device, "product_id", usb_device->id_product) < 0 ||
            varlink_struct_set_int(device, "bus_nr", usb_device->busnum) < 0 ||
            varlink_struct_set_int(device, "device_nr", usb_device->devnum) < 0 ||
            varlink_struct_set_string(device, "product", usb_device->product ?: "") < 0 ||
            varlink_struct_set_string(device, "manufacturer", usb_device->manufacturer ?: "") < 0 ||
            varlink_struct_set_string(device, "serial", usb_device->serial ?: ""))
                return -EUCLEAN;

        return varlink_array_append_struct(devices, device);
}

static long org_kernel_devices_usb_Monitor(VarlinkConnection *connection,
                                           VarlinkStruct *parameters,
                                           void *userdata) {
        _cleanup_(varlink_array_unrefp) VarlinkArray *devices = NULL;
        _cleanup_(varlink_struct_unrefp) VarlinkStruct *reply = NULL;
        long r;

        r = varlink_array_new(&devices);
        if (r < 0)
                return varlink_connection_reply_error(connection, "Error: %s", strerror(-r));

        /* Add all current devices to the array */
        r = usb_device_sysfs_enumerate(usb_device_add, devices);
        if (r < 0)
                return varlink_connection_reply_error(connection, "Error: %s", strerror(-r));

        if (varlink_struct_new(&reply) < 0 ||
            varlink_struct_set_string(reply, "event", "current") < 0 ||
            varlink_struct_set_array(reply, "devices", devices))
                return varlink_connection_reply_error(connection, "Error");

        return varlink_connection_reply(connection, reply);
}

static long usb_monitor(Manager *m, const char *action, USBDevice *usb_device) {
        VarlinkConnection **connections;
        int n_connections, i;
        _cleanup_(varlink_struct_unrefp) VarlinkStruct *device = NULL;
        _cleanup_(varlink_array_unrefp) VarlinkArray *devices = NULL;
        _cleanup_(varlink_struct_unrefp) VarlinkStruct *reply = NULL;

        n_connections = varlink_server_get_monitor_connections(m->server,
                                                               "org.kernel.devices.usb.Monitor",
                                                               &connections);
        if (n_connections <= 0)
                return 0;

        if (varlink_struct_new(&device) < 0 ||
            varlink_struct_set_int(device, "vendor_id", usb_device->id_vendor) < 0 ||
            varlink_struct_set_int(device, "product_id", usb_device->id_product) < 0 ||
            varlink_struct_set_int(device, "bus_nr", usb_device->busnum) < 0 ||
            varlink_struct_set_int(device, "device_nr", usb_device->devnum) < 0 ||
            varlink_struct_set_string(device, "product", usb_device->product ?: "") < 0 ||
            varlink_struct_set_string(device, "manufacturer", usb_device->manufacturer ?: "") < 0 ||
            varlink_struct_set_string(device, "serial", usb_device->serial ?: ""))
                return -EUCLEAN;

        if (varlink_array_new(&devices) < 0 || varlink_array_append_struct(devices, device) < 0)
                return -EUCLEAN;

        if (varlink_struct_new(&reply) < 0 ||
            varlink_struct_set_string(reply, "event", action) < 0 ||
            varlink_struct_set_array(reply, "devices", devices) < 0)
                return -EUCLEAN;

        for (i = 0; i < n_connections; i++)
                varlink_connection_reply(connections[i], reply);

        return 0;
}

int main(int argc, char **argv) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *address;
        int fd = -1;
        sigset_t mask;
        struct epoll_event ev = {};
        bool exit = false;
        long r;

        r = manager_new(&m);
        if (r < 0)
                return EXIT_FAILURE;

        address = argv[1];
        if (!address) {
                fprintf(stderr, "Error: missing address.\n");

                return EXIT_FAILURE;
        }

        /* An activator passed us our connection. */
        if (read(3, NULL, 0) == 0)
                fd = 3;

        r = varlink_server_new(&m->server,
                               address, fd,
                               program_invocation_short_name,
                               "The USB Device Service provides information to query "
                               "and monitor USB devices.",
                               "Url: https://github.com/fabrix/org.kernel.devices.usb",
                               &org_kernel_devices_usb_varlink, 1,
                               NULL);
        if (r < 0)
                return EXIT_FAILURE;

        r = varlink_server_set_method_callback(m->server,
                                               "org.kernel.devices.usb.Info",
                                               org_kernel_devices_usb_Info, m);
        if (r < 0)
                return EXIT_FAILURE;

        r = varlink_server_set_method_callback(m->server,
                                               "org.kernel.devices.usb.Monitor",
                                               org_kernel_devices_usb_Monitor, m);
        if (r < 0)
                return EXIT_FAILURE;

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0)
                return EXIT_FAILURE;

        ev.events = EPOLLIN;
        ev.data.fd = varlink_server_get_fd(m->server);
        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, varlink_server_get_fd(m->server), &ev) < 0)
                return EXIT_FAILURE;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        m->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (m->signal_fd < 0)
                return EXIT_FAILURE;

        ev.events = EPOLLIN;
        ev.data.fd = m->signal_fd;
        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->signal_fd, &ev) < 0)
                return EXIT_FAILURE;

        r = usb_device_uevent_connect(&m->uevent_fd);
        if (r < 0)
                return EXIT_FAILURE;

        ev.events = EPOLLIN;
        ev.data.fd = m->uevent_fd;
        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->uevent_fd, &ev) < 0)
                return EXIT_FAILURE;

        while (!exit) {
                int n;

                n = epoll_wait(m->epoll_fd, &ev, 1, -1);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        return EXIT_FAILURE;
                }

                if (n == 0)
                        continue;

                if (ev.data.fd == varlink_server_get_fd(m->server)) {
                        r = varlink_server_process_events(m->server);
                        if (r < 0) {
                                fprintf(stderr, "Control: %s\n", strerror(-r));
                                if (r != -EPIPE)
                                        return EXIT_FAILURE;
                        }

                } else if (ev.data.fd == m->signal_fd) {
                        struct signalfd_siginfo fdsi;
                        long size;

                        size = read(m->signal_fd, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size != sizeof(struct signalfd_siginfo))
                                continue;

                        switch (fdsi.ssi_signo) {
                                case SIGTERM:
                                case SIGINT:
                                        exit = true;
                                        break;

                                default:
                                        abort();
                        }

                } else if (ev.data.fd == m->uevent_fd) {
                        _cleanup_(freep) char *action = NULL;
                        _cleanup_(usb_device_unrefp) USBDevice *device = NULL;

                        r = usb_device_uevent_receive(m->uevent_fd, &action, &device);
                        if (r < 0)
                                return EXIT_FAILURE;

                        if (r == 0)
                                continue;

                        r = usb_monitor(m, action, device);
                        if (r < 0)
                                return EXIT_FAILURE;
                }
        }

        return EXIT_SUCCESS;
}
