/*
 * x86 device tree generation for device plane filtering
 *
 * Generate a flattened device tree describing devices that belong to
 * non-guest planes (e.g. SVSM firmware plane).  The resulting FDT is
 * passed to the firmware via IGVM so it can discover virtio-mmio
 * assigned to its plane.
 *
 * The device tree is intentionally incomplete: CPUs and memory are
 * not included as firmware obtains that information through other
 * channels.
 *
 * Based on hw/i386/microvm-dt.c
 *
 * Copyright (c) Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/device_tree.h"
#include "hw/char/serial-isa.h"
#include "hw/core/sysbus.h"
#include "hw/virtio/virtio-mmio.h"
#include "qom/object.h"

#include "x86_dt_common.h"
#include <libfdt.h>


static bool debug;

static void dt_add_virtio(MachineState *ms, VirtIOMMIOProxy *mmio)
{
    SysBusDevice *dev = SYS_BUS_DEVICE(mmio);
    VirtioBusState *mmio_virtio_bus = &mmio->bus;
    BusState *mmio_bus = &mmio_virtio_bus->parent_obj;
    VirtIODevice *vdev;
    hwaddr base = dev->mmio[0].addr;
    hwaddr size = 512;
    char *nodename;
    uint8_t plane;

    if (QTAILQ_EMPTY(&mmio_bus->children)) {
        return;
    }

    /* Get the plane property of the inner device */
    vdev = virtio_bus_get_device(mmio_virtio_bus);
    plane = object_property_get_int(OBJECT(vdev), "plane", &error_fatal);

    nodename = g_strdup_printf("/virtio_mmio@%" PRIx64, base);
    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop_string(ms->fdt, nodename, "compatible", "virtio,mmio");

    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg", 2, base, 2, size);
    qemu_fdt_setprop_cell(ms->fdt, nodename, "plane", plane);
    qemu_fdt_setprop(ms->fdt, nodename, "dma-coherent", NULL, 0);
    g_free(nodename);
}

static void dt_add_isa_serial(MachineState *ms, ISADevice *dev)
{
    const char compat[] = "ns16550";
    hwaddr base = object_property_get_int(OBJECT(dev), "iobase", &error_fatal);
    uint8_t plane = object_property_get_int(OBJECT(dev), "plane", &error_fatal);

    hwaddr size = 8;
    char *nodename;

    nodename = g_strdup_printf("/serial@%" PRIx64, base);
    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop(ms->fdt, nodename, "compatible", compat, sizeof(compat));
    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg", 2, base, 2, size);
    qemu_fdt_setprop_cell(ms->fdt, nodename, "plane", plane);

    g_free(nodename);
}

static void dt_setup_isa_bus(MachineState *ms, BusState *bus)
{
    BusChild *kid;
    Object *obj;

    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;

        /* serial */
        obj = object_dynamic_cast(OBJECT(dev), TYPE_ISA_SERIAL);
        if (obj) {
            dt_add_isa_serial(ms, ISA_DEVICE(obj));
            continue;
        }

        if (debug) {
            fprintf(stderr, "%s: unhandled: %s type: %s\n", __func__,
                    dev->canonical_path,
                    object_get_typename(OBJECT(dev)));
        }
    }
}

static void dt_setup_sys_bus(MachineState *ms)
{
    ISABus *isa_bus;
    BusState *bus;
    BusChild *kid;
    Object *obj;

    /* PC Architecture always contains an ISA bus */
    isa_bus = ISA_BUS(object_resolve_path_type("", TYPE_ISA_BUS, NULL));
    dt_setup_isa_bus(ms, BUS(isa_bus));

    bus = sysbus_get_default();

    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;

        /* virtio */
        obj = object_dynamic_cast(OBJECT(dev), TYPE_VIRTIO_MMIO);
        if (obj) {
            dt_add_virtio(ms, VIRTIO_MMIO(obj));
            continue;
        }

        if (debug) {
            fprintf(stderr, "%s: unhandled: %s type: %s\n", __func__,
                    dev->canonical_path,
                    object_get_typename(OBJECT(dev)));
        }
    }
}

void dt_setup_x86(MachineState *ms)
{
    int fdt_size = 0;

    g_free(ms->fdt);
    ms->fdt = create_device_tree(&fdt_size);

    /* root node */
    qemu_fdt_setprop_string(ms->fdt, "/", "compatible", "svsm");
    qemu_fdt_setprop_cell(ms->fdt, "/", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(ms->fdt, "/", "#size-cells", 0x2);
    qemu_fdt_setprop_cell(ms->fdt, "/", "device-plane", ms->device_plane);

    dt_setup_sys_bus(ms);

    if (fdt_pack(ms->fdt) < 0) {
        error_report("x86: Error while packing FDT");
        return;
    }
}
