/*
 * QDev helpers specific to user emulation.
 *
 * Copyright 2025 Linaro, Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qom/object.h"
#include "hw/core/qdev.h"

uint8_t qdev_default_irq_plane(void)
{
    return 0;
}

unsigned int qdev_num_irq_planes(void)
{
    return 1;
}

void qdev_request_irq_plane(DeviceState *dev)
{
}

void qdev_create_fake_machine(void)
{
    Object *fake_machine_obj;

    fake_machine_obj = object_property_add_new_container(object_get_root(),
                                                         "machine");
    object_property_add_new_container(fake_machine_obj, "unattached");
}
