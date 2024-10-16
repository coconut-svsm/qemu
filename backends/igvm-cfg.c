/*
 * QEMU IGVM interface
 *
 * Copyright (C) 2023-2024 SUSE
 *
 * Authors:
 *  Roy Hopkins <roy.hopkins@suse.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "sysemu/igvm-cfg.h"
#include "igvm.h"
#include "qom/object_interfaces.h"

static char *get_igvm(Object *obj, Error **errp)
{
    IgvmCfg *igvm = IGVM_CFG(obj);
    return g_strdup(igvm->filename);
}

static void set_igvm(Object *obj, const char *value, Error **errp)
{
    IgvmCfg *igvm = IGVM_CFG(obj);
    g_free(igvm->filename);
    igvm->filename = g_strdup(value);
}

OBJECT_DEFINE_TYPE_WITH_INTERFACES(IgvmCfg, igvm_cfg, IGVM_CFG, OBJECT,
                                   { TYPE_USER_CREATABLE }, { NULL })

static void igvm_cfg_class_init(ObjectClass *oc, void *data)
{
    IgvmCfgClass *igvmc = IGVM_CFG_CLASS(oc);

    object_class_property_add_str(oc, "file", get_igvm, set_igvm);
    object_class_property_set_description(oc, "file",
                                          "Set the IGVM filename to use");

    igvmc->process = qigvm_process_file;
}

static void igvm_cfg_init(Object *obj)
{
}

static void igvm_cfg_finalize(Object *obj)
{
}
