/*
 * QEMU IGVM configuration backend for Confidential Guests
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

#if defined(CONFIG_IGVM)

#include "exec/confidential-guest-support.h"
#include "qemu/queue.h"
#include "qemu/typedefs.h"

#include "exec/igvm.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"

#include <igvm/igvm.h>
#include <igvm/igvm_defs.h>
#include <linux/kvm.h>

typedef struct IgvmParameterData {
    QTAILQ_ENTRY(IgvmParameterData) next;
    uint8_t *data;
    uint32_t size;
    uint32_t index;
} IgvmParameterData;

/*
 * Some directives are specific individual confidential computing platforms.
 * Define required types for each of those platforms here.
 */

/* SEV/SEV-ES/SEV-SNP */
struct QEMU_PACKED sev_id_block {
	uint8_t ld[48];
	uint8_t family_id[16];
	uint8_t image_id[16];
	uint32_t version;
	uint32_t guest_svn;
	uint64_t policy;
};

struct QEMU_PACKED sev_id_authentication {
	uint32_t id_key_alg;
	uint32_t auth_key_algo;
	uint8_t reserved[56];
	uint8_t id_block_sig[512];
	uint8_t id_key[1028];
	uint8_t reserved2[60];
	uint8_t id_key_sig[512];
	uint8_t author_key[1028];
	uint8_t reserved3[892];
};

struct igvm_context {
    /*
     * Compatibility mask that is used to check if IGVM directives apply
     * to the current platform.
     */
    uint32_t compatibility_mask;

    /*
     * IGVM definition of the current platform type.
     */
    IgvmPlatformType platform_type;

    /*
     * The ConfidentialGuestSupport object that is used to process directives
     * in the IGVM file.
     */
    ConfidentialGuestSupport *cgs;

    /*
     * For SEV platforms, optionally contains the ID block and authentication
     * that should be verified by the guest.
     */
    struct sev_id_block *id_block;
    struct sev_id_authentication *id_auth;

    /* Define the guest policy for SEV guests */
    uint64_t sev_policy;

    /* List of all parameters to populate in the guest */
    QTAILQ_HEAD(, IgvmParameterData) parameter_data;
};

static int directive_page_data(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_vp_context(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_parameter_area(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_parameter_insert(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_memory_map(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_vp_count(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_environment_info(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_required_memory(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
static int directive_snp_id_block(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);

static int initialization_guest_policy(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);

struct IGVMHandler {
    uint32_t type;
    uint32_t section;
    int (*handler)(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp);
};

static struct IGVMHandler handlers[] = {
    { IGVM_VHT_PAGE_DATA, HEADER_SECTION_DIRECTIVE, directive_page_data },
    { IGVM_VHT_VP_CONTEXT, HEADER_SECTION_DIRECTIVE, directive_vp_context },
    { IGVM_VHT_PARAMETER_AREA, HEADER_SECTION_DIRECTIVE, directive_parameter_area },
    { IGVM_VHT_PARAMETER_INSERT, HEADER_SECTION_DIRECTIVE, directive_parameter_insert },
    { IGVM_VHT_MEMORY_MAP, HEADER_SECTION_DIRECTIVE, directive_memory_map },
    { IGVM_VHT_VP_COUNT_PARAMETER, HEADER_SECTION_DIRECTIVE, directive_vp_count },
    { IGVM_VHT_ENVIRONMENT_INFO_PARAMETER, HEADER_SECTION_DIRECTIVE, directive_environment_info },
    { IGVM_VHT_REQUIRED_MEMORY, HEADER_SECTION_DIRECTIVE, directive_required_memory },
    { IGVM_VHT_SNP_ID_BLOCK, HEADER_SECTION_DIRECTIVE, directive_snp_id_block },
    { IGVM_VHT_GUEST_POLICY, HEADER_SECTION_INITIALIZATION, initialization_guest_policy },
};

static int handle(uint32_t type, struct igvm_context *ctx, int i, Error **errp)
{
    size_t handler;
    IgvmHandle header_handle;
    const uint8_t *header_data;
    int result;

    for (handler = 0; handler < (sizeof(handlers) /
                                 sizeof(struct IGVMHandler));
         ++handler) {
        if (handlers[handler].type == type) {
            header_handle =
                igvm_get_header(ctx->cgs->igvm, handlers[handler].section, i);
            if (header_handle < 0) {
                error_setg(
                    errp,
                    "IGVM file is invalid: Failed to read header (code: %d)",
                    (int)header_handle);
                return -1;
            }
            header_data = igvm_get_buffer(ctx->cgs->igvm, header_handle) +
                          sizeof(IGVM_VHS_VARIABLE_HEADER);
            result = handlers[handler].handler(ctx, i, header_data, errp);
            igvm_free_buffer(ctx->cgs->igvm, header_handle);
            return result;
        }
    }
    error_setg(errp,
               "IGVM: Unknown header type encountered when processing file: "
               "(type 0x%X)",
               type);
    return -1;
}

static void *igvm_prepare_memory(uint64_t addr, uint64_t size,
                                 int region_identifier, Error **errp)
{
    ERRP_GUARD();
    MemoryRegion *igvm_pages = NULL;
    Int128 gpa_region_size;
    MemoryRegionSection mrs =
        memory_region_find(get_system_memory(), addr, size);
    if (mrs.mr) {
        if (!memory_region_is_ram(mrs.mr)) {
            memory_region_unref(mrs.mr);
            error_setg(
                errp,
                "Processing of IGVM file failed: Could not prepare memory "
                "at address 0x%lX due to existing non-RAM region",
                addr);
            return NULL;
        }

        gpa_region_size = int128_make64(size);
        if (int128_lt(mrs.size, gpa_region_size)) {
            memory_region_unref(mrs.mr);
            error_setg(
                errp,
                "Processing of IGVM file failed: Could not prepare memory "
                "at address 0x%lX: region size exceeded",
                addr);
            return NULL;
        }
        return qemu_map_ram_ptr(mrs.mr->ram_block, mrs.offset_within_region);
    } else {
        /*
         * The region_identifier is the is the index of the IGVM directive that
         * contains the page with the lowest GPA in the region. This will
         * generate a unique region name.
         */
        g_autofree char *region_name =
            g_strdup_printf("igvm.%X", region_identifier);
        igvm_pages = g_malloc(sizeof(*igvm_pages));
        memory_region_init_ram_guest_memfd(igvm_pages, NULL, region_name, size,
                                    errp);
        if (*errp) {
            return NULL;
        }
        memory_region_add_subregion(get_system_memory(), addr, igvm_pages);
        return memory_region_get_ram_ptr(igvm_pages);
    }
}

static int igvm_type_to_cgs_type(IgvmPageDataType memory_type, bool unmeasured,
                                 bool zero)
{
    switch (memory_type) {
    case NORMAL: {
        if (unmeasured) {
            return CGS_PAGE_TYPE_UNMEASURED;
        } else {
            return zero ? CGS_PAGE_TYPE_ZERO : CGS_PAGE_TYPE_NORMAL;
        }
    }
    case SECRETS:
        return CGS_PAGE_TYPE_SECRETS;
    case CPUID_DATA:
        return CGS_PAGE_TYPE_CPUID;
    case CPUID_XF:
        return CGS_PAGE_TYPE_CPUID;
    default:
        return -1;
    }
}

static bool page_attrs_equal(IgvmHandle igvm, int i,
                             const IGVM_VHS_PAGE_DATA *page_1,
                             const IGVM_VHS_PAGE_DATA *page_2)
{
    IgvmHandle data_handle1, data_handle2;

    /*
     * If one page has data and the other doesn't then this results in different
     * page types: NORMAL vs ZERO.
     */
    data_handle1 = igvm_get_header_data(igvm, HEADER_SECTION_DIRECTIVE, i - 1);
    data_handle2 = igvm_get_header_data(igvm, HEADER_SECTION_DIRECTIVE, i);
    if ((data_handle1 == IGVMAPI_NO_DATA) &&
        (data_handle2 != IGVMAPI_NO_DATA)) {
        return false;
    } else if ((data_handle1 != IGVMAPI_NO_DATA) &&
               (data_handle2 == IGVMAPI_NO_DATA)) {
        return false;
    }
    return ((*(const uint32_t *)&page_1->flags ==
             *(const uint32_t *)&page_2->flags) &&
            (page_1->data_type == page_2->data_type) &&
            (page_1->compatibility_mask == page_2->compatibility_mask));
}

static int igvm_process_mem_region(struct igvm_context *ctx,
                                   int start_index,
                                   uint64_t gpa_start, int page_count,
                                   const IgvmPageDataFlags *flags,
                                   const IgvmPageDataType page_type,
                                   Error **errp)
{
    ERRP_GUARD();
    uint8_t *region;
    IgvmHandle data_handle;
    const void *data;
    uint32_t data_size;
    int i;
    bool zero = true;
    const uint64_t page_size = flags->is_2mb_page ? 0x200000 : 0x1000;
    int result;
    int cgs_page_type;

    region = igvm_prepare_memory(gpa_start, page_count * page_size, start_index,
                                 errp);
    if (!region) {
        return -1;
    }

    for (i = 0; i < page_count; ++i) {
        data_handle = igvm_get_header_data(ctx->cgs->igvm, HEADER_SECTION_DIRECTIVE,
                                           i + start_index);
        if (data_handle == IGVMAPI_NO_DATA) {
            /* No data indicates a zero page */
            memset(&region[i * page_size], 0, page_size);
        } else if (data_handle < 0) {
            error_setg(
                errp,
                "IGVM file contains invalid page data for directive with "
                "index %d",
                i + start_index);
            return -1;
        } else {
            zero = false;
            data_size = igvm_get_buffer_size(ctx->cgs->igvm, data_handle);
            if (data_size < page_size) {
                memset(&region[i * page_size], 0, page_size);
            } else if (data_size > page_size) {
                error_setg(errp,
                           "IGVM file contains page data with invalid size for "
                           "directive with index %d",
                           i + start_index);
                return -1;
            }
            data = igvm_get_buffer(ctx->cgs->igvm, data_handle);
            memcpy(&region[i * page_size], data, data_size);
            igvm_free_buffer(ctx->cgs->igvm, data_handle);
        }
    }

    cgs_page_type = igvm_type_to_cgs_type(page_type, flags->unmeasured, zero);
    if (cgs_page_type < 0) {
        error_setg(
            errp,
            "Invalid page type in IGVM file. Directives: %d to %d, "
            "page type: %d",
            start_index, start_index + page_count, page_type);
        return -1;
    }

    result = ctx->cgs->set_guest_state(gpa_start, region, page_size * page_count,
                                  cgs_page_type, 0, errp);
    if ((result < 0) && !*errp) {
        error_setg(errp, "IGVM set guest state failed with code %d", result);
        return -1;
    }
    return 0;
}

static int process_mem_page(struct igvm_context *ctx, int i,
                            const IGVM_VHS_PAGE_DATA *page_data, Error **errp)
{
    ERRP_GUARD();
    static IGVM_VHS_PAGE_DATA prev_page_data;
    static uint64_t region_start;
    static int region_start_i;
    static int last_i;
    static int page_count;

    if (page_data) {
        if (page_count == 0) {
            region_start = page_data->gpa;
            region_start_i = i;
        } else {
            if (!page_attrs_equal(ctx->cgs->igvm, i, page_data, &prev_page_data) ||
                ((prev_page_data.gpa +
                  (prev_page_data.flags.is_2mb_page ? 0x200000 : 0x1000)) !=
                 page_data->gpa) ||
                (last_i != (i - 1))) {
                /* End of current region */
                if (igvm_process_mem_region(ctx, region_start_i,
                                        region_start, page_count,
                                        &prev_page_data.flags,
                                        prev_page_data.data_type, errp) < 0) {
                    return -1;
                }
                page_count = 0;
                region_start = page_data->gpa;
                region_start_i = i;
            }
        }
        memcpy(&prev_page_data, page_data, sizeof(prev_page_data));
        last_i = i;
        ++page_count;
    } else {
        if (page_count > 0) {
            if (igvm_process_mem_region(ctx, region_start_i,
                                    region_start, page_count,
                                    &prev_page_data.flags,
                                    prev_page_data.data_type, errp) < 0) {
                return -1;
            }
            page_count = 0;
        }
    }
    return 0;
}

static int directive_page_data(struct igvm_context *ctx, int i,
                               const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_PAGE_DATA *page_data =
        (const IGVM_VHS_PAGE_DATA *)header_data;
    if (page_data->compatibility_mask & ctx->compatibility_mask) {
        return process_mem_page(ctx, i, page_data, errp);
    }
    return 0;
}

static int directive_vp_context(struct igvm_context *ctx, int i,
                                const uint8_t *header_data, Error **errp)
{
    ERRP_GUARD();
    const IGVM_VHS_VP_CONTEXT *vp_context =
        (const IGVM_VHS_VP_CONTEXT *)header_data;
    IgvmHandle data_handle;
    uint8_t *data;
    int result;

    if (vp_context->compatibility_mask & ctx->compatibility_mask) {
        data_handle =
            igvm_get_header_data(ctx->cgs->igvm, HEADER_SECTION_DIRECTIVE, i);
        if (data_handle < 0) {
            error_setg(errp, "Invalid VP context in IGVM file. Error code: %X",
                       data_handle);
            return -1;
        }

        data = (uint8_t *)igvm_get_buffer(ctx->cgs->igvm, data_handle);
        result = ctx->cgs->set_guest_state(
            vp_context->gpa, data,
            igvm_get_buffer_size(ctx->cgs->igvm, data_handle),
            CGS_PAGE_TYPE_VMSA, vp_context->vp_index, errp);
        igvm_free_buffer(ctx->cgs->igvm, data_handle);
        if (result != 0) {
            if (!*errp) {
                error_setg(errp,
                           "IGVM: Failed to set CPU context: error_code=%d",
                           result);
            }
            return -1;
        }
    }
    return 0;
}

static int directive_parameter_area(struct igvm_context *ctx, int i,
                                    const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_PARAMETER_AREA *param_area =
        (const IGVM_VHS_PARAMETER_AREA *)header_data;
    IgvmParameterData *param_entry;

    param_entry = g_new0(IgvmParameterData, 1);
    param_entry->size = param_area->number_of_bytes;
    param_entry->index = param_area->parameter_area_index;
    param_entry->data = g_malloc0(param_entry->size);

    QTAILQ_INSERT_TAIL(&ctx->parameter_data, param_entry, next);
    return 0;
}

static int directive_parameter_insert(struct igvm_context *ctx, int i,
                                      const uint8_t *header_data, Error **errp)
{
    ERRP_GUARD();
    const IGVM_VHS_PARAMETER_INSERT *param =
        (const IGVM_VHS_PARAMETER_INSERT *)header_data;
    IgvmParameterData *param_entry;
    int result;
    void *region;

    QTAILQ_FOREACH(param_entry, &ctx->parameter_data, next)
    {
        if (param_entry->index == param->parameter_area_index) {
            region =
                igvm_prepare_memory(param->gpa, param_entry->size, i, errp);
            if (!region) {
                return -1;
            }
            memcpy(region, param_entry->data, param_entry->size);
            g_free(param_entry->data);
            param_entry->data = NULL;

            result = ctx->cgs->set_guest_state(param->gpa, region, param_entry->size,
                                          CGS_PAGE_TYPE_UNMEASURED, 0, errp);
            if (result != 0) {
                if (!*errp) {
                    error_setg(errp,
                               "IGVM: Failed to set guest state: error_code=%d",
                               result);
                }
                return -1;
            }
        }
    }
    return 0;
}

static int cmp_mm_entry(const void *a, const void *b)
{
    const IGVM_VHS_MEMORY_MAP_ENTRY *entry_a =
        (const IGVM_VHS_MEMORY_MAP_ENTRY *)a;
    const IGVM_VHS_MEMORY_MAP_ENTRY *entry_b =
        (const IGVM_VHS_MEMORY_MAP_ENTRY *)b;
    if (entry_a->starting_gpa_page_number < entry_b->starting_gpa_page_number) {
        return -1;
    } else if (entry_a->starting_gpa_page_number >
               entry_b->starting_gpa_page_number) {
        return 1;
    } else {
        return 0;
    }
}

static int directive_memory_map(struct igvm_context *ctx, int i,
                                const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_PARAMETER *param = (const IGVM_VHS_PARAMETER *)header_data;
    IgvmParameterData *param_entry;
    int max_entry_count;
    int entry = 0;
    IGVM_VHS_MEMORY_MAP_ENTRY *mm_entry;
    ConfidentialGuestMemoryMapEntry cgmm_entry;
    int retval = 0;

    /* Find the parameter area that should hold the memory map */
    QTAILQ_FOREACH(param_entry, &ctx->parameter_data, next)
    {
        if (param_entry->index == param->parameter_area_index) {
            max_entry_count =
                param_entry->size / sizeof(IGVM_VHS_MEMORY_MAP_ENTRY);
            mm_entry = (IGVM_VHS_MEMORY_MAP_ENTRY *)param_entry->data;

            retval = ctx->cgs->get_mem_map_entry(entry, &cgmm_entry, errp);
            while (retval == 0) {
                if (entry > max_entry_count) {
                    error_setg(
                        errp,
                        "IGVM: guest memory map size exceeds parameter area defined in IGVM file");
                    return -1;
                }
                mm_entry[entry].starting_gpa_page_number = cgmm_entry.gpa >> 12;
                mm_entry[entry].number_of_pages = cgmm_entry.size >> 12;

                switch (cgmm_entry.type) {
                case CGS_MEM_RAM:
                    mm_entry[entry].entry_type = MEMORY;
                    break;
                case CGS_MEM_RESERVED:
                    mm_entry[entry].entry_type = PLATFORM_RESERVED;
                    break;
                case CGS_MEM_ACPI:
                    mm_entry[entry].entry_type = PLATFORM_RESERVED;
                    break;
                case CGS_MEM_NVS:
                    mm_entry[entry].entry_type = PERSISTENT;
                    break;
                case CGS_MEM_UNUSABLE:
                    mm_entry[entry].entry_type = PLATFORM_RESERVED;
                    break;
                }
                retval = ctx->cgs->get_mem_map_entry(++entry, &cgmm_entry, errp);
            }
            if (retval < 0) {
                return retval;
            }
            /* The entries need to be sorted */
            qsort(mm_entry, entry, sizeof(IGVM_VHS_MEMORY_MAP_ENTRY),
                  cmp_mm_entry);

            break;
        }
    }
    return 0;
}

static int directive_vp_count(struct igvm_context *ctx, int i,
                              const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_PARAMETER *param = (const IGVM_VHS_PARAMETER *)header_data;
    IgvmParameterData *param_entry;
    uint32_t *vp_count;
    CPUState *cpu;

    QTAILQ_FOREACH(param_entry, &ctx->parameter_data, next)
    {
        if (param_entry->index == param->parameter_area_index) {
            vp_count = (uint32_t *)(param_entry->data + param->byte_offset);
            *vp_count = 0;
            CPU_FOREACH(cpu)
            {
                (*vp_count)++;
            }
            break;
        }
    }
    return 0;
}

static int directive_environment_info(struct igvm_context *ctx, int i,
                                      const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_PARAMETER *param = (const IGVM_VHS_PARAMETER *)header_data;
    IgvmParameterData *param_entry;
    IgvmEnvironmentInfo *environmental_state;

    QTAILQ_FOREACH(param_entry, &ctx->parameter_data, next)
    {
        if (param_entry->index == param->parameter_area_index) {
            environmental_state =
                (IgvmEnvironmentInfo *)(param_entry->data + param->byte_offset);
            environmental_state->memory_is_shared = 1;
            break;
        }
    }
    return 0;
}

static int directive_required_memory(struct igvm_context *ctx, int i,
                                     const uint8_t *header_data, Error **errp)
{
    ERRP_GUARD();
    const IGVM_VHS_REQUIRED_MEMORY *mem =
        (const IGVM_VHS_REQUIRED_MEMORY *)header_data;
    uint8_t *region;
    int result;

    if (mem->compatibility_mask & ctx->compatibility_mask) {
        region = igvm_prepare_memory(mem->gpa, mem->number_of_bytes, i, errp);
        if (!region) {
            return -1;
        }
        result = ctx->cgs->set_guest_state(mem->gpa, region, mem->number_of_bytes,
                                      CGS_PAGE_TYPE_REQUIRED_MEMORY, 0, errp);
        if (result < 0) {
            if (!*errp) {
                error_setg(errp,
                           "IGVM: Failed to set guest state: error_code=%d",
                           result);
            }
            return -1;
        }
    }
    return 0;
}

static int directive_snp_id_block(struct igvm_context *ctx, int i,
                                     const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_SNP_ID_BLOCK *igvm_id =
        (const IGVM_VHS_SNP_ID_BLOCK *)header_data;

    if (ctx->compatibility_mask & igvm_id->compatibility_mask) {
        if (ctx->id_block) {
            error_setg(errp, "IGVM: Multiple ID blocks encountered "
                             "in IGVM file.");
            return -1;
        }
        ctx->id_block = g_malloc0(sizeof(struct sev_id_block));
        ctx->id_auth = g_malloc0(sizeof(struct sev_id_authentication));

        memcpy(ctx->id_block->family_id, igvm_id->family_id,
               sizeof(ctx->id_block->family_id));
        memcpy(ctx->id_block->image_id, igvm_id->image_id,
               sizeof(ctx->id_block->image_id));
        ctx->id_block->guest_svn = igvm_id->guest_svn;
        ctx->id_block->version = 1;
        memcpy(ctx->id_block->ld, igvm_id->ld, sizeof(ctx->id_block->ld));

        ctx->id_auth->id_key_alg = igvm_id->id_key_algorithm;
        memcpy(ctx->id_auth->id_block_sig, &igvm_id->id_key_signature,
               sizeof(igvm_id->id_key_signature));

        ctx->id_auth->auth_key_algo = igvm_id->author_key_algorithm;
        memcpy(ctx->id_auth->id_key_sig, &igvm_id->author_key_signature,
               sizeof(igvm_id->author_key_signature));

        /*
         * SEV and IGVM public key structure population are slightly different.
         * See SEV Secure Nested Paging Firmware ABI Specification, Chapter 10.
         */
        *((uint32_t *)ctx->id_auth->id_key) = igvm_id->id_public_key.curve;
        memcpy(&ctx->id_auth->id_key[4], &igvm_id->id_public_key.qx, 72);
        memcpy(&ctx->id_auth->id_key[76], &igvm_id->id_public_key.qy, 72);

        *((uint32_t *)ctx->id_auth->author_key) =
            igvm_id->author_public_key.curve;
        memcpy(&ctx->id_auth->author_key[4], &igvm_id->author_public_key.qx,
               72);
        memcpy(&ctx->id_auth->author_key[76], &igvm_id->author_public_key.qy,
               72);
    }

    return 0;
}

static int initialization_guest_policy(struct igvm_context *ctx, int i,
                                     const uint8_t *header_data, Error **errp)
{
    const IGVM_VHS_GUEST_POLICY *guest =
        (const IGVM_VHS_GUEST_POLICY *)header_data;

    if (guest->compatibility_mask & ctx->compatibility_mask) {
        ctx->sev_policy = guest->policy;
    }
    return 0;
}

static int supported_platform_compat_mask(struct igvm_context *ctx,
                                               Error **errp)
{
    int32_t result;
    int i;
    IgvmHandle header_handle;
    IGVM_VHS_SUPPORTED_PLATFORM *platform;

    ctx->compatibility_mask = 0;

    result = igvm_header_count(ctx->cgs->igvm, HEADER_SECTION_PLATFORM);
    if (result < 0) {
        error_setg(errp,
                   "Invalid platform header count in IGVM file. Error code: %X",
                   result);
        return 0;
    }

    for (i = 0; i < (int)result; ++i) {
        IgvmVariableHeaderType typ =
            igvm_get_header_type(ctx->cgs->igvm, HEADER_SECTION_PLATFORM, i);
        if (typ == IGVM_VHT_SUPPORTED_PLATFORM) {
            header_handle =
                igvm_get_header(ctx->cgs->igvm, HEADER_SECTION_PLATFORM, i);
            if (header_handle < 0) {
                error_setg(errp,
                           "Invalid platform header in IGVM file. "
                           "Index: %d, Error code: %X",
                           i, header_handle);
                return 0;
            }
            platform =
                (IGVM_VHS_SUPPORTED_PLATFORM *)(igvm_get_buffer(ctx->cgs->igvm,
                                                                header_handle) +
                                                sizeof(
                                                    IGVM_VHS_VARIABLE_HEADER));
            /* Currently only support SEV-SNP. */
            if (platform->platform_type == SEV_SNP) {
                /*
                 * IGVM does not define a platform types of SEV or SEV_ES.
                 * Translate SEV_SNP into CGS_PLATFORM_SEV_ES and
                 * CGS_PLATFORM_SEV and let the cgs function implementations
                 * check whether each IGVM directive results in an operation
                 * that is supported by the particular derivative of SEV.
                 */
                if (ctx->cgs->check_support(
                        CGS_PLATFORM_SEV_SNP, platform->platform_version,
                        platform->highest_vtl, platform->shared_gpa_boundary) ||
                    ctx->cgs->check_support(
                        CGS_PLATFORM_SEV_ES, platform->platform_version,
                        platform->highest_vtl, platform->shared_gpa_boundary) ||
                    ctx->cgs->check_support(
                        CGS_PLATFORM_SEV, platform->platform_version,
                        platform->highest_vtl, platform->shared_gpa_boundary)) {
                    ctx->compatibility_mask = platform->compatibility_mask;
                    ctx->platform_type = platform->platform_type;
                    break;
                }
            }
            igvm_free_buffer(ctx->cgs->igvm, header_handle);
        }
    }
    if (ctx->compatibility_mask == 0) {
        error_setg(
            errp,
            "IGVM file does not describe a compatible supported platform");
        return -1;
    }
    return 0;
}

static int handle_policy(struct igvm_context *ctx, Error **errp)
{
    if (ctx->platform_type == SEV_SNP) {
        int id_block_len = 0;
        int id_auth_len = 0;
        if (ctx->id_block) {
            ctx->id_block->policy = ctx->sev_policy;
            id_block_len = sizeof(struct sev_id_block);
            id_auth_len = sizeof(struct sev_id_authentication);
        }
        return ctx->cgs->set_guest_policy(GUEST_POLICY_SEV, ctx->sev_policy,
                                          ctx->id_block, id_block_len,
                                          ctx->id_auth, id_auth_len, errp);
    }
    return 0;
}

int igvm_file_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    g_autofree uint8_t *buf = NULL;
    unsigned long len;
    g_autoptr(GError) gerr = NULL;

    if (!cgs->igvm_filename) {
        return 0;
    }

    if (!g_file_get_contents(cgs->igvm_filename, (gchar **)&buf, &len, &gerr)) {
        error_setg(errp, "Unable to load %s: %s", cgs->igvm_filename,
                   gerr->message);
        return -1;
    }

    if ((cgs->igvm = igvm_new_from_binary(buf, len)) < 0) {
        error_setg(errp, "Unable to parse IGVM file %s: %d", cgs->igvm_filename,
                   cgs->igvm);
        return -1;
    }

    return 0;
}

int igvm_process(ConfidentialGuestSupport *cgs, Error **errp)
{
    int32_t result;
    int i;
    IgvmParameterData *parameter;
    int retval = 0;
    struct igvm_context ctx;

    /*
     * If this is not a Confidential guest or no IGVM has been provided then
     * this is a no-op.
     */
    if (!cgs->igvm) {
        return 0;
    }

    memset(&ctx, 0, sizeof(struct igvm_context));
    QTAILQ_INIT(&ctx.parameter_data);
    ctx.cgs = cgs;

    /*
     * Check that the IGVM file provides configuration for the current
     * platform
     */
    if (supported_platform_compat_mask(&ctx, errp) != 0) {
        return -1;
    }

    result = igvm_header_count(cgs->igvm, HEADER_SECTION_DIRECTIVE);
    if (result < 0) {
        error_setg(
            errp, "Invalid directive header count in IGVM file. Error code: %X",
            result);
        return -1;
    }

    for (i = 0; i < (int)result; ++i) {
        IgvmVariableHeaderType type =
            igvm_get_header_type(cgs->igvm, HEADER_SECTION_DIRECTIVE, i);
        if (handle(type, &ctx, i, errp) < 0) {
            retval = -1;
            break;
        }
    }

    result = igvm_header_count(cgs->igvm, HEADER_SECTION_INITIALIZATION);
    if (result < 0) {
        error_setg(
            errp, "Invalid initialization header count in IGVM file. Error code: %X",
            result);
        return -1;
    }

    for (i = 0; i < (int)result; ++i) {
        IgvmVariableHeaderType type =
            igvm_get_header_type(cgs->igvm, HEADER_SECTION_INITIALIZATION, i);
        if (handle(type, &ctx, i, errp) < 0) {
            retval = -1;
            break;
        }
    }

    /*
     * Contiguous pages of data with compatible flags are grouped together in
     * order to reduce the number of memory regions we create. Make sure the
     * last group is processed with this call.
     */
    if (retval == 0) {
        retval = process_mem_page(&ctx, i, NULL, errp);
    }

    if (retval == 0) {
        retval = handle_policy(&ctx, errp);
    }

    /* Clean up the context */
    QTAILQ_FOREACH(parameter, &ctx.parameter_data, next)
    {
        g_free(parameter->data);
        parameter->data = NULL;
    }
    g_free(ctx.id_block);
    g_free(ctx.id_auth);

    return retval;
}

#endif
