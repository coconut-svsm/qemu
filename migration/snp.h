/*
 * QEMU SEV-SNP confidential machine migration
 *
 * Authors:
 *  Jakub Růžička <jakub.ruzicka@matfyz.cz>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef MIGRATION_SNP_H
#define MIGRATION_SNP_H

#include "migration/migration.h"

// Used in communication with SVSM
#define SNP_MIGRATION_STATUS_NOT_STARTED 0x0
#define SNP_MIGRATION_STATUS_INCOMING 0x1
#define SNP_MIGRATION_STATUS_RUNNING 0x2
#define SNP_MIGRATION_STATUS_COMPLETED 0x3

#define SNP_MIGRATION_DATA_READY 0x4
#define SNP_MIGRATION_DATA_READ 0x5

// Used in communication with the other QEMU
#define SNP_MIGRATION_FLAG_DATA 0x5
#define SNP_MIGRATION_FLAG_COMPLETED 0x6

#define STATUS_REGISTER_OFFSET 0x0
#define DATA_REGISTER_OFFSET 0x1
#define DATA_BUFFER_OFFSET 0x800
#define DATA_BUFFER_SIZE 0x800

struct SnpMigrationState { 
    bool incoming;
    QEMUFile *migration_stream;
    uint64_t migration_page_addr;

    int channels_len; // Store them to free them at the end 
    void *channels[]; // Store them to free them at the end 
};

void snp_just_for_test(int64_t migration_page_addr);
void snp_migrate(MigrationChannelList *channels, int64_t migration_page_addr, bool incoming, Error **errp);
void snp_migrate_socket(SocketAddress *saddr, Error **errp);
void snp_migrate_socket_incoming(SocketAddress *saddr, Error **errp);

#endif
