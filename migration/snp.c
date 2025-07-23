/*
 * QEMU SEV-SNP confidential machine migration
 *
 * Authors:
 *  Jakub Růžička <jakub.ruzicka@matfyz.cz>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu-file.h"
#include "qemu/main-loop.h"
#include "io/channel-socket.h"
#include "snp.h"
#include "trace.h"
#include "qapi/error.h"

static SnpMigrationState current_snp_migration;

static void write_status_register(uint8_t value) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + STATUS_REGISTER_OFFSET;
    uint8_t buf[1] = {value};
    cpu_physical_memory_write(pa, buf, 1);
}

static uint8_t read_status_register(void) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + STATUS_REGISTER_OFFSET;
    uint8_t buf[1] = {0};
    cpu_physical_memory_read(pa, buf, 1);
    return buf[0];
}

static void write_data_register(uint8_t value) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + DATA_REGISTER_OFFSET;
    uint8_t buf[1] = {value};
    cpu_physical_memory_write(pa, buf, 1);
}

static uint8_t read_data_register(void) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + DATA_REGISTER_OFFSET;
    uint8_t buf[1] = {0};
    cpu_physical_memory_read(pa, buf, 1);
    return buf[0];
}

static void read_page_buffer(uint8_t *buffer) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + DATA_BUFFER_OFFSET;
    cpu_physical_memory_read(pa, buffer, DATA_BUFFER_SIZE);
}

static void write_page_buffer(uint8_t *buffer, size_t size) {
    SnpMigrationState *s = &current_snp_migration;
    uint64_t pa = s->migration_page_addr + DATA_BUFFER_OFFSET;
    cpu_physical_memory_write(pa, buffer, size);
}

static void
*snp_process_migration_incoming(void *opaque) {
    SnpMigrationState *s = opaque;
    QEMUFile *f = s->migration_stream;
    write_status_register(SNP_MIGRATION_STATUS_INCOMING);
    /* Setting data_register to SNP_MIGRATION_DATA_READ in order to start with a
     * known state of data register and allow writing fist data. Otherwise
     * deadlock is possible as the loop below waits for data_register to
     * contain SNP_MIGRATION_DATA_READ value in order to not override data that
     * SVSM did not yet processed.
     */
    write_data_register(SNP_MIGRATION_DATA_READ);
    uint64_t header = qemu_get_be64(f);
    while (header != SNP_MIGRATION_FLAG_COMPLETED) {
        switch (header) {
            case SNP_MIGRATION_FLAG_DATA:
                uint8_t buffer[DATA_BUFFER_SIZE] = {0};
                qemu_get_buffer(f, buffer, DATA_BUFFER_SIZE);
                uint8_t data;
                // Wait for the latest written page to be processed.
                do {
                    data = read_data_register();
                } while (data != SNP_MIGRATION_DATA_READ);
                write_page_buffer(buffer, DATA_BUFFER_SIZE);
                write_data_register(SNP_MIGRATION_DATA_READY);
                break;;
            default:
                qemu_log("Unknown header %ld:", header);
        }
        header = qemu_get_be64(f);
    }
    write_status_register(SNP_MIGRATION_STATUS_COMPLETED);// FIXME: only for debugging purposes, should be deleted in future.
    qemu_fclose(f);
    for(int i = 0; i < s->channels_len; i++) {
        object_unref(OBJECT(s->channels[i]));
    }
    return NULL;
}

static void
*mock_snp_process_migration(void *opaque) {
    write_data_register(SNP_MIGRATION_DATA_READ);
    write_status_register(SNP_MIGRATION_STATUS_RUNNING);
    uint8_t status;
    do {
        status = read_status_register();
        if (read_data_register() == SNP_MIGRATION_DATA_READY) {
            write_data_register(SNP_MIGRATION_DATA_READ);
        }
    } while (status != SNP_MIGRATION_STATUS_COMPLETED);
    return 0;
}

void snp_just_for_test(int64_t migration_page_addr) {
    // Only mocks the sending
    SnpMigrationState *state = &current_snp_migration;
    state->migration_page_addr = migration_page_addr;

    QemuThread thread;
    qemu_thread_create(&thread, "snp_worker", mock_snp_process_migration, state, QEMU_THREAD_JOINABLE);
}


static void
*snp_process_migration(void *opaque) {
    SnpMigrationState *s = opaque;
    QEMUFile *f = s->migration_stream;
    /* Set the data_register to a known state before starting the migration */
    write_data_register(SNP_MIGRATION_DATA_READ);
    write_status_register(SNP_MIGRATION_STATUS_RUNNING);

    uint8_t status;
    do {
        status = read_status_register();
        if (read_data_register() == SNP_MIGRATION_DATA_READY) {
            uint8_t buffer[DATA_BUFFER_SIZE] = {0};
            read_page_buffer(buffer);
            write_data_register(SNP_MIGRATION_DATA_READ);

            qemu_put_be64(f, SNP_MIGRATION_FLAG_DATA);
            qemu_put_buffer(f, buffer, DATA_BUFFER_SIZE);
        }
    } while (status != SNP_MIGRATION_STATUS_COMPLETED);
    qemu_put_be64(f, SNP_MIGRATION_FLAG_COMPLETED);
    qemu_fflush(f);
    uint64_t transferred = qemu_file_transferred(f);
    qemu_log("Bytes transferred: %ld\n", transferred);
    qemu_fclose(f);
    for(int i = 0; i < s->channels_len; i++) {
        object_unref(OBJECT(s->channels[i]));
    }
    return NULL;
}

void snp_migrate_socket(SocketAddress *saddr, Error **errp) {
    QIOChannelSocket *sioc = qio_channel_socket_new();
    if (qio_channel_socket_connect_sync(sioc, saddr, errp) < 0) {
        error_report("Connection to the destinatino socket failed");
        return;
    }
    QIOChannel *ioc = QIO_CHANNEL(sioc);
    QEMUFile *f = qemu_file_new_output(ioc);
    if (!f) {
        error_report("Failed to create QEMUFile from channel");
        return;
    }
    SnpMigrationState *state = &current_snp_migration;
    state->migration_stream = f;
    state->channels[0] = ioc;
    state->channels_len = 1;

    QemuThread thread;
    qemu_thread_create(&thread, "snp_worker", snp_process_migration, state, QEMU_THREAD_JOINABLE);
}

void snp_migrate_socket_incoming(SocketAddress *saddr, Error **errp) 
{
    QIOChannelSocket *listener = qio_channel_socket_new();

    if (qio_channel_socket_listen_sync(listener, saddr, 1, errp) < 0) {
        error_report("Listening for migration on socket failed");
        return;
    }

    QIOChannelSocket *sioc = qio_channel_socket_accept(listener, errp);
    if (!sioc) {
        return;
    }

    QIOChannel *ioc = QIO_CHANNEL(sioc);
    QEMUFile *f = qemu_file_new_input(ioc);
    if (!f) {
        error_report("Failed to create QEMUFile from channel");
        return;
    }
    SnpMigrationState *state = &current_snp_migration;
    state->migration_stream = f;
    state->channels[0] = ioc;
    state->channels[1] = listener;
    state->channels_len = 2;

    QemuThread thread;
    qemu_thread_create(&thread, "snp_worker", snp_process_migration_incoming, state, QEMU_THREAD_JOINABLE);
}


void snp_migrate(MigrationChannelList *channels, int64_t migration_page_addr, bool incoming, Error **errp){
    MigrationAddress *addr = NULL;

    if (!channels) {
        error_setg(errp, "Channel list must be non-empty");
        return;
    }

    if (channels) {
        /* To verify that Migrate channel list has only item */
        if (channels->next) {
            error_setg(errp, "Channel list has more than one entries");
            return;
        }
        addr = channels->value->addr;
    }
    SnpMigrationState *state = &current_snp_migration;
    state->migration_page_addr = migration_page_addr;
    state->incoming = incoming;

    if (addr->transport == MIGRATION_ADDRESS_TYPE_SOCKET) {
        SocketAddress *saddr = &addr->u.socket;
        if (saddr->type == SOCKET_ADDRESS_TYPE_INET ||
            saddr->type == SOCKET_ADDRESS_TYPE_UNIX ||
            saddr->type == SOCKET_ADDRESS_TYPE_VSOCK) {
            if (incoming) {
                snp_migrate_socket_incoming(saddr, errp);
            } else {
                snp_migrate_socket(saddr, errp);
            }
        } else if (saddr->type == SOCKET_ADDRESS_TYPE_FD) {
            error_setg(errp, "fd is currently not implemented");
        }
#ifdef CONFIG_RDMA
    } else if (addr->transport == MIGRATION_ADDRESS_TYPE_RDMA) {
        error_setg(errp, "rdma is currently not implemented");
#endif
    } else if (addr->transport == MIGRATION_ADDRESS_TYPE_EXEC) {
        error_setg(errp, "exec is currently not implemented");
    } else if (addr->transport == MIGRATION_ADDRESS_TYPE_FILE) {
        error_setg(errp, "file is currently not implemented");
    } else {
        error_setg(errp, "unknown migration protocol");
    }
}

