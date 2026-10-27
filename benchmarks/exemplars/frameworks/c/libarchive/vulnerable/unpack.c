/* Unpack an uploaded archive into a user's workspace directory. */
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int copy_data(struct archive *ar, struct archive *aw) {
    const void *buff;
    size_t size;
    la_int64_t offset;
    for (;;) {
        int r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return ARCHIVE_OK;
        if (r < ARCHIVE_OK)
            return r;
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK)
            return ARCHIVE_FATAL;
    }
}

int unpack(const char *archive_path, const char *workspace) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;

    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_TIME);
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK)
        return 1;

    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        char dest[1024];
        snprintf(dest, sizeof(dest), "%s/%s", workspace, name);
        archive_entry_set_pathname(entry, dest); /* frame-expect: CWE-22 */
        if (archive_write_header(ext, entry) == ARCHIVE_OK)
            copy_data(a, ext);
        archive_write_finish_entry(ext);
    }
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s archive\n", argv[0]);
        return 2;
    }
    /* The workspace is the service's own directory; the archive is the upload. */
    return unpack(argv[1], "/srv/workspaces/current");
}
