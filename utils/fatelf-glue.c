/**
 * FatELF; support multiple ELF binaries in one file.
 *
 * Please see the file LICENSE.txt in the source's root directory.
 *
 *  This file written by Ryan C. Gordon.
 */

#define FATELF_UTILS 1
#include "fatelf-utils.h"

static struct spec
{
    char const* file;
    fatelf_osabi_info const* osabi;
} inputs[255];
static int n_inputs;

static int fatelf_glue(const char *out)
{
    const size_t struct_size = fatelf_header_size(n_inputs);
    FATELF_header *header = (FATELF_header *) xmalloc(struct_size);
    const int outfd = xopen(out, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    uint64_t offset = FATELF_DISK_FORMAT_SIZE(n_inputs);

    unlink_on_xfail = out;

    if (n_inputs == 0)
        xfail("Nothing to do.");

    // pad out some bytes for the header we'll write at the end...
    xwrite_zeros(out, outfd, (size_t) offset);

    header->magic = FATELF_MAGIC;
    header->version = FATELF_FORMAT_VERSION;
    header->num_records = n_inputs;

    for (int i = 0; i < n_inputs; i++)
    {
        const uint64_t binary_offset = align_to_page(offset);
        const char *fname = inputs[i].file;
        const int fd = xopen(fname, O_RDONLY, 0755);
        FATELF_record *record = &header->records[i];

        xread_elf_header(fname, fd, 0, record);
        record->offset = binary_offset;
        if (inputs[i].osabi)
            record->osabi = inputs[i].osabi->id;
        if (!record->osabi)
        {
            fatelf_osabi_info const *o = get_osabi_by_id(0);
            fprintf(stderr, "Warning: %s has ABI %s (%s). Consider overriding with --osabi\n", fname, o->name, o->desc);
        }
        // make sure we don't have a duplicate target.
        for (int j = 0; j < i; j++)
        {
            if (fatelf_record_matches(record, &header->records[j]))
                xfail("'%s' and '%s' are for the same target. %s", inputs[j].file, fname, get_osabi_by_id(record->osabi)->name);
        } // for

        // append this binary to the final file, padded to page alignment.
        xwrite_zeros(out, outfd, (size_t) (binary_offset - offset));
        record->size = xcopyfile(fname, fd, out, outfd);
        offset = binary_offset + record->size;

        // done with this binary!
        xclose(fname, fd);
    } // for

    // Write the actual FatELF header now...
    xwrite_fatelf_header(out, outfd, header);
    xclose(out, outfd);
    free(header);

    unlink_on_xfail = NULL;

    return 0;  // success.
} // fatelf_glue

int main(int argc, const char **argv)
{
    xfatelf_init(argc, argv);
    if (argc < 4)  // this could stand to use getopt(), later.
        xfail("USAGE: %s <out> [--osabi name] <bin1> [--osabi name] <bin2> [[--osabi name] bins...]", argv[0]);

    fatelf_osabi_info const* osabi = 0;

    for (int i = 2; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--osabi"))
        {
            if (++i == argc)
                xfail("--osabi requires an argument");
            osabi = get_osabi_by_name(argv[i]);
            if (!osabi)
                xfail("Unknown OS ABI '%s'", argv[i]);
            continue;
        }
        if (n_inputs > 255)
            xfail("Too many binaries (max is 255).");
        struct spec* input = inputs + n_inputs++;
        input->file = argv[i];
        input->osabi = osabi;
    }

    return fatelf_glue(argv[1]);
} // main

// end of fatelf-glue.c ...

