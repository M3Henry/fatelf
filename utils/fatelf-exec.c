/**
 * FatELF; support multiple ELF binaries in one file.
 *
 * Please see the file LICENSE.txt in the source's root directory.
 *
 *  This file written by Henry W. Wilson.
 */

#define _GNU_SOURCE
#define FATELF_UTILS 1
#include "fatelf-utils.h"
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

static FATELF_record * xfind_matching_record(FATELF_record const *tgt, FATELF_header *header)
{
    for (uint8_t i = 0; i < header->num_records; i++)
	if (fatelf_record_matches(header->records + i, tgt))
		return header->records + i;

    xfail("Unable to find %s in FatElf records", fatelf_get_target_name(tgt, FATELF_WANT_EVERYTHING));
} // xfind_matching_record

int main(int argc, char *argv[], char *envp[])
{
    xfatelf_init(argc, (char const**)argv);
    if (argc < 2)
        xfail("USAGE: %s [--version] fatelf-file [args...]", argv[0]);

    int fd = xopen(argv[1], O_RDONLY | O_CLOEXEC, 0);
    FATELF_header *header = xread_fatelf_header(argv[1], fd);

    int self = xopen("/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
    FATELF_record self_elf;
    xread_elf_header(argv[0], self, 0, &self_elf);

    if (!self_elf.osabi) {
	struct utsname n;
	uname(&n);
	const fatelf_osabi_info *osabi = get_osabi_by_uname(n.sysname);
	if (!osabi)
	    xfail("fatelf-exec running on unknown OS ABI: %s", n.sysname);
	self_elf.osabi = osabi->id;
    }
    FATELF_record const *rec = xfind_matching_record(&self_elf, header);

    int outfd = memfd_create("ELF", MFD_CLOEXEC);
    if (outfd < 0)
        xfail("memfd_create");

    xcopyfile_range(argv[1], fd, "memfd:ELF", outfd, rec->offset, rec->size);

    fexecve(outfd, (argv + 1), envp);
    xfail("fexecve");
} // main

// end of fatelf-exec.c ...
