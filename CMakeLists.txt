cmake_minimum_required(VERSION 3.0.0)
project(FatELF)

include(CheckSymbolExists)
include(GNUInstallDirs)

execute_process(
    COMMAND git rev-list HEAD~..
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE GITVERSION_RC
    OUTPUT_VARIABLE FATELF_VERSION
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
)


if(CMAKE_COMPILER_IS_GNUCC)
    add_definitions(-pipe -fsigned-char -Wall -Werror)
endif()

add_definitions(-DAPPID=fatelf)
add_definitions(-DAPPREV="${FATELF_VERSION}")

include_directories(include)

add_library(fatelf-utils STATIC utils/fatelf-utils.c)

macro(add_fatelf_executable _NAME)
    add_executable(${_NAME} utils/${_NAME}.c)
    target_link_libraries(${_NAME} fatelf-utils)
    install(TARGETS ${_NAME} RUNTIME DESTINATION bin)
endmacro()

add_fatelf_executable(fatelf-glue)
add_fatelf_executable(fatelf-info)
add_fatelf_executable(fatelf-extract)
add_fatelf_executable(fatelf-replace)
add_fatelf_executable(fatelf-remove)
add_fatelf_executable(fatelf-verify)
add_fatelf_executable(fatelf-split)
add_fatelf_executable(fatelf-validate)

set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(memfd_create sys/mman.h MEMFD)
check_symbol_exists(fexecve unistd.h FEXECVE)
if(MEMFD AND FEXECVE AND EXISTS /proc/self/exe)
    add_fatelf_executable(fatelf-exec)

    find_program(BINFMT systemd-binfmt PATHS /usr/lib/systemd)
    if(BINFMT)
        configure_file(fatelf.conf.in fatelf.conf)
        install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LIBDIR}/binfmt.d)
        install(FILES ${CMAKE_BINARY_DIR}/fatelf.conf DESTINATION ${CMAKE_INSTALL_LIBDIR}/binfmt.d/)
    endif()
endif()

# end of CMakeLists.txt ...

