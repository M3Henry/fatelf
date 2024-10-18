cmake_minimum_required(VERSION 3.5.0)
project(FatELF VERSION 1.0.0)

include(CheckSymbolExists)
include(GNUInstallDirs)

execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE GITVERSION_RC
    OUTPUT_VARIABLE FATELF_VERSION
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    include(FindPkgConfig)
    pkg_check_modules(libbsd REQUIRED IMPORTED_TARGET libbsd-overlay)
    link_libraries(PkgConfig::libbsd)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    add_definitions(-pipe -fsigned-char -Wall -Werror)
endif()

add_definitions(-DAPPID=fatelf)
add_definitions(-DAPPREV="${FATELF_VERSION}")

include_directories(include)

add_library(fatelf-utils OBJECT utils/fatelf-utils.c)

macro(add_fatelf_executable_src _NAME _SRC)
    add_executable(${_NAME} utils/${_SRC})
    target_link_libraries(${_NAME} fatelf-utils)
    install(TARGETS ${_NAME} RUNTIME)
endmacro()

macro(add_fatelf_executable _NAME)
    add_fatelf_executable_src(${_NAME} ${_NAME}.c)
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
check_symbol_exists(mkostemp stdlib.h MKOSTEMP)
check_symbol_exists(fexecve unistd.h FEXECVE)
if(MEMFD AND FEXECVE AND EXISTS /proc/self/exe)
    add_fatelf_executable(fatelf-exec)

    find_program(BINFMT systemd-binfmt PATHS /usr/lib/systemd)
    if(BINFMT)
        configure_file(fatelf.conf.in fatelf.conf)
        install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LIBDIR}/binfmt.d)
        install(FILES ${CMAKE_BINARY_DIR}/fatelf.conf DESTINATION ${CMAKE_INSTALL_LIBDIR}/binfmt.d/)
    endif()
elseif(MKOSTEMP)
    add_fatelf_executable_src(fatelf-exec fatelf-exec-openbsd.c)
endif()

set(CPACK_PACKAGE_CONTACT a@example.com)

list(APPEND CPACK_GENERATOR TGZ)

find_program(DPKG dpkg)
if(DPKG)
    list(APPEND CPACK_GENERATOR DEB)
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()

find_program(RPMBUILD rpmbuild)
if(RPMBUILD)
    list(APPEND CPACK_GENERATOR RPM)
endif()

include(CPack)

# end of CMakeLists.txt ...

