# LIBUBOX_FOUND - true if library and headers were found
# LIBUBOX_INCLUDE_DIRS - include directories
# LIBUBOX_LIBRARIES - library directories

find_package(PkgConfig)
pkg_check_modules(PC_LIBUBOX QUIET libubox)

find_path(LIBUBOX_INCLUDE_DIR libubox/uloop.h
	HINTS ${PC_LIBUBOX_INCLUDEDIR} ${PC_LIBUBOX_INCLUDE_DIRS} PATH_SUFFIXES libubox)

find_library(LIBUBOX_LIBRARY NAMES ubox libubox
	HINTS ${PC_LIBUBOX_LIBDIR} ${PC_LIBUBOX_LIBRARY_DIRS})

set(LIBUBOX_LIBRARIES ${LIBUBOX_LIBRARY})
set(LIBUBOX_INCLUDE_DIRS ${LIBUBOX_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LIBUBOX DEFAULT_MSG LIBUBOX_LIBRARY LIBUBOX_INCLUDE_DIR)

mark_as_advanced(LIBUBOX_INCLUDE_DIR LIBUBOX_LIBRARY)
