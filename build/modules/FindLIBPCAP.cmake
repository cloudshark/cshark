# LIBPCAP_FOUND - true if library and headers were found
# LIBPCAP_INCLUDE_DIRS - include directories
# LIBPCAP_LIBRARIES - library directories

find_package(PkgConfig)
pkg_check_modules(PC_LIBPCAP QUIET libpcap)

find_path(LIBPCAP_INCLUDE_DIR libpcap/pcap.h pcap.h
	HINTS ${PC_LIBPCAP_INCLUDEDIR} ${PC_LIBPCAP_INCLUDE_DIRS} PATH_SUFFIXES libpcap)

find_library(LIBPCAP_LIBRARY NAMES pcap libpcap
	HINTS ${PC_LIBPCAP_LIBDIR} ${PC_LIBPCAP_LIBRARY_DIRS})

set(LIBPCAP_LIBRARIES ${LIBPCAP_LIBRARY})
set(LIBPCAP_INCLUDE_DIRS ${LIBPCAP_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LIBPCAP DEFAULT_MSG LIBPCAP_LIBRARY LIBPCAP_INCLUDE_DIR)

mark_as_advanced(LIBPCAP_INCLUDE_DIR LIBPCAP_LIBRARY)
