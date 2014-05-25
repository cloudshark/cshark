/*
 * Author: Luka Perkov <luka.perkov@sartura.hr>
 *
 * Copyright (C) 2014, QA Cafe, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * For more information see the project website [1].
 *
 * [1] https://www.cloudshark.org/
 */

#ifndef __CSHARK_H__
#define __CSHARK_H__

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <syslog.h>

#include <pcap.h>

#include <libubox/uclient.h>

#define PROJECT_NAME "cshark"
#define PROJECT_VERSION "v0.1"

struct cshark {
	char *interface;
	char *filename;
	int snaplen;
	char *filter;

	pcap_t *p;
	pcap_dumper_t *p_dumper;
	struct bpf_program p_bfp;

	uint64_t packets;
	uint64_t limit_packets;

	uint64_t caplen;
	uint64_t limit_caplen;

	struct uclient *ucl;
};

extern struct cshark cshark;

#ifdef WITH_DEBUG
#define DEBUG(fmt, ...) do { \
		fprintf(stderr, "%s: %s(%d): " fmt, PROJECT_NAME, __func__, __LINE__, ## __VA_ARGS__); \
	} while (0)
#else
#define DEBUG( ... )
#endif

#define LOG(fmt, ...) do { \
		syslog(0, fmt, ## __VA_ARGS__); \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
	} while (0)

#define ERROR(fmt, ...) do { \
		syslog(0, fmt, ## __VA_ARGS__); \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
	} while (0)


#ifndef __unused
#define __unused __attribute__((unused))
#endif

#ifdef __APPLE__
#define LIB_EXT "dylib"
#else
#define LIB_EXT "so"
#endif

#endif /* __CSHARK_H__ */
