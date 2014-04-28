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

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

#include <libubox/uloop.h>
#include <libubox/uclient.h>

#include "config.h"
#include "cshark.h"
#include "pcap.h"
#include "uclient.h"

struct cshark cshark;

static void show_help()
{
	printf("usage: %s [-iwsk] [ expression ]\n\n%s", PROJECT_NAME, \
		"  -i  listen on interface\n" \
		"  -w  write the raw packets to specific file\n" \
		"  -s  snarf snaplen bytes of data\n" \
		"  -k  keep the file after uploading it to cloudshark.org\n" \
		"  -h  shows this help\n");
}

int main(int argc, char *argv[])
{
	int rc, c;
	int keep = 0;

	/* zero out main struct */
	memset(&cshark, 0, sizeof(cshark));

	/* preconfigure defaults */
	cshark.interface = "any";
	cshark.filename = NULL;
	cshark.snaplen = 65535;
	cshark.filter = NULL;

	openlog(PROJECT_NAME, LOG_PERROR | LOG_PID, LOG_DAEMON);

	while ((c = getopt(argc, argv, "i:w:s:kh")) != -1) {
		switch (c) {
			case 'i':
				cshark.interface = optarg;
				break;

			case 'w':
				cshark.filename = optarg;
				break;

			case 's':
				cshark.snaplen = atoi(optarg);
				if (!cshark.snaplen) cshark.snaplen = 65535;
				break;

			case 'k':
				keep = 1;
				break;

			case 'h':
				show_help();
				return EXIT_FAILURE;

			default:
				break;
		}
	}

	while (optind < argc) {
		asprintf(&cshark.filter, "%s %s", \
			cshark.filter ? cshark.filter : "", argv[optind]);
		optind++;
	}

	if (!cshark.filename) {
		cshark.filename = strdup("/tmp/cshark.pcap-XXXXXX");

		int fd = mkstemp(cshark.filename);
		if (fd == -1) {
			ERROR("unable to create dump file\n");
			return	EXIT_FAILURE;
		}
	}

	rc = config_load();
	if (rc) {
		ERROR("unable to load configuration\n");
		rc = EXIT_FAILURE;
		goto exit;
	}

	uloop_init();

	rc = cshark_pcap_init(&cshark);
	if (rc) {
		rc = EXIT_FAILURE;
		goto exit;
	}

	printf("capturing traffic to file: '%s' ...\n", cshark.filename);
	uloop_run();

	cshark_pcap_done(&cshark);

	rc = cshark_uclient_init(&cshark);
	if (rc) {
		rc = EXIT_FAILURE;
		goto exit;
	}

	printf("\nuploading capture ...\n");
	uloop_run();

	uloop_done();

	rc = EXIT_SUCCESS;

exit:
	cshark_pcap_done(&cshark);
	cshark_uclient_done(&cshark);
	if (!keep) remove(cshark.filename);

	return rc;
}
