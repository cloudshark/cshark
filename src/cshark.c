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
#include <sys/vfs.h>

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
	printf("usage: %s [-iwskTPSpvh] [ expression ]\n\n%s", PROJECT_NAME, \
		"  -i  listen on interface\n" \
		"  -w  write the raw packets to specific file\n" \
		"  -s  snarf snaplen bytes of data\n" \
		"  -k  keep the file after uploading it to cloudshark.org\n" \
		"  -T  stop capture after this many seconds have passed, use 0 for no timeout\n" \
		"  -P  stop capture after this many packets have been captured, use 0 for no limit\n" \
		"  -S  stop capture after this many bytes have been saved, use 0 for no limit\n" \
		"  -p  save pid to a file\n" \
		"  -v  shows version\n" \
		"  -h  shows this help\n");
}

static void dump_timeout_callback(struct uloop_timeout *t)
{
	DEBUG("timeout reached, stopping capture\n");
	uloop_end();
}

static uint64_t cshark_max_caplen( char *path )
{
        struct statfs result;

        if (statfs(path, &result) < 0 ) {
                ERROR("Unable to determine free disk space for %s\n", path);
                return 0;
        } else {
                /* Allow up to 50% of remaining space */
                return (uint64_t) (result.f_bsize * result.f_bfree * 0.5);
        }
}

int main(int argc, char *argv[])
{
	int rc, c;
	int keep = 0;
	uint64_t max_caplen;
	char *pid_filename = NULL;

	/* zero out main struct */
	memset(&cshark, 0, sizeof(cshark));

	/* preconfigure defaults */
	cshark.interface = "any";
	cshark.filename = NULL;
	cshark.snaplen = 65535;
	cshark.filter = NULL;
	cshark.packets = 0;
	cshark.limit_packets = 0;
	cshark.caplen = 0;
	cshark.limit_caplen = 0;

	openlog(PROJECT_NAME, LOG_PERROR | LOG_PID, LOG_DAEMON);

	while ((c = getopt(argc, argv, "i:w:s:T:P:S:p:kvh")) != -1) {
		switch (c) {
			case 'i':
				cshark.interface = optarg;
				break;

			case 'w':
				cshark.filename = strdup(optarg);
				if (!cshark.filename) {
					ERROR("not enough memory\n");
					rc = EXIT_FAILURE;
					goto exit;
				}
				break;

			case 's':
				cshark.snaplen = atoi(optarg);
				if (!cshark.snaplen) cshark.snaplen = 65535;
				break;

			case 'T':
			{
				struct uloop_timeout dump_timeout = {
					.cb = dump_timeout_callback
				};

				int dump_timeout_s = atoi(optarg);
				if (dump_timeout_s > 0)
					uloop_timeout_set(&dump_timeout, dump_timeout_s * 1000);

				break;
			}

			case 'P':
				cshark.limit_packets = atoi(optarg);
				break;

			case 'S':
				cshark.limit_caplen = atoi(optarg);
				break;

			case 'p':
			{
				pid_t pid = getpid();

				pid_filename = optarg;
				FILE *f = fopen(pid_filename, "w");
				if (!f) {
					fprintf(stderr, "Failed writing PID to '%s'\n", optarg);
					return EXIT_FAILURE;
				}

				fprintf(f, "%d\n", pid);

				fclose(f);
				sync();

				break;
			}

			case 'k':
				keep = 1;
				break;

			case 'v':
				printf("%s version %s\n", PROJECT_NAME, PROJECT_VERSION);
				return EXIT_FAILURE;

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

	rc = config_load();
	if (rc) {
		ERROR("unable to load configuration\n");
		rc = EXIT_FAILURE;
		goto exit;
	}

	if (!cshark.filename) {
		int len = 0;
		len = snprintf(cshark.filename, 0, "%s/cshark.pcap-XXXXXX", config.dir);

		cshark.filename = calloc(len + 1, sizeof(char));
		if (!cshark.filename) {
			ERROR("not enough memory\n");
			rc = EXIT_FAILURE;
			goto exit;
		}
		snprintf(cshark.filename, len + 1, "%s/cshark.pcap-XXXXXX", config.dir);

		int fd = mkstemp(cshark.filename);
		if (fd == -1) {
			ERROR("unable to create dump file\n");
			rc = EXIT_FAILURE;
			goto exit;
		}
	}

	/* Always set a max capture len to prevent filling up the disk/memory */
	max_caplen = cshark_max_caplen( cshark.filename );
	if ( !cshark.limit_caplen || cshark.limit_caplen > max_caplen ) {
		cshark.limit_caplen = max_caplen;
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
	free(cshark.filename);
	if (!keep) remove(cshark.filename);
	if (pid_filename) remove(pid_filename);

	return rc;
}

