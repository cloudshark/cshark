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

#include <sys/vfs.h>

#include <libubox/uloop.h>

#include "cshark.h"
#include "pcap.h"

struct uloop_fd ufd_pcap = { .cb = cshark_pcap_handle_packet_cb };
static char *filename = NULL;

struct pcap_timeval {
	bpf_int32 tv_sec; /* seconds */
	bpf_int32 tv_usec; /* microseconds */
};

struct pcap_sf_pkthdr {
	struct pcap_timeval ts; /* time stamp */
	bpf_u_int32 caplen; /* length of portion present */
	bpf_u_int32 len; /* length this packet (off wire) */
};

void cshark_pcap_manage_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *sp)
{
	struct cshark *cs = (struct cshark *) user;
	static int stop_writing = false;
	static unsigned long captured_size = 0;
	struct statfs result;

	if (stop_writing) return;

	/* no need to check on every packet so check on every 10th that comes along */
	if (cs->packets % 10 == 0) {
		if (statfs(filename, &result) < 0 ) {
			ERROR("unable to determine free disk space for '%s'\n", filename);
			stop_writing = true;
			uloop_end();
			return;
		}

		/* leave a bit less then 512K of disk space available */
		if ((result.f_bsize * result.f_bfree) < captured_size) {
			DEBUG("stopping capture due to low disk space\n");
			stop_writing = true;
			uloop_end();
			return;
		}
	}

	captured_size += header->len;

	cs->packets++;
	if (cs->limit_packets && (cs->limit_packets < cs->packets)) {
		uloop_end();
		return;
	}

	cs->caplen += header->caplen;
	if (cs->limit_caplen && (cs->limit_caplen < cs->caplen)) {
		uloop_end();
		return;
	}

	/* pcap_dump does not handle errors so make fixes here instead */

	struct pcap_sf_pkthdr sf_hdr;
	size_t num = 0;		

	sf_hdr.ts.tv_sec = header->ts.tv_sec;
	sf_hdr.ts.tv_usec = header->ts.tv_usec;
	sf_hdr.caplen = header->caplen;
	sf_hdr.len = header->len;

	num = fwrite(&sf_hdr, sizeof(sf_hdr), 1, (FILE *) cs->p_dumper);
	if (num != 1) {
		uloop_end();
		return;
	}

	num = fwrite(sp, header->caplen, 1, (FILE *) cs->p_dumper);
	if (num != 1) {
		uloop_end();
		return;
	}
}

void cshark_pcap_handle_packet_cb(struct uloop_fd *ufd, __unused unsigned int events)
{
	int rc;

	rc = pcap_dispatch(cshark.p, -1, cshark_pcap_manage_packet, (u_char *) &cshark);
	if (rc < 0) {
		uloop_end();
		return;
	}

	DEBUG("received '%d' packets\n", (int) cshark.packets);
	DEBUG("received '%d' bytes\n", (int) cshark.caplen);
}

int cshark_pcap_init(struct cshark *cs)
{
	int rc = -1;

	/* potential libpcap errors will end up here*/
	char e[PCAP_ERRBUF_SIZE];
	memset(e, 0, PCAP_ERRBUF_SIZE);

	/* open device in promiscuous mode */
	cs->p = pcap_open_live(cs->interface, cs->snaplen, 1, 0x0400, e);
	if (cs->p == NULL) {
		ERROR("pcap_open_live(): %s\n", e);
		goto exit;
	}

	if (cs->filter) {
		rc = pcap_compile(cs->p, &cs->p_bfp, cs->filter, 1, PCAP_NETMASK_UNKNOWN);
		if (rc == -1) {
			ERROR("pcap_compile(): could not parse filter\n");
			goto exit;
		}

		rc = pcap_setfilter(cs->p, &cs->p_bfp);
		if (rc == -1) {
			ERROR("pcap_setfilter(): could not parse filter\n");
			goto exit;
		}
	}

	cs->p_dumper = pcap_dump_open(cs->p, cs->filename);
	if (cs->p_dumper == NULL) {
		ERROR("pcap: could not open file for storing capture\n");
		rc = EXIT_FAILURE;
		goto exit;
	}

	/* we need to access this value in one of the callbacks */
	filename = cs->filename;

	/* set non-blocking state */
	rc = pcap_setnonblock(cs->p, 1, e);
	if (rc < 0) {
		ERROR("pcap_setnonblock(): %s\n", e);
		goto exit;
	}

	int socket;
	socket = pcap_get_selectable_fd(cs->p);
	if (socket < 0) {
		ERROR("pcap_get_selectable_fd(): invalid socket received\n");
		rc = -1;
		goto exit;
	}

	ufd_pcap.fd = socket;
	uloop_fd_add(&ufd_pcap, ULOOP_READ);

	rc = 0;
exit:
	return rc;
}

void cshark_pcap_done(struct cshark *cs)
{
	if (cs->p_dumper) {
		pcap_dump_close(cs->p_dumper);
		cs->p_dumper = NULL;
	}

	if (cs->p) {
		pcap_close(cs->p);
		cs->p = NULL;
	}
}
