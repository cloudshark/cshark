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

#include <libubox/uloop.h>

#include "cshark.h"
#include "pcap.h"

struct uloop_fd ufd_pcap = { .cb = cshark_pcap_handle_packet_cb };

void cshark_pcap_manage_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *sp)
{
	struct cshark *cs = (struct cshark *) user;

	pcap_dump((u_char *)cs->p_dumper, header, sp);

	cs->packets++;
}

void cshark_pcap_handle_packet_cb(struct uloop_fd *ufd, __unused unsigned int events)
{
	int rc;

	rc = pcap_dispatch(cshark.p, -1, cshark_pcap_manage_packet, (u_char *) &cshark);
	if (rc < 0)
		return;

	DEBUG("received '%d' packets\n", cshark.packets);
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
