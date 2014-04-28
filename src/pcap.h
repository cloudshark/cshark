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

#ifndef __CSHARK_PCAP_H__
#define __CSHARK_PCAP_H__

#include <pcap.h>

#include "cshark.h"

void cshark_pcap_manage_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *sp);
void cshark_pcap_handle_packet_cb(struct uloop_fd *ufd, __unused unsigned int events);

int cshark_pcap_init(struct cshark *cs);
void cshark_pcap_done(struct cshark *cs);

extern struct uloop_fd ufd_pcap;

#endif /* __CSHARK_PCAP_H__ */
