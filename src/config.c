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

#include <stdlib.h>
#include <uci.h>
#include <string.h>
#include <libubox/blobmsg.h>
#include <uci_blob.h>

#include <libgen.h>
#include <sys/stat.h>

#include "config.h"

struct config config;

enum cshark_config {
	CSHARK_URL,
	CSHARK_TOKEN,
	CSHARK_CA,
	__CSHARK_MAX
};

const struct blobmsg_policy cshark_policy[__CSHARK_MAX] = {
	[CSHARK_URL] = { .name = "url", .type = BLOBMSG_TYPE_STRING },
	[CSHARK_TOKEN] = { .name = "token", .type = BLOBMSG_TYPE_STRING },
	[CSHARK_CA] = { .name = "ca", .type = BLOBMSG_TYPE_STRING }
};

const struct uci_blob_param_list config_attr_list = {
	.n_params = __CSHARK_MAX,
	.params = cshark_policy
};

int config_load(void)
{
	int rc;
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *conf = NULL;
	struct blob_attr *tb[__CSHARK_MAX], *c;
	static struct blob_buf buf;

	rc = uci_load(uci, "cshark", &conf);
	if (rc) goto exit;

	blob_buf_init(&buf, 0);

	struct uci_element *section_elem;
	uci_foreach_element(&conf->sections, section_elem) {
		struct uci_section *s = uci_to_section(section_elem);
		uci_to_blob(&buf, s, &config_attr_list);
	}

	blobmsg_parse(cshark_policy, __CSHARK_MAX, tb, blob_data(buf.head), blob_len(buf.head));

	if (!(c = tb[CSHARK_URL])) {
		rc = -1;
		goto exit;
	}
	snprintf(config.url, URL_MAX, "%s", blobmsg_get_string(c));

	/* we are adding '/' later in the code */
	if (config.url[strlen(config.url)] == '/') {
		config.url[strlen(config.url)] = 0;
	}

	if (!(c = tb[CSHARK_TOKEN])) {
		rc = -1;
		goto exit;
	}
	snprintf(config.token, TOKEN_MAX, "%s", blobmsg_get_string(c));

	/* ca option is optional */
	if (!(c = tb[CSHARK_CA])) {
		memset(config.ca, 0, PATH_MAX);
	} else {
		snprintf(config.ca, PATH_MAX, "%s", blobmsg_get_string(c));
	}

	rc = 0;
exit:
	blob_buf_free(&buf);
	uci_unload(uci, conf);
	uci_free_context(uci);

	return rc;
}
