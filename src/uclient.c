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

#include <dlfcn.h>

#include <libubox/uloop.h>

#include <json/json.h>

#include "cshark.h"
#include "config.h"
#include "uclient.h"

static struct ustream_ssl_ctx *ssl_ctx;
static const struct ustream_ssl_ops *ssl_ops;

static void cshark_uclient_read_data_cb(struct uclient *ucl)
{
	char buf[256];
	int len;
	json_object *json_obj = NULL, *obj;
	json_tokener *json_tok;
	enum json_tokener_error jerr;

	json_tok = json_tokener_new();

	do {
		len = uclient_read(ucl, buf, sizeof(buf));
		if (len == -1) {
			ERROR("error while reading response \n");
			goto exit;
		}
		if (len == 0) {
			DEBUG("done reading response\n");
			break;
		}

		json_obj = json_tokener_parse_ex(json_tok, buf, len);

	} while ((jerr = json_tokener_get_error(json_tok)) == json_tokener_continue);

	if (!json_obj || jerr != json_tokener_success) {
		ERROR("json stream contains invalid data\n");
		return;
	}

	json_bool exists = json_object_object_get_ex(json_obj, "id", &obj);
	if (!exists) goto exit;

	printf("... uploading completed!\n");
	printf("%s/captures/%s\n", config.url, json_object_get_string(obj));

exit:
	json_tokener_free(json_tok);
	json_object_put(json_obj);

	uloop_end();
}

static void cshark_uclient_eof_cb(struct uclient *ucl)
{
	uloop_end();
}

static void cshark_uclient_error_cb(struct uclient *ucl, int code)
{
	bool e = false;

        switch(code) {
		case UCLIENT_ERROR_CONNECT:
			printf("%s: connection failed\n", PROJECT_NAME);
			e = true;
			break;
		case UCLIENT_ERROR_SSL_INVALID_CERT:
			printf("%s: invalid SSL certificate\n", PROJECT_NAME);
			e = true;
			break;
		case UCLIENT_ERROR_SSL_CN_MISMATCH:
			printf("%s: server hostname does not match SSL certificate\n", PROJECT_NAME);
			e = true;
			break;
		default:
			break;
	}

	if (e) {
		uclient_disconnect(ucl);
		uloop_end();
	}
}

static const struct uclient_cb cb = {
	.data_read = cshark_uclient_read_data_cb,
	.data_eof = cshark_uclient_eof_cb,
	.error = cshark_uclient_error_cb,
};

static void cshark_ustream_ssl_init(void)
{
	void *dlh;

	dlh = dlopen("libustream-ssl." LIB_EXT, RTLD_LAZY | RTLD_LOCAL);
	if (!dlh)
		return;

	ssl_ops = dlsym(dlh, "ustream_ssl_ops");
	if (!ssl_ops)
		return;

	ssl_ctx = ssl_ops->context_new(false);

	if (config.ca)
		ssl_ops->context_add_ca_crt_file(ssl_ctx, config.ca);
}

int cshark_uclient_init(struct cshark *cs)
{
	int capture_length, len;
	char capture_length_str[32];
	char buf[BUFSIZ];
	char url[BUFSIZ];
	FILE *fd = NULL;
	int rc = -1;

	len = snprintf(url, BUFSIZ, "%s/api/v1/%s/upload", config.url, config.token);
	if (len < 0 || len >= BUFSIZ) {
		ERROR("url is invalid or too big\n");
		goto exit;
	}

	cshark_ustream_ssl_init();

	if (!strncmp(config.url, "https", 5) && !ssl_ctx) {
		ERROR("SSL support not available, please install ustream-ssl\n");
		goto exit;
	}

	cs->ucl = uclient_new(url, NULL, &cb);

	uclient_http_set_ssl_ctx(cs->ucl, ssl_ops, ssl_ctx, true);

	rc = uclient_connect(cs->ucl);
	if (rc) {
		ERROR("%s: could not connect to '%s'\n", PROJECT_NAME, url);
		goto exit;
	}

	rc = uclient_http_set_request_type(cs->ucl, "PUT");
	if (rc) {
		ERROR("uclient: could not set request type\n");
		goto exit;
	}

	fd = fopen(cs->filename, "rb");
	if (fd == NULL) {
		ERROR("uclient: could not open file '%s'\n", cs->filename);
		goto exit;
	}

	fseek(fd, 0L, SEEK_END);
	capture_length = ftell(fd);
	fseek(fd, 0L, SEEK_SET);

	snprintf(capture_length_str, 32, "%d", capture_length);
	rc = uclient_http_set_header(cs->ucl, "Content-Length", capture_length_str);
	if (rc) {
		ERROR("uclient: could not set header\n");
		goto exit;
	}

	while ((len = fread(buf, sizeof(char), BUFSIZ, fd)) != 0) {
		rc = uclient_write(cs->ucl, buf, len);
		if (rc != -1) {
			break;
		}
	}

	rc = uclient_request(cs->ucl);
	if (rc) {
		ERROR("uclient: request failed\n");
		goto exit;
	}

	rc = 0;
exit:
	if (fd)
		fclose(fd);

	return rc;
}

void cshark_uclient_done(struct cshark *cs)
{
	if (cs->ucl) {
		uclient_free(cs->ucl);
		cs->ucl = NULL;
	}
}
