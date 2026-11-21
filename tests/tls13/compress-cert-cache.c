/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32) || !defined(HAVE_ZLIB)

int main(int argc, char **argv)
{
	exit(77);
}

#else

#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "cert-common.h"
#include "utils.h"

#define PRIO "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3"
#define CHECK(X) assert((X) >= 0)

static pid_t child;
static unsigned cache_hits;

static void log_func(int level, const char *str)
{
	if (strstr(str, "certificate compression cache hit") != NULL)
		cache_hits++;
}

static int compressed_cert_callback(gnutls_session_t session, unsigned htype,
				    unsigned post, unsigned incoming,
				    const gnutls_datum_t *msg)
{
	if (incoming)
		*(unsigned *)gnutls_session_get_ptr(session) += 1;

	return 0;
}

static void client(int fd)
{
	int ret;
	unsigned status;
	unsigned compressed = 0;
	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_compression_method_t methods[] = { GNUTLS_COMP_ZLIB };

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_trust_mem(x509_cred, &ca3_cert,
						    GNUTLS_X509_FMT_PEM));
	CHECK(gnutls_init(&session, GNUTLS_CLIENT));
	CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				     x509_cred));
	CHECK(gnutls_priority_set_direct(session, PRIO, NULL));
	CHECK(gnutls_compress_certificate_set_methods(
		session, methods, sizeof(methods) / sizeof(methods[0])));

	gnutls_session_set_ptr(session, &compressed);
	gnutls_handshake_set_hook_function(
		session, GNUTLS_HANDSHAKE_COMPRESSED_CERTIFICATE_PKT,
		GNUTLS_HOOK_PRE, compressed_cert_callback);
	gnutls_transport_set_int(session, fd);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		fail("client: handshake failed: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	if (compressed == 0)
		fail("client: compressed certificate was not received\n");

	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0)
		fail("client: certificate verification failed: %s\n",
		     gnutls_strerror(ret));
	if (status)
		fail("client: certificate verification failed\n");

	gnutls_bye(session, GNUTLS_SHUT_WR);

cleanup:
	close(fd);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
}

static void server(int fd, gnutls_certificate_credentials_t x509_cred)
{
	int ret;
	unsigned compressed = 0;
	gnutls_session_t session;
	gnutls_compression_method_t methods[] = { GNUTLS_COMP_ZLIB };

	CHECK(gnutls_init(&session, GNUTLS_SERVER));
	CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				     x509_cred));
	CHECK(gnutls_priority_set_direct(session, PRIO, NULL));
	CHECK(gnutls_compress_certificate_set_methods(
		session, methods, sizeof(methods) / sizeof(methods[0])));

	gnutls_session_set_ptr(session, &compressed);
	gnutls_handshake_set_hook_function(
		session, GNUTLS_HANDSHAKE_COMPRESSED_CERTIFICATE_PKT,
		GNUTLS_HOOK_PRE, compressed_cert_callback);
	gnutls_transport_set_int(session, fd);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0)
		fail("server: handshake failed: %s\n", gnutls_strerror(ret));

	if (gnutls_compress_certificate_get_selected_method(session) !=
	    GNUTLS_COMP_ZLIB)
		fail("server: zlib certificate compression was not selected\n");

	gnutls_bye(session, GNUTLS_SHUT_WR);
	close(fd);
	gnutls_deinit(session);
}

void doit(void)
{
	int ret;
	int fd[2];
	unsigned round;
	gnutls_certificate_credentials_t server_cred;

	signal(SIGPIPE, SIG_IGN);
	CHECK(gnutls_global_init());
	gnutls_global_set_log_function(log_func);
	gnutls_global_set_log_level(4);

	CHECK(gnutls_certificate_allocate_credentials(&server_cred));
	CHECK(gnutls_certificate_set_x509_key_mem(
		server_cred, &server_ca3_localhost_cert_chain,
		&server_ca3_key, GNUTLS_X509_FMT_PEM));

	for (round = 0; round < 2; round++) {
		cache_hits = 0;

		ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
		if (ret < 0) {
			perror("socketpair");
			exit(1);
		}

		child = fork();
		if (child < 0) {
			perror("fork");
			exit(1);
		}

		if (child == 0) {
			close(fd[0]);
			client(fd[1]);
			exit(0);
		}

		close(fd[1]);
		server(fd[0], server_cred);

		if (round == 0 && cache_hits != 0)
			fail("server: cache hit before the cache was populated\n");
		if (round == 1 && cache_hits == 0)
			fail("server: compressed certificate cache was not used\n");

		waitpid(child, &ret, 0);
		check_wait_status(ret);
	}

	gnutls_certificate_free_credentials(server_cred);
	gnutls_global_deinit();
}

#endif /* _WIN32 */
