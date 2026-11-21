#!/bin/sh

# Copyright (C) 2026 Red Hat, Inc.
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

: ${srcdir=.}
: ${SERV=../src/gnutls-serv${EXEEXT}}
: ${CLI=../src/gnutls-cli${EXEEXT}}
: ${OPENSSL=openssl}

if ! test -x "${SERV}" || ! test -x "${CLI}"; then
	exit 77
fi

if test "${WINDIR}" != ""; then
	exit 77
fi

if ! command -v "${OPENSSL}" >/dev/null 2>&1; then
	exit 77
fi

if ! "${OPENSSL}" s_client -help 2>&1 | grep -q -- '-no_rx_cert_comp' ||
   ! "${OPENSSL}" s_server -help 2>&1 | grep -q -- '-cert_comp'; then
	exit 77
fi

if ! "${CLI}" --list 2>/dev/null | grep -q 'COMP-ZLIB'; then
	exit 77
fi

if ! "${CLI}" --help 2>&1 | grep -q -- '--compress-cert'; then
	exit 77
fi

. "${srcdir}/scripts/common.sh"

testdir=`create_testdir compress-cert-interop`
KEY="${testdir}/key.pem"
CERT="${testdir}/cert.pem"
TRACE="${testdir}/trace.txt"
LOGFILE="${testdir}/log.txt"
PRIO="NORMAL:-VERS-ALL:+VERS-TLS1.3"

"${OPENSSL}" req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
	-keyout "${KEY}" -out "${CERT}" -subj "/CN=localhost" \
	>/dev/null 2>&1 || exit 1

echo "Checking OpenSSL client against GnuTLS server"
eval "${GETPORT}"
SERV="${SERV} -q"
launch_server --echo --x509keyfile "${KEY}" --x509certfile "${CERT}" \
	--compress-cert zlib --priority "${PRIO}"
PID=$!
wait_server "${PID}"

printf '\n' | timeout 15 "${OPENSSL}" s_client -connect "127.0.0.1:${PORT}" -tls1_3 \
	-servername localhost -trace -msgfile "${TRACE}" \
	>"${LOGFILE}" 2>&1
rc=$?
kill "${PID}" 2>/dev/null
wait "${PID}" 2>/dev/null
if test "${rc}" != 0; then
	cat "${LOGFILE}"
	fail "" "OpenSSL client handshake failed"
fi
if ! grep -q "CompressedCertificate" "${TRACE}"; then
	fail "" "OpenSSL client did not receive a compressed certificate"
fi
if ! grep -q "compress_certificate(27)" "${TRACE}"; then
	fail "" "OpenSSL client did not send or negotiate compress_certificate"
fi

echo "Checking GnuTLS client against OpenSSL server"
eval "${GETPORT}"
"${OPENSSL}" s_server -accept "${PORT}" -cert "${CERT}" -key "${KEY}" \
	-tls1_3 -www -cert_comp -trace -msgfile "${TRACE}" \
	>"${LOGFILE}" 2>&1 &
PID=$!
wait_for_port "${PORT}"
if test $? != 0; then
	kill "${PID}" 2>/dev/null
	fail "" "OpenSSL server did not start"
fi

printf 'GET / HTTP/1.0\r\n\r\n' | timeout 15 "${CLI}" --insecure --compress-cert zlib \
	--priority "${PRIO}" -p "${PORT}" localhost \
	>"${LOGFILE}" 2>&1
rc=$?
kill "${PID}" 2>/dev/null
wait "${PID}" 2>/dev/null
if test "${rc}" != 0; then
	cat "${LOGFILE}"
	fail "" "GnuTLS client handshake failed"
fi
if ! grep -q "CompressedCertificate" "${TRACE}"; then
	fail "" "OpenSSL server did not send a compressed certificate"
fi
if ! grep -q "compress_certificate(27)" "${TRACE}"; then
	fail "" "GnuTLS client did not negotiate compress_certificate"
fi

exit 0
