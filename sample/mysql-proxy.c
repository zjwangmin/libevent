/*
  This example code shows how to write an (optionally encrypting) SSL proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "util-internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "openssl-compat.h"

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;
static int use_wrapper = 1;

static SSL_CTX *ssl_in_ctx = NULL;
static int cc = 1;

#define MAX_OUTPUT (512*1024)
#define CA_CERT_FILE "cacert.pem"
#define SERVER_CERT_FILE "server.crt"
#define SERVER_KEY_FILE "server.key"

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);
static void do_ssl_in_out(evutil_socket_t in_fd, struct bufferevent *out_fd);

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len, nLen = 0, i;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	
	printf("Received %zu bytes\n", len);
    	printf("----- data ----\n");
	char *data = evbuffer_pullup(src, -1);
	for(i = 0; i < len; i++)
		printf("%c", data[i]);
	printf("\n");

	if (!partner) {
		printf("return to some bev\n");
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, readcb, drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}

	if(cc == 2){
		bufferevent_disable(bev, EV_WRITE);
		bufferevent_disable(partner, EV_READ);
		do_ssl_in_out(bufferevent_getfd(bev), partner);
	}
	if(cc++ == 1000000)
		cc = 3;
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			unsigned long err;
			while ((err = (bufferevent_get_openssl_error(bev)))) {
				const char *msg = (const char*)
				    ERR_reason_error_string(err);
				const char *lib = (const char*)
				    ERR_lib_error_string(err);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
				fprintf(stderr,
					"%s in1 %s\n", msg, lib);
#else
				const char *func = (const char*)
				    ERR_func_error_string(err);
				fprintf(stderr,
				    "%s in2 %s %s\n", msg, lib, func);
#endif
			}
			if (errno)
				perror("connection error");
		}

		if (partner) {
			/* Flush all pending data */
			readcb(bev, ctx);

			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    eventcb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
}

static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fputs("   le-proxy <listen-on-addr> <connect-to-addr>\n", stderr);
	fputs("Example:\n", stderr);
	fputs("   le-proxy 127.0.0.1:8888 1.2.3.4:80\n", stderr);

	exit(1);
}

static SSL_CTX * evssl_init(void)
{
    SSL_CTX  *server_ctx;

    /* Initialize the OpenSSL library */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
	printf("ssl init...\n");
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_server_method());

    if (! SSL_CTX_use_certificate_chain_file(server_ctx, "cert") ||
        ! SSL_CTX_use_PrivateKey_file(server_ctx, "pkey", SSL_FILETYPE_PEM)) {
        puts("Couldn't read 'pkey' or 'cert' file.  To generate a key\n"
           "and self-signed certificate, run:\n"
           "  openssl genrsa -out pkey 2048\n"
           "  openssl req -new -key pkey -out cert.req\n"
           "  openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert");
        return NULL;
    }
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

    return server_ctx;
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_out, *b_in;
	/* Create two linked bufferevent objects: one to connect, one for the
	 * new connection */
	b_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	
	assert(b_in && b_out);

	if (bufferevent_socket_connect(b_out, (struct sockaddr*)&connect_to_addr, connect_to_addrlen)<0) {
		perror("bufferevent_socket_connect");
		bufferevent_free(b_out);
		bufferevent_free(b_in);
		return;
	}

	cc = 1;

	bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
	bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

	bufferevent_enable(b_in, EV_READ|EV_WRITE);
	bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

static void
do_ssl_in_out(evutil_socket_t in_fd, struct bufferevent *out_fd)
{
	struct bufferevent *b_out, *b_in;
	SSL *ssl_in = SSL_new(ssl_in_ctx);
	b_in = bufferevent_openssl_socket_new(base, in_fd, ssl_in, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	
	SSL_CTX *ssl_out_ctx = SSL_CTX_new(SSLv23_client_method());
	SSL *ssl_out = SSL_new(ssl_out_ctx);
	struct bufferevent *b_ssl = bufferevent_openssl_filter_new(base, out_fd, ssl_out, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (!b_ssl) {
		perror("Bufferevent_openssl_new");
		bufferevent_free(b_out);
		bufferevent_free(b_in);
		return;
	}
	b_out = b_ssl;

	bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
	bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

	bufferevent_enable(b_in, EV_READ|EV_WRITE);
	bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

int
main(int argc, char **argv)
{
	int i;
	int socklen;

	struct evconnlistener *listener;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("signal()");
		return 1;
	}

	if (argc < 3)
		syntax();

	for (i=1; i < argc; ++i) {
		if (argv[i][0] == '-') {
			syntax();
		} else
			break;
	}

	if (i+2 != argc)
		syntax();

	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(argv[i],
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		int p = atoi(argv[i]);
		struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
		if (p < 1 || p > 65535)
			syntax();
		sin->sin_port = htons(p);
		sin->sin_addr.s_addr = htonl(0x7f000001);
		sin->sin_family = AF_INET;
		socklen = sizeof(struct sockaddr_in);
	}

	memset(&connect_to_addr, 0, sizeof(connect_to_addr));
	connect_to_addrlen = sizeof(connect_to_addr);
	printf("argv[i+1]:%s argv[i+0]:%s\n", argv[i+1], argv[i+0]);
	if (evutil_parse_sockaddr_port(argv[i+1], (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0)
		syntax();

	SSL_CTX *ctx = evssl_init();
	ssl_in_ctx = ctx;
    	if (ctx == NULL)
        	return 1;
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}


	listener = evconnlistener_new_bind(base, accept_cb, ctx, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (! listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);

	return 0;
}
