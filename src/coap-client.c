/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2020 Ken Bannister
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_coap_client_sample, LOG_LEVEL_DBG);

#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>

#include <net/socket.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/tls_credentials.h>
#include <net/udp.h>
#include <net/coap.h>

#include "net_private.h"
#include "ca_certificate.h"

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define PEER_PORT 5684
#else
#define PEER_PORT 5683
#endif
#define MAX_COAP_MSG_LEN 256

/* CoAP socket fd */
static int sock;

struct pollfd fds[1];
static int nfds;

/* CoAP Options */
static const char * path_segs[] = { "a1r", "d1", "int" };
static const int pathlen = 3;

static void wait(void)
{
	if (poll(fds, nfds, -1) < 0) {
		LOG_ERR("Error in poll:%d", errno);
	}
}

static void prepare_fds(void)
{
	fds[nfds].fd = sock;
	fds[nfds].events = POLLIN;
	nfds++;
}

static int start_coap_client(void)
{
	int ret = 0;

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	ret = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK,
				psk,
				sizeof(psk));
	if (ret < 0) {
		LOG_ERR("Failed to register PSK: %d", ret);
    return ret;
	}
	ret = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK_ID,
				psk_id,
				sizeof(psk_id) - 1);
	if (ret < 0) {
		LOG_ERR("Failed to register PSK ID: %d", ret);
    return ret;
	}
#endif

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PEER_PORT);

	inet_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
		  &addr.sin_addr);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	sock = socket(addr.sin_family, SOCK_DGRAM, IPPROTO_DTLS_1_2);
#else
	sock = socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
#endif
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		LOG_ERR("Cannot connect to UDP remote : %d", errno);
		return -errno;
	}

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	sec_tag_t sec_tag_list[] = {
		PSK_TAG,
	};

	ret = setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_SEC_TAG_LIST option: %d", errno);
		ret = -errno;
	}

	ret = setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
			 TLS_PEER_HOSTNAME, sizeof(TLS_PEER_HOSTNAME));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_HOSTNAME option: %d", errno);
		ret = -errno;
	}
#endif

	prepare_fds();

	return 0;
}

static int process_simple_coap_reply(void)
{
	struct coap_packet reply;
	uint8_t *data;
	int rcvd;
	int ret;

	wait();

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	rcvd = recv(sock, data, MAX_COAP_MSG_LEN, MSG_DONTWAIT);
	if (rcvd == 0) {
		ret = -EIO;
		goto end;
	}

	if (rcvd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -errno;
		}

		goto end;
	}

	net_hexdump("Response", data, rcvd);

	ret = coap_packet_parse(&reply, data, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
	}

end:
	k_free(data);

	return ret;
}

static int send_simple_coap_request(uint8_t method)
{
	uint8_t payload[] = "1001";
	struct coap_packet request;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
			     1, COAP_TYPE_CON, 8, coap_next_token(),
			     method, coap_next_id());
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		goto end;
	}

	for (int i = 0; i < pathlen; i++) {
		r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					      path_segs[i], strlen(path_segs[i]));
		if (r < 0) {
			LOG_ERR("Unable add option to request");
			goto end;
		}
	}

	switch (method) {
	case COAP_METHOD_GET:
	case COAP_METHOD_DELETE:
		break;

	case COAP_METHOD_PUT:
	case COAP_METHOD_POST:
		r = coap_packet_append_payload_marker(&request);
		if (r < 0) {
			LOG_ERR("Unable to append payload marker");
			goto end;
		}

		r = coap_packet_append_payload(&request, (uint8_t *)payload,
					       sizeof(payload) - 1);
		if (r < 0) {
			LOG_ERR("Not able to append payload");
			goto end;
		}

		break;
	default:
		r = -EINVAL;
		goto end;
	}

	net_hexdump("Request", request.data, request.offset);

	r = send(sock, request.data, request.offset, 0);

end:
	k_free(data);

	return 0;
}

static int send_simple_coap_msgs_and_wait_for_reply(void)
{
	int r;

  /* Test CoAP POST method*/
  printk("\nCoAP client POST\n");
  r = send_simple_coap_request(COAP_METHOD_POST);
  if (r < 0) {
    return r;
  }

  r = process_simple_coap_reply();
  if (r < 0) {
    return r;
  }

	return 0;
}

void main(void)
{
	int r;

	LOG_INF("Start CoAP-client sample");
	r = start_coap_client();
	if (r < 0) {
		goto quit;
	}

  for (int i = 0; i < 3; i++) {
    r = send_simple_coap_msgs_and_wait_for_reply();
    if (r < 0) {
      goto quit;
    }
    k_sleep(K_SECONDS(3));
  }

	/* Close the socket */
	(void)close(sock);

	LOG_INF("Done");

	return;

quit:
	(void)close(sock);

	LOG_ERR("quit");
}
