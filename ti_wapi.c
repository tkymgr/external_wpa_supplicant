/***************************************************************************
**+----------------------------------------------------------------------+**
**|                                ****                                  |**
**|                                ****                                  |**
**|                                ******o***                            |**
**|                          ********_///_****                           |**
**|                           ***** /_//_/ ****                          |**
**|                            ** ** (__/ ****                           |**
**|                                *********                             |**
**|                                 ****                                 |**
**|                                  ***                                 |**
**|                                                                      |**
**|     Copyright (c) 1998 - 2010 Texas Instruments Incorporated         |**
**|                        ALL RIGHTS RESERVED                           |**
**|                                                                      |**
**| Permission is hereby granted to licensees of Texas Instruments       |**
**| Incorporated (TI) products to use this computer program for the sole |**
**| purpose of implementing a licensee product based on TI products.     |**
**| No other rights to reproduce, use, or disseminate this computer      |**
**| program, whether in part or in whole, are granted.                   |**
**|                                                                      |**
**| TI makes no representation or warranties with respect to the         |**
**| performance of this computer program, and specifically disclaims     |**
**| any responsibility for any damages, special or consequential,        |**
**| connected with the use of this program.                              |**
**|                                                                      |**
**+----------------------------------------------------------------------+**/
/*
 * ti_wapi.c
 *
 */

#include <sys/stat.h>

#include "includes.h"
#include "ti_wapi.h"
#include "common.h"
#include "config.h"
#include "os.h"
#include "sha256.h"
#include "wpa_supplicant_i.h"
#include "wpa_supplicant.h"
#include "l2_packet.h"
#include "defs.h"
#include "gem.h"
#include "base64.h"
#include "ec.h"
#include "crypto.h"
#include <openssl/pem.h>
#include "keystore_get.h"
#include <openssl/bn.h>

#define WAPI_IE_MIN_LEN 22           /* minimal size when all suites are present*/


/* expansion strings to be used in key derivation process */
#define WAPI_EXPANSION_PSK_BK "preshared key expansion for authentication and key negotiation"
#define WAPI_EXPANSION_PSK_BK_LEN 62

#define WAPI_EXPANSION_BK_UCAST "pairwise key expansion for unicast and additional keys and nonce"
#define WAPI_EXPANSION_BK_UCAST_LEN 64

#define WAPI_EXPANSION_NMK "multicast or station key expansion for station unicast and multicast and broadcast"
#define WAPI_EXPANSION_NMK_LEN 82

#define WAPI_EXPANSION_EC_BK "base key expansion for key and additional nonce"
#define WAPI_EXPANSION_EC_BK_LEN 47
static int wapi_get_fromKeyStorage(const char* key, char* value);

static const u8 WAPI_CIPHER_SUITE_SMS4[] = { 0x00, 0x14, 0x72, 1 };
static const u8 WAPI_AUTH_SUITE_CERTIFICATE[] = { 0x00, 0x14, 0x72, 1 };
static const u8 WAPI_AUTH_SUITE_PSK[] = { 0x00, 0x14, 0x72, 2 };
static const u8 WAPI_ECDH_PARAMS[] = {0x06,0x09,0x2A,0x81,0x1C,0xD7,0x63,0x01,0x01,0x02,0x01};
static const u8 WAPI_SIGNATURE_ALG[] = {0x00,0x10,0x01,0x01,0x01,0x00,0x0B,0x06,0x09,0x2A,0x81,0x1C,0xD7,0x63,0x01,0x01,0x02,0x01};

/*test*/
#define SHA256_MAC_LEN 32

extern void hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		      const u8 *addr[], const size_t *len, u8 *mac);
extern void hmac_sha256(const u8 *key, size_t key_len, const u8 *data,
		 size_t data_len, u8 *mac);
extern void sha256_prf(const u8 *key, size_t key_len, const char *label,
	      const u8 *data, size_t data_len, u8 *buf, size_t buf_len);

/*test*/

int wapi_retrieve_cert(struct wpa_supplicant *wpa_s);
/**
 * Returns an OUI sequence as a bitfield for authentication method
 * @s: string to decode. should be at least 4 byte long
 */
int wapi_auth_selector_to_bitfield(const u8 *s)
{
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (os_memcmp(s, WAPI_AUTH_SUITE_CERTIFICATE, WAPI_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_WAPI_CERT;

	if (os_memcmp(s, WAPI_AUTH_SUITE_PSK, WAPI_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_WAPI_PSK;

	wpa_printf(MSG_WAPI, "WAPI %s: unknown authentication suite selector", __func__);
	return 0;
}

/**
 * returns an OUI sequence as a bitfield for cipher method
 * @s: string to decode. should be at least 4 byte long
 */
static int wapi_cipher_selector_to_bitfield(const u8 *s)
{
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (os_memcmp(s, WAPI_CIPHER_SUITE_SMS4, WAPI_SELECTOR_LEN) == 0)
		return WPA_CIPHER_SMS4;
	wpa_printf(MSG_WAPI, "WAPI %s: unknown cipher suite selector", __func__);
	return 0;
}


/**
 * encodes an IE from AKM suite, unicast suite, multicast suite
 * @wapi_ie: buffer big enough to hold ie
 * @wapi_ie_len: length of buffer. holds length of generated ie after execution
 * @akm_suite: bitfield for supported akm suites
 * @unicast_cipher: bitfield for supported unicast ciphers
 * @multicast_cipher: bitfield for supported multicast ciphers
 */
static int wapi_gen_ie(u8 *wapi_ie, size_t *wapi_ie_len,
			      int akm_suite, int unicast_cipher, int multicast_cipher)
{
	u8 *pos = wapi_ie;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	if (*wapi_ie_len < WAPI_IE_MIN_LEN) {
		wpa_printf(MSG_WAPI, "WAPI %s: ie len too short %lu", __func__,
				(unsigned long) *wapi_ie_len);
		return -1;
	}

	*pos = WAPI_INFO_ELEM; /* 68 */
	++pos;

	++pos; /* skip length. we'll fill it in the end */

	WPA_PUT_LE16(pos, WAPI_VERSION); /* version */
	pos += 2;

	if ((akm_suite & WPA_KEY_MGMT_WAPI_PSK) && (akm_suite & WPA_KEY_MGMT_WAPI_CERT)) {
		WPA_PUT_LE16(pos, 2);  /* akm count */
		pos += 2;
	}
	else if (akm_suite) {
		WPA_PUT_LE16(pos, 1);  /* akm count */
		pos += 2;
	}
	if (akm_suite & WPA_KEY_MGMT_WAPI_CERT) {
		os_memcpy(pos, WAPI_AUTH_SUITE_CERTIFICATE, WAPI_SELECTOR_LEN);
		pos += WAPI_SELECTOR_LEN;
	}
	if (akm_suite & WPA_KEY_MGMT_WAPI_PSK) {
		os_memcpy(pos, WAPI_AUTH_SUITE_PSK, WAPI_SELECTOR_LEN);
		pos += WAPI_SELECTOR_LEN;
	}

	WPA_PUT_LE16(pos, 1);  /* unicast cipher count */
	pos += 2;
	os_memcpy(pos, WAPI_CIPHER_SUITE_SMS4, WAPI_SELECTOR_LEN);
	pos += WAPI_SELECTOR_LEN;

	os_memcpy(pos, WAPI_CIPHER_SUITE_SMS4, WAPI_SELECTOR_LEN);
	pos += WAPI_SELECTOR_LEN;  /* multicast cipher count */

	WPA_PUT_LE16(pos, 0);  /* capabilities */
	pos += 2;

	WPA_PUT_LE16(pos, 0);  /* BKID count */
	pos += 2;

	*(wapi_ie + 1) = (pos-wapi_ie-2);
	*wapi_ie_len = pos-wapi_ie;

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}


/**
 * decode byte array into struct wapi_ie
 * @wapi_ie_buf: buffer containing ie
 * @wapi_ie_len: length of buffer
 * @ie: space to decode ie to
 */
int wapi_parse_ie(const u8 *wapi_ie_buf, size_t wapi_ie_len,
		struct wapi_ie *ie)
{
	const u8 *pos, *end;
	int i, count;

	wpa_hexdump(MSG_WAPI, "WAPI wapi_parse_ie - Got IE",wapi_ie_buf,wapi_ie_len);

	if (wapi_ie_len < WAPI_IE_MIN_LEN) {
		wpa_printf(MSG_WAPI, "WAPI %s: ie len too short %lu", __func__,
				(unsigned long) wapi_ie_len);
		return -1;
	}

	if (wapi_ie_len-2 != *(wapi_ie_buf+1)) {
		wpa_printf(MSG_WAPI, "WAPI %s: ie len mismatch %lu", __func__,
				(unsigned long) wapi_ie_len);
		return -1;
	}

	os_memset(ie, 0, sizeof(*ie));

	pos = wapi_ie_buf;
	end = pos + wapi_ie_len;

	ie->id = (u8) *pos++;
	ie->length = (u8) *pos++;

	ie->version = WPA_GET_LE16(pos);
	pos += 2;

	if (ie->version != WAPI_VERSION) {
		wpa_printf(MSG_WAPI, "WAPI %s: malformed ie or unknown version", __func__);
		return -1;
	}

	count = WPA_GET_LE16(pos);
	pos += 2;

	/* wpa_printf(MSG_WAPI, "WAPI wapi: akm suite count = %d, pos=%x, end=%x", count, pos, end ); */

	if (count == 0) {
		wpa_printf(MSG_WAPI, "WAPI %s: akm suite count = 0, ", __func__);
		return -1;
	}
	for (i = 0; i<count; ++i) {
		if (pos + WAPI_SELECTOR_LEN > end) {
			wpa_printf(MSG_WAPI, "WAPI %s: buffer is not long enough 1", __func__);
			return -1;
		}
		ie->akm_suite |= wapi_auth_selector_to_bitfield(pos);
		pos += WAPI_SELECTOR_LEN;
	}

	count = WPA_GET_LE16(pos);
	pos += 2;

	if (count == 0) {
		wpa_printf(MSG_WAPI, "WAPI %s: unicast cipher suite count = 0, ", __func__);
		return -1;
	}
	for (i = 0; i<count; ++i) {
		if (pos + WAPI_SELECTOR_LEN > end) {
			wpa_printf(MSG_WAPI, "WAPI %s: buffer is not long enough 2", __func__);
			return -1;
		}

		ie->unicast_suite |= wapi_cipher_selector_to_bitfield(pos);
		pos += WAPI_SELECTOR_LEN;

	}

	if (pos + WAPI_SELECTOR_LEN > end) {
		wpa_printf(MSG_WAPI, "WAPI %s: buffer is not long enough 3", __func__);
		return -1;
	}
	ie->multicast_suite |= wapi_cipher_selector_to_bitfield(pos);
	pos += WAPI_SELECTOR_LEN;

	ie->capabilities = WPA_GET_LE16(pos);
	pos += 2;

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}

/**
 * convert subtype number to string
 */
static const char * wapi_subtype2str(wapi_msg_subtype subtype) {
	switch (subtype) {
	case WAPI_SUBTYPE_PRE_AUTH_START: return "Pre-Authentication Start";
	case WAPI_SUBTYPE_ST_STAKEY_REQ: return "STAKey Request";
	case WAPI_SUBTYPE_AUTH_ACTIVACTION: return "Authentication Activation";
	case WAPI_SUBTYPE_ACCESS_AUTH_REQ: return "Access Authentication Request";
	case WAPI_SUBTYPE_ACCESS_AUT_RESP: return "Access Authentication Response";
	case WAPI_SUBTYPE_CERT_AUTH_REQ: return "Certificate Authentication Request";
	case WAPI_SUBTYPE_CERT_AUTH_RES: return "Certificate Authentication Response";
	case WAPI_SUBTYPE_UKEY_NEGO_REQ: return "Unicast Key Negotiation Request";
	case WAPI_SUBTYPE_UKEY_NEGO_RES: return "Unicast Key Negotiation Response";
	case WAPI_SUBTYPE_UKEY_NEGO_CONFIRM: return "Unicast Key Negotiation Confirmation";
	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE: return "Multicast key/STAKey Announcement";
	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE_RES: return "Multicast key/STAKey Announcement Response";
	}
	return "UNKNOWN MESSAGE SUBTYPE";
}




/**
 * WAPI Key derivation code (an hmac chain)
 *
 * @text: indicates the input text of the key derivation algorithm;
 * @text_len: indicates the length of the input text (in octet);
 * @key: indicates the input key of the key derivation algorithm;
 * @key_len: indicates the length of the input key (in octet);
 * @output: indicates the output of the key derivation algorithm;
 * @length: indicates the length of the output of the key derivation algorithm (in octet).
 */
void wapi_kd_hmac_sha256(const u8 *text,size_t text_len,const u8 *key,
			size_t key_len,	u8 *output,size_t length) {
	int i;
	u8 buffer[SHA256_DIGEST_SIZE];

	for(i=0;length/SHA256_DIGEST_SIZE;i++,length-=SHA256_DIGEST_SIZE) {

		hmac_sha256(key, key_len, text, text_len, &output[i*SHA256_DIGEST_SIZE]);
		text=&output[i*SHA256_DIGEST_SIZE];
		text_len=SHA256_DIGEST_SIZE;
	}
	if(length>0) {
		hmac_sha256(key,key_len,text,text_len,buffer);
		os_memcpy(&output[i*SHA256_DIGEST_SIZE], buffer, length);
	}

}

/**
 * Concatenate several buffers into one buffer
 * @elements: num of elements
 * @addr: an array containing the addresses of the buffers
 * @len: an array containing the lengths of the buffers
 * @buffer: a buffer to hold the result
 */
static void wapi_construct_buffer(int elements, const u8 *addr[],
		const size_t *len, u8 *buffer) {
	int i;
	u8 *pos = buffer;

	for (i = 0; i<elements; ++i) {
		os_memcpy(pos, addr[i], len[i]);
		pos += len[i];
	}
}


/**
 * Handles unicast key negotiation request.
 */
static int wapi_answer_ukey_req(struct wpa_supplicant *wpa_s, struct wapi_msg *msg) {
	/* 2*ETH_ALEN || challenge1 || challenge2 || expansion */
	u8 buffer[2*ETH_ALEN + 2*WAPI_CHALLENGE_LEN +
	          WAPI_EXPANSION_BK_UCAST_LEN];
	struct wapi_sm *sm = wpa_s->wapi;

	const u8 *addr[4];
	size_t len[4];
	u8 *encoded_msg;
	size_t encoded_msg_len;
	struct wapi_msg reply;
	u8 bkid[WAPI_BKID_LEN];

	if (sm->state != WAPI_STATE_DONE)
		wapi_supplicant_set_state(wpa_s, WPA_4WAY_HANDSHAKE);

	/* generate ASUE challenge */
	wpa_printf(MSG_WAPI, "WAPI %s: generating challenge",__func__);
	if (sm->new_challenge) {
		if (hostapd_get_rand(sm->asue_challenge, WAPI_CHALLENGE_LEN)) {
			wpa_printf(MSG_WAPI, "WAPI %s: cannot generate random number ", __func__);
			return -1;
		}
		sm->new_challenge = 0;
	}

	if (sm->cur_ssid && sm->cur_ssid->wapi_psk &&
		(sm->cur_ssid->key_mgmt & WPA_KEY_MGMT_WAPI_PSK)) {
		/* generate BK from passphrase if wasn't generated from certificate auth. */
		if (sm->cur_ssid->wapi_key_type == WAPI_PSK_MODE_ASCII) {
			wpa_printf(MSG_WAPI, "WAPI %s: using ASCII PSK '%s' to generate BK ",__func__,
					sm->cur_ssid->wapi_psk);

			wapi_kd_hmac_sha256((const u8*) WAPI_EXPANSION_PSK_BK,
					WAPI_EXPANSION_PSK_BK_LEN, (u8*)sm->cur_ssid->wapi_psk,
					strlen((const char *)sm->cur_ssid->wapi_psk),sm->bk,
					WAPI_BK_LEN);
		}
		else {
			int wapi_psk_hex_len;
			char* wapi_psk_hex = os_malloc(WAPI_MAX_PSK_HEX_LEN);
			if (!wapi_psk_hex){
				wpa_printf(MSG_WAPI, "WAPI %s: cannot allocate for wapi_psk_hex", __func__);
				return -1;
			}
			BIGNUM *parsed = BN_new();
			if (!parsed){
				wpa_printf(MSG_WAPI, "WAPI %s: cannot create BIGNUM", __func__);
				os_free(wapi_psk_hex);
				return -1;
			}
			// Convert the passwd to big number
			if (!BN_hex2bn(&parsed, sm->cur_ssid->wapi_psk)) {
				wpa_printf(MSG_WAPI, "WAPI %s: provided string does not contain a valid hex number",__func__);
				BN_free(parsed);
				os_free(wapi_psk_hex);
				return -1;
			}
			memset(wapi_psk_hex, 0x00, WAPI_MAX_PSK_HEX_LEN);
			// Convert big number to hex password. Write to new wapi_psk_hex variable
			// as the sm->cur_ssid->wapi_psk variable will be overwritten otherwise.
			wapi_psk_hex_len = BN_bn2bin(parsed, wapi_psk_hex);
			wpa_printf(MSG_WAPI, "WAPI %s: using HEX PSK to generate BK",__func__);
			wpa_hexdump(MSG_WAPI, "PSK HEX", wapi_psk_hex, wapi_psk_hex_len);

			wapi_kd_hmac_sha256((const u8*) WAPI_EXPANSION_PSK_BK,
					WAPI_EXPANSION_PSK_BK_LEN, wapi_psk_hex,
					wapi_psk_hex_len,sm->bk,
					WAPI_BK_LEN);
			os_free(wapi_psk_hex);
			wapi_psk_hex = NULL;
			BN_free(parsed);
		}
		wpa_hexdump(MSG_WAPI, "WAPI BK", sm->bk, WAPI_BK_LEN);
	}
	else
		wpa_printf(MSG_WAPI, "WAPI %s: using certificate to generate BK ",__func__);

	wapi_kd_hmac_sha256(msg->addid, 2*ETH_ALEN, sm->bk, WAPI_BK_LEN, bkid, WAPI_BKID_LEN);
	if (os_memcmp(msg->bkid, bkid, WAPI_BKID_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: BKID doesn't match calculated BKID", __func__);
		return -1;
	}
	else
		wpa_printf(MSG_WAPI, "WAPI %s: BKID matches",__func__);

	/* generate USK from BK, ASUE/AE challaneges, ADDID & expansion string */
	addr[0] = msg->addid;
	len[0] = 2*ETH_ALEN;
	addr[1] = msg->ae_challenge;
	len[1] = WAPI_CHALLENGE_LEN;
	addr[2] = sm->asue_challenge;
	len[2] = WAPI_CHALLENGE_LEN;
	addr[3] = (u8*) WAPI_EXPANSION_BK_UCAST;
	len[3] = WAPI_EXPANSION_BK_UCAST_LEN;

	wapi_construct_buffer(4, addr, len, buffer);

	wapi_kd_hmac_sha256(buffer,sizeof(buffer),sm->bk, WAPI_BK_LEN,
			(u8 *)&sm->usk, sizeof(sm->usk));

	wpa_hexdump(MSG_WAPI, "WAPI uek", sm->usk.uek, 16);
	wpa_hexdump(MSG_WAPI, "WAPI uck", sm->usk.uck, 16);
	wpa_hexdump(MSG_WAPI, "WAPI kck", sm->usk.kck, 16);
	wpa_hexdump(MSG_WAPI, "WAPI kek", sm->usk.kek, 16);


	wpa_hexdump(MSG_WAPI, "WAPI AE Challenge", msg->ae_challenge, WAPI_CHALLENGE_LEN);
	wpa_hexdump(MSG_WAPI, "WAPI ASUE Challenge", sm->asue_challenge, WAPI_CHALLENGE_LEN);
	wpa_hexdump(MSG_WAPI, "WAPI Next AE Challenge", sm->usk.challenge_seed, WAPI_CHALLENGE_LEN);

	/* create reply to AE */
	os_memset(&reply, 0, sizeof(reply));

	os_memcpy(reply.addid, msg->addid, ETH_ALEN*2);
	os_memcpy(reply.ae_challenge, msg->ae_challenge, WAPI_CHALLENGE_LEN);
	os_memcpy(reply.asue_challenge, sm->asue_challenge, WAPI_CHALLENGE_LEN);
	os_memcpy(&reply.flag, &(msg->flag), sizeof(reply.flag));
	os_memcpy(&reply.uskid, &(msg->uskid), sizeof(&reply.uskid));

	if (wapi_parse_ie(sm->ie_assoc, sm->ie_assoc_len, &reply.wapi_ie))
		return -1;
	/* os_memcpy(&reply.wapi_ie, &sm->ie, sizeof(reply.wapi_ie)); */

	os_memcpy(reply.kck, sm->usk.kck, WAPI_KCK_LEN);
	os_memcpy(reply.bkid, msg->bkid, WAPI_BKID_LEN);
	reply.header.subtype = WAPI_SUBTYPE_UKEY_NEGO_RES;
	os_memcpy(&reply.header.pkt_seq, &msg->header.pkt_seq,
		  sizeof(reply.header.pkt_seq));

	wpa_printf(MSG_WAPI, "WAPI %s: Sending unicast negotiation response",__func__);
	if (wapi_encode_msg(sm, &reply, &encoded_msg, &encoded_msg_len,NULL)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error encoding message", __func__);
		return -1;
	}
	wpa_hexdump(MSG_WAPI, "WAPI unicast nego. dump", encoded_msg, encoded_msg_len);
	if (wapi_tx_wai(wpa_s, sm->bssid, encoded_msg, encoded_msg_len)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error sending message", __func__);
		return -1;
	}
	os_free(encoded_msg);


#ifdef TI_WAPI
	wpa_printf(MSG_WAPI, "WAPI %s: setting key with keyidx %d", __func__, msg->uskid & WAPI_USKID_KEYID);

	if (wpa_drv_set_key(wpa_s, WPA_ALG_WAPI, sm->bssid, msg->uskid & WAPI_USKID_KEYID, 1,
			NULL, 0, (u8 *)&sm->usk, WAPI_UEK_LEN + WAPI_UCK_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error setting key", __func__);
		return -1;
	}
#else
	wpa_printf(MSG_WAPI, "WAPI %s: key wasn't set!", __func__);
#endif

	sm->state = WAPI_STATE_USKNEGOTIATING;
	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}


/*int wapi_isequal_ie(struct wapi_ie *ie1, struct wapi_ie *ie2) {
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	return ie1->akm_suite == ie2->akm_suite &&
		ie1->capabilities == ie2->capabilities &&
		ie1->multicast_suite == ie2->multicast_suite &&
		ie1->unicast_suite == ie2->unicast_suite;
}*/


/**
 * Handles unicast key negotiation confirmation
 */
int wapi_process_ukey_confirm(struct wpa_supplicant *wpa_s, struct wapi_msg *msg,
		const u8 mac[WAPI_MAC_LEN]) {
	struct wapi_sm *sm = wpa_s->wapi;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	if (os_memcmp(sm->asue_challenge, msg->asue_challenge,
			WAPI_CHALLENGE_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: asue challenge doesn't match challenge"
				" from Unicast Key Negotiation Response message", __func__);
		wpa_hexdump(MSG_WAPI, "WAPI current  asue challange", msg->asue_challenge, WAPI_CHALLENGE_LEN);
		wpa_hexdump(MSG_WAPI, "WAPI previous asue challange", sm->asue_challenge, WAPI_CHALLENGE_LEN);
		return -1;
	}
	if (os_memcmp(msg->msg_auth_code, mac, WAPI_MAC_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: calculated MAC doesn't match "
				"MAC from message ", __func__);
		wpa_hexdump(MSG_WAPI, "WAPI MAC from msg  ", msg->msg_auth_code, WAPI_MAC_LEN);
		wpa_hexdump(MSG_WAPI, "WAPI calculated MAC", mac, WAPI_MAC_LEN);

		return -1;
	}

	sm->new_challenge = 1;
	sm->state = WAPI_STATE_USKDONE;

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);

	return 0;
}

/**
 * wapi_notify_assoc - Notify WAPI state machine about association
 * @sm: Pointer to WAPI state machine data from wpa_sm_init()
 * @bssid: The BSSID of the new association
 *
 * This function is called to let WAPI state machine know that the connection
 * was established.
 */
void wapi_notify_assoc(struct wapi_sm *sm, const u8 *bssid)
{
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (sm == NULL)
		return;

	os_memcpy(sm->bssid, bssid, ETH_ALEN);
}


/**
 * Saves association IE in WAPI SM
 * @sm: wapi sm
 * @ie: ie buffer
 * @len: ie len
 */
int wapi_set_assoc_ie(struct wapi_sm *sm, const u8 *ie, size_t len) {
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (!sm) {
		wpa_printf(MSG_WAPI, "WAPI %s: sm is null", __func__);
		return -1;
	}

	os_free(sm->ie_assoc);
	sm->ie_assoc = NULL;
	sm->ie_assoc_len = 0;

	if (ie && len) {
		sm->ie_assoc = os_malloc(len);
		if (!sm->ie_assoc) {
			wpa_printf(MSG_WAPI, "WAPI %s: error allocating memory", __func__);
			return -1;
		}
		sm->ie_assoc_len = len;
		os_memcpy(sm->ie_assoc, ie, len);
	}

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}

/**
 * Saves IE from associated AP
 * @sm: wapi sm
 * @ie: ie buffer
 * @len: ie len
 */
int wapi_set_ap_ie(struct wapi_sm *sm, const u8 *ie, size_t len) {
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (!sm) {
		wpa_printf(MSG_WAPI, "WAPI %s: sm is nulll", __func__);
		return -1;
	}

	os_free(sm->ie_ap);
	sm->ie_ap = NULL;
	sm->ie_ap_len = 0;

	if (ie && len) {
		sm->ie_ap = os_malloc(len);
		if (!sm->ie_ap) {
			wpa_printf(MSG_WAPI, "WAPI %s: error allocating memory", __func__);
			return -1;
		}
		sm->ie_ap_len = len;
		os_memcpy(sm->ie_ap, ie, len);
	}

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}


void wapi_wrong_msg_err(wapi_msg_subtype expected, wapi_msg_subtype received,
		const char *func)
{
	wpa_printf(MSG_WAPI, "WAPI %s: expecting message '%s' received '%s'",
	func,
	wapi_subtype2str(expected),
	wapi_subtype2str(received));
}


/**
 * Calculate WAPI mac on a WAI message that includes a header.
 * Automatically skips the WAI header and ignores the last WAPI_MAC_LEN bytes
 * @kck: key
 * @msg: WAI message
 * @len: mesage length
 * @mac: buffer for storing the MAC
 */
void wapi_calc_mac(const u8 *kck, const u8 *msg, size_t len,
		u8 mac[WAPI_MAC_LEN]) {
	u8 buffer[SHA256_DIGEST_SIZE];
	hmac_sha256(kck, WAPI_KCK_LEN, msg+sizeof(struct wapi_wai_hdr),
			len-sizeof(struct wapi_wai_hdr)-WAPI_MAC_LEN, buffer);
	os_memcpy(mac, buffer, WAPI_MAC_LEN);
}

/**
 * Compares two hex arrays of the same size.
 * @first: first array
 * @second: second array
 * @len: length of arrays
 * Returns: -1 if first is bigger, 0 if equal, 1 if second is bigger
 */
int wapi_cmp_hex(const u8 *first, const u8 *second, size_t len) {
	size_t i;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (!first || !second) {
		wpa_printf(MSG_WAPI, "WAPI %s: received null ", __func__);
		return 0;
	}

	for (i = 0; i<len; ++i) {
		if (first[i] > second[i])
			return -1;
		if (first[i] < second[i])
			return 1;
	}
	return 0;
}


/**
 * handles multicast key announcement message
 */
int wapi_answer_mkey_announce(struct wpa_supplicant *wpa_s, struct wapi_msg *msg,
		const u8 mac[WAPI_MAC_LEN]) {
	struct wapi_sm *sm = wpa_s->wapi;
	u8 nmk[WAPI_NMK_LEN];
	struct wapi_msg reply;
	u8 *encoded_msg;
	size_t encoded_msg_len;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (msg->flag & WAPI_FLAG_STAKEY_NEGO) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet discarded. no support for "
				"STAKey announcement", __func__);
		return -1;
	}

	if (os_memcmp(msg->msg_auth_code, mac, WAPI_MAC_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet discarded. calculated MAC doesn't "
				"match MAC from message ", __func__);
		return -1;
	}

	if (wapi_cmp_hex(sm->prev_key_announcement, msg->key_announcment_id,
			WAPI_KEY_ANNOUNCMENT_ID_LEN) >= 0) {
		os_memcpy(sm->prev_key_announcement, msg->key_announcment_id,
						WAPI_KEY_ANNOUNCMENT_ID_LEN);
	}
	else {
		wpa_printf(MSG_WAPI, "WAPI %s: packet discarded. key announcement id is "
				"not monotonous", __func__);
		return -1;
	}

	/* decode nmk using sms4 and then use it to generate MSK + MIC using
	 * expansion string	 */
	sms4_decrypt(sm->usk.kek, msg->key_announcment_id, msg->key_data.content, nmk);
	wpa_printf(MSG_WAPI, "WAPI %s: decoding nmk", __func__);
	wpa_hexdump(MSG_WAPI, "WAPI IV", msg->key_announcment_id, WAPI_KEY_ANNOUNCMENT_ID_LEN);
	wpa_hexdump(MSG_WAPI, "WAPI encrypted key", msg->key_data.content, msg->key_data.len);
	wpa_hexdump(MSG_WAPI, "WAPI nmk", nmk, WAPI_NMK_LEN);

	wapi_kd_hmac_sha256((u8*)WAPI_EXPANSION_NMK, WAPI_EXPANSION_NMK_LEN,
			nmk, WAPI_NMK_LEN, (u8*)&sm->mkey, WAPI_MSK_LEN+WAPI_MIC_LEN);

	os_memset(&reply, 0, sizeof(reply));
	reply.header.subtype = WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE_RES;
	reply.flag = msg->flag;
	reply.mskid_stakid = msg->mskid_stakid;
	reply.uskid = msg->uskid;
	os_memcpy(&reply.header.pkt_seq, &msg->header.pkt_seq,
		  sizeof(reply.header.pkt_seq));
	os_memcpy(&reply.addid, &msg->addid,ETH_ALEN*2);
	os_memcpy(&reply.key_announcment_id, &msg->key_announcment_id,
			WAPI_KEY_ANNOUNCMENT_ID_LEN);
	os_memcpy(reply.kck, sm->usk.kck, WAPI_KCK_LEN);

	wpa_printf(MSG_WAPI, "WAPI %s: Sending multicast key announcement "
			"response",__func__);
	if (wapi_encode_msg(sm, &reply, &encoded_msg, &encoded_msg_len,NULL)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet encoding error ", __func__);
		return -1;
	}
	if (wapi_tx_wai(wpa_s, sm->bssid, encoded_msg, encoded_msg_len)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet tx error ", __func__);
		return -1;
	}
	os_free(encoded_msg);


#ifdef TI_WAPI
	wpa_printf(MSG_WAPI, "WAPI %s: keyidx %d", __func__, msg->mskid_stakid & WAPI_MSKID_KEYID);
	if (wpa_drv_set_key(wpa_s, WPA_ALG_WAPI, (u8 *) "\xff\xff\xff\xff\xff\xff",
			msg->mskid_stakid & WAPI_MSKID_KEYID, 1,
			NULL, 0, (u8*)&sm->mkey, WAPI_MSK_LEN+WAPI_MIC_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error setting key", __func__);
		return -1;
	}
#else
	wpa_printf(MSG_WAPI, "WAPI %s: multicast key wasn't set!!!", __func__);
#endif
	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return 0;
}

int wapi_send_split_msg(struct wpa_supplicant *wpa_s, const u8 *dest,
			       const u8 *msg, size_t msg_len) {
	u8 split[2000];
	struct wapi_wai_hdr *hdr;
	int msg_count = 0;
	const u8 *pos;
	size_t len_to_go;
	size_t cur_len;

	pos = msg + sizeof(struct wapi_wai_hdr);
	hdr = (struct wapi_wai_hdr *) split;
	len_to_go = msg_len - sizeof(struct wapi_wai_hdr);

	wpa_printf(MSG_WAPI, "WAPI %s: splitting messages before send", __func__);

	while (len_to_go > 0) {
		os_memcpy(split, msg, sizeof(struct wapi_wai_hdr));
		cur_len = MIN(WAPI_MTU, len_to_go);
		os_memcpy(split+sizeof(struct wapi_wai_hdr), pos, cur_len);
		pos += cur_len;
		len_to_go -= cur_len;

		if (len_to_go > 0)
			hdr->more_frag |= WAPI_MORE_FRAG;
		hdr->frag_seq = msg_count++;

		WPA_PUT_BE16(hdr->len, cur_len+sizeof(struct wapi_wai_hdr));

		wpa_printf(MSG_WAPI, "WAPI %s: sending msg #%d with length %d", __func__,
				hdr->frag_seq, cur_len);

		if (wapi_tx_wai(wpa_s, dest, split, cur_len + sizeof(struct wapi_wai_hdr))) {
			wpa_printf(MSG_WAPI, "WAPI %s: packet tx error ", __func__);
			return -1;
		}
	}

	return 0;
}



int wapi_answer_auth_activation(struct wpa_supplicant *wpa_s, struct wapi_msg *msg) {
	struct wapi_msg reply;
	struct wapi_sm *sm = wpa_s->wapi;
	EC_GROUP *group = NULL;
	int retval = -1;
	u8 *encoded_msg = NULL;
	size_t encoded_msg_len;
	u8 identity_ap[500], identity_sta[500];
	X509 *sta = NULL;
	u8* p;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	os_memset(&reply, 0, sizeof(reply));
	reply.header.subtype = WAPI_SUBTYPE_ACCESS_AUTH_REQ;
	reply.flag |= WAPI_FLAG_CERT_AUTH_REQ;
	os_memcpy(reply.auth_id, msg->auth_id, WAPI_AUTH_ID_LEN);
	if (hostapd_get_rand(reply.asue_challenge, WAPI_CHALLENGE_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error generating random number", __func__);
		goto end;
	}
	if (sm->new_ecdh) {
		wpa_printf(MSG_WAPI, "WAPIDBG %s: generating new ecdh key", __func__);
		if (!(group = wapi_ec_group()) || !EC_KEY_set_group(sm->ecdh_key, group) ||
				!EC_KEY_generate_key(sm->ecdh_key)) {
			wpa_printf(MSG_WAPI, "WAPI %s: error setting ecdh parameters", __func__);
			goto end;
		}
		sm->new_ecdh = 0;
	}
	p = msg->ae_cert.value;

	if (sm->ae_cert)
		X509_free(sm->ae_cert);

	sm->ae_cert = d2i_X509(NULL, (const unsigned char **)&p, msg->ae_cert.len);
	if (!sm->ae_cert) {
		wpa_printf(MSG_WAPI, "WAPI %s: error decoding ae certificate", __func__);
		goto end;
	}
	if (wapi_encode_pubkey(sm->ecdh_key, &reply.asue_key_data)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error encoding pubkey", __func__);
		goto end;
	}

	reply.id_ae.len = wapi_construct_identity(sm->ae_cert, identity_ap);
	reply.id_ae.type = 1;
	reply.id_ae.value = identity_ap;
	if (reply.id_ae.len < 0)
		goto end;
	wpa_hexdump(MSG_WAPI, "WAPI identity_ap", identity_ap, reply.id_ae.len);

	reply.asue_cert.len = sm->asue_cert_len;
	reply.asue_cert.type = 1;
	reply.asue_cert.value = sm->asue_cert;

	reply.ecdh_params.len = 11;
	reply.ecdh_params.type = 1;
	reply.ecdh_params.value = (u8*) WAPI_ECDH_PARAMS;

	p = sm->asue_cert;
	sta = d2i_X509(NULL, (const unsigned char **)&p, sm->asue_cert_len);
	if (!sta) {
		wpa_printf(MSG_WAPI, "WAPI %s: error parsing sta cert", __func__);
		goto end;
	}

	reply.signature.identity.type = 1;
	reply.signature.identity.len = wapi_construct_identity(sta, identity_sta);
	reply.signature.identity.value = identity_sta;
	if (reply.signature.identity.len < 0)
		goto end;
	wpa_hexdump(MSG_WAPI, "WAPI identity_sta", identity_sta, reply.signature.identity.len);

	reply.signature.id = 1;
	reply.signature.len = 72+reply.signature.identity.len;
	os_memcpy(reply.signature.signature_alg, WAPI_SIGNATURE_ALG, WAPI_SIGNATURE_ALG_LEN);
	reply.signature.signature.len = 48;

	wpa_printf(MSG_WAPI, "WAPI %s: encoding access authentication "
			"request",__func__);
	if (wapi_encode_msg(sm, &reply, &encoded_msg, &encoded_msg_len, sm->asue_priv_key)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet encoding error ", __func__);
		goto end;
	}

	wpa_printf(MSG_WAPI, "WAPI %s: Sending access authentication "
			"request",__func__);

	if (wapi_send_split_msg(wpa_s, sm->bssid, encoded_msg, encoded_msg_len)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet split tx error ", __func__);
		goto end;
	}

	wpa_printf(MSG_WAPI, "WAPI %s: done sending", __func__);
	retval = 0;
end:
	if (group)
		EC_GROUP_free(group);
	os_free(encoded_msg);

	if (sta)
		X509_free(sta);

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return retval;
}


/* returns 0 if succesful, 1 if unsuccesful, 2 on error */
int validate_mcvr(struct wpa_supplicant *wpa_s, struct wapi_msg *msg) {
	struct wapi_sm *sm = wpa_s->wapi;
	u8 cert[5000];
	u8 *p;
	int retval;

	wpa_printf(MSG_WAPI, "WAPI %s: debug 1", __func__);
	if (!sm->root_cert) {
		wpa_printf(MSG_WAPI, "WAPI %s: no root certificate available", __func__);
		return 2;
	}
	wpa_printf(MSG_WAPI, "WAPI %s: debug 2", __func__);
	switch (wapi_ecdsa_verify_frame(sm->root_cert, msg->auth_result.raw_mcvr,
			msg->auth_result.raw_mcvr_len, msg->server_signature_asue.ecdsa)) {
	case 0:
		wpa_printf(MSG_WAPI, "WAPI %s: successfully verified mcvr signature", __func__);
		break;
	case 1:
		wpa_printf(MSG_WAPI, "WAPI %s: couldn't verify mcvr signature", __func__);
		return 1;
	case 2:
		wpa_printf(MSG_WAPI, "WAPI %s: error verifying mcvr signature", __func__);
		return 2;
	}

	if (os_memcmp(msg->ae_challenge, msg->auth_result.nonce1, WAPI_CHALLENGE_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: nonce1 doesn't match ae_challenge", __func__);
		wpa_hexdump(MSG_WAPI, "nonce", msg->auth_result.nonce1, WAPI_CHALLENGE_LEN);
		wpa_hexdump(MSG_WAPI, "ae_challenge", msg->ae_challenge, WAPI_CHALLENGE_LEN);
		return 1;
	}

	if (os_memcmp(msg->asue_challenge, msg->auth_result.nonce2, WAPI_CHALLENGE_LEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: nonce2 doesn't match asue_challenge", __func__);
		wpa_hexdump(MSG_WAPI, "nonce2", msg->auth_result.nonce2, WAPI_CHALLENGE_LEN);
		wpa_hexdump(MSG_WAPI, "asue_challenge", msg->asue_challenge, WAPI_CHALLENGE_LEN);
		return 1;
	}
	if (msg->auth_result.ver_result1 != WAPI_ACCESS_RESULT_SUCCESS) {
		wpa_printf(MSG_WAPI, "WAPI %s: failed on verification result 1", __func__);
		return 1;
	}
	if (msg->auth_result.ver_result2 != WAPI_ACCESS_RESULT_SUCCESS) {
		wpa_printf(MSG_WAPI, "WAPI %s: failed on verification result 2", __func__);
		return 1;
	}
	if (os_memcmp(sm->asue_cert, msg->auth_result.cert1.value, sm->asue_cert_len)) {
		wpa_printf(MSG_WAPI, "WAPI %s: certificate1 doesn't match", __func__);
		wpa_hexdump(MSG_WAPI, "asue_cert", sm->asue_cert, sm->asue_cert_len);
		wpa_hexdump(MSG_WAPI, "msg_cert", msg->auth_result.cert1.value, msg->auth_result.cert1.len);
		return 1;
	}
	p = cert;
	retval = i2d_X509(sm->ae_cert, &p);
	if (retval < 0) {
		wpa_printf(MSG_WAPI, "WAPI %s: error decoding certificate", __func__);
		return 2;
	}
	if (os_memcmp(cert, msg->auth_result.cert2.value, retval)) {
		wpa_printf(MSG_WAPI, "WAPI %s: certificate2 doesn't match", __func__);
		wpa_hexdump(MSG_WAPI, "ae_cert", cert, retval);
		wpa_hexdump(MSG_WAPI, "msg_cert", msg->auth_result.cert2.value, msg->auth_result.cert2.len);
		return 1;
	}
	return 0;
}

int wapi_process_aa_response(struct wpa_supplicant *wpa_s, struct wapi_msg *msg,
		const u8 *raw_msg) {
	EC_POINT *bk = NULL;
	const EC_GROUP *group = NULL;
	BIGNUM *bk_x = NULL;
	const BIGNUM *priv_key = NULL;
	u8 bk_x_buf[WAPI_EC_PRIV_LEN];
	struct wapi_sm *sm = (struct wapi_sm*) wpa_s->wapi;
	int retval = -1;
	const u8 *addr[3];
	size_t len[3];
	u8 expansion_buf[WAPI_EXPANSION_EC_BK_LEN+2*WAPI_CHALLENGE_LEN];

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	switch (wapi_ecdsa_verify_frame(sm->ae_cert, raw_msg+sizeof(struct wapi_wai_hdr),
			msg->signed_content_length, msg->signature.ecdsa)) {
	case 0:
		wpa_printf(MSG_WAPI, "WAPI %s: successfully verified message from ae", __func__);
		break;
	case 1:
		wpa_printf(MSG_WAPI, "WAPI %s: couldn't verify message from ae", __func__);
		goto end;
		break;
	case 2:
		wpa_printf(MSG_WAPI, "WAPI %s: error verifying message from ae", __func__);
		goto end;
		break;
	}

	if (msg->flag & WAPI_FLAG_OPTIONAL) {
		wpa_printf(MSG_WAPI, "WAPI %s: validating mcvr", __func__);

		switch (validate_mcvr(wpa_s, msg)) {
		case 0:
			wpa_printf(MSG_WAPI, "WAPI %s: successfully validated mcvr", __func__);
			break;
		case 1:
			wpa_printf(MSG_WAPI, "WAPI %s: mcvr wasn't validated. deauthenticating", __func__);
			wpa_supplicant_deauthenticate(wpa_s, 1); /* 1 == reason unspecified */
			goto end;
		case 2:
			wpa_printf(MSG_WAPI, "WAPI %s: error validating mcvr", __func__);
			goto end;
		}

	}
	else
		wpa_printf(MSG_WAPI, "WAPI %s: mcvr is not present", __func__);



	if (msg->access_result == WAPI_ACCESS_RESULT_SUCCESS)
		wpa_printf(MSG_WAPI, "WAPI %s: received successful access result", __func__);
	else {
		wpa_printf(MSG_WAPI, "WAPI %s: received UNSUCCESSFUL access result. "
				"deauthenticating", __func__);
		wpa_supplicant_deauthenticate(wpa_s, 1); /* 1 == reason unspecified */
		goto end;
	}

	/* compute bk */
	wpa_printf(MSG_WAPI, "WAPIDBG %s: compute bk", __func__);
	group = EC_KEY_get0_group(sm->ecdh_key);
	bk = EC_POINT_new(group);
	bk_x = BN_new();
	if (!bk || !bk_x) {
		wpa_printf(MSG_WAPI, "WAPI %s: error creating openssl elements", __func__);
		goto end;
	}

	if (!EC_POINT_oct2point(group, bk,
			msg->ae_key_data.content, msg->ae_key_data.len, NULL)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error converting oct2point", __func__);
		goto end;
	}

	priv_key = EC_KEY_get0_private_key(sm->ecdh_key);
	wpa_printf(MSG_WAPI, "WAPI %s: temporary ecdh private key %s", __func__, BN_bn2hex(priv_key));
	if (!EC_POINT_mul(group, bk, NULL, bk, priv_key, NULL)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error creating mutual secret", __func__);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, bk, bk_x, NULL, NULL)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error retreiving x coordinate", __func__);
		goto end;
	}
	if (BN_bn2bin(bk_x, bk_x_buf) != WAPI_EC_PRIV_LEN) {
		wpa_printf(MSG_WAPI, "WAPI %s: error in number of bytes written", __func__);
		goto end;
	}
	wpa_hexdump(MSG_WAPI, "WAPI shared secret x", bk_x_buf, WAPI_EC_PRIV_LEN);

	addr[0] = msg->ae_challenge;
	len[0]  = WAPI_CHALLENGE_LEN;
	addr[1] = msg->asue_challenge;
	len[1]  = WAPI_CHALLENGE_LEN;
	addr[2] = (u8*) WAPI_EXPANSION_EC_BK;
	len[2]  = WAPI_EXPANSION_EC_BK_LEN;

	wapi_construct_buffer(3, addr, len, expansion_buf);
	wpa_hexdump(MSG_WAPI, "WAPI expansion for bk", expansion_buf, WAPI_EXPANSION_EC_BK_LEN+2*WAPI_CHALLENGE_LEN);

	wapi_kd_hmac_sha256(expansion_buf, WAPI_EXPANSION_EC_BK_LEN+2*WAPI_CHALLENGE_LEN,
			bk_x_buf, WAPI_EC_PRIV_LEN, sm->bk, WAPI_BK_LEN);

	wpa_hexdump(MSG_WAPI, "WAPI BK", sm->bk, WAPI_BK_LEN);

	retval = 0;
end:
	if (bk)
		EC_POINT_free(bk);
	if (bk_x)
		BN_free(bk_x);

	wpa_printf(MSG_WAPI, "WAPIDBG %s: DONE", __func__);
	return retval;
}



u8* wapi_encode_signature(u8 *pos, struct wapi_signature *sign) {
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	*pos++ = sign->id; /* id */
	WPA_PUT_BE16(pos, sign->len); /* len */
	pos += 2;

	WPA_PUT_BE16(pos, sign->identity.type); /* identity id */
	pos += 2;

	WPA_PUT_BE16(pos, sign->identity.len); /* identity len */
	pos += 2;

	os_memcpy(pos, sign->identity.value, sign->identity.len);
	pos += sign->identity.len;

	os_memcpy(pos, sign->signature_alg, WAPI_SIGNATURE_ALG_LEN);
	pos += WAPI_SIGNATURE_ALG_LEN;

	WPA_PUT_BE16(pos, WAPI_EC_ECDSA_LEN);
	pos += 2;

	os_memcpy(pos, sign->ecdsa, WAPI_EC_ECDSA_LEN);
	pos += WAPI_EC_ECDSA_LEN;

	return pos;
}


/**
 * Entry point of the WAPI SM. This function is registered as the callback
 * function using l2_packet_init() in wpa_supplicant_driver_init(). The function
 * is invoked each time a new WAI message is received. If a message is received
 * out of context, is invalid, contains wrong MAC, etc, it will be discarded.
 * @ctx: callback data
 * @src_addr: source address
 * @buf: buffer holding the message
 * @len: length of buffer
 */
void wapi_rx_wai(void *ctx, const u8 *src_addr, const u8 *buf, size_t len) {
	struct wpa_supplicant *wpa_s = ctx;
	struct wapi_msg msg; /* can be used only while buf is in scope because */
	                     /* the struct has references to it */

	u8 mac[WAPI_MAC_LEN];
	struct wapi_sm *sm = wpa_s->wapi;
	const struct wapi_wai_hdr *hdr = (const struct wapi_wai_hdr *) buf;

	/* this check is currently disabled. see comment in wpa_supplicant_rx_eapol()
	if (os_memcmp(src_addr, sm->bssid, ETH_ALEN)) {
		wpa_printf(MSG_WAPI, "WAPI %s: packet discarded. bssid doesn't"
				" match", __func__);
				return;
	}*/

#ifndef TI_WAPI
	wpa_printf(MSG_WAPI, "WAPI WARNING: TI_WLAN_DRIVER is disabled!!!");
#endif

	os_memset(&msg, 0, sizeof(msg));
	wpa_printf(MSG_WAPI, "WAPI \n%s: received WAI message: %s",__func__,
			wapi_subtype2str(hdr->subtype));

	if ((hdr->more_frag & WAPI_MORE_FRAG) && !hdr->frag_seq) {
		wpa_printf(MSG_WAPI, "WAPI %s: receiving first fragment with length %d", __func__, len);

		os_free(sm->trunc_msg); /* cleaning previously used buffer (of previous msgs) */
		sm->trunc_msg = os_malloc(len);
		if (!sm->trunc_msg) {
			wpa_printf(MSG_WAPI, "WAPI %s: failed on malloc", __func__);
			return;
		}
		os_memcpy(sm->trunc_msg, buf, len);
		sm->trunc_msg_len = len;
		return;
	}
	if (hdr->frag_seq) {
		wpa_printf(MSG_WAPI, "WAPI %s: receiving fragment #%d with length %d", __func__, hdr->frag_seq+1, len);
		if (!sm->trunc_msg) {
			wpa_printf(MSG_WAPI, "WAPI %s: wrong order of fragments (where's first fragment?)", __func__);
			return;
		}
		sm->trunc_msg = os_realloc(sm->trunc_msg,
				sm->trunc_msg_len + len - sizeof(struct wapi_wai_hdr));
		if (!sm->trunc_msg) {
			wpa_printf(MSG_WAPI, "WAPI %s: failed on realloc", __func__);
			return;
		}
		os_memcpy(sm->trunc_msg+sm->trunc_msg_len,buf+sizeof(struct wapi_wai_hdr),len-sizeof(struct wapi_wai_hdr));
		sm->trunc_msg_len += len-sizeof(struct wapi_wai_hdr);

		if (hdr->more_frag & WAPI_MORE_FRAG)
			return;
		wpa_printf(MSG_WAPI, "WAPI %s: received last fragment of msg", __func__);
		wpa_printf(MSG_WAPI, "WAPI %s: total length %d", __func__, sm->trunc_msg_len);

		buf = sm->trunc_msg;
		len = sm->trunc_msg_len;
	}

	/* NOTICE: msg can be used only while buf is in scope!!! */
	if (wapi_decode_msg(&msg, buf, len)) {
		wpa_printf(MSG_WAPI, "WAPI %s: fail to decode WAPI msg", __func__);
		return;
	}

	switch (msg.header.subtype) {
	case WAPI_SUBTYPE_AUTH_ACTIVACTION:
		/* save message a second time for when reentering sm */

		if (!sm->fetch_cert) { /* first time - fetch cert from repository */
			wpa_printf(MSG_WAPI, "WAPIDBG %s: fetching cert from repository", __func__);
			os_free(sm->reentrant_raw);
			sm->reentrant_raw = os_malloc(len);
			if (!sm->reentrant_raw) {
				wpa_printf(MSG_WAPI, "WAPI %s: failed on malloc", __func__);
				return;
			}
			os_memcpy(sm->reentrant_raw, buf, len);
			sm->reentrant_raw_len = len;

			if (wapi_decode_msg(&(sm->reentrant_msg), sm->reentrant_raw, sm->reentrant_raw_len)) {
				wpa_printf(MSG_WAPI, "WAPI %s: fail to decode WAPI msg", __func__);
				return;
			}
			else
				wpa_printf(MSG_WAPI, "WAPIDBG %s: successfully decoded reentrant msg", __func__);
			sm->fetch_cert = 1;
			if (wapi_retrieve_cert(wpa_s)){
				wpa_msg(wpa_s, MSG_INFO, "WPA: Cert checking failed - " "cert files may be incorrect");
			}
		}
		else if (sm->asue_cert_len){
			wpa_printf(MSG_WAPI, "WAPI %s: calling wapi_answer_auth_activation() regular mode",
					__func__);
			if (wapi_answer_auth_activation(wpa_s, &msg)) {
				wpa_printf(MSG_WAPI, "WAPI %s: error wapi_answer_auth_activation", __func__);
				return;
			}
		}


		break;
	case WAPI_SUBTYPE_ACCESS_AUT_RESP:
		if (wapi_process_aa_response(wpa_s, &msg, buf)) {
			wpa_printf(MSG_WAPI, "WAPI %s: wapi_process_aa_response()", __func__);
			return;
		}
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_REQ:
		if (wapi_answer_ukey_req(wpa_s, &msg)) {
			wpa_printf(MSG_WAPI, "WAPI %s: wapi_answer_ukey_req()", __func__);
			return;
		}
		break;


	case WAPI_SUBTYPE_UKEY_NEGO_CONFIRM:
		wapi_calc_mac(sm->usk.kck, buf, len, mac);
		if (wapi_process_ukey_confirm(wpa_s, &msg, mac)) {
			wpa_printf(MSG_WAPI, "WAPI %s: wapi_process_ukey_confirm()", __func__);
			return;
		}
		break;

	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE:
		wapi_calc_mac(sm->usk.kck, buf, len, mac);

		if (sm->state != WAPI_STATE_DONE)
			wapi_supplicant_set_state(wpa_s, WPA_GROUP_HANDSHAKE);

		if (wapi_answer_mkey_announce(wpa_s, &msg, mac)) {
			wpa_printf(MSG_WAPI, "WAPI %s: wapi_answer_mkey_announce()", __func__);
			return;
		}

		if (sm->state != WAPI_STATE_DONE) {

			wpa_supplicant_cancel_auth_timeout(wpa_s);
			wpa_supplicant_cancel_scan_timeout(wpa_s);
			sm->state = WAPI_STATE_DONE;

			wapi_supplicant_set_state(wpa_s, WPA_COMPLETED);
#ifdef TI_WAPI
			wpa_printf(MSG_WAPI, "WAPIDBG %s: registering wapi_port_state_callback", __func__);
			if (wpa_drv_set_port_state(wpa_s, 1)) {
					wpa_printf(MSG_WAPI, "WAPI %s: error opening port", __func__);
			}
			else
					wpa_printf(MSG_WAPI, "WAPI %s: port was opened successfully", __func__);
#endif
		}

		break;
	default:
		wpa_printf(MSG_WAPI, "WAPI %s: packet discarded. not supported subtype %d",
				__func__, msg.header.subtype);
		return;
	}
}


/* macros to read/write an arbitrary field from/to the buffer.
   assumes the following variables in scope:
   'params' - struct to hold parameters
   'pos'    = pointer to current position in buffer
   'len'    - remaining space in buffer

   always works in BIG-ENDIAN mode.
   will update params, pos and len.
   will return -1 on error.
*/


#define READ_BUFFER(dest,len_to_read)				\
if (len_to_read > len) {					\
	wpa_printf(MSG_WAPI, "WAPI Error parsing field " #dest );	\
	return -1;						\
}								\
if (len_to_read==2)						\
	*((u16 *)(dest)) = WPA_GET_BE16(pos);			\
else if (len_to_read==4)					\
	*((u32 *)(dest)) = WPA_GET_BE32(pos);			\
else								\
	os_memcpy( (u8 *)(dest), pos, (len_to_read) );		\
pos+=(len_to_read);						\
len-=(len_to_read)

#define READ_SINGLE_FIELD(field)			\
READ_BUFFER(&(params->field),sizeof(params->field))

#define WRITE_BUFFER(src,len_to_write)				\
if (len_to_write > len) {					\
	wpa_printf(MSG_WAPI, "WAPI Error encoding field " #src );	\
	return -1;						\
}								\
if (len_to_write==2)						\
	WPA_PUT_BE16(pos,*((u16 *)(src)));			\
else if (len_to_write==4)					\
	WPA_PUT_BE32(pos,*((u32 *)(src)));			\
else								\
	os_memcpy( pos, (const u8 *)(src), (len_to_write) );	\
pos+=(len_to_write);						\
len-=(len_to_write)

#define WRITE_SINGLE_FIELD(field)			\
WRITE_BUFFER(&(params->field),sizeof(params->field))

#define READ_TLV(field,type_len) \
	do {if (read_tlv(&(params->field), type_len, &pos, &len)) \
		return -1; } while(0)

int read_tlv(struct wapi_tlv *tlv, const size_t type_len, const u8 **pos, size_t *len ) {
	/* type */
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (*len < type_len) {
		wpa_printf(MSG_WAPI, "WAPI Error reading field (type)");
		return -1;
	}
	if (type_len == 1)
		tlv->type = **pos;
	else if (type_len == 2)
		tlv->type = WPA_GET_BE16(*pos);

	*pos += type_len;
	*len -= type_len;

	wpa_printf(MSG_WAPI, "WAPIDBG %s: type %d", __func__, tlv->type);

	/* length */
	if (*len < 2) {
		wpa_printf(MSG_WAPI, "WAPI Error reading field (length)");
		return -1;
	}

	tlv->len = WPA_GET_BE16(*pos);
	*pos += 2;
	*len -= 2;

	wpa_printf(MSG_WAPI, "WAPIDBG %s: length %d", __func__, tlv->len);

	/* value */
	if (*len < tlv->len) {
		wpa_printf(MSG_WAPI, "WAPI Error reading field (value)");
		return -1;
	}
	tlv->value = (u8*)*pos;
	*pos += tlv->len;
	*len -= tlv->len;
	return 0;
}


/* id_len  -  length in octets of id field
 * len_len -  length in octets of length field
 */
#define WRITE_TLV(field,type_len,len_len) \
	do {if (write_tlv(&(params->field), type_len, len_len, &pos, &len)) \
		return -1; } while(0)

int write_tlv(struct wapi_tlv *tlv, size_t type_len, size_t len_len, u8 **pos, size_t *len) {
	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);

	/* type */
	if (type_len > *len) {
		wpa_printf(MSG_WAPI, "WAPI Error writing field (type)");
		return -1;
	}
	if (type_len == 1)
		**pos = tlv->type;
	else if (type_len == 2)
		WPA_PUT_BE16(*pos,tlv->type);
	*pos += type_len;
	*len -= type_len;

	/* length */
	if (len_len > *len) {
		wpa_printf(MSG_WAPI, "WAPI Error writing field (length)");
		return -1;
	}
	if (len_len == 1)
		**pos = tlv->len;
	else if (len_len == 2)
		WPA_PUT_BE16(*pos,tlv->len);

	*pos += len_len;
	*len -= len_len;
	if (tlv->len > *len) {
		wpa_printf(MSG_WAPI, "WAPI Error writing field (value)");
		return -1;
	}
	os_memcpy( *pos, tlv->value, tlv->len);
	*pos += tlv->len;
	*len -= tlv->len;
	return 0;
}



/**
 * wapi_decode_msg - decode a wapi message from a byte array
 * @params: struct to hold decoded params (valid only while input_buffer is in scope)
 * @input_buffer: byte stream to decode (must be in scope while params is being accessed)
 * @input_buffer_length: length of input buffer
 *
 * params->msg_auth_code is the MAC that appears in the message. not calculated
 * by the supplicant!
 */
int wapi_decode_msg( struct wapi_msg *params,
		     const u8 *input_buffer,
		     size_t input_buffer_length )
{
	const u8 *pos = input_buffer;
	size_t len = input_buffer_length;
	size_t ie_len;

	READ_SINGLE_FIELD(header);

	switch (params->header.subtype) {
	case WAPI_SUBTYPE_PRE_AUTH_START:
	case WAPI_SUBTYPE_ST_STAKEY_REQ:
		wpa_printf(MSG_WAPI, "WAPI Unsupported Message subtype=%d", params->header.subtype );
		return -1;

	case WAPI_SUBTYPE_ACCESS_AUT_RESP:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(asue_challenge);
		READ_SINGLE_FIELD(ae_challenge);
		READ_SINGLE_FIELD(access_result);
		READ_SINGLE_FIELD(asue_key_data.len);
		READ_BUFFER(&(params->asue_key_data.content), params->asue_key_data.len);
		READ_SINGLE_FIELD(ae_key_data.len);
		READ_BUFFER(&(params->ae_key_data.content), params->ae_key_data.len);

		READ_TLV(id_ae,2);
		READ_TLV(id_asue,2);

		if (params->flag & WAPI_FLAG_OPTIONAL) {
			wpa_printf(MSG_WAPI, "WAPI %s: reading optional parameter", __func__);

			/* reading auth response */
			params->auth_result.raw_mcvr = pos;

			READ_SINGLE_FIELD(auth_result.type);
			params->auth_result.len = WPA_GET_BE16(pos);
			pos += 2;
			len -= 2;
			READ_SINGLE_FIELD(auth_result.nonce1);
			READ_SINGLE_FIELD(auth_result.nonce2);
			READ_SINGLE_FIELD(auth_result.ver_result1);
			READ_TLV(auth_result.cert1,2);
			READ_SINGLE_FIELD(auth_result.ver_result2);
			READ_TLV(auth_result.cert2,2);

			params->auth_result.raw_mcvr_len = (size_t) (pos - params->auth_result.raw_mcvr);

			wpa_printf(MSG_WAPI, "WAPI %s: length left: %d", __func__, len);

			/* first signature */
			READ_SINGLE_FIELD(server_signature_asue.id);
			READ_SINGLE_FIELD(server_signature_asue.len);
			READ_TLV(server_signature_asue.identity, 2);
			READ_SINGLE_FIELD(server_signature_asue.signature_alg);
			pos += 2; /* skipping 48 */
			len -= 2;
			READ_BUFFER(&(params->server_signature_asue.ecdsa), WAPI_EC_ECDSA_LEN);

			params->signed_content_length = (size_t) (pos-input_buffer-
					sizeof(struct wapi_wai_hdr));
			/* second signature */
			READ_SINGLE_FIELD(server_signature_ae.id);
			READ_SINGLE_FIELD(server_signature_ae.len);
			READ_TLV(server_signature_ae.identity, 2);
			READ_SINGLE_FIELD(server_signature_ae.signature_alg);
			pos += 2; /* skipping 48 */
			len -= 2;
			READ_BUFFER(&(params->server_signature_ae.ecdsa), WAPI_EC_ECDSA_LEN);
		}
		if (len > 0) {
			params->signed_content_length = (size_t) (pos-input_buffer-
					sizeof(struct wapi_wai_hdr));
			READ_SINGLE_FIELD(signature.id);
			READ_SINGLE_FIELD(signature.len);
			READ_TLV(signature.identity, 2);
			READ_SINGLE_FIELD(signature.signature_alg);
			pos += 2; /* skipping 48 */
			len -= 2;
			READ_BUFFER(&(params->signature.ecdsa), WAPI_EC_ECDSA_LEN);
		}
		else {
			os_memcpy(&(params->signature), &(params->server_signature_ae),
					sizeof(params->signature));
			os_memset(&(params->server_signature_ae), 0, sizeof(params->server_signature_ae));
		}

		wpa_printf(MSG_WAPI, "WAPI %s: signed content length: %d", __func__,
				params->signed_content_length);

		break;

	case WAPI_SUBTYPE_AUTH_ACTIVACTION:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(auth_id);
		READ_TLV(id_asu,2);
		READ_TLV(ae_cert,2);
		READ_TLV(ecdh_params,1);
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_REQ:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(bkid);
		READ_SINGLE_FIELD(uskid);
		READ_SINGLE_FIELD(addid);
		READ_SINGLE_FIELD(ae_challenge);
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_RES:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(bkid);
		READ_SINGLE_FIELD(uskid);
		READ_SINGLE_FIELD(addid);
		READ_SINGLE_FIELD(asue_challenge);
		READ_SINGLE_FIELD(ae_challenge);
		ie_len = *(pos+1)+2;
		if (ie_len > len) {
			wpa_printf(MSG_WAPI, "WAPI %s: IE len mismatch", __func__);
			return -1;
		}

		if ( wapi_parse_ie( pos, ie_len, &(params->wapi_ie) ) )
			return -1;

		pos += ie_len;
		len -= ie_len;

		READ_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_CONFIRM:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(bkid);
		READ_SINGLE_FIELD(uskid);
		READ_SINGLE_FIELD(addid);
		READ_SINGLE_FIELD(asue_challenge);

		ie_len = *(pos+1)+2;
		if (ie_len > len) {
			wpa_printf(MSG_WAPI, "WAPI %s: IE len mismatch", __func__);
			return -1;
		}

		if ( wapi_parse_ie( pos, ie_len, &(params->wapi_ie) ) ) {
			return -1;
		}
		pos += ie_len;
		len -= ie_len;
		READ_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(mskid_stakid);
		READ_SINGLE_FIELD(uskid);
		READ_SINGLE_FIELD(addid);
		READ_SINGLE_FIELD(data_pkt_num);
		READ_SINGLE_FIELD(key_announcment_id);
		READ_SINGLE_FIELD(key_data.len);
		READ_BUFFER(&(params->key_data.content), params->key_data.len);
		READ_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE_RES:
		READ_SINGLE_FIELD(flag);
		READ_SINGLE_FIELD(mskid_stakid);
		READ_SINGLE_FIELD(uskid);
		READ_SINGLE_FIELD(addid);
		READ_SINGLE_FIELD(key_announcment_id);
		READ_SINGLE_FIELD(msg_auth_code);
		break;

	default:
		wpa_printf(MSG_WAPI, "WAPI Unknown Message subtype=%d", params->header.subtype );
		return -1;
	}

	return 0;
}



/**
 * wapi_encode_msg - encodes a wapi message to byte array
 * @params: WAI message to encode as a byte array
 * @output_buffer: output buffer (acquired by the function)
 * @output_buffer_len: output buffer length
 * @key: key for ecdsa or message auth code (length varies by context)
 * Returns: -1 on error, 0 on success
 *
 * It is the user's responsibility to fill in the correct fields in the struct,
 * according to the message type.
 * The user needs to free the returned buffer by calling os_free()
 * The function constructs WAI message header at the beginning of the buffer &
 * calculates MAC and append to the end.
 */
int wapi_encode_msg( struct wapi_sm *sm, struct wapi_msg *msg,
		     u8 **output_buffer,
		     size_t *output_buffer_length, u8 *key)
{
	size_t len = WAPI_MAX_MESSAGE_LENGTH;
	u8 *pos = os_malloc( len );
	u8 *mac_start_pos;
	struct wapi_msg *params = msg;
	size_t wapi_ie_len;
	struct wapi_wai_hdr *hdr;
	u8 ecdsa[WAPI_EC_ECDSA_LEN];

	if (pos == NULL) {
		wpa_printf(MSG_WAPI, "WAPI Not enough memory to allocate message buffer");
		return -1;
	}
	(*output_buffer) = pos;

	mac_start_pos = pos;

	hdr = (struct wapi_wai_hdr *) pos;
	WRITE_SINGLE_FIELD(header);

	switch (params->header.subtype) {
	case WAPI_SUBTYPE_PRE_AUTH_START:
	case WAPI_SUBTYPE_ST_STAKEY_REQ:
	case WAPI_SUBTYPE_AUTH_ACTIVACTION:

	case WAPI_SUBTYPE_ACCESS_AUT_RESP:
		wpa_printf(MSG_WAPI, "WAPI Unsupported Message subtype=%d", params->header.subtype );
		os_free(pos);
		return -1;

	case WAPI_SUBTYPE_ACCESS_AUTH_REQ:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(auth_id);
		WRITE_SINGLE_FIELD(asue_challenge);
		WRITE_SINGLE_FIELD(asue_key_data.len);
		WRITE_BUFFER(&(params->asue_key_data.content), params->asue_key_data.len);
		WRITE_TLV(id_ae, 2, 2);
		WRITE_TLV(asue_cert, 2, 2);
		WRITE_TLV(ecdh_params, 1,2);

		wapi_ecdsa_sign_frame(key, mac_start_pos+sizeof(struct wapi_wai_hdr),
				pos-(mac_start_pos+sizeof(struct wapi_wai_hdr)), ecdsa);

		WRITE_SINGLE_FIELD(signature.id);
		WRITE_SINGLE_FIELD(signature.len);
		WRITE_TLV(signature.identity, 2, 2);
		WRITE_SINGLE_FIELD(signature.signature_alg);
		WPA_PUT_BE16(pos, WAPI_EC_ECDSA_LEN);
		pos += 2;
		len -= 2;
		WRITE_BUFFER(ecdsa, WAPI_EC_ECDSA_LEN);

		break;

	case WAPI_SUBTYPE_UKEY_NEGO_REQ:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(bkid);
		WRITE_SINGLE_FIELD(uskid);
		WRITE_SINGLE_FIELD(addid);
		WRITE_SINGLE_FIELD(ae_challenge);
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_RES:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(bkid);
		WRITE_SINGLE_FIELD(uskid);
		WRITE_SINGLE_FIELD(addid);
		WRITE_SINGLE_FIELD(asue_challenge);
		WRITE_SINGLE_FIELD(ae_challenge);
		wapi_ie_len = len;
		if ( wapi_gen_ie( pos, &wapi_ie_len, params->wapi_ie.akm_suite,
				  params->wapi_ie.unicast_suite, params->wapi_ie.multicast_suite ) != 0 ) {
			os_free(pos);
			return -1;
		}
		pos += wapi_ie_len;
		len -= wapi_ie_len;
		/* TODO: (wapi) use parameter instead of params->kck */
		wapi_calc_mac( params->kck, mac_start_pos, (size_t)(pos - mac_start_pos) + WAPI_MAC_LEN, params->msg_auth_code );
		WRITE_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_UKEY_NEGO_CONFIRM:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(bkid);
		WRITE_SINGLE_FIELD(uskid);
		WRITE_SINGLE_FIELD(addid);
		WRITE_SINGLE_FIELD(asue_challenge);
		wapi_ie_len = len;
		if ( wapi_gen_ie( pos, &wapi_ie_len, params->wapi_ie.akm_suite,
				  params->wapi_ie.unicast_suite, params->wapi_ie.multicast_suite ) != 0 ) {
			os_free(pos);
			return -1;
		}
		pos += wapi_ie_len;
		len -= wapi_ie_len;
		/* TODO: (wapi) use parameter instead of params->kck */
		wapi_calc_mac( params->kck, mac_start_pos, (size_t)(pos - mac_start_pos) + WAPI_MAC_LEN, params->msg_auth_code );
		WRITE_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(mskid_stakid);
		WRITE_SINGLE_FIELD(uskid);
		WRITE_SINGLE_FIELD(addid);
		WRITE_SINGLE_FIELD(data_pkt_num);
		WRITE_SINGLE_FIELD(key_announcment_id);
		WRITE_SINGLE_FIELD(key_data.len);
		WRITE_BUFFER(&(params->key_data.content), params->key_data.len);
		wapi_calc_mac( params->kck, mac_start_pos, (size_t)(pos - mac_start_pos) + WAPI_MAC_LEN, params->msg_auth_code );
		WRITE_SINGLE_FIELD(msg_auth_code);
		break;

	case WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE_RES:
		WRITE_SINGLE_FIELD(flag);
		WRITE_SINGLE_FIELD(mskid_stakid);
		WRITE_SINGLE_FIELD(uskid);
		WRITE_SINGLE_FIELD(addid);
		WRITE_SINGLE_FIELD(key_announcment_id);
		wapi_calc_mac( params->kck, mac_start_pos, (size_t)(pos - mac_start_pos) + WAPI_MAC_LEN, params->msg_auth_code );
		WRITE_SINGLE_FIELD(msg_auth_code);
		break;

	default:
		wpa_printf(MSG_WAPI, "WAPI Unknown Message subtype=%d", params->header.subtype );
		os_free(pos);
		return -1;
	}

	(*output_buffer_length) = (size_t) (pos - (*output_buffer));

	WPA_PUT_BE16(hdr->version, 1);
	hdr->type = 1;
	WPA_PUT_BE16(hdr->pkt_seq, sm->pkt_seq);
	sm->pkt_seq++;
	WPA_PUT_BE16(hdr->len, pos - (*output_buffer));

	return 0;
}


int wapi_set_suites(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *bss,
			      struct wpa_ssid *ssid,
			      u8 *wpa_ie, size_t *wpa_ie_len)
{
	struct wapi_ie ie;

	wpa_printf(MSG_WAPI, "WAPIDBG %s", __func__);
	if (!bss) {
		wpa_printf(MSG_WAPI, "WAPI %s: BSS is null", __func__);
		return -1;
	}
	if (wapi_parse_ie(bss->wapi_ie, bss->wapi_ie_len, &ie)) {
		return -1;
	}

	if ((ssid->key_mgmt & ie.akm_suite) & WPA_KEY_MGMT_WAPI_PSK)
		wpa_s->key_mgmt = WPA_KEY_MGMT_WAPI_PSK;
	else if ((ssid->key_mgmt & ie.akm_suite) & WPA_KEY_MGMT_WAPI_CERT)
		wpa_s->key_mgmt = WPA_KEY_MGMT_WAPI_CERT;
	else {
		wpa_printf(MSG_WAPI, "WAPI %s: Failed to select key management.", __func__);
		return -1;
	}
	wpa_s->group_cipher = wpa_s->pairwise_cipher = WPA_CIPHER_SMS4;

	if (wapi_set_ap_ie(wpa_s->wapi, bss->wapi_ie, bss->wapi_ie_len))
		return -1;

	if (wapi_gen_ie(wpa_ie, wpa_ie_len, wpa_s->key_mgmt,
			WPA_CIPHER_SMS4, WPA_CIPHER_SMS4))
		return -1;

	if (wapi_set_assoc_ie(wpa_s->wapi,wpa_ie, *wpa_ie_len))
		return -1;

	return 0;
}


void wapi_set_config(struct wapi_sm *sm, struct wpa_ssid *config) {
	if (sm)
		sm->cur_ssid = config;
}

void wapi_deinit_sm(struct wapi_sm *sm) {
	wpa_printf(MSG_WAPI, "WAPI %s: deinit wapi sm", __func__);
	if (!sm)
		return;
	os_free(sm->ie_ap);
	sm->ie_ap = NULL;
	os_free(sm->ie_assoc);
	sm->ie_assoc = NULL;
	os_free(sm->trunc_msg);
	sm->trunc_msg = NULL;
	if (sm->ecdh_key)
		EC_KEY_free(sm->ecdh_key);
	sm->ecdh_key = NULL;
	if (sm->ae_cert)
		X509_free(sm->ae_cert);
	sm->ae_cert = NULL;

	if (sm->root_cert)
		X509_free(sm->root_cert);
	sm->root_cert = NULL;

	os_free(sm->reentrant_raw);
}


int wapi_tx_wai(struct wpa_supplicant *wpa_s, const u8 *dest,
			       u8 *msg, size_t msg_len) {
	if (wpa_s->wapi_l2)
		return (l2_packet_send(wpa_s->wapi_l2, dest, WAPI_ETHER_TYPE, msg, msg_len) < 0);

	return (wpa_drv_send_eapol(wpa_s, dest, WAPI_ETHER_TYPE, msg, msg_len) < 0);
}


void wapi_init_sm(struct wapi_sm *sm) {
	if (!sm) {
		wpa_printf(MSG_WAPI, "WAPI %s: init wapi sm (sm is null)", __func__);
		return;
	}
	wpa_printf(MSG_WAPI, "WAPI %s: init wapi sm", __func__);
	os_memset(sm, 0, sizeof(*sm));

	sm->state = WAPI_STATE_INITPSK;
	sm->pkt_seq = 1;
	sm->new_challenge = 1;
	sm->new_ecdh = 1;
	sm->ecdh_key = EC_KEY_new();
	if (!sm->ecdh_key)
		wpa_printf(MSG_WAPI, "WAPI %s: error allocating ecdh key", __func__);
}

void wapi_notify_disassoc(struct wapi_sm *sm) {
	wpa_printf(MSG_WAPI, "WAPI %s: received disassoc, reinit sm", __func__);
	wapi_deinit_sm(sm);
	wapi_init_sm(sm);
}


size_t wapi_file_size(FILE *fp) {
	struct stat file_stat;
	if (fstat(fileno(fp), &file_stat) != 0) {
		wpa_printf(MSG_WAPI, "%s: error retreiving file stat", __func__);
		return -1;
	}

	return file_stat.st_size;
}


int wapi_retrieve_cert(struct wpa_supplicant *wpa_s) {

	char cert[WAPI_CERT_LEN];
	char root[WAPI_CERT_LEN];

	struct wapi_sm *sm = wpa_s->wapi;

	wpa_printf(MSG_WAPI, "%s: parsing content from repository", __func__);

	if (wpa_s->wapi->asue_cert_len) {
		wpa_printf(MSG_WAPI, "%s: already holding certificate", __func__);
		return -1;
	}

	if ((!wpa_s->current_ssid->user_cert_uri) || (!wpa_s->current_ssid->as_cert_uri || (!wpa_s->current_ssid->user_key_uri))) {
		wpa_printf(MSG_WAPI, "%s: no wapi certificate/private key filenames were set", __func__);
		return -1;
	}

	wpa_printf(MSG_WAPI, "\n\ncalling cert storage: \n%s\n", wpa_s->current_ssid->user_cert_uri);
	int cert_len = wapi_get_fromKeyStorage(wpa_s->current_ssid->user_cert_uri, cert);
	if (cert_len < 0){
		wpa_printf(MSG_WAPI, "%s: Failed to parse WAPI user certificate", __func__);
		return -1;
	}
	wpa_printf(MSG_WAPI, "\n\ncalling cert storage: %s \n%s\n", wpa_s->current_ssid->user_key_uri);
	int tmp_len = wapi_get_fromKeyStorage(wpa_s->current_ssid->user_key_uri, &cert[cert_len]);
	if (tmp_len < 0){
		wpa_printf(MSG_WAPI, "%s: Failed to parse WAPI user key certificate", __func__);
		return -1;
	}
	cert_len += tmp_len;

	int root_len =  wapi_get_fromKeyStorage(wpa_s->current_ssid->as_cert_uri, root);
	if (root_len < 0)
	{
		wpa_printf(MSG_WAPI, "%s: Failed to parse WAPI root certificate", __func__);
		return -1;
	}

	if (wapi_ec_extract_pkey_from_PEM((char *) cert, cert_len, sm->asue_priv_key)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error extracting private key", __func__);
		return -1;
	}

	if (wapi_ec_X509_PEM_to_DER((char *) cert, cert_len, &(sm->asue_cert_len), sm->asue_cert)) {
		wpa_printf(MSG_WAPI, "WAPI %s: error decoding user certificate", __func__);
		return -1;
	}

	if (sm->root_cert)
		X509_free(sm->root_cert);
	sm->root_cert = wapi_X509_from_PEM((char *) root, root_len);
	if (!sm->root_cert) {
		wpa_printf(MSG_WAPI, "WAPI %s: error decoding root certificate", __func__);
		return -1;
	}

	return 0;
}

static int wapi_get_fromKeyStorage(const char* key, char* value)
{
#define KEYSTORE "keystore://"
    if (NULL == key || NULL == value) {
        wpa_printf(MSG_ERROR, "key or value is NULL");
        return -1;
    }

    if (strlen(key) < strlen(KEYSTORE)) {
        wpa_printf(MSG_ERROR, "key must be at least %d chars", strlen(KEYSTORE));
        return -1;
    }

    if (strncmp(KEYSTORE, key, strlen(KEYSTORE))) {
        wpa_printf(MSG_ERROR, "key must contain the phrase \"%s\"", KEYSTORE);
        return -1;
    }
    return keystore_get(&key[11], value);
}
