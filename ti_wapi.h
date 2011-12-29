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
 * ti_wapi.h
 *
 */

#ifndef WAPI_H_
#define WAPI_H_

#include "common.h"
#include "ec.h"
#include <openssl/ec.h>

#ifndef BIT
#define BIT(n) (1 << (n))
#endif

#ifndef MIN
   #define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#define WAPI_CERT_REQ "CTRL-REQ-WAPI_CERT"
#define WAPI_CERT_RSP "CTRL-RSP-WAPI_CERT"

#define MSG_WAPI MSG_DEBUG
#define MSG_WAPI_DEBUG MSG_INFO

#define WAPI_INFO_ELEM 0x44
#define WAPI_VERSION 1
#define WAPI_SELECTOR_LEN 4
#define WAPI_ETHER_TYPE 0x88B4

#define WAPI_MAX_MESSAGE_LENGTH 32000
#define WAPI_CHALLENGE_LEN 32

/* unicast key */
#define WAPI_UEK_LEN 16
#define WAPI_UCK_LEN 16
#define WAPI_KCK_LEN 16
#define WAPI_KEK_LEN 16

/* multicast key */
#define WAPI_MSK_LEN 16
#define WAPI_MIC_LEN 16
#define WAPI_NMK_LEN 16

#define WAPI_BK_LEN  16
#define WAPI_MAC_LEN 20
#define WAPI_MORE_FRAG BIT(0)

struct wapi_wai_hdr {
	u8 version[2];
	u8 type;
	u8 subtype;
	u8 reserved[2];
	u8 len[2];
	u8 pkt_seq[2];
	u8 frag_seq;
	u8 more_frag;
} STRUCT_PACKED;

typedef enum {
	WAPI_SUBTYPE_PRE_AUTH_START            = 0x01,
	WAPI_SUBTYPE_ST_STAKEY_REQ             = 0x02,
	WAPI_SUBTYPE_AUTH_ACTIVACTION          = 0x03,
	WAPI_SUBTYPE_ACCESS_AUTH_REQ           = 0x04,
	WAPI_SUBTYPE_ACCESS_AUT_RESP           = 0x05,
	WAPI_SUBTYPE_CERT_AUTH_REQ             = 0x06,
	WAPI_SUBTYPE_CERT_AUTH_RES             = 0x07,
	WAPI_SUBTYPE_UKEY_NEGO_REQ             = 0x08,
	WAPI_SUBTYPE_UKEY_NEGO_RES             = 0x09,
	WAPI_SUBTYPE_UKEY_NEGO_CONFIRM         = 0x0a,
	WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE      = 0x0b,
	WAPI_SUBTYPE_MKEY_STAKEY_ANNOUNCE_RES  = 0x0c
} wapi_msg_subtype;

typedef enum {
	WAPI_PSK_MODE_ASCII,
	WAPI_PSK_MODE_HEX
} wapi_psk_mode;


#define WAPI_MAX_BKID 20
#define WAPI_BKID_LEN 16
#define WAPI_AUTH_ID_LEN 32
#define WAPI_SIGNATURE_ALG_LEN 18
#define SHA256_DIGEST_SIZE 32
#define WAPI_CTRL_IFACE_LEN 10000
#define WAPI_CERT_LEN 5000
#define WAPI_MTU 1486

/* suite selector bits now defined in config_ssid.h
#define WAPI_CIPHER_SMS4 BIT(1)
#define WAPI_AUTH_CERTIFICATE BIT(1)
#define WAPI_AUTH_PSK BIT(2)   */

struct wapi_ie {
	u8 id;
	u8 length;
	u16 version;

	/* akm_suite, unicast_suite & multicast_suite to be used with "suite
	 * selector bits from above */
	int akm_suite;
	int unicast_suite;
	int multicast_suite;
	u16 capabilities;

	u16 bkid_count;
	u8 bkid[WAPI_MAX_BKID][WAPI_BKID_LEN];
};

#define WAPI_MAX_KEY_DATA_LEN 256

struct wapi_key_data {
	u8 len;
	u8 content[WAPI_MAX_KEY_DATA_LEN];
} STRUCT_PACKED;


#define WAPI_MSG_AUTH_CODE_LEN 20
#define WAPI_DATA_PKT_NUM_LEN 16
#define WAPI_KEY_ANNOUNCMENT_ID_LEN 16
#define WAPI_ACCESS_RESULT_SUCCESS 0

struct wapi_tlv {
	int type;
	size_t len;
	u8 *value;
};

struct wapi_signature {
	u8 id;
	u16 len;
	struct wapi_tlv identity;
	u8 signature_alg[WAPI_SIGNATURE_ALG_LEN];
	struct wapi_tlv signature;
	u8 ecdsa[WAPI_EC_ECDSA_LEN];
};

struct wapi_auth_result {
	u8 type;
	size_t len;
	u8 nonce1[WAPI_CHALLENGE_LEN];
	u8 nonce2[WAPI_CHALLENGE_LEN];
	u8 ver_result1;
	struct wapi_tlv cert1;
	u8 ver_result2;
	struct wapi_tlv cert2;

	const u8 *raw_mcvr;
	size_t raw_mcvr_len;
};

struct wapi_msg {
	struct wapi_wai_hdr header;
	u8    flag;
	u8    bkid[WAPI_BKID_LEN];
	u8    uskid;
	u8    addid[ETH_ALEN*2];
	u8    ae_challenge[WAPI_CHALLENGE_LEN];
	u8    asue_challenge[WAPI_CHALLENGE_LEN];
	u8    msg_auth_code[WAPI_MSG_AUTH_CODE_LEN];
	u8    mskid_stakid;
	u8    data_pkt_num[WAPI_DATA_PKT_NUM_LEN];
	u8    key_announcment_id[WAPI_KEY_ANNOUNCMENT_ID_LEN];
	u8    kck[WAPI_KCK_LEN];
	struct wapi_key_data key_data;
	struct wapi_key_data ae_key_data;
	struct wapi_key_data asue_key_data;

	struct wapi_ie wapi_ie;

	/* certificate messages */
	/* authentication activation */
	struct wapi_tlv id_asu;
	struct wapi_tlv ae_cert;
	struct wapi_tlv ecdh_params;
	u8 auth_id[WAPI_AUTH_ID_LEN];

	/* access authentication request */
	struct wapi_tlv id_ae;
	struct wapi_tlv asue_cert;
	struct wapi_signature signature;

	/* access authentication response */
	u8 access_result;

	struct wapi_tlv id_asue;

	/*struct wapi_tlv auth_result;*/
	struct wapi_auth_result auth_result;

	struct wapi_signature server_signature_asue;
	struct wapi_signature server_signature_ae;

	size_t signed_content_length;

};



/* other states are not needed for now */
typedef enum {
/*	WAPI_STATE_DISCONNECT,
	WAPI_STATE_INITIALIZE,
	WAPI_STATE_AUTHENTICATION,*/
	WAPI_STATE_INITPSK,
/*	WAPI_STATE_BKNEGOTIATING,
	WAPI_STATE_BKDONE, */
	WAPI_STATE_USKNEGOTIATING,
	WAPI_STATE_USKDONE,
/*	WAPI_STATE_MSKDONE,
	WAPI_STATE_IDLE, */
	WAPI_STATE_DONE

} wapi_state;


struct wapi_usk {
	u8 uek[WAPI_UEK_LEN];
	u8 uck[WAPI_UCK_LEN];
	u8 kck[WAPI_KCK_LEN];
	u8 kek[WAPI_KEK_LEN];
	u8 challenge_seed[WAPI_CHALLENGE_LEN];
} STRUCT_PACKED;

struct wapi_mcast_key {
	u8 msk[WAPI_MSK_LEN];
	u8 mic[WAPI_MIC_LEN];
} STRUCT_PACKED;


struct wapi_sm {
	struct wapi_usk usk;
	struct wapi_mcast_key mkey;

	u8 bk[WAPI_BK_LEN];

	wapi_state state;

	u8* ie_assoc;
	size_t ie_assoc_len;

	u8* ie_ap;
	size_t ie_ap_len;

	u8 prev_key_announcement[WAPI_KEY_ANNOUNCMENT_ID_LEN];
	u8 bssid[ETH_ALEN];
	u8 asue_challenge[WAPI_CHALLENGE_LEN];

	u8* trunc_msg;
	size_t trunc_msg_len;
	int frag_seq;

	int new_challenge;
	int new_ecdh;

	struct wpa_ssid *cur_ssid;
	u16 pkt_seq;

	EC_KEY *ecdh_key;
	struct wapi_msg reentrant_msg;
	u8 *reentrant_raw;
	size_t reentrant_raw_len;
	int fetch_cert;
	X509 *ae_cert;
	X509 *root_cert;

	/* info from the repository */
	u8 asue_cert[WAPI_CERT_LEN];
	size_t asue_cert_len;
	u8 asue_priv_key[WAPI_EC_PRIV_LEN];
};

#define WAPI_FLAG_BK_REKEYING     BIT(0)
#define WAPI_FLAG_PRE_AUTH        BIT(1)
#define WAPI_FLAG_CERT_AUTH_REQ   BIT(2)
#define WAPI_FLAG_OPTIONAL        BIT(3)
#define WAPI_FLAG_USK_REKEYING    BIT(4)
#define WAPI_FLAG_STAKEY_NEGO     BIT(5)
#define WAPI_FLAG_STAKEY_REVOKING BIT(6)
#define WAPI_FLAG_RESERVED        BIT(7)

#define WAPI_MSKID_KEYID     BIT(0)
#define WAPI_USKID_KEYID     BIT(0)



int wapi_encode_msg( struct wapi_sm *sm,
			 struct wapi_msg *msg,
		     u8 **output_buffer,
		     size_t *output_buffer_length, u8 *key);


void wapi_sms4(const u8 *key, size_t keylen, const u8 *iv,
	      u8 *data, size_t data_len);

int wapi_decode_msg( struct wapi_msg *params,
		     const u8 *input_buffer,
		     size_t input_buffer_length);


void wapi_notify_assoc(struct wapi_sm *sm, const u8 *bssid);
void wapi_notify_disassoc(struct wapi_sm *sm);
int wapi_set_assoc_ie(struct wapi_sm *sm, const u8 *ie, size_t len);
int wapi_set_ap_ie(struct wapi_sm *sm, const u8 *ie, size_t len);

struct wpa_scan_result;
struct wpa_ssid;
struct wpa_supplicant;

int wapi_set_suites(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *bss,
			      struct wpa_ssid *ssid,
			      u8 *wpa_ie, size_t *wpa_ie_len);

void wapi_set_config(struct wapi_sm *sm, struct wpa_ssid *config);
void wapi_deinit_sm(struct wapi_sm *sm);

void wapi_rx_wai(void *ctx, const u8 *src_addr, const u8 *buf, size_t len);

int wapi_tx_wai(struct wpa_supplicant *wpa_s, const u8 *dest,
			       u8 *msg, size_t msg_len);

void wapi_init_sm(struct wapi_sm *sm);

int wapi_parse_ie(const u8 *wapi_ie_buf, size_t wapi_ie_len,
		struct wapi_ie *ie);

int wapi_answer_auth_activation(struct wpa_supplicant *wpa_s, struct wapi_msg *msg);

int wapi_handle_cmds(struct wpa_supplicant *wpa_s, char *buf);

#endif /* WAPI_H_ */
