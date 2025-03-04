#ifndef HEADER_stl_proto_h
#define HEADER_stl_proto_h

/* stl_proto.h defines STL protocol data structures. */

#include "fd_stl_base.h"
#include <stdint.h>

/* STL_MTU controls the maximum supported UDP payload size. */

#define STL_MTU     (2048UL)
#define STL_MTU_MIN (1200UL)

/* STL_V{...} identify STL versions. */

#define STL_V0  ((uchar)0x00)

/* STL_TYPE_{...} identify STL packet types. */

#define STL_TYPE_NULL               ((uchar)0x00)  /* invalid */
#define STL_TYPE_APP_SIMPLE         ((uchar)0x01)
#define STL_TYPE_APP_AUTH           ((uchar)0x02)
#define STL_TYPE_APP_ENCRYPTED      ((uchar)0x03)
#define STL_TYPE_APP_TLV            ((uchar)0x04)

#define STL_TYPE_HS_CLIENT_INITIAL  ((uchar)0x08)
#define STL_TYPE_HS_SERVER_CONTINUE ((uchar)0x09)
#define STL_TYPE_HS_CLIENT_ACCEPT   ((uchar)0x0A)
#define STL_TYPE_HS_SERVER_ACCEPT   ((uchar)0x0B)

#define STL_TYPE_HS_DONE            ((uchar)0xFF) /* invalid on wire */

/* STL_SUITE_{...} defines cipher suite IDs.

   Each suite consists of:
   - A signature scheme for authentication
   - A key exchange mechanism
   - An authenticated encrypted scheme
   - A hash function for key expansion */

#define STL_SUITE_S0  ((ushort)0x0000)  /* Ed25519 auth, unencrypted */
#define STL_SUITE_S1  ((ushort)0x0001)  /* Ed25519 auth, X25519 KEX, AES-128-GCM AEAD, HMAC-SHA256 hash */

/* STL_SESSION_ID_SZ is the byte size of the session ID. */

#define STL_SESSION_ID_SZ (7UL)

/* STL_COOKIE_SZ is the cookie byte size used in the handshake
   mechanism.  (Handshake cookies are analogous to TCP SYN cookies). */

#define STL_COOKIE_SZ (8UL)

#define STL_COOKIE_KEY_SZ (16UL)

#define STL_ED25519_KEY_SZ (32UL)

/* STL_TOKEN_SZ is the byte size of the "random token" value.  Both
   client and server mix in their token value into the handshake
   commitment to prevent replay attacks. */

#define STL_TOKEN_SZ (16UL)

/* STL_MAC_SZ is the byte size of the MAC tag in authenticated packets */

#define STL_MAC_SZ (16UL)

/* STL_BASIC_PAYLOAD_MTU is the MTU of the payload carried by the
   0x1 frame type */

#define STL_BASIC_PAYLOAD_MTU (STL_MTU - STL_SESSION_ID_SZ - STL_MAC_SZ - 1)

#define FD_STL_MAX_BUF (2UL)

#define FD_STL_MAX_SESSION_TMP (3)

#define FD_STL_MAGIC (0xdeadbeeffeebdaedUL)


struct fd_stl_payload {
   ushort sz;
   uchar data[STL_BASIC_PAYLOAD_MTU];
};

typedef struct fd_stl_payload fd_stl_payload_t;

/* stl_hdr_t is the common STL header shared by all packets. */

struct __attribute__((packed)) stl_hdr {
  uchar version_type;
  uchar session_id[ STL_SESSION_ID_SZ ];
};

typedef struct stl_hdr stl_hdr_t;

/* stl_hs_hdr_t is the STL header shared by all handshake packets. */

struct __attribute__((packed)) stl_hs_hdr {
  stl_hdr_t base;
  uchar   cookie[ STL_COOKIE_SZ ];
};

typedef struct stl_hs_hdr stl_hdr_hs_t;


FD_PROTOTYPES_BEGIN

/* stl_hdr_{version,type} extract the version and type fields from
   an stl_hdr_t. */

__attribute__((pure))
static inline uchar
stl_hdr_version( stl_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type >> 4 );
}

__attribute__((pure))
static inline uchar
stl_hdr_type( stl_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type & 0x0F );
}

/* stl_hdr_version_type assembles the version_type compound field. */

__attribute__((const))
static inline uchar
stl_hdr_version_type( unsigned int version,
                      unsigned int type ) {
  return (uchar)( ( version << 4 ) | ( type & 0x0F ) );
}

/* seq_{compress,expand} compress 64-bit sequence numbers to 32-bit
   compact versions and vice versa.

   seq_compress implements lossy compression by masking off the high
   half of the sequence number.

   seq_expand attempts to recover a 64-bit sequence given the
   compressed form (seq_compact), and the largest previously
   recovered sequence number (last_seq; does not necessarily have
   to be the previous packet).  For a given unreliable packet stream,
   seq_expand returns the correct result assuming conditions:

   1. The sequence number increments by one for each packet in the
      original order that the packets were sent in.
   2. Less than 2^31 packets were lost between the packet that
      yielded last_seq and the packet carrying seq_compact.
      (Otherwise, the returned sequence number is too small)
   3. The packet carrying seq_compact was reordered less than 2^31
      packets ahead.  (Otherwise, the returned sequence number is
      too large)

   The re-expanded packet number must be authenticated.  E.g.
   in STL_SUITE_S1, it is part of the IV.  Thus, if an incorrect
   packet number is recovered, decryption fails.  Only sequence
   numbers that passed authentication sholud be considered for
   last_seq. */

static inline uint
seq_compress( ulong seq ) {
  return (uint)seq;
}

static inline ulong
seq_expand( uint seq_compact,
            ulong last_seq ) {
  /* O(3): 32-bit subtract, sign extend, 64-bit add */
  return last_seq + (ulong)(int)(seq_compact - (uint)last_seq);
}

FD_PROTOTYPES_END


/* Suite S0 structures ************************************************/

/* stl_s0_app_hdr_t is the STL header of application unencrypted packets
   using STL_SUITE_S0. */

typedef struct stl_hdr stl_s0_app_hdr_t;

/* stl_s0_hs_pkt_t is the STL header of handshake packets using
   STL_SUITE_S0. */

union __attribute__((packed)) stl_s0_hs_pkt {

  struct {
    stl_hdr_hs_t hs;

    uchar  identity[32];
    uchar  key_share[32];
    uchar  verify[64]; /* signature */
    uchar  client_token[ STL_TOKEN_SZ ];
    uchar  server_token[ STL_TOKEN_SZ ];
  };

  uchar raw[186];

};

typedef union stl_s0_hs_pkt stl_s0_hs_pkt_t;


#endif /* HEADER_stl_proto_h */
