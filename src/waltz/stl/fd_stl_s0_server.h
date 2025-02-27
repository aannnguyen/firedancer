#ifndef HEADER_stl_s0_server_h
#define HEADER_stl_s0_server_h

/* stl_s0.h provides APIs for STL in suite S0 mode (unencrypted). */

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include <stdbool.h>

struct stl_s0_server_params {

  /* identity is a compound structure of the identity private and
     public key */
  uint8_t identity[ STL_COOKIE_KEY_SZ * 2 ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uint8_t cookie_secret[ STL_COOKIE_KEY_SZ ];

  uint8_t token[16];

};

typedef struct stl_s0_server_params stl_s0_server_params_t;

struct stl_s0_server_hs {
  uint8_t identity[ STL_COOKIE_KEY_SZ ];
  uint8_t session_id[ STL_SESSION_ID_SZ ];
  bool    done;
};

typedef struct stl_s0_server_hs stl_s0_server_hs_t;

STL_PROTOTYPES_BEGIN

uint64_t
stl_s0_server_handshake( stl_s0_server_params_t const * server,
                         stl_net_ctx_t const *          ctx,
                         uint8_t const *                in,
                         uint64_t                       in_sz,
                         uint8_t                        out[ STL_MTU ],
                         stl_s0_server_hs_t *           hs );

/* stl_s0_server_rotate_keys re-generates the ephemeral keys
   (cookie_secret and signature_seed).  This invalidates any active
   handshakes.  (Established session IDs are not affected) */

void
stl_s0_server_rotate_keys( stl_s0_server_params_t * server );


/* stl_s0_decode_appdata is a temp function that
   unwraps the STL protocol from the payload. It
   takes encoded_buf off the wire and decodes it
   into pkt_out */
int64_t
stl_s0_decode_appdata( stl_s0_server_hs_t* hs,
                       const uint8_t* encoded_buf,
                       uint16_t encoded_sz,
                       uint8_t  pkt_out[static STL_BASIC_PAYLOAD_MTU] );
                       /* FIX ME get rid of static keyword in buf allocs */

STL_PROTOTYPES_END

#endif /* HEADER_stl_s0_server_h */
