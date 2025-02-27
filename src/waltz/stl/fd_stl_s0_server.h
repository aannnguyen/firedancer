#ifndef HEADER_stl_s0_server_h
#define HEADER_stl_s0_server_h

/* stl_s0.h provides APIs for STL in suite S0 mode (unencrypted). */

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include <stdbool.h>

struct stl_s0_server_params {

  /* identity is a compound structure of the identity private and
     public key */
  uchar identity[ STL_COOKIE_KEY_SZ * 2 ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uchar cookie_secret[ STL_COOKIE_KEY_SZ ];

  uchar token[16];

};

typedef struct stl_s0_server_params stl_s0_server_params_t;

struct stl_s0_server_hs {
  uchar identity[ STL_COOKIE_KEY_SZ ];
  uchar session_id[ STL_SESSION_ID_SZ ];
  bool    done;
};

typedef struct stl_s0_server_hs stl_s0_server_hs_t;

FD_PROTOTYPES_BEGIN

ulong
stl_s0_server_handshake( stl_s0_server_params_t const * server,
                         stl_net_ctx_t const *          ctx,
                         uchar const *                in,
                         ulong                       in_sz,
                         uchar                        out[ STL_MTU ],
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
long
stl_s0_decode_appdata( stl_s0_server_hs_t* hs,
                       const uchar* encoded_buf,
                       ushort encoded_sz,
                       uchar  pkt_out[static STL_BASIC_PAYLOAD_MTU] );
                       /* FIX ME get rid of static keyword in buf allocs */

FD_PROTOTYPES_END

#endif /* HEADER_stl_s0_server_h */
