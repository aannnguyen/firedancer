#ifndef HEADER_stl_private_h
#define HEADER_stl_private_h

/* stl_private.h contains reusable internal modules.  The APIs in this
   file may change without notice. */

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include <stdint.h>
#include <stddef.h>

/* stl_cookie_claims_t contains the public data hashed into the
   cookie value. */

union __attribute__((aligned(16UL))) stl_cookie_claims {

  struct __attribute__((packed)) {
    stl_net_ctx_t net;
    uint16_t      suite;
    uint8_t       padding[ 12 ];
  };

# define STL_COOKIE_CLAIMS_B_SZ (20UL)
  uint8_t b[ STL_COOKIE_CLAIMS_B_SZ ];

};

typedef union stl_cookie_claims stl_cookie_claims_t;


_Static_assert( offsetof(stl_cookie_claims_t, padding) == STL_COOKIE_CLAIMS_B_SZ,
                "stl_cookie_claims_t is not packed" );

STL_PROTOTYPES_BEGIN

/* stl_cookie_create issues a cookie for the Server Continue
   packet.  hs contains the incoming Client Initial packet for which
   a cookie should be issued.  Writes the HMAC cookie to the given
   array and returns it. */

uint8_t *
stl_cookie_create( uint8_t                     cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uint8_t const               cookie_secret[ static STL_COOKIE_KEY_SZ ] );

/* stl_cookie_verify verifies a cookie in a Client Accept
   packet.  Returns 1 if cookie is valid.  Otherwise, returns 0. */

__attribute__((pure,warn_unused_result))
int
stl_cookie_verify( uint8_t const               cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uint8_t const               cookie_secret[ static STL_COOKIE_KEY_SZ ] );

/* stl_gen_session_id generates a new random session ID. */

void
stl_gen_session_id( uint8_t session_id[ static STL_SESSION_ID_SZ ] );

STL_PROTOTYPES_END

#endif /* HEADER_stl_private_h */
