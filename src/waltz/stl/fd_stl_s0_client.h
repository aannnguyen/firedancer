#ifndef HEADER_stl_s0_client_h
#define HEADER_stl_s0_client_h

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include <stdbool.h>

struct stl_s0_client_params {

  /* identity is a compound structure of the identity private and
     public key */
  uchar identity[ STL_EDBLAH_KEY_SZ ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uchar cookie_secret[ STL_COOKIE_KEY_SZ ];

};

typedef struct stl_s0_client_params stl_s0_client_params_t;

/* TODO: decouple handshake, connection, and client objects*/
struct stl_s0_client_hs {
  uchar server_token[ STL_TOKEN_SZ ]; /* TODO: unnecessary? */
  uchar client_token[ STL_TOKEN_SZ ];
  // crypto_hash_sha256_state transcript;
  uchar state;
  uchar session_id[ STL_SESSION_ID_SZ ];
  uchar server_identity[ STL_EDBLAH_KEY_SZ ];
};

typedef struct stl_s0_client_hs stl_s0_client_hs_t;

FD_PROTOTYPES_BEGIN

stl_s0_client_hs_t *
stl_s0_client_hs_new( void * hs );

ulong
stl_s0_client_initial( stl_s0_client_params_t const * client,
                       stl_s0_client_hs_t const *     hs,
                       uchar                        pkt_out[ static STL_MTU ] );

ulong
stl_s0_client_handshake( stl_s0_client_params_t const * client,
                         stl_s0_client_hs_t *           hs,
                         uchar const *                pkt_in,
                         ulong                       pkt_in_sz,
                         uchar                        pkt_out[ static STL_MTU ] );

/*
  stl_s0_encode_appdata is a temporary function that encodes the payload into
  pkt_out using STL 0x1. It takes session details from hs. It returns the total
  number of bytes encoded, or a negative value for err
*/
long
stl_s0_encode_appdata( stl_s0_client_hs_t * hs,
                     const uchar *      payload, /* TODO: create a 0cp mode */
                     ushort             payload_sz,
                     uchar              pkt_out[ static STL_MTU ] );

FD_PROTOTYPES_END

#endif /* HEADER_stl_s0_client_h */
