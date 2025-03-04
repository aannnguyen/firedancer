
#include "fd_stl_base.h"
#include "fd_stl_s0_server.h"
#include "fd_stl_s0_client.h"
#include "fd_stl_proto.h"
#include "fd_stl_private.h"
#include "fd_stl.h"

#include <string.h>

#if 0
static char const sign_prefix_server[32] =
  "STL v0 s0 server transcript     ";

static char const sign_prefix_client[32] =
  "STL v0 s0 client transcript     ";
#endif

long
fd_stl_s0_server_handle_initial( fd_stl_s0_server_params_t const * server,
                              stl_net_ctx_t const *          ctx,
                              stl_s0_hs_pkt_t const *        pkt,
                              uchar                        out[ STL_MTU ],
                              fd_stl_s0_server_hs_t *           hs ) {

  (void)pkt;

  /* Create a SYN cookie */

  stl_cookie_claims_t claims[1];
  fd_memset( claims, 0, sizeof(claims) );
  claims->net   = *ctx;

  uchar cookie[ STL_COOKIE_SZ ];
  stl_cookie_create( cookie, claims, server->cookie_secret );

  /* Send back the cookie and our server identity */

  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;
  fd_memset( out_pkt, 0, sizeof(*out_pkt) );

  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_SERVER_CONTINUE );
  fd_memcpy( out_pkt->hs.cookie,    cookie,            STL_COOKIE_SZ );
  fd_memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ  );
  fd_memcpy( out_pkt->server_token, server->token,     STL_TOKEN_SZ  );
  fd_memcpy( out_pkt->identity, server->identity, STL_COOKIE_KEY_SZ*2); /* FIXME, probs being very dumb */

  /* Return info to user */

  fd_memset( hs, 0, sizeof(fd_stl_s0_server_hs_t) );
  hs->done = 0;

  return sizeof(stl_s0_hs_pkt_t);
}

long
fd_stl_s0_server_handle_accept( fd_stl_s0_server_params_t const * server,
                             stl_net_ctx_t const *          ctx,
                             stl_s0_hs_pkt_t const *        pkt,
                             uchar                        out[ STL_MTU ],
                             fd_stl_s0_server_hs_t *           hs,
                             fd_stl_sesh_t * sesh ) {

  /* Verify the SYN cookie */

  stl_cookie_claims_t claims[1];
  fd_memset( claims, 0, sizeof(claims) );
  claims->net   = *ctx;

  if( !stl_cookie_verify( pkt->hs.cookie, claims, server->cookie_secret ) )
    return 0UL;


  uchar server_pubkey[32];
  fd_memcpy( server_pubkey, server->identity, STL_COOKIE_KEY_SZ*2 );
#if 0
  /* Create the transcript hash */
  crypto_hash_sha256_state state0[1];
  crypto_hash_sha256_state state1[1];
  crypto_hash_sha256_init( state0 );
  crypto_hash_sha256_update( state0, server_pubkey,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state0, pkt->identity,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state0, server->token,     STL_TOKEN_SZ );
  crypto_hash_sha256_update( state0, pkt->client_token, STL_TOKEN_SZ );
  crypto_hash_sha256_update( state0, (uchar const *)&claims->suite, sizeof(ushort) );
  *state1 = *state0;

  /* Verify signature */

  uchar client_signed_msg[64];
  fd_memcpy( client_signed_msg, sign_prefix_client, 32 );
  crypto_hash_sha256_final( state0, client_signed_msg+32 );

  int vfy_err = crypto_sign_ed25519_verify_detached(
      pkt->verify, client_signed_msg, sizeof(client_signed_msg), pkt->identity );
  if( vfy_err ) return 0UL;
#endif

  /* Derive session ID */

  uchar session_id[ STL_SESSION_ID_SZ ];
  stl_gen_session_id( session_id );

  /* Prepare response */

  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;
  fd_memset( out_pkt, 0, sizeof(*out_pkt) );

#if 0
  uchar server_commitment[ crypto_hash_sha256_BYTES ];
  crypto_hash_sha256_update( state1, session_id, STL_SESSION_ID_SZ );
  crypto_hash_sha256_final( state1, server_commitment );

  /* Sign verify */

  uchar server_signed_msg[64];
  fd_memcpy( server_signed_msg,    sign_prefix_server, 32 );
  fd_memcpy( server_signed_msg+32, server_commitment,  32 );

  crypto_sign_ed25519_detached(
      out_pkt->verify, NULL, server_signed_msg, sizeof(server_signed_msg), server->identity );
#endif

  /* Send back response */

  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_SERVER_ACCEPT );
  fd_memcpy( out_pkt->hs.cookie,    pkt->hs.cookie,    STL_COOKIE_SZ );
  fd_memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ  );
  fd_memcpy( out_pkt->server_token, server->token,     STL_TOKEN_SZ  );
  fd_memcpy( out_pkt->hs.base.session_id, session_id, STL_SESSION_ID_SZ );

  /* Return info to caller */

  fd_memset( hs, 0, sizeof(fd_stl_s0_server_hs_t) );
  hs->done = 1;
  fd_memcpy( hs->session_id, session_id, STL_SESSION_ID_SZ );
  fd_memcpy( &hs->identity, pkt->identity, STL_COOKIE_KEY_SZ );

  sesh->session_id = FD_LOAD( ulong, hs->session_id );
  sesh->socket_addr = ctx->b;
  sesh->server = 1;

  return sizeof(stl_s0_hs_pkt_t);
}

// long
// fd_stl_s0_server_handshake( fd_stl_s0_server_params_t const * server,
//                          stl_net_ctx_t const *          ctx,
//                          uchar const *                in,
//                          ulong                       in_sz,
//                          uchar                        out[ STL_MTU ],
//                          fd_stl_s0_server_hs_t *           hs ) {

//   if( FD_UNLIKELY( in_sz < 1200UL ) )
//     return 0UL;

//   stl_s0_hs_pkt_t const * pkt = (stl_s0_hs_pkt_t const *)in;

//   if( FD_UNLIKELY( stl_hdr_version( &pkt->hs.base ) != STL_V0 ) )
//     return 0UL;

//   switch( stl_hdr_type( &pkt->hs.base ) ) {
//   case STL_TYPE_HS_CLIENT_INITIAL:
//     return fd_stl_s0_server_handle_initial( server, ctx, pkt, out, hs );
//   case STL_TYPE_HS_CLIENT_ACCEPT:
//     return fd_stl_s0_server_handle_accept( server, ctx, pkt, out, hs );
//   default:
//     return 0UL;
//   }

// }

void
fd_stl_s0_server_rotate_secrets( fd_stl_s0_server_params_t * server ) {
  static fd_rng_t _rng[1];
  static int _done_init = 0;
  if( !_done_init ) {
    fd_rng_join( fd_rng_new( _rng, 3, 4 ) ); /* TODO - figure out correct args here */
    _done_init = 1;
  }

  *(ulong*)(server->cookie_secret)   = fd_rng_ulong( _rng );
  *(ulong*)(server->cookie_secret+8) = fd_rng_ulong( _rng );
}

fd_stl_s0_client_hs_t *
fd_stl_s0_client_hs_new( void * mem ) {

  fd_stl_s0_client_hs_t * hs = (fd_stl_s0_client_hs_t *)mem;
  fd_memset( hs, 0, sizeof(fd_stl_s0_client_hs_t) );
  hs->state = STL_TYPE_HS_CLIENT_INITIAL;
  return hs;
}

long
fd_stl_s0_client_initial( fd_stl_s0_client_params_t const * client,
                       fd_stl_s0_client_hs_t const *     hs,
                       uchar                        pkt_out[ STL_MTU ] ) {

  stl_s0_hs_pkt_t * pkt = (stl_s0_hs_pkt_t *)pkt_out;
  fd_memset( pkt, 0, 1200 );  /* TODO fix magic constant */
  pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_CLIENT_INITIAL );
  fd_memcpy( pkt->identity, client->identity, STL_COOKIE_KEY_SZ*2 );
  fd_memcpy( pkt->client_token, hs->client_token, STL_TOKEN_SZ );
  return 1200;
}

long
fd_stl_s0_client_handle_continue( fd_stl_s0_client_params_t const * client,
                               stl_s0_hs_pkt_t const *        pkt,
                               uchar                        out[ STL_MTU ],
                               fd_stl_s0_client_hs_t *           hs ) {

  if( FD_UNLIKELY( stl_hdr_type( &pkt->hs.base ) != STL_TYPE_HS_SERVER_CONTINUE ) )
    return 0UL;

  /* Ignore packet if server identity is unexpected */

  if( FD_UNLIKELY( 0!=memcmp( pkt->identity, hs->server_identity, STL_EDBLAH_KEY_SZ ) ) )
    return 0UL;

  uchar client_identity[ 32 ];
  fd_memcpy( client_identity, client->identity, STL_COOKIE_KEY_SZ*2 );

#if 0
  /* Create transcript hash */
  crypto_hash_sha256_state state[1];
  crypto_hash_sha256_init( state );
  crypto_hash_sha256_update( state, hs->server_identity, crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state, client_identity,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state, pkt->server_token,   STL_TOKEN_SZ );
  crypto_hash_sha256_update( state, hs->client_token,    STL_TOKEN_SZ );
  crypto_hash_sha256_update( state, (uchar const *)&pkt->hs.suite, sizeof(ushort) );
  /* FIXME: add cookie to hash */
  hs->transcript = *state;

  uchar client_signed_msg[ 64 ]; /* TODO: client_to_be_signed :) */
  fd_memcpy( client_signed_msg, sign_prefix_client, 32 );
  crypto_hash_sha256_final( state, client_signed_msg+32 );

#endif
  /* Assemble response */
  fd_memset( out, 0, 1200UL );
  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;

#if 0
  /* Sign */

  int sign_err = crypto_sign_ed25519_detached( out_pkt->verify, NULL, client_signed_msg, sizeof(client_signed_msg), client->identity );
  if( FD_UNLIKELY( sign_err ) ) return 0UL;
#endif
  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_CLIENT_ACCEPT );
  fd_memcpy( out_pkt->hs.cookie,    pkt->hs.cookie,    STL_COOKIE_SZ );
  fd_memcpy( out_pkt->identity,     client_identity,   STL_EDBLAH_KEY_SZ );
  fd_memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ );
  fd_memcpy( out_pkt->server_token, pkt->server_token, STL_TOKEN_SZ );

  hs->state = STL_TYPE_HS_SERVER_CONTINUE;

  return 1200UL;
}

long
fd_stl_s0_client_handle_accept( fd_stl_t* stl,
                                stl_s0_hs_pkt_t const * pkt,
                                uchar                  out[ STL_MTU ],
                                fd_stl_s0_client_hs_t *    hs ) {

  (void)out;
  if( FD_UNLIKELY( stl_hdr_type( &pkt->hs.base ) != STL_TYPE_HS_SERVER_ACCEPT ) )
    return 0UL;

#if 0
  /* Derive server commitment */

  crypto_hash_sha256_state state[1];
  *state = hs->transcript;
  crypto_hash_sha256_update( state, pkt->hs.base.session_id, STL_SESSION_ID_SZ );

  /* Verify server signature */

  uchar signed_msg[64];
  fd_memcpy( signed_msg, sign_prefix_server, 32 );
  crypto_hash_sha256_final( state, signed_msg+32 );

  int vfy_err = crypto_sign_ed25519_verify_detached(
      pkt->verify, signed_msg, sizeof(signed_msg), hs->server_identity );
  if( vfy_err ) return 0UL;
#endif

  /* Success!  Return info to caller */

  hs->state = STL_TYPE_HS_SERVER_ACCEPT;
  fd_memcpy( hs->session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ );

  /* create a new session object */
  fd_stl_state_private_t * priv = (fd_stl_state_private_t *)(stl+1);
  fd_stl_sesh_t * sesh = priv->sessions + priv->session_sz++;

  sesh->session_id = FD_LOAD( ulong, hs->session_id);
  sesh->socket_addr = hs->socket_addr;
  sesh->server = 0;

  uchar buf[STL_MTU];
  stl_net_ctx_t sock_addr = {0};
  for (uchar i = 0; i < hs->buffers_sz; i++) {
    long sz = fd_stl_s0_encode_appdata( sesh, hs->buffers[i].data, hs->buffers[i].sz, buf );
    if (sz > 0) {
      sock_addr.b = sesh->socket_addr;
      stl->cb.tx( stl, &sock_addr, buf, (ulong)sz );
    }
  }

  return 0UL;
}

// long
// fd_stl_s0_client_handshake( fd_stl_s0_client_params_t const * client,
//                          fd_stl_s0_client_hs_t *           hs,
//                          uchar const *                pkt_in,
//                          ulong                       pkt_in_sz,
//                          uchar                        pkt_out[ static STL_MTU ] ) {

//   if( FD_UNLIKELY( pkt_in_sz < sizeof(stl_s0_hs_pkt_t) ) )
//     return 0UL;

//   stl_s0_hs_pkt_t const * pkt = (stl_s0_hs_pkt_t const *)pkt_in;

//   if( FD_UNLIKELY(
//       /* Verify protocol version */
//       ( stl_hdr_version( &pkt->hs.base ) != STL_V0       ) |
//       /* Verify client token */
//       ( 0!=memcmp( pkt->client_token, hs->client_token, STL_TOKEN_SZ ) ) ) )
//     return 0UL;

//   switch( hs->state ) {
//   case STL_TYPE_HS_CLIENT_INITIAL:
//     return stl_s0_client_handle_continue( client, pkt, pkt_out, hs );
//   case STL_TYPE_HS_SERVER_CONTINUE:
//     return stl_s0_client_handle_accept  ( pkt, hs );
//   default:
//     return 0UL;
//   }

// }

long
fd_stl_s0_encode_appdata( fd_stl_sesh_t * sesh,
                     const uchar *      payload, /* TODO: create a 0cp mode */
                     ushort             payload_sz,
                     uchar              pkt_out[ STL_MTU ] ) {
  stl_hdr_t* ptr = (stl_hdr_t*)pkt_out;
  ptr->version_type = stl_hdr_version_type( STL_V0, STL_TYPE_APP_SIMPLE );
  fd_memcpy( ptr->session_id, &(sesh->session_id), STL_SESSION_ID_SZ );

  uchar* payload_ptr = (uchar*)(ptr+1);
  fd_memcpy( payload_ptr, payload, payload_sz );
  payload_ptr += payload_sz;

  /* append some fake MAC */
  fd_memset( payload_ptr, 0xff, STL_MAC_SZ);
  payload_ptr += STL_MAC_SZ;

  return payload_ptr-pkt_out;
}

long
fd_stl_s0_decode_appdata(fd_stl_s0_server_hs_t* hs,
                      const uchar* encoded_buf,
                      ushort encoded_sz,
                      uchar pkt_out[STL_BASIC_PAYLOAD_MTU]) {
  /* Check minimum packet size (version + session_id + MAC) */
  const ushort min_size = 1 + STL_SESSION_ID_SZ + STL_MAC_SZ;
  if( encoded_sz < min_size ) {
      return -1;
  }

  const uchar* ptr = encoded_buf;

  /* Check version and type */
  if( *ptr != 0x1 ) { // version 0, type 1
      return -2;
  }
  ptr += 1;

  /* Verify session id */
  if( memcmp( ptr, hs->session_id, STL_SESSION_ID_SZ ) != 0 ) {
      return -3;
  }
  ptr += STL_SESSION_ID_SZ;

  /* Verify MAC (currently fake in encode, so just check for 0xff) */
  const uchar* mac_ptr = encoded_buf + encoded_sz - STL_MAC_SZ;
  for( ulong i=0; i<STL_MAC_SZ; i++ ) {
      if( mac_ptr[i]!= 0xff ) {
          return -4;
      }
  }

  /* Calculate payload size (everything after headers) */
  long read_sz = mac_ptr - ptr;
  if( read_sz > 0)
    fd_memcpy( pkt_out, ptr, (size_t)read_sz );

  return read_sz;
}

