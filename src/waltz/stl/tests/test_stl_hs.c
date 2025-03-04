#define _POSIX_C_SOURCE 199309L

#include "../fd_stl_private.h"
#include "../fd_stl_s0_server.h"
#include "../fd_stl_s0_client.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static long
wallclock( void ) {
  struct timespec ts[1];
  clock_gettime( CLOCK_REALTIME, ts );
  return ((long)1e9)*((long)ts->tv_sec) + (long)ts->tv_nsec;
}


static void
test_s0_handshake( void ) {

  // uchar server_identity_seed[32]={0}; server_identity_seed[31] = 0x01;
  // uchar client_identity_seed[32]={0}; client_identity_seed[31] = 0x81;

  // uchar scratch[32];

  fd_stl_s0_server_params_t server = {0};

  for( uint i=0; i < STL_EDBLAH_KEY_SZ; ++i ) {
    server.identity[i] = (uchar)(i&0xff);
  }
  server.cookie_secret[15] = 0x02;
  server.token[15] = 0x03; /* FIXME: shouldn't this be rng in stl_s0_server_handshake? */

  fd_stl_s0_client_params_t client = {0};
  for( uint i=0; i < STL_EDBLAH_KEY_SZ; ++i ) {
    server.identity[i] = (uchar)(i&0x7f);
  }
  client.cookie_secret[15] = 0x12;

  fd_stl_s0_server_hs_t server_hs = {0};
  fd_stl_s0_client_hs_t client_hs; fd_stl_s0_client_hs_new( &client_hs );

  /* FIXME: create fn to init with server identity and gen token */
  memcpy( client_hs.server_identity, server.identity, STL_EDBLAH_KEY_SZ );
  client_hs.client_token[15] = 0x13;

  stl_net_ctx_t client_addr = FD_STL_NET_CTX_T_EMPTY;
  client_addr.parts.ip4 = 0x21;
  client_addr.parts.port = 8001;

  uchar client_pkt[ STL_MTU ];
  uchar server_pkt[ STL_MTU ];

  long client_pkt_sz;
  long server_pkt_sz;

  client_pkt_sz = fd_stl_s0_client_initial( &client, &client_hs, client_pkt );
  assert( client_pkt_sz>0L );
  assert( client_hs.state == STL_TYPE_HS_CLIENT_INITIAL );

  server_pkt_sz = fd_stl_s0_server_handle_initial( &server, &client_addr, client_pkt, client_pkt_sz, server_pkt, &server_hs );
  assert( server_pkt_sz>0L );
  assert( !server_hs.done );

  client_pkt_sz = fd_stl_s0_client_handle_continue( &client, &client_hs, server_pkt, server_pkt_sz, client_pkt );
  assert( client_pkt_sz>0L );
  assert( client_hs.state == STL_TYPE_HS_SERVER_CONTINUE );

  server_pkt_sz = fd_stl_s0_server_handle_accept( &server, &client_addr, client_pkt, client_pkt_sz, server_pkt, &server_hs );
  assert( server_pkt_sz>0L );
  assert( server_hs.done );

  client_pkt_sz = fd_stl_s0_client_handle_accept( &client, &client_hs, server_pkt, server_pkt_sz, client_pkt );
  assert( client_pkt_sz==0L ); /* FIXME: 0 should not be both error and success */
  assert( client_hs.state == STL_TYPE_HS_SERVER_ACCEPT );

  puts( "S0 handshake: OK" );

  uchar payload[STL_BASIC_PAYLOAD_MTU]; /* FIXME: use the correct MTU here */
  uchar rcv_payload[STL_BASIC_PAYLOAD_MTU];
  ushort payload_sz = STL_BASIC_PAYLOAD_MTU;
  long rcv_payload_sz;

  for( ushort i=0; i<payload_sz; ++i ) {
    payload[i] = (uchar)(i&0xff);
  }

  /*
  stl_endpoint_send_all( payload, ..list_of_dst.. ) {
    if (multicast_enabled) {
      stl_s0_endpoint_send(..., config={ multicast })
    }
    for dst in list_of_dst {
      if dst.is_multicast {
        continue
      }
      stl_s0_endpoint_send(..., config={ })
    }
  }
  */

  long encoded_sz = fd_stl_s0_encode_appdata(&client_hs, payload, payload_sz, client_pkt /*, config */);
  assert(encoded_sz > 0L);

  /* client_pkt to net tile -> client_pkt from net tile */

  rcv_payload_sz = fd_stl_s0_decode_appdata(&server_hs, client_pkt, (ushort)encoded_sz, rcv_payload);
  assert(server_pkt_sz > 0UL);
  assert(rcv_payload_sz == payload_sz);
  assert(memcmp(rcv_payload, payload, (size_t)rcv_payload_sz) == 0);
  puts("S0 application decode/encode: OK");

}

static void
bench_cookie( void ) {

  stl_cookie_claims_t const claims = {0};
  uchar const cookie_secret[ STL_COOKIE_KEY_SZ ] = {0};
  uchar cookie[32];

  /* warmup */
  for( unsigned long rem=1000000UL; rem; rem-- ) {
    stl_cookie_create( cookie, &claims, cookie_secret );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (cookie[0]) );
  }

  /* for real */
  unsigned long iter = 20000000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    stl_cookie_create( cookie, &claims, cookie_secret );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (cookie[0]) );
  }
  dt += wallclock();

  double ops  = ((double)iter) / ((double)dt) * 1e3;
  double ns   = ((double)dt) / ((double)iter);
  double gbps = ((float)(8UL*(70UL+1200UL)*iter)) / ((float)dt);
  fprintf( stderr, "Benchmarking cookie issue\n" );
  fprintf( stderr, "\t~%.3f Gbps Ethernet equiv throughput / core\n", gbps );
  fprintf( stderr, "\t~%6.3f Mpps / core\n", ops );
  fprintf( stderr, "\t~%6.3f ns / op\n", ns );
}

static void
bench_cookie_verify( void ) {

  stl_cookie_claims_t claims = {0};
  uchar const cookie_secret[ STL_COOKIE_KEY_SZ ] = {0};
  uchar cookie[32] = {0};

  /* warmup */
  for( unsigned long rem=1000000UL; rem; rem-- ) {
    int res = stl_cookie_verify( cookie, &claims, cookie_secret );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (cookie[0]) );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (res      ) );
  }

  /* for real */
  unsigned long iter = 20000000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    int res = stl_cookie_verify( cookie, &claims, cookie_secret );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (cookie[0]) );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (res      ) );
  }
  dt += wallclock();

  double ops  = ((double)iter) / ((double)dt) * 1e3;
  double ns   = ((double)dt) / ((double)iter);
  double gbps = ((float)(8UL*(70UL+1200UL)*iter)) / ((float)dt);
  fprintf( stderr, "Benchmarking cookie verify\n" );
  fprintf( stderr, "\t~%.3f Gbps Ethernet equiv throughput / core\n", gbps );
  fprintf( stderr, "\t~%6.3f Mpps / core\n", ops );
  fprintf( stderr, "\t~%6.3f ns / op\n", ns );
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  test_s0_handshake();
  bench_cookie();
  bench_cookie_verify();

  return 0;
}
