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

  /* Init server, server_hs */
  fd_stl_s0_server_params_t server[1] = {0};
  for( uint i=0; i < STL_ED25519_KEY_SZ; ++i ) {
    server->identity[i] = (uchar)(i&0xff);
  }
  fd_stl_s0_server_hs_t server_hs[1] = {0};

  /* Init client, client_hs */
  fd_stl_s0_client_params_t client[1] = {0};
  for( uint i=0; i < STL_ED25519_KEY_SZ; ++i ) {
    client->identity[i] = (uchar)(i&0x7f);
  }
  fd_stl_s0_client_hs_t client_hs[1]; fd_stl_s0_client_hs_new( client_hs );

  stl_net_ctx_t ctx[1] = { 0 };
  fd_stl_sesh_t server_sesh[1] = { 0 };

  uchar client_pkt[ STL_MTU ];
  uchar server_pkt[ STL_MTU ];

  long client_pkt_sz;
  long server_pkt_sz;

  assert( client_hs->state == 0 );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_stl_s0_client_initial( client, client_hs, client_pkt );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == STL_TYPE_HS_SERVER_CONTINUE );

  server_pkt_sz = fd_stl_s0_server_handle_initial( server, ctx, (stl_s0_hs_pkt_t *)client_pkt, server_pkt, server_hs );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_stl_s0_client_handle_continue( client, (stl_s0_hs_pkt_t *)server_pkt, client_pkt, client_hs );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == STL_TYPE_HS_SERVER_ACCEPT );

  server_pkt_sz = fd_stl_s0_server_handle_accept( server, ctx, (stl_s0_hs_pkt_t *)client_pkt, server_pkt, server_hs, server_sesh );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == STL_TYPE_HS_DONE );

  client_pkt_sz = fd_stl_s0_client_handle_accept( client, (stl_s0_hs_pkt_t *)server_pkt, client_hs );
  assert( client_pkt_sz==0L );
  assert( client_hs->state == STL_TYPE_HS_DONE );

  puts( "S0 handshake: OK" );

#if 0
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

  long encoded_sz = fd_stl_s0_encode_appdata(client_hs, payload, payload_sz, client_pkt /*, config */);
  assert(encoded_sz > 0L);

  /* client_pkt to net tile -> client_pkt from net tile */

  rcv_payload_sz = fd_stl_s0_decode_appdata(&server_hs, client_pkt, (ushort)encoded_sz, rcv_payload);
  assert(server_pkt_sz > 0UL);
  assert(rcv_payload_sz == payload_sz);
  assert(memcmp(rcv_payload, payload, (size_t)rcv_payload_sz) == 0);
  puts("S0 application decode/encode: OK");
#endif
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
