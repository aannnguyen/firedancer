#include "fd_grpc.h"
#include "../h2/fd_h2_rbuf.h"
#include "../h2/fd_hpack.h"
#include "../../util/fd_util.h"
#include "../../app/fdctl/version.h"

static void
test_h2_gen_request_hdr( void ) {
  uchar buf[ 2048 ];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, buf, sizeof(buf) );

  fd_grpc_req_t req = {
    .https    = 1,
    .path     = "/block_engine.BlockEngineValidator/SubscribePackets",
    .path_len = 51
  };
  FD_TEST( fd_grpc_h2_gen_request_hdr( &req, rbuf_tx )==1 );
  FD_TEST( rbuf_tx->lo_off==0 && rbuf_tx->lo==buf );

  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, buf, rbuf_tx->hi_off );

  fd_h2_hdr_t hdr[1];
  uchar * scratch = NULL;

# define EXPECT_HDR( nam, val )                                        \
  do {                                                                 \
    FD_TEST( !fd_hpack_rd_done( hpack_rd ) );                          \
    FD_TEST( !fd_hpack_rd_next( hpack_rd, hdr, &scratch, 0UL ) );      \
    FD_TEST( hdr->name_len==sizeof(nam)-1 );                           \
    FD_TEST( fd_memeq( hdr->name, nam, sizeof(nam)-1 ) );              \
    FD_TEST( hdr->value_len==sizeof(val)-1 );                          \
    FD_TEST( fd_memeq( hdr->value, val, sizeof(val)-1 ) );             \
  } while(0)
  EXPECT_HDR( ":method", "POST" );
  EXPECT_HDR( ":scheme", "https" );
  EXPECT_HDR( ":path", "/block_engine.BlockEngineValidator/SubscribePackets" );
  EXPECT_HDR( "te", "trailers" );
  EXPECT_HDR( "content-type", "application/grpc+proto" );
  EXPECT_HDR( "user-agent", "grpc-firedancer/" FD_EXPAND_THEN_STRINGIFY(FDCTL_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_PATCH_VERSION) );
# undef EXPECT_HDR
  FD_TEST( fd_hpack_rd_done( hpack_rd ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_h2_gen_request_hdr();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
