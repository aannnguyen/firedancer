#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_siphash13.h"

static fd_siphash13_t sip[1];
static fd_siphash13_t sip_fast[1];

int
LLVMFuzzerInitialize( int  *   pargc,
                      char *** pargv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

#define FAST_HASH_CHUNK_SZ (32UL) /* MUST be a multiple of 8 */

struct fuzz_siphash13
{
  ulong k0;
  ulong k1;
  uchar flex [];
};


int
LLVMFuzzerTestOneInput( uchar const * fuzz_data,
                        ulong         fuzz_data_sz ) {

  if (fuzz_data_sz < sizeof(struct fuzz_siphash13)) {
    return -1;
  };

  // Clear buffers on the heap
  memset( sip, 0, sizeof(fd_siphash13_t) );
  memset( sip_fast, 0, sizeof(fd_siphash13_t) );


  struct fuzz_siphash13 * testcase = (struct fuzz_siphash13 *)(fuzz_data);
  ulong flex_sz = fuzz_data_sz - sizeof(struct fuzz_siphash13);

  assert( sip == fd_siphash13_init  ( sip, testcase->k0, testcase->k1 ) );
  assert( sip == fd_siphash13_append( sip, testcase->flex, flex_sz ) );

  ulong hash = fd_siphash13_fini( sip );
  assert( hash == fd_siphash13_hash( testcase->flex, flex_sz, testcase->k0, testcase->k1 ) );

  // fuzz fast hashing
  assert( sip_fast == fd_siphash13_init( sip_fast, testcase->k0, testcase->k1 ) );

  uchar const * data_chunk = testcase->flex;
  for( ulong rem = flex_sz/FAST_HASH_CHUNK_SZ; rem > 0; rem-- ) {
    assert( sip_fast == fd_siphash13_append_fast( sip_fast, data_chunk, FAST_HASH_CHUNK_SZ ) );
    data_chunk += FAST_HASH_CHUNK_SZ;
  }
  assert( sip_fast == fd_siphash13_append( sip_fast, data_chunk, flex_sz%FAST_HASH_CHUNK_SZ ) );
  ulong hash_fast = fd_siphash13_fini( sip_fast );
  assert( hash == hash_fast );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
