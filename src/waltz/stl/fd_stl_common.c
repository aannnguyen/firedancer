#include "fd_stl_private.h"
#include "../../ballet/siphash13/fd_siphash13.h"
#include <sys/random.h>

uint8_t *
stl_cookie_create(uint8_t cookie[static STL_COOKIE_SZ],
                  stl_cookie_claims_t const *ctx,
                  uint8_t const cookie_secret[static STL_COOKIE_KEY_SZ])
{
  *(uint64_t *)cookie = fd_siphash13_hash(
      ctx->b,
      STL_COOKIE_CLAIMS_B_SZ,
      *(uint64_t *)cookie_secret,
      *(uint64_t *)(cookie_secret + 8));

  return cookie;
}

int stl_cookie_verify(uint8_t const cookie[static STL_COOKIE_SZ],
                      stl_cookie_claims_t const *ctx,
                      uint8_t const cookie_secret[static STL_COOKIE_KEY_SZ])
{

  uint8_t expected[STL_COOKIE_KEY_SZ];
  stl_cookie_create(expected, ctx, cookie_secret);

  return (*(volatile uint64_t *)expected) == (*(volatile uint64_t *)cookie);
}

void stl_gen_session_id(uint8_t session_id[static STL_SESSION_ID_SZ])
{
  if (getrandom(session_id, STL_SESSION_ID_SZ, 0))
  {
    ;
  }
}
