#include "fd_stl_private.h"
#include "../../ballet/siphash13/fd_siphash13.h"
#include <sys/random.h>

uchar *
stl_cookie_create(uchar cookie[static STL_COOKIE_SZ],
                  stl_cookie_claims_t const *ctx,
                  uchar const cookie_secret[static STL_COOKIE_KEY_SZ])
{
  *(ulong *)cookie = fd_siphash13_hash(
      ctx->b,
      STL_COOKIE_CLAIMS_B_SZ,
      *(ulong *)cookie_secret,
      *(ulong *)(cookie_secret + 8));

  return cookie;
}

int stl_cookie_verify(uchar const cookie[static STL_COOKIE_SZ],
                      stl_cookie_claims_t const *ctx,
                      uchar const cookie_secret[static STL_COOKIE_KEY_SZ])
{

  uchar expected[STL_COOKIE_KEY_SZ];
  stl_cookie_create(expected, ctx, cookie_secret);

  return (*(volatile ulong *)expected) == (*(volatile ulong *)cookie);
}

void stl_gen_session_id(uchar session_id[static STL_SESSION_ID_SZ])
{
  if (getrandom(session_id, STL_SESSION_ID_SZ, 0))
  {
    ;
  }
}
