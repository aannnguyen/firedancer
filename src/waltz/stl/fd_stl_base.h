#ifndef HEADER_stl_base_h
#define HEADER_stl_base_h

#include <endian.h>
#include <stdint.h>

/* stl_base.h is a minimal version of fd_util_base.h. */

/* Compiler checks ****************************************************/

#if __BYTE_ORDER != __LITTLE_ENDIAN
#error "Sorry, stl.h only supports little endian targets."
#endif

#ifdef __cplusplus
#define STL_PROTOTYPES_BEGIN extern "C" {
#else
#define STL_PROTOTYPES_BEGIN
#endif

#ifdef __cplusplus
#define STL_PROTOTYPES_END }
#else
#define STL_PROTOTYPES_END
#endif

#define STL_LIKELY(c)   __builtin_expect( !!(c), 1L )
#define STL_UNLIKELY(c) __builtin_expect( !!(c), 0L )

/* Common structures **************************************************/

/* stl_net_ctx_t is the endpoint of the peer identified by IPv6
   address and UDP port.  Supports IPv4 via IPv4-mapped IPv6
   addresses (RFC 4291). */

struct __attribute__((packed)) stl_net_ctx {
  uint8_t  src_addr[16];
  uint16_t src_port;
};

typedef struct stl_net_ctx stl_net_ctx_t;

#endif /* HEADER_stl_base_h */
