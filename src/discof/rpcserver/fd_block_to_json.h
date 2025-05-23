#ifndef HEADER_fd_src_discof_rpcserver_fd_block_to_json_h
#define HEADER_fd_src_discof_rpcserver_fd_block_to_json_h

#include "../../util/fd_util.h"

#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/runtime/fd_blockstore.h"

typedef struct fd_webserver fd_webserver_t;

typedef enum {
  FD_ENC_BASE58, FD_ENC_BASE64, FD_ENC_BASE64_ZSTD, FD_ENC_JSON, FD_ENC_JSON_PARSED
} fd_rpc_encoding_t;

enum fd_block_detail { FD_BLOCK_DETAIL_FULL, FD_BLOCK_DETAIL_ACCTS, FD_BLOCK_DETAIL_SIGS, FD_BLOCK_DETAIL_NONE };

const char* fd_txn_meta_to_json( fd_webserver_t * ws,
                                 const void * meta_raw,
                                 ulong meta_raw_sz );

const char* fd_txn_to_json( fd_webserver_t * ws,
                            fd_txn_t* txn,
                            const uchar* raw,
                            ulong raw_sz,
                            fd_rpc_encoding_t encoding,
                            long maxvers,
                            enum fd_block_detail detail );

const char* fd_block_to_json( fd_webserver_t * ws,
                              fd_blockstore_t * blockstore,
                              int blockstore_fd,
                              const char * call_id,
                              const uchar * blk_data,
                              ulong blk_sz,
                              fd_block_info_t * meta,
                              fd_hash_t * parent_hash,
                              fd_rpc_encoding_t encoding,
                              long maxvers,
                              enum fd_block_detail detail,
                              fd_block_rewards_t * rewards );

#define FD_LONG_UNSET (1L << 63L)

const char* fd_account_to_json( fd_webserver_t * ws,
                                fd_pubkey_t acct,
                                fd_rpc_encoding_t enc,
                                uchar const * val,
                                ulong val_sz,
                                long off,
                                long len );

#endif /* HEADER_fd_src_discof_rpcserver_fd_block_to_json_h */
