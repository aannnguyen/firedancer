#include "../tiles.h"

#include "generated/fd_shred_tile_seccomp.h"
#include "../topo/fd_pod_format.h"
#include "../shred/fd_shredder.h"
#include "../shred/fd_shred_dest.h"
#include "../shred/fd_fec_resolver.h"
#include "../shred/fd_stake_ci.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyswitch.h"
#include "../fd_disco.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../util/net/fd_net_headers.h"

#include <linux/unistd.h>

/* The shred tile handles shreds from two data sources: shreds
   generated from microblocks from the banking tile, and shreds
   retransmitted from the network.

   They have rather different semantics, but at the end of the day, they
   both result in a bunch of shreds and FEC sets that need to be sent to
   the blockstore and on the network, which is why one tile handles
   both.

   We segment the memory for the two types of shreds into two halves of
   a dcache because they follow somewhat different flow control
   patterns. For flow control, the normal guarantee we want to provide
   is that the dcache entry is not overwritten unless the mcache entry
   has also been overwritten.  The normal way to do this when using both
   cyclically and with a 1-to-1 mapping is to make the dcache at least
   `burst` entries bigger than the mcache.

   In this tile, we use one output mcache with one output dcache (which
   is logically partitioned into two) for the two sources of data.  The
   worst case for flow control is when we're only sending with one of
   the dcache partitions at a time though, so we can consider them
   separately.

   From bank: Every FEC set triggers at least two mcache entries (one
   for parity and one for data), so at most, we have ceil(mcache
   depth/2) FEC sets exposed.  This means we need to decompose dcache
   into at least ceil(mcache depth/2)+1 FEC sets.

   From the network: The FEC resolver doesn't use a cyclic order, but it
   does promise that once it returns an FEC set, it will return at least
   complete_depth FEC sets before returning it again.  This means we
   want at most complete_depth-1 FEC sets exposed, so
   complete_depth=ceil(mcache depth/2)+1 FEC sets as above.  The FEC
   resolver has the ability to keep individual shreds for partial_depth
   calls, but because in this version of the shred tile, we send each
   shred to all its destinations as soon as we get it, we don't need
   that functionality, so we set partial_depth=1.

   Adding these up, we get 2*ceil(mcache_depth/2)+3+fec_resolver_depth
   FEC sets, which is no more than mcache_depth+4+fec_resolver_depth.
   Each FEC is paired with 4 fd_shred34_t structs, so that means we need
   to decompose the dcache into 4*mcache_depth + 4*fec_resolver_depth +
   16 fd_shred34_t structs. */


/* The memory this tile uses is a bit complicated and has some logical
   aliasing to facilitate zero-copy use.  We have a dcache containing
   fd_shred34_t objects, which are basically 34 fd_shred_t objects
   padded to their max size, where 34 is set so that the size of the
   fd_shred34_t object (including some metadata) is less than
   USHORT_MAX, which facilitates sending it using Tango.  Then, for each
   set of 4 consecutive fd_shred34_t objects, we have an fd_fec_set_t.
   The first 34 data shreds point to the payload section of the payload
   section of each of the packets in the first fd_shred34_t.  The other
   33 data shreds point into the second fd_shred34_t.  Similar for the
   parity shreds pointing into the third and fourth fd_shred34_t. */

/* There's nothing deep about this max, but I just find it easier to
   have a max and use statically sized arrays than alloca. */
#define MAX_BANK_CNT 64UL

/* MAX_SHRED_DESTS indicates the maximum number of destinations (i.e. a
   pubkey -> ip, port) that the shred tile can keep track of. */
#define MAX_SHRED_DESTS 40200UL

#define FD_SHRED_TILE_SCRATCH_ALIGN 128UL

#define IN_KIND_CONTACT (0UL)
#define IN_KIND_STAKE   (1UL)
#define IN_KIND_POH     (2UL)
#define IN_KIND_NET     (3UL)
#define IN_KIND_SIGN    (4UL)

#define STORE_OUT_IDX   0
#define NET_OUT_IDX     1
#define SIGN_OUT_IDX    2
#define REPLAY_OUT_IDX  3

#define MAX_SLOTS_PER_EPOCH 432000UL

#define DCACHE_ENTRIES_PER_FEC_SET (4UL)
FD_STATIC_ASSERT( sizeof(fd_shred34_t) < USHORT_MAX, shred_34 );
FD_STATIC_ASSERT( 34*DCACHE_ENTRIES_PER_FEC_SET >= FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX, shred_34 );
FD_STATIC_ASSERT( sizeof(fd_shred34_t) == FD_SHRED_STORE_MTU, shred_34 );

FD_STATIC_ASSERT( sizeof(fd_entry_batch_meta_t)==24UL, poh_shred_mtu );

#define FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT 2

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_shred_in_ctx_t;

typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  ulong                round_robin_id;
  ulong                round_robin_cnt;
  /* Number of batches shredded from PoH during the current slot.
     This should be the same for all the shred tiles. */
  ulong                batch_cnt;
  /* Slot of the most recent microblock we've seen from PoH,
     or 0 if we haven't seen one yet */
  ulong                slot;

  fd_keyswitch_t *     keyswitch;
  fd_keyguard_client_t keyguard_client[1];

  /* shred34 and fec_sets are very related: fec_sets[i] has pointers
     to the shreds in shred34[4*i + k] for k=0,1,2,3. */
  fd_shred34_t       * shred34;
  fd_fec_set_t       * fec_sets;

  fd_stake_ci_t      * stake_ci;
  /* These are used in between during_frag and after_frag */
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;
  ulong                      shredded_txn_cnt;

  ulong poh_in_expect_seq;

  ushort net_id;

  int skip_frag;

  fd_shred_dest_weighted_t adtl_dest[1];

  fd_ip4_udp_hdrs_t data_shred_net_hdr  [1];
  fd_ip4_udp_hdrs_t parity_shred_net_hdr[1];

  fd_wksp_t * shred_store_wksp;

  ulong shredder_fec_set_idx;     /* In [0, shredder_max_fec_set_idx) */
  ulong shredder_max_fec_set_idx; /* exclusive */

  ulong send_fec_set_idx;
  ulong tsorig;  /* timestamp of the last packet in compressed form */

  /* Includes Ethernet, IP, UDP headers */
  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];


  fd_shred_in_ctx_t in[ 32 ];
  int               in_kind[ 32 ];

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  fd_blockstore_t   blockstore_ljoin;
  fd_blockstore_t * blockstore;

  struct {
    fd_histf_t contact_info_cnt[ 1 ];
    fd_histf_t batch_sz[ 1 ];
    fd_histf_t batch_microblock_cnt[ 1 ];
    fd_histf_t shredding_timing[ 1 ];
    fd_histf_t add_shred_timing[ 1 ];
    ulong shred_processing_result[ FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ];
  } metrics[ 1 ];

  struct {
    ulong txn_cnt;
    ulong pos; /* in payload, so 0<=pos<63671 */
    ulong slot; /* set to 0 when pos==0 */
    union {
      struct {
        ulong microblock_cnt;
        uchar payload[ 63679UL - 8UL ];
      };
      uchar raw[ 63679UL ]; /* The largest that fits in 1 FEC set */
    };
  } pending_batch;

  fd_shred_features_activation_t features_activation[1];
  /* too large to be left in the stack */
  fd_shred_dest_idx_t scratchpad_dests[ FD_SHRED_DEST_MAX_FANOUT*(FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX) ];

} fd_shred_ctx_t;

/* PENDING_BATCH_WMARK: Following along the lines of dcache, batch
   microblocks until either the slot ends or we excede the watermark.
   We know that if we're <= watermark, we can always accept a message of
   maximum size. */
#define PENDING_BATCH_WMARK (63679UL - 8UL - FD_POH_SHRED_MTU)

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, tile->shred.depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt = tile->shred.depth + tile->shred.fec_resolver_depth + 4UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shred_ctx_t),          sizeof(fd_shred_ctx_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()                 );
  l = FD_LAYOUT_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint                  );
  l = FD_LAYOUT_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()                 );
  l = FD_LAYOUT_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt        );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_shred_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ulong seq_must_complete = ctx->keyswitch->param;

    if( FD_UNLIKELY( fd_seq_lt( ctx->poh_in_expect_seq, seq_must_complete ) ) ) {
      /* See fd_keyswitch.h, we need to flush any in-flight shreds from
         the leader pipeline before switching key. */
      FD_LOG_WARNING(( "Flushing in-flight unpublished shreds, must reach seq %lu, currently at %lu ...", seq_must_complete, ctx->poh_in_expect_seq ));
      return;
    }

    fd_memcpy( ctx->identity_key->uc, ctx->keyswitch->bytes, 32UL );
    fd_stake_ci_set_identity( ctx->stake_ci, ctx->identity_key );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_shred_ctx_t * ctx ) {
  FD_MHIST_COPY( SHRED, CLUSTER_CONTACT_INFO_CNT,   ctx->metrics->contact_info_cnt      );
  FD_MHIST_COPY( SHRED, BATCH_SZ,                   ctx->metrics->batch_sz              );
  FD_MHIST_COPY( SHRED, BATCH_MICROBLOCK_CNT,       ctx->metrics->batch_microblock_cnt  );
  FD_MHIST_COPY( SHRED, SHREDDING_DURATION_SECONDS, ctx->metrics->shredding_timing      );
  FD_MHIST_COPY( SHRED, ADD_SHRED_DURATION_SECONDS, ctx->metrics->add_shred_timing      );

  FD_MCNT_ENUM_COPY( SHRED, SHRED_PROCESSED, ctx->metrics->shred_processing_result      );
}

static inline void
handle_new_cluster_contact_info( fd_shred_ctx_t * ctx,
                                 uchar const    * buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = header[ 0 ];
  fd_histf_sample( ctx->metrics->contact_info_cnt, dest_cnt );

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );
  fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    dests[i].ip4  = in_dests[i].ip4_addr;
    dests[i].port = in_dests[i].udp_port;
  }
}

static inline void
finalize_new_cluster_contact_info( fd_shred_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static inline int
before_frag( fd_shred_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) ctx->poh_in_expect_seq = seq+1UL;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) )     return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED;
  else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) return  (fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK) &
                                                                      (fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_FEAT_ACT_SLOT);
  return 0;
}

static void
during_frag( fd_shred_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl ) {

  ctx->skip_frag = 0;

  ctx->tsorig = fd_frag_meta_ts_comp( fd_tickcount() );


  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_CONTACT ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) {
    if( FD_UNLIKELY( (fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_FEAT_ACT_SLOT) ) ) {
      /* There is a subset of FD_SHRED_FEATURES_ACTIVATION_... slots that
          the shred tile needs to be aware of.  Since this requires the
          bank, we are forced (so far) to receive them from the poh tile
          (as a POH_PKT_TYPE_FEAT_ACT_SLOT).  This is not elegant, and it
          should be revised in the future (TODO), but it provides a
          "temporary" working solution to handle features activation. */
      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=(sizeof(fd_shred_features_activation_t)) ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_shred_features_activation_t const * act_data = (fd_shred_features_activation_t const *)dcache_entry;
      fd_memcpy( ctx->features_activation, act_data, sizeof(fd_shred_features_activation_t) );
    }
    else { /* (fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK) */
      /* This is a frag from the PoH tile.  We'll copy it to our pending
        microblock batch and shred it if necessary (last in block or
        above watermark).  We just go ahead and shred it here, even
        though we may get overrun.  If we do end up getting overrun, we
        just won't send these shreds out and we'll reuse the FEC set for
        the next one.  From a higher level though, if we do get overrun,
        a bunch of shreds will never be transmitted, and we'll end up
        producing a block that never lands on chain. */
      fd_fec_set_t * out = ctx->fec_sets + ctx->shredder_fec_set_idx;

      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_POH_SHRED_MTU ||
          sz<(sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t)) ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_entry_batch_meta_t const * entry_meta = (fd_entry_batch_meta_t const *)dcache_entry;
      uchar const *                 entry      = dcache_entry + sizeof(fd_entry_batch_meta_t);
      ulong                         entry_sz   = sz           - sizeof(fd_entry_batch_meta_t);

      fd_entry_batch_header_t const * microblock = (fd_entry_batch_header_t const *)entry;

      /* It should never be possible for this to fail, but we check it
        anyway. */
      FD_TEST( entry_sz + ctx->pending_batch.pos <= sizeof(ctx->pending_batch.payload) );

      ulong target_slot = fd_disco_poh_sig_slot( sig );
      if( FD_UNLIKELY( (ctx->pending_batch.microblock_cnt>0) & (ctx->pending_batch.slot!=target_slot) ) ) {
        /* TODO: The Agave client sends a dummy entry batch with only 1
          byte and the block-complete bit set.  This helps other
          validators know that the block is dead and they should not try
          to continue building a fork on it.  We probably want a similar
          approach eventually. */
        FD_LOG_WARNING(( "Abandoning %lu microblocks for slot %lu and switching to slot %lu",
              ctx->pending_batch.microblock_cnt, ctx->pending_batch.slot, target_slot ));
        ctx->pending_batch.slot           = 0UL;
        ctx->pending_batch.pos            = 0UL;
        ctx->pending_batch.microblock_cnt = 0UL;
        ctx->pending_batch.txn_cnt        = 0UL;
        ctx->batch_cnt                    = 0UL;

        FD_MCNT_INC( SHRED, MICROBLOCKS_ABANDONED, 1UL );
      }

      ctx->pending_batch.slot = target_slot;
      if( FD_UNLIKELY( target_slot!=ctx->slot )) {
        /* Reset batch count if we are in a new slot */
        ctx->batch_cnt = 0UL;
        ctx->slot      = target_slot;
      }
      if( FD_UNLIKELY( ctx->batch_cnt%ctx->round_robin_cnt==ctx->round_robin_id ) ) {
        /* Ugh, yet another memcpy */
        fd_memcpy( ctx->pending_batch.payload + ctx->pending_batch.pos, entry, entry_sz );
      } else {
        /* If we are not processing this batch, filter */
        ctx->skip_frag = 1;
      }
      ctx->pending_batch.pos            += entry_sz;
      ctx->pending_batch.microblock_cnt += 1UL;
      ctx->pending_batch.txn_cnt        += microblock->txn_cnt;

      int last_in_batch = entry_meta->block_complete | (ctx->pending_batch.pos > PENDING_BATCH_WMARK);

      ctx->send_fec_set_idx = ULONG_MAX;
      if( FD_UNLIKELY( last_in_batch )) {
        if( FD_UNLIKELY( ctx->batch_cnt%ctx->round_robin_cnt==ctx->round_robin_id ) ) {
          /* If it's our turn, shred this batch. FD_UNLIKELY because shred tile cnt generally >= 2 */
          ulong batch_sz = sizeof(ulong)+ctx->pending_batch.pos;

          /* We sized this so it fits in one FEC set */
          long shredding_timing =  -fd_tickcount();

          if( FD_UNLIKELY( entry_meta->block_complete && batch_sz < FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ ) ) {

            /* Ensure the last batch generates >= 32 data shreds by
              padding with 0s. Because the last FEC set is "oddly sized"
              we only expect this code path to execute for blocks
              containing less data than can fill 32 data shred payloads
              (hence FD_UNLIKELY).

              See documentation for FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ
              for further context. */

            fd_memset( ctx->pending_batch.payload + ctx->pending_batch.pos, 0, FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ - batch_sz );
            batch_sz = FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ;
          }

          fd_shredder_init_batch( ctx->shredder, ctx->pending_batch.raw, batch_sz, target_slot, entry_meta );
          FD_TEST( fd_shredder_next_fec_set( ctx->shredder, out ) );
          fd_shredder_fini_batch( ctx->shredder );
          shredding_timing      +=  fd_tickcount();

          d_rcvd_join( d_rcvd_new( d_rcvd_delete( d_rcvd_leave( out->data_shred_rcvd   ) ) ) );
          p_rcvd_join( p_rcvd_new( p_rcvd_delete( p_rcvd_leave( out->parity_shred_rcvd ) ) ) );
          ctx->shredded_txn_cnt = ctx->pending_batch.txn_cnt;

          ctx->send_fec_set_idx = ctx->shredder_fec_set_idx;

          /* Update metrics */
          fd_histf_sample( ctx->metrics->batch_sz,             batch_sz                          );
          fd_histf_sample( ctx->metrics->batch_microblock_cnt, ctx->pending_batch.microblock_cnt );
          fd_histf_sample( ctx->metrics->shredding_timing,     (ulong)shredding_timing           );
        } else {
          /* If it's not our turn, update the indices for this slot */
          fd_shredder_skip_batch( ctx->shredder, sizeof(ulong)+ctx->pending_batch.pos, target_slot );
        }

        ctx->pending_batch.slot           = 0UL;
        ctx->pending_batch.pos            = 0UL;
        ctx->pending_batch.microblock_cnt = 0UL;
        ctx->pending_batch.txn_cnt        = 0UL;
        ctx->batch_cnt++;
      }
    }
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    /* The common case, from the net tile.  The FEC resolver API does
       not present a prepare/commit model. If we get overrun between
       when the FEC resolver verifies the signature and when it stores
       the local copy, we could end up storing and retransmitting
       garbage.  Instead we copy it locally, sadly, and only give it to
       the FEC resolver when we know it won't be overrun anymore. */
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    uchar const * dcache_entry = (uchar const *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) + ctl;
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    fd_shred_t const * shred = fd_shred_parse( dcache_entry+hdr_sz, sz-hdr_sz );
    if( FD_UNLIKELY( !shred ) ) {
      ctx->skip_frag = 1;
      return;
    };
    /* all shreds in the same FEC set will have the same signature
       so we can round-robin shreds between the shred tiles based on
       just the signature without splitting individual FEC sets. */
    ulong sig = fd_ulong_load_8( shred->signature );
    if( FD_LIKELY( sig%ctx->round_robin_cnt!=ctx->round_robin_id ) ) {
      ctx->skip_frag = 1;
      return;
    }
    fd_memcpy( ctx->shred_buffer, dcache_entry+hdr_sz, sz-hdr_sz );
    ctx->shred_buffer_sz = sz-hdr_sz;
  }
}

static inline void
send_shred( fd_shred_ctx_t                 * ctx,
            fd_shred_t const               * shred,
            fd_shred_dest_weighted_t const * dest,
            ulong                            tsorig ) {

  if( FD_UNLIKELY( !dest->ip4 ) ) return;

  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  int is_data = fd_shred_is_data( fd_shred_type( shred->variant ) );
  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( is_data ? ctx->data_shred_net_hdr : ctx->parity_shred_net_hdr );

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dest->ip4;
  ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  ip4->check  = 0U;
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );

  hdr->udp->net_dport = fd_ushort_bswap( dest->port );

  ulong shred_sz = fd_ulong_if( is_data, FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), shred, shred_sz );

  ulong pkt_sz = shred_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig    = fd_disco_netmux_sig( dest->ip4, dest->port, dest->ip4, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, pkt_sz, 0UL, tsorig, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, pkt_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
after_frag( fd_shred_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)_tspub;

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_CONTACT ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( (ctx->in_kind[ in_idx ]==IN_KIND_POH) & (ctx->send_fec_set_idx==ULONG_MAX) ) ) {
    /* Entry from PoH that didn't trigger a new FEC set to be made */
    return;
  }

  ulong fanout = 200UL; /* Default Agave's DATA_PLANE_FANOUT = 200UL */

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    uchar * shred_buffer    = ctx->shred_buffer;
    ulong   shred_buffer_sz = ctx->shred_buffer_sz;

    fd_shred_t const * shred = fd_shred_parse( shred_buffer, shred_buffer_sz );
    if( FD_UNLIKELY( !shred       ) ) { ctx->metrics->shred_processing_result[ 1 ]++; return; }

    fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, shred->slot );
    if( FD_UNLIKELY( !lsched      ) ) { ctx->metrics->shred_processing_result[ 0 ]++; return; }

    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, shred->slot );
    if( FD_UNLIKELY( !slot_leader ) ) { ctx->metrics->shred_processing_result[ 0 ]++; return; } /* Count this as bad slot too */

    fd_fec_set_t const * out_fec_set[1];
    fd_shred_t const   * out_shred[1];
    fd_bmtree_node_t     out_merkle_root[1];

    long add_shred_timing  = -fd_tickcount();
    int rv = fd_fec_resolver_add_shred( ctx->resolver, shred, shred_buffer_sz, slot_leader->uc, out_fec_set, out_shred, out_merkle_root );
    add_shred_timing      +=  fd_tickcount();

    fd_histf_sample( ctx->metrics->add_shred_timing, (ulong)add_shred_timing );
    ctx->metrics->shred_processing_result[ rv + FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ]++;

    /* Fanout is subject to feature activation. The code below replicates
        Agave's get_data_plane_fanout() in turbine/src/cluster_nodes.rs
        on 2025-03-25. Default Agave's DATA_PLANE_FANOUT = 200UL.
        TODO once the experiments are disabled, consider removing these
        fanout variations from the code. */
    if( FD_LIKELY( shred->slot >= ctx->features_activation->disable_turbine_fanout_experiments ) ) {
      fanout = 200UL;
    } else {
      if( FD_LIKELY( shred->slot >= ctx->features_activation->enable_turbine_extended_fanout_experiments ) ) {
        switch( shred->slot % 359 ) {
          case  11UL: fanout = 1152UL;  break;
          case  61UL: fanout = 1280UL;  break;
          case 111UL: fanout = 1024UL;  break;
          case 161UL: fanout = 1408UL;  break;
          case 211UL: fanout =  896UL;  break;
          case 261UL: fanout = 1536UL;  break;
          case 311UL: fanout =  768UL;  break;
          default   : fanout =  200UL;
        }
      } else {
        switch( shred->slot % 359 ) {
          case  11UL: fanout =   64UL;  break;
          case  61UL: fanout =  768UL;  break;
          case 111UL: fanout =  128UL;  break;
          case 161UL: fanout =  640UL;  break;
          case 211UL: fanout =  256UL;  break;
          case 261UL: fanout =  512UL;  break;
          case 311UL: fanout =  384UL;  break;
          default   : fanout =  200UL;
        }
      }
    }

    if( (rv==FD_FEC_RESOLVER_SHRED_OKAY) | (rv==FD_FEC_RESOLVER_SHRED_COMPLETES) ) {
      /* Relay this shred */
      ulong max_dest_cnt[1];
      do {
        /* If we've validated the shred and it COMPLETES but we can't
           compute the destination for whatever reason, don't forward
           the shred, but still send it to the blockstore. */
        fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, shred->slot );
        if( FD_UNLIKELY( !sdest ) ) break;
        fd_shred_dest_idx_t * dests = fd_shred_dest_compute_children( sdest, &shred, 1UL, ctx->scratchpad_dests, 1UL, fanout, fanout, max_dest_cnt );
        if( FD_UNLIKELY( !dests ) ) break;

        send_shred( ctx, *out_shred, ctx->adtl_dest, ctx->tsorig );
        for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, *out_shred, fd_shred_dest_idx_to_dest( sdest, dests[ j ]), ctx->tsorig );
      } while( 0 );

      if( FD_LIKELY( ctx->blockstore && rv==FD_FEC_RESOLVER_SHRED_OKAY ) ) { /* optimize for the compiler - branch predictor will still be correct */
        uchar * buf = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
        ulong   sz  = fd_shred_header_sz( shred->variant );
        fd_memcpy( buf, shred, sz );
        ulong tspub       = fd_frag_meta_ts_comp( fd_tickcount() );
        ulong replay_sig  = fd_disco_shred_replay_sig( shred->slot, shred->idx, shred->fec_set_idx, fd_shred_is_code( fd_shred_type( shred->variant ) ), 0 );
        fd_stem_publish( stem, REPLAY_OUT_IDX, replay_sig, ctx->replay_out_chunk, sz, 0UL, ctx->tsorig, tspub );
        ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sz, ctx->replay_out_chunk0, ctx->replay_out_wmark );
      }
    }
    if( FD_LIKELY( rv!=FD_FEC_RESOLVER_SHRED_COMPLETES ) ) return;

    FD_TEST( ctx->fec_sets <= *out_fec_set );
    ctx->send_fec_set_idx = (ulong)(*out_fec_set - ctx->fec_sets);
    ctx->shredded_txn_cnt = 0UL;
  } else {
    /* We know we didn't get overrun, so advance the index */
    ctx->shredder_fec_set_idx = (ctx->shredder_fec_set_idx+1UL)%ctx->shredder_max_fec_set_idx;
  }
  /* If this was the shred that completed an FEC set or this was a
     microblock we shredded ourself, we now have a full FEC set that we
     need to send to the blockstore and on the network (skipping any
     shreds we already sent). */

  fd_fec_set_t * set = ctx->fec_sets + ctx->send_fec_set_idx;
  fd_shred34_t * s34 = ctx->shred34 + 4UL*ctx->send_fec_set_idx;

  s34[ 0 ].shred_cnt =                         fd_ulong_min( set->data_shred_cnt,   34UL );
  s34[ 1 ].shred_cnt = set->data_shred_cnt   - fd_ulong_min( set->data_shred_cnt,   34UL );
  s34[ 2 ].shred_cnt =                         fd_ulong_min( set->parity_shred_cnt, 34UL );
  s34[ 3 ].shred_cnt = set->parity_shred_cnt - fd_ulong_min( set->parity_shred_cnt, 34UL );

  ulong s34_cnt     = 2UL + !!(s34[ 1 ].shred_cnt) + !!(s34[ 3 ].shred_cnt);
  ulong txn_per_s34 = ctx->shredded_txn_cnt / s34_cnt;

  /* Attribute the transactions evenly to the non-empty shred34s */
  for( ulong j=0UL; j<4UL; j++ ) s34[ j ].est_txn_cnt = fd_ulong_if( s34[ j ].shred_cnt>0UL, txn_per_s34, 0UL );

  /* Add whatever is left to the last shred34 */
  s34[ fd_ulong_if( s34[ 3 ].shred_cnt>0UL, 3, 2 ) ].est_txn_cnt += ctx->shredded_txn_cnt - txn_per_s34*s34_cnt;

  /* Set the sz field so that metrics are more accurate. */
  ulong sz0 = sizeof(fd_shred34_t) - (34UL - s34[ 0 ].shred_cnt)*FD_SHRED_MAX_SZ;
  ulong sz1 = sizeof(fd_shred34_t) - (34UL - s34[ 1 ].shred_cnt)*FD_SHRED_MAX_SZ;
  ulong sz2 = sizeof(fd_shred34_t) - (34UL - s34[ 2 ].shred_cnt)*FD_SHRED_MAX_SZ;
  ulong sz3 = sizeof(fd_shred34_t) - (34UL - s34[ 3 ].shred_cnt)*FD_SHRED_MAX_SZ;

  if( FD_LIKELY( ctx->blockstore ) ) {
    /* If the shred has a completes flag, then in the replay tile it
       will do immediate polling for shreds in that FEC set, under
       the assumption that they live in the blockstore. When a shred
       completes a FEC set, we need to add the shreds to the
       blockstore before we notify replay of a completed FEC set.
       Replay does not poll the blockstore for shreds on notifies of
       a regular non-completing shred. */

    for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
      fd_shred_t const * data_shred = (fd_shred_t const *)fd_type_pun_const( set->data_shreds[ i ] );
      fd_blockstore_shred_insert( ctx->blockstore, data_shred );
    }
    if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
      /* Shred came from block we didn't produce. This is not our leader
         slot. */
      fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( ctx->shred_buffer );
      uchar * buf = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
      ulong   sz  = fd_shred_header_sz( shred->variant );
      fd_memcpy( buf, shred, sz );
      ulong tspub       = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong replay_sig  = fd_disco_shred_replay_sig( shred->slot, shred->idx, shred->fec_set_idx, fd_shred_is_code( fd_shred_type( shred->variant ) ), 1 );
      fd_stem_publish( stem, REPLAY_OUT_IDX, replay_sig, ctx->replay_out_chunk, sz, 0UL, ctx->tsorig, tspub );
      ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sz, ctx->replay_out_chunk0, ctx->replay_out_wmark );
    }
  }

  /* Send to the blockstore, skipping any empty shred34_t s. */
  ulong new_sig = ctx->in_kind[ in_idx ]!=IN_KIND_NET; /* sig==0 means the store tile will do extra checks */
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+0UL ), sz0, 0UL, ctx->tsorig, tspub );
  if( FD_UNLIKELY( s34[ 1 ].shred_cnt ) )
    fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+1UL ), sz1, 0UL, ctx->tsorig, tspub );
  fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+2UL), sz2, 0UL, ctx->tsorig, tspub );
  if( FD_UNLIKELY( s34[ 3 ].shred_cnt ) )
    fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+3UL ), sz3, 0UL, ctx->tsorig, tspub );

  /* Compute all the destinations for all the new shreds */

  fd_shred_t const * new_shreds[ FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX ];
  ulong k=0UL;
  for( ulong i=0UL; i<set->data_shred_cnt; i++ )
    if( !d_rcvd_test( set->data_shred_rcvd,   i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->data_shreds  [ i ];
  for( ulong i=0UL; i<set->parity_shred_cnt; i++ )
    if( !p_rcvd_test( set->parity_shred_rcvd, i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->parity_shreds[ i ];

  if( FD_UNLIKELY( !k ) ) return;
  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, new_shreds[ 0 ]->slot );
  if( FD_UNLIKELY( !sdest ) ) return;

  ulong out_stride;
  ulong max_dest_cnt[1];
  fd_shred_dest_idx_t * dests;
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    out_stride = k;
    /* In the case of feature activation, the fanout used below is
        the same as the one calculated/modified previously at the
        begining of after_frag() for IN_KIND_NET in this slot. */
    dests = fd_shred_dest_compute_children( sdest, new_shreds, k, ctx->scratchpad_dests, k, fanout, fanout, max_dest_cnt );
  } else {
    out_stride = 1UL;
    *max_dest_cnt = 1UL;
    dests = fd_shred_dest_compute_first   ( sdest, new_shreds, k, ctx->scratchpad_dests );
  }
  if( FD_UNLIKELY( !dests ) ) return;

  /* Send only the ones we didn't receive. */
  for( ulong i=0UL; i<k; i++ ) {
    send_shred( ctx, new_shreds[ i ], ctx->adtl_dest, ctx->tsorig );
    for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, new_shreds[ i ], fd_shred_dest_idx_to_dest( sdest, dests[ j*out_stride+i ]), ctx->tsorig );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->shred.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->shred.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
fd_shred_signer( void *        signer_ctx,
                 uchar         signature[ static 64 ],
                 uchar const   merkle_root[ static 32 ] ) {
  fd_keyguard_client_sign( signer_ctx, signature, merkle_root, 32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_LIKELY( tile->out_cnt==3UL ) ) { /* frankendancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[STORE_OUT_IDX]].name,  "shred_store"  ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "shred_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SIGN_OUT_IDX]].name,   "shred_sign"   ) );
  } else if( FD_LIKELY( tile->out_cnt==4UL ) ) { /* firedancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[STORE_OUT_IDX]].name,  "shred_storei"  ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "shred_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SIGN_OUT_IDX]].name,   "shred_sign"   ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[REPLAY_OUT_IDX]].name, "shred_replay" ) );
  } else {
    FD_LOG_ERR(( "shred tile has unexpected cnt of output links %lu", tile->out_cnt ));
  }

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "shred tile has no primary output link" ));

  ulong shred_store_mcache_depth = tile->shred.depth;
  if( topo->links[ tile->out_link_id[ 0 ] ].depth != shred_store_mcache_depth )
    FD_LOG_ERR(( "shred tile out depths are not equal %lu %lu",
                 topo->links[ tile->out_link_id[ 0 ] ].depth, shred_store_mcache_depth ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;
  ctx->batch_cnt       = 0UL;
  ctx->slot            = ULONG_MAX;

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, shred_store_mcache_depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt            = shred_store_mcache_depth + tile->shred.fec_resolver_depth + 4UL;

  void * store_out_dcache = topo->links[ tile->out_link_id[ 0 ] ].dcache;

  ulong required_dcache_sz = fec_set_cnt*DCACHE_ENTRIES_PER_FEC_SET*sizeof(fd_shred34_t);
  if( fd_dcache_data_sz( store_out_dcache )<required_dcache_sz ) {
    FD_LOG_ERR(( "shred->store dcache too small. It is %lu bytes but must be at least %lu bytes.",
                 fd_dcache_data_sz( store_out_dcache ),
                 required_dcache_sz ));
  }

  if( FD_UNLIKELY( !tile->shred.fec_resolver_depth ) ) FD_LOG_ERR(( "fec_resolver_depth not set" ));
  if( FD_UNLIKELY( !tile->shred.shred_listen_port  ) ) FD_LOG_ERR(( "shred_listen_port not set" ));

  ulong bank_cnt   = fd_topo_tile_name_cnt( topo, "bank" );
  ulong replay_cnt = fd_topo_tile_name_cnt( topo, "replay" );

  if( FD_UNLIKELY( !bank_cnt && !replay_cnt ) ) FD_LOG_ERR(( "0 bank/replay tiles" ));
  if( FD_UNLIKELY( bank_cnt>MAX_BANK_CNT ) ) FD_LOG_ERR(( "Too many banks" ));

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * _resolver = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint             );
  void * _shredder = FD_SCRATCH_ALLOC_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()            );
  void * _fec_sets = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt   );

  fd_fec_set_t * fec_sets = (fd_fec_set_t *)_fec_sets;
  fd_shred34_t * shred34  = (fd_shred34_t *)store_out_dcache;

  for( ulong i=0UL; i<fec_set_cnt; i++ ) {
    fd_shred34_t * p34_base = shred34 + i*DCACHE_ENTRIES_PER_FEC_SET;
    for( ulong k=0UL; k<DCACHE_ENTRIES_PER_FEC_SET; k++ ) {
      fd_shred34_t * p34 = p34_base + k;

      p34->stride   = (ulong)p34->pkts[1].buffer - (ulong)p34->pkts[0].buffer;
      p34->offset   = (ulong)p34->pkts[0].buffer - (ulong)p34;
      p34->shred_sz = fd_ulong_if( k<2UL, 1203UL, 1228UL );
    }

    uchar ** data_shred   = fec_sets[ i ].data_shreds;
    uchar ** parity_shred = fec_sets[ i ].parity_shreds;
    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) data_shred  [ j ] = p34_base[       j/34UL ].pkts[ j%34UL ].buffer;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) parity_shred[ j ] = p34_base[ 2UL + j/34UL ].pkts[ j%34UL ].buffer;
  }

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ulong expected_shred_version = tile->shred.expected_shred_version;
  if( FD_LIKELY( !expected_shred_version ) ) {
    ulong busy_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    FD_LOG_INFO(( "Waiting for shred version to be determined via gossip." ));
    do {
      expected_shred_version = FD_VOLATILE_CONST( *gossip_shred_version );
    } while( expected_shred_version==ULONG_MAX );
  }

  if( FD_UNLIKELY( expected_shred_version > USHORT_MAX ) ) FD_LOG_ERR(( "invalid shred version %lu", expected_shred_version ));
  FD_LOG_INFO(( "Using shred version %hu", (ushort)expected_shred_version ));

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  /* populate ctx */
  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_shred", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  NONNULL( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) ) );

  ulong shred_limit = fd_ulong_if( tile->shred.larger_shred_limits_per_block, 32UL*32UL*1024UL, 32UL*1024UL );
  fd_fec_set_t * resolver_sets = fec_sets + (shred_store_mcache_depth+1UL)/2UL + 1UL;
  ctx->shredder = NONNULL( fd_shredder_join     ( fd_shredder_new     ( _shredder, fd_shred_signer, ctx->keyguard_client, (ushort)expected_shred_version ) ) );
  ctx->resolver = NONNULL( fd_fec_resolver_join ( fd_fec_resolver_new ( _resolver,
                                                                        fd_shred_signer, ctx->keyguard_client,
                                                                        tile->shred.fec_resolver_depth, 1UL,
                                                                        (shred_store_mcache_depth+3UL)/2UL,
                                                                        128UL * tile->shred.fec_resolver_depth, resolver_sets,
                                                                        (ushort)expected_shred_version,
                                                                        shred_limit                                           ) ) );

  ctx->shred34  = shred34;
  ctx->fec_sets = fec_sets;

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key ) );

  ctx->net_id   = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->data_shred_net_hdr,   FD_SHRED_MIN_SZ, 0, tile->shred.shred_listen_port );
  fd_ip4_udp_hdr_init( ctx->parity_shred_net_hdr, FD_SHRED_MAX_SZ, 0, tile->shred.shred_listen_port );

  ctx->adtl_dest->ip4  = tile->shred.adtl_dest.ip;
  ctx->adtl_dest->port = tile->shred.adtl_dest.port;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "net_shred"   ) ) ) ctx->in_kind[ i ] = IN_KIND_NET;
    else if( FD_LIKELY( !strcmp( link->name, "poh_shred"   ) ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else if( FD_LIKELY( !strcmp( link->name, "stake_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "crds_shred"  ) ) ) ctx->in_kind[ i ] = IN_KIND_CONTACT;
    else if( FD_LIKELY( !strcmp( link->name, "sign_shred"  ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else FD_LOG_ERR(( "shred tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ];

  ctx->store_out_mem    = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_out_chunk0 = fd_dcache_compact_chunk0( ctx->store_out_mem, store_out->dcache );
  ctx->store_out_wmark  = fd_dcache_compact_wmark ( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk  = ctx->store_out_chunk0;

  if( FD_LIKELY( tile->out_cnt==4UL ) ) { /* firedancer */
    fd_topo_link_t * replay_out = &topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ];

    ctx->replay_out_mem    = topo->workspaces[ topo->objs[ replay_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, replay_out->dcache );
    ctx->replay_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_out_mem, replay_out->dcache, replay_out->mtu );
    ctx->replay_out_chunk  = ctx->replay_out_chunk0;
  }

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  if (FD_LIKELY( blockstore_obj_id!=ULONG_MAX )) {
    ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
    FD_TEST( ctx->blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );
  } else {
    ctx->blockstore = NULL;
  }

  ctx->poh_in_expect_seq = 0UL;

  ctx->shredder_fec_set_idx = 0UL;
  ctx->shredder_max_fec_set_idx = (shred_store_mcache_depth+1UL)/2UL + 1UL;

  ctx->send_fec_set_idx    = ULONG_MAX;

  ctx->shred_buffer_sz  = 0UL;
  fd_memset( ctx->shred_buffer, 0xFF, FD_NET_MTU );

  fd_histf_join( fd_histf_new( ctx->metrics->contact_info_cnt,     FD_MHIST_MIN(         SHRED, CLUSTER_CONTACT_INFO_CNT   ),
                                                                   FD_MHIST_MAX(         SHRED, CLUSTER_CONTACT_INFO_CNT   ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->batch_sz,             FD_MHIST_MIN(         SHRED, BATCH_SZ                   ),
                                                                   FD_MHIST_MAX(         SHRED, BATCH_SZ                   ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->batch_microblock_cnt, FD_MHIST_MIN(         SHRED, BATCH_MICROBLOCK_CNT       ),
                                                                   FD_MHIST_MAX(         SHRED, BATCH_MICROBLOCK_CNT       ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->shredding_timing,     FD_MHIST_SECONDS_MIN( SHRED, SHREDDING_DURATION_SECONDS ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, SHREDDING_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->add_shred_timing,     FD_MHIST_SECONDS_MIN( SHRED, ADD_SHRED_DURATION_SECONDS ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, ADD_SHRED_DURATION_SECONDS ) ) );
  memset( ctx->metrics->shred_processing_result, '\0', sizeof(ctx->metrics->shred_processing_result) );

  ctx->pending_batch.microblock_cnt = 0UL;
  ctx->pending_batch.txn_cnt        = 0UL;
  ctx->pending_batch.pos            = 0UL;
  ctx->pending_batch.slot           = 0UL;
  fd_memset( ctx->pending_batch.payload, 0, sizeof(ctx->pending_batch.payload) );

  for( ulong i=0UL; i<FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT; i++ )
    ctx->features_activation->slots[i] = FD_SHRED_FEATURES_ACTIVATION_SLOT_DISABLED;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_shred_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_shred_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (5UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_shred_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_shred_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shred = {
  .name                     = "shred",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
