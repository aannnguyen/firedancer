#include "fd_stl.h"

ulong
fd_stl_footprint( fd_stl_limits_t const * limits ) {
  /* AMAN TODO - implement me */
  (void)limits;
  return 0xff;
}

void *
fd_stl_new( void* mem,
            fd_stl_limits_t const * limits ) {
  /* AMAN TODO - implement me */
  (void)limits;

  return mem;
}

fd_stl_t *
fd_stl_join( void* shstl ) {
  /* AMAN TODO - implement me */
  return shstl;
}


fd_stl_t *
fd_stl_init( fd_stl_t* stl ) {
  /* AMAN TODO - implement me */
  return stl;
}

fd_stl_t *
fd_stl_fini( fd_stl_t* stl ) {
  /* AMAN TODO - implement me */
  return stl;
}

int
fd_stl_service_timers( fd_stl_t * stl ) {
  /* AMAN TODO - implement me */
  (void)stl;
  return ~0;
}


int
fd_stl_send( fd_stl_t * stl,
             stl_net_ctx_t *  dst,
             void const *     data,
             ulong            data_sz) {
  /* TODO better error handling */
  if( data_sz > STL_BASIC_PAYLOAD_MTU ) {
    return -1;
  }

  /* first check if we already have a connection */
  fd_stl_state_private_t* priv = (fd_stl_state_private_t*)(stl+1);
  uchar i;
  for( i=0; i<FD_STL_MAX_SESSION_TMP; ++i ) {
    if( priv->sessions[i].socket_addr == dst->b ) {
      break;
    }
  }
  uchar buf[STL_MTU];
  long sz;
  if( i < FD_STL_MAX_SESSION_TMP ) {
    /* we have a connection, just send on it */
    sz = fd_stl_s0_encode_appdata( priv->sessions+i, data, (ushort)data_sz, buf );
    if( sz < 0 ) {
      /* TODO - error handling */
      return -2;
    }
  } else {
    /* init hs */
    if( priv->session_sz >= FD_STL_MAX_SESSION_TMP ) {
      FD_LOG_NOTICE(("STL session overflow")); /* TODO - change this */
    }

    fd_stl_s0_client_hs_t* hs = priv->client_hs + priv->client_hs_sz++;
    fd_stl_s0_client_hs_new( hs );

    fd_stl_s0_client_params_t params[1];
    sz = fd_stl_s0_client_initial( params , hs, buf );

    /* buffer data */
    fd_stl_payload_t* payload_buf = hs->buffers + hs->buffers_sz++;
    payload_buf->sz = (ushort)data_sz;
    fd_memcpy( payload_buf->data, data, data_sz );
  }

  stl->cb.tx( stl, dst, buf, (ulong)sz );
  return 0;
}

void
fd_stl_process_packet( fd_stl_t *     stl,
                       const uchar *  data,
                       ulong          data_sz,
                       uint          src_ip,
                       ushort          src_port ) {
  /* AMAN TODO - implement me */

  /* Create network context for the sender */
  stl_net_ctx_t sender;
  sender.parts.ip4 = src_ip;
  sender.parts.port = src_port;

  /* Now data points to the STL payload and data_sz is the payload size */

  stl_s0_hs_pkt_t * pkt = (stl_s0_hs_pkt_t *)data;
  fd_stl_state_private_t* priv = (fd_stl_state_private_t*)(stl+1);

  uchar buf[STL_MTU];
  long send_sz = 0;

  int type = stl_hdr_type( &pkt->hs.base );

  if( FD_LIKELY( type == STL_TYPE_APP_SIMPLE ) ) {
    ushort i;
    for( i=0; i<priv->session_sz; ++i ) {
      /* TODO: clean up all the ulong/uchar[] punning */
      if( memcmp( &(priv->sessions[i].session_id), pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }

    if( i == priv->session_sz ) {
      FD_LOG_ERR(("STL session not found"));
      return;
    }

    fd_stl_s0_server_hs_t* hs = priv->server_hs + i;
    long rec_sz = fd_stl_s0_decode_appdata( hs, data, (ushort)data_sz, buf );
    if( rec_sz < 0 ) {
      FD_LOG_ERR(("STL decode appdata failed"));
      return;
    }
    stl->cb.rx( stl, &sender, buf, (ulong)rec_sz );

    send_sz = 0;
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_CLIENT_INITIAL ) ) {
    fd_stl_s0_server_hs_t* hs = priv->server_hs + priv->server_hs_sz++;
    send_sz = fd_stl_s0_server_handle_initial( &stl->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL server handle initial failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_CLIENT_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->server_hs_sz; ++i ) {
      if( memcmp( priv->server_hs[i].session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }
    if( i == priv->server_hs_sz ) {
      FD_LOG_ERR(("STL server hs not found"));
      return;
    }
    fd_stl_s0_server_hs_t* hs = priv->server_hs + i;
    send_sz = fd_stl_s0_server_handle_accept( &stl->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL server handle accept failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_SERVER_CONTINUE ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( memcmp( priv->client_hs[i].session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_ERR(("STL client hs not found"));
      return;
    }
    fd_stl_s0_client_hs_t* hs = priv->client_hs + i;

    send_sz = fd_stl_s0_client_handle_continue( &stl->client_params,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL client handle continue failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_SERVER_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( memcmp( priv->client_hs[i].session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_ERR(("STL client hs not found"));
      return;
    }
    fd_stl_s0_client_hs_t* hs = priv->client_hs + i;
    send_sz = fd_stl_s0_client_handle_accept( stl,
                                         pkt,
                                         buf,
                                         hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL client handle accept failed"));
      return;
    }
  } else {
    FD_LOG_NOTICE(("stl_process_packet: Unknown hdr type %d", type));
  }
  if( send_sz > 0 ) {
    stl->cb.rx( stl, &sender, buf, (ulong)send_sz );
  }
}

