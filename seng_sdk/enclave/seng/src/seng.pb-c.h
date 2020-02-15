/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: seng.proto */

#ifndef PROTOBUF_C_seng_2eproto__INCLUDED
#define PROTOBUF_C_seng_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _SengProto__IpAssignment SengProto__IpAssignment;
typedef struct _SengProto__IpAssignACK SengProto__IpAssignACK;
typedef struct _SengProto__ShadowSrvMsg SengProto__ShadowSrvMsg;
typedef struct _SengProto__ShadowSrvMsg__RequestCliSockShadowing SengProto__ShadowSrvMsg__RequestCliSockShadowing;
typedef struct _SengProto__ShadowSrvMsg__NotifyAboutClose SengProto__ShadowSrvMsg__NotifyAboutClose;
typedef struct _SengProto__CliBlockerMsg SengProto__CliBlockerMsg;
typedef struct _SengProto__CliBlockerMsg__RequestSockBlocking SengProto__CliBlockerMsg__RequestSockBlocking;
typedef struct _SengProto__CliBlockerMsg__CloseNotify SengProto__CliBlockerMsg__CloseNotify;
typedef struct _SengProto__CliBlockerReply SengProto__CliBlockerReply;
typedef struct _SengProto__ShadowReqReply SengProto__ShadowReqReply;
typedef struct _SengProto__ListenStartConfirm SengProto__ListenStartConfirm;


/* --- enums --- */

typedef enum _SengProto__CliBlockerReply__Replies {
  SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES__DENIED = 0,
  SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES__GRANTED = 1,
  SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES__IN_USE = 2,
  SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES__WAS_NOT_BLOCKED = 3,
  SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES__NOW_UNLBOCKED = 4
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SENG_PROTO__CLI_BLOCKER_REPLY__REPLIES)
} SengProto__CliBlockerReply__Replies;
typedef enum _SengProto__ShadowReqReply__Replies {
  SENG_PROTO__SHADOW_REQ_REPLY__REPLIES__DENIED = 0,
  SENG_PROTO__SHADOW_REQ_REPLY__REPLIES__GRANTED = 1
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SENG_PROTO__SHADOW_REQ_REPLY__REPLIES)
} SengProto__ShadowReqReply__Replies;
typedef enum _SengProto__ListenStartConfirm__Replies {
  SENG_PROTO__LISTEN_START_CONFIRM__REPLIES__FAILED = 0,
  SENG_PROTO__LISTEN_START_CONFIRM__REPLIES__NOW_LISTENING = 1
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SENG_PROTO__LISTEN_START_CONFIRM__REPLIES)
} SengProto__ListenStartConfirm__Replies;

/* --- messages --- */

/*
 * Sent from NGW to Tunnel Netif (setup phase)
 */
struct  _SengProto__IpAssignment
{
  ProtobufCMessage base;
  /*
   * 32bit
   */
  uint32_t ip;
  /*
   * 32bit
   */
  uint32_t netmask;
  /*
   * 32bit
   */
  uint32_t gw_ip;
};
#define SENG_PROTO__IP_ASSIGNMENT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__ip_assignment__descriptor) \
    , 0, 0, 0 }


/*
 * Sent from Tunnel Netif to NGW (setup phase)
 */
struct  _SengProto__IpAssignACK
{
  ProtobufCMessage base;
  /*
   * 32bit
   */
  uint32_t ip;
};
#define SENG_PROTO__IP_ASSIGN_ACK__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__ip_assign_ack__descriptor) \
    , 0 }


struct  _SengProto__ShadowSrvMsg__RequestCliSockShadowing
{
  ProtobufCMessage base;
  uint32_t handle;
  /*
   * 16bit
   */
  uint32_t port;
  /*
   * 8 bit
   */
  uint32_t proto;
};
#define SENG_PROTO__SHADOW_SRV_MSG__REQUEST_CLI_SOCK_SHADOWING__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__shadow_srv_msg__request_cli_sock_shadowing__descriptor) \
    , 0, 0, 0 }


struct  _SengProto__ShadowSrvMsg__NotifyAboutClose
{
  ProtobufCMessage base;
  uint32_t handle;
};
#define SENG_PROTO__SHADOW_SRV_MSG__NOTIFY_ABOUT_CLOSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__shadow_srv_msg__notify_about_close__descriptor) \
    , 0 }


typedef enum {
  SENG_PROTO__SHADOW_SRV_MSG__MSG__NOT_SET = 0,
  SENG_PROTO__SHADOW_SRV_MSG__MSG_REQ_SHADOW = 1,
  SENG_PROTO__SHADOW_SRV_MSG__MSG_CLOSE_NOTIFY = 2,
} SengProto__ShadowSrvMsg__MsgCase;

/*
 * Sent from Enclave to NGW
 */
struct  _SengProto__ShadowSrvMsg
{
  ProtobufCMessage base;
  SengProto__ShadowSrvMsg__MsgCase msg_case;
  union {
    SengProto__ShadowSrvMsg__RequestCliSockShadowing *reqshadow;
    SengProto__ShadowSrvMsg__NotifyAboutClose *closenotify;
  };
};
#define SENG_PROTO__SHADOW_SRV_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__shadow_srv_msg__descriptor) \
    , SENG_PROTO__SHADOW_SRV_MSG__MSG__NOT_SET, {0} }


struct  _SengProto__CliBlockerMsg__RequestSockBlocking
{
  ProtobufCMessage base;
  /*
   * 16bit
   */
  uint32_t port;
  /*
   * 8bit
   */
  uint32_t proto;
  /*
   * 256b = 32B = uint8_t[32]
   */
  ProtobufCBinaryData mr_enclave;
  /*
   * same
   */
  ProtobufCBinaryData mr_signer;
};
#define SENG_PROTO__CLI_BLOCKER_MSG__REQUEST_SOCK_BLOCKING__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__cli_blocker_msg__request_sock_blocking__descriptor) \
    , 0, 0, {0,NULL}, {0,NULL} }


struct  _SengProto__CliBlockerMsg__CloseNotify
{
  ProtobufCMessage base;
  /*
   * 16bit
   */
  uint32_t port;
  /*
   * 8bit
   */
  uint32_t proto;
};
#define SENG_PROTO__CLI_BLOCKER_MSG__CLOSE_NOTIFY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__cli_blocker_msg__close_notify__descriptor) \
    , 0, 0 }


typedef enum {
  SENG_PROTO__CLI_BLOCKER_MSG__MSG__NOT_SET = 0,
  SENG_PROTO__CLI_BLOCKER_MSG__MSG_SOCK_BLOCK = 1,
  SENG_PROTO__CLI_BLOCKER_MSG__MSG_CLOSE_NOTIFY = 2,
} SengProto__CliBlockerMsg__MsgCase;

/*
 * Sent from NGW to CliSB
 */
struct  _SengProto__CliBlockerMsg
{
  ProtobufCMessage base;
  SengProto__CliBlockerMsg__MsgCase msg_case;
  union {
    SengProto__CliBlockerMsg__RequestSockBlocking *sockblock;
    SengProto__CliBlockerMsg__CloseNotify *closenotify;
  };
};
#define SENG_PROTO__CLI_BLOCKER_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__cli_blocker_msg__descriptor) \
    , SENG_PROTO__CLI_BLOCKER_MSG__MSG__NOT_SET, {0} }


/*
 * Sent from CliSB to NGW
 */
struct  _SengProto__CliBlockerReply
{
  ProtobufCMessage base;
  SengProto__CliBlockerReply__Replies reply;
};
#define SENG_PROTO__CLI_BLOCKER_REPLY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__cli_blocker_reply__descriptor) \
    , 0 }


/*
 * Sent from NGW to Enclave
 */
struct  _SengProto__ShadowReqReply
{
  ProtobufCMessage base;
  SengProto__ShadowReqReply__Replies reply;
};
#define SENG_PROTO__SHADOW_REQ_REPLY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__shadow_req_reply__descriptor) \
    , 0 }


/*
 * Sent from Enclave to NGW
 */
struct  _SengProto__ListenStartConfirm
{
  ProtobufCMessage base;
  SengProto__ListenStartConfirm__Replies reply;
};
#define SENG_PROTO__LISTEN_START_CONFIRM__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&seng_proto__listen_start_confirm__descriptor) \
    , 0 }


/* SengProto__IpAssignment methods */
void   seng_proto__ip_assignment__init
                     (SengProto__IpAssignment         *message);
size_t seng_proto__ip_assignment__get_packed_size
                     (const SengProto__IpAssignment   *message);
size_t seng_proto__ip_assignment__pack
                     (const SengProto__IpAssignment   *message,
                      uint8_t             *out);
size_t seng_proto__ip_assignment__pack_to_buffer
                     (const SengProto__IpAssignment   *message,
                      ProtobufCBuffer     *buffer);
SengProto__IpAssignment *
       seng_proto__ip_assignment__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__ip_assignment__free_unpacked
                     (SengProto__IpAssignment *message,
                      ProtobufCAllocator *allocator);
/* SengProto__IpAssignACK methods */
void   seng_proto__ip_assign_ack__init
                     (SengProto__IpAssignACK         *message);
size_t seng_proto__ip_assign_ack__get_packed_size
                     (const SengProto__IpAssignACK   *message);
size_t seng_proto__ip_assign_ack__pack
                     (const SengProto__IpAssignACK   *message,
                      uint8_t             *out);
size_t seng_proto__ip_assign_ack__pack_to_buffer
                     (const SengProto__IpAssignACK   *message,
                      ProtobufCBuffer     *buffer);
SengProto__IpAssignACK *
       seng_proto__ip_assign_ack__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__ip_assign_ack__free_unpacked
                     (SengProto__IpAssignACK *message,
                      ProtobufCAllocator *allocator);
/* SengProto__ShadowSrvMsg__RequestCliSockShadowing methods */
void   seng_proto__shadow_srv_msg__request_cli_sock_shadowing__init
                     (SengProto__ShadowSrvMsg__RequestCliSockShadowing         *message);
/* SengProto__ShadowSrvMsg__NotifyAboutClose methods */
void   seng_proto__shadow_srv_msg__notify_about_close__init
                     (SengProto__ShadowSrvMsg__NotifyAboutClose         *message);
/* SengProto__ShadowSrvMsg methods */
void   seng_proto__shadow_srv_msg__init
                     (SengProto__ShadowSrvMsg         *message);
size_t seng_proto__shadow_srv_msg__get_packed_size
                     (const SengProto__ShadowSrvMsg   *message);
size_t seng_proto__shadow_srv_msg__pack
                     (const SengProto__ShadowSrvMsg   *message,
                      uint8_t             *out);
size_t seng_proto__shadow_srv_msg__pack_to_buffer
                     (const SengProto__ShadowSrvMsg   *message,
                      ProtobufCBuffer     *buffer);
SengProto__ShadowSrvMsg *
       seng_proto__shadow_srv_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__shadow_srv_msg__free_unpacked
                     (SengProto__ShadowSrvMsg *message,
                      ProtobufCAllocator *allocator);
/* SengProto__CliBlockerMsg__RequestSockBlocking methods */
void   seng_proto__cli_blocker_msg__request_sock_blocking__init
                     (SengProto__CliBlockerMsg__RequestSockBlocking         *message);
/* SengProto__CliBlockerMsg__CloseNotify methods */
void   seng_proto__cli_blocker_msg__close_notify__init
                     (SengProto__CliBlockerMsg__CloseNotify         *message);
/* SengProto__CliBlockerMsg methods */
void   seng_proto__cli_blocker_msg__init
                     (SengProto__CliBlockerMsg         *message);
size_t seng_proto__cli_blocker_msg__get_packed_size
                     (const SengProto__CliBlockerMsg   *message);
size_t seng_proto__cli_blocker_msg__pack
                     (const SengProto__CliBlockerMsg   *message,
                      uint8_t             *out);
size_t seng_proto__cli_blocker_msg__pack_to_buffer
                     (const SengProto__CliBlockerMsg   *message,
                      ProtobufCBuffer     *buffer);
SengProto__CliBlockerMsg *
       seng_proto__cli_blocker_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__cli_blocker_msg__free_unpacked
                     (SengProto__CliBlockerMsg *message,
                      ProtobufCAllocator *allocator);
/* SengProto__CliBlockerReply methods */
void   seng_proto__cli_blocker_reply__init
                     (SengProto__CliBlockerReply         *message);
size_t seng_proto__cli_blocker_reply__get_packed_size
                     (const SengProto__CliBlockerReply   *message);
size_t seng_proto__cli_blocker_reply__pack
                     (const SengProto__CliBlockerReply   *message,
                      uint8_t             *out);
size_t seng_proto__cli_blocker_reply__pack_to_buffer
                     (const SengProto__CliBlockerReply   *message,
                      ProtobufCBuffer     *buffer);
SengProto__CliBlockerReply *
       seng_proto__cli_blocker_reply__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__cli_blocker_reply__free_unpacked
                     (SengProto__CliBlockerReply *message,
                      ProtobufCAllocator *allocator);
/* SengProto__ShadowReqReply methods */
void   seng_proto__shadow_req_reply__init
                     (SengProto__ShadowReqReply         *message);
size_t seng_proto__shadow_req_reply__get_packed_size
                     (const SengProto__ShadowReqReply   *message);
size_t seng_proto__shadow_req_reply__pack
                     (const SengProto__ShadowReqReply   *message,
                      uint8_t             *out);
size_t seng_proto__shadow_req_reply__pack_to_buffer
                     (const SengProto__ShadowReqReply   *message,
                      ProtobufCBuffer     *buffer);
SengProto__ShadowReqReply *
       seng_proto__shadow_req_reply__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__shadow_req_reply__free_unpacked
                     (SengProto__ShadowReqReply *message,
                      ProtobufCAllocator *allocator);
/* SengProto__ListenStartConfirm methods */
void   seng_proto__listen_start_confirm__init
                     (SengProto__ListenStartConfirm         *message);
size_t seng_proto__listen_start_confirm__get_packed_size
                     (const SengProto__ListenStartConfirm   *message);
size_t seng_proto__listen_start_confirm__pack
                     (const SengProto__ListenStartConfirm   *message,
                      uint8_t             *out);
size_t seng_proto__listen_start_confirm__pack_to_buffer
                     (const SengProto__ListenStartConfirm   *message,
                      ProtobufCBuffer     *buffer);
SengProto__ListenStartConfirm *
       seng_proto__listen_start_confirm__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   seng_proto__listen_start_confirm__free_unpacked
                     (SengProto__ListenStartConfirm *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*SengProto__IpAssignment_Closure)
                 (const SengProto__IpAssignment *message,
                  void *closure_data);
typedef void (*SengProto__IpAssignACK_Closure)
                 (const SengProto__IpAssignACK *message,
                  void *closure_data);
typedef void (*SengProto__ShadowSrvMsg__RequestCliSockShadowing_Closure)
                 (const SengProto__ShadowSrvMsg__RequestCliSockShadowing *message,
                  void *closure_data);
typedef void (*SengProto__ShadowSrvMsg__NotifyAboutClose_Closure)
                 (const SengProto__ShadowSrvMsg__NotifyAboutClose *message,
                  void *closure_data);
typedef void (*SengProto__ShadowSrvMsg_Closure)
                 (const SengProto__ShadowSrvMsg *message,
                  void *closure_data);
typedef void (*SengProto__CliBlockerMsg__RequestSockBlocking_Closure)
                 (const SengProto__CliBlockerMsg__RequestSockBlocking *message,
                  void *closure_data);
typedef void (*SengProto__CliBlockerMsg__CloseNotify_Closure)
                 (const SengProto__CliBlockerMsg__CloseNotify *message,
                  void *closure_data);
typedef void (*SengProto__CliBlockerMsg_Closure)
                 (const SengProto__CliBlockerMsg *message,
                  void *closure_data);
typedef void (*SengProto__CliBlockerReply_Closure)
                 (const SengProto__CliBlockerReply *message,
                  void *closure_data);
typedef void (*SengProto__ShadowReqReply_Closure)
                 (const SengProto__ShadowReqReply *message,
                  void *closure_data);
typedef void (*SengProto__ListenStartConfirm_Closure)
                 (const SengProto__ListenStartConfirm *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor seng_proto__ip_assignment__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__ip_assign_ack__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__shadow_srv_msg__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__shadow_srv_msg__request_cli_sock_shadowing__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__shadow_srv_msg__notify_about_close__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__cli_blocker_msg__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__cli_blocker_msg__request_sock_blocking__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__cli_blocker_msg__close_notify__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__cli_blocker_reply__descriptor;
extern const ProtobufCEnumDescriptor    seng_proto__cli_blocker_reply__replies__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__shadow_req_reply__descriptor;
extern const ProtobufCEnumDescriptor    seng_proto__shadow_req_reply__replies__descriptor;
extern const ProtobufCMessageDescriptor seng_proto__listen_start_confirm__descriptor;
extern const ProtobufCEnumDescriptor    seng_proto__listen_start_confirm__replies__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_seng_2eproto__INCLUDED */
