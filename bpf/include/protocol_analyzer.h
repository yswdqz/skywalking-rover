// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

#define CONNECTION_PROTOCOL_UNKNOWN 0
#define CONNECTION_PROTOCOL_HTTP1 1
#define CONNECTION_PROTOCOL_HTTP2 2
#define CONNECTION_PROTOCOL_MYSQL 3


#define CONNECTION_MESSAGE_TYPE_UNKNOWN 0
#define CONNECTION_MESSAGE_TYPE_REQUEST 1
#define CONNECTION_MESSAGE_TYPE_RESPONSE 2

#define MYSQL_MESSAGE_TYPE_UNKNOWN 0
#define MYSQL_MESSAGE_TYPE_REQUEST 1
#define MYSQL_MESSAGE_TYPE_RESPONSE 2

#define COM_SLEEP               0x00
#define COM_QUIT                0x01
#define COM_INIT_DB             0x02
#define COM_QUERY               0x03
#define COM_FIELD_LIST          0x04
#define COM_CREATE_DB           0x05
#define COM_DROP_DB             0x06
#define COM_REFRESH             0x07
#define COM_SHUTDOWN            0x08
#define COM_STATISTICS          0x09
#define COM_PROCESS_INFO        0x0A
#define COM_CONNECT             0x0B
#define COM_PROCESS_KILL        0x0C
#define COM_DEBUG               0x0D
#define COM_PING                0x0E
#define COM_TIME                0x0F
#define COM_DELAYED_INSERT      0x10
#define COM_CHANGE_USER         0x11
#define COM_BINLOG_DUMP         0x12
#define COM_TABLE_DUMP          0x13
#define COM_CONNECT_OUT         0x14
#define COM_REGISTER_SLAVE      0x15
#define COM_STMT_PREPARE        0x16
#define COM_STMT_EXECUTE        0x17
#define COM_STMT_SEND_LONG_DATA 0x18
#define COM_STMT_CLOSE          0x19
#define COM_STMT_RESET          0x1A
#define COM_SET_OPTION          0x1B
#define COM_STMT_FETCH          0x1C

#define RESPONSE_OK_PACKET      0x00
#define RESPONSE_ERR_PACKET     0xFF
#define RESPONSE_EOF_PACKET     0xFE

static __inline __u32 infer_mysql_message(const char* buf, size_t count) {
    if (count < 4) {
        return MYSQL_MESSAGE_TYPE_UNKNOWN;
    }

    // 读取包长度
    uint32_t packet_length = ((uint8_t)buf[0]) | (((uint8_t)buf[1]) << 8) | (((uint8_t)buf[2]) << 16);

    if (count < packet_length + 4) {
        return MYSQL_MESSAGE_TYPE_UNKNOWN;
    }

    // 读取负载数据的第一个字节来判断消息类型
    uint8_t message_type = (uint8_t)buf[4];

    // 判断是否为响应类型
    if (message_type == RESPONSE_OK_PACKET || message_type == RESPONSE_ERR_PACKET || message_type == RESPONSE_EOF_PACKET) {
        return MYSQL_MESSAGE_TYPE_RESPONSE;
    }

    // 判断是否为请求类型
    switch (message_type) {
        case COM_SLEEP:
        case COM_QUIT:
        case COM_INIT_DB:
        case COM_QUERY:
        case COM_FIELD_LIST:
        case COM_CREATE_DB:
        case COM_DROP_DB:
        case COM_REFRESH:
        case COM_SHUTDOWN:
        case COM_STATISTICS:
        case COM_PROCESS_INFO:
        case COM_CONNECT:
        case COM_PROCESS_KILL:
        case COM_DEBUG:
        case COM_PING:
        case COM_TIME:
        case COM_DELAYED_INSERT:
        case COM_CHANGE_USER:
        case COM_BINLOG_DUMP:
        case COM_TABLE_DUMP:
        case COM_CONNECT_OUT:
        case COM_REGISTER_SLAVE:
        case COM_STMT_PREPARE:
        case COM_STMT_EXECUTE:
        case COM_STMT_SEND_LONG_DATA:
        case COM_STMT_CLOSE:
        case COM_STMT_RESET:
        case COM_SET_OPTION:
        case COM_STMT_FETCH:
            return MYSQL_MESSAGE_TYPE_REQUEST;
        default:
            return MYSQL_MESSAGE_TYPE_UNKNOWN;
    }
}

// HTTP 1.x
// request frame format: https://www.rfc-editor.org/rfc/rfc2068.html#section-5
// response frame format: https://www.rfc-editor.org/rfc/rfc2068.html#section-6
static __inline __u32 infer_http1_message(const char* buf, size_t count) {
    if (count < 16) {
        return CONNECTION_MESSAGE_TYPE_UNKNOWN;
    }
    // response
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        return CONNECTION_MESSAGE_TYPE_RESPONSE;
    }
    // request
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O'
        && buf[5] == 'N' && buf[6] == 'S')
    {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' && buf[4] == 'E'
        && buf[5] == 'C' && buf[6] == 'T')
    {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'T' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'C' && buf[4] == 'E') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H') {
        return CONNECTION_MESSAGE_TYPE_REQUEST;
    }
    return CONNECTION_MESSAGE_TYPE_UNKNOWN;
}

static bool is_http2_magic(const char *buf_src, size_t count)
{
	static const char magic[] = "PRI * HTTP/2";
	char buffer[sizeof(magic)] = { 0 };
	bpf_probe_read(buffer, sizeof(buffer) - 1, buf_src);
	for (int idx = 0; idx < sizeof(magic); ++idx) {
		if (magic[idx] == buffer[idx])
			continue;
		return false;
	}
	return true;
}

// HTTP 2.x
// frame format: https://www.rfc-editor.org/rfc/rfc7540.html#section-4.1
static __inline __u32 infer_http2_message(const char* buf, size_t count) {
    static const __u8 kFrameBasicSize = 0x9; // including Length, Type, Flags, Reserved, Stream Identity
    static const __u8 kFrameTypeHeader = 0x1; // the type of the frame: https://www.rfc-editor.org/rfc/rfc7540.html#section-6.2
    static const __u8 kFrameLoopCount = 5;

    static const __u8 kStaticTableMaxSize = 61;// https://www.rfc-editor.org/rfc/rfc7541#appendix-A
    static const __u8 kStaticTableAuth = 1;
    static const __u8 kStaticTableGet = 2;
    static const __u8 kStaticTablePost = 3;
    static const __u8 kStaticTablePath1 = 4;
    static const __u8 kStaticTablePath2 = 5;

    // the buffer size must bigger than basic frame size
    if (count < kFrameBasicSize) {
		return CONNECTION_MESSAGE_TYPE_UNKNOWN;
    }

    // frame info
    __u8 frame[21] = { 0 };
    __u32 frameOffset = 0;
    // header info
    __u8 staticInx, headerBlockFragmentOffset;

    if (is_http2_magic(buf, count)) {
        frameOffset = 24;
    }

    // each all frame
#pragma unroll
    for (__u8 i = 0; i < kFrameLoopCount; i++) {
        if (frameOffset >= count) {
            break;
        }

        // read frame
        bpf_probe_read(frame, sizeof(frame), buf + frameOffset);
        frameOffset += (bpf_ntohl(*(__u32 *) frame) >> 8) + kFrameBasicSize;

        // is header frame
        if (frame[3] != kFrameTypeHeader) {
            continue;
        }

        // validate the header(unset): not HTTP2 protocol
        // this frame must is a send request
        if ((frame[4] & 0xd2) || frame[5] & 0x01) {
            return CONNECTION_MESSAGE_TYPE_UNKNOWN;
        }

        // locate the header block fragment offset
        headerBlockFragmentOffset = kFrameBasicSize;
        if (frame[4] & 0x20) {  // PADDED flag is set
            headerBlockFragmentOffset += 1;
        }
        if (frame[4] & 0x20) {  // PRIORITY flag is set
            headerBlockFragmentOffset += 5;
        }

#pragma unroll
        for (__u8 j = 0; j <= kStaticTablePath2; j++) {
            if (headerBlockFragmentOffset > count) {
                return CONNECTION_MESSAGE_TYPE_UNKNOWN;
            }
            staticInx = frame[headerBlockFragmentOffset] & 0x7f;
            if (staticInx <= kStaticTableMaxSize && staticInx > 0) {
                if (staticInx == kStaticTableAuth ||
                    staticInx == kStaticTableGet ||
                    staticInx == kStaticTablePost ||
                    staticInx == kStaticTablePath1 ||
                    staticInx == kStaticTablePath2) {
                    return CONNECTION_MESSAGE_TYPE_REQUEST;
                } else {
                    return CONNECTION_MESSAGE_TYPE_RESPONSE;
                }
            }
            headerBlockFragmentOffset++;
        }
    }

	return CONNECTION_MESSAGE_TYPE_UNKNOWN;
}

static __inline __u32 analyze_protocol(char *buf, __u32 count, __u8 *protocol_ref) {
    __u32 protocol = CONNECTION_PROTOCOL_UNKNOWN, type = CONNECTION_MESSAGE_TYPE_UNKNOWN;

    // support http 1.x and 2.x
    if ((type = infer_http1_message(buf, count)) != CONNECTION_PROTOCOL_UNKNOWN) {
        protocol = CONNECTION_PROTOCOL_HTTP1;
    } else if ((type = infer_http2_message(buf, count)) != CONNECTION_PROTOCOL_UNKNOWN) {
        protocol = CONNECTION_PROTOCOL_HTTP2;
    } else if ((type = infer_mysql_message(buf, count)) != CONNECTION_PROTOCOL_UNKNOWN) {
        protocol = CONNECTION_PROTOCOL_MYSQL;
    }

    if (protocol != CONNECTION_PROTOCOL_UNKNOWN) {
        *protocol_ref = protocol;
    }

    return type;
}