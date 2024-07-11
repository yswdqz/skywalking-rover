package reader

import (
	"fmt"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
)

// MySQL消息类型
type MessageType int

const (
	MessageTypeRequest MessageType = iota
	MessageTypeResponse
	MessageTypeUnknown
)

// MySQL请求命令类型
const (
	COM_QUIT                = 0x01
	COM_INIT_DB             = 0x02
	COM_QUERY               = 0x03
	COM_FIELD_LIST          = 0x04
	COM_CREATE_DB           = 0x05
	COM_DROP_DB             = 0x06
	COM_REFRESH             = 0x07
	COM_SHUTDOWN            = 0x08
	COM_STATISTICS          = 0x09
	COM_PROCESS_INFO        = 0x0A
	COM_CONNECT             = 0x0B
	COM_PROCESS_KILL        = 0x0C
	COM_DEBUG               = 0x0D
	COM_PING                = 0x0E
	COM_TIME                = 0x0F
	COM_DELAYED_INSERT      = 0x10
	COM_CHANGE_USER         = 0x11
	COM_BINLOG_DUMP         = 0x12
	COM_TABLE_DUMP          = 0x13
	COM_CONNECT_OUT         = 0x14
	COM_REGISTER_SLAVE      = 0x15
	COM_STMT_PREPARE        = 0x16
	COM_STMT_EXECUTE        = 0x17
	COM_STMT_SEND_LONG_DATA = 0x18
	COM_STMT_CLOSE          = 0x19
	COM_STMT_RESET          = 0x1A
	COM_SET_OPTION          = 0x1B
	COM_STMT_FETCH          = 0x1C
)

// MySQL响应类型
const (
	RESPONSE_OK_PACKET  = 0x00
	RESPONSE_ERR_PACKET = 0xFF
	RESPONSE_EOF_PACKET = 0xFE
)

var log = logger.GetLogger("profiling", "task", "network", "layer7", "protocols", "mysql", "reader")

// IdentityMessageType 识别MySQL消息类型
func IdentityMessageType(reader *buffer.Buffer) (MessageType, error) {
	// MySQL包头最小长度为4字节
	const headerSize = 4
	headBuffer := make([]byte, headerSize)
	n, err := reader.Peek(headBuffer)
	if err != nil {
		return MessageTypeUnknown, err
	} else if n != len(headBuffer) {
		return MessageTypeUnknown, fmt.Errorf("need more content for header")
	}

	// 读取包长度
	packetLength := int(headBuffer[0]) | int(headBuffer[1])<<8 | int(headBuffer[2])<<16

	// 检查是否有足够的数据
	if reader.Len() < packetLength+headerSize {
		return MessageTypeUnknown, fmt.Errorf("need more content for packet")
	}

	// 读取完整的数据包
	packetBuffer := make([]byte, packetLength+headerSize)
	_, err = reader.Read(packetBuffer)
	if err != nil {
		return MessageTypeUnknown, err
	}

	// 读取负载数据的第一个字节来判断消息类型
	payload := packetBuffer[headerSize]
	switch payload {
	case RESPONSE_ERR_PACKET, RESPONSE_EOF_PACKET:
		return MessageTypeResponse, nil
	case COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST, COM_CREATE_DB, COM_DROP_DB, COM_REFRESH,
		COM_SHUTDOWN, COM_STATISTICS, COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
		COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP, COM_TABLE_DUMP, COM_CONNECT_OUT,
		COM_REGISTER_SLAVE, COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, COM_STMT_CLOSE,
		COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH:
		return MessageTypeRequest, nil
	case 0x00:
		// 对于 0x00，我们需要进一步区分是OK包还是COM_SLEEP
		// 通过包的长度和内容特征来区分
		if packetLength == 0 { // COM_SLEEP 没有负载数据
			return MessageTypeRequest, nil
		} else if packetLength >= 7 { // OK包最小长度通常是7字节
			return MessageTypeResponse, nil
		}
	default:
		return MessageTypeUnknown, nil
	}

	return MessageTypeUnknown, nil
}
