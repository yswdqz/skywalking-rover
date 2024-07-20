package reader

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"io"
)

type Request struct {
	header *Header
	body   interface{}
}
type Header struct {
	Length     uint32
	SequenceID uint8
}

// MySQLLoginRequest 表示 MySQL 登录请求
type MySQLLoginRequest struct {
	Username string
	Database string
}

// MySQLQueryRequest 表示 MySQL 查询请求
type MySQLQueryRequest struct {
	Query string
}
type MySQLPingRequest struct{}

func ParseHeader(bufReader *bufio.Reader) (*Header, error) {
	header := Header{}

	lengthBytes := make([]byte, 3)
	if _, err := io.ReadFull(bufReader, lengthBytes); err != nil {
		return nil, err
	}

	// 数据包长度是一个 3 字节无符号整数
	header.Length = uint32(lengthBytes[0]) | uint32(lengthBytes[1])<<8 | uint32(lengthBytes[2])<<16

	// 读取头部的第 4 字节（序列号）
	if sequenceID, err := bufReader.ReadByte(); err != nil {
		return nil, err
	} else {
		header.SequenceID = sequenceID
	}

	return &header, nil
}

func ParseRequest(bufReader *bufio.Reader) (interface{}, *Header, error) {
	header, err := ParseHeader(bufReader)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing MySQL packet header: %w", err)
	}

	request, err := doParseRequest(bufReader, header)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing MySQL request: %w", err)
	}

	return request, header, nil
}

func doParseRequest(bufReader *bufio.Reader, header *Header) (interface{}, error) {
	commandByte, err := bufReader.ReadByte()
	if err != nil {
		return nil, err
	}

	length := header.Length - 1

	switch commandByte {
	case 0x03:
		return parseMySQLQueryRequest(bufReader, length)
	case 0x0e:
		return parseMySQLPingRequest(bufReader, length)
	case 0x10:
		return parseMySQLLoginRequest(bufReader, length)
	default:
		return nil, fmt.Errorf("unsupported command byte: 0x%x", commandByte)
	}
}

func ReadRequest(buf *buffer.Buffer) (*Request, enums.ParseResult, error) {
	bufReader := bufio.NewReader(buf)
	request := &Request{}
	req, header, err := ParseRequest(bufReader)
	if err != nil {
		fmt.Errorf("parse error: %w", err)
		return nil, 0, err
	}
	request.header = header
	request.body = req

	return request, enums.ParseResultSuccess, nil
}

// parseMySQLLoginRequest 解析 MySQL 登录请求
func parseMySQLLoginRequest(bufReader *bufio.Reader, length uint32) (*MySQLLoginRequest, error) {
	request := MySQLLoginRequest{}
	body := make([]byte, length)
	if _, err := io.ReadFull(bufReader, body); err != nil {
		return nil, err
	}

	usernameEnd := bytes.IndexByte(body, 0x00)
	if usernameEnd == -1 {
		return nil, fmt.Errorf("invalid login request: no null terminator for username")
	}
	request.Username = string(body[:usernameEnd])

	databaseStart := usernameEnd + 1
	if databaseStart >= int(length) {
		return nil, fmt.Errorf("invalid login request: no database name")
	}
	databaseEnd := bytes.IndexByte(body[databaseStart:], 0x00)
	if databaseEnd == -1 {
		return nil, fmt.Errorf("invalid login request: no null terminator for database name")
	}
	request.Database = string(body[databaseStart : databaseStart+databaseEnd])

	return &request, nil
}

// parseMySQLQueryRequest 解析 MySQL 查询请求
func parseMySQLQueryRequest(bufReader *bufio.Reader, length uint32) (*MySQLQueryRequest, error) {
	request := MySQLQueryRequest{}
	body := make([]byte, length)
	if _, err := io.ReadFull(bufReader, body); err != nil {
		return nil, err
	}

	request.Query = string(body)
	return &request, nil
}

// parseMySQLPingRequest 解析 MySQL Ping 请求
func parseMySQLPingRequest(bufReader *bufio.Reader, length uint32) (*MySQLPingRequest, error) {
	if _, err := bufReader.Discard(int(length)); err != nil {
		return nil, err
	}
	return &MySQLPingRequest{}, nil
}
