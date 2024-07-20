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

package reader

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"io"
)

type Response struct {
}

func ReadResponse(req *Request, buf *buffer.Buffer, readBody bool) (*Response, enums.ParseResult, error) {
	bufReader := bufio.NewReader(buf)
	parseMySQLResponse(bufReader)
	res := &Response{}
	return res, enums.ParseResultSuccess, nil
}

func parseMySQLResponse(reader *bufio.Reader) {
	for {
		length, seqNum, payload, err := readPacket(reader)
		if err != nil {
			log.Println("Finished reading packets")
			break
		}

		fmt.Printf("Packet length: %d\n", length)
		fmt.Printf("Sequence number: %d\n", seqNum)
		fmt.Printf("Payload: %x\n", payload)

		if len(payload) == 0 {
			fmt.Println("Empty payload, end of response")
			break
		}

		parsePayload(payload)
	}
}

func readPacket(reader *bufio.Reader) (int, byte, []byte, error) {
	lengthBytes := make([]byte, 3)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return 0, 0, nil, err
	}
	length := int(lengthBytes[0]) | int(lengthBytes[1])<<8 | int(lengthBytes[2])<<16

	seqNum, err := reader.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, 0, nil, err
	}

	return length, seqNum, payload, nil
}

func parsePayload(payload []byte) {
	switch payload[0] {
	case 0x00:
		parseOKPacket(payload)
	case 0xff:
		parseErrorPacket(payload)
	case 0xfe:
		parseEOFPacket(payload)
	default:
		parseResultSet(payload)
	}
}

func parseOKPacket(payload []byte) {
	fmt.Println("OK Packet:")
	// 进一步解析OK包
	// 这里可以根据协议解析影响的行数、插入ID、状态标志、警告数等
}

func parseErrorPacket(payload []byte) {
	fmt.Println("Error Packet:")
	errorCode := binary.LittleEndian.Uint16(payload[1:3])
	errorMsg := string(payload[3:])
	fmt.Printf("Error Code: %d\n", errorCode)
	fmt.Printf("Error Message: %s\n", errorMsg)
}

func parseEOFPacket(payload []byte) {
	fmt.Println("EOF Packet:")
	// 进一步解析EOF包
	// 这里可以根据协议解析警告数和状态标志
}

func parseResultSet(payload []byte) {
	fmt.Println("Result Set Packet:")
	// 进一步解析结果集包
	// 结果集包的解析涉及字段定义、行数据等
	// 这里只是一个简单示例
	fieldCount := payload[0]
	fmt.Printf("Field Count: %d\n", fieldCount)

	// 示例：假设接下来是字段定义，行数据等
	// 这里需要根据具体协议继续解析
}
