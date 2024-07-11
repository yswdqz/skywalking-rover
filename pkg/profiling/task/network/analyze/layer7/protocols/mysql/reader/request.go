package reader

import (
	"bufio"
	"fmt"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

type Request struct {
	*MessageOpt
	original     *http.Request
	headerBuffer *buffer.Buffer
	bodyBuffer   *buffer.Buffer
}

type Message interface {
	Headers() http.Header
	HeaderBuffer() *buffer.Buffer
	BodyBuffer() *buffer.Buffer
}

type MessageOpt struct {
	Message
}

func ReadRequest(buf *buffer.Buffer, readBody bool) (*Request, enums.ParseResult, error) {
	bufReader := bufio.NewReader(buf)
	tp := textproto.NewReader(bufReader)
	req := &http.Request{}
	result := &Request{original: req}
	result.MessageOpt = &MessageOpt{result}

	headerStartPosition := buf.Position()
	line, err := tp.ReadLine()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("read request first lint failure: %v", err)
	}
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("the first line is not request: %s", line)
	}

	isRequest := false
	for _, m := range requestMethods {
		if method == m {
			isRequest = true
			break
		}
	}
	if !isRequest {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("is not request: %s", method)
	}
	major, minor, ok := http.ParseHTTPVersion(proto)
	if !ok {
		return nil, enums.ParseResultSkipPackage, fmt.Errorf("the protocol version cannot be identity: %s", proto)
	}
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(requestURI, "/")
	if justAuthority {
		requestURI = "http://" + requestURI
	}
	uri, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return nil, enums.ParseResultSkipPackage, err
	}
	req.Method, req.URL, req.RequestURI = method, uri, requestURI
	req.Proto, req.ProtoMajor, req.ProtoMinor = proto, major, minor

	// header reader
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, enums.ParseResultSkipPackage, err
	}
	req.Header = http.Header(mimeHeader)

	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}

	result.buildHeaderBuffer(headerStartPosition, buf, bufReader)
	if readBody {
		if b, r, err := result.readFullBody(bufReader, buf); err != nil {
			return nil, enums.ParseResultSkipPackage, err
		} else if r != enums.ParseResultSuccess {
			return nil, r, nil
		} else {
			result.bodyBuffer = b
		}
	}

	return result, enums.ParseResultSuccess, nil
}
