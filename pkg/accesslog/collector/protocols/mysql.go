package protocols

import (
	"container/list"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/accesslog/forwarder"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/mysql/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
	"io"
	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"
)

var mysqllog = logger.GetLogger("accesslog", "collector", "protocols", "mysql")

func init() {
	registeredProtocols[enums.ConnectionProtocolMySQL] = func(ctx *common.AccessLogContext) Protocol {
		return &MySQLProtocol{ctx: ctx}
	}
}

type MySQLProtocol struct {
	ctx *common.AccessLogContext
}

type MySQLMetrics struct {
	connectionID uint64
	randomID     uint64

	halfRequests *list.List
}

func (p *MySQLProtocol) GenerateConnection(connectionID, randomID uint64) ProtocolMetrics {
	return &MySQLMetrics{
		connectionID: connectionID,
		randomID:     randomID,
		halfRequests: list.New(),
	}
}

func (p *MySQLProtocol) Analyze(metrics ProtocolMetrics, buf *buffer.Buffer, _ *AnalyzeHelper) error {
	MySQLMetrics := metrics.(*MySQLMetrics)
	mysqllog.Debugf("ready to analyze mysql protocol data, connection ID: %d, random ID: %d, data len: %d",
		MySQLMetrics.connectionID, MySQLMetrics.randomID, buf.DataLength())
	buf.ResetForLoopReading()
	for {
		if !buf.PrepareForReading() {
			return nil
		}

		messageType, err := reader.IdentityMessageType(buf)
		if err != nil {
			mysqllog.Debugf("failed to identity message type, %v", err)
			if buf.SkipCurrentElement() {
				break
			}
			continue
		}

		var result enums.ParseResult
		switch messageType {
		case reader.MessageTypeRequest:
			result, _ = p.handleRequest(metrics, buf)
		case reader.MessageTypeResponse:
			result, _ = p.handleResponse(metrics, buf)
		case reader.MessageTypeUnknown:
			result = enums.ParseResultSkipPackage
		}

		finishReading := false
		switch result {
		case enums.ParseResultSuccess:
			finishReading = buf.RemoveReadElements()
		case enums.ParseResultSkipPackage:
			finishReading = buf.SkipCurrentElement()
		}

		if finishReading {
			break
		}
	}
	return nil
}

func (p *MySQLProtocol) handleRequest(metrics ProtocolMetrics, buf *buffer.Buffer) (enums.ParseResult, error) {
	req, result, err := reader.ReadRequest(buf, true)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
	metrics.(*MySQLMetrics).appendRequestToList(req)
	return result, nil
}

func (p *MySQLProtocol) handleResponse(metrics ProtocolMetrics, b *buffer.Buffer) (enums.ParseResult, error) {
	MySQLMetrics := metrics.(*MySQLMetrics)
	firstRequest := MySQLMetrics.halfRequests.Front()
	if firstRequest == nil {
		return enums.ParseResultSkipPackage, nil
	}
	request := MySQLMetrics.halfRequests.Remove(firstRequest).(*reader.Request)

	// parsing response
	response, result, err := reader.ReadResponse(request, b, true)
	defer func() {
		// if parsing response failed, then put the request back to the list
		if result != enums.ParseResultSuccess {
			MySQLMetrics.halfRequests.PushFront(request)
		}
	}()
	if err != nil {
		return enums.ParseResultSkipPackage, err
	} else if result != enums.ParseResultSuccess {
		return result, nil
	}

	// getting the request and response, then send to the forwarder
	p.handleHTTPData(MySQLMetrics, request, response)
	return enums.ParseResultSuccess, nil
}

func (p *MySQLProtocol) handleHTTPData(metrics *MySQLMetrics, request *reader.Request, response *reader.Response) {
	detailEvents := make([]*events.SocketDetailEvent, 0)
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, request.HeaderBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, request.BodyBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, response.HeaderBuffer())
	detailEvents = appendSocketDetailsFromBuffer(detailEvents, response.BodyBuffer())

	if len(detailEvents) == 0 {
		mysqllog.Warnf("cannot found any detail events for HTTP/1.x protocol, data id: %d-%d",
			request.MinDataID(), response.BodyBuffer().LastSocketBuffer().DataID())
		return
	}
	mysqllog.Debugf("found fully MYSQL request and response, contains %d detail events , connection ID: %d, random ID: %d",
		len(detailEvents), metrics.connectionID, metrics.randomID)
	originalRequest := request.Original()
	originalResponse := response.Original()

	defer func() {
		p.closeStream(originalRequest.Body)
		p.closeStream(originalResponse.Body)
	}()
	forwarder.SendTransferProtocolEvent(p.ctx, detailEvents, &v3.AccessLogProtocolLogs{
		Protocol: &v3.AccessLogProtocolLogs_Http{
			Http: &v3.AccessLogHTTPProtocol{
				StartTime: forwarder.BuildOffsetTimestamp(detailEvents[0].StartTime),
				EndTime:   forwarder.BuildOffsetTimestamp(detailEvents[len(detailEvents)-1].EndTime),
				Version:   v3.AccessLogHTTPProtocolVersion_MYSQL,
				Request: &v3.AccessLogHTTPProtocolRequest{
					Method:             transformHTTPMethod(originalRequest.Method),
					Path:               originalRequest.URL.Path,
					SizeOfHeadersBytes: uint64(request.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(request.BodyBuffer().DataSize()),

					Trace: analyzeTraceInfo(func(key string) string {
						return originalRequest.Header.Get(key)
					}, mysqllog),
				},
				Response: &v3.AccessLogHTTPProtocolResponse{
					StatusCode:         int32(originalResponse.StatusCode),
					SizeOfHeadersBytes: uint64(response.HeaderBuffer().DataSize()),
					SizeOfBodyBytes:    uint64(response.BodyBuffer().DataSize()),
				},
			},
		},
	})
}

func (p *MySQLProtocol) closeStream(ioReader io.Closer) {
	if ioReader != nil {
		_ = ioReader.Close()
	}
}

func transformHTTPMethod(method string) v3.AccessLogHTTPProtocolRequestMethod {
	switch method {
	case "GET":
		return v3.AccessLogHTTPProtocolRequestMethod_Get
	case "POST":
		return v3.AccessLogHTTPProtocolRequestMethod_Post
	case "PUT":
		return v3.AccessLogHTTPProtocolRequestMethod_Put
	case "DELETE":
		return v3.AccessLogHTTPProtocolRequestMethod_Delete
	case "HEAD":
		return v3.AccessLogHTTPProtocolRequestMethod_Head
	case "OPTIONS":
		return v3.AccessLogHTTPProtocolRequestMethod_Options
	case "TRACE":
		return v3.AccessLogHTTPProtocolRequestMethod_Trace
	case "CONNECT":
		return v3.AccessLogHTTPProtocolRequestMethod_Connect
	case "PATCH":
		return v3.AccessLogHTTPProtocolRequestMethod_Patch
	}
	mysqllog.Warnf("unknown http method: %s", method)
	return v3.AccessLogHTTPProtocolRequestMethod_Get
}

func (m *MySQLMetrics) appendRequestToList(req *reader.Request) {
	if m.halfRequests.Len() == 0 {
		m.halfRequests.PushFront(req)
		return
	}
	if m.halfRequests.Back().Value.(*reader.Request).MinDataID() < req.MinDataID() {
		m.halfRequests.PushBack(req)
		return
	}
	beenAdded := false
	for element := m.halfRequests.Front(); element != nil; element = element.Next() {
		existEvent := element.Value.(*reader.Request)
		if existEvent.MinDataID() > req.MinDataID() {
			m.halfRequests.InsertBefore(req, element)
			beenAdded = true
			break
		}
	}
	if !beenAdded {
		m.halfRequests.PushBack(req)
	}
}
