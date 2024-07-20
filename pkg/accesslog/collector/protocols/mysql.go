package protocols

import (
	"container/list"
	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/mysql/reader"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
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
	_, result, err := reader.ReadRequest(buf)
	if err != nil {
		return enums.ParseResultSkipPackage, err
	}
	if result != enums.ParseResultSuccess {
		return result, nil
	}
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
	_, result, err := reader.ReadResponse(request, b, true)
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

	return enums.ParseResultSuccess, nil
}
