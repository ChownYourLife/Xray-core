package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestIncrementalPickerFailure(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockWorkerFactory := mocks.NewMuxClientWorkerFactory(mockCtl)
	mockWorkerFactory.EXPECT().Create().Return(nil, errors.New("test"))

	picker := mux.IncrementalWorkerPicker{
		Factory: mockWorkerFactory,
	}

	_, err := picker.PickAvailable()
	if err == nil {
		t.Error("expected error, but nil")
	}
}

func TestClientWorkerEOF(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	common.Must(writer.Close())

	worker, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	common.Must(err)

	select {
	case <-worker.WaitClosed():
	case <-time.After(5 * time.Second):
		t.Fatal("EOF did not close the worker")
	}

	f := worker.Dispatch(context.Background(), nil)
	if f {
		t.Error("expected failed dispatching, but actually not")
	}
}

func TestClientWorkerClose(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	worker1, err := mux.NewClientWorker(transport.Link{
		Reader: r1,
		Writer: w1,
	}, mux.ClientStrategy{
		MaxConcurrency: 4,
		MaxConnection:  4,
	})
	common.Must(err)

	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	worker2, err := mux.NewClientWorker(transport.Link{
		Reader: r2,
		Writer: w2,
	}, mux.ClientStrategy{
		MaxConcurrency: 4,
		MaxConnection:  4,
	})
	common.Must(err)

	factory := mocks.NewMuxClientWorkerFactory(mockCtl)
	gomock.InOrder(
		factory.EXPECT().Create().Return(worker1, nil),
		factory.EXPECT().Create().Return(worker2, nil),
	)

	picker := &mux.IncrementalWorkerPicker{
		Factory: factory,
	}
	manager := &mux.ClientManager{
		Picker: picker,
	}

	tr1, tw1 := pipe.New(pipe.WithoutSizeLimit())
	ctx1 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	common.Must(manager.Dispatch(ctx1, &transport.Link{
		Reader: tr1,
		Writer: tw1,
	}))
	defer tw1.Close()

	common.Must(w1.Close())

	select {
	case <-worker1.WaitClosed():
	case <-time.After(5 * time.Second):
		t.Fatal("worker1 did not close")
	}

	tr2, tw2 := pipe.New(pipe.WithoutSizeLimit())
	ctx2 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	common.Must(manager.Dispatch(ctx2, &transport.Link{
		Reader: tr2,
		Writer: tw2,
	}))
	defer tw2.Close()

	common.Must(w2.Close())
}

func TestClientWorkerUDPSource(t *testing.T) {
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: downR, Writer: upW}, mux.ClientStrategy{})
	common.Must(err)

	inR, inW := pipe.New(pipe.WithoutSizeLimit())
	outR, outW := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: inR, Writer: outW}) {
		t.Fatal("failed to dispatch")
	}
	b := buf.New()
	b.WriteString("query")
	common.Must(inW.WriteMultiBuffer(buf.MultiBuffer{b}))
	mb, err := upR.ReadMultiBuffer() // New frame, the session is UDP from now on
	common.Must(err)
	buf.ReleaseMulti(mb)

	srcs := []net.Destination{
		net.UDPDestination(net.ParseAddress("1.1.1.1"), 1111),
		net.UDPDestination(net.DomainAddress("example.com"), 2222),
		net.UDPDestination(net.ParseAddress("3.3.3.3"), 3333),
	}
	w := mux.NewResponseWriter(1, downW, protocol.TransferTypePacket)
	var got buf.MultiBuffer
	for i := range srcs {
		b := buf.New()
		b.WriteString("reply")
		b.UDP = &srcs[i]
		common.Must(w.WriteMultiBuffer(buf.MultiBuffer{b}))
		// keep earlier replies around while the next frame is parsed
		mb, err := outR.ReadMultiBuffer()
		common.Must(err)
		got = append(got, mb...)
	}
	for i, b := range got {
		if b.UDP == nil || *b.UDP != srcs[i] {
			t.Errorf("reply %d: source = %v, want %v", i, b.UDP, srcs[i])
		}
	}
}

// blockedOutbound deliberately blocks on the transport, not ctx.Done:
// cancellation must interrupt the pipes as well as canceling the context.
type blockedOutbound struct {
	started chan struct{}
	ended   chan struct{}
}

func (p *blockedOutbound) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	close(p.started)
	mb, err := link.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	close(p.ended)
	return err
}

func TestDialingWorkerCancellationInterruptsTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy := &blockedOutbound{started: make(chan struct{}), ended: make(chan struct{})}
	factory := &mux.DialingWorkerFactory{
		Context: ctx,
		Proxy:   proxy,
		Strategy: mux.ClientStrategy{
			MaxConcurrency: 4,
			MaxConnection:  4,
		},
	}
	picker := &mux.IncrementalWorkerPicker{Factory: factory}
	manager := &mux.ClientManager{Picker: picker}
	defer manager.Close()
	worker, err := picker.PickAvailable()
	common.Must(err)
	select {
	case <-proxy.started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker transport did not start")
	}
	cancel()
	select {
	case <-worker.WaitClosed():
	case <-time.After(5 * time.Second):
		t.Fatal("owner cancellation did not close the worker")
	}
	select {
	case <-proxy.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled worker left its transport blocked")
	}
	common.Must(manager.Close())
	if _, err := picker.PickAvailable(); err == nil {
		t.Fatal("closed picker opened a new transport")
	}
}
