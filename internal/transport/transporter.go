package transport

import "github.com/redhatinsights/yggdrasil"

type DataReceiveHandlerFunc func([]byte, string)

// Transporter is an interface representing the ability to send and receive
// data. It abstracts away the concrete implementation, leaving that up to the
// implementing type.
type Transporter interface {
	Connect() error
	Disconnect(quiesce uint)
	SendData(data []byte, dest string) (yggdrasil.Response, error)
	ReceiveData(data []byte, dest string) error
}
