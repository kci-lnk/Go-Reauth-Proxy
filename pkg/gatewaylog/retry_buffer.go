package gatewaylog

import "io"

// logBuffer admits whole records. A flush failure must retain unwritten bytes
// so an ENOSPC recovery can retry without duplicating the successfully written
// prefix or permanently latching an error as bufio.Writer does.
type logBuffer interface {
	Write([]byte) (int, error)
	WriteString(string) (int, error)
	Flush() error
}

type retryLogBuffer struct {
	writer  io.Writer
	pending []byte
	limit   int
	failed  bool
	written int
}

func newRetryLogBuffer(writer io.Writer, limit int) *retryLogBuffer {
	return &retryLogBuffer{writer: writer, pending: make([]byte, 0, limit), limit: limit}
}

func (b *retryLogBuffer) Write(p []byte) (int, error) {
	if b.failed || len(b.pending)+len(p) > b.limit {
		if err := b.Flush(); err != nil {
			return 0, err
		}
	}
	// The caller caps individual records below maxScanToken. Even a record larger
	// than the regular buffer is admitted atomically and remains bounded.
	b.pending = append(b.pending, p...)
	return len(p), nil
}
func (b *retryLogBuffer) WriteString(p string) (int, error) { return b.Write([]byte(p)) }
func (b *retryLogBuffer) Flush() error {
	for b.written < len(b.pending) {
		n, err := b.writer.Write(b.pending[b.written:])
		if n < 0 || n > len(b.pending)-b.written {
			b.failed = true
			return io.ErrShortWrite
		}
		b.written += n
		if err != nil {
			b.failed = true
			return err
		}
		if n == 0 {
			b.failed = true
			return io.ErrShortWrite
		}
	}
	if cap(b.pending) > 2*b.limit {
		b.pending = make([]byte, 0, b.limit)
	} else {
		b.pending = b.pending[:0]
	}
	b.written = 0
	b.failed = false
	return nil
}
