package privsep

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/rpc"
)

// maxMessage bounds each gob message the parent reads from the web
// process. The largest request is a staged model; HTTP bodies are capped
// at 4 MiB of JSON, and gob is more compact than that.
const maxMessage = 8 << 20

var errTooBig = errors.New("message from the web process is too big")

// limitReader passes a gob stream through, refusing a message whose
// length prefix is over max before the decoder sees it. The decoder
// allocates what a prefix claims (up to 1 GiB) before reading it, so a
// check after the fact would be too late.
type limitReader struct {
	r       *bufio.Reader
	max     uint64
	pending []byte // a length prefix, read but not yet passed on
	left    uint64 // bytes of the current message not yet passed on
}

func newLimitReader(r io.Reader, max uint64) *limitReader {
	return &limitReader{r: bufio.NewReader(r), max: max}
}

func (l *limitReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(l.pending) == 0 && l.left == 0 {
		// At a message boundary: check the next length first.
		prefix, n, err := readGobUint(l.r)
		if err != nil {
			return 0, err
		}
		if n == 0 || n > l.max {
			return 0, fmt.Errorf("%w (%d bytes, the most is %d)", errTooBig, n, l.max)
		}
		l.pending, l.left = prefix, n
	}
	if len(l.pending) > 0 {
		c := copy(p, l.pending)
		l.pending = l.pending[c:]
		return c, nil
	}
	if uint64(len(p)) > l.left {
		p = p[:l.left]
	}
	c, err := l.r.Read(p)
	l.left -= uint64(c)
	if err == io.EOF && l.left > 0 {
		err = io.ErrUnexpectedEOF
	}
	return c, err
}

// readGobUint reads an unsigned integer in gob's encoding, returning
// its bytes and value: one byte below 0x80, otherwise a byte holding
// the negated count of big-endian bytes that follow (at most 8).
func readGobUint(r *bufio.Reader) ([]byte, uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, 0, err
	}
	if b < 0x80 {
		return []byte{b}, uint64(b), nil
	}
	n := -int(int8(b))
	if n > 8 {
		return nil, 0, fmt.Errorf("invalid gob length prefix %#x", b)
	}
	buf := make([]byte, 1+n)
	buf[0] = b
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		return nil, 0, io.ErrUnexpectedEOF
	}
	var v uint64
	for _, c := range buf[1:] {
		v = v<<8 | uint64(c)
	}
	return buf, v, nil
}

// The codecs frame each message with gob, which is what limitReader
// can bound, but carry request and reply bodies as JSON inside it. gob
// leaves out every zero value, pointers to zero included, so a reply's
// *int that's 0 (an exit status, a handshake a second ago) would arrive
// as nil, "unknown". The bodies are the API's JSON types, and JSON only
// leaves out what omitempty says.

func encodeBody(enc *gob.Encoder, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return enc.Encode(b)
}

func decodeBody(dec *gob.Decoder, body any) error {
	var b []byte
	if err := dec.Decode(&b); err != nil {
		return err
	}
	if body == nil {
		return nil // net/rpc discarding a body
	}
	return json.Unmarshal(b, body)
}

// serverCodec is net/rpc's gob server codec, which isn't exported,
// reading through a limitReader, with JSON bodies.
type serverCodec struct {
	rwc    io.ReadWriteCloser
	dec    *gob.Decoder
	enc    *gob.Encoder
	encBuf *bufio.Writer
	closed bool
}

func newServerCodec(conn io.ReadWriteCloser) *serverCodec {
	buf := bufio.NewWriter(conn)
	return &serverCodec{
		rwc:    conn,
		dec:    gob.NewDecoder(newLimitReader(conn, maxMessage)),
		enc:    gob.NewEncoder(buf),
		encBuf: buf,
	}
}

func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error { return c.dec.Decode(r) }

func (c *serverCodec) ReadRequestBody(body any) error { return decodeBody(c.dec, body) }

func (c *serverCodec) WriteResponse(r *rpc.Response, body any) error {
	if err := c.enc.Encode(r); err != nil {
		if c.encBuf.Flush() == nil {
			c.Close() // the header didn't encode; the stream is unusable
		}
		return err
	}
	if err := encodeBody(c.enc, body); err != nil {
		if c.encBuf.Flush() == nil {
			c.Close()
		}
		return err
	}
	return c.encBuf.Flush()
}

func (c *serverCodec) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.rwc.Close()
}

// clientCodec is the web process's side: net/rpc's gob client codec,
// with JSON bodies.
type clientCodec struct {
	rwc    io.ReadWriteCloser
	dec    *gob.Decoder
	enc    *gob.Encoder
	encBuf *bufio.Writer
}

func newClientCodec(conn io.ReadWriteCloser) *clientCodec {
	buf := bufio.NewWriter(conn)
	return &clientCodec{rwc: conn, dec: gob.NewDecoder(bufio.NewReader(conn)), enc: gob.NewEncoder(buf), encBuf: buf}
}

func (c *clientCodec) WriteRequest(r *rpc.Request, body any) error {
	if err := c.enc.Encode(r); err != nil {
		return err
	}
	if err := encodeBody(c.enc, body); err != nil {
		return err
	}
	return c.encBuf.Flush()
}

func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error { return c.dec.Decode(r) }

func (c *clientCodec) ReadResponseBody(body any) error { return decodeBody(c.dec, body) }

func (c *clientCodec) Close() error { return c.rwc.Close() }
