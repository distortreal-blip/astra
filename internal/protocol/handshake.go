package protocol

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
)

const (
	Version              = "v1"
	StatusOK             = "ok"
	StatusDeny           = "deny"
	CodeInvalidFormat    = "INVALID_FORMAT"
	CodeInvalidSignature = "INVALID_SIGNATURE"
	CodeClockSkew        = "CLOCK_SKEW"
	CodeNonceReplay      = "NONCE_REPLAY"
	CodeTokenMissing     = "TOKEN_MISSING"
	CodeTokenInvalid     = "TOKEN_INVALID"
	CodeTokenExpired     = "TOKEN_EXPIRED"
	CodeTokenRevoked     = "TOKEN_REVOKED"
	CodeRateLimited      = "RATE_LIMITED"
	CodeClientBlocked    = "CLIENT_BLOCKED"
)

const obfsMagic = "ASOB"

type HandshakeRequest struct {
	Version   string `json:"version"`
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Token     string `json:"token,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`
	Transport string `json:"transport,omitempty"`
	ObfsMode  string `json:"obfs_mode,omitempty"`
	Signature string `json:"signature"`
}

type HandshakeResponse struct {
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
}

func SignPayload(req *HandshakeRequest) string {
	return req.Version + "|" + req.ClientID + "|" + req.PublicKey + "|" + int64ToString(req.Timestamp) + "|" + req.Nonce + "|" + req.Token + "|" + req.NetworkID + "|" + req.ProfileID + "|" + req.Transport + "|" + req.ObfsMode
}

func VerifySignature(req *HandshakeRequest) error {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(SignPayload(req)), sigBytes) {
		return errors.New("signature mismatch")
	}
	return nil
}

func WriteHandshake(w *bufio.Writer, req *HandshakeRequest, preamble []byte) error {
	if len(preamble) > 0 {
		if _, err := w.WriteString(obfsMagic); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint16(len(preamble))); err != nil {
			return err
		}
		if _, err := w.Write(preamble); err != nil {
			return err
		}
	}
	enc, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := w.Write(enc); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return err
	}
	return w.Flush()
}

func ReadHandshake(r *bufio.Reader) (*HandshakeRequest, error) {
	if err := consumePreambleIfPresent(r); err != nil {
		return nil, err
	}
	if err := consumeTLSAppPreambleIfPresent(r); err != nil {
		return nil, err
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var req HandshakeRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func WriteResponse(w *bufio.Writer, resp *HandshakeResponse) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := w.Write(enc); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return err
	}
	return w.Flush()
}

func ReadResponse(r *bufio.Reader) (*HandshakeResponse, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp HandshakeResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func IsClockSkew(ts int64, window time.Duration) bool {
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return diff > int64(window.Seconds())
}

func consumePreambleIfPresent(r *bufio.Reader) error {
	peek, err := r.Peek(len(obfsMagic))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if string(peek) != obfsMagic {
		return nil
	}
	if _, err := r.Discard(len(obfsMagic)); err != nil {
		return err
	}
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}
	if length == 0 {
		return nil
	}
	_, err = r.Discard(int(length))
	return err
}

func consumeTLSAppPreambleIfPresent(r *bufio.Reader) error {
	peek, err := r.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if bytes.HasPrefix(peek, []byte("PRI ")) {
		if err := discardExact(r, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
			return err
		}
		return discardHTTP2Frames(r, 6)
	}
	if bytes.HasPrefix(peek, []byte("GET ")) || bytes.HasPrefix(peek, []byte("POST")) || bytes.HasPrefix(peek, []byte("HEAD")) {
		return discardUntilDoubleCRLF(r)
	}
	return nil
}

func discardUntilDoubleCRLF(r *bufio.Reader) error {
	needle := []byte("\r\n\r\n")
	window := make([]byte, 0, len(needle))
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if len(window) < len(needle) {
			window = append(window, b)
		} else {
			copy(window, window[1:])
			window[len(window)-1] = b
		}
		if len(window) == len(needle) && bytes.Equal(window, needle) {
			return nil
		}
	}
}

func discardExact(r *bufio.Reader, data []byte) error {
	buf := make([]byte, len(data))
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if !bytes.Equal(buf, data) {
		return errors.New("unexpected preamble")
	}
	return nil
}

func discardHTTP2Frames(r *bufio.Reader, maxFrames int) error {
	for i := 0; i < maxFrames; i++ {
		peek, err := r.Peek(9)
		if err != nil {
			return nil
		}
		frameType := peek[3]
		if frameType != 0x4 && frameType != 0x6 && frameType != 0x8 && frameType != 0x1 && frameType != 0x0 {
			return nil
		}
		header := make([]byte, 9)
		if _, err := io.ReadFull(r, header); err != nil {
			return err
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if length > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return err
			}
		}
	}
	return nil
}

func int64ToString(v int64) string {
	return strconv.FormatInt(v, 10)
}
