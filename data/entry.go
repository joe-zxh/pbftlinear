package data

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
)

type Command string

// BlockHash represents a SHA256 hashsum of a Block
type EntryHash [64]byte

func (d EntryHash) String() string {
	return hex.EncodeToString(d[:])
}

func (d EntryHash) ToSlice() []byte {
	return d[:]
}

type EntryID struct {
	V uint32
	N uint32
}

type Entry struct {
	Mut sync.Mutex
	PP  *PrePrepareArgs

	PreparedCert *QuorumCert // SigContent是PrepareHash
	Prepared     bool

	CommittedCert *QuorumCert // SigContent是CommitHash
	Committed     bool

	Digest      *EntryHash
	PrepareHash *EntryHash // 签名内容：hash("prepare"+Digest)
	CommitHash  *EntryHash // 签名内容: hash(“commit”+PrepareHash) // 因为有些节点先收到P再收到PP，没有Digest，所以用的是PrepareHash
}

//type Entry struct {
//	Mut        sync.Mutex
//	PP         *PrePrepareArgs
//	P          []*PrepareArgs
//	SendCommit bool
//	C          []*CommitArgs
//	Committed  bool
//	Digest     *EntryHash
//}

func (e *Entry) String() string {
	return fmt.Sprintf("Entry{View: %d, Seq: %d, Committed: %v}",
		e.PP.View, e.PP.Seq, e.Committed)
}

// Hash returns a hash digest of the block.
func (e *Entry) GetDigest() EntryHash {
	// return cached hash if available
	if e.Digest != nil {
		return *e.Digest
	}

	if e.PP == nil {
		panic(`PrePrepare args of entry is empty!!!`)
	}

	s512 := sha512.New()

	byte4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(byte4, uint32(e.PP.View))
	s512.Write(byte4[:])

	binary.LittleEndian.PutUint32(byte4, uint32(e.PP.Seq))
	s512.Write(byte4[:])

	for _, cmd := range e.PP.Commands {
		s512.Write([]byte(cmd))
	}

	e.Digest = new(EntryHash)
	sum := s512.Sum(nil)
	copy(e.Digest[:], sum)

	return *e.Digest
}

func (e *Entry) GetPrepareHash() EntryHash {
	// return cached hash if available
	if e.PrepareHash != nil {
		return *e.PrepareHash
	}

	s512 := sha512.New()

	byte4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(byte4, uint32(e.PP.View))
	s512.Write(byte4[:])

	binary.LittleEndian.PutUint32(byte4, uint32(e.PP.Seq))
	s512.Write(byte4[:])

	s512.Write([]byte("prepare"))
	s512.Write(e.GetDigest().ToSlice())

	e.PrepareHash = new(EntryHash)
	sum := s512.Sum(nil)
	copy(e.PrepareHash[:], sum)

	return *e.PrepareHash
}

func (e *Entry) GetCommitHash() EntryHash {
	// return cached hash if available
	if e.CommitHash != nil {
		return *e.CommitHash
	}

	s512 := sha512.New()
	s512.Write([]byte("commit"))
	s512.Write(e.GetPrepareHash().ToSlice())

	e.CommitHash = new(EntryHash)
	sum := s512.Sum(nil)
	copy(e.CommitHash[:], sum)

	return *e.CommitHash
}
