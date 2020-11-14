package data

type PrePrepareArgs struct {
	View     uint32
	Seq      uint32
	Commands []Command
}

type PrePrepareReply struct {
	Sig *PartialSig
}

type PrepareArgs struct {
	View   uint32
	Seq    uint32
	Digest EntryHash
	Sender uint32
}

type PrepareReply struct {
	Sig *PartialSig
}

type CommitArgs struct {
	View   uint32
	Seq    uint32
	Digest EntryHash
	Sender uint32
}

//
//type PartialSig struct {
//	ReplicaID int32
//	R         []byte
//	S         []byte
//}
//
//type QuorumCert struct {
//	Sigs []*PartialSig
//}
