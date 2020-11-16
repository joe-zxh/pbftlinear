// proto的类型是用于rpc时的传输，它的字段会更精简；而普通数据结构是存在 本地的，它会记录更多的字段。这个文件是用于转换的。
package proto

import (
	"github.com/joe-zxh/pbftlinear/config"
	"github.com/joe-zxh/pbftlinear/data"
	"math/big"
)

func PP2Proto(dpp *data.PrePrepareArgs) *PrePrepareArgs {
	commands := make([]*Command, 0, len(dpp.Commands))
	for _, cmd := range dpp.Commands {
		commands = append(commands, CommandToProto(cmd))
	}
	return &PrePrepareArgs{
		View:     dpp.View,
		Seq:      dpp.Seq,
		Commands: commands,
	}
}

func (pp *PrePrepareArgs) Proto2PP() *data.PrePrepareArgs {
	commands := make([]data.Command, 0, len(pp.GetCommands()))
	for _, cmd := range pp.GetCommands() {
		commands = append(commands, cmd.Proto2Command())
	}
	dpp := &data.PrePrepareArgs{
		View:     pp.View,
		Seq:      pp.Seq,
		Commands: commands,
	}
	return dpp
}

func CommandToProto(cmd data.Command) *Command {
	return &Command{Data: []byte(cmd)}
}

func (cmd *Command) Proto2Command() data.Command {
	return data.Command(cmd.GetData())
}

func PartialSig2Proto(dPs *data.PartialSig) *PartialSig {
	return &PartialSig{
		ReplicaID: int32(dPs.ID),
		R:         dPs.R.Bytes(),
		S:         dPs.S.Bytes(),
	}
}

func (pPs *PartialSig) Proto2PartialSig() *data.PartialSig {
	r := big.NewInt(0)
	s := big.NewInt(0)
	r.SetBytes(pPs.GetR())
	s.SetBytes(pPs.GetS())
	return &data.PartialSig{
		ID: config.ReplicaID(pPs.GetReplicaID()),
		R:  r,
		S:  s,
	}
}

func QuorumCertToProto(qc *data.QuorumCert) *QuorumCert {
	sigs := make([]*PartialSig, 0, len(qc.Sigs))
	for _, psig := range qc.Sigs {
		sigs = append(sigs, PartialSig2Proto(&psig))
	}
	return &QuorumCert{
		Sigs: sigs,
		SigContent: qc.SigContent[:],
	}
}

func (pqc *QuorumCert) Proto2QuorumCert() *data.QuorumCert {
	qc := &data.QuorumCert{
		Sigs: make(map[config.ReplicaID]data.PartialSig),
	}
	copy(qc.SigContent[:], pqc.SigContent)
	for _, ppsig := range pqc.GetSigs() {
		psig := ppsig.Proto2PartialSig()
		qc.Sigs[psig.ID] = *psig
	}
	return qc
}
