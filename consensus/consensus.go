package consensus

import (
	"context"
	"fmt"
	"go.uber.org/atomic"
	"log"
	"sync"
	"time"

	"github.com/joe-zxh/pbftlinear/config"
	"github.com/joe-zxh/pbftlinear/data"
	"github.com/joe-zxh/pbftlinear/internal/logging"
	"github.com/joe-zxh/pbftlinear/util"
)

const (
	changeViewTimeout = 60 * time.Second
	checkpointDiv     = 2000000
)

var logger *log.Logger

func init() {
	logger = logging.GetLogger()
}

// PBFTLinearCore is the safety core of the PBFTLinearCore protocol
type PBFTLinearCore struct {
	// from hotstuff

	cmdCache *data.CommandSet // Contains the commands that are waiting to be proposed
	Config   *config.ReplicaConfig
	SigCache *data.SignatureCache
	cancel   context.CancelFunc // stops goroutines

	Exec chan []data.Command

	// from pbftlinear
	Mut        sync.Mutex // Lock for all internal data
	ID         uint32
	tSeq       atomic.Uint32           // Total sequence number of next request
	seqmap     map[data.EntryID]uint32 // Use to map {Cid,CSeq} to global sequence number for all prepared message
	View       uint32
	Apply      uint32                       // Sequence number of last executed request
	Log        map[data.EntryID]*data.Entry // bycon的log是一个数组，因为需要保证连续，leader可以处理log inconsistency，而pbft不需要。client只有执行完上一条指令后，才会发送下一条请求，所以顺序 并没有问题。
	cps        map[int]*CheckPoint
	WaterLow   uint32
	WaterHigh  uint32
	F          uint32
	Q          uint32
	N          uint32
	monitor    bool
	Change     *time.Timer
	Changing   bool                // Indicate if this node is changing view
	state      interface{}         // Deterministic state machine's state
	ApplyQueue *util.PriorityQueue // 因为PBFT的特殊性(log是一个map，而不是list)，所以这里需要一个applyQueue。
	vcs        map[uint32][]*ViewChangeArgs
	lastcp     uint32

	Leader   uint32 // view改变的时候，再改变
	IsLeader bool   // view改变的时候，再改变
}

func (pbftlinear *PBFTLinearCore) AddCommand(command data.Command) {
	pbftlinear.cmdCache.Add(command)
}

func (pbftlinear *PBFTLinearCore) CommandSetLen(command data.Command) int {
	return pbftlinear.cmdCache.Len()
}

// CreateProposal creates a new proposal
func (pbftlinear *PBFTLinearCore) CreateProposal(timeout bool) *data.PrePrepareArgs {

	var batch []data.Command

	if timeout { // timeout的时候，不管够不够batch都要发起共识。
		batch = pbftlinear.cmdCache.RetriveFirst(pbftlinear.Config.BatchSize)
	} else {
		batch = pbftlinear.cmdCache.RetriveExactlyFirst(pbftlinear.Config.BatchSize)
	}

	if batch == nil {
		return nil
	}
	e := &data.PrePrepareArgs{
		View:     pbftlinear.View,
		Seq:      pbftlinear.tSeq.Inc(),
		Commands: batch,
	}
	return e
}

// New creates a new PBFTLinearCore instance
func New(conf *config.ReplicaConfig) *PBFTLinearCore {
	logger.SetPrefix(fmt.Sprintf("hs(id %d): ", conf.ID))

	ctx, cancel := context.WithCancel(context.Background())

	pbftlinear := &PBFTLinearCore{
		// from hotstuff
		Config:   conf,
		cancel:   cancel,
		SigCache: data.NewSignatureCache(conf),
		cmdCache: data.NewCommandSet(),
		Exec:     make(chan []data.Command, 1),

		// pbftlinear
		ID:         uint32(conf.ID),
		seqmap:     make(map[data.EntryID]uint32),
		View:       1,
		Apply:      0,
		Log:        make(map[data.EntryID]*data.Entry),
		cps:        make(map[int]*CheckPoint),
		WaterLow:   0,
		WaterHigh:  2 * checkpointDiv,
		F:          uint32(len(conf.Replicas)-1) / 3,
		N:          uint32(len(conf.Replicas)),
		monitor:    false,
		Change:     nil,
		Changing:   false,
		state:      make([]interface{}, 1),
		ApplyQueue: util.NewPriorityQueue(),
		vcs:        make(map[uint32][]*ViewChangeArgs),
		lastcp:     0,
	}
	pbftlinear.Q = pbftlinear.F*2 + 1
	pbftlinear.Leader = (pbftlinear.View-1)%pbftlinear.N + 1
	pbftlinear.IsLeader = (pbftlinear.Leader == pbftlinear.ID)

	// Put an initial stable checkpoint
	cp := pbftlinear.getCheckPoint(-1)
	cp.Stable = true
	cp.State = pbftlinear.state

	go pbftlinear.proposeConstantly(ctx)

	return pbftlinear
}

func (pbftlinear *PBFTLinearCore) proposeConstantly(ctx context.Context) {
	for {
		select {
		// todo: 一个计时器，如果是leader，就开始preprepare
		case <-ctx.Done():
			return
		}
	}
}

func (pbftlinear *PBFTLinearCore) Close() {
	pbftlinear.cancel()
}

func (pbftlinear *PBFTLinearCore) GetExec() chan []data.Command {
	return pbftlinear.Exec
}

func (pbftlinear *PBFTLinearCore) GetEntry(id data.EntryID) *data.Entry {
	_, ok := pbftlinear.Log[id]
	if !ok {
		pbftlinear.Log[id] = &data.Entry{}
	}
	return pbftlinear.Log[id]
}
