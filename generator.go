package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

type Generator interface {
	NewV4() (UUID, error)
	NewV7() (UUID, error)
}

func (u *UUID) SetVersion(v byte) {
	u[6] = (u[6] & 0x0F) | (v << 4)
}

// SetVariant sets the variant bits.
func (u *UUID) SetVariant(v byte) {
	switch v {
	case VariantNCS:
		u[8] = (u[8]&(0xff>>1) | (0x00 << 7))
	case VariantRFC9562:
		u[8] = (u[8]&(0xff>>2) | (0x02 << 6))
	case VariantMicrosoft:
		u[8] = (u[8]&(0xff>>3) | (0x06 << 5))
	case VariantFuture:
		fallthrough
	default:
		u[8] = (u[8]&(0xff>>3) | (0x07 << 5))
	}
}

const (
	v7CounterMax = 1 << 12
	randBufSize  = 1024 // 空间换时间：预取 1KB 随机数
)

type v7State struct {
	lastMs  atomic.Uint64
	counter atomic.Uint32
	// 缓冲区和索引，减少系统调用开销
	randBuf [randBufSize]byte
	randIdx int
	// 缓存行填充 (Padding)，防止 False Sharing (伪共享)
	// 确保每个 v7State 独立占据 Cache Line
	_ [64]byte
}

type gen struct {
	rand   io.Reader
	shards []v7State
	mask   uint32
}

func newDefaultGen() *gen {
	// 向上取 2 的幂次，方便位运算
	n := runtime.GOMAXPROCS(0)
	size := 1
	for size < n {
		size <<= 1
	}

	g := &gen{
		rand:   rand.Reader,
		shards: make([]v7State, size),
		mask:   uint32(size - 1),
	}

	// 预填充所有分片的缓冲区
	for i := range g.shards {
		_, _ = io.ReadFull(g.rand, g.shards[i].randBuf[:])
	}
	return g
}

var defaultGen = newDefaultGen()

// 快速获取分片：使用 runtime 提供的调度信息（或简单的计数器轮询）
func (g *gen) getShard() *v7State {
	// 在高并发下，这里可以用 atomic 递增来实现公平分发
	staticIdx := uint32(runtime.NumGoroutine())
	return &g.shards[staticIdx&g.mask]
}

// NewV7 生成单调递增的 V7 UUID
func (g *gen) NewV7() (UUID, error) {
	s := &g.shards[uint32(runtime.NumGoroutine())&g.mask]
	now := uint64(time.Now().UnixMilli())

	var ms uint64
	var ctr uint32

	for {
		last := s.lastMs.Load()
		if now > last {
			if s.lastMs.CompareAndSwap(last, now) {
				// 新毫秒：取 2 字节随机数做 seed
				var seed [2]byte
				if err := g.fillFromBuf(s, seed[:]); err != nil {
					return NilUUID, err
				}
				c := uint32(binary.BigEndian.Uint16(seed[:])) & (v7CounterMax - 1)
				s.counter.Store(c)
				ms, ctr = now, c
				break
			}
			continue
		}

		// 同毫秒或回退
		c := s.counter.Add(1)
		if c >= v7CounterMax {
			runtime.Gosched()
			now = uint64(time.Now().UnixMilli())
			continue
		}
		ms, ctr = last, c
		break
	}

	var u UUID
	// 时间戳
	u[0], u[1], u[2], u[3], u[4], u[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)

	// 填充剩余随机位
	if err := g.fillFromBuf(s, u[6:]); err != nil {
		return NilUUID, err
	}

	// 修正版本和变体
	u.SetVersion(7)
	u[6] = (u[6] & 0x0F) | byte(ctr>>8)
	u[7] = byte(ctr)
	u.SetVariant(VariantRFC9562)

	return u, nil
}

// fillFromBuf：从缓冲区读取随机数，如果缓冲区耗尽则重新填充
func (g *gen) fillFromBuf(s *v7State, b []byte) error {
	if s.randIdx+len(b) > randBufSize {
		// 缓冲区耗尽，触发系统调用重新填充
		if _, err := io.ReadFull(g.rand, s.randBuf[:]); err != nil {
			return err
		}
		s.randIdx = 0
	}
	copy(b, s.randBuf[s.randIdx:s.randIdx+len(b)])
	s.randIdx += len(b)
	return nil
}

// 满足 Generator 接口的其他方法...
func (g *gen) NewV4() (UUID, error) {
	var u UUID
	s := g.getShard()
	g.fillFromBuf(s, u[:])
	u.SetVersion(4)
	u.SetVariant(VariantRFC9562)
	return u, nil
}
