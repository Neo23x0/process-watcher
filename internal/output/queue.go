package output

import (
	"context"
	"sync"
)

// item is one queued event. line is shared with all other outputs and is
// never modified.
type item struct {
	id   string
	line []byte
}

type pushResult int

const (
	pushed pushResult = iota
	pushFull
	pushClosed
)

// queue is a bounded FIFO with a single consumer. Its storage grows on
// demand up to limit, so a large configured limit costs nothing until a
// backlog actually builds up. push never blocks.
type queue struct {
	mu     sync.Mutex
	buf    []item
	head   int
	n      int
	limit  int
	closed bool
	wake   chan struct{} // capacity 1; coalesces wake-ups for the consumer
}

func newQueue(limit int) *queue {
	return &queue{
		buf:   make([]item, min(limit, 64)),
		limit: limit,
		wake:  make(chan struct{}, 1),
	}
}

func (q *queue) push(it item) pushResult {
	q.mu.Lock()
	switch {
	case q.closed:
		q.mu.Unlock()
		return pushClosed
	case q.n >= q.limit:
		q.mu.Unlock()
		return pushFull
	}
	if q.n == len(q.buf) {
		q.grow()
	}
	q.buf[(q.head+q.n)%len(q.buf)] = it
	q.n++
	q.mu.Unlock()
	q.signal()
	return pushed
}

func (q *queue) grow() {
	nb := make([]item, min(2*len(q.buf), q.limit))
	for i := 0; i < q.n; i++ {
		nb[i] = q.buf[(q.head+i)%len(q.buf)]
	}
	q.buf, q.head = nb, 0
}

func (q *queue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// pop returns the oldest item. It blocks until one is available and reports
// false once the queue is closed and drained, or ctx is done.
func (q *queue) pop(ctx context.Context) (item, bool) {
	for {
		if ctx.Err() != nil {
			return item{}, false
		}
		q.mu.Lock()
		if q.n > 0 {
			it := q.buf[q.head]
			q.buf[q.head] = item{} // release the reference
			q.head = (q.head + 1) % len(q.buf)
			q.n--
			q.mu.Unlock()
			return it, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return item{}, false
		}
		select {
		case <-q.wake:
		case <-ctx.Done():
			return item{}, false
		}
	}
}

// close stops accepting items; queued ones can still be popped.
func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.signal()
}

// drain discards everything that is queued and returns how many items it was.
func (q *queue) drain() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := q.n
	for i := 0; i < q.n; i++ {
		q.buf[(q.head+i)%len(q.buf)] = item{}
	}
	q.head, q.n = 0, 0
	return n
}

func (q *queue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}
