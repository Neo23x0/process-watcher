package output

import (
	"context"
	"math/rand/v2"
	"time"
)

const (
	defaultBackoffBase   = time.Second
	defaultBackoffMax    = 30 * time.Second
	defaultBackoffJitter = 0.2
)

// backoffPolicy computes exponential waits: base, 2*base, 4*base ... capped at
// max, with +-jitter applied and the result never above max again.
type backoffPolicy struct {
	base, max time.Duration
	jitter    float64
	rnd       func() float64 // uniform in [0,1)
}

func newBackoff(h Hooks) backoffPolicy {
	b := backoffPolicy{base: h.BackoffBase, max: h.BackoffMax, jitter: h.BackoffJitter, rnd: rand.Float64}
	if b.base <= 0 {
		b.base = defaultBackoffBase
	}
	if b.max <= 0 {
		b.max = defaultBackoffMax
	}
	if b.max < b.base {
		b.max = b.base
	}
	switch {
	case b.jitter == 0:
		b.jitter = defaultBackoffJitter
	case b.jitter < 0:
		b.jitter = 0
	}
	return b
}

// delay returns the wait before retry number n (n >= 1).
func (b backoffPolicy) delay(n int) time.Duration {
	d := b.base
	for i := 1; i < n; i++ {
		if d > b.max/2 {
			d = b.max
			break
		}
		d *= 2
	}
	d = min(d, b.max)
	if b.jitter > 0 {
		d = time.Duration(float64(d) * (1 + b.jitter*(2*b.rnd()-1)))
	}
	return min(max(d, 0), b.max)
}

// sleepContext waits for d or until ctx is done, whichever comes first.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
