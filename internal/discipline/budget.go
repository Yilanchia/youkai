package discipline

import (
	"context"
	"sync"
	"time"
)

// limiter is the passport's shared request budget.
//
// It is a separate object because a Guard can be cloned: account provisioning
// uses one clone per identity (separate cookie jars), and the browser uses
// another. All of them must draw from the SAME budget, otherwise a page that
// opens many requests - or a manifest with many accounts - could multiply the
// authorisation the human granted.
type limiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	used   int
}

func newLimiter(scope *Scope, now time.Time) *limiter {
	return &limiter{tokens: scope.RPS, last: now}
}

// reset refills the bucket and clears the counter (a new passport was installed).
func (l *limiter) reset(scope *Scope, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = scope.RPS
	l.last = now
	l.used = 0
}

// count is the number of admitted requests.
func (l *limiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

// take admits one request, waiting (under ctx) when the bucket is empty.
//
// It returns the wait that had to happen so callers can log it; the request is
// counted either way. A ctx cancellation turns into an error the caller must
// treat as a refusal.
func (l *limiter) take(ctx context.Context, scope *Scope, now func() time.Time, sleep func(context.Context, time.Duration) error) (time.Duration, error) {
	l.mu.Lock()
	t := now()
	elapsed := t.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * scope.RPS
		if l.tokens > scope.RPS {
			l.tokens = scope.RPS
		}
		l.last = t
	}
	var wait time.Duration
	if l.tokens < 1 {
		wait = time.Duration((1 - l.tokens) / scope.RPS * float64(time.Second))
		l.tokens = 0
		l.last = t
	} else {
		l.tokens--
	}
	l.used++
	l.mu.Unlock()

	if wait <= 0 {
		return 0, nil
	}
	if err := sleep(ctx, wait); err != nil {
		return wait, err
	}
	return wait, nil
}
