package watch

import "math"

// floatFromBits + bitsFromFloat let Backoff store the last-sampled
// load avg in an atomic.Uint64 so concurrent Current()/LastSignals()
// readers don't need a mutex.
func floatFromBits(b uint64) float64 { return math.Float64frombits(b) }
func bitsFromFloat(f float64) uint64 { return math.Float64bits(f) }
