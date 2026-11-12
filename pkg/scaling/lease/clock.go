/*
Copyright 2026 The KEDA Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lease

import "time"

// Clock is the time source used by the lease Manager. It is an interface so
// tests can drive time deterministically, including wall-clock rollbacks.
// Implementations must be safe for concurrent use.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// SystemClock reads time from the local process clock. time.Time values
// returned by time.Now carry a monotonic reading, so differences computed
// between two of them are unaffected by wall-clock adjustments (including
// backwards jumps).
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time {
	return time.Now()
}
