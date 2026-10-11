package pgtrace

import "testing"

func TestKindsDistinct(t *testing.T) {
	if KindClient == KindParallel || KindParallel == KindFastpath || KindClient == 0 {
		t.Fatal("kinds must be distinct and non-zero (0 is an unused map slot)")
	}
}
