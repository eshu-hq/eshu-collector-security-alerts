package securityalert

import (
	"sync"
	"testing"
)

// CI-SEED round D: genuine data race (unsynchronized shared counter).
// Must fail under -race while the plain suite stays green.
func TestSeedDataRace(t *testing.T) {
	counter := 0
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				counter++
			}
		}()
	}
	wg.Wait()
	if counter == 0 {
		t.Fatal("impossible")
	}
}
