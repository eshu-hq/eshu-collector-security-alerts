package securityalert

import "fmt"

// CI-SEED round B: vet-only seed to prove the fixed aggregator fails red.
func seedVetOnly() {
	fmt.Printf("%d", "not-a-number")
}
