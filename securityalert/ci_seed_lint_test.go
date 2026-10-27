package securityalert

import "fmt"

// CI-SEED: mismatched verb must fail the vet step.
func seedVet() {
	fmt.Printf("%d", "not-a-number")
}

// CI-SEED: unused symbol must fail the lint step.
const seedUnusedConst = 1
