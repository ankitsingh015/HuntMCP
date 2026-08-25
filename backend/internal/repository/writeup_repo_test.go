package repository

import "testing"

// pgvector's `vector` type only accepts "[v1,v2,...]" syntax, not
// Postgres's native "{v1,v2,...}" array syntax that pq.Array produces.
func TestVectorLiteral(t *testing.T) {
	cases := []struct {
		name string
		in   []float32
		want string
	}{
		{"empty", []float32{}, "[]"},
		{"single", []float32{0.5}, "[0.5]"},
		{"multiple", []float32{0.1, -0.2, 3}, "[0.1,-0.2,3]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vectorLiteral(tc.in)
			if got != tc.want {
				t.Errorf("vectorLiteral(%v) = %q, want %q", tc.in, got, tc.want)
			}
			if got[0] != '[' || got[len(got)-1] != ']' {
				t.Errorf("vectorLiteral(%v) = %q, want pgvector bracket syntax", tc.in, got)
			}
		})
	}
}
