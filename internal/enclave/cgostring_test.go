//go:build darwin

package enclave

import "testing"

func TestCGoString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "normal string",
			input: []byte{'h', 'e', 'l', 'l', 'o', 0, 0, 0},
			want:  "hello",
		},
		{
			name:  "empty string",
			input: []byte{0, 'a', 'b'},
			want:  "",
		},
		{
			name:  "no null terminator",
			input: []byte{'a', 'b', 'c'},
			want:  "abc",
		},
		{
			name:  "null in middle",
			input: []byte{'a', 'b', 0, 'c', 'd'},
			want:  "ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cGoString(tt.input)
			if got != tt.want {
				t.Errorf("cGoString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
