package validate

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateEmail(t *testing.T) {

	baseLocal := "han"
	baseDomain := "falcon"
	baseTld := "io"
	exactMinEmail := fmt.Sprintf("%s@%s.%s", baseLocal, baseDomain, baseTld)

	maxLocal := strings.Repeat("x", 64)
	maxDomain := strings.Repeat("y", 185)
	exactMaxEmail := fmt.Sprintf("%s@%s.%s", maxLocal, maxDomain, "com")

	tests := []struct {
		name      string
		email     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_jedi_address",
			email:   "luke.skywalker@rebellion.org",
			wantErr: false,
		},
		{
			name:    "valid_sith_address",
			email:   "darth.vader@empire.com",
			wantErr: false,
		},
		{
			name:    "valid_with_plus_alias",
			email:   "leia+alderaan@resistance.net",
			wantErr: false,
		},
		{
			name:    "valid_exact_min_length",
			email:   exactMinEmail,
			wantErr: false,
		},
		{
			name:    "valid_exact_max_length",
			email:   exactMaxEmail,
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			email:     "y@z.i",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_missing_at",
			email:     "obi.wan.jeditemple.org",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_missing_domain",
			email:     "mando@",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_missing_tld",
			email:     "ahsoka@fulcrum",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_comma_character",
			email:     "darth,vader@empire.com",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_space_character",
			email:     "rey skywalker@jedi.com",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_tld_too_long",
			email:     "bo.katan@mandalore.abcdefgh",
			wantErr:   true,
			errSubstr: "valid format",
		},
		{
			name:      "invalid_too_long",
			email:     exactMaxEmail + "z",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			email:     "",
			wantErr:   true,
			errSubstr: "between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for email %q", tt.email)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for email %q: %v", tt.email, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid_randomized_rebellion",
			password: "L3ia!WinsAgainst3mpire",
			wantErr:  false,
		},
		{
			name:     "valid_trims_outer_spaces",
			password: "   Gr0gu!FindsTh3F0rceNow   ",
			wantErr:  false,
		},
		{
			name:     "valid_exact_min_length",
			password: "Y0da!Teach3sJedi!",
			wantErr:  false,
		},
		{
			name:     "valid_exact_max_length",
			password: strings.Repeat("Aa1!", 16),
			wantErr:  false,
		},
		{
			name:      "invalid_too_short",
			password:  "Vader!1short",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			password:  strings.Repeat("J", 61) + "k8!X",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_no_uppercase",
			password:  "rebellion!alwayswins7",
			wantErr:   true,
			errSubstr: "uppercase",
		},
		{
			name:      "invalid_no_lowercase",
			password:  "EMPIRE!FALLSAGAIN9",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_no_number",
			password:  "GeneralKenobi!NoDigitsHere",
			wantErr:   true,
			errSubstr: "number",
		},
		{
			name:      "invalid_no_special_char",
			password:  "MandaloreR1sesAgainSoon",
			wantErr:   true,
			errSubstr: "special character",
		},
		{
			name:      "invalid_keyboard_sequence_forward",
			password:  "Ahsoka!Qwerty7BeatsSith",
			wantErr:   true,
			errSubstr: "keyboard sequences",
		},
		{
			name:      "invalid_keyboard_sequence_reverse",
			password:  "BoKatan!Poiuy9Returns",
			wantErr:   true,
			errSubstr: "keyboard sequences",
		},
		{
			name:      "invalid_alphabet_forward_sequence",
			password:  "Thrawn!Abcde7Strategy",
			wantErr:   true,
			errSubstr: "keyboard sequences",
		},
		{
			name:      "invalid_alphabet_reverse_sequence",
			password:  "Rex!Zyxwv9CloneLegend",
			wantErr:   true,
			errSubstr: "keyboard sequences",
		},
		{
			name:      "invalid_repeated_chars_case_insensitive",
			password:  "Mace!Wiiiii9WillFall",
			wantErr:   true,
			errSubstr: "repeated characters",
		},
		{
			name:      "invalid_empty",
			password:  "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:     "valid_exactly_four_repeat_chars",
			password: "Leia!WiiiiAgainst3mpire",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for password %q", tt.password)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for password %q: %v", tt.password, err)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "Leia",
			wantErr: false,
		},
		{
			name:    "valid_unicode",
			input:   "Muñoz",
			wantErr: false,
		},
		{
			name:    "valid_apostrophe",
			input:   "O'Bri-Wan",
			wantErr: false,
		},
		{
			name:    "valid_hyphen",
			input:   "Jean-Luc",
			wantErr: false,
		},
		{
			name:    "valid_space",
			input:   "Din Djarin",
			wantErr: false,
		},
		{
			name:    "valid_exact_max_length",
			input:   strings.Repeat("A", NameMax),
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("B", NameMax+1),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_number",
			input:     "Clone99",
			wantErr:   true,
			errSubstr: "illegal",
		},
		{
			name:      "invalid_symbol",
			input:     "Darth+Vader",
			wantErr:   true,
			errSubstr: "illegal",
		},
		{
			name:      "invalid_emoji",
			input:     "Grogu💚",
			wantErr:   true,
			errSubstr: "illegal",
		},
		{
			name:      "invalid_at_sign",
			input:     "holo@net",
			wantErr:   true,
			errSubstr: "illegal",
		},
		{
			name:      "invalid_slash",
			input:     "Rey/Skywalker",
			wantErr:   true,
			errSubstr: "illegal",
		},
		{
			name:    "valid_single_char",
			input:   "A",
			wantErr: false,
		},
		{
			name:      "invalid_whitespace_only",
			input:     "   ",
			wantErr:   true,
			errSubstr: "between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for name %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for name %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateBirthday(t *testing.T) {
	now := time.Now()
	validEdgeBirthday := now.AddDate(-120, 0, 0).Format("2006-01-02")
	tooOldBirthday := now.AddDate(-121, 0, 0).Format("2006-01-02")
	futureBirthday := now.AddDate(0, 0, 1).Format("2006-01-02")

	tests := []struct {
		name      string
		dob       string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_empty_optional",
			dob:     "",
			wantErr: false,
		},
		{
			name:    "valid_typical_republic_era",
			dob:     "1977-05-25",
			wantErr: false,
		},
		{
			name:    "valid_near_max_age_boundary",
			dob:     validEdgeBirthday,
			wantErr: false,
		},
		{
			name:      "invalid_bad_format",
			dob:       "19-BB-Y",
			wantErr:   true,
			errSubstr: "not properly formatted",
		},
		{
			name:      "invalid_future_date",
			dob:       futureBirthday,
			wantErr:   true,
			errSubstr: "future",
		},
		{
			name:      "invalid_120_years_old",
			dob:       tooOldBirthday,
			wantErr:   true,
			errSubstr: "greater than 120 years ago",
		},
		{
			name:    "valid_today",
			dob:     now.Format("2006-01-02"),
			wantErr: false,
		},
		{
			name:      "invalid_wrong_format",
			dob:       "04/14/2026",
			wantErr:   true,
			errSubstr: "not properly formatted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBirthday(tt.dob)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for dob %q", tt.dob)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for dob %q: %v", tt.dob, err)
			}
		})
	}
}

func TestValidateUuid(t *testing.T) {
	tests := []struct {
		name      string
		uuid      string
		expectErr bool
	}{
		{
			name:      "valid_lowercase",
			uuid:      "93c10464-0a09-435c-a8fc-3b8a38525b8d",
			expectErr: false,
		},
		{
			name:      "valid_uppercase",
			uuid:      "93C10464-0A09-435C-A8FC-3B8A38525B8D",
			expectErr: false,
		},
		{
			name:      "invalid_not_uuid",
			uuid:      "not-a-uuid",
			expectErr: true,
		},
		{
			name:      "invalid_missing_hyphens",
			uuid:      "93c104640a09435ca8fc3b8a38525b8d",
			expectErr: true,
		},
		{
			name:      "invalid_wrong_length_short",
			uuid:      "93c10464-0a09-435c-a8fc-3b8a38525b8",
			expectErr: true,
		},
		{
			name:      "invalid_wrong_length_long",
			uuid:      "93c10464-0a09-435c-a8fc-3b8a38525b8dd",
			expectErr: true,
		},
		{
			name:      "invalid_illegal_hex_char",
			uuid:      "93c10464-0a09-435c-a8fc-3b8a38525b8g",
			expectErr: true,
		},
		{
			name:      "invalid_empty",
			uuid:      "",
			expectErr: true,
		},
		{
			name:      "valid_all_zeros",
			uuid:      "00000000-0000-0000-0000-000000000000",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUuid(tt.uuid)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ValidateUuid(%q) error = %v, expectErr = %v", tt.uuid, err, tt.expectErr)
			}
		})
	}
}

func TestRepeatChar(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "valid_four_consecutive", password: "aaaa", wantErr: false},
		{name: "invalid_five_consecutive", password: "aaaaa", wantErr: true},
		{name: "valid_four_case_insensitive", password: "aAaA", wantErr: false},
		{name: "invalid_five_case_insensitive", password: "AaAaA", wantErr: true},
		{name: "valid_no_repeats", password: "abcde", wantErr: false},
		{name: "valid_empty", password: "", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RepeatChar(tt.password)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.password)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.password, err)
			}
		})
	}
}

func TestTooShort(t *testing.T) {
	tests := []struct {
		name  string
		field string
		min   int
		want  bool
	}{
		{name: "below_min", field: "ab", min: 3, want: true},
		{name: "at_min", field: "abc", min: 3, want: false},
		{name: "whitespace_trimmed", field: "  a  ", min: 2, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TooShort(tt.field, tt.min)
			if got != tt.want {
				t.Fatalf("TooShort(%q, %d) = %v, want %v", tt.field, tt.min, got, tt.want)
			}
		})
	}
}

func TestTooLong(t *testing.T) {
	tests := []struct {
		name  string
		field string
		max   int
		want  bool
	}{
		{name: "above_max", field: "abcd", max: 3, want: true},
		{name: "at_max", field: "abc", max: 3, want: false},
		{name: "whitespace_trimmed", field: "  abcd  ", max: 3, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TooLong(tt.field, tt.max)
			if got != tt.want {
				t.Fatalf("TooLong(%q, %d) = %v, want %v", tt.field, tt.max, got, tt.want)
			}
		})
	}
}
