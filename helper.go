package kmip

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func ContainsEnum(slice []Enum, item Enum) bool {
	for _, element := range slice {
		if element == item {
			return true
		}
	}
	return false
}

func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func ValidateDuration(input string) error {
	// Regex pattern for duration strings like "1y", "6M", "30d", "12h", "45m", "30s"
	durationRegex := regexp.MustCompile(`^(\d+)([yMwdhms])$`)
	matches := durationRegex.FindStringSubmatch(input)

	if len(matches) != 3 {
		return errors.New("invalid format. Expected format: 1y, 6M, 30d, etc.")
	}

	// Convert the number part
	value, err := strconv.Atoi(matches[1])
	if err != nil || value <= 0 {
		return errors.New("duration must be a positive number")
	}

	// Check the unit
	unit := matches[2]
	switch unit {
	case "y", "M", "w", "d", "h", "m", "s":
		return nil
	default:
		return errors.New("unsupported duration unit")
	}
}

func IsValidHostname(hostname string) bool {
	if hostname == "localhost" {
		return true
	}

	hostnameRegex := `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	re := regexp.MustCompile(hostnameRegex)
	return re.MatchString(hostname)
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func ValidateHostnamesOrIPs(input string) error {
	if input == "" {
		return errors.New("missing value for field")
	}

	entries := strings.Split(input, ",")
	for _, entry := range entries {
		trimmedEntry := strings.TrimSpace(entry)
		if trimmedEntry == "" {
			return errors.New("empty value found in the list")
		}
		if !IsValidHostname(trimmedEntry) && !IsValidIP(trimmedEntry) {
			return fmt.Errorf("invalid hostname or IP: %s", trimmedEntry)
		}
	}

	return nil
}

// isHexEncoded checks if the given byte slice appears to be hex-encoded
// It returns true if all characters are valid hex characters (0-9, a-f, A-F)
func isHexEncoded(data []byte) bool {
	if len(data) == 0 || len(data)%2 != 0 {
		return false
	}

	for _, b := range data {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}

	return true
}

// decodeHexIfEncoded checks if data is hex-encoded and decodes it if so
// Returns the decoded data (or original if not hex), and a boolean indicating if it was hex-encoded
func decodeHexIfEncoded(data []byte) ([]byte, bool, error) {
	if isHexEncoded(data) {
		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			// If decoding fails, treat it as not hex-encoded
			return data, false, nil
		}
		return decoded, true, nil
	}
	return data, false, nil
}

// encodeToHex converts binary data to hex-encoded string bytes
func encodeToHex(data []byte) []byte {
	return []byte(hex.EncodeToString(data))
}
