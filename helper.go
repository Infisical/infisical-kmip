package kmip

import (
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
