package kmip

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
