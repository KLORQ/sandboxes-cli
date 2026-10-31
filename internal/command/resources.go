package command

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	minMemoryMiB = 128
	maxMemoryMiB = 65536
	maxCPUs      = 64
)

func parseMemoryMiB(value string) (uint32, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, nil
	}
	multiplier := uint64(1)
	for _, suffix := range []struct {
		suffix     string
		multiplier uint64
	}{
		{"gib", 1024}, {"gb", 1024}, {"g", 1024},
		{"mib", 1}, {"mb", 1}, {"m", 1},
	} {
		if strings.HasSuffix(value, suffix.suffix) {
			value = strings.TrimSuffix(value, suffix.suffix)
			multiplier = suffix.multiplier
			break
		}
	}
	amount, err := strconv.ParseUint(value, 10, 64)
	if err != nil || amount == 0 {
		return 0, errors.New("memory must be an integer with an optional binary unit such as 512m or 2g")
	}
	if amount > maxMemoryMiB*multiplier {
		return 0, fmt.Errorf("memory exceeds %d MiB", maxMemoryMiB)
	}
	mib := amount * multiplier
	if mib > maxMemoryMiB {
		return 0, fmt.Errorf("memory exceeds %d MiB", maxMemoryMiB)
	}
	if mib < minMemoryMiB {
		return 0, fmt.Errorf("memory must be at least %d MiB", minMemoryMiB)
	}
	return uint32(mib), nil
}

func validateCPUs(value uint) (uint32, error) {
	if value > maxCPUs {
		return 0, fmt.Errorf("cpus must be between 1 and %d, or 0 for the default", maxCPUs)
	}
	return uint32(value), nil
}
