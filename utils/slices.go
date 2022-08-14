package utils

import (
	"fmt"
)

// Waiting for slices lib to land

func DeleteFromSlice[T any](slice []T, i int) ([]T, error) {
	if i >= len(slice) || i < 0 {
		return slice, fmt.Errorf("deleteFromSlice: Index %d out of range", i)
	}
	return append(slice[:i], slice[i+1:]...), nil
}

// Returns index of item, -1 if not found
func FindInSlice[T comparable](slice []T,item T) int{
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return -1
}