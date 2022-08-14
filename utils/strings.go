package utils

import "strings"

// Splits around first instance of separator. If separator wasn't found
// everything is put into rest, to make anything before separator optional
func SplitFirstRest(s string, separator string) (first string, rest string){
	before, after, found := strings.Cut(s, separator)
	if !found {
		return "", before
	}
	return before, after
}