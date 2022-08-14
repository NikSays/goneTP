package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/NikSays/goneTP/utils"
)



func parseAlgorithm(value string) (algorithmTypes, error){
	switch strings.ToLower(value) {
	case "sha1":
		return SHA1, nil
	case "sha256":
		return SHA256, nil
	case "sha512":
		return SHA512, nil
	default:
		return -1, fmt.Errorf("parseAlgorithm: Unknown algorithm '%s'", value)
}
}

func ParseURI(uri string) (*OTP, error) {
	newOTP := OTP{}
	newOTP.setDefaults()

	scheme, uri := utils.SplitFirstRest(uri, "://")
	if scheme != "" && scheme != "otpauth" {
		return nil, fmt.Errorf("ParseURI: Invalid scheme '%s'", scheme)
	}

	host, uri := utils.SplitFirstRest(uri, "/")
	switch host {
	case "totp":
		newOTP.OTPtype = TOTP
	case "hotp":
		newOTP.OTPtype = HOTP
	default:
		return nil, fmt.Errorf("ParseURI: Host '%s' is neither totp nor hotp", host)
	}

	issuer, uri := utils.SplitFirstRest(uri, ":")
	newOTP.Issuer = issuer
	
	account, queries, found := strings.Cut(uri, "?")
	if account == "" {
		return nil, fmt.Errorf("ParseURI: No account name")
	}
	newOTP.Account = account
	if !found || queries == "" {
		return nil, fmt.Errorf("ParseURI: No query parameters supplied")
	}
	
	for _, query := range strings.Split(queries, "&") {
		splitQuery := strings.Split(query, "=")
		if len(splitQuery) != 2 {
			return nil, fmt.Errorf("ParseURI: Invalid query param '%s'", query)
		}
		name := strings.ToLower(splitQuery[0])
		value := splitQuery[1]
		
		switch name {
		case "secret":
			newOTP.Secret = value
		case "issuer":
			// If label contained ':' but different issuer is set in query, maybe ':' was part of account
			if newOTP.Issuer != "" && newOTP.Issuer != value {
				newOTP.Account = fmt.Sprintf("%s:%s", newOTP.Issuer, newOTP.Account)
			} 
			newOTP.Issuer = value
		case "algorithm":
				algorithm, err := parseAlgorithm(value)
				if err != nil {
					return nil, fmt.Errorf("ParseURI -> %w", err)	
				}
				newOTP.Algorithm = algorithm
		case "digits":
			digits, _ := strconv.Atoi(value)
			if digits < 6 || digits > 8 {
				return nil, fmt.Errorf("ParseURI: Digits '%d' is not a number between 6 and 8", digits)
			}
			newOTP.Digits = digits
		case "counter":
			counter, _ := strconv.Atoi(value)
			if counter <= 0 {
				return nil, fmt.Errorf("ParseURI: Counter '%s' is not a positive number", value)
			}
			newOTP.Counter = counter
		case "period":
			period, _ := strconv.Atoi(value)
			if period <= 0 {
				return nil, fmt.Errorf("ParseURI: Period %s is not a positive number", value)
			}
			newOTP.Period = period
		}
	}

	if len(newOTP.Secret) < 16 {
		return nil, fmt.Errorf("ParseURI: Secret length < 16")
	}

	return &newOTP, nil
}