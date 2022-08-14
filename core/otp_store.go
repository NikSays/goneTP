package core

import (
	"fmt"

	"github.com/NikSays/goneTP/utils"
)
type algorithmTypes int 
const (
	SHA1 algorithmTypes = iota
	SHA256
	SHA512 
)

type otpTypes int
const (
	TOTP  otpTypes = iota
	HOTP
)

type OTP struct {
	OTPtype otpTypes
	Issuer string
	Account string
	Secret string
	Algorithm algorithmTypes
	Digits int
	Counter int
	Period int
} 
func (otp *OTP) setDefaults(){
	otp.Algorithm = SHA1
	otp.Digits = 6
	otp.Period = 30
	otp.Counter = 0
}
type OTPstore []OTP

func (store *OTPstore) Add(otp OTP) error {
	if utils.FindInSlice(store.GetNames(), otp.Account) != -1 {
		return fmt.Errorf("OTPstore.Add: Account name already exists")
	}
	*store = append(*store, otp)
	return nil
}

func (store OTPstore) GetNames() (names []string) {
	for _, otp := range store {
		names = append(names, otp.Account)
	}
	return
}

func (store *OTPstore) Delete(id int) (err error) {
	*store, err = utils.DeleteFromSlice(*store, id)
	if err != nil {
		err = fmt.Errorf("OTPstore.Delete: Can't delete element -> %w", err)
	}
	return
}
