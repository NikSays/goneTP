package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/NikSays/goneTP/core"
)

func main() {
	args := os.Args[1:]
	if len(args) == 2  && args[0] == "load"{
		store, err := core.LoadStore("", []byte(args[1]))
		if err != nil {
			if errors.Is(err, core.ErrWrongPassword) {
				fmt.Println("Wrong passord")
			} else {
				fmt.Println(err)
			}
		}
		fmt.Println(store)
	} else if len(args) == 3 && args[0] == "save" {
		store := core.OTPstore{}
		otp, err := core.ParseURI(args[2])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(store)
		err = store.Add(*otp)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = core.SaveStore("", store, []byte(args[1]))
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		fmt.Println("TEST SCRIPT: Either `gonetp save <password> <URL>` or `gonetp load <password>`")
	}
}