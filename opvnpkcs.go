package main

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"reflect"
	"regexp"
)

func main() {
	lsusb()
	openvpnshowpkcs11()

}

func lsusb() {
	cmd := exec.Command("lsusb")
	r, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return
	}
	cmd.Stderr = cmd.Stdout
	done := make(chan struct{})

	var ykregex = regexp.MustCompile(`Yubikey`)
	var match int
	scanner := bufio.NewScanner(r)

	go func() {
		for scanner.Scan() {
			if len(scanner.Text()) < 1 {
				continue
			}
			switch {
			case ykregex.MatchString(scanner.Text()):
				match++
			}
		}
		done <- struct{}{}
	}()
	if err := cmd.Start(); err != nil {
		log.Println(err)
		return
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println(err)
		return
	}

	if match == 0 {
		fmt.Println("no yubikey found")
	} else {
		fmt.Println("yubikey inserted")
	}
}
func openvpnshowpkcs11() {
	cmd := exec.Command("/usr/sbin/openvpn", "--show-pkcs11-ids", "/usr/lib64/opensc-pkcs11.so")
	r, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return
	}

	// stderr and stdout to the same stdotupipe
	cmd.Stderr = cmd.Stdout

	// all stdout/stderr got to this channel
	done := make(chan struct{})

	certnr := 0
	var certs = make(map[int]Ykcert)
	var ykcert Ykcert
	var certregex = regexp.MustCompile(`^Certificate`)
	var dnregex = regexp.MustCompile(`\s+DN:\s+`)
	var serialregex = regexp.MustCompile(`\s+Serial:`)
	var serialidregex = regexp.MustCompile(`\s+Serialized id:`)
	scanner := bufio.NewScanner(r)

	go func() {
		for scanner.Scan() {
			if len(scanner.Text()) < 1 {
				continue
			}
			switch {
			case certregex.MatchString(scanner.Text()):
				certnr++
			case dnregex.MatchString(scanner.Text()):
				ykcert.Modify(&ykcert, "DN", scanner.Text())
				certs[certnr] = ykcert
			case serialregex.MatchString(scanner.Text()):
				ykcert.Modify(&ykcert, "Serial", scanner.Text())
				certs[certnr] = ykcert
			case serialidregex.MatchString(scanner.Text()):
				ykcert.Modify(&ykcert, "Serializedid", scanner.Text())
				certs[certnr] = ykcert
			}
		}
		done <- struct{}{}
	}()

	if err := cmd.Start(); err != nil {
		log.Println(err)
		return
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println(err)
		return
	}

	for _, v := range certs {
		fmt.Println(v.DN)
		fmt.Println(v.Serializedid)
	}
}

type Ykcert struct {
	DN           string
	Serial       string
	Serializedid string
}

func (yk *Ykcert) Modify(obj any, field string, value any) {
	ref := reflect.ValueOf(obj)
	if ref.Kind() == reflect.Ptr {
		ref = reflect.Indirect(ref)
	}
	if ref.Kind() == reflect.Interface {
		ref = ref.Elem()
	}
	if ref.Kind() != reflect.Struct {
		log.Fatalln("unexpected type")
	}

	prop := ref.FieldByName(field)
	prop.Set(reflect.ValueOf(value))
}

func (yk *Ykcert) Modifyserial(serial string) {
	yk.Serial = serial

}
func (yk *Ykcert) ModifyDN(dn string) {
	yk.DN = dn

}

func (yk *Ykcert) ModifySerialized(serializedid string) {
	yk.Serializedid = serializedid

}
