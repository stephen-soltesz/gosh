package flagext

import (
	"io/ioutil"
)

// FileBytes contains the byte array read from the file.
type FileBytes []byte

func (fb FileBytes) String() string {
	return string(fb)
}

// Set reads the content of filename.
func (fb *FileBytes) Set(filename string) error {
	var err error
	*fb, err = ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return nil
}

func (fb FileBytes) Get() interface{} {
	return fb
}
