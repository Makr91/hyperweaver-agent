//go:build !windows && !darwin && !linux

package keepawake

import "errors"

func acquire(string) (func(), error) {
	return nil, errors.New("sleep prevention is not implemented on this platform")
}
