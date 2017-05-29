package shadowsocks

import (
	"log"
)

var setmax = make(chan int)
var attain = make(chan bool)
var release = make(chan bool)
var getcur = make(chan int)
var cur = 0
var max = 1000

func init() {
	go monitor()
}

func monitor() {
	for {
		if cur < 0 {
			log.Panic("Negative number of opened fds")
		}
		if cur >= max {
			select {
			case max = <-setmax:
			case <-release:
				cur--
			case getcur <- cur:
			}
		} else {
			select {
			case max = <-setmax:
			case <-release:
				cur--
			case <-attain:
				cur++
			case getcur <- cur:
			}
		}
	}
}

func FDSetMax(max int) {
	setmax <- max
}

func FDGetCur() int {
	return <-getcur
}

func FDAttain() {
	attain <- true
}

func FDRelease() {
	release <- true
}
