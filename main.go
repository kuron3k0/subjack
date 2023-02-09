package main

import (
	"flag"
	"fmt"
	"subjack/subjack"
)

func main() {
	var domain string
	flag.StringVar(&domain, "d", "", "domain to check")
	flag.Parse()
	fmt.Println(subjack.Runner(domain))
}
