package main

import (
	"fmt"
	"subjack/subjack"
)

func main() {

	fmt.Println(subjack.HttpGet("71.222.91.65"))
	// 读取结果
	//fmt.Println(resp.StatusCode())

	//fmt.Println(subjack.Runner("landing.peopleticker.com"))

}
