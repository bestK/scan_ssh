package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// 获取本地IP前缀
func getLocalIPPrefixes() []string {
	var ipPrefixes []string
	var cmd *exec.Cmd

	// 根据操作系统选择合适的命令
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ipconfig")
	case "linux", "darwin":
		cmd = exec.Command("ip", "addr")
	default:
		return ipPrefixes
	}

	output, err := cmd.Output()
	if err != nil {
		return ipPrefixes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		switch runtime.GOOS {
		case "windows":
			if strings.Contains(line, "IPv4") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					ip := strings.TrimSpace(parts[1])
					ipParts := strings.Split(ip, ".")
					if len(ipParts) == 4 {
						prefix := fmt.Sprintf("%s.%s.%s", ipParts[0], ipParts[1], ipParts[2])
						if !contains(ipPrefixes, prefix) {
							ipPrefixes = append(ipPrefixes, prefix)
						}
					}
				}
			}
		case "linux", "darwin":
			if strings.Contains(line, "inet ") && !strings.Contains(line, "inet6") {
				fields := strings.Fields(line)
				for _, field := range fields {
					if strings.Contains(field, "/") {
						ip := strings.Split(field, "/")[0]
						ipParts := strings.Split(ip, ".")
						if len(ipParts) == 4 {
							prefix := fmt.Sprintf("%s.%s.%s", ipParts[0], ipParts[1], ipParts[2])
							if !contains(ipPrefixes, prefix) {
								ipPrefixes = append(ipPrefixes, prefix)
							}
						}
						break
					}
				}
			}
		}
	}
	return ipPrefixes
}

// 辅助函数：检查切片中是否包含指定值
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 测试SSH服务
func testSSH(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := string(buffer[:n])
	if strings.Contains(banner, "SSH") {
		return ip
	}
	return ""
}

// 验证IP前缀格式
func validateIPPrefix(ipPrefix string) bool {
	parts := strings.Split(ipPrefix, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		num := 0
		_, err := fmt.Sscanf(part, "%d", &num)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

func main() {
	// 打印banner
	fmt.Println("====================================")
	fmt.Println("         SSH服务扫描器 v1.0")
	fmt.Println("====================================")
	fmt.Printf(" 作者: https://github.com/bestk/scanssh\n")
	fmt.Printf(" 时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("====================================")

	// 获取本地IP前缀
	localIPPrefixes := getLocalIPPrefixes()

	var ipPrefix string
	for {
		fmt.Println("请选择扫描方式：")
		for i, prefix := range localIPPrefixes {
			fmt.Printf("%d. 扫描本地网段 (%s.0/24)\n", i+1, prefix)
		}
		fmt.Printf("%d. 自定义网段\n", len(localIPPrefixes)+1)

		var choice string
		fmt.Printf("\n请输入选项 (1-%d) 或直接输入网段: ", len(localIPPrefixes)+1)
		fmt.Scanln(&choice)

		if strings.Contains(choice, ".") {
			if validateIPPrefix(choice) {
				ipPrefix = choice
				break
			}
			fmt.Println("[错误] 请输入正确的网段格式 (例如: 192.168.1)")
			continue
		}

		var choiceNum int
		_, err := fmt.Sscanf(choice, "%d", &choiceNum)
		if err == nil {
			if choiceNum >= 1 && choiceNum <= len(localIPPrefixes) {
				ipPrefix = localIPPrefixes[choiceNum-1]
				break
			} else if choiceNum == len(localIPPrefixes)+1 {
				for {
					fmt.Print("请输入要扫描的网段前缀 (例如: 192.168.1): ")
					fmt.Scanln(&ipPrefix)
					if validateIPPrefix(ipPrefix) {
						break
					}
					fmt.Println("[错误] 请输入正确的网段格式 (例如: 192.168.1)")
				}
				break
			}
		}
		fmt.Printf("[错误] 请输入1-%d之间的数字，或直接输入要扫描的网段\n", len(localIPPrefixes)+1)
	}

	// 设置结果文件
	resultFile := fmt.Sprintf("ssh_available_%s.txt", strings.ReplaceAll(ipPrefix, ".", "_"))
	file, err := os.Create(resultFile)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	// 写入文件头
	fmt.Fprintf(file, "=================================\n")
	fmt.Fprintf(file, "        SSH可用服务器列表\n")
	fmt.Fprintf(file, "=================================\n")
	fmt.Fprintf(file, "扫描时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "扫描网段：%s.0/24\n", ipPrefix)
	fmt.Fprintf(file, "=================================\n\n")

	fmt.Printf("\n[信息] 开始扫描网段: %s.0/24\n", ipPrefix)
	fmt.Println("[信息] 正在检测SSH服务...")

	var wg sync.WaitGroup
	results := make(chan string, 255)
	semaphore := make(chan struct{}, 100) // 限制并发数

	// 开始扫描
	for i := 1; i < 255; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			ip := fmt.Sprintf("%s.%d", ipPrefix, i)
			if result := testSSH(ip); result != "" {
				results <- result
				fmt.Printf("[成功] SSH服务: %s\n", result)
				file.WriteString(result + "\n")
			}
		}(i)
	}

	// 等待所有goroutine完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	var availableIPs []string
	for ip := range results {
		availableIPs = append(availableIPs, ip)
	}

	fmt.Println("\n[完成] 扫描结束！")

	// 打印结果
	fmt.Println("\n可用的SSH服务器列表：")
	fmt.Println("=====================")
	if len(availableIPs) > 0 {
		for _, ip := range availableIPs {
			fmt.Println(ip)
		}
		fmt.Printf("结果已保存到：%s\n", resultFile)
	} else {
		fmt.Println("未发现可用的SSH服务器")
	}
	fmt.Println("=====================")

	// 写入统计信息
	fmt.Fprintf(file, "\n=================================\n")
	fmt.Fprintf(file, "扫描完成时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "发现可用服务器：%d 台\n", len(availableIPs))
	fmt.Fprintf(file, "=================================\n")

	fmt.Print("\n按回车键退出...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
