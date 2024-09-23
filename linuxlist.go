package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

// FileInfo represents the information collected for each file or directory
type FileInfo struct {
	Path            string    `json:"path"`
	Name            string    `json:"name"`
	Size            int64     `json:"size"`
	Mode            string    `json:"mode"`
	Permissions     string    `json:"permissions"`
	AccessTime      time.Time `json:"access_time"`
	ModTime         time.Time `json:"mod_time"`
	InodeChangeTime time.Time `json:"inode_change_time"`
	IsDir           bool      `json:"is_dir"`
	SHA256          string    `json:"sha256,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// getFileInfo collects information about a file or directory
func getFileInfo(path string, skipHashing bool) FileInfo {
	info, err := os.Lstat(path)
	if err != nil {
		return FileInfo{Path: path, Error: err.Error()}
	}

	fileInfo := FileInfo{
		Path:        path,
		Name:        info.Name(),
		Size:        info.Size(),
		Mode:        info.Mode().String(),
		Permissions: info.Mode().Perm().String(),
		ModTime:     info.ModTime().UTC(),
		IsDir:       info.IsDir(),
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		fileInfo.AccessTime = time.Unix(stat.Atim.Sec, stat.Atim.Nsec).UTC()
		fileInfo.InodeChangeTime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC()
	} else {
		fileInfo.Error = "Failed to get detailed file information"
	}

	if !info.IsDir() && info.Mode().IsRegular() && !skipHashing {
		hash, err := calculateSHA256(path)
		if err != nil {
			fileInfo.Error = fmt.Sprintf("Error calculating SHA256: %v", err)
		} else {
			fileInfo.SHA256 = hash
		}
	}

	return fileInfo
}

// calculateSHA256 computes the SHA256 hash of a file
func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// listDirectory recursively lists all files and directories
func listDirectory(dir string, jsonlFile *os.File, logFile *os.File) error {
	var count int64
	var errorCount int64
	var lastLog time.Time
	startTime := time.Now().UTC()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
			return nil // Continue to next file/directory
		}

		skipHashing := isSpecialDir(path)

		atomic.AddInt64(&count, 1)
		if time.Since(lastLog) > 30*time.Second {
			log.Printf("Processed %d files/directories in %v (Errors: %d)\n",
				atomic.LoadInt64(&count),
				time.Since(startTime),
				atomic.LoadInt64(&errorCount))
			lastLog = time.Now().UTC()
		}

		fileInfo := getFileInfo(path, skipHashing)
		if err != nil {
			fileInfo.Error = err.Error()
		}

		jsonData, err := json.Marshal(fileInfo)
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
			return nil
		}

		_, err = jsonlFile.Write(append(jsonData, '\n'))
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
		}

		return nil
	})

	log.Printf("Total files/directories processed: %d\n", atomic.LoadInt64(&count))
	log.Printf("Total errors encountered: %d\n", atomic.LoadInt64(&errorCount))
	return err
}

// isSpecialDir checks if a path is within a special directory that should be handled differently
func isSpecialDir(path string) bool {
	specialDirs := []string{"/dev", "/proc", "/sys"}
	for _, dir := range specialDirs {
		if path == dir || filepath.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// printUsage displays the help message
func printUsage() {
	fmt.Println("LinuxList - A tool for listing and hashing files on Linux systems")
	fmt.Println("\nUsage:")
	fmt.Println("  linuxlist [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -h, --help             Show this help message")
	fmt.Println("  -m, --mount <path>     Specify a mount point for a forensic image")
	fmt.Println("\nExamples:")
	fmt.Println("  Run on live system:")
	fmt.Println("    sudo ./linuxlist")
	fmt.Println("  Run on mounted forensic image:")
	fmt.Println("    sudo ./linuxlist -m /mnt/evidence")
	fmt.Println("\nNote: This tool requires root privileges to access all files.")
	fmt.Println("\nCollected JSON Fields:")
	fmt.Println("  path: Full path of the file or directory")
	fmt.Println("  name: Name of the file or directory")
	fmt.Println("  size: Size of the file in bytes")
	fmt.Println("  mode: File mode and permissions")
	fmt.Println("  permissions: Unix permission string")
	fmt.Println("  access_time: Last access time (UTC)")
	fmt.Println("  mod_time: Last modification time (UTC)")
	fmt.Println("  inode_change_time: Last inode change time (UTC)")
	fmt.Println("  is_dir: Boolean indicating if it's a directory")
	fmt.Println("  sha256: SHA256 hash of file contents (for regular files only)")
	fmt.Println("  error: Any error encountered while processing the file")
	fmt.Println("\nPurpose of collected fields:")
	fmt.Println("  - Provide a comprehensive inventory of the file system")
	fmt.Println("  - Capture file metadata for forensic analysis")
	fmt.Println("  - Allow for file integrity verification using SHA256 hashes")
	fmt.Println("  - Identify potential issues or access problems with specific files")
}

func main() {
	var mountPoint string
	var showHelp bool

	flag.StringVar(&mountPoint, "mount", "", "Specify a mount point for a forensic image")
	flag.StringVar(&mountPoint, "m", "", "Specify a mount point for a forensic image (shorthand)")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message (shorthand)")
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	startTime := time.Now().UTC()

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("Error getting hostname: %v\n", err)
		hostname = "unknown"
	}

	timeStamp := startTime.Format("20060102_150405Z")
	logFileName := fmt.Sprintf("%s_%s_linuxlist.log", hostname, timeStamp)
	jsonlFileName := fmt.Sprintf("%s_%s_linuxlist.jsonl", hostname, timeStamp)

	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		return
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	log.Printf("LinuxList started at: %s\n", startTime.Format(time.RFC3339))
	log.Printf("Go version: %s\n", runtime.Version())
	log.Printf("GOOS: %s, GOARCH: %s\n", runtime.GOOS, runtime.GOARCH)

	if mountPoint != "" {
		log.Printf("Mount point: %s\n", mountPoint)
	} else {
		log.Println("Running on live system")
		mountPoint = "/"
	}

	jsonlFile, err := os.Create(jsonlFileName)
	if err != nil {
		log.Printf("Error creating JSONL file: %v\n", err)
		return
	}
	defer jsonlFile.Close()

	log.Printf("Starting directory listing and file hashing...")
	err = listDirectory(mountPoint, jsonlFile, logFile)
	if err != nil {
		log.Printf("Error listing directory: %v\n", err)
	}

	endTime := time.Now().UTC()
	duration := endTime.Sub(startTime)
	log.Printf("LinuxList completed at: %s\n", endTime.Format(time.RFC3339))
	log.Printf("Total run time: %s\n", duration)
	log.Printf("Output files: %s, %s\n", logFileName, jsonlFileName)
}
