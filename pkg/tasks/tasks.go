package exampletasks

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/RichardKnop/machinery/v1/log"
	//"github.com/cslqm/gin-machinery-task/pkg/util"
)

func CreateFile(args ...string) error {
	filePath := args[0]
	context := args[1]

	f, err := os.Create(filePath)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("create file %s failed, stderr: %s.", filePath, err.Error())
	} else {
		var errWrite error
		_, errWrite = f.Write([]byte(context))
		if errWrite != nil {
			return fmt.Errorf("writer %s to file %s failed, stderr: %s.", context, filePath, errWrite.Error())
		}
	}
	return nil
}


func CreateImage(args ...string) (log string, path string, err error) {
	context := args[0]
	pathUUID := args[1]

	// create workdir
	var strBuffer string

	if pathUUID == "" {
		return "", "", fmt.Errorf("Fail: arg 2 string is empty.")
	}

	strBuffer = fmt.Sprintf("/my_data/task/task_agent/%s", pathUUID)
	if _, errPathExist := os.Stat(strBuffer); os.IsNotExist(errPathExist) == true {
		// for i := 0; i < 100; i++ {
		// 	randomString := util.GetRandomString(16)
		// 	strBuffer = fmt.Sprintf("/my_data/task/task_agent/task_agent-%s", randomString)
		// 	if _, errExist := os.Stat(strBuffer); os.IsNotExist(errExist) {
		// 		break
		// 	}
		// 	if i == 99 {
		// 		return "", "", fmt.Errorf("Fail: genrate random string to create file.")
		// 	}
		// }
		;
	} else {
		return "", "", fmt.Errorf("Fail: %s path is exist.", strBuffer)
	}

	if mkdirErr := os.MkdirAll(strBuffer, 0755); mkdirErr != nil {
		return "", "", mkdirErr
	}

	workdir := strBuffer
	if errChdir := os.Chdir(workdir); errChdir != nil {
		return "", "", errChdir
	}

	// write json file
	jsonFile := fmt.Sprintf("%s/packer.json", workdir)
	f, errOpenFile := os.OpenFile(jsonFile, os.O_RDWR|os.O_CREATE, 0644)
	if errOpenFile != nil {
		return "", "", errOpenFile
	}

	if _, errWriter := f.WriteString(context); errWriter != nil {
		return "", "", errWriter
	}

	if errClose := f.Close(); errClose != nil {
		return "", "", errClose
	}

	// run packer to create, output log to logfile.
	logFile := fmt.Sprintf("%s/packer.log", workdir)
	cmdCommand := exec.Command("/sbin/packer", "build", jsonFile)
	saveLogEnv := fmt.Sprintf("PACKER_LOG=1")
	newEnv := append(os.Environ(), saveLogEnv)
	logPathEnv := fmt.Sprintf("PACKER_LOG_PATH=%s", logFile)
	newEnv = append(newEnv, logPathEnv)
	cmdCommand.Env = newEnv
	stdoutStderr, errCmd := cmdCommand.CombinedOutput()
	if errCmd != nil {
		errString := fmt.Errorf("exec '/sbin/packer build %s' fail, stderr : %s", jsonFile, string(stdoutStderr))
		return "", "", errString
	}

	// read log from logfile, return.
	buffer, errRead := ioutil.ReadFile(logFile)
	if errRead != nil {
		return "", "", errRead
	}

	bufferString := string(buffer)
	if bufferString != "" {
		return bufferString, workdir, nil
	} else {
		return "", "", fmt.Errorf("Nothing read from %s.", logFile)
	}

	return "", workdir, nil
}

// Add ...
func Add(args ...int64) (int64, error) {
	sum := int64(0)
	for _, arg := range args {
		sum += arg
	}
	return sum, nil
}

// Multiply ...
func Multiply(args ...int64) (int64, error) {
	sum := int64(1)
	for _, arg := range args {
		sum *= arg
	}
	return sum, nil
}

// SumInts ...
func SumInts(numbers []int64) (int64, error) {
	var sum int64
	for _, num := range numbers {
		sum += num
	}
	return sum, nil
}

// SumFloats ...
func SumFloats(numbers []float64) (float64, error) {
	var sum float64
	for _, num := range numbers {
		sum += num
	}
	return sum, nil
}

// Concat ...
func Concat(strs []string) (string, error) {
	var res string
	for _, s := range strs {
		res += s
	}
	return res, nil
}

// Split ...
func Split(str string) ([]string, error) {
	return strings.Split(str, ""), nil
}

// PanicTask ...
func PanicTask() (string, error) {
	panic(errors.New("oops"))
}

// LongRunningTask ...
func LongRunningTask() error {
	log.INFO.Print("Long running task started")
	for i := 0; i < 10; i++ {
		log.INFO.Print(10 - i)
		time.Sleep(1 * time.Second)
	}
	log.INFO.Print("Long running task finished")
	return nil
}
