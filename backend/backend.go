package backend

import (
	//"encoding/base64"
	"fmt"
	"log"
	//"strconv"
	"time"

	"github.com/RichardKnop/machinery/v1"
	"github.com/RichardKnop/machinery/v1/config"
	//"github.com/RichardKnop/machinery/v1/tasks"
	"github.com/RichardKnop/machinery/v1/backends/iface"
	"github.com/astaxie/beego/validation"

	"github.com/cslqm/gin-machinery-task/models"
	"github.com/cslqm/gin-machinery-task/pkg/setting"
	exampletasks "github.com/cslqm/gin-machinery-task/pkg/tasks"
)

var (
	SUCCESS  = 0
	PENDING  = 1
	RECEIVED = 2
	STARTED  = 3
	RETRY    = 4
	FAILURE  = 5
)

var SenderServer *machinery.Server
var BackendServer iface.Backend

func init() {
	var cnf = &config.Config{
		Broker:          setting.Broker,
		DefaultQueue:    setting.DefaultQueue,
		ResultBackend:   setting.ResultBackend,
		ResultsExpireIn: setting.ResultsExpireIn,
		AMQP: &config.AMQPConfig{
			Exchange:      setting.Exchange,
			ExchangeType:  setting.ExchangeType,
			BindingKey:    setting.BindingKey,
			PrefetchCount: setting.PrefetchCount,
		},
	}

	//init server
	var errServer error
	SenderServer, errServer = machinery.NewServer(cnf)
	if errServer != nil {
		log.Fatal(errServer)
	}

	// Register tasks
	tasksList := map[string]interface{}{
		"add":                   exampletasks.Add,
		"multiply":              exampletasks.Multiply,
		"sum_ints":              exampletasks.SumInts,
		"sum_floats":            exampletasks.SumFloats,
		"concat":                exampletasks.Concat,
		"split":                 exampletasks.Split,
		"panic_task":            exampletasks.PanicTask,
		"long_running_task":     exampletasks.LongRunningTask,
		"create_file":           exampletasks.CreateFile,
		"create_image":          exampletasks.CreateImage,
	}
	SenderServer.RegisterTasks(tasksList)
	BackendServer = SenderServer.GetBackend()
}

// UpdateState update state of task
func UpdateState() {
	var dataTasks []models.Task
	// read dataTasks from db
	dataTasks = GetTaskInfos()
	for _, dataTask := range dataTasks {
		log.Printf("find ID:%d, State:%d, TaskUUID:%s, Time:%d.", dataTask.ID, dataTask.State, dataTask.TaskUUID, dataTask.CreatedOn)
		switch dataTask.State {
		case SUCCESS, FAILURE:
			continue
		case PENDING, RECEIVED, STARTED, RETRY:
			errUpdate := UpdateStateToDB(dataTask)
			if errUpdate != nil {
				log.Printf("Fail: update task: %s dataTask to DB. stderr: %s.", dataTask.TaskUUID, errUpdate.Error())
				continue
			}
		default:
			continue
		}
	}
}

// GetTaskInfos get statks from DB
func GetTaskInfos() (infos []models.Task) {
	var data []models.Task
	valid := validation.Validation{}

	if !valid.HasErrors() {
		data = models.GetTasksInfo()
	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}
	return data
}

// GetStateFromBackend get state of task from backend
func GetStateFromBackend(taskUUID string) (state int, err error) {
	taskState, errGetState := BackendServer.GetState(taskUUID)
	if errGetState != nil {
		return 1, fmt.Errorf("this create image task fial, stderr: %s.", errGetState.Error())
	}

	switch taskState.State {
	case "SUCCESS":
		return SUCCESS, nil
	case "PENDING":
		return PENDING, nil
	case "RECEIVED":
		return RECEIVED, nil
	case "STARTED":
		return STARTED, nil
	case "RETRY":
		return RETRY, nil
	case "FAILURE":
		return FAILURE, nil
	default:
		return 1, fmt.Errorf("unkown state")
	}
}

// GetErrorFromBackend when task is FAILURE, get state of task from backend
func GetErrorFromBackend(taskUUID string) (taskError string, err error) {
	taskState, errGetState := BackendServer.GetState(taskUUID)
	if errGetState != nil {
		return "", fmt.Errorf("this create image task fial, stderr: %s.", errGetState.Error())
	}

	return taskState.Error, nil
}

// GetResultsFromBackend when task is SUCCESS, get results of task from backend
func GetResultsFromBackend(taskUUID string) (taskResults string, err error) {
	taskState, errGetState := BackendServer.GetState(taskUUID)
	if errGetState != nil {
		return "", fmt.Errorf("this create image task fial, stderr: %s.", errGetState.Error())
	}

	var bufStr string
	for _, result := range taskState.Results {
		bufStr = bufStr + "/n" + result.Value.(string)
	}

	return bufStr, nil
}

// TaskRunTimeout if task is send success, duration TASK_TIMEOUT, task is not FAILURE or SUCCESS.
func TaskRunTimeout(taskUUID string, taskCreateOn int) bool {
	nowTime := time.Now().Unix()
	taskTimeout := taskCreateOn + setting.TaskTimeout

	if nowTime > int64(taskTimeout) {
		return true
	} else {
		return false
	}
}

// UpdateStateToDB update info of task in DB
func UpdateStateToDB(dataTask models.Task) error {
	var errorTaskStr string
	var resultsTaskStr string

	taskID := dataTask.ID
	taskUUID := dataTask.TaskUUID
	taskCreateOn := dataTask.CreatedOn

	// get state from backend
	state, errState := GetStateFromBackend(taskUUID)
	if errState != nil {
		return fmt.Errorf("fail GetStateFromBackend, stderr: %s.", errState.Error())
	}
	log.Printf("task state: %d, uuid: %s.", state, taskUUID)

	var errGet error
	if state == FAILURE {
		errorTaskStr, errGet = GetErrorFromBackend(taskUUID)
		if errGet != nil {
			return fmt.Errorf("fail GetErrorFromBackend, stderr: %s.", errGet.Error())
		}
		log.Printf("The task is run fail, error massage: %s.", errorTaskStr)
	} else if state == SUCCESS {
		resultsTaskStr, errGet = GetResultsFromBackend(taskUUID)
		if errGet != nil {
			return fmt.Errorf("fail GetResultsFromBackend, stderr: %s.", errGet.Error())
		}

		// resultsTaskStr as task_log of DB
		errorTaskStr = resultsTaskStr
	} else {
		isTimeout := TaskRunTimeout(taskUUID, taskCreateOn)
		if isTimeout == true {
			state = FAILURE
			errorTaskStr = fmt.Sprintf("The task status does not change to failure or success for a long time(%d s) after the task is published.", setting.TaskTimeout)
			log.Printf(errorTaskStr)
			for i := 1; i < 4; i++ {
				errDeleteTask := BackendServer.PurgeState(taskUUID)
				if errDeleteTask == nil {
					break
				} else {
					log.Printf("Fail: delete task %s for redis.", taskUUID)
				}
			}
		}
	}

	data := make(map[string]interface{})
	data["state"] = state
	data["task_log"] = errorTaskStr

	models.UpdateTask(taskID, data)
	return nil
}
