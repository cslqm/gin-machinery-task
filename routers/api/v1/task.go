package v1

import (
	"encoding/base64"
	"log"
	"net/http"
	//"strconv"

	"github.com/RichardKnop/machinery/v1"
	"github.com/RichardKnop/machinery/v1/backends/iface"
	"github.com/RichardKnop/machinery/v1/config"
	"github.com/RichardKnop/machinery/v1/tasks"
	"github.com/Unknwon/com"
	"github.com/astaxie/beego/validation"
	"github.com/gin-gonic/gin"

	"github.com/cslqm/gin-machinery-task/models"
	"github.com/cslqm/gin-machinery-task/pkg/e"
	"github.com/cslqm/gin-machinery-task/pkg/setting"
	exampletasks "github.com/cslqm/gin-machinery-task/pkg/tasks"
	"github.com/cslqm/gin-machinery-task/pkg/util"
)

var SenderServer *machinery.Server
var BackendServer iface.Backend

type AddTaskJson struct {
	TaskName string `json:"task_name"`
	Content  string `json:"content"`
}

type UpdateTaskJson struct {
	State   string `json:"state"`
	TaskLog string `json:"task_log"`
}

type UpdateTaskUUID struct {
	TaskUUID string `json:"task_uuid"`
}

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

//获取单个task
func GetTask(c *gin.Context) {
	id := com.StrTo(c.Param("id")).MustInt()

	valid := validation.Validation{}
	valid.Min(id, 1, "id").Message("ID必须大于0")

	code := e.INVALID_PARAMS
	var data interface{}
	if !valid.HasErrors() {
		if models.ExistTaskByID(id) {
			data = models.GetTask(id)
			code = e.SUCCESS
		} else {
			code = e.ERROR_NOT_EXIST_TASK
		}
	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  e.GetMsg(code),
		"data": data,
	})
}

//获取多个task
func GetTasks(c *gin.Context) {
	data := make(map[string]interface{})
	maps := make(map[string]interface{})
	valid := validation.Validation{}

	var state int = -1
	if arg := c.Query("state"); arg != "" {
		state = com.StrTo(arg).MustInt()
		maps["state"] = state

		valid.Range(state, 0, 1, "state").Message("状态只允许0或1")
	}

	code := e.INVALID_PARAMS
	if !valid.HasErrors() {
		code = e.SUCCESS

		data["lists"] = models.GetTasks(util.GetPage(c), setting.PageSize, maps)
		data["total"] = models.GetTaskTotal(maps)

	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  e.GetMsg(code),
		"data": data,
	})
}

func AddTask(c *gin.Context) {
	var taskID int

	// new json body
	var taskName string
	var contentEncode string
	var contentDecode string
	var state int
	token := c.Request.Header.Get("token")

	var dataJson AddTaskJson
	if c.BindJSON(&dataJson) == nil {
		taskName = dataJson.TaskName
		contentEncode = dataJson.Content
	}

	valid := validation.Validation{}
	valid.Required(taskName, "task_name").Message("任务名不能为空")
	valid.Required(token, "token").Message("内容不能为空")

	// state == 1 task is create and send
	state = 1

	code := e.INVALID_PARAMS
	if contentEncode != "" {
		//decode base64
		decodeBytes, err := base64.StdEncoding.DecodeString(contentEncode)
		if err != nil {
			code = e.ERROR
		}
		contentDecode = string(decodeBytes)
	}
	valid.Required(contentDecode, "content").Message("内容不能为空")
	if !valid.HasErrors() {
		username, errGetUsername := util.GetUsername(token)
		if errGetUsername != nil {
			code = e.ERROR
		}
		if username == "" {
			code = e.ERROR
		}

		data := make(map[string]interface{})
		data["task_name"] = taskName
		data["content"] = contentDecode
		data["created_by"] = username
		data["state"] = state
		data["task_uuid"] = ""

		var ok bool
		if taskID, ok = models.AddTask(data); ok == false {
			code = e.ERROR
		} else {
			code = e.SUCCESS
		}
		args := make([]tasks.Arg, 2)
		signCreateImage, errNewSign := tasks.NewSignature("create_image", args)
		if errNewSign != nil {
			code = e.ERROR
		}

		if ok := SenderServer.IsTaskRegistered(signCreateImage.Name); ok == true {
			log.Printf("this is task is exist: %s.", signCreateImage.Name)
		}
		signCreateImage.Args[0] = tasks.Arg{
			Type:  "string",
			Value: data["content"],
		}
		signCreateImage.Args[1] = tasks.Arg{
			Type:  "string",
			Value: signCreateImage.UUID,
		}
		//eta := time.Now().UTC().Add(time.Second * 100)
		//signCreateImage.ETA = &eta
		/*
			group, errNewGroup := tasks.NewGroup(signCreateImage)
			if errNewGroup != nil {
				log.Fatal(errNewGroup)
			}
			chord, errNewChord := tasks.NewChord(group, signCallback)
			if errNewChord != nil {
				log.Fatal(errNewChord)
			}

			//chordAsyncResult, errSend := SenderServer.SendChord(chord, 5)
			_, errSend := SenderServer.SendChord(chord, 5)
			if errSend != nil {
				log.Fatal(errSend)
			}
		*/
		//asyncResult, errSend := SenderServer.SendTask(signCallback)
		_, errSend := SenderServer.SendTask(signCreateImage)
		if errSend != nil {
			log.Fatal(errSend)
		}

		taskState, errGetState := BackendServer.GetState(signCreateImage.UUID)
		if errGetState != nil {
			log.Fatal(errGetState)
		}

		if taskState.IsFailure() == true {
			log.Printf("this %s task is failure.", signCreateImage.UUID)
		} else {
			log.Printf("this %s task is no failure.", signCreateImage.UUID)
		}

		log.Printf("one get this task state is %s.", taskState.State)

		// update task_uuid
		dataUUID := make(map[string]interface{})

		dataUUID["task_uuid"] = signCreateImage.UUID
		if ok = models.UpdateTask(taskID, dataUUID); ok == false {
			code = e.ERROR
		} else {
			code = e.SUCCESS
		}

		//res, err := asyncResult.Get(1)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//log.Printf("worker run task success, return %s.", res)
	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}

	data := make(map[string]interface{})
	data["task_id"] = taskID

	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  e.GetMsg(code),
		"data": data,
	})
}

func UpdateTask(c *gin.Context) {
	var state int = -1
	var task_log string
	valid := validation.Validation{}

	id := com.StrTo(c.Param("id")).MustInt()
	token := c.Request.Header.Get("token")

	var dataJson UpdateTaskJson
	if c.BindJSON(&dataJson) == nil {
		task_log = dataJson.TaskLog
		state = com.StrTo(dataJson.State).MustInt()
	}

	valid.Min(id, 1, "id").Message("ID必须大于0")
	valid.MaxSize(task_log, 65535, "task_log").Message("内容最长为65535字符")
	valid.Required(token, "token").Message("内容不能为空")
	valid.Range(state, 0, 1, "state").Message("状态只允许0或1")

	code := e.INVALID_PARAMS
	if !valid.HasErrors() {
		username, errGetUsername := util.GetUsername(token)
		if errGetUsername != nil {
			code = e.ERROR
		}
		if username == "" {
			code = e.ERROR
		}

		//if models.ExistTaskByID(id) {
		if models.ExistTaskByIDAndUsername(id, username) {
			data := make(map[string]interface{})
			if state != -1 {
				data["state"] = state
			}
			if task_log != "" {
				data["task_log"] = task_log
			}

			models.UpdateTask(id, data)
			code = e.SUCCESS
		} else {
			code = e.ERROR_NOT_EXIST_TASK
		}
	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  e.GetMsg(code),
		"data": make(map[string]string),
	})
}

func DeleteTask(c *gin.Context) {
	id := com.StrTo(c.Param("id")).MustInt()
	token := c.Request.Header.Get("token")

	valid := validation.Validation{}
	valid.Min(id, 1, "id").Message("ID必须大于0")
	valid.Required(token, "token").Message("内容不能为空")

	code := e.INVALID_PARAMS
	if !valid.HasErrors() {
		username, errGetUsername := util.GetUsername(token)
		if errGetUsername != nil {
			code = e.ERROR
		}
		if username == "" {
			code = e.ERROR
		}

		//if models.ExistTaskByID(id) {
		if models.ExistTaskByIDAndUsername(id, username) {
			//todo  delete task of redis
			var dataTask models.Task
			dataTask = models.GetTask(id)

			targetTaskState, errGetState := BackendServer.GetState(dataTask.TaskUUID)
			if errGetState != nil {
				code = e.ERROR
				c.JSON(http.StatusOK, gin.H{
					"code": code,
					"msg":  e.GetMsg(code),
					"data": make(map[string]string),
				})
				return
			}

			if targetTaskState.IsCompleted() == true || targetTaskState.State == tasks.StatePending {
				for i := 1; i < 4; i++ {
					errDeleteTask := BackendServer.PurgeState(dataTask.TaskUUID)
					if errDeleteTask == nil {
						break
					} else {
						log.Printf("Fail: delete task %s for redis.", dataTask.TaskUUID)
					}
				}
			}

			models.DeleteTask(id)
			code = e.SUCCESS
		} else {
			code = e.ERROR_NOT_EXIST_TASK
		}
	} else {
		for _, err := range valid.Errors {
			log.Printf("err.key: %s, err.message: %s", err.Key, err.Message)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  e.GetMsg(code),
		"data": make(map[string]string),
	})
}
