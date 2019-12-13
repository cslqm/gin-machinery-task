package models

import (
	"github.com/jinzhu/gorm"

	"log"
	"time"
)

type Task struct {
	//Model
	ID         int `gorm:"AUTO_INCREMENT;primary_key;" json:"id"`
	CreatedOn  int `json:"created_on"`
	ModifiedOn int `json:"modified_on"`

	TaskName  string `json:"task_name"`
	Content   string `json:"content"`
	CreatedBy string `json:"created_by"`
	State     int    `json:"state"`
	TaskLog   string `json:"task_log"`
	TaskUUID  string `json:"task_uuid"`
}

type TaskInfo struct {
	ID       int    `gorm:"AUTO_INCREMENT;primary_key;" json:"id"`
	State    int    `json:"state"`
	TaskUUID string `json:"task_uuid"`
}

func ExistTaskByID(id int) bool {
	var task Task
	db.Select("id").Where("id = ?", id).First(&task)

	if task.ID > 0 {
		return true
	}

	return false
}

func ExistTaskByIDAndUsername(id int, username string) bool {
	var task Task

	//db.Select("id").Where("id = ?", id).First(&task)
	db.Select("id").Where("id = ? and created_by = ?", id, username).First(&task)

	if task.ID > 0 {
		return true
	}

	return false
}

func GetTasksInfo() (tasks []Task) {
	//db.Select("id, state, task_uuid").Find(&tasksInfo)
	//db.Table("task").Select("id, state, task_uuid").Scan(&tasks)
	//db.Select("id, state, task_uuid").Find(&tasks)
	db.Select("id, state, task_uuid, created_on").Find(&tasks)

	return
}

func GetTaskTotal(maps interface{}) (count int) {
	db.Model(&Task{}).Where(maps).Count(&count)

	return
}

func GetTasks(pageNum int, pageSize int, maps interface{}) (tasks []Task) {
	db.Preload("Tag").Where(maps).Offset(pageNum).Limit(pageSize).Find(&tasks)

	return
}

func GetTask(id int) (task Task) {
	db.Where("id = ?", id).First(&task)
	//db.Model(&task).Related(&task.Tag)

	return
}

func UpdateTask(id int, data interface{}) bool {
	db.Model(&Task{}).Where("id = ?", id).Updates(data)

	return true
}

func AddTask(data map[string]interface{}) (id int, ok bool) {
	var task Task
	task = Task{
		TaskName:  data["task_name"].(string),
		Content:   data["content"].(string),
		CreatedBy: data["created_by"].(string),
		State:     data["state"].(int),
		TaskUUID:  data["task_uuid"].(string),
	}

	db.Create(&task)

	//db.Create(&Task{
	//	TaskName:  data["task_name"].(string),
	//	Content:   data["content"].(string),
	//	CreatedBy: data["created_by"].(string),
	//	State:     data["state"].(int),
	//})

	if dbErr := db.GetErrors(); dbErr != nil {
		if len(dbErr) > 0 {
			for i := 0; i < len(dbErr); i++ {
				log.Printf("add new task fail, stderr: %s.", dbErr[i].Error())
			}
			return -1, false
		}
	}
	//return task.Model.ID, true
	return task.ID, true
}

func DeleteTask(id int) bool {
	db.Where("id = ?", id).Delete(Task{})

	return true
}

func (task *Task) BeforeCreate(scope *gorm.Scope) error {
	scope.SetColumn("CreatedOn", time.Now().Unix())

	return nil
}

//func (task *Task) BeforeUpdate(scope *gorm.Scope) error {
//	scope.SetColumn("ModifiedOn", time.Now().Unix())
//
//	return nil
//}
