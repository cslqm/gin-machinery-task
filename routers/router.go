package routers

import (
	//"net/http"
	"github.com/gin-gonic/gin"

	"github.com/cslqm/gin-machinery-task/middleware/jwt"
	"github.com/cslqm/gin-machinery-task/pkg/setting"
	"github.com/cslqm/gin-machinery-task/routers/api"
	"github.com/cslqm/gin-machinery-task/routers/api/v1"
)

func InitRouter() *gin.Engine {
	r := gin.New()

	r.Use(gin.Logger())

	r.Use(gin.Recovery())

	gin.SetMode(setting.RunMode)

	//r.LoadHTMLGlob("templates/*")
	//r.GET("/", func(c *gin.Context) {
	//	c.HTML(http.StatusOK, "index.html", gin.H{
	//	//	"title": "Packer make image server",
	//	})
	//})

	r.GET("/user", api.GetUser)

	apiv1 := r.Group("/api/v1")
	//apiv1.Use(jwt.JWT())
	apiv1.Use(jwt.JWTV1())
	{
		apiv1.GET("/tasks", v1.GetTasks)
		apiv1.GET("/tasks/:id", v1.GetTask)
		apiv1.POST("/tasks", v1.AddTask)
		apiv1.POST("/tasks/:id", v1.UpdateTask)
		apiv1.DELETE("/tasks/:id", v1.DeleteTask)
	}

	return r
}
