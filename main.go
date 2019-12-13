package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/robfig/cron"
	"log"

	"github.com/cslqm/gin-machinery-task/backend"
	"github.com/cslqm/gin-machinery-task/pkg/setting"
	"github.com/cslqm/gin-machinery-task/routers"
)

func main() {
	router := routers.InitRouter()

	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", setting.HTTPPort),
		Handler:        router,
		ReadTimeout:    setting.ReadTimeout,
		WriteTimeout:   setting.WriteTimeout,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Printf("Listen: %s\n", err)
		}
	}()

	go func() {
		c := cron.New()
		c.AddFunc("0 */1 * * * *", func() {
			log.Println("Run Cron...")
			backend.UpdateState()
		})
		c.Start()
		t1 := time.NewTimer(time.Second * 10)
		for {
			select {
			case <-t1.C:
				t1.Reset(time.Second * 10)
			}
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}

	log.Println("Server exiting")
}
