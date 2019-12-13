package setting

import (
	"log"
	"time"

	"github.com/go-ini/ini"
)

var (
	Cfg *ini.File

	RunMode string

	HTTPPort     int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	PageSize    int
	JwtSecret   string
	TaskTimeout int

	Broker          string
	DefaultQueue    string
	ResultBackend   string
	ResultsExpireIn int
	BindingKey      string
	Exchange        string
	ExchangeType    string
	PrefetchCount   int
)

func init() {
	var err error
	Cfg, err = ini.Load("conf/app.ini")
	if err != nil {
		log.Fatalf("Fail to parse 'conf/app.ini': %v", err)
	}

	LoadBase()
	LoadServer()
	LoadApp()
	LoadMachinery()
}

func LoadBase() {
	RunMode = Cfg.Section("").Key("RUN_MODE").MustString("debug")
}

func LoadServer() {
	sec, err := Cfg.GetSection("server")
	if err != nil {
		log.Fatalf("Fail to get section 'server': %v", err)
	}

	RunMode = Cfg.Section("").Key("RUN_MODE").MustString("debug")

	HTTPPort = sec.Key("HTTP_PORT").MustInt(8000)
	ReadTimeout = time.Duration(sec.Key("READ_TIMEOUT").MustInt(60)) * time.Second
	WriteTimeout = time.Duration(sec.Key("WRITE_TIMEOUT").MustInt(60)) * time.Second
}

func LoadApp() {
	sec, err := Cfg.GetSection("app")
	if err != nil {
		log.Fatalf("Fail to get section 'app': %v", err)
	}

	JwtSecret = sec.Key("JWT_SECRET").MustString("!@)*#)!@U#@*!@!)")
	PageSize = sec.Key("PAGE_SIZE").MustInt(10)

	var errTaskTimeout error
	//TaskTimeout = time.Duration(sec.Key("TASK_TIMEOUT").MustInt(60)) * time.Second
	TaskTimeout, errTaskTimeout = sec.Key("TASK_TIMEOUT").Int()
	if errTaskTimeout != nil {
		// default timeout is 30 minutes
		TaskTimeout = 1800
	}
}

func LoadMachinery() {
	sec, err := Cfg.GetSection("machiney")
	if err != nil {
		log.Fatalf("Fail to get section 'machiney': %v", err)
	}

	var errResultsExpireIn error
	var errPrefetchCount error

	Broker = sec.Key("BROKER").String()
	DefaultQueue = sec.Key("DEFAULT_QUEUE").String()
	ResultBackend = sec.Key("RESULT_BACKEND").String()
	ResultsExpireIn, errResultsExpireIn = sec.Key("RESULTS_EXPIRE_IN").Int()
	if errResultsExpireIn != nil {
		ResultsExpireIn = 3600000
	}

	BindingKey = sec.Key("BINDING_KEY").String()
	Exchange = sec.Key("EXCHANGE").String()
	ExchangeType = sec.Key("EXCHANGE_TYPE").String()
	PrefetchCount, errPrefetchCount = sec.Key("PREFETCH_COUNT").Int()
	if errPrefetchCount != nil {
		PrefetchCount = 3
	}
}
