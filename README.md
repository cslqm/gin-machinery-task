# gin-machinery-task

Use gin and machinery develop task manage server.

## API
``` 
GET    /user                     --> github.com/cslqm/gin-machinery-task/routers/api.GetUser (3 handlers)
GET    /api/v1/tasks             --> github.com/cslqm/gin-machinery-task/routers/api/v1.GetTasks (4 handlers)
GET    /api/v1/tasks/:id         --> github.com/cslqm/gin-machinery-task/routers/api/v1.GetTask (4 handlers)
POST   /api/v1/tasks             --> github.com/cslqm/gin-machinery-task/routers/api/v1.AddTask (4 handlers)
POST   /api/v1/tasks/:id         --> github.com/cslqm/gin-machinery-task/routers/api/v1.UpdateTask (4 handlers)
DELETE /api/v1/tasks/:id         --> github.com/cslqm/gin-machinery-task/routers/api/v1.DeleteTask (4 handlers)
```
