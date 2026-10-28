package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) { c.String(200, "pong") })
	_ = r.Run()
}
