package middleware

import (
	"context"
	"one-api/common/helper"
	"one-api/common/logger"

	"github.com/gin-gonic/gin"
)

func RequestId() func(c *gin.Context) {
	return func(c *gin.Context) {
		id := helper.GenRequestID()
		c.Set(logger.RequestIdKey, id)
		ctx := context.WithValue(c.Request.Context(), logger.RequestIdKey, id)
		c.Request = c.Request.WithContext(ctx)
		c.Header(logger.RequestIdKey, id)
		c.Next()
	}
}
