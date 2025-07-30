package middleware

import (
	"fmt"
	"net/http"
	"one-api/common/ctxkey"
	"one-api/common/logger"
	"one-api/model"
	"one-api/relay/channeltype"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type ModelRequest struct {
	Model string `json:"model" form:"model"`
}

func Distribute() func(c *gin.Context) {
	return func(c *gin.Context) {
		userId := c.GetInt(ctxkey.Id)
		userGroup, _ := model.CacheGetUserGroup(userId)
		c.Set(ctxkey.Group, userGroup)
		var requestModel string
		var channel *model.Channel

		// 检查是否是飞桨模型的API接口
		requestPath := c.Request.URL.Path
		isPaddleXAPI := IsPaddleXAPI(requestPath)

		channelId, ok := c.Get(ctxkey.SpecificChannelId)
		if ok {
			id, err := strconv.Atoi(channelId.(string))
			if err != nil {
				abortWithMessage(c, http.StatusBadRequest, "无效的渠道 Id")
				return
			}
			channel, err = model.GetChannelById(id, true)
			if err != nil {
				abortWithMessage(c, http.StatusBadRequest, "无效的渠道 Id")
				return
			}
			if channel.Status != model.ChannelStatusEnabled {
				abortWithMessage(c, http.StatusForbidden, "该渠道已被禁用")
				return
			}
		} else {
			if isPaddleXAPI {
				// 对于飞桨模型API，使用路径作为模型名称
				requestModel = strings.TrimPrefix(requestPath, "/v1/")
				// 查找飞桨模型类型的渠道
				var err error
				channel, err = model.CacheGetRandomSatisfiedChannel(userGroup, requestModel, false)
				if err != nil {
					// 如果没有找到对应的渠道，尝试查找任何飞桨模型渠道
					channel, err = model.CacheGetRandomSatisfiedChannel(userGroup, "ocr", false)
					if err != nil {
						message := fmt.Sprintf("当前分组 %s 下对于飞桨模型 %s 无可用渠道", userGroup, requestModel)
						abortWithMessage(c, http.StatusServiceUnavailable, message)
						return
					}
				}
			} else {
				requestModel = c.GetString(ctxkey.RequestModel)
				var err error
				channel, err = model.CacheGetRandomSatisfiedChannel(userGroup, requestModel, false)
				if err != nil {
					message := fmt.Sprintf("当前分组 %s 下对于模型 %s 无可用渠道", userGroup, requestModel)
					if channel != nil {
						logger.SysError(fmt.Sprintf("渠道不存在：%d", channel.Id))
						message = "数据库一致性已被破坏，请联系管理员"
					}
					abortWithMessage(c, http.StatusServiceUnavailable, message)
					return
				}
			}
		}
		SetupContextForSelectedChannel(c, channel, requestModel)
		c.Next()
	}
}

// IsPaddleXAPI 检查是否是飞桨模型的API接口
func IsPaddleXAPI(path string) bool {
	paddleXAPIs := []string{
		"/ocr",
		"/table-recognition",
		"/layout-parsing",
		"/formula-recognition",
		"/seal-recognition",
		"/document-preprocessing",
		"/image-classification",
		"/object-detection",
		"/instance-segmentation",
		"/semantic-segmentation",
		"/multilabel-image-classification",
		"/small-object-detection",
		"/anomaly-detection",
		"/rotated-object-detection",
		"/shitu-index-build",
		"/face-recognition-index-build",
	}

	for _, api := range paddleXAPIs {
		if strings.HasSuffix(path, api) {
			return true
		}
	}
	return false
}

func SetupContextForSelectedChannel(c *gin.Context, channel *model.Channel, modelName string) {
	c.Set(ctxkey.Channel, channel.Type)
	c.Set(ctxkey.ChannelId, channel.Id)
	c.Set(ctxkey.ChannelName, channel.Name)
	if channel.SystemPrompt != nil && *channel.SystemPrompt != "" {
		c.Set(ctxkey.SystemPrompt, *channel.SystemPrompt)
	}
	c.Set(ctxkey.ModelMapping, channel.GetModelMapping())
	c.Set(ctxkey.OriginalModel, modelName) // for retry
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", channel.Key))
	c.Set(ctxkey.BaseURL, channel.GetBaseURL())
	cfg, _ := channel.LoadConfig()
	// this is for backward compatibility
	if channel.Other != nil {
		switch channel.Type {
		case channeltype.Azure:
			if cfg.APIVersion == "" {
				cfg.APIVersion = *channel.Other
			}
		case channeltype.Xunfei:
			if cfg.APIVersion == "" {
				cfg.APIVersion = *channel.Other
			}
		case channeltype.Gemini:
			if cfg.APIVersion == "" {
				cfg.APIVersion = *channel.Other
			}
		case channeltype.AIProxyLibrary:
			if cfg.LibraryID == "" {
				cfg.LibraryID = *channel.Other
			}
		case channeltype.Ali:
			if cfg.Plugin == "" {
				cfg.Plugin = *channel.Other
			}
		}
	}
	c.Set(ctxkey.Config, cfg)
}
