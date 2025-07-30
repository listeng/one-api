package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"one-api/common/config"
	"one-api/common/logger"
	"one-api/common/message"
	"one-api/middleware"
	"one-api/model"
	"one-api/monitor"
	relaymodel "one-api/relay/model"
	"strconv"
	"strings"
	"sync"
	"time"

	"one-api/common/ctxkey"
	relay "one-api/relay"
	"one-api/relay/channeltype"
	"one-api/relay/controller"
	"one-api/relay/meta"
	"one-api/relay/relaymode"

	"github.com/gin-gonic/gin"
)

func buildTestRequest(modelName string, modelType int) *relaymodel.GeneralOpenAIRequest {
	if modelName == "" {
		switch modelType {
		case model.ModelTypeEmbedding:
			modelName = "text-embedding-ada-002"
		case model.ModelTypeRerank:
			modelName = "rerank-english-v2.0"
		case model.ModelTypePaddleX:
			// 飞桨模型取第一个可用模型
			modelName = "ocr"
		default: // ModelTypeLanguage
			modelName = "gpt-3.5-turbo"
		}
	}

	switch modelType {
	case model.ModelTypeEmbedding:
		// 构建嵌入模型测试请求
		testRequest := &relaymodel.GeneralOpenAIRequest{
			Model: modelName,
		}
		testRequest.Input = []string{"test"}
		return testRequest
	case model.ModelTypeRerank:
		// 构建重排模型测试请求
		testRequest := &relaymodel.GeneralOpenAIRequest{
			Model:     modelName,
			Query:     "test query",
			Documents: []string{"test document"},
		}
		return testRequest
	case model.ModelTypePaddleX:
		// 构建飞桨模型测试请求
		// 使用一个简单的测试图像base64数据
		testImageBase64 := test_img_data
		fileType := 1
		testRequest := &relaymodel.GeneralOpenAIRequest{
			Model:    modelName,
			File:     testImageBase64,
			FileType: &fileType,
		}
		return testRequest
	default: // ModelTypeLanguage
		// 构建语言模型测试请求
		testRequest := &relaymodel.GeneralOpenAIRequest{
			MaxTokens: 2,
			Model:     modelName,
		}
		testMessage := relaymodel.Message{
			Role:    "user",
			Content: "hi",
		}
		testRequest.Messages = append(testRequest.Messages, testMessage)
		return testRequest
	}
}

func testChannel(channel *model.Channel, request *relaymodel.GeneralOpenAIRequest) (err error, openaiErr *relaymodel.Error) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// 根据模型类型决定测试接口
	var testPath string
	var relayMode int

	switch channel.ModelType {
	case model.ModelTypeEmbedding:
		testPath = "/v1/embeddings"
		relayMode = relaymode.Embeddings
	case model.ModelTypeRerank:
		testPath = "/v1/rerank"
		relayMode = relaymode.Rerank
	case model.ModelTypePaddleX:
		// 飞桨模型使用第一个可用模型作为测试路径
		// 飞桨模型的路径格式是 /模型名称，例如 /ocr
		modelNames := strings.Split(channel.Models, ",")
		if len(modelNames) > 0 {
			testPath = "/" + modelNames[0]
		} else {
			testPath = "/ocr"
		}
		relayMode = relaymode.ChatCompletions // 使用默认模式
	default: // ModelTypeLanguage
		testPath = "/v1/chat/completions"
		relayMode = relaymode.ChatCompletions
	}

	c.Request = &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: testPath},
		Body:   nil,
		Header: make(http.Header),
	}
	c.Request.Header.Set("Authorization", "Bearer "+channel.Key)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(ctxkey.Channel, channel.Type)
	c.Set(ctxkey.BaseURL, channel.GetBaseURL())
	cfg, _ := channel.LoadConfig()
	c.Set(ctxkey.Config, cfg)
	middleware.SetupContextForSelectedChannel(c, channel, "")
	meta := meta.GetByContext(c)
	apiType := channeltype.ToAPIType(channel.Type)
	adaptor := relay.GetAdaptor(apiType)
	if adaptor == nil {
		return fmt.Errorf("invalid api type: %d, adaptor is nil", apiType), nil
	}
	adaptor.Init(meta)
	modelName := request.Model
	modelMap := channel.GetModelMapping()
	if modelName == "" || !strings.Contains(channel.Models, modelName) {
		modelNames := strings.Split(channel.Models, ",")
		if len(modelNames) > 0 {
			modelName = modelNames[0]
		}
	}
	if modelMap != nil && modelMap[modelName] != "" {
		modelName = modelMap[modelName]
	}
	meta.OriginModelName, meta.ActualModelName = request.Model, modelName
	request.Model = modelName
	convertedRequest, err := adaptor.ConvertRequest(c, relayMode, request)
	if err != nil {
		return err, nil
	}
	jsonData, err := json.Marshal(convertedRequest)
	if err != nil {
		return err, nil
	}
	logger.SysLog(string(jsonData))
	requestBody := bytes.NewBuffer(jsonData)
	c.Request.Body = io.NopCloser(requestBody)
	resp, err := adaptor.DoRequest(c, meta, requestBody)
	if err != nil {
		return err, nil
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		err := controller.RelayErrorHandler(resp)
		return fmt.Errorf("status code %d: %s", resp.StatusCode, err.Error.Message), &err.Error
	}
	usage, respErr := adaptor.DoResponse(c, resp, meta)
	if respErr != nil {
		return fmt.Errorf("%s", respErr.Error.Message), &respErr.Error
	}
	// 飞桨模型不返回usage，所以跳过usage检查
	if usage == nil && channel.ModelType != model.ModelTypePaddleX {
		return errors.New("usage is nil"), nil
	}
	result := w.Result()
	// print result.Body
	respBody, err := io.ReadAll(result.Body)
	if err != nil {
		return err, nil
	}
	logger.SysLog(fmt.Sprintf("testing channel #%d, response: \n%s", channel.Id, string(respBody)))
	return nil, nil
}

func TestChannel(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	channel, err := model.GetChannelById(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	modelName := c.Query("model")
	testRequest := buildTestRequest(modelName, channel.ModelType)
	tik := time.Now()
	err, _ = testChannel(channel, testRequest)
	tok := time.Now()
	milliseconds := tok.Sub(tik).Milliseconds()
	if err != nil {
		milliseconds = 0
	}
	go channel.UpdateResponseTime(milliseconds)
	consumedTime := float64(milliseconds) / 1000.0
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
			"time":    consumedTime,
			"model":   modelName,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"time":    consumedTime,
		"model":   modelName,
	})
	return
}

var testAllChannelsLock sync.Mutex
var testAllChannelsRunning bool = false

func testChannels(notify bool, scope string) error {
	if config.RootUserEmail == "" {
		config.RootUserEmail = model.GetRootUserEmail()
	}
	testAllChannelsLock.Lock()
	if testAllChannelsRunning {
		testAllChannelsLock.Unlock()
		return errors.New("测试已在运行中")
	}
	testAllChannelsRunning = true
	testAllChannelsLock.Unlock()
	channels, err := model.GetAllChannels(0, 0, scope)
	if err != nil {
		return err
	}
	var disableThreshold = int64(config.ChannelDisableThreshold * 1000)
	if disableThreshold == 0 {
		disableThreshold = 10000000 // a impossible value
	}
	go func() {
		for _, channel := range channels {
			isChannelEnabled := channel.Status == model.ChannelStatusEnabled
			tik := time.Now()
			testRequest := buildTestRequest("", channel.ModelType)
			err, openaiErr := testChannel(channel, testRequest)
			tok := time.Now()
			milliseconds := tok.Sub(tik).Milliseconds()
			if isChannelEnabled && milliseconds > disableThreshold {
				err = fmt.Errorf("响应时间 %.2fs 超过阈值 %.2fs", float64(milliseconds)/1000.0, float64(disableThreshold)/1000.0)
				if config.AutomaticDisableChannelEnabled {
					monitor.DisableChannel(channel.Id, channel.Name, err.Error())
				} else {
					_ = message.Notify(message.ByAll, fmt.Sprintf("渠道 %s （%d）测试超时", channel.Name, channel.Id), "", err.Error())
				}
			}
			if isChannelEnabled && monitor.ShouldDisableChannel(openaiErr, -1) {
				monitor.DisableChannel(channel.Id, channel.Name, err.Error())
			}
			if !isChannelEnabled && monitor.ShouldEnableChannel(err, openaiErr) {
				monitor.EnableChannel(channel.Id, channel.Name)
			}
			channel.UpdateResponseTime(milliseconds)
			time.Sleep(config.RequestInterval)
		}
		testAllChannelsLock.Lock()
		testAllChannelsRunning = false
		testAllChannelsLock.Unlock()
		if notify {
			err := message.Notify(message.ByAll, "渠道测试完成", "", "渠道测试完成，如果没有收到禁用通知，说明所有渠道都正常")
			if err != nil {
				logger.SysError(fmt.Sprintf("failed to send email: %s", err.Error()))
			}
		}
	}()
	return nil
}

func TestChannels(c *gin.Context) {
	scope := c.Query("scope")
	if scope == "" {
		scope = "all"
	}
	err := testChannels(true, scope)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func AutomaticallyTestChannels(frequency int) {
	for {
		time.Sleep(time.Duration(frequency) * time.Minute)
		logger.SysLog("testing all channels")
		_ = testChannels(false, "all")
		logger.SysLog("channel test finished")
	}
}
