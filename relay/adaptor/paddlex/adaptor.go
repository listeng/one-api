package paddlex

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"one-api/common/config"
	"one-api/relay/adaptor"
	"one-api/relay/meta"
	"one-api/relay/model"
	relaymodel "one-api/relay/model"

	"github.com/gin-gonic/gin"
)

var _ adaptor.Adaptor = new(Adaptor)

const channelName = "paddlex"

type Adaptor struct{}

func (a *Adaptor) Init(meta *meta.Meta) {
}

func (a *Adaptor) ConvertRequest(c *gin.Context, relayMode int, request *model.GeneralOpenAIRequest) (any, error) {
	// 飞桨模型透传所有参数
	// 将GeneralOpenAIRequest转换为map[string]interface{}，透传所有字段
	paddleRequest := make(map[string]interface{})

	// 使用JSON序列化和反序列化来复制所有字段
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonData, &paddleRequest)
	if err != nil {
		return nil, err
	}

	return paddleRequest, nil
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, meta *meta.Meta) (usage *model.Usage, err *model.ErrorWithStatusCode) {
	// 直接传递响应
	for k, v := range resp.Header {
		for _, vv := range v {
			c.Writer.Header().Set(k, vv)
		}
	}

	c.Writer.WriteHeader(resp.StatusCode)
	if _, gerr := io.Copy(c.Writer, resp.Body); gerr != nil {
		return nil, &relaymodel.ErrorWithStatusCode{
			StatusCode: http.StatusInternalServerError,
			Error: relaymodel.Error{
				Message: gerr.Error(),
			},
		}
	}

	return nil, nil
}

func (a *Adaptor) GetModelList() (models []string) {
	return ModelList
}

func (a *Adaptor) GetChannelName() string {
	return channelName
}

func (a *Adaptor) GetRequestURL(meta *meta.Meta) (string, error) {
	requestPath := meta.RequestURLPath

	// 如果配置了BasePath，先移除BasePath前缀
	if config.BasePath != "" {
		basePath := "/" + strings.Trim(config.BasePath, "/")
		requestPath = strings.TrimPrefix(requestPath, basePath)
	}

	// 移除/v1前缀
	requestPath = strings.TrimPrefix(requestPath, "/v1")

	return meta.BaseURL + requestPath, nil
}

func (a *Adaptor) SetupRequestHeader(c *gin.Context, req *http.Request, meta *meta.Meta) error {
	// 设置飞桨模型的请求头
	req.Header.Set("Content-Type", "application/json")

	// 飞桨模型可能使用不同的认证方式
	// 这里假设使用API Key作为Authorization
	if meta.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+meta.APIKey)
	}

	// 可以根据飞桨模型的具体要求添加其他请求头
	// 例如：req.Header.Set("X-PaddleX-Version", "1.0")

	return nil
}

func (a *Adaptor) ConvertImageRequest(request *model.ImageRequest) (any, error) {
	// 飞桨模型支持图像处理，但可能需要特殊格式
	// 这里可以根据需要转换图像请求格式
	return request, nil
}

func (a *Adaptor) DoRequest(c *gin.Context, meta *meta.Meta, requestBody io.Reader) (*http.Response, error) {
	return adaptor.DoRequestHelper(a, c, meta, requestBody)
}
