package cohere

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"one-api/relay/adaptor"
	"one-api/relay/meta"
	"one-api/relay/model"
	"one-api/relay/relaymode"

	"github.com/gin-gonic/gin"
)

type Adaptor struct {
}

func (a *Adaptor) Init(meta *meta.Meta) {

}

func (a *Adaptor) GetRequestURL(meta *meta.Meta) (string, error) {
	switch meta.Mode {
	case relaymode.ChatCompletions:
		return fmt.Sprintf("%s/v1/chat", meta.BaseURL), nil
	case relaymode.Rerank:
		return fmt.Sprintf("%s/v1/rerank", meta.BaseURL), nil
	default:
		return "", fmt.Errorf("unsupported relay mode %d for cohere", meta.Mode)
	}
}

func (a *Adaptor) SetupRequestHeader(c *gin.Context, req *http.Request, meta *meta.Meta) error {
	adaptor.SetupCommonRequestHeader(c, req, meta)
	req.Header.Set("Authorization", "Bearer "+meta.APIKey)
	return nil
}

func (a *Adaptor) ConvertRequest(c *gin.Context, relayMode int, request *model.GeneralOpenAIRequest) (any, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	switch relayMode {
	case relaymode.ChatCompletions:
		return ConvertRequest(*request), nil
	case relaymode.Rerank:
		// Rerank requests are handled differently
		return nil, fmt.Errorf("rerank requests should use ConvertRerankRequest")
	default:
		return ConvertRequest(*request), nil
	}
}

func (a *Adaptor) ConvertRerankRequest(rerankRequest *model.RerankRequest) (*RerankRequest, error) {
	if rerankRequest == nil {
		return nil, errors.New("rerank request is nil")
	}

	return &RerankRequest{
		Model:           rerankRequest.Model,
		Query:           rerankRequest.Query,
		Documents:       rerankRequest.Documents,
		TopN:            rerankRequest.TopN,
		ReturnDocuments: rerankRequest.ReturnDocuments,
		ScoreThreshold:  rerankRequest.ScoreThreshold,
		User:            rerankRequest.User,
	}, nil
}

func (a *Adaptor) ConvertImageRequest(request *model.ImageRequest) (any, error) {
	return nil, errors.New("not implemented")
}

func (a *Adaptor) DoRequest(c *gin.Context, meta *meta.Meta, requestBody io.Reader) (*http.Response, error) {
	return adaptor.DoRequestHelper(a, c, meta, requestBody)
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, meta *meta.Meta) (usage *model.Usage, err *model.ErrorWithStatusCode) {
	switch meta.Mode {
	case relaymode.Rerank:
		err, usage = RerankHandler(c, resp)
	default:
		if meta.IsStream {
			err, usage = StreamHandler(c, resp)
		} else {
			err, usage = Handler(c, resp, meta.PromptTokens, meta.ActualModelName)
		}
	}
	return
}

func (a *Adaptor) GetModelList() []string {
	return ModelList
}

func (a *Adaptor) GetChannelName() string {
	return "cohere"
}
