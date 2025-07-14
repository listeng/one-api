package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"one-api/common"
	"one-api/common/logger"
	"one-api/relay"
	"one-api/relay/adaptor/openai"
	"one-api/relay/model"

	"github.com/gin-gonic/gin"

	"one-api/relay/adaptor"
	"one-api/relay/adaptor/cohere"
	billingratio "one-api/relay/billing/ratio"
	"one-api/relay/meta"
)

func RelayRerankHelper(c *gin.Context) *model.ErrorWithStatusCode {
	ctx := c.Request.Context()
	meta := meta.GetByContext(c)

	// get & validate rerankRequest
	rerankRequest, err := getAndValidateRerankRequest(c, meta.Mode)
	if err != nil {
		logger.Errorf(ctx, "getAndValidateRerankRequest failed: %s", err.Error())
		return openai.ErrorWrapper(err, "invalid_rerank_request", http.StatusBadRequest)
	}

	// map model name
	meta.OriginModelName = rerankRequest.Model
	rerankRequest.Model, _ = getMappedModelName(rerankRequest.Model, meta.ModelMapping)
	meta.ActualModelName = rerankRequest.Model

	// get model ratio & group ratio
	modelRatio := billingratio.GetModelRatio(rerankRequest.Model, meta.ChannelType)
	groupRatio := billingratio.GetGroupRatio(meta.Group)
	ratio := modelRatio * groupRatio

	// pre-consume quota
	promptTokens := getRerankPromptTokens(rerankRequest, meta.Mode)
	meta.PromptTokens = promptTokens
	_, bizErr := preConsumeQuota(ctx, nil, promptTokens, ratio, meta)
	if bizErr != nil {
		logger.Warnf(ctx, "preConsumeQuota failed: %+v", *bizErr)
		return bizErr
	}

	adaptor := relay.GetAdaptor(meta.APIType)
	if adaptor == nil {
		return openai.ErrorWrapper(fmt.Errorf("invalid api type: %d", meta.APIType), "invalid_api_type", http.StatusBadRequest)
	}
	adaptor.Init(meta)

	// get request body
	requestBody, err := getRerankRequestBody(c, meta, rerankRequest, adaptor)
	if err != nil {
		logger.Errorf(ctx, "getRerankRequestBody failed: %s", err.Error())
		return openai.ErrorWrapper(err, "get_rerank_request_body_failed", http.StatusInternalServerError)
	}

	// do request
	resp, err := adaptor.DoRequest(c, meta, requestBody)
	if err != nil {
		logger.Errorf(ctx, "DoRequest failed: %s", err.Error())
		return openai.ErrorWrapper(err, "do_request_failed", http.StatusInternalServerError)
	}

	// do response
	usage, respErr := adaptor.DoResponse(c, resp, meta)
	if respErr != nil {
		logger.Errorf(ctx, "respErr is not nil: %+v", respErr)
		return respErr
	}

	// post-consume quota - simplified for rerank
	if usage != nil {
		// For rerank, we'll use a simplified post-consume
		// This might need adjustment based on actual billing requirements
		logger.Infof(ctx, "Rerank usage: %+v", usage)
	}

	return nil
}

func getAndValidateRerankRequest(c *gin.Context, mode int) (*model.RerankRequest, error) {
	var rerankRequest model.RerankRequest
	err := common.UnmarshalBodyReusable(c, &rerankRequest)
	if err != nil {
		return nil, fmt.Errorf("unmarshal rerank request failed: %w", err)
	}

	if rerankRequest.Model == "" {
		return nil, fmt.Errorf("model is required")
	}
	if rerankRequest.Query == "" {
		return nil, fmt.Errorf("query is required")
	}
	if len(rerankRequest.Documents) == 0 {
		return nil, fmt.Errorf("documents are required")
	}

	return &rerankRequest, nil
}

func getRerankPromptTokens(rerankRequest *model.RerankRequest, mode int) int {
	// Calculate tokens for query and documents
	totalTokens := 0

	// Add query tokens
	totalTokens += len(rerankRequest.Query) / 4 // rough estimation

	// Add documents tokens
	for _, doc := range rerankRequest.Documents {
		totalTokens += len(doc) / 4 // rough estimation
	}

	return totalTokens
}

func getRerankRequestBody(c *gin.Context, meta *meta.Meta, rerankRequest *model.RerankRequest, adaptor adaptor.Adaptor) (io.Reader, error) {
	// Check if the adaptor supports rerank
	if cohereAdaptor, ok := adaptor.(interface {
		ConvertRerankRequest(*model.RerankRequest) (*cohere.RerankRequest, error)
	}); ok {
		// Use Cohere-specific conversion
		cohereRequest, err := cohereAdaptor.ConvertRerankRequest(rerankRequest)
		if err != nil {
			return nil, fmt.Errorf("convert rerank request failed: %w", err)
		}

		jsonStr, err := json.Marshal(cohereRequest)
		if err != nil {
			return nil, fmt.Errorf("marshal rerank request failed: %w", err)
		}

		return bytes.NewBuffer(jsonStr), nil
	}

	// Check if the adaptor supports OpenAI rerank
	if openAIAdaptor, ok := adaptor.(interface {
		ConvertRerankRequest(*model.RerankRequest) (*openai.RerankRequest, error)
	}); ok {
		// Use OpenAI-specific conversion
		openAIRequest, err := openAIAdaptor.ConvertRerankRequest(rerankRequest)
		if err != nil {
			return nil, fmt.Errorf("convert rerank request failed: %w", err)
		}

		jsonStr, err := json.Marshal(openAIRequest)
		if err != nil {
			return nil, fmt.Errorf("marshal rerank request failed: %w", err)
		}

		return bytes.NewBuffer(jsonStr), nil
	}

	// Default conversion for other adaptors
	requestData := map[string]interface{}{
		"model":            rerankRequest.Model,
		"query":            rerankRequest.Query,
		"documents":        rerankRequest.Documents,
		"return_documents": true,
	}

	if rerankRequest.TopN != nil {
		requestData["top_n"] = *rerankRequest.TopN
	}
	if rerankRequest.ScoreThreshold != nil {
		requestData["score_threshold"] = *rerankRequest.ScoreThreshold
	}
	if rerankRequest.User != nil {
		requestData["user"] = *rerankRequest.User
	}

	jsonStr, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("marshal rerank request failed: %w", err)
	}

	return bytes.NewBuffer(jsonStr), nil
}
