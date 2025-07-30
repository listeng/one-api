package model

type ResponseFormat struct {
	Type       string      `json:"type,omitempty"`
	JsonSchema *JSONSchema `json:"json_schema,omitempty"`
}

type JSONSchema struct {
	Description string                 `json:"description,omitempty"`
	Name        string                 `json:"name"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	Strict      *bool                  `json:"strict,omitempty"`
}

type Audio struct {
	Voice  string `json:"voice,omitempty"`
	Format string `json:"format,omitempty"`
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

type GeneralOpenAIRequest struct {
	// https://platform.openai.com/docs/api-reference/chat/create
	Messages            []Message       `json:"messages,omitempty"`
	Model               string          `json:"model,omitempty"`
	Store               *bool           `json:"store,omitempty"`
	Metadata            any             `json:"metadata,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
	LogitBias           any             `json:"logit_bias,omitempty"`
	Logprobs            *bool           `json:"logprobs,omitempty"`
	TopLogprobs         *int            `json:"top_logprobs,omitempty"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	N                   int             `json:"n,omitempty"`
	Modalities          []string        `json:"modalities,omitempty"`
	Prediction          any             `json:"prediction,omitempty"`
	Audio               *Audio          `json:"audio,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	ResponseFormat      *ResponseFormat `json:"response_format,omitempty"`
	Seed                float64         `json:"seed,omitempty"`
	ServiceTier         *string         `json:"service_tier,omitempty"`
	Stop                any             `json:"stop,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	StreamOptions       *StreamOptions  `json:"stream_options,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	TopK                int             `json:"top_k,omitempty"`
	Tools               []Tool          `json:"tools,omitempty"`
	ToolChoice          any             `json:"tool_choice,omitempty"`
	ParallelTooCalls    *bool           `json:"parallel_tool_calls,omitempty"`
	User                string          `json:"user,omitempty"`
	FunctionCall        any             `json:"function_call,omitempty"`
	Functions           any             `json:"functions,omitempty"`
	// https://platform.openai.com/docs/api-reference/embeddings/create
	Input          any    `json:"input,omitempty"`
	EncodingFormat string `json:"encoding_format,omitempty"`
	Dimensions     int    `json:"dimensions,omitempty"`
	// https://platform.openai.com/docs/api-reference/images/create
	Prompt  any     `json:"prompt,omitempty"`
	Quality *string `json:"quality,omitempty"`
	Size    string  `json:"size,omitempty"`
	Style   *string `json:"style,omitempty"`
	// https://platform.openai.com/docs/api-reference/rerank
	Query           string   `json:"query,omitempty"`
	Documents       []string `json:"documents,omitempty"`
	TopN            *int     `json:"top_n,omitempty"`
	ReturnDocuments *bool    `json:"return_documents,omitempty"`
	ScoreThreshold  *float64 `json:"score_threshold,omitempty"`
	// Others
	Instruction string    `json:"instruction,omitempty"`
	NumCtx      int       `json:"num_ctx,omitempty"`
	Thinking    *Thinking `json:"thinking,omitempty"`
	// 飞桨模型相关字段
	File                      string   `json:"file,omitempty"`                      // 服务器可访问的图像文件或PDF文件的URL，或上述类型文件内容的Base64编码结果
	FileType                  *int     `json:"fileType,omitempty"`                  // 文件类型。0表示PDF文件，1表示图像文件
	UseDocUnwarping           *bool    `json:"useDocUnwarping,omitempty"`           // 请参阅产线对象中 predict 方法的 use_doc_unwarping 参数相关说明
	UseTextlineOrientation    *bool    `json:"useTextlineOrientation,omitempty"`    // 请参阅产线对象中 predict 方法的 use_textline_orientation 参数相关说明
	TextDetLimitSideLen       *int     `json:"textDetLimitSideLen,omitempty"`       // 请参阅产线对象中 predict 方法的 text_det_limit_side_len 参数相关说明
	TextDetLimitType          *string  `json:"textDetLimitType,omitempty"`          // 请参阅产线对象中 predict 方法的 text_det_limit_type 参数相关说明
	TextDetThresh             *float64 `json:"textDetThresh,omitempty"`             // 请参阅产线对象中 predict 方法的 text_det_thresh 参数相关说明
	TextDetBoxThresh          *float64 `json:"textDetBoxThresh,omitempty"`          // 请参阅产线对象中 predict 方法的 text_det_box_thresh 参数相关说明
	TextDetUnclipRatio        *float64 `json:"textDetUnclipRatio,omitempty"`        // 请参阅产线对象中 predict 方法的 text_det_unclip_ratio 参数相关说明
	TextRecScoreThresh        *float64 `json:"textRecScoreThresh,omitempty"`        // 请参阅产线对象中 predict 方法的 text_rec_score_thresh 参数相关说明
	Visualize                 *bool    `json:"visualize,omitempty"`                 // 是否返回可视化结果图以及处理过程中的中间图像等
	UseDocOrientationClassify *bool    `json:"useDocOrientationClassify,omitempty"` // 请参阅产线对象中 predict 方法的 use_doc_orientation_classify 参数相关说明
}

type Thinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens" binding:"omitempty,min=1024"`
}

func (r GeneralOpenAIRequest) ParseInput() []string {
	if r.Input == nil {
		return nil
	}
	var input []string
	switch r.Input.(type) {
	case string:
		input = []string{r.Input.(string)}
	case []any:
		input = make([]string, 0, len(r.Input.([]any)))
		for _, item := range r.Input.([]any) {
			if str, ok := item.(string); ok {
				input = append(input, str)
			}
		}
	}
	return input
}

// RerankRequest represents a rerank request
type RerankRequest struct {
	Model           string   `json:"model"`
	Query           string   `json:"query"`
	Documents       []string `json:"documents"`
	TopN            *int     `json:"top_n,omitempty"`
	ReturnDocuments *bool    `json:"return_documents,omitempty"`
	ScoreThreshold  *float64 `json:"score_threshold,omitempty"`
	User            *string  `json:"user,omitempty"`
}

// RerankDocument represents a single rerank document
type RerankDocument struct {
	Index int     `json:"index"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

// RerankDocumentResult represents a single rerank result with document structure
type RerankDocumentResult struct {
	Index    int `json:"index"`
	Document struct {
		Text string `json:"text"`
	} `json:"document"`
	RelevanceScore float64 `json:"relevance_score"`
}

// RerankResult represents a rerank result
type RerankResult struct {
	Model string           `json:"model"`
	Docs  []RerankDocument `json:"docs"`
}

// RerankTokens represents tokens information in rerank response
type RerankTokens struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// RerankResponse represents the new rerank response format
type RerankResponse struct {
	Id      string                 `json:"id"`
	Model   string                 `json:"model"`
	Usage   *Usage                 `json:"usage,omitempty"`
	Tokens  *RerankTokens          `json:"tokens,omitempty"`
	Results []RerankDocumentResult `json:"results"`
}
