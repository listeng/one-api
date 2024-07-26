package relay

import (
	"one-api/relay/adaptor"
	"one-api/relay/adaptor/aiproxy"
	"one-api/relay/adaptor/ali"
	"one-api/relay/adaptor/anthropic"
	"one-api/relay/adaptor/aws"
	"one-api/relay/adaptor/baidu"
	"one-api/relay/adaptor/cloudflare"
	"one-api/relay/adaptor/cohere"
	"one-api/relay/adaptor/coze"
	"one-api/relay/adaptor/deepl"
	"one-api/relay/adaptor/gemini"
	"one-api/relay/adaptor/ollama"
	"one-api/relay/adaptor/openai"
	"one-api/relay/adaptor/palm"
	"one-api/relay/adaptor/proxy"
	"one-api/relay/adaptor/tencent"
	"one-api/relay/adaptor/vertexai"
	"one-api/relay/adaptor/xunfei"
	"one-api/relay/adaptor/zhipu"
	"one-api/relay/apitype"
)

func GetAdaptor(apiType int) adaptor.Adaptor {
	switch apiType {
	case apitype.AIProxyLibrary:
		return &aiproxy.Adaptor{}
	case apitype.Ali:
		return &ali.Adaptor{}
	case apitype.Anthropic:
		return &anthropic.Adaptor{}
	case apitype.AwsClaude:
		return &aws.Adaptor{}
	case apitype.Baidu:
		return &baidu.Adaptor{}
	case apitype.Gemini:
		return &gemini.Adaptor{}
	case apitype.OpenAI:
		return &openai.Adaptor{}
	case apitype.PaLM:
		return &palm.Adaptor{}
	case apitype.Tencent:
		return &tencent.Adaptor{}
	case apitype.Xunfei:
		return &xunfei.Adaptor{}
	case apitype.Zhipu:
		return &zhipu.Adaptor{}
	case apitype.Ollama:
		return &ollama.Adaptor{}
	case apitype.Coze:
		return &coze.Adaptor{}
	case apitype.Cohere:
		return &cohere.Adaptor{}
	case apitype.Cloudflare:
		return &cloudflare.Adaptor{}
	case apitype.DeepL:
		return &deepl.Adaptor{}
	case apitype.VertexAI:
		return &vertexai.Adaptor{}
	case apitype.Proxy:
		return &proxy.Adaptor{}
	}
	return nil
}
