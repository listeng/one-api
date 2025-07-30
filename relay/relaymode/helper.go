package relaymode

import (
	"strings"

	"one-api/common/config"
	"one-api/middleware"
)

func GetByPath(path string) int {
	relayMode := Unknown
	pathReal := path
	// 去掉 BASE_PATH 前缀
	if config.BasePath != "" {
		prefix := "/" + config.BasePath
		if strings.HasPrefix(path, prefix) {
			pathReal = strings.TrimPrefix(path, prefix)
		}
	}

	if strings.HasPrefix(pathReal, "/v1/chat/completions") {
		relayMode = ChatCompletions
	} else if strings.HasPrefix(pathReal, "/v1/completions") {
		relayMode = Completions
	} else if strings.HasPrefix(pathReal, "/v1/embeddings") {
		relayMode = Embeddings
	} else if strings.HasSuffix(pathReal, "embeddings") {
		relayMode = Embeddings
	} else if strings.HasPrefix(pathReal, "/v1/rerank") {
		relayMode = Rerank
	} else if strings.HasPrefix(pathReal, "/v1/moderations") {
		relayMode = Moderations
	} else if strings.HasPrefix(pathReal, "/v1/images/generations") {
		relayMode = ImagesGenerations
	} else if strings.HasPrefix(pathReal, "/v1/edits") {
		relayMode = Edits
	} else if strings.HasPrefix(pathReal, "/v1/audio/speech") {
		relayMode = AudioSpeech
	} else if strings.HasPrefix(pathReal, "/v1/audio/transcriptions") {
		relayMode = AudioTranscription
	} else if strings.HasPrefix(pathReal, "/v1/audio/translations") {
		relayMode = AudioTranslation
	} else if strings.HasPrefix(pathReal, "/v1/oneapi/proxy") {
		relayMode = Proxy
	} else if middleware.IsPaddleXAPI(pathReal) {
		relayMode = PaddleX
	}
	return relayMode
}
