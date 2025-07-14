package cohere

var ModelList = []string{
	"command", "command-nightly",
	"command-light", "command-light-nightly",
	"command-r", "command-r-plus",
	"rerank-english-v2.0", "rerank-multilingual-v2.0",
}

func init() {
	num := len(ModelList)
	for i := 0; i < num; i++ {
		ModelList = append(ModelList, ModelList[i]+"-internet")
	}
}
