package router

import (
	"embed"
	"fmt"
	"one-api/common"
	"one-api/common/config"
	"one-api/middleware"
	"os"
	"path/filepath"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

func SetWebRouter(router *gin.RouterGroup, buildFS embed.FS) {
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	//router.Use(middleware.GlobalWebRateLimit())
	router.Use(middleware.Cache())

	// 静态文件服务配置
	// 由于 webGroup 已经包含了 BasePath 前缀，所以这里使用根路径即可
	router.Use(static.Serve("/", common.EmbedFolder(buildFS, fmt.Sprintf("web/build/%s", config.Theme))))

	// 添加静态文件服务
	if config.PublicDir != "" {
		// 检查目录是否存在
		if _, err := os.Stat(config.PublicDir); err == nil {
			// 使用绝对路径
			absPath, err := filepath.Abs(config.PublicDir)
			if err == nil {
				router.Use(static.Serve("/public", static.LocalFile(absPath, false)))
			}
		}
	}
}
