package router

import (
	"embed"
	"fmt"
	"net/http"
	"one-api/common/config"
	"one-api/common/logger"
	"one-api/controller"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func SetRouter(router *gin.Engine, buildFS embed.FS) {
	// 创建带前缀的路由组
	var apiGroup, dashboardGroup, relayGroup, webGroup *gin.RouterGroup

	if config.BasePath != "" {
		// 如果有路径前缀，创建带前缀的路由组
		baseGroup := router.Group(config.BasePath)
		apiGroup = baseGroup.Group("/api")
		dashboardGroup = baseGroup.Group("/")
		relayGroup = baseGroup.Group("/v1")
		webGroup = baseGroup.Group("/")
	} else {
		// 没有路径前缀，使用默认路由
		apiGroup = router.Group("/api")
		dashboardGroup = router.Group("/")
		relayGroup = router.Group("/v1")
		webGroup = router.Group("/")
	}

	SetApiRouter(apiGroup)
	SetDashboardRouter(dashboardGroup)
	SetRelayRouter(relayGroup)

	frontendBaseUrl := os.Getenv("FRONTEND_BASE_URL")
	if config.IsMasterNode && frontendBaseUrl != "" {
		frontendBaseUrl = ""
		logger.SysLog("FRONTEND_BASE_URL is ignored on master node")
	}
	if frontendBaseUrl == "" {
		SetWebRouter(webGroup, buildFS)
		// 处理 NoRoute，包括前端页面和 API 路由
		router.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path

			// 检查是否是 API 或 v1 路由
			if strings.HasPrefix(path, "/v1") || strings.HasPrefix(path, "/api") {
				// 如果有路径前缀，需要检查带前缀的路径
				if config.BasePath != "" {
					prefixedPath := config.BasePath + path
					if strings.HasPrefix(prefixedPath, config.BasePath+"/v1") || strings.HasPrefix(prefixedPath, config.BasePath+"/api") {
						controller.RelayNotFound(c)
						return
					}
				} else {
					controller.RelayNotFound(c)
					return
				}
			}

			// 检查是否是带前缀的 API 或 v1 路由
			if config.BasePath != "" {
				basePath := "/" + strings.Trim(config.BasePath, "/")
				if strings.HasPrefix(path, basePath+"/v1") || strings.HasPrefix(path, basePath+"/api") {
					controller.RelayNotFound(c)
					return
				}

				// 检查是否是带前缀的静态文件请求
				if strings.HasPrefix(path, basePath+"/") {
					// 去掉前缀后的路径
					staticPath := strings.TrimPrefix(path, basePath)

					// 检查是否是静态文件（通过文件扩展名判断）
					ext := filepath.Ext(staticPath)
					if isStaticFile(ext) {
						// 尝试从嵌入的文件系统中读取静态文件
						filePath := fmt.Sprintf("web/build/%s%s", config.Theme, staticPath)
						if data, err := buildFS.ReadFile(filePath); err == nil {
							contentType := getContentType(ext)
							c.Header("Cache-Control", "public, max-age=86400") // 24小时缓存
							c.Data(http.StatusOK, contentType, data)
							return
						}
					}
				}
			}

			// 对于其他所有请求，返回前端页面
			indexPageData, _ := buildFS.ReadFile(fmt.Sprintf("web/build/%s/index.html", config.Theme))
			c.Header("Cache-Control", "no-cache")
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexPageData)
		})
	} else {
		frontendBaseUrl = strings.TrimSuffix(frontendBaseUrl, "/")
		router.NoRoute(func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("%s%s", frontendBaseUrl, c.Request.RequestURI))
		})
	}
}

// 判断是否是静态文件
func isStaticFile(ext string) bool {
	staticExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".json"}
	for _, staticExt := range staticExts {
		if ext == staticExt {
			return true
		}
	}
	return false
}

// 根据文件扩展名获取 Content-Type
func getContentType(ext string) string {
	switch ext {
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	case ".map":
		return "application/json"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}
