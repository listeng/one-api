package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"one-api/common/config"
	"one-api/common/logger"
	"one-api/common/random"
	"one-api/model"
	"regexp"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// CASUserInfo 存储从CAS服务器获取的用户信息
type CASUserInfo struct {
	Uid         string
	Username    string
	DisplayName string
	UserType    string
	Roles       string
}

// validateCASTicket 验证CAS票据并返回用户信息
func validateCASTicket(ticket string, serviceURL string) (*CASUserInfo, error) {
	if !config.CASAuthEnabled {
		return nil, fmt.Errorf("CAS 登录未启用")
	}

	if ticket == "" {
		return nil, fmt.Errorf("没有票据")
	}

	// 构建验证URL
	validateURL := fmt.Sprintf("%s?ticket=%s&service=%s",
		config.CASValidateURL,
		url.QueryEscape(ticket),
		url.QueryEscape(serviceURL))

	logger.SysLog(fmt.Sprintf("开始CAS验证 - 票据: %s, 服务URL: %s, 验证URL: %s", ticket, serviceURL, validateURL))

	// 记录请求开始时间
	startTime := time.Now()

	// 创建带超时的HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second, // 设置30秒超时
	}

	// 发送验证请求
	resp, err := client.Get(validateURL)
	if err != nil {
		logger.SysError(fmt.Sprintf("CAS验证请求失败: %v", err))
		return nil, fmt.Errorf("CAS登录失败")
	}
	defer resp.Body.Close()

	// 记录响应时间
	responseTime := time.Since(startTime)
	logger.SysLog(fmt.Sprintf("CAS服务器响应时间: %v, 状态码: %d", responseTime, resp.StatusCode))

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.SysError(fmt.Sprintf("读取CAS服务器响应失败: %v", err))
		return nil, fmt.Errorf("读取CAS服务器响应失败")
	}

	bodyStr := string(body)
	logger.SysLog(fmt.Sprintf("CAS服务器响应内容: %s", bodyStr))

	// 检查是否认证成功
	if !strings.Contains(bodyStr, "cas:authenticationSuccess") {
		logger.SysError("CAS认证失败 - 响应中未找到authenticationSuccess标记")
		return nil, fmt.Errorf("CAS拒绝登录")
	}

	// 提取用户ID (cas:uid)
	re := regexp.MustCompile(`<cas:uid>(.*?)</cas:uid>`)
	uidMatch := re.FindStringSubmatch(bodyStr)
	if len(uidMatch) < 2 {
		logger.SysError("CAS响应中未找到用户ID (cas:uid)")
		return nil, fmt.Errorf("CAS没有返回用户ID")
	}
	uid := uidMatch[1]

	// 提取 <cas:user>
	re = regexp.MustCompile(`<cas:user>(.*?)</cas:user>`)
	userMatch := re.FindStringSubmatch(bodyStr)
	username := uid // 默认使用uid作为用户名
	if len(userMatch) >= 2 {
		username = userMatch[1]
	}

	// 提取显示名称 (cas:uname) 并进行URL解码
	re = regexp.MustCompile(`<cas:uname>(.*?)</cas:uname>`)
	unameMatch := re.FindStringSubmatch(bodyStr)
	displayName := uid // 默认使用uid作为显示名称
	if len(unameMatch) >= 2 {
		encodedName := unameMatch[1]
		// URL解码显示名称
		decodedName, err := url.QueryUnescape(encodedName)
		if err == nil {
			displayName = decodedName
		} else {
			logger.SysError(fmt.Sprintf("URL解码显示名称失败: %v", err))
			displayName = encodedName
		}
	}

	// 提取用户类型 (cas:utype)
	re = regexp.MustCompile(`<cas:utype>(.*?)</cas:utype>`)
	userTypeMatch := re.FindStringSubmatch(bodyStr)
	userType := "user" // 默认用户类型
	if len(userTypeMatch) >= 2 {
		userType = userTypeMatch[1]
	}

	// 提取用户角色 (cas:roles)
	re = regexp.MustCompile(`<cas:roles>(.*?)</cas:roles>`)
	userRolesMatch := re.FindStringSubmatch(bodyStr)
	roles := ""
	if len(userRolesMatch) >= 2 {
		roles = userRolesMatch[1]
		// URL解码角色字符串
		decodedRoles, err := url.QueryUnescape(roles)
		if err == nil {
			roles = decodedRoles
		}
	}

	logger.SysLog(fmt.Sprintf("CAS登录成功 - 用户ID: %s, 显示名称: %s, 类型: %s, 角色: %s", uid, displayName, userType, roles))

	return &CASUserInfo{
		Uid:         uid,
		Username:    username,
		DisplayName: displayName,
		UserType:    userType,
		Roles:       roles,
	}, nil
}

// CASAuth CAS认证处理函数
func CASAuth(c *gin.Context) {
	logger.SysLog(fmt.Sprintf("收到CAS认证请求 - 票据: %s, 服务URL: %s", c.Query("ticket"), c.Query("service")))

	if !config.CASAuthEnabled {
		logger.SysError("CAS认证未启用")
		html := `
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>管理员未开启通过 CAS 登录以及注册</p>
    <script>
      alert("管理员未开启通过 CAS 登录以及注册");
      window.location.href = '/';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	ticket := c.Query("ticket")
	serviceURL := c.Query("service")

	if ticket == "" {
		logger.SysError("CAS认证请求中缺少票据")
		html := `
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>没有票据</p>
    <script>
      alert("没有票据");
      window.location.href = '/';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 验证CAS票据
	logger.SysLog("开始验证CAS票据")

	// 如果serviceURL为空，使用callback URL作为默认值
	if serviceURL == "" {
		serviceURL = fmt.Sprintf("%s/api/oauth/cas", config.ServerAddress)
		logger.SysLog(fmt.Sprintf("serviceURL为空，使用默认callback URL: %s", serviceURL))
	}

	casUser, err := validateCASTicket(ticket, serviceURL)
	if err != nil {
		logger.SysError(fmt.Sprintf("CAS票据验证失败: %v", err))
		html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	logger.SysLog(fmt.Sprintf("CAS票据验证成功，用户ID: %s", casUser.Username))

	// 查找或创建用户
	user := model.User{
		CASId: casUser.Uid, // 使用uid作为CASId
	}

	if model.IsCASIdAlreadyTaken(user.CASId) {
		logger.SysLog(fmt.Sprintf("CAS用户已存在: %s", casUser.Username))
		// 用户已存在，获取用户信息
		err = user.FillUserByCASId()
		if err != nil {
			logger.SysError(fmt.Sprintf("获取CAS用户信息失败: %v", err))
			html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
			return
		}
	} else {
		logger.SysLog(fmt.Sprintf("CAS用户不存在，准备创建新用户: %s", casUser.Username))
		// 用户不存在，创建新用户
		if config.RegisterEnabled && config.CASCreateNewUser {
			user.CASId = casUser.Uid               // 使用uid作为用户名
			user.Username = casUser.Username       // 使用uid作为用户名
			user.DisplayName = casUser.DisplayName // 使用解码后的显示名称
			user.Role = model.RoleCommonUser
			user.Status = model.UserStatusEnabled

			// 根据用户类型设置角色
			if casUser.UserType == "admin" || casUser.UserType == "super" {
				user.Role = model.RoleAdminUser
			}

			// 根据角色设置管理员权限
			if config.CASAdminRole != "" && casUser.Roles != "" {
				roles := strings.Split(casUser.Roles, ",")
				for _, role := range roles {
					if strings.TrimSpace(role) == config.CASAdminRole {
						user.Role = model.RoleAdminUser
						break
					}
				}
			}

			// 生成随机密码
			user.Password = random.GetRandomString(32)

			if err := user.Insert(0); err != nil {
				logger.SysError(fmt.Sprintf("创建CAS用户失败: %v", err))
				html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
				c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
				return
			}
			logger.SysLog(fmt.Sprintf("成功创建CAS用户: %s", user.Username))
		} else {
			logger.SysError("管理员关闭了新用户注册")
			html := `
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>管理员关闭了新用户注册</p>
    <script>
      alert("管理员关闭了新用户注册");
      window.location.href = '/';
    </script>
  </body>
</html>
`
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
			return
		}
	}

	// 检查用户状态
	if user.Status != model.UserStatusEnabled {
		logger.SysError(fmt.Sprintf("CAS用户已被封禁: %s", user.Username))
		html := `
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>用户已被封禁</p>
    <script>
      alert("用户已被封禁");
      window.location.href = '/';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	logger.SysLog(fmt.Sprintf("CAS认证成功，设置用户登录会话: %s", user.Username))

	// 设置登录会话
	session := sessions.Default(c)
	session.Set("id", user.Id)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("status", user.Status)
	err = session.Save()
	if err != nil {
		html := `
<html>
  <body>
    <h1>CAS认证失败</h1>
    <p>无法保存会话信息，请重试</p>
    <script>
      alert("无法保存会话信息，请重试");
      window.location.href = '/';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 添加调试日志
	logger.SysLog(fmt.Sprintf("CAS认证成功，用户: %s, 会话已设置", user.Username))
	logger.SysLog(fmt.Sprintf("响应头信息: %v", c.Writer.Header()))

	// 正确处理user.Id为int类型，避免类型不匹配
	html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS认证成功</h1>
    <script>
      let data = {
        id: %d,
        username: '%s',
        role: '%d',
        status: '%d'
      };
      localStorage.setItem('user', JSON.stringify(data));
      window.location.href = '/';
    </script>
  </body>
</html>
`, user.Id, user.Username, user.Role, user.Status)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// CASBind CAS账户绑定
func CASBind(c *gin.Context) {
	if !config.CASAuthEnabled {
		html := `
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>管理员未开启通过 CAS 登录以及注册</p>
    <script>
      alert("管理员未开启通过 CAS 登录以及注册");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	ticket := c.Query("ticket")
	serviceURL := c.Query("service")

	if ticket == "" {
		html := `
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>没有票据</p>
    <script>
      alert("没有票据");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 验证CAS票据

	// 如果serviceURL为空，使用callback URL作为默认值
	if serviceURL == "" {
		serviceURL = fmt.Sprintf("%s/api/oauth/cas/bind", config.ServerAddress)
		logger.SysLog(fmt.Sprintf("serviceURL为空，使用默认callback URL: %s", serviceURL))
	}

	casUser, err := validateCASTicket(ticket, serviceURL)
	if err != nil {
		html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 检查CAS账户是否已被绑定
	if model.IsCASIdAlreadyTaken(casUser.Uid) {
		html := `
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>该 CAS 账户已被绑定</p>
    <script>
      alert("该 CAS 账户已被绑定");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 获取当前登录用户
	session := sessions.Default(c)
	id := session.Get("id")
	if id == nil {
		html := `
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>请先登录</p>
    <script>
      alert("请先登录");
      window.location.href = '/login';
    </script>
  </body>
</html>
`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	user := model.User{Id: id.(int)}
	err = user.FillUserById()
	if err != nil {
		html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 绑定CAS账户
	user.CASId = casUser.Uid
	err = user.Update(false)
	if err != nil {
		html := fmt.Sprintf(`
<html>
  <body>
    <h1>CAS绑定失败</h1>
    <p>%s</p>
    <script>
      alert("%s");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`, err.Error(), err.Error())
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
		return
	}

	// 绑定成功
	html := `
<html>
  <body>
    <h1>CAS绑定成功</h1>
    <p>CAS账户绑定成功！</p>
    <script>
      alert("CAS账户绑定成功！");
      window.location.href = '/setting';
    </script>
  </body>
</html>
`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// GenerateCASLoginURL 生成CAS登录URL
func GenerateCASLoginURL(c *gin.Context) {
	if !config.CASAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "CAS登录未启用",
		})
		return
	}

	// 生成state参数防止CSRF攻击
	state := random.GetRandomString(16)
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Save()

	// 构建CAS登录URL
	serviceURL := fmt.Sprintf("%s/api/oauth/cas", config.ServerAddress)
	loginURL := fmt.Sprintf("%s?service=%s&state=%s",
		config.CASLoginURL,
		url.QueryEscape(serviceURL),
		state)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    loginURL,
	})
}
