package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/example/clean-script-go/internal/config"
	"github.com/example/clean-script-go/internal/fileops"
	"github.com/example/clean-script-go/internal/manager"
	"github.com/example/clean-script-go/internal/model"
	"github.com/example/clean-script-go/internal/scanner"
	"github.com/example/clean-script-go/internal/scheduler"
	webassets "github.com/example/clean-script-go/web"
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewHandler),
	fx.Provide(NewRouter),
	fx.Invoke(RegisterServer),
)

type Handler struct {
	cfg     config.AppConfig
	manager *manager.Manager
	sched   *scheduler.Service
	scanner *scanner.Service
	fileops *fileops.Service
}

func NewHandler(cfg config.AppConfig, manager *manager.Manager, sched *scheduler.Service, scanner *scanner.Service, fileops *fileops.Service) *Handler {
	return &Handler{
		cfg:     cfg,
		manager: manager,
		sched:   sched,
		scanner: scanner,
		fileops: fileops,
	}
}

func NewRouter(cfg config.AppConfig, handler *Handler) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(corsMiddleware(cfg.Web.AllowOrigins))

	router.GET("/", handler.index)
	router.GET("/app.js", handler.appJS)
	router.GET("/style.css", handler.styleCSS)
	router.GET("/api/config", handler.apiConfig)
	router.POST("/api/scan", handler.apiScan)
	router.GET("/api/scan/stream", handler.apiScanStream)
	router.POST("/api/delete-401", handler.apiDelete401)
	router.GET("/api/status", handler.apiStatus)

	return router
}

func RegisterServer(lc fx.Lifecycle, cfg config.AppConfig, router *gin.Engine) {
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port),
		Handler:           router,
		ReadTimeout:       time.Duration(cfg.App.ReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(cfg.App.WriteTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Printf("http server stopped with error: %v\n", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return server.Shutdown(ctx)
		},
	})
}

func (h *Handler) index(c *gin.Context) {
	h.serveAsset(c, "index.html", "text/html; charset=utf-8")
}

func (h *Handler) appJS(c *gin.Context) {
	h.serveAsset(c, "app.js", "application/javascript; charset=utf-8")
}

func (h *Handler) styleCSS(c *gin.Context) {
	h.serveAsset(c, "style.css", "text/css; charset=utf-8")
}

func (h *Handler) apiConfig(c *gin.Context) {
	c.JSON(http.StatusOK, config.DefaultsResponse(h.cfg))
}

func (h *Handler) apiScan(c *gin.Context) {
	var req model.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	options, err := config.BuildScanOptions(h.cfg, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.manager.StartScan(options, func(ctx context.Context, publish func(model.ProgressEvent)) (model.ScanFinalEvent, error) {
		return h.scanner.Scan(ctx, options, publish)
	})
	if err != nil {
		if errors.Is(err, manager.ErrScanAlreadyRunning) {
			c.JSON(http.StatusConflict, gin.H{"detail": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "status": "started"})
}

func (h *Handler) apiScanStream(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	if message, ok := h.manager.LastResult(); ok {
		if !h.manager.Snapshot().Running {
			_ = writeSSE(c.Writer, message.Payload)
			return
		}
	}

	subscriber := h.manager.Subscribe()
	defer h.manager.Unsubscribe(subscriber)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.String(http.StatusInternalServerError, "streaming unsupported")
		return
	}

	pingTicker := time.NewTicker(15 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-pingTicker.C:
			if _, err := io.WriteString(c.Writer, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case message, ok := <-subscriber:
			if !ok {
				return
			}
			if err := writeSSE(c.Writer, message.Payload); err != nil {
				return
			}
			flusher.Flush()
			if message.Terminal {
				return
			}
		}
	}
}

func (h *Handler) apiDelete401(c *gin.Context) {
	var req model.Delete401Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	defaultOptions, err := config.BuildScanOptions(h.cfg, model.ScanRequest{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	deletedFiles, deleteErrors := h.fileops.DeleteFiles(req.Files, h.manager.AllowedRoots(defaultOptions.AuthDir, defaultOptions.ExceededDir))
	c.JSON(http.StatusOK, gin.H{
		"deleted_count": len(deletedFiles),
		"deleted_files": deletedFiles,
		"errors":        deleteErrors,
	})
}

func (h *Handler) apiStatus(c *gin.Context) {
	snapshot := h.manager.Snapshot()
	c.JSON(http.StatusOK, model.StatusResponse{
		Running:      snapshot.Running,
		HasResult:    snapshot.HasResult,
		LastResultAt: snapshot.LastResultAt,
		Schedule:     h.sched.Status(),
	})
}

func (h *Handler) serveAsset(c *gin.Context, name, contentType string) {
	asset, err := webassets.FS.ReadFile(name)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.Data(http.StatusOK, contentType, asset)
}

func writeSSE(writer io.Writer, payload []byte) error {
	if _, err := writer.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	_, err := writer.Write([]byte("\n\n"))
	return err
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	normalized := make([]string, 0, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			normalized = append(normalized, origin)
		}
	}
	if len(normalized) == 0 {
		normalized = []string{"*"}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if len(normalized) == 1 && normalized[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" && slices.Contains(normalized, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Accept")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
