package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/handler"
	"github.com/ankitsingh015/HuntMCP/backend/internal/middleware"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
	"github.com/ankitsingh015/HuntMCP/backend/internal/service"
)

func main() {
	db, err := repository.NewDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.RunMigrations(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	writeupRepo := repository.NewWriteupRepository(db)
	huntRepo := repository.NewHuntRepository(db)
	authService := service.NewAuthService(db)

	healthHandler := handler.NewHealthHandler(db)
	writeupHandler := handler.NewWriteupHandler(writeupRepo)
	huntHandler := handler.NewHuntHandler(huntRepo)
	authHandler := handler.NewAuthHandler(authService)
	mcpHandler := handler.NewMCPHandler(writeupRepo, huntRepo)

	rateLimiter := middleware.NewDefaultRateLimiter()
	cors := middleware.CORSMiddleware()

	router := gin.Default()
	router.Use(cors)
	router.Use(rateLimiter.Middleware())

	router.GET("/health", healthHandler.Health)
	router.GET("/", healthHandler.Health)

	api := router.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(authService))
		{
			protected.GET("/writeups", writeupHandler.List)
			protected.GET("/writeups/:id", writeupHandler.GetByID)
			protected.POST("/writeups", writeupHandler.Create)
			protected.PUT("/writeups/:id", writeupHandler.Update)
			protected.DELETE("/writeups/:id", writeupHandler.Delete)
			protected.POST("/writeups/batch", writeupHandler.BatchCreate)
			protected.POST("/query", writeupHandler.QueryRAG)

			protected.GET("/hunts/recall", huntHandler.Recall)
			protected.GET("/hunts", huntHandler.ListByUser)
			protected.POST("/hunts", huntHandler.Save)
			protected.POST("/hunts/search", huntHandler.SearchByTech)
			protected.DELETE("/hunts/:id", huntHandler.Delete)
			protected.GET("/stats", huntHandler.Stats)
		}

		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(authService))
		admin.Use(middleware.AdminMiddleware())
		{
			admin.GET("/users", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "admin endpoint"})
			})
		}
	}

	router.POST("/mcp", mcpHandler.ServeMCP)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("HuntMCP API server starting on :%s", port)
	log.Printf("  Endpoints:")
	log.Printf("    GET  /health")
	log.Printf("    POST /api/v1/auth/register")
	log.Printf("    POST /api/v1/auth/login")
	log.Printf("    GET  /api/v1/writeups")
	log.Printf("    POST /api/v1/writeups")
	log.Printf("    POST /api/v1/query")
	log.Printf("    POST /api/v1/hunts")
	log.Printf("    POST /mcp")

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
