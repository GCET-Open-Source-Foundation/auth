package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware verifies JWT from httpOnly cookie or Authorization header
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		// Try cookie first
		if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
			tokenStr = cookie
		} else {
			// fallback: Authorization header
			auth := c.GetHeader("Authorization")
			if auth == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
				c.Abort()
				return
			}
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
				c.Abort()
				return
			}
			tokenStr = parts[1]
		}

		userID, err := ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// store userID in context for handlers
		c.Set("currentUserID", userID)
		c.Next()
	}
}

// Helper to get current user ID in any handler
func GetCurrentUserID(c *gin.Context) (string, bool) {
	v, ok := c.Get("currentUserID")
	if !ok {
		return "", false
	}
	if id, ok := v.(string); ok {
		return id, true
	}
	return "", false
}
