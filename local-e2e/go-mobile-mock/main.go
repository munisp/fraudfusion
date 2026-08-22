package main

import (
  "crypto/rand"
  "crypto/subtle"
  "encoding/hex"
  "encoding/json"
  "log"
  "net/http"
  "os"
  "strings"
  "time"
)

type statusRecorder struct {
  http.ResponseWriter
  status int
}

func (w *statusRecorder) WriteHeader(status int) {
  w.status = status
  w.ResponseWriter.WriteHeader(status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(status)
  _ = json.NewEncoder(w).Encode(value)
}

func newRequestID() string {
  bytes := make([]byte, 16)
  if _, err := rand.Read(bytes); err != nil {
    return "unavailable"
  }
  return hex.EncodeToString(bytes)
}

func withRequestLog(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    requestID := r.Header.Get("X-Request-ID")
    if requestID == "" {
      requestID = newRequestID()
    }
    w.Header().Set("X-Request-ID", requestID)
    recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
    started := time.Now()
    next.ServeHTTP(recorder, r)
    log.Printf(`{"event":"http_request","request_id":%q,"method":%q,"path":%q,"status":%d,"duration_ms":%d}`,
      requestID, r.Method, r.URL.Path, recorder.status, time.Since(started).Milliseconds())
  })
}

func requireLocalBearer(expectedToken string, next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    valid := len(provided) == len(expectedToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(expectedToken)) == 1
    if !valid {
      writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "local contract bearer token required"})
      return
    }
    next(w, r)
  }
}

func main() {
  expectedToken := os.Getenv("LOCAL_E2E_TOKEN")
  if expectedToken == "" {
    log.Fatal("LOCAL_E2E_TOKEN must be configured for the local contract server")
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]string{"status": "ok"}) })
  mux.HandleFunc("/api/v1/auth/me", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"id": "staging-user", "name": "Staging User", "notificationEnabled": true, "biometricEnabled": true}) }))
  mux.HandleFunc("/api/v1/mobile/dashboard", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"openCases": 1, "pendingKyc": 1, "unreadNotifications": 2, "riskLevel": "low"}) }))
  mux.HandleFunc("/api/v1/notifications", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, []map[string]any{{"id": "notice-1", "title": "Contract notification", "body": "Delivered by local Go mock", "createdAt": time.Now().UTC().Format(time.RFC3339)}}) }))
  mux.HandleFunc("/api/v1/mobile/fraud-alerts", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, []map[string]any{{"id": "alert-1", "title": "Contract alert", "severity": "high", "status": "open", "createdAt": time.Now().UTC().Format(time.RFC3339)}}) }))
  mux.HandleFunc("/api/v1/documents", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, []map[string]any{{"id": "doc-1", "name": "passport", "type": "passport", "status": "verified", "createdAt": time.Now().UTC().Format(time.RFC3339)}}) }))
  mux.HandleFunc("/api/v1/kyc/sessions", requireLocalBearer(expectedToken, func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
      writeJSON(w, http.StatusCreated, map[string]any{"id": "kyc-1", "status": "created", "updatedAt": time.Now().UTC().Format(time.RFC3339)})
      return
    }
    writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
  }))
  log.Fatal(http.ListenAndServe(":8080", withRequestLog(mux)))
}
