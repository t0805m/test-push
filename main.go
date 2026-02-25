package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
)

// DeviceStats хранит статистику по устройству
type DeviceStats struct {
	DeviceToken    string    `json:"device_token"`
	SilentSent     int       `json:"silent_sent"`      // отправлено silent
	AlertSent      int       `json:"alert_sent"`       // отправлено alert
	Confirmed      int       `json:"confirmed"`        // получено подтверждений
	LastSilentSent time.Time `json:"last_silent_sent"` // время последнего silent
	LastAlertSent  time.Time `json:"last_alert_sent"`  // время последнего alert
	LastConfirmed  time.Time `json:"last_confirmed"`   // время последнего подтверждения
}

// Хранилище статистики
var (
	statsMap = make(map[string]*DeviceStats)
	mu       sync.RWMutex
)

// updateSentStats обновляет счётчик отправок в зависимости от типа
func updateSentStats(token, pushType string) {
	mu.Lock()
	defer mu.Unlock()
	stats, exists := statsMap[token]
	if !exists {
		stats = &DeviceStats{DeviceToken: token}
		statsMap[token] = stats
	}
	now := time.Now()
	switch pushType {
	case "silent":
		stats.SilentSent++
		stats.LastSilentSent = now
	case "alert":
		stats.AlertSent++
		stats.LastAlertSent = now
	}
}

// updateConfirmStats обновляет счётчик подтверждений
func updateConfirmStats(token string) {
	mu.Lock()
	defer mu.Unlock()
	stats, exists := statsMap[token]
	if !exists {
		stats = &DeviceStats{DeviceToken: token}
		statsMap[token] = stats
	}
	stats.Confirmed++
	stats.LastConfirmed = time.Now()
}

// getConfirmations возвращает список подтверждений (для обратной совместимости)
func getConfirmations() []map[string]interface{} {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]map[string]interface{}, 0, len(statsMap))
	for _, s := range statsMap {
		if s.Confirmed > 0 {
			list = append(list, map[string]interface{}{
				"device_token": s.DeviceToken,
				"count":        s.Confirmed,
				"last_seen":    s.LastConfirmed,
			})
		}
	}
	return list
}

// getAllStats возвращает полную статистику
func getAllStats() []*DeviceStats {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]*DeviceStats, 0, len(statsMap))
	for _, s := range statsMap {
		list = append(list, s)
	}
	return list
}

func main() {
	// Загружаем конфигурацию из переменных окружения
	certBase64 := os.Getenv("APNS_CERT_BASE64")
	certPassword := os.Getenv("APNS_CERT_PASSWORD")
	bundleID := os.Getenv("APNS_TOPIC")
	env := os.Getenv("APNS_ENVIRONMENT")
	authKey := os.Getenv("AUTH_KEY")
	deviceTokensStr := os.Getenv("DEVICE_TOKENS")
	enablePeriodic := os.Getenv("ENABLE_PERIODIC_SEND") == "true"

	if certBase64 == "" || certPassword == "" || bundleID == "" || env == "" {
		log.Fatal("Не все обязательные переменные окружения установлены: нужны APNS_CERT_BASE64, APNS_CERT_PASSWORD, APNS_TOPIC, APNS_ENVIRONMENT")
	}

	// Декодируем сертификат из base64
	certData, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		log.Fatalf("Ошибка декодирования сертификата: %v", err)
	}

	// Загружаем сертификат p12
	cert, err := certificate.FromP12Bytes(certData, certPassword)
	if err != nil {
		log.Fatalf("Ошибка загрузки сертификата: %v", err)
	}

	// Создаём клиент APNs с нужным окружением
	client := apns2.NewClient(cert)
	if env == "production" {
		client = client.Production()
	} else {
		client = client.Development()
	}

	// Разбираем device tokens для периодической отправки
	var periodicTokens []string
	if enablePeriodic {
		if deviceTokensStr == "" {
			log.Fatal("ENABLE_PERIODIC_SEND=true, но DEVICE_TOKENS не задан")
		}
		for _, t := range strings.Split(deviceTokensStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				periodicTokens = append(periodicTokens, t)
			}
		}
		if len(periodicTokens) == 0 {
			log.Fatal("DEVICE_TOKENS не содержит ни одного токена")
		}
		log.Printf("Загружено %d device token'ов для периодической отправки", len(periodicTokens))
	}

	// Запускаем периодическую отправку, если включено
	if enablePeriodic {
		startPeriodicSend(client, bundleID, periodicTokens)
	}

	http.HandleFunc("/test-latency", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Эндпоинт для отправки silent push на один device token
	http.HandleFunc("/send-silent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			DeviceToken string `json:"device_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.DeviceToken == "" {
			http.Error(w, "device_token is required", http.StatusBadRequest)
			return
		}

		pl := payload.NewPayload().ContentAvailable()
		notification := &apns2.Notification{
			DeviceToken: req.DeviceToken,
			Topic:       bundleID,
			Priority:    apns2.PriorityLow,
			PushType:    apns2.PushTypeBackground,
			Payload:     pl,
			Expiration:  time.Now().Add(24 * time.Hour),
		}

		resp, err := client.Push(notification)
		result := make(map[string]string)
		if err != nil {
			result["status"] = "error"
			result["reason"] = err.Error()
			log.Printf("Ошибка отправки для %s: %v", req.DeviceToken, err)
		} else if resp.StatusCode == 200 {
			result["status"] = "success"
			log.Printf("Успешно отправлено на %s", req.DeviceToken)
			updateSentStats(req.DeviceToken, "silent")
		} else {
			result["status"] = "apns_error"
			result["reason"] = resp.Reason
			log.Printf("Ошибка APNs для %s: %s", req.DeviceToken, resp.Reason)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Эндпоинт для отправки обычного push
	http.HandleFunc("/send-simple", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			DeviceToken string `json:"device_token"`
			Title       string `json:"title"`
			Body        string `json:"body"`
			Sound       string `json:"sound"`
			Badge       int    `json:"badge"`
			Category    string `json:"category"`
			ThreadID    string `json:"thread_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.DeviceToken == "" {
			http.Error(w, "device_token is required", http.StatusBadRequest)
			return
		}
		if req.Title == "" && req.Body == "" {
			http.Error(w, "either title or body must be provided", http.StatusBadRequest)
			return
		}

		pl := payload.NewPayload().AlertTitle(req.Title).AlertBody(req.Body)
		if req.Sound != "" {
			pl.Sound(req.Sound)
		} else {
			pl.Sound("default")
		}
		if req.Badge > 0 {
			pl.Badge(req.Badge)
		}
		if req.Category != "" {
			pl.Category(req.Category)
		}
		if req.ThreadID != "" {
			pl.ThreadID(req.ThreadID)
		}

		notification := &apns2.Notification{
			DeviceToken: req.DeviceToken,
			Topic:       bundleID,
			PushType:    apns2.PushTypeAlert,
			Payload:     pl,
			Expiration:  time.Now().Add(24 * time.Hour),
		}

		resp, err := client.Push(notification)
		result := make(map[string]string)
		if err != nil {
			result["status"] = "error"
			result["reason"] = err.Error()
			log.Printf("Ошибка отправки обычного пуша для %s: %v", req.DeviceToken, err)
		} else if resp.StatusCode == 200 {
			result["status"] = "success"
			log.Printf("Успешно отправлен обычный пуш на %s", req.DeviceToken)
			updateSentStats(req.DeviceToken, "alert")
		} else {
			result["status"] = "apns_error"
			result["reason"] = resp.Reason
			log.Printf("Ошибка APNs для обычного пуша на %s: %s", req.DeviceToken, resp.Reason)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Эндпоинт для подтверждения получения пуша от устройства
	http.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			DeviceToken string `json:"device_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.DeviceToken == "" {
			http.Error(w, "device_token is required", http.StatusBadRequest)
			return
		}

		updateConfirmStats(req.DeviceToken)
		log.Printf("Получено подтверждение от устройства %s", req.DeviceToken)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"confirmed"}`))
	})

	// Эндпоинт для просмотра только подтверждений (как раньше)
	http.HandleFunc("/confirmations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		list := getConfirmations()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	// Эндпоинт для полной статистики
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		list := getAllStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	// Health check
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("PORT не задан, используется порт по умолчанию: %s", port)
	}

	log.Printf("Сервер запущен на порту %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// startPeriodicSend запускает горутину, которая отправляет silent push по списку токенов каждые 15 минут.
func startPeriodicSend(client *apns2.Client, bundleID string, tokens []string) {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		// Сразу выполняем первую отправку при старте
		sendPeriodic(client, bundleID, tokens)
		for range ticker.C {
			sendPeriodic(client, bundleID, tokens)
		}
	}()
	log.Println("Запущена периодическая отправка silent push каждые 15 минут")
}

// sendPeriodic выполняет отправку silent push по всем токенам и обновляет статистику.
func sendPeriodic(client *apns2.Client, bundleID string, tokens []string) {
	log.Println("Начинаем периодическую отправку silent push...")
	pl := payload.NewPayload().ContentAvailable()
	notification := &apns2.Notification{
		Topic:      bundleID,
		Priority:   apns2.PriorityLow,
		PushType:   apns2.PushTypeBackground,
		Payload:    pl,
		Expiration: time.Now().Add(24 * time.Hour),
	}

	for _, token := range tokens {
		notification.DeviceToken = token
		resp, err := client.Push(notification)
		if err != nil {
			log.Printf("Периодическая отправка: ошибка для %s: %v", token, err)
		} else if resp.StatusCode == 200 {
			log.Printf("Периодическая отправка: успешно на %s", token)
			updateSentStats(token, "silent")
		} else {
			log.Printf("Периодическая отправка: APNs ошибка для %s: %s", token, resp.Reason)
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Println("Периодическая отправка завершена")
}