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

// Структура для хранения подтверждения со счётчиком
type Confirmation struct {
	DeviceToken string    `json:"device_token"`
	Count       int       `json:"count"`       // сколько раз подтвердил
	LastSeen    time.Time `json:"last_seen"`   // время последнего подтверждения
}

// Хранилище подтверждений в памяти
var (
	confirmations = make(map[string]*Confirmation) // храним указатель для удобства обновления
	mu            sync.RWMutex
)

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

	// Эндпоинт для отправки silent push на один device token
	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
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

		mu.Lock()
		// Ищем существующую запись
		if conf, ok := confirmations[req.DeviceToken]; ok {
			conf.Count++
			conf.LastSeen = time.Now()
		} else {
			// Создаём новую
			confirmations[req.DeviceToken] = &Confirmation{
				DeviceToken: req.DeviceToken,
				Count:       1,
				LastSeen:    time.Now(),
			}
		}
		mu.Unlock()

		log.Printf("Получено подтверждение от устройства %s", req.DeviceToken)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"confirmed"}`))
	})

	// Эндпоинт для просмотра всех подтверждений со счётчиками
	http.HandleFunc("/confirmations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if authKey != "" && r.Header.Get("Authorization") != "Bearer "+authKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		mu.RLock()
		list := make([]*Confirmation, 0, len(confirmations))
		for _, conf := range confirmations {
			list = append(list, conf)
		}
		mu.RUnlock()

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

// sendPeriodic выполняет отправку silent push по всем токенам.
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
		} else {
			log.Printf("Периодическая отправка: APNs ошибка для %s: %s", token, resp.Reason)
		}
		// Небольшая задержка, чтобы не флудить APNs
		time.Sleep(100 * time.Millisecond)
	}
	log.Println("Периодическая отправка завершена")
}