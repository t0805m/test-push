package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
)

type Confirmation struct {
	DeviceToken string    `json:"device_token"`
	ReceivedAt  time.Time `json:"received_at"`
}

var (
	confirmations = make(map[string]Confirmation)
	mu            sync.RWMutex
)

func main() {
	certBase64 := os.Getenv("APNS_CERT_BASE64")
	certPassword := os.Getenv("APNS_CERT_PASSWORD")
	bundleID := os.Getenv("APNS_TOPIC")
	env := os.Getenv("APNS_ENVIRONMENT")
	authKey := os.Getenv("AUTH_KEY")

	if certBase64 == "" || certPassword == "" || bundleID == "" || env == "" {
		log.Fatal("Не все обязательные переменные окружения установлены: нужны APNS_CERT_BASE64, APNS_CERT_PASSWORD, APNS_TOPIC, APNS_ENVIRONMENT")
	}

	certData, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		log.Fatalf("Ошибка декодирования сертификата: %v", err)
	}

	cert, err := certificate.FromP12Bytes(certData, certPassword)
	if err != nil {
		log.Fatalf("Ошибка загрузки сертификата: %v", err)
	}

	client := apns2.NewClient(cert)
	if env == "production" {
		client = client.Production()
	} else {
		client = client.Development()
	}

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
		confirmations[req.DeviceToken] = Confirmation{
			DeviceToken: req.DeviceToken,
			ReceivedAt:  time.Now(),
		}
		mu.Unlock()

		log.Printf("Получено подтверждение от устройства %s", req.DeviceToken)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"confirmed"}`))
	})

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
		list := make([]Confirmation, 0, len(confirmations))
		for _, conf := range confirmations {
			list = append(list, conf)
		}
		mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

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