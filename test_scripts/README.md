# Test Scripts for ActiveDirectoryMCP

Bu klasörde ActiveDirectoryMCP sunucusunu test etmek için çeşitli scriptler bulunmaktadır.

## 📋 Mevcut Test Scriptleri

### 🌐 test_http_server.py

HTTP transport üzerinden ActiveDirectoryMCP sunucusunu test eden kapsamlı script.

**Kullanım:**
```bash
# Varsayılan URL ile test (http://localhost:8813/activedirectory-mcp)
python test_http_server.py

# Özel URL ile test
python test_http_server.py http://your-server:8813/activedirectory-mcp
```

**Test Edilen Özellikler:**
- ✅ Sunucu sağlık kontrolü
- ✅ LDAP bağlantı testi
- ✅ Schema bilgisi alma
- ✅ Kullanıcı listeleme
- ✅ Grup listeleme
- ✅ Bilgisayar listeleme
- ✅ Domain bilgisi alma
- ✅ Ayrıcalıklı grup analizi
- ✅ Admin hesap denetimi
- ✅ Hata yönetimi

**Örnek Çıktı:**
```
🔧 ActiveDirectoryMCP HTTP Server Test Script
============================================================
🌐 Testing server at: http://localhost:8813/activedirectory-mcp

🔍 Checking server availability...
✅ Server is available!

🚀 Testing Basic Operations
============================================================
🔍 Health Check
============================================================
✅ Success
{
  "status": "ok",
  "server": "ActiveDirectoryMCP-HTTP",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "ldap_connection": "connected"
}
```

## 🚀 Test Scriptlerini Çalıştırma

### Önkoşullar

1. **ActiveDirectoryMCP sunucusunun çalışıyor olması:**
   ```bash
   # Docker Compose ile
   docker compose up -d
   
   # Veya manuel olarak
   ./start_http_server.sh
   ```

2. **Python bağımlılıklarının yüklü olması:**
   ```bash
   pip install requests
   ```

3. **Active Directory bağlantısının yapılandırılmış olması:**
   - `ad-config/config.json` dosyasının doğru şekilde yapılandırılmış olması
   - LDAP sunucusuna erişim izni

### Test Senaryoları

#### 🟢 Temel Fonksiyonellik Testi
```bash
python test_http_server.py
```

#### 🟡 Farklı Sunucu Testi
```bash
python test_http_server.py http://production-server:8813/activedirectory-mcp
```

#### 🔴 Hata Durumu Testi
```bash
# Sunucu kapalıyken test et
docker compose down
python test_http_server.py
```

## 📊 Test Çıktılarını Anlama

### ✅ Başarılı Test
- `✅ Success` ile başlayan çıktılar
- JSON formatında detaylı yanıt
- HTTP 200 durum kodu

### ❌ Başarısız Test
- `❌ Error` ile başlayan çıktılar
- Hata mesajı ve açıklama
- HTTP hata kodları

### 🔍 Test Kategorileri

1. **Temel İşlemler**
   - Sağlık kontrolü
   - Bağlantı testi
   - Schema bilgisi

2. **Dizin İşlemleri**
   - Kullanıcı listeleme
   - Grup listeleme
   - Bilgisayar listeleme

3. **Güvenlik İşlemleri**
   - Domain analizi
   - Ayrıcalıklı grup kontrolü
   - Admin denetimi

4. **Hata Yönetimi**
   - Geçersiz metod testleri
   - Hatalı parametre testleri

## 🔧 Test Scriptlerini Özelleştirme

### Yeni Test Ekleme

Test script'e yeni test eklemek için:

1. `ActiveDirectoryMCPClient` sınıfına yeni metod ekleyin:
   ```python
   def my_custom_test(self, param: str) -> Dict[str, Any]:
       return self.call_tool("my_tool", {"param": param})
   ```

2. Ana test fonksiyonunda kullanın:
   ```python
   def test_custom_operations(client: ActiveDirectoryMCPClient) -> None:
       response = client.my_custom_test("test_value")
       print_response("Custom Test", response)
   ```

### Test Parametrelerini Değiştirme

Environment variables ile test parametrelerini özelleştirebilirsiniz:

```bash
export AD_TEST_OU="OU=TestUsers,DC=company,DC=com"
export AD_TEST_TIMEOUT=60
python test_http_server.py
```

## 🐛 Sorun Giderme

### Yaygın Hatalar

1. **Connection Refused**
   ```
   ❌ Error: Request failed: Connection refused
   ```
   **Çözüm:** Sunucunun çalıştığından emin olun

2. **Timeout Error**
   ```
   ❌ Error: Request failed: Read timeout
   ```
   **Çözüm:** Timeout değerini artırın veya LDAP bağlantısını kontrol edin

3. **Authentication Error**
   ```
   ❌ Error: LDAP authentication failed
   ```
   **Çözüm:** AD konfigürasyonunu kontrol edin

### Debug Modu

Detaylı hata ayıklama için:

```bash
# Detaylı log çıktısı ile
export DEBUG=1
python test_http_server.py

# Curl ile manuel test
curl -X POST "http://localhost:8813/activedirectory-mcp" \
  -H "Content-Type: application/json" \
  -d '{"method": "health", "params": {}}'
```

## 📈 Performans Testi

Test script'leri aynı zamanda performans ölçümü için de kullanılabilir:

```python
import time

start_time = time.time()
response = client.list_users()
end_time = time.time()

print(f"⏱️ Operation took: {end_time - start_time:.2f} seconds")
```

## 🔄 Otomatik Test Çalıştırma

CI/CD pipeline'lar için:

```bash
#!/bin/bash
# Sunucuyu başlat
docker compose up -d

# Sunucunun hazır olmasını bekle
sleep 10

# Test'leri çalıştır
python test_scripts/test_http_server.py

# Sonucu kontrol et
if [ $? -eq 0 ]; then
    echo "✅ All tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi

# Sunucuyu durdur
docker compose down
```

## 📝 Test Sonuçlarını Kaydetme

Test sonuçlarını dosyaya kaydetmek için:

```bash
python test_http_server.py > test_results_$(date +%Y%m%d_%H%M%S).log 2>&1
```

---

**💡 İpucu:** Test script'lerini düzenli olarak çalıştırarak Active Directory entegrasyonunuzun sağlığını kontrol edebilirsiniz.
