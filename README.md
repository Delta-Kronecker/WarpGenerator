# Warp Generator

## English

Cloudflare WARP endpoint scanner and config generator.

### Features
- Scans WARP endpoints using Xray core
- Supports IPv4 (14 IP ranges, 54 ports per IP)
- UDP noise for ISP bypass
- Ctrl+S to stop and save results
- Generates: .conf files, wireguard:// links, Clash YAML config


### Usage
1. Select IP ranges 
2. Choose noise mode (1: with noise, 2: without)
3. Set concurrent workers (default: 50)
4. Press Ctrl+S to stop early
5. Generate WARP config with wgcf

### Outputs
| File | Description |
|------|-------------|
| `result.json` | Scan results |
| `warp_configs.zip` | WireGuard configs per endpoint |
| `warp_links.txt` | wireguard:// URI links |
| `clash_config.yaml` | Clash config (url-test strategy) |

### Build
```bash
# Linux
go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator .

# Windows
GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator.exe .

# Termux (ARM64)
GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator .
```

## فارسی

ابزار اسکن و ساخت کانفیگ Cloudflare WARP

### ویژگی‌ها
- اسکن اندپوینت‌های WARP با Xray core
- پشتیبانی از IPv4 (۱۴ رینج IP، ۵۴ پورت در هر IP)
- UDP noise برای عبور از فیلترینگ ISP
- Ctrl+S برای توقف و ذخیره نتایج
- خروجی: فایل‌های .conf، لینک‌های wireguard://، کانفیگ Clash


### نحوه استفاده
1. رینج‌های IP رو انتخاب کنید
2. حالت noise رو انتخاب کنید (۱: با noise، ۲: بدون)
3. تعداد وورکر همزمان رو تنظیم کنید (پیش‌فرض: ۵۰)
4. Ctrl+S بزنید برای توقف زودهنگام
5. ساخت کانفیگ WARP با wgcf

### خروجی‌ها
| فایل | توضیح |
|------|-------|
| `result.json` | نتایج اسکن |
| `warp_configs.zip` | کانفیگ‌های WireGuard برای هر endpoint |
| `warp_links.txt` | لینک‌های wireguard:// |
| `clash_config.yaml` | کانفیگ Clash (استراتژی url-test) |

### ساخت
```bash
# لینوکس
go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator .

# ویندوز
GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator.exe .

# Termux (ARM64)
GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-w -s" -o WarpGenerator .
```
