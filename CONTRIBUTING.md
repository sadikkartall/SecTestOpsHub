# Katkıda Bulunma Rehberi

SecTestOps Hub projesine katkıda bulunmak istediğiniz için teşekkür ederiz! 🎉

## 🚀 Başlarken

### Geliştirme Ortamı Kurulumu

1. **Repository'yi Fork Edin**

2. **Klonlayın**
```bash
git clone https://github.com/YOUR_USERNAME/SecTestOps_Hub.git
cd SecTestOps_Hub
```

3. **Branch Oluşturun**
```bash
git checkout -b feature/amazing-feature
```

4. **Development Environment'ı Başlatın**
```bash
docker-compose up --build
```

## 📝 Geliştirme Kuralları

### Code Style

**Python (Backend/Worker):**
- PEP 8 standartlarına uyun
- Type hints kullanın
- Docstring yazın (Google style)
```python
def my_function(param: str) -> dict:
    """
    Brief description.
    
    Args:
        param: Description of param
        
    Returns:
        Description of return value
    """
    pass
```

**JavaScript (Frontend):**
- ESLint kurallarına uyun
- Functional components kullanın
- PropTypes veya TypeScript ile type checking

### Commit Messages

Format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: Yeni özellik
- `fix`: Bug fix
- `docs`: Dokümantasyon
- `style`: Formatting, noktalı virgül vs
- `refactor`: Code refactoring
- `test`: Test ekleme/düzenleme
- `chore`: Build, dependencies vs

Örnek:
```
feat(api): Add export functionality for findings

- Add PDF export endpoint
- Add Markdown export endpoint
- Update API documentation

Closes #123
```

### Branch Naming

- `feature/` - Yeni özellikler
- `fix/` - Bug fixes
- `docs/` - Dokümantasyon
- `refactor/` - Code refactoring
- `test/` - Test ekleme

Örnek: `feature/add-pdf-export`, `fix/scan-timeout-issue`

## 🧪 Testing

### Unit Tests Yazın

**Backend:**
```python
# api/tests/test_endpoints.py
def test_create_target(client):
    response = client.post("/api/targets", json={
        "url": "https://example.com",
        "description": "Test target"
    })
    assert response.status_code == 201
```

**Frontend:**
```javascript
// frontend/src/components/__tests__/SeverityChip.test.js
test('renders critical severity correctly', () => {
  render(<SeverityChip severity="critical" />);
  expect(screen.getByText('CRITICAL')).toBeInTheDocument();
});
```

### Test Coverage

```bash
# Backend
pytest --cov=api tests/

# Frontend
npm test -- --coverage
```

## 📦 Pull Request Süreci

1. **Değişikliklerinizi Commit Edin**
```bash
git add .
git commit -m "feat(api): Add new endpoint"
```

2. **Branch'inizi Push Edin**
```bash
git push origin feature/amazing-feature
```

3. **Pull Request Oluşturun**
   - Clear title ve description
   - Related issues'a referans
   - Screenshots (UI değişiklikleri için)
   - Test sonuçları

4. **Code Review**
   - Review yorumlarına yanıt verin
   - Gerekli değişiklikleri yapın
   - CI/CD testlerinin geçtiğinden emin olun

## 🐛 Bug Raporu

Bug bulduğunuzda GitHub Issues'da şu bilgileri paylaşın:

**Template:**
```markdown
## Bug Tanımı
Clear ve concise açıklama

## Tekrar Etme Adımları
1. Go to '...'
2. Click on '...'
3. See error

## Beklenen Davranış
Ne olması gerekiyordu?

## Ekran Görüntüleri
Varsa ekran görüntüleri ekleyin

## Ortam
- OS: [e.g. Ubuntu 22.04]
- Docker Version: [e.g. 24.0.5]
- Browser: [e.g. Chrome 120]

## Ek Bilgi
Loglar, error messages vs.
```

## ✨ Özellik Önerisi

Yeni özellik önerinizi GitHub Issues'da paylaşın:

**Template:**
```markdown
## Özellik Açıklaması
Clear açıklama

## Motivasyon
Neden gerekli?

## Önerilen Çözüm
Nasıl implement edilmeli?

## Alternatifler
Düşünülen diğer çözümler

## Ek Bilgi
Mockup, diagram vs.
```

## 📚 Dokümantasyon

- README'yi güncel tutun
- API değişikliklerini dokümante edin
- Code comments ekleyin
- Architecture dokümantasyonunu güncelleyin

## 🔒 Güvenlik

Güvenlik açığı bulursanız:
- **ASLA** public issue açmayın
- Email: [security@example.com]
- Detaylı açıklama + PoC (varsa)

## 💡 İyi Pratikler

### Backend/API

- Async endpoint'ler kullanın
- Input validation yapın
- Error handling ekleyin
- Logging ekleyin
```python
logger.info(f"Target created: {target.id}")
logger.error(f"Scan failed: {error}")
```

### Worker/Tasks

- Timeout değerleri belirleyin
- Retry logic ekleyin
- Progress tracking yapın
- Clean error messages

### Frontend

- Loading states ekleyin
- Error handling yapın
- Responsive design
- Accessibility (a11y)

### Database

- Migration dosyaları oluşturun
- Foreign key constraints kullanın
- Index'leri optimize edin
- Backup stratejisi düşünün

## 🎨 UI/UX Guidelines

- Material-UI components kullanın
- Consistent color scheme
- Mobile-friendly
- User feedback (toasts, alerts)
- Loading indicators

## 📊 Performance

- N+1 query'leri önleyin
- Pagination kullanın
- Cache stratejisi uygulayın
- Optimize image sizes
- Lazy loading

## 🏗️ Architecture Decisions

Büyük değişiklikler için:
1. Architecture Decision Record (ADR) yazın
2. Team'le discuss edin
3. Alternatif çözümleri değerlendirin
4. Pros/cons listeleyin

## 📖 Kaynaklar

- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [React Docs](https://react.dev/)
- [Material-UI Docs](https://mui.com/)
- [PostgreSQL Docs](https://www.postgresql.org/docs/)
- [Docker Docs](https://docs.docker.com/)

## 🤝 Community

- Respectful communication
- Constructive feedback
- Help others
- Share knowledge

## 📜 License

Katkılarınız projenin lisansı altında paylaşılacaktır.

---

**Teşekkürler! 🙏**

Katkılarınız SecTestOps Hub'ı daha iyi hale getiriyor!

