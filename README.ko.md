# Ridi-DRM-Remover

리디북스에서 구매하여 다운로드한 전자책의 DRM을 제거하여 일반적인 EPUB/PDF 파일로 변환해주는 CLI 도구입니다.

> **면책 조항 (Disclaimer)**
>
> 본 소프트웨어를 통해 취득한 결과물을 공유, 배포 또는 판매하는 행위는 엄격히 금지됩니다. 본 소프트웨어의 오용으로 인해 발생하는 모든 책임은 사용자 본인에게 있습니다. 사용 시 주의하시기 바랍니다.

## 준비 사항

- **Python 3.8 이상**
- **리디북스 PC/Mac 앱**: DRM을 제거하려는 도서가 공식 앱을 통해 미리 다운로드되어 있어야 합니다.

## 설치 방법

1. 저장소를 클론합니다:

   ```bash
   git clone https://github.com/thecats1105/Ridi-DRM-Remover.git
   cd Ridi-DRM-Remover
   ```

2. (선택 사항) 가상 환경을 생성하고 활성화합니다:

   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. 필요한 패키지를 설치합니다:
   ```bash
   pip install -r requirements.txt
   ```

## 사용 방법

모든 작업은 `ridi.py`를 통해 수행됩니다.

### 1. 계정 인증 및 설정 (`auth`)

도서를 추출하기 전, `device_id`와 `user_idx`를 설정하기 위해 로그인을 진행해야 합니다.

```bash
python ridi.py auth login
```

- 안내에 따라 브라우저에서 리디북스에 로그인합니다.
- 로그인 후 표시되는 페이지의 JSON 데이터를 복사합니다.
- 터미널에 붙여넣은 뒤, 도서가 다운로드된 기기를 선택하세요.

**기타 인증 명령:**

- `python ridi.py auth list`: 저장된 계정 목록 보기.
- `python ridi.py auth switch`: 활성 계정 전환.
- `python ridi.py auth logout`: 계정 정보 삭제.

### 2. 도서 목록 확인 (`books`)

로컬 라이브러리에 다운로드된 도서 중 추출 가능한 목록을 확인합니다.

```bash
python ridi.py books
```

- **제목 필터링**: `python ridi.py books -n "제목"`
- **ID로 필터링**: `python ridi.py books -i "123456"`

### 3. 도서 내보내기 (`export`)

도서의 DRM을 제거하여 지정된 디렉토리에 저장합니다.

```bash
# 모든 다운로드된 도서 내보내기
python ridi.py export --all -o ./output

# 특정 ID의 도서만 내보내기
python ridi.py export -i "123456" -o ./output

# 제목이 포함된 도서 내보내기
python ridi.py export -n "제목"
```

## 컴파일 (빌드)

[Nuitka](https://nuitka.net/)를 사용하여 `ridi.py`를 단일 실행 파일(.exe)로 컴파일할 수 있습니다. 안정적인 컴파일을 위해 **Python 3.13** 사용을 권장합니다:

```bash
# 단일 실행 파일로 컴파일
python -m nuitka --onefile --output-dir=builds/ ridi.py
```

## 주요 기능

- **다중 계정 지원**: 여러 개의 리디 계정을 관리할 수 있습니다. 기기 선택은 현재 리디북스 뷰어가 활성화된 기기의 암호화 데이터를 일치시키기 위해 사용됩니다.
- **제목 자동 추출**: EPUB/PDF 메타데이터를 분석하여 실제 도서 제목으로 파일 이름을 생성합니다.
- **EPUB & PDF 지원**: 리디북스에서 제공하는 두 가지 주요 포맷을 모두 지원합니다.
- **파일명 정리**: 파일 시스템에서 오류를 일으킬 수 있는 문자를 자동으로 제거합니다.

## 참고

- [Retro-Rex8/Ridi-DRM-Remover](https://github.com/Retro-Rex8/Ridi-DRM-Remover)
- [hsj1/ridiculous](https://github.com/hsj1/ridiculous)
- 이 프로젝트는 리디 DRM에 대한 커뮤니티의 여러 연구를 바탕으로 제작되었습니다.
