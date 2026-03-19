"""
TokenIDS — Módulo KYC Determinista
"""
import re
import logging
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, date
from pathlib import Path
from typing import Optional

try:
    import pytesseract
    from PIL import Image, ImageFilter, ImageEnhance
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

logger = logging.getLogger(__name__)


class DocumentType(Enum):
    CEDULA_COLOMBIANA = "CC"
    PASAPORTE = "PP"
    CEDULA_EXTRANJERIA = "CE"
    NIT = "NIT"
    UNKNOWN = "UNKNOWN"


class KYCDecision(Enum):
    APPROVED = "APPROVED"
    ESCALATE_TO_AI = "ESCALATE"
    REJECTED = "REJECTED"


@dataclass
class KYCResult:
    decision: KYCDecision
    confidence: float
    document_type: DocumentType
    document_number: Optional[str]
    full_name: Optional[str]
    birth_date: Optional[date]
    is_adult: bool
    raw_text: str
    processing_ms: int
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "confidence": round(self.confidence, 4),
            "document_type": self.document_type.value,
            "document_number": self.document_number,
            "full_name": self.full_name,
            "birth_date": self.birth_date.isoformat() if self.birth_date else None,
            "is_adult": self.is_adult,
            "processing_ms": self.processing_ms,
            "error_message": self.error_message,
        }


class ColombianDocumentValidator:
    CEDULA_PATTERN = re.compile(r'\b([1-9]\d{5,9})\b')
    NIT_PATTERN = re.compile(r'\b(\d{9})-?(\d)\b')
    PASSPORT_PATTERN = re.compile(r'\b([A-Z]{1,2}\d{6,8})\b')
    DATE_PATTERNS = [
        re.compile(r'\b(\d{1,2})[/\-\.](\d{1,2})[/\-\.](\d{4})\b'),
        re.compile(r'\b(\d{4})[/\-\.](\d{1,2})[/\-\.](\d{1,2})\b'),
    ]
    CEDULA_KEYWORDS = [
        'cedula', 'cédula', 'ciudadania', 'ciudadanía',
        'c.c.', 'registraduria', 'registraduría',
        'republica de colombia', 'república de colombia',
    ]
    PASSPORT_KEYWORDS = ['pasaporte', 'passport']

    @classmethod
    def detect_document_type(cls, text: str) -> DocumentType:
        text_lower = text.lower()
        
        # ⚠️ PRIMERO verificar PASAPORTE (prioridad)
        if 'pasaporte' in text_lower or 'passport' in text_lower:
            match = cls.PASSPORT_PATTERN.search(text.upper())
            if match:
                return DocumentType.PASAPORTE
        
        # Luego CÉDULA
        if any(kw in text_lower for kw in cls.CEDULA_KEYWORDS):
            return DocumentType.CEDULA_COLOMBIANA
        
        # Luego NIT
        if 'nit' in text_lower or 'tributario' in text_lower:
            return DocumentType.NIT
        
        # Luego Cédula de Extranjería
        if 'extranjeria' in text_lower or 'extranjería' in text_lower:
            return DocumentType.CEDULA_EXTRANJERIA
        
        return DocumentType.UNKNOWN

    @classmethod
    def extract_document_number(cls, text: str, doc_type: DocumentType) -> Optional[str]:
        if doc_type == DocumentType.CEDULA_COLOMBIANA:
            matches = cls.CEDULA_PATTERN.findall(text)
            if matches:
                return max(matches, key=len)
        elif doc_type == DocumentType.PASAPORTE:
            match = cls.PASSPORT_PATTERN.search(text.upper())
            if match:
                return match.group(0)
        elif doc_type == DocumentType.NIT:
            match = cls.NIT_PATTERN.search(text)
            if match:
                return f"{match.group(1)}-{match.group(2)}"
        return None

    @classmethod
    def extract_birth_date(cls, text: str) -> Optional[date]:
        text_lower = text.lower()
        birth_keywords = ['nacimiento', 'nacido', 'fecha nac', 'date of birth', 'born', 'dob']
        for pattern in cls.DATE_PATTERNS:
            for match in pattern.finditer(text):
                start = max(0, match.start() - 50)
                context = text_lower[start:match.end() + 10]
                if any(kw in context for kw in birth_keywords):
                    try:
                        groups = match.groups()
                        if len(groups[0]) == 4:
                            return date(int(groups[0]), int(groups[1]), int(groups[2]))
                        else:
                            return date(int(groups[2]), int(groups[1]), int(groups[0]))
                    except (ValueError, IndexError):
                        continue
        return None

    @classmethod
    def extract_full_name(cls, text: str) -> Optional[str]:
        name_keywords = [
            r'apellidos?\s+y\s+nombres?\s*[:\n]?\s*([A-ZÁÉÍÓÚÑ ]{5,50})',
            r'nombres?\s+y\s+apellidos?\s*[:\n]?\s*([A-ZÁÉÍÓÚÑ ]{5,50})',
            r'nombre\s+completo\s*[:\n]?\s*([A-ZÁÉÍÓÚÑ ]{5,50})',
        ]
        for pattern in name_keywords:
            match = re.search(pattern, text.upper())
            if match:
                name = match.group(1).strip()
                if 5 <= len(name) <= 60:
                    return name.title()
        return None


class ImagePreprocessor:
    @staticmethod
    def preprocess(image_path: str) -> "Image.Image":
        img = Image.open(image_path)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img = img.convert("L")
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(2.0)
        img = img.filter(ImageFilter.SHARPEN)
        min_width = 800
        if img.width < min_width:
            ratio = min_width / img.width
            new_size = (min_width, int(img.height * ratio))
            img = img.resize(new_size, Image.LANCZOS)
        return img


class ConfidenceCalculator:
    @staticmethod
    def calculate(doc_type: DocumentType, doc_number: Optional[str], full_name: Optional[str], birth_date: Optional[date]) -> float:
        score = 0.0
        if doc_type != DocumentType.UNKNOWN:
            score += 0.30
        if doc_number:
            if len(doc_number.replace('-', '')) >= 6:
                score += 0.30
            else:
                score += 0.15
        if full_name:
            words = full_name.split()
            if len(words) >= 2:
                score += 0.20
            else:
                score += 0.10
        if birth_date:
            if birth_date < date.today():
                score += 0.20
        return round(min(score, 1.0), 4)


class KYCProcessor:
    def __init__(self):
        if not TESSERACT_AVAILABLE:
            raise RuntimeError("pytesseract o PIL no están instalados.")
        self.tesseract_config = "--oem 3 --psm 3 -l spa+eng"
        self.preprocessor = ImagePreprocessor()
        self.validator = ColombianDocumentValidator()
        self.confidence_calc = ConfidenceCalculator()

    def process(self, image_path: str) -> KYCResult:
        start_time = datetime.now()
        if not Path(image_path).exists():
            return KYCResult(
                decision=KYCDecision.REJECTED,
                confidence=0.0,
                document_type=DocumentType.UNKNOWN,
                document_number=None,
                full_name=None,
                birth_date=None,
                is_adult=False,
                raw_text="",
                processing_ms=0,
                error_message=f"Archivo no encontrado: {image_path}"
            )
        try:
            img = self.preprocessor.preprocess(image_path)
            raw_text = pytesseract.image_to_string(img, config=self.tesseract_config)
            doc_type = self.validator.detect_document_type(raw_text)
            doc_number = self.validator.extract_document_number(raw_text, doc_type)
            full_name = self.validator.extract_full_name(raw_text)
            birth_date = self.validator.extract_birth_date(raw_text)
            confidence = self.confidence_calc.calculate(doc_type, doc_number, full_name, birth_date)
            is_adult = False
            if birth_date:
                age = (date.today() - birth_date).days // 365
                is_adult = age >= 18
            if confidence >= 0.90:
                decision = KYCDecision.APPROVED
            elif confidence >= 0.70:
                decision = KYCDecision.ESCALATE_TO_AI
            else:
                decision = KYCDecision.REJECTED
            processing_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            return KYCResult(
                decision=decision,
                confidence=confidence,
                document_type=doc_type,
                document_number=doc_number,
                full_name=full_name,
                birth_date=birth_date,
                is_adult=is_adult,
                raw_text=raw_text,
                processing_ms=processing_ms,
            )
        except Exception as e:
            processing_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            return KYCResult(
                decision=KYCDecision.REJECTED,
                confidence=0.0,
                document_type=DocumentType.UNKNOWN,
                document_number=None,
                full_name=None,
                birth_date=None,
                is_adult=False,
                raw_text="",
                processing_ms=processing_ms,
                error_message=str(e)
            )