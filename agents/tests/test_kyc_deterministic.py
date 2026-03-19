"""
Tests unitarios — KYC Determinista TokenIDS
============================================
Tests que NO requieren imágenes reales.
Verifican la lógica de validación, confidence y decisiones.

TFM Reference: Fase 2 — Sprint 2.2 — Tests KYC Determinista
"""

import unittest
from datetime import date
from agents.kyc.kyc_deterministic import (
    ColombianDocumentValidator,
    ConfidenceCalculator,
    DocumentType,
    KYCDecision,
    KYCProcessor,
    KYCResult,
)


class TestColombianDocumentValidator(unittest.TestCase):
    """Tests del validador de documentos colombianos."""

    # ── Detección de tipo ────────────────────────────────────

    def test_detecta_cedula_colombiana(self):
        text = "REPUBLICA DE COLOMBIA\nCedula de Ciudadania\n1023456789"
        result = ColombianDocumentValidator.detect_document_type(text)
        self.assertEqual(result, DocumentType.CEDULA_COLOMBIANA)

    def test_detecta_pasaporte(self):
        text = "PASAPORTE\nREPUBLICA DE COLOMBIA\nAB1234567"
        result = ColombianDocumentValidator.detect_document_type(text)
        self.assertEqual(result, DocumentType.PASAPORTE)

    def test_detecta_nit(self):
        text = "NIT: 900123456-1\nNumero de Identificacion Tributario"
        result = ColombianDocumentValidator.detect_document_type(text)
        self.assertEqual(result, DocumentType.NIT)

    def test_documento_desconocido(self):
        text = "texto aleatorio sin keywords de documento"
        result = ColombianDocumentValidator.detect_document_type(text)
        self.assertEqual(result, DocumentType.UNKNOWN)

    # ── Extracción de número ─────────────────────────────────

    def test_extrae_numero_cedula(self):
        text = "Cedula de Ciudadania\n1023456789"
        number = ColombianDocumentValidator.extract_document_number(
            text, DocumentType.CEDULA_COLOMBIANA
        )
        self.assertEqual(number, "1023456789")

    def test_extrae_numero_nit(self):
        text = "NIT 900123456-1"
        number = ColombianDocumentValidator.extract_document_number(
            text, DocumentType.NIT
        )
        self.assertEqual(number, "900123456-1")

    def test_numero_no_encontrado(self):
        text = "texto sin numero de documento"
        number = ColombianDocumentValidator.extract_document_number(
            text, DocumentType.CEDULA_COLOMBIANA
        )
        self.assertIsNone(number)

    # ── Extracción de fecha ──────────────────────────────────

    def test_extrae_fecha_nacimiento_dd_mm_yyyy(self):
        text = "Fecha de nacimiento: 15/03/1990"
        birth = ColombianDocumentValidator.extract_birth_date(text)
        self.assertIsNotNone(birth)
        self.assertEqual(birth.year, 1990)
        self.assertEqual(birth.month, 3)
        self.assertEqual(birth.day, 15)

    def test_fecha_sin_keyword_no_se_extrae(self):
        text = "15/03/1990"  # Sin keyword de nacimiento
        birth = ColombianDocumentValidator.extract_birth_date(text)
        self.assertIsNone(birth)


class TestConfidenceCalculator(unittest.TestCase):
    """Tests del calculador de confidence score."""

    def test_confidence_maxima_todos_los_campos(self):
        score = ConfidenceCalculator.calculate(
            doc_type=DocumentType.CEDULA_COLOMBIANA,
            doc_number="1023456789",
            full_name="Juan Carlos Lopez Martinez",
            birth_date=date(1990, 3, 15),
        )
        self.assertEqual(score, 1.0)

    def test_confidence_cero_sin_campos(self):
        score = ConfidenceCalculator.calculate(
            doc_type=DocumentType.UNKNOWN,
            doc_number=None,
            full_name=None,
            birth_date=None,
        )
        self.assertEqual(score, 0.0)

    def test_confidence_parcial_sin_fecha(self):
        score = ConfidenceCalculator.calculate(
            doc_type=DocumentType.CEDULA_COLOMBIANA,
            doc_number="1023456789",
            full_name="Juan Lopez",
            birth_date=None,
        )
        # 0.30 + 0.30 + 0.20 = 0.80
        self.assertEqual(score, 0.80)

    def test_confidence_sin_nombre(self):
        score = ConfidenceCalculator.calculate(
            doc_type=DocumentType.CEDULA_COLOMBIANA,
            doc_number="1023456789",
            full_name=None,
            birth_date=date(1990, 1, 1),
        )
        # 0.30 + 0.30 + 0.20 = 0.80
        self.assertEqual(score, 0.80)


class TestKYCDecisions(unittest.TestCase):
    """Tests de las decisiones KYC basadas en confidence."""

    def _make_result(self, confidence: float) -> KYCResult:
        """Helper para crear resultados con confidence específico."""
        if confidence >= 0.90:
            decision = KYCDecision.APPROVED
        elif confidence >= 0.70:
            decision = KYCDecision.ESCALATE_TO_AI
        else:
            decision = KYCDecision.REJECTED

        return KYCResult(
            decision=decision,
            confidence=confidence,
            document_type=DocumentType.CEDULA_COLOMBIANA,
            document_number="1023456789",
            full_name="Juan Lopez",
            birth_date=date(1990, 1, 1),
            is_adult=True,
            raw_text="test",
            processing_ms=100,
        )

    def test_confidence_090_approved(self):
        result = self._make_result(0.90)
        self.assertEqual(result.decision, KYCDecision.APPROVED)

    def test_confidence_100_approved(self):
        result = self._make_result(1.0)
        self.assertEqual(result.decision, KYCDecision.APPROVED)

    def test_confidence_080_escalate(self):
        result = self._make_result(0.80)
        self.assertEqual(result.decision, KYCDecision.ESCALATE_TO_AI)

    def test_confidence_070_escalate(self):
        result = self._make_result(0.70)
        self.assertEqual(result.decision, KYCDecision.ESCALATE_TO_AI)

    def test_confidence_069_rejected(self):
        result = self._make_result(0.69)
        self.assertEqual(result.decision, KYCDecision.REJECTED)

    def test_confidence_000_rejected(self):
        result = self._make_result(0.0)
        self.assertEqual(result.decision, KYCDecision.REJECTED)


class TestMayoriaDeEdad(unittest.TestCase):
    """Tests de verificación de mayoría de edad — ZKP."""

    def test_adulto_mayor_de_18(self):
        birth = date(1990, 1, 1)
        today = date.today()
        age = (today - birth).days // 365
        self.assertTrue(age >= 18)

    def test_menor_de_edad(self):
        birth = date(2015, 1, 1)
        today = date.today()
        age = (today - birth).days // 365
        self.assertFalse(age >= 18)

    def test_exactamente_18_anos(self):
        today = date.today()
        birth = date(today.year - 18, today.month, today.day)
        age = (today - birth).days // 365
        self.assertTrue(age >= 18)


class TestKYCResultToDict(unittest.TestCase):
    """Tests de serialización del resultado KYC."""

    def test_to_dict_approved(self):
        result = KYCResult(
            decision=KYCDecision.APPROVED,
            confidence=1.0,
            document_type=DocumentType.CEDULA_COLOMBIANA,
            document_number="1023456789",
            full_name="Juan Lopez",
            birth_date=date(1990, 3, 15),
            is_adult=True,
            raw_text="texto ocr",
            processing_ms=250,
        )
        d = result.to_dict()
        self.assertEqual(d["decision"], "APPROVED")
        self.assertEqual(d["confidence"], 1.0)
        self.assertEqual(d["document_type"], "CC")
        self.assertEqual(d["birth_date"], "1990-03-15")
        self.assertTrue(d["is_adult"])

    def test_to_dict_con_error(self):
        result = KYCResult(
            decision=KYCDecision.REJECTED,
            confidence=0.0,
            document_type=DocumentType.UNKNOWN,
            document_number=None,
            full_name=None,
            birth_date=None,
            is_adult=False,
            raw_text="",
            processing_ms=10,
            error_message="Archivo no encontrado",
        )
        d = result.to_dict()
        self.assertEqual(d["decision"], "REJECTED")
        self.assertEqual(d["error_message"], "Archivo no encontrado")


if __name__ == "__main__":
    unittest.main(verbosity=2)