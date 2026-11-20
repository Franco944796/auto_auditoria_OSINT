import pytest

from app.analysis.risk import RiskLevel, assess, assess_category, overall_level
from app.analysis.rules import Severity, assess_finding
from app.sources.base import Category, Finding


def breach(classes, **flags) -> Finding:
    return Finding(
        source="hibp",
        category=Category.BREACHES,
        code="breach.exposed",
        title="SitioX",
        data={"data_classes": classes, **flags},
    )


def photo(code: str, name: str = "a.jpg") -> Finding:
    return Finding(
        source="exif", category=Category.PHOTOS, code=code, title=code, data={"photo": name}
    )


@pytest.mark.parametrize(
    ("classes", "flags", "expected"),
    [
        (["Email addresses", "Passwords"], {}, Severity.HIGH),
        (["Email addresses", "Credit cards"], {}, Severity.HIGH),
        (["Email addresses", "Phone numbers"], {}, Severity.MEDIUM),
        (["Email addresses", "Dates of birth"], {}, Severity.MEDIUM),
        (["Email addresses"], {"is_sensitive": True}, Severity.MEDIUM),
        (["Email addresses"], {"is_stealer_log": True}, Severity.HIGH),
        (["Email addresses", "Names"], {}, Severity.LOW),
    ],
)
def test_severidad_de_brechas(classes, flags, expected):
    assert assess_finding(breach(classes, **flags)).severity is expected


def test_remediacion_de_brecha_con_contrasenas():
    steps = assess_finding(breach(["Passwords", "Phone numbers"])).remediation
    text = " ".join(steps)
    assert "Cambiá la contraseña de SitioX" in text
    assert "2FA" in text
    assert "SIM" in text
    assert len(steps) == len(set(steps))


def test_contrasenas():
    compromised = Finding(
        source="pwned_passwords",
        category=Category.PASSWORDS,
        code="password.compromised",
        title="1",
    )
    clean = compromised.model_copy(update={"code": "password.clean"})
    assert assess_finding(compromised).severity is Severity.HIGH
    assert assess_finding(clean).severity is Severity.INFO


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("exif.gps", Severity.HIGH),
        ("exif.identifiers", Severity.MEDIUM),
        ("exif.device", Severity.LOW),
        ("exif.datetime", Severity.LOW),
        ("exif.clean", Severity.INFO),
    ],
)
def test_severidad_exif(code, expected):
    assert assess_finding(photo(code)).severity is expected


def test_codigo_desconocido_es_bajo_con_paso_generico():
    assessment = assess_finding(photo("exif.inventado"))
    assert assessment.severity is Severity.LOW and assessment.remediation


def test_nivel_de_categoria_es_el_peor_hallazgo_y_ordena():
    category = assess_category(
        Category.PHOTOS, [photo("exif.device"), photo("exif.gps"), photo("exif.clean", "b.jpg")]
    )
    assert category.level is RiskLevel.HIGH
    assert category.findings[0].code == "exif.gps"
    assert category.summary == "Revisaste 2 fotos: 1 revela la ubicación exacta."


def test_categoria_sin_hallazgos_es_baja_y_no_revisada_queda_sin_nivel():
    categories = assess({Category.BREACHES: []})
    by_category = {c.category: c for c in categories}
    assert by_category[Category.BREACHES].level is RiskLevel.LOW
    assert "no aparece" in by_category[Category.BREACHES].summary
    assert by_category[Category.PASSWORDS].evaluated is False
    assert by_category[Category.PASSWORDS].level is None
    assert overall_level(categories) is RiskLevel.LOW


def test_nivel_global_es_el_peor():
    categories = assess(
        {Category.BREACHES: [breach(["Phone numbers"])], Category.PHOTOS: [photo("exif.gps")]}
    )
    assert overall_level(categories) is RiskLevel.HIGH
    assert overall_level(assess({})) is None
