import io
from itertools import pairwise

import pytest
from PIL import Image, ImageDraw

from src.classifiers.pattern_matcher import find_sensitive_patterns
from src.utils.format_redactor import (
    _expanded_box,
    _ktp_value_regions,
    _ocr_blocks_to_redact,
    redact_document,
)


def test_mykad_redaction_includes_portrait_region_when_ic_is_detected():
    lines = [
        {"Text": "KAD PENGENALAN MALAYSIA"},
        {"Text": "900101-14-5555", "Geometry": {"BoundingBox": {
            "Left": .08, "Top": .18, "Width": .35, "Height": .06,
        }}},
        {"Text": "SYNTHETIC PERSON", "Geometry": {"BoundingBox": {
            "Left": .08, "Top": .32, "Width": .35, "Height": .06,
        }}},
    ]
    selected = _ocr_blocks_to_redact({"my_ic": ["900101-14-5555"]}, lines)

    portrait = [line for line in selected if line.get("PortraitRegion")]
    assert len(portrait) == 2
    box = portrait[0]["Geometry"]["BoundingBox"]
    assert box == {"Left": .66, "Top": .22, "Width": .33, "Height": .74}


def test_ocr_geometry_expands_beyond_detected_glyph_box():
    box = {"Left": 0.10, "Top": 0.20, "Width": 0.30, "Height": 0.05}

    left, top, right, bottom = _expanded_box(box, 1000, 800)

    assert left < 100
    assert top < 160
    assert right > 400
    assert bottom > 200


def test_malay_address_label_redacts_following_ocr_lines_and_name():
    lines = [
        {"Text": "NAMA: SYNTHETIC STUDENT"},
        {"Text": "ALAMAT:"},
        {"Text": "BLOK B-12-3 PANGSAPURI HARMONI"},
        {"Text": "43000 KAJANG SELANGOR"},
        {"Text": "FAKULTI TEKNOLOGI MAKLUMAT"},
    ]

    selected = _ocr_blocks_to_redact({"name": ["SYNTHETIC STUDENT"]}, lines)
    selected_text = [line["Text"] for line in selected]

    assert "ALAMAT:" in selected_text
    assert "BLOK B-12-3 PANGSAPURI HARMONI" in selected_text
    assert "43000 KAJANG SELANGOR" in selected_text
    assert "NAMA: SYNTHETIC STUDENT" in selected_text
    assert "FAKULTI TEKNOLOGI MAKLUMAT" not in selected_text


def test_split_identifier_on_skewed_image_is_covered_by_polygon():
    image = Image.new("RGB", (600, 400), "white")
    draw = ImageDraw.Draw(image)
    draw.polygon([(130, 180), (365, 120), (375, 145), (140, 205)], fill="red")
    source = io.BytesIO()
    image.save(source, format="PNG")
    lines = [
        {
            "Text": "PASSPORT NO: A1234",
            "Geometry": {
                "BoundingBox": {"Left": .23, "Top": .32, "Width": .35, "Height": .09},
                "Polygon": [
                    {"X": .21, "Y": .44}, {"X": .62, "Y": .28},
                    {"X": .64, "Y": .38}, {"X": .23, "Y": .52},
                ],
            },
        },
        {
            "Text": "5678",
            "Geometry": {
                "BoundingBox": {"Left": .35, "Top": .33, "Width": .30, "Height": .08},
                "Polygon": [
                    {"X": .34, "Y": .42}, {"X": .65, "Y": .29},
                    {"X": .66, "Y": .40}, {"X": .35, "Y": .53},
                ],
            },
        },
    ]
    protected, _, evidence = redact_document(
        source.getvalue(), "passport.png", "PASSPORT NO: A1234\n5678",
        {"government_id": ["A12345678"]}, ocr_lines=lines,
    )
    with Image.open(io.BytesIO(protected)) as result:
        pixels = result.convert("RGB").tobytes()
        assert not any(
            pixels[index] > 100 and pixels[index + 1] < 100 and pixels[index + 2] < 100
            for index in range(0, len(pixels), 3)
        )
    assert evidence["redaction_hits"] == 2


def test_missing_ocr_geometry_fails_closed_even_when_other_line_is_redacted():
    image = Image.new("RGB", (200, 100), "white")
    source = io.BytesIO()
    image.save(source, format="PNG")
    lines = [
        {"Text": "PASSPORT: A12345678", "Geometry": {"BoundingBox": {
            "Left": .1, "Top": .1, "Width": .5, "Height": .1,
        }}},
        {"Text": "ADDRESS: 8 Jalan Demo", "Geometry": {}},
    ]
    with pytest.raises(ValueError, match="invalid redaction geometry"):
        redact_document(
            source.getvalue(), "passport.png", "PASSPORT: A12345678\nADDRESS: 8 Jalan Demo",
            {"government_id": ["A12345678"], "address": ["8 Jalan Demo"]},
            ocr_lines=lines,
        )


def test_unmapped_sensitive_value_fails_closed_instead_of_returning_partial_copy():
    image = Image.new("RGB", (200, 100), "white")
    source = io.BytesIO()
    image.save(source, format="PNG")
    lines = [{"Text": "NRIC: 900101145555", "Geometry": {"BoundingBox": {
        "Left": .1, "Top": .1, "Width": .5, "Height": .1,
    }}}]
    with pytest.raises(ValueError, match="every detected sensitive value"):
        redact_document(
            source.getvalue(), "identity.png", "NRIC: 900101145555",
            {"my_ic": ["900101145555"], "government_id": ["A12345678"]},
            ocr_lines=lines,
        )


def test_passport_mrz_is_detected_and_both_lines_are_selected():
    first = "P<MYSDEMO<<PERSON<<<<<<<<<<<<<<<<<<<<<<<<<<"
    second = "A12345678<MYS9001011M3001012<<<<<<<<<<<<<<02"
    lines = [{"Text": "PASSPORT"}, {"Text": first}, {"Text": second}]
    matches = find_sensitive_patterns("\n".join(line["Text"] for line in lines))
    selected = _ocr_blocks_to_redact(matches, lines)

    assert second in matches["government_id"]
    assert first in [line["Text"] for line in selected]
    assert second in [line["Text"] for line in selected]


def test_identity_fields_with_separate_values_are_masked_without_hiding_name():
    lines = [
        {"Text": "PASSPORT MALAYSIA"},
        {"Text": "NAME: SYNTHETIC PERSON"},
        {"Text": "DATE OF EXPIRY:"},
        {"Text": "02/05/2030"},
        {"Text": "NATIONALITY: MALAYSIAN"},
        {"Text": "PLACE OF BIRTH: KUALA LUMPUR"},
    ]
    selected = {block["Text"] for block in _ocr_blocks_to_redact({}, lines)}

    assert "NAME: SYNTHETIC PERSON" not in selected
    assert {"DATE OF EXPIRY:", "02/05/2030", "NATIONALITY: MALAYSIAN", "PLACE OF BIRTH: KUALA LUMPUR"} <= selected


def test_ktp_value_strips_remain_separate_and_do_not_cover_labels():
    labels = [
        "NIK", "Nama", "Tempat/Tgl Lahir", "Jenis Kelamin", "Alamat",
        "RT/RW", "Kel/Desa", "Kecamatan",
    ]
    lines = [{"Text": "PROVINSI DKI JAKARTA"}, {"Text": "Alamat"}]
    lines.extend({
        "Text": label,
        "Geometry": {"BoundingBox": {
            "Left": 0.03, "Top": 0.12 + index * 0.05,
            "Width": 0.18, "Height": 0.035,
        }},
    } for index, label in enumerate(labels))
    regions = _ktp_value_regions(lines)

    assert regions is not None
    assert len(regions) == len(labels)
    assert all(region["ExactRegion"] for region in regions)
    boxes = [region["Geometry"]["BoundingBox"] for region in regions]
    assert all(box["Left"] > 0.21 for box in boxes)
    assert all(
        first["Top"] + first["Height"] < second["Top"]
        for first, second in pairwise(boxes)
    )

    selective = _ktp_value_regions(lines, {"name", "address"})
    assert selective is not None
    assert len(selective) == 3  # NIK, birth field and sex remain covered.


def test_indonesian_nik_is_classified_as_government_id():
    matches = find_sensitive_patterns("NIK: 3174010101900001")
    assert "3174010101900001" in matches["government_id"]
