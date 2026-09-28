"""Behavioral tests for the local cv2 forensics layer.

These are REAL ordering assertions on synthetic fixtures generated in
conftest.py: the moire fixture must score lower screen-replay integrity than
the clean capture, the blurred fixture lower blur, the flat render lower
border/colour integrity, etc.

Run: python3 -m pytest tests/ -q   (from services/python/doc-verification)
"""

from __future__ import annotations

import local_cv
from conftest import to_png


class TestBlur:
    def test_blurry_scores_lower_than_clean(self, clean_card, blurry):
        assert local_cv.blur_score(blurry) < local_cv.blur_score(clean_card)

    def test_blurry_below_poor_threshold(self, blurry):
        assert local_cv.blur_score(blurry) < local_cv.BLUR_POOR_THRESHOLD

    def test_clean_above_good_threshold(self, clean_card):
        assert local_cv.blur_score(clean_card) > local_cv.BLUR_GOOD_THRESHOLD


class TestGlare:
    def test_glare_overlay_scores_higher_than_clean(self, clean_card, glare):
        assert local_cv.glare_score(glare) > local_cv.glare_score(clean_card)

    def test_glare_overlay_exceeds_poor_fraction(self, glare):
        assert local_cv.glare_score(glare) > local_cv.GLARE_POOR_FRACTION

    def test_white_background_is_not_glare(self, flat_render):
        # A nearly all-white flat render is a blank background, not laminate
        # glare — the signal is not measurable there.
        assert local_cv.glare_score(flat_render) == 0.0


class TestScreenReplay:
    def test_moire_scores_lower_integrity_than_clean(self, clean_card, moire):
        assert (local_cv.screen_replay_integrity(moire)
                < local_cv.screen_replay_integrity(clean_card))

    def test_moire_flagged_as_replay(self, moire):
        assert local_cv.screen_replay_integrity(moire) < 0.35

    def test_clean_and_flat_not_flagged(self, clean_card, flat_render):
        assert local_cv.screen_replay_integrity(clean_card) == 1.0
        assert local_cv.screen_replay_integrity(flat_render) == 1.0

    def test_moire_detection_across_periods(self, clean_card):
        import numpy as np
        yy, xx = np.mgrid[0:clean_card.shape[0], 0:clean_card.shape[1]]
        for px, py in ((4, 4), (11, 13), (3, 7)):
            grid = 12 * (np.sin(2 * np.pi * xx / px) * np.sin(2 * np.pi * yy / py))
            img = (clean_card.astype(np.float64) + grid[:, :, None]).clip(0, 255)
            assert local_cv.screen_replay_integrity(img.astype("uint8")) < 0.5, \
                f"moire period ({px},{py}) not detected"


class TestEdgeBorder:
    def test_flat_render_has_no_border(self, clean_card, flat_render):
        assert (local_cv.edge_border_integrity(flat_render)
                < local_cv.edge_border_integrity(clean_card))

    def test_bordered_card_scores_high(self, clean_card):
        assert local_cv.edge_border_integrity(clean_card) >= 0.5


class TestResolutionAndColor:
    def test_tiny_image_fails_resolution(self):
        import numpy as np
        img = np.full((1, 1, 3), 128, np.uint8)
        res = local_cv.resolution_sanity(img)
        assert res["ok"] is False and res["reason"]

    def test_normal_capture_passes_resolution(self, clean_card):
        assert local_cv.resolution_sanity(clean_card)["ok"] is True

    def test_flat_render_less_diverse_than_capture(self, clean_card, flat_render):
        assert (local_cv.color_diversity(flat_render)["unique_colors"]
                < local_cv.color_diversity(clean_card)["unique_colors"])


class TestComposite:
    def test_clean_capture_is_good_quality(self, clean_card):
        out = local_cv.analyze_document_image(to_png(clean_card))
        assert out["decode_ok"] is True
        assert out["quality"] == "good"
        assert out["screen_replay_integrity"] == 1.0

    def test_blurry_is_poor(self, blurry):
        out = local_cv.analyze_document_image(to_png(blurry))
        assert out["quality"] == "poor"
        assert any("blurred" in r for r in out["verdict_reasons"])

    def test_glare_is_poor(self, glare):
        out = local_cv.analyze_document_image(to_png(glare))
        assert out["quality"] == "poor"
        assert any("glare" in r for r in out["verdict_reasons"])

    def test_moire_reports_replay_reason(self, moire):
        out = local_cv.analyze_document_image(to_png(moire))
        assert out["screen_replay_integrity"] < 0.35
        assert any("moire" in r or "screen" in r for r in out["verdict_reasons"])

    def test_flat_render_low_cutout_integrity(self, clean_card, flat_render):
        clean_out = local_cv.analyze_document_image(to_png(clean_card))
        flat_out = local_cv.analyze_document_image(to_png(flat_render))
        assert (flat_out["printed_cutout_integrity"]
                < clean_out["printed_cutout_integrity"])
        assert flat_out["printed_cutout_integrity"] < 0.25

    def test_undecodable_bytes_reported_honestly(self):
        out = local_cv.analyze_document_image(b"\x00\xffnot-an-image")
        assert out["decode_ok"] is False
        assert out["quality"] == "poor"
        assert out["screen_replay_integrity"] is None
        assert out["verdict_reasons"]
