// Run with: node --test tests/similarity.test.mjs
// Reference distances come from py-tlsh (Trend Micro's implementation):
// tlsh.diff(a, b) on pairs from data/dataset.b64.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tlshDistance, tlshScore } from "../js/similarity.js";

const REFERENCE = [
  ["T18E133B23EED0093B0987479EEA780B6689F8C52541327DFCF9EC771E900364C9B7A659",
   "T123133C53EFC4083B0D97479ED9780B6684B8CA7985327CBCE9ED7B0E900264C977E259", 32],
  ["T176C3424466C1E89843D79B7F3A1BB1D6F56A0ECDE544480EE294F8D0E0B4607FAE5AF0",
   "T1D8A423B4F9229E9F6DD76DB91B24831DE181C172589D4C2313AE94A34F3D632BF2C816", 397],
  ["T1FF063913FCA555E5C0AEA1358A629252BB717C492B3123C33FA0F7382F76BD0A979354",
   "T170286C43A2E751D8F0BBD17497E65323E932BC490B3469EF12944B312F72AE0A779B11", 558],
  ["T17CF63FEB32519595DC79370DB594FCB0026DFC31AA5A636CB6A20B0502A7FAB5C33363",
   "T1417186684F1EE445F1CAD551D18F2CECCAB894582A563C8A31BF93D09E3433D92896FB", 1406],
];

test("TLSH distance matches the reference implementation", () => {
  for (const [a, b, expected] of REFERENCE) {
    assert.equal(tlshDistance(a, b), expected);
    assert.equal(tlshDistance(b, a), expected);
  }
});

test("identical digests are distance 0, malformed ones are not comparable", () => {
  const [a] = REFERENCE[0];
  assert.equal(tlshDistance(a, a.toLowerCase()), 0);
  assert.equal(tlshDistance(a, a.slice(0, -2)), null);
  assert.equal(tlshDistance(a, a.slice(0, -1) + "Z"), null);
  assert.equal(tlshScore(a, null).present, false);
});
