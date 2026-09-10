"""Tests for titan.modules.coverage.proof — Merkle-tree coverage proofs.

Pure computation over tracker records: record hashing, tree building,
proof extraction, bundle verification, and script generation. No I/O.
"""

import json

from titan.modules.coverage.proof import CoverageProof, CoverageProofBundle
from titan.modules.coverage.proof import TestProof as ProofRecord
from titan.modules.coverage.tracker import CoverageTracker


def _tracker_with(n: int) -> CoverageTracker:
    t = CoverageTracker()
    for i in range(n):
        t.record_test(f"/ep{i}", "sqli", f"payload-{i}", "executed", 200, f"body-{i}")
    return t


class TestHashRecord:
    def test_hash_is_deterministic_and_canonical(self):
        t = _tracker_with(1)
        p = CoverageProof(t)
        rec = t.get_records()[0]
        h1 = p._hash_record(rec)
        h2 = p._hash_record(rec)
        assert h1 == h2
        # canonical form: sorted keys of the documented field set
        data = json.dumps(
            {
                "endpoint": rec.endpoint,
                "attack_type": rec.attack_type,
                "status": rec.status,
                "response_code": rec.response_code,
                "response_hash": rec.response_hash,
                "timestamp": rec.timestamp,
            },
            sort_keys=True,
        )
        import hashlib

        assert h1 == hashlib.sha256(data.encode()).hexdigest()

    def test_different_records_hash_differently(self):
        t = _tracker_with(2)
        p = CoverageProof(t)
        r1, r2 = t.get_records()
        assert p._hash_record(r1) != p._hash_record(r2)


class TestMerkleTree:
    def test_empty_tree(self):
        p = CoverageProof(CoverageTracker())
        assert p._build_merkle_tree([]) == []
        assert p._get_root_hash([]) == ""

    def test_single_leaf_is_root(self):
        p = CoverageProof(CoverageTracker())
        tree = p._build_merkle_tree(["leaf"])
        assert tree == [["leaf"]]
        assert p._get_root_hash(tree) == "leaf"

    def test_even_leaves(self):
        import hashlib

        p = CoverageProof(CoverageTracker())
        tree = p._build_merkle_tree(["a", "b"])
        expected = hashlib.sha256(b"ab").hexdigest()
        assert len(tree) == 2
        assert tree[0] == ["a", "b"]
        assert tree[1] == [expected]

    def test_odd_leaf_is_duplicated_and_hashed(self):
        import hashlib

        p = CoverageProof(CoverageTracker())
        tree = p._build_merkle_tree(["a", "b", "c"])
        h_ab = hashlib.sha256(b"ab").hexdigest()
        h_cc = hashlib.sha256(b"cc").hexdigest()  # odd leaf duplicated, then hashed
        expected_root = hashlib.sha256((h_ab + h_cc).encode()).hexdigest()
        assert len(tree) == 3
        assert tree[1] == [h_ab, h_cc]
        assert p._get_root_hash(tree) == expected_root

    def test_root_changes_when_a_leaf_changes(self):
        p = CoverageProof(CoverageTracker())
        t1 = p._build_merkle_tree(["a", "b"])
        t2 = p._build_merkle_tree(["a", "x"])
        assert p._get_root_hash(t1) != p._get_root_hash(t2)


class TestGenerateBundle:
    def test_bundle_shape(self):
        t = _tracker_with(4)
        p = CoverageProof(t)
        bundle = p.generate()
        assert isinstance(bundle, CoverageProofBundle)
        assert bundle.total_tests == 4
        assert len(bundle.test_proofs) == 4
        assert all(isinstance(tp, ProofRecord) for tp in bundle.test_proofs)
        assert bundle.root_hash == p._get_root_hash(bundle.merkle_tree)
        assert bundle.verification_script.startswith("#!/bin/bash")

    def test_proof_covers_every_record(self):
        t = _tracker_with(3)
        bundle = CoverageProof(t).generate()
        t_records = t.get_records()
        for proof, rec in zip(bundle.test_proofs, t_records):
            assert proof.endpoint == rec.endpoint
            assert proof.response_hash == rec.response_hash
            assert proof.status == rec.status
            assert proof.verification_command  # non-empty

    def test_merkle_proof_length_matches_depth(self):
        t = _tracker_with(8)
        bundle = CoverageProof(t).generate()
        # 8 leaves -> 4 levels; proofs reference all but the root level
        assert len(bundle.merkle_tree) == 4
        for tp in bundle.test_proofs:
            assert len(tp.merkle_proof) == len(bundle.merkle_tree) - 1

    def test_verify_script_embeds_every_test(self):
        t = _tracker_with(2)
        bundle = CoverageProof(t).generate()
        for tp in bundle.test_proofs:
            assert f"Test: {tp.endpoint} × {tp.attack_type}" in bundle.verification_script
        assert "Root hash:" in bundle.verification_script


class TestVerifyProof:
    def test_verify_valid_bundle(self):
        t = _tracker_with(5)
        p = CoverageProof(t)
        bundle = p.generate()
        result = p.verify_proof(bundle)
        assert result["merkle_tree_valid"] is True
        assert result["tamper_detected"] is False
        assert result["total_tests"] == 5
        assert len(result["verification_hash"]) == 64
        assert "instructions" in result["third_party_verification"]

    def test_verify_detects_tampered_leaf(self):
        t = _tracker_with(5)
        p = CoverageProof(t)
        bundle = p.generate()
        # mutate a leaf hash deep in the tree
        tampered = CoverageProofBundle(
            root_hash=bundle.root_hash,
            timestamp=bundle.timestamp,
            total_tests=bundle.total_tests,
            test_proofs=bundle.test_proofs,
            merkle_tree=[level[:] for level in bundle.merkle_tree],
            verification_script=bundle.verification_script,
        )
        tampered.merkle_tree[0][2] = "0" * 64
        result = p.verify_proof(tampered)
        assert result["merkle_tree_valid"] is False

    def test_verify_tampered_proof_record(self):
        t = _tracker_with(4)
        p = CoverageProof(t)
        bundle = p.generate()
        # forge a proof whose response_hash doesn't match any hashed leaf
        forged = ProofRecord(
            test_id=bundle.test_proofs[0].test_id,
            endpoint="/evil",
            attack_type="rce",
            status=bundle.test_proofs[0].status,
            response_code=200,
            response_hash="f" * 64,
            timestamp=bundle.test_proofs[0].timestamp,
            merkle_proof=bundle.test_proofs[0].merkle_proof,
            verification_command="true",
        )
        tampered = CoverageProofBundle(
            root_hash=bundle.root_hash,
            timestamp=bundle.timestamp,
            total_tests=bundle.total_tests,
            test_proofs=[forged] + bundle.test_proofs[1:],
            merkle_tree=bundle.merkle_tree,
            verification_script=bundle.verification_script,
        )
        result = p.verify_proof(tampered)
        assert result["merkle_tree_valid"] is False

    def test_to_dict_roundtrip_fields(self):
        t = _tracker_with(3)
        p = CoverageProof(t)
        bundle = p.generate()
        d = p.to_dict(bundle)
        assert d["root_hash"] == bundle.root_hash
        assert d["total_tests"] == 3
        assert d["test_proofs_count"] == 3
        assert d["merkle_tree_depth"] == len(bundle.merkle_tree)
        assert d["verification_script"] == bundle.verification_script
