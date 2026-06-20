#!/usr/bin/env python3
"""Build a tiny ONNX model for the agent-side ml-local smoke path.

The model implements:

    output = sigmoid(input @ W + b)

It is intentionally a deterministic smoke model, not a production detector.
The purpose is to validate that the agent can load a feature ONNX model with
input `input[1,16]` and output `output[1,1]`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper


def build_model(output: Path) -> dict[str, object]:
    output.parent.mkdir(parents=True, exist_ok=True)

    weights = np.zeros((16, 1), dtype=np.float32)
    weights[1, 0] = 4.0   # file entropy
    weights[2, 0] = 0.8   # valid PE
    weights[7, 0] = 2.0   # suspicious imports
    weights[11, 0] = 10.0 # suspicious strings
    bias = np.array([-3.2], dtype=np.float32)

    graph = helper.make_graph(
        [
            helper.make_node("MatMul", ["input", "weights"], ["weighted"]),
            helper.make_node("Add", ["weighted", "bias"], ["logit"]),
            helper.make_node("Sigmoid", ["logit"], ["output"]),
        ],
        "tamandua_ml_feature_smoke",
        [
            helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 16]),
        ],
        [
            helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 1]),
        ],
        [
            numpy_helper.from_array(weights, name="weights"),
            numpy_helper.from_array(bias, name="bias"),
        ],
    )
    model = helper.make_model(
        graph,
        producer_name="tamandua-agent-ml-feature-smoke",
        opset_imports=[helper.make_operatorsetid("", 13)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    onnx.save(model, output)

    return {
        "model": str(output),
        "input": {"name": "input", "shape": [1, 16], "dtype": "float32"},
        "output": {"name": "output", "shape": [1, 1], "dtype": "float32"},
        "weights": weights.flatten().round(6).tolist(),
        "bias": bias.round(6).tolist(),
        "claim_boundary": "Deterministic smoke model only; not a production malware detector.",
    }


def write_samples(output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)

    benign = output_dir / "benign_mz_control.exe"
    benign.write_bytes(
        b"MZ"
        + b"\x00" * 58
        + (128).to_bytes(4, "little")
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x4c\x01\x01\x00"
        + b"\x00" * 512
    )

    suspicious = output_dir / "suspicious_mz_control.exe"
    body = (
        b"MZ"
        + b"\x00" * 58
        + (128).to_bytes(4, "little")
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x4c\x01\x03\x00"
        + b"\x00" * 128
        + b"cmd.exe powershell VirtualAlloc WriteProcessMemory "
        + b"CreateRemoteThread http://example.invalid ransom encrypt "
    )
    high_entropy_tail = bytes((i * 73 + 19) % 256 for i in range(4096))
    suspicious.write_bytes(body + high_entropy_tail)

    return {"benign": str(benign), "suspicious": str(suspicious)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build ml-local smoke ONNX model")
    parser.add_argument("--model-out", default="apps/tamandua_agent/models/malware_features.onnx")
    parser.add_argument("--sample-dir", default="tmp/ml_feature_smoke")
    parser.add_argument("--manifest-out", default="tmp/ml_feature_smoke/manifest.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    model_info = build_model(Path(args.model_out))
    sample_info = write_samples(Path(args.sample_dir))
    manifest = {"model": model_info, "samples": sample_info}
    manifest_path = Path(args.manifest_out)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"ml_feature_smoke_model={args.model_out} manifest={manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
